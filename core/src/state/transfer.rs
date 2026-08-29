//! 传输会话状态机（每会话一个实例）
//!
//! 双方共识状态（阶段变更需对端 ack），不是本地字段。
//! 详见 V4-TRANSFER-MODULE.md §二、§三。
//!
//! 状态：Idle / Preparing / Reconciling / Transferring / Paused /
//! Degrading / Verifying / Completed / Failed / Aborted
//!
//! 关键性质：
//! - **终态单调**：一旦进入 Completed / Aborted，不可回退（Failed 允许显式 Retry 开启新尝试）。
//! - **降级不回切**：会话内从 Advanced 降级到 Basic 后，不再切回 Advanced
//!   （防止主/基反复横跳）；下次会话重新检测。
//! - **连接断开即中止**：PeerLost 在任何非终态都直接进 Aborted。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    Idle,
    Preparing,
    Reconciling,
    Transferring,
    Paused,
    Degrading,
    Verifying,
    Completed,
    Failed,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IllegalTransition {
    pub from: TransferState,
    pub event: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferEvent {
    /// 注册会话（Idle → Preparing）
    Register,
    /// 协商结果：对端具备 Advanced 能力 → 进入 Reconciling 拉块位图
    NegotiateAdvanced,
    /// 协商结果：对端无能力 → 直接用 Basic，跳到 Transferring
    NegotiateBasic,
    /// 块位图对账完成（Reconciling → Transferring）
    Reconciled,
    /// 对账连续失败（Reconciling → Degrading）
    ReconcileFailed,
    /// 传输进度事件（Transferring → Transferring，幂等）
    Progress,
    /// 心跳超时（Transferring → Paused）
    HeartbeatTimeout,
    /// 连续块失败达阈值（Transferring → Degrading）
    ChunkRetryExhausted,
    /// 显式降级（Preparing/Reconciling/Transferring/Paused → Degrading）
    Degrade,
    /// 降级完成，切到基础算法继续（Degrading → Transferring）
    DegradeComplete,
    /// 全部块传完，进入整体校验（Transferring → Verifying）
    BeginVerify,
    /// 校验通过（Verifying → Completed）
    VerifyOk,
    /// 校验失败（Verifying → Degrading，仍有基础算法可兜底）
    VerifyFailed,
    /// 用户/系统中止（多数态 → Aborted）
    Abort,
    /// 连接断开（任何非终态 → Aborted）
    PeerLost,
    /// 重试（Paused/Failed → Preparing，开启新尝试）
    Retry,
    /// 暂停后重试耗尽（Paused → Failed）
    RetryExhausted,
    /// 应用重置（任意 → Idle）
    ForceReset,
}

impl TransferState {
    pub fn transition(self, ev: TransferEvent) -> Result<Self, IllegalTransition> {
        use TransferState::*;
        let next = match (self, ev) {
            (Idle, TransferEvent::Register) => Preparing,
            (Preparing, TransferEvent::NegotiateAdvanced) => Reconciling,
            (Preparing, TransferEvent::NegotiateBasic) => Transferring,
            (Preparing, TransferEvent::Degrade) => Degrading,
            (Preparing, TransferEvent::Abort) => Aborted,
            (Preparing, TransferEvent::PeerLost) => Aborted,
            (Preparing, TransferEvent::ForceReset) => Idle,
            (Reconciling, TransferEvent::Reconciled) => Transferring,
            (Reconciling, TransferEvent::ReconcileFailed) => Degrading,
            (Reconciling, TransferEvent::Degrade) => Degrading,
            (Reconciling, TransferEvent::Abort) => Aborted,
            (Reconciling, TransferEvent::PeerLost) => Aborted,
            (Reconciling, TransferEvent::ForceReset) => Idle,
            (Transferring, TransferEvent::Progress) => Transferring,
            (Transferring, TransferEvent::HeartbeatTimeout) => Paused,
            (Transferring, TransferEvent::ChunkRetryExhausted) => Degrading,
            (Transferring, TransferEvent::BeginVerify) => Verifying,
            (Transferring, TransferEvent::Degrade) => Degrading,
            (Transferring, TransferEvent::Abort) => Aborted,
            (Transferring, TransferEvent::PeerLost) => Aborted,
            (Transferring, TransferEvent::ForceReset) => Idle,
            (Paused, TransferEvent::Retry) => Preparing,
            (Paused, TransferEvent::RetryExhausted) => Failed,
            (Paused, TransferEvent::Degrade) => Degrading,
            (Paused, TransferEvent::Abort) => Aborted,
            (Paused, TransferEvent::PeerLost) => Aborted,
            (Paused, TransferEvent::ForceReset) => Idle,
            (Degrading, TransferEvent::DegradeComplete) => Transferring,
            (Degrading, TransferEvent::Abort) => Aborted,
            (Degrading, TransferEvent::PeerLost) => Aborted,
            (Degrading, TransferEvent::ForceReset) => Idle,
            (Verifying, TransferEvent::VerifyOk) => Completed,
            (Verifying, TransferEvent::VerifyFailed) => Degrading,
            (Verifying, TransferEvent::Abort) => Aborted,
            (Verifying, TransferEvent::PeerLost) => Aborted,
            (Verifying, TransferEvent::ForceReset) => Idle,
            // 终态：Completed / Failed / Aborted 只接受 ForceReset
            (Completed, TransferEvent::ForceReset) => Idle,
            (Failed, TransferEvent::Retry) => Preparing, // 显式重试开启新尝试
            (Failed, TransferEvent::ForceReset) => Idle,
            (Aborted, TransferEvent::ForceReset) => Idle,
            // 其余所有 (state, event) 组合均非法
            _ => return Err(self.illegal(ev, "当前状态不允许该事件")),
        };
        Ok(next)
    }

    fn illegal(self, event: TransferEvent, reason: &'static str) -> IllegalTransition {
        IllegalTransition {
            from: self,
            event: event.name(),
            reason,
        }
    }

    /// 是否允许「中止」（V4-TRANSFER-MODULE §3.3）
    ///
    /// 只有**进行中**的状态可中止。四个「静止」状态都不可：
    /// `Idle` 没有传输，`Completed`/`Failed`/`Aborted` 都已结束
    /// —— 对已结束的任务再发中止毫无意义，只会让 UI 出现一个点了没反应的按钮。
    pub fn allows_abort(self) -> bool {
        matches!(
            self,
            TransferState::Preparing
                | TransferState::Reconciling
                | TransferState::Transferring
                | TransferState::Paused
                | TransferState::Degrading
                | TransferState::Verifying
        )
    }

    /// 是否允许「重试」（V4-TRANSFER-MODULE §3.3）
    ///
    /// `Completed` 排除在外：成功的传输没有「重试」的语义（§3.3 提示「传输已成功」）。
    /// `Aborted` 包含在内 —— 但注意它**不是**原地复活，见 [`Self::retry_events`]。
    pub fn allows_retry(self) -> bool {
        matches!(
            self,
            TransferState::Paused | TransferState::Failed | TransferState::Aborted
        )
    }

    /// 是否允许「开始传输」（V4-TRANSFER-MODULE §3.3）
    ///
    /// 除 `Idle` 外，三个终态也允许 —— 否则传完一次就再也开不了第二次。
    /// 同样不是原地重启，见 [`Self::start_events`]。
    pub fn allows_start(self) -> bool {
        matches!(
            self,
            TransferState::Idle
                | TransferState::Completed
                | TransferState::Failed
                | TransferState::Aborted
        )
    }

    /// 「重试」按钮实际要派发的事件序列（V4-TRANSFER-MODULE §3.2 语义表）。
    ///
    /// # 为什么不是单个事件
    ///
    /// 文档 §3.3 说 `aborted` 时「重试」可用，而 §2 说「终态单调，Aborted 不可回退」。
    /// 两者并不矛盾 —— 按钮可用指的是**新建一次会话**，而不是把旧会话拉回来。
    /// 差别落在事件序列上：`Aborted` 必须先 `ForceReset` 回 `Idle` 再 `Register`。
    ///
    /// 把这个映射放在状态机里而不是留给调用方，是因为调用方一旦猜错，
    /// 就会对 `Aborted` 直接发 `Retry`，拿到一个非法迁移错误 —— 表现为「点了没反应」，
    /// 正是本次重构要消灭的那类静默失败。
    pub fn retry_events(self) -> &'static [TransferEvent] {
        match self {
            // 重新对账（拉取权威位图）→ 从断点继续
            TransferState::Paused => &[TransferEvent::Retry],
            // 开启新尝试（状态机直接支持 Failed → Preparing）
            TransferState::Failed => &[TransferEvent::Retry],
            // 终态单调：必须新建会话
            TransferState::Aborted => &[TransferEvent::ForceReset, TransferEvent::Register],
            _ => &[],
        }
    }

    /// 「开始传输」按钮实际要派发的事件序列（同 [`Self::retry_events`] 的道理）。
    pub fn start_events(self) -> &'static [TransferEvent] {
        match self {
            TransferState::Idle => &[TransferEvent::Register],
            TransferState::Completed | TransferState::Failed | TransferState::Aborted => {
                &[TransferEvent::ForceReset, TransferEvent::Register]
            }
            _ => &[],
        }
    }

    /// 是否为终态（Completed/Failed/Aborted）
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TransferState::Completed | TransferState::Failed | TransferState::Aborted
        )
    }
}

impl TransferEvent {
    pub fn name(self) -> &'static str {
        match self {
            TransferEvent::Register => "Register",
            TransferEvent::NegotiateAdvanced => "NegotiateAdvanced",
            TransferEvent::NegotiateBasic => "NegotiateBasic",
            TransferEvent::Reconciled => "Reconciled",
            TransferEvent::ReconcileFailed => "ReconcileFailed",
            TransferEvent::Progress => "Progress",
            TransferEvent::HeartbeatTimeout => "HeartbeatTimeout",
            TransferEvent::ChunkRetryExhausted => "ChunkRetryExhausted",
            TransferEvent::Degrade => "Degrade",
            TransferEvent::DegradeComplete => "DegradeComplete",
            TransferEvent::BeginVerify => "BeginVerify",
            TransferEvent::VerifyOk => "VerifyOk",
            TransferEvent::VerifyFailed => "VerifyFailed",
            TransferEvent::Abort => "Abort",
            TransferEvent::PeerLost => "PeerLost",
            TransferEvent::Retry => "Retry",
            TransferEvent::RetryExhausted => "RetryExhausted",
            TransferEvent::ForceReset => "ForceReset",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_advanced_happy_path() {
        let s = TransferState::Idle;
        let s = s.transition(TransferEvent::Register).unwrap();
        assert_eq!(s, TransferState::Preparing);
        let s = s.transition(TransferEvent::NegotiateAdvanced).unwrap();
        assert_eq!(s, TransferState::Reconciling);
        let s = s.transition(TransferEvent::Reconciled).unwrap();
        assert_eq!(s, TransferState::Transferring);
        let s = s.transition(TransferEvent::Progress).unwrap();
        assert_eq!(s, TransferState::Transferring);
        let s = s.transition(TransferEvent::BeginVerify).unwrap();
        assert_eq!(s, TransferState::Verifying);
        let s = s.transition(TransferEvent::VerifyOk).unwrap();
        assert_eq!(s, TransferState::Completed);
        assert!(s.is_terminal());
    }

    #[test]
    fn basic_path_skips_reconcile() {
        let s = TransferState::Idle;
        let s = s.transition(TransferEvent::Register).unwrap();
        let s = s.transition(TransferEvent::NegotiateBasic).unwrap();
        assert_eq!(s, TransferState::Transferring);
    }

    #[test]
    fn heartbeat_timeout_to_paused_then_retry() {
        let s = TransferState::Transferring;
        let s = s.transition(TransferEvent::HeartbeatTimeout).unwrap();
        assert_eq!(s, TransferState::Paused);
        let s = s.transition(TransferEvent::Retry).unwrap();
        assert_eq!(s, TransferState::Preparing);
    }

    #[test]
    fn paused_retry_exhausted_to_failed() {
        let s = TransferState::Paused;
        let s = s.transition(TransferEvent::RetryExhausted).unwrap();
        assert_eq!(s, TransferState::Failed);
    }

    #[test]
    fn degrade_from_transferring() {
        let s = TransferState::Transferring;
        let s = s.transition(TransferEvent::ChunkRetryExhausted).unwrap();
        assert_eq!(s, TransferState::Degrading);
        let s = s.transition(TransferEvent::DegradeComplete).unwrap();
        assert_eq!(s, TransferState::Transferring);
    }

    #[test]
    fn verify_failed_triggers_degrade() {
        let s = TransferState::Verifying;
        let s = s.transition(TransferEvent::VerifyFailed).unwrap();
        assert_eq!(s, TransferState::Degrading);
    }

    #[test]
    fn peer_lost_aborts() {
        for s in [
            TransferState::Preparing,
            TransferState::Reconciling,
            TransferState::Transferring,
            TransferState::Paused,
            TransferState::Degrading,
            TransferState::Verifying,
        ] {
            assert_eq!(
                s.transition(TransferEvent::PeerLost).unwrap(),
                TransferState::Aborted
            );
        }
    }

    #[test]
    fn completed_is_terminal_no_retry() {
        let s = TransferState::Completed;
        assert!(!s.allows_retry());
        assert!(s.transition(TransferEvent::Retry).is_err());
        assert!(s.transition(TransferEvent::Abort).is_err());
        // 只有 ForceReset 能离开终态
        assert_eq!(
            s.transition(TransferEvent::ForceReset).unwrap(),
            TransferState::Idle
        );
    }

    #[test]
    fn failed_allows_explicit_retry() {
        let s = TransferState::Failed;
        assert!(s.allows_retry());
        assert_eq!(
            s.transition(TransferEvent::Retry).unwrap(),
            TransferState::Preparing
        );
    }

    /// 事件序列必须**真的能走通**。
    ///
    /// 光断言「Aborted 的重试序列是 [ForceReset, Register]」没有意义 ——
    /// 那只是复述了实现。真正要验的是把序列喂进状态机后能落到 Preparing。
    #[test]
    fn retry_event_sequences_are_actually_legal() {
        for src in [
            TransferState::Paused,
            TransferState::Failed,
            TransferState::Aborted,
        ] {
            assert!(src.allows_retry(), "{src:?} 应可重试");
            let evs = src.retry_events();
            assert!(!evs.is_empty(), "{src:?} 可重试却没有事件序列");

            let mut s = src;
            for ev in evs {
                s = s
                    .transition(*ev)
                    .unwrap_or_else(|e| panic!("{src:?} 的重试序列在 {ev:?} 处非法：{e:?}"));
            }
            assert_eq!(s, TransferState::Preparing, "{src:?} 重试后应到 Preparing");
        }
    }

    #[test]
    fn start_event_sequences_are_actually_legal() {
        for src in [
            TransferState::Idle,
            TransferState::Completed,
            TransferState::Failed,
            TransferState::Aborted,
        ] {
            assert!(src.allows_start(), "{src:?} 应可开始新传输");
            let mut s = src;
            for ev in src.start_events() {
                s = s
                    .transition(*ev)
                    .unwrap_or_else(|e| panic!("{src:?} 的开始序列在 {ev:?} 处非法：{e:?}"));
            }
            assert_eq!(s, TransferState::Preparing, "{src:?} 开始后应到 Preparing");
        }
    }

    /// 不可用的状态必须给出**空**序列，避免调用方拿到一个「看似可执行」的序列
    #[test]
    fn unavailable_actions_yield_empty_sequences() {
        for s in [
            TransferState::Preparing,
            TransferState::Reconciling,
            TransferState::Transferring,
            TransferState::Degrading,
            TransferState::Verifying,
        ] {
            assert!(!s.allows_retry());
            assert!(s.retry_events().is_empty());
            assert!(!s.allows_start());
            assert!(s.start_events().is_empty());
        }
        // Completed 可开始新传输，但不可「重试」（已成功）
        assert!(TransferState::Completed.allows_start());
        assert!(!TransferState::Completed.allows_retry());
        assert!(TransferState::Completed.retry_events().is_empty());
        // Paused 可重试，但不可「开始新传输」（应先重试或中止）
        assert!(TransferState::Paused.allows_retry());
        assert!(!TransferState::Paused.allows_start());
        assert!(TransferState::Paused.start_events().is_empty());
    }

    /// §3.3：`failed` 不可中止（传输已结束），此前实现误判为可中止
    #[test]
    fn abort_excludes_all_settled_states() {
        for s in [
            TransferState::Idle,
            TransferState::Completed,
            TransferState::Failed,
            TransferState::Aborted,
        ] {
            assert!(!s.allows_abort(), "{s:?} 不应可中止");
        }
        for s in [
            TransferState::Preparing,
            TransferState::Reconciling,
            TransferState::Transferring,
            TransferState::Paused,
            TransferState::Degrading,
            TransferState::Verifying,
        ] {
            assert!(s.allows_abort(), "{s:?} 应可中止");
            // 可中止就必须真的能迁移到 Aborted
            assert_eq!(
                s.transition(TransferEvent::Abort).unwrap(),
                TransferState::Aborted
            );
        }
    }

    #[test]
    fn illegal_transitions_rejected() {
        // Idle 直接传块？非法
        assert!(TransferState::Idle
            .transition(TransferEvent::BeginVerify)
            .is_err());
        // Transferring 直接 Completed？非法（必须经 Verifying）
        assert!(TransferState::Transferring
            .transition(TransferEvent::VerifyOk)
            .is_err());
        // Aborted 不可重试
        assert!(TransferState::Aborted
            .transition(TransferEvent::Retry)
            .is_err());
    }
}
