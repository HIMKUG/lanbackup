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

    /// 是否允许「中止」
    pub fn allows_abort(self) -> bool {
        !matches!(self, TransferState::Idle | TransferState::Completed | TransferState::Aborted)
    }

    /// 是否允许「重试」
    pub fn allows_retry(self) -> bool {
        matches!(self, TransferState::Paused | TransferState::Failed)
    }

    /// 是否为终态（Completed/Failed/Aborted）
    pub fn is_terminal(self) -> bool {
        matches!(self, TransferState::Completed | TransferState::Failed | TransferState::Aborted)
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
            assert_eq!(s.transition(TransferEvent::PeerLost).unwrap(), TransferState::Aborted);
        }
    }

    #[test]
    fn completed_is_terminal_no_retry() {
        let s = TransferState::Completed;
        assert!(!s.allows_retry());
        assert!(s.transition(TransferEvent::Retry).is_err());
        assert!(s.transition(TransferEvent::Abort).is_err());
        // 只有 ForceReset 能离开终态
        assert_eq!(s.transition(TransferEvent::ForceReset).unwrap(), TransferState::Idle);
    }

    #[test]
    fn failed_allows_explicit_retry() {
        let s = TransferState::Failed;
        assert!(s.allows_retry());
        assert_eq!(s.transition(TransferEvent::Retry).unwrap(), TransferState::Preparing);
    }

    #[test]
    fn illegal_transitions_rejected() {
        // Idle 直接传块？非法
        assert!(TransferState::Idle.transition(TransferEvent::BeginVerify).is_err());
        // Transferring 直接 Completed？非法（必须经 Verifying）
        assert!(TransferState::Transferring.transition(TransferEvent::VerifyOk).is_err());
        // Aborted 不可重试
        assert!(TransferState::Aborted.transition(TransferEvent::Retry).is_err());
    }
}
