//! M32：取消收件的「两步走」编排 —— 本地停止无条件先行，通知对端是独立第二步
//!
//! # 问题
//!
//! 旧的取消收件实现把「本地停止」和「通知对端」揉在一步里：
//! 通知先发，本地等服务停完才动 —— 结果通知失败时本地也没停，
//! 用户看到的是「取消失败，还在收」；或者反过来，本地停了但通知丢了，
//! 对端继续发，本机表现为「取消了对方还在传」。
//!
//! # 两步走的顺序为什么不能换
//!
//! ① **本地停止必须无条件先行**：取消是用户不可撤回的意图，先让本机
//! 停止一切收发动作（传输状态机 `Abort` → `Aborted`，见
//! [`crate::state::transfer::TransferState`]），后续通知成败都不影响
//! 这一步已经达成的结果。
//!
//! ② **通知对端是独立第二步**：失败不回滚①，也不阻塞重试 ——
//! 对端没收到通知最多是多传几块，靠会话闲置巡检 / 心跳超时收尾，
//! 不会造成本机继续收件。
//!
//! # 四种成败组合，各有独立文案
//!
//! 两步各有一个布尔结果，乘积就是四种结局。用户看到的一定是
//! 与事实一一对应的文案（E10：不靠平台层再写一份 match 翻译）。
//!
//! # 纯策略，不碰 IO
//!
//! 与 [`crate::transfer::session`] 同哲学：本地停止的落地是传输状态机
//! 的 `Abort` 迁移（服务端 abort 处理器已实现），通知对端是平台层的
//! HTTP 调用；本模块只负责顺序、四态组合与文案 —— 于是「取消收件」
//! 这条只在用户点按钮时才走到的路径也能被纯同步断言覆盖。

/// 取消收件的两个步骤。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelStep {
    /// ① 本地停止（无条件先行）
    LocalStop,
    /// ② 通知对端（独立第二步）
    NotifyPeer,
}

/// 一步的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepResult {
    Ok,
    Failed,
}

/// 取消收件的四种结局（M32：各有独立文案）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelOutcome {
    /// 本地停止成功 + 通知成功
    BothOk,
    /// 本地停止成功 + 通知失败（本地不受影响）
    LocalOkNotifyFailed,
    /// 本地停止失败 + 通知成功
    LocalFailedNotifyOk,
    /// 本地停止失败 + 通知失败
    BothFailed,
}

impl CancelOutcome {
    /// 直接可展示的中文文案（原实现 `App.vue:2150-2192` 的四段文案语义）。
    pub fn copy(self) -> &'static str {
        match self {
            CancelOutcome::BothOk => "已停止接收，并已通知对方",
            CancelOutcome::LocalOkNotifyFailed => "已停止接收；通知对方失败（不影响本地停止）",
            CancelOutcome::LocalFailedNotifyOk => "本地停止失败，但已通知对方",
            CancelOutcome::BothFailed => "本地停止失败，且通知对方失败",
        }
    }
}

/// 取消收件的两步编排器（M32）。
///
/// 顺序契约由 [`Self::next`] 强制：未上报 `LocalStop` 结果前，
/// `next` 永远返回 `LocalStop`；只有第一步有结果后才轮到 `NotifyPeer`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelTwoStep {
    local: Option<StepResult>,
    notify: Option<StepResult>,
}

impl Default for CancelTwoStep {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelTwoStep {
    pub fn new() -> Self {
        Self {
            local: None,
            notify: None,
        }
    }

    /// 下一步该执行哪一步；`None` = 两步均已上报，可以读结局。
    ///
    /// 第一步永远是 `LocalStop` —— 无条件先行，即使本地停止失败
    /// （会话已终态 / 不存在）也**继续**走第二步：通知对端让双方认知
    /// 收敛，是独立于本地停止是否成功的动作。
    pub fn next(&self) -> Option<CancelStep> {
        match (self.local, self.notify) {
            (None, _) => Some(CancelStep::LocalStop),
            (Some(_), None) => Some(CancelStep::NotifyPeer),
            (Some(_), Some(_)) => None,
        }
    }

    /// 喂入一步的结果。返回 `Some` 表示两步都已上报、流程结束；
    /// `None` 表示还有下一步。乱序上报（先喂 `NotifyPeer`）会被拒绝
    /// —— 该顺序由 [`Self::next`] 保证，正常调用不会发生。
    pub fn feed(&mut self, step: CancelStep, result: StepResult) -> Option<CancelOutcome> {
        // 顺序由 next() 强制：只接受"当前该上报的那一步"，乱序上报直接拒绝
        // （否则先喂 NotifyPeer 会提前占用槽位，导致真正的 LocalStop 无处可去）。
        if self.next() != Some(step) {
            return None;
        }
        match step {
            CancelStep::LocalStop => self.local = Some(result),
            CancelStep::NotifyPeer => self.notify = Some(result),
        }
        match (self.local, self.notify) {
            (Some(l), Some(n)) => Some(match (l, n) {
                (StepResult::Ok, StepResult::Ok) => CancelOutcome::BothOk,
                (StepResult::Ok, StepResult::Failed) => CancelOutcome::LocalOkNotifyFailed,
                (StepResult::Failed, StepResult::Ok) => CancelOutcome::LocalFailedNotifyOk,
                (StepResult::Failed, StepResult::Failed) => CancelOutcome::BothFailed,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_step_is_always_local_stop() {
        let c = CancelTwoStep::new();
        assert_eq!(c.next(), Some(CancelStep::LocalStop));
    }

    #[test]
    fn local_failure_does_not_block_the_notify_step() {
        // M32 的核心：①本地停止失败，②仍要继续 —— 通知对端是独立动作
        let mut c = CancelTwoStep::new();
        assert!(c.feed(CancelStep::LocalStop, StepResult::Failed).is_none());
        assert_eq!(
            c.next(),
            Some(CancelStep::NotifyPeer),
            "本地停止失败也必须继续通知对端"
        );
    }

    #[test]
    fn four_combinations_map_to_four_distinct_outcomes() {
        let cases = [
            (StepResult::Ok, StepResult::Ok, CancelOutcome::BothOk),
            (
                StepResult::Ok,
                StepResult::Failed,
                CancelOutcome::LocalOkNotifyFailed,
            ),
            (
                StepResult::Failed,
                StepResult::Ok,
                CancelOutcome::LocalFailedNotifyOk,
            ),
            (
                StepResult::Failed,
                StepResult::Failed,
                CancelOutcome::BothFailed,
            ),
        ];
        for (local, notify, want) in cases {
            let mut c = CancelTwoStep::new();
            assert!(c.feed(CancelStep::LocalStop, local).is_none());
            assert_eq!(
                c.feed(CancelStep::NotifyPeer, notify),
                Some(want),
                "({local:?}, {notify:?}) 应映射到 {want:?}"
            );
        }
    }

    #[test]
    fn next_is_none_after_both_steps() {
        let mut c = CancelTwoStep::new();
        c.feed(CancelStep::LocalStop, StepResult::Ok);
        assert_eq!(c.next(), Some(CancelStep::NotifyPeer));
        c.feed(CancelStep::NotifyPeer, StepResult::Ok);
        assert_eq!(c.next(), None);
    }

    #[test]
    fn out_of_order_feed_is_rejected() {
        // 顺序由 next() 保证；乱序上报不污染状态（保持 None）
        let mut c = CancelTwoStep::new();
        assert!(c.feed(CancelStep::NotifyPeer, StepResult::Ok).is_none());
        assert_eq!(c.next(), Some(CancelStep::LocalStop), "乱序上报不应消耗步骤");
        c.feed(CancelStep::LocalStop, StepResult::Ok);
        assert_eq!(c.next(), Some(CancelStep::NotifyPeer), "第二步仍待执行");
    }

    #[test]
    fn copies_are_distinct_and_human_readable() {
        use std::collections::HashSet;
        let all = [
            CancelOutcome::BothOk,
            CancelOutcome::LocalOkNotifyFailed,
            CancelOutcome::LocalFailedNotifyOk,
            CancelOutcome::BothFailed,
        ];
        let set: HashSet<_> = all.iter().map(|o| o.copy()).collect();
        assert_eq!(set.len(), 4, "四种结局的文案必须各不相同");
        for o in all {
            let copy = o.copy();
            assert!(!copy.is_empty());
            assert!(
                copy.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
                "文案应为中文可读，实际：{copy}"
            );
        }
    }
}
