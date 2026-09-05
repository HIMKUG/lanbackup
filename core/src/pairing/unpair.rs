//! M31：解除配对通知的送达策略 ——「重试 3 次，仍失败切吊销兜底，兜底也失败则放弃」
//!
//! # 为什么要有这个模块
//!
//! 三代实测「解配对不彻底」有一条高频复现路径：发起方向对端发解除通知，
//! 对方恰好不可达（切网 / 进程被杀 / 短暂离线），通知一丢，发起方就此罢手 ——
//! 对端还留着配对记录，继续发 beacon、继续尝试连接，本机表现为
//! 「已解除的设备又出现了」。
//!
//! M31 的处方是**重试**：通知失败就再发，同一通道最多 3 次；3 次全失败
//! 再切到吊销兜底（`revoke-notify`，携带 24 小时吊销令牌 —— 对端上线后
//! 凭令牌也能收尾）；兜底也失败才放弃主动送达（此时信任状态停留在
//! `Revoking`，由对账兜底 [`crate::pairing::trust`] 的
//! `RevocationConfirmed` 收尾）。
//!
//! # 纯策略，不碰 socket
//!
//! 与 [`crate::transfer::session`] 同哲学：平台层（桌面 / 手机）负责真实的
//! HTTP 发送与签名构造，本模块只回答三个问题：
//!
//! 1. 下一步该发哪种通知（`unpair-request` 还是 `revoke-notify`）？
//! 2. 同一通道还剩几次尝试？
//! 3. 何时切换通道、何时放弃？
//!
//! 这样「重试 3 次」这条规则只有一份实现，双端不会各自漂移出一套重试次数。

use crate::routes::{REVOKE_NOTIFY, UNPAIR_REQUEST};

/// M31：同一通道（`unpair-request` 或 `revoke-notify`）的最大尝试次数。
///
/// 原实现 `App.vue:1596-1607` 对解除通知重试 3 次。
pub const UNPAIR_ATTEMPTS: u32 = 3;

/// 解除配对的两类通知通道。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnpairChannel {
    /// `POST /api/v4/unpair-request` —— 对端在线时的标准解除通知（带 ECDSA 签名）
    Request,
    /// `POST /api/v4/revoke-notify` —— 对端离线的吊销兜底（带吊销令牌 + 签名）
    RevokeNotify,
}

impl UnpairChannel {
    /// 该通道对应的端点路径（单一来源，锁死 [`crate::routes`]）。
    pub const fn path(self) -> &'static str {
        match self {
            UnpairChannel::Request => UNPAIR_REQUEST,
            UnpairChannel::RevokeNotify => REVOKE_NOTIFY,
        }
    }
}

/// 一次发送的送达结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// 送达（HTTP 2xx）
    Delivered,
    /// 未送达（网络错误 / 超时 / 4xx / 5xx）
    Failed,
}

/// 喂入一次送达结果后的下一步指示。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnpairStep {
    /// 本次送达成功。`channel` 是送达的那条通道，`attempt` 从 1 起计数
    Delivered { channel: UnpairChannel, attempt: u32 },
    /// 本次失败，同一通道仍有重试次数，继续发
    Retry { channel: UnpairChannel, attempt: u32 },
    /// `unpair-request` 重试耗尽，切换到 `revoke-notify` 兜底（重新计数）
    FellBackToRevoke { after_attempts: u32 },
    /// 兜底通道也失败耗尽，放弃主动送达（交给对账兜底）
    GiveUp,
}

/// 解除配对通知的重试策略（M31）。
///
/// 调用契约（与 [`crate::transfer::session::SessionDriver`] 的
/// `next_step` / `feed` 同构）：
/// - 循环读 [`Self::next`]；`Some` 就发对应通道，把结果喂给 [`Self::feed`]；
/// - `feed` 返回 `Retry` 则继续发**同一**通道（次数已递减）；
/// - `feed` 返回 `FellBackToRevoke` 则改用 `revoke-notify` 重开计数；
/// - [`Self::next`] 返回 `None` 表示流程已结束（送达或放弃）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnpairRetry {
    channel: UnpairChannel,
    used: u32,
    settled: bool,
}

impl Default for UnpairRetry {
    fn default() -> Self {
        Self::new()
    }
}

impl UnpairRetry {
    pub fn new() -> Self {
        Self {
            channel: UnpairChannel::Request,
            used: 0,
            settled: false,
        }
    }

    /// 下一步该发哪种通知；`None` = 流程已结束（送达成功或已放弃）。
    pub fn next(&self) -> Option<UnpairChannel> {
        if self.settled {
            None
        } else {
            Some(self.channel)
        }
    }

    /// 当前通道剩余的尝试次数（不含刚结束的那一次）。
    pub fn attempts_left(&self) -> u32 {
        if self.settled {
            0
        } else {
            UNPAIR_ATTEMPTS - self.used
        }
    }

    /// 喂入一次发送结果，返回下一步该做什么。
    ///
    /// 流程结束后（`settled`）再喂结果是调用方 bug：`next` 已经返回 `None`，
    /// 此时不应再有任何发送动作。用 `debug_assert` 拦（release 下不产生
    /// 运行时开销 —— 违规调用只可能来自编程错误，不是外部输入）。
    pub fn feed(&mut self, delivery: Delivery) -> UnpairStep {
        debug_assert!(!self.settled, "解除流程已结束，不应再喂送达结果");
        let attempt = self.used + 1; // 1 起计数，与 `next` 的通道状态一致
        match delivery {
            Delivery::Delivered => {
                self.settled = true;
                UnpairStep::Delivered {
                    channel: self.channel,
                    attempt,
                }
            }
            Delivery::Failed => {
                self.used = attempt;
                if self.used < UNPAIR_ATTEMPTS {
                    UnpairStep::Retry {
                        channel: self.channel,
                        attempt,
                    }
                } else {
                    match self.channel {
                        UnpairChannel::Request => {
                            // 重试耗尽 → 切吊销兜底，重开计数
                            self.channel = UnpairChannel::RevokeNotify;
                            self.used = 0;
                            UnpairStep::FellBackToRevoke {
                                after_attempts: UNPAIR_ATTEMPTS,
                            }
                        }
                        UnpairChannel::RevokeNotify => {
                            // 兜底也耗尽 → 放弃主动送达
                            self.settled = true;
                            UnpairStep::GiveUp
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::{REVOKE_NOTIFY, UNPAIR_REQUEST};

    #[test]
    fn first_attempt_delivery_succeeds_immediately() {
        let mut r = UnpairRetry::new();
        assert_eq!(r.next(), Some(UnpairChannel::Request));
        assert_eq!(r.attempts_left(), 3);
        assert_eq!(
            r.feed(Delivery::Delivered),
            UnpairStep::Delivered {
                channel: UnpairChannel::Request,
                attempt: 1
            }
        );
        // 送达后流程结束
        assert_eq!(r.next(), None);
        assert_eq!(r.attempts_left(), 0);
    }

    #[test]
    fn transient_failure_retries_same_channel_then_delivers() {
        let mut r = UnpairRetry::new();
        assert_eq!(
            r.feed(Delivery::Failed),
            UnpairStep::Retry {
                channel: UnpairChannel::Request,
                attempt: 1
            }
        );
        assert_eq!(r.attempts_left(), 2);
        assert_eq!(r.next(), Some(UnpairChannel::Request), "重试仍走同一通道");
        assert_eq!(
            r.feed(Delivery::Delivered),
            UnpairStep::Delivered {
                channel: UnpairChannel::Request,
                attempt: 2
            }
        );
        assert_eq!(r.next(), None);
    }

    #[test]
    fn request_exhausted_falls_back_to_revoke_notify() {
        let mut r = UnpairRetry::new();
        // 前两次失败 → 继续同一通道
        assert!(matches!(r.feed(Delivery::Failed), UnpairStep::Retry { attempt: 1, .. }));
        assert!(matches!(r.feed(Delivery::Failed), UnpairStep::Retry { attempt: 2, .. }));
        assert_eq!(
            r.feed(Delivery::Failed),
            UnpairStep::FellBackToRevoke {
                after_attempts: UNPAIR_ATTEMPTS
            }
        );
        // 已切到吊销兜底，重新计数
        assert_eq!(r.next(), Some(UnpairChannel::RevokeNotify));
        assert_eq!(r.attempts_left(), 3);
    }

    #[test]
    fn revoke_notify_delivery_ends_the_flow() {
        let mut r = UnpairRetry::new();
        // 耗尽 unpair-request 后兜底一次成功
        r.feed(Delivery::Failed);
        r.feed(Delivery::Failed);
        r.feed(Delivery::Failed);
        assert_eq!(
            r.feed(Delivery::Delivered),
            UnpairStep::Delivered {
                channel: UnpairChannel::RevokeNotify,
                attempt: 1
            }
        );
        assert_eq!(r.next(), None);
    }

    #[test]
    fn revoke_notify_exhaustion_gives_up() {
        let mut r = UnpairRetry::new();
        for _ in 0..UNPAIR_ATTEMPTS {
            r.feed(Delivery::Failed);
        }
        assert!(matches!(r.feed(Delivery::Failed), UnpairStep::Retry { attempt: 1, .. }));
        assert!(matches!(r.feed(Delivery::Failed), UnpairStep::Retry { attempt: 2, .. }));
        assert_eq!(r.feed(Delivery::Failed), UnpairStep::GiveUp);
        assert_eq!(r.next(), None, "放弃后不得再发任何通知");
        assert_eq!(r.attempts_left(), 0);
    }

    #[test]
    fn a_mid_flow_success_cancels_remaining_attempts() {
        // 对端在第 2 次重试时恢复在线 → 送达即收尾，绝不超发
        let mut r = UnpairRetry::new();
        r.feed(Delivery::Failed);
        assert!(matches!(r.feed(Delivery::Delivered), UnpairStep::Delivered { attempt: 2, .. }));
        assert_eq!(r.next(), None);
    }

    #[test]
    fn channel_paths_match_the_route_table() {
        assert_eq!(UnpairChannel::Request.path(), UNPAIR_REQUEST);
        assert_eq!(UnpairChannel::RevokeNotify.path(), REVOKE_NOTIFY);
    }

    #[test]
    fn attempts_left_never_exceeds_the_limit() {
        let mut r = UnpairRetry::new();
        for _ in 0..UNPAIR_ATTEMPTS {
            assert!(r.attempts_left() <= UNPAIR_ATTEMPTS);
            r.feed(Delivery::Failed);
        }
        assert_eq!(r.attempts_left(), UNPAIR_ATTEMPTS, "切到兜底后重新计数");
        assert!(r.attempts_left() <= UNPAIR_ATTEMPTS);
    }
}
