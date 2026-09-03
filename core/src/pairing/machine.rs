//! 配对状态机（V4-ARCHITECTURE §3.3 / V4-TRANSFER-MODULE §状态机）
//!
//! # 全量流转表（唯一依据）
//!
//! | 当前 | 事件 | 目标 | 说明 |
//! |---|---|---|---|
//! | `None` | `Initiate` | `Pending` | 用户点"配对"，已发出请求 |
//! | `Pending` | `PeerConfirmed` | `Active` | 对端验签通过 |
//! | `Pending` | `PeerRejected` | `None` | 连接码错 / 用户在对端点了拒绝 |
//! | `Pending` | `PendingTimeout` | `None` | 对端没响应，回到未配对 |
//! | `Active` | `LocalUnpair` | `Revoking` | 本机发起解除，等对端 ack |
//! | `Active` | `PeerUnpair` | `Revoked` | 对端已解除并通知到了，无需等待 |
//! | `Active` | `ReconcileDenied` | `Revoking` | 对账发现对端不认我了 |
//! | `Revoking` | `RevokeAcked` | `Revoked` | 对端确认解除 |
//! | `Revoking` | `PeerUnpair` | `Revoked` | 双方同时解除，正常收敛 |
//! | `Revoking` | `RevokeTimeout` | `Revoked` | 对端长期离线，本机单方面收尾 |
//! | `Revoked` | `Repair` | `None` | **显式**重新配对，开启新的生命周期 |
//!
//! 其余组合全部非法，返回 [`IllegalTransition`] 并带可读原因 —— 不静默忽略。
//! 「静默忽略非法事件」是 V3 状态不一致的主要来源：一个被吞掉的事件让双端
//! 从此对"当前是什么状态"产生分歧，之后每个决策都错。
//!
//! # 三处刻意的设计
//!
//! **`Active + PeerUnpair` 直达 `Revoked`，不经 `Revoking`。**
//! `Revoking` 的语义是"我在等对端确认"。对端主动通知我解除，说明它已经解了，
//! 没有可等的对象。多走一步 `Revoking` 只会让本机卡在那儿等一个永不到来的 ack。
//!
//! **`Revoking + RevokeTimeout → Revoked` 是必须的兜底。**
//! 没有它，对端一直不上线本机就永久停在 `Revoking`：既不能传输，也不能重新配对，
//! 用户看到的是"解配对卡住了，什么都干不了"。吊销令牌有 30 天有效期正是为此 ——
//! 本机先收尾，对端上线后用令牌补齐。这直接对应实测问题「解配对不彻底」。
//!
//! **`Revoked → None` 只能由 `Repair` 触发，不得靠超时或自动跳转。**
//! `Revoked` 是当次配对生命周期的终态。若允许自动回到 `None`，
//! 就会出现"刚解除的设备过一会儿自己又冒出来可以配对"，
//! 用户完全无法确认自己到底解没解掉。重新配对必须是一次显式的用户动作。

use crate::dto::handshake::PairingState;

/// 配对状态机的事件
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingEvent {
    /// 用户发起配对
    Initiate,
    /// 对端确认（验签通过）
    PeerConfirmed,
    /// 对端拒绝（连接码错误 / 用户拒绝）
    PeerRejected,
    /// 等待对端确认超时
    PendingTimeout,
    /// 本机发起解配对
    LocalUnpair,
    /// 收到对端的解配对通知
    PeerUnpair,
    /// 双向对账发现对端已不认本机
    ReconcileDenied,
    /// 对端确认了本机的解除请求
    RevokeAcked,
    /// 等待对端 ack 超时（对端长期离线）
    RevokeTimeout,
    /// 用户显式发起重新配对
    Repair,
}

/// 非法流转。带可读原因，直接可以呈现给用户或写进日志。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("配对状态机非法流转：{from:?} + {event:?} —— {reason}")]
pub struct IllegalTransition {
    pub from: PairingState,
    pub event: PairingEvent,
    pub reason: &'static str,
}

/// 唯一的流转函数。**所有**配对状态变更必须经过它。
pub fn transition(
    from: PairingState,
    event: PairingEvent,
) -> Result<PairingState, IllegalTransition> {
    use PairingEvent as E;
    use PairingState as S;

    let to = match (from, event) {
        (S::None, E::Initiate) => S::Pending,

        (S::Pending, E::PeerConfirmed) => S::Active,
        (S::Pending, E::PeerRejected) | (S::Pending, E::PendingTimeout) => S::None,

        (S::Active, E::LocalUnpair) | (S::Active, E::ReconcileDenied) => S::Revoking,
        (S::Active, E::PeerUnpair) => S::Revoked,

        (S::Revoking, E::RevokeAcked)
        | (S::Revoking, E::PeerUnpair)
        | (S::Revoking, E::RevokeTimeout) => S::Revoked,

        (S::Revoked, E::Repair) => S::None,

        // ── 以下是"看着像该支持、实际必须拒绝"的组合，逐个给出原因 ──
        (S::None, E::PeerConfirmed) => {
            return Err(illegal(
                from,
                event,
                "未发起配对却收到确认：可能是对端重放旧响应",
            ))
        }
        (S::None, E::LocalUnpair) | (S::None, E::PeerUnpair) => {
            return Err(illegal(from, event, "本就未配对，无可解除"))
        }
        (S::Pending, E::Initiate) => {
            return Err(illegal(
                from,
                event,
                "已在等待对端确认，重复发起会产生两个 requestId、双端认知分叉",
            ))
        }
        (S::Active, E::Initiate) => {
            return Err(illegal(
                from,
                event,
                "已配对；如需换连接码请先解除再重新配对",
            ))
        }
        (S::Revoking, E::Initiate) | (S::Revoking, E::PeerConfirmed) => {
            return Err(illegal(
                from,
                event,
                "解除尚未收尾，此时重新配对会让双端一半认一半不认",
            ))
        }
        (S::Revoked, E::PeerConfirmed) | (S::Revoked, E::Initiate) => {
            return Err(illegal(
                from,
                event,
                "已解除；重新配对必须由用户显式触发 Repair，不得自动复活",
            ))
        }
        _ => return Err(illegal(from, event, "该状态不接受此事件")),
    };
    Ok(to)
}

fn illegal(from: PairingState, event: PairingEvent, reason: &'static str) -> IllegalTransition {
    IllegalTransition {
        from,
        event,
        reason,
    }
}

/// 是否为当次配对生命周期的终态
pub fn is_terminal(state: PairingState) -> bool {
    matches!(state, PairingState::Revoked)
}

/// 该状态下是否允许发起传输。
///
/// **只有 `Active`**。`Revoking` 明确排除：解除已经开始，再放新任务进去
/// 只会产出一个注定被中断的传输，用户体验比直接拒绝更差。
pub fn allows_transfer(state: PairingState) -> bool {
    matches!(state, PairingState::Active)
}

/// 该状态下是否应继续发送 presence beacon。
///
/// 解除流程中仍要发：对端需要看到我在线才能完成 ack，
/// 否则解配对只能等 30 天的令牌兜底。
pub fn should_emit_beacon(state: PairingState) -> bool {
    matches!(
        state,
        PairingState::Active | PairingState::Pending | PairingState::Revoking
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use PairingEvent as E;
    use PairingState as S;

    /// 文档流转表逐行落测（E10：文档里的表格必须有测试）
    #[test]
    fn documented_transitions_hold() {
        let table = [
            (S::None, E::Initiate, S::Pending),
            (S::Pending, E::PeerConfirmed, S::Active),
            (S::Pending, E::PeerRejected, S::None),
            (S::Pending, E::PendingTimeout, S::None),
            (S::Active, E::LocalUnpair, S::Revoking),
            (S::Active, E::PeerUnpair, S::Revoked),
            (S::Active, E::ReconcileDenied, S::Revoking),
            (S::Revoking, E::RevokeAcked, S::Revoked),
            (S::Revoking, E::PeerUnpair, S::Revoked),
            (S::Revoking, E::RevokeTimeout, S::Revoked),
            (S::Revoked, E::Repair, S::None),
        ];
        for (from, event, want) in table {
            assert_eq!(
                transition(from, event),
                Ok(want),
                "{from:?} + {event:?} 应到 {want:?}"
            );
        }
    }

    /// 流转表之外的组合**全部**必须被拒且带可读原因。
    /// 穷举而非抽查：漏掉一格就是一个能被静默吞掉的事件。
    #[test]
    fn everything_outside_the_table_is_rejected_with_a_reason() {
        let states = [S::None, S::Pending, S::Active, S::Revoking, S::Revoked];
        let events = [
            E::Initiate,
            E::PeerConfirmed,
            E::PeerRejected,
            E::PendingTimeout,
            E::LocalUnpair,
            E::PeerUnpair,
            E::ReconcileDenied,
            E::RevokeAcked,
            E::RevokeTimeout,
            E::Repair,
        ];
        let legal = [
            (S::None, E::Initiate),
            (S::Pending, E::PeerConfirmed),
            (S::Pending, E::PeerRejected),
            (S::Pending, E::PendingTimeout),
            (S::Active, E::LocalUnpair),
            (S::Active, E::PeerUnpair),
            (S::Active, E::ReconcileDenied),
            (S::Revoking, E::RevokeAcked),
            (S::Revoking, E::PeerUnpair),
            (S::Revoking, E::RevokeTimeout),
            (S::Revoked, E::Repair),
        ];
        for from in states {
            for event in events {
                if legal.contains(&(from, event)) {
                    continue;
                }
                let err = transition(from, event)
                    .expect_err(&format!("{from:?} + {event:?} 不在表内却被放行"));
                assert!(
                    !err.reason.is_empty(),
                    "{from:?} + {event:?} 的拒绝原因为空，用户看不懂"
                );
                assert_eq!(err.from, from);
                assert_eq!(err.event, event);
            }
        }
    }

    /// 「解配对不彻底」的直接回归：对端离线也必须能收尾。
    #[test]
    fn unpair_completes_even_if_peer_never_answers() {
        let s = transition(S::Active, E::LocalUnpair).unwrap();
        assert_eq!(s, S::Revoking);
        let s = transition(s, E::RevokeTimeout).unwrap();
        assert_eq!(
            s,
            S::Revoked,
            "对端不上线就永久卡在 Revoking = 什么都干不了"
        );
        assert!(is_terminal(s));
    }

    /// 解除后不得自动复活 —— 用户必须能确认"确实解掉了"。
    #[test]
    fn revoked_never_self_resurrects() {
        for e in [
            E::PeerConfirmed,
            E::Initiate,
            E::PendingTimeout,
            E::RevokeTimeout,
        ] {
            assert!(
                transition(S::Revoked, e).is_err(),
                "{e:?} 让已解除的配对自己回来了"
            );
        }
        assert_eq!(transition(S::Revoked, E::Repair), Ok(S::None));
    }

    /// 对端主动通知解除时不该再等 ack
    #[test]
    fn peer_initiated_unpair_skips_revoking() {
        assert_eq!(transition(S::Active, E::PeerUnpair), Ok(S::Revoked));
    }

    /// 对账说"我不认你了" → 本机必须跟着进入解除流程，不能单方面维持 Active。
    /// 这是实测问题「一方解除后另一方仍显示已配对」的修复点。
    #[test]
    fn reconcile_denial_drives_local_revocation() {
        assert_eq!(transition(S::Active, E::ReconcileDenied), Ok(S::Revoking));
    }

    #[test]
    fn duplicate_initiate_is_rejected_to_avoid_two_request_ids() {
        let err = transition(S::Pending, E::Initiate).unwrap_err();
        assert!(err.reason.contains("requestId"));
    }

    #[test]
    fn only_active_allows_transfer() {
        assert!(allows_transfer(S::Active));
        for s in [S::None, S::Pending, S::Revoking, S::Revoked] {
            assert!(!allows_transfer(s), "{s:?} 不应允许发起传输");
        }
    }

    #[test]
    fn beacon_continues_during_revocation() {
        assert!(
            should_emit_beacon(S::Revoking),
            "解除中停发 beacon 会让 ack 永远等不到"
        );
        assert!(should_emit_beacon(S::Active));
        assert!(should_emit_beacon(S::Pending));
        assert!(!should_emit_beacon(S::None));
        assert!(!should_emit_beacon(S::Revoked));
    }

    #[test]
    fn illegal_transition_message_is_human_readable() {
        let err = transition(S::None, E::LocalUnpair).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("None"), "{msg}");
        assert!(msg.contains("无可解除"), "{msg}");
    }

    /// 完整生命周期走一遍：配对 → 用 → 解除 → 重新配对
    #[test]
    fn full_lifecycle_round_trip() {
        let mut s = S::None;
        for e in [
            E::Initiate,
            E::PeerConfirmed,
            E::LocalUnpair,
            E::RevokeAcked,
            E::Repair,
            E::Initiate,
            E::PeerConfirmed,
        ] {
            s = transition(s, e).unwrap_or_else(|err| panic!("{err}"));
        }
        assert_eq!(s, S::Active);
    }
}
