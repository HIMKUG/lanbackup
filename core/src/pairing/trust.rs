//! 双向信任对账（`GET /api/v4/sync/status`）
//!
//! # 问的不是"你在吗"，而是"你还认我吗"
//!
//! V3 的配对状态是**本机单方面记录**：我写了一行"已配对"，就一直认为配对着。
//! 于是实测出现这个现象 —— 一方解除配对，另一方弹出提示，
//! **自己却仍然显示已配对**，还能点"连接"，然后失败。
//!
//! V4 的规则只有一句：
//!
//! > **本机有效信任 = 本机记录 ∩ 对端确认**
//!
//! 交集里任一方缺失，有效信任就不成立。对账周期性执行，任一方说"不认"，
//! 本机立即跟进解除流程，不再单方面维持 `Active`。
//!
//! # 对账兼作 ack 的兜底通路
//!
//! `Revoking` 状态本来等的是 `revoke-ack` 那个 HTTP 响应。可它完全可能丢
//! （对端刚好切网、进程被杀）。如果只认那一条通路，本机就得干等到 30 天令牌超时。
//!
//! 但对账已经能给出等价结论：对端回答"我不认你了"，本质上就是 ack 的内容。
//! 因此 `Revoking` + 对端否认 ⇒ [`TrustVerdict::RevocationConfirmed`]，
//! 直接收尾。**同一个事实的两条独立通路**，任一条通即可，这才是让"解配对彻底"
//! 的关键。
//!
//! # `trust_version` 的作用
//!
//! 每次本机配对状态变更就 +1，随对账响应带给对端。对端据此判断
//! "我缓存的这份结论是不是过期了" —— 版本号前进但结论一致时，
//! 只需更新缓存，**不必**触发任何状态机事件。少了它，每轮对账都得
//! 把结论重新走一遍流程，日志里全是无意义的状态变更。

use crate::dto::handshake::{PairingState, SyncStatusResponse};
use crate::pairing::machine::{transition, IllegalTransition, PairingEvent};

/// 本机对某个对端的信任记录
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRecord {
    /// 本机记录的配对状态
    pub state: PairingState,
    /// 本机信任版本号，每次状态变更 +1
    pub trust_version: u64,
    /// 上次对账时记下的**对端**版本号
    pub peer_trust_version: u64,
}

impl Default for TrustRecord {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustRecord {
    pub fn new() -> Self {
        Self {
            state: PairingState::None,
            trust_version: 0,
            peer_trust_version: 0,
        }
    }

    /// 走一次状态机，并在成功时递增版本号。
    ///
    /// 版本号只在**状态真的变了**时递增。非法事件不改版本 ——
    /// 否则对端会看到版本号无故前进，误以为本机记录变了而反复重新对账。
    pub fn apply(&mut self, event: PairingEvent) -> Result<PairingState, IllegalTransition> {
        let next = transition(self.state, event)?;
        if next != self.state {
            self.state = next;
            self.trust_version = self.trust_version.saturating_add(1);
        }
        Ok(next)
    }

    /// 记下对端最新的版本号（对账后调用）
    pub fn note_peer_version(&mut self, peer_version: u64) {
        self.peer_trust_version = self.peer_trust_version.max(peer_version);
    }
}

/// 一次对账的结论
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustVerdict {
    /// 双方一致，无需动作
    Consistent { effective: PairingState },
    /// 本机认为已配对，**对端不认** → 必须跟进解除
    PeerDenies,
    /// 本机已不认，**对端还认** → 本机的解配对通知丢了，需重发
    ResendUnpair,
    /// 本机还在 `Pending`，对端已确认 → 落地为 `Active`
    PeerAhead,
    /// 本机在 `Revoking`，对端已不认 → 等价于收到 ack，直接收尾
    RevocationConfirmed,
    /// 结论一致但对端版本号前进了 → 只更新缓存，不触发状态机
    PeerAdvanced { peer_version: u64 },
}

impl TrustVerdict {
    /// 该结论应触发的状态机事件（`None` 表示无需变更状态）
    pub fn recommended_event(&self) -> Option<PairingEvent> {
        match self {
            Self::PeerDenies => Some(PairingEvent::ReconcileDenied),
            Self::PeerAhead => Some(PairingEvent::PeerConfirmed),
            Self::RevocationConfirmed => Some(PairingEvent::RevokeAcked),
            Self::Consistent { .. } | Self::ResendUnpair | Self::PeerAdvanced { .. } => None,
        }
    }

    /// 是否需要向用户告警（信任被单方面打破，属于需要解释的事件）
    pub fn needs_user_notice(&self) -> bool {
        matches!(self, Self::PeerDenies)
    }
}

/// 本机有效信任 = 本机记录 ∩ 对端确认。
///
/// `Active` 且对端否认 ⇒ 有效状态降为 `Revoking`（而不是硬说成 `Revoked`）：
/// 本机还需要走一遍清理流程（停传输、删会话、通知 UI），
/// 直接跳终态会把这些清理动作跳过去。
pub fn effective_state(local: PairingState, peer_confirms: bool) -> PairingState {
    match (local, peer_confirms) {
        (PairingState::Active, false) => PairingState::Revoking,
        (state, _) => state,
    }
}

/// 对端是否仍然认可本机。
///
/// **两个字段都要看**：只看 `youArePairedWithMe` 会漏掉"对端已进入 `Revoking`、
/// 但那一行记录还没改完"的中间态 —— 那一瞬间它会回答"还认你"，
/// 而实际上它正在解除。把 `status` 一并纳入，中间态就不会被误读成正常。
pub fn peer_still_trusts(peer: &SyncStatusResponse) -> bool {
    peer.you_are_paired_with_me && matches!(peer.status, PairingState::Active)
}

/// 对账。
pub fn reconcile(local: &TrustRecord, peer: &SyncStatusResponse) -> TrustVerdict {
    let trusts = peer_still_trusts(peer);
    match (local.state, trusts) {
        (PairingState::Active, true) => {
            if peer.my_trust_version > local.peer_trust_version {
                TrustVerdict::PeerAdvanced {
                    peer_version: peer.my_trust_version,
                }
            } else {
                TrustVerdict::Consistent {
                    effective: PairingState::Active,
                }
            }
        }
        (PairingState::Active, false) => TrustVerdict::PeerDenies,

        (PairingState::Pending, true) => TrustVerdict::PeerAhead,
        // 还在等对端确认，对端尚未认可属正常，不是冲突
        (PairingState::Pending, false) => TrustVerdict::Consistent {
            effective: PairingState::Pending,
        },

        // 等 ack 期间对端已不认 ⇒ ack 的实质内容达成
        (PairingState::Revoking, false) => TrustVerdict::RevocationConfirmed,
        (PairingState::Revoking, true) => TrustVerdict::Consistent {
            effective: PairingState::Revoking,
        },

        // 本机已不认，对端还认 ⇒ 我们的解除通知没送到，重发
        (PairingState::None, true) | (PairingState::Revoked, true) => TrustVerdict::ResendUnpair,
        (state, false) => TrustVerdict::Consistent { effective: state },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::Presence;

    fn peer(paired: bool, status: PairingState, version: u64) -> SyncStatusResponse {
        SyncStatusResponse {
            device_id: "peer-1".to_string(),
            you_are_paired_with_me: paired,
            my_trust_version: version,
            status,
            presence: Presence::Online,
        }
    }

    fn record(state: PairingState, peer_version: u64) -> TrustRecord {
        TrustRecord {
            state,
            trust_version: 1,
            peer_trust_version: peer_version,
        }
    }

    #[test]
    fn both_sides_agree_is_consistent() {
        let v = reconcile(
            &record(PairingState::Active, 5),
            &peer(true, PairingState::Active, 5),
        );
        assert_eq!(
            v,
            TrustVerdict::Consistent {
                effective: PairingState::Active
            }
        );
        assert_eq!(v.recommended_event(), None);
        assert!(!v.needs_user_notice());
    }

    /// 实测问题的直接回归：一方解除后，另一方**不得**继续显示已配对。
    #[test]
    fn peer_denial_breaks_local_active() {
        let v = reconcile(
            &record(PairingState::Active, 5),
            &peer(false, PairingState::Revoked, 6),
        );
        assert_eq!(v, TrustVerdict::PeerDenies);
        assert_eq!(v.recommended_event(), Some(PairingEvent::ReconcileDenied));
        assert!(
            v.needs_user_notice(),
            "信任被打破必须告知用户，不能静默降级"
        );
    }

    /// 对端「说还认我、但状态已是 Revoking」的中间态不得被读成正常。
    #[test]
    fn peer_mid_revocation_is_not_treated_as_trusting() {
        let p = peer(true, PairingState::Revoking, 7);
        assert!(
            !peer_still_trusts(&p),
            "只看 youArePairedWithMe 会漏掉这个中间态"
        );
        assert_eq!(
            reconcile(&record(PairingState::Active, 5), &p),
            TrustVerdict::PeerDenies
        );
    }

    /// 对账兼作 ack 兜底：revoke-ack 那个请求丢了也能收尾。
    #[test]
    fn reconcile_can_finish_a_stalled_revocation() {
        let v = reconcile(
            &record(PairingState::Revoking, 5),
            &peer(false, PairingState::Revoked, 9),
        );
        assert_eq!(v, TrustVerdict::RevocationConfirmed);
        assert_eq!(v.recommended_event(), Some(PairingEvent::RevokeAcked));

        // 把建议事件喂回状态机，应当真的收敛到终态
        let mut rec = record(PairingState::Revoking, 5);
        rec.apply(v.recommended_event().unwrap()).unwrap();
        assert_eq!(rec.state, PairingState::Revoked);
    }

    #[test]
    fn revoking_while_peer_still_trusts_keeps_waiting() {
        let v = reconcile(
            &record(PairingState::Revoking, 5),
            &peer(true, PairingState::Active, 5),
        );
        assert_eq!(
            v,
            TrustVerdict::Consistent {
                effective: PairingState::Revoking
            }
        );
    }

    #[test]
    fn peer_confirmed_first_is_picked_up_by_reconcile() {
        let v = reconcile(
            &record(PairingState::Pending, 0),
            &peer(true, PairingState::Active, 1),
        );
        assert_eq!(v, TrustVerdict::PeerAhead);
        assert_eq!(v.recommended_event(), Some(PairingEvent::PeerConfirmed));
    }

    #[test]
    fn pending_without_peer_confirmation_is_not_a_conflict() {
        let v = reconcile(
            &record(PairingState::Pending, 0),
            &peer(false, PairingState::Pending, 0),
        );
        assert_eq!(
            v,
            TrustVerdict::Consistent {
                effective: PairingState::Pending
            }
        );
        assert!(!v.needs_user_notice());
    }

    /// 本机已解除但对端还认 → 通知丢了，必须重发，否则对端永远挂着一个死配对。
    #[test]
    fn local_revoked_but_peer_still_trusts_triggers_resend() {
        for state in [PairingState::None, PairingState::Revoked] {
            let v = reconcile(&record(state, 0), &peer(true, PairingState::Active, 3));
            assert_eq!(v, TrustVerdict::ResendUnpair, "{state:?}");
            assert_eq!(v.recommended_event(), None, "重发是 IO 动作，不改本机状态");
        }
    }

    /// 版本号前进但结论一致时，只更新缓存，**不**触发状态机事件。
    #[test]
    fn peer_version_advance_does_not_churn_the_state_machine() {
        let mut rec = record(PairingState::Active, 5);
        let v = reconcile(&rec, &peer(true, PairingState::Active, 8));
        assert_eq!(v, TrustVerdict::PeerAdvanced { peer_version: 8 });
        assert_eq!(v.recommended_event(), None);

        rec.note_peer_version(8);
        assert_eq!(
            reconcile(&rec, &peer(true, PairingState::Active, 8)),
            TrustVerdict::Consistent {
                effective: PairingState::Active
            },
            "记下版本号后应回到一致，不该每轮都报一次前进"
        );
    }

    #[test]
    fn note_peer_version_never_goes_backwards() {
        let mut rec = TrustRecord::new();
        rec.note_peer_version(9);
        rec.note_peer_version(3); // 乱序响应
        assert_eq!(rec.peer_trust_version, 9);
    }

    #[test]
    fn effective_trust_is_the_intersection() {
        assert_eq!(
            effective_state(PairingState::Active, true),
            PairingState::Active
        );
        assert_eq!(
            effective_state(PairingState::Active, false),
            PairingState::Revoking,
            "对端否认时应降为 Revoking 以便走完清理，而不是直接跳终态"
        );
        // 本机本就不认，对端认不认都不改变本机结论
        assert_eq!(
            effective_state(PairingState::None, true),
            PairingState::None
        );
    }

    #[test]
    fn trust_version_increments_only_on_real_change() {
        let mut rec = TrustRecord::new();
        assert_eq!(rec.trust_version, 0);

        rec.apply(PairingEvent::Initiate).unwrap();
        assert_eq!((rec.state, rec.trust_version), (PairingState::Pending, 1));

        // 非法事件不得改版本号 —— 否则对端会误判本机记录变了
        assert!(rec.apply(PairingEvent::Initiate).is_err());
        assert_eq!(rec.trust_version, 1);

        rec.apply(PairingEvent::PeerConfirmed).unwrap();
        assert_eq!((rec.state, rec.trust_version), (PairingState::Active, 2));
    }

    /// 端到端：从 Active 出发，仅凭对账就能走完整个解除流程。
    #[test]
    fn full_revocation_via_reconcile_only() {
        let mut rec = record(PairingState::Active, 0);

        // 第一轮：发现对端不认
        let v1 = reconcile(&rec, &peer(false, PairingState::Revoked, 1));
        rec.apply(v1.recommended_event().unwrap()).unwrap();
        assert_eq!(rec.state, PairingState::Revoking);

        // 第二轮：确认收尾
        let v2 = reconcile(&rec, &peer(false, PairingState::Revoked, 1));
        rec.apply(v2.recommended_event().unwrap()).unwrap();
        assert_eq!(rec.state, PairingState::Revoked);

        // 之后再对账应稳定，不再产生任何事件（收敛性）
        let v3 = reconcile(&rec, &peer(false, PairingState::Revoked, 1));
        assert_eq!(v3.recommended_event(), None);
    }
}
