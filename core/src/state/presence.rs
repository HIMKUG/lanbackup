//! 在线性状态机（每设备一个实例）
//!
//! 由 UDP beacon 维护，**与「是否已配对」「是否已连接」完全正交**。
//! 三代并存的 bug 之一就是把在线性与连接态混为一谈，导致
//! 「对方离线却可以连接」。本状态机把在线性独立建模，连接态从它派生。
//!
//! TTL 规则（来自 V4-ARCHITECTURE.md §3.3-B，beacon 周期 500ms）：
//! - 收到 beacon → `Online`
//! - 距上次 beacon 超过 1500ms → `Stale`（弱信号，仍可显示但不可用）
//! - 距上次 beacon 超过 3000ms → `Offline`

use crate::dto::Presence;

/// 非法迁移错误（携带可读原因，供上层提示）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IllegalTransition {
    pub from: Presence,
    pub reason: &'static str,
}

/// 收到一次 beacon。直接回到 `Online`，并重置计时。
pub fn on_beacon(_state: Presence) -> Presence {
    Presence::Online
}

/// 距上次 beacon 经过 `elapsed_ms` 后的状态推导。
///
/// 纯函数、无副作用，便于测试与在任意线程调用（对照 DESIGN-WISDOM-REGISTER
/// D1「绝不在调用方线程 app.emit()」—— 这里只算状态，不碰 UI）。
pub fn tick(state: Presence, elapsed_ms: u64) -> Presence {
    match state {
        Presence::Unknown => Presence::Unknown, // 从未收到过 beacon
        Presence::Online => {
            if elapsed_ms >= 3000 {
                Presence::Offline
            } else if elapsed_ms >= 1500 {
                Presence::Stale
            } else {
                Presence::Online
            }
        }
        Presence::Stale => {
            if elapsed_ms >= 3000 {
                Presence::Offline
            } else {
                Presence::Stale
            }
        }
        Presence::Offline => Presence::Offline,
    }
}

/// 设备被遗忘 / 会话重置。
pub fn reset(_state: Presence) -> Presence {
    Presence::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_recovers_from_any() {
        for s in [Presence::Unknown, Presence::Stale, Presence::Offline] {
            assert_eq!(on_beacon(s), Presence::Online);
        }
    }

    #[test]
    fn online_decay_to_stale_then_offline() {
        assert_eq!(tick(Presence::Online, 0), Presence::Online);
        assert_eq!(tick(Presence::Online, 1499), Presence::Online);
        assert_eq!(tick(Presence::Online, 1500), Presence::Stale);
        assert_eq!(tick(Presence::Online, 2999), Presence::Stale);
        assert_eq!(tick(Presence::Online, 3000), Presence::Offline);
    }

    #[test]
    fn stale_never_returns_to_online_without_beacon() {
        // 没有 beacon 时，Stale 只能继续衰减到 Offline，不能自愈
        assert_eq!(tick(Presence::Stale, 0), Presence::Stale);
        assert_eq!(tick(Presence::Stale, 1000), Presence::Stale);
        assert_eq!(tick(Presence::Stale, 3000), Presence::Offline);
    }

    #[test]
    fn offline_is_sink_without_beacon() {
        assert_eq!(tick(Presence::Offline, 0), Presence::Offline);
        assert_eq!(tick(Presence::Offline, 99999), Presence::Offline);
    }

    #[test]
    fn unknown_stays_unknown() {
        assert_eq!(tick(Presence::Unknown, 99999), Presence::Unknown);
    }
}
