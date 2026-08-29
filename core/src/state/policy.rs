//! 交互裁决（唯一依据）
//!
//! V4-TRANSFER-MODULE.md 的核心要求：**每个按钮的启用与禁用完全由状态机推导，
//! 禁止在非法状态下响应点击；非法操作需给出可读提示而非静默失败。**
//!
//! 实现方式：单一函数 `can(action, ctx)` 同时供两层使用 ——
//! 1. UI 层：用 `enabled` 推导 `disabled` 绑定，`reason` 作为 `title`/tooltip；
//! 2. 运行时：点击 handler 再次调用 `can()`，不通过则把 `reason` 作为可读错误返回。
//!
//! 双保险，不存在「状态在点击瞬间变了」的竞态漏洞，也不存在静默失败。

use crate::dto::Presence;
use crate::state::connection::ConnectionState;
use crate::state::transfer::TransferState;

/// 六个受控动作（对应 UI 六个按钮）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiAction {
    Connect,
    Disconnect,
    StartTransfer,
    Abort,
    Retry,
    /// 重新启用主算法（清除设备级 preferBasic 记忆，下次会话生效）
    ReenableAdvanced,
}

/// 裁决所需的上下文快照（从三张状态机取当前值）
#[derive(Debug, Clone, Copy)]
pub struct UiContext {
    pub presence: Presence,
    pub connection: ConnectionState,
    pub transfer: TransferState,
    /// 当前会话是否已降级到基础算法
    pub degraded_now: bool,
    /// 降级原因是否为「对端无主算法能力」（稳定原因，不可重新启用主算法）
    pub degraded_due_to_peer_capability: bool,
}

/// 裁决结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub enabled: bool,
    /// 禁用时的可读提示；启用时也可给正向说明（UI 作 tooltip）
    pub reason: &'static str,
}

impl Verdict {
    fn allow(reason: &'static str) -> Self {
        Verdict { enabled: true, reason }
    }
    fn deny(reason: &'static str) -> Self {
        Verdict { enabled: false, reason }
    }
}

/// 单一裁决入口。
pub fn can(action: UiAction, ctx: &UiContext) -> Verdict {
    let online = matches!(ctx.presence, Presence::Online);

    match action {
        UiAction::Connect => {
            // 仅当对方在线且当前未处于任何连接态（含 failed/lost 走「重试」）
            if !online {
                return Verdict::deny("对方离线，无法连接");
            }
            match ctx.connection {
                ConnectionState::Disconnected => Verdict::allow("发起连接"),
                ConnectionState::Connecting => Verdict::deny("正在连接…"),
                ConnectionState::Connected => Verdict::deny("已连接"),
                ConnectionState::Disconnecting => Verdict::deny("正在断开…"),
                ConnectionState::Lost => Verdict::deny("连接已丢失，请重试"),
                ConnectionState::Failed => Verdict::deny("连接失败，请重试"),
            }
        }

        UiAction::Disconnect => match ctx.connection {
            ConnectionState::Connected | ConnectionState::Connecting => Verdict::allow("断开连接"),
            ConnectionState::Disconnecting => Verdict::deny("正在断开…"),
            _ => Verdict::deny("当前未连接"),
        },

        UiAction::StartTransfer => {
            // 仅当双方已连接（connected 蕴含 online）
            if ctx.connection != ConnectionState::Connected {
                return Verdict::deny("未连接，无法传输");
            }
            match ctx.transfer {
                TransferState::Idle => Verdict::allow("开始传输"),
                _ => Verdict::deny("传输进行中或已结束"),
            }
        }

        UiAction::Abort => {
            if ctx.transfer.allows_abort() {
                Verdict::allow("中止传输")
            } else {
                Verdict::deny("当前无可中止的传输")
            }
        }

        UiAction::Retry => {
            if ctx.transfer.allows_retry() {
                Verdict::allow("重试")
            } else {
                Verdict::deny("当前状态不可重试")
            }
        }

        UiAction::ReenableAdvanced => {
            // 仅在「环境性降级」且仍在线已连接时可清除 preferBasic
            if !ctx.degraded_now {
                return Verdict::deny("当前未降级");
            }
            if ctx.degraded_due_to_peer_capability {
                return Verdict::deny("对端不支持主算法，无法启用");
            }
            if ctx.connection != ConnectionState::Connected {
                return Verdict::deny("需保持连接才能重新启用");
            }
            Verdict::allow("重新启用主算法（下次会话生效）")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::connection::ConnectionState as C;
    use crate::state::transfer::TransferState as T;

    fn ctx(
        presence: Presence,
        conn: C,
        transfer: T,
        degraded_now: bool,
        degraded_cap: bool,
    ) -> UiContext {
        UiContext {
            presence,
            connection: conn,
            transfer,
            degraded_now,
            degraded_due_to_peer_capability: degraded_cap,
        }
    }

    #[test]
    fn connect_only_when_online_and_disconnected() {
        // 离线：禁用
        assert!(!can(
            UiAction::Connect,
            &ctx(Presence::Offline, C::Disconnected, T::Idle, false, false)
        )
        .enabled);
        // 在线 + 未连接：启用
        assert!(can(
            UiAction::Connect,
            &ctx(Presence::Online, C::Disconnected, T::Idle, false, false)
        )
        .enabled);
        // 在线 + 已连接：禁用（已连接）
        assert!(!can(
            UiAction::Connect,
            &ctx(Presence::Online, C::Connected, T::Idle, false, false)
        )
        .enabled);
        // 在线 + 连接中：禁用（正在连接）
        assert!(!can(
            UiAction::Connect,
            &ctx(Presence::Online, C::Connecting, T::Idle, false, false)
        )
        .enabled);
    }

    #[test]
    fn start_transfer_requires_connected() {
        assert!(can(
            UiAction::StartTransfer,
            &ctx(Presence::Online, C::Connected, T::Idle, false, false)
        )
        .enabled);
        // 未连接：禁用
        assert!(!can(
            UiAction::StartTransfer,
            &ctx(Presence::Online, C::Disconnected, T::Idle, false, false)
        )
        .enabled);
        // 传输进行中：禁用
        assert!(!can(
            UiAction::StartTransfer,
            &ctx(Presence::Online, C::Connected, T::Transferring, false, false)
        )
        .enabled);
    }

    #[test]
    fn abort_retry_gates() {
        // 传输中可中止
        assert!(can(
            UiAction::Abort,
            &ctx(Presence::Online, C::Connected, T::Transferring, false, false)
        )
        .enabled);
        // 空闲不可中止
        assert!(!can(
            UiAction::Abort,
            &ctx(Presence::Online, C::Connected, T::Idle, false, false)
        )
        .enabled);
        // Paused 可重试
        assert!(can(
            UiAction::Retry,
            &ctx(Presence::Online, C::Connected, T::Paused, false, false)
        )
        .enabled);
        // Idle 不可重试
        assert!(!can(
            UiAction::Retry,
            &ctx(Presence::Online, C::Connected, T::Idle, false, false)
        )
        .enabled);
    }

    #[test]
    fn reenable_advanced_gated_by_degrade_cause() {
        // 环境性降级（对端有能力）：可重新启用
        assert!(can(
            UiAction::ReenableAdvanced,
            &ctx(Presence::Online, C::Connected, T::Transferring, true, false)
        )
        .enabled);
        // 对端无能力降级：不可重新启用
        assert!(!can(
            UiAction::ReenableAdvanced,
            &ctx(Presence::Online, C::Connected, T::Transferring, true, true)
        )
        .enabled);
        // 未降级：禁用
        assert!(!can(
            UiAction::ReenableAdvanced,
            &ctx(Presence::Online, C::Connected, T::Transferring, false, false)
        )
        .enabled);
        // 降级但连接断开：禁用
        assert!(!can(
            UiAction::ReenableAdvanced,
            &ctx(Presence::Online, C::Disconnected, T::Transferring, true, false)
        )
        .enabled);
    }

    #[test]
    fn offline_disables_every_interaction_except_nothing() {
        // 离线时，连接/传输类动作全部禁用
        let base = ctx(Presence::Offline, C::Disconnected, T::Idle, false, false);
        assert!(!can(UiAction::Connect, &base).enabled);
        assert!(!can(UiAction::StartTransfer, &base).enabled);
        assert!(!can(UiAction::Disconnect, &base).enabled);
    }
}
