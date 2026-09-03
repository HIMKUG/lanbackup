//! 交互裁决（唯一依据）
//!
//! V4-TRANSFER-MODULE.md 的核心要求：**每个按钮的启用与禁用完全由状态机推导，
//! 禁止在非法状态下响应点击；非法操作需给出可读提示而非静默失败。**
//!
//! 实现方式：单一函数 [`can`] 同时供两层使用 ——
//! 1. UI 层：用 `enabled` 推导 `disabled` 绑定，`reason` 作为 `title`/tooltip；
//! 2. 运行时：点击 handler 再次调用 [`can`]，不通过则把 `reason` 作为可读错误返回。
//!
//! 双保险，不存在「状态在点击瞬间变了」的竞态漏洞，也不存在静默失败。
//!
//! # 本文件是 §3.2 / §3.3 / §3.4 三张表的**可执行副本**
//!
//! 文件末尾的表驱动测试逐行断言文档表格。改动此处的裁决逻辑而不同步改文档
//! （或反之），测试就会失败 —— 这是防止「文档写一套、代码跑另一套」的唯一手段。

use crate::dto::Presence;
use crate::state::connection::ConnectionState;
use crate::state::transfer::TransferState;

/// 六个受控动作（对应 UI 六个按钮，V4-TRANSFER-MODULE §3.1）
///
/// serde 是为了让 [`crate::ffi`] 的 `policy.can` 能被移动端问到 ——
/// **UI 不得自己判断按钮能不能点**，一律跨 FFI 问这里。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UiAction {
    /// 每设备：建立 V4 握手
    Connect,
    /// 每设备：主动断开
    Disconnect,
    /// 每设备：新建会话并开始传输
    StartTransfer,
    /// 每会话：终止进行中的传输
    Abort,
    /// 每会话：从 failed / paused / aborted 恢复
    Retry,
    /// 每设备：清除设备级 `preferBasic` 记忆，下次会话重新尝试主算法
    ReenableAdvanced,
}

/// 裁决所需的上下文快照（从三张状态机 + 设备级降级记忆取当前值）
/// `camelCase` 与协议层其余 DTO 一致（`generatedAt` / `deviceCode` / `preferBasic`）。
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiContext {
    pub presence: Presence,
    pub connection: ConnectionState,
    pub transfer: TransferState,
    /// 设备级降级记忆是否生效（连续 3 次非「对端无能力」的主算法失败后置位）。
    ///
    /// 这是「重新启用主算法」按钮的**唯一**依据（§3.4）。
    /// 注意不是「本次会话是否已降级」—— 会话内降级是常态，
    /// 而该按钮要清除的是跨会话的持久记忆；两者混淆会让按钮在错误的时机出现。
    pub prefer_basic: bool,
}

/// 裁决结果
/// 只 `Serialize` 不 `Deserialize`：`reason` 是 `&'static str`，
/// 反序列化需要借用一个调用方给不出保证的生命周期，而它本来也只用于出参。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Verdict {
    pub enabled: bool,
    /// 禁用时的可读提示；启用时也可给正向说明（UI 作 tooltip）
    pub reason: &'static str,
}

impl Verdict {
    fn allow(reason: &'static str) -> Self {
        Verdict {
            enabled: true,
            reason,
        }
    }
    fn deny(reason: &'static str) -> Self {
        Verdict {
            enabled: false,
            reason,
        }
    }
}

/// 单一裁决入口。
pub fn can(action: UiAction, ctx: &UiContext) -> Verdict {
    match action {
        UiAction::Connect => can_connect(ctx),
        UiAction::Disconnect => can_disconnect(ctx),
        UiAction::StartTransfer => can_start_transfer(ctx),
        UiAction::Abort => can_abort(ctx),
        UiAction::Retry => can_retry(ctx),
        UiAction::ReenableAdvanced => can_reenable_advanced(ctx),
    }
}

/// §3.2 连接
fn can_connect(ctx: &UiContext) -> Verdict {
    // 在线性是连接的前置门控。三种「非在线」各有专属话术 ——
    // 把 unknown / stale 一律说成「对方离线」是误导：
    // 前者是本端还没确认，后者是信号不稳仍在重试，用户的应对完全不同。
    match ctx.presence {
        Presence::Unknown => return Verdict::deny("正在确认对方状态…"),
        Presence::Offline => return Verdict::deny("对方离线，无法连接"),
        Presence::Stale => return Verdict::deny("对方状态不稳定，正在重试确认…"),
        Presence::Online => {}
    }

    match ctx.connection {
        ConnectionState::Disconnected => Verdict::allow("发起连接"),
        ConnectionState::Connecting => Verdict::deny("正在连接…"),
        ConnectionState::Connected => Verdict::deny("已连接"),
        ConnectionState::Disconnecting => Verdict::deny("正在断开…"),
        // Lost / Failed 必须允许再次连接：这两态下「断开」也不可用（无连接可断），
        // 若「连接」同时禁用，用户就被彻底卡住 —— 没有任何按钮能让他回到可用状态。
        ConnectionState::Lost => Verdict::allow("重新连接"),
        ConnectionState::Failed => Verdict::allow("重新连接"),
    }
}

/// §3.2 断开
fn can_disconnect(ctx: &UiContext) -> Verdict {
    // 非在线时无连接可断：连接态机维护 `Connected ⇒ Online` 不变量，
    // 对端掉线会被降为 Lost，因此这里不会误禁掉一个真实存在的连接。
    if !matches!(ctx.presence, Presence::Online) {
        return Verdict::deny("当前未连接");
    }
    match ctx.connection {
        ConnectionState::Connected => Verdict::allow("断开连接"),
        // 握手在途不给断：中途撤销会留下双端认知不一致的半开会话，
        // 该由握手超时（5s）收口，而不是让用户插一脚。
        ConnectionState::Connecting => Verdict::deny("正在连接…"),
        ConnectionState::Disconnecting => Verdict::deny("正在断开…"),
        ConnectionState::Lost => Verdict::deny("连接已丢失"),
        ConnectionState::Disconnected | ConnectionState::Failed => Verdict::deny("当前未连接"),
    }
}

/// §3.3 开始传输
fn can_start_transfer(ctx: &UiContext) -> Verdict {
    if ctx.connection != ConnectionState::Connected {
        return Verdict::deny("未连接，请先连接对方");
    }
    if ctx.transfer.allows_start() {
        return match ctx.transfer {
            TransferState::Idle => Verdict::allow("开始传输"),
            // 终态可开始，但语义是**新建会话**（终态单调，旧会话不复活）
            _ => Verdict::allow("开始新的传输"),
        };
    }
    Verdict::deny(in_progress_hint(ctx.transfer))
}

/// §3.3 中止
fn can_abort(ctx: &UiContext) -> Verdict {
    if ctx.transfer.allows_abort() {
        return Verdict::allow("中止传输");
    }
    match ctx.transfer {
        TransferState::Idle => Verdict::deny("没有进行中的传输"),
        TransferState::Completed => Verdict::deny("传输已完成"),
        TransferState::Failed | TransferState::Aborted => Verdict::deny("传输已结束"),
        _ => Verdict::deny("当前无可中止的传输"),
    }
}

/// §3.3 重试
fn can_retry(ctx: &UiContext) -> Verdict {
    if ctx.transfer.allows_retry() {
        return match ctx.transfer {
            TransferState::Paused => Verdict::allow("重新对账并从断点继续"),
            _ => Verdict::allow("新建会话重试"),
        };
    }
    match ctx.transfer {
        TransferState::Idle => Verdict::deny("没有可重试的任务"),
        TransferState::Completed => Verdict::deny("传输已成功"),
        _ => Verdict::deny(in_progress_hint(ctx.transfer)),
    }
}

/// §3.4 重新启用主算法
///
/// 只看设备级记忆，**不看**连接状态与本次会话是否降级：
/// `preferBasic` 按 §4.3 只存在本机、不告知对端，清除它无需任何网络交互；
/// 而按钮最自然的使用时机恰恰是「连接之前」—— 要求已连接反而让它形同虚设。
fn can_reenable_advanced(ctx: &UiContext) -> Verdict {
    if ctx.prefer_basic {
        Verdict::allow("清除降级记忆，下次传输将重新尝试主算法")
    } else {
        Verdict::deny("未启用降级记忆，无需重新启用")
    }
}

/// 「进行中」类状态的统一提示（§3.3 提示列）
fn in_progress_hint(t: TransferState) -> &'static str {
    match t {
        TransferState::Preparing | TransferState::Reconciling | TransferState::Transferring => {
            "传输进行中"
        }
        TransferState::Paused => "传输已暂停，请重试或中止",
        TransferState::Degrading => "正在切换算法",
        TransferState::Verifying => "正在校验",
        _ => "当前状态不允许该操作",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::connection::ConnectionState as C;
    use crate::state::transfer::TransferState as T;

    const ALL_CONN: [C; 6] = [
        C::Disconnected,
        C::Connecting,
        C::Connected,
        C::Disconnecting,
        C::Lost,
        C::Failed,
    ];
    const ALL_TRANSFER: [T; 10] = [
        T::Idle,
        T::Preparing,
        T::Reconciling,
        T::Transferring,
        T::Paused,
        T::Degrading,
        T::Verifying,
        T::Completed,
        T::Failed,
        T::Aborted,
    ];

    fn ctx(presence: Presence, connection: C, transfer: T) -> UiContext {
        UiContext {
            presence,
            connection,
            transfer,
            prefer_basic: false,
        }
    }

    // ────────────────────────────────────────────────────────────
    // §3.2 连接 / 断开 —— 逐行对照文档表格
    // ────────────────────────────────────────────────────────────

    /// 文档 §3.2 表格的可执行副本：(presence, connection) → (连接, 断开)
    #[test]
    fn doc_table_3_2_connect_disconnect() {
        // (presence, connection, 连接可用, 断开可用)
        let rows: &[(Presence, C, bool, bool)] = &[
            // unknown / offline / stale：任意 connection 下两者皆不可用
            (Presence::Unknown, C::Disconnected, false, false),
            (Presence::Unknown, C::Connected, false, false),
            (Presence::Offline, C::Disconnected, false, false),
            (Presence::Offline, C::Connected, false, false),
            (Presence::Stale, C::Disconnected, false, false),
            (Presence::Stale, C::Connected, false, false),
            // online × 六个连接态
            (Presence::Online, C::Disconnected, true, false),
            (Presence::Online, C::Connecting, false, false),
            (Presence::Online, C::Connected, false, true),
            (Presence::Online, C::Disconnecting, false, false),
            (Presence::Online, C::Lost, true, false),
            (Presence::Online, C::Failed, true, false),
        ];

        for &(p, c, want_connect, want_disconnect) in rows {
            let cx = ctx(p, c, T::Idle);
            let got_connect = can(UiAction::Connect, &cx).enabled;
            let got_disconnect = can(UiAction::Disconnect, &cx).enabled;
            assert_eq!(
                got_connect, want_connect,
                "§3.2 连接：presence={p:?} connection={c:?} 期望 {want_connect}，实际 {got_connect}"
            );
            assert_eq!(
                got_disconnect, want_disconnect,
                "§3.2 断开：presence={p:?} connection={c:?} 期望 {want_disconnect}，实际 {got_disconnect}"
            );
        }
    }

    /// 回归测试：连接丢失/失败后必须有出路，否则用户被卡死
    #[test]
    fn user_is_never_stranded_after_connection_loss() {
        for c in [C::Lost, C::Failed] {
            let cx = ctx(Presence::Online, c, T::Idle);
            let connect = can(UiAction::Connect, &cx);
            let disconnect = can(UiAction::Disconnect, &cx);
            assert!(
                connect.enabled || disconnect.enabled,
                "connection={c:?} 时连接与断开同时禁用，用户无任何出路"
            );
            // 明确要求是「连接」这条出路
            assert!(connect.enabled, "connection={c:?} 应可重新连接");
        }
    }

    /// unknown / stale 不得被误报为「离线」
    #[test]
    fn unknown_and_stale_have_distinct_hints() {
        let unknown = can(
            UiAction::Connect,
            &ctx(Presence::Unknown, C::Disconnected, T::Idle),
        );
        let stale = can(
            UiAction::Connect,
            &ctx(Presence::Stale, C::Disconnected, T::Idle),
        );
        let offline = can(
            UiAction::Connect,
            &ctx(Presence::Offline, C::Disconnected, T::Idle),
        );

        assert_eq!(unknown.reason, "正在确认对方状态…");
        assert_eq!(stale.reason, "对方状态不稳定，正在重试确认…");
        assert_eq!(offline.reason, "对方离线，无法连接");
        // 三者互不相同
        assert_ne!(unknown.reason, offline.reason);
        assert_ne!(stale.reason, offline.reason);
    }

    // ────────────────────────────────────────────────────────────
    // §3.3 开始传输 / 中止 / 重试 —— 逐行对照文档表格
    // ────────────────────────────────────────────────────────────

    /// 文档 §3.3 表格的可执行副本：connected × transfer → (开始, 中止, 重试)
    #[test]
    fn doc_table_3_3_start_abort_retry_when_connected() {
        // (transfer, 开始传输, 中止, 重试)
        let rows: &[(T, bool, bool, bool)] = &[
            (T::Idle, true, false, false),
            (T::Preparing, false, true, false),
            (T::Reconciling, false, true, false),
            (T::Transferring, false, true, false),
            (T::Paused, false, true, true),
            (T::Degrading, false, true, false),
            (T::Verifying, false, true, false),
            (T::Completed, true, false, false),
            (T::Failed, true, false, true),
            (T::Aborted, true, false, true),
        ];

        for &(t, want_start, want_abort, want_retry) in rows {
            let cx = ctx(Presence::Online, C::Connected, t);
            assert_eq!(
                can(UiAction::StartTransfer, &cx).enabled,
                want_start,
                "§3.3 开始传输：transfer={t:?}"
            );
            assert_eq!(
                can(UiAction::Abort, &cx).enabled,
                want_abort,
                "§3.3 中止：transfer={t:?}"
            );
            assert_eq!(
                can(UiAction::Retry, &cx).enabled,
                want_retry,
                "§3.3 重试：transfer={t:?}"
            );
        }
    }

    /// §3.3 首行：非 connected 时「开始传输」在任何 transfer 状态下都不可用
    #[test]
    fn start_transfer_requires_connected_for_every_transfer_state() {
        for c in ALL_CONN {
            if c == C::Connected {
                continue;
            }
            for t in ALL_TRANSFER {
                let v = can(UiAction::StartTransfer, &ctx(Presence::Online, c, t));
                assert!(
                    !v.enabled,
                    "connection={c:?} transfer={t:?} 未连接却允许开始传输"
                );
                assert_eq!(v.reason, "未连接，请先连接对方");
            }
        }
    }

    /// 回归测试：传完一次后必须还能再传
    #[test]
    fn can_start_new_transfer_after_settled() {
        for t in [T::Completed, T::Failed, T::Aborted] {
            let v = can(
                UiAction::StartTransfer,
                &ctx(Presence::Online, C::Connected, t),
            );
            assert!(v.enabled, "transfer={t:?} 后应能开始新的传输");
            assert_eq!(v.reason, "开始新的传输");
        }
    }

    /// 「可用」的动作必须真的能走通状态机 —— 裁决与状态机不得脱节
    #[test]
    fn enabled_actions_have_legal_state_machine_paths() {
        for t in ALL_TRANSFER {
            let cx = ctx(Presence::Online, C::Connected, t);

            if can(UiAction::StartTransfer, &cx).enabled {
                assert!(
                    !t.start_events().is_empty(),
                    "transfer={t:?} 允许开始却没有合法事件序列"
                );
            }
            if can(UiAction::Retry, &cx).enabled {
                assert!(
                    !t.retry_events().is_empty(),
                    "transfer={t:?} 允许重试却没有合法事件序列"
                );
            }
            if can(UiAction::Abort, &cx).enabled {
                assert!(
                    t.transition(crate::state::transfer::TransferEvent::Abort)
                        .is_ok(),
                    "transfer={t:?} 允许中止却无法迁移到 Aborted"
                );
            }
        }
    }

    /// 被禁用的动作一律带非空可读提示（不得静默失败）
    #[test]
    fn every_denial_carries_a_readable_reason() {
        let actions = [
            UiAction::Connect,
            UiAction::Disconnect,
            UiAction::StartTransfer,
            UiAction::Abort,
            UiAction::Retry,
            UiAction::ReenableAdvanced,
        ];
        for p in [
            Presence::Unknown,
            Presence::Offline,
            Presence::Stale,
            Presence::Online,
        ] {
            for c in ALL_CONN {
                for t in ALL_TRANSFER {
                    for a in actions {
                        let v = can(a, &ctx(p, c, t));
                        assert!(
                            !v.reason.is_empty(),
                            "{a:?} 在 ({p:?},{c:?},{t:?}) 下提示为空"
                        );
                    }
                }
            }
        }
    }

    // ────────────────────────────────────────────────────────────
    // §3.4 重新启用主算法
    // ────────────────────────────────────────────────────────────

    /// 只由设备级记忆决定，与连接态、传输态、在线性全部无关
    #[test]
    fn doc_table_3_4_reenable_advanced_depends_only_on_memory() {
        for p in [Presence::Unknown, Presence::Offline, Presence::Online] {
            for c in ALL_CONN {
                for t in ALL_TRANSFER {
                    let mut cx = ctx(p, c, t);

                    cx.prefer_basic = false;
                    let off = can(UiAction::ReenableAdvanced, &cx);
                    assert!(!off.enabled, "记忆未生效时不应可用（{p:?},{c:?},{t:?}）");

                    cx.prefer_basic = true;
                    let on = can(UiAction::ReenableAdvanced, &cx);
                    assert!(
                        on.enabled,
                        "记忆生效时应可用，不得被连接/传输态牵连（{p:?},{c:?},{t:?}）"
                    );
                }
            }
        }
    }

    /// 关键场景：连接之前就该能清除记忆（这是最自然的使用时机）
    #[test]
    fn reenable_advanced_works_while_disconnected() {
        let cx = UiContext {
            presence: Presence::Offline,
            connection: C::Disconnected,
            transfer: T::Idle,
            prefer_basic: true,
        };
        let v = can(UiAction::ReenableAdvanced, &cx);
        assert!(v.enabled, "离线未连接时也应能清除本机降级记忆");
        assert_eq!(v.reason, "清除降级记忆，下次传输将重新尝试主算法");
    }
}
