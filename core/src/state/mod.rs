//! 状态机集合 —— 所有交互的唯一依据
//!
//! 三张正交状态机：
//! - [`presence`]：在线性（每设备，由 UDP beacon 维护，与配对/连接正交）
//! - [`connection`]：连接态（每设备，不变量 `Connected ⇒ Online`）
//! - [`transfer`]：传输会话态（每会话）
//!
//! 以及 [`policy`]：单一裁决函数 `can(action, ctx)`，
//! 同时驱动 UI 的按钮可用性与运行时的非法操作拦截。

pub mod connection;
pub mod policy;
pub mod presence;
pub mod transfer;

pub use connection::{ConnEvent, ConnectionState, IllegalTransition as ConnIllegal};
pub use policy::{can, UiAction, UiContext, Verdict};
pub use presence::{on_beacon, reset, tick};
pub use transfer::{IllegalTransition as TransferIllegal, TransferEvent, TransferState};
