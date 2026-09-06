//! pairing/mod.rs — 配对模块根
//!
//! 将 `handle_pairing_conn` 按协议阶段拆分为独立子模块：
//! - error.rs      — 统一错误类型（PairingError）
//! - types.rs      — 阶段数据结构
//! - auth.rs       — 握手解析与验证
//! - key_exchange.rs — 密钥协商
//! - v4.rs         — v4 配对协议（当前唯一路径）
//!
//! 主路由函数 `handle_pairing_conn` 在 auth.rs 中导出。

pub mod auth;
pub mod error;
pub mod key_exchange;
pub mod types;
pub mod v4;

pub use auth::handle_pairing_conn;
