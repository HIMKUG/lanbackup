//! pairing/mod.rs — 配对模块根
//!
//! 将 `handle_pairing_conn` 按协议阶段拆分为独立子模块：
//! - error.rs      — 统一错误类型（PairingError）
//! - types.rs      — 阶段数据结构（已删除未落地类型，保留注释供将来参考）
//! - auth.rs       — 握手解析与验证
//! - key_exchange.rs — 密钥协商（本版本未启用，保留接口）
//! - v3.rs         — v3 配对协议（当前唯一路径）
//!
//! 主路由函数 `handle_pairing_conn` 在 auth.rs 中导出。

pub mod auth;
pub mod error;
pub mod key_exchange;
pub mod types;
pub mod v3;

pub use auth::handle_pairing_conn;
