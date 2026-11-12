//! pairing/mod.rs — 配对模块根
//!
//! V4 配对全部走 core `lanbackup-core`（`/api/v4/handshake/*`，53317）；
//! 遗留 53318 手写配对服务（auth.rs / v4.rs 代理层）已按 WB-0100/D3 删除，
//! 源码留档于 `backups/quarantine/region3-deadcode-2026-11-12/`。
//!
//! 保留子模块：
//! - error.rs      — 统一错误类型（PairingError，预留接口）
//! - key_exchange.rs — 密钥协商（预留接口）
//! - types.rs      — 阶段数据结构（预留）

pub mod error;
pub mod key_exchange;
pub mod types;
