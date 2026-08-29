//! lanbackup-core —— 局域网备份工具核心（V4）
//!
//! 这是 workspace 的第五个包，也是 V4 重构的落点：
//! **协议与算法只此一份实现**，桌面端（Tauri）直接依赖，手机端经 JNI/uniFFI 调用。
//!
//! # 为什么要这个包
//!
//! 三代并存阶段，同一份协议在 TypeScript、Rust、Java 里各写一遍，
//! 零共享测试向量。实测中出现的全部稳定性问题（断点续传不稳、
//! 双端状态机不匹配、解配对不彻底、离线可连接、任务认知分歧）
//! 根因都是**三份实现各跑各的**。
//!
//! # 模块现状
//!
//! 各模块按 V4 计划分阶段落地，未落地的模块在下方 `TODO(阶段 N)` 标注。
//!
//! # 必读
//!
//! - `V4-ARCHITECTURE.md` —— 架构方向
//! - `V4-TRANSFER-MODULE.md` —— 传输状态机、按钮可用性、降级策略
//! - `DESIGN-WISDOM-REGISTER.md` —— **既有代码的实测智慧清单，重构不得遗漏**

pub mod crypto;
pub mod dto;
pub mod error;
pub mod presence;
pub mod server;
pub mod state;
pub mod transfer;
pub mod version;

pub use error::{Error, ErrorCode, ErrorEnvelope, Result};
pub use version::{Capabilities, API_PREFIX, PROTOCOL_VERSION};

// ── 已落地 ─────────────────────────────────────────────────────────────
// 阶段 1   dto / error / version   —— 契约先行：DTO 生成 schema + golden 指纹
// 阶段 2   state / transfer::chunk —— 三张状态机 + can() 裁决 + 分块降级引擎
//          crypto::merkle          —— Merkle root
// 阶段 2.4 server                  —— hyper 路由 /api/v4/*、内存会话、状态机门控
// 阶段 2.5 crypto::merkle          —— proof/verify_piece（接收端独立验证任意 piece）
//          transfer::chunk         —— 弱/强双校验 + ChunkDiff 三分类
//          transfer::schedule      —— 全局信号量 12 + 重试独立配额 4 + 全抖动退避
// 阶段 4.3 presence::beacon        —— 32B UDP beacon 报文与 HMAC 认证（纯计算部分）
//
// ── 待落地 ─────────────────────────────────────────────────────────────
// TODO(阶段 2.6): 主算法 IO 编排（把 chunk/schedule/merkle 串成实际收发流水线）
// TODO(阶段 4):   presence 传输层 —— UDP 收发、Android MulticastLock（W5/M22）
// TODO(阶段 4):   pub mod sync;      —— 三路增量、manifest、archive/mirror 策略
// TODO(阶段 5):   pub mod pairing;   —— 配对、解配对、吊销、双向对账
// TODO(阶段 5):   pub mod discovery; —— 组播与子网探测
// TODO(阶段 5):   pub mod identity;  —— 设备身份与连接码派生
// TODO(阶段 6):   uniffi 绑定导出
