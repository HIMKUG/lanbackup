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

pub mod error;
pub mod version;

pub use error::{Error, ErrorCode, ErrorEnvelope, Result};
pub use version::{Capabilities, API_PREFIX, PROTOCOL_VERSION};

// TODO(阶段 1): pub mod dto;      —— V4 全部 DTO，schemars 生成 JSON Schema
// TODO(阶段 2): pub mod server;   —— 单一 hyper 路由表（吸收 localsend 的 HTTP 管道）
// TODO(阶段 2.5): pub mod transfer; —— 主算法 + 基础算法
// TODO(阶段 3): pub mod schedule; —— 并发控制（tokio Semaphore）
// TODO(阶段 3): pub mod state;    —— 会话/连接/在线性状态机
// TODO(阶段 4.5): pub mod crypto; —— 握手层 ECDSA 签名 + 统一 AEAD 传输加密
// TODO(阶段 5): pub mod pairing;  —— 配对、解配对、吊销、双向对账
// TODO(阶段 4): pub mod presence; —— UDP beacon 与在线性维护
// TODO(阶段 4): pub mod sync;     —— 三路增量、manifest、archive/mirror 策略
// TODO(阶段 5): pub mod discovery; —— 组播与子网探测
// TODO(阶段 5): pub mod identity; —— 设备身份与连接码派生
// TODO(阶段 6): uniffi 绑定导出
