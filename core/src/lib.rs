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
pub mod discovery;
pub mod dto;
pub mod error;
pub mod ffi;
pub mod identity;
pub mod pairing;
pub mod presence;
pub mod routes;
pub mod server;
pub mod state;
pub mod sync;
pub mod transfer;
pub mod version;

pub use error::{Error, ErrorCode, ErrorEnvelope, Result};
pub use identity::DeviceIdentity;
pub use version::{Capabilities, API_PREFIX, PROTOCOL_VERSION};

// ── 已落地 ─────────────────────────────────────────────────────────────
// 阶段 1   dto / error / version   —— 契约先行：DTO 生成 schema + golden 指纹
// 阶段 2   state / transfer::chunk —— 三张状态机 + can() 裁决 + 分块降级引擎
//          crypto::merkle          —— Merkle root
// 阶段 2.4 server                  —— hyper 路由 /api/v4/*、内存会话、状态机门控
// 阶段 2.5 crypto::merkle          —— proof/verify_piece（接收端独立验证任意 piece）
//          transfer::chunk         —— 弱/强双校验 + ChunkDiff 三分类
//          transfer::schedule      —— 全局信号量 12 + 重试独立配额 4 + 全抖动退避（握手/块两套）
// 阶段 2.6 transfer::session       —— 编排器：决策与 IO 分离，驱动状态机串起 prepare/对账/收发/校验
//          transfer::cleanup       —— §六 断开/中止有序清理清单（先停请求→释放许可→清内存→删文件）
//          transfer::degrade       —— DegradeController 接入编排循环（observe 真实信号、执行 events、算进度、出可见性）
// 阶段 3   state::policy           —— 按钮可用性与文档 §3 三张表逐行对齐（表驱动测试）
// 阶段 4.1 transfer::degrade       —— D1-D6 降级判定 + 设备级记忆 + UI 可见性快照
// 阶段 4.3 presence::beacon        —— 32B UDP beacon 报文与 HMAC 认证（纯计算部分）
//          presence::tracker       —— (ts,seq) 单调水位重放防护 + 在线性衰减
// 阶段 4   presence::transport     —— UDP 收发、多网卡、组播锁抽象（M22）、套接字自愈（W5）
//          routes                  —— 端点单一来源，逐行抄自文档 §六 24 个端点（含方法）
// 阶段 4   sync::manifest          —— 路径归一化、墓碑目录、清单去重
//          sync::plan              —— 三路增量六集合 + archive/mirror 策略
// 阶段 5   identity                —— 设备身份（长生命周期 ECDSA）+ 连接码派生
//          pairing::transcript     —— 长度前缀帧 + 域分隔（含服务端静态公钥，防 MITM）
//          pairing::token          —— 紧凑 JWS，一次性 jti 才是真正的重放防御
//          pairing::machine        —— 配对状态机（11 条迁移，越界迁移一律给可读原因）
//          pairing::trust          —— 双向信任对账；对账兼任吊销 ack 的兜底通路
//          discovery               —— /24 子网 HTTP 探测（掩码一律收窄到 /24）+ 并发窗口
// 阶段 6   ffi                     —— 稳定 C ABI 门面：热路径定长签名 + 冷路径 JSON
//
// ── 全部阶段已落地 ─────────────────────────────────────────────────────
//
// 唯一的例外是 uniffi：它不在可用的 registry 索引里（离线环境），
// 故阶段 6 落地为**与绑定框架无关**的 C ABI 门面（见 `ffi` 模块文档）。
// 等 uniffi 可用时，它接在这一层**之上**，core 无需改动 ——
// 这恰好守住了本 crate 存在的理由：协议与算法只此一份实现。
//
// ── 仍待推进（非阻塞，属后续工程化）───────────────────────────────────
// - `SessionStore` 现已接**磁盘持久化**（断点续传在重启/杀后台/切 Wi-Fi 后成立）：
//   内存热表 + 写穿镜像 + 冷启动重载，接口在 `server::persist`。
//   注意本环境无 C 工具链，`rusqlite`(bundled) 无法编译，故暂用**纯 Rust 原子写
//   JSON** 作后端；接口与 rusqlite 后端同构，后续具备 C 工具链时替换 `persist`
//   模块实现即可，上层零改动。
// - `server` 的 24 个端点已全部接线（`server::tests::every_declared_route_is_actually_wired`
//   逐条验证 `routes::ALL` 都落到了 match 分支上）
// - Android JNI 层需实现 `MulticastGuard`（M22：收发两条路径都要持锁）
