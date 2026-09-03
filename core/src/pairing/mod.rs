//! 配对 —— 建立、解除、吊销、双向对账
//!
//! 文档：`V4-ARCHITECTURE.md` §3.3（配对状态机）、§4.3（密钥树 L1-L2）
//!
//! # 为什么配对要单独成模块
//!
//! 三代实测里"解配对不彻底"是复现率最高的问题：A 删了 B，B 那边还留着记录，
//! 于是 B 继续发 beacon、继续尝试连接，A 侧表现为"已删除的设备又出现了"。
//! 根因是**配对被当成一个布尔字段**（paired: true/false），而它实际上是
//! 一个带中间态（Pending / Revoking）的分布式状态机：
//!
//! - 中间态必须存在：解配对请求可能丢包，需要可重发的 `Revoking`
//! - 单侧记录不足以判定信任：必须 `本地记录 ∩ 对端确认`
//! - 终态必须不可复活：`Revoked` 不允许被任何事件带回 `Active`
//!
//! # 子模块分工
//!
//! | 子模块 | 职责 | 纯计算 |
//! |---|---|---|
//! | [`transcript`] | 长度前缀帧 + 域分隔的握手/解配对/吊销签名载荷 | 是 |
//! | [`token`] | 紧凑 JWS（HS256）挑战票据与吊销票据 + jti 一次性消费 | 是 |
//! | [`machine`] | 配对状态机 `transition(from, event)`，非法转换给可读理由 | 是 |
//! | [`trust`] | 信任记录与双向对账 `reconcile(local, peer)` | 是 |
//!
//! 四个子模块**全部是纯计算**，不碰 socket 与磁盘 —— 网络与持久化由调用方
//! （server 路由 / 桌面端 / 手机端）注入，这样配对逻辑可以被确定性地测试。

pub mod machine;
pub mod token;
pub mod transcript;
pub mod trust;

pub use machine::{
    allows_transfer, is_terminal, should_emit_beacon, transition, IllegalTransition, PairingEvent,
};
pub use token::{
    mint, verify, Claims, ConsumedTokens, TokenError, TokenKind, VerifiedToken, CHALLENGE_TTL_SECS,
    REVOKE_TOKEN_TTL_SECS,
};
pub use transcript::{
    frame, path_a_key, path_a_transcript, revoke_payload, tag, unpair_payload, verify_tag,
    DOMAIN_PATH_A, DOMAIN_PATH_A_KEY, DOMAIN_REVOKE, DOMAIN_UNPAIR,
};
pub use trust::{effective_state, peer_still_trusts, reconcile, TrustRecord, TrustVerdict};
