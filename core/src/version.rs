//! V4 协议版本与能力位图
//!
//! 设计要点见 `V4-ARCHITECTURE.md` §二。
//!
//! 三代并存的教训是"命名空间与版本号各自演进"：项目里曾同时存在
//! `/api/localsend/v2/*`、`/api/backup/v1/*`（`PROTOCOL_VERSION = '1.1'`）、
//! `/api/v3/*`，以及三个独立的 `KDF_VERSION` / `CRYPTO_VERSION` / device-id 版本。
//! V4 收敛为**一个版本号 + 一张能力位图**。

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// V4 协议版本。单一版本号，取代此前的 PROTOCOL_VERSION / KDF_VERSION / CRYPTO_VERSION 三个。
pub const PROTOCOL_VERSION: u32 = 4;

/// API 命名空间前缀。带上产品前缀以避开上游 localsend 的 v2/v3 命名冲突。
pub const API_PREFIX: &str = "/api/v4";

// ============================================================
// 能力位图
// ============================================================

/// V4 配对握手
pub const CAP_PAIRING_V4: u32 = 1 << 0;
/// 主传输算法：块级差异同步 + Merkle + 断点续传 + 并发
pub const CAP_ADVANCED: u32 = 1 << 1;
/// 双端状态对账（权威块位图与任务终态）
pub const CAP_RECONCILE: u32 = 1 << 2;
/// 传输层加密（默认开启，可协商降级为明文，仍保留 HMAC 完整性）
pub const CAP_ENCRYPT: u32 = 1 << 3;
/// UDP presence beacon（支撑 0.5s 在线性 TTL）
pub const CAP_BEACON: u32 = 1 << 4;

/// 本机支持的全部能力。新增能力时必须同时提供降级路径。
pub const CAPABILITIES_ALL: u32 =
    CAP_PAIRING_V4 | CAP_ADVANCED | CAP_RECONCILE | CAP_ENCRYPT | CAP_BEACON;

/// 能力位图
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Capabilities(u32);

impl Capabilities {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn all() -> Self {
        Self(CAPABILITIES_ALL)
    }

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, cap: u32) -> bool {
        self.0 & cap == cap
    }

    pub const fn with(mut self, cap: u32) -> Self {
        self.0 |= cap;
        self
    }

    pub const fn without(mut self, cap: u32) -> Self {
        self.0 &= !cap;
        self
    }

    /// 双方能力按位与 —— 只有两端都支持的能力才会启用
    pub const fn negotiate(self, peer: Capabilities) -> Capabilities {
        Capabilities(self.0 & peer.0)
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        Self::all()
    }
}

// ============================================================
// 分块常量 —— 单一来源
// ============================================================
//
// 教训：项目中曾四处并存 4MB / 8MB / 16MB 三个值
//   - shared-core/src/transfer.ts:196  chunkSize = piece 大小 = 4MB
//   - shared-core/src/transfer.ts:659  CHUNK_SIZE = 8MB
//   - shared-core/src/scheduler.ts:601 buildDegradedChunkPlan = 16MB
//   - V4-ARCHITECTURE 早期稿：小文件 <16MB 跳过 diff
// 这导致降级时已传进度无法换算，只能从头重传。
//
// V4 规则：基础算法分块必须是主算法 piece 大小的**整数倍**，
// 这样降级时已完成的连续 piece 可以直接换算为已完成的块。

/// Merkle 叶块大小（BEP-0052）
pub const MERKLE_LEAF_SIZE: u64 = 16 * 1024;

/// 主算法 piece 大小
pub const PIECE_SIZE: u64 = 4 * 1024 * 1024;

/// 基础算法分块大小 = 4 × PIECE_SIZE
///
/// **必须保持整数倍关系**，否则降级时无法复用已传进度。
pub const BASIC_CHUNK_SIZE: u64 = 4 * PIECE_SIZE;

/// 基础算法分块相对主算法 piece 的倍数
pub const BASIC_CHUNK_PIECES: u64 = BASIC_CHUNK_SIZE / PIECE_SIZE;

/// tiny 文件阈值：小于此值走 ustar tar 批量聚合
///
/// 理由（原注释）：手机相册动辄上万个 <10KB 文件，逐文件
/// prepare-upload + upload 的握手开销远大于数据量本身。
/// 聚合后"万次握手 → 1 次连接"。
pub const TINY_THRESHOLD: u64 = 10 * 1024;

/// tiny 文件每批打包数量。原注释：50-100 为工程平衡点
pub const TINY_BATCH_SIZE: usize = 75;

/// 大文件阈值：超过此值才构建 Merkle 树
///
/// 理由：小文件建 Merkle 树的开销大于收益（一次 SHA-256 就够了）。
pub const LARGE_FILE_THRESHOLD: u64 = 100 * 1024 * 1024;

// ============================================================
// 端口
// ============================================================

/// 数据面与控制面统一端口。
///
/// V4 消灭了 53318 上那套手写的 `TcpListener` + 手工 HTTP/1.1 解析器，
/// 全部端点收敛到单一 hyper 路由表。
pub const DEFAULT_PORT: u16 = 53317;

// ============================================================
// 阈值 —— 状态机与降级
// ============================================================
//
// 完整说明见 V4-TRANSFER-MODULE.md §2.4

pub mod timeout {
    /// 握手超时
    pub const HANDSHAKE_MS: u64 = 5_000;
    /// 心跳周期
    pub const HEARTBEAT_MS: u64 = 5_000;
    /// 心跳超时（连续 3 个周期无响应）→ 传输 paused / 连接 lost
    pub const HEARTBEAT_TIMEOUT_MS: u64 = 15_000;
    /// beacon 发送周期
    pub const BEACON_MS: u64 = 500;
    /// online → stale（3 个 beacon 周期）
    pub const PRESENCE_STALE_MS: u64 = 1_500;
    /// stale → offline（6 个 beacon 周期）
    pub const PRESENCE_OFFLINE_MS: u64 = 3_000;
    /// 会话无进展超时
    pub const SESSION_STALLED_MS: u64 = 30 * 60 * 1_000;
}

pub mod retry {
    /// 握手重试次数
    pub const HANDSHAKE: u32 = 3;
    /// 单块重试次数
    pub const CHUNK: u32 = 3;
    /// 对账重试次数
    pub const RECONCILE: u32 = 3;
    /// 整体校验重试次数
    pub const VERIFY: u32 = 2;
    /// 连续块失败达到此值触发降级
    pub const CHUNK_FAIL_DEGRADE: u32 = 3;
    /// 全抖动退避基数（AWS 标准）
    pub const BACKOFF_BASE_MS: u64 = 1_000;
    /// 退避上限
    pub const BACKOFF_MAX_MS: u64 = 64_000;
    /// 退避指数上限（2^5 * 1000 = 32s）
    pub const BACKOFF_MAX_EXPONENT: u32 = 5;

    // 块重试退避与握手退避**不共用参数**（文档 V4-TRANSFER-MODULE §2.4 T13）。
    //
    // 教训：旧实现只有一套 backoff（base 1s / max 64s），块重试也走它。
    // 结果传大文件时一个偶发坏块会让该分片睡上几十秒，而并发窗口里
    // 这个 slot 一直被占着 —— 表现为"传输卡住但没报错"。
    // 块重试发生在热路径，必须快重试；握手重试关系到"对端到底在不在"，
    // 必须慢一点，否则网络刚抖一下就把 3 次重试在 1 秒内烧完直接判死。

    /// 单块重试退避基数（T13：200ms）
    pub const CHUNK_BACKOFF_BASE_MS: u64 = 200;
    /// 单块重试退避上限（T13：5s）
    pub const CHUNK_BACKOFF_MAX_MS: u64 = 5_000;

    // 编译期护栏：把"两套退避参数不许被统一"钉死在类型系统这一层。
    // 用 const assert 而不是 #[test] —— 后者要跑起来才报错，前者连编译都不给过。
    const _: () = assert!(
        CHUNK_BACKOFF_BASE_MS < BACKOFF_BASE_MS,
        "块重试基数必须小于握手基数：块重试在传输热路径上，慢退避会让偶发坏块长时间占着并发 slot"
    );
    const _: () = assert!(
        CHUNK_BACKOFF_MAX_MS < BACKOFF_MAX_MS,
        "块重试退避上限必须小于握手退避上限"
    );
    const _: () = assert!(
        CHUNK_BACKOFF_BASE_MS > 0 && BACKOFF_BASE_MS > 0,
        "退避基数为 0 会让随机区间退化为空"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_chunk_is_multiple_of_piece() {
        // 这是降级能否复用进度的前提，改动常量时此测试必须仍然通过
        assert_eq!(
            BASIC_CHUNK_SIZE % PIECE_SIZE,
            0,
            "BASIC_CHUNK_SIZE 必须是 PIECE_SIZE 的整数倍，否则降级时无法换算已传进度"
        );
        assert_eq!(BASIC_CHUNK_PIECES, 4);
    }

    #[test]
    fn capability_negotiation() {
        let local = Capabilities::all();
        let peer = Capabilities::empty().with(CAP_PAIRING_V4).with(CAP_ENCRYPT);
        let agreed = local.negotiate(peer);
        assert!(agreed.contains(CAP_PAIRING_V4));
        assert!(agreed.contains(CAP_ENCRYPT));
        assert!(
            !agreed.contains(CAP_ADVANCED),
            "对端不支持主算法 → 必须降级"
        );
    }

    #[test]
    fn piece_size_is_multiple_of_merkle_leaf() {
        assert_eq!(PIECE_SIZE % MERKLE_LEAF_SIZE, 0);
    }
}
