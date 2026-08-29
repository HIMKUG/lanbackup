//! 传输会话的 V4 DTO
//!
//! 端点：
//! - `POST /api/v4/session/register`    会话注册
//! - `POST /api/v4/session/prepare`     上传准备，响应带协商后的能力
//! - `POST /api/v4/session/chunk`       分块上传
//! - `GET  /api/v4/session/diff`        块差异探测（**权威块位图来源**）
//! - `GET  /api/v4/session/verify`      整体校验
//! - `GET  /api/v4/session/phase`       查询会话当前阶段（phase 对账）
//! - `POST /api/v4/session/heartbeat`   心跳
//! - `POST /api/v4/session/abort`       中止会话
//! - `POST /api/v4/session/receipt`     文件回执（**任务终态由接收端权威回传**）
//! - `GET  /api/v4/session/tasks`       查询会话内每个文件的终态

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::version::Capabilities;

// ============================================================
// 会话阶段
// ============================================================

/// 传输会话阶段。
///
/// **这是双方共识，不是本地字段** —— 阶段变更需对端 ack
/// （`V4-TRANSFER-MODULE.md` §2.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TransferPhase {
    /// 无会话
    Idle,
    /// 建立会话、能力协商、选择算法
    Preparing,
    /// 拉取对端权威块位图（仅主算法）
    Reconciling,
    /// 传块中
    Transferring,
    /// 心跳超时/网络中断，等待重试或对账
    Paused,
    /// 正在从主算法切换到基础算法
    Degrading,
    /// 整体校验
    Verifying,
    /// 已完成（终态）
    Completed,
    /// 失败（终态）
    Failed,
    /// 已中止（终态）
    Aborted,
}

impl TransferPhase {
    /// 是否为终态。**终态单调**：一旦进入不可回退到任何非终态。
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Aborted)
    }

    /// 是否允许"中止"操作
    pub fn allows_abort(self) -> bool {
        matches!(
            self,
            Self::Preparing
                | Self::Reconciling
                | Self::Transferring
                | Self::Paused
                | Self::Degrading
                | Self::Verifying
        )
    }

    /// 是否允许"重试"操作
    pub fn allows_retry(self) -> bool {
        matches!(self, Self::Paused | Self::Failed)
    }
}

/// 当前生效的算法
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    /// 主算法：块级差异 + Merkle + 断点续传 + 并发
    Advanced,
    /// 基础算法：16MB 分块顺序传输 + 简单续传
    Basic,
}

/// 降级原因码。UI 必须显示"当前算法 + 降级原因 + 已传进度处置"。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DegradeReason {
    /// 对端不具备主算法能力。稳定原因，**不**记入设备级降级记忆
    /// （对端升级后自然恢复）。
    PeerNoCapability,
    /// 主算法初始化失败（Merkle 构建 / 密钥派生 / 端点异常）
    InitFailed,
    /// 对账连续失败
    ReconcileFailed,
    /// 心跳超时后对账重试耗尽
    RetryExhausted,
    /// 连续块失败达到阈值
    ChunkRetryExhausted,
    /// 整体校验反复失败
    VerifyFailed,
}

impl DegradeReason {
    /// 线上原因码（`V4-TRANSFER-MODULE.md` §4.1 的「降级原因码」列）。
    ///
    /// **这是唯一真源** —— HTTP 层、日志、UI 都必须调用这里，
    /// 不允许各自再写一份 match（两份映射必然漂移，见登记表 E10）。
    pub fn code(self) -> &'static str {
        match self {
            Self::PeerNoCapability => "PEER_NO_CAPABILITY",
            Self::InitFailed => "INIT_FAILED",
            Self::ReconcileFailed => "RECONCILE_FAILED",
            Self::RetryExhausted => "RETRY_EXHAUSTED",
            Self::ChunkRetryExhausted => "CHUNK_RETRY_EXHAUSTED",
            Self::VerifyFailed => "VERIFY_FAILED",
        }
    }

    /// 给用户看的中文文案（§4.4 要求 UI 明示降级原因）。
    ///
    /// 与 [`Self::code`] 分离：原因码是给机器/日志对账的，
    /// 这句是给人读的 —— 二者都不能省。
    pub fn text(self) -> &'static str {
        match self {
            Self::PeerNoCapability => "对方版本较旧，不支持高级传输",
            Self::InitFailed => "高级传输初始化失败",
            Self::ReconcileFailed => "块对账连续失败",
            Self::RetryExhausted => "断线后重试已用尽",
            Self::ChunkRetryExhausted => "数据块连续失败",
            Self::VerifyFailed => "整体校验反复失败",
        }
    }

    /// 是否计入**设备级降级记忆**（§4.3）。
    ///
    /// 区分两种降级原因是这套记忆机制的关键：
    /// - `PeerNoCapability` 是**稳定**原因 —— 对端就是老版本，
    ///   记进记忆毫无意义（对端升级后自然恢复），因此返回 `false`。
    /// - 其余都是「有能力但跑不通」的**环境性**原因 —— 值得记住，
    ///   避免每次会话都白试一遍主算法。
    pub fn counts_toward_memory(self) -> bool {
        !matches!(self, Self::PeerNoCapability)
    }
}

// ============================================================
// POST /api/v4/session/register
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionRegisterRequest {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    pub alias: String,
    /// 会话 ID，必须用 CSPRNG 生成。
    ///
    /// 原 `Date.now() + Math.random()` 生成方式可预测，
    /// 同网段攻击者能猜测并劫持/污染会话（原 `scheduler.ts:391-397`）。
    #[serde(rename = "sessionId")]
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionRegisterResponse {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// 协商后的能力（两端按位与）
    pub capabilities: Capabilities,
}

// ============================================================
// POST /api/v4/session/prepare
// ============================================================

/// 待传输文件的元数据。
///
/// **文件名只在此阶段携带** —— upload 阶段不带 fileName，
/// 接收端自行从会话中查（LocalSend v2 数据面最容易实现错的一点）。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FileMeta {
    /// 文件唯一 ID
    #[serde(rename = "fileId")]
    pub file_id: String,
    #[serde(rename = "fileName")]
    pub file_name: String,
    /// 相对路径（统一 `/` 分隔，已去掉 `./` 前缀与结尾 `/`）
    #[serde(rename = "relPath")]
    pub rel_path: String,
    pub size: u64,
    /// 修改时间（毫秒）。
    ///
    /// **接收端必须保留此值** —— 一旦被重置为写入时间，
    /// 发送端三路对比会永久误判为变更，每次全量重传
    /// （原 `transfer.ts:187`）。
    pub mtime: i64,
    /// 整个文件的 SHA-256（hex），可选
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Merkle 根（主算法扩展字段，大文件才有）
    #[serde(rename = "merkleRoot", skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
    /// 每个 piece 的 SHA-256（piece = 4MB）
    #[serde(rename = "pieceHashes", skip_serializing_if = "Option::is_none")]
    pub piece_hashes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PrepareRequest {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    /// 以 `fileId` 为 key 的字典（**不是数组**，v2.2 协议要求）
    pub files: std::collections::HashMap<String, FileMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PrepareResponse {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// `fileId` → 上传 token（**值是纯字符串，不是对象**）
    pub files: std::collections::HashMap<String, String>,
    /// 协商后的能力。对端无 `CAP_ADVANCED` 时调用方必须直接用基础算法。
    pub capabilities: Capabilities,
}

// ============================================================
// GET /api/v4/session/diff —— 权威块位图
// ============================================================

/// 块差异分析结果。
///
/// 四类语义（原 `scheduler.ts:21-29`）：
/// - `missing`：接收端完全没有
/// - `matched`：**弱校验与强校验都匹配**
/// - `mismatched`：**弱校验命中但 SHA-256 不匹配** —— 该块写坏了，
///   只需重传这一块而不是整个文件
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ChunkDiff {
    #[serde(rename = "fileId")]
    pub file_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// 接收端完全没有的块
    #[serde(rename = "missingChunks", default)]
    pub missing_chunks: Vec<u64>,
    /// 弱校验 + 强校验都匹配的块
    #[serde(rename = "matchedChunks", default)]
    pub matched_chunks: Vec<u64>,
    /// 弱校验命中但 SHA-256 不匹配的块
    #[serde(rename = "mismatchedChunks", default)]
    pub mismatched_chunks: Vec<u64>,
    /// 所有块都已到齐且校验通过
    #[serde(rename = "fileComplete")]
    pub file_complete: bool,
}

/// diff 端点的 HTTP 状态码语义（**非显而易见，必须照此实现**）：
///
/// | 状态码 | 含义 |
/// |---|---|
/// | 206 | 块存在且 ETag 匹配 |
/// | 412 | 块存在但 SHA-256 不匹配（NACK），响应带 `expected` / `actual` |
/// | 416 | Range 越界，响应带 `Content-Range: bytes * /{total}` |
/// | 200 | ETag 不匹配，文件已变，需全量重传 |
///
/// 把"存在性"和"正确性"用两个不同状态码分开表达，
/// 发送端才能区分"没传过"和"传过但坏了"。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DiffMismatch {
    /// 期望的 SHA-256
    pub expected: String,
    /// 实际的 SHA-256
    pub actual: String,
}

// ============================================================
// GET /api/v4/session/verify
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyFileResponse {
    #[serde(rename = "fileId")]
    pub file_id: String,
    /// 校验通过时返回实际 SHA-256
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// 校验失败时返回原因
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ============================================================
// GET /api/v4/session/phase
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PhaseResponse {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub phase: TransferPhase,
    pub algorithm: Algorithm,
    /// 降级原因；未降级时为空
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degrade_reason: Option<DegradeReason>,
    /// 本端已确认的块位图版本号，供对端判断是否需要重新对账
    #[serde(rename = "bitmapVersion")]
    pub bitmap_version: u64,
}

// ============================================================
// POST /api/v4/session/heartbeat
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HeartbeatRequest {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// 本端当前阶段（用于对账）
    pub phase: TransferPhase,
    /// 本端权威块位图版本号
    #[serde(rename = "bitmapVersion")]
    pub bitmap_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HeartbeatResponse {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// 对端当前阶段。与本端不一致时触发对账。
    pub phase: TransferPhase,
    /// 对端权威块位图版本号
    #[serde(rename = "bitmapVersion")]
    pub bitmap_version: u64,
}

// ============================================================
// POST /api/v4/session/receipt —— 任务终态
// ============================================================

/// 单个文件的任务终态。
///
/// **终态由接收端判定** —— 数据在谁的磁盘上谁知道。
/// 发送端心跳超时时**不允许自行判定失败**，必须先查询对端终态
/// （这正是"一方认为在传输可重试、另一方认为已完成"的直接原因）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Queued,
    Transferring,
    Completed,
    Failed,
    Cancelled,
}

impl TaskStatus {
    /// 终态单调：一旦确认不可回退
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TaskReceipt {
    #[serde(rename = "fileId")]
    pub file_id: String,
    #[serde(rename = "relPath")]
    pub rel_path: String,
    pub status: TaskStatus,
    /// 接收端实际落盘的大小
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// 接收端保留的 mtime（必须等于发送端的 mtime）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime: Option<i64>,
    /// 因冲突重命名后的最终文件名
    #[serde(rename = "finalName", skip_serializing_if = "Option::is_none")]
    pub final_name: Option<String>,
    /// 失败原因
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptRequest {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub tasks: Vec<TaskReceipt>,
}

/// `GET /api/v4/session/tasks` 的响应
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TaskListResponse {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub phase: TransferPhase,
    pub tasks: Vec<TaskReceipt>,
}

// ============================================================
// POST /api/v4/session/abort
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AbortRequest {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// 中止原因，用于 UI 提示
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
