//! 清单与同步的 V4 DTO
//!
//! 端点：
//! - `GET  /api/v4/manifest`        备份清单
//! - `GET  /api/v4/chunk-status`    块状态查询
//! - `POST /api/v4/sync-dir`        目录映射同步
//! - `POST /api/v4/move-to-delete`  移到待删（假删除）
//! - `POST /api/v4/disconnect`      断开连接

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::handshake::PairingState;
use super::Presence;

// ============================================================
// 增量策略
// ============================================================

/// 同步策略。
///
/// **archive（默认）只增不删**：对端已删除的文件不自动补回 ——
/// 删除视为用户的有意行为，只告警不复活。
/// 备份工具若复活用户手动删掉的文件，用户就永远删不掉东西了。
///
/// **mirror 完整镜像**：补传全部对端缺失，并清理对端多余文件。
/// 删除语义有风险，**必须由用户显式开启**。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SyncStrategy {
    /// 只增不删（默认）
    #[default]
    Archive,
    /// 完整镜像，含删除语义
    Mirror,
}

// ============================================================
// 清单
// ============================================================

/// 清单中的单个文件条目。
///
/// **判据是 mtime + size，不是内容哈希** —— 这是刻意的取舍：
/// 手机端 CPU 弱，相册几万文件算内容哈希会把扫描从秒级拖到分钟级
/// （原 `sync.ts:5`）。
///
/// 已知限制：同 path 同 size 但内容损坏的文件无法用 size 检出。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ManifestEntry {
    pub size: u64,
    /// 修改时间（**毫秒**，与 shared-core 一致）
    pub mtime: i64,
}

/// 备份清单。
///
/// **相对路径已归一化**：统一 `/` 分隔，去掉开头 `./` 与结尾 `/`。
/// 平台层可能返回 `.\sub\file.txt` 或 `dir\`，不归一化会让同一文件
/// 在清单里出现多个 key（原 `manifest.ts:43-51`）。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Manifest {
    /// 清单版本号
    pub version: u32,
    /// 生成时间戳（**秒**，与 golden 文件一致）
    #[serde(rename = "generatedAt")]
    pub generated_at: i64,
    /// 所属设备的公开 deviceId。
    ///
    /// **M2：这里绝不是连接码！** `deviceCode` 是历史命名，线格式为了兼容
    /// 旧协议保留 `deviceCode` 键名，但**值只能是设备公开指纹**。连接码是
    /// 加密密钥材料，一旦进任何响应体就会被局域网嗅探者拿到明文密钥。
    /// 平台层调用 `build_manifest` 时若把连接码传进来，此处是最后一道防线。
    #[serde(rename = "deviceCode")]
    pub device_id: String,
    /// 相对路径 → 条目
    pub files: std::collections::HashMap<String, ManifestEntry>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            version: 1,
            generated_at: 0,
            device_id: String::new(),
            files: std::collections::HashMap::new(),
        }
    }
}

// ============================================================
// 三路对比的结果分类
// ============================================================

/// 三路对比（A 当前 / A 上次快照 / B 当前）的传输集合。
///
/// 三类语义不同，处置策略也不同：
/// - `added`   —— A 新增
/// - `changed` —— A 修改过
/// - `residual`—— **B 端存在但 size 不一致** = 残留/损坏/部分传输
///
/// `residual` 单独拎出来当"变更"处理是关键：只按"存在与否"判断，
/// 上次传输中断留下的半截文件永远不会被修复（原 `sync.ts:97-100`）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SyncPlan {
    /// A 端新增
    pub added: Vec<String>,
    /// A 端变更
    pub changed: Vec<String>,
    /// B 端有但 size 不一致（残留/损坏）
    pub residual: Vec<String>,
    /// archive 策略下的自愈补全：
    /// **只补上次快照里存在过**的对端缺失文件 —— 之前备份过、
    /// 对端误删的重新推送；从未备份过的仍不补，尊重"只增不删"。
    #[serde(rename = "healMissing")]
    pub heal_missing: Vec<String>,
    /// B 端已删除但 A 端仍在（archive 下仅告警，mirror 下补回）
    #[serde(rename = "absentOnPeer")]
    pub absent_on_peer: Vec<String>,
    /// mirror 策略下 B 端多余、需清理的文件。
    ///
    /// **注意**：生成时必须排除 `delete/` 与 `delete\` 前缀 ——
    /// moveToDelete 后文件仍留在 delete 文件夹，若仍算"对端多余"
    /// 会导致镜像模式**无限弹确认框**（原 `sync.ts:131-137`，实测问题5）。
    #[serde(rename = "peerExtra")]
    pub peer_extra: Vec<String>,
}

// ============================================================
// GET /api/v4/chunk-status
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ChunkStatusResponse {
    /// 已收到的块索引
    #[serde(rename = "receivedChunks")]
    pub received_chunks: Vec<u64>,
    /// **第一个缺失块的索引**（不是已收块数）。
    ///
    /// 三代实现的 Java 侧返回 `chunks.length()`，与 golden 语义
    /// （第一个缺失片）漂移，会导致发送端跳片。
    #[serde(rename = "nextChunk")]
    pub next_chunk: u64,
    /// 文件是否已完整。
    ///
    /// Java 侧此字段恒为 false，从不告诉对端"文件已完整"。
    #[serde(rename = "fileComplete")]
    pub file_complete: bool,
}

// ============================================================
// POST /api/v4/sync-dir
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SyncDirRequest {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    /// 本机备份根目录标识
    #[serde(rename = "rootId")]
    pub root_id: String,
    /// 对端应使用的接收目录名
    #[serde(rename = "targetDir")]
    pub target_dir: String,
    pub strategy: SyncStrategy,
}

// ============================================================
// POST /api/v4/move-to-delete
// ============================================================

/// 假删除请求。
///
/// 不真删，移到 `delete/` 目录 —— 误删不可逆，镜像模式的删除必须是假的。
///
/// **Android 实现注意**：SAF 没有跨目录 rename，必须用"复制 + 删除"实现
/// （原 `LocalReceiverPlugin.java:1642-1693`）。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MoveToDeleteRequest {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    /// 相对路径列表
    #[serde(rename = "relPaths")]
    pub rel_paths: Vec<String>,
}

// ============================================================
// POST /api/v4/disconnect
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DisconnectRequest {
    #[serde(rename = "deviceId")]
    pub device_id: String,
}

// ============================================================
// 响应 DTO（WB-0415/0425/0435：响应必须有 schema，不得手写 json! 漂移）
// ============================================================

/// `POST /api/v4/sync-dir` 响应：映射登记结果 + 本端清单（发起端一次往返跑三路对比）。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SyncDirResponse {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "rootId")]
    pub root_id: String,
    /// 归一化并通过路径闸后的接收目录名
    #[serde(rename = "targetDir")]
    pub target_dir: String,
    pub strategy: SyncStrategy,
    #[serde(rename = "peerManifest")]
    pub peer_manifest: Manifest,
}

/// `POST /api/v4/move-to-delete` 响应：**逐路径**结果。
///
/// 一批里既有能搬的、也有本端没有的、还有被路径闸拒绝的 —— 三类必须分开，
/// "全成功/全失败"会让对端无从判断该重试哪些（WB-0425）。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MoveToDeleteResponse {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    /// 已搬入 `delete/` 的墓碑路径
    pub moved: Vec<String>,
    /// 幂等重放（已在 `delete/`）或本端清单里不存在的路径
    pub skipped: Vec<String>,
    /// 路径闸拒绝或磁盘搬移失败的路径
    pub rejected: Vec<String>,
}

/// `POST /api/v4/disconnect` 响应。
///
/// `pairingState` 明确回传"断开不动配对"—— 收到 `revoked` 才意味着配对没了。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DisconnectResponse {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "pairingState")]
    pub pairing_state: PairingState,
    pub presence: Presence,
    #[serde(rename = "abortedSessions")]
    pub aborted_sessions: Vec<String>,
}
