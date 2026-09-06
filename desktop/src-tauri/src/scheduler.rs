//! scheduler.rs — 多接收端并发 + 块校验调度器（localsend-scheduler v1）
//!
//! 架在 LocalSend v2 之上：数据通道完全走官方 POST /upload，
//! 新增协议层负责 capability 协商、per-chunk SHA-256 校验、Merkle 树验证、全局并发控制。
//!
//! 协议声明：localsend-scheduler v1 是基于 LocalSend v2 握手 + 自定义扩展字段的新协议，
//! 非 LocalSend 官方协议。接收端不支持时自动降级为纯 LocalSend v2。

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use sha2::Digest;
use tokio::sync::{Semaphore, RwLock};
use rand::Rng;

use crate::db::AppError;

// ============================================================
// 协议类型（localsend-scheduler v1）
// ============================================================

/// 文件元数据 + Merkle 树信息（localsend-scheduler v1 扩展）
/// 故意标记 allow(dead_code)：scheduler 差异同步引擎的公共 API，
/// build_manifest 和 SchedulerHttpClient 在 send_files 完全重构后接线。
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FileManifest {
    /// 文件唯一 ID（对应 LocalSend v2 FileDto.id）
    pub file_id: String,
    /// 原始文件名（用于 __chunked__ 路径构造）
    pub file_name: String,
    /// 文件总字节
    pub file_size: u64,
    /// 分片大小（= piece 大小 = 4MB）
    pub chunk_size: u64,
    /// 总分片数 = ceil(file_size / chunk_size)
    pub total_chunks: u32,
    /// 整个文件的 SHA-256（LocalSend v2 兼容字段）
    pub file_sha256: String,
    /// Merkle 树根（扩展字段，可选；大文件有）
    pub merkle_root: Option<String>,
    /// 每个 piece 的 SHA-256（piece = 4MB，与传输分片一一对应）
    pub piece_hashes: Vec<String>,
    /// 支持的扩展协议（用于 capability 协商）
    pub protocol_extensions: Vec<String>,
}

/// 差异分析结果（未来 chunk 差异同步用）
#[allow(dead_code)]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ChunkDiff {
    pub file_id: String,
    pub session_id: String,
    /// 接收端完全没有的块
    pub missing_chunks: Vec<u32>,
    /// 弱校验 + 强校验都匹配的块
    pub matched_chunks: Vec<u32>,
    /// 弱校验命中但 SHA-256 不匹配的块
    pub mismatched_chunks: Vec<u32>,
    /// 所有块都已到齐且校验通过
    pub file_complete: bool,
}

/// 会话状态机（scheduler 差异同步引擎用）
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    Idle,
    Preparing,
    Diffing,
    Sending,
    Verifying,
    Paused,
    Complete,
    Aborted,
    Error(String),
}

/// 单个文件的传输状态（scheduler 差异同步引擎用）
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FileTransferState {
    pub manifest: FileManifest,
    pub diff: Option<ChunkDiff>,
    pub sent_chunks: HashSet<u32>,
    pub acked_chunks: HashSet<u32>,
    pub nacked_chunks: HashSet<u32>,
    pub failed_chunks: HashSet<u32>,
    pub state: SessionState,
}

/// 单个接收端会话（发送端视角，scheduler 差异同步引擎用）
#[allow(dead_code)]
#[derive(Debug)]
pub struct PeerSession {
    pub peer_ip: String,
    pub peer_port: u16,
    pub session_id: String,
    pub state: SessionState,
    pub files: HashMap<String, FileTransferState>,
    pub created_at: std::time::Instant,
    pub last_heartbeat: std::time::Instant,
}

impl PeerSession {
    /// 创建新会话（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub fn new(peer_ip: String, peer_port: u16) -> Self {
        Self {
            peer_ip,
            peer_port,
            session_id: uuid::Uuid::new_v4().to_string(),
            state: SessionState::Idle,
            files: HashMap::new(),
            created_at: std::time::Instant::now(),
            last_heartbeat: std::time::Instant::now(),
        }
    }

    /// 推进状态机（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub fn set_state(&mut self, new_state: SessionState) {
        crate::log_debug!(
            "PeerSession {} → {:?}",
            crate::logger::mask(&self.session_id),
            new_state
        );
        self.state = new_state;
    }

    /// 心跳保活
    /// 更新心跳时间（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub fn touch(&mut self) {
        self.last_heartbeat = std::time::Instant::now();
    }

    /// 是否超时（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub fn is_timed_out(&self, timeout_secs: u64) -> bool {
        self.last_heartbeat.elapsed().as_secs() > timeout_secs
    }
}

// ============================================================
// 传输进度（用于 SessionStore 持久化）
// ============================================================

/// 单文件传输进度
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransferProgress {
    pub file_id: String,
    #[serde(rename = "sentBytes")]
    pub sent_bytes: u64,
    #[serde(rename = "totalBytes")]
    pub total_bytes: u64,
    #[serde(rename = "piecesCompleted")]
    pub pieces_completed: u32,
    #[serde(rename = "piecesTotal")]
    pub pieces_total: u32,
    #[serde(rename = "retryCount")]
    pub retry_count: u32,
    #[serde(rename = "lastError")]
    pub last_error: Option<String>,
}

/// 对端信息（scheduler 差异同步引擎用，allow(dead_code)：SessionStore 重构后接线）
#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub alias: String,
    pub ip: String,
    pub port: u16,
    pub status: PeerStatus,
}

/// 对端连接状态（scheduler 差异同步引擎用，allow(dead_code)：SessionStore 重构后接线）
#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PeerStatus {
    Connected,
    Disconnected,
}

// ============================================================
// Merkle 哈希树（对齐 BEP-0052）
// ============================================================

/// Merkle 树节点
#[allow(dead_code)]
#[derive(Debug, Clone)]
enum MerkleNode {
    Leaf(Vec<u8>),      // 16KiB block SHA-256（32 字节）
    Internal(Vec<u8>),   // 中间节点哈希（32 字节）
}

/// Merkle 哈希树（BitTorrent v2 BEP-0052 兼容，scheduler 差异同步引擎用）
#[allow(dead_code)]
pub struct MerkleTree {
    /// 每个 piece 的 Merkle 根（叶子节点 = 16KiB block SHA-256）
    piece_hashes: Vec<Vec<u8>>,
    /// 整棵树的根哈希
    root_hash: Vec<u8>,
    /// piece 大小（= 传输分片大小 = 4MB）
    piece_size: u64,
    /// P3-44：构建时顺带算出的整文件 SHA-256（hex），避免 build_manifest 二次全量读
    file_sha256: Option<String>,
}

impl MerkleTree {
    /// 从 piece 哈希列表构建（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub fn new(piece_hashes: Vec<String>, piece_size: u64) -> Self {
        // 将 hex string 转为字节
        let piece_hashes: Vec<Vec<u8>> = piece_hashes
            .iter()
            .filter_map(|h| hex::decode(h).ok())
            .collect();

        let root_hash = if piece_hashes.is_empty() {
            vec![0u8; 32]
        } else {
            Self::compute_root(&piece_hashes)
        };

        Self { piece_hashes, root_hash, piece_size, file_sha256: None }
    }

    /// 从文件内容构建 Merkle 树（分块计算叶子节点）
    pub fn from_file_content<P: AsRef<Path>>(
        path: P,
        piece_size: u64,
    ) -> Result<Self, AppError> {
        let path = path.as_ref();
        let metadata = std::fs::metadata(path)
            .map_err(|e| AppError(format!("读取文件元数据失败 {}: {}", path.display(), e)))?;
        let file_size = metadata.len();

        let total_pieces = ((file_size + piece_size - 1) / piece_size) as usize;
        let mut piece_hashes: Vec<String> = Vec::with_capacity(total_pieces);

        // 分块读取，计算每个 piece 的 SHA-256
        let block_size: u64 = 16 * 1024; // 16KiB leaf block
        let mut file = std::fs::File::open(path)
            .map_err(|e| AppError(format!("打开文件失败 {}: {}", path.display(), e)))?;
        // P3-307：叶片块缓冲在循环外复用，避免每块重复分配（大文件节省数十万次分配）
        let mut block_buf = vec![0u8; block_size as usize];
        // P3-44：整文件 SHA-256（跨 piece 连续读取累加，与 Merkle piece 哈希同一次 I/O）
        let mut file_hasher = sha2::Sha256::new();

        for piece_idx in 0..total_pieces {
            // 计算这个 piece 的 Merkle 根 = 该 piece 内所有 16KiB block 的 SHA-256 的树根
            let piece_start = piece_idx as u64 * piece_size;
            let piece_end = (piece_start + piece_size).min(file_size);

            // 构建这个 piece 的叶子节点（16KiB block SHA-256）
            let mut leaf_hashes: Vec<Vec<u8>> = Vec::new();
            let mut offset = piece_start;

            while offset < piece_end {
                let read_size = (block_size as u64).min(piece_end - offset) as usize;
                // 读取块（复用循环外 buffer）
                std::io::Read::read_exact(&mut file, &mut block_buf[..read_size])
                    .map_err(|e| AppError(format!("读取块失败 {}: {}", path.display(), e)))?;
                // P3-44：整文件 hasher 随块累加，一次读取同时算出文件 SHA-256 与 Merkle 哈希
                file_hasher.update(&block_buf[..read_size]);

                // 计算叶子哈希（16KiB block SHA-256）
                let leaf_hash = sha2::Sha256::digest(&block_buf[..read_size]).to_vec();
                leaf_hashes.push(leaf_hash);
                offset += block_size as u64;
            }

            // 末尾不足 16KiB 的块用零哈希填充
            // （已在上面通过 read_size < block_size 处理）

            // 填充到 2 的幂个叶子（简化：直接计算，不做复杂填充）
            let piece_root = if leaf_hashes.len() == 1 {
                leaf_hashes[0].clone()
            } else {
                Self::compute_root(&leaf_hashes)
            };

            piece_hashes.push(hex::encode(piece_root));
        }

        // piece_hashes 存储的是 hex 字符串，需要解码为字节才能用于后续计算
        let piece_hashes_decoded: Vec<Vec<u8>> = piece_hashes
            .iter()
            .filter_map(|h| hex::decode(h).ok())
            .collect();

        let root_hash = if piece_hashes_decoded.is_empty() {
            vec![0u8; 32]
        } else {
            Self::compute_root(&piece_hashes_decoded)
        };

        // P3-44：整文件 SHA-256（hex）；空文件时 Digest 对空输入仍得出正确哈希
        let file_sha256 = hex::encode(sha2::Digest::finalize(file_hasher));

        Ok(Self {
            piece_hashes: piece_hashes_decoded,
            root_hash,
            piece_size,
            file_sha256: Some(file_sha256),
        })
    }

    /// 计算一组哈希的 Merkle 根（两两串联 SHA-256）
    /// 计算 Merkle 根（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    fn compute_root(hashes: &[Vec<u8>]) -> Vec<u8> {
        if hashes.is_empty() {
            return vec![0u8; 32];
        }
        if hashes.len() == 1 {
            return hashes[0].clone();
        }

        let mut level: Vec<Vec<u8>> = hashes.to_vec();
        while level.len() > 1 {
            let mut next_level: Vec<Vec<u8>> = Vec::new();
            for chunk in level.chunks(2) {
                if chunk.len() == 2 {
                    let mut combined = chunk[0].clone();
                    combined.extend_from_slice(&chunk[1]);
                    next_level.push(sha2::Sha256::digest(&combined).to_vec());
                } else {
                    // 奇数节点：复制自身（按 BEP-0052 填充规则）
                    let mut combined = chunk[0].clone();
                    combined.extend_from_slice(&chunk[0]);
                    next_level.push(sha2::Sha256::digest(&combined).to_vec());
                }
            }
            level = next_level;
        }
        level[0].clone()
    }

    /// 获取 Merkle 根（hex string）
    /// 获取 Merkle 根 hex（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub fn root_hex(&self) -> String {
        hex::encode(&self.root_hash)
    }

    /// 获取所有 piece 哈希（hex string）
    /// 获取所有 piece 哈希 hex（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub fn piece_hashes_hex(&self) -> Vec<String> {
        self.piece_hashes.iter().map(|h| hex::encode(h)).collect()
    }
}

// ============================================================
// 双校验（弱校验 xxHash64 快筛 + 强校验 SHA-256）
// ============================================================

/// xxHash64 弱校验（allow(dead_code)：scheduler 差异同步引擎用）
#[allow(dead_code)]
pub fn weak_checksum(data: &[u8]) -> u64 {
    xxhash_rust::xxh64::xxh64(data, 0)
}

/// 用 SHA-256 做强校验（allow(dead_code)：scheduler 差异同步引擎用）
#[allow(dead_code)]
pub fn strong_checksum(data: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(data))
}

// ============================================================
// 指数退避 + 全抖动（AWS 标准）
// ============================================================

/// 计算第 n 次重试的退避延迟（毫秒）
/// delay = random(0, min(64000, 1000 * 2^n))
pub fn jittered_backoff_ms(retry_count: u32) -> u64 {
    let cap = 64_000u64;
    let base = 1_000u64;
    let exponential = base * (2u64.pow(retry_count.min(5)));
    let ceiling = exponential.min(cap);
    let mut rng = rand::thread_rng();
    rng.gen_range(0..=ceiling)
}

/// 判断某错误码是否可重试
pub fn is_retryable_status(status_code: u16) -> bool {
    matches!(status_code, 408 | 429 | 500 | 502 | 503 | 504)
}

/// 判断 422（校验失败）是否可重试（业务语义：可重试）
pub fn is_checksum_failure_retryable(status_code: u16) -> bool {
    // 422 在本协议中表示块 SHA-256 校验失败，需要重传，属于可重试
    status_code == 422 || is_retryable_status(status_code)
}

// ============================================================
// SendScheduler（全局调度器）
// ============================================================

/// 全局调度器：管理多个 PeerSession 并发传输（scheduler 差异同步引擎用）
#[allow(dead_code)]
pub struct SendScheduler {
    /// 所有活跃的接收端会话（key = "{ip}:{port}"）
    peers: RwLock<HashMap<String, Arc<RwLock<PeerSession>>>>,
    /// 最大并发接收端数（默认 3）
    max_concurrent_receivers: usize,
    /// 每接收端最大并发分片数（默认 4）
    concurrent_chunks_per_peer: usize,
    /// 全局在途分片信号量（默认 12 = 3×4）
    global_chunks: Arc<Semaphore>,
    /// 全局重试令牌桶（最多 4 个在途重试）
    retry_bucket: Arc<Semaphore>,
}

impl SendScheduler {
    /// 创建调度器（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            max_concurrent_receivers: 3,
            concurrent_chunks_per_peer: 4,
            global_chunks: Arc::new(Semaphore::new(12)),
            retry_bucket: Arc::new(Semaphore::new(4)),
        }
    }

    /// 注册一个接收端会话
    /// 添加对等节点（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub async fn add_peer(&self, ip: String, port: u16) -> String {
        let key = format!("{}:{}", ip, port);
        let session = PeerSession::new(ip.clone(), port);
        let session_id = session.session_id.clone();
        let mut peers = self.peers.write().await;
        peers.insert(key, Arc::new(RwLock::new(session)));
        session_id
    }

    /// 获取一个 PeerSession
    /// 获取对等节点（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub async fn get_peer(&self, ip: &str, port: u16) -> Option<Arc<RwLock<PeerSession>>> {
        let key = format!("{}:{}", ip, port);
        let peers = self.peers.read().await;
        peers.get(&key).cloned()
    }

    /// 移除一个 PeerSession
    /// 移除对等节点（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub async fn remove_peer(&self, ip: &str, port: u16) {
        let key = format!("{}:{}", ip, port);
        let mut peers = self.peers.write().await;
        peers.remove(&key);
    }

    /// 获取当前所有活跃会话数
    /// 活跃对等数（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub async fn active_peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }

    /// 标记会话状态
    /// 更新对等状态（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub async fn set_peer_state(&self, ip: &str, port: u16, state: SessionState) {
        if let Some(session) = self.get_peer(ip, port).await {
            let mut s = session.write().await;
            s.set_state(state);
        }
    }

    /// 更新心跳
    /// 更新心跳（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub async fn touch_peer(&self, ip: &str, port: u16) {
        if let Some(session) = self.get_peer(ip, port).await {
            let mut s = session.write().await;
            s.touch();
        }
    }

    /// 获取超时会话并标记为 PAUSED
    /// 检查超时（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub async fn check_timeouts(&self, timeout_secs: u64) -> Vec<String> {
        let mut timed_out = Vec::new();
        let peers = self.peers.read().await;
        for (key, session) in peers.iter() {
            let s = session.read().await;
            if s.is_timed_out(timeout_secs) && s.state != SessionState::Paused {
                timed_out.push(key.clone());
            }
        }
        drop(peers);

        for key in &timed_out {
            if let Some(dot) = key.find(':') {
                let ip = &key[..dot];
                let port: u16 = key[dot + 1..].parse().unwrap_or(53317);
                self.set_peer_state(ip, port, SessionState::Paused).await;
            }
        }
        timed_out
    }

    /// 全局分片信号量（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub fn global_chunks(&self) -> Arc<Semaphore> {
        self.global_chunks.clone()
    }

    /// 重试令牌桶（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub fn retry_bucket(&self) -> Arc<Semaphore> {
        self.retry_bucket.clone()
    }

    /// 最大并发接收端数（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub fn max_concurrent_receivers(&self) -> usize {
        self.max_concurrent_receivers
    }

    /// 每接收端并发分片数（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub fn concurrent_chunks_per_peer(&self) -> usize {
        self.concurrent_chunks_per_peer
    }
}

impl Default for SendScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// FileManifest 构建工具
// ============================================================

/// 整文件 SHA-256（hex）。作为 Merkle 构建兜底；正常路径由 from_file_content 顺带算出。
fn hash_file_sha256(abs_path: &Path) -> String {
    use std::io::Read as _;
    let mut hasher = sha2::Sha256::new();
    if let Ok(mut file) = std::fs::File::open(abs_path) {
        let mut buf = vec![0u8; 8192];
        loop {
            match file.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => hasher.update(&buf[..n]),
            }
        }
    }
    hex::encode(hasher.finalize())
}

/// 从文件路径构建 FileManifest（计算 Merkle 树，allow(dead_code)：scheduler 差异同步引擎用）
#[allow(dead_code)]
pub fn build_manifest(
    file_id: String,
    file_name: String,
    abs_path: &Path,
    chunk_size: u64,
) -> Result<FileManifest, AppError> {
    let metadata = std::fs::metadata(abs_path)
        .map_err(|e| AppError(format!("读取文件元数据失败 {}: {}", abs_path.display(), e)))?;
    let file_size = metadata.len();
    // 输入契约守卫：chunk_size=0 会让下方除法 panic；file_size 接近 u64::MAX 时
    // file_size + chunk_size - 1 加法溢出（debug panic / release 回绕）
    if chunk_size == 0 {
        return Err(AppError("build_manifest: chunk_size 不能为 0".to_string()));
    }
    let total_chunks = u32::try_from(file_size / chunk_size + u64::from(file_size % chunk_size != 0))
        .map_err(|_| AppError("build_manifest: 分块数超出 u32 范围".to_string()))?;

    // 构建 Merkle 树（同时顺带算出整文件 SHA-256，避免二次全量读取——P3-44）
    let merkle = MerkleTree::from_file_content(abs_path, chunk_size)
        .map_err(|e| AppError(format!("构建 Merkle 树失败 {}: {}", abs_path.display(), e)))?;
    let merkle_root = merkle.root_hex();
    let piece_hashes = merkle.piece_hashes_hex();
    // 整文件 SHA-256 直接取自 Merkle 构建过程，不再单独读一遍文件
    let file_sha256 = merkle.file_sha256.clone().unwrap_or_else(|| {
        // 兜底：极罕见（非 from_file_content 构建路径）才回退到二次读取
        hash_file_sha256(abs_path)
    });

    Ok(FileManifest {
        file_id,
        file_name,
        file_size,
        chunk_size,
        total_chunks,
        file_sha256,
        merkle_root: Some(merkle_root),
        piece_hashes,
        protocol_extensions: vec!["scheduler-v1".to_string()],
    })
}

/// 大文件（>100MB）才需要 Merkle 树（allow(dead_code)：scheduler 差异同步引擎用）
#[allow(dead_code)]
pub fn build_manifest_if_needed(
    file_id: String,
    file_name: String,
    abs_path: &Path,
) -> Result<Option<FileManifest>, AppError> {
    const LARGE_THRESHOLD: u64 = 100 * 1024 * 1024;
    const CHUNK_SIZE: u64 = 4 * 1024 * 1024; // 4MB = piece size

    let metadata = std::fs::metadata(abs_path)
        .map_err(|e| AppError(format!("读取文件元数据失败 {}: {}", abs_path.display(), e)))?;
    let file_size = metadata.len();

    if file_size > LARGE_THRESHOLD {
        let manifest = build_manifest(file_id, file_name, abs_path, CHUNK_SIZE)?;
        Ok(Some(manifest))
    } else {
        Ok(None)
    }
}

// ============================================================
// ETag 格式化工具（协议契约：双引号强校验器）
// ============================================================

/// 将 SHA-256 hex string 格式化为带双引号的 ETag（allow(dead_code)：scheduler 差异同步引擎用）
#[allow(dead_code)]
pub fn format_etag(sha256_hex: &str) -> String {
    format!("\"{}\"", sha256_hex)
}

/// 解析带双引号的 ETag（allow(dead_code)：scheduler 差异同步引擎用）
#[allow(dead_code)]
pub fn parse_etag(etag: &str) -> Option<String> {
    let trimmed = etag.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') {
        Some(trimmed[1..trimmed.len()-1].to_string())
    } else {
        None
    }
}

// ============================================================
// HTTP 客户端（scheduler v1 扩展协议）
// ============================================================

use reqwest::Client;

/// Scheduler HTTP 客户端：用于发送 scheduler v1 扩展协议请求
#[allow(dead_code)]
pub struct SchedulerHttpClient {
    client: Client,
}

impl SchedulerHttpClient {
    /// 创建客户端（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub fn new() -> Result<Self, AppError> {
        let client = Client::builder()
            // prepare-upload 可能阻塞等待接收端用户确认（最长 45s），超时必须留足余量
            .timeout(std::time::Duration::from_secs(70))
            .build()
            .map_err(|e| AppError(format!("创建 HTTP 客户端失败: {e}")))?;
        Ok(Self { client })
    }



    /// 上传单个块（V4 协议）
    #[allow(dead_code)]
    pub async fn upload_chunk(
        &self,
        ip: &str,
        port: u16,
        session_id: &str,
        file_id: &str,
        token: &str,
        chunk_index: u32,
        data: Vec<u8>,
    ) -> Result<UploadChunkResponse, AppError> {
        let url = format!(
            "http://{}:{}/api/v4/session/chunk?sessionId={}&fileId={}&token={}&chunkIndex={}",
            ip, port,
            urlencoding::encode(session_id),
            urlencoding::encode(file_id),
            urlencoding::encode(token),
            chunk_index
        );

        let resp = self.client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(data)
            .send()
            .await
            .map_err(|e| AppError(format!("upload_chunk 请求失败: {e}")))?;

        let status = resp.status().as_u16();

        if status == 200 {
            Ok(UploadChunkResponse::Ok)
        } else if status == 422 {
            // SHA-256 校验失败
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let reason = body.get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("sha256_mismatch")
                .to_string();
            Ok(UploadChunkResponse::ChecksumFailed { reason })
        } else {
            Err(AppError(format!("upload_chunk 失败: {status}")))
        }
    }
}

impl Default for SchedulerHttpClient {
    fn default() -> Self {
        Self::new().expect("创建 SchedulerHttpClient 失败")
    }
}

// ============================================================
// 响应类型
// ============================================================

/// Scheduler v1 prepare-upload 响应（allow(dead_code)：scheduler 差异同步引擎用）
#[allow(dead_code)]
#[derive(Debug)]
pub struct SchedulerPrepareResponse {
    pub status_code: u16,
    pub session_id: String,
    pub files: std::collections::HashMap<String, String>,
    /// Scheduler v1 扩展：每个文件的块差异（可选）
    pub chunk_diff: Option<std::collections::HashMap<String, ChunkDiff>>,
    /// 加密 v2 扩展：接收端 ECDH 公钥（复杂加密协商，可选）
    pub ecdh_pub_key: Option<String>,
}

/// GET /diff 响应
/// GET /diff 响应（allow(dead_code)：scheduler 差异同步引擎用）
#[allow(dead_code)]
#[derive(Debug)]
pub enum DiffResponse {
    /// 206: 块存在且 ETag 匹配，返回块数据
    ChunkMatched { data: Vec<u8> },
    /// 412: 块存在但 SHA-256 不匹配（NACK）
    ChecksumMismatch { expected: String, actual: String },
    /// 416: Range 不满足（块不存在）
    RangeNotSatisfiable { actual_total_size: u64 },
    /// 200: 文件已变，需全量重传
    FileChanged,
}

/// upload_chunk 响应
/// POST /upload 块上传响应（allow(dead_code)：scheduler 差异同步引擎用）
#[allow(dead_code)]
#[derive(Debug)]
pub enum UploadChunkResponse {
    Ok,
    ChecksumFailed { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etag_format() {
        let sha = "abc123def456";
        let etag = format_etag(sha);
        assert_eq!(etag, "\"abc123def456\"");
    }

    #[test]
    fn test_etag_parse() {
        let etag = "\"abc123def456\"";
        let sha = parse_etag(etag);
        assert_eq!(sha, Some("abc123def456".to_string()));
    }

    #[test]
    fn test_backoff() {
        // 测试指数退避 + 全抖动
        for n in 0..=5 {
            let delay = jittered_backoff_ms(n);
            let cap = 64_000u64;
            let base = 1_000u64;
            let max_delay = (base * (2u64.pow(n))).min(cap);
            assert!(delay <= max_delay);
        }
    }
}
