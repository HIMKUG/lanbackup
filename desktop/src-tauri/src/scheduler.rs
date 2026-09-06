use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use sha2::Digest;
use tokio::sync::{Semaphore, RwLock};
use rand::Rng;

use reqwest::Client;

use crate::db::AppError;

#[derive(Debug, Clone)]
pub struct FileManifest {
    pub file_id: String,
    pub file_name: String,
    pub file_size: u64,
    pub chunk_size: u64,
    pub total_chunks: u32,
    pub file_sha256: String,
    pub merkle_root: Option<String>,
    pub piece_hashes: Vec<String>,
    pub protocol_extensions: Vec<String>,
}

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

#[derive(Debug, Clone)]
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

    pub fn set_state(&mut self, new_state: SessionState) {
        self.state = new_state;
    }

    pub fn touch(&mut self) {
        self.last_heartbeat = std::time::Instant::now();
    }

    pub fn is_timed_out(&self, timeout_secs: u64) -> bool {
        self.last_heartbeat.elapsed().as_secs() > timeout_secs
    }
}

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

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ChunkDiff {
    pub file_id: String,
    pub session_id: String,
    pub missing_chunks: Vec<u32>,
    pub matched_chunks: Vec<u32>,
    pub mismatched_chunks: Vec<u32>,
    pub file_complete: bool,
}

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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub alias: String,
    pub ip: String,
    pub port: u16,
    pub status: PeerStatus,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PeerStatus {
    Connected,
    Disconnected,
}

enum MerkleNode {
    Leaf(Vec<u8>),
    Internal(Vec<u8>),
}

pub struct MerkleTree {
    piece_hashes: Vec<Vec<u8>>,
    root_hash: Vec<u8>,
    piece_size: u64,
    file_sha256: Option<String>,
}

impl MerkleTree {
    pub fn new(piece_hashes: Vec<String>, piece_size: u64) -> Self {
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

        let block_size: u64 = 16 * 1024;
        let mut file = std::fs::File::open(path)
            .map_err(|e| AppError(format!("打开文件失败 {}: {}", path.display(), e)))?;
        let mut block_buf = vec![0u8; block_size as usize];
        let mut file_hasher = sha2::Sha256::new();

        for piece_idx in 0..total_pieces {
            let piece_start = piece_idx as u64 * piece_size;
            let piece_end = (piece_start + piece_size).min(file_size);

            let mut leaf_hashes: Vec<Vec<u8>> = Vec::new();
            let mut offset = piece_start;

            while offset < piece_end {
                let read_size = (block_size as u64).min(piece_end - offset) as usize;
                std::io::Read::read_exact(&mut file, &mut block_buf[..read_size])
                    .map_err(|e| AppError(format!("读取块失败 {}: {}", path.display(), e)))?;
                file_hasher.update(&block_buf[..read_size]);

                let leaf_hash = sha2::Sha256::digest(&block_buf[..read_size]).to_vec();
                leaf_hashes.push(leaf_hash);
                offset += block_size as u64;
            }

            let piece_root = if leaf_hashes.len() == 1 {
                leaf_hashes[0].clone()
            } else {
                Self::compute_root(&leaf_hashes)
            };

            piece_hashes.push(hex::encode(piece_root));
        }

        let file_sha256 = Some(hex::encode(file_hasher.finalize()));

        let root_hash = if piece_hashes.is_empty() {
            vec![0u8; 32]
        } else {
            let decoded: Vec<Vec<u8>> = piece_hashes
                .iter()
                .filter_map(|h| hex::decode(h).ok())
                .collect();
            Self::compute_root(&decoded)
        };

        let decoded_piece_hashes: Vec<Vec<u8>> = piece_hashes
            .iter()
            .filter_map(|h| hex::decode(h).ok())
            .collect();

        Ok(Self {
            piece_hashes: decoded_piece_hashes,
            root_hash,
            piece_size,
            file_sha256,
        })
    }

    fn compute_root(hashes: &[Vec<u8>]) -> Vec<u8> {
        if hashes.is_empty() {
            return vec![0u8; 32];
        }

        let mut level: Vec<Vec<u8>> = hashes.to_vec();
        while level.len() > 1 {
            let next_len = (level.len() + 1) / 2;
            let mut next: Vec<Vec<u8>> = Vec::with_capacity(next_len);
            for chunk in level.chunks(2) {
                if chunk.len() == 2 {
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(&chunk[0]);
                    hasher.update(&chunk[1]);
                    next.push(hasher.finalize().to_vec());
                } else {
                    next.push(chunk[0].clone());
                }
            }
            level = next;
        }

        level.into_iter().next().unwrap_or_else(|| vec![0u8; 32])
    }

    pub fn root_hex(&self) -> String {
        hex::encode(&self.root_hash)
    }

    pub fn piece_hashes_hex(&self) -> Vec<String> {
        self.piece_hashes.iter().map(|h| hex::encode(h)).collect()
    }
}

pub fn jittered_backoff_ms(retry_count: u32) -> u64 {
    let cap = 64_000u64;
    let base = 1_000u64;
    let exponential = base * (2u64.pow(retry_count.min(5)));
    let ceiling = exponential.min(cap);
    let mut rng = rand::thread_rng();
    rng.gen_range(0..=ceiling)
}

pub fn is_retryable_status(status_code: u16) -> bool {
    matches!(status_code, 408 | 429 | 500 | 502 | 503 | 504)
}

pub fn is_checksum_failure_retryable(status_code: u16) -> bool {
    status_code == 422 || is_retryable_status(status_code)
}

pub struct SendScheduler {
    peers: RwLock<HashMap<String, Arc<RwLock<PeerSession>>>>,
    max_concurrent_receivers: usize,
    concurrent_chunks_per_peer: usize,
    global_chunks: Arc<Semaphore>,
    retry_bucket: Arc<Semaphore>,
}

impl SendScheduler {
    pub fn new() -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            max_concurrent_receivers: 3,
            concurrent_chunks_per_peer: 4,
            global_chunks: Arc::new(Semaphore::new(12)),
            retry_bucket: Arc::new(Semaphore::new(4)),
        }
    }

    pub async fn add_peer(&self, ip: String, port: u16) -> String {
        let key = format!("{}:{}", ip, port);
        let session = PeerSession::new(ip.clone(), port);
        let session_id = session.session_id.clone();
        let mut peers = self.peers.write().await;
        peers.insert(key, Arc::new(RwLock::new(session)));
        session_id
    }

    pub async fn get_peer(&self, ip: &str, port: u16) -> Option<Arc<RwLock<PeerSession>>> {
        let key = format!("{}:{}", ip, port);
        let peers = self.peers.read().await;
        peers.get(&key).cloned()
    }

    pub async fn remove_peer(&self, ip: &str, port: u16) {
        let key = format!("{}:{}", ip, port);
        let mut peers = self.peers.write().await;
        peers.remove(&key);
    }

    pub async fn active_peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }

    pub async fn set_peer_state(&self, ip: &str, port: u16, state: SessionState) {
        if let Some(session) = self.get_peer(ip, port).await {
            let mut s = session.write().await;
            s.set_state(state);
        }
    }

    pub async fn touch_peer(&self, ip: &str, port: u16) {
        if let Some(session) = self.get_peer(ip, port).await {
            let mut s = session.write().await;
            s.touch();
        }
    }

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

    pub fn global_chunks(&self) -> Arc<Semaphore> {
        self.global_chunks.clone()
    }

    pub fn retry_bucket(&self) -> Arc<Semaphore> {
        self.retry_bucket.clone()
    }

    pub fn max_concurrent_receivers(&self) -> usize {
        self.max_concurrent_receivers
    }

    pub fn concurrent_chunks_per_peer(&self) -> usize {
        self.concurrent_chunks_per_peer
    }
}

impl Default for SendScheduler {
    fn default() -> Self {
        Self::new()
    }
}

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

pub fn build_manifest(
    file_id: String,
    file_name: String,
    abs_path: &Path,
    chunk_size: u64,
) -> Result<FileManifest, AppError> {
    let metadata = std::fs::metadata(abs_path)
        .map_err(|e| AppError(format!("读取文件元数据失败 {}: {}", abs_path.display(), e)))?;
    let file_size = metadata.len();
    if chunk_size == 0 {
        return Err(AppError("build_manifest: chunk_size 不能为 0".to_string()));
    }
    let total_chunks = u32::try_from(file_size / chunk_size + u64::from(file_size % chunk_size != 0))
        .map_err(|_| AppError("build_manifest: 分块数超出 u32 范围".to_string()))?;

    let merkle = MerkleTree::from_file_content(abs_path, chunk_size)
        .map_err(|e| AppError(format!("构建 Merkle 树失败 {}: {}", abs_path.display(), e)))?;
    let merkle_root = merkle.root_hex();
    let piece_hashes = merkle.piece_hashes_hex();
    let file_sha256 = merkle.file_sha256.clone().unwrap_or_else(|| {
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

#[derive(Debug)]
pub enum UploadChunkResponse {
    Ok,
    ChecksumFailed { reason: String },
}

pub struct SchedulerHttpClient {
    client: Client,
}

impl SchedulerHttpClient {
    pub fn new() -> Result<Self, AppError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(70))
            .build()
            .map_err(|e| AppError(format!("创建 HTTP 客户端失败: {e}")))?;
        Ok(Self { client })
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff() {
        for n in 0..=5 {
            let delay = jittered_backoff_ms(n);
            let cap = 64_000u64;
            let base = 1_000u64;
            let max_delay = (base * (2u64.pow(n))).min(cap);
            assert!(delay <= max_delay);
        }
    }
}
