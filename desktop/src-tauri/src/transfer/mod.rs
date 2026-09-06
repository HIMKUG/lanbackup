//! 传输模块
//!
//! 基于 V4 HTTP 协议，核心接入 lanbackup-core：
//! - DTO 类型使用 core dto::session 定义
//! - 发送端使用 SessionDriver + V4 端点
//! - 接收端使用 core::server::SessionStore 启动 HTTP 服务
//!
//! 模块拆分：
//! - `util`：路径/时间戳/文件类型等通用工具函数
//! - `store`：配对记录持久化（SQLite）与同步
//! - `send`：发送端流程（SessionDriver 驱动）
//! - `receive`：接收端流程（服务器启动 / 事件循环 / 解密合并）

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::sync::Arc;

use futures_util::{StreamExt, TryStreamExt};
use tauri::{AppHandle, Emitter, Manager};
use serde::{Deserialize, Serialize};

use crate::db::AppError;
use crate::identity;
use crate::session_store;

pub mod v3;

mod send;
mod receive;
mod store;
mod util;

pub use send::*;
pub use receive::*;
pub use store::*;
pub use util::*;
pub use v3::*;

pub struct V4ServerHandle {
     pub port: u16,
     stop_tx: tokio::sync::watch::Sender<()>,
     pub stopped: Arc<std::sync::atomic::AtomicBool>,
 }

 impl V4ServerHandle {
     pub fn port(&self) -> u16 {
         self.port
     }
     pub async fn stop(&self) {
        self.stopped.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = self.stop_tx.send(());
    }
 }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct FileDto {
    pub id: String,
    #[serde(rename = "fileName")]
    pub file_name: String,
    pub size: u64,
    #[serde(rename = "fileType")]
    pub file_type: String,
    pub sha256: Option<String>,
    pub preview: Option<String>,
    pub metadata: Option<FileMetadata>,
    #[serde(rename = "protocolExtensions", skip_serializing_if = "Option::is_none")]
    pub protocol_extensions: Option<serde_json::Value>,
    #[serde(rename = "merkleRoot", skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
    #[serde(rename = "pieceHashes", skip_serializing_if = "Option::is_none")]
    pub piece_hashes: Option<Vec<String>>,
    #[serde(rename = "chunkSize", skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct FileMetadata {
    pub modified: Option<String>,
    pub accessed: Option<String>,
}

/// 配对连接并发额度守卫（RAII）
struct PairConnGuard(std::sync::Arc<std::sync::Mutex<u32>>);
impl Drop for PairConnGuard {
    fn drop(&mut self) {
        if let Ok(mut c) = self.0.lock() {
            *c = c.saturating_sub(1);
        }
    }
}

/// 全局传输状态（由 lib.rs 注入）
pub struct TransferState {
    #[allow(dead_code)]
    server: Mutex<Option<Arc<V4ServerHandle>>>,
    #[allow(dead_code)]
    stop_tx: Mutex<Option<tokio::sync::watch::Sender<()>>>,
    pub(crate) receive_dir: Mutex<Option<PathBuf>>,
    pub(crate) pending_receive_approvals: Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>,
    pub(crate) pending_receive_times: Mutex<HashMap<String, std::time::Instant>>,
    pub(crate) pending_pairing_approvals: Mutex<HashMap<String, std::sync::mpsc::Sender<bool>>>,
    #[allow(dead_code)]
    pub(crate) pending_pairing_times: Mutex<HashMap<String, std::time::Instant>>,
    #[allow(dead_code)]
    pairing_listener: Mutex<Option<std::net::TcpListener>>,
    pub(crate) receiver_should_run: AtomicBool,
    pub(crate) receiver_stop_intent: AtomicBool,
    pub(crate) discoverable: AtomicBool,
    pub(crate) defensive_hidden: AtomicBool,
    pub(crate) active_sessions:
        Mutex<HashMap<String, tokio_util::sync::CancellationToken>>,
    #[allow(dead_code)]
    pub(crate) ecdh_session_keys: Mutex<HashMap<String, [u8; 32]>>,
    #[allow(dead_code)]
    pub(crate) v3_sender: Mutex<HashMap<String, String>>,
    #[allow(dead_code)]
    pub(crate) session_last_activity: Mutex<HashMap<String, std::time::Instant>>,
}

#[allow(dead_code)]
pub(crate) const IDLE_SESSION_TTL_SECS: u64 = 300;
#[allow(dead_code)]
pub(crate) const SESSION_SWEEP_INTERVAL_SECS: u64 = 60;

impl Default for TransferState {
    fn default() -> Self {
        Self {
            server: Mutex::new(None),
            stop_tx: Mutex::new(None),
            receive_dir: Mutex::new(None),
            pending_receive_approvals: Mutex::new(HashMap::new()),
            pending_receive_times: Mutex::new(HashMap::new()),
            pending_pairing_approvals: Mutex::new(HashMap::new()),
            pending_pairing_times: Mutex::new(HashMap::new()),
            pairing_listener: Mutex::new(None),
            receiver_should_run: AtomicBool::new(false),
            receiver_stop_intent: AtomicBool::new(false),
            discoverable: AtomicBool::new(false),
            defensive_hidden: AtomicBool::new(false),
            active_sessions: Mutex::new(HashMap::new()),
            ecdh_session_keys: Mutex::new(HashMap::new()),
            v3_sender: Mutex::new(HashMap::new()),
            session_last_activity: Mutex::new(HashMap::new()),
        }
    }
}

const PENDING_APPROVAL_TTL_SECS: u64 = 60;

#[allow(dead_code)]
impl TransferState {
    #[allow(dead_code)]
    pub(crate) fn cleanup_stale_approvals(&self) {
        let cutoff = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(PENDING_APPROVAL_TTL_SECS))
            .unwrap_or(std::time::Instant::now());
        {
            let mut times = match self.pending_receive_times.lock() {
                Ok(t) => t,
                Err(p) => p.into_inner(),
            };
            let mut approvals = match self.pending_receive_approvals.lock() {
                Ok(a) => a,
                Err(p) => p.into_inner(),
            };
            times.retain(|k, v| {
                if *v < cutoff {
                    approvals.remove(k);
                    false
                } else {
                    true
                }
            });
        }
        {
            let mut times = match self.pending_pairing_times.lock() {
                Ok(t) => t,
                Err(p) => p.into_inner(),
            };
            let mut approvals = match self.pending_pairing_approvals.lock() {
                Ok(a) => a,
                Err(p) => p.into_inner(),
            };
            times.retain(|k, v| {
                if *v < cutoff {
                    approvals.remove(k);
                    false
                } else {
                    true
                }
            });
        }
    }
}

/// 待发送的文件条目（Tauri 命令参数）
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Clone)]
pub struct SendFileItem {
    rel_path: String,
    abs_path: String,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub size: Option<u64>,
}

impl SendFileItem {
    pub fn rel_path(&self) -> &str {
        &self.rel_path
    }
}

/// 配对服务全局状态（由 lib.rs 注入）
pub struct PairingState {
    pub synced_dirs: Mutex<HashMap<String, String>>,
    pub paired: Mutex<HashMap<String, serde_json::Value>>,
    pub transfer_count: AtomicUsize,
    pub notify_disconnect: std::sync::Arc<std::sync::Mutex<std::sync::mpsc::Sender<()>>>,
    #[allow(dead_code)]
    pub verify_rate: Mutex<HashMap<String, (u32, u64)>>,
    pub static_key: Mutex<Option<(String, String)>>,
    pub sig_key: Mutex<Option<(String, String)>>,
    pub secrets: tokio::sync::RwLock<HashMap<String, Vec<u8>>>,
    pub used_jtis: Mutex<HashSet<String>>,
}

impl Default for PairingState {
    fn default() -> Self {
        let (tx, _) = std::sync::mpsc::channel();
        Self {
            synced_dirs: Mutex::new(HashMap::new()),
            paired: Mutex::new(HashMap::new()),
            transfer_count: AtomicUsize::new(0),
            notify_disconnect: std::sync::Arc::new(std::sync::Mutex::new(tx)),
            verify_rate: Mutex::new(HashMap::new()),
            static_key: Mutex::new(None),
            sig_key: Mutex::new(None),
            secrets: tokio::sync::RwLock::new(HashMap::new()),
            used_jtis: Mutex::new(HashSet::new()),
        }
    }
}

pub(crate) fn get_or_create_sig_key(app: &AppHandle) -> (String, String) {
    if let Some(st) = app.try_state::<PairingState>() {
        if let Ok(k) = st.sig_key.lock() {
            if let Some((p, u)) = k.as_ref() {
                return (p.clone(), u.clone());
            }
        }
    }
    if let Ok(Some((priv_b64, pub_b64))) = crate::db::load_sig_key(app) {
        let generated = (priv_b64, pub_b64);
        if let Some(st) = app.try_state::<PairingState>() {
            if let Ok(mut k) = st.sig_key.lock() {
                *k = Some(generated.clone());
            }
        }
        return generated;
    }
    let generated = crate::crypto::sig_generate_keypair().unwrap_or_default();
    let _ = crate::db::save_sig_key(app, &generated.0, &generated.1);
    if let Some(st) = app.try_state::<PairingState>() {
        if let Ok(mut k) = st.sig_key.lock() {
            *k = Some((generated.0.clone(), generated.1.clone()));
        }
    }
    generated
}

pub fn notify_peers_disconnect(app: &AppHandle) {
    if let Some(st) = app.try_state::<PairingState>() {
        if let Ok(tx) = st.notify_disconnect.lock() {
            let _ = tx.send(());
        }
    }
}

pub fn pairing_port(receiver_port: u16) -> u16 {
    receiver_port + 1
}

pub fn spawn_pairing_server(app: AppHandle) {
    let port = pairing_port(53317);
    crate::probe!("pairing: 开始绑定端口");
    let mut listener = None;
    for attempt in 0..5 {
        match std::net::TcpListener::bind(("0.0.0.0", port)) {
            Ok(l) => {
                listener = Some(l);
                crate::probe!(format!("pairing: 端口绑定成功（第 {} 次尝试）", attempt + 1));
                break;
            }
            Err(_) if attempt < 4 => {
                std::thread::sleep(std::time::Duration::from_millis(120));
            }
            Err(e) => {
                crate::probe!("pairing: 端口绑定失败");
                crate::log_warn!(
                    "配对服务端口 {port} 绑定失败: {e}。对端按 (接收端口+1) 访问本机配对服务，\
                     请释放占用 {port} 的进程后重启（不做端口回退：换端口会导致对端不可达）"
                );
                return;
            }
        }
    }
    let listener = match listener {
        Some(l) => l,
        None => return,
    };
    let thread_listener = match listener.try_clone() {
        Ok(l) => l,
        Err(e) => {
            crate::log_warn!("配对服务 try_clone 失败: {e}");
            return;
        }
    };
    if let Ok(mut st) = app.state::<TransferState>().pairing_listener.lock() {
        *st = Some(listener);
    }
    let pair_sem = Arc::new(std::sync::Mutex::new(0u32));
    std::thread::spawn(move || {
        crate::log_info!("配对服务已启动: 端口 {port}");
        for stream in thread_listener.incoming() {
            match stream {
                Ok(mut s) => {
                    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(30)));
                    let _ = s.set_write_timeout(Some(std::time::Duration::from_secs(30)));
                    let app = app.clone();
                    let pair_cap = 32u32;
                    let over_cap = {
                        let mut c = match pair_sem.lock() {
                            Ok(g) => g,
                            Err(p) => p.into_inner(),
                        };
                        if *c >= pair_cap {
                            true
                        } else {
                            *c += 1;
                            false
                        }
                    };
                    if over_cap {
                        crate::log_warn!("配对服务并发连接达上限({pair_cap})，丢弃多余连接");
                        continue;
                    }
                    let pair_sem = pair_sem.clone();
                    std::thread::spawn(move || {
                        let _guard = PairConnGuard(pair_sem);
                        let _ = handle_pairing_conn(app, &mut s);
                    });
                }
                Err(_) => {
                    crate::log_info!("配对服务已停止");
                    break;
                }
            }
        }
    });
}

#[allow(dead_code)]
pub fn stop_pairing_server(app: AppHandle) {
    if let Ok(mut st) = app.state::<TransferState>().pairing_listener.lock() {
        if let Some(l) = st.take() {
            drop(l);
        }
    }
}

pub(crate) fn handle_move_to_delete(app: &AppHandle, body: &str) -> usize {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return 0;
    };
    let Some(files) = v.get("files").and_then(|f| f.as_array()) else {
        return 0;
    };
    let Some(dir) = app
        .state::<TransferState>()
        .receive_dir
        .lock()
        .ok()
        .and_then(|d| d.clone())
    else {
        return 0;
    };
    let delete_dir = dir.join("delete");
    let mut moved = 0;
    for f in files {
        let Some(rel) = f.as_str() else { continue };
        if rel.is_empty() || rel.contains("..") {
            continue;
        }
        let src = dir.join(rel);
        let dst = delete_dir.join(rel);
        if src.exists() {
            if let Some(parent) = dst.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::rename(&src, &dst).is_ok() {
                moved += 1;
            }
        }
    }
    crate::log_info!("镜像模式移动多余文件到 delete: {moved} 个");
    moved
}

pub fn handle_pairing_conn(
    app: AppHandle,
    stream: &mut std::net::TcpStream,
) -> Result<(), AppError> {
    crate::pairing::handle_pairing_conn(app, stream)
}

#[allow(dead_code)]
pub fn send_unpair(_ip: String, _port: u16, _device_id: String) -> Result<bool, AppError> {
    Err(AppError("send_unpair 已废弃，请使用 unpair_peer（store.rs）".to_string()))
}

pub async fn move_to_delete(ip: String, port: u16, files: Vec<String>) -> Result<usize, AppError> {
    let body = serde_json::json!({
        "deviceId": crate::identity::get_device_id_no_ctx(),
        "relPaths": files,
    }).to_string();
    tauri::async_runtime::spawn_blocking(move || {
        let v = http_json_request(&ip, port, "POST", "/api/v4/move-to-delete", &body)?;
        Ok(v.get("moved").and_then(|x| x.as_u64()).unwrap_or(0) as usize)
    })
    .await
    .map_err(|e| AppError(format!("任务执行失败: {e}")))?
}

pub fn send_disconnect(ip: String, port: u16, device_id: String) -> Result<bool, AppError> {
    let body = serde_json::json!({"deviceId": device_id}).to_string();
    let v = http_json_request(&ip, port, "POST", "/api/v4/disconnect", &body)?;
    Ok(v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false))
}

pub fn spawn_ui_watchdog(app: AppHandle) {
    crate::log_info!("UI 主线程 watchdog 已启动（心跳 500ms / 超时 1500ms）");
    std::thread::spawn(move || {
        let probe_path = std::env::temp_dir().join("wd_alive.txt");
        let mut beats: u64 = 0;
        loop {
            beats += 1;
            let start = std::time::Instant::now();
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let app2 = app.clone();
            let _ = app2.run_on_main_thread(move || {
                let _ = tx.send(());
            });
            match rx.recv_timeout(std::time::Duration::from_millis(1500)) {
                Ok(()) => {
                    let ms = start.elapsed().as_millis();
                    if crate::PROBE_ENABLED {
                        if let Ok(mut f) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&probe_path)
                        {
                            use std::io::Write as _;
                            let _ = writeln!(f, "[beat {beats}] main-ok {ms}ms");
                        }
                    } else if ms >= 800 {
                        crate::log_warn!("主线程响应偏慢: {ms}ms（仍在阈值内）");
                    }
                }
                Err(_) => {
                    let ms = start.elapsed().as_millis();
                    if crate::PROBE_ENABLED {
                        if let Ok(mut f) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&probe_path)
                        {
                            use std::io::Write as _;
                            let _ = writeln!(f, "[beat {beats}] !!MAIN-BLOCKED {ms}ms");
                        }
                    }
                    crate::log_error!(
                        "!! UI 主线程阻塞检测: 心跳超时，阻塞 ≥{ms}ms——疑似同步命令占用 IPC 线程"
                    );
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    });
}

pub fn probe_peer_port(ip: String, port: u16) -> Result<bool, AppError> {
    let addr = format!("{ip}:{port}")
        .parse::<std::net::SocketAddr>()
        .map_err(|e| AppError(format!("地址解析失败: {e}")))?;
    Ok(std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(1)).is_ok())
}

pub fn spawn_receiver_watchdog(app: AppHandle) {
    crate::log_info!("接收服务器自愈 watchdog 已启动（5s 端口自检）");
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let state = app.state::<TransferState>();
            if !state.receiver_should_run.load(Ordering::Relaxed)
                || state.receiver_stop_intent.load(Ordering::Relaxed)
            {
                continue;
            }
            let port = match state.server.lock() {
                Ok(g) => match g.as_ref() {
                    Some(h) => h.port(),
                    None => continue,
                },
                Err(_) => continue,
            };
            let dir = match state.receive_dir.lock() {
                Ok(g) => g.clone(),
                Err(_) => continue,
            };
            let Some(dir) = dir else { continue };
            let Ok(addr) = format!("127.0.0.1:{port}").parse::<std::net::SocketAddr>() else {
                continue;
            };
            let probe_ok = tauri::async_runtime::spawn_blocking(move || {
                std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(800))
                    .is_ok()
            })
            .await
            .unwrap_or(false);
            if probe_ok {
                continue;
            }
            crate::log_error!("接收服务器疑似异常退出（端口 {port} 拒连但状态为运行中），自动重启");
            let app2 = app.clone();
            match start_receiver(app2, dir.to_string_lossy().to_string(), port).await {
                Ok(_) => {
                    crate::log_info!("接收服务器自愈重启成功: 端口 {port}");
                    let _ = app.emit("receiver-auto-restart", serde_json::json!({ "port": port }));
                }
                Err(e) => {
                    crate::log_error!("接收服务器自愈重启失败（5s 后重试）: {e}");
                }
            }
        }
    });
}

pub fn get_peer_manifest(ip: String, port: u16) -> Result<serde_json::Value, AppError> {
    let self_id = crate::identity::get_device_id_no_ctx();
    let path = format!("/api/v4/manifest?deviceId={}", self_id);
    http_json_request(&ip, port, "GET", &path, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_dto(name: &str, size: u64, modified: Option<&str>) -> FileDto {
        FileDto {
            id: "f0".to_string(),
            file_name: name.to_string(),
            size,
            file_type: "file".to_string(),
            sha256: None,
            preview: None,
            metadata: modified.map(|m| FileMetadata {
                modified: Some(m.to_string()),
                accessed: None,
            }),
            protocol_extensions: None,
            merkle_root: None,
            piece_hashes: None,
            chunk_size: None,
        }
    }

    #[test]
    fn no_conflict_uses_original_path() {
        let dir = PathBuf::from("C:/backup");
        let target = resolve_target_path(&dir, &file_dto("a/b.txt", 100, None));
        assert_eq!(target, dir.join("a/b.txt"));
    }

    #[test]
    fn conflict_renames_with_timestamp() {
        let dir = std::env::temp_dir().join("transfer_test_conflict");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.txt"), "old content").unwrap();
        let target = resolve_target_path(&dir, &file_dto("b.txt", 9999, Some("2025-08-15T08:23:45Z")));
        let name = target.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with("b_"), "应重命名为 b_MMDDhhmmss.txt, got {name}");
        assert!(name.ends_with(".txt"), "扩展名应保留, got {name}");
        assert_ne!(name, "b.txt");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn identical_file_is_not_renamed() {
        let dir = std::env::temp_dir().join("transfer_test_identical");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.txt"), "same").unwrap();
        let target = resolve_target_path(&dir, &file_dto("b.txt", 4, None));
        assert_eq!(target, dir.join("b.txt"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn timestamp_format_is_10_digits() {
        let s = format_mmddhhmmss(1755239025);
        assert_eq!(s.len(), 10, "MMDDhhmmss 应为 10 位数字, got {s}");
        assert!(s.chars().all(|c| c.is_ascii_digit()));
    }
}
