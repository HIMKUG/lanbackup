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
use lanbackup_core::server::SessionStore;

mod send;
mod receive;
mod store;
mod util;
mod v4;

pub use send::*;
pub use v4::*;
pub use receive::*;
pub use store::*;
pub use util::*;

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

/// 全局传输状态（由 lib.rs 注入）
pub struct TransferState {
    /// WB-0117：启停单飞锁 —— start/stop 全程持锁串行化，
    /// 并发 start_receiver 不再出现"双绑端口/旧服务未停新服务已起"的竞态。
    pub(crate) lifecycle_lock: tokio::sync::Mutex<()>,
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
            lifecycle_lock: tokio::sync::Mutex::new(()),
            server: Mutex::new(None),
            stop_tx: Mutex::new(None),
            receive_dir: Mutex::new(None),
            pending_receive_approvals: Mutex::new(HashMap::new()),
            pending_receive_times: Mutex::new(HashMap::new()),
            pending_pairing_approvals: Mutex::new(HashMap::new()),
            pending_pairing_times: Mutex::new(HashMap::new()),
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
    #[allow(unused)]
    pub used_jtis: Mutex<HashSet<String>>,
    /// core SessionStore（由 receive.rs::start_receiver 注入）。
    /// 用于在配对变更时同步写 core PeerStore，消除 SQLite↔core drift。
    pub(crate) session_store: Mutex<Option<std::sync::Arc<SessionStore>>>,
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
            session_store: Mutex::new(None),
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
    let generated = match crate::crypto::sig_generate_keypair() {
        Ok(k) => k,
        Err(e) => {
            crate::log_error!("签名密钥生成失败（拒绝落空密钥）: {e}");
            return (String::new(), String::new());
        }
    };
    if generated.0.is_empty() || generated.1.is_empty() {
        crate::log_error!("签名密钥生成返回空值（拒绝落盘）");
        return (String::new(), String::new());
    }
    if let Err(e) = crate::db::save_sig_key(app, &generated.0, &generated.1) {
        crate::log_error!("签名密钥落盘失败: {e}");
    }
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
        // WB-0425：core 响应是 typed MoveToDeleteResponse —— `moved` 是**路径数组**，
        // 不是数字。此前按 as_u64 读恒得 0，前端"镜像确认"永远以为没删任何东西。
        Ok(v.get("moved")
            .and_then(|x| x.as_array())
            .map(|a| a.len())
            .unwrap_or(0))
    })
    .await
    .map_err(|e| AppError(format!("任务执行失败: {e}")))?
}

pub fn send_disconnect(ip: String, port: u16, device_id: String) -> Result<bool, AppError> {
    let body = serde_json::json!({"deviceId": device_id}).to_string();
    let v = http_json_request(&ip, port, "POST", "/api/v4/disconnect", &body)?;
    // WB-0435：core 响应是 typed DisconnectResponse（deviceId/pairingState/presence/
    // abortedSessions），没有 `ok` 字段 —— 此前恒读 false，前端把每次断开都当失败。
    // 断开语义：presence 归 offline 即成功（配对状态原样保留）。
    Ok(v.get("presence")
        .and_then(|x| x.as_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("offline")))
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
            // 防御模式下 probe 会被 core 总闸拒绝，不能据此判定服务死亡。
            if state.defensive_hidden.load(Ordering::Relaxed) {
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
            let Ok(_addr) = format!("127.0.0.1:{port}").parse::<std::net::SocketAddr>() else {
                continue;
            };
            // WB-0058：TCP 能连上只说明端口有人监听，可能是别的进程。
            // 必须走真实 /probe 并核对本机 deviceId，否则端口被占用时会误判健康。
            let self_id = identity::get_device_id_no_ctx();
            let probe_ok = tauri::async_runtime::spawn_blocking(move || {
                match http_json_request_internal(
                    "127.0.0.1",
                    port,
                    "GET",
                    "/api/v4/probe",
                    "",
                    &HttpRequestOptions {
                        connect_ms: 800,
                        read_ms: 1500,
                        write_ms: 800,
                        protocol_version: Some("4.0"),
                    },
                ) {
                    Ok(v) => {
                        v.get("deviceId").and_then(|d| d.as_str()) == Some(self_id.as_str())
                    }
                    Err(_) => false,
                }
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
