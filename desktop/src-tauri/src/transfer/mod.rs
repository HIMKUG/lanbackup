//! 传输模块
//!
//! 基于 LocalSend core（localsend crate）实现：
//! - 接收端：启动 v2 HTTP 服务器，文件保存到备份目录，冲突自动重命名（`原名_MMDDhhmmss.扩展名`）
//! - 发送端：`LsHttpClientV2` 发送文件到目标设备（纯 HTTP，与手机端 TS 实现协议兼容）
//!
//! 两端均使用纯 HTTP（无 mTLS）：桌面端服务器启动时 `tls_config` 传 `None`，
//! 手机端 WebView 无法加载客户端证书，因此协议层走明文 HTTP。
//!
//! 模块拆分说明（纯文件拆分重构，逻辑零改动）：
//! - `util`：路径/时间戳/文件类型等通用工具函数
//! - `v3`：v3 控制面客户端（probe / handshake）与 HTTP 请求工具
//! - `store`：配对记录持久化（SQLite）与同步
//! - `send`：发送端流程（send_files / 上传 / 分片）
//! - `receive`：接收端流程（服务器启动 / 事件循环 / 解密合并）
//! 子模块通过 `pub use ...::*` 重导出，外部 `crate::transfer::xxx` 引用保持不变。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::sync::Arc;

use localsend::http::client::v2::LsHttpClientV2;
use localsend::http::dto_v2::{PrepareUploadRequestDtoV2, RegisterDtoV2};
use localsend::http::server::common::save::FileUploadTarget;
use localsend::http::server::v2::{PrepareUploadDecisionV2, ServerEventV2};
use futures_util::{StreamExt, TryStreamExt};
use localsend::http::server::{start_with_port, ServerConfigV2, ServerHandle};
use localsend::http::state::ClientInfo;
use localsend::model::discovery::{DeviceType, ProtocolType};
use localsend::model::transfer::FileDto;
use tauri::{AppHandle, Emitter, Manager};

use crate::db::AppError;
use crate::identity;
use crate::scheduler::{jittered_backoff_ms, is_checksum_failure_retryable};
use crate::session_store;

mod send;
mod receive;
mod store;
mod v3;
mod util;

pub use send::*;
pub use receive::*;
pub use store::*;
pub use v3::*;
pub use util::*;

/// 配对连接并发额度守卫（RAII）：持有期间 +1，drop 时 -1。
/// 配合 spawn_pairing_server 的并发上限，防止局域网恶意并发连接拖垮进程。
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
    /// 正在运行的接收服务器
    server: Mutex<Option<ServerHandle>>,
    /// 停止服务器的信号发送端
    stop_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// 接收文件保存的根目录
    pub(crate) receive_dir: Mutex<Option<PathBuf>>,
    /// 接收确认：sessionId → 等待前端同意/拒绝（prepare-upload 阻塞等待用户确认）
    pub(crate) pending_receive_approvals: Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>,
    /// 接收确认创建时间（用于 TTL 过期清理；与 pending_receive_approvals 一一对应）
    pub(crate) pending_receive_times: Mutex<HashMap<String, std::time::Instant>>,
    /// 配对确认：deviceId → 等待前端同意/拒绝（/verify 配对验证阻塞等待被动方确认）
    pub(crate) pending_pairing_approvals: Mutex<HashMap<String, std::sync::mpsc::Sender<bool>>>,
    /// 配对确认创建时间（用于 TTL 过期清理）
    pub(crate) pending_pairing_times: Mutex<HashMap<String, std::time::Instant>>,
    /// 配对服务监听器（53318）：隐藏模式（接收服务停止）时关闭它即停止配对服务，
    /// 让"本机已隐藏"真正不可达（不再响应 /info /verify）
    pairing_listener: Mutex<Option<std::net::TcpListener>>,
    /// 接收服务器应处于运行状态（自愈 watchdog 依据；成功启动置 true，主动停止置 false）
    pub(crate) receiver_should_run: AtomicBool,
    /// 用户主动停止进行中（watchdog 在此窗口内不介入，避免把"刚停止"误判为异常退出）
    pub(crate) receiver_stop_intent: AtomicBool,
    /// 可被发现标志：UI 点击「开始发现」时置 true（v3 probe 响应真实 deviceId），
    /// 停止发现置 false → probe 返回空 deviceId，手机子网扫描跳过本机
    pub(crate) discoverable: AtomicBool,
    /// 防御性总开关（最高优先级）：true = 本机在局域网完全隐藏。
    /// 隐藏时：停止明文 announce 与加密存在，拒绝一切入站连接（含已配对凭证直连、连接码直连），
    /// 仅保留本机主动外连。覆盖发现/收件/加密存在所有开关。
    pub(crate) defensive_hidden: AtomicBool,
    /// 活跃传输会话（cancel 端点按 sessionId 取消对应发送任务）。
    /// value 为发送任务的 cancel token：handle_cancel 从本表取 token 并 .cancel()，
    /// 使发送循环真正中断（之前只清理表项+emit 事件，发送循环不停 → 取消不生效）。
    pub(crate) active_sessions:
        Mutex<HashMap<String, tokio_util::sync::CancellationToken>>,
    /// 加密 v2：ECDH 复杂加密的会话密钥（session_id → session_key，prepare-upload 协商后
    /// 由接收端保存，FileUpload 解密时按 session_id 取用；会话结束由 SessionEnd 清理）
    pub(crate) ecdh_session_keys: Mutex<HashMap<String, [u8; 32]>>,
    /// P6：v3 配对发送方映射（session_id → sender device_id）。
    /// PrepareUpload 识别发送方 fingerprint 有 v3 pairing_secret 时记录，
    /// FileUpload 据此 + file_id 派生 per-file transfer_key 解密（方案.txt §6.3）。
    /// 会话结束由 SessionEnd 清理，防陈旧条目泄漏。
    pub(crate) v3_sender: Mutex<HashMap<String, String>>,
    /// A2：会话最近活动时间（session_id → 最后一次分片到达时刻）。
    /// 超时清理任务据此判断"闲置"——活跃长传输持续续期，不会被误杀；
    /// 只有闲置超过 IDLE_SESSION_TTL 的会话才被清理。SessionEnd 同步移除。
    pub(crate) session_last_activity: Mutex<HashMap<String, std::time::Instant>>,
}

/// A2：会话闲置判定阈值——分片停止到达超过此时长才视为异常残留
pub(crate) const IDLE_SESSION_TTL_SECS: u64 = 300;
/// A2：清理任务的巡检间隔（闲置时长精度 = 此值 + 调度误差）
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

/// TTL 过期时间（秒）：略长于 prepare-upload 的 45s 超时，留足够余量
const PENDING_APPROVAL_TTL_SECS: u64 = 60;

impl TransferState {
    /// 清理超时的 pending 记录（上次清理后仍存在的陈旧条目）。
    /// 在每次插入新条目时调用，实现"按需清理"，避免维护后台清理线程。
    /// 注意：频繁调用此方法有轻微 O(n) 成本（n = 当前 pending 数），实际可忽略。
    pub(crate) fn cleanup_stale_approvals(&self) {
        let cutoff = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(PENDING_APPROVAL_TTL_SECS))
            .unwrap_or(std::time::Instant::now());
        // 清理超时的接收确认
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
        // 清理超时的配对确认
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
    /// 相对路径（含目录层级），接收端据此重建目录结构
    rel_path: String,
    /// 本地绝对路径
    abs_path: String,
    /// 分片起始偏移（大文件分片续传用；None = 整文件）
    #[serde(default)]
    pub offset: Option<u64>,
    /// 分片字节数（None = 整文件）
    #[serde(default)]
    pub size: Option<u64>,
}

impl SendFileItem {
    /// 相对路径（供日志/包装层读取）
    pub fn rel_path(&self) -> &str {
        &self.rel_path
    }
}

/// 配对服务全局状态（由 lib.rs 注入）
pub struct PairingState {
    /// direction → 对方同步过来的目录名
    pub synced_dirs: Mutex<HashMap<String, String>>,
    /// 双端配对记录：对方验证本机码通过后记录（deviceId → {name,ip,port,fingerprint}）
    pub paired: Mutex<HashMap<String, serde_json::Value>>,
    /// 当前传输计数（M5-3 锁：刷新连接码时检查此计数 > 0 则拒绝）
    pub transfer_count: AtomicUsize,
/// 通知配对服务断开所有连接的信号（M2）；由 spawn_pairing_server 写入。
/// 注意：当前实现中 channel 在 PairingState::default() 时就断开了（M3-2 遗留死代码），
/// 实际 M2 断连逻辑由 pairing_server 的 shutdown 信号替代，此字段已失效但保留以避免
/// 破坏性重构；如需启用需在 spawn_pairing_server 构造时传入真实的 rx。
pub notify_disconnect: std::sync::Arc<std::sync::Mutex<std::sync::mpsc::Sender<()>>>,
    /// /verify 端点限速：IP → (尝试次数, 窗口起始时间戳(秒))（P2 硬升级：v2 verify 已删，字段保留兼容）
    #[allow(dead_code)]
    pub verify_rate: Mutex<HashMap<String, (u32, u64)>>,
    /// v3：设备静态密钥对 (priv_b64, pub_b64)，P-256 SEC1 非压缩；首次生成后缓存（P5 落 SQLite）
    pub static_key: Mutex<Option<(String, String)>>,
    /// v5：设备 ECDSA P-256 签名密钥对 (priv_b64, pub_b64)（新架构信任锚，独立于 ECDH static_key）
    pub sig_key: Mutex<Option<(String, String)>>,
    /// v3：deviceId → 长期 pairing_secret（内存态；SQLite 持久化接线属 P5）
    /// 注意：PairingState 在 HTTP 处理路径（v3.rs，tokio 上下文）中被访问，
    /// 使用 tokio::sync::RwLock 而非 std::sync::Mutex 避免阻塞 tokio 调度器。
    pub secrets: tokio::sync::RwLock<HashMap<String, Vec<u8>>>,
    /// v3：JWT jti 防重放集合（jti → 存在，5 分钟过期后删除）
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

/// 获取（或生成）设备 ECDSA P-256 签名密钥对 (priv_b64, pub_b64)（v5 新架构）。
/// 与 static_key（ECDH）分离，专用于消息签名/验签（配对信任锚、吊销令牌）。
/// 持久化到 SQLite local_identity.sig_* 列。启动顺序：内存缓存 → SQLite → 新生成并保存。
/// 供 pairing/v3.rs（服务端）与 transfer/v3.rs（客户端）共用。
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

/// M2: 通知所有配对设备断开连接（异步，不清除配对记录，传输完成后重新建立）。
/// 转发给 pairing_server 线程处理。
pub fn notify_peers_disconnect(app: &AppHandle) {
    if let Some(st) = app.try_state::<PairingState>() {
        if let Ok(tx) = st.notify_disconnect.lock() {
            let _ = tx.send(());
        }
    }
}

/// 配对服务端口（接收端口 + 1）
pub fn pairing_port(receiver_port: u16) -> u16 {
    receiver_port + 1
}

/// 启动配对服务（跟随接收服务启停：可见时启动，隐藏时由 stop_pairing_server 关闭）。
/// 端口被占用时短暂重试同一端口（旧实例关闭后端口释放有微小竞态窗口）。
/// 注意：不做 port+1 回退——配对端口 = 接收端口+1 是线缆协议假设，
/// 手机端 LocalReceiverPlugin 与桌面 get_peer_manifest/send_sync_dir 全部硬编码 (port+1)，
/// 静默换端口会让本机"启动成功"但对端全部不可达（比绑定失败更难排查）。
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
            Err(_e) if attempt < 4 => {
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
    // 保存原始 listener：stop_pairing_server 关闭它即可让 accept 循环退出
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
                    // 读/写超时：无超时 + 每连接无线程上限 = 局域网内任意主机可用
                    // 半个 HTTP 头挂住任意多线程（Slowloris DoS）
                    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(30)));
                    let _ = s.set_write_timeout(Some(std::time::Duration::from_secs(30)));
                    let app = app.clone();
                    // P3-289：有界并发（限制同时处理的配对连接线程数），超限直接丢弃连接，
                    // 防 Slowloris/大量并发连接拖垮进程（对比 send 侧 Semaphore(64) 有界线程池）
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
                        // 无论处理结果如何，处理结束后释放并发额度
                        let _guard = PairConnGuard(pair_sem);
                        let _ = handle_pairing_conn(app, &mut s);
                    });
                }
                Err(_) => {
                    // 监听器被 stop_pairing_server 关闭 → 退出线程
                    crate::log_info!("配对服务已停止");
                    break;
                }
            }
        }
    });
}

/// 停止配对服务（关闭监听 → accept 循环退出）。隐藏模式时由 UI 调用。
#[allow(dead_code)]
pub fn stop_pairing_server(app: AppHandle) {
    if let Ok(mut st) = app.state::<TransferState>().pairing_listener.lock() {
        if let Some(l) = st.take() {
            drop(l);
        }
    }
}

/// 镜像模式：把对端多余文件移动到 <接收目录>/delete/ 下（假删除，保留原相对路径）。
/// 返回成功移动的文件数；接收服务未运行（无接收目录）时返回 0。
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

/// 处理单条配对服务连接（委托给 pairing::auth 模块）
pub fn handle_pairing_conn(
    app: AppHandle,
    stream: &mut std::net::TcpStream,
) -> Result<(), AppError> {
    crate::pairing::handle_pairing_conn(app, stream)
}

/// 通知目标设备解除配对（POST /unpair 于配对服务端口+1，双向删除信任）
pub fn send_unpair(ip: String, port: u16, device_id: String) -> Result<bool, AppError> {
    let body = serde_json::json!({"deviceId": device_id}).to_string();
    let v = http_json_request(&ip, port + 1, "POST", "/api/localsend/v2/unpair", &body)?;
    Ok(v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false))
}

/// 镜像模式：通知目标设备把多余文件移动到其 <接收目录>/delete/ 下（假删除）。
/// 返回成功移动的文件数。
pub async fn move_to_delete(ip: String, port: u16, files: Vec<String>) -> Result<usize, AppError> {
    // 阻塞 HTTP 移出 tokio worker（与 send_unpair/send_disconnect 的 spawn_blocking 模式一致，
    // 避免占死异步工作线程直到网络超时）
    let body = serde_json::json!({"files": files}).to_string();
    tauri::async_runtime::spawn_blocking(move || {
        let v = http_json_request(&ip, port + 1, "POST", "/api/backup/v1/move-to-delete", &body)?;
        Ok(v.get("moved").and_then(|x| x.as_u64()).unwrap_or(0) as usize)
    })
    .await
    .map_err(|e| AppError(format!("任务执行失败: {e}")))?
}

/// 通知目标设备断开连接（POST /api/backup/v1/disconnect 于配对服务端口+1，
/// 仅清除对方"已连接"状态，不解除配对）
pub fn send_disconnect(ip: String, port: u16, device_id: String) -> Result<bool, AppError> {
    let body = serde_json::json!({"deviceId": device_id}).to_string();
    let v = http_json_request(&ip, port + 1, "POST", "/api/backup/v1/disconnect", &body)?;
    Ok(v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false))
}

/// UI 主线程阻塞检测（诊断"程序全局未响应/切窗口卡死"）。
///
/// 原理：后台线程每 500ms 通过 `run_on_main_thread` 向主线程投递一个心跳回调，
/// 回调在**主线程**执行并回写 channel。若 1.5s 内未回 → 主线程被阻塞
/// （同步 Tauri 命令如 ping_device / verify_device 的 HTTP 请求占用 IPC 线程），
/// 记录 ERROR（含阻塞时长与时间戳）。用户复现卡死→导出日志→可定位阻塞点。
pub fn spawn_ui_watchdog(app: AppHandle) {
    crate::log_info!("UI 主线程 watchdog 已启动（心跳 500ms / 超时 1500ms）");
    std::thread::spawn(move || {
        // PROBE_ENABLED 门控：诊断期心跳直写独立文件（绕开 logger，排除其自身阻塞干扰）；
        // 生产模式仅通过 logger 上报异常，零每拍文件 I/O
        let probe_path = std::env::temp_dir().join("wd_alive.txt");
        let mut beats: u64 = 0;
        loop {
            beats += 1;
            let start = std::time::Instant::now();
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let app2 = app.clone();
            // 投递回调到主线程；若主线程忙/阻塞，回调排队等待
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

/// 探测对端接收端口（53317）是否可连。ping_device 走配对服务（端口+1）的 /info，
/// 探不到接收服务本身；发送前的"唤醒后等就绪"用这个直连探测。
pub fn probe_peer_port(ip: String, port: u16) -> Result<bool, AppError> {
    let addr = format!("{ip}:{port}")
        .parse::<std::net::SocketAddr>()
        .map_err(|e| AppError(format!("地址解析失败: {e}")))?;
    Ok(std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(1)).is_ok())
}

/// 接收服务器僵尸自愈 watchdog：服务器任务可能因异常退出而监听已关闭，
/// 但前端 serverRunning 仍为 true → peer-connected 自动拉起被跳过、对端上传被拒连。
/// 每 5s TCP 自检 127.0.0.1:port；"应运行但拒连" = 僵尸 → 用原目录原端口自动重启。
/// 用户主动停止（stop_intent / should_run=false）不介入。
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
            // 短持锁取端口与目录（不在持锁窗口内 await）
            let port = match state.server.lock() {
                Ok(g) => match g.as_ref() {
                    Some(h) => h.port(),
                    None => continue, // 状态已清：等待正常启动路径补齐
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
            // 阻塞 connect 移出 async 上下文（spawn_blocking）：每 5s 占住 worker ≤800ms
            // 改为不占用任何异步工作线程
            let probe_ok = tauri::async_runtime::spawn_blocking(move || {
                std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(800))
                    .is_ok()
            })
            .await
            .unwrap_or(false);
            if probe_ok {
                continue; // 监听正常
            }
            crate::log_error!("接收服务器疑似异常退出（端口 {port} 拒连但状态为运行中），自动重启");
            let app2 = app.clone();
            match start_receiver(app2, dir.to_string_lossy().to_string(), port).await {
                Ok(_) => {
                    crate::log_info!("接收服务器自愈重启成功: 端口 {port}");
                    let _ = app.emit("receiver-auto-restart", serde_json::json!({ "port": port }));
                }
                Err(e) => {
                    // 重启失败保持 should_run=true：下一轮继续重试（端口无人监听，重试无害）
                    crate::log_error!("接收服务器自愈重启失败（5s 后重试）: {e}");
                }
            }
        }
    });
}

/// 获取对端接收目录的当前清单（GET 对方配对服务 /api/backup/v1/manifest，三路对比增量备份用）
pub fn get_peer_manifest(ip: String, port: u16) -> Result<serde_json::Value, AppError> {
    http_json_request(&ip, port + 1, "GET", "/api/backup/v1/manifest", "")
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
            metadata: modified.map(|m| localsend::model::transfer::FileMetadata {
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
        // 已存在同名不同大小文件 → 冲突
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
        // 大小一致且无 mtime 信息 → 视为已备份，不重命名
        let target = resolve_target_path(&dir, &file_dto("b.txt", 4, None));
        assert_eq!(target, dir.join("b.txt"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn timestamp_format_is_10_digits() {
        let s = format_mmddhhmmss(1755239025); // 2025-08-15 ~06:23:45 UTC
        assert_eq!(s.len(), 10, "MMDDhhmmss 应为 10 位数字, got {s}");
        assert!(s.chars().all(|c| c.is_ascii_digit()));
    }
}
