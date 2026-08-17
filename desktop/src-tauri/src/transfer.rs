//! 传输模块
//!
//! 基于 LocalSend core（localsend crate）实现：
//! - 接收端：启动 v2 HTTP 服务器，文件保存到备份目录，冲突自动重命名（`原名_MMDDhhmmss.扩展名`）
//! - 发送端：`LsHttpClientV2` 发送文件到目标设备（纯 HTTP，与手机端 TS 实现协议兼容）
//!
//! 两端均使用纯 HTTP（无 mTLS）：桌面端服务器启动时 `tls_config` 传 `None`，
//! 手机端 WebView 无法加载客户端证书，因此协议层走明文 HTTP。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

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
use crate::scheduler::{self, jittered_backoff_ms, is_checksum_failure_retryable};

/// 全局传输状态（由 lib.rs 注入）
pub struct TransferState {
    /// 正在运行的接收服务器
    server: Mutex<Option<ServerHandle>>,
    /// 停止服务器的信号发送端
    stop_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// 接收文件保存的根目录
    receive_dir: Mutex<Option<PathBuf>>,
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
}

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

/// 启动接收服务器（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
///
/// 启动后自动接受所有上传请求（备份场景无需逐文件确认），
/// 文件写入 `receive_dir`，同名且内容不同则自动重命名，永不覆盖。
pub async fn start_receiver(
    app: AppHandle,
    receive_dir: String,
    port: u16,
) -> Result<String, AppError> {
    crate::log_info!("启动接收服务器: 目录={receive_dir} 端口={port}");
    let state = app.state::<TransferState>();

    // 已有服务器在运行 → 先停止旧实例再以新目录启动。
    // 关键：用户重新选择接收目录时若不重启，文件会继续写入旧目录。
    {
        let stop_tx = state
            .stop_tx
            .lock()
            .map_err(|_| AppError::from_poison())?
            .take();
        if let Some(tx) = stop_tx {
            let _ = tx.send(());
        }
        let old_handle = state
            .server
            .lock()
            .map_err(|_| AppError::from_poison())?
            .take();
        if let Some(handle) = old_handle {
            handle.wait_stopped().await;
        }
    }

    let dir = PathBuf::from(&receive_dir);
    std::fs::create_dir_all(&dir).map_err(AppError::from_display)?;

    // 事件通道：服务器 → 本模块的事件循环
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<ServerEventV2>(64);
    // 停止通道：stop_receiver 触发
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

    // 本机设备信息：register/info 响应只携带 设备名 + 公开 deviceId，
    // 连接码只用于接收端解密（事件循环内按码缓存派生），绝不向请求方暴露
    let device_name = identity::get_device_name(&app);
    let device_id = identity::get_device_id(&app);
    crate::log_debug!(
        "接收服务器本机信息 名称={} 公开ID={}",
        device_name,
        crate::logger::mask(&device_id)
    );
    // 接收端解密在事件循环内进行（按连接码缓存派生密钥，见下方 cached_code）
    let info = ClientInfo {
        alias: device_name,
        version: "2.2".to_string(),
        device_model: Some("Windows".to_string()),
        device_type: Some(DeviceType::Desktop),
        token: device_id,
    };

    let v2_config = ServerConfigV2 {
        pin: None,
        // 关闭校验和验证：备份场景免去接收后哈希开销
        verify_checksums: false,
        event_tx,
    };

    let handle = start_with_port(port, None, info, None, Some(v2_config), None, stop_rx)
        .await
        .map_err(|e| AppError(format!("启动接收服务器失败: {e}")))?;

    // 保存服务器状态
    *state
        .server
        .lock()
        .map_err(|_| AppError::from_poison())? = Some(handle);
    *state
        .stop_tx
        .lock()
        .map_err(|_| AppError::from_poison())? = Some(stop_tx);
    *state
        .receive_dir
        .lock()
        .map_err(|_| AppError::from_poison())? = Some(dir.clone());
    // 自愈依据：服务器应运行 + 非停止意图（清掉上次停止残留的标记）
    state.receiver_should_run.store(true, Ordering::Relaxed);
    state.receiver_stop_intent.store(false, Ordering::Relaxed);

    // 事件循环：自动接受上传，决定每个文件的保存路径（含冲突重命名），写完后解密
    let event_dir = dir.clone();
    tauri::async_runtime::spawn(async move {
        // 接收会话累计：按会话聚合写入接收历史（文件数/字节/耗时）
        let mut recv_started: Option<std::time::Instant> = None;
        let mut recv_expected: Option<u64> = None;
        let mut recv_count: u64 = 0;
        let mut recv_bytes: u64 = 0;
        let mut recv_total: u64 = 0;
        // 接收超时兜底：会话中断（发送方崩溃/网络断开/文件缺失）时若 5 分钟无任何事件，
        // 强制落一条接收历史并退出事件循环，避免"接收中"永久卡住
        let recv_timeout = std::time::Duration::from_secs(300);
        // 解密密钥缓存：连接码不变时逐文件零派生开销（原先每文件一次磁盘读 + SHA-256）；
        // 刷新连接码后自动重算，「刷新立即生效」语义不变
        let mut cached_code = identity::get_self_code(&app);
        let mut decrypt_key = crate::crypto::derive_key(&cached_code);
        loop {
            let event = match tokio::time::timeout(recv_timeout, event_rx.recv()).await {
                Ok(Some(ev)) => ev,
                Ok(None) => break, // 发送方正常关闭通道
                Err(_) => {
                    crate::log_warn!("接收会话超时（5 分钟无事件），强制结束本次接收");
                    finalize_receive(&app, &mut recv_started, &mut recv_count, &mut recv_bytes);
                    break;
                }
            };
            match event {
                ServerEventV2::PrepareUpload {
                    files,
                    decision_tx,
                    session_id,
                    ip,
                    info,
                    ..
                } => {
                    // 接收确认：通知前端弹窗（发送者/文件数/总大小），阻塞等待用户同意。
                    // 45 秒超时：已配对来源自动接受（备份场景），非配对默认拒绝（防未授权设备试探）
                    let ids: HashSet<String> = files.keys().cloned().collect();
                    let total_bytes: u64 = files.values().map(|f| f.size).sum();
                    crate::log_info!(
                        "收到 prepare-upload 请求（{} 个文件，{}B），等待用户确认",
                        ids.len(),
                        total_bytes
                    );
                    let approved = {
                        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
                        {
                            let st = app.state::<TransferState>();
                            // TTL 清理：每次插入前清理超时的旧条目（60s > 45s 超时）
                            st.cleanup_stale_approvals();
                            let now = std::time::Instant::now();
                            {
                                let mut m = st
                                    .pending_receive_approvals
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner());
                                m.insert(session_id.clone(), tx);
                            }
                            {
                                let mut t = st
                                    .pending_receive_times
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner());
                                t.insert(session_id.clone(), now);
                            }
                        }
                        let _ = app.emit(
                            "incoming-request",
                            serde_json::json!({
                                "sessionId": session_id,
                                "count": ids.len(),
                                "totalBytes": total_bytes,
                                "senderName": info.alias,
                                "senderIp": ip.to_string(),
                            }),
                        );
                        match tokio::time::timeout(std::time::Duration::from_secs(45), rx).await {
                            Ok(Ok(true)) => true,
                            Ok(Ok(false)) => false,
                            _ => is_trusted_sender(&app, &ip.to_string()), // 超时：配对来源自动接受
                        }
                    };
                    // 无论结果如何都清理 pending 表项（防 Sender 累积泄漏）
                    {
                        let st = app.state::<TransferState>();
                        let _ = st
                            .pending_receive_approvals
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&session_id);
                        let _ = st
                            .pending_receive_times
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&session_id);
                    }
                    if !approved {
                        crate::log_warn!("用户拒绝接收会话（{} 个文件）", ids.len());
                        let _ = decision_tx.send(PrepareUploadDecisionV2::Decline);
                        continue;
                    }
                    let _ = decision_tx.send(PrepareUploadDecisionV2::Accept(ids));
                    // 会话累计：记录开始时间/期望文件数/总字节（接收历史按会话聚合）
                    recv_started = Some(std::time::Instant::now());
                    recv_expected = Some(files.len() as u64);
                    recv_count = 0;
                    recv_bytes = 0;
                    recv_total = total_bytes;
                }
                ServerEventV2::FileUpload {
                    file,
                    target_tx,
                    ..
                } => {
                    // 大文件分片续传识别：fileName = __chunked__/{pct编码的正式路径}/{index}/{total}
                    // 分片写入 part 目录（不冲突重命名）；普通文件走冲突重命名
                    let chunked_meta: Option<(String, u32, u32)> = file
                        .file_name
                        .strip_prefix("__chunked__/")
                        .and_then(|rest| {
                            let parts: Vec<&str> = rest.split('/').collect();
                            if parts.len() == 3 {
                                Some((
                                    parts[0].to_string(),
                                    parts[1].parse::<u32>().unwrap_or(0),
                                    parts[2].parse::<u32>().unwrap_or(0),
                                ))
                            } else {
                                None
                            }
                        });
                    // 计算目标路径（冲突 → 重命名），由服务器直接写入磁盘
                    let path = match &chunked_meta {
                        Some((pct, idx, _)) => event_dir
                            .join(".chunks")
                            .join(pct)
                            .join(idx.to_string()),
                        None => resolve_target_path(&event_dir, &file),
                    };
                    // File::create 不会创建父目录：先建目录层级，保证子目录文件可保存
                    // P0 修复：std::fs::create_dir_all 是阻塞 I/O，用 Arc 克隆后送入 spawn_blocking
                    if let Some(parent) = path.parent() {
                        let parent_arc = std::sync::Arc::new(parent.to_path_buf());
                        match tokio::task::spawn_blocking({
                            let p = parent_arc.clone();
                            move || std::fs::create_dir_all(&*p)
                        }).await {
                            Ok(Err(e)) => crate::log_error!("创建接收目录失败 {}: {e}", parent_arc.display()),
                            Err(e) => crate::log_warn!("创建目录任务失败: {e}"),
                            _ => {}
                        }
                    }
                    crate::log_debug!(
                        "接收文件 {} ({}B) → {}",
                        file.file_name,
                        file.size,
                        path.display()
                    );
                    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
                    let _ = target_tx.send(FileUploadTarget::Path {
                        path: path.clone(),
                        result_tx,
                        progress_tx: None,
                    });
                    // 等待服务器写入完成，然后解密
                    match result_rx.await {
                        Ok(Ok(())) => {
                            // 写入成功：尝试解密（本应用加密文件带 LSBK 魔数头）。
                            // 码变化时才重派生密钥（identity 内已有进程内缓存）
                            {
                                let code = identity::get_self_code(&app);
                                if code != cached_code {
                                    cached_code = code;
                                    decrypt_key = crate::crypto::derive_key(&cached_code);
                                }
                            }
                            match decrypt_file_in_place(&decrypt_key, &path) {
                                Ok(true) => crate::log_debug!("文件解密完成: {}", path.display()),
                                Ok(false) => crate::log_debug!(
                                    "文件非加密格式，原样保存: {}",
                                    path.display()
                                ),
                                Err(e) => crate::log_error!(
                                    "文件解密失败 {}: {e}",
                                    path.display()
                                ),
                            }
                            // tiny 批量聚合：识别 x-batch-agg → 解包为独立文件，删除聚合本体
                            // spawn_blocking 包装：std::fs::read 是同步阻塞 I/O，必须移出 async 线程池
                            if file.file_type == "application/x-batch-agg" {
                                let path_clone = path.clone();
                                let dir_clone = event_dir.clone();
                                match tokio::task::spawn_blocking(move || {
                                    let tar = std::fs::read(&path_clone)
                                        .map_err(|e| AppError(format!("读取批量 tar 失败: {e}")))?;
                                    unpack_batch(&tar, &dir_clone)
                                        .map_err(|e| AppError(format!("批量 tar 解包失败: {e}")))
                                }).await {
                                    Ok(Ok(n)) => {
                                        crate::log_info!(
                                            "批量 tar 解包完成: {} 个成员（{}）",
                                            n,
                                            file.file_name
                                        );
                                        let _ = std::fs::remove_file(&path);
                                    }
                                    Ok(Err(e)) => crate::log_error!("批量 tar 解包失败: {}", e),
                                    Err(e) => crate::log_error!("批量 tar 解包线程失败: {}", e),
                                }
                            }
                            // 大文件分片到齐 → 合并为正式文件（按 index 顺序流式拼接，删 part）
                            if let Some((pct, _idx, total)) = &chunked_meta {
                                match merge_chunked(&event_dir, pct, *total) {
                                    Ok(true) => crate::log_info!(
                                        "分片合并完成: {} ({} 片)",
                                        pct_decode(pct),
                                        total
                                    ),
                                    Ok(false) => { /* 尚未到齐，等待后续分片 */ }
                                    Err(e) => crate::log_error!("分片合并失败: {e}"),
                                }
                            }
                            // 保留发送端文件时间戳（增量锚点准确）
                            // P0 修复：set_file_mtime 内部 std::fs::File::open 是阻塞 I/O，clone 送入 spawn_blocking
                            if let Some(meta) = &file.metadata {
                                if let Some(ts) = meta.modified.as_deref() {
                                    if let Some(secs) = parse_timestamp_secs(ts) {
                                        let path_log = path.clone();
                                        let path_clone = path.clone();
                                        match tokio::task::spawn_blocking(move || {
                                            set_file_mtime(&path_clone, secs)
                                        }).await {
                                            Ok(Err(e)) => crate::log_debug!(
                                                "设置文件时间戳失败 {}: {e}",
                                                path_log.display()
                                            ),
                                            Err(e) => crate::log_warn!("设置文件时间戳任务失败: {e}"),
                                            _ => {}
                                        }
                                    }
                                }
                            }
                            // 接收会话累计：按实际成功写入的文件累加字节（非预求和，
                            // 避免部分失败时 SessionEnd 兜底路径多报字节数）
                            recv_bytes += file.size;
                            recv_count += 1;
                            // 接收进度事件：前端实时显示总量/已传/速率/剩余时间
                            let _ = app.emit(
                                "receive-progress",
                                serde_json::json!({
                                    "fileName": file.file_name,
                                    "receivedBytes": recv_bytes,
                                    "totalBytes": recv_total,
                                    "receivedCount": recv_count,
                                    "totalCount": recv_expected.unwrap_or(recv_count),
                                }),
                            );
                            if let Some(expected) = recv_expected {
                                if recv_count >= expected {
                                    finalize_receive(
                                        &app,
                                        &mut recv_started,
                                        &mut recv_count,
                                        &mut recv_bytes,
                                    );
                                }
                            }
                        }
                        Ok(Err(e)) => crate::log_error!("接收文件写入失败: {e}"),
                        Err(_) => crate::log_warn!("接收文件写入通道关闭"),
                    }
                }
                ServerEventV2::SessionEnd { .. } => {
                    // 兜底：会话结束事件到达时若尚未按文件数完成，则落一条接收历史
                    finalize_receive(&app, &mut recv_started, &mut recv_count, &mut recv_bytes);
                }
                _ => {
                    // Register / CancelReceived / PrepareUploadAborted：
                    // 备份场景无需处理，忽略（取消会清掉累计状态，由下次 PrepareUpload 重置）
                }
            }
        }
        crate::log_info!("接收服务器事件循环退出");
    });

    Ok(format!("接收服务器已启动，端口 {port}"))
}

/// 接收会话完成：落一条接收历史（含字节/耗时）并通知前端刷新
fn finalize_receive(
    app: &AppHandle,
    started: &mut Option<std::time::Instant>,
    count: &mut u64,
    bytes: &mut u64,
) {
    let Some(s) = started.take() else {
        return;
    };
    let dur = s.elapsed().as_millis() as u64;
    let (c, b) = (*count, *bytes);
    *count = 0;
    *bytes = 0;
    crate::log_info!("接收会话完成: {c} 个文件 {b}B {dur}ms");
    if let Err(e) = app
        .state::<crate::AppState>()
        .db
        .add_transfer("in", "对方设备", c, b, dur)
    {
        crate::log_warn!("写入接收历史失败: {e}");
    }
    let _ = app.emit("transfers-updated", ());
    // 接收完成统计：前端进度框显示「备份完成」明细（文件数/总量/耗时）
    let _ = app.emit(
        "receive-complete",
        serde_json::json!({ "count": c, "bytes": b, "durationMs": dur }),
    );
}

/// 发送方是否已配对（按 IP 匹配配对信任表；用于接收/配对确认超时自动策略）
fn is_trusted_sender(app: &AppHandle, ip: &str) -> bool {
    if ip.is_empty() {
        return false;
    }
    app.state::<PairingState>()
        .paired
        .lock()
        .map(|m| m.values().any(|p| p.get("ip").and_then(|v| v.as_str()) == Some(ip)))
        .unwrap_or(false)
}

/// 停止接收服务器（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
pub async fn stop_receiver(app: AppHandle) -> Result<(), AppError> {
    crate::log_info!("停止接收服务器");
    let state = app.state::<TransferState>();
    // 停止意图先置位：watchdog 在清理窗口内不把"端口即将关闭"判为异常退出
    state.receiver_stop_intent.store(true, Ordering::Relaxed);
    state.receiver_should_run.store(false, Ordering::Relaxed);

    // 触发停止信号（guard 在表达式结束即释放，避免跨 await）
    let stop_tx = state
        .stop_tx
        .lock()
        .map_err(|_| AppError::from_poison())?
        .take();
    if let Some(tx) = stop_tx {
        let _ = tx.send(());
    }
    // 取出 handle 后再 await，等待服务器任务结束、端口释放
    let handle = state
        .server
        .lock()
        .map_err(|_| AppError::from_poison())?
        .take();
    if let Some(handle) = handle {
        handle.wait_stopped().await;
    }
    *state
        .receive_dir
        .lock()
        .map_err(|_| AppError::from_poison())? = None;
    Ok(())
}

/// 发送文件（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
///
/// 流程：register → prepare-upload（协商会话）→ 逐个上传（流式，不载入内存）。
/// 若 `target_code` 非空，发送前用 AES-256-GCM 加密文件内容。
/// 返回成功上传的文件数。
pub async fn send_files(
    app: AppHandle,
    target_ip: String,
    target_port: u16,
    target_code: String,
    files: Vec<SendFileItem>,
) -> Result<u64, AppError> {
    crate::log_info!(
        "发送文件: 目标={target_ip}:{target_port} 文件数={} 加密={}",
        files.len(),
        if target_code.is_empty() { "否" } else { "是" }
    );
    if files.is_empty() {
        return Ok(0);
    }
    let started = std::time::Instant::now();

    let enc_key = if target_code.is_empty() {
        None
    } else {
        Some(crate::crypto::derive_key(&target_code))
    };

    let client = LsHttpClientV2::try_new_without_cert()
        .map_err(|e| AppError(format!("初始化传输客户端失败: {e}")))?;
    let cancel = tokio_util::sync::CancellationToken::new();

    // 构造发送方设备信息（设备名 + 公开 deviceId，不暴露连接码）
    let device_name = identity::get_device_name(&app);
    let device_id = identity::get_device_id(&app);
    // 唤醒对端接收服务：连接问候（非 probe）触发对端 peer-connected → 自动拉起其接收服务器，
    // 然后等接收端口可连再继续。断网重连/对端重启后配对服务（端口+1）常驻可达、但接收服务未监听，
    // 直接上传会 Failed to connect（「恢复按钮失败」的根因）；就绪前查清单还会拿到空清单误判全量重传。
    {
        let ip = target_ip.clone();
        let body = serde_json::json!({
            "code": "",
            "deviceId": device_id,
            "name": device_name,
            "probe": false,
            "port": 53317u16,
        })
        .to_string();
        let greeted = tauri::async_runtime::spawn_blocking(move || {
            if http_json_request(&ip, target_port + 1, "POST", "/api/localsend/v2/verify", &body).is_ok() {
                // 问候可达才等待（对端拉起需 1-2s；拒连是即时的，超时说明主机本身不可达）
                for _ in 0..10 {
                    let addr = format!("{ip}:{target_port}");
                    if let Ok(a) = addr.parse::<std::net::SocketAddr>() {
                        if std::net::TcpStream::connect_timeout(
                            &a,
                            std::time::Duration::from_millis(500),
                        )
                        .is_ok()
                        {
                            return true;
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(300));
                }
            }
            false
        })
        .await
        .unwrap_or(false);
        if greeted {
            crate::log_debug!("对端接收服务已就绪: {target_ip}:{target_port}");
        } else {
            crate::log_warn!("唤醒对端接收服务未确认就绪，继续尝试传输: {target_ip}:{target_port}");
        }
    }
    let info = RegisterDtoV2 {
        alias: device_name,
        version: "2.2".to_string(),
        device_model: Some("Windows".to_string()),
        device_type: Some(DeviceType::Desktop),
        fingerprint: device_id,
        port: target_port,
        protocol: ProtocolType::Http,
        download: false,
    };

    // 文件分类（传输策略矩阵，见规格书）：
    // - tiny（<10KB 且非空）→ 每 20 个打包为 ustar tar 流，单会话聚合传输
    // - large/huge（>100MB）→ 8MB 分片续传（分片即独立文件单元，查 B 端已收分片只传缺失）
    // - 其余（small/normal/empty）→ 单文件流式上传，upload 端点并发
    // - symlink/special 已在扫描阶段跳过；sparse/hardlink 桌面端按整文件传输（降级）
    const CHUNK_SIZE: u64 = 8 * 1024 * 1024; // 8MB 大分块（局域网 RTT<3ms 下最优）
    const LARGE_THRESHOLD: u64 = 100 * 1024 * 1024; // >100MB 视为大文件
    const TINY_BATCH_SIZE: usize = 20; // tiny 每批聚合数
    let mut tiny: Vec<SendFileItem> = Vec::new();
    let mut normal: Vec<SendFileItem> = Vec::new();
    let mut large: Vec<(SendFileItem, u64)> = Vec::new();
    for f in &files {
        let size = std::fs::metadata(&f.abs_path).map(|m| m.len()).unwrap_or(0);
        if size > 0 && size < 10 * 1024 {
            tiny.push(f.clone());
        } else if size > LARGE_THRESHOLD {
            large.push((f.clone(), size));
        } else {
            normal.push(f.clone());
        }
    }
    let mut chunked_items: Vec<SendFileItem> = Vec::new();
    if !large.is_empty() {
        // 断点续传分片查询并行化：spawn_blocking 防止同步 HTTP 占住 async worker，
        // join_all 全部并发（原先逐文件串行、单次查询最长阻塞 ~4.5s）
        let queries: Vec<_> = large
            .iter()
            .map(|(f, _)| {
                let ip = target_ip.clone();
                let rel = f.rel_path.clone();
                tauri::async_runtime::spawn_blocking(move || {
                    query_chunk_status(&ip, target_port, &rel)
                })
            })
            .collect();
        let results = futures_util::future::join_all(queries).await;
        for ((f, size), res) in large.iter().zip(results) {
            let status = match res {
                Ok(Ok(v)) => Ok(v),
                _ => Err(()),
            };
            match status {
                Ok(received) => {
                    let total = ((size + CHUNK_SIZE - 1) / CHUNK_SIZE) as u32;
                    let mut idx = 0u32;
                    let mut off = 0u64;
                    while off < *size {
                        if !received.contains(&idx) {
                            let chunk_size = (*size).min(off + CHUNK_SIZE) - off;
                            let width = total.to_string().len();
                            chunked_items.push(SendFileItem {
                                rel_path: format!(
                                    "__chunked__/{}/{:0width$}/{:0width$}",
                                    pct_encode(&f.rel_path),
                                    idx,
                                    total,
                                    width = width
                                ),
                                abs_path: f.abs_path.clone(),
                                offset: Some(off),
                                size: Some(chunk_size),
                            });
                        }
                        off += CHUNK_SIZE;
                        idx += 1;
                    }
                    if !received.is_empty() {
                        crate::log_info!(
                            "断点续传: {} 已收 {} 个分片，本次补传缺失分片",
                            f.rel_path,
                            received.len()
                        );
                    }
                }
                Err(_) => {
                    // 查询失败（B 端不支持/不可达）→ 降级整文件传输
                    crate::log_warn!("分片状态查询失败，整文件传输: {}", f.rel_path);
                    normal.push(f.clone());
                }
            }
        }
    }
    // 上传单元列表：batch（tar 聚合）优先，其后是分片/普通文件
    let mut upload_items: Vec<SendFileItem> = Vec::with_capacity(files.len() + 1);
    let mut batch_tmp: Vec<PathBuf> = Vec::new();
    for chunk in tiny.chunks(TINY_BATCH_SIZE) {
        let tar = pack_batch(chunk)?;
        // 文件名必须唯一：同一毫秒内多个 batch 会冲突互相覆盖（致命），加序号区分
        let tmp = std::env::temp_dir().join(format!(
            "backup_batch_{}_{}_{}.tar",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            batch_tmp.len()
        ));
        std::fs::write(&tmp, &tar).map_err(AppError::from_display)?;
        batch_tmp.push(tmp.clone());
        upload_items.push(SendFileItem {
            rel_path: format!("__batch__.agg.{}", batch_tmp.len()),
            abs_path: tmp.to_string_lossy().to_string(),
            offset: None,
            size: None,
        });
    }
    upload_items.extend(chunked_items);
    upload_items.extend(normal.iter().cloned());
    let batch_count = batch_tmp.len();

    // 流式加密的输出大小可精确预计算（头 12B + 每块 32B 开销 + 明文），
    // 因此加密完全在 upload 流内进行（upload_single 内嵌 LSBK 加密流），
    // 不再需要「全文读→写密文临时文件→上传再读」的三遍磁盘 IO 与双倍磁盘占用
    let sizes: Vec<u64> = upload_items
        .iter()
        .map(|f| {
            let plain = f
                .size
                .unwrap_or_else(|| std::fs::metadata(&f.abs_path).map(|m| m.len()).unwrap_or(0));
            if enc_key.is_some() {
                crate::crypto::enc_output_size(plain)
            } else {
                plain
            }
        })
        .collect();

    // 构建文件清单（size = 加密后大小 / 分片大小）
    let mut files_map: HashMap<String, FileDto> = HashMap::new();
    for (i, f) in upload_items.iter().enumerate() {
        let is_batch = i < batch_count;
        files_map.insert(
            format!("f{i}"),
            FileDto {
                id: format!("f{i}"),
                file_name: f.rel_path.clone(),
                size: sizes[i],
                file_type: if is_batch {
                    "application/x-batch-agg".to_string()
                } else {
                    infer_file_type(&f.rel_path)
                },
                sha256: None,
                preview: None,
                metadata: file_modified_rfc3339(&f.abs_path).map(|m| {
                    localsend::model::transfer::FileMetadata {
                        modified: Some(m),
                        accessed: None,
                    }
                }),
            },
        );
    }

    // 注册（通知对方本机在线；失败不阻断传输）
    let reg = client
        .register(ProtocolType::Http, &target_ip, target_port, info.clone())
        .await;
    match &reg {
        Ok(_) => crate::log_debug!("register 成功"),
        Err(e) => crate::log_warn!("register 失败（不阻断传输）: {e}"),
    }

    // prepare-upload：协商会话
    let payload = PrepareUploadRequestDtoV2 {
        info,
        files: files_map,
    };
    let prepared = client
        .prepare_upload(
            ProtocolType::Http,
            &target_ip,
            target_port,
            None,
            payload,
            None,
            cancel.clone(),
        )
        .await
        .map_err(|e| AppError(format!("准备上传失败: {e}")))?;

    // 无文件被接受（目标端拒绝或 204）
    let Some(response) = prepared.response else {
        crate::log_info!("prepare-upload 无响应（目标端未接受任何文件）");
        // 清理临时文件（仅聚合 batch；加密已无临时文件）
        for t in &batch_tmp {
            let _ = std::fs::remove_file(t);
        }
        return Ok(0);
    };
    crate::log_info!(
        "prepare-upload 成功 session={} 接受文件数={}",
        crate::logger::mask(&response.session_id),
        response.files.len()
    );


    // 第 2 遍：流式上传——加密在流内进行（upload_single 内嵌 LSBK 加密流），全程零临时文件。
    // batch tar 顺序上传；分片/普通文件用 buffer_unordered(8) 滚动并发：
    // 任何时刻保持 8 个在途，单个慢文件不再拖住整组（原先按组 join_all 的 convoy 问题）
    use std::sync::atomic::Ordering;
    let total_units = upload_items.len() as u64;
    let sent_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let planned_bytes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    // batch 文件（upload_items[0..batch_count]）顺序上传
    for (bi, f) in upload_items.iter().take(batch_count).enumerate() {
        let file_id = format!("f{bi}");
        let Some(token) = response.files.get(&file_id) else {
            continue;
        };
        let upload_size = sizes[bi];
        planned_bytes.fetch_add(upload_size, Ordering::Relaxed);
        crate::log_info!("批量聚合上传 tiny → {} ({}B)", f.rel_path, upload_size);
        upload_single_with_retry(
            &client,
            target_ip.clone(),
            target_port,
            response.session_id.clone(),
            file_id,
            token.clone(),
            PathBuf::from(&f.abs_path),
            upload_size,
            None,
            None,
            enc_key,
            cancel.clone(),
            app.clone(),
            f.rel_path.clone(),
            started,
            sent_counter.load(Ordering::Relaxed),
            total_units,
        )
        .await
        .map_err(|e| {
            for t in &batch_tmp {
                let _ = std::fs::remove_file(t);
            }
            e
        })?;
        sent_counter.fetch_add(1, Ordering::Relaxed);
    }
    // 分片/普通文件：滚动 8 并发（完成一个补位一个）
    let normal_units: Vec<(usize, &SendFileItem)> = upload_items
        .iter()
        .enumerate()
        .filter(|(i, _)| *i >= batch_count)
        .collect();
    let mut futs = Vec::with_capacity(normal_units.len());
    for (i, f) in normal_units {
        let Some(token) = response.files.get(&format!("f{i}")).cloned() else {
            crate::log_debug!("目标端未接受 {}，跳过", f.rel_path);
            continue;
        };
        planned_bytes.fetch_add(sizes[i], Ordering::Relaxed);
        let sent_now = sent_counter.load(Ordering::Relaxed);
        let counter = sent_counter.clone();
        let app2 = app.clone();
        let ip = target_ip.clone();
        let sid = response.session_id.clone();
        let cancel2 = cancel.clone();
        let rel = f.rel_path.clone();
        let path = PathBuf::from(&f.abs_path);
        let size_i = sizes[i];
        let offset = f.offset;
        let csize = f.size;
        let client_ref = &client;
        futs.push(async move {
            upload_single_with_retry(
                client_ref,
                ip,
                target_port,
                sid,
                format!("f{i}"),
                token,
                path,
                size_i,
                offset,
                csize,
                enc_key,
                cancel2,
                app2.clone(),
                rel,
                started,
                sent_now,
                total_units,
            )
            .await?;
            // 完成级进度事件：前端实时刷新文件数（字节级进度在 upload_single 流内 250ms 限频）
            let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
            let _ = app2.emit(
                "send-progress",
                serde_json::json!({
                    "sent": n,
                    "total": total_units,
                    "fileName": "",
                    "stage": "sending",
                    "bytes": 0,
                    "totalBytes": 0,
                    "bytesSent": 0,
                    "elapsedMs": started.elapsed().as_millis() as u64,
                }),
            );
            Ok::<(), AppError>(())
        });
    }
    let results: Result<Vec<()>, AppError> = futures_util::stream::iter(futs)
        .buffer_unordered(8)
        .try_collect()
        .await;
    if let Err(e) = results {
        for t in &batch_tmp {
            let _ = std::fs::remove_file(t);
        }
        return Err(e);
    }
    let sent = sent_counter.load(Ordering::Relaxed);
    let total_bytes = planned_bytes.load(Ordering::Relaxed);
    crate::log_info!("发送完成: 共发送 {sent}/{total_units} 个传输单元");

    // 记录传输历史（SQLite）：方向=发送、对端、文件数、字节、耗时
    if let Err(e) = app
        .state::<crate::AppState>()
        .db
        .add_transfer("out", &target_ip, sent, total_bytes, started.elapsed().as_millis() as u64)
    {
        crate::log_warn!("写入传输历史失败: {e}");
    }
    // 通知前端刷新传输历史（发送方自己的记录也实时可见）
    let _ = app.emit("transfers-updated", ());

    // 清理临时文件（仅剩聚合 batch tar；加密路径已零临时文件）
    for t in &batch_tmp {
        let _ = std::fs::remove_file(t);
    }

    Ok(sent)
}

/// 单个传输单元流式上传（含块级进度事件，250ms 限频）。
/// enc_key 存在时边读边加密（LSBK 多块流式，输出大小与 crypto::enc_output_size 预计算一致），
/// 全程零临时文件：加密不再有「全文读→写临时→再读」的三遍磁盘 IO。
/// 参数全部 owned：供并发任务 move 进 future，避免借用循环局部变量。
#[allow(clippy::too_many_arguments)]
async fn upload_single(
    client: &LsHttpClientV2,
    target_ip: String,
    target_port: u16,
    session_id: String,
    file_id: String,
    token: String,
    upload_path: PathBuf,
    upload_size: u64,
    offset: Option<u64>,
    chunk_size: Option<u64>,
    enc_key: Option<[u8; 32]>,
    cancel: tokio_util::sync::CancellationToken,
    app: tauri::AppHandle,
    file_name: String,
    started: std::time::Instant,
    sent_so_far: u64,
    total_units: u64,
) -> Result<(), AppError> {
    crate::log_debug!("开始上传 {} ({}B)", file_name, upload_size);
    let mut file = tokio::fs::File::open(&upload_path)
        .await
        .map_err(|e| AppError(format!("打开文件失败 {}: {e}", upload_path.display())))?;
    // 分片续传：seek 到 offset 并只读 size 字节（加密与明文都按明文区间读取，加密在流内进行）
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    if let Some(off) = offset {
        file.seek(std::io::SeekFrom::Start(off))
            .await
            .map_err(|e| AppError(format!("分片 seek 失败 {}: {e}", upload_path.display())))?;
    }
    let limited = file.take(chunk_size.unwrap_or(u64::MAX));
    // 块级进度：包装流，每 ~250ms 推送一次 send-progress（含已传/总字节，前端实时速率）
    let fname = file_name.clone();
    let mut bytes_sent = 0u64;
    let mut last_progress = std::time::Instant::now();
    let app2 = app.clone();
    let mut on_chunk = move |n: usize| {
        bytes_sent += n as u64;
        let now = std::time::Instant::now();
        if now.duration_since(last_progress).as_millis() >= 250 {
            last_progress = now;
            let _ = app2.emit(
                "send-progress",
                serde_json::json!({
                    "sent": sent_so_far,
                    "total": total_units,
                    "fileName": fname,
                    "stage": "sending",
                    "bytes": bytes_sent,
                    "totalBytes": upload_size,
                    "bytesSent": bytes_sent,
                    "elapsedMs": started.elapsed().as_millis() as u64,
                }),
            );
        }
    };
    let body = if let Some(k) = enc_key {
        // 流式加密：凑满 8MB 明文块（短读合并）→ GCM 原地密封 → 产出网络块；
        // 空文件仍输出 12B 格式头（与 encrypt_stream 行为一致，接收端可识别）
        let stream = futures_util::stream::unfold(
            (limited, k, false),
            |(mut r, key, header_sent)| async move {
                let mut buf = vec![0u8; crate::crypto::STREAM_ENC_BLOCK];
                let mut total = 0usize;
                while total < buf.len() {
                    match r.read(&mut buf[total..]).await {
                        Ok(0) => break,
                        Ok(n) => total += n,
                        Err(e) => return Some((Err(e), (r, key, header_sent))),
                    }
                }
                if total == 0 {
                    if header_sent {
                        return None; // 正常 EOF
                    }
                    let out = crate::crypto::stream_header_bytes(crate::crypto::STREAM_ENC_BLOCK)
                        .to_vec();
                    return Some((Ok(out), (r, key, true)));
                }
                let mut out = Vec::with_capacity(12 + total + 32);
                if !header_sent {
                    out.extend_from_slice(&crate::crypto::stream_header_bytes(
                        crate::crypto::STREAM_ENC_BLOCK,
                    ));
                }
                buf.truncate(total);
                match crate::crypto::seal_stream_block(&key, &mut buf, &mut out) {
                    Ok(()) => Some((Ok(out), (r, key, true))),
                    Err(e) => Some((
                        Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                        (r, key, true),
                    )),
                }
            },
        )
        .map(move |chunk| {
            if let Ok(data) = &chunk {
                on_chunk(data.len());
            }
            chunk
        });
        localsend::reqwest::Body::wrap_stream(stream)
    } else {
        let stream = tokio_util::io::ReaderStream::with_capacity(limited, 256 * 1024).map(
            move |chunk| {
                if let Ok(data) = &chunk {
                    on_chunk(data.len());
                }
                chunk
            },
        );
        localsend::reqwest::Body::wrap_stream(stream)
    };
    client
        .upload(
            ProtocolType::Http,
            &target_ip,
            target_port,
            None,
            &session_id,
            &file_id,
            &token,
            body,
            cancel,
        )
        .await
        .map_err(|e| AppError(format!("上传失败 {file_name}: {e}")))?;
    crate::log_debug!("上传完成 {file_name} ({}B)", upload_size);
    Ok(())
}

// ============================================================
// scheduler v1 扩展：422 重试 + 指数退避
// ============================================================

/// 从错误字符串中提取 HTTP 状态码（用于判断是否 422 校验失败）
fn extract_status_code(err: &str) -> Option<u16> {
    // LocalSend 返回格式：JSON {"statusCode":422,...} 或 "statusCode":422
    err.split("statusCode")
        .nth(1)
        .and_then(|s| s.chars().filter(|c| c.is_ascii_digit()).take(3).collect::<String>().parse().ok())
}

/// 判断错误是否表示校验失败（422）
fn is_422_error(err: &str) -> bool {
    extract_status_code(err) == Some(422)
}

/// 带重试的上传包装器：检测到 422 校验失败时，使用指数退避重试（最多 5 次）。
/// 其他错误直接返回。
async fn upload_single_with_retry(
    client: &LsHttpClientV2,
    target_ip: String,
    target_port: u16,
    session_id: String,
    file_id: String,
    token: String,
    upload_path: PathBuf,
    upload_size: u64,
    offset: Option<u64>,
    chunk_size: Option<u64>,
    enc_key: Option<[u8; 32]>,
    cancel: tokio_util::sync::CancellationToken,
    app: tauri::AppHandle,
    file_name: String,
    started: std::time::Instant,
    sent_so_far: u64,
    total_units: u64,
) -> Result<(), AppError> {
    const MAX_RETRIES: u32 = 5;

    let mut attempt = 0;
    loop {
        match upload_single(
            client,
            target_ip.clone(),
            target_port,
            session_id.clone(),
            file_id.clone(),
            token.clone(),
            upload_path.clone(),
            upload_size,
            offset,
            chunk_size,
            enc_key,
            cancel.clone(),
            app.clone(),
            file_name.clone(),
            started,
            sent_so_far,
            total_units,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                let err_str = e.0.as_str();
                // 提取状态码判断
                let status = extract_status_code(err_str).unwrap_or(0);

                // 仅 422/408/429/5xx 可重试
                if !is_checksum_failure_retryable(status) {
                    crate::log_warn!("上传失败（不重试 status={}) {}", status, err_str);
                    return Err(e);
                }

                if attempt >= MAX_RETRIES {
                    crate::log_error!("上传重试耗尽（status={}) {}", status, err_str);
                    return Err(e);
                }

                let delay_ms = jittered_backoff_ms(attempt);
                crate::log_warn!(
                    "上传 422 校验失败，重试 {}/{}（delay={}ms）: {}",
                    attempt + 1,
                    MAX_RETRIES,
                    delay_ms,
                    file_name
                );
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                attempt += 1;
                // 重试时重新打开文件（upload_single 内部会 seek 到 offset）
            }
        }
    }
}

// ============================================================
// ustar tar 打包/解包（手写实现，不引依赖）
// tiny 文件批量聚合：多个小文件打包为单一 tar 流，一次连接传输
// ============================================================

/// 把一批 tiny 文件打包为自定义聚合字节流（批次 ≤ 数百个 10KB 级文件，内存可接受）。
/// 格式（无对齐、无校验和、无 100 字符文件名限制）：
/// `[u32 LE 文件名长度][文件名][u64 LE 文件大小][文件内容]` 循环。
/// fileType 仍标记为 application/x-tar-batch（协议兼容），内容为上述自定义格式。
fn pack_batch(files: &[SendFileItem]) -> Result<Vec<u8>, AppError> {
    let mut out: Vec<u8> = Vec::new();
    for f in files {
        let data = std::fs::read(&f.abs_path)
            .map_err(|e| AppError(format!("读取小文件失败 {}: {e}", f.abs_path)))?;
        let name = f.rel_path.as_bytes();
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(&data);
    }
    Ok(out)
}

/// 路径安全过滤：去掉空段/`.`/`..`，防穿越
fn sanitize_rel_path(name: &str) -> String {
    let mut parts = Vec::new();
    for comp in name.split('/') {
        match comp {
            "" | "." | ".." => continue,
            c => parts.push(c),
        }
    }
    parts.join("/")
}

/// 自定义聚合格式解包：读字节流，按成员 relPath 写入目标目录（防穿越 + 大小校验）。
/// 返回写入的成员数。
fn unpack_batch(bytes: &[u8], target_dir: &Path) -> Result<usize, AppError> {
    let mut off = 0usize;
    let mut count = 0usize;
    while off + 12 <= bytes.len() {
        let name_len = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
            as usize;
        off += 4;
        if off + name_len > bytes.len() {
            crate::log_warn!("batch 解包: 文件名越界，中断");
            break;
        }
        let name = String::from_utf8_lossy(&bytes[off..off + name_len]).into_owned();
        off += name_len;
        if off + 8 > bytes.len() {
            crate::log_warn!("batch 解包: 大小字段越界，中断");
            break;
        }
        let size = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap_or([0u8; 8]));
        off += 8;
        if off + size as usize > bytes.len() {
            crate::log_warn!("batch 解包: 成员数据越界，中断 {}", name);
            break;
        }
        let rel = sanitize_rel_path(&name);
        if !rel.is_empty() {
            let target = target_dir.join(&rel);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(AppError::from_display)?;
            }
            std::fs::write(&target, &bytes[off..off + size as usize])
                .map_err(AppError::from_display)?;
            count += 1;
        }
        off += size as usize;
    }
    Ok(count)
}

/// URL 百分号编码（分片文件名内嵌正式相对路径用；保留字母数字及 `-_.`）
fn pct_encode(s: &str) -> String {
    // 预分配 + hex 查表：原先每个非安全字节一次 format! 堆分配
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => out.push(b as char),
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 查询 B 端大文件已收分片（GET 配对服务 /api/backup/v1/chunk-status，断点续传用）
pub fn query_chunk_status(ip: &str, port: u16, rel_path: &str) -> Result<Vec<u32>, AppError> {
    let path = format!(
        "/api/backup/v1/chunk-status?encodedPath={}",
        pct_encode(rel_path)
    );
    let v = http_json_request(ip, port + 1, "GET", &path, "")?;
    Ok(v.get("receivedChunks")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|c| c.as_u64().map(|u| u as u32)).collect())
        .unwrap_or_default())
}

/// 分片合并：`__chunked__/{pct}/` 下所有 part 按 index 顺序拼接为正式文件，删除 part 目录。
/// 全部到齐返回 true；未到齐返回 false（等待后续分片）。
/// 只增不删语义：目标已存在且大小一致 → 视为已备份跳过；大小不一致 → 冲突重命名。
fn merge_chunked(receive_dir: &Path, pct: &str, total: u32) -> Result<bool, AppError> {
    let part_dir = receive_dir.join(".chunks").join(pct);
    // 收集时一次 stat 缓存片长（原先校验一遍 + 求和再一遍 = 每片两次元数据查询）
    let mut parts: Vec<(u32, PathBuf, u64)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&part_dir) {
        for e in rd.flatten() {
            if let Ok(idx) = e.file_name().to_string_lossy().parse::<u32>() {
                let len = std::fs::metadata(e.path()).map(|m| m.len()).unwrap_or(0);
                parts.push((idx, e.path(), len));
            }
        }
    }
    if parts.len() != total as usize {
        return Ok(false); // 严格到齐：缺失或残留多于 total 都等待/失败（防旧版本残留拼接损坏）
    }
    parts.sort_by_key(|(i, _, _)| *i);
    // 校验索引必须恰好 0..total 且每片大小合法（前 total-1 片 = 8MB，最后片 ≤ 8MB）
    let mut expected: u64 = 0;
    for (k, (idx, _p, len)) in parts.iter().enumerate() {
        if *idx != k as u32 {
            crate::log_error!("分片索引不连续（应 {k} 实得 {idx}），放弃合并: {}", pct_decode(pct));
            let _ = std::fs::remove_dir_all(&part_dir);
            return Err(AppError("分片索引不连续，已清理".to_string()));
        }
        if *len == 0 || *len > 8 * 1024 * 1024 {
            crate::log_error!("分片大小异常（{}B），放弃合并: {}", len, pct_decode(pct));
            let _ = std::fs::remove_dir_all(&part_dir);
            return Err(AppError("分片大小异常，已清理".to_string()));
        }
        expected += len;
    }
    let real_name = pct_decode(pct);
    // 目标路径（冲突处理）
    let target = receive_dir.join(&real_name);
    let mut final_path = target;
    if final_path.exists() {
        let existing = std::fs::metadata(&final_path).map(|m| m.len()).unwrap_or(0);
        if existing == expected {
            // 已备份（大小一致）→ 清理 part 目录即可
            let _ = std::fs::remove_dir_all(&part_dir);
            return Ok(true);
        }
        // 冲突 → _MMDDhhmmss 重命名
        let mut candidate = rename_with_suffix(
            Path::new(&real_name),
            &format_mmddhhmmss(now_utc_secs()),
        );
        let mut counter = 1;
        while receive_dir.join(&candidate).exists() {
            candidate = rename_with_counter(&candidate, counter);
            counter += 1;
        }
        final_path = receive_dir.join(&candidate);
        crate::log_warn!("分片合并冲突重命名: {} → {}", real_name, candidate.display());
    }
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent).map_err(AppError::from_display)?;
    }
    // 1MB 缓冲手写复制：std::io::copy 默认 8KB 缓冲，GB 级分片合并时 syscall 数量爆炸
    {
        use std::io::{Read, Write};
        let mut out = std::fs::File::create(&final_path).map_err(AppError::from_display)?;
        let mut buf = vec![0u8; 1024 * 1024];
        for (_, p, _) in &parts {
            let mut f = std::fs::File::open(p).map_err(AppError::from_display)?;
            loop {
                let n = f.read(&mut buf).map_err(AppError::from_display)?;
                if n == 0 {
                    break;
                }
                out.write_all(&buf[..n]).map_err(AppError::from_display)?;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&part_dir);
    Ok(true)
}

/// 计算接收文件的保存路径：目录层级重建 + 冲突自动重命名（永不覆盖）
///
/// 规则与 shared-core `conflict.ts` 一致：
/// - 目标不存在 → 直接用相对路径
/// - 目标存在且内容一致（大小相同、mtime 相同或未知）→ 视为已备份，覆盖无副作用
/// - 目标存在且内容不同 → 重命名为 `原名_MMDDhhmmss.扩展名`，仍冲突则追加序号
///
/// 安全：过滤掉路径穿越组件（`..`、`.`），防止恶意文件名写入备份目录之外。
fn resolve_target_path(receive_dir: &Path, file: &FileDto) -> PathBuf {
    // 防路径穿越：过滤掉 `..` 和 `.` 组件
    let rel = Path::new(&file.file_name);
    let mut safe = PathBuf::new();
    for comp in rel.components() {
        match comp {
            std::path::Component::ParentDir | std::path::Component::CurDir => continue,
            other => safe.push(other.as_os_str()),
        }
    }
    // 全部被过滤（极端情况）→ 用原始文件名以不丢失文件
    let rel = if safe.as_os_str().is_empty() {
        rel.file_name().map(PathBuf::from).unwrap_or_default()
    } else {
        safe
    };
    // 绝对路径 → 只保留文件名
    let rel = if rel.is_absolute() {
        rel.file_name().map(PathBuf::from).unwrap_or_default()
    } else {
        rel
    };
    let target = receive_dir.join(&rel);

    if !target.exists() {
        return target;
    }

    // 大小写冲突检测（Windows 大小写不敏感）：同目录存在仅大小写不同的路径 → 视为冲突，
    // 否则 "Photo.jpg" 与 "photo.JPG" 会互相覆盖（ext4/NTFS 语义差异）
    #[cfg(windows)]
    {
        if let Some(parent) = target.parent() {
            let target_lower = target.to_string_lossy().to_lowercase();
            let mut conflict = false;
            if let Ok(rd) = std::fs::read_dir(parent) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p == target {
                        continue;
                    }
                    // ASCII 忽略大小写比较，免掉逐项 to_lowercase 分配
                    //（Windows 路径的大小写冲突段实际都是 ASCII）
                    if p.to_string_lossy().eq_ignore_ascii_case(&target_lower) {
                        conflict = true;
                        break;
                    }
                }
            }
            if conflict {
                crate::log_warn!(
                    "大小写冲突: {} 与同目录仅大小写不同的文件冲突，重命名",
                    target.display()
                );
                let ts_secs = file
                    .metadata
                    .as_ref()
                    .and_then(|m| m.modified.as_deref())
                    .and_then(parse_timestamp_secs)
                    .unwrap_or_else(now_utc_secs);
                let mut candidate = rename_with_suffix(&rel, &format_mmddhhmmss(ts_secs));
                let mut counter = 1;
                while receive_dir.join(&candidate).exists() {
                    candidate = rename_with_counter(&candidate, counter);
                    counter += 1;
                }
                return receive_dir.join(candidate);
            }
        }
    }

    // 已存在：判断是否与即将上传的文件内容一致
    let identical = std::fs::metadata(&target)
        .map(|m| {
            let same_size = m.len() == file.size;
            let same_mtime = match file.metadata.as_ref() {
                Some(md) => match md.modified.as_deref() {
                    Some(ts) => parse_timestamp_secs(ts) == modified_secs(&m),
                    // 发送方未提供 mtime → 仅按大小判断
                    None => true,
                },
                // 无 metadata（手机端）→ 仅按大小判断
                None => true,
            };
            same_size && same_mtime
        })
        .unwrap_or(false);

    if identical {
        return target;
    }

    // 冲突 → 重命名 _MMDDhhmmss
    let ts_secs = file
        .metadata
        .as_ref()
        .and_then(|m| m.modified.as_deref())
        .and_then(parse_timestamp_secs)
        .unwrap_or_else(now_utc_secs);
    let mut candidate = rename_with_suffix(&rel, &format_mmddhhmmss(ts_secs));
    let mut counter = 1;
    while receive_dir.join(&candidate).exists() {
        candidate = rename_with_counter(&candidate, counter);
        counter += 1;
    }
    crate::log_warn!(
        "冲突重命名: {} → {}",
        target.display(),
        receive_dir.join(&candidate).display()
    );
    receive_dir.join(candidate)
}

/// `原名_MMDDhhmmss.扩展名`（与 shared-core `conflictRename` 同规则）
fn rename_with_suffix(rel: &Path, suffix: &str) -> PathBuf {
    let parent = rel.parent().unwrap_or_else(|| Path::new(""));
    let name = rel
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let (base, ext) = match name.rfind('.') {
        Some(idx) if idx > 0 => (&name[..idx], &name[idx..]),
        _ => (name.as_str(), ""),
    };
    parent.join(format!("{base}_{suffix}{ext}"))
}

/// 重命名后仍冲突 → 追加序号 `_N`（与 shared-core `resolveFileName` 一致）
fn rename_with_counter(candidate: &Path, counter: u32) -> PathBuf {
    let parent = candidate.parent().unwrap_or_else(|| Path::new(""));
    let name = candidate
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let (base, ext) = match name.rfind('.') {
        Some(idx) if idx > 0 => (&name[..idx], &name[idx..]),
        _ => (name.as_str(), ""),
    };
    parent.join(format!("{base}_{counter}{ext}"))
}

/// 文件 mtime 的 Unix 秒
fn modified_secs(m: &std::fs::Metadata) -> Option<i64> {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}

/// 解析 LocalSend 时间戳（RFC3339，如 "2025-08-15T08:23:45Z"）为 Unix 秒
fn parse_timestamp_secs(ts: &str) -> Option<i64> {
    let Ok(dt) = time::OffsetDateTime::parse(
        ts,
        &time::format_description::well_known::Rfc3339,
    ) else {
        return None;
    };
    Some(dt.unix_timestamp())
}

/// 文件 mtime → RFC3339 字符串（发送端填 FileDto.metadata）
fn file_modified_rfc3339(abs_path: &str) -> Option<String> {
    let meta = std::fs::metadata(abs_path).ok()?;
    let modified = meta.modified().ok()?;
    let millis = modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis() as u64;
    let secs = (millis / 1000) as i64;
    let dt = time::OffsetDateTime::from_unix_timestamp(secs).ok()?;
    dt.format(&time::format_description::well_known::Rfc3339).ok()
}

/// 设置文件 mtime（接收端保留发送方时间戳）
fn set_file_mtime(path: &Path, secs: i64) -> std::io::Result<()> {
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs.max(0) as u64);
    let f = std::fs::File::options().write(true).open(path)?;
    f.set_modified(t)
}

/// 当前 UTC Unix 秒
fn now_utc_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Unix 秒 → `MMDDhhmmss`（UTC，用于重命名后缀；仅需唯一性，无需本地时区）
fn format_mmddhhmmss(secs: i64) -> String {
    let Ok(dt) = time::OffsetDateTime::from_unix_timestamp(secs) else {
        return "0000000000".to_string();
    };
    let Ok(fmt) = time::format_description::parse_borrowed::<3>(
        "[month][day][hour][minute][second]",
    ) else {
        return "0000000000".to_string();
    };
    dt.format(&fmt).unwrap_or_else(|_| "0000000000".to_string())
}

/// 根据文件名推断 LocalSend 文件类型（与 shared-core `inferFileType` 一致）
fn infer_file_type(name: &str) -> String {
    let lower = name.to_lowercase();
    if lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".png")
        || lower.ends_with(".gif")
        || lower.ends_with(".webp")
        || lower.ends_with(".bmp")
    {
        "image".to_string()
    } else if lower.ends_with(".mp4")
        || lower.ends_with(".mkv")
        || lower.ends_with(".avi")
        || lower.ends_with(".mov")
        || lower.ends_with(".webm")
    {
        "video".to_string()
    } else if lower.ends_with(".mp3")
        || lower.ends_with(".wav")
        || lower.ends_with(".flac")
        || lower.ends_with(".m4a")
        || lower.ends_with(".aac")
    {
        "audio".to_string()
    } else {
        "file".to_string()
    }
}

/// 目录扫描条目（Tauri 命令返回值）
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannedEntry {
    /// 相对路径（含目录层级）
    rel_path: String,
    /// 文件大小（字节）
    size: u64,
    /// 修改时间（Unix 毫秒，与 shared-core mtime 单位一致）
    mtime: u64,
}

/// 递归扫描目录，返回文件清单（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
///
/// 重 IO 操作：spawn_blocking 异步执行，避免阻塞 Tauri 命令线程池导致窗口冻结。
pub async fn scan_directory(dir: String) -> Result<Vec<ScannedEntry>, AppError> {
    crate::log_debug!("扫描目录: {dir}");
    let dir_for_task = dir.clone();
    let entries = tokio::task::spawn_blocking(move || {
        let mut entries = Vec::new();
        scan_dir_recursive(&PathBuf::from(&dir_for_task), "", &mut entries)?;
        Ok::<_, AppError>(entries)
    })
    .await
    .map_err(|e| AppError(format!("扫描任务执行失败: {e}")))??;
    crate::log_debug!("扫描目录完成: {dir} 共 {} 条", entries.len());
    Ok(entries)
}

fn scan_dir_recursive(
    base: &Path,
    rel: &str,
    out: &mut Vec<ScannedEntry>,
) -> Result<(), AppError> {
    let cur = if rel.is_empty() {
        base.to_path_buf()
    } else {
        base.join(rel)
    };
    for entry in std::fs::read_dir(&cur).map_err(AppError::from_display)? {
        // 跳过不可读条目（损坏符号链接、权限不足等），而非中止整个目录扫描
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                crate::log_warn!("跳过不可读目录条目: {e}");
                continue;
            }
        };
        let name = entry.file_name().to_string_lossy().to_string();
        let child_rel = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        let ftype = match entry.file_type() {
            Ok(t) => t,
            Err(e) => {
                crate::log_warn!("跳过不可读类型 {}: {e}", name);
                continue;
            }
        };
        // 符号链接：归档备份不跟随链接（rsync -a 隐含 -l 语义），跳过并记录
        if ftype.is_symlink() {
            crate::log_warn!("跳过符号链接（不跟随，归档语义）: {child_rel}");
            continue;
        }
        // 内部文件/目录（分片、解密临时、聚合批次）不进入清单，避免污染 B 端三路对比。
        // __chunked__ 同为分片残留名（旧版发送端/异构端落盘命名），一并排除
        if name == ".chunks"
            || name == "__chunked__"
            || name.ends_with(".dec_tmp")
            || name.starts_with("__batch__")
        {
            crate::log_debug!("跳过内部文件: {child_rel}");
            continue;
        }
        // 特殊文件（设备/管道/套接字）：本项目场景极少，跳过并记录（rsync -D 需 root）
        if !ftype.is_file() && !ftype.is_dir() {
            crate::log_warn!("跳过特殊文件（设备/管道/套接字）: {child_rel}");
            continue;
        }
        if ftype.is_dir() {
            scan_dir_recursive(base, &child_rel, out)?;
        } else if ftype.is_file() {
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    crate::log_warn!("跳过不可读元数据 {}: {e}", name);
                    continue;
                }
            };
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            out.push(ScannedEntry {
                rel_path: child_rel,
                size: meta.len(),
                mtime,
            });
        }
    }
    Ok(())
}

/// 解密已写入磁盘的文件（原地替换）。
/// 返回 `Ok(true)` 表示已解密；`Ok(false)` 表示非本应用加密格式（原样保留）。
fn decrypt_file_in_place(key: &[u8; 32], path: &Path) -> Result<bool, String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).map_err(|e| format!("读取文件失败: {e}"))?;
    // 先 peek 魔数：非本应用加密格式 → 原样保留（不重写磁盘）
    let mut head = [0u8; 4];
    let got = f.read(&mut head).map_err(|e| e.to_string())?;
    if got < 4 || &head != crate::crypto::MAGIC {
        return Ok(false);
    }
    f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("dec_tmp");
    {
        let mut w = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        crate::crypto::decrypt_stream(key, &mut f, &mut w)?;
    }
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(true)
}

// ================================================================
// 配对服务（端口 = 接收端口 + 1，即 53318）
//
// 接收服务器由 localsend crate 托管、无法加自定义路由，因此配对相关的
// 两个端点（/verify 连接码验证、/sync-dir 目录映射同步）由本小型 HTTP
// 服务提供。手机端配对时向 桌面端口+1 发起请求。
// ================================================================

/// 配对服务全局状态（由 lib.rs 注入）
pub struct PairingState {
    /// direction → 对方同步过来的目录名
    pub synced_dirs: Mutex<HashMap<String, String>>,
    /// 双端配对记录：对方验证本机码通过后记录（deviceId → {name,ip,port,fingerprint}）
    pub paired: Mutex<HashMap<String, serde_json::Value>>,
}

impl Default for PairingState {
    fn default() -> Self {
        Self {
            synced_dirs: Mutex::new(HashMap::new()),
            paired: Mutex::new(HashMap::new()),
        }
    }
}

/// 配对服务端口（接收端口 + 1）
pub fn pairing_port(receiver_port: u16) -> u16 {
    receiver_port + 1
}

/// 启动配对服务（跟随接收服务启停：可见时启动，隐藏时由 stop_pairing_server 关闭）。
/// 端口被占用时短暂重试（旧实例关闭后端口释放有微小竞态窗口）。
pub fn spawn_pairing_server(app: AppHandle) {
    let port = pairing_port(53317);
    let mut listener = None;
    for attempt in 0..5 {
        match std::net::TcpListener::bind(("0.0.0.0", port)) {
            Ok(l) => {
                listener = Some(l);
                break;
            }
            Err(e) if attempt < 4 => {
                std::thread::sleep(std::time::Duration::from_millis(120));
            }
            Err(e) => {
                crate::log_warn!("配对服务端口 {port} 绑定失败（可能已被占用）: {e}");
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
    std::thread::spawn(move || {
        crate::log_info!("配对服务已启动: 端口 {port}");
        for stream in thread_listener.incoming() {
            match stream {
                Ok(mut s) => {
                    let app = app.clone();
                    std::thread::spawn(move || {
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

/// 停止配对服务（关闭监听 → accept 循环退出）。隐藏模式（接收服务停止）时调用。
pub fn stop_pairing_server(app: AppHandle) {
    if let Ok(mut st) = app.state::<TransferState>().pairing_listener.lock() {
        if let Some(l) = st.take() {
            drop(l);
        }
    }
}

/// 镜像模式：把对端多余文件移动到 <接收目录>/delete/ 下（假删除，保留原相对路径）。
/// 返回成功移动的文件数；接收服务未运行（无接收目录）时返回 0。
fn handle_move_to_delete(app: &AppHandle, body: &str) -> usize {
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

/// 处理单条配对服务连接（读请求 → 路由 → 回 JSON）
fn handle_pairing_conn(app: AppHandle, stream: &mut std::net::TcpStream) -> Result<(), AppError> {
    use std::io::{Read, Write};
    let client_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    // 循环读取直到完整请求（头部 \r\n\r\n + Content-Length 字节 body），
    // 不再依赖单次 8192 字节读取（大 JSON body 如多设备配对信息可能被截断）
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut search_from = 0usize;
    let mut hdr_end_opt: Option<usize> = None;
    loop {
        let n = stream.read(&mut tmp).map_err(AppError::from_display)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        // 增量扫描：只在头部未找到且新数据到达时从上次断点继续（避免每读一次全量重扫的 O(n²)）
        if hdr_end_opt.is_none() {
            if let Some(rel) = buf[search_from..].windows(4).position(|w| w == b"\r\n\r\n") {
                hdr_end_opt = Some(search_from + rel);
            } else {
                search_from = buf.len().saturating_sub(3);
            }
        }
        if let Some(hdr_end) = hdr_end_opt {
            let hdr = String::from_utf8_lossy(&buf[..hdr_end]);
            let cl = hdr
                .lines()
                .find_map(|l| {
                    l.to_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            if buf.len() >= hdr_end + 4 + cl {
                break;
            }
        }
        if buf.len() > 65536 {
            break; // 安全上限：64KB 足够任何配对请求
        }
    }
    if buf.is_empty() {
        return Ok(());
    }
    let req = String::from_utf8_lossy(&buf).to_string();
    let mut lines = req.lines();
    let request_line = lines.next().unwrap_or("").to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path_raw = parts.next().unwrap_or("").to_string();
    // 剥离 query string：与 Java 端 handlePairingClient 对称，
    // 否则 GET /api/backup/v1/manifest?xxx 等带参数的请求会 404
    let path = path_raw.split('?').next().unwrap_or("").to_string();

    let mut content_length = 0usize;
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        if let Some(v) = line.to_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let body_start = req.find("\r\n\r\n").map(|i| i + 4).unwrap_or(req.len());
    let body_end = (body_start + content_length).min(req.len());
    // 按 Content-Length 的字节计数截取 body（不能用 chars().take() ——
    // 它按字符数截取，多字节 UTF-8 如中文设备名会多读字节，破坏 JSON）
    let body = String::from_utf8_lossy(
        &req.as_bytes()[body_start.min(req.len())..body_end],
    )
    .into_owned();

    let (status, json) = match (method.as_str(), path.as_str()) {
        ("GET", "/api/localsend/v2/info") => {
            // 配对服务常驻在线：未启动接收服务器时，对方也能探测到本机（发现/在线状态）
            let name = identity::get_device_name(&app);
            let id = identity::get_device_id(&app);
            (
                200,
                serde_json::json!({
                    "alias": name,
                    "version": "2.2",
                    "deviceModel": "Windows",
                    "deviceType": "desktop",
                    "fingerprint": id,
                    "port": 53317,
                    "protocol": "http",
                    "download": false,
                }).to_string(),
            )
        }
        ("POST", "/api/localsend/v2/verify") => {
            let body_v: Option<serde_json::Value> = serde_json::from_str(&body).ok();
            let entered = body_v
                .as_ref()
                .and_then(|v| v.get("code").and_then(|c| c.as_str()).map(|c| {
                    c.chars()
                        .filter(|ch| ch.is_ascii_alphanumeric())
                        .collect::<String>()
                        .to_uppercase()
                }))
                .unwrap_or_default();
            let mut ok;
            let mut reason = "";
            if !entered.is_empty() {
                // 配对验证：本地比对码 → 弹窗让被动方确认（同意才配对，拒绝/超时则拒绝）
                let mine = identity::get_self_code(&app);
                ok = entered == mine;
                if ok {
                    if let Some(v) = &body_v {
                        let device_id = v.get("deviceId").and_then(|d| d.as_str()).unwrap_or("");
                        if !device_id.is_empty() {
                            let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("未知设备");
                            // 配对双向确认：通知被动方前端弹窗「是否同意与 xx 配对」
                            let (duplicate, too_many);
                            let approved = {
                                let (tx, rx) = std::sync::mpsc::channel::<bool>();
                                {
                                    let st = app.state::<TransferState>();
                                    let mut m = st
                                        .pending_pairing_approvals
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner());
                                    // 同 deviceId 已有审批在途 → 拒绝重复请求（避免旧 Sender 被覆盖导致超时误拒）
                                    duplicate = m.contains_key(device_id);
                                    // 并发审批上限：防恶意批量配对请求堆积 45s 超时线程
                                    too_many = m.len() >= 10;
                                    if !duplicate && !too_many {
                                        m.insert(device_id.to_string(), tx);
                                    }
                                }
                                if duplicate || too_many {
                                    crate::log_warn!(
                                        "配对请求被拒绝（{}）: deviceId={}",
                                        if too_many { "审批并发已达上限" } else { "已有审批在途" },
                                        crate::logger::mask(device_id)
                                    );
                                    false
                                } else {
                                    let _ = app.emit(
                                        "pairing-request",
                                        serde_json::json!({
                                            "deviceId": device_id,
                                            "name": name,
                                            "ip": client_ip,
                                        }),
                                    );
                                    // 45 秒超时默认拒绝（未授权的主动方不应自动建立配对）
                                    let result = rx.recv_timeout(std::time::Duration::from_secs(45))
                                        .unwrap_or(false);
                                    // 无论结果如何清理 pending 表项（防 Sender 累积泄漏）
                                    let st = app.state::<TransferState>();
                                    let _ = st
                                        .pending_pairing_approvals
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner())
                                        .remove(device_id);
                                    result
                                }
                            };
                            if approved {
                                let peer = serde_json::json!({
                                    "name": name,
                                    "ip": client_ip,
                                    "port": v.get("port").and_then(|p| p.as_u64()).unwrap_or(53317),
                                    "fingerprint": v.get("myCode").and_then(|c| c.as_str()).unwrap_or(""),
                                });
                                if let Ok(mut m) = app.state::<PairingState>().paired.lock() {
                                    m.insert(device_id.to_string(), peer);
                                }
                                crate::log_info!(
                                    "配对确认（被动方已同意）: deviceId={}",
                                    crate::logger::mask(device_id)
                                );
                                let _ = app.emit("paired-updated", ());
                                persist_paired(&app);
                            } else {
                                crate::log_warn!(
                                    "被动方拒绝配对: deviceId={}",
                                    crate::logger::mask(device_id)
                                );
                                ok = false;
                                reason = "rejected";
                            }
                        }
                    }
                }
                if !ok && reason.is_empty() {
                    reason = "code_mismatch";
                }
            } else {
                // 连接问候：校验对方 deviceId 是否仍被本机信任（防绕过设备码）；
                // probe=true 为状态探测（只查信任、不触发已连接事件）
                let device_id = body_v
                    .as_ref()
                    .and_then(|v| v.get("deviceId").and_then(|d| d.as_str()))
                    .unwrap_or("");
                let probe = body_v
                    .as_ref()
                    .and_then(|v| v.get("probe").and_then(|p| p.as_bool()))
                    .unwrap_or(false);
                ok = !device_id.is_empty()
                    && app
                        .state::<PairingState>()
                        .paired
                        .lock()
                        .map(|m| m.contains_key(device_id))
                        .unwrap_or(false);
                if ok && !probe {
                    // 通知前端：对方已连接本机（probe 状态探测不触发，避免轮询自动置已连接）
                    let name = body_v
                        .as_ref()
                        .and_then(|v| v.get("name").and_then(|n| n.as_str()))
                        .unwrap_or("");
                    let _ = app.emit(
                        "peer-connected",
                        serde_json::json!({ "deviceId": device_id, "name": name }),
                    );
                }
            }
            crate::log_info!(
                "配对服务: {} {}",
                if entered.is_empty() { "连接问候" } else { "连接码验证" },
                if ok { "通过" } else { "失败/未信任" }
            );
            (200, serde_json::json!({"ok": ok, "reason": reason}).to_string())
        }
        ("POST", "/api/localsend/v2/file-receipt") => {
            // 接收方回执：某文件已成功写入（让发送方确认同步完成情况）
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                let file_name = v.get("fileName").and_then(|x| x.as_str()).unwrap_or("");
                crate::log_info!("收到文件回执: {file_name}");
                let _ = app.emit("file-receipt", serde_json::json!({ "fileName": file_name }));
            }
            (200, "{\"ok\":true}".to_string())
        }
        ("POST", "/api/localsend/v2/unpair") => {
            // 对方解除配对：从信任列表删除并通知前端即时删除本地配对
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(device_id) = v.get("deviceId").and_then(|d| d.as_str()) {
                    if let Ok(mut m) = app.state::<PairingState>().paired.lock() {
                        m.remove(device_id);
                    }
                    crate::log_info!(
                        "收到解除配对: deviceId={}",
                        crate::logger::mask(device_id)
                    );
                    let _ = app.emit(
                        "pair-unpaired",
                        serde_json::json!({ "deviceId": device_id }),
                    );
                    // 信任表已变更 → 落盘 SQLite
                    persist_paired(&app);
                }
            }
            (200, "{\"ok\":true}".to_string())
        }
        ("POST", "/api/backup/v1/disconnect") => {
            // 对方主动断开连接：仅通知前端清除"已连接"状态（不解除配对、不删信任）
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(device_id) = v.get("deviceId").and_then(|d| d.as_str()) {
                    crate::log_info!(
                        "收到断开连接: deviceId={}",
                        crate::logger::mask(device_id)
                    );
                    let _ = app.emit(
                        "peer-disconnected",
                        serde_json::json!({ "deviceId": device_id }),
                    );
                }
            }
            (200, "{\"ok\":true}".to_string())
        }
        ("POST", "/api/backup/v1/move-to-delete") => {
            // 镜像模式：把对端多余文件移动到 <接收目录>/delete/ 下（假删除，保持目录一致）
            let moved = handle_move_to_delete(&app, &body);
            (200, serde_json::json!({"ok": true, "moved": moved}).to_string())
        }
        ("POST", "/api/localsend/v2/sync-dir") => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                if let (Some(dir), Some(name)) = (
                    v.get("direction").and_then(|d| d.as_str()),
                    v.get("name").and_then(|n| n.as_str()),
                ) {
                    if let Ok(mut m) = app.state::<PairingState>().synced_dirs.lock() {
                        m.insert(dir.to_string(), name.to_string());
                    }
                    crate::log_info!("配对服务: 收到目录同步 {dir} = {name}");
                }
            }
            (200, "{\"ok\":true}".to_string())
        }
        ("GET", "/api/backup/v1/chunk-status") => {
            // 断点续传查询：返回大文件已收分片索引（encodedPath 参数 = pct 编码的正式相对路径）
            let file = path_raw
                .split('?')
                .nth(1)
                .unwrap_or("")
                .split('&')
                .find_map(|kv| kv.strip_prefix("encodedPath="))
                .unwrap_or("");
            let st = app.state::<TransferState>();
            let dir = st.receive_dir.lock().map(|g| g.clone()).unwrap_or(None);
            let mut chunks: Vec<u32> = Vec::new();
            if let Some(d) = dir {
                let part_dir = std::path::Path::new(&d).join(".chunks").join(file);
                if let Ok(rd) = std::fs::read_dir(&part_dir) {
                    for e in rd.flatten() {
                        if let Ok(i) = e.file_name().to_string_lossy().parse::<u32>() {
                            chunks.push(i);
                        }
                    }
                }
            }
            chunks.sort();
            // 前缀连续探测（已排序，O(n)）：Vec::contains 套循环是 O(n²)，
            // 万级分片（100GB/8MB）时单次查询上亿次比较
            let mut next_chunk = 0u32;
            while (next_chunk as usize) < chunks.len()
                && chunks[next_chunk as usize] == next_chunk
            {
                next_chunk += 1;
            }
            (
                200,
                serde_json::json!({
                    "receivedChunks": chunks,
                    "nextChunk": next_chunk,
                    "fileComplete": false,
                })
                .to_string(),
            )
        }
        ("GET", "/api/backup/v1/manifest") => {
            // B 端清单：当前接收目录的文件快照（三路对比增量备份的第三路）
            let st = app.state::<TransferState>();
            let dir = st.receive_dir.lock().map(|g| g.clone()).unwrap_or(None);
            match dir {
                Some(d) => {
                    let mut entries = Vec::new();
                    let _ = scan_dir_recursive(&d, "", &mut entries);
                    let mut files = serde_json::Map::new();
                    for e in entries {
                        files.insert(e.rel_path, serde_json::json!({"size": e.size, "mtime": e.mtime}));
                    }
                    (
                        200,
                        serde_json::json!({
                            "generatedAt": chrono_now_ms() / 1000,
                            "deviceCode": identity::get_device_id(&app),
                            "files": serde_json::Value::Object(files),
                            "version": 1,
                        })
                        .to_string(),
                    )
                }
                None => (
                    200,
                    serde_json::json!({
                        "generatedAt": 0,
                        "deviceCode": identity::get_device_id(&app),
                        "files": {},
                        "version": 1,
                        "available": false,
                    })
                    .to_string(),
                ),
            }
        }
        _ => (404, "{\"error\":\"not found\"}".to_string()),
    };

    let resp = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
        json.len()
    );
    stream.write_all(resp.as_bytes()).map_err(AppError::from_display)
}

/// 原始 HTTP JSON 请求（客户端侧：探测/验证/同步目录）
pub(crate) fn http_json_request(
    ip: &str,
    port: u16,
    method: &str,
    path: &str,
    body: &str,
) -> Result<serde_json::Value, AppError> {
    // 诊断埋点：记录 HTTP 请求耗时，慢请求（≥800ms）记警告——
    // 定位"UI 全局卡死"问题（同步命令阻塞 IPC 线程）
    let start = std::time::Instant::now();
    let r = http_json_request_inner(ip, port, method, path, body);
    let ms = start.elapsed().as_millis();
    if r.is_ok() {
        if ms >= 800 {
            crate::log_warn!("HTTP 请求耗时 {ms}ms: {method} {ip}:{port}{path}");
        }
    } else {
        crate::log_debug!("HTTP 请求失败 {ms}ms: {method} {ip}:{port}{path}");
    }
    r
}

fn http_json_request_inner(
    ip: &str,
    port: u16,
    method: &str,
    path: &str,
    body: &str,
) -> Result<serde_json::Value, AppError> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    // 关键：connect 必须设置超时！默认 TcpStream::connect 对不可达 IP 会触发 TCP
    // SYN 重试，可挂起 10~20 秒（表现为应用无响应且无日志）。
    let addr = (ip, port)
        .to_socket_addrs()
        .map_err(|e| AppError(format!("解析地址 {ip}:{port} 失败: {e}")))?
        .next()
        .ok_or_else(|| AppError(format!("无可用地址: {ip}:{port}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(1500))
        .map_err(|e| AppError(format!("连接 {ip}:{port} 失败: {e}")))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(3000)))
        .map_err(AppError::from_display)?;
    stream
        .set_write_timeout(Some(Duration::from_millis(3000)))
        .map_err(AppError::from_display)?;
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).map_err(AppError::from_display)?;
    // 64MB 上限 + 预留容量：read_to_end 对异常对端无内存保护（正常清单响应为数 KB~数 MB）
    let mut resp_buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    {
        let mut tmp = [0u8; 16 * 1024];
        loop {
            let n = stream.read(&mut tmp).map_err(AppError::from_display)?;
            if n == 0 {
                break;
            }
            resp_buf.extend_from_slice(&tmp[..n]);
            if resp_buf.len() > 64 * 1024 * 1024 {
                return Err(AppError("HTTP 响应超过 64MB 上限".to_string()));
            }
        }
    }
    let text = String::from_utf8_lossy(&resp_buf);
    let json_part = text.splitn(2, "\r\n\r\n").nth(1).unwrap_or("");
    serde_json::from_str(json_part)
        .map_err(|e| AppError(format!("解析响应失败: {e}")))
}

/// 探测目标设备在线状态（GET /info 于配对服务端口+1），返回其公开信息（设备名 + deviceId）
pub fn ping_device(ip: String, port: u16) -> Result<PingedDevice, AppError> {
    let v = http_json_request(&ip, port + 1, "GET", "/api/localsend/v2/info", "")?;
    Ok(PingedDevice {
        alias: v.get("alias").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        fingerprint: v
            .get("fingerprint")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        port: v.get("port").and_then(|x| x.as_u64()).unwrap_or(port as u64) as u16,
    })
}

/// 向目标设备提交连接码验证 / 连接问候（POST /verify 于配对服务端口+1，目标本地比对）
pub fn verify_device(
    ip: String,
    port: u16,
    code: String,
    device_id: String,
    name: String,
    my_code: String,
    probe: Option<bool>,
) -> Result<serde_json::Value, AppError> {
    let mut payload = serde_json::json!({"code": code});
    if !device_id.is_empty() {
        payload["deviceId"] = serde_json::json!(device_id);
    }
    if !name.is_empty() {
        payload["name"] = serde_json::json!(name);
    }
    if !my_code.is_empty() {
        payload["myCode"] = serde_json::json!(my_code);
    }
    payload["probe"] = serde_json::json!(probe.unwrap_or(false));
    payload["port"] = serde_json::json!(53317);
    let body = payload.to_string();
    // 直接返回对方响应（含 ok 与 reason：code_mismatch=码错误 / rejected=对方拒绝）
    http_json_request(&ip, port + 1, "POST", "/api/localsend/v2/verify", &body)
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
    let body = serde_json::json!({"files": files}).to_string();
    let v = http_json_request(&ip, port + 1, "POST", "/api/backup/v1/move-to-delete", &body)?;
    Ok(v.get("moved").and_then(|x| x.as_u64()).unwrap_or(0) as usize)
}

/// 通知目标设备断开连接（POST /api/backup/v1/disconnect 于配对服务端口+1，
/// 仅清除对方"已连接"状态，不解除配对）
pub fn send_disconnect(ip: String, port: u16, device_id: String) -> Result<bool, AppError> {
    let body = serde_json::json!({"deviceId": device_id}).to_string();
    let v = http_json_request(&ip, port + 1, "POST", "/api/backup/v1/disconnect", &body)?;
    Ok(v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false))
}

/// 本机被验证方记录的对端信任列表（双端配对同步）
pub fn get_paired_peers(app: AppHandle) -> Vec<serde_json::Value> {
    let start = std::time::Instant::now();
    let out = get_paired_peers_inner(&app);
    let ms = start.elapsed().as_millis();
    if ms >= 100 {
        crate::log_warn!("get_paired_peers 耗时 {ms}ms（疑似 SQLite 锁竞争）");
    }
    out
}

fn get_paired_peers_inner(app: &AppHandle) -> Vec<serde_json::Value> {
    let st = app.state::<PairingState>();
    let mut out = Vec::new();
    if let Ok(m) = st.paired.lock() {
        for (id, v) in m.iter() {
            let mut p = v.clone();
            p["deviceId"] = serde_json::json!(id);
            out.push(p);
        }
    }
    out
}

/// 本端主动确认配对：把配对记录写入后端 paired map。
/// 关键：本端作为"验证方"配对成功时，后端 greet 校验查的是这个 map；
/// 不写入会导致对方问候本机时返回"未信任"，被误判为解除配对。
/// 前端在配对成功/启动时批量调用，进程重启后自动回填（自愈）。
pub fn confirm_paired(
    app: AppHandle,
    device_id: String,
    name: String,
    ip: String,
    port: u16,
    fingerprint: String,
) -> Result<(), AppError> {
    let peer = serde_json::json!({
        "name": name,
        "ip": ip,
        "port": port,
        "fingerprint": fingerprint,
    });
    if let Ok(mut m) = app.state::<PairingState>().paired.lock() {
        m.insert(device_id.clone(), peer);
    }
    crate::log_info!(
        "本端确认配对: deviceId={} name={}",
        crate::logger::mask(&device_id),
        name
    );
    persist_paired(&app);
    Ok(())
}

/// 本端全量同步配对记录到后端 paired map（清空后重建）。
/// 关键：后端 paired map 是 greet 校验依据；只增不删会导致已解除配对的
/// 残留记录继续被信任，造成"已解除又弹回/状态横跳"。全量替换保证
/// 后端与前端本地配对始终一致，解除后后端立即删除。
pub fn sync_paired(app: AppHandle, peers: Vec<serde_json::Value>) -> Result<(), AppError> {
    let start = std::time::Instant::now();
    let peer_count = peers.len();
    let st = app.state::<PairingState>();
    if let Ok(mut m) = st.paired.lock() {
        m.clear();
        for p in peers {
            if let Some(device_id) = p.get("deviceId").and_then(|d| d.as_str()) {
                let mut peer = p.clone();
                if let Some(obj) = peer.as_object_mut() {
                    obj.remove("deviceId");
                }
                m.insert(device_id.to_string(), peer);
            }
        }
    }
    crate::log_info!("配对记录已全量同步: {peer_count} 台");
    persist_paired(&app);
    let ms = start.elapsed().as_millis();
    if ms >= 100 {
        crate::log_warn!("sync_paired 耗时 {ms}ms（疑似 SQLite 落盘瓶颈）");
    }
    Ok(())
}

/// 将当前配对信任表落盘 SQLite（每次增删后调用；数据量极小，全量重写即可）
pub fn persist_paired(app: &AppHandle) {
    let peers = get_paired_peers(app.clone());
    let rows: Vec<(String, String, String, i64, String)> = peers
        .iter()
        .filter_map(|p| {
            Some((
                p.get("deviceId").and_then(|d| d.as_str())?.to_string(),
                p.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                p.get("ip").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                p.get("port").and_then(|n| n.as_u64()).unwrap_or(53317) as i64,
                p.get("fingerprint").and_then(|n| n.as_str()).unwrap_or("").to_string(),
            ))
        })
        .collect();
    if let Err(e) = crate::db::save_paired_peers(&app, rows) {
        crate::log_warn!("配对记录落盘失败: {e}");
    }
}

/// 启动时从 SQLite 恢复配对信任表（与前端 localStorage 互为镜像，双保险）
pub fn load_paired_from_db(app: &AppHandle) {
    match crate::db::load_paired_peers(app) {
        Ok(peers) => {
            let count = peers.len();
            let st = app.state::<PairingState>();
            if let Ok(mut m) = st.paired.lock() {
                for p in peers {
                    if let Some(device_id) = p.get("deviceId").and_then(|d| d.as_str()) {
                        let mut peer = p.clone();
                        if let Some(obj) = peer.as_object_mut() {
                            obj.remove("deviceId");
                        }
                        m.insert(device_id.to_string(), peer);
                    }
                }
            }
            crate::log_info!("配对记录已从数据库恢复: {} 台", count);
        }
        Err(e) => crate::log_warn!("配对记录从数据库恢复失败: {e}"),
    }
}

/// 通知目标设备本机选择的备份目录名（POST /sync-dir 于配对服务端口+1）
pub fn send_sync_dir(
    ip: String,
    port: u16,
    direction: String,
    name: String,
) -> Result<bool, AppError> {
    let body = serde_json::json!({"direction": direction, "name": name}).to_string();
    let v = http_json_request(&ip, port + 1, "POST", "/api/localsend/v2/sync-dir", &body)?;
    Ok(v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false))
}

/// 读取对方同步过来的目录名
pub fn get_synced_dir(app: AppHandle, direction: String) -> Option<serde_json::Value> {
    let st = app.state::<PairingState>();
    let name = st.synced_dirs.lock().ok()?.get(&direction).cloned()?;
    Some(serde_json::json!({ "name": name, "at": chrono_now_ms() }))
}

/// 当前毫秒时间戳（无 chrono 依赖，用 SystemTime）
fn chrono_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
        loop {
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let app2 = app.clone();
            // 投递回调到主线程；若主线程忙/阻塞，回调排队等待
            if app2.run_on_main_thread(move || {
                let _ = tx.send(());
            })
            .is_err()
            {
                crate::log_error!("watchdog: run_on_main_thread 投递失败（主线程不可用）");
            }
            let start = std::time::Instant::now();
            match rx.recv_timeout(std::time::Duration::from_millis(1500)) {
                Ok(()) => {
                    // 健康：主线程及时响应
                    let ms = start.elapsed().as_millis();
                    if ms >= 800 {
                        crate::log_warn!("主线程响应偏慢: {ms}ms（仍在阈值内）");
                    }
                }
                Err(_) => {
                    let ms = start.elapsed().as_millis();
                    crate::log_error!(
                        "!! UI 主线程阻塞检测: 心跳超时，阻塞 ≥{ms}ms（时间戳 {}）——疑似同步命令占用 IPC 线程",
                        chrono_now_ms()
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
            if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(800))
                .is_ok()
            {
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

/// 探测结果（Tauri 命令返回值）
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingedDevice {
    pub alias: String,
    pub fingerprint: String,
    pub port: u16,
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
