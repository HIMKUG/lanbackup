//! 电脑端 Tauri 后端
//!
//! 职责：
//! - 设备身份（基于 MachineGuid 生成连接码）
//! - SQLite 加密存储（每配对设备一份状态）
//! - 传输模块（复用 LocalSend 的 Rust crate，见 transfer.rs）
//! - 设备发现（multicast，见 discovery.rs）
//! - 全链路 Debug 日志（见 logger.rs）
//!
//! 命令注册统一在 `commands` 子模块的包装层：每条命令记录入口/出口
//! （参数与返回值脱敏），具体实现委托给各模块的纯逻辑函数。
//!
//! 注意：包装函数必须放在子模块而非 crate 根。Tauri 的 `#[tauri::command]`
//! 会对 `pub fn` 生成 `#[macro_export] macro_rules! __cmd__名`，若函数位于
//! crate 根，宏会与自身命名冲突（E0255）。

mod db;
mod crypto;
pub(crate) mod discovery;
pub(crate) mod identity;
mod logger;
pub(crate) mod scheduler;
pub(crate) mod session_store;
mod transfer;

// 重导出 AppError，供 transfer.rs 使用
pub use db::AppError;

use tauri::{AppHandle, Manager};

/// 应用状态
pub struct AppState {
    pub db: db::Database,
}

/// 启动应用
pub fn run() {
    // panic 信息写入日志缓冲，可随日志导出排查
    logger::install_panic_hook();
    if let Err(e) = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .setup(|app| {
            let db = db::Database::open(app.handle())?;
            app.manage(AppState { db });
            app.manage(transfer::TransferState::default());
            app.manage(discovery::DiscoveryState::default());
            app.manage(transfer::PairingState::default());
            // 实时日志文件（程序卡死时仍可复制；见 logger.rs）
            logger::init_file(app.handle());
            // 从 SQLite 恢复配对信任表（重启后配对关系不丢，见 transfer.rs）
            transfer::load_paired_from_db(app.handle());
            // UI 主线程阻塞检测（诊断"切换窗口后程序未响应"问题）
            transfer::spawn_ui_watchdog(app.handle().clone());
            // 配对服务（端口 53318）常驻：已配对设备穿透隐藏连接（白名单校验），
            // 未配对设备无法连接（/verify 问候校验白名单）；隐藏时接收服务器关闭，
            // 子网扫描探测不到本机（/register 无响应），未配对设备无法发现
            transfer::spawn_pairing_server(app.handle().clone());
            // 接收服务器僵尸自愈：服务器任务异常退出（端口拒连但状态为运行中）时自动重启，
            // 否则对端"恢复任务"会 Failed to connect 且 peer-connected 自动拉起被 serverRunning 跳过
            transfer::spawn_receiver_watchdog(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_self_code,
            commands::refresh_self_code,
            commands::get_self_info,
            commands::set_self_name,
            commands::get_device_state,
            commands::save_device_state,
            commands::get_all_devices,
            commands::start_receiver,
            commands::stop_receiver,
            commands::send_files,
            commands::scan_directory,
            commands::get_peer_manifest,
            commands::start_discovery,
            commands::stop_discovery,
            commands::get_discovered_devices,
            commands::ping_device,
            commands::probe_peer_port,
            commands::verify_device,
            commands::send_unpair,
            commands::send_disconnect,
            commands::move_to_delete,
            commands::resolve_incoming,
            commands::resolve_pairing,
            commands::get_paired_peers,
            commands::confirm_paired,
            commands::sync_paired,
            commands::send_sync_dir,
            commands::get_synced_dir,
            commands::get_transfers,
            commands::clear_transfers,
            commands::delete_transfer,
            commands::get_config,
            commands::set_config,
            logger::export_logs,
        ])
        .run(tauri::generate_context!())
    {
        eprintln!("tauri application error: {e}");
        std::process::exit(1);
    }
}

/// 命令包装层：记录入口/出口（敏感参数与返回值脱敏）
mod commands {
    use super::*;

    /// 记录命令出入口的辅助宏（模块名统一为 cmd，消息带命令名）
    macro_rules! cmd_log {
        ($level:expr, $name:literal, $($arg:tt)*) => {
            logger::log($level, "cmd", &format!("{} {}", $name, format!($($arg)*)))
        };
    }

    /// 异步化辅助：把阻塞闭包移到 tokio 线程池执行。
    /// 修复核心：同步 Tauri 命令在 IPC 主线程执行，网络/DB 阻塞会占住主线程
    /// → 窗口事件循环卡死（watchdog 日志实锤）。所有网络/DB 命令经此分发到线程池。
    async fn run_blocking<T: Send + 'static>(
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, AppError> {
        tauri::async_runtime::spawn_blocking(f)
            .await
            .map_err(|e| AppError(format!("任务执行失败: {e}")))
    }

    #[tauri::command]
    pub fn get_self_code(app: AppHandle) -> String {
        cmd_log!(logger::LogLevel::Info, "get_self_code", "入口");
        let code = identity::get_self_code(&app);
        cmd_log!(
            logger::LogLevel::Info,
            "get_self_code",
            "出口 code={}",
            logger::mask(&code)
        );
        code
    }

    #[tauri::command]
    pub fn refresh_self_code(app: AppHandle) -> String {
        cmd_log!(logger::LogLevel::Info, "refresh_self_code", "入口");
        let code = identity::refresh_self_code(&app);
        cmd_log!(
            logger::LogLevel::Info,
            "refresh_self_code",
            "出口 code={}",
            logger::mask(&code)
        );
        code
    }

    #[tauri::command]
    pub async fn get_device_state(
        app: AppHandle,
        connection_code: String,
    ) -> Result<Option<serde_json::Value>, AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "get_device_state",
            "入口 code={}",
            logger::mask(&connection_code)
        );
        let r = run_blocking(move || db::get_device_state(app, connection_code)).await?;
        cmd_log!(
            logger::LogLevel::Info,
            "get_device_state",
            "出口 命中={}",
            r.as_ref().map(|v| v.is_some()).unwrap_or(false)
        );
        r
    }

    #[tauri::command]
    pub async fn save_device_state(
        app: AppHandle,
        connection_code: String,
        device_name: String,
        state: serde_json::Value,
    ) -> Result<(), AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "save_device_state",
            "入口 code={} 名称={} 状态keys={}",
            logger::mask(&connection_code),
            device_name,
            state.as_object().map(|o| o.len()).unwrap_or(0)
        );
        let r = run_blocking(move || {
            db::save_device_state(app, connection_code, device_name, state)
        })
        .await?;
        cmd_log!(
            logger::LogLevel::Info,
            "save_device_state",
            "出口 ok={}",
            r.is_ok()
        );
        r
    }

    #[tauri::command]
    pub fn get_self_info(app: AppHandle) -> serde_json::Value {
        cmd_log!(logger::LogLevel::Info, "get_self_info", "入口");
        let info = serde_json::json!({
            "name": identity::get_device_name(&app),
            "id": identity::get_device_id(&app),
            "code": identity::get_self_code(&app),
        });
        cmd_log!(
            logger::LogLevel::Info,
            "get_self_info",
            "出口 名称={}",
            info["name"]
        );
        info
    }

    #[tauri::command]
    pub fn set_self_name(app: AppHandle, name: String) -> Result<(), AppError> {
        cmd_log!(logger::LogLevel::Info, "set_self_name", "入口 名称={name}");
        let r = identity::set_device_name(&app, name);
        cmd_log!(
            logger::LogLevel::Info,
            "set_self_name",
            "出口 ok={}",
            r.is_ok()
        );
        r
    }

    #[tauri::command]
    pub async fn ping_device(ip: String, port: u16) -> Result<transfer::PingedDevice, AppError> {
        cmd_log!(logger::LogLevel::Info, "ping_device", "入口 目标={ip}:{port}");
        // 异步化：阻塞 HTTP 移出主线程（spawn_blocking 线程池）。
        // 修复：同步命令占用 IPC 主线程，不可达设备 1.5s connect 超时导致 UI 全局卡死
        // （watchdog 日志实锤：阻塞 ≥1500ms 与 verify/ping 超时逐条对应）
        let r = tauri::async_runtime::spawn_blocking(move || transfer::ping_device(ip, port))
            .await
            .map_err(|e| AppError(format!("探测任务执行失败: {e}")))?;
        cmd_log!(
            logger::LogLevel::Info,
            "ping_device",
            "出口 ok={}",
            r.is_ok()
        );
        r
    }

    #[tauri::command]
    pub async fn probe_peer_port(ip: String, port: u16) -> Result<bool, AppError> {
        // 直连探测对端接收端口（ping_device 走配对服务端口+1，探不到接收服务）
        let r = tauri::async_runtime::spawn_blocking(move || transfer::probe_peer_port(ip, port))
            .await
            .map_err(|e| AppError(format!("探测任务执行失败: {e}")))?;
        let ok = r.as_ref().copied().unwrap_or(false);
        cmd_log!(logger::LogLevel::Debug, "probe_peer_port", "出口 目标可达={}", ok);
        r
    }

    #[tauri::command]
    pub async fn verify_device(
        ip: String,
        port: u16,
        code: String,
        device_id: String,
        name: String,
        my_code: String,
        probe: Option<bool>,
    ) -> Result<serde_json::Value, AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "verify_device",
            "入口 目标={ip}:{port} 模式={} 探测={}",
            if code.is_empty() { "问候" } else { "验证" },
            probe.unwrap_or(false)
        );
        // 异步化：阻塞 HTTP 探测移出主线程（spawn_blocking 线程池）。
        // 返回对方完整响应 {ok, reason}（reason: code_mismatch / rejected）
        let r = tauri::async_runtime::spawn_blocking(move || {
            transfer::verify_device(ip, port, code, device_id, name, my_code, probe)
        })
        .await
        .map_err(|e| AppError(format!("探测任务执行失败: {e}")))?;
        cmd_log!(
            logger::LogLevel::Info,
            "verify_device",
            "出口 ok={}",
            r.as_ref().map(|v| v.get("ok").and_then(|o| o.as_bool()).unwrap_or(false)).unwrap_or(false)
        );
        r
    }

    /// 前端响应「接收确认」弹窗：同意/拒绝当前 prepare-upload 会话
    #[tauri::command]
    pub async fn resolve_incoming(app: AppHandle, session_id: String, accept: bool) -> Result<(), AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "resolve_incoming",
            "入口 session={} accept={}",
            logger::mask(&session_id),
            accept
        );
        run_blocking(move || {
            let st = app.state::<transfer::TransferState>();
            {
                let mut m = st
                    .pending_receive_approvals
                    .lock()
                    .map_err(|_| AppError::from_poison())?;
                if let Some(tx) = m.remove(&session_id) {
                    let _ = tx.send(accept);
                }
            }
            // 清理时间戳（与 pending_receive_approvals 严格对应）
            {
                let mut t = st
                    .pending_receive_times
                    .lock()
                    .map_err(|_| AppError::from_poison())?;
                t.remove(&session_id);
            }
            Ok(())
        })
        .await?
    }

    /// 前端响应「配对确认」弹窗：同意/拒绝与主动方的配对请求
    #[tauri::command]
    pub async fn resolve_pairing(app: AppHandle, device_id: String, accept: bool) -> Result<(), AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "resolve_pairing",
            "入口 deviceId={} accept={}",
            logger::mask(&device_id),
            accept
        );
        run_blocking(move || {
            let st = app.state::<transfer::TransferState>();
            let mut m = st
                .pending_pairing_approvals
                .lock()
                .map_err(|_| AppError::from_poison())?;
            if let Some(tx) = m.remove(&device_id) {
                let _ = tx.send(accept);
            }
            Ok(())
        })
        .await?
    }

    #[tauri::command]
    pub async fn send_unpair(ip: String, port: u16, device_id: String) -> Result<bool, AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "send_unpair",
            "入口 目标={ip}:{port} deviceId={}",
            logger::mask(&device_id)
        );
        run_blocking(move || transfer::send_unpair(ip, port, device_id)).await?
    }

    #[tauri::command]
    pub async fn move_to_delete(ip: String, port: u16, files: Vec<String>) -> Result<usize, AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "move_to_delete",
            "入口 目标={ip}:{port} 文件数={}",
            files.len()
        );
        transfer::move_to_delete(ip, port, files).await
    }

    #[tauri::command]
    pub async fn send_disconnect(ip: String, port: u16, device_id: String) -> Result<bool, AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "send_disconnect",
            "入口 目标={ip}:{port} deviceId={}",
            logger::mask(&device_id)
        );
        run_blocking(move || transfer::send_disconnect(ip, port, device_id)).await?
    }

    #[tauri::command]
    pub async fn get_paired_peers(app: AppHandle) -> Vec<serde_json::Value> {
        cmd_log!(logger::LogLevel::Info, "get_paired_peers", "入口");
        run_blocking(move || transfer::get_paired_peers(app))
            .await
            .unwrap_or_default()
    }

    #[tauri::command]
    pub fn confirm_paired(
        app: AppHandle,
        device_id: String,
        name: String,
        ip: String,
        port: u16,
        fingerprint: String,
    ) -> Result<(), AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "confirm_paired",
            "入口 deviceId={} name={}",
            logger::mask(&device_id),
            name
        );
        let r = transfer::confirm_paired(app, device_id, name, ip, port, fingerprint);
        cmd_log!(
            logger::LogLevel::Info,
            "confirm_paired",
            "出口 ok={}",
            r.is_ok()
        );
        r
    }

    #[tauri::command]
    pub async fn sync_paired(app: AppHandle, peers: Vec<serde_json::Value>) -> Result<(), AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "sync_paired",
            "入口 数量={}",
            peers.len()
        );
        let r = run_blocking(move || transfer::sync_paired(app, peers)).await?;
        cmd_log!(
            logger::LogLevel::Info,
            "sync_paired",
            "出口 ok={}",
            r.is_ok()
        );
        r
    }

    #[tauri::command]
    pub async fn send_sync_dir(
        ip: String,
        port: u16,
        direction: String,
        name: String,
    ) -> Result<bool, AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "send_sync_dir",
            "入口 目标={ip}:{port} 方向={direction} 名称={name}"
        );
        run_blocking(move || transfer::send_sync_dir(ip, port, direction, name)).await?
    }

    #[tauri::command]
    pub fn get_synced_dir(app: AppHandle, direction: String) -> Option<serde_json::Value> {
        cmd_log!(
            logger::LogLevel::Info,
            "get_synced_dir",
            "入口 方向={direction}"
        );
        transfer::get_synced_dir(app, direction)
    }

    #[tauri::command]
    pub async fn get_transfers(app: AppHandle, limit: usize) -> Result<Vec<serde_json::Value>, AppError> {
        cmd_log!(logger::LogLevel::Info, "get_transfers", "入口 limit={limit}");
        run_blocking(move || {
            let state = app.state::<AppState>();
            state.db.get_transfers(limit.max(1).min(100))
        })
        .await?
    }

    #[tauri::command]
    pub async fn clear_transfers(app: AppHandle) -> Result<(), AppError> {
        cmd_log!(logger::LogLevel::Info, "clear_transfers", "入口");
        run_blocking(move || {
            let state = app.state::<AppState>();
            state.db.clear_transfers()
        })
        .await?
    }

    #[tauri::command]
    pub async fn delete_transfer(app: AppHandle, id: i64) -> Result<(), AppError> {
        cmd_log!(logger::LogLevel::Info, "delete_transfer", "入口 id={id}");
        run_blocking(move || {
            let state = app.state::<AppState>();
            state.db.delete_transfer(id)
        })
        .await?
    }

    /// 读取应用配置（app_data_dir/config.json；无配置返回空对象，前端用默认值规范化）
    #[tauri::command]
    pub async fn get_config(app: AppHandle) -> Result<serde_json::Value, AppError> {
        cmd_log!(logger::LogLevel::Info, "get_config", "入口");
        run_blocking(move || {
            let dir = app.path().app_data_dir().map_err(AppError::from_display)?;
            let path = dir.join("config.json");
            match std::fs::read_to_string(&path) {
                Ok(s) => serde_json::from_str(&s).map_err(AppError::from_display),
                Err(_) => Ok(serde_json::json!({})),
            }
        })
        .await?
    }

    /// 保存应用配置（角色/接收端/发送端，存 app_data_dir/config.json）
    #[tauri::command]
    pub async fn set_config(app: AppHandle, config: serde_json::Value) -> Result<(), AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "set_config",
            "入口 角色={}",
            config.get("role").and_then(|r| r.as_str()).unwrap_or("?")
        );
        run_blocking(move || {
            let dir = app.path().app_data_dir().map_err(AppError::from_display)?;
            std::fs::create_dir_all(&dir).map_err(AppError::from_display)?;
            let path = dir.join("config.json");
            std::fs::write(&path, config.to_string()).map_err(AppError::from_display)?;
            Ok(())
        })
        .await?
    }

    #[tauri::command]
    pub async fn get_all_devices(app: AppHandle) -> Result<Vec<String>, AppError> {
        cmd_log!(logger::LogLevel::Info, "get_all_devices", "入口");
        let r = run_blocking(move || db::get_all_devices(app)).await?;
        cmd_log!(
            logger::LogLevel::Info,
            "get_all_devices",
            "出口 数量={}",
            r.as_ref().map(|v| v.len()).unwrap_or(0)
        );
        r
    }

    #[tauri::command]
    pub async fn start_receiver(
        app: AppHandle,
        receive_dir: String,
        port: u16,
    ) -> Result<String, AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "start_receiver",
            "入口 目录={receive_dir} 端口={port}"
        );
        let r = transfer::start_receiver(app, receive_dir, port).await;
        cmd_log!(
            logger::LogLevel::Info,
            "start_receiver",
            "出口 ok={}",
            r.is_ok()
        );
        r
    }

    #[tauri::command]
    pub async fn stop_receiver(app: AppHandle) -> Result<(), AppError> {
        cmd_log!(logger::LogLevel::Info, "stop_receiver", "入口");
        let r = transfer::stop_receiver(app).await;
        cmd_log!(
            logger::LogLevel::Info,
            "stop_receiver",
            "出口 ok={}",
            r.is_ok()
        );
        r
    }

    #[tauri::command]
    pub async fn send_files(
        app: AppHandle,
        target_ip: String,
        target_port: u16,
        target_code: String,
        files: Vec<transfer::SendFileItem>,
    ) -> Result<u64, AppError> {
        let names: Vec<String> = files.iter().map(|f| f.rel_path().to_string()).collect();
        cmd_log!(
            logger::LogLevel::Info,
            "send_files",
            "入口 目标={target_ip}:{target_port} 文件数={} 加密={} 列表=[{}]",
            files.len(),
            if target_code.is_empty() { "否" } else { "是" },
            names.join(", ")
        );
        let r = transfer::send_files(app, target_ip, target_port, target_code, files).await;
        cmd_log!(
            logger::LogLevel::Info,
            "send_files",
            "出口 ok={} 已发送={}",
            r.is_ok(),
            r.as_ref().map(|n| *n).unwrap_or(0)
        );
        r
    }

    #[tauri::command]
    pub async fn scan_directory(dir: String) -> Result<Vec<transfer::ScannedEntry>, AppError> {
        cmd_log!(logger::LogLevel::Info, "scan_directory", "入口 目录={dir}");
        let r = transfer::scan_directory(dir).await;
        cmd_log!(
            logger::LogLevel::Info,
            "scan_directory",
            "出口 ok={} 条目数={}",
            r.is_ok(),
            r.as_ref().map(|v| v.len()).unwrap_or(0)
        );
        r
    }

    #[tauri::command]
    pub async fn get_peer_manifest(ip: String, port: u16) -> Result<serde_json::Value, AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "get_peer_manifest",
            "入口 目标={ip}:{port}"
        );
        let r = run_blocking(move || transfer::get_peer_manifest(ip, port)).await?;
        cmd_log!(
            logger::LogLevel::Info,
            "get_peer_manifest",
            "出口 ok={}",
            r.is_ok()
        );
        r
    }

    #[tauri::command]
    pub async fn start_discovery(app: AppHandle, server_port: u16) -> Result<String, AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "start_discovery",
            "入口 广播端口={server_port}"
        );
        let r = discovery::start_discovery(app, server_port).await;
        cmd_log!(
            logger::LogLevel::Info,
            "start_discovery",
            "出口 ok={}",
            r.is_ok()
        );
        r
    }

    #[tauri::command]
    pub async fn stop_discovery(app: AppHandle) -> Result<(), AppError> {
        cmd_log!(logger::LogLevel::Info, "stop_discovery", "入口");
        let r = discovery::stop_discovery(app).await;
        cmd_log!(
            logger::LogLevel::Info,
            "stop_discovery",
            "出口 ok={}",
            r.is_ok()
        );
        r
    }

    #[tauri::command]
    pub fn get_discovered_devices(
        app: AppHandle,
    ) -> Result<Vec<discovery::DiscoveredDeviceInfo>, AppError> {
        cmd_log!(logger::LogLevel::Info, "get_discovered_devices", "入口");
        let r = discovery::get_discovered_devices(app);
        cmd_log!(
            logger::LogLevel::Info,
            "get_discovered_devices",
            "出口 数量={}",
            r.as_ref().map(|v| v.len()).unwrap_or(0)
        );
        r
    }
}
