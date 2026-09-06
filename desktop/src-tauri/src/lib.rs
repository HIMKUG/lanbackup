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
mod bcpd;
pub(crate) mod identity;
mod logger;
pub(crate) mod scheduler;
pub(crate) mod session_store;
pub(crate) mod pairing;
mod transfer;
mod ball;

// 重导出 AppError，供 transfer.rs 使用
pub use db::AppError;

use tauri::{AppHandle, Manager};

/// 应用状态
pub struct AppState {
    pub db: db::Database,
}

/// 探针功能总开关（性能优化）：false 时 probe!/proc_alive 全部编译为空操作。
/// 排查启动卡死/无响应类问题时改为 true 重新编译，探针点保留在源码中无需重写。
/// 使用记录：2026-08-22 凭借该探针时间线定位到 parse_log_line 越界 panic 导致的启动冻结。
pub const PROBE_ENABLED: bool = false;

/// 探针起点：进程内首次使用时计时归零（所有探针输出相对它的耗时）
pub static PROBE_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// 写文件探针（追加模式 + 相对耗时）：诊断启动卡顿的时间线工具。
/// 输出到 %TEMP%\tauri_debug_log.txt，格式 `[+秒] 消息`；main.rs 启动时先删除旧文件。
/// 注意：绝不写盘符根目录——根目录高频写入是杀软 HIPS 行为检测的典型触发特征，
/// 曾导致整个进程被 360 挂起 → 窗口瞬间"无响应"。
/// #[macro_export] 使其他模块（transfer.rs 等）可用 `crate::probe!` 调用。
#[macro_export]
macro_rules! probe {
    ($msg:expr) => {{
        if $crate::PROBE_ENABLED {
            let start = $crate::PROBE_START.get_or_init(std::time::Instant::now);
            let line = format!("[+{:>7.3}s] {}\n", start.elapsed().as_secs_f64(), $msg);
            let path = std::env::temp_dir().join("tauri_debug_log.txt");
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                use std::io::Write as _;
                let _ = f.write_all(line.as_bytes());
            }
        }
    }};
}

/// 启动应用
pub fn run() {
    probe!("[1] run() 函数入口");

    // panic 信息写入日志缓冲，可随日志导出排查
    logger::install_panic_hook();
    probe!("[2] panic_hook 已安装");

    // OpenTelemetry 初始化已移除（需要在 async 上下文中初始化，暂不在 startup 调用）
    // 如需可观测性，请在此处引入 tracing subscriber + opentelemetry_otlp

    probe!("[3] 开始构建 Tauri Builder");

    let result = tauri::Builder::default()
        // 单实例：第二个实例启动时唤起已有主窗口后退出，
        // 避免双实例互相抢占 53318/53317 端口（此前导致配对服务绑定失败 + 接收服务反复重启）
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.unminimize();
                let _ = win.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .setup(|app| {
            probe!("[4] setup 闭包入口");

            probe!("[5] 即将打开 Database");
            let db = db::Database::open(app.handle())?;
            probe!("[6] Database 已打开");

            app.manage(AppState { db });
            probe!("[7] AppState 已注册");

            app.manage(transfer::TransferState::default());
            app.manage(discovery::DiscoveryState::default());
            app.manage(transfer::PairingState::default());
            // Scheduler 差异同步引擎的全局并发调度器（多接收端/多分片并发控制）
            app.manage(scheduler::SendScheduler::default());
            app.manage(bcpd::BcpdState::default());
            probe!("[8] TransferState/DiscoveryState/PairingState/SendScheduler/BcpdState 已注册");

            // Session 持久化存储（跨重启保持传输会话状态）
            let app_data = app.path().app_data_dir().map_err(|e| AppError(e.to_string()))?;
            probe!("[9] app_data_dir 获取成功");
            let session_store = session_store::DesktopSessionStore::new(&app_data)
                .map_err(|e| AppError(format!("SessionStore 初始化失败: {e}")))?;
            probe!("[10] DesktopSessionStore 已初始化");
            app.manage(session_store);
            probe!("[11] SessionStore 已注册");

            // OpenTelemetry 初始化已禁用：OTLP gRPC 连接 localhost:4317（无服务监听）。
            // tonic 连接内部经 getaddrinfo 做网络栈初始化时会持有 Windows 加载器锁，
            // 连接挂起即连锁锁死主线程（症状：主线程永久阻塞于"网络 I/O"，窗口无响应，
            // 进程其余部分与 WebView2 渲染正常）。如需启用，必须在专用线程 +
            // 带 connect timeout 的前提下重写，且 collector 地址可配置。
            probe!("[12] telemetry 未引入（可观测性预留）");

            // 实时日志文件（程序卡死时仍可复制；见 logger.rs）
            logger::init_file(app.handle());
            probe!("[13] logger::init_file 完成");

            // 关键：所有耗时/阻塞初始化改为异步执行，setup 闭包立即返回，
            // 让主窗口尽快渲染响应用户输入，避免 OS 将窗口标记为"未响应"。
            // 悬浮球窗口、后台 watchdog、配对服务等全部后台启动。
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                // 从 SQLite 恢复配对信任表（重启后配对关系不丢）
                transfer::load_paired_from_db(&app_handle);
                crate::log_info!("后台初始化：load_paired_from_db 完成");
            });

            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                probe!("[bg] 开始启动 watchdog");
                transfer::spawn_ui_watchdog(app_handle.clone());
                probe!("[bg] watchdog 完成，开始配对服务");
                transfer::spawn_pairing_server(app_handle.clone());
                probe!("[bg] 配对服务完成，开始接收 watchdog");
                transfer::spawn_receiver_watchdog(app_handle.clone());
                probe!("[bg] 接收 watchdog 完成，开始常驻加密存在广播");
                // 常驻加密存在：只要运行即宣告存在（仅受防御总闸约束），驱动已配对设备在线/离线
                bcpd::start_bcpd(app_handle.clone());
                probe!("[bg] 后台服务全部启动完成");
                crate::log_info!("后台初始化：watchdog + pairing_server + receiver_watchdog 启动完成");
            });

            // 悬浮球：状态初始化 + 窗口创建 + 系统托盘（可能涉及 GPU 渲染，异步化避免卡主线程）
            // 诊断开关：LANBACKUP_NO_BALL=1 时完全跳过悬浮球/托盘/光标跟随，
            // 用于隔离"透明球窗口拖垮 WebView2 compositor"的启动冻结问题
            app.manage(ball::BallState::default());
            let ball_disabled = std::env::var("LANBACKUP_NO_BALL").map(|v| v == "1").unwrap_or(false);
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if ball_disabled {
                    probe!("[ball] LANBACKUP_NO_BALL=1 → 跳过悬浮球/托盘/光标跟随");
                    crate::log_info!("悬浮球已被 LANBACKUP_NO_BALL 禁用（诊断模式）");
                } else {
                    probe!("[ball] 开始创建托盘");
                    if let Err(e) = ball::setup_tray(&app_handle) {
                        probe!("[ball] 托盘创建失败");
                        crate::log_error!("悬浮球托盘初始化失败: {}", e);
                    }
                    probe!("[ball] 托盘完成，开始创建球窗口（透明 WebView2）");
                    if let Err(e) = ball::create_ball_window(&app_handle) {
                        probe!("[ball] 球窗口创建失败");
                        crate::log_error!("悬浮球窗口创建失败: {}", e);
                    } else {
                        probe!("[ball] 球窗口创建完成，启动光标跟随");
                        crate::log_info!("悬浮球窗口已就绪");
                        // 全局光标跟随（球窗口创建后再启动）
                        ball::spawn_cursor_tracker(&app_handle);
                    }
                }
                // 主窗口关闭 → 隐藏到托盘（而非退出）
                ball::setup_main_window_close_to_tray(&app_handle);
                probe!("[ball] 后台初始化块结束");
            });

            probe!("[18] setup 闭包立即返回（后台任务运行中）");

            // 进程存活探针（PROBE_ENABLED 门控）：独立 std 线程，每秒直写 %TEMP%\proc_alive.txt。
            // 与 logger/主线程/任何锁零共享——用于区分"进程被挂起"与"特定组件阻塞"。
            if PROBE_ENABLED {
                std::thread::spawn(|| {
                    let path = std::env::temp_dir().join("proc_alive.txt");
                    let t0 = std::time::Instant::now();
                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        if let Ok(mut f) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&path)
                        {
                            use std::io::Write as _;
                            let _ = writeln!(f, "[{}ms] proc alive", t0.elapsed().as_millis());
                        }
                    }
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::fe_probe,
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
            commands::set_defensive,
            commands::get_defensive,
            commands::remove_device,
            commands::probe_peer_port,
            commands::v3_probe,
            commands::v3_handshake_challenge,
            commands::v3_handshake_verify,
            commands::v3_pair,
            commands::v4_probe,
            commands::v4_pair,
            commands::unpair_peer,
            commands::sync_all_peers,
            commands::reset_all_pairings,
            commands::reset_all_state,
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
            commands::set_debug_mode,
            commands::get_debug_mode,
            commands::ball_emit_emotion,
            commands::ball_set_state,
            commands::set_ball_enabled,
            commands::set_ball_visible,
            logger::export_logs,
            logger::get_rust_logs,
        ])
        .run(tauri::generate_context!());

    probe!("[19] .run() 调用完成");

    if let Err(e) = result {
        // Windows GUI 无控制台，eprintln 不可见：改用日志框架 + 显式写调试日志文件
        crate::log_error!("Tauri 初始化失败: {e}");
        // 写 %TEMP%（不写盘符根目录：根目录写入是杀软 HIPS 触发特征）
        let log_path = std::env::temp_dir().join("tauri_debug_log.txt");
        if let Err(e2) = std::fs::write(
            &log_path,
            format!("[ERR] tauri builder error: {e}\n"),
        ) {
            crate::log_error!("写入调试日志到 {:?} 也失败: {e2}", log_path);
        }
        std::process::exit(1);
    }
    probe!("[20] 程序正常退出");
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

    /// 前端启动探针：把前端各启动步骤追加进 D:\tauri_debug_log.txt（与 Rust 探针同一时间线）
    #[tauri::command]
    pub fn fe_probe(msg: String) {
        probe!(format!("FE {}", msg));
    }

    #[tauri::command]
    pub fn get_self_code(app: AppHandle) -> String {        cmd_log!(logger::LogLevel::Info, "get_self_code", "入口");
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
    pub async fn probe_peer_port(ip: String, port: u16) -> Result<bool, AppError> {
        // 直连探测对端接收端口（v3 probe 走配对服务端口+1，探不到接收服务）
        let r = tauri::async_runtime::spawn_blocking(move || transfer::probe_peer_port(ip, port))
            .await
            .map_err(|e| AppError(format!("探测任务执行失败: {e}")))?;
        let ok = r.as_ref().copied().unwrap_or(false);
        cmd_log!(logger::LogLevel::Debug, "probe_peer_port", "出口 目标可达={}", ok);
        r
    }

    /// v3 控制面：GET /api/v3/probe（发现对端 v3 能力，路径A 配对材料）
    #[tauri::command]
    pub async fn v3_probe(ip: String, port: u16) -> Result<serde_json::Value, AppError> {
        cmd_log!(logger::LogLevel::Info, "v3_probe", "入口 目标={ip}:{port}");
        tauri::async_runtime::spawn_blocking(move || transfer::v3_probe(ip, port))
            .await
            .map_err(|e| AppError(format!("v3_probe 任务执行失败: {e}")))?
    }

    /// v3 控制面：POST /api/v3/handshake/challenge（重连路径B）
    #[tauri::command]
    pub async fn v3_handshake_challenge(
        ip: String,
        port: u16,
        device_id: String,
    ) -> Result<serde_json::Value, AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "v3_handshake_challenge",
            "入口 目标={ip}:{port}"
        );
        tauri::async_runtime::spawn_blocking(move || transfer::v3_handshake_challenge(ip, port, device_id))
            .await
            .map_err(|e| AppError(format!("v3_handshake_challenge 任务执行失败: {e}")))?
    }

    /// v3 控制面：POST /api/v3/handshake/verify（首次配对路径A / 重连路径B）。
    /// 路径A 服务端弹窗确认最长 45s，客户端长读超时 60s（P0 修复）。
    #[tauri::command]
    pub async fn v3_handshake_verify(
        ip: String,
        port: u16,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "v3_handshake_verify",
            "入口 目标={ip}:{port} deviceId={}",
            body.get("deviceId").and_then(|d| d.as_str()).unwrap_or("")
        );
        tauri::async_runtime::spawn_blocking(move || transfer::v3_handshake_verify(ip, port, body))
            .await
            .map_err(|e| AppError(format!("v3_handshake_verify 任务执行失败: {e}")))?
    }

    /// v3 首次配对（路径A，完整客户端流程）：probe → ECDH → 派生 → HMAC → verify。
    /// 加密全部在 Rust 层完成（前端不做密码学）。服务端弹窗确认最长 45s → 长读超时 60s（P0 修复）。
    /// approved 后持久化 pairing_secret 到 PairingState.secrets（供路径B重连）。
    #[tauri::command]
    pub async fn v3_pair(
        app: AppHandle,
        ip: String,
        port: u16,
        code: String,
        name: String,
    ) -> Result<serde_json::Value, AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "v3_pair",
            "入口 目标={ip}:{port} name={name}"
        );
        let (r, secret) = tauri::async_runtime::spawn_blocking({
            let app = app.clone();
            move || transfer::v3_pair(app, ip, port, code, name)
        })
            .await
            .map_err(|e| AppError(format!("v3_pair 任务执行失败: {e}")))??;
        // approved → 持久化 pairing_secret（路径B重连用）
        if r.get("status").and_then(|s| s.as_str()) == Some("approved") {
            if let Some(device_id) = r.get("deviceId").and_then(|d| d.as_str()) {
                if let Ok(mut m) = app.state::<crate::transfer::PairingState>().secrets.try_write() {
                    m.insert(device_id.to_string(), secret);
                }
                // P5b：approved 后落库 pairing_secret（路径B重连跨进程可用）
                crate::transfer::persist_paired(&app);
                // v5：发起方视角写入对端 ECDSA 签名公钥（信任锚）。
                // 配对记录由前端 sync_paired 建立，此处 upsert 最小记录并补公钥，
                // sync_paired 的 merge 语义会保留 peerPublicKey，门禁（check_trusted）才能放行。
                if let Some(pub_key) = r.get("publicKey").and_then(|k| k.as_str()) {
                    if !pub_key.is_empty() {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(0);
                        if let Ok(mut m) = app.state::<crate::transfer::PairingState>().paired.lock() {
                            let rec = m.entry(device_id.to_string()).or_insert_with(|| serde_json::json!({}));
                            if let Some(o) = rec.as_object_mut() {
                                o.insert("peerPublicKey".to_string(), serde_json::json!(pub_key));
                                o.entry("status".to_string()).or_insert_with(|| serde_json::json!("ACTIVE"));
                                o.entry("pairingTimestamp".to_string()).or_insert_with(|| serde_json::json!(now));
                            }
                        }
                        crate::transfer::persist_paired(&app);
                    }
                }
                cmd_log!(logger::LogLevel::Info, "v3_pair", "已持久化 pairing_secret deviceId={}", crate::logger::mask(device_id));
            }
        }
        Ok(r)
    }

    /// v4 控制面：GET /api/v4/probe（直连对端 receive port，不走 port+1）
    #[tauri::command]
    pub async fn v4_probe(ip: String, port: u16) -> Result<serde_json::Value, AppError> {
        cmd_log!(logger::LogLevel::Info, "v4_probe", "入口 目标={ip}:{port}");
        tauri::async_runtime::spawn_blocking(move || transfer::v4_probe(ip, port))
            .await
            .map_err(|e| AppError(format!("v4_probe 任务执行失败: {e}")))?
    }

    /// v4 路径 A 配对（完整流程）：probe → HMAC 认证 → verify。
    /// 与 v3 的 ECDH 密钥派生完全不同：v4 用连接码 + 双 nonce 派生出 HMAC 密钥。
    /// 直连对端 receive port（port 参数），60s 长读超时（服务端弹窗确认最长 45s）。
    #[tauri::command]
    pub async fn v4_pair(
        app: AppHandle,
        ip: String,
        port: u16,
        code: String,
        name: String,
    ) -> Result<serde_json::Value, AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "v4_pair",
            "入口 目标={ip}:{port} name={name}"
        );
        let r = tauri::async_runtime::spawn_blocking({
            let app = app.clone();
            move || transfer::v4_pair(app, ip, port, code, name)
        })
            .await
            .map_err(|e| AppError(format!("v4_pair 任务执行失败: {e}")))??;
        if r.get("status").and_then(|s| s.as_str()) == Some("active") {
            if let Some(device_id) = r.get("deviceId").and_then(|d| d.as_str()) {
                if let Ok(mut m) = app.state::<crate::transfer::PairingState>().paired.lock() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(0);
                    let rec = m.entry(device_id.to_string()).or_insert_with(|| serde_json::json!({}));
                    if let Some(o) = rec.as_object_mut() {
                        o.entry("status".to_string()).or_insert_with(|| serde_json::json!("ACTIVE"));
                        o.entry("pairingTimestamp".to_string()).or_insert_with(|| serde_json::json!(now));
                    }
                }
                crate::transfer::persist_paired(&app);
                cmd_log!(logger::LogLevel::Info, "v4_pair", "已持久化配对记录 deviceId={}", crate::logger::mask(device_id));
            }
        }
        Ok(r)
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
            // 锁范围最小化：仅用于取出 tx，send() 在锁外执行避免持有锁时阻塞
            let tx = {
                let mut m = st
                    .pending_pairing_approvals
                    .lock()
                    .map_err(|_| AppError::from_poison())?;
                m.remove(&device_id)
            };
            if let Some(tx) = tx {
                let _ = tx.send(accept);
            }
            Ok(())
        })
        .await?
    }

    /// v5：解除配对统一入口（在线直连 / 离线 REVOKE_PENDING + 吊销令牌）
    #[tauri::command]
    pub async fn unpair_peer(app: AppHandle, device_id: String) -> Result<serde_json::Value, AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "unpair_peer",
            "入口 deviceId={}",
            logger::mask(&device_id)
        );
        run_blocking(move || transfer::unpair_peer(app, device_id)).await?
    }

    /// v5：上线状态同步（事件驱动，直连所有已配对设备发 sync-status）
    #[tauri::command]
    pub async fn sync_all_peers(app: AppHandle) -> Result<serde_json::Value, AppError> {
        cmd_log!(logger::LogLevel::Info, "sync_all_peers", "入口");
        run_blocking(move || transfer::sync_all_peers(app)).await?
    }

    /// v5：物理重置（清空所有配对 + 重新生成签名身份）
    #[tauri::command]
    pub async fn reset_all_pairings(app: AppHandle) -> Result<(), AppError> {
        cmd_log!(logger::LogLevel::Info, "reset_all_pairings", "入口");
        run_blocking(move || transfer::reset_all_pairings(app)).await?
    }

    /// 重置状态：清空全部业务数据（设备/配对/传输历史/身份密钥）+ 重新生成全新身份。
    /// 设置页「重置状态」二次确认后调用；不可撤销。
    #[tauri::command]
    pub async fn reset_all_state(app: AppHandle) -> Result<(), AppError> {
        cmd_log!(logger::LogLevel::Info, "reset_all_state", "入口");
        run_blocking(move || {
            transfer::reset_all_state(&app)?;
            let state = app.state::<AppState>();
            state.db.reset_all()?;
            // 清空前端配置（config.json）：缺失时 get_config 返回空对象，前端用默认值规范化
            if let Ok(dir) = app.path().app_data_dir() {
                let _ = std::fs::remove_file(dir.join("config.json"));
            }
            Ok(())
        })
        .await?
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
        // UI 轮询命令（每 10s 一次）：DEBUG 级别，release 默认不产生日志噪音
        cmd_log!(logger::LogLevel::Debug, "get_paired_peers", "入口");
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
        peer_public_key: String,
    ) -> Result<(), AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "confirm_paired",
            "入口 deviceId={} name={}",
            logger::mask(&device_id),
            name
        );
        let r = transfer::confirm_paired(app, device_id, name, ip, port, fingerprint, peer_public_key);
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
        // UI 轮询命令：DEBUG 级别
        cmd_log!(
            logger::LogLevel::Debug,
            "sync_paired",
            "入口 数量={}",
            peers.len()
        );
        let r = run_blocking(move || transfer::sync_paired(app, peers)).await?;
        cmd_log!(
            logger::LogLevel::Debug,
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
        cmd_log!(logger::LogLevel::Debug, "get_transfers", "入口 limit={limit}");
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
        cmd_log!(logger::LogLevel::Debug, "get_config", "入口");
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
        encryption_mode: String,
    ) -> Result<u64, AppError> {
        let names: Vec<String> = files.iter().map(|f| f.rel_path().to_string()).collect();
        cmd_log!(
            logger::LogLevel::Info,
            "send_files",
            "入口 目标={target_ip}:{target_port} 文件数={} 加密={} 模式={} 列表=[{}]",
            files.len(),
            if target_code.is_empty() { "否" } else { "是" },
            encryption_mode,
            names.join(", ")
        );
        let r = transfer::send_files(
            app,
            target_ip,
            target_port,
            target_code,
            files,
            encryption_mode,
        )
        .await;
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
    pub fn set_defensive(app: AppHandle, hidden: bool) {
        cmd_log!(
            logger::LogLevel::Info,
            "set_defensive",
            "入口 hidden={hidden}"
        );
        app.state::<crate::transfer::TransferState>()
            .defensive_hidden
            .store(hidden, std::sync::atomic::Ordering::Relaxed);
        // 防御总闸隐藏：本机不再明文/加密广播、拒绝一切入站连接（句柄层拒绝 + probe 空 id + announce 停）
        cmd_log!(
            logger::LogLevel::Info,
            "set_defensive",
            "出口 hidden={hidden}"
        );
    }

    #[tauri::command]
    pub fn get_defensive(app: AppHandle) -> bool {
        app.state::<crate::transfer::TransferState>()
            .defensive_hidden
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[tauri::command]
    pub fn get_discovered_devices(
        app: AppHandle,
    ) -> Result<Vec<discovery::DiscoveredDeviceInfo>, AppError> {
        // UI 轮询命令（发现页每 1.5s 拉一次）：DEBUG 级别
        cmd_log!(logger::LogLevel::Debug, "get_discovered_devices", "入口");
        let r = discovery::get_discovered_devices(app);
        cmd_log!(
            logger::LogLevel::Debug,
            "get_discovered_devices",
            "出口 数量={}",
            r.as_ref().map(|v| v.len()).unwrap_or(0)
        );
        r
    }

    /// 按 IP 移除发现列表中的设备（Gap 6：前端确认可疑设备/僵尸设备后清理后端缓存，
    /// 否则下次 get_discovered_devices 又会把该设备带回来）。
    #[tauri::command]
    pub fn remove_device(app: AppHandle, ip: String) -> Result<(), AppError> {
        cmd_log!(logger::LogLevel::Info, "remove_device", "入口 ip={ip}");
        discovery::remove_by_ip(app, &ip);
        Ok(())
    }

    /// 动态开启/关闭调试模式（前端控制台 DevTools 可调用）。
    /// 开启后 log_debug! 宏输出完整；关闭后静默丢弃（release 也能开启）。
    #[tauri::command]
    pub fn set_debug_mode(enabled: bool) {
        logger::set_debug_mode(enabled);
    }

    /// 查询当前调试模式状态
    #[tauri::command]
    pub fn get_debug_mode() -> bool {
        cfg!(debug_assertions)
    }

    // ---------- 悬浮球表情驱动 ----------
    /// 发送表情到悬浮球窗口（由 App.vue emitBall() 调用）
    #[tauri::command]
    pub fn ball_emit_emotion(app: AppHandle, emotion_id: String, tips: String) -> Result<(), AppError> {
        ball::emit_ball_emotion(&app, &emotion_id, Some(&tips));
        Ok(())
    }

    /// 发送「状态」到悬浮球窗口（球端行为机按脚本演出，现代化行为化驱动）
    #[tauri::command]
    pub fn ball_set_state(app: AppHandle, state: String) -> Result<(), AppError> {
        ball::emit_ball_state(&app, &state);
        Ok(())
    }

    // ---------- 悬浮球显隐/启用控制 ----------
    /// 设置悬浮球启用状态（false 时隐藏窗口），由设置页"悬浮球"开关调用
    #[tauri::command]
    pub fn set_ball_enabled(app: AppHandle, enabled: bool) -> Result<(), AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "set_ball_enabled",
            "入口 enabled={}",
            enabled
        );
        ball::set_ball_enabled(&app, enabled);
        Ok(())
    }

    /// 设置悬浮球显隐（不改变启用状态），由设置页"悬浮球"开关联动调用
    #[tauri::command]
    pub fn set_ball_visible(app: AppHandle, visible: bool) -> Result<(), AppError> {
        cmd_log!(
            logger::LogLevel::Info,
            "set_ball_visible",
            "入口 visible={}",
            visible
        );
        ball::set_ball_visible(&app, visible);
        Ok(())
    }
}
