//! 悬浮球模块
//!
//! 职责：
//! - 管理悬浮球窗口（ball.html）的创建与生命周期
//! - 系统托盘：关闭主窗口时隐藏到托盘，点托盘恢复
//! - Rust → ball 窗口的事件通道（表情更新、显隐控制）
//! - ball 窗口 → Rust 的 action 事件（唤起主窗口等）
//!
//! 通信协议：
//!   Rust emit "ball:emotion" → { emotionId: string, tips?: string }
//!   Rust emit "ball:visible" → bool
//!   Rust emit "ball:enabled" → bool
//!   ball emit "ball:action"  → { type: "open-main" | "click", emotionId?: string }

use std::sync::Mutex;
use tauri::{
    AppHandle, Emitter, Listener, Manager,
    WebviewUrl, WebviewWindowBuilder,
    menu::{Menu, MenuItem},
    tray::{TrayIcon, TrayIconBuilder},
    image::Image,
};

/// 悬浮球状态
pub struct BallState {
    /// 悬浮球窗口是否已创建
    pub window_created: Mutex<bool>,
    /// 当前表情 ID
    pub current_emotion: Mutex<String>,
    /// 是否启用（false 时隐藏窗口）
    pub enabled: Mutex<bool>,
    /// 托盘图标
    pub tray: Mutex<Option<TrayIcon>>,
}

impl Default for BallState {
    fn default() -> Self {
        Self {
            window_created: Mutex::new(false),
            current_emotion: Mutex::new("02".to_string()),
            enabled: Mutex::new(true),
            tray: Mutex::new(None),
        }
    }
}

/// 创建悬浮球窗口
pub fn create_ball_window(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<BallState>();

    {
        let created = state.window_created.lock().map_err(|e| e.to_string())?;
        if *created {
            return Ok(()); // 已创建，无需重复
        }
    }

    // 创建透明、无边框、置顶的小窗口（透明视觉保留；启动冻结根因已确认为
    // get_rust_logs 的 parse_log_line 越界 panic，与透明窗口/GPU 无关）
    let _ball_window = WebviewWindowBuilder::new(
        app,
        "ball",
        WebviewUrl::App("ball.html".into()),
    )
    .title("Floating Ball")
    .inner_size(200.0, 200.0)
    .decorations(false)
    .transparent(true)
    .shadow(false)
    .background_color(tauri::window::Color(0, 0, 0, 0))
    .always_on_top(true)
    .skip_taskbar(true)
    .resizable(false)
    .visible(false)
    .build()
    .map_err(|e| e.to_string())?;

    // 初始移到工作区右下角：用 work_area 避开任务栏遮挡；
    // 全部按物理坐标计算（monitor 尺寸为物理像素，窗口物理尺寸 = 逻辑 200 × 缩放），避免双重缩放
    if let Some(mon) = app.primary_monitor().ok().flatten() {
        let scale = mon.scale_factor();
        let area = mon.work_area();
        let (bw, bh) = (200.0 * scale, 200.0 * scale); // 窗口物理尺寸
        let margin = 24.0 * scale;
        let x = area.position.x as f64 + (area.size.width as f64 - bw - margin).max(0.0);
        let y = area.position.y as f64 + (area.size.height as f64 - bh - margin).max(0.0);
        let _ = _ball_window.set_position(tauri::PhysicalPosition::new(x as i32, y as i32));
    }

    // 标记已创建
    {
        let mut created = state.window_created.lock().map_err(|e| e.to_string())?;
        *created = true;
    }

    // 监听来自 ball 窗口的 action 事件
    let app_handle = app.clone();
    app.listen("ball:action", move |event| {
        // 此版本 event.payload() 直接返回 &str（非 Option），配合 from_str 解析
        let payload = event.payload();
        if let Ok(action) = serde_json::from_str::<serde_json::Value>(payload) {
            if let Some(typ) = action.get("type").and_then(|v| v.as_str()) {
                match typ {
                    "open-main" => {
                        // 唤起主窗口
                        if let Some(main_win) = app_handle.get_webview_window("main") {
                            let _ = main_win.show();
                            let _ = main_win.set_focus();
                        }
                    }
                    "click" => {
                        // 单击换表情，由 ball 窗口自行处理，无需 Rust 介入
                        log::info!("ball: click action, emotionId={:?}",
                            action.get("emotionId").and_then(|v| v.as_str()));
                    }
                    "drop-folder" => {
                        // 拖文件夹到悬浮球：把路径转发给主窗口前端，执行「只同步这一个文件夹」
                        if let Some(path) = action.get("path").and_then(|v| v.as_str()) {
                            if let Some(main_win) = app_handle.get_webview_window("main") {
                                let _ = main_win.emit(
                                    "ball:drop-folder",
                                    serde_json::json!({ "path": path }),
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    log::info!("悬浮球窗口已创建");
    Ok(())
}

/// 发送表情到悬浮球窗口
pub fn emit_ball_emotion(app: &AppHandle, emotion_id: &str, tips: Option<&str>) {
    let payload = serde_json::json!({
        "emotionId": emotion_id,
        "tips": tips.unwrap_or(""),
    });
    if let Some(win) = app.get_webview_window("ball") {
        let _ = win.emit("ball:emotion", payload);
        // 同步更新状态
        if let Some(state) = app.try_state::<BallState>() {
            if let Ok(mut cur) = state.current_emotion.lock() {
                *cur = emotion_id.to_string();
            }
        }
    }
}

/// 发送「状态」到悬浮球窗口：球端行为机按脚本演出（现代化行为化驱动）
pub fn emit_ball_state(app: &AppHandle, state: &str) {
    let payload = serde_json::json!({ "stateId": state });
    if let Some(win) = app.get_webview_window("ball") {
        let _ = win.emit("ball:state", payload);
    }
}

/// 设置悬浮球显隐
pub fn set_ball_visible(app: &AppHandle, visible: bool) {
    if let Some(win) = app.get_webview_window("ball") {
        if visible {
            let _ = win.show();
        } else {
            let _ = win.hide();
        }
    }
}

/// 设置悬浮球启用状态
pub fn set_ball_enabled(app: &AppHandle, enabled: bool) {
    if let Some(state) = app.try_state::<BallState>() {
        if let Ok(mut en) = state.enabled.lock() {
            *en = enabled;
        }
    }
    if let Some(win) = app.get_webview_window("ball") {
        let _ = win.emit("ball:enabled", enabled);
        if enabled {
            let _ = win.show();
        } else {
            let _ = win.hide();
        }
    }
}

/// 全局光标跟随：每 ~33ms 轮询一次系统光标，换算成「相对球心」的归一化偏移，
/// 通过 ball:cursor 推给球窗口前端（前端喂给 engine.setGaze）。
///
/// 为什么这么做：悬浮球是独立的 80×80 透明小窗口，前端的 pointermove 只能收到
/// 球窗口内部的鼠标事件；鼠标移到窗口外就收不到。因此必须由 Rust 全局读光标，
/// 才能做到「无论鼠标在哪，球都看着它」。
pub fn spawn_cursor_tracker(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        use std::time::Duration;
        let mut last = (-10.0f64, -10.0f64);
        let mut ignoring = true; // 初始：窗口整体对鼠标穿透（透明区域不挡桌面点击）
        loop {
            tokio::time::sleep(Duration::from_millis(33)).await;
            // 悬浮球被关闭时：完全停止全局鼠标轮询 / 穿透切换 / 注视推送，避免后台空转耗 CPU
            if let Some(state) = app.try_state::<BallState>() {
                if let Ok(en) = state.enabled.lock() {
                    if !*en {
                        continue;
                    }
                }
            }
            // 球窗口可能尚未创建（并发），失败则跳过本轮
            let Some(win) = app.get_webview_window("ball") else {
                continue;
            };
            let Some(pos) = win.outer_position().ok() else {
                continue;
            };
            let Some(mon) = win.current_monitor().ok().flatten() else {
                continue;
            };
            let scale = mon.scale_factor();
            // 光标所在显示器尺寸（归一化的分母），避免球贴边时偏移饱和过快
            let msize = mon.size();
            let half_w = (msize.width / 2).max(1) as f64;
            let half_h = (msize.height / 2).max(1) as f64;

            let mouse = match mouse_position::mouse_position::Mouse::get_mouse_position() {
                mouse_position::mouse_position::Mouse::Position { x, y } => (x as f64, y as f64),
                _ => continue,
            };
            // 窗口 200×200（逻辑）→ 物理尺寸 = 200×scale；球心 = 窗口左上 + 物理半宽
            let w_phys = 200.0 * scale;
            let (cx, cy) = (pos.x as f64 + w_phys / 2.0, pos.y as f64 + w_phys / 2.0);

            // 穿透切换：光标落在球体（窗口中央 80×80 物理区域）内 → 窗口接收鼠标事件
            // （可拖拽/点击/长按）；否则穿透，放大出的透明区域不挡桌面点击。
            let ball_phys = 80.0 * scale;
            let in_ball = (mouse.0 - cx).abs() <= ball_phys / 2.0
                && (mouse.1 - cy).abs() <= ball_phys / 2.0;
            let want_ignore = !in_ball;
            if want_ignore != ignoring {
                ignoring = want_ignore;
                let _ = win.set_ignore_cursor_events(want_ignore);
            }

            // 相对球心的偏移，除以半屏宽度 → 归一化；静默兜底：光标不在副屏时用其距主屏中心的相对量
            let nx = ((mouse.0 - cx) / half_w).clamp(-1.0, 1.0);
            let ny = ((mouse.1 - cy) / half_h).clamp(-1.0, 1.0);
            // 未变化则跳过（省 IPC/重绘）
            if (nx - last.0).abs() < 0.004 && (ny - last.1).abs() < 0.004 {
                continue;
            }
            last = (nx, ny);
            let payload = serde_json::json!({ "nx": nx, "ny": ny });
            let _ = win.emit("ball:cursor", payload);
        }
    });
    log::info!("全局光标跟随线程已启动");
}

/// 设置主窗口关闭行为：点关闭 = 直接退出应用（悬浮球/托盘一并清理）。
/// 最小化保持系统默认（缩到任务栏）。此前关闭是隐藏到托盘——用户明确要求改为真退出。
pub fn setup_main_window_close_to_tray(app: &AppHandle) {
    if let Some(main_win) = app.get_webview_window("main") {
        let app2 = app.clone();
        main_win.clone().on_window_event(move |event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                log::info!("主窗口关闭 → 应用退出");
                app2.exit(0);
            }
        });
    }
}

/// 初始化系统托盘
pub fn setup_tray(app: &AppHandle) -> Result<(), String> {
    // "显示主窗口" 菜单项
    let show_item = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)
        .map_err(|e| e.to_string())?;
    let quit_item = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)
        .map_err(|e| e.to_string())?;

    let menu = Menu::with_items(app, &[&show_item, &quit_item])
        .map_err(|e| e.to_string())?;

    // 加载托盘图标：默认窗口图标已内嵌打包，避免 `include_bytes!` 的编译期路径依赖
    let icon = app.default_window_icon().cloned()
        .unwrap_or_else(|| Image::new(&[], 0, 0));

    let tray = TrayIconBuilder::new()
        .icon(icon)
        .menu(&menu)
        .tooltip("局域网备份 · 悬浮球")
        .on_menu_event(move |app, event| {
            match event.id.as_ref() {
                "show" => {
                    if let Some(win) = app.get_webview_window("main") {
                        let _ = win.show();
                        let _ = win.set_focus();
                    }
                }
                "quit" => {
                    // 真正退出程序
                    app.exit(0);
                }
                _ => {}
            }
        })
        .build(app)
        .map_err(|e| e.to_string())?;

    // 存入状态（保持引用）
    if let Some(state) = app.try_state::<BallState>() {
        if let Ok(mut tray_store) = state.tray.lock() {
            *tray_store = Some(tray);
        }
    }

    log::info!("系统托盘已初始化");
    Ok(())
}
