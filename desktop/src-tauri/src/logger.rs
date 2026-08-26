//! logger.rs - 全链路 Debug 日志（Rust 端）
//!
//! 自定义日志宏（不依赖 log crate，避免引入额外依赖树）：
//! 日志**同时**输出到：
//! 1. 控制台（println）
//! 2. 内存环形缓冲区（最多 1000 条，防内存溢出，供 UI「预览日志」）
//! 3. **实时文件**（`{Documents}/BackupLogs/live_pc.log`，每条同步 append + flush）——
//!    程序完全无响应/崩溃时，日志仍已在磁盘，用户可直接复制该文件，无需经 UI 导出。
//!
//! 日志格式与 shared-core logger.ts 一致：
//! `[YYYY-MM-DD HH:mm:ss.SSS] [LEVEL] [ModuleName] Message`
//! 敏感信息（连接码/指纹/token）用 `mask` 脱敏后再记录。

use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use tauri::{Emitter, Manager};

use crate::db::AppError;

/// 日志级别
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    fn as_str(self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

/// 环形缓冲区上限（条）
const CAPACITY: usize = 1000;
/// 单个实时日志文件上限（字节）：超过轮转为 live_pc.1.log（仅保留一代，防越囤越多）
const FILE_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// 连续重复折叠窗口（毫秒，策略四·分层水位线）：窗口内相同消息只补一条 ×N 汇总。
/// WARN/ERROR 永不折叠——故障态保留 100% 原始毫秒明细；正常态重复压缩 ~99%。
const FOLD_WINDOW_MS: i64 = 50;
/// 测试专用：覆盖折叠窗口时长（并行测试不受真实时钟影响）。0 = 用默认值。
#[cfg(test)]
static FOLD_WINDOW_OVERRIDE_MS: AtomicI64 = AtomicI64::new(0);

/// 当前生效的折叠窗口（测试可覆盖）
fn fold_window_ms() -> i64 {
    #[cfg(test)]
    {
        let o = FOLD_WINDOW_OVERRIDE_MS.load(Ordering::Relaxed);
        if o > 0 {
            return o;
        }
    }
    FOLD_WINDOW_MS
}
/// 导出文件保留天数：更早的 debug_*.log 导出时自动清理
const EXPORT_RETENTION_DAYS: i64 = 30;
/// 导出文件数量上限：超出删最旧
const EXPORT_MAX_FILES: usize = 20;

/// 未关闭的重复折叠窗口（首条已正常落盘，后续重复暂存计数）
struct PendingFold {
    level: LogLevel,
    module: String,
    message: String,
    /// 含首条在内的总出现次数
    count: usize,
    first_ms: i64,
}

/// 内存日志缓冲
struct Logger {
    buffer: Mutex<VecDeque<String>>,
    /// 实时落盘文件（程序卡死/崩溃时日志不丢；None = 文件未初始化或写入失败）
    file: Mutex<Option<std::fs::File>>,
    /// 当前文件已写字节数（轮转判断用，避免每条 stat syscall）
    file_bytes: AtomicU64,
    /// 运行时调试模式开关：debug build 默认开，release build 默认关，
    /// 前端可通过 Tauri 命令动态切换，使 log_debug! 在 release 中也生效（不靠编译器剥离）。
    debug_enabled: AtomicBool,
    /// 折叠窗口槽（None = 无未决窗口）
    pending: Mutex<Option<PendingFold>>,
}

impl Logger {
    fn new() -> Self {
        Self {
            buffer: Mutex::new(VecDeque::with_capacity(CAPACITY)),
            file: Mutex::new(None),
            file_bytes: AtomicU64::new(0),
            // debug build 默认开启；release build 默认关闭，由前端通过 set_debug_mode 开启
            debug_enabled: AtomicBool::new(cfg!(debug_assertions)),
            pending: Mutex::new(None),
        }
    }
}

static LOGGER: OnceLock<Logger> = OnceLock::new();
static APP_HANDLE: OnceLock<tauri::AppHandle> = OnceLock::new();

fn instance() -> &'static Logger {
    LOGGER.get_or_init(Logger::new)
}

/// 初始化实时日志文件（应用启动时调用一次）：
/// 覆盖写 `{Documents}/BackupLogs/live_pc.log`（固定名，复现问题后直接复制该文件）。
pub fn init_file(app: &tauri::AppHandle) {
    register_app_handle(app);

    let docs = match app.path().document_dir() {
        Ok(d) => d,
        Err(e) => {
            let _ = e;
            return;
        }
    };
    let dir = docs.join("BackupLogs");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("live_pc.log");
    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
    {
        Ok(f) => {
            let logger = instance();
            if let Ok(mut guard) = logger.file.lock() {
                *guard = Some(f);
            }
            log(
                LogLevel::Info,
                "logger",
                &format!("实时日志文件已打开（程序无响应时直接复制此文件）: {}", path.display()),
            );
        }
        Err(e) => {
            // 文件不可用不阻断业务（内存缓冲/控制台仍可用）
            let _ = e;
        }
    }
}

/// 动态切换调试模式（前端通过 Tauri 命令调用）。
/// debug=true 时 log_debug! 输出完整；debug=false 时 log_debug! 静默丢弃。
/// 对 log_info!/log_warn!/log_error! 无影响。
pub fn set_debug_mode(enabled: bool) {
    let logger = instance();
    let was = logger.debug_enabled.load(Ordering::Relaxed);
    logger.debug_enabled.store(enabled, Ordering::Relaxed);
    log(
        LogLevel::Info,
        "logger",
        &format!(
            "调试模式切换: {} → {}",
            if was { "开" } else { "关" },
            if enabled { "开" } else { "关" }
        ),
    );
}

/// 当前毫秒时间戳（折叠窗口/事件负载共用）
fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 记录一条日志（由宏调用）。
/// console 输出 + 入环形缓冲 + **实时 append 到磁盘文件**（每条 flush，保证卡死时已落盘）。
/// DEBUG 级别消息仅在 debug_enabled 开关为 true 时输出（release 也能通过 set_debug_mode 开启）。
/// 策略四：INFO/DEBUG 连续重复消息在 50ms 窗口内折叠为 ×N 汇总（首条照常立即落盘）；
/// WARN/ERROR 永不折叠——故障现场逐条保留完整毫秒时间戳。
pub fn log(level: LogLevel, module: &str, message: &str) {
    let logger = instance();
    // DEBUG 消息：debug_enabled 关闭时静默丢弃（不落盘、不进缓冲、不打印）
    if level == LogLevel::Debug && !logger.debug_enabled.load(Ordering::Relaxed) {
        return;
    }

    // —— 折叠窗口（仅 INFO/DEBUG；WARN/ERROR 直通并强制冲刷未决窗口，保证错误前后顺序正确）——
    {
        let mut slot = logger.pending.lock().unwrap_or_else(|p| p.into_inner());
        let foldable = level < LogLevel::Warn;
        if let Some(p) = slot.as_mut() {
            if foldable
                && p.level == level
                && p.module == module
                && p.message == message
                && now_millis() - p.first_ms <= fold_window_ms()
            {
                p.count += 1;
                return; // 重复消息折叠进窗口，不产生新行
            }
        }
        // 窗口关闭（不同消息 / 超窗 / 来了 WARN+）：先落上一窗口的 ×N 汇总
        if let Some(p) = slot.take() {
            write_fold_summary(&p);
        }
        if foldable {
            *slot = Some(PendingFold {
                level,
                module: module.to_string(),
                message: message.to_string(),
                count: 1,
                first_ms: now_millis(),
            });
        }
        // 首条/WARN+ 继续走常规写入（崩溃安全：首条永远即时落盘）
    }

    write_log_line(level, module, message);
}

/// 冲刷未决折叠窗口：count>1 时补一条 `×N` 汇总行。
/// 由 sweeper 线程（窗口超时）、下一条不同消息、dump/export 三处触发。
/// 汇总行时间戳为冲刷时刻（≤窗口关闭后 100ms），首条原始时间戳已在前面正常落盘。
fn write_fold_summary(p: &PendingFold) {
    if p.count <= 1 {
        return;
    }
    let line = format!(
        "[{}] [{}] [{}] {} ×{}（连续重复已折叠，首条见上）",
        timestamp(),
        p.level.as_str(),
        p.module,
        p.message,
        p.count
    );
    write_line(&line);
    // 折叠汇总同样实时推送前端（消息体带 ×N 标记）
    emit_log_event(
        p.level,
        &p.module,
        &format!("{} ×{}（连续重复已折叠，首条见上）", p.message, p.count),
    );
}

/// 强制冲刷当前未决窗口（导出/查询前调用，保证快照完整）
fn flush_pending() {
    let logger = instance();
    if let Some(p) = logger.pending.lock().unwrap_or_else(|p| p.into_inner()).take() {
        write_fold_summary(&p);
    }
}

/// 统一写出一行：console + 环形缓冲 + 实时文件（含轮转检查）。
/// 仅 WARN/ERROR 立即 flush（关键信息崩溃前落盘）；其余交给 OS 批量刷出。
fn write_log_line(level: LogLevel, module: &str, message: &str) {
    let line = format!("[{}] [{}] [{}] {}", timestamp(), level.as_str(), module, message);
    write_line(&line);
    // 发送给前端（shared-core logger 消费）
    emit_log_event(level, module, message);
}

fn write_line(line: &str) {
    let logger = instance();
    println!("{line}");
    // 入环形缓冲（上限 1000 条，防内存溢出）
    {
        let mut buf = logger.buffer.lock().unwrap_or_else(|p| p.into_inner());
        if buf.len() >= CAPACITY {
            buf.pop_front();
        }
        buf.push_back(line.to_string());
    }
    // 实时落盘 + 体积轮转。写失败静默，不影响业务。
    if let Ok(mut guard) = logger.file.lock() {
        // 轮转：超过 FILE_MAX_BYTES → 关闭 → live_pc.1.log（覆盖旧备份）→ 重开新文件
        if logger.file_bytes.load(Ordering::Relaxed) >= FILE_MAX_BYTES {
            if let Some(f) = guard.as_mut() {
                let _ = f.flush();
            }
            *guard = None;
            if let Some(app) = APP_HANDLE.get() {
                if let Ok(docs) = app.path().document_dir() {
                    let dir = docs.join("BackupLogs");
                    let cur = dir.join("live_pc.log");
                    let bak = dir.join("live_pc.1.log");
                    let _ = std::fs::remove_file(&bak);
                    let _ = std::fs::rename(&cur, &bak);
                    if let Ok(nf) = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(&cur) {
                        *guard = Some(nf);
                        logger.file_bytes.store(0, Ordering::Relaxed);
                        let note = format!("[{}] [INFO] [logger] live_pc.log 已满 {}MB，轮转为 live_pc.1.log", timestamp(), FILE_MAX_BYTES / 1024 / 1024);
                        println!("{note}");
                    }
                }
            }
        }
        if let Some(f) = guard.as_mut() {
            let bytes = line.as_bytes();
            let _ = f.write_all(bytes);
            let _ = f.write_all(b"\n");
            logger.file_bytes.fetch_add(bytes.len() as u64 + 1, Ordering::Relaxed);
            // 仅 WARN/ERROR 立即 flush（关键信息崩溃前落盘）；其余交给 OS 批量刷出
            if line.contains("[WARN]") || line.contains("[ERROR]") {
                let _ = f.flush();
            }
        }
    }
}

/// 取当前模块路径的最后一段（如 `backup_desktop_lib::transfer` → `transfer`）
#[macro_export]
macro_rules! module_tag {
    () => {{
        let p = module_path!();
        p.rsplit("::").next().unwrap_or(p)
    }};
}

/// 记录 DEBUG 日志（自动带模块名）。
/// 输出前提：debug_enabled 开关为 true（debug build 默认开；release build 由前端 set_debug_mode 开启）。
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Debug, $crate::module_tag!(), &format!($($arg)*))
    };
}

/// 记录 INFO 日志（自动带模块名）
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Info, $crate::module_tag!(), &format!($($arg)*))
    };
}

/// 记录 WARN 日志（自动带模块名）
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Warn, $crate::module_tag!(), &format!($($arg)*))
    };
}

/// 记录 ERROR 日志（自动带模块名）
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Error, $crate::module_tag!(), &format!($($arg)*))
    };
}

/// 脱敏：只保留前 2 + 后 2 字符，中间打码（与 shared-core maskSecret 一致）。
pub fn mask(secret: &str) -> String {
    if secret.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 4 {
        return "****".to_string();
    }
    let first2: String = chars[..2].iter().collect();
    let last2: String = chars[chars.len() - 2..].iter().collect();
    format!("{first2}****{last2}")
}

/// 当前时间戳 `[YYYY-MM-DD HH:mm:ss.SSS]`（本地时区）
fn timestamp() -> String {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    let Ok(fmt) = time::format_description::parse_borrowed::<3>(
        "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]",
    ) else {
        return String::new();
    };
    now.format(&fmt).unwrap_or_else(|_| String::new())
}

/// 紧凑时间戳 `YYYYMMDD_HHmmss`（日志文件名用）
fn timestamp_compact() -> String {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    let Ok(fmt) =
        time::format_description::parse_borrowed::<3>("[year][month][day]_[hour][minute][second]")
    else {
        return String::new();
    };
    now.format(&fmt).unwrap_or_else(|_| String::new())
}

/// 拼接缓冲中的全部日志（含末尾换行）。先冲刷未决折叠窗口，保证快照完整。
pub fn dump() -> String {
    flush_pending();
    let buf = instance().buffer.lock().unwrap_or_else(|p| p.into_inner());
    let mut out = String::new();
    for line in buf.iter() {
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// 安装 panic hook：panic 信息写入日志缓冲，便于随日志导出排查。
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        log(LogLevel::Error, "panic", &info.to_string());
    }));
}

/// 清理过期导出文件：删除 EXPORT_RETENTION_DAYS 天前的 debug_*.log；
/// 若数量仍超 EXPORT_MAX_FILES，再删最旧（防日志越囤越多占满磁盘）。
fn cleanup_old_exports(dir: &std::path::Path) {
    let cutoff_ms = now_millis() - EXPORT_RETENTION_DAYS * 86_400_000;
    let mut entries: Vec<(std::time::SystemTime, std::path::PathBuf)> = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let path = e.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        if !name.starts_with("debug_") || !name.ends_with(".log") {
            continue;
        }
        let Ok(meta) = e.metadata() else { continue };
        let modified = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
        entries.push((modified, path));
    }
    // 按修改时间升序（最旧在前）
    entries.sort_by_key(|(t, _)| *t);
    let mut kept = 0usize;
    for (modified, path) in entries.iter().rev() {
        let expired = modified
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| (d.as_millis() as i64) < cutoff_ms)
            .unwrap_or(false);
        if expired || kept >= EXPORT_MAX_FILES {
            let _ = std::fs::remove_file(path);
        } else {
            kept += 1;
        }
    }
}

/// 导出日志（Tauri 命令）
///
/// 写入 `{Documents}/BackupLogs/debug_YYYYMMDD_HHmmss.log`，返回完整路径。
/// `extra_lines` 为前端 TS 侧日志（shared-core logger.export()），合并写入同一文件。
#[tauri::command]
pub fn export_logs(
    app: tauri::AppHandle,
    extra_lines: Option<String>,
) -> Result<String, AppError> {
    let docs = app.path().document_dir().map_err(AppError::from_display)?;
    let dir = docs.join("BackupLogs");
    std::fs::create_dir_all(&dir).map_err(AppError::from_display)?;
    cleanup_old_exports(&dir);
    // 文件名固定英文前缀，避免设备名含中文/特殊字符造成解码问题
    let name = format!("debug_pc_{}.log", timestamp_compact());
    let path = dir.join(&name);

    let mut content = String::new();
    content.push_str("===== Rust log (device: PC) =====\n");
    content.push_str(&dump());
    if let Some(extra) = extra_lines.as_deref() {
        if !extra.trim().is_empty() {
            content.push_str("===== 前端 TS 端日志（shared-core） =====\n");
            content.push_str(extra);
        }
    }
    std::fs::write(&path, content).map_err(AppError::from_display)?;

    let path_str = path.to_string_lossy().to_string();
    log(LogLevel::Info, "logger", &format!("日志已导出: {path_str}"));
    Ok(path_str)
}

/// 日志事件通道：log() 只做非阻塞 send，专用线程串行派发 Tauri 事件。
/// 关键设计：绝不在调用方线程直接 app.emit()——emit 需向主线程派发 WebView2 eval，
/// 多个工作线程（日志/光标跟踪/配对服务）并发派发会形成跨线程消息死锁，
/// 症状为整进程瞬间冻结（所有线程互相等待）而 WebView2 子进程照常渲染动画。
static LOG_EVENT_TX: OnceLock<std::sync::mpsc::Sender<serde_json::Value>> = OnceLock::new();

/// 实时日志事件：投递到队列（永不阻塞、永不派发），由 drain 线程发往前端。
fn emit_log_event(level: LogLevel, module: &str, message: &str) {
    if let Some(tx) = LOG_EVENT_TX.get() {
        let payload = serde_json::json!({
            "ts": now_millis(),
            "level": match level {
                LogLevel::Debug => "DEBUG",
                LogLevel::Info  => "INFO",
                LogLevel::Warn  => "WARN",
                LogLevel::Error => "ERROR",
            },
            "module": module,
            "message": message,
        });
        let _ = tx.send(payload);
    }
}

/// 注册 AppHandle（setup 阶段调用一次，之后所有 log() 都能发事件）。
/// 同时启动事件派发线程：唯一允许调用 app.emit 的日志路径。
pub fn register_app_handle(app: &tauri::AppHandle) {
    let _ = APP_HANDLE.set(app.clone());
    // 幂等：重复注册不重复启动派发线程
    if LOG_EVENT_TX.get().is_some() {
        return;
    }
    // 折叠窗口 sweeper：窗口超时后落 ×N 汇总行（否则尾窗会一直挂到下一条不同消息才冲刷）
    std::thread::spawn(|| loop {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let logger = instance();
        let expired = {
            let slot = logger.pending.lock().unwrap_or_else(|p| p.into_inner());
            match slot.as_ref() {
                Some(p) => now_millis() - p.first_ms > fold_window_ms(),
                None => false,
            }
        };
        if expired {
            flush_pending();
        }
    });
    let (tx, rx) = std::sync::mpsc::channel::<serde_json::Value>();
    if LOG_EVENT_TX.set(tx).is_err() {
        return; // 另一线程已初始化
    }
    std::thread::spawn(move || {
        // 批量合并：一次 recv 阻塞等待，随后把积压事件一次性取空再统一派发，
        // 启动日志洪峰（数十条/毫秒）也只产生少数几次跨线程派发
        while let Ok(first) = rx.recv() {
            let mut batch = vec![first];
            while let Ok(more) = rx.try_recv() {
                batch.push(more);
            }
            if let Some(app) = APP_HANDLE.get() {
                for payload in batch {
                    let _ = app.emit("rust_log_event", payload);
                }
            }
        }
    });
}

/// 拉取当前缓冲区的所有日志（供前端主动拉取，不依赖事件）。先冲刷未决折叠窗口。
#[tauri::command]
pub fn get_rust_logs() -> Vec<serde_json::Value> {
    flush_pending();
    let buf = instance().buffer.lock().unwrap_or_else(|p| p.into_inner());
    buf.iter()
        .filter_map(|line| {
            // 格式：[YYYY-MM-DD HH:mm:ss.SSS] [LEVEL] [module] message
            // 解析出 ts/level/module/message
            parse_log_line(line)
        })
        .collect()
}

/// 解析单行日志文本为结构化对象（供 get_rust_logs 和事件 payload 使用）。
/// 全程使用 strip_prefix/find 做边界检查——绝不做裸切片。
/// 历史教训：曾用 `line[find(" [")+1 .. find("] [")]` 提取时间戳，
/// 对标准行 start>end 必然越界 panic；release 配置 panic=abort 会直接杀死进程。
fn parse_log_line(line: &str) -> Option<serde_json::Value> {
    let line = line.trim();
    // 格式：[YYYY-MM-DD HH:mm:ss.SSS] [LEVEL] [module] message
    let rest = line.strip_prefix('[')?;
    let ts_end = rest.find(']')?;
    let ts_str = &rest[..ts_end];

    let rest = rest[ts_end + 1..].trim_start();
    let rest = rest.strip_prefix('[')?;
    let level_end = rest.find(']')?;
    let level = &rest[..level_end];

    let rest = rest[level_end + 1..].trim_start();
    let rest = rest.strip_prefix('[')?;
    let module_end = rest.find(']')?;
    let module = &rest[..module_end];

    let message = rest[module_end + 1..].trim();
    if level.is_empty() || module.is_empty() {
        return None;
    }

    let ts = parse_timestamp(ts_str).unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    });

    Some(serde_json::json!({
        "ts": ts,
        "level": level,
        "module": module,
        "message": message,
    }))
}

/// 解析 "YYYY-MM-DD HH:mm:ss.SSS" 为毫秒时间戳
fn parse_timestamp(s: &str) -> Option<i64> {
    let fmt = time::format_description::parse_borrowed::<3>("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]").ok()?;
    let dt = time::OffsetDateTime::parse(s, &fmt).ok()?;
    Some((dt.unix_timestamp_nanos() / 1_000_000i128) as i64)
}


#[allow(dead_code)]
pub(crate) fn buffer_len() -> usize {
    instance().buffer.lock().unwrap_or_else(|p| p.into_inner()).len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 状态型日志测试的串行锁：logger 是进程级单例，并行测试互写缓冲会破坏断言
    static TEST_SER: Mutex<()> = Mutex::new(());

    #[test]
    fn mask_keeps_first_two_and_last_two() {
        assert_eq!(mask("ABCD1234"), "AB****34");
        assert_eq!(mask("ab"), "****");
        assert_eq!(mask(""), "");
    }

    #[test]
    fn timestamp_has_expected_shape() {
        let ts = timestamp();
        assert!(ts.len() >= 23, "timestamp too short: {ts}");
        assert!(ts.starts_with("20"), "should be year first: {ts}");
    }

    #[test]
    fn ring_buffer_caps_at_capacity() {
        let _g = TEST_SER.lock().unwrap_or_else(|p| p.into_inner());
        // release 下 debug 日志默认关闭（debug_enabled=false 会静默丢弃），
        // 测试前显式开启，保证本测试在 debug/release 两种 profile 下行为一致
        set_debug_mode(true);
        // 直接写入缓冲，验证上限
        for i in 0..(CAPACITY + 50) {
            log(LogLevel::Debug, "test", &format!("msg-{i}"));
        }
        let out = dump();
        assert!(out.contains("msg-50"), "应保留最新");
        assert!(!out.contains("msg-0"), "最旧应被丢弃");
        assert!(buffer_len() <= CAPACITY);
    }

    #[test]
    fn parse_log_line_standard_format() {
        // 回归测试：曾因 find(" [")+1 > find("] [") 对标准行必然越界 panic
        // （release panic=abort 直接杀死进程 → 启动冻结事故）
        let v = parse_log_line("[2026-08-22 08:57:25.120] [INFO] [db] 打开数据库成功").unwrap();
        assert_eq!(v["level"], "INFO");
        assert_eq!(v["module"], "db");
        assert_eq!(v["message"], "打开数据库成功");
        assert!(v["ts"].as_i64().unwrap() > 0, "时间戳应解析成功");
    }

    #[test]
    fn parse_log_line_malformed_never_panics() {
        assert!(parse_log_line("").is_none());
        assert!(parse_log_line("garbage without brackets").is_none());
        assert!(parse_log_line("[unclosed").is_none());
        assert!(parse_log_line("[ts] [INFO] [mod").is_none());
    }

    #[test]
    fn fold_window_collapses_burst_and_flushes_on_new_message() {
        let _g = TEST_SER.lock().unwrap_or_else(|p| p.into_inner());
        set_debug_mode(true);
        flush_pending(); // 清空其他测试遗留的未决窗口
        // 冻结窗口时长为极大值：并行测试不受真实 50ms 时钟影响
        FOLD_WINDOW_OVERRIDE_MS.store(i64::MAX / 2, Ordering::Relaxed);
        // 窗口内连续 10 条相同消息 → 首条落盘 + 其余折叠，新消息触发冲刷出 1 条 ×N 汇总
        for _ in 0..10 {
            log(LogLevel::Info, "fold_test", "重复消息A");
        }
        log(LogLevel::Info, "fold_test", "不同消息B");
        FOLD_WINDOW_OVERRIDE_MS.store(0, Ordering::Relaxed);
        let out = dump();
        let a_count = out.matches("重复消息A").count();
        assert_eq!(a_count, 2, "首条 + ×N 汇总共 2 行，实际 {a_count} 行");
        assert!(out.contains("重复消息A ×10（连续重复已折叠"), "汇总行应含 ×10 标记");
        flush_pending();
    }

    #[test]
    fn warn_never_folds() {
        let _g = TEST_SER.lock().unwrap_or_else(|p| p.into_inner());
        set_debug_mode(true);
        flush_pending();
        FOLD_WINDOW_OVERRIDE_MS.store(i64::MAX / 2, Ordering::Relaxed);
        // WARN 级别即使完全相同也逐条保留（故障态 100% 保真）
        for _ in 0..3 {
            log(LogLevel::Warn, "fold_test", "警告W");
        }
        FOLD_WINDOW_OVERRIDE_MS.store(0, Ordering::Relaxed);
        flush_pending();
        let out = dump();
        assert_eq!(out.matches("[WARN] [fold_test] 警告W").count(), 3, "WARN 不参与折叠，应 3 行全保留");
    }
}
