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
use std::sync::{Mutex, OnceLock};

use tauri::Manager;

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

/// 内存日志缓冲
struct Logger {
    buffer: Mutex<VecDeque<String>>,
    /// 实时落盘文件（程序卡死/崩溃时日志不丢；None = 文件未初始化或写入失败）
    file: Mutex<Option<std::fs::File>>,
}

impl Logger {
    fn new() -> Self {
        Self {
            buffer: Mutex::new(VecDeque::with_capacity(CAPACITY)),
            file: Mutex::new(None),
        }
    }
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

fn instance() -> &'static Logger {
    LOGGER.get_or_init(Logger::new)
}

/// 初始化实时日志文件（应用启动时调用一次）：
/// 覆盖写 `{Documents}/BackupLogs/live_pc.log`（固定名，复现问题后直接复制该文件）。
pub fn init_file(app: &tauri::AppHandle) {
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

/// 记录一条日志（由宏调用）。
/// console 输出 + 入环形缓冲 + **实时 append 到磁盘文件**（每条 flush，保证卡死时已落盘）。
pub fn log(level: LogLevel, module: &str, message: &str) {
    let line = format!("[{}] [{}] [{}] {}", timestamp(), level.as_str(), module, message);
    println!("{line}");
    let logger = instance();
    // 入环形缓冲（上限 1000 条，防内存溢出）
    {
        let mut buf = logger.buffer.lock().unwrap_or_else(|p| p.into_inner());
        if buf.len() >= CAPACITY {
            buf.pop_front();
        }
        buf.push_back(line.clone());
    }
    // 实时落盘：写失败静默，不影响业务
    if let Ok(mut guard) = logger.file.lock() {
        if let Some(f) = guard.as_mut() {
            let _ = writeln!(f, "{line}");
            let _ = f.flush();
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

/// 记录 DEBUG 日志（自动带模块名）
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

/// 拼接缓冲中的全部日志（含末尾换行）
pub fn dump() -> String {
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

/// 断言 helper 供测试
#[allow(dead_code)]
pub(crate) fn buffer_len() -> usize {
    instance().buffer.lock().unwrap_or_else(|p| p.into_inner()).len()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // 直接写入缓冲，验证上限
        for i in 0..(CAPACITY + 50) {
            log(LogLevel::Debug, "test", &format!("msg-{i}"));
        }
        let out = dump();
        assert!(out.contains("msg-50"), "应保留最新");
        assert!(!out.contains("msg-0"), "最旧应被丢弃");
        assert!(buffer_len() <= CAPACITY);
    }
}
