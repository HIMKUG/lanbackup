//! 传输模块 - 通用工具（路径 / 时间戳 / 文件类型 / 目录扫描）
//!
//! 纯文件拆分重构：本文件内容从原 transfer.rs 原样移入，逻辑零改动。
//! 通过 `use super::*` 访问 mod.rs 中的类型与外部 use；被兄弟模块调用的
//! 私有函数提升为 `pub(crate)`（依赖 mod.rs 顶部 `pub use util::*` 重导出）。

use super::*;

/// 目录扫描条目（Tauri 命令返回值）
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannedEntry {
    rel_path: String,
    size: u64,
    mtime: u64,
}

/// URL 百分号编码（RFC3986 子集，保留 `~`）。
///
/// 当前发送端使用 `urlencoding` crate；保留本函数供 B4 的移动端对齐与
/// 旧调用点迁移，避免各端各写一份编码表（WB-0507）。
#[allow(dead_code)]
pub(crate) fn pct_encode(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

#[allow(dead_code)]
pub(crate) fn sanitize_rel_path(name: &str) -> String {
    let mut parts = Vec::new();
    for comp in name.split(['/', '\\']) {
        match comp {
            "" | "." | ".." => continue,
            c if c.contains(':') => continue,
            c => parts.push(c),
        }
    }
    parts.join("/")
}

#[allow(dead_code)]
pub(crate) fn resolve_target_path(receive_dir: &Path, file: &FileDto) -> PathBuf {
    let rel = Path::new(&file.file_name);
    let mut safe = PathBuf::new();
    for comp in rel.components() {
        match comp {
            std::path::Component::ParentDir | std::path::Component::CurDir => continue,
            other => safe.push(other.as_os_str()),
        }
    }
    let rel = if safe.as_os_str().is_empty() {
        rel.file_name().map(PathBuf::from).unwrap_or_default()
    } else {
        safe
    };
    let rel = if rel.is_absolute() {
        rel.file_name().map(PathBuf::from).unwrap_or_default()
    } else {
        rel
    };
    let target = receive_dir.join(&rel);
    if !target.exists() {
        return target;
    }
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
    let identical = std::fs::metadata(&target)
        .map(|m| {
            let same_size = m.len() == file.size;
            let same_mtime = match file.metadata.as_ref() {
                Some(md) => match md.modified.as_deref() {
                    Some(ts) => parse_timestamp_secs(ts) == modified_secs(&m),
                    None => true,
                },
                None => true,
            };
            same_size && same_mtime
        })
        .unwrap_or(false);
    if identical {
        return target;
    }
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

#[allow(dead_code)]
pub(crate) fn rename_with_suffix(rel: &Path, suffix: &str) -> PathBuf {
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

#[allow(dead_code)]
pub(crate) fn rename_with_counter(candidate: &Path, counter: u32) -> PathBuf {
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

#[allow(dead_code)]
fn modified_secs(m: &std::fs::Metadata) -> Option<i64> {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}

#[allow(dead_code)]
pub(crate) fn parse_timestamp_secs(ts: &str) -> Option<i64> {
    let Ok(dt) = time::OffsetDateTime::parse(
        ts,
        &time::format_description::well_known::Rfc3339,
    ) else {
        return None;
    };
    Some(dt.unix_timestamp())
}

#[allow(dead_code)]
pub(crate) fn file_modified_rfc3339(abs_path: &str) -> Option<String> {
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

#[allow(dead_code)]
pub(crate) fn set_file_mtime(path: &Path, secs: i64) -> std::io::Result<()> {
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs.max(0) as u64);
    let f = std::fs::File::options().write(true).open(path)?;
    f.set_modified(t)
}

#[allow(dead_code)]
pub(crate) fn now_utc_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[allow(dead_code)]
pub(crate) fn format_mmddhhmmss(secs: i64) -> String {
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

#[allow(dead_code)]
pub(crate) fn infer_file_type(name: &str) -> String {
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

/// [`http_json_request_internal`] 的超时与协议头选项（缺省：1.5s 连接 / 3s 读写 / 不带版本头）。
#[derive(Debug, Clone, Copy)]
pub(crate) struct HttpRequestOptions<'a> {
    pub connect_ms: u64,
    pub read_ms: u64,
    pub write_ms: u64,
    pub protocol_version: Option<&'a str>,
}

impl Default for HttpRequestOptions<'_> {
    fn default() -> Self {
        Self { connect_ms: 1500, read_ms: 3000, write_ms: 3000, protocol_version: None }
    }
}

/// HTTP JSON 请求内部实现（纯 TcpStream，无外部依赖）。
///
/// 超时与 `protocol_version` 打包成 [`HttpRequestOptions`]：参数从 9 个降到 6 个，
/// 调用方用 `..Default::default()` 只覆盖自己关心的项。
/// body 最大 64MB，超出返回错误。
pub(crate) fn http_json_request_internal(
    ip: &str,
    port: u16,
    method: &str,
    path: &str,
    body: &str,
    options: &HttpRequestOptions,
) -> Result<serde_json::Value, AppError> {
    let HttpRequestOptions {
        connect_ms,
        read_ms,
        write_ms,
        protocol_version,
    } = *options;
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let addr = (ip, port)
        .to_socket_addrs()
        .map_err(|e| AppError(format!("解析地址 {ip}:{port} 失败: {e}")))?
        .next()
        .ok_or_else(|| AppError(format!("无可用地址: {ip}:{port}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(connect_ms))
        .map_err(|e| AppError(format!("连接 {ip}:{port} 失败: {e}")))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(read_ms)))
        .map_err(AppError::from_display)?;
    stream
        .set_write_timeout(Some(Duration::from_millis(write_ms)))
        .map_err(AppError::from_display)?;

    let self_device_id = crate::identity::get_device_id_no_ctx();
    let proto_header = protocol_version
        .map(|v| format!("X-Protocol-Version: {v}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nX-Device-Id: {self_device_id}\r\n{proto_header}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).map_err(AppError::from_display)?;

    let mut resp_buf: Vec<u8> = Vec::with_capacity(16 * 1024);
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
    let text = String::from_utf8_lossy(&resp_buf);
    let json_part = text.split_once("\r\n\r\n").map(|x| x.1)
        .ok_or_else(|| AppError("HTTP 响应缺少 body 分隔符".to_string()))?;
    if json_part.trim().is_empty() {
        return Err(AppError("HTTP 响应 body 为空".to_string()));
    }
    serde_json::from_str(json_part)
        .map_err(|e| AppError(format!("解析响应失败: {e}")))
}

/// 扫描接收目录并构建 core 清单（含 `delete/` 墓碑）。
///
/// 清单是 `GET /api/v4/manifest` 的唯一数据源：不喂给 core，对端拿到的
/// 永远是空清单，增量规划会退化为每次全量传输。
pub(crate) fn scan_manifest(
    dir: &Path,
) -> Result<lanbackup_core::dto::sync::Manifest, AppError> {
    let mut entries = Vec::new();
    scan_dir_recursive(dir, "", 0, &mut entries)?;
    let pairs = entries.into_iter().map(|e| {
        (
            e.rel_path,
            lanbackup_core::dto::sync::ManifestEntry {
                size: e.size,
                mtime: e.mtime as i64,
            },
        )
    });
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    Ok(lanbackup_core::sync::manifest::build_manifest(
        &identity::get_device_id_no_ctx(),
        now_ms,
        pairs,
    ))
}

/// 递归扫描目录
pub async fn scan_directory(dir: String) -> Result<Vec<ScannedEntry>, AppError> {
    let dir_for_task = dir.clone();
    let entries = tokio::task::spawn_blocking(move || {
        let mut entries = Vec::new();
        scan_dir_recursive(&PathBuf::from(&dir_for_task), "", 0, &mut entries)?;
        Ok::<_, AppError>(entries)
    })
    .await
    .map_err(|e| AppError(format!("扫描任务执行失败: {e}")))??;
    crate::log_debug!("扫描目录完成: {dir} 共 {} 条", entries.len());
    Ok(entries)
}

/// 扫描防护（WB-0502）：深度与条目上限 —— 深树防栈溢出，海量条目防内存膨胀。
/// 触顶按错误上抛（调用方可见），绝不静默截断后冒充完整清单。
const SCAN_MAX_DEPTH: usize = 32;
const SCAN_MAX_ENTRIES: usize = 200_000;

fn scan_dir_recursive(
    base: &Path,
    rel: &str,
    depth: usize,
    out: &mut Vec<ScannedEntry>,
) -> Result<(), AppError> {
    if depth > SCAN_MAX_DEPTH {
        return Err(AppError(format!(
            "目录嵌套超过 {SCAN_MAX_DEPTH} 层，已停止扫描（疑似循环挂载/异常深树）: {rel}"
        )));
    }
    let cur = if rel.is_empty() {
        base.to_path_buf()
    } else {
        base.join(rel)
    };
    for entry in std::fs::read_dir(&cur).map_err(AppError::from_display)? {
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
        // 不跟随符号链接与 Windows junction/reparse（WB-0503）：file_type()
        // 在 Windows 上把 junction 识别为 symlink，两平台一致跳过。
        if ftype.is_symlink() {
            crate::log_warn!("跳过符号链接/junction（不跟随，归档语义）: {child_rel}");
            continue;
        }
        if name == ".chunks"
            || name == "__chunked__"
            || name.ends_with(".dec_tmp")
            || name.starts_with("__batch__")
        {
            crate::log_debug!("跳过内部文件: {child_rel}");
            continue;
        }
        // WB-0504：core 接收端的传输临时文件 `*.part.<sid>.<fid>` 不得混进清单，
        // 否则半截文件会被当成真实文件同步/备份。
        if name.contains(".part.") {
            crate::log_debug!("跳过传输临时文件: {child_rel}");
            continue;
        }
        if out.len() >= SCAN_MAX_ENTRIES {
            return Err(AppError(format!(
                "扫描条目数超过上限（{SCAN_MAX_ENTRIES}），已停止：请缩小目录范围"
            )));
        }
        if !ftype.is_file() && !ftype.is_dir() {
            crate::log_warn!("跳过特殊文件（设备/管道/套接字）: {child_rel}");
            continue;
        }
        if ftype.is_dir() {
            scan_dir_recursive(base, &child_rel, depth + 1, out)?;
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
