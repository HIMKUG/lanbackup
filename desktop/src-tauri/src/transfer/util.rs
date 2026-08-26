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
    /// 相对路径（含目录层级）
    rel_path: String,
    /// 文件大小（字节）
    size: u64,
    /// 修改时间（Unix 毫秒，与 shared-core mtime 单位一致）
    mtime: u64,
}

/// URL 百分号编码（分片文件名内嵌正式相对路径用；保留字母数字及 `-_.`）
pub(crate) fn pct_encode(s: &str) -> String {
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

pub(crate) fn pct_decode(s: &str) -> String {
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

/// 路径安全过滤：去掉空段/`.`/`..`，防穿越。
/// 同时按反斜杠切分（Windows 下 `a\..\..\evil` 整体作为单组件可绕过纯 '/' 切分）；
/// 过滤含 `:` 的组件（盘符 `C:` 与 NTFS 备用数据流）——join 遇盘符会整体替换前缀。
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

/// 计算接收文件的保存路径：目录层级重建 + 冲突自动重命名（永不覆盖）
///
/// 规则与 shared-core `conflict.ts` 一致：
/// - 目标不存在 → 直接用相对路径
/// - 目标存在且内容一致（大小相同、mtime 相同或未知）→ 视为已备份，覆盖无副作用
/// - 目标存在且内容不同 → 重命名为 `原名_MMDDhhmmss.扩展名`，仍冲突则追加序号
///
/// 安全：过滤掉路径穿越组件（`..`、`.`），防止恶意文件名写入备份目录之外。
pub(crate) fn resolve_target_path(receive_dir: &Path, file: &FileDto) -> PathBuf {
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

/// 重命名后仍冲突 → 追加序号 `_N`（与 shared-core `resolveFileName` 一致）
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

/// 文件 mtime 的 Unix 秒
fn modified_secs(m: &std::fs::Metadata) -> Option<i64> {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}

/// 解析 LocalSend 时间戳（RFC3339，如 "2025-08-15T08:23:45Z"）为 Unix 秒
pub(crate) fn parse_timestamp_secs(ts: &str) -> Option<i64> {
    let Ok(dt) = time::OffsetDateTime::parse(
        ts,
        &time::format_description::well_known::Rfc3339,
    ) else {
        return None;
    };
    Some(dt.unix_timestamp())
}

/// 文件 mtime → RFC3339 字符串（发送端填 FileDto.metadata）
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

/// 设置文件 mtime（接收端保留发送方时间戳）
pub(crate) fn set_file_mtime(path: &Path, secs: i64) -> std::io::Result<()> {
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs.max(0) as u64);
    let f = std::fs::File::options().write(true).open(path)?;
    f.set_modified(t)
}

/// 当前 UTC Unix 秒
pub(crate) fn now_utc_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Unix 秒 → `MMDDhhmmss`（UTC，用于重命名后缀；仅需唯一性，无需本地时区）
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

/// 根据文件名推断 LocalSend 文件类型（与 shared-core `inferFileType` 一致）
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
