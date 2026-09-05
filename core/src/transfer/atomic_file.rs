//! V4 接收端最终落盘的**原子替换契约**（对应文档第五层「`*.part` 原子 rename」）。
//!
//! # 为什么需要契约
//!
//! 断点续传 / 任务文件传输要真正成立，**光有块位图不够**
//! （块位图持久化见 [`crate::server::persist`]）。接收端把收到的块写进一个
//! **临时文件**，等全部到齐并校验通过后，再**原子地**把它换成最终文件名。
//! 这一步若不是原子的，并发读或崩溃恢复就会看到「半截文件」——
//! 即文档第五层要解决的「最终一致性」问题。
//!
//! # M20 约束：Android SAF 无跨目录 rename
//!
//! 实测智慧清单 **M20**：SAF（`DocumentsContract`）**只能在同一个父目录内**
//! `rename` / `moveDocument`，跨目录移动只能「复制 + 删除」。
//! 因此本契约**强制**：临时文件必须落在最终文件**同一目录**内，最终提交是
//! 同目录 rename（POSIX / NTFS / SAF 同父都原子且可行）。任何把临时文件放到
//! 别的目录再 rename 过来的写法，在 Android 上要么失败、要么退化成非原子移动。
//!
//! # 两条提交路径
//!
//! - [`commit_rename`]（默认）：同目录 `rename(part → final)`，原子替换。
//! - [`commit_copy_delete`]（降级）：跨设备 / 不支持同父 rename 时的退路，
//!   先复制再删临时文件。**代价**：存在「旧 final 已删、新 final 还没写完」的
//!   极短读取窗口，文档记为已知代价，仅在 rename 不可用时启用。
//!
//! 平台层（桌面 `std::fs` / Android SAF）都应遵循同一套路：
//! **写 `.part`（与 final 同目录）→ 全到齐且校验通过 → [`commit`]**。
//!
//! # 与块位图的关系
//!
//! - 块级「哪些块已确认」由 core 的 `confirmed` 位图负责（[`crate::server::persist`]）；
//! - 字节级「已经写到第几个字节」由本模块的 [`committed_bytes`] 从 `.part` 实际大小读出，
//!   供平台在重连后把**字节偏移**喂回发送端，从断点继续写。
//!
//! 两者互补：位图决定「传哪些块」，`.part` 的字节长度决定「从哪接着写」。
//!
//! # 提交后的关键收尾（平台责任，务必遵守）
//!
//! 提交完成后，平台**必须**把最终文件的 `mtime` 设回 [`crate::dto::session::FileMeta::mtime`]
//! —— 发送端三路对比依赖 mtime 判变更，一旦被写成「写入时间」就会永久误判为变更、
//! 每次全量重传（原 `transfer.ts:187` 的老坑）。这条在 DTO 注释里也强调过，
//! 这里再锁一次：原子替换**不**自动保留 mtime，是平台的事。

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// 冲突检查结果（A18/A19）。
///
/// 平台在 [`commit`] **之前**调用 [`resolve_conflict`] 决定如何落盘：
/// - [`ConflictOutcome::None`] —— 目标不存在，可正常提交；
/// - [`ConflictOutcome::Identical`] —— 已存在且 size/mtime 一致，**幂等跳过**
///   （A19：否则上次中断后的重试会造出一堆 `_0815234500` 副本）；
/// - [`ConflictOutcome::Renamed`] —— 旧文件已按 `原名_MMDDhhmmss.扩展名` 改名，
///   新文件可正常提交（A18：**绝不覆盖、绝不弹窗**，局域网备份无人值守时
///   弹窗会挂死流程，宁可多一份副本也不静默丢数据）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictOutcome {
    /// 目标文件不存在，可正常提交
    None,
    /// A19：同名且 size/mtime 完全一致 → 视为已存在，跳过本次落盘
    Identical,
    /// A18：旧文件已重命名（返回改名后的路径），新文件可正常提交
    Renamed(PathBuf),
}

/// 检查并处理最终文件路径上的冲突（A18/A19），返回落盘决策。
///
/// `expected_size` / `expected_mtime_ns` 来自发送端清单（`FileMeta`）。判断"是否
/// 幂等已存在"用 size 严格相等 + mtime 容差 2s（部分平台 mtime 精度落秒级，
/// 与 [`restore_mtime`] 的测试容忍一致）。改名时间戳用本地时间 `MMDDhhmmss`。
pub fn resolve_conflict(
    final_path: &Path,
    expected_size: u64,
    expected_mtime_ns: i64,
) -> std::io::Result<ConflictOutcome> {
    let meta = match std::fs::metadata(final_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ConflictOutcome::None),
        Err(e) => return Err(e),
    };

    // A19：size/mtime 都一致 → 上次已成功落盘，幂等跳过
    let existing_ns = meta
        .modified()
        .map(|t| t.duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0))
        .unwrap_or(0);
    if meta.len() == expected_size && (existing_ns - expected_mtime_ns).abs() <= 2_000_000_000 {
        return Ok(ConflictOutcome::Identical);
    }

    // A18：存在但内容对不上 → 旧文件改名保留，绝不覆盖
    let renamed = conflict_rename_path(final_path);
    std::fs::rename(final_path, &renamed)?;
    Ok(ConflictOutcome::Renamed(renamed))
}

/// 冲突副本路径：`原名_MMDDhhmmss.扩展名`（无扩展名则直接追加）。
fn conflict_rename_path(final_path: &Path) -> PathBuf {
    let name = final_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (&name[..], ""),
    };
    // UTC 时间戳（10 位 MMDDhhmmss）：避免引入 local-offset feature 的平台差异；
    // 时间戳只用于「副本名不冲突」，时区不影响正确性
    let stamp = time::OffsetDateTime::now_utc()
        .format(&time::macros::format_description!("[month][day][hour][minute][second]"))
        .unwrap_or_default();
    let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{stem}_{stamp}{ext}"))
}

/// 临时文件名后缀里允许出现的字符：仅字母数字与 `-_`。
///
/// `session_id` / `file_id` 虽由本端 CSPRNG 生成（可控），但契约面向「任何调用方」，
/// 仍按不可信输入对待，过滤掉 `/` `..` 等可能破坏同目录约束的字符。
fn sanitize(id: &str) -> String {
    let s: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if s.is_empty() {
        "x".to_string()
    } else {
        s
    }
}

/// 为「最终文件路径」算出对应的「临时文件路径」。
///
/// 规则：与 `final_path` **同目录**（满足 M20 同目录 rename 约束），文件名追加
/// `.part.<session_id>.<file_id>` 后缀。用 session/file id 区分「并发传输同一
/// `relPath` 的不同会话」，避免两个会话的 `.part` 互相覆盖。
///
/// # 例
///
/// `part_path("/backup/photo.jpg", "s1", "f1")` →
/// `"/backup/photo.jpg.part.s1.f1"`（与 `photo.jpg` 同目录）。
pub fn part_path(final_path: &Path, session_id: &str, file_id: &str) -> PathBuf {
    let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = final_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let s = sanitize(session_id);
    let f = sanitize(file_id);
    parent.join(format!("{stem}.part.{s}.{f}"))
}

/// 提交方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitMode {
    /// 同目录 rename（原子，默认）
    Rename,
    /// 复制 + 删除（降级路径，存在读取窗口）
    CopyDelete,
}

/// 按契约自动选择提交方式：同目录 → [`CommitMode::Rename`]，否则 → [`CommitMode::CopyDelete`]。
pub fn choose_commit_mode(part: &Path, final_path: &Path) -> CommitMode {
    match (part.parent(), final_path.parent()) {
        (Some(p1), Some(p2)) if p1 == p2 => CommitMode::Rename,
        _ => CommitMode::CopyDelete,
    }
}

/// 把临时文件**原子替换**为最终文件（同目录 rename）。
///
/// 前置条件：临时文件与最终文件**同目录**（见 M20）。若不同目录，直接返回 `Err`
/// 而不执行任何移动 —— 调用方应改用 [`commit_copy_delete`] 或 SAF 同父 `moveDocument`。
///
/// 成功时旧的最终文件（若存在）被原子覆盖；临时文件消失，最终文件出现。
/// 并发读因此永远看不到「半截」中间态。
pub fn commit_rename(part: &Path, final_path: &Path) -> std::io::Result<()> {
    match (part.parent(), final_path.parent()) {
        (Some(p1), Some(p2)) if p1 == p2 => {}
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "原子替换要求临时文件与最终文件同目录（M20：SAF 无跨目录 rename）",
            ))
        }
    }
    std::fs::rename(part, final_path)
}

/// 降级提交：把临时文件**复制**到最终路径，再删临时文件。
///
/// **代价**：复制过程中（以及覆盖旧 final 的瞬间）存在「旧 final 已删/未写完、
/// 新 final 还没好」的极短读取窗口，文档记为已知代价。仅在 [`commit_rename`]
/// 不可用（跨设备）时启用。
///
/// 注意：复制用 `std::fs::copy` 直接覆盖 `final_path`，所以不需要额外的临时 final。
pub fn commit_copy_delete(part: &Path, final_path: &Path) -> std::io::Result<()> {
    std::fs::copy(part, final_path)?;
    // 复制成功后再删临时文件（失败也不影响：final 已是正确内容）
    let _ = std::fs::remove_file(part);
    Ok(())
}

/// 按契约提交（自动选路径）。桌面 / Android 平台层都应经此唯一入口，
/// 不要在别处手写 rename/copy，以免破坏 M20 同目录约束。
pub fn commit(part: &Path, final_path: &Path) -> std::io::Result<()> {
    match choose_commit_mode(part, final_path) {
        CommitMode::Rename => commit_rename(part, final_path),
        CommitMode::CopyDelete => commit_copy_delete(part, final_path),
    }
}

/// 已落盘字节数（用于字节级续传的起始偏移）。
///
/// 返回临时文件当前大小；不存在则 0（表示从头传）。平台在重连后调用本函数，
/// 把返回值作为「已写字节偏移」喂回发送端，从断点继续写——与 core 的
/// `confirmed` 块位图互补（位图管「传哪些块」，`committed_bytes` 管「从哪接着写」）。
pub fn committed_bytes(part: &Path) -> u64 {
    std::fs::metadata(part).map(|m| m.len()).unwrap_or(0)
}

/// 把最终文件的 mtime 恢复到发送端声明的原始值（见模块文档「提交后的关键收尾」）。
///
/// 原子替换（rename / copy）会把 final 的 mtime 写成「本次写入时间」，
/// 而发送端三路对比依赖 mtime 判变更 —— 不恢复则每次都被误判为变更、全量重传。
/// 平台在 [`commit`] 之后**必须**调用本函数把 [`crate::dto::session::FileMeta::mtime`]
/// 写回。
///
/// `mtime_ns` 为纳秒级 Unix 时间戳（与 DTO 中的 `mtime` 字段语义一致）。
pub fn restore_mtime(final_path: &Path, mtime_ns: i64) -> std::io::Result<()> {
    let secs = mtime_ns.div_euclid(1_000_000_000).max(0) as u64;
    let nsec = mtime_ns.rem_euclid(1_000_000_000) as u32;
    let t = UNIX_EPOCH + std::time::Duration::new(secs, nsec);
    let f = std::fs::OpenOptions::new().write(true).open(final_path)?;
    f.set_modified(t)
}

/// 平台写盘的统一入口：写临时文件 → [`commit`] 原子替换 → 恢复 mtime（可选）。
///
/// `write_part` 由调用方提供：把数据落到 `part` 路径（本函数不关心写盘细节，
/// 以便桌面 `std::fs` / Android SAF 各自实现）。这样把「写盘」留给平台，而
/// 「原子替换 + mtime 恢复」这一易错步骤集中在核心里，杜绝各端各写一套导致漂移。
///
/// `mtime_ns` 为 `Some` 时，提交后会把 final 的 mtime 恢复为发送端原始值。
pub fn write_committed<F>(
    part: &Path,
    final_path: &Path,
    mtime_ns: Option<i64>,
    write_part: F,
) -> std::io::Result<()>
where
    F: FnOnce(&Path) -> std::io::Result<()>,
{
    write_part(part)?;
    commit(part, final_path)?;
    if let Some(ns) = mtime_ns {
        restore_mtime(final_path, ns)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        // 每个测试用独立子目录，避免相互干扰
        let dir = std::env::temp_dir().join(format!("lanbak-atomic-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn part_path_is_in_same_dir_and_encodes_ids() {
        let final_path = Path::new("/backup/photos/IMG_001.jpg");
        let part = part_path(final_path, "sess_1", "file-2");
        assert_eq!(part.parent(), final_path.parent(), "临时文件必须和 final 同目录（M20）");
        let name = part.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("IMG_001.jpg.part."), "后缀格式 {name}");
        assert!(name.contains("sess_1"), "应包含 session_id");
        assert!(name.contains("file-2"), "应包含 file_id");
    }

    #[test]
    fn part_path_sanitizes_hostile_ids() {
        // 不可信 id 想穿越目录：过滤后应仍落在同目录，不出现 `..`
        let final_path = Path::new("/backup/a.txt");
        let part = part_path(final_path, "../../etc", "f/../x");
        let name = part.file_name().unwrap().to_string_lossy().into_owned();
        assert!(!name.contains(".."), "净化后不应含路径穿越字符：{name}");
        assert_eq!(part.parent(), Some(Path::new("/backup")));
    }

    #[test]
    fn commit_rename_is_atomic_and_overwrites_old() {
        let dir = tmp();
        let final_path = dir.join("final.txt");
        let part = dir.join("final.txt.part.s1.f1");
        std::fs::write(&final_path, b"OLD").unwrap();
        std::fs::write(&part, b"NEW-CONTENT").unwrap();

        commit_rename(&part, &final_path).expect("同目录 rename 应成功");

        assert_eq!(std::fs::read(&final_path).unwrap(), b"NEW-CONTENT");
        assert!(!part.exists(), "提交后临时文件应消失");
    }

    #[test]
    fn commit_rename_rejects_cross_dir() {
        let dir = tmp();
        let other = dir.join("sub");
        std::fs::create_dir_all(&other).unwrap();
        let part = dir.join("a.part.s1.f1");
        let final_path = other.join("a");
        std::fs::write(&part, b"x").unwrap();

        let r = commit_rename(&part, &final_path);
        assert!(r.is_err(), "跨目录 rename 必须被拒绝（M20）");
        assert!(part.exists(), "拒绝时不应移动任何文件");
    }

    #[test]
    fn commit_copy_delete_overwrites_and_cleans_up() {
        let dir = tmp();
        let other = dir.join("sub");
        std::fs::create_dir_all(&other).unwrap();
        let part = dir.join("a.part.s1.f1");
        let final_path = other.join("a");
        std::fs::write(&final_path, b"OLD").unwrap();
        std::fs::write(&part, b"BRAND-NEW").unwrap();

        commit_copy_delete(&part, &final_path).expect("降级提交应成功");
        assert_eq!(std::fs::read(&final_path).unwrap(), b"BRAND-NEW");
        assert!(!part.exists(), "降级提交后临时文件应被删");
    }

    #[test]
    fn choose_commit_mode_picks_rename_when_same_dir() {
        let dir = tmp();
        let part = dir.join("a.part.s1.f1");
        let final_path = dir.join("a");
        assert_eq!(choose_commit_mode(&part, &final_path), CommitMode::Rename);

        let other = dir.join("sub");
        std::fs::create_dir_all(&other).unwrap();
        let final_cross = other.join("a");
        assert_eq!(
            choose_commit_mode(&part, &final_cross),
            CommitMode::CopyDelete
        );
    }

    #[test]
    fn commit_auto_routes_by_dir() {
        let dir = tmp();
        // 同目录 → rename
        let part = dir.join("a.part.s1.f1");
        let final_same = dir.join("a");
        std::fs::write(&part, b"X").unwrap();
        commit(&part, &final_same).unwrap();
        assert_eq!(std::fs::read(&final_same).unwrap(), b"X");
        assert!(!part.exists());

        // 跨目录 → copy/delete（不报错）
        let dir2 = tmp();
        let part2 = dir2.join("b.part.s1.f1");
        let final_cross = dir2.join("sub").join("b");
        std::fs::create_dir_all(dir2.join("sub")).unwrap();
        std::fs::write(&part2, b"Y").unwrap();
        commit(&part2, &final_cross).unwrap();
        assert_eq!(std::fs::read(&final_cross).unwrap(), b"Y");
        assert!(!part2.exists());
    }

    #[test]
    fn committed_bytes_reads_part_size_or_zero() {
        let dir = tmp();
        let part = dir.join("a.part.s1.f1");
        assert_eq!(committed_bytes(&part), 0, "不存在的临时文件应报 0（从头传）");
        std::fs::write(&part, b"1234567890").unwrap(); // 10 bytes
        assert_eq!(committed_bytes(&part), 10, "应读出已落盘字节数，供字节级续传");
    }

    #[test]
    fn restore_mtime_sets_declared_timestamp() {
        let dir = tmp();
        let final_path = dir.join("f.txt");
        std::fs::write(&final_path, b"data").unwrap();
        // 2023-11-14T22:13:20Z 的纳秒时间戳
        let want_ns: i64 = 1_700_000_000_000_000_000;
        restore_mtime(&final_path, want_ns).expect("恢复 mtime 应成功");

        let got = std::fs::metadata(&final_path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        // 部分平台 mtime 精度会落到秒级，容忍 2 秒偏差
        assert!((got - want_ns).abs() <= 2_000_000_000, "mtime 应近似等于声明值（误差 {:.3}s）", (got - want_ns).abs() as f64 / 1e9);
    }

    #[test]
    fn write_committed_writes_commits_and_restores_mtime() {
        let dir = tmp();
        let final_path = dir.join("final.bin");
        let part = part_path(&final_path, "s9", "f9");
        let want_ns: i64 = 1_700_000_000_000_000_000;

        write_committed(&part, &final_path, Some(want_ns), |p| {
            std::fs::write(p, b"payload-bytes")
        })
        .expect("write_committed 应成功");

        assert_eq!(std::fs::read(&final_path).unwrap(), b"payload-bytes");
        assert!(!part.exists(), "提交后临时文件应被清理");

        let got = std::fs::metadata(&final_path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        assert!((got - want_ns).abs() <= 2_000_000_000, "提交后 mtime 应被恢复");
    }

    #[test]
    fn write_committed_can_skip_mtime_restore() {
        let dir = tmp();
        let final_path = dir.join("final2.bin");
        let part = part_path(&final_path, "s9", "f9");
        write_committed(&part, &final_path, None, |p| std::fs::write(p, b"x"))
            .expect("无 mtime 时也应成功");
        assert_eq!(std::fs::read(&final_path).unwrap(), b"x");
        assert!(!part.exists());
    }

    // ---- A18/A19 冲突处理 ----

    fn mtime_ns_of(p: &Path) -> i64 {
        std::fs::metadata(p)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64
    }

    #[test]
    fn a18_no_conflict_when_target_absent() {
        let dir = tmp();
        let final_path = dir.join("new.txt");
        assert_eq!(
            resolve_conflict(&final_path, 3, 0).unwrap(),
            ConflictOutcome::None,
            "目标不存在时应放行提交"
        );
    }

    #[test]
    fn a19_identical_existing_file_is_skipped_idempotently() {
        let dir = tmp();
        let final_path = dir.join("photo.jpg");
        std::fs::write(&final_path, b"ABC").unwrap();
        let want_ns = mtime_ns_of(&final_path);

        // size+mtime 一致 → 幂等跳过，绝不产生 `_MMDDhhmmss` 副本
        assert_eq!(
            resolve_conflict(&final_path, 3, want_ns).unwrap(),
            ConflictOutcome::Identical
        );
        assert_eq!(std::fs::read(&final_path).unwrap(), b"ABC", "原文件不动");
        let names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names.len(), 1, "不应出现冲突副本");
    }

    #[test]
    fn a18_mismatch_renames_old_file_never_overwrites() {
        let dir = tmp();
        let final_path = dir.join("photo.jpg");
        std::fs::write(&final_path, b"OLD-CONTENT").unwrap();

        // size 不一致 → 旧文件改名保留，新文件路径腾空
        let outcome = resolve_conflict(&final_path, 999, 0).unwrap();
        let ConflictOutcome::Renamed(renamed) = outcome else {
            panic!("应返回 Renamed，实际 {outcome:?}");
        };
        assert!(renamed.exists(), "旧内容必须保留在副本里");
        assert_eq!(std::fs::read(&renamed).unwrap(), b"OLD-CONTENT");
        assert!(!final_path.exists(), "目标路径应腾空供新文件提交");

        // 副本命名遵循 `原名_MMDDhhmmss.扩展名`（扩展名保留）
        let name = renamed.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("photo_"), "副本名 {name}");
        assert!(name.ends_with(".jpg"), "扩展名应保留：{name}");
        assert!(
            name.len() == "photo_".len() + 10 + ".jpg".len(),
            "时间戳应为 10 位 MMDDhhmmss：{name}"
        );
    }

    #[test]
    fn a18_extensionless_file_still_gets_stamp() {
        let dir = tmp();
        let final_path = dir.join("README");
        std::fs::write(&final_path, b"OLD").unwrap();

        let outcome = resolve_conflict(&final_path, 42, 0).unwrap();
        let ConflictOutcome::Renamed(renamed) = outcome else {
            panic!("应返回 Renamed，实际 {outcome:?}");
        };
        let name = renamed.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("README_"), "无扩展名文件也应有时间戳：{name}");
        assert_eq!(renamed.parent(), final_path.parent(), "副本与原文件同目录");
    }
}
