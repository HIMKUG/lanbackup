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
}
