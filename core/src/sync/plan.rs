//! 三路增量对比（阶段 4）
//!
//! # 三路是哪三路
//!
//! | 输入 | 含义 | 缺了它会怎样 |
//! |---|---|---|
//! | A 当前 | 本机现在有什么 | —— |
//! | A 上次快照 | 上次**成功**同步后本机有什么 | 无法区分「本机新增」与「对端删除」 |
//! | B 当前 | 对端现在有什么 | 无法发现残留与对端多余 |
//!
//! 两路对比（只比 A 当前与 B 当前）看起来够用，实际上永远答不了一个问题：
//! 对端少了一个文件，是**我新加的还没传**，还是**我传过了但对端删了**？
//! 前者要传，后者要看用户意图。第三路快照就是为了回答它。
//!
//! # 六个输出集合（互不重叠地驱动不同动作）
//!
//! | 集合 | 定义 | archive | mirror |
//! |---|---|---|---|
//! | `added` | A 有、快照无、B 无 | 上传 | 上传 |
//! | `changed` | A 与快照的 size/mtime 不一致 | 上传 | 上传 |
//! | `residual` | A、B 都有但 **size 不一致** | 上传（修残） | 上传（修残） |
//! | `heal_missing` | A 有、快照有、B 无、**且 B 无墓碑** | 上传（自愈） | 上传（自愈） |
//! | `absent_on_peer` | A 有、B 无（全集，含墓碑） | 仅告警 | 仅告警 |
//! | `peer_extra` | B 有、A 无、且不在 `delete/` 下 | 空 | 移入 `delete/` |
//!
//! # `residual` 为什么必须单列
//!
//! 只按「存在与否」判断，上次传输中断留下的半截文件**永远不会被修复**：
//! 它存在，于是被跳过；它损坏，于是永远损坏（原 `sync.ts:97-100`）。
//!
//! # 墓碑：调和「自愈」与「不复活」
//!
//! `archive` 的语义是「删除是用户的有意行为，只告警不复活」，
//! 而自愈的语义是「传丢了要补回」。两者看似矛盾，区别在于**谁删的**：
//!
//! - 用户在 B 上有意删除 → 走 `moveToDelete`，文件落在 `delete/<path>`（墓碑）
//!   → 判为 `absent_on_peer`，**只告警**。
//! - 传输中断 / 对端存储损坏 / 误删且未走假删除 → 无墓碑
//!   → 判为 `heal_missing`，**补传**。
//!
//! 于是「不复活用户删掉的东西」与「传丢了要补」可以同时成立，
//! 判据是既有的 `delete/` 机制，不需要新增协议字段。

use std::collections::BTreeSet;

use crate::dto::sync::{Manifest, ManifestEntry, SyncPlan, SyncStrategy};
use crate::sync::manifest::{
    is_in_delete_dir, is_safe_rel_path, normalize_manifest, tombstone_path,
};

/// mtime 比较容差（毫秒）。
///
/// **不能用严格相等**：FAT/exFAT 的 mtime 粒度是 2 秒，Android SAF 的复制会
/// 四舍五入，网络传输后重设 mtime 也有毫秒级误差。严格相等会让每一轮同步都
/// 把全部文件判成 `changed` —— 表现为「无限全量重传」，而 size 明明一样。
///
/// 取 2000ms = FAT 的粒度上限。**size 不一致时不看容差**，直接算变更。
pub const MTIME_TOLERANCE_MS: i64 = 2000;

/// 单条条目是否发生了实质变更（相对上次快照）
pub fn entry_changed(now: &ManifestEntry, snapshot: &ManifestEntry) -> bool {
    now.size != snapshot.size || (now.mtime - snapshot.mtime).abs() > MTIME_TOLERANCE_MS
}

/// 一次同步的完整决策：既有面向 UI 的分类（`plan`），也有可直接执行的动作列表。
///
/// 分类与动作分开，是为了让 UI 展示与执行逻辑各取所需，
/// 而不是让执行侧自己再从六个集合里推一遍（推错就是漏传或多删）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncDecision {
    /// 面向 UI / 协议的分类结果
    pub plan: SyncPlan,
    /// 需要上传的相对路径（已去重、已排序）
    pub uploads: Vec<String>,
    /// 需要请对端移入 `delete/` 的路径（仅 mirror；archive 恒为空）
    pub move_to_delete: Vec<String>,
    /// 对端已移入 `delete/`（用户有意删除）→ 只告警，不补传
    pub tombstoned: Vec<String>,
    /// 因路径不安全（`..`、盘符）被拒的条目 —— 应向用户显式报告，不可静默丢弃
    pub rejected_unsafe: Vec<String>,
    /// 生效的策略（回传便于 UI 显示与日志排查）
    pub strategy: SyncStrategy,
}

impl SyncDecision {
    /// 是否无事可做（用于「已是最新」的提示，避免弹出空任务）
    pub fn is_noop(&self) -> bool {
        self.uploads.is_empty() && self.move_to_delete.is_empty()
    }
}

/// 三路对比，输出可执行决策。
///
/// `local_snapshot` 为 `None` 表示首次同步：此时无法判定 `changed`，
/// 也无法判定「曾备份过」，全部对端缺失一律按 `added` 处理。这是正确的降级
/// —— 首次同步本就该把 A 的内容推上去。
///
/// 所有输出集合均**按字典序排序**。清单是 `HashMap`，迭代顺序随机；
/// 不排序会让同一份输入产出不同顺序的计划，导致 UI 列表乱跳、测试随机失败、
/// 日志无法对比。确定性不是锦上添花，是可排查性的前提。
pub fn decide(
    local_now: &Manifest,
    local_snapshot: Option<&Manifest>,
    peer_now: &Manifest,
    strategy: SyncStrategy,
) -> SyncDecision {
    let local = normalize_manifest(local_now);
    let peer = normalize_manifest(peer_now);
    let snapshot = local_snapshot.map(normalize_manifest);

    let mut added = BTreeSet::new();
    let mut changed = BTreeSet::new();
    let mut residual = BTreeSet::new();
    let mut heal = BTreeSet::new();
    let mut absent = BTreeSet::new();
    let mut tombstoned = BTreeSet::new();
    let mut rejected = BTreeSet::new();

    for (path, entry) in &local.files {
        if !is_safe_rel_path(path) {
            rejected.insert(path.clone());
            continue;
        }
        // 本机自己的 delete/ 目录不参与同步：它是本地的回收站，不是备份内容。
        if is_in_delete_dir(path) {
            continue;
        }

        let snap_entry = snapshot.as_ref().and_then(|s| s.files.get(path));

        match peer.files.get(path) {
            Some(peer_entry) => {
                if peer_entry.size != entry.size {
                    // 对端有、但大小不符 = 残留 / 损坏 / 上次传了一半
                    residual.insert(path.clone());
                } else if snap_entry.is_some_and(|s| entry_changed(entry, s)) {
                    // 大小相同但本机改过（原地编辑）→ 仍需重传
                    changed.insert(path.clone());
                }
            }
            None => {
                absent.insert(path.clone());
                let has_tombstone = peer.files.contains_key(&tombstone_path(path));
                if has_tombstone {
                    // 用户在对端有意删除 → 尊重，不复活
                    tombstoned.insert(path.clone());
                } else if snap_entry.is_some() {
                    // 曾成功备份过、对端却没有、也没有墓碑 → 传丢了，自愈
                    heal.insert(path.clone());
                } else {
                    added.insert(path.clone());
                }
            }
        }
    }

    // 对端多余：仅 mirror 关心。archive 只增不删，恒为空。
    let mut peer_extra = BTreeSet::new();
    if strategy == SyncStrategy::Mirror {
        for path in peer.files.keys() {
            if local.files.contains_key(path) {
                continue;
            }
            // 已移入 delete/ 的不算多余 —— 否则镜像模式会无限弹确认框
            if is_in_delete_dir(path) {
                continue;
            }
            if !is_safe_rel_path(path) {
                rejected.insert(path.clone());
                continue;
            }
            peer_extra.insert(path.clone());
        }
    }

    let uploads: BTreeSet<String> = added
        .iter()
        .chain(changed.iter())
        .chain(residual.iter())
        .chain(heal.iter())
        .cloned()
        .collect();

    SyncDecision {
        plan: SyncPlan {
            added: added.into_iter().collect(),
            changed: changed.into_iter().collect(),
            residual: residual.into_iter().collect(),
            heal_missing: heal.into_iter().collect(),
            absent_on_peer: absent.into_iter().collect(),
            peer_extra: peer_extra.iter().cloned().collect(),
        },
        uploads: uploads.into_iter().collect(),
        move_to_delete: peer_extra.into_iter().collect(),
        tombstoned: tombstoned.into_iter().collect(),
        rejected_unsafe: rejected.into_iter().collect(),
        strategy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn manifest(files: &[(&str, u64, i64)]) -> Manifest {
        Manifest {
            files: files
                .iter()
                .map(|(p, size, mtime)| {
                    (
                        (*p).to_string(),
                        ManifestEntry {
                            size: *size,
                            mtime: *mtime,
                        },
                    )
                })
                .collect::<HashMap<_, _>>(),
            ..Default::default()
        }
    }

    fn empty() -> Manifest {
        Manifest::default()
    }

    #[test]
    fn first_sync_pushes_everything_as_added() {
        let a = manifest(&[("x.txt", 10, 1000), ("d/y.txt", 20, 1000)]);
        let d = decide(&a, None, &empty(), SyncStrategy::Archive);
        assert_eq!(d.plan.added, vec!["d/y.txt", "x.txt"], "必须按字典序");
        assert_eq!(d.uploads, vec!["d/y.txt", "x.txt"]);
        assert!(d.plan.changed.is_empty());
        assert!(d.plan.heal_missing.is_empty());
        assert!(!d.is_noop());
    }

    #[test]
    fn unchanged_files_are_skipped() {
        let a = manifest(&[("x.txt", 10, 1000)]);
        let d = decide(&a, Some(&a), &a, SyncStrategy::Archive);
        assert!(d.uploads.is_empty(), "已一致却仍要传：{:?}", d.uploads);
        assert!(d.is_noop());
    }

    /// 残留必须被单列并重传 —— 否则上次中断留下的半截文件永远修不好。
    #[test]
    fn size_mismatch_on_peer_is_residual() {
        let a = manifest(&[("big.bin", 1000, 500)]);
        let b = manifest(&[("big.bin", 400, 500)]); // 只传到 400 字节就断了
        let d = decide(&a, Some(&a), &b, SyncStrategy::Archive);
        assert_eq!(d.plan.residual, vec!["big.bin"]);
        assert_eq!(d.uploads, vec!["big.bin"]);
        assert!(d.plan.added.is_empty());
        assert!(d.plan.changed.is_empty());
    }

    #[test]
    fn local_edit_with_same_size_is_changed() {
        let snap = manifest(&[("note.txt", 10, 1_000_000)]);
        let now = manifest(&[("note.txt", 10, 1_000_000 + 60_000)]); // 原地改，大小巧合相同
        let peer = manifest(&[("note.txt", 10, 1_000_000)]);
        let d = decide(&now, Some(&snap), &peer, SyncStrategy::Archive);
        assert_eq!(d.plan.changed, vec!["note.txt"]);
        assert_eq!(d.uploads, vec!["note.txt"]);
    }

    /// FAT 2 秒粒度 / SAF 四舍五入不得被当成变更，否则无限全量重传。
    #[test]
    fn mtime_within_tolerance_is_not_a_change() {
        let snap = manifest(&[("a.txt", 10, 1_000_000)]);
        let now = manifest(&[("a.txt", 10, 1_000_000 + MTIME_TOLERANCE_MS)]);
        let peer = manifest(&[("a.txt", 10, 1_000_000)]);
        let d = decide(&now, Some(&snap), &peer, SyncStrategy::Archive);
        assert!(d.uploads.is_empty(), "容差内的 mtime 抖动被误判为变更");

        // 刚好越界就必须算变更
        let now2 = manifest(&[("a.txt", 10, 1_000_000 + MTIME_TOLERANCE_MS + 1)]);
        let d2 = decide(&now2, Some(&snap), &peer, SyncStrategy::Archive);
        assert_eq!(d2.plan.changed, vec!["a.txt"]);
    }

    #[test]
    fn size_difference_ignores_mtime_tolerance() {
        let snap = manifest(&[("a.txt", 10, 1_000_000)]);
        let now = manifest(&[("a.txt", 11, 1_000_000)]); // mtime 没动，size 变了
        let peer = manifest(&[("a.txt", 11, 1_000_000)]);
        let d = decide(&now, Some(&snap), &peer, SyncStrategy::Archive);
        assert_eq!(d.plan.changed, vec!["a.txt"]);
    }

    /// 曾备份过、对端没有、也没墓碑 → 自愈补传。
    #[test]
    fn previously_backed_up_and_vanished_is_healed() {
        let a = manifest(&[("photo.jpg", 100, 500)]);
        let d = decide(&a, Some(&a), &empty(), SyncStrategy::Archive);
        assert_eq!(d.plan.heal_missing, vec!["photo.jpg"]);
        assert_eq!(d.plan.absent_on_peer, vec!["photo.jpg"]);
        assert_eq!(d.uploads, vec!["photo.jpg"]);
        assert!(d.plan.added.is_empty(), "曾备份过的不该算新增");
    }

    /// 对端有墓碑 = 用户有意删除 → 只告警，绝不复活。
    /// 「备份工具若复活用户手动删掉的文件，用户就永远删不掉东西了」。
    #[test]
    fn tombstoned_file_is_not_resurrected() {
        let a = manifest(&[("photo.jpg", 100, 500)]);
        let peer = manifest(&[("delete/photo.jpg", 100, 500)]);
        let d = decide(&a, Some(&a), &peer, SyncStrategy::Archive);
        assert_eq!(d.tombstoned, vec!["photo.jpg"]);
        assert_eq!(d.plan.absent_on_peer, vec!["photo.jpg"], "仍应告警");
        assert!(
            d.plan.heal_missing.is_empty(),
            "有墓碑却仍自愈 = 复活了用户删的文件"
        );
        assert!(d.uploads.is_empty());
        assert!(d.is_noop());
    }

    #[test]
    fn archive_never_deletes_on_peer() {
        let a = manifest(&[("keep.txt", 1, 1)]);
        let peer = manifest(&[("keep.txt", 1, 1), ("peer-only.txt", 5, 5)]);
        let d = decide(&a, Some(&a), &peer, SyncStrategy::Archive);
        assert!(d.plan.peer_extra.is_empty(), "archive 只增不删");
        assert!(d.move_to_delete.is_empty());
    }

    #[test]
    fn mirror_moves_peer_extra_to_delete() {
        let a = manifest(&[("keep.txt", 1, 1)]);
        let peer = manifest(&[("keep.txt", 1, 1), ("peer-only.txt", 5, 5)]);
        let d = decide(&a, Some(&a), &peer, SyncStrategy::Mirror);
        assert_eq!(d.plan.peer_extra, vec!["peer-only.txt"]);
        assert_eq!(d.move_to_delete, vec!["peer-only.txt"]);
    }

    /// 实测问题 5：`delete/` 下的文件被算作"对端多余"→ 镜像模式无限弹确认框。
    #[test]
    fn mirror_does_not_loop_on_already_deleted_files() {
        let a = manifest(&[("keep.txt", 1, 1)]);
        let peer = manifest(&[
            ("keep.txt", 1, 1),
            ("delete/gone.txt", 9, 9),
            (r"delete\also-gone.txt", 9, 9), // Java 侧可能给反斜杠
        ]);
        let d = decide(&a, Some(&a), &peer, SyncStrategy::Mirror);
        assert!(
            d.move_to_delete.is_empty(),
            "delete/ 下的文件被再次要求删除，会无限弹框：{:?}",
            d.move_to_delete
        );
        assert!(d.is_noop());
    }

    #[test]
    fn paths_are_normalized_before_comparison() {
        // 两端写法不同但指同一文件，不得判为「新增 + 多余」
        let a = manifest(&[(r".\photos\a.jpg", 100, 500)]);
        let peer = manifest(&[("photos/a.jpg", 100, 500)]);
        let d = decide(&a, Some(&a), &peer, SyncStrategy::Mirror);
        assert!(d.uploads.is_empty(), "归一化失效：{:?}", d.uploads);
        assert!(
            d.move_to_delete.is_empty(),
            "归一化失效：{:?}",
            d.move_to_delete
        );
    }

    #[test]
    fn unsafe_paths_are_reported_not_silently_dropped() {
        let a = manifest(&[("../escape.txt", 1, 1), ("ok.txt", 1, 1)]);
        let d = decide(&a, None, &empty(), SyncStrategy::Archive);
        assert_eq!(d.rejected_unsafe, vec!["../escape.txt"]);
        assert_eq!(d.uploads, vec!["ok.txt"], "不安全条目不得进入上传集合");
    }

    #[test]
    fn peer_side_unsafe_extra_is_rejected_not_deleted() {
        let a = manifest(&[("ok.txt", 1, 1)]);
        let peer = manifest(&[("ok.txt", 1, 1), ("../../evil", 1, 1)]);
        let d = decide(&a, Some(&a), &peer, SyncStrategy::Mirror);
        assert!(
            d.move_to_delete.is_empty(),
            "绝不能对不安全路径发起删除动作 —— 那等于让对端在备份根之外操作文件"
        );
        assert_eq!(d.rejected_unsafe, vec!["../../evil"]);
    }

    #[test]
    fn local_delete_dir_is_not_synced() {
        let a = manifest(&[("delete/trash.txt", 1, 1), ("ok.txt", 1, 1)]);
        let d = decide(&a, None, &empty(), SyncStrategy::Archive);
        assert_eq!(
            d.uploads,
            vec!["ok.txt"],
            "本机回收站不该被当成备份内容上传"
        );
    }

    #[test]
    fn all_output_sets_are_sorted_and_deduped() {
        let a = manifest(&[("c", 1, 1), ("a", 1, 1), ("b", 1, 1), ("./a", 1, 1)]);
        let d = decide(&a, None, &empty(), SyncStrategy::Archive);
        assert_eq!(d.plan.added, vec!["a", "b", "c"]);
        assert_eq!(d.uploads, vec!["a", "b", "c"]);
    }

    /// archive 与 mirror 的**唯一**区别是删除动作；上传集合必须一致。
    /// 这条锁住策略语义，防止后来者「顺手」让 mirror 多传或少传。
    #[test]
    fn strategies_differ_only_in_deletion() {
        let snap = manifest(&[("kept.txt", 5, 100)]);
        let now = manifest(&[("kept.txt", 5, 100), ("new.txt", 1, 200)]);
        let peer = manifest(&[("stale.txt", 3, 50)]);
        let arch = decide(&now, Some(&snap), &peer, SyncStrategy::Archive);
        let mirr = decide(&now, Some(&snap), &peer, SyncStrategy::Mirror);
        assert_eq!(arch.uploads, mirr.uploads);
        assert!(arch.move_to_delete.is_empty());
        assert_eq!(mirr.move_to_delete, vec!["stale.txt"]);
    }

    #[test]
    fn strategy_is_echoed_for_ui_and_logs() {
        let d = decide(&empty(), None, &empty(), SyncStrategy::Mirror);
        assert_eq!(d.strategy, SyncStrategy::Mirror);
        assert!(d.is_noop());
    }
}
