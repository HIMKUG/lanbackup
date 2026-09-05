//! 连接断开 / 中止时的清理清单（V4-TRANSFER-MODULE.md §六）
//!
//! # 为什么清理要有自己的模块
//!
//! 文档 §六 用一张表列了 8 个清理对象，并在表下附了一句关键约束：
//!
//! ```text
//! 清理顺序固定：先停请求 → 再释放许可 → 再清内存 → 最后删文件。
//! 反过来会在请求仍持有引用时删除文件，导致不可预期的 IO 错误。
//! ```
//!
//! 这句话如果只活在 Markdown 里，实现时必然被打散成七八处 `drop`、
//! 若干个 `if let Some(h) = handle { h.abort() }`，散落在 `Drop` impl、
//! 错误分支和 `match` 的各个 arm 上 —— 顺序就无从保证了，
//! 而顺序错误的表现（偶发 IO 错误、许可泄漏导致后续传输起不来）
//! 恰好是最难复现、最难归因的那一类。
//!
//! 所以这里把清单做成**一个有序的动作序列**：
//! 顺序由 [`CleanupPlan::actions`] 单点决定，由测试锁死，
//! 执行方只能顺序遍历、不能挑着做。
//!
//! # 这个模块不做的事
//!
//! 不执行任何真实 IO。它只回答"该做哪些事、按什么顺序"。
//! 真正的 `abort()` / `remove_file()` 由平台侧执行 —— 因为桌面端与
//! Android 的文件语义（SAF vs 路径）根本不同，混进来就没法共用了。

use std::path::{Path, PathBuf};

use crate::state::transfer::TransferState;

/// 触发清理的原因。决定"数据库会话记录里写什么"以及 UI 提示语。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupTrigger {
    /// 用户主动中止
    UserAbort,
    /// 连接断开（`connection → lost`）
    PeerLost,
    /// 不可恢复错误导致会话失败
    Failed,
    /// 会话正常完成 —— **也要清理**，见 [`CleanupPlan::for_trigger`] 的说明
    Completed,
}

impl CleanupTrigger {
    /// 写入数据库会话记录的原因（§六「数据库会话记录」行：标记 aborted 并写入原因）
    pub fn record_reason(self) -> &'static str {
        match self {
            Self::UserAbort => "USER_ABORT",
            Self::PeerLost => "PEER_LOST",
            Self::Failed => "UNRECOVERABLE_ERROR",
            Self::Completed => "COMPLETED",
        }
    }

    /// 给用户看的中止原因（§六「UI」行：清空进度条，显示中止原因）
    pub fn text(self) -> &'static str {
        match self {
            Self::UserAbort => "已取消传输",
            Self::PeerLost => "与对端的连接已断开",
            Self::Failed => "传输失败，请查看日志",
            Self::Completed => "传输完成",
        }
    }

    /// 是否是异常收场。决定要不要把未确认任务标记 `cancelled`。
    pub fn is_abnormal(self) -> bool {
        !matches!(self, Self::Completed)
    }
}

/// 一个清理动作。**顺序有意义**，见模块文档。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupAction {
    /// 1. 取消所有在途块请求的 future，关闭上传流
    CancelInflightRequests,
    /// 2. 归还全局 + 每 peer 的 Semaphore 许可
    ///
    /// 本仓库里许可是 RAII（[`crate::transfer::schedule::ChunkPermit`]），
    /// drop 即归还，所以这一步实际是"drop 掉持有许可的那些任务句柄"。
    /// 清单里仍显式列出，是因为**一旦有人改成手工 acquire/release，
    /// 这一步就必须真的做** —— 许可泄漏的症状是"下次传输永远卡在 0%"，
    /// 与本次断开毫无表面关联，排查代价极高。
    ReleaseSemaphorePermits,
    /// 3. 停止心跳 interval 并 drop
    StopHeartbeat,
    /// 4. 清除内存态：FileTransferState / PeerSession / 权威块位图
    ClearMemoryState,
    /// 5. 删除 `__chunked__/` 下的部分块文件
    ///
    /// **必须排在取消请求之后** —— 否则仍持有文件引用的在途写入会撞上删除。
    DeletePartialChunkFiles,
    /// 6. 数据库会话记录标记原因，**不删除**（便于排查）
    MarkSessionRecord { reason: &'static str },
    /// 7. 未确认的任务一律标记 `cancelled`，不猜测成败
    MarkUnconfirmedTasksCancelled,
    /// 8. UI：清空进度条并显示原因
    ClearUiProgress { text: &'static str },
}

impl CleanupAction {
    /// 该动作是否触碰文件系统。用于断言"文件操作一定排在请求取消之后"。
    #[cfg(test)]
    fn touches_files(&self) -> bool {
        matches!(self, Self::DeletePartialChunkFiles)
    }

    /// 该动作是否会释放在途请求持有的资源
    #[cfg(test)]
    fn releases_inflight(&self) -> bool {
        matches!(
            self,
            Self::CancelInflightRequests | Self::ReleaseSemaphorePermits
        )
    }
}

/// 一次清理的完整计划
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupPlan {
    pub trigger: CleanupTrigger,
    /// 清理发生时所处的传输状态（日志用）
    pub from_state: TransferState,
    actions: Vec<CleanupAction>,
}

impl CleanupPlan {
    /// 按 §六 的固定顺序生成清理计划。
    ///
    /// # 为什么 `Completed` 也要清理
    ///
    /// 直觉上"传完了就没什么要清的"。但 §六 那张表里除了「标记 aborted」
    /// 一行，其余每一行在成功路径上同样成立：在途请求要收尾、许可要归还、
    /// 心跳要停、临时分块文件要删。旧实现只在失败路径挂了清理，
    /// 结果连续传若干个大文件后许可被慢慢吃光 —— 表现为"传了几个之后就卡住"。
    ///
    /// 所以这里对成功路径也返回完整清单，只是：
    /// - 数据库记录原因写 `COMPLETED` 而不是中止原因
    /// - 不做「未确认任务标记 cancelled」（成功路径上没有未确认任务，
    ///   若真有，那是 bug，应该让校验阶段拦住，而不是在这里悄悄改成 cancelled）
    pub fn for_trigger(trigger: CleanupTrigger, from_state: TransferState) -> Self {
        let mut actions = vec![
            // ---- 先停请求 ----
            CleanupAction::CancelInflightRequests,
            // ---- 再释放许可 ----
            CleanupAction::ReleaseSemaphorePermits,
            CleanupAction::StopHeartbeat,
            // ---- 再清内存 ----
            CleanupAction::ClearMemoryState,
            // ---- 最后删文件 ----
            CleanupAction::DeletePartialChunkFiles,
            // ---- 记录与呈现（不涉及资源，放最后）----
            CleanupAction::MarkSessionRecord {
                reason: trigger.record_reason(),
            },
        ];
        if trigger.is_abnormal() {
            actions.push(CleanupAction::MarkUnconfirmedTasksCancelled);
        }
        actions.push(CleanupAction::ClearUiProgress {
            text: trigger.text(),
        });
        Self {
            trigger,
            from_state,
            actions,
        }
    }

    /// 按序遍历清理动作。**不提供索引访问**，避免调用方挑着做。
    pub fn actions(&self) -> impl Iterator<Item = &CleanupAction> {
        self.actions.iter()
    }

    pub fn len(&self) -> usize {
        self.actions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

// ============================================================
// P36：崩溃残留（.tmp_* / .dec_tmp）判定与清理
// ============================================================

/// P36：文件名是否属于崩溃残留。
///
/// 两类残留都只在崩溃 / 强杀时出现，正常流程会在提交后删掉它们：
/// - `.tmp_*` —— 原子写入的临时文件（写一半崩溃）；
/// - `*.dec_tmp` —— 解密中间文件（扫描器刻意排除该扩展名，用户不可见
///   → 若不清，是**隐形泄漏**，占着磁盘却永远不被扫到）。
///
/// 启动时应清一次（桌面用 [`sweep_residue`]；Android SAF 用同一判定 +
/// `DocumentFile` 删除，名字判据必须一致，否则两端行为漂移）。
pub fn is_residue_name(name: &str) -> bool {
    name.starts_with(".tmp_") || name.ends_with(".dec_tmp")
}

/// 递归删除 `root` 下所有崩溃残留文件（P36），返回已删除的路径列表。
///
/// 清理是**尽力而为**：残留文件不影响正确性，只是隐形占用；
/// 单个文件的删除失败只跳过它（下次启动再清），不让整个清理因一个
/// 锁定的文件而中断。目录本身不删，只删匹配 [`is_residue_name`] 的文件。
pub fn sweep_residue(root: &Path) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    sweep_into(root, &mut removed);
    removed
}

fn sweep_into(dir: &Path, removed: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_dir() {
            sweep_into(&path, removed);
        } else if ft.is_file() {
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if is_residue_name(name) && std::fs::remove_file(&path).is_ok() {
                    removed.push(path);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_are_deleted_only_after_inflight_requests_are_released() {
        // §六 的那句约束：先停请求 → 再释放许可 → 再清内存 → 最后删文件。
        // 这里验的是它的**因果核心**：任何触碰文件的动作，都必须排在
        // 全部"释放在途资源"的动作之后。
        for trigger in [
            CleanupTrigger::UserAbort,
            CleanupTrigger::PeerLost,
            CleanupTrigger::Failed,
            CleanupTrigger::Completed,
        ] {
            let plan = CleanupPlan::for_trigger(trigger, TransferState::Transferring);
            let acts: Vec<_> = plan.actions().collect();
            let last_release = acts
                .iter()
                .rposition(|a| a.releases_inflight())
                .expect("必须有释放在途资源的步骤");
            let first_file = acts
                .iter()
                .position(|a| a.touches_files())
                .expect("必须有删除临时文件的步骤");
            assert!(
                first_file > last_release,
                "{trigger:?}：删文件（idx {first_file}）排在了释放在途资源（idx {last_release}）之前，\
                 会在请求仍持有引用时删除文件"
            );
        }
    }

    #[test]
    fn order_is_exactly_the_documented_one() {
        let plan = CleanupPlan::for_trigger(CleanupTrigger::PeerLost, TransferState::Transferring);
        let acts: Vec<_> = plan.actions().cloned().collect();
        assert_eq!(
            acts,
            vec![
                CleanupAction::CancelInflightRequests,
                CleanupAction::ReleaseSemaphorePermits,
                CleanupAction::StopHeartbeat,
                CleanupAction::ClearMemoryState,
                CleanupAction::DeletePartialChunkFiles,
                CleanupAction::MarkSessionRecord {
                    reason: "PEER_LOST"
                },
                CleanupAction::MarkUnconfirmedTasksCancelled,
                CleanupAction::ClearUiProgress {
                    text: "与对端的连接已断开"
                },
            ]
        );
    }

    #[test]
    fn success_path_still_cleans_resources() {
        // 旧实现只在失败路径清理，导致连传多个大文件后许可被吃光。
        let plan = CleanupPlan::for_trigger(CleanupTrigger::Completed, TransferState::Completed);
        let acts: Vec<_> = plan.actions().cloned().collect();
        for must in [
            CleanupAction::CancelInflightRequests,
            CleanupAction::ReleaseSemaphorePermits,
            CleanupAction::StopHeartbeat,
            CleanupAction::ClearMemoryState,
            CleanupAction::DeletePartialChunkFiles,
        ] {
            assert!(acts.contains(&must), "成功路径也必须执行 {must:?}");
        }
    }

    #[test]
    fn success_path_does_not_mass_cancel_tasks() {
        // 成功路径上若还有未确认任务，那是 bug，应由校验阶段拦下，
        // 不该在清理里悄悄改成 cancelled 把证据抹掉。
        let plan = CleanupPlan::for_trigger(CleanupTrigger::Completed, TransferState::Completed);
        assert!(!plan
            .actions()
            .any(|a| matches!(a, CleanupAction::MarkUnconfirmedTasksCancelled)));
        // 异常路径必须有
        for trigger in [
            CleanupTrigger::UserAbort,
            CleanupTrigger::PeerLost,
            CleanupTrigger::Failed,
        ] {
            let plan = CleanupPlan::for_trigger(trigger, TransferState::Transferring);
            assert!(
                plan.actions()
                    .any(|a| matches!(a, CleanupAction::MarkUnconfirmedTasksCancelled)),
                "{trigger:?} 必须标记未确认任务为 cancelled"
            );
        }
    }

    #[test]
    fn session_record_is_never_deleted_only_marked() {
        // §六 明确「不删除（便于排查）」。清单里只能出现"标记"，
        // 不允许出现任何删除会话记录的动作 —— 这条测试是给未来的人看的：
        // 如果你想加 DeleteSessionRecord，先来改这条断言，顺便读一下 §六。
        for trigger in [
            CleanupTrigger::UserAbort,
            CleanupTrigger::PeerLost,
            CleanupTrigger::Failed,
            CleanupTrigger::Completed,
        ] {
            let plan = CleanupPlan::for_trigger(trigger, TransferState::Transferring);
            let marks = plan
                .actions()
                .filter(|a| matches!(a, CleanupAction::MarkSessionRecord { .. }))
                .count();
            assert_eq!(marks, 1, "{trigger:?} 应恰好标记一次会话记录");
        }
    }

    #[test]
    fn reason_codes_and_texts_are_distinct_per_trigger() {
        // 原因码若重复，日志里就分不清"用户取消"和"对端断线"——
        // 这两者的后续处理完全不同（一个不该重试，一个该自动重连）。
        let triggers = [
            CleanupTrigger::UserAbort,
            CleanupTrigger::PeerLost,
            CleanupTrigger::Failed,
            CleanupTrigger::Completed,
        ];
        let mut codes: Vec<&str> = triggers.iter().map(|t| t.record_reason()).collect();
        codes.sort_unstable();
        let n = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), n, "清理原因码不得重复");

        let mut texts: Vec<&str> = triggers.iter().map(|t| t.text()).collect();
        texts.sort_unstable();
        let n = texts.len();
        texts.dedup();
        assert_eq!(texts.len(), n, "清理提示文案不得重复");
    }

    #[test]
    fn only_completed_is_normal() {
        assert!(!CleanupTrigger::Completed.is_abnormal());
        for t in [
            CleanupTrigger::UserAbort,
            CleanupTrigger::PeerLost,
            CleanupTrigger::Failed,
        ] {
            assert!(t.is_abnormal(), "{t:?} 应视为异常收场");
        }
    }

    // ── P36 崩溃残留 ────────────────────────────────────────

    #[test]
    fn tmp_and_dec_tmp_residues_are_detected() {
        for name in [
            ".tmp_1234",
            ".tmp_x.part",
            "photo.jpg.dec_tmp",
            "a.dec_tmp",
        ] {
            assert!(is_residue_name(name), "{name:?} 应判为残留");
        }
        // 正常文件绝不误判
        for name in [
            "photo.jpg",
            "a.txt",
            ".tmp",
            "dec_tmp",
            ".dec_tmp_backup",
            "keep.dec_tmp.bak",
        ] {
            assert!(!is_residue_name(name), "{name:?} 不是残留，误判会删正常文件");
        }
    }

    /// P36：递归清理只删残留、不动正常文件，并如实报告删了什么。
    #[test]
    fn sweep_residue_removes_only_crash_leftovers() {
        let dir = std::env::temp_dir().join(format!("lanbak-p36-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("sub/deep")).unwrap();

        let keep1 = dir.join("photo.jpg");
        let keep2 = dir.join("sub/normal.txt");
        let residue1 = dir.join(".tmp_abc");
        let residue2 = dir.join("sub/deep/photo.jpg.dec_tmp");
        std::fs::write(&keep1, b"1").unwrap();
        std::fs::write(&keep2, b"2").unwrap();
        std::fs::write(&residue1, b"3").unwrap();
        std::fs::write(&residue2, b"4").unwrap();

        let removed = sweep_residue(&dir);
        assert_eq!(removed.len(), 2, "应恰好删掉两个残留：{removed:?}");
        assert!(removed.iter().any(|p| p == &residue1));
        assert!(removed.iter().any(|p| p == &residue2));
        assert!(keep1.exists() && keep2.exists(), "正常文件被误删");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P36：目录不存在时清理安静返回，不让启动流程因清理报错。
    #[test]
    fn sweep_residue_on_missing_dir_is_quiet() {
        let ghost = std::env::temp_dir().join("lanbak-p36-ghost-uuid-never-exists");
        assert!(sweep_residue(&ghost).is_empty());
    }
}
