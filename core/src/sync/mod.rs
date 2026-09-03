//! 目录同步：清单、三路增量、假删除（阶段 4）
//!
//! 全模块**纯计算**，不触碰文件系统、不触网。
//! 扫描目录、读写文件、发起 HTTP 全部由调用方完成，本模块只回答一个问题：
//! **给定两端的清单和上次快照，该传哪些、该删哪些。**
//!
//! 这样切分的收益是可测性：三路增量是整个产品最容易出静默错误的地方
//! （少传一个文件用户不会立刻发现，多删一个文件用户会立刻发现但已经晚了），
//! 而纯函数可以用几十组清单组合穷举验证。
//!
//! | 子模块 | 职责 |
//! |---|---|
//! | [`manifest`] | 路径归一化、路径安全（拒绝 `..`）、墓碑路径、清单构建 |
//! | [`plan`] | 三路对比 → [`plan::SyncDecision`]（分类 + 可执行动作） |
//!
//! # 判据是 mtime + size，不是内容哈希
//!
//! 刻意的取舍：手机端 CPU 弱，相册几万文件算内容哈希会把扫描从秒级拖到分钟级
//! （原 `sync.ts:5`）。已知代价是「同 path 同 size 但内容损坏」检不出来 ——
//! 这一层由传输阶段的 Merkle 强校验兜底（[`crate::crypto::merkle`]），
//! 两层职责不重叠：清单负责**选出候选**，传输负责**保证正确**。

pub mod manifest;
pub mod plan;

pub use manifest::{
    build_manifest, is_in_delete_dir, is_safe_rel_path, normalize_manifest, normalize_rel_path,
    tombstone_path, DELETE_DIR,
};
pub use plan::{decide, entry_changed, SyncDecision, MTIME_TOLERANCE_MS};
