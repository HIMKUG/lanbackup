//! 分块计划与降级换算 —— V4 传输的核心引擎
//!
//! **两套算法共用同一份字节流，只是粒度不同**：
//! - 主算法（Advanced）：`PIECE_SIZE` = 4 MiB 的 piece，内容寻址、Merkle、
//!   并发、断点续传。
//! - 基础算法（Basic）：`BASIC_CHUNK_SIZE` = 16 MiB 的块，顺序传输、简单续传。
//!
//! 关键不变量（来自 V4-TRANSFER-MODULE.md §4.2，也是 DESIGN-WISDOM-REGISTER
//! 的 C10「分块常量单一来源」）：
//!
//! ```text
//! BASIC_CHUNK_SIZE 必须是 PIECE_SIZE 的整数倍
//! ```
//!
//! 为什么强制？降级发生在「传输中断且重试无效」时。此时主算法视角下已有
//! 若干 piece 被对端确认。若 16 MiB 不是 4 MiB 的整数倍，一个基础块边界
//! 会劈开某个 piece —— 该块既不能算「完整」（含未确认的半截 piece），又
//! 不能干净地续传，于是**降级等于丢弃全部进度、从头再来**。那降级本身就是
//! 灾难。
//!
//! 对齐后：基础块 `b` 完整 ⟺ 其涵盖的 `PIECES_PER_BLOCK` 个 piece 全部被确认。
//! 已完成的连续 piece 直接换算为已完成的基础块，**只有落在最后一个不完整
//! 块内的部分需要重传**。

use crate::dto::session::Algorithm;

// 分块常量**只在 `crate::version` 定义一处**，此处仅重导出。
//
// 这不是洁癖。本模块开头引的 C10 就是「四处并存 4MB/8MB/16MB」那次事故，
// 而此前 chunk.rs 自己又写了一遍 `PIECE_SIZE = 4MiB` / `BASIC_CHUNK_SIZE = 16MiB`，
// 与 version.rs 的定义**数值上恰好相等**——纯属运气。
// 只要有人调 version.rs 里的 BASIC_CHUNK_SIZE（那里写成 `4 * PIECE_SIZE`，
// 看起来就是"可以调的"），对齐不变式在 chunk.rs 这边毫无察觉，
// 编译期断言也拦不住——因为它守的是 chunk.rs 那份副本。

/// 主算法分块单位（piece）。所有续传 / 差异 / 并发以 piece 为最小粒度。
pub use crate::version::PIECE_SIZE;

/// 基础算法块大小。见模块文档的不变式说明。
pub use crate::version::BASIC_CHUNK_SIZE;

/// 一个基础块涵盖多少个主算法 piece。由对齐不变式保证为整数。
///
/// `version::BASIC_CHUNK_PIECES` 的别名，保留本模块的命名习惯。
pub use crate::version::BASIC_CHUNK_PIECES as PIECES_PER_BLOCK;

// 编译期断言：对齐不变式不能被破坏（破坏则降级会丢失进度）。
// 现在守的是**唯一那份**定义。
const _: () = assert!(
    BASIC_CHUNK_SIZE.is_multiple_of(PIECE_SIZE),
    "BASIC_CHUNK_SIZE 必须是 PIECE_SIZE 的整数倍，否则降级会丢弃进度"
);
const _: () = assert!(PIECE_SIZE > 0 && BASIC_CHUNK_SIZE > 0);
const _: () = assert!(PIECES_PER_BLOCK > 0);

/// 计算文件被切成多少个 piece（空文件为 0）
pub fn piece_count(file_size: u64) -> u64 {
    if file_size == 0 {
        0
    } else {
        file_size.div_ceil(PIECE_SIZE)
    }
}

/// 计算文件被切成多少个基础块（空文件为 0）
pub fn block_count(file_size: u64) -> u64 {
    if file_size == 0 {
        0
    } else {
        file_size.div_ceil(BASIC_CHUNK_SIZE)
    }
}

/// 单个文件的分块计划（不可变、可克隆）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkPlan {
    pub file_size: u64,
    pub algorithm: Algorithm,
    pub piece_count: u64,
    /// 基础块数量（= ceil(piece_count / PIECES_PER_BLOCK)）
    pub block_count: u64,
}

impl ChunkPlan {
    /// 为某文件构建分块计划。算法在此时确定（协商结果）。
    pub fn new(file_size: u64, algorithm: Algorithm) -> Self {
        let piece_count = piece_count(file_size);
        let block_count = if piece_count == 0 {
            0
        } else {
            piece_count.div_ceil(PIECES_PER_BLOCK)
        };
        Self {
            file_size,
            algorithm,
            piece_count,
            block_count,
        }
    }

    /// 第 `piece_idx` 个 piece 的字节区间 `[start, end)`（含末尾块收缩）
    pub fn piece_range(&self, piece_idx: u64) -> (u64, u64) {
        assert!(piece_idx < self.piece_count, "piece_idx 越界");
        let start = piece_idx * PIECE_SIZE;
        let end = ((piece_idx + 1) * PIECE_SIZE).min(self.file_size);
        (start, end)
    }

    /// 第 `block_idx` 个基础块的字节区间 `[start, end)`
    pub fn block_range(&self, block_idx: u64) -> (u64, u64) {
        assert!(block_idx < self.block_count, "block_idx 越界");
        let start = block_idx * BASIC_CHUNK_SIZE;
        let end = ((block_idx + 1) * BASIC_CHUNK_SIZE).min(self.file_size);
        (start, end)
    }

    /// piece → 所属基础块
    pub fn piece_to_block(&self, piece_idx: u64) -> u64 {
        piece_idx / PIECES_PER_BLOCK
    }

    /// 基础块 `block_idx` 涵盖的 piece 区间 `[first, last)`（last 为开区间、
    /// 已夹到 piece_count 内，处理末尾不足一块的情况）
    pub fn block_pieces(&self, block_idx: u64) -> (u64, u64) {
        let first = block_idx * PIECES_PER_BLOCK;
        let last = ((block_idx + 1) * PIECES_PER_BLOCK).min(self.piece_count);
        (first, last)
    }
}

/// 降级处置结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradePlan {
    /// 基础算法可**直接跳过**的块（其全部 piece 已被对端确认）
    pub completed_blocks: Vec<u64>,
    /// 基础算法**需要传输**的块（按序），含部分完成的块
    pub pending_blocks: Vec<u64>,
}

/// 从主算法视角下「对端已确认的 piece 集合」换算基础算法视角的进度。
///
/// 这是降级时保留进度的唯一机制：已完成的基础块直接跳过，
/// 只有未完成（含部分完成）的块需要重传。
///
/// `confirmed_pieces` 应来自接收端的权威块位图（`GET /api/v4/session/diff`
/// 或 `phase` 的 bitmapVersion 拉取），**不能**用发送端本地推测。
pub fn degrade_from_pieces(confirmed_pieces: &[u64], plan: &ChunkPlan) -> DegradePlan {
    let confirmed: std::collections::HashSet<u64> = confirmed_pieces.iter().copied().collect();
    let mut completed_blocks = Vec::new();
    let mut pending_blocks = Vec::new();
    for b in 0..plan.block_count {
        let (first, last) = plan.block_pieces(b);
        // 空文件或末块缩成 0 piece 时：first==last，视为已完成（无需传）
        let all_done = if first == last {
            true
        } else {
            (first..last).all(|p| confirmed.contains(&p))
        };
        if all_done {
            completed_blocks.push(b);
        } else {
            pending_blocks.push(b);
        }
    }
    DegradePlan {
        completed_blocks,
        pending_blocks,
    }
}

/// 基础算法视角下，给定「已完成的基础块集合」，换算回主算法 piece 集合。
///
/// 用于「从基础算法切回主算法」或调试对账：已完成块 ⟹ 块内全部 piece 完成。
/// 注意：基础算法以 block 为粒度，块内不存在「部分完成」，所以这是无损的。
pub fn blocks_to_pieces(completed_blocks: &[u64], plan: &ChunkPlan) -> Vec<u64> {
    let mut pieces = Vec::new();
    for &b in completed_blocks {
        let (first, last) = plan.block_pieces(b);
        for p in first..last {
            pieces.push(p);
        }
    }
    pieces
}

// ===== 弱/强双校验 + ChunkDiff（接通 scheduler.ts 死代码，见 V4-ARCHITECTURE §3.4 问题2 / §7.1） =====
//
// 设计约束（来自 DESIGN-WISDOM-REGISTER）：
// - E6：旧 weakChecksum 注释写 xxHash64，但常量与标准实现不符 —— 若 Rust 用标准 xxHash64
//   弱校验将永不命中。V4 改用**无歧义的 Adler-32**（rsync 标准弱校验），从根上消除「常量对不上」风险。
// - 弱校验只做「快筛」（廉价、可错），强校验（SHA-256）才是正确性依据；两者配合实现
//   rsync 式 missing / matched / mismatched 三分类（与 `dto::session::ChunkDiff` 语义对齐）。

use std::collections::{HashMap, HashSet};

/// 强校验：piece 内容的 SHA-256（单一事实源，复用 `crypto::merkle::sha256_of`）
pub use crate::crypto::merkle::sha256_of as strong_checksum;

/// 弱校验（Adler-32，rsync 标准）。
///
/// 选用 Adler-32 而非 xxHash64 的考量（见 E6）：xxHash64 在旧实现里常量写错、非标准，
/// 且 V4 要「统一」弱校验算法。Adler-32 定义明确、无魔数歧义，作为快筛足够。
/// 注意：弱校验**不是**完整性依据，仅用于 cheap 地判断「对端可能有这块」，
/// 最终是否一致以 `strong_checksum`（SHA-256）为准。
pub fn weak_checksum(data: &[u8]) -> u32 {
    const MOD: u32 = 65521; // 65521 = 最大素数 < 65536
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

/// 单个 piece 的双校验摘要
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceHash {
    pub index: u64,
    /// 弱校验（Adler-32），用于快筛
    pub weak: u32,
    /// 强校验（SHA-256），作为正确性依据
    pub strong: [u8; 32],
}

impl PieceHash {
    /// 由 piece 字节一次性算出弱/强双校验
    pub fn from_piece(index: u64, data: &[u8]) -> Self {
        Self {
            index,
            weak: weak_checksum(data),
            strong: strong_checksum(data),
        }
    }
}

/// 块差异结果（与 `dto::session::ChunkDiff` 的三分类语义一致）
///
/// - `missing`：对端完全没有（必须传输）
/// - `matched`：对端有且强校验一致（可跳过）
/// - `mismatched`：对端有但强校验不一致（内容已变，需重传）
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiffResult {
    pub missing: Vec<u64>,
    pub matched: Vec<u64>,
    pub mismatched: Vec<u64>,
}

/// 发送端用：把本地 piece 双校验集合与对端已确认的强校验集合比对，产出差异。
///
/// `peer_strong` 来自接收端的权威块位图（`GET /api/v4/session/diff`），**不能用发送端本地推测**。
/// 分类规则：
/// - 对端无该 piece（不在 `peer_strong`）→ `missing`
/// - 对端有且该 piece 强校验一致 → `matched`
/// - 对端有但强校验不一致 → `mismatched`
pub fn compute_chunk_diff(
    source: &[PieceHash],
    peer_strong: &HashMap<u64, [u8; 32]>,
) -> DiffResult {
    let mut diff = DiffResult::default();
    for ph in source {
        match peer_strong.get(&ph.index) {
            None => diff.missing.push(ph.index),
            Some(s) if s == &ph.strong => diff.matched.push(ph.index),
            Some(_) => diff.mismatched.push(ph.index),
        }
    }
    // 排序保证结果确定性（便于对账与测试）
    diff.missing.sort_unstable();
    diff.matched.sort_unstable();
    diff.mismatched.sort_unstable();
    diff
}

/// 弱校验快筛：对端是否可能存在该块的弱校验命中。
///
/// 命中**不代表**内容一致（需强校验确认），但不命中一定可跳过强校验计算，
/// 用于在带宽受限场景先发弱校验、只对候选块取强校验。
pub fn weak_screen(weak: u32, peer_weak: &HashSet<u32>) -> bool {
    peer_weak.contains(&weak)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invariant_alignment() {
        assert_eq!(BASIC_CHUNK_SIZE % PIECE_SIZE, 0);
        assert_eq!(PIECES_PER_BLOCK, 4);
    }

    #[test]
    fn piece_and_block_count() {
        // 17 MiB：主算法 5 个 piece（4+4+4+4+1），基础算法 2 个块（16+1）
        let size = 17 * 1024 * 1024;
        let plan = ChunkPlan::new(size, Algorithm::Advanced);
        assert_eq!(plan.piece_count, 5);
        assert_eq!(plan.block_count, 2);
        // 末块收缩到 1 MiB
        assert_eq!(plan.block_range(1), (16 * 1024 * 1024, 17 * 1024 * 1024));
        // 末 piece 收缩到 1 MiB
        assert_eq!(plan.piece_range(4), (16 * 1024 * 1024, 17 * 1024 * 1024));
    }

    #[test]
    fn empty_file_has_zero_chunks() {
        let plan = ChunkPlan::new(0, Algorithm::Advanced);
        assert_eq!(plan.piece_count, 0);
        assert_eq!(plan.block_count, 0);
    }

    #[test]
    fn exactly_aligned_size() {
        let size = 16 * 1024 * 1024; // 正好 4 个块
        let plan = ChunkPlan::new(size, Algorithm::Basic);
        assert_eq!(plan.block_count, 1);
        assert_eq!(plan.piece_count, 4);
        assert_eq!(plan.block_pieces(0), (0, 4));
    }

    #[test]
    fn degrade_preserves_aligned_progress() {
        // 17 MiB 文件，主算法 5 piece。假设前 4 个 piece（= 第 0 块）已确认。
        let size = 17 * 1024 * 1024;
        let plan = ChunkPlan::new(size, Algorithm::Advanced);
        let confirmed = vec![0, 1, 2, 3];
        let d = degrade_from_pieces(&confirmed, &plan);
        // 第 0 块完整 → 跳过；第 1 块（含 piece 4）未完成 → 需传
        assert_eq!(d.completed_blocks, vec![0]);
        assert_eq!(d.pending_blocks, vec![1]);
    }

    #[test]
    fn degrade_partial_block_must_resend() {
        // 第 0 块只完成了 3/4 piece（piece 0,1,2），piece 3 缺失
        let size = 17 * 1024 * 1024;
        let plan = ChunkPlan::new(size, Algorithm::Advanced);
        let confirmed = vec![0, 1, 2];
        let d = degrade_from_pieces(&confirmed, &plan);
        // 第 0 块不完整 → 整块需重传（基础算法以 block 为粒度）
        assert_eq!(d.completed_blocks, Vec::<u64>::new());
        assert_eq!(d.pending_blocks, vec![0, 1]);
    }

    #[test]
    fn degrade_no_progress_all_pending() {
        let size = 17 * 1024 * 1024;
        let plan = ChunkPlan::new(size, Algorithm::Advanced);
        let d = degrade_from_pieces(&[], &plan);
        assert!(d.completed_blocks.is_empty());
        assert_eq!(d.pending_blocks, vec![0, 1]);
    }

    #[test]
    fn blocks_to_pieces_roundtrip() {
        let size = 17 * 1024 * 1024;
        let plan = ChunkPlan::new(size, Algorithm::Advanced);
        let pieces = blocks_to_pieces(&[0], &plan);
        assert_eq!(pieces, vec![0, 1, 2, 3]);
    }

    #[test]
    fn piece_to_block_mapping() {
        let plan = ChunkPlan::new(100 * 1024 * 1024, Algorithm::Advanced);
        assert_eq!(plan.piece_to_block(0), 0);
        assert_eq!(plan.piece_to_block(3), 0);
        assert_eq!(plan.piece_to_block(4), 1);
        assert_eq!(plan.piece_to_block(7), 1);
        assert_eq!(plan.piece_to_block(8), 2);
    }

    // ===== 弱/强双校验 + ChunkDiff 测试 =====

    #[test]
    fn weak_checksum_empty_is_adler_one() {
        // Adler-32 规范：空输入 = 1
        assert_eq!(weak_checksum(&[]), 1);
    }

    #[test]
    fn weak_checksum_single_byte_known() {
        // "a"：a = 1+97 = 98, b = 0+98 = 98 → (98<<16)|98
        assert_eq!(weak_checksum(b"a"), (98u32 << 16) | 98);
    }

    #[test]
    fn weak_checksum_is_deterministic_and_changes() {
        assert_eq!(weak_checksum(b"hello"), weak_checksum(b"hello"));
        // 单字节差异应改变弱校验（足够做快筛）
        assert_ne!(weak_checksum(b"ab"), weak_checksum(b"ac"));
    }

    #[test]
    fn piece_hash_from_piece_computes_both() {
        let ph = PieceHash::from_piece(3, b"payload");
        assert_eq!(ph.index, 3);
        assert_eq!(ph.weak, weak_checksum(b"payload"));
        assert_eq!(ph.strong, strong_checksum(b"payload"));
    }

    #[test]
    fn diff_classifies_missing_matched_mismatched() {
        // 3 个 piece 的源端哈希
        let p0 = PieceHash::from_piece(0, b"alpha");
        let p1 = PieceHash::from_piece(1, b"bravo");
        let p2 = PieceHash::from_piece(2, b"charlie");
        let source = vec![p0.clone(), p1.clone(), p2.clone()];

        // 对端只持有 p0（一致）和 p1（但内容变了 → 强校验不符）
        let mut peer: HashMap<u64, [u8; 32]> = HashMap::new();
        peer.insert(0, p0.strong); // 一致 → matched
        peer.insert(1, strong_checksum(b"BRAVO-CHANGED")); // 不一致 → mismatched

        let diff = compute_chunk_diff(&source, &peer);
        assert_eq!(diff.matched, vec![0]);
        assert_eq!(diff.mismatched, vec![1]);
        assert_eq!(diff.missing, vec![2]);
    }

    #[test]
    fn diff_all_missing_when_peer_empty() {
        let source = vec![
            PieceHash::from_piece(0, b"x"),
            PieceHash::from_piece(1, b"y"),
        ];
        let peer: HashMap<u64, [u8; 32]> = HashMap::new();
        let diff = compute_chunk_diff(&source, &peer);
        assert_eq!(diff.missing, vec![0, 1]);
        assert!(diff.matched.is_empty());
        assert!(diff.mismatched.is_empty());
    }

    #[test]
    fn diff_all_matched_when_peer_fully_in_sync() {
        let s0 = PieceHash::from_piece(0, b"x");
        let s1 = PieceHash::from_piece(1, b"y");
        let source = vec![s0.clone(), s1.clone()];
        let mut peer: HashMap<u64, [u8; 32]> = HashMap::new();
        peer.insert(0, s0.strong);
        peer.insert(1, s1.strong);
        let diff = compute_chunk_diff(&source, &peer);
        assert_eq!(diff.matched, vec![0, 1]);
        assert!(diff.missing.is_empty());
        assert!(diff.mismatched.is_empty());
    }

    #[test]
    fn weak_screen_filters_by_weak_checksum() {
        let mut peer = HashSet::new();
        peer.insert(weak_checksum(b"hit"));
        assert!(weak_screen(weak_checksum(b"hit"), &peer));
        assert!(!weak_screen(weak_checksum(b"miss"), &peer));
    }
}
