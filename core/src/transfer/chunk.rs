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

/// 主算法分块单位（piece）。所有续传 / 差异 / 并发以 piece 为最小粒度。
pub const PIECE_SIZE: u64 = 4 * 1024 * 1024; // 4 MiB

/// 基础算法块大小。见模块文档的不变式说明。
pub const BASIC_CHUNK_SIZE: u64 = 16 * 1024 * 1024; // 16 MiB

/// 一个基础块涵盖多少个主算法 piece。由对齐不变式保证为整数。
pub const PIECES_PER_BLOCK: u64 = BASIC_CHUNK_SIZE / PIECE_SIZE;

// 编译期断言：对齐不变式不能被破坏（破坏则降级会丢失进度）
const _: () = assert!(
    BASIC_CHUNK_SIZE.is_multiple_of(PIECE_SIZE),
    "BASIC_CHUNK_SIZE 必须是 PIECE_SIZE 的整数倍，否则降级会丢弃进度"
);
const _: () = assert!(PIECE_SIZE > 0 && BASIC_CHUNK_SIZE > 0);

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
}
