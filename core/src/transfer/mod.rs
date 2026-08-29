//! V4 传输模块
//!
//! 设计见 `V4-TRANSFER-MODULE.md`：
//! **一套主算法（Advanced：块差异 + Merkle + 续传 + 并发）作为主传输路径，
//! 其下内嵌一套基础算法（Basic：16MB 分块 + 简单续传）作为兜底。**
//!
//! 当主算法能力检测不通过 / 初始化失败 / 传输中断且重试无效时，
//! 自动降级到基础算法（见 [`chunk::degrade_from_pieces`]），界面明示当前算法与降级原因。

pub mod chunk;

pub use chunk::{
    block_count, blocks_to_pieces, degrade_from_pieces, piece_count, ChunkPlan, DegradePlan,
    BASIC_CHUNK_SIZE, PIECE_SIZE, PIECES_PER_BLOCK,
};
