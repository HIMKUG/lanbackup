//! V4 传输模块
//!
//! 设计见 `V4-TRANSFER-MODULE.md`：
//! **一套主算法（Advanced：块差异 + Merkle + 续传 + 并发）作为主传输路径，
//! 其下内嵌一套基础算法（Basic：16MB 分块 + 简单续传）作为兜底。**
//!
//! 当主算法能力检测不通过 / 初始化失败 / 传输中断且重试无效时，
//! 自动降级到基础算法（见 [`chunk::degrade_from_pieces`]），界面明示当前算法与降级原因。

//! # 模块分工
//!
//! | 模块 | 职责 | 边界 |
//! |---|---|---|
//! | [`chunk`] | 分块几何、弱/强校验、差异计算、piece→block 换算 | 纯函数，不含策略 |
//! | [`schedule`] | 并发许可、重试退避 | 不判断"该不该降级" |
//! | [`degrade`] | **何时降级、记多久、给用户看什么** | 不自己转状态机 |

pub mod chunk;
pub mod degrade;
pub mod schedule;

pub use chunk::{
    block_count, blocks_to_pieces, compute_chunk_diff, degrade_from_pieces, piece_count,
    weak_checksum, weak_screen, ChunkPlan, DegradePlan, DiffResult, PieceHash, BASIC_CHUNK_SIZE,
    PIECES_PER_BLOCK, PIECE_SIZE,
};

pub use degrade::{
    degrade_progress, DegradeAction, DegradeController, DegradeDecision, DegradeMemory,
    DegradeProgress, DegradeRecord, DegradeSignal, DegradeVisibility, InitFailure, MemoryChange,
    SessionOutcome,
};

pub use schedule::{full_jitter_backoff_ms, ChunkPermit, RetryPermit, TransferScheduler};
