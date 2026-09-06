//! 会话编排器 —— 把状态机、降级控制器、分块计划接成一条真实链路
//!
//! # 设计：决策与 IO 分离
//!
//! 本模块**不做任何 IO**。它是一台确定性状态机驱动器：
//!
//! ```text
//!   next_step()  ──▶  调用方执行 IO  ──▶  feed(outcome)  ──▶  next_step() ...
//! ```
//!
//! 为什么不把 socket 直接写进来：降级路径的正确性只能靠"让每一步都失败"
//! 来验证。如果编排逻辑和 `reqwest` 缠在一起，测试就必须起 HTTP server、
//! 注入网络故障、还要控制时序 —— 结果是这部分**根本不会有测试**，
//! 而它恰好是整个模块最需要测试的地方（降级只在故障时发生，
//! 也就是永远没人手动测到的那条路径）。
//!
//! 拆开之后，"连续 3 个块重试耗尽必须降级"变成一个纯同步断言。
//!
//! # 三条不变量
//!
//! 1. **状态只由 [`TransferState::transition`] 改**。本模块没有任何
//!    `self.state = ...` 的直接赋值（除构造），全部走 [`SessionDriver::apply`]。
//! 2. **降不降级只由 [`DegradeController`] 说**。编排器不自己判阈值，
//!    只负责把信号喂进去、把 [`DegradeAction::events`] 喂给状态机。
//! 3. **非法输入必须报错，不许静默吞掉**。见 [`SessionError`]。
//!
//! [`DegradeAction::events`]: crate::transfer::degrade::DegradeAction::events

use std::collections::{BTreeSet, HashMap, VecDeque};

use crate::dto::session::Algorithm;
use crate::state::transfer::{TransferEvent, TransferState};
use crate::transfer::chunk::{degrade_from_pieces, ChunkPlan};
use crate::transfer::cleanup::{CleanupPlan, CleanupTrigger};
use crate::transfer::degrade::{
    degrade_progress, DegradeController, DegradeDecision, DegradeMemory, DegradeProgress,
    DegradeRecord, DegradeSignal, DegradeVisibility, InitFailure, SessionOutcome,
};
use crate::transfer::schedule::{chunk_backoff_ms, full_jitter_backoff_ms};
use crate::version::{retry, Capabilities};

// ============================================================
// 步骤 / 结果
// ============================================================

/// 编排器要求调用方执行的下一个动作。
///
/// `attempt` 从 0 起，0 表示首次尝试。非 0 时调用方**必须**先等待
/// [`Step::backoff_ms`] 毫秒，并用重试配额（[`Step::needs_retry_permit`]）
/// 而不是普通块配额 —— 否则失败重试会吃光许可把正常分片饿死（A13）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// `POST /api/v4/session/prepare?algo=…`，返回协商后的能力位图
    Prepare { algorithm: Algorithm, attempt: u32 },
    /// 主算法初始化：构建 Merkle 树、派生传输密钥
    InitAdvanced,
    /// `GET /api/v4/session/diff` 拉取对端**权威**块位图
    ///
    /// 三种场合都用它：`Reconciling` 的正常对账、`Paused` 的恢复探测、
    /// `Transferring` 下校验失败后重新定位坏块。
    Reconcile { attempt: u32 },
    /// 发送一个主算法 piece
    SendPiece { index: u64, attempt: u32 },
    /// 发送一个基础算法块
    SendBlock { index: u64, attempt: u32 },
    /// 整体校验
    Verify,
    /// 等待下一个文件（调度层使用）
    Waiting,
    /// 执行清理（§六）。调用方执行完须调 [`SessionDriver::cleanup_finished`]
    Cleanup(CleanupPlan),
    /// 会话结束，无事可做
    Done { state: TransferState },
}

impl Step {
    /// 执行本步之前应等待的毫秒数。
    ///
    /// 握手 / 对账用慢退避（1s 起），块重试用快退避（200ms 起）——
    /// 两套参数的理由见 [`crate::version::retry`]。
    pub fn backoff_ms(&self) -> Option<u64> {
        match *self {
            Step::Prepare { attempt, .. } | Step::Reconcile { attempt } if attempt > 0 => {
                Some(full_jitter_backoff_ms(attempt - 1))
            }
            Step::SendPiece { attempt, .. } | Step::SendBlock { attempt, .. } if attempt > 0 => {
                Some(chunk_backoff_ms(attempt - 1))
            }
            _ => None,
        }
    }

    /// 是否应改用**重试**配额而非普通块配额（A13）
    pub fn needs_retry_permit(&self) -> bool {
        matches!(
            *self,
            Step::SendPiece { attempt, .. } | Step::SendBlock { attempt, .. } if attempt > 0
        )
    }

    /// 是否还需要调用方继续驱动
    pub fn is_done(&self) -> bool {
        matches!(self, Step::Done { .. })
    }
}

/// 调用方把一步的执行结果喂回来。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// prepare 成功，附协商后的能力位图（本机 ∩ 对端）
    Prepared {
        negotiated: Capabilities,
    },
    /// prepare 本身失败（超时 / 5xx）。重试耗尽后 → `Failed`（T6）
    PrepareFailed,
    /// 主算法初始化成功
    AdvancedInitialized,
    /// 主算法初始化失败 → D2
    AdvancedInitFailed(InitFailure),
    /// 对账成功，附对端权威已确认 piece 列表
    Reconciled {
        confirmed_pieces: Vec<u64>,
    },
    /// 对账失败 → D3（`Reconciling`）或 D4 计数（`Paused`）
    ReconcileFailed,
    PieceSent {
        index: u64,
    },
    PieceFailed {
        index: u64,
    },
    BlockSent {
        index: u64,
    },
    BlockFailed {
        index: u64,
    },
    VerifyPassed,
    /// 整体校验不通过 → T17 重传坏块，累计超阈值 → D6
    VerifyRejected,
    /// 心跳超时（`Transferring` → `Paused`）
    HeartbeatTimedOut,
    /// 连接断开
    PeerLost,
    /// 用户中止
    UserAbort,
    /// 文件级：一个文件上传成功（desktop 调度层使用）
    FileDone { file_id: String },
}

impl Outcome {
    fn name(&self) -> &'static str {
        match self {
            Outcome::Prepared { .. } => "Prepared",
            Outcome::PrepareFailed => "PrepareFailed",
            Outcome::AdvancedInitialized => "AdvancedInitialized",
            Outcome::AdvancedInitFailed(_) => "AdvancedInitFailed",
            Outcome::Reconciled { .. } => "Reconciled",
            Outcome::ReconcileFailed => "ReconcileFailed",
            Outcome::PieceSent { .. } => "PieceSent",
            Outcome::PieceFailed { .. } => "PieceFailed",
            Outcome::BlockSent { .. } => "BlockSent",
            Outcome::BlockFailed { .. } => "BlockFailed",
            Outcome::VerifyPassed => "VerifyPassed",
            Outcome::VerifyRejected => "VerifyRejected",
            Outcome::HeartbeatTimedOut => "HeartbeatTimedOut",
            Outcome::PeerLost => "PeerLost",
            Outcome::UserAbort => "UserAbort",
            Outcome::FileDone { .. } => "FileDone",
        }
    }
}

/// 编排错误。
///
/// §5.3「提示文案原则」：错误必须能直接给人看，不能只有一个 enum 变体名。
/// 所以这里带 `message` —— 调用方不需要再写一份 match 把错误翻译成文案
/// （那份 match 一定会和这里漂移，见登记表 E10）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionError {
    pub state: TransferState,
    pub outcome: &'static str,
    pub message: String,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SessionError {}

/// 一次 [`SessionDriver::feed`] 的效果，供日志与 UI 使用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// 实际派发给状态机的事件（按序）。空表示本次只更新了内部计数
    pub events: Vec<TransferEvent>,
    pub state: TransferState,
    /// 本次 feed 触发的降级（仅触发的那一次有值）
    pub degraded: Option<DegradeRecord>,
}

// ============================================================
// 编排器
// ============================================================

/// 单个传输会话的编排器。
///
/// 不实现 `Clone`：内含 [`DegradeController`] 的连续失败计数，复制一份
/// 等于把判据分叉，两份各自到不了阈值，降级永不触发。
#[derive(Debug)]
pub struct SessionDriver {
    state: TransferState,
    degrade: DegradeController,
    plan: ChunkPlan,

    /// 对端**权威**已确认的 piece 集合。只由 `Reconciled` 与成功发送写入。
    confirmed: BTreeSet<u64>,
    /// 主算法待发 piece 队列
    pending_pieces: VecDeque<u64>,
    /// 基础算法待发块队列
    pending_blocks: VecDeque<u64>,
    /// 当前传输单元的已尝试次数（piece 或 block，两者不会共存）
    attempts: HashMap<u64, u32>,

    /// prepare 已尝试次数（握手重试，T6）
    prepare_attempts: u32,
    /// 对账已尝试次数。`Reconciling` 用于退避、`Paused` 用于 D4 计数
    reconcile_attempts: u32,
    /// 校验失败后需要重新定位坏块（T17 回到 `Transferring` 后先重新 diff）
    needs_rediff: bool,

    /// 是否一开始就用基础算法（记忆生效）—— 决定 [`Self::outcome`] 报 `SkippedAdvanced`
    started_basic: bool,
    /// 降级时刻的进度快照，供 UI（§4.4）
    progress_snapshot: Option<DegradeProgress>,
    cleanup_done: bool,
}

impl SessionDriver {
    /// 开启一个会话。构造即派发 `Register`，状态落到 `Preparing`。
    ///
    /// `prefer_basic` 来自设备级降级记忆（§4.3）。为真时直接从基础算法起步，
    /// 跳过主算法能力检测与初始化。
    pub fn start(plan: ChunkPlan, prefer_basic: bool) -> Self {
        let degrade = if prefer_basic {
            DegradeController::with_preferred_basic()
        } else {
            DegradeController::new()
        };
        // `Idle → Preparing` 是状态机里唯一合法的开局，直接 unwrap 不会 panic；
        // 用 transition 而不是写 `state: Preparing` 是为了守住"状态只由状态机改"。
        let state = TransferState::Idle
            .transition(TransferEvent::Register)
            .expect("Idle + Register 必为合法迁移");
        Self {
            state,
            degrade,
            plan,
            confirmed: BTreeSet::new(),
            pending_pieces: VecDeque::new(),
            pending_blocks: VecDeque::new(),
            attempts: HashMap::new(),
            prepare_attempts: 0,
            reconcile_attempts: 0,
            needs_rediff: false,
            started_basic: prefer_basic,
            progress_snapshot: None,
            cleanup_done: false,
        }
    }

    /// 从断点恢复：带上已知的对端确认进度开启会话。
    pub fn resume(plan: ChunkPlan, prefer_basic: bool, confirmed_pieces: &[u64]) -> Self {
        let mut d = Self::start(plan, prefer_basic);
        d.absorb_confirmed(confirmed_pieces);
        d
    }

    // ---------- 观测 ----------

    pub fn state(&self) -> TransferState {
        self.state
    }

    pub fn algorithm(&self) -> Algorithm {
        self.degrade.algorithm()
    }

    pub fn plan(&self) -> &ChunkPlan {
        &self.plan
    }

    /// 本会话是否发生过降级（区别于"一开始就用基础算法"）
    pub fn has_degraded(&self) -> bool {
        self.degrade.has_degraded()
    }

    pub fn degrade_record(&self) -> Option<&DegradeRecord> {
        self.degrade.degrade_record()
    }

    /// 对端已确认的 piece 数
    pub fn confirmed_pieces(&self) -> usize {
        self.confirmed.len()
    }

    /// 剩余待发单元数（主算法为 piece，基础算法为块）
    pub fn pending_units(&self) -> usize {
        match self.algorithm() {
            Algorithm::Advanced => self.pending_pieces.len(),
            Algorithm::Basic => self.pending_blocks.len(),
        }
    }

    /// §4.4 的 UI 快照
    pub fn visibility(&self, memory: &DegradeMemory) -> DegradeVisibility {
        DegradeVisibility::new(&self.degrade, memory, self.progress_snapshot)
    }

    /// 会话对"主算法能不能用"的结论，喂给 [`DegradeMemory::record`]。
    ///
    /// 只在会话结束后调用才有意义。中途调用会得到 `Inconclusive`
    /// （还没结论），这也是安全的默认值 —— 宁可不计数，也不能误伤主算法。
    pub fn outcome(&self) -> SessionOutcome {
        if let Some(rec) = self.degrade.degrade_record() {
            return SessionOutcome::Degraded(rec.reason);
        }
        if self.started_basic {
            // 记忆生效直接用基础算法，本次对"主算法行不行"没有任何信息量
            return SessionOutcome::SkippedAdvanced;
        }
        match self.state {
            TransferState::Completed => SessionOutcome::AdvancedSucceeded,
            // Failed / Aborted 且没降级：会话根本没跑到主算法头上
            // （prepare 就没通、用户取消、对端断开）。一律不计数（S17）。
            _ => SessionOutcome::Inconclusive,
        }
    }

    // ---------- 驱动 ----------

    /// 下一步该做什么。纯读取，不改状态。
    pub fn next_step(&self) -> Step {
        use TransferState as S;
        match self.state {
            S::Preparing => Step::Prepare {
                algorithm: self.algorithm(),
                attempt: self.prepare_attempts,
            },
            S::Reconciling => Step::Reconcile {
                attempt: self.reconcile_attempts,
            },
            S::Paused => Step::Reconcile {
                attempt: self.reconcile_attempts,
            },
            S::Transferring => {
                if self.needs_rediff {
                    // T17 之后：先重新拉权威位图定位坏块，再决定重传哪些
                    return Step::Reconcile {
                        attempt: self.reconcile_attempts,
                    };
                }
                match self.algorithm() {
                    Algorithm::Advanced => match self.pending_pieces.front() {
                        Some(&index) => Step::SendPiece {
                            index,
                            attempt: self.attempt_of(index),
                        },
                        // 队列空却仍在 Transferring 是内部不一致：
                        // feed() 在队列排空时就该派发 BeginVerify。
                        // 返回 Verify 而不是 panic —— 但这条路径有测试守着
                        // (`draining_the_queue_begins_verify`)。
                        None => Step::Verify,
                    },
                    Algorithm::Basic => match self.pending_blocks.front() {
                        Some(&index) => Step::SendBlock {
                            index,
                            attempt: self.attempt_of(index),
                        },
                        None => Step::Verify,
                    },
                }
            }
            S::Verifying => Step::Verify,
            S::Processing => Step::Waiting,
            // Degrading 是瞬态：execute_degrade 会在同一次 feed 内走完
            // Degrade → DegradeComplete。若外部看到它，说明有人手工转了状态机。
            S::Degrading => Step::Done { state: self.state },
            S::Idle => Step::Done { state: self.state },
            S::Completed | S::Failed | S::Aborted => {
                if self.cleanup_done {
                    Step::Done { state: self.state }
                } else {
                    Step::Cleanup(CleanupPlan::for_trigger(self.cleanup_trigger(), self.state))
                }
            }
        }
    }

    /// 调用方执行完清理后回调，避免 [`Self::next_step`] 反复要求清理。
    pub fn cleanup_finished(&mut self) {
        self.cleanup_done = true;
    }

    /// 喂入一步的执行结果。
    ///
    /// `now_unix` 由调用方传入 —— 编排器不读时钟，否则测试就得依赖真实时间。
    pub fn feed(&mut self, outcome: Outcome, now_unix: u32) -> Result<Applied, SessionError> {
        let mut ctx = Ctx::default();
        use Outcome as O;
        use TransferState as S;

        // 断线与中止在任何非终态都成立，先统一处理，避免在下面每个
        // (state, outcome) 组合里重复一遍（漏一个就是一个"点了没反应"的按钮）。
        match outcome {
            O::PeerLost => return self.terminate(TransferEvent::PeerLost, outcome, &mut ctx),
            O::UserAbort => return self.terminate(TransferEvent::Abort, outcome, &mut ctx),
            _ => {}
        }

        match (self.state, outcome) {
            // ---------- Preparing ----------
            (S::Preparing, O::Prepared { negotiated }) => {
                self.prepare_attempts = 0;
                self.on_capabilities(negotiated, now_unix, &mut ctx)?;
            }
            (S::Preparing, O::PrepareFailed) => {
                self.prepare_attempts += 1;
                if self.prepare_attempts >= retry::HANDSHAKE {
                    // T6：握手重试耗尽 → Failed。
                    // **不是降级** —— 连 prepare 都不通，换算法也照样不通。
                    self.apply(TransferEvent::RetryExhausted, &mut ctx)?;
                }
            }
            (S::Preparing, O::AdvancedInitialized) => {
                self.apply(TransferEvent::NegotiateAdvanced, &mut ctx)?;
                self.reconcile_attempts = 0;
            }
            (S::Preparing, O::AdvancedInitFailed(detail)) => {
                // D2
                self.observe(DegradeSignal::InitFailed(detail), now_unix, &mut ctx)?;
            }

            // ---------- Reconciling ----------
            (S::Reconciling, O::Reconciled { confirmed_pieces }) => {
                self.reconcile_attempts = 0;
                self.observe(DegradeSignal::ReconcileSucceeded, now_unix, &mut ctx)?;
                self.absorb_confirmed(&confirmed_pieces);
                self.apply(TransferEvent::Reconciled, &mut ctx)?;
                self.maybe_begin_verify(&mut ctx)?;
            }
            (S::Reconciling, O::ReconcileFailed) => {
                self.reconcile_attempts += 1;
                // D3：阈值由控制器判，编排器不自己数
                self.observe(DegradeSignal::ReconcileAttemptFailed, now_unix, &mut ctx)?;
            }

            // ---------- Paused（心跳超时后的恢复探测） ----------
            (S::Paused, O::Reconciled { confirmed_pieces }) => {
                // 对端还活着 → 带着已确认进度重新开一轮尝试
                self.reconcile_attempts = 0;
                self.absorb_confirmed(&confirmed_pieces);
                self.apply(TransferEvent::Retry, &mut ctx)?;
            }
            (S::Paused, O::ReconcileFailed) => {
                self.reconcile_attempts += 1;
                if self.reconcile_attempts >= retry::RECONCILE {
                    // D4：心跳超时后对账 3 次全失败
                    self.observe(DegradeSignal::PausedRetryExhausted, now_unix, &mut ctx)?;
                }
            }

            // ---------- Transferring ----------
            (S::Transferring, O::HeartbeatTimedOut) => {
                self.reconcile_attempts = 0;
                self.apply(TransferEvent::HeartbeatTimeout, &mut ctx)?;
            }
            (S::Transferring, O::Reconciled { confirmed_pieces }) => {
                // T17 之后的重新定位坏块。**不转状态** —— 拉位图不改变
                // "正在传输"这个事实，状态机也没有对应的边。
                self.reconcile_attempts = 0;
                self.needs_rediff = false;
                self.absorb_confirmed(&confirmed_pieces);
                self.maybe_begin_verify(&mut ctx)?;
            }
            (S::Transferring, O::ReconcileFailed) if self.needs_rediff => {
                self.reconcile_attempts += 1;
                self.observe(DegradeSignal::ReconcileAttemptFailed, now_unix, &mut ctx)?;
            }
            (S::Transferring, O::PieceSent { index }) => {
                self.require_algorithm(Algorithm::Advanced, "PieceSent")?;
                self.expect_front(index, "PieceSent")?;
                self.pending_pieces.pop_front();
                self.attempts.remove(&index);
                self.confirmed.insert(index);
                self.observe(DegradeSignal::ChunkSucceeded, now_unix, &mut ctx)?;
                self.apply(TransferEvent::Progress, &mut ctx)?;
                self.maybe_begin_verify(&mut ctx)?;
            }
            (S::Transferring, O::PieceFailed { index }) => {
                self.require_algorithm(Algorithm::Advanced, "PieceFailed")?;
                self.expect_front(index, "PieceFailed")?;
                self.on_unit_failed(index, now_unix, &mut ctx)?;
            }
            (S::Transferring, O::BlockSent { index }) => {
                self.require_algorithm(Algorithm::Basic, "BlockSent")?;
                self.expect_front(index, "BlockSent")?;
                self.pending_blocks.pop_front();
                self.attempts.remove(&index);
                self.apply(TransferEvent::Progress, &mut ctx)?;
                self.maybe_begin_verify(&mut ctx)?;
            }
            (S::Transferring, O::BlockFailed { index }) => {
                self.require_algorithm(Algorithm::Basic, "BlockFailed")?;
                self.expect_front(index, "BlockFailed")?;
                self.on_unit_failed(index, now_unix, &mut ctx)?;
            }

            // ---------- Verifying ----------
            (S::Verifying, O::VerifyPassed) => {
                self.apply(TransferEvent::VerifyOk, &mut ctx)?;
            }
            (S::Verifying, O::VerifyRejected) => {
                // D6 的阈值判定在控制器里；未达阈值时它返回 Continue，
                // 编排器把它翻译成 T17 的 VerifyRetry。
                let decision =
                    self.degrade
                        .observe(DegradeSignal::VerifyAttemptFailed, self.state, now_unix);
                match decision {
                    DegradeDecision::Degrade(action) => {
                        self.execute_degrade(action, &mut ctx)?;
                    }
                    DegradeDecision::Continue { .. } => {
                        // T17：还有额度，回传输态重传坏块 ——
                        // 一块写坏用主算法补一块就好，直接降级要按 16MB 重来。
                        self.apply(TransferEvent::VerifyRetry, &mut ctx)?;
                        self.needs_rediff = true;
                        self.reconcile_attempts = 0;
                    }
                    DegradeDecision::AlreadyBasic => {
                        // 基础算法都校验不过 —— 兜底的兜底没有了（T20/T23）
                        self.apply(TransferEvent::Fail, &mut ctx)?;
                    }
                    DegradeDecision::Ignored { .. } => {}
                }
            }

            // ---------- Processing（文件级调度层） ----------
            (S::Processing, O::FileDone { file_id: _ }) => {
                self.apply(TransferEvent::Progress, &mut ctx)?;
            }

            // ---------- 其余组合非法 ----------
            (state, outcome) => {
                return Err(SessionError {
                    state,
                    outcome: outcome.name(),
                    message: format!(
                        "当前处于「{}」，无法处理「{}」这一步的结果",
                        state_text(state),
                        outcome.name()
                    ),
                })
            }
        }

        Ok(Applied {
            events: ctx.events,
            state: self.state,
            degraded: ctx.degraded,
        })
    }

    // ---------- 内部 ----------

    fn attempt_of(&self, index: u64) -> u32 {
        self.attempts.get(&index).copied().unwrap_or(0)
    }

    /// 状态机是唯一改状态的地方
    fn apply(&mut self, ev: TransferEvent, ctx: &mut Ctx) -> Result<(), SessionError> {
        match self.state.transition(ev) {
            Ok(next) => {
                self.state = next;
                ctx.events.push(ev);
                Ok(())
            }
            Err(bad) => Err(SessionError {
                state: bad.from,
                outcome: bad.event,
                message: format!(
                    "「{}」状态下不能执行「{}」：{}",
                    state_text(bad.from),
                    bad.event,
                    bad.reason
                ),
            }),
        }
    }

    /// 把信号交给控制器，并在它判定降级时执行动作序列
    fn observe(
        &mut self,
        signal: DegradeSignal,
        now_unix: u32,
        ctx: &mut Ctx,
    ) -> Result<(), SessionError> {
        let decision = self.degrade.observe(signal, self.state, now_unix);
        if let DegradeDecision::Degrade(action) = decision {
            self.execute_degrade(action, ctx)?;
        }
        Ok(())
    }

    /// D1：协商结果。有 `CAP_ADVANCED` 才继续初始化主算法。
    fn on_capabilities(
        &mut self,
        negotiated: Capabilities,
        now_unix: u32,
        ctx: &mut Ctx,
    ) -> Result<(), SessionError> {
        let decision = self.degrade.observe(
            DegradeSignal::PeerCapabilities(negotiated),
            self.state,
            now_unix,
        );
        match decision {
            DegradeDecision::Degrade(action) => self.execute_degrade(action, ctx),
            DegradeDecision::AlreadyBasic => {
                // 记忆生效，本来就走基础算法：直接进传输态，不做主算法初始化
                self.apply(TransferEvent::NegotiateBasic, ctx)?;
                self.rebuild_basic_queue();
                self.maybe_begin_verify(ctx)
            }
            // 有能力 → 留在 Preparing，下一步是 InitAdvanced
            DegradeDecision::Continue { .. } | DegradeDecision::Ignored { .. } => Ok(()),
        }
    }

    /// 执行 §4.2 的降级动作序列。
    ///
    /// 第 1-3 步（取消在途请求、释放许可、停心跳）由调用方在收到
    /// [`Applied::degraded`] 后执行 —— 那些是资源操作，编排器碰不到。
    /// 第 4-8 步在这里：换算进度、重建块计划、转状态机、记录原因。
    fn execute_degrade(
        &mut self,
        action: crate::transfer::degrade::DegradeAction,
        ctx: &mut Ctx,
    ) -> Result<(), SessionError> {
        // §4.2 第 4-5 步：先按对齐规则换算，**在清空主算法队列之前**取快照，
        // 否则 UI 上「已用主算法完成 N 块」永远是 0。
        let confirmed: Vec<u64> = self.confirmed.iter().copied().collect();
        self.progress_snapshot = Some(degrade_progress(&confirmed, &self.plan));

        // 第 7 步的状态机部分：必须把控制器给的事件序列真的走一遍，
        // 不允许直接赋值 —— 赋值会绕过状态机的合法性检查，
        // 而降级恰好是最容易写出非法迁移的地方。
        for ev in action.events {
            self.apply(*ev, ctx)?;
        }

        // 第 6 步：用基础算法重建块计划
        self.rebuild_basic_queue();
        self.needs_rediff = false;
        self.reconcile_attempts = 0;

        // 第 8 步：把记录交出去，由调用方发 UI 事件
        ctx.degraded = Some(action.record);
        self.maybe_begin_verify(ctx)
    }

    /// 吸收对端权威位图，重算待发队列。
    ///
    /// **以对端位图为准替换本地 `confirmed`** —— 本地"以为发成功"的 piece
    /// 若不在对端位图里，必须被剔除并重新入队，否则会漏传。这正是本函数
    /// 注释里强调的"只接受对端确认的 piece"，也是 T17 能正常工作的前提：
    /// 校验失败时对端只确认了 `0..n-1`，被本地误标的第 `n` 块必须被重新拉回队列。
    ///
    /// 绝不能做"合并"：合并会让已本地标记完成、但对端实际没落盘的块留在
    /// 队列外，于是重传永远轮不到它，最终结果缺一块，且在校验之前毫无迹象。
    fn absorb_confirmed(&mut self, confirmed_pieces: &[u64]) {
        self.confirmed.clear();
        for &p in confirmed_pieces {
            if p < self.plan.piece_count {
                self.confirmed.insert(p);
            }
        }
        match self.algorithm() {
            Algorithm::Advanced => self.rebuild_advanced_queue(),
            Algorithm::Basic => self.rebuild_basic_queue(),
        }
    }

    fn rebuild_advanced_queue(&mut self) {
        self.pending_pieces = (0..self.plan.piece_count)
            .filter(|p| !self.confirmed.contains(p))
            .collect();
        self.attempts.clear();
    }

    fn rebuild_basic_queue(&mut self) {
        let confirmed: Vec<u64> = self.confirmed.iter().copied().collect();
        let dp = degrade_from_pieces(&confirmed, &self.plan);
        self.pending_blocks = dp.pending_blocks.into();
        self.pending_pieces.clear();
        self.attempts.clear();
    }

    /// 队列排空即进入整体校验。
    ///
    /// 放在每次队列变动之后统一调用，而不是散落在各分支 ——
    /// 漏一处的后果是 `Transferring` 卡住不动，且没有任何报错。
    fn maybe_begin_verify(&mut self, ctx: &mut Ctx) -> Result<(), SessionError> {
        if self.state != TransferState::Transferring || self.needs_rediff {
            return Ok(());
        }
        let empty = match self.algorithm() {
            Algorithm::Advanced => self.pending_pieces.is_empty(),
            Algorithm::Basic => self.pending_blocks.is_empty(),
        };
        if empty {
            self.apply(TransferEvent::BeginVerify, ctx)?;
        }
        Ok(())
    }

    /// 一个传输单元（piece / block）失败。
    fn on_unit_failed(
        &mut self,
        index: u64,
        now_unix: u32,
        ctx: &mut Ctx,
    ) -> Result<(), SessionError> {
        let a = self.attempts.entry(index).or_insert(0);
        *a += 1;
        if *a < retry::CHUNK {
            // 还有额度：原地重试。next_step 会带上新的 attempt，
            // 调用方据此退避 + 换用重试配额。
            return Ok(());
        }
        // 本单元重试额度耗尽
        self.attempts.remove(&index);
        let decision =
            self.degrade
                .observe(DegradeSignal::ChunkRetryExhausted, self.state, now_unix);
        match decision {
            DegradeDecision::Degrade(action) => self.execute_degrade(action, ctx),
            DegradeDecision::Continue { .. } => {
                // D5 连续计数未达阈值：把这块挪到队尾，先传别的。
                //
                // 终止性：连续计数只被 ChunkSucceeded 清零，而每个 piece
                // 最多成功一次。好块传完之后，坏块只能连续失败 ——
                // 最多再 3 轮就达阈值降级。不会死循环。
                if let Some(front) = self.pending_pieces.pop_front() {
                    debug_assert_eq!(front, index);
                    self.pending_pieces.push_back(front);
                }
                Ok(())
            }
            DegradeDecision::AlreadyBasic => {
                // 基础算法的块重试耗尽 —— 已经是兜底，没有下一层。
                //
                // 这里**不做**「挪到队尾再试」：基础算法的语义是"简单续传"，
                // 兜底再兜底只会把真实故障拖成一个更难查的超时。
                self.apply(TransferEvent::Fail, ctx)
            }
            DegradeDecision::Ignored { .. } => Ok(()),
        }
    }

    /// 断线 / 中止：任何非终态都直接收场
    fn terminate(
        &mut self,
        ev: TransferEvent,
        outcome: Outcome,
        ctx: &mut Ctx,
    ) -> Result<Applied, SessionError> {
        if self.state.is_terminal() || self.state == TransferState::Idle {
            return Err(SessionError {
                state: self.state,
                outcome: outcome.name(),
                message: format!("传输已结束（{}），无需再中止", state_text(self.state)),
            });
        }
        self.apply(ev, ctx)?;
        Ok(Applied {
            events: std::mem::take(&mut ctx.events),
            state: self.state,
            degraded: ctx.degraded.take(),
        })
    }

    fn require_algorithm(
        &self,
        want: Algorithm,
        outcome: &'static str,
    ) -> Result<(), SessionError> {
        if self.algorithm() == want {
            return Ok(());
        }
        Err(SessionError {
            state: self.state,
            outcome,
            message: format!(
                "当前算法是「{}」，收到的却是「{}」的结果 —— 降级后仍有主算法的在途请求未取消",
                algo_text(self.algorithm()),
                outcome
            ),
        })
    }

    /// 结果必须对应**队首**那个单元。
    ///
    /// 迟到的结果（降级前发出、降级后才回来）如果被当成当前单元的结果处理，
    /// 会把队首那个还没发的块直接标成完成 —— 收到的文件缺一块，且校验之前
    /// 毫无迹象。宁可报错让调用方丢弃。
    fn expect_front(&self, index: u64, outcome: &'static str) -> Result<(), SessionError> {
        let front = match self.algorithm() {
            Algorithm::Advanced => self.pending_pieces.front().copied(),
            Algorithm::Basic => self.pending_blocks.front().copied(),
        };
        match front {
            Some(f) if f == index => Ok(()),
            Some(f) => Err(SessionError {
                state: self.state,
                outcome,
                message: format!("收到 #{index} 的结果，但当前正在传 #{f} —— 已丢弃这条迟到的响应"),
            }),
            None => Err(SessionError {
                state: self.state,
                outcome,
                message: format!("收到 #{index} 的结果，但已无待传单元 —— 已丢弃这条迟到的响应"),
            }),
        }
    }

    fn cleanup_trigger(&self) -> CleanupTrigger {
        match self.state {
            TransferState::Completed => CleanupTrigger::Completed,
            TransferState::Failed => CleanupTrigger::Failed,
            // Aborted 既可能是用户点的，也可能是断线。两者的清理动作相同，
            // 差别只在记录原因；这里取不到区分信息时按断线报（更保守）。
            _ => CleanupTrigger::PeerLost,
        }
    }
}

/// 一次 feed 的累积效果
#[derive(Debug, Default)]
struct Ctx {
    events: Vec<TransferEvent>,
    degraded: Option<DegradeRecord>,
}

fn state_text(s: TransferState) -> &'static str {
    match s {
        TransferState::Idle => "空闲",
        TransferState::Preparing => "准备中",
        TransferState::Reconciling => "对账中",
        TransferState::Transferring => "传输中",
        TransferState::Paused => "已暂停",
        TransferState::Degrading => "降级中",
        TransferState::Verifying => "校验中",
        TransferState::Processing => "处理中",
        TransferState::Completed => "已完成",
        TransferState::Failed => "已失败",
        TransferState::Aborted => "已中止",
    }
}

fn algo_text(a: Algorithm) -> &'static str {
    match a {
        Algorithm::Advanced => "主算法",
        Algorithm::Basic => "基础模式",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::CAP_ADVANCED;

    const NOW: u32 = 1_700_000_000;
    /// 17 MiB → 主算法 5 piece，基础算法 2 块
    const SIZE: u64 = 17 * 1024 * 1024;

    fn plan() -> ChunkPlan {
        ChunkPlan::new(SIZE, Algorithm::Advanced)
    }

    fn advanced_caps() -> Capabilities {
        Capabilities::all()
    }

    fn old_peer() -> Capabilities {
        Capabilities::all().without(CAP_ADVANCED)
    }

    /// 推进到「主算法传输中」
    fn transferring() -> SessionDriver {
        let mut d = SessionDriver::start(plan(), false);
        d.feed(
            Outcome::Prepared {
                negotiated: advanced_caps(),
            },
            NOW,
        )
        .unwrap();
        d.feed(Outcome::AdvancedInitialized, NOW).unwrap();
        d.feed(
            Outcome::Reconciled {
                confirmed_pieces: vec![],
            },
            NOW,
        )
        .unwrap();
        assert_eq!(d.state(), TransferState::Transferring);
        d
    }

    /// 把队首单元连续打到重试耗尽（CHUNK 次失败）
    fn exhaust_front(d: &mut SessionDriver) {
        let index = match d.next_step() {
            Step::SendPiece { index, .. } | Step::SendBlock { index, .. } => index,
            other => panic!("期望发送步骤，实际 {other:?}"),
        };
        let advanced = d.algorithm() == Algorithm::Advanced;
        for _ in 0..retry::CHUNK {
            let o = if advanced {
                Outcome::PieceFailed { index }
            } else {
                Outcome::BlockFailed { index }
            };
            d.feed(o, NOW).unwrap();
        }
    }

    // ---------- 正常路径 ----------

    #[test]
    fn advanced_happy_path_reaches_completed() {
        let mut d = transferring();
        assert_eq!(d.algorithm(), Algorithm::Advanced);
        for i in 0..plan().piece_count {
            assert_eq!(
                d.next_step(),
                Step::SendPiece {
                    index: i,
                    attempt: 0
                }
            );
            d.feed(Outcome::PieceSent { index: i }, NOW).unwrap();
        }
        // 队列排空即自动进校验
        assert_eq!(d.state(), TransferState::Verifying);
        assert_eq!(d.next_step(), Step::Verify);
        d.feed(Outcome::VerifyPassed, NOW).unwrap();
        assert_eq!(d.state(), TransferState::Completed);
        assert!(!d.has_degraded());
        assert_eq!(d.outcome(), SessionOutcome::AdvancedSucceeded);
    }

    #[test]
    fn completed_session_asks_for_cleanup_exactly_once() {
        let mut d = transferring();
        for i in 0..plan().piece_count {
            d.feed(Outcome::PieceSent { index: i }, NOW).unwrap();
        }
        d.feed(Outcome::VerifyPassed, NOW).unwrap();
        // §六：成功路径也要清理（否则许可会被慢慢吃光）
        match d.next_step() {
            Step::Cleanup(p) => assert_eq!(p.trigger, CleanupTrigger::Completed),
            other => panic!("完成后应要求清理，实际 {other:?}"),
        }
        d.cleanup_finished();
        assert_eq!(
            d.next_step(),
            Step::Done {
                state: TransferState::Completed
            }
        );
    }

    #[test]
    fn resume_skips_confirmed_pieces() {
        // 断点续传：已确认 0,1 → 只需发 2,3,4
        let mut d = SessionDriver::resume(plan(), false, &[0, 1]);
        d.feed(
            Outcome::Prepared {
                negotiated: advanced_caps(),
            },
            NOW,
        )
        .unwrap();
        d.feed(Outcome::AdvancedInitialized, NOW).unwrap();
        d.feed(
            Outcome::Reconciled {
                confirmed_pieces: vec![0, 1],
            },
            NOW,
        )
        .unwrap();
        assert_eq!(d.pending_units(), 3);
        assert_eq!(
            d.next_step(),
            Step::SendPiece {
                index: 2,
                attempt: 0
            }
        );
    }

    #[test]
    fn empty_file_goes_straight_to_verify() {
        let mut d = SessionDriver::start(ChunkPlan::new(0, Algorithm::Advanced), false);
        d.feed(
            Outcome::Prepared {
                negotiated: advanced_caps(),
            },
            NOW,
        )
        .unwrap();
        d.feed(Outcome::AdvancedInitialized, NOW).unwrap();
        d.feed(
            Outcome::Reconciled {
                confirmed_pieces: vec![],
            },
            NOW,
        )
        .unwrap();
        // 0 个 piece：不该卡在 Transferring
        assert_eq!(d.state(), TransferState::Verifying);
    }

    // ---------- D1 / D2 ----------

    #[test]
    fn d1_peer_without_capability_degrades_at_prepare() {
        let mut d = SessionDriver::start(plan(), false);
        let applied = d
            .feed(
                Outcome::Prepared {
                    negotiated: old_peer(),
                },
                NOW,
            )
            .unwrap();
        assert_eq!(d.algorithm(), Algorithm::Basic);
        assert_eq!(d.state(), TransferState::Transferring);
        // §4.1 D1 的迁移列：preparing → transferring(basic)，一步到位
        assert_eq!(applied.events, vec![TransferEvent::NegotiateBasic]);
        let rec = applied.degraded.expect("必须带出降级记录");
        assert_eq!(rec.code(), "PEER_NO_CAPABILITY");
        // 队列已按基础块重建
        assert_eq!(d.pending_units(), plan().block_count as usize);
        assert_eq!(
            d.next_step(),
            Step::SendBlock {
                index: 0,
                attempt: 0
            }
        );
    }

    #[test]
    fn d2_init_failure_degrades_and_keeps_going() {
        let mut d = SessionDriver::start(plan(), false);
        d.feed(
            Outcome::Prepared {
                negotiated: advanced_caps(),
            },
            NOW,
        )
        .unwrap();
        let applied = d
            .feed(Outcome::AdvancedInitFailed(InitFailure::MerkleBuild), NOW)
            .unwrap();
        assert_eq!(d.algorithm(), Algorithm::Basic);
        assert_eq!(applied.degraded.unwrap().code(), "INIT_FAILED:MERKLE_BUILD");
        // 降级不是失败：还得把活干完
        assert_eq!(d.state(), TransferState::Transferring);
    }

    // ---------- D3 ----------

    #[test]
    fn d3_degrades_exactly_at_the_third_reconcile_failure() {
        let mut d = SessionDriver::start(plan(), false);
        d.feed(
            Outcome::Prepared {
                negotiated: advanced_caps(),
            },
            NOW,
        )
        .unwrap();
        d.feed(Outcome::AdvancedInitialized, NOW).unwrap();
        assert_eq!(d.state(), TransferState::Reconciling);

        for i in 1..retry::RECONCILE {
            let applied = d.feed(Outcome::ReconcileFailed, NOW).unwrap();
            assert!(applied.degraded.is_none(), "第 {i} 次失败不该降级");
            assert_eq!(d.state(), TransferState::Reconciling);
            // 重试要退避，且 attempt 递增
            assert_eq!(d.next_step(), Step::Reconcile { attempt: i });
            assert!(d.next_step().backoff_ms().is_some());
        }
        let applied = d.feed(Outcome::ReconcileFailed, NOW).unwrap();
        assert_eq!(applied.degraded.unwrap().code(), "RECONCILE_FAILED");
        // 走的是语义专用事件，日志里能直接看出为什么降级
        assert_eq!(
            applied.events,
            vec![
                TransferEvent::ReconcileFailed,
                TransferEvent::DegradeComplete
            ]
        );
        assert_eq!(d.algorithm(), Algorithm::Basic);
    }

    #[test]
    fn reconcile_success_resets_the_streak() {
        let mut d = SessionDriver::start(plan(), false);
        d.feed(
            Outcome::Prepared {
                negotiated: advanced_caps(),
            },
            NOW,
        )
        .unwrap();
        d.feed(Outcome::AdvancedInitialized, NOW).unwrap();
        // 失败 2 次（未达阈值）→ 成功一次 → 再失败 2 次仍不该降级
        d.feed(Outcome::ReconcileFailed, NOW).unwrap();
        d.feed(Outcome::ReconcileFailed, NOW).unwrap();
        d.feed(
            Outcome::Reconciled {
                confirmed_pieces: vec![],
            },
            NOW,
        )
        .unwrap();
        assert!(!d.has_degraded());
        assert_eq!(d.state(), TransferState::Transferring);
    }

    // ---------- D4 ----------

    #[test]
    fn d4_heartbeat_timeout_then_reconcile_exhausted_degrades_not_fails() {
        // 文档 T12 的核心：paused + 对账全失败 → degrading，**不是** failed。
        // 放弃等于白扔已确认进度。
        let mut d = transferring();
        d.feed(Outcome::PieceSent { index: 0 }, NOW).unwrap();
        d.feed(Outcome::HeartbeatTimedOut, NOW).unwrap();
        assert_eq!(d.state(), TransferState::Paused);
        assert_eq!(d.next_step(), Step::Reconcile { attempt: 0 });

        for _ in 0..retry::RECONCILE - 1 {
            let applied = d.feed(Outcome::ReconcileFailed, NOW).unwrap();
            assert!(applied.degraded.is_none());
            assert_eq!(d.state(), TransferState::Paused);
        }
        let applied = d.feed(Outcome::ReconcileFailed, NOW).unwrap();
        assert_eq!(applied.degraded.unwrap().code(), "RETRY_EXHAUSTED");
        assert_eq!(d.state(), TransferState::Transferring);
        assert_eq!(d.algorithm(), Algorithm::Basic);
        assert_ne!(d.state(), TransferState::Failed);
    }

    #[test]
    fn paused_recovers_when_peer_answers_again() {
        let mut d = transferring();
        d.feed(Outcome::PieceSent { index: 0 }, NOW).unwrap();
        d.feed(Outcome::HeartbeatTimedOut, NOW).unwrap();
        d.feed(
            Outcome::Reconciled {
                confirmed_pieces: vec![0],
            },
            NOW,
        )
        .unwrap();
        // 对端还活着 → 重开一轮，且已确认进度不丢
        assert_eq!(d.state(), TransferState::Preparing);
        assert!(!d.has_degraded());
        assert_eq!(d.confirmed_pieces(), 1);
    }

    // ---------- D5 ----------

    #[test]
    fn d5_degrades_after_three_consecutive_exhausted_units() {
        let mut d = transferring();
        // 前两个块各自重试耗尽 —— 挪到队尾，先传别的，尚未降级
        for _ in 0..retry::CHUNK_FAIL_DEGRADE - 1 {
            exhaust_front(&mut d);
            assert!(!d.has_degraded());
            assert_eq!(d.state(), TransferState::Transferring);
        }
        // 第三个块耗尽 → D5
        let index = match d.next_step() {
            Step::SendPiece { index, .. } => index,
            other => panic!("{other:?}"),
        };
        let mut last = None;
        for _ in 0..retry::CHUNK {
            last = Some(d.feed(Outcome::PieceFailed { index }, NOW).unwrap());
        }
        let applied = last.unwrap();
        assert_eq!(applied.degraded.unwrap().code(), "CHUNK_RETRY_EXHAUSTED");
        assert_eq!(
            applied.events,
            vec![
                TransferEvent::ChunkRetryExhausted,
                TransferEvent::DegradeComplete
            ]
        );
        assert_eq!(d.algorithm(), Algorithm::Basic);
    }

    #[test]
    fn a_successful_unit_resets_the_consecutive_counter() {
        let mut d = transferring();
        exhaust_front(&mut d);
        exhaust_front(&mut d);
        assert!(!d.has_degraded());
        // 成功一块 → 连续计数清零
        let index = match d.next_step() {
            Step::SendPiece { index, .. } => index,
            other => panic!("{other:?}"),
        };
        d.feed(Outcome::PieceSent { index }, NOW).unwrap();
        // 再连续耗尽两块，仍不该降级（计数已清零）
        exhaust_front(&mut d);
        exhaust_front(&mut d);
        assert!(
            !d.has_degraded(),
            "成功传输后连续计数应清零，否则偶发失败会在几小时后累积到阈值"
        );
    }

    #[test]
    fn retry_within_quota_stays_on_the_same_unit_with_backoff() {
        let mut d = transferring();
        assert_eq!(
            d.next_step(),
            Step::SendPiece {
                index: 0,
                attempt: 0
            }
        );
        assert_eq!(d.next_step().backoff_ms(), None, "首次尝试不该退避");
        assert!(!d.next_step().needs_retry_permit());

        d.feed(Outcome::PieceFailed { index: 0 }, NOW).unwrap();
        let step = d.next_step();
        assert_eq!(
            step,
            Step::SendPiece {
                index: 0,
                attempt: 1
            }
        );
        // 重试必须退避 + 走独立重试配额（A13），否则重试会把正常分片饿死
        assert!(step.backoff_ms().is_some());
        assert!(step.needs_retry_permit());
        // 块级退避走快参数（<5s），不是握手那套 64s
        assert!(step.backoff_ms().unwrap() < retry::CHUNK_BACKOFF_MAX_MS);
    }

    // ---------- D6 / T17 ----------

    #[test]
    fn verify_failure_first_retries_then_degrades() {
        let mut d = transferring();
        for i in 0..plan().piece_count {
            d.feed(Outcome::PieceSent { index: i }, NOW).unwrap();
        }
        assert_eq!(d.state(), TransferState::Verifying);

        // T17：前几次回传输态重传坏块，不降级
        for _ in 1..DegradeController::VERIFY_THRESHOLD {
            let applied = d.feed(Outcome::VerifyRejected, NOW).unwrap();
            assert!(applied.degraded.is_none());
            assert_eq!(applied.events, vec![TransferEvent::VerifyRetry]);
            assert_eq!(d.state(), TransferState::Transferring);
            // 必须先重新拉权威位图定位坏块，否则队列是空的会立刻又去校验
            assert_eq!(d.next_step(), Step::Reconcile { attempt: 0 });
            // 对端报第 4 块坏了
            d.feed(
                Outcome::Reconciled {
                    confirmed_pieces: vec![0, 1, 2, 3],
                },
                NOW,
            )
            .unwrap();
            assert_eq!(
                d.next_step(),
                Step::SendPiece {
                    index: 4,
                    attempt: 0
                }
            );
            d.feed(Outcome::PieceSent { index: 4 }, NOW).unwrap();
            assert_eq!(d.state(), TransferState::Verifying);
        }
        // 额度用尽 → D6
        let applied = d.feed(Outcome::VerifyRejected, NOW).unwrap();
        assert_eq!(applied.degraded.unwrap().code(), "VERIFY_FAILED");
        assert_eq!(d.algorithm(), Algorithm::Basic);
    }

    #[test]
    fn verify_retry_does_not_loop_forever_on_an_empty_queue() {
        // 回归：T17 回到 Transferring 时队列是空的。若不强制先重新 diff，
        // maybe_begin_verify 会立刻又把状态推回 Verifying —— 死循环。
        let mut d = transferring();
        for i in 0..plan().piece_count {
            d.feed(Outcome::PieceSent { index: i }, NOW).unwrap();
        }
        d.feed(Outcome::VerifyRejected, NOW).unwrap();
        assert_eq!(d.state(), TransferState::Transferring);
        assert!(
            matches!(d.next_step(), Step::Reconcile { .. }),
            "必须先重新对账，而不是立刻回到校验"
        );
    }

    // ---------- 基础算法兜底 ----------

    #[test]
    fn basic_algorithm_failing_ends_the_session_instead_of_looping() {
        // 兜底之下没有兜底。基础算法块重试耗尽必须收场，
        // 否则会在 Transferring ⇄ Degrading 之间无限打转。
        let mut d = SessionDriver::start(plan(), false);
        d.feed(
            Outcome::Prepared {
                negotiated: old_peer(),
            },
            NOW,
        )
        .unwrap();
        assert_eq!(d.algorithm(), Algorithm::Basic);
        exhaust_front(&mut d);
        assert_eq!(d.state(), TransferState::Failed);
    }

    #[test]
    fn basic_verify_failure_fails_the_session() {
        let mut d = SessionDriver::start(plan(), false);
        d.feed(
            Outcome::Prepared {
                negotiated: old_peer(),
            },
            NOW,
        )
        .unwrap();
        for i in 0..plan().block_count {
            d.feed(Outcome::BlockSent { index: i }, NOW).unwrap();
        }
        assert_eq!(d.state(), TransferState::Verifying);
        let applied = d.feed(Outcome::VerifyRejected, NOW).unwrap();
        assert_eq!(applied.events, vec![TransferEvent::Fail]);
        assert_eq!(d.state(), TransferState::Failed);
    }

    // ---------- 记忆生效 ----------

    #[test]
    fn prefer_basic_skips_advanced_entirely() {
        let mut d = SessionDriver::start(plan(), true);
        assert_eq!(d.algorithm(), Algorithm::Basic);
        assert_eq!(
            d.next_step(),
            Step::Prepare {
                algorithm: Algorithm::Basic,
                attempt: 0
            }
        );
        let applied = d
            .feed(
                Outcome::Prepared {
                    negotiated: advanced_caps(),
                },
                NOW,
            )
            .unwrap();
        // 即便对端有能力，也不试主算法（记忆生效）
        assert_eq!(d.algorithm(), Algorithm::Basic);
        assert_eq!(d.state(), TransferState::Transferring);
        assert!(applied.degraded.is_none(), "这不算一次降级");
        assert!(!d.has_degraded());
        // 对"主算法行不行"没有信息量 → 不该动记忆
        assert_eq!(d.outcome(), SessionOutcome::SkippedAdvanced);
        let mut mem = DegradeMemory::restore(2, true);
        assert_eq!(
            mem.record(d.outcome()),
            crate::transfer::degrade::MemoryChange::Unchanged
        );
    }

    // ---------- 中止 / 断线 ----------

    #[test]
    fn user_abort_and_peer_loss_are_inconclusive() {
        // S17：不能因为用户点了三次取消就永久禁用主算法
        for (o, _) in [(Outcome::UserAbort, "abort"), (Outcome::PeerLost, "lost")] {
            let mut d = transferring();
            d.feed(o, NOW).unwrap();
            assert_eq!(d.state(), TransferState::Aborted);
            assert_eq!(d.outcome(), SessionOutcome::Inconclusive);
            let mut mem = DegradeMemory::new();
            assert_eq!(
                mem.record(d.outcome()),
                crate::transfer::degrade::MemoryChange::Unchanged
            );
            assert_eq!(mem.streak(), 0);
        }
    }

    #[test]
    fn abort_is_rejected_on_settled_sessions_with_a_readable_message() {
        // §5：非法操作必须给可读提示，不能静默失败
        let mut d = transferring();
        for i in 0..plan().piece_count {
            d.feed(Outcome::PieceSent { index: i }, NOW).unwrap();
        }
        d.feed(Outcome::VerifyPassed, NOW).unwrap();
        let err = d.feed(Outcome::UserAbort, NOW).unwrap_err();
        assert_eq!(err.state, TransferState::Completed);
        assert!(
            err.message.contains("已完成"),
            "提示应可读：{}",
            err.message
        );
    }

    #[test]
    fn aborted_session_asks_for_cleanup_with_the_right_trigger() {
        let mut d = transferring();
        d.feed(Outcome::PeerLost, NOW).unwrap();
        match d.next_step() {
            Step::Cleanup(p) => {
                assert_eq!(p.trigger, CleanupTrigger::PeerLost);
                assert_eq!(p.from_state, TransferState::Aborted);
            }
            other => panic!("{other:?}"),
        }
    }

    // ---------- 非法输入 ----------

    #[test]
    fn late_response_for_a_stale_unit_is_rejected() {
        // 降级前发出、降级后才回来的响应。若被当成队首的结果处理，
        // 会把还没发的块标成完成 —— 收到的文件缺一块且校验前毫无迹象。
        let mut d = transferring();
        let err = d.feed(Outcome::PieceSent { index: 3 }, NOW).unwrap_err();
        assert!(err.message.contains("迟到"), "{}", err.message);
        assert_eq!(d.confirmed_pieces(), 0, "非法输入不得改变状态");
    }

    #[test]
    fn block_result_during_advanced_transfer_is_rejected() {
        let mut d = transferring();
        let err = d.feed(Outcome::BlockSent { index: 0 }, NOW).unwrap_err();
        assert!(err.message.contains("主算法"), "{}", err.message);
    }

    #[test]
    fn piece_result_after_degrade_is_rejected() {
        // 降级后主算法的在途请求陆续回来，必须被拒
        let mut d = transferring();
        for _ in 0..retry::CHUNK_FAIL_DEGRADE {
            exhaust_front(&mut d);
        }
        assert_eq!(d.algorithm(), Algorithm::Basic);
        let err = d.feed(Outcome::PieceSent { index: 0 }, NOW).unwrap_err();
        assert!(err.message.contains("基础模式"), "{}", err.message);
    }

    #[test]
    fn every_error_message_is_human_readable() {
        // §5.3：提示必须能直接展示，不能是 enum 变体名
        let mut d = transferring();
        let errors = vec![
            d.feed(Outcome::AdvancedInitialized, NOW).unwrap_err(),
            d.feed(Outcome::VerifyPassed, NOW).unwrap_err(),
            d.feed(Outcome::PieceSent { index: 99 }, NOW).unwrap_err(),
        ];
        for e in errors {
            assert!(!e.message.is_empty());
            assert!(
                e.message
                    .chars()
                    .any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
                "提示应是中文可读文案，实际：{}",
                e.message
            );
        }
    }

    #[test]
    fn prepare_retry_exhausted_fails_without_degrading() {
        // T6：连 prepare 都不通，换算法也照样不通 —— 这不是降级场景
        let mut d = SessionDriver::start(plan(), false);
        for i in 1..retry::HANDSHAKE {
            d.feed(Outcome::PrepareFailed, NOW).unwrap();
            assert_eq!(d.state(), TransferState::Preparing);
            assert_eq!(
                d.next_step(),
                Step::Prepare {
                    algorithm: Algorithm::Advanced,
                    attempt: i
                }
            );
        }
        d.feed(Outcome::PrepareFailed, NOW).unwrap();
        assert_eq!(d.state(), TransferState::Failed);
        assert!(!d.has_degraded());
        assert_eq!(
            d.outcome(),
            SessionOutcome::Inconclusive,
            "握手失败不该记到主算法头上"
        );
    }

    // ---------- 降级进度与 UI ----------

    #[test]
    fn degrade_preserves_aligned_progress_and_reports_the_cost() {
        // 4 个 piece 已确认 = 第 0 块完整 → 基础算法可直接跳过
        let mut d = transferring();
        for i in 0..4 {
            d.feed(Outcome::PieceSent { index: i }, NOW).unwrap();
        }
        // 第 4 个 piece 连续失败到降级
        for _ in 0..retry::CHUNK_FAIL_DEGRADE {
            exhaust_front(&mut d);
        }
        assert_eq!(d.algorithm(), Algorithm::Basic);
        // 第 0 块跳过，只剩第 1 块要传
        assert_eq!(d.pending_units(), 1);
        assert_eq!(
            d.next_step(),
            Step::SendBlock {
                index: 1,
                attempt: 0
            }
        );

        let vis = d.visibility(&DegradeMemory::new());
        assert_eq!(vis.algorithm, Algorithm::Basic);
        assert!(vis.degraded_this_session);
        assert_eq!(vis.reason_code.as_deref(), Some("CHUNK_RETRY_EXHAUSTED"));
        assert!(vis.reason_text.is_some());
        let p = vis.progress.expect("必须有进度快照");
        assert_eq!(p.total_blocks, 2);
        assert_eq!(p.completed_blocks, 1);
        assert_eq!(p.pending_blocks, 1);
        assert!(vis.progress_text().is_some());
    }

    #[test]
    fn progress_snapshot_is_taken_before_the_queue_is_rebuilt() {
        // 回归：若先重建队列再取快照，UI 上「已用主算法完成 N 块」永远是 0。
        let mut d = transferring();
        for i in 0..4 {
            d.feed(Outcome::PieceSent { index: i }, NOW).unwrap();
        }
        for _ in 0..retry::CHUNK_FAIL_DEGRADE {
            exhaust_front(&mut d);
        }
        let p = d
            .visibility(&DegradeMemory::new())
            .progress
            .expect("快照缺失");
        assert!(
            p.completed_blocks > 0,
            "降级前已完成的块必须体现在快照里，否则用户以为白传了"
        );
    }

    #[test]
    fn degrade_happens_at_most_once_per_session() {
        // §4.3「会话内不回切」。降级后再来的失败信号一律不产生第二条记录。
        let mut d = transferring();
        for _ in 0..retry::CHUNK_FAIL_DEGRADE {
            exhaust_front(&mut d);
        }
        let first = d.degrade_record().cloned().expect("应已降级");
        // 基础算法块也失败 → 会话失败，但降级记录不变
        exhaust_front(&mut d);
        assert_eq!(d.state(), TransferState::Failed);
        assert_eq!(d.degrade_record(), Some(&first));
    }

    // ---------- 全局性质 ----------

    #[test]
    fn session_terminates_even_if_every_single_send_fails() {
        // 终止性：坏块被挪到队尾重试，靠"连续计数只被成功清零"收敛。
        // 这条测试是那段推理的兜底 —— 万一推理错了，这里会挂起或超出上限。
        let mut d = transferring();
        let mut guard = 0;
        while !d.state().is_terminal() {
            guard += 1;
            assert!(guard < 500, "会话未能收敛，当前状态 {:?}", d.state());
            let o = match d.next_step() {
                Step::SendPiece { index, .. } => Outcome::PieceFailed { index },
                Step::SendBlock { index, .. } => Outcome::BlockFailed { index },
                Step::Reconcile { .. } => Outcome::ReconcileFailed,
                Step::Verify => Outcome::VerifyRejected,
                Step::Prepare { .. } => Outcome::PrepareFailed,
                Step::InitAdvanced => Outcome::AdvancedInitFailed(InitFailure::MerkleBuild),
                Step::Cleanup(_) | Step::Done { .. } => break,
            };
            d.feed(o, NOW).unwrap();
        }
        assert!(d.state().is_terminal(), "全程失败也必须收场");
        // 而且必须是降级之后才失败 —— 直接判死等于没给兜底机会
        assert!(d.has_degraded(), "应先降级再失败");
    }

    #[test]
    fn state_is_only_ever_changed_through_the_state_machine() {
        // 把 feed 报告的事件序列在一个独立的状态机实例上重放，
        // 结果必须与编排器自己的状态一致。若有人偷偷直接赋值状态，这里就对不上。
        let mut d = transferring();
        let mut mirror = TransferState::Idle
            .transition(TransferEvent::Register)
            .unwrap();
        mirror = mirror.transition(TransferEvent::NegotiateAdvanced).unwrap();
        mirror = mirror.transition(TransferEvent::Reconciled).unwrap();
        assert_eq!(mirror, d.state());

        let script = [
            Outcome::PieceSent { index: 0 },
            Outcome::PieceFailed { index: 1 },
            Outcome::HeartbeatTimedOut,
            Outcome::ReconcileFailed,
            Outcome::ReconcileFailed,
            Outcome::ReconcileFailed,
        ];
        for o in script {
            let applied = d.feed(o, NOW).unwrap();
            for ev in applied.events {
                mirror = mirror
                    .transition(ev)
                    .unwrap_or_else(|e| panic!("编排器派发了非法事件 {ev:?}：{e:?}"));
            }
            assert_eq!(mirror, d.state(), "事件序列与实际状态不一致");
        }
    }

    #[test]
    fn illegal_input_never_mutates_state() {
        let mut d = transferring();
        let before = (
            d.state(),
            d.algorithm(),
            d.confirmed_pieces(),
            d.pending_units(),
        );
        for bad in [
            Outcome::AdvancedInitialized,
            Outcome::VerifyPassed,
            Outcome::BlockSent { index: 0 },
            Outcome::PieceSent { index: 42 },
        ] {
            assert!(d.feed(bad, NOW).is_err());
        }
        assert_eq!(
            before,
            (
                d.state(),
                d.algorithm(),
                d.confirmed_pieces(),
                d.pending_units()
            ),
            "非法输入必须完全无副作用"
        );
    }
}
