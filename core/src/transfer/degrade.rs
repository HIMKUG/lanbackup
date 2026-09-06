//! 降级决策控制器 —— 主算法（Advanced）→ 基础算法（Basic）的唯一判定入口
//!
//! 对应 `V4-TRANSFER-MODULE.md` §4.1（触发条件）、§4.2（动作序列）、
//! §4.3（恢复策略）、§4.4（可见性）。
//!
//! # 为什么要有这么一个"控制器"而不是散在各处 if
//!
//! V3 的降级逻辑散落在 `scheduler.ts` / `transfer.ts` 的十几处分支里，
//! 结果是：**没人说得清"现在为什么在用基础算法"**。同一次会话里可能
//! 一段路走主算法、一段路走基础算法，进度显示与真实传输互相矛盾。
//!
//! V4 把降级收敛成三件事：
//!
//! | 关注点 | 载体 | 不变量 |
//! |---|---|---|
//! | 什么时候降 | [`DegradeController`] | 会话内**一旦降级不回切** |
//! | 降了要记多久 | [`DegradeMemory`] | 只记「有能力但跑不通」，且**只存本机** |
//! | 用户看到什么 | [`DegradeVisibility`] | 算法 + 原因 + 进度处置，三者缺一不可 |
//!
//! # 关键设计
//!
//! 1. **控制器不持有传输状态** —— 当前状态由状态机唯一持有，`observe`
//!    时作为参数传入。两处各存一份"当前状态"必然漂移（登记表 S12）。
//! 2. **控制器不自己转状态机** —— 它只输出应发送的**事件序列**
//!    （[`DegradeAction::events`]），由调用方喂进真实状态机。
//!    这样非法转移会被状态机拦下，而不是被旁路。
//! 3. **控制器不读时钟** —— `now_unix` 由调用方传入，便于测试构造任意时序。
//! 4. **阈值全部来自 [`crate::version::retry`]** —— 不在此处硬编码数字。

use crate::dto::session::{Algorithm, DegradeReason};
use crate::state::transfer::{TransferEvent, TransferState};
use crate::transfer::chunk::ChunkPlan;
use crate::version::{retry, Capabilities, CAP_ADVANCED};

// ============================================================
// D2 的失败细节
// ============================================================

/// 主算法初始化失败的细分原因。
///
/// 文档 §4.1 的原因码写作 `INIT_FAILED:<detail>` —— detail 不可省：
/// 「Merkle 建树失败」和「内存不足」的运维处置完全不同，
/// 只报 `INIT_FAILED` 等于把根因扔了。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitFailure {
    /// Merkle 树构建失败
    MerkleBuild,
    /// 会话密钥派生失败
    KeyDerivation,
    /// diff 端点返回 5xx
    DiffEndpoint,
    /// 内存不足（大文件建树时最常见）
    OutOfMemory,
}

impl InitFailure {
    pub fn detail(self) -> &'static str {
        match self {
            Self::MerkleBuild => "MERKLE_BUILD",
            Self::KeyDerivation => "KEY_DERIVATION",
            Self::DiffEndpoint => "DIFF_ENDPOINT",
            Self::OutOfMemory => "OUT_OF_MEMORY",
        }
    }

    pub fn text(self) -> &'static str {
        match self {
            Self::MerkleBuild => "校验树构建失败",
            Self::KeyDerivation => "会话密钥派生失败",
            Self::DiffEndpoint => "对方的差异探测接口异常",
            Self::OutOfMemory => "内存不足",
        }
    }
}

// ============================================================
// 触发信号
// ============================================================

/// 送进控制器的观测信号。
///
/// **注意成对出现的"复位"信号**（[`Self::ReconcileSucceeded`] /
/// [`Self::ChunkSucceeded`]）：D3 与 D5 判的是**连续**失败，
/// 少喂复位信号会让偶发失败在几小时后累积到阈值，
/// 表现为「传着传着突然降级了，日志里前后失败隔了半小时」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradeSignal {
    /// D1：prepare 响应里协商后的能力位图。无 `CAP_ADVANCED` 即降级。
    PeerCapabilities(Capabilities),
    /// D2：主算法初始化失败。一次即降级，不累积。
    InitFailed(InitFailure),
    /// D3 计数：一次对账失败
    ReconcileAttemptFailed,
    /// D3 复位：对账成功
    ReconcileSucceeded,
    /// D4：心跳超时进入 paused 后，对账重试全部耗尽。一次即降级。
    PausedRetryExhausted,
    /// D5 计数：某个块的重试次数耗尽
    ChunkRetryExhausted,
    /// D5 复位：任一块传输成功
    ChunkSucceeded,
    /// D6 计数：一次整体校验失败
    VerifyAttemptFailed,
}

// ============================================================
// 决策
// ============================================================

/// 一次降级的完整记录（§4.2 第 7 步「记录降级原因与时间戳」）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradeRecord {
    pub reason: DegradeReason,
    /// 仅 `InitFailed` 有值
    pub detail: Option<InitFailure>,
    /// 降级发生时所处的状态（日志对账用）
    pub from_state: TransferState,
    pub at_unix: u32,
}

impl DegradeRecord {
    /// 完整原因码：`INIT_FAILED:MERKLE_BUILD` / `CHUNK_RETRY_EXHAUSTED`
    pub fn code(&self) -> String {
        match self.detail {
            Some(d) => format!("{}:{}", self.reason.code(), d.detail()),
            None => self.reason.code().to_string(),
        }
    }

    /// 给用户看的完整文案
    pub fn text(&self) -> String {
        match self.detail {
            Some(d) => format!("{}（{}）", self.reason.text(), d.text()),
            None => self.reason.text().to_string(),
        }
    }
}

/// 控制器判定"应当降级"时输出的动作。
///
/// 调用方拿到后须执行 §4.2 的动作序列，其中状态机部分**必须**
/// 按 [`Self::events`] 顺序喂给真实状态机 —— 不允许直接赋值状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradeAction {
    pub record: DegradeRecord,
    /// 从当前状态到「基础算法传输中」的合法事件序列
    pub events: &'static [TransferEvent],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DegradeDecision {
    /// 未达阈值，继续主算法。带上计数便于日志打印「3 次里的第 2 次」
    Continue { streak: u32, threshold: u32 },
    /// 触发降级
    Degrade(DegradeAction),
    /// 已在基础算法上 —— **会话内不回切**，信号被吸收
    AlreadyBasic,
    /// 会话已定局（Idle / 终态）或该状态无法降级，信号丢弃
    Ignored { state: TransferState },
}

impl DegradeDecision {
    pub fn is_degrade(&self) -> bool {
        matches!(self, Self::Degrade(_))
    }

    pub fn action(&self) -> Option<&DegradeAction> {
        match self {
            Self::Degrade(a) => Some(a),
            _ => None,
        }
    }
}

/// 从 `from` 状态降级到「基础算法传输中」的合法事件序列。
///
/// 优先使用状态机里**语义专用**的事件（`ReconcileFailed` /
/// `ChunkRetryExhausted` / `VerifyFailed`），退而用通用 `Degrade`。
/// 这样状态机的事件日志本身就能回答"为什么降级"，
/// 不必再去翻另一份日志做时间戳对齐。
///
/// 该状态是否**存在**通往「基础算法传输中」的合法路径。
///
/// 与具体降级原因无关 —— [`events_for`] 对每个可降级状态都有兜底分支。
/// 单独抽出来是因为它必须在**任何计数器被修改之前**判断：
/// 否则一个迟到的 `ChunkRetryExhausted`（会话已 Aborted）会把连续失败
/// 计数悄悄加一，下次会话若复用了这个控制器就会提前降级。
/// 测试 `state_admissibility_matches_event_table` 锁死两者一致。
fn can_degrade_from(state: TransferState) -> bool {
    use TransferState as S;
    matches!(
        state,
        S::Preparing | S::Reconciling | S::Transferring | S::Paused | S::Verifying
    )
}

/// 返回 `None` 表示该状态不允许降级（Idle / Degrading / 终态）。
fn events_for(reason: DegradeReason, from: TransferState) -> Option<&'static [TransferEvent]> {
    use DegradeReason as R;
    use TransferState as S;
    let evs: &'static [TransferEvent] = match (reason, from) {
        // §4.1 D1/D2 的迁移列写的是 preparing → transferring(basic)：
        // 此刻还没有在途块请求、没有 Semaphore 许可要释放，
        // 因此不必绕经 Degrading，一步 NegotiateBasic 到位。
        (R::PeerNoCapability, S::Preparing) | (R::InitFailed, S::Preparing) => {
            &[TransferEvent::NegotiateBasic]
        }
        (R::ReconcileFailed, S::Reconciling) => &[
            TransferEvent::ReconcileFailed,
            TransferEvent::DegradeComplete,
        ],
        (R::ChunkRetryExhausted, S::Transferring) => &[
            TransferEvent::ChunkRetryExhausted,
            TransferEvent::DegradeComplete,
        ],
        (R::VerifyFailed, S::Verifying) => {
            &[TransferEvent::VerifyFailed, TransferEvent::DegradeComplete]
        }
        // 其余可降级状态走通用路径
        (_, S::Preparing) | (_, S::Reconciling) | (_, S::Transferring) | (_, S::Paused) => {
            &[TransferEvent::Degrade, TransferEvent::DegradeComplete]
        }
        // Verifying 通往 Degrading 的**唯一**合法事件是 VerifyFailed
        // （状态机没有 (Verifying, Degrade) 这条边）。因此即便真实原因不是
        // 校验失败，状态机事件也只能用它 —— 真实原因保存在
        // [`DegradeRecord::reason`] 里，日志与 UI 取那里，不会被这条边带偏。
        (_, S::Verifying) => &[TransferEvent::VerifyFailed, TransferEvent::DegradeComplete],
        // Idle：还没会话；Degrading：正在降级中；Processing：调度层状态不参与降级；终态：已定局
        (_, S::Idle) | (_, S::Degrading) | (_, S::Processing) | (_, S::Completed) | (_, S::Failed) | (_, S::Aborted) => {
            return None
        }
    };
    Some(evs)
}

// ============================================================
// 控制器
// ============================================================

/// 每会话一个实例。
///
/// 不实现 `Clone` 是刻意的：复制一份计数器等于把"连续失败"的
/// 判断依据分叉，两份各自到不了阈值，降级永远不触发。
#[derive(Debug)]
pub struct DegradeController {
    algorithm: Algorithm,
    degraded: Option<DegradeRecord>,
    /// D3 连续对账失败
    reconcile_streak: u32,
    /// D5 连续块失败
    chunk_streak: u32,
    /// D6 校验失败累计（文档写「失败 > 2 次」，是累计不是连续 ——
    /// 整体校验本来就只在传完后做，没有"中间成功"可复位）
    verify_failures: u32,
}

impl Default for DegradeController {
    fn default() -> Self {
        Self::new()
    }
}

impl DegradeController {
    /// D3 阈值：对账连续失败次数
    pub const RECONCILE_THRESHOLD: u32 = retry::RECONCILE;
    /// D5 阈值：连续块失败次数
    pub const CHUNK_THRESHOLD: u32 = retry::CHUNK_FAIL_DEGRADE;
    /// D6 阈值：文档写「verifying 失败 > 2 次」，即重试额度 +1 次才触发
    pub const VERIFY_THRESHOLD: u32 = retry::VERIFY + 1;

    /// 新会话：从主算法起步
    pub fn new() -> Self {
        Self {
            algorithm: Algorithm::Advanced,
            degraded: None,
            reconcile_streak: 0,
            chunk_streak: 0,
            verify_failures: 0,
        }
    }

    /// 设备级记忆生效时的构造方式：**跳过主算法尝试**（§4.3「设备级降级记忆」）。
    ///
    /// 注意这里 `degraded` 仍为 `None` —— 本次会话不是"降级"来的，
    /// 而是一开始就用基础算法。UI 措辞应区分"已降级"与"按记忆直接用基础模式"。
    pub fn with_preferred_basic() -> Self {
        Self {
            algorithm: Algorithm::Basic,
            ..Self::new()
        }
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn degrade_record(&self) -> Option<&DegradeRecord> {
        self.degraded.as_ref()
    }

    /// 本会话是否已降级（区别于"一开始就用基础算法"）
    pub fn has_degraded(&self) -> bool {
        self.degraded.is_some()
    }

    /// 观测一个信号并给出裁决。
    ///
    /// `state` 是**状态机的当前状态**，由调用方传入而不是控制器自存 —— 见模块文档。
    pub fn observe(
        &mut self,
        signal: DegradeSignal,
        state: TransferState,
        now_unix: u32,
    ) -> DegradeDecision {
        // 会话内不回切：已经是基础算法，任何降级信号都没有意义。
        // 放在最前面是为了让这条不变量**结构上不可绕过** ——
        // 后面所有计数器逻辑都不会执行，也就不可能"降级两次"。
        if self.algorithm == Algorithm::Basic {
            return DegradeDecision::AlreadyBasic;
        }

        // 状态准入必须在**任何计数器被修改之前**判断。
        // 反例（曾被测试抓到）：会话已 Aborted 后到达一个迟到的
        // ChunkRetryExhausted，若先加计数再判状态，计数器就被污染了 ——
        // 一个已定局的会话不该留下任何"离降级还差 2 次"的痕迹。
        if !can_degrade_from(state) {
            return DegradeDecision::Ignored { state };
        }

        match signal {
            // ---------- D1 能力检测 ----------
            DegradeSignal::PeerCapabilities(caps) => {
                if caps.contains(CAP_ADVANCED) {
                    DegradeDecision::Continue {
                        streak: 0,
                        threshold: 0,
                    }
                } else {
                    self.fire(DegradeReason::PeerNoCapability, None, state, now_unix)
                }
            }

            // ---------- D2 初始化失败（一次即降） ----------
            DegradeSignal::InitFailed(detail) => {
                self.fire(DegradeReason::InitFailed, Some(detail), state, now_unix)
            }

            // ---------- D3 对账连续失败 ----------
            DegradeSignal::ReconcileAttemptFailed => {
                self.reconcile_streak += 1;
                if self.reconcile_streak >= Self::RECONCILE_THRESHOLD {
                    self.fire(DegradeReason::ReconcileFailed, None, state, now_unix)
                } else {
                    DegradeDecision::Continue {
                        streak: self.reconcile_streak,
                        threshold: Self::RECONCILE_THRESHOLD,
                    }
                }
            }
            DegradeSignal::ReconcileSucceeded => {
                self.reconcile_streak = 0;
                DegradeDecision::Continue {
                    streak: 0,
                    threshold: Self::RECONCILE_THRESHOLD,
                }
            }

            // ---------- D4 暂停后重试耗尽（一次即降） ----------
            DegradeSignal::PausedRetryExhausted => {
                self.fire(DegradeReason::RetryExhausted, None, state, now_unix)
            }

            // ---------- D5 块连续失败 ----------
            DegradeSignal::ChunkRetryExhausted => {
                self.chunk_streak += 1;
                if self.chunk_streak >= Self::CHUNK_THRESHOLD {
                    self.fire(DegradeReason::ChunkRetryExhausted, None, state, now_unix)
                } else {
                    DegradeDecision::Continue {
                        streak: self.chunk_streak,
                        threshold: Self::CHUNK_THRESHOLD,
                    }
                }
            }
            DegradeSignal::ChunkSucceeded => {
                self.chunk_streak = 0;
                DegradeDecision::Continue {
                    streak: 0,
                    threshold: Self::CHUNK_THRESHOLD,
                }
            }

            // ---------- D6 校验反复失败 ----------
            DegradeSignal::VerifyAttemptFailed => {
                self.verify_failures += 1;
                if self.verify_failures >= Self::VERIFY_THRESHOLD {
                    self.fire(DegradeReason::VerifyFailed, None, state, now_unix)
                } else {
                    DegradeDecision::Continue {
                        streak: self.verify_failures,
                        threshold: Self::VERIFY_THRESHOLD,
                    }
                }
            }
        }
    }

    /// 真正落降级。**唯一**会把 `algorithm` 写成 `Basic` 的地方。
    fn fire(
        &mut self,
        reason: DegradeReason,
        detail: Option<InitFailure>,
        state: TransferState,
        now_unix: u32,
    ) -> DegradeDecision {
        let Some(events) = events_for(reason, state) else {
            // 状态不允许降级（例如对端已断开进了 Aborted）。
            // 关键：**不修改任何内部状态** —— 否则一个迟到的信号
            // 会把已定局的会话标记成"已降级"，UI 显示一个不存在的降级。
            return DegradeDecision::Ignored { state };
        };
        let record = DegradeRecord {
            reason,
            detail,
            from_state: state,
            at_unix: now_unix,
        };
        self.algorithm = Algorithm::Basic;
        self.degraded = Some(record.clone());
        DegradeDecision::Degrade(DegradeAction { record, events })
    }
}

// ============================================================
// 设备级降级记忆（§4.3）
// ============================================================

/// 一次会话对"主算法能不能用"的结论。
///
/// 中间两档最容易被写错：**用户中止 / 对端断开不是算法的错**。
/// 若把它们计入失败，用户连点三次取消就会永久失去主算法，
/// 而且毫无提示 —— 这类"惩罚用户正常操作"的 bug 极难被投诉定位。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOutcome {
    /// 全程主算法且成功 —— 环境是好的，清零连续计数
    AdvancedSucceeded,
    /// 本次发生了降级
    Degraded(DegradeReason),
    /// 本次直接用基础算法（记忆已生效）—— 没有信息量，不计数不清零
    SkippedAdvanced,
    /// 结论不明：用户中止 / 对端断开 / 应用退出 —— 不计数不清零
    Inconclusive,
}

/// 记忆变化，供调用方决定是否要持久化 + 是否要弹提示
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryChange {
    Unchanged,
    /// 连续失败 +1，但还没到阈值
    StreakAdvanced {
        streak: u32,
        threshold: u32,
    },
    /// 连续计数被成功清零
    StreakReset,
    /// 刚刚达到阈值：`prefer_basic` 置位（**需要持久化 + 通知 UI**）
    PreferBasicSet,
    /// 人工恢复：清除记忆
    Cleared,
}

/// 设备级降级记忆。
///
/// # 故意不实现 `Serialize` / `Deserialize` / `JsonSchema`
///
/// §4.3 最后一条：**记忆不持久化到对端**。不给它序列化能力，
/// 就没人能"顺手"把它塞进某个 DTO 发出去。
/// 落本机磁盘请由上层显式取 [`Self::prefer_basic`] 与
/// [`Self::streak`] 两个数存，不要整体序列化。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DegradeMemory {
    /// 连续「有能力但跑不通」的次数
    streak: u32,
    prefer_basic: bool,
}

impl DegradeMemory {
    /// 连续多少次非 D1 降级后置位 `prefer_basic`
    pub const THRESHOLD: u32 = 3;

    pub fn new() -> Self {
        Self::default()
    }

    /// 从持久化的两个字段恢复
    pub fn restore(streak: u32, prefer_basic: bool) -> Self {
        Self {
            streak,
            prefer_basic,
        }
    }

    /// 下次会话是否**跳过**主算法直接用基础算法
    pub fn prefer_basic(&self) -> bool {
        self.prefer_basic
    }

    pub fn streak(&self) -> u32 {
        self.streak
    }

    /// 一次会话结束时登记结论
    pub fn record(&mut self, outcome: SessionOutcome) -> MemoryChange {
        match outcome {
            SessionOutcome::AdvancedSucceeded => {
                // 主算法跑通了 —— 之前的连续失败不再"连续"
                if self.streak == 0 {
                    MemoryChange::Unchanged
                } else {
                    self.streak = 0;
                    MemoryChange::StreakReset
                }
            }
            SessionOutcome::Degraded(reason) => {
                if !reason.counts_toward_memory() {
                    // D1：对端没能力。既不计数，也**不清零** ——
                    // 中间夹一次"换了台老手机"不该抹掉本机环境的失败历史。
                    return MemoryChange::Unchanged;
                }
                if self.prefer_basic {
                    // 已经生效，无需重复置位
                    return MemoryChange::Unchanged;
                }
                self.streak += 1;
                if self.streak >= Self::THRESHOLD {
                    self.prefer_basic = true;
                    MemoryChange::PreferBasicSet
                } else {
                    MemoryChange::StreakAdvanced {
                        streak: self.streak,
                        threshold: Self::THRESHOLD,
                    }
                }
            }
            // 这两档一律不动计数
            SessionOutcome::SkippedAdvanced | SessionOutcome::Inconclusive => {
                MemoryChange::Unchanged
            }
        }
    }

    /// 人工恢复（UI「重新启用主算法」按钮，§4.3）。
    ///
    /// 必须**连计数一起清** —— 只清 `prefer_basic` 会让下一次失败
    /// 立刻又达阈值，按钮形同虚设。
    pub fn clear(&mut self) -> MemoryChange {
        if !self.prefer_basic && self.streak == 0 {
            return MemoryChange::Unchanged;
        }
        self.streak = 0;
        self.prefer_basic = false;
        MemoryChange::Cleared
    }
}

// ============================================================
// 进度处置（§4.2 第 4-5 步 / §4.4 的进度文案）
// ============================================================

/// 降级时已传进度换算到基础算法视角的结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DegradeProgress {
    pub total_blocks: u64,
    /// 可直接跳过的基础块
    pub completed_blocks: u64,
    /// 仍需传输的基础块（含部分完成的）
    pub pending_blocks: u64,
    /// 其中"部分完成但要整块重传"的块数 —— 这些是降级真正的代价，
    /// UI 必须如实说出来，别让用户以为降级是免费的
    pub wasted_blocks: u64,
}

/// 按 §4.2 第 4-5 步换算：已确认 piece → 基础块进度。
///
/// `confirmed_pieces` 必须来自**对端权威位图**（`GET /api/v4/session/diff`），
/// 不能用发送端本地推测 —— 本地以为传成功而对端没落盘，
/// 会把未到达的块算成已完成，降级后直接漏传。
pub fn degrade_progress(confirmed_pieces: &[u64], plan: &ChunkPlan) -> DegradeProgress {
    let confirmed: std::collections::HashSet<u64> = confirmed_pieces.iter().copied().collect();
    let mut completed = 0u64;
    let mut pending = 0u64;
    let mut wasted = 0u64;
    for b in 0..plan.block_count {
        let (first, last) = plan.block_pieces(b);
        if first == last {
            // 空文件 / 末块缩成 0 piece：无需传，算已完成
            completed += 1;
            continue;
        }
        let done = (first..last).filter(|p| confirmed.contains(p)).count() as u64;
        let span = last - first;
        if done == span {
            completed += 1;
        } else {
            pending += 1;
            if done > 0 {
                wasted += 1;
            }
        }
    }
    DegradeProgress {
        total_blocks: plan.block_count,
        completed_blocks: completed,
        pending_blocks: pending,
        wasted_blocks: wasted,
    }
}

// ============================================================
// UI 可见性快照（§4.4）
// ============================================================

/// 供 UI 一次性渲染的降级快照。
///
/// §4.4 要求界面同时给出三样东西：**当前算法、降级原因、已传进度的处置**。
/// 做成一个快照结构体而不是若干 getter，是为了让"漏显示一项"
/// 变成编译期就能发现的字段缺失，而不是上线后才发现少了一行字。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradeVisibility {
    pub algorithm: Algorithm,
    /// 本会话是否由主算法降级而来（false + Basic = 按记忆直接用基础模式）
    pub degraded_this_session: bool,
    /// 机器可读原因码，如 `INIT_FAILED:MERKLE_BUILD`
    pub reason_code: Option<String>,
    /// 人可读原因
    pub reason_text: Option<String>,
    pub at_unix: Option<u32>,
    pub progress: Option<DegradeProgress>,
    /// 是否显示「重新启用主算法」按钮（= 设备级记忆生效）
    pub show_reenable_advanced: bool,
}

impl DegradeVisibility {
    /// 组装快照。
    ///
    /// `progress` 传 `None` 表示尚无可换算的进度（例如 preparing 阶段就降级了）。
    pub fn new(
        controller: &DegradeController,
        memory: &DegradeMemory,
        progress: Option<DegradeProgress>,
    ) -> Self {
        let rec = controller.degrade_record();
        Self {
            algorithm: controller.algorithm(),
            degraded_this_session: rec.is_some(),
            reason_code: rec.map(|r| r.code()),
            reason_text: rec.map(|r| r.text()),
            at_unix: rec.map(|r| r.at_unix),
            progress,
            show_reenable_advanced: memory.prefer_basic(),
        }
    }

    /// §4.4 示意框里的那句进度文案
    pub fn progress_text(&self) -> Option<String> {
        let p = self.progress?;
        Some(format!(
            "已用主算法完成 {}/{} 块，将重传 {} 块",
            p.completed_blocks, p.total_blocks, p.wasted_blocks
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u32 = 1_700_000_000;

    fn advanced_caps() -> Capabilities {
        Capabilities::all()
    }

    fn old_peer_caps() -> Capabilities {
        Capabilities::all().without(CAP_ADVANCED)
    }

    // ---------- D1 ----------

    #[test]
    fn d1_peer_without_advanced_degrades_at_preparing() {
        let mut c = DegradeController::new();
        let d = c.observe(
            DegradeSignal::PeerCapabilities(old_peer_caps()),
            TransferState::Preparing,
            T,
        );
        let a = d.action().expect("应降级");
        assert_eq!(a.record.reason, DegradeReason::PeerNoCapability);
        assert_eq!(a.record.code(), "PEER_NO_CAPABILITY");
        // 文档 §4.1：preparing → transferring(basic)，一步到位
        assert_eq!(a.events, &[TransferEvent::NegotiateBasic]);
        assert_eq!(c.algorithm(), Algorithm::Basic);
    }

    #[test]
    fn d1_capable_peer_does_not_degrade() {
        let mut c = DegradeController::new();
        let d = c.observe(
            DegradeSignal::PeerCapabilities(advanced_caps()),
            TransferState::Preparing,
            T,
        );
        assert!(!d.is_degrade());
        assert_eq!(c.algorithm(), Algorithm::Advanced);
    }

    // ---------- D2 ----------

    #[test]
    fn d2_init_failure_degrades_immediately_and_keeps_detail() {
        for f in [
            InitFailure::MerkleBuild,
            InitFailure::KeyDerivation,
            InitFailure::DiffEndpoint,
            InitFailure::OutOfMemory,
        ] {
            let mut c = DegradeController::new();
            let d = c.observe(DegradeSignal::InitFailed(f), TransferState::Preparing, T);
            let a = d.action().expect("初始化失败必须一次即降");
            assert_eq!(a.record.detail, Some(f));
            // 根因不能被吞掉：原因码必须带 detail
            assert_eq!(a.record.code(), format!("INIT_FAILED:{}", f.detail()));
            assert!(a.record.text().contains(f.text()));
        }
    }

    // ---------- D3 ----------

    #[test]
    fn d3_reconcile_degrades_exactly_at_threshold() {
        let mut c = DegradeController::new();
        for i in 1..DegradeController::RECONCILE_THRESHOLD {
            let d = c.observe(
                DegradeSignal::ReconcileAttemptFailed,
                TransferState::Reconciling,
                T,
            );
            assert_eq!(
                d,
                DegradeDecision::Continue {
                    streak: i,
                    threshold: DegradeController::RECONCILE_THRESHOLD
                },
                "第 {i} 次失败不应降级"
            );
        }
        let d = c.observe(
            DegradeSignal::ReconcileAttemptFailed,
            TransferState::Reconciling,
            T,
        );
        let a = d.action().expect("达到阈值必须降级");
        assert_eq!(a.record.reason, DegradeReason::ReconcileFailed);
        assert_eq!(
            a.events,
            &[
                TransferEvent::ReconcileFailed,
                TransferEvent::DegradeComplete
            ]
        );
    }

    #[test]
    fn d3_success_resets_streak_so_sporadic_failures_never_accumulate() {
        let mut c = DegradeController::new();
        // 失败-成功交替 100 轮，永远不该降级
        for _ in 0..100 {
            c.observe(
                DegradeSignal::ReconcileAttemptFailed,
                TransferState::Reconciling,
                T,
            );
            c.observe(
                DegradeSignal::ReconcileAttemptFailed,
                TransferState::Reconciling,
                T,
            );
            let d = c.observe(
                DegradeSignal::ReconcileSucceeded,
                TransferState::Reconciling,
                T,
            );
            assert!(!d.is_degrade());
        }
        assert_eq!(c.algorithm(), Algorithm::Advanced);
    }

    // ---------- D4 ----------

    #[test]
    fn d4_paused_retry_exhausted_degrades_from_paused() {
        let mut c = DegradeController::new();
        let d = c.observe(
            DegradeSignal::PausedRetryExhausted,
            TransferState::Paused,
            T,
        );
        let a = d.action().expect("应降级");
        assert_eq!(a.record.reason, DegradeReason::RetryExhausted);
        assert_eq!(
            a.events,
            &[TransferEvent::Degrade, TransferEvent::DegradeComplete]
        );
    }

    // ---------- D5 ----------

    #[test]
    fn d5_chunk_degrades_exactly_at_threshold() {
        let mut c = DegradeController::new();
        for _ in 1..DegradeController::CHUNK_THRESHOLD {
            let d = c.observe(
                DegradeSignal::ChunkRetryExhausted,
                TransferState::Transferring,
                T,
            );
            assert!(!d.is_degrade());
        }
        let d = c.observe(
            DegradeSignal::ChunkRetryExhausted,
            TransferState::Transferring,
            T,
        );
        let a = d.action().expect("连续块失败达阈值必须降级");
        assert_eq!(a.record.reason, DegradeReason::ChunkRetryExhausted);
        assert_eq!(
            a.events,
            &[
                TransferEvent::ChunkRetryExhausted,
                TransferEvent::DegradeComplete
            ]
        );
    }

    #[test]
    fn d5_chunk_success_resets_streak() {
        let mut c = DegradeController::new();
        c.observe(
            DegradeSignal::ChunkRetryExhausted,
            TransferState::Transferring,
            T,
        );
        c.observe(
            DegradeSignal::ChunkRetryExhausted,
            TransferState::Transferring,
            T,
        );
        c.observe(
            DegradeSignal::ChunkSucceeded,
            TransferState::Transferring,
            T,
        );
        let d = c.observe(
            DegradeSignal::ChunkRetryExhausted,
            TransferState::Transferring,
            T,
        );
        assert!(!d.is_degrade(), "复位后计数应从 1 重新开始");
    }

    // ---------- D6 ----------

    #[test]
    fn d6_verify_degrades_after_more_than_retry_budget() {
        // 文档：verifying 失败 > 2 次 → 第 3 次才降级
        assert_eq!(DegradeController::VERIFY_THRESHOLD, 3);
        let mut c = DegradeController::new();
        assert!(!c
            .observe(
                DegradeSignal::VerifyAttemptFailed,
                TransferState::Verifying,
                T
            )
            .is_degrade());
        assert!(!c
            .observe(
                DegradeSignal::VerifyAttemptFailed,
                TransferState::Verifying,
                T
            )
            .is_degrade());
        let d = c.observe(
            DegradeSignal::VerifyAttemptFailed,
            TransferState::Verifying,
            T,
        );
        let a = d.action().expect("第 3 次校验失败必须降级");
        assert_eq!(a.record.reason, DegradeReason::VerifyFailed);
        assert_eq!(
            a.events,
            &[TransferEvent::VerifyFailed, TransferEvent::DegradeComplete]
        );
    }

    // ---------- 不变量：会话内不回切 ----------

    #[test]
    fn session_never_reverts_to_advanced() {
        let mut c = DegradeController::new();
        c.observe(
            DegradeSignal::PausedRetryExhausted,
            TransferState::Paused,
            T,
        );
        assert_eq!(c.algorithm(), Algorithm::Basic);
        // 之后即便对端报告"我有主算法能力"，也绝不回切
        let d = c.observe(
            DegradeSignal::PeerCapabilities(advanced_caps()),
            TransferState::Transferring,
            T,
        );
        assert_eq!(d, DegradeDecision::AlreadyBasic);
        assert_eq!(c.algorithm(), Algorithm::Basic);
    }

    #[test]
    fn only_first_degrade_is_recorded() {
        let mut c = DegradeController::new();
        c.observe(
            DegradeSignal::InitFailed(InitFailure::OutOfMemory),
            TransferState::Preparing,
            T,
        );
        let first = c.degrade_record().cloned().unwrap();
        // 后续任何信号都不该改写"第一次降级"的原因与时间戳
        for s in [
            DegradeSignal::ReconcileAttemptFailed,
            DegradeSignal::ChunkRetryExhausted,
            DegradeSignal::VerifyAttemptFailed,
            DegradeSignal::PausedRetryExhausted,
        ] {
            assert_eq!(
                c.observe(s, TransferState::Transferring, T + 999),
                DegradeDecision::AlreadyBasic
            );
        }
        assert_eq!(c.degrade_record().unwrap(), &first);
    }

    #[test]
    fn preferred_basic_controller_absorbs_everything_without_claiming_degrade() {
        let mut c = DegradeController::with_preferred_basic();
        assert_eq!(c.algorithm(), Algorithm::Basic);
        let d = c.observe(
            DegradeSignal::ChunkRetryExhausted,
            TransferState::Transferring,
            T,
        );
        assert_eq!(d, DegradeDecision::AlreadyBasic);
        // 关键：不是"降级"来的，UI 不该显示降级原因
        assert!(!c.has_degraded());
        assert!(c.degrade_record().is_none());
    }

    // ---------- 迟到信号不得污染已定局会话 ----------

    #[test]
    fn late_signal_after_settled_is_ignored_and_changes_nothing() {
        for state in [
            TransferState::Idle,
            TransferState::Completed,
            TransferState::Failed,
            TransferState::Aborted,
        ] {
            let mut c = DegradeController::new();
            let d = c.observe(DegradeSignal::ChunkRetryExhausted, state, T);
            assert_eq!(d, DegradeDecision::Ignored { state });
            assert_eq!(
                c.algorithm(),
                Algorithm::Advanced,
                "{state:?} 下的迟到信号不得把会话标记成已降级"
            );
            assert!(!c.has_degraded());
        }
    }

    #[test]
    fn ignored_signals_do_not_pollute_the_streak_counters() {
        let mut c = DegradeController::new();
        // 会话已中止后到达一批迟到的块失败信号
        for _ in 0..10 {
            assert_eq!(
                c.observe(
                    DegradeSignal::ChunkRetryExhausted,
                    TransferState::Aborted,
                    T
                ),
                DegradeDecision::Ignored {
                    state: TransferState::Aborted
                }
            );
        }
        // 之后在合法状态下仍需完整阈值才降级 —— 计数器没被污染
        for _ in 1..DegradeController::CHUNK_THRESHOLD {
            assert!(!c
                .observe(
                    DegradeSignal::ChunkRetryExhausted,
                    TransferState::Transferring,
                    T
                )
                .is_degrade());
        }
        assert!(c
            .observe(
                DegradeSignal::ChunkRetryExhausted,
                TransferState::Transferring,
                T
            )
            .is_degrade());
    }

    #[test]
    fn state_admissibility_matches_event_table() {
        // can_degrade_from 与 events_for 是同一事实的两种表达，必须永远一致
        let states = [
            TransferState::Idle,
            TransferState::Preparing,
            TransferState::Reconciling,
            TransferState::Transferring,
            TransferState::Paused,
            TransferState::Degrading,
            TransferState::Verifying,
            TransferState::Completed,
            TransferState::Failed,
            TransferState::Aborted,
        ];
        let reasons = [
            DegradeReason::PeerNoCapability,
            DegradeReason::InitFailed,
            DegradeReason::ReconcileFailed,
            DegradeReason::RetryExhausted,
            DegradeReason::ChunkRetryExhausted,
            DegradeReason::VerifyFailed,
        ];
        for s in states {
            for r in reasons {
                assert_eq!(
                    can_degrade_from(s),
                    events_for(r, s).is_some(),
                    "{r:?}@{s:?}：准入判断与事件表不一致"
                );
            }
        }
    }

    #[test]
    fn all_event_tables_are_legal_paths_to_basic_transferring() {
        // 穷举：事件表里每一条路径都必须能真的把状态机带到 Transferring
        let states = [
            TransferState::Preparing,
            TransferState::Reconciling,
            TransferState::Transferring,
            TransferState::Paused,
            TransferState::Verifying,
        ];
        let reasons = [
            DegradeReason::PeerNoCapability,
            DegradeReason::InitFailed,
            DegradeReason::ReconcileFailed,
            DegradeReason::RetryExhausted,
            DegradeReason::ChunkRetryExhausted,
            DegradeReason::VerifyFailed,
        ];
        for from in states {
            for r in reasons {
                let evs = events_for(r, from).expect("可降级状态必须有事件表");
                let mut s = from;
                for ev in evs {
                    s = s
                        .transition(*ev)
                        .unwrap_or_else(|e| panic!("{r:?}@{from:?} 事件 {ev:?} 非法：{e:?}"));
                }
                assert_eq!(
                    s,
                    TransferState::Transferring,
                    "{r:?}@{from:?} 未到达传输态"
                );
            }
        }
    }

    #[test]
    fn signal_while_already_degrading_is_ignored() {
        let mut c = DegradeController::new();
        let d = c.observe(
            DegradeSignal::InitFailed(InitFailure::MerkleBuild),
            TransferState::Degrading,
            T,
        );
        assert_eq!(
            d,
            DegradeDecision::Ignored {
                state: TransferState::Degrading
            }
        );
        assert!(!c.has_degraded());
    }

    // ---------- 事件序列必须真的能跑通状态机 ----------

    #[test]
    fn every_degrade_action_reaches_transferring_through_real_state_machine() {
        // 「按钮可点但状态机走不通」是换皮的静默失败（登记表 S16）：
        // 这里把控制器输出的事件序列真的喂进状态机验证可达。
        let cases: &[(DegradeSignal, TransferState)] = &[
            (
                DegradeSignal::PeerCapabilities(Capabilities::empty()),
                TransferState::Preparing,
            ),
            (
                DegradeSignal::InitFailed(InitFailure::MerkleBuild),
                TransferState::Preparing,
            ),
            (
                DegradeSignal::InitFailed(InitFailure::DiffEndpoint),
                TransferState::Reconciling,
            ),
            (DegradeSignal::PausedRetryExhausted, TransferState::Paused),
        ];
        for (sig, from) in cases {
            let mut c = DegradeController::new();
            let d = c.observe(*sig, *from, T);
            let a = d
                .action()
                .unwrap_or_else(|| panic!("{sig:?}@{from:?} 应降级"));
            let mut s = *from;
            for ev in a.events {
                s = s
                    .transition(*ev)
                    .unwrap_or_else(|e| panic!("{sig:?}@{from:?} 事件 {ev:?} 非法：{e:?}"));
            }
            assert_eq!(
                s,
                TransferState::Transferring,
                "{sig:?}@{from:?} 的事件序列应把状态机带到 Transferring"
            );
        }
    }

    #[test]
    fn threshold_degrade_actions_also_reach_transferring() {
        // D3 / D5 / D6 需要先喂满阈值
        let cases: &[(DegradeSignal, TransferState, u32)] = &[
            (
                DegradeSignal::ReconcileAttemptFailed,
                TransferState::Reconciling,
                DegradeController::RECONCILE_THRESHOLD,
            ),
            (
                DegradeSignal::ChunkRetryExhausted,
                TransferState::Transferring,
                DegradeController::CHUNK_THRESHOLD,
            ),
            (
                DegradeSignal::VerifyAttemptFailed,
                TransferState::Verifying,
                DegradeController::VERIFY_THRESHOLD,
            ),
        ];
        for (sig, from, n) in cases {
            let mut c = DegradeController::new();
            let mut action = None;
            for _ in 0..*n {
                if let DegradeDecision::Degrade(a) = c.observe(*sig, *from, T) {
                    action = Some(a);
                }
            }
            let a = action.unwrap_or_else(|| panic!("{sig:?} 喂满 {n} 次应降级"));
            let mut s = *from;
            for ev in a.events {
                s = s
                    .transition(*ev)
                    .unwrap_or_else(|e| panic!("{sig:?}@{from:?} 事件 {ev:?} 非法：{e:?}"));
            }
            assert_eq!(s, TransferState::Transferring);
        }
    }

    // ---------- 设备级记忆 ----------

    #[test]
    fn memory_sets_prefer_basic_after_three_environmental_failures() {
        let mut m = DegradeMemory::new();
        assert!(!m.prefer_basic());
        assert_eq!(
            m.record(SessionOutcome::Degraded(DegradeReason::InitFailed)),
            MemoryChange::StreakAdvanced {
                streak: 1,
                threshold: 3
            }
        );
        assert_eq!(
            m.record(SessionOutcome::Degraded(DegradeReason::ReconcileFailed)),
            MemoryChange::StreakAdvanced {
                streak: 2,
                threshold: 3
            }
        );
        assert_eq!(
            m.record(SessionOutcome::Degraded(DegradeReason::VerifyFailed)),
            MemoryChange::PreferBasicSet
        );
        assert!(m.prefer_basic());
        // 已生效后不再重复置位
        assert_eq!(
            m.record(SessionOutcome::Degraded(DegradeReason::ChunkRetryExhausted)),
            MemoryChange::Unchanged
        );
    }

    #[test]
    fn d1_neither_counts_nor_clears_the_streak() {
        let mut m = DegradeMemory::new();
        m.record(SessionOutcome::Degraded(DegradeReason::InitFailed));
        m.record(SessionOutcome::Degraded(DegradeReason::InitFailed));
        assert_eq!(m.streak(), 2);
        // 中间连了一台老设备：不计数
        assert_eq!(
            m.record(SessionOutcome::Degraded(DegradeReason::PeerNoCapability)),
            MemoryChange::Unchanged
        );
        // 也不清零 —— 本机环境的失败历史不该被"换了台老手机"抹掉
        assert_eq!(m.streak(), 2);
        assert!(!m.prefer_basic());
    }

    #[test]
    fn d1_alone_never_sets_prefer_basic() {
        let mut m = DegradeMemory::new();
        for _ in 0..50 {
            m.record(SessionOutcome::Degraded(DegradeReason::PeerNoCapability));
        }
        assert!(
            !m.prefer_basic(),
            "对端没能力是稳定原因，升级后自然恢复，不该记进记忆"
        );
        assert_eq!(m.streak(), 0);
    }

    #[test]
    fn user_abort_and_peer_loss_must_not_disable_advanced() {
        // 若把中止/断连计入失败，用户连点三次取消就永久失去主算法
        let mut m = DegradeMemory::new();
        for _ in 0..10 {
            assert_eq!(
                m.record(SessionOutcome::Inconclusive),
                MemoryChange::Unchanged
            );
        }
        assert!(!m.prefer_basic());
        assert_eq!(m.streak(), 0);
    }

    #[test]
    fn skipped_advanced_sessions_do_not_reinforce_memory() {
        // 记忆生效后每次都走 basic；若这些会话继续计数，
        // 记忆会自我强化成永久状态，人工恢复也难以摆脱
        let mut m = DegradeMemory::restore(2, false);
        for _ in 0..10 {
            assert_eq!(
                m.record(SessionOutcome::SkippedAdvanced),
                MemoryChange::Unchanged
            );
        }
        assert_eq!(m.streak(), 2);
    }

    #[test]
    fn success_resets_streak() {
        let mut m = DegradeMemory::new();
        m.record(SessionOutcome::Degraded(DegradeReason::InitFailed));
        m.record(SessionOutcome::Degraded(DegradeReason::InitFailed));
        assert_eq!(
            m.record(SessionOutcome::AdvancedSucceeded),
            MemoryChange::StreakReset
        );
        assert_eq!(m.streak(), 0);
        // 已归零时重复成功不产生变化事件（避免无意义的持久化写盘）
        assert_eq!(
            m.record(SessionOutcome::AdvancedSucceeded),
            MemoryChange::Unchanged
        );
    }

    #[test]
    fn manual_clear_also_zeroes_streak() {
        let mut m = DegradeMemory::new();
        for _ in 0..3 {
            m.record(SessionOutcome::Degraded(DegradeReason::ChunkRetryExhausted));
        }
        assert!(m.prefer_basic());
        assert_eq!(m.clear(), MemoryChange::Cleared);
        assert!(!m.prefer_basic());
        assert_eq!(
            m.streak(),
            0,
            "只清 prefer_basic 不清计数，下一次失败会立刻又达阈值，按钮形同虚设"
        );
        // 清干净后再失败一次，只是 streak=1
        assert_eq!(
            m.record(SessionOutcome::Degraded(DegradeReason::ChunkRetryExhausted)),
            MemoryChange::StreakAdvanced {
                streak: 1,
                threshold: 3
            }
        );
    }

    #[test]
    fn clear_on_fresh_memory_is_a_noop() {
        let mut m = DegradeMemory::new();
        assert_eq!(m.clear(), MemoryChange::Unchanged);
    }

    // ---------- 进度换算 ----------

    #[test]
    fn progress_counts_completed_pending_and_wasted_blocks() {
        // 10 个 piece = 3 个基础块（4+4+2）
        let plan = ChunkPlan::new(10 * crate::transfer::PIECE_SIZE, Algorithm::Advanced);
        assert_eq!(plan.piece_count, 10);
        assert_eq!(plan.block_count, 3);
        // 块0 全齐；块1 只齐一半（白传）；块2 一个没传
        let p = degrade_progress(&[0, 1, 2, 3, 4, 5], &plan);
        assert_eq!(p.total_blocks, 3);
        assert_eq!(p.completed_blocks, 1);
        assert_eq!(p.pending_blocks, 2);
        assert_eq!(p.wasted_blocks, 1, "块1 已传 2 个 piece，降级后要整块重传");
    }

    #[test]
    fn progress_with_nothing_confirmed_wastes_nothing() {
        let plan = ChunkPlan::new(10 * crate::transfer::PIECE_SIZE, Algorithm::Advanced);
        let p = degrade_progress(&[], &plan);
        assert_eq!(p.completed_blocks, 0);
        assert_eq!(p.pending_blocks, 3);
        assert_eq!(p.wasted_blocks, 0);
    }

    #[test]
    fn progress_fully_confirmed_has_no_pending() {
        let plan = ChunkPlan::new(10 * crate::transfer::PIECE_SIZE, Algorithm::Advanced);
        let all: Vec<u64> = (0..10).collect();
        let p = degrade_progress(&all, &plan);
        assert_eq!(p.completed_blocks, 3);
        assert_eq!(p.pending_blocks, 0);
        assert_eq!(p.wasted_blocks, 0);
    }

    #[test]
    fn progress_agrees_with_chunk_module_degrade_plan() {
        // 两条换算路径必须一致，否则 UI 显示的进度和真实重传计划打架
        let plan = ChunkPlan::new(23 * crate::transfer::PIECE_SIZE + 1234, Algorithm::Advanced);
        let confirmed: Vec<u64> = vec![0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 20];
        let a = crate::transfer::degrade_from_pieces(&confirmed, &plan);
        let b = degrade_progress(&confirmed, &plan);
        assert_eq!(a.completed_blocks.len() as u64, b.completed_blocks);
        assert_eq!(a.pending_blocks.len() as u64, b.pending_blocks);
    }

    // ---------- UI 可见性 ----------

    #[test]
    fn visibility_shows_algorithm_reason_and_progress_together() {
        let mut c = DegradeController::new();
        for _ in 0..DegradeController::CHUNK_THRESHOLD {
            c.observe(
                DegradeSignal::ChunkRetryExhausted,
                TransferState::Transferring,
                T,
            );
        }
        let m = DegradeMemory::new();
        let plan = ChunkPlan::new(10 * crate::transfer::PIECE_SIZE, Algorithm::Advanced);
        let prog = degrade_progress(&[0, 1, 2, 3, 4, 5], &plan);
        let v = DegradeVisibility::new(&c, &m, Some(prog));

        assert_eq!(v.algorithm, Algorithm::Basic);
        assert!(v.degraded_this_session);
        assert_eq!(v.reason_code.as_deref(), Some("CHUNK_RETRY_EXHAUSTED"));
        assert_eq!(v.reason_text.as_deref(), Some("数据块连续失败"));
        assert_eq!(v.at_unix, Some(T));
        assert_eq!(
            v.progress_text().as_deref(),
            Some("已用主算法完成 1/3 块，将重传 1 块")
        );
        // 记忆未生效 → 不显示恢复按钮
        assert!(!v.show_reenable_advanced);
    }

    #[test]
    fn visibility_reenable_button_follows_memory_only() {
        // §3.4：「重新启用主算法」只取决于设备级记忆，与本次会话是否降级无关
        let c = DegradeController::new();
        let mut m = DegradeMemory::new();
        assert!(!DegradeVisibility::new(&c, &m, None).show_reenable_advanced);
        for _ in 0..3 {
            m.record(SessionOutcome::Degraded(DegradeReason::InitFailed));
        }
        let v = DegradeVisibility::new(&c, &m, None);
        assert!(v.show_reenable_advanced);
        assert!(
            !v.degraded_this_session,
            "本次会话没降级，但按钮仍应出现 —— 二者是不同的事实"
        );
    }

    #[test]
    fn visibility_distinguishes_degraded_from_preferred_basic() {
        let c = DegradeController::with_preferred_basic();
        let m = DegradeMemory::restore(3, true);
        let v = DegradeVisibility::new(&c, &m, None);
        assert_eq!(v.algorithm, Algorithm::Basic);
        assert!(
            !v.degraded_this_session,
            "按记忆直接用基础模式，不是本次降级 —— UI 措辞必须不同"
        );
        assert!(v.reason_code.is_none());
        assert!(v.show_reenable_advanced);
    }

    // ---------- 原因码 / 文案 ----------

    #[test]
    fn every_reason_has_distinct_code_and_nonempty_text() {
        let all = [
            DegradeReason::PeerNoCapability,
            DegradeReason::InitFailed,
            DegradeReason::ReconcileFailed,
            DegradeReason::RetryExhausted,
            DegradeReason::ChunkRetryExhausted,
            DegradeReason::VerifyFailed,
        ];
        let mut codes: Vec<&str> = all.iter().map(|r| r.code()).collect();
        codes.sort_unstable();
        let n = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), n, "原因码必须互不相同");
        for r in all {
            assert!(!r.text().is_empty(), "{r:?} 缺少可读文案");
            assert!(
                r.code().chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                "{r:?} 原因码应为 SCREAMING_SNAKE_CASE"
            );
        }
    }

    #[test]
    fn only_peer_no_capability_is_excluded_from_memory() {
        assert!(!DegradeReason::PeerNoCapability.counts_toward_memory());
        for r in [
            DegradeReason::InitFailed,
            DegradeReason::ReconcileFailed,
            DegradeReason::RetryExhausted,
            DegradeReason::ChunkRetryExhausted,
            DegradeReason::VerifyFailed,
        ] {
            assert!(r.counts_toward_memory(), "{r:?} 应计入设备级记忆");
        }
    }

    #[test]
    fn thresholds_come_from_the_shared_constant_source() {
        // 阈值只能有一处定义，改文档 §2.4 时必须同步改 version::retry
        assert_eq!(DegradeController::RECONCILE_THRESHOLD, retry::RECONCILE);
        assert_eq!(
            DegradeController::CHUNK_THRESHOLD,
            retry::CHUNK_FAIL_DEGRADE
        );
        assert_eq!(DegradeController::VERIFY_THRESHOLD, retry::VERIFY + 1);
        assert_eq!(DegradeController::RECONCILE_THRESHOLD, 3);
        assert_eq!(DegradeController::CHUNK_THRESHOLD, 3);
    }
}
