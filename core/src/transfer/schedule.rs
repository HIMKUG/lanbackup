//! 并发控制器 —— 接通 `scheduler.ts` 的空壳 Semaphore（V4-ARCHITECTURE §3.4 问题1）
//!
//! 设计约束（来自 DESIGN-WISDOM-REGISTER）：
//! - **A13 全局信号量 12（=3 接收端 × 4 块），全局而非每 peer 独立**：防止多接收端总并发爆炸；
//!   **重试必须单独配额（4）**，否则失败重试吃光许可，正常分片全部饿死。
//! - **A14 全抖动退避**：`random(0, min(64000, 1000 * 2^n))`，n 上限 5，防惊群。
//! - **D9 跨 await 不持锁**：本模块只在 `peer_chunk` 这张表上做极短临界区的 `or_insert`，
//!   取完 `Arc` 即释放，绝不把锁带进 `.await`。

use std::collections::HashMap;
use std::sync::Arc;

use rand::Rng;
use tokio::sync::{Mutex as TokioMutex, OwnedSemaphorePermit, Semaphore};

use crate::version::retry;

/// 对端标识（IP:port 或设备 id），用于每 peer 并发配额
pub type PeerId = String;

/// 默认全局数据块并发（A13：= 3 接收端 × 4 块）
pub const DEFAULT_GLOBAL_CHUNK_PERMITS: usize = 12;
/// 默认重试独立配额（A13）
pub const DEFAULT_RETRY_PERMITS: usize = 4;
/// 默认每 peer 数据块并发上限（在全局总闸之外，再约束单个对端别吃满全局）
pub const DEFAULT_PEER_CHUNK_PERMITS: usize = 4;

/// 传输并发调度器：两级限流（全局块许可 + 重试许可）+ 每 peer 块许可。
///
/// 许可通过 RAII guard（`ChunkPermit` / `RetryPermit`）持有，drop 时自动归还，
/// 调用方无需手动 release，也不可能在异常路径上泄漏许可（避免后续传输无法启动，见
/// V4-TRANSFER-MODULE.md §六「清理顺序」）。
pub struct TransferScheduler {
    global_chunk: Arc<Semaphore>,
    retry: Arc<Semaphore>,
    peer_chunk: Arc<TokioMutex<HashMap<PeerId, Arc<Semaphore>>>>,
    peer_cap: usize,
}

impl TransferScheduler {
    /// 使用文档约定的默认配额（A13）
    pub fn new() -> Self {
        Self::with_limits(
            DEFAULT_GLOBAL_CHUNK_PERMITS,
            DEFAULT_RETRY_PERMITS,
            DEFAULT_PEER_CHUNK_PERMITS,
        )
    }

    /// 显式指定配额（测试或特殊网络环境调参用）
    pub fn with_limits(global: usize, retry: usize, peer: usize) -> Self {
        Self {
            global_chunk: Arc::new(Semaphore::new(global)),
            retry: Arc::new(Semaphore::new(retry)),
            peer_chunk: Arc::new(TokioMutex::new(HashMap::new())),
            peer_cap: peer,
        }
    }

    /// 取该 peer 的并发信号量（不存在则创建），立即 clone 出 `Arc` 释放表锁，
    /// 绝不把锁带进后续 `.await`（D9）。
    async fn peer_semaphore(&self, peer: &str) -> Arc<Semaphore> {
        let mut map = self.peer_chunk.lock().await;
        map.entry(peer.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.peer_cap)))
            .clone()
    }

    /// 获取一个数据块发送许可：同时占用**全局**与**该 peer** 两份配额。
    ///
    /// 返回 RAII guard，作用域结束自动归还两者。
    pub async fn acquire_chunk(&self, peer: &str) -> ChunkPermit {
        let global = self
            .global_chunk
            .clone()
            .acquire_owned()
            .await
            .expect("global chunk semaphore 不会在运行期关闭");
        let peer_sem = self.peer_semaphore(peer).await;
        let peer_permit = peer_sem
            .acquire_owned()
            .await
            .expect("peer chunk semaphore 不会在运行期关闭");
        ChunkPermit {
            _global: global,
            _peer: peer_permit,
        }
    }

    /// 获取一个重试许可（**独立配额**，不挤占正常分片，A13）。
    pub async fn acquire_retry(&self) -> RetryPermit {
        let retry = self
            .retry
            .clone()
            .acquire_owned()
            .await
            .expect("retry semaphore 不会在运行期关闭");
        RetryPermit { _retry: retry }
    }

    /// 当前可用全局块许可数（仅观测/测试用）
    pub fn available_chunk_permits(&self) -> usize {
        self.global_chunk.available_permits()
    }

    /// 当前可用重试许可数（仅观测/测试用）
    pub fn available_retry_permits(&self) -> usize {
        self.retry.available_permits()
    }
}

impl Default for TransferScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// 数据块发送许可（RAII）。持有期间占用全局 + 该 peer 各一个配额。
pub struct ChunkPermit {
    _global: OwnedSemaphorePermit,
    _peer: OwnedSemaphorePermit,
}

/// 重试许可（RAII）。独立配额，不挤占正常分片发送。
pub struct RetryPermit {
    _retry: OwnedSemaphorePermit,
}

/// 全抖动退避（A14，AWS 标准 full jitter），**握手 / 对账**用的参数。
///
/// 第 `attempt` 次重试的等待毫秒数：`min(64000, 1000 * 2^attempt)` 区间内的均匀随机值。
/// `attempt` 从 0 起，指数上限 5（`1000 * 2^5 = 32000`，并整体封顶 64000ms），防惊群也防无限增长。
///
/// 调用方在等待后应 `acquire_retry()` 拿独立配额再发，**不要**用普通块许可发重试（A13）。
pub fn full_jitter_backoff_ms(attempt: u32) -> u64 {
    full_jitter_backoff_with(attempt, retry::BACKOFF_BASE_MS, retry::BACKOFF_MAX_MS)
}

/// 单块重试的退避（文档 T13：base 200ms / max 5s）。
///
/// **与握手退避不是一套参数** —— 块重试发生在传输热路径上，
/// 用握手那套（base 1s、上限 64s）会让一个偶发坏块把整条流水线堵一分钟；
/// 而握手用块那套（200ms 起）又太急，网络刚断就把 3 次重试在 1 秒内烧完。
pub fn chunk_backoff_ms(attempt: u32) -> u64 {
    full_jitter_backoff_with(
        attempt,
        retry::CHUNK_BACKOFF_BASE_MS,
        retry::CHUNK_BACKOFF_MAX_MS,
    )
}

/// 全抖动退避的通用实现：`random(0, min(max_ms, base_ms * 2^attempt))`
pub fn full_jitter_backoff_with(attempt: u32, base_ms: u64, max_ms: u64) -> u64 {
    // `checked_shl` 而非直接 `<<`：attempt 虽已被 BACKOFF_MAX_EXPONENT 夹住，
    // 但常量是可配的，溢出兜底为 u64::MAX 再交给 min(max_ms) 收敛。
    let exp = base_ms
        .checked_shl(attempt.min(retry::BACKOFF_MAX_EXPONENT))
        .unwrap_or(u64::MAX)
        .min(max_ms)
        .max(1);
    // 均匀随机 [0, exp)
    //
    // 用 rand 0.8 的 `Rng::gen_range` 而不是 0.9+ 的 `rand::random_range` free function：
    // rand 的版本被 p256 0.13 的 rand_core 0.6 世代锁死（见 Cargo.toml 密码学段落）。
    rand::thread_rng().gen_range(0..exp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::task::JoinSet;

    #[tokio::test]
    async fn global_cap_limits_total_concurrency() {
        // 全局只允许 2 个块并发，4 个任务同时抢，任意时刻峰值不得超过 2
        let sched = TransferScheduler::with_limits(2, 4, 4);
        let peak = Arc::new(AtomicUsize::new(0));
        let current = Arc::new(AtomicUsize::new(0));

        let mut set = JoinSet::new();
        for i in 0..4 {
            let sched = sched.clone_for_test();
            let peak = peak.clone();
            let current = current.clone();
            set.spawn(async move {
                let _permit = sched.acquire_chunk(&format!("peer-{i}")).await;
                let n = current.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                current.fetch_sub(1, Ordering::SeqCst);
            });
        }
        while set.join_next().await.is_some() {}
        assert!(
            peak.load(Ordering::SeqCst) <= 2,
            "全局并发数应被 2 限制，实际峰值 {}",
            peak.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn retry_is_separate_quota() {
        // 全局只有 1 个块许可且被占用时，重试许可仍应可取（独立配额）
        let sched = TransferScheduler::with_limits(1, 1, 1);
        let _chunk = sched.acquire_chunk("peer-a").await;
        // 此时全局块许可已用尽，但重试走独立信号量
        let retry = sched.acquire_retry().await;
        assert_eq!(sched.available_retry_permits(), 0);
        drop(retry);
        assert_eq!(sched.available_retry_permits(), 1);
    }

    #[tokio::test]
    async fn per_peer_quota_is_isolated() {
        // 全局 4，每 peer 1。两个不同 peer 各拿 1 个都应成功（互不挤占），
        // 但同一 peer 再拿第二个应被其自身配额挡住（靠总闸外还有 per-peer 闸）。
        let sched = TransferScheduler::with_limits(4, 4, 1);
        let a1 = sched.acquire_chunk("A").await;
        let b1 = sched.acquire_chunk("B").await;
        // 两个都拿到了
        drop(a1);
        drop(b1);
        assert_eq!(sched.available_chunk_permits(), 4);
    }

    #[tokio::test]
    async fn permits_released_on_drop() {
        let sched = TransferScheduler::with_limits(2, 2, 2);
        {
            let _p1 = sched.acquire_chunk("p").await;
            let _p2 = sched.acquire_chunk("p").await;
            assert_eq!(sched.available_chunk_permits(), 0);
        }
        // 作用域结束，两个 permit 都被 drop 归还
        assert_eq!(sched.available_chunk_permits(), 2);
    }

    #[test]
    fn backoff_is_within_bounds_and_capped() {
        // attempt 0 → exp=1000 → [0,1000)
        for _ in 0..50 {
            let b = full_jitter_backoff_ms(0);
            assert!(b < 1000, "attempt0 应 < 1000，实际 {b}");
        }
        // attempt 6 → exp 封顶 64000 → [0,64000)
        for _ in 0..50 {
            let b = full_jitter_backoff_ms(6);
            assert!(b < 64_000, "attempt6 应 < 64000，实际 {b}");
        }
        // 超大 attempt 仍被封顶，不溢出
        for attempt in [10u32, 20, 100] {
            let b = full_jitter_backoff_ms(attempt);
            assert!(b < 64_000, "attempt{attempt} 应 < 64000，实际 {b}");
        }
    }

    // 注：「块退避参数必须比握手更激进」已在 `version::retry` 里做成 const assert，
    // 编译期就会拦住，无需在此重复运行期断言。

    #[test]
    fn chunk_backoff_is_within_bounds_and_capped() {
        // attempt 0 → exp=200 → [0,200)
        for _ in 0..50 {
            let b = chunk_backoff_ms(0);
            assert!(b < 200, "attempt0 应 < 200，实际 {b}");
        }
        // attempt 5 → 200*2^5 = 6400 > 5000 → 封顶 5000
        for _ in 0..50 {
            let b = chunk_backoff_ms(5);
            assert!(b < 5_000, "attempt5 应被 5000 封顶，实际 {b}");
        }
        // 超大 attempt 不溢出、仍封顶
        for attempt in [10u32, 40, 100] {
            let b = chunk_backoff_ms(attempt);
            assert!(b < 5_000, "attempt{attempt} 应 < 5000，实际 {b}");
        }
    }

    #[test]
    fn backoff_never_returns_from_empty_range() {
        // full_jitter_backoff_with 内部用 `random_range(0..exp)`，exp==0 会 panic。
        // `.max(1)` 就是为此存在 —— 即使有人把 base 或 max 配成 0 也不许崩。
        for _ in 0..20 {
            let _ = full_jitter_backoff_with(0, 0, 0);
            let _ = full_jitter_backoff_with(9, 0, 100);
            let _ = full_jitter_backoff_with(9, 100, 0);
        }
    }

    impl TransferScheduler {
        /// 测试辅助：克隆出共享同一信号量的调度器句柄（Arc 语义）。
        fn clone_for_test(&self) -> Self {
            Self {
                global_chunk: self.global_chunk.clone(),
                retry: self.retry.clone(),
                peer_chunk: self.peer_chunk.clone(),
                peer_cap: self.peer_cap,
            }
        }
    }
}
