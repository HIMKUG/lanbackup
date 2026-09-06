//! 块哈希增量缓存（V4-ARCHITECTURE.md §7.2 问题 5）。
//!
//! 发送端每次 Reconcile / 重连对账 / 重试 diff 都要重算本地全部 piece 的弱/强双校验
//! （见 [`crate::transfer::chunk::PieceHash::from_piece`]）。大文件上这是 O(n) 次 SHA-256，
//! 在「增量同步」「VerifyRejected 重新 diff」「连续重连」场景下代价极高。
//!
//! 本模块以「文件身份 + mtime + size」为键缓存 piece 哈希：键命中则直接复用，
//! 仅当 inode / mtime / size 任一变化（文件被改写）才整文件失效重算。
//!
//! **为什么键里不含内容？** 内容变了而 mtime 没变，缓存不会命中——
//! 因为真正兜住正确性的是强校验（SHA-256），缓存只负责省掉「明显没变的文件」的重复哈希。

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use crate::transfer::chunk::PieceHash;

/// 缓存键：文件身份（设备 + inode）+ 修改时间 + 大小。
///
/// 按 §7.2 的约定 `key = inode + mtime + size`。Rust 侧用 `dev` + `inode` 表达「文件身份」，
/// 避免同一路径被「删了再建」复用后误命中旧哈希。Windows 没有 inode，用
/// `volume_serial_number + file_index` 等价表达。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PieceCacheKey {
    dev: u64,
    inode: u64,
    mtime_ns: i64,
    size: u64,
}

impl PieceCacheKey {
    /// 从文件元数据构造键。拿不到元数据（如文件不存在）返回 `None`。
    pub fn from_path(path: &Path, size: u64) -> Option<Self> {
        let meta = fs::metadata(path).ok()?;
        let (dev, inode) = dev_ino(&meta);
        let mtime_ns = meta
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        Some(Self {
            dev,
            inode,
            mtime_ns,
            size,
        })
    }
}

#[cfg(unix)]
fn dev_ino(meta: &fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

#[cfg(windows)]
fn dev_ino(meta: &fs::Metadata) -> (u64, u64) {
    use std::os::windows::fs::MetadataExt;
    // `creation_time()` 是稳定 API（自 1601-01-01 起的 100ns 计数），用作身份代理。
    // 非完美（复制后变化），但最坏只是缓存未命中→重算，正确性不受影响。
    (0, meta.creation_time())
}

/// 线程安全的块哈希缓存（多会话 / 并发传输共享同一份）。
#[derive(Default)]
pub struct PieceHashCache {
    inner: Mutex<HashMap<PieceCacheKey, Vec<PieceHash>>>,
}

impl PieceHashCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// 命中且 piece 数相符时返回缓存的整组哈希（克隆成本 = O(piece 数)，通常很小）。
    pub fn get(&self, key: &PieceCacheKey) -> Option<Vec<PieceHash>> {
        self.inner.lock().ok()?.get(key).cloned()
    }

    /// 写入一组 piece 哈希。
    pub fn insert(&self, key: PieceCacheKey, hashes: Vec<PieceHash>) {
        if let Ok(mut g) = self.inner.lock() {
            g.insert(key, hashes);
        }
    }

    /// 显式失效（极端情况下文件被外部改写但 mtime 未变时由调用方触发）。
    pub fn invalidate(&self, key: &PieceCacheKey) {
        if let Ok(mut g) = self.inner.lock() {
            g.remove(key);
        }
    }

    /// 构造某文件的 piece 哈希，**优先走缓存**：
    /// - 键命中且 piece 数相符 → 直接返回缓存；
    /// - 未命中 → 逐 piece 调 [`crate::transfer::chunk::PieceHash::from_piece`] 计算后写入缓存。
    ///
    /// `read_piece` 由调用方提供：给定 piece 索引返回该 piece 的字节。
    /// 模块不持有文件 IO，便于测试与跨平台（桌面 `std::fs` / Android SAF）。
    ///
    /// 返回 `Vec` 的 `len` 由调用方保证与 `piece_count` 一致。
    pub fn build_piece_hashes<F>(&self, key: PieceCacheKey, piece_count: u64, mut read_piece: F) -> Vec<PieceHash>
    where
        F: FnMut(u64) -> Vec<u8>,
    {
        if let Some(cached) = self.get(&key) {
            if cached.len() as u64 == piece_count {
                return cached;
            }
        }
        let mut out = Vec::with_capacity(piece_count as usize);
        for i in 0..piece_count {
            let data = read_piece(i);
            out.push(PieceHash::from_piece(i, &data));
        }
        self.insert(key, out.clone());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_read(size: u64) -> impl FnMut(u64) -> Vec<u8> {
        move |i| vec![i as u8; (i + 1) as usize % 7 + 1].repeat((i + 1) as usize % 3 + 1).into_iter().cycle().take(size as usize).collect::<Vec<u8>>().into_iter().take((i as usize) + 1).collect()
    }

    // 简化：用可控的 read_piece 计数来验证「命中即跳过计算」。
    #[test]
    fn rebuild_when_cache_miss_then_hit_skips_recompute() {
        let cache = PieceHashCache::new();
        let key = PieceCacheKey {
            dev: 1,
            inode: 1,
            mtime_ns: 1000,
            size: 100,
        };

        let calls = std::cell::Cell::new(0u64);
        let mut read = |i: u64| {
            calls.set(calls.get() + 1);
            vec![i as u8; 4]
        };

        let _ = cache.build_piece_hashes(key.clone(), 3, &mut read);
        assert_eq!(calls.get(), 3, "未命中必须逐 piece 计算");

        // 同样的键 → 不应再调用 read_piece
        let mut read2 = |i: u64| {
            calls.set(calls.get() + 1);
            vec![i as u8; 4]
        };
        let got = cache.build_piece_hashes(key.clone(), 3, &mut read2);
        assert_eq!(calls.get(), 3, "命中缓存后不得重复计算");
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].index, 0);
        assert_eq!(got[2].index, 2);
    }

    #[test]
    fn dirty_mtime_triggers_recompute() {
        let cache = PieceHashCache::new();
        let key_a = PieceCacheKey {
            dev: 1,
            inode: 1,
            mtime_ns: 1000,
            size: 100,
        };
        let key_b = PieceCacheKey {
            dev: 1,
            inode: 1,
            mtime_ns: 2000, // mtime 变了
            size: 100,
        };
        let calls = std::cell::Cell::new(0u64);
        let mut read = |i: u64| {
            calls.set(calls.get() + 1);
            vec![i as u8; 4]
        };

        let _ = cache.build_piece_hashes(key_a, 2, &mut read);
        assert_eq!(calls.get(), 2);
        // 不同 mtime → 视为不同文件 → 重新计算
        let _ = cache.build_piece_hashes(key_b, 2, &mut read);
        assert_eq!(calls.get(), 4, "mtime 变化必须失效重算");
    }

    #[test]
    fn piece_count_mismatch_invalidates_cache() {
        let cache = PieceHashCache::new();
        let key = PieceCacheKey {
            dev: 1,
            inode: 1,
            mtime_ns: 1000,
            size: 100,
        };
        let calls = std::cell::Cell::new(0u64);
        let mut read = |i: u64| {
            calls.set(calls.get() + 1);
            vec![i as u8; 4]
        };
        let _ = cache.build_piece_hashes(key.clone(), 3, &mut read);
        assert_eq!(calls.get(), 3);
        // 同一键但 piece 数变了（文件被截断/增长且 mtime 恰好未变）→ 重算
        let mut read2 = |i: u64| {
            calls.set(calls.get() + 1);
            vec![i as u8; 4]
        };
        let _ = cache.build_piece_hashes(key.clone(), 5, &mut read2);
        assert_eq!(calls.get(), 8, "piece 数不符必须重算");
    }

    // 抑制未使用告警（dummy_read 仅作文档示例）
    #[allow(dead_code)]
    fn _use_dummy() {
        let _ = dummy_read(8);
    }

    // ============================================================
    // P1-4：真实文件路径的缓存命中 / 失效（生产形态）
    // ============================================================

    /// 真实文件路径：`PieceCacheKey::from_path` 构造键 → 首次逐 piece 计算 →
    /// 同路径再次构建命中缓存（read_piece 零调用）→ `invalidate` 后重算 →
    /// 文件 mtime 变化（外部改写）→ 键变化 → 自动重算。
    ///
    /// 这是发送端对账重算的**生产调用形态**：区别于纯内存 stub 测试，
    /// 它验证了「文件身份 + mtime + size」键在真实磁盘元数据下的行为。
    #[test]
    fn real_file_path_cache_hit_and_invalidate() {
        use crate::transfer::chunk::{piece_count, PIECE_SIZE};

        let dir = std::env::temp_dir().join(format!("lanbak-pc-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("data.bin");
        // 2 个 piece 的数据（PIECE_SIZE + 42 字节），确定性内容便于重复计算
        let data: Vec<u8> = (0..PIECE_SIZE + 42).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();

        let cache = PieceHashCache::new();
        let key = PieceCacheKey::from_path(&path, data.len() as u64).expect("文件元数据可读");
        let n = piece_count(data.len() as u64);
        assert_eq!(n, 2, "测试前提：应恰好 2 个 piece");

        // 读 piece 的公共实现：从内存 data 切片（等价于平台层 read 文件片段）
        let reads = std::cell::Cell::new(0u64);
        let read_piece = |i: u64| {
            reads.set(reads.get() + 1);
            let start = (i * PIECE_SIZE) as usize;
            let end = (((i + 1) * PIECE_SIZE).min(data.len() as u64)) as usize;
            data[start..end].to_vec()
        };
        let mut rp = read_piece;
        let hashes = cache.build_piece_hashes(key.clone(), n, &mut rp);
        assert_eq!(reads.get(), n, "首次必须逐 piece 计算（读 {n} 次）");
        assert_eq!(hashes.len() as u64, n);

        // 同路径、同 mtime、同 size → 键不变 → 命中缓存，read_piece 零调用
        let reads2 = std::cell::Cell::new(0u64);
        let read_piece2 = |i: u64| {
            reads2.set(reads2.get() + 1);
            let start = (i * PIECE_SIZE) as usize;
            let end = (((i + 1) * PIECE_SIZE).min(data.len() as u64)) as usize;
            data[start..end].to_vec()
        };
        let mut rp2 = read_piece2;
        let cached = cache.build_piece_hashes(key.clone(), n, &mut rp2);
        assert_eq!(reads2.get(), 0, "缓存命中后不得重读文件");
        assert_eq!(cached, hashes, "命中缓存必须返回与首次计算一致的结果");

        // 显式失效（外部改写但 mtime 未变的极端情况）→ 必须重算
        cache.invalidate(&key);
        let reads3 = std::cell::Cell::new(0u64);
        let read_piece3 = |_i: u64| {
            reads3.set(reads3.get() + 1);
            vec![0u8; 1]
        };
        let mut rp3 = read_piece3;
        let _ = cache.build_piece_hashes(key.clone(), n, &mut rp3);
        assert_eq!(reads3.get(), n, "invalidate 后必须逐 piece 重算");

        // 文件被外部改写（mtime 变化）→ 新键 ≠ 旧键 → 自动重算
        std::fs::write(&path, &data).unwrap(); // 内容相同但 mtime 前进
        let key2 = PieceCacheKey::from_path(&path, data.len() as u64).expect("改写后元数据可读");
        assert_ne!(key2, key, "mtime 变化后键必须不同，否则缓存永不过期");
        let reads4 = std::cell::Cell::new(0u64);
        let read_piece4 = |_i: u64| {
            reads4.set(reads4.get() + 1);
            vec![1u8; 1]
        };
        let mut rp4 = read_piece4;
        let _ = cache.build_piece_hashes(key2.clone(), n, &mut rp4);
        assert_eq!(reads4.get(), n, "mtime 变化后必须重算，不能误命中旧缓存");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 文件不存在时 `from_path` 返回 `None`（拿不到元数据不该 panic）。
    #[test]
    fn from_path_missing_file_is_none() {
        let ghost = std::env::temp_dir().join("lanbak-pc-ghost-never-exists.bin");
        assert!(
            PieceCacheKey::from_path(&ghost, 0).is_none(),
            "文件不存在应返回 None 而非 panic"
        );
    }
}
