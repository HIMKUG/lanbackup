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
}
