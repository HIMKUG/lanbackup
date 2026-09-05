//! S11：密钥滚动轮换（previousKeys 机制）
//!
//! # 解决的问题
//!
//! 连接码 / pairing_secret 刷新后，**已在传输中**的文件仍由旧密钥加密：
//! 若只保留当前 key，解这些旧密文会失败 → 正在进行的传输直接断掉。
//! 因此保留最近几个版本的 key，解密时按 version 降序尝试，直到 GCM tag 通过
//! （登记簿 S11：`previousKeys` 保留 7 天 / 最多 5 个）。
//!
//! # 为什么逐 key 尝试是安全的
//!
//! AES-GCM 认证是完备的：用错误 key 解密必然 tag 校验失败（返回 `None`），
//! 不会出现"部分解密成功"。所以这里没有给攻击者提供 oracle —— 与
//! `crypto/mod.rs::ct_eq` 恒定时间比较是同一类把关。
//!
//! # 容量与过期
//!
//! - [`MAX_PREVIOUS_KEYS`] = 5：previous 里最多 5 个旧 key（超出丢最旧）；
//! - [`PREVIOUS_KEY_TTL`] = 7 天：超过 7 天的旧 key 在下次 [`KeyRing::rotate`]
//!   时被清理（7 天足够覆盖"连接码刷新后在途传输"的窗口，再旧的就是僵尸密钥）。

use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

use crate::crypto::aead::{decrypt, KEY_LEN};

/// previous 里最多保留的旧 key 数（S11：最多 5 个）
pub const MAX_PREVIOUS_KEYS: usize = 5;
/// 旧 key 的保留窗口（S11：7 天）
pub const PREVIOUS_KEY_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// 一个带版本与生日的密钥。
#[derive(Debug, Clone)]
pub struct KeyVersion {
    pub version: u64,
    pub key: [u8; KEY_LEN],
    pub created_at: SystemTime,
}

/// 密钥环：当前 key + 至多 [`MAX_PREVIOUS_KEYS`] 个旧 key。
#[derive(Debug, Clone)]
pub struct KeyRing {
    current: KeyVersion,
    previous: VecDeque<KeyVersion>,
}

impl KeyRing {
    /// 以 `version` 起建立密钥环（仅当前 key，无历史）。
    pub fn new(version: u64, key: [u8; KEY_LEN]) -> Self {
        Self {
            current: KeyVersion {
                version,
                key,
                created_at: SystemTime::now(),
            },
            previous: VecDeque::new(),
        }
    }

    /// 轮换到新密钥：当前 key 降级为 previous，新 key 成为 current。
    ///
    /// - `version` 与当前相同视为"同一密钥刷新"，不重复入历史（避免版本号抖动）；
    /// - 轮换后立即按 [`PREVIOUS_KEY_TTL`] / [`MAX_PREVIOUS_KEYS`] 清理；
    /// - 清理只丢"最旧"，绝不影响刚入列的当前上一版。
    pub fn rotate(&mut self, version: u64, key: [u8; KEY_LEN]) {
        if version != self.current.version {
            self.previous.push_front(std::mem::replace(
                &mut self.current,
                KeyVersion {
                    version,
                    key,
                    created_at: SystemTime::now(),
                },
            ));
        } else {
            self.current.key = key;
            self.current.created_at = SystemTime::now();
        }
        self.prune(SystemTime::now());
    }

    /// 清理过期与超量历史（测试可注入 `now`）。
    pub fn prune(&mut self, now: SystemTime) {
        self.previous.retain(|v| {
            now.duration_since(v.created_at)
                .map(|d| d < PREVIOUS_KEY_TTL)
                .unwrap_or(false)
        });
        while self.previous.len() > MAX_PREVIOUS_KEYS {
            self.previous.pop_back();
        }
    }

    /// 当前密钥的字节（供 [`crate::crypto::aead::encrypt`] 使用）。
    pub fn current_key(&self) -> &[u8; KEY_LEN] {
        &self.current.key
    }

    /// 当前版本号（对端可据此判断是否已轮换）。
    pub fn current_version(&self) -> u64 {
        self.current.version
    }

    /// 持有的密钥总数（含当前）。
    pub fn len(&self) -> usize {
        1 + self.previous.len()
    }

    /// 是否没有任何历史 key（仅当前）。
    pub fn is_empty(&self) -> bool {
        self.previous.is_empty()
    }

    /// 按 version **降序**尝试解密：当前 key 优先，旧 key 依次回退。
    ///
    /// 返回 `(明文, 命中的 version)`；全部失败返回 `None`。GCM 认证保证
    /// 错误 key 只会失败不会误开，因此逐 key 尝试不构成 oracle。
    pub fn decrypt(
        &self,
        nonce: &[u8; crate::crypto::aead::NONCE_LEN],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Option<(Vec<u8>, u64)> {
        let mut candidates: Vec<&KeyVersion> =
            self.previous.iter().chain(std::iter::once(&self.current)).collect();
        // previous 内部按入列顺序（新→旧），但版本号未必严格单调，显式排序保证降序
        candidates.sort_by_key(|v| std::cmp::Reverse(v.version));
        for v in candidates {
            if let Some(plain) = decrypt(&v.key, nonce, ciphertext, aad) {
                return Some((plain, v.version));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::{encrypt, NONCE_LEN};

    fn key(b: u8) -> [u8; KEY_LEN] {
        [b; KEY_LEN]
    }

    fn nonce() -> [u8; NONCE_LEN] {
        [1u8; NONCE_LEN]
    }

    #[test]
    fn fresh_ring_decrypts_own_ciphertext() {
        let ring = KeyRing::new(1, key(9));
        let ct = encrypt(ring.current_key(), &nonce(), b"hi", b"").unwrap();
        let (plain, v) = ring.decrypt(&nonce(), &ct, b"").unwrap();
        assert_eq!(plain, b"hi");
        assert_eq!(v, 1);
    }

    #[test]
    fn s11_old_key_can_still_decrypt_after_rotate() {
        let mut ring = KeyRing::new(1, key(1));
        // 旧 key 加密的在途数据
        let ct = encrypt(&key(1), &nonce(), b"in-flight", b"").unwrap();

        ring.rotate(2, key(2)); // 连接码刷新，轮换

        assert_eq!(ring.current_version(), 2);
        assert_eq!(ring.len(), 2, "旧 key 必须保留");
        let (plain, v) = ring.decrypt(&nonce(), &ct, b"").unwrap();
        assert_eq!(plain, b"in-flight", "在途文件应仍可解密");
        assert_eq!(v, 1, "应命中旧版本 key");
    }

    #[test]
    fn s11_decrypt_prefers_current_version() {
        let mut ring = KeyRing::new(1, key(1));
        let ct = encrypt(&key(2), &nonce(), b"latest", b"").unwrap();
        ring.rotate(2, key(2));
        let (_, v) = ring.decrypt(&nonce(), &ct, b"").unwrap();
        assert_eq!(v, 2, "应命中最新版本");
    }

    #[test]
    fn s11_unknown_key_fails_all_candidates() {
        let ring = KeyRing::new(1, key(1));
        let ct = encrypt(&key(99), &nonce(), b"?", b"").unwrap();
        assert!(ring.decrypt(&nonce(), &ct, b"").is_none());
    }

    #[test]
    fn s11_previous_capped_at_five() {
        let mut ring = KeyRing::new(1, key(1));
        for v in 2..=10 {
            ring.rotate(v, key(v as u8));
        }
        assert_eq!(ring.len(), MAX_PREVIOUS_KEYS + 1, "含当前共 6 把，5 旧 + 1 新");
        assert_eq!(ring.current_version(), 10);

        // 最旧的三把（1/2/3 已被丢出 previous）解不了自己的密文
        for v in 1..=3 {
            let ct = encrypt(&key(v as u8), &nonce(), b"old", b"").unwrap();
            assert!(
                ring.decrypt(&nonce(), &ct, b"").is_none(),
                "version {v} 应已超出 5 个保留窗口"
            );
        }
        // 新近的仍可解
        let ct = encrypt(&key(6), &nonce(), b"recent", b"").unwrap();
        assert!(ring.decrypt(&nonce(), &ct, b"").is_some());
    }

    #[test]
    fn s11_expired_keys_are_pruned() {
        let mut ring = KeyRing::new(1, key(1));
        let old = SystemTime::now() - PREVIOUS_KEY_TTL - Duration::from_secs(1);
        ring.rotate(2, key(2));
        // 手动把上一版 key 的生日改到 7 天以前，模拟过期
        let mut fake = ring.clone();
        fake.previous[0].created_at = old;

        // 过期 key 应被 prune 掉
        fake.prune(SystemTime::now());
        assert_eq!(fake.len(), 1, "过期历史应被清理");
        let ct = encrypt(&key(1), &nonce(), b"stale", b"").unwrap();
        assert!(fake.decrypt(&nonce(), &ct, b"").is_none());
    }

    #[test]
    fn s11_same_version_rotate_refreshes_without_dup_history() {
        let mut ring = KeyRing::new(1, key(1));
        ring.rotate(1, key(2)); // 同版本：应原地刷新，不新增历史
        assert_eq!(ring.len(), 1, "同版本轮换不应制造重复历史");
        assert_eq!(*ring.current_key(), key(2));
    }
}
