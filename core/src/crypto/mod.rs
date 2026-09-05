//! 密码学原语
//!
//! - `merkle` 主算法 Merkle 校验原语（纯计算、可独立测试）
//! - `kdf`    密钥树 L1–L4（storage → pairing → session → file，见 §4.3）
//! - `mac`    HMAC-SHA256 单一来源（beacon / 转写本 / 令牌 / PBKDF2 内层共用）
//! - `sign`   握手层 ECDSA P-256 签名 + ECDH 密钥协商（§4.2：握手只认证不加密）
//! - `aead`   统一加密层：单一 AES-256-GCM 实例（§4.2 规则二）
//! - `id`     CSPRNG 会话/文件 ID 生成（P26）
//! - `keyring` 密钥滚动轮换 previousKeys（S11）

pub mod aead;
pub mod id;
pub mod kdf;
pub mod keyring;
pub mod mac;
pub mod merkle;
pub mod sign;

pub use aead::{
    decrypt as aead_decrypt, encrypt as aead_encrypt, KEY_LEN as AEAD_KEY_LEN,
    NONCE_LEN as AEAD_NONCE_LEN,
};
pub use id::{new_file_id, new_session_id};
pub use kdf::{
    derive_file_key, derive_pairing_secret, derive_session_key, derive_storage_key, sha256,
    KEY_LEN as KDF_KEY_LEN, PBKDF2_ITERATIONS,
};
pub use mac::{hmac_sha256, hmac_sha256_parts, HMAC_LEN};
pub use merkle::{merkle_root, sha256_of, verify_piece, MerkleProof, MerkleRoot, MerkleTree};
pub use sign::{ephemeral_from_bytes, verify as verify_signature, EphemeralKeyPair, KeyPair};

/// 恒定时间字节比较。
///
/// 所有**认证标签**的比较必须走这里，不得用 `==` 或 `slice::eq`：
/// 那些实现会在首个不等字节处短路返回，比较耗时随"猜对的前缀长度"变化。
/// 攻击者据此可以把一次 2^256 的离线穷举，降级成逐字节的在线爆破
/// （32 字节 × 256 次试探即可还原整个标签）。
///
/// 长度不等直接返回 `false` —— 长度本身不是秘密，提前返回不泄漏内容。
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn ct_eq_matches_plain_equality() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"", b"a"));
        // 首字节即不同（短路实现会在此提前返回）
        assert!(!ct_eq(b"zbc", b"abc"));
    }
}
