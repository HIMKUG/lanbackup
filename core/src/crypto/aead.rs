//! 统一加密层：单一 AES-256-GCM 实例（V4-ARCHITECTURE §4.2）
//!
//! 握手成功后派生 `session_key`（见 [`crate::crypto::kdf`]），此后**所有**流量
//! （数据 / 心跳 / 对账 / phase 同步）走同一个 AEAD 实例，不存在第二层加密
//! （§4.2 规则二）。
//!
//! 退化路径（§4.4 加密降级矩阵）：特殊网络环境若加密连续失败，可协商降级为
//! 明文传输 —— 但**保留 HMAC 完整性校验**（防篡改），默认由用户在设置中控制关闭。

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

/// AEAD 密钥长度（AES-256）
pub const KEY_LEN: usize = 32;
/// AEAD nonce 长度（AES-GCM 固定 12 字节）
pub const NONCE_LEN: usize = 12;

fn make_key(key: &[u8; KEY_LEN]) -> Option<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM, key).ok()?;
    Some(LessSafeKey::new(unbound))
}

/// 加密 `plaintext`，把 16 字节 GCM tag 追加到返回值的尾部（与 ring 默认一致）。
///
/// `nonce` 必须**每消息唯一**（建议 = 块序号或单调计数器，见 §4.3 L4 的 nonce 说明）。
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    let k = make_key(key)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
    let mut in_out = plaintext.to_vec();
    k.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .ok()?;
    Some(in_out)
}

/// 解密 [`encrypt`] 的产物：尾部 16 字节为 GCM tag。
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    let k = make_key(key)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
    let mut in_out = ciphertext.to_vec();
    let plain = k.open_in_place(nonce, Aad::from(aad), &mut in_out).ok()?;
    Some(plain.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [9u8; 32];
        let nonce = [1u8; 12];
        let pt = b"secret payload";
        let ct = encrypt(&key, &nonce, pt, b"").unwrap();
        assert_ne!(&ct, pt);
        let dec = decrypt(&key, &nonce, &ct, b"").unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn tamper_detected() {
        let key = [9u8; 32];
        let nonce = [1u8; 12];
        let mut ct = encrypt(&key, &nonce, b"data", b"").unwrap();
        ct[0] ^= 0xff;
        assert!(decrypt(&key, &nonce, &ct, b"").is_none());
    }

    #[test]
    fn aad_must_match() {
        let key = [9u8; 32];
        let nonce = [1u8; 12];
        let ct = encrypt(&key, &nonce, b"data", b"meta").unwrap();
        assert!(decrypt(&key, &nonce, &ct, b"other").is_none());
        assert!(decrypt(&key, &nonce, &ct, b"meta").is_some());
    }
}
