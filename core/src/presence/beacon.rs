//! UDP presence beacon 报文（V4-ARCHITECTURE §3.3-B）
//!
//! 32 字节定长：
//!
//! ```text
//!   0        8       12       16       24              32
//!  ├────────┼────────┼────────┼────────┼───────────────┤
//!  │devId前8B│ ts(4B) │ seq(4B) │ 保留(8B)│ HMAC 截断(8B) │
//!  └────────┴────────┴────────┴────────┴───────────────┘
//! ```
//!
//! **设计取舍（§3.3-B）**：presence 只需要 **authenticity（防伪造）**，不需要 confidentiality。
//! deviceId 本就不是秘密，加密一个公开标识符没有意义；真正要防的是「伪造某设备在线」，
//! 因此只用 HMAC-SHA256 认证标签。截断 8 字节比 AES-256-GCM 快一个数量级，
//! 且 64 bit 认证标签对防伪造绰绰有余（伪造成功率 1/2⁶⁴，且 0.5s 内即失效）。
//! 密钥直接用已建立的 `pairing_secret`（见 §4.3 L2），无需额外密钥交换。

// hmac 0.13 起 `Mac` 不再以 `KeyInit` 为父 trait，`new_from_slice` 需显式导入 `KeyInit`。
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// beacon 报文总长度（字节）
pub const BEACON_LEN: usize = 32;
/// deviceId 前缀长度（局域网内区分足够）
pub const DEVICE_ID_PREFIX_LEN: usize = 8;
/// 认证标签长度（HMAC 截断）
pub const AUTH_TAG_LEN: usize = 8;

/// 已签名的 beacon 报文（32 字节定长）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconPacket(pub [u8; BEACON_LEN]);

impl BeaconPacket {
    /// 由 32 字节切片构造；长度不符返回 `None`
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() != BEACON_LEN {
            return None;
        }
        let mut arr = [0u8; BEACON_LEN];
        arr.copy_from_slice(buf);
        Some(BeaconPacket(arr))
    }

    /// 取底层 32 字节
    pub fn as_bytes(&self) -> &[u8; BEACON_LEN] {
        &self.0
    }
}

/// 被认证的可信三元组（deviceId 前缀、Unix 秒、单调递增序号）
pub type BeaconClaim = ([u8; DEVICE_ID_PREFIX_LEN], u32, u32);

/// 用 `pairing_secret` 对 `(device_id_prefix, ts, seq)` 签名出一个 beacon。
pub fn sign_beacon(
    secret: &[u8],
    device_id_prefix: &[u8; DEVICE_ID_PREFIX_LEN],
    ts: u32,
    seq: u32,
) -> BeaconPacket {
    let mut packet = [0u8; BEACON_LEN];
    packet[..DEVICE_ID_PREFIX_LEN].copy_from_slice(device_id_prefix);
    packet[DEVICE_ID_PREFIX_LEN..DEVICE_ID_PREFIX_LEN + 4].copy_from_slice(&ts.to_be_bytes());
    packet[DEVICE_ID_PREFIX_LEN + 4..DEVICE_ID_PREFIX_LEN + 8].copy_from_slice(&seq.to_be_bytes());
    // 认证载荷 = deviceId 前缀 + ts + seq（不含保留段与标签本身）
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC 接受任意长度密钥，不会失败");
    mac.update(&packet[..DEVICE_ID_PREFIX_LEN + 8]);
    let tag = mac.finalize().into_bytes();
    packet[BEACON_LEN - AUTH_TAG_LEN..].copy_from_slice(&tag[..AUTH_TAG_LEN]); // 截断前 8 字节置于尾部
    BeaconPacket(packet)
}

/// 校验 beacon 的 HMAC 标签，返回被认证的三元组；标签不符（伪造/篡改/错密钥）返回 `None`。
///
/// 比较使用恒定时间，避免时序侧信道。
pub fn verify_beacon(secret: &[u8], packet: &BeaconPacket) -> Option<BeaconClaim> {
    let p = packet.0;
    let mut device_id_prefix = [0u8; DEVICE_ID_PREFIX_LEN];
    device_id_prefix.copy_from_slice(&p[..DEVICE_ID_PREFIX_LEN]);
    let ts = u32::from_be_bytes([p[8], p[9], p[10], p[11]]);
    let seq = u32::from_be_bytes([p[12], p[13], p[14], p[15]]);

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC 接受任意长度密钥，不会失败");
    mac.update(&p[..DEVICE_ID_PREFIX_LEN + 8]);
    let tag = mac.finalize().into_bytes();

    let provided = &p[BEACON_LEN - AUTH_TAG_LEN..];
    if constant_time_eq(&tag[..AUTH_TAG_LEN], provided) {
        Some((device_id_prefix, ts, seq))
    } else {
        None
    }
}

/// 恒定时间相等比较（防时序侧信道）
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
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
    use super::*;

    fn secret() -> Vec<u8> {
        b"pairing-secret-for-test".to_vec()
    }
    fn dev() -> [u8; 8] {
        [1, 2, 3, 4, 5, 6, 7, 8]
    }

    #[test]
    fn roundtrip_sign_verify() {
        let s = secret();
        let pkt = sign_beacon(&s, &dev(), 1_700_000_000, 42);
        let v = verify_beacon(&s, &pkt).expect("应校验通过");
        assert_eq!(v.0, dev());
        assert_eq!(v.1, 1_700_000_000);
        assert_eq!(v.2, 42);
    }

    #[test]
    fn wrong_secret_rejected() {
        let pkt = sign_beacon(&secret(), &dev(), 1, 1);
        assert!(verify_beacon(b"other-secret", &pkt).is_none());
    }

    #[test]
    fn tampered_device_id_rejected() {
        let mut pkt = sign_beacon(&secret(), &dev(), 1, 1);
        pkt.0[0] ^= 0xff; // 篡改 deviceId 前缀
        assert!(verify_beacon(&secret(), &pkt).is_none());
    }

    #[test]
    fn tampered_tag_rejected() {
        let mut pkt = sign_beacon(&secret(), &dev(), 1, 1);
        pkt.0[BEACON_LEN - 1] ^= 0xff; // 篡改 auth tag 末字节
        assert!(verify_beacon(&secret(), &pkt).is_none());
    }

    #[test]
    fn tampered_timestamp_rejected() {
        let mut pkt = sign_beacon(&secret(), &dev(), 1, 1);
        pkt.0[8] ^= 0xff; // 篡改 ts
        assert!(verify_beacon(&secret(), &pkt).is_none());
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(BeaconPacket::from_bytes(&[0u8; 31]).is_none());
        assert!(BeaconPacket::from_bytes(&[0u8; 33]).is_none());
    }

    #[test]
    fn seq_changes_tag_for_replay_protection() {
        let s = secret();
        let a = sign_beacon(&s, &dev(), 1, 1);
        let b = sign_beacon(&s, &dev(), 1, 2);
        assert_ne!(
            a.0[BEACON_LEN - AUTH_TAG_LEN..],
            b.0[BEACON_LEN - AUTH_TAG_LEN..]
        );
    }

    /// **RFC 4231 已知答案测试**：钉死 HMAC-SHA256 是标准实现。
    ///
    /// 登记表 E6 的教训：旧版 `scheduler.ts` 注释写 xxHash64，常量却是自造的，
    /// 导致跨实现弱校验永不命中。凡影响线路格式的密码学原语，
    /// **必须**用公开测试向量锚定，不能只靠「自己签自己验」的往返测试
    /// —— 往返测试对一个算错的算法同样会通过。
    #[test]
    fn hmac_sha256_matches_rfc4231_vectors() {
        fn tag(key: &[u8], msg: &[u8]) -> String {
            let mut mac = HmacSha256::new_from_slice(key).unwrap();
            mac.update(msg);
            mac.finalize()
                .into_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        }

        // RFC 4231 Test Case 1：key = 0x0b × 20，data = "Hi There"
        assert_eq!(
            tag(&[0x0b; 20], b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );

        // RFC 4231 Test Case 2：key = "Jefe"（短于块长，需右侧补零）
        assert_eq!(
            tag(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );

        // RFC 4231 Test Case 3：key = 0xaa × 20，data = 0xdd × 50
        assert_eq!(
            tag(&[0xaa; 20], &[0xdd; 50]),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn reserved_bytes_do_not_affect_tag() {
        // 保留段 [16,24) 不参与认证，但若被填入非零也不该让校验失败（它本就被忽略）
        let mut pkt = sign_beacon(&secret(), &dev(), 7, 9);
        pkt.0[16] = 0xab;
        pkt.0[23] = 0xcd;
        assert!(verify_beacon(&secret(), &pkt).is_some());
    }
}
