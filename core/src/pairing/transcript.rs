//! 握手转写本（transcript）与路径 A 的 HMAC 认证（V4-ARCHITECTURE §4.2）
//!
//! # 为什么要"转写本"这个概念
//!
//! 双端要对同一串字节做 HMAC/签名。三代实现里这串字节是各自
//! `deviceId + clientNonce + serverNonce` 直接拼接出来的，于是踩了两个坑：
//!
//! 1. **拼接顺序/分隔符各写各的** → 双端算出的标签不同，握手永远失败，
//!    而两边代码"看起来都对"。
//! 2. **无分隔拼接本身有歧义** —— `"ab" ‖ "c"` 与 `"a" ‖ "bc"` 是同一串字节。
//!    攻击者可以把一段内容的尾部挪到下一段的头部，得到不同语义、相同标签。
//!
//! 因此本模块规定唯一的**长度前缀帧格式**（每段 `u16` 大端长度 + 内容），
//! 并用域分隔前缀把不同用途的签名彻底隔开（防止把解配对签名当握手签名重用）。
//! 格式由 [`golden 测试`](#) 用十六进制钉死，跨语言实现照抄即可。
//!
//! # 路径 A 的安全边界（必须写明）
//!
//! 路径 A（首次配对）的密钥材料是**用户口述的低熵连接码**。
//! 攻击者若抓到一次完整握手记录，就可以离线穷举连接码 —— 这是**无 PAKE
//! 设计的固有代价**，本模块无法消除。实际缓解手段有三层：
//!
//! - 连接码一次性使用，配对完成即失效；
//! - 服务端对 `handshake/verify` 做速率限制（失败即拉长退避）；
//! - 配对一旦完成，立刻切换到 ECDH 派生的长期 `pairing_secret`，
//!   连接码不再参与任何在线协议。
//!
//! 想从根上解决需要引入 SPAKE2 / OPAQUE 之类的 PAKE，属后续演进，
//! **不要**在这里悄悄"加强"成自造方案。

use crate::crypto::{ct_eq, hmac_sha256, hmac_sha256_parts};

/// 单段最大长度（受 `u16` 长度前缀限制）
pub const MAX_FIELD_LEN: usize = u16::MAX as usize;

/// 域分隔：路径 A 握手认证
pub const DOMAIN_PATH_A: &[u8] = b"lanbackup/v4/handshake/path-a";
/// 域分隔：解配对签名
pub const DOMAIN_UNPAIR: &[u8] = b"lanbackup/v4/pair/unpair";
/// 域分隔：吊销签名
pub const DOMAIN_REVOKE: &[u8] = b"lanbackup/v4/pair/revoke";
/// 域分隔：路径 A 的 HMAC 密钥派生
pub const DOMAIN_PATH_A_KEY: &[u8] = b"lanbackup/v4/handshake/path-a/key";

/// 按长度前缀帧格式拼装字节串。
///
/// 布局：`[u16 len ‖ bytes]` × (1 + parts.len())，其中第一段固定是 `domain`。
/// 任一段超过 [`MAX_FIELD_LEN`] 返回 `None` —— 宁可拒绝也不截断，
/// 截断会让两端在超长输入上算出不同结果。
pub fn frame(domain: &[u8], parts: &[&[u8]]) -> Option<Vec<u8>> {
    if domain.len() > MAX_FIELD_LEN || parts.iter().any(|p| p.len() > MAX_FIELD_LEN) {
        return None;
    }
    let total = 2 + domain.len() + parts.iter().map(|p| 2 + p.len()).sum::<usize>();
    let mut out = Vec::with_capacity(total);
    for part in std::iter::once(domain).chain(parts.iter().copied()) {
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    Some(out)
}

/// 路径 A 的转写本。
///
/// 字段顺序即协议，**不得调整**。包含 `server_static_pub` 是关键：
/// 它把响应方的长期身份绑进转写本，中间人换上自己的静态公钥后标签必然不符。
/// 少了它，攻击者可以在 probe 阶段替换公钥而握手照样通过。
pub fn path_a_transcript(
    device_id: &str,
    client_eph_pub: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
    server_static_pub: &[u8],
) -> Option<Vec<u8>> {
    frame(
        DOMAIN_PATH_A,
        &[
            device_id.as_bytes(),
            client_eph_pub,
            client_nonce,
            server_nonce,
            server_static_pub,
        ],
    )
}

/// 由连接码派生路径 A 的 HMAC 密钥（等价于 HKDF-Extract）。
///
/// 双 nonce 进 salt，使同一个连接码在每次握手中派生出不同密钥 ——
/// 抓到的标签无法重放到另一次握手。
pub fn path_a_key(connection_code: &str, client_nonce: &[u8], server_nonce: &[u8]) -> [u8; 32] {
    // salt 走 HMAC 的 key 位（等价于 HKDF-Extract 的 salt 位置）。
    // 这里的 salt 是三段裸拼接，但三段中只有 nonce 是变长的、且长度由协议固定，
    // 不存在 frame 要防的那种字段边界歧义。
    let mut salt =
        Vec::with_capacity(DOMAIN_PATH_A_KEY.len() + client_nonce.len() + server_nonce.len());
    salt.extend_from_slice(DOMAIN_PATH_A_KEY);
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);

    hmac_sha256_parts(&salt, &[connection_code.as_bytes()])
}

/// 对转写本算认证标签
pub fn tag(key: &[u8], transcript: &[u8]) -> [u8; 32] {
    hmac_sha256(key, transcript)
}

/// 恒定时间校验标签。**必须**用这个而不是 `==`：
/// 逐字节短路比较会泄漏"前几个字节猜对了"，把离线穷举降级成在线逐字节爆破。
pub fn verify_tag(key: &[u8], transcript: &[u8], provided: &[u8]) -> bool {
    ct_eq(&tag(key, transcript), provided)
}

/// 解配对签名的待签字节（用静态 ECDSA 私钥签）
pub fn unpair_payload(device_id: &str, request_id: &str) -> Option<Vec<u8>> {
    frame(
        DOMAIN_UNPAIR,
        &[device_id.as_bytes(), request_id.as_bytes()],
    )
}

/// 吊销签名的待签字节
pub fn revoke_payload(device_id: &str, revoke_token: &str) -> Option<Vec<u8>> {
    frame(
        DOMAIN_REVOKE,
        &[device_id.as_bytes(), revoke_token.as_bytes()],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **线路格式 golden**：跨语言实现照抄这个十六进制串即可对齐。
    ///
    /// 登记表 E6 的教训：凡影响线路格式的东西，必须有可照抄的固定值，
    /// 不能只靠"自己算自己验"的往返测试 —— 往返测试对一个算错的格式同样会通过。
    #[test]
    fn framing_golden_vector() {
        let framed = frame(b"D", &[b"ab", b""]).unwrap();
        assert_eq!(hex::encode(framed), "000144000261620000");
    }

    /// 无分隔拼接的歧义必须被消除
    #[test]
    fn framing_is_unambiguous() {
        let a = frame(DOMAIN_PATH_A, &[b"ab", b"c"]).unwrap();
        let b = frame(DOMAIN_PATH_A, &[b"a", b"bc"]).unwrap();
        assert_ne!(a, b, "长度前缀没起作用，切分歧义仍然存在");
    }

    #[test]
    fn domains_separate_signature_purposes() {
        let u = unpair_payload("dev", "req").unwrap();
        let r = revoke_payload("dev", "req").unwrap();
        assert_ne!(u, r, "不同用途的待签字节相同 = 签名可跨用途重用");
    }

    #[test]
    fn oversized_field_is_rejected_not_truncated() {
        let big = vec![0u8; MAX_FIELD_LEN + 1];
        assert!(frame(b"D", &[&big]).is_none());
        assert!(frame(&big, &[b"x"]).is_none());
        // 恰好等于上限应通过
        let exact = vec![0u8; MAX_FIELD_LEN];
        assert!(frame(b"D", &[&exact]).is_some());
    }

    fn sample_transcript() -> Vec<u8> {
        path_a_transcript("dev-1", b"eph-pub", b"cn", b"sn", b"static-pub").unwrap()
    }

    #[test]
    fn path_a_tag_roundtrip() {
        let key = path_a_key("1234-5678", b"cn", b"sn");
        let t = sample_transcript();
        let tg = tag(&key, &t);
        assert!(verify_tag(&key, &t, &tg));
        assert!(!verify_tag(&key, &t, &[0u8; 32]));
    }

    #[test]
    fn wrong_connection_code_fails() {
        let t = sample_transcript();
        let good = path_a_key("1234-5678", b"cn", b"sn");
        let bad = path_a_key("0000-0000", b"cn", b"sn");
        assert!(!verify_tag(&bad, &t, &tag(&good, &t)));
    }

    /// 同一连接码 + 不同 nonce ⇒ 不同密钥 ⇒ 标签不可跨握手重放
    #[test]
    fn nonces_make_key_session_specific() {
        let k1 = path_a_key("1234-5678", b"cn1", b"sn1");
        let k2 = path_a_key("1234-5678", b"cn2", b"sn1");
        let k3 = path_a_key("1234-5678", b"cn1", b"sn2");
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k2, k3);
    }

    /// 中间人替换静态公钥必须导致标签不符
    #[test]
    fn mitm_swapping_static_pubkey_breaks_tag() {
        let key = path_a_key("1234-5678", b"cn", b"sn");
        let honest = path_a_transcript("dev-1", b"eph", b"cn", b"sn", b"server-pub").unwrap();
        let mitm = path_a_transcript("dev-1", b"eph", b"cn", b"sn", b"attacker-pub").unwrap();
        assert!(!verify_tag(&key, &mitm, &tag(&key, &honest)));
    }

    /// 任一字段被篡改都要被检出（逐字段扫一遍，防止漏把某个字段放进转写本）
    #[test]
    fn every_field_is_covered_by_the_tag() {
        let key = path_a_key("1234-5678", b"cn", b"sn");
        let base = path_a_transcript("dev-1", b"eph", b"cn", b"sn", b"pub").unwrap();
        let expected = tag(&key, &base);

        let variants = [
            path_a_transcript("dev-2", b"eph", b"cn", b"sn", b"pub").unwrap(),
            path_a_transcript("dev-1", b"EPH", b"cn", b"sn", b"pub").unwrap(),
            path_a_transcript("dev-1", b"eph", b"CN", b"sn", b"pub").unwrap(),
            path_a_transcript("dev-1", b"eph", b"cn", b"SN", b"pub").unwrap(),
            path_a_transcript("dev-1", b"eph", b"cn", b"sn", b"PUB").unwrap(),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert!(
                !verify_tag(&key, v, &expected),
                "第 {i} 个字段未被转写本覆盖"
            );
        }
    }

    #[test]
    fn tag_length_mismatch_is_rejected() {
        let key = path_a_key("c", b"a", b"b");
        let t = sample_transcript();
        assert!(!verify_tag(&key, &t, &[]));
        assert!(!verify_tag(&key, &t, &[0u8; 31]));
        assert!(!verify_tag(&key, &t, &[0u8; 33]));
    }
}
