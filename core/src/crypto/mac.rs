//! HMAC-SHA256 —— 全 crate 的单一来源
//!
//! # 为什么要这一层薄封装
//!
//! HMAC-SHA256 在本项目里有四个调用方：presence beacon 认证标签、配对转写本标签、
//! JWS 令牌签名、PBKDF2 的内层伪随机函数。它们此前各自 `use hmac::{Hmac, KeyInit, Mac}`
//! 并各自定义 `type HmacSha256 = Hmac<Sha256>`。
//!
//! 这带来一个具体的维护成本：RustCrypto 在 `digest 0.10 → 0.11` 之间挪动了
//! `new_from_slice` 的归属 trait（0.12 时代由 `Mac` 提供，0.13 起需显式导入 `KeyInit`）。
//! 于是每次依赖世代变动，就要改四处 import、四处 alias，还容易漏掉某一处
//! 导致"同一个算法在两个文件里用两种方式构造"。
//!
//! 收敛成一个函数后，世代变动的影响面就只有这个文件（约束 C10：常量与原语单一来源）。
//!
//! # 使用约束
//!
//! - 返回**完整 32 字节**标签。需要截断（如 beacon 的 8 字节）由调用方自己切片，
//!   这样"截断了多少"这个协议决策留在协议层可见，而不是藏在原语里。
//! - 标签比较**必须**走 [`crate::crypto::ct_eq`]，不得用 `==`。

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 标签长度（字节）
pub const HMAC_LEN: usize = 32;

/// HMAC-SHA256(key, msg)
///
/// `key` 可为任意长度：短于块长右侧补零，长于块长先做一次 SHA-256（RFC 2104 规定），
/// 因此构造不会失败。
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; HMAC_LEN] {
    hmac_sha256_parts(key, &[msg])
}

/// HMAC-SHA256(key, parts[0] ‖ parts[1] ‖ …)
///
/// 分段喂入避免为拼接分配临时 `Vec`。
///
/// > **注意**：直接拼接是**没有域分隔**的。凡是多字段拼装的待签载荷，
/// > 必须先经 [`crate::pairing::transcript::frame`] 做长度前缀帧，
/// > 否则 `("ab","c")` 与 `("a","bc")` 会算出同一个标签。
pub fn hmac_sha256_parts(key: &[u8], parts: &[&[u8]]) -> [u8; HMAC_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC 接受任意长度密钥，构造不会失败");
    for part in parts {
        mac.update(part);
    }
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; HMAC_LEN];
    buf.copy_from_slice(&out);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// **RFC 4231 已知答案测试**：钉死这里的 HMAC-SHA256 就是标准实现。
    ///
    /// 登记表 E6 的教训：旧版 `scheduler.ts` 注释写 xxHash64、常量却是自造的，
    /// 结果跨实现的弱校验永不命中。凡影响线路格式的密码学原语，**必须**用公开
    /// 测试向量锚定 —— "自己签自己验"的往返测试对一个算错的算法同样会通过。
    #[test]
    fn matches_rfc4231_vectors() {
        // Test Case 1：key = 0x0b × 20，data = "Hi There"
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );

        // Test Case 2：key = "Jefe"（短于块长 → 右侧补零）
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );

        // Test Case 3：key = 0xaa × 20，data = 0xdd × 50
        assert_eq!(
            hex(&hmac_sha256(&[0xaa; 20], &[0xdd; 50])),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );

        // Test Case 6：key = 0xaa × 131（长于块长 → 先 SHA-256 压缩）
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn parts_equal_concatenated() {
        let key = b"k";
        assert_eq!(
            hmac_sha256_parts(key, &[b"abc", b"def"]),
            hmac_sha256(key, b"abcdef"),
            "分段喂入必须与一次性喂入完全等价"
        );
        assert_eq!(
            hmac_sha256_parts(key, &[]),
            hmac_sha256(key, b""),
            "空分段等价于空消息"
        );
    }

    #[test]
    fn concatenation_is_ambiguous_without_framing() {
        // 这不是 bug，是刻意留下的护栏测试：证明 hmac_sha256_parts 本身没有域分隔，
        // 提醒后来者多字段载荷必须先过 transcript::frame。
        let key = b"k";
        assert_eq!(
            hmac_sha256_parts(key, &[b"ab", b"c"]),
            hmac_sha256_parts(key, &[b"a", b"bc"]),
            "裸拼接存在歧义 —— 多字段签名必须走长度前缀帧"
        );
    }

    #[test]
    fn key_and_message_both_matter() {
        assert_ne!(hmac_sha256(b"k1", b"m"), hmac_sha256(b"k2", b"m"));
        assert_ne!(hmac_sha256(b"k", b"m1"), hmac_sha256(b"k", b"m2"));
    }
}
