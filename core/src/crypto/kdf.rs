//! 密钥树 L1–L4（V4-ARCHITECTURE §4.3）
//!
//! ```text
//! L1  storage_key   = PBKDF2-HMAC-SHA256(连接码, salt=SHA256(device_id), 600k, 32B)
//!                     加密本地存储的 pairing_secret（连接码 40bit 低熵 → 必须慢 KDF）
//! L2  pairing_secret = HKDF-SHA256(ECDH_shared, salt=H(连接码), info=...)
//!                     长期存储。用于：握手签名、会话密钥派生、presence beacon 认证
//! L3  session_key    = HKDF-SHA256(session_shared, salt=pairing_secret, info=".../session/"||id)
//!                     每会话一把，喂给统一加密层
//! L4  file_key       = HKDF-SHA256(session_key, info=".../file/"||file_id)
//!                     每文件一把；nonce = chunk_index（文件内从 0 单调递增）
//! ```
//!
//! **L4 必须保留**：AES-GCM 的 nonce 复用是灾难性的（泄露明文异或与认证子密钥）。
//! 每文件独立密钥 + nonce 用块序号，保证 nonce 在文件内绝不重复；断点续传时按块序号
//! 重建 nonce 即可，**不需要持久化 nonce 计数器** —— 这是三层设计真正的价值所在。

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// 所有派生密钥长度（字节）
pub const KEY_LEN: usize = 32;
/// 慢 KDF 迭代次数（§4.3 L1）：40bit 低熵连接码必须经慢 KDF 拉伸
pub const PBKDF2_ITERATIONS: u32 = 600_000;

// 编译期护栏：迭代次数是唯一挡住"连接码离线字典攻击"的东西。
//
// "为了让测试跑快一点先把它调小"是真实发生过的事，而且这种改动在
// 代码评审里极不显眼（只是一个数字）。用 const assert 而不是 #[test]：
// 后者要跑起来才报错，前者连编译都不给过。
// 同样的手法见 `version::retry` 里对两套退避参数的护栏。
const _: () = assert!(
    PBKDF2_ITERATIONS >= 600_000,
    "连接码只有 40bit 熵，PBKDF2 迭代次数不得低于 600k"
);

/// SHA-256 摘要
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

/// L1：连接码 → 本地存储加密密钥。
///
/// 用 PBKDF2 拉伸低熵连接码，避免字典攻击直接解出本地存的 `pairing_secret`。
///
/// > **运行期提醒（约束 C8）**：600k 次迭代是重 CPU 负载，**绝不能持锁执行**。
/// > 调用方须将其放到 `spawn_blocking` / 专用线程，否则会拖垮接收路径甚至死锁。
pub fn derive_storage_key(connection_code: &str, device_id: &[u8]) -> [u8; KEY_LEN] {
    derive_storage_key_with(connection_code, device_id, PBKDF2_ITERATIONS)
}

/// L1 的可配迭代次数版本。
///
/// **生产代码一律走 [`derive_storage_key`]**，这个入口存在只有两个正当理由：
///
/// 1. 已知答案测试需要用公开向量的迭代次数（RFC 风格 KAT 用 1 / 2 / 4096）
/// 2. 单元测试不该为了验证"派生是确定性的"而每次烧掉 600k 次迭代 ——
///    debug 构建下那是几十秒级的开销，会把整个测试套件拖成不可用
///
/// 迭代次数是安全参数，**不要**从配置或对端输入接进来。
pub fn derive_storage_key_with(
    connection_code: &str,
    device_id: &[u8],
    iterations: u32,
) -> [u8; KEY_LEN] {
    let salt = sha256(device_id);
    let mut out = [0u8; KEY_LEN];
    // 用已审计的 `pbkdf2` crate 而不是手写外层循环：
    // 手写版本在 dkLen > hLen 时的分块拼接极易写错，而这里的输出长度是可能变的常量。
    pbkdf2::pbkdf2_hmac::<Sha256>(connection_code.as_bytes(), &salt, iterations, &mut out);
    out
}

/// L2：ECDH 共享秘密 → `pairing_secret`（长期存储）。
///
/// `extra_info` 承载 §4.3 的 `eph_pub ‖ static_pub ‖ 双 nonce`，调用方按协议填入。
pub fn derive_pairing_secret(
    ecdh_shared: &[u8],
    connection_code: &str,
    extra_info: &[u8],
) -> [u8; KEY_LEN] {
    let mut info = b"lanbackup/v4/pairing/".to_vec();
    info.extend_from_slice(extra_info);
    hkdf_sha256(ecdh_shared, &sha256(connection_code.as_bytes()), &info)
}

/// L3：每会话一把的 `session_key`。
pub fn derive_session_key(
    session_shared: &[u8],
    pairing_secret: &[u8],
    session_id: &str,
) -> [u8; KEY_LEN] {
    let info = format!("lanbackup/v4/session/{session_id}");
    hkdf_sha256(session_shared, pairing_secret, info.as_bytes())
}

/// L4：每文件一把的 `file_key`。
///
/// nonce 由调用方按块序号单调递增生成，无需持久化计数器。
pub fn derive_file_key(session_key: &[u8], file_id: &str) -> [u8; KEY_LEN] {
    let info = format!("lanbackup/v4/file/{file_id}");
    hkdf_sha256(session_key, &[], info.as_bytes())
}

/// HKDF-SHA256 抽取+扩展（RFC 5869），输出定长 [`KEY_LEN`]。
///
/// **返回值而不是写出参**：早先的版本签名是 `fn hkdf_expand(..., okm: &mut [u8])`，
/// 三个调用点都写成 `hkdf_expand(ikm, salt, info, &mut [0u8; KEY_LEN])` ——
/// 填了一个临时数组然后丢掉，函数返回 `()`。这类"忘记取回输出"的错误
/// 在返回值风格下根本无法表达，所以接口就该这么写。
///
/// 空 `salt` 按 RFC 5869 等价于 HashLen 个零字节（HMAC 会把空密钥补零到块长）。
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(info, &mut okm)
        .expect("okm 长度 ≤ 255×HashLen；KEY_LEN=32 必然满足");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用迭代次数。安全性由 [`iterations_constant_is_not_weakened`] 单独守住。
    const TEST_ITERS: u32 = 1_000;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// **PBKDF2-HMAC-SHA256 已知答案测试**（E6：线路/存储格式必须被公开向量锚定）。
    ///
    /// 向量取自广为引用的 PBKDF2-HMAC-SHA256 测试集（P="password"、S="salt"），
    /// 与 Python `hashlib.pbkdf2_hmac('sha256', ...)` 逐字节一致 ——
    /// 这是一次真正的跨实现交叉验证，而非"自己算自己对"。
    #[test]
    fn pbkdf2_matches_known_answer_vectors() {
        fn kat(iterations: u32) -> String {
            let mut out = [0u8; 32];
            pbkdf2::pbkdf2_hmac::<Sha256>(b"password", b"salt", iterations, &mut out);
            hex(&out)
        }
        assert_eq!(
            kat(1),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        assert_eq!(
            kat(2),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
        assert_eq!(
            kat(4096),
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
    }

    /// **HKDF-SHA256 已知答案测试**：RFC 5869 Test Case 1。
    #[test]
    fn hkdf_matches_rfc5869_case1() {
        // IKM = 0x0b × 22, salt = 0x000102...0c, info = 0xf0f1...f9, L = 42
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0x00u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn storage_key_is_deterministic() {
        let k1 = derive_storage_key_with("1234-5678", b"device-aaaaaaaa", TEST_ITERS);
        let k2 = derive_storage_key_with("1234-5678", b"device-aaaaaaaa", TEST_ITERS);
        assert_eq!(k1, k2, "同一连接码+设备必须稳定派生");
        let k3 = derive_storage_key_with("9999-9999", b"device-aaaaaaaa", TEST_ITERS);
        assert_ne!(k1, k3, "不同连接码必须派生出不同密钥");
    }

    #[test]
    fn different_device_same_code_differs() {
        let a = derive_storage_key_with("1234-5678", b"device-aaaaaaaa", TEST_ITERS);
        let b = derive_storage_key_with("1234-5678", b"device-bbbbbbbb", TEST_ITERS);
        assert_ne!(a, b, "salt 含 device_id，不同设备必须不同");
    }

    #[test]
    fn iteration_count_changes_output() {
        // 保证迭代次数真的进了计算，而不是被某个缓存/短路吃掉
        let a = derive_storage_key_with("1234-5678", b"dev", 1_000);
        let b = derive_storage_key_with("1234-5678", b"dev", 1_001);
        assert_ne!(a, b);
    }

    #[test]
    fn key_tree_is_deterministic_and_distinct() {
        let shared = [7u8; 32];
        let ps = derive_pairing_secret(&shared, "1234-5678", b"eph|static|nn");
        let sk = derive_session_key(&shared, &ps, "sess-1");
        let fk = derive_file_key(&sk, "file-9");
        assert_ne!(ps, sk);
        assert_ne!(sk, fk);
        // 派生结果不能是全零 —— 那是"忘记取回输出"这类 bug 的典型症状
        assert_ne!(ps, [0u8; KEY_LEN], "L2 输出不得为全零");
        assert_ne!(sk, [0u8; KEY_LEN], "L3 输出不得为全零");
        assert_ne!(fk, [0u8; KEY_LEN], "L4 输出不得为全零");
        // 重放必须稳定
        assert_eq!(
            ps,
            derive_pairing_secret(&shared, "1234-5678", b"eph|static|nn")
        );
        assert_eq!(
            fk,
            derive_file_key(&derive_session_key(&shared, &ps, "sess-1"), "file-9")
        );
    }

    #[test]
    fn pairing_secret_binds_code_and_extra_info() {
        let shared = [7u8; 32];
        let base = derive_pairing_secret(&shared, "1111-1111", b"ctx");
        assert_ne!(
            base,
            derive_pairing_secret(&shared, "2222-2222", b"ctx"),
            "连接码进了 salt，必须影响结果"
        );
        assert_ne!(
            base,
            derive_pairing_secret(&shared, "1111-1111", b"other"),
            "extra_info（eph_pub‖static_pub‖双 nonce）必须影响结果"
        );
    }

    #[test]
    fn session_key_binds_session_id_and_pairing_secret() {
        let shared = [1u8; 32];
        let ps = [2u8; 32];
        assert_ne!(
            derive_session_key(&shared, &ps, "s1"),
            derive_session_key(&shared, &ps, "s2"),
            "每会话一把：session_id 必须影响结果"
        );
        assert_ne!(
            derive_session_key(&shared, &ps, "s1"),
            derive_session_key(&shared, &[3u8; 32], "s1"),
            "pairing_secret 在 salt 位，必须影响结果"
        );
    }

    #[test]
    fn file_key_depends_on_file_id() {
        let sk = [3u8; 32];
        assert_ne!(derive_file_key(&sk, "a"), derive_file_key(&sk, "b"));
    }

    /// 生产参数的真实开销测试，默认跳过（debug 构建下 600k 迭代要跑很久）。
    ///
    /// 需要验证生产路径时：`cargo test --release -- --ignored`
    #[test]
    #[ignore = "600k 迭代，仅在需要验证生产参数时手动运行"]
    fn production_iterations_still_work() {
        let k = derive_storage_key("1234-5678", b"device-aaaaaaaa");
        assert_ne!(k, [0u8; KEY_LEN]);
    }
}
