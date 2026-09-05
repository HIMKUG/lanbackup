//! 设备身份 + 连接码派生（V4-ARCHITECTURE §4.3 L1/L2）
//!
//! 设备身份由两部分组成，**性质完全不同，绝不可混用**：
//!
//! | 材料 | 是否秘密 | 是否上线 | 用途 |
//! |---|---|---|---|
//! | `device_id` | 否 | 是（probe / beacon / 清单） | 公开标识，局域网内区分设备 |
//! | 静态 ECDSA 私钥 | **是** | 否 | 握手层身份签名、解配对/吊销签名 |
//! | 连接码 | **是** | **绝不** | 只做 KDF 输入（L1 存储密钥、L2 配对密钥） |
//!
//! 三代实现的事故根因就是这张表被混淆：广播里带了连接码、
//! probe 响应里 `staticPub` 与 `publicKey` 两个字段并存且编码不同。
//! V4 把它们分成三种类型，让「把秘密写到线上」在类型层面就写不出来。
//!
//! - `derive_storage_key` 是 L1：慢 KDF 把低熵连接码拉伸成加密本地存储的密钥。
//! - `derive_pairing_secret` 是 L2：由握手阶段的 ECDH 共享秘密派生长期配对密钥。
//!
//! 详情见 [`crate::crypto::kdf`]。
//!
//! ## 连接码规范化（登记簿 E8 最终决策）
//!
//! V4 采用**严格版**：去除所有非 `[A-Z0-9]` 字符并统一大写
//! （[`normalize_connection_code`]）。连接码是网络协议线格式的一部分
//! （KDF/HMAC 输入），双端必须从同一个原始输入规范化出**完全相同的字节**，
//! 否则派生的密钥永不相等。旧 TS 双实现（`identity.ts:80` 只去 `[\s\-_]`
//! vs `pairing.ts:259` 去所有 `[^A-Z0-9]`）正是此类分歧的根源 —— `a.b`
//! 在宽松版会保留为 `A.B`（非法线格式）。core 侧唯一输入边界
//! [`crate::server::control::HandshakeStore::set_pairing_code`] 已统一规范化；
//! 任何直接调用 `derive_*` / `path_a_key` 的入口（如手机端实现）必须先过
//! [`normalize_connection_code`]。

use std::sync::Mutex;

use crate::crypto::kdf;
use crate::crypto::sign::{EphemeralKeyPair, KeyPair};
use crate::presence::beacon::DEVICE_ID_PREFIX_LEN;

/// 设备 ID 长度（字节）。beacon 只用前 8 字节做局域网内区分。
pub const DEVICE_ID_LEN: usize = 16;

/// 连接码字母表（31 字符，去掉易混淆字符 0/O、1/I/L —— 与 `identity.ts` 逐位一致）。
///
/// 这是**跨端契约**：字符集增删任何一个字符，同一设备在两端的 8 位码
/// 就会不同，配对永远对不上（登记簿 M4）。两侧实现必须从同一字符集、
/// 同一顺序生成。
pub const CODE_ALPHABET: &str = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

/// 连接码长度（位）。
pub const CODE_LENGTH: usize = 8;

/// 派生输入的域分隔后缀（与 `identity.ts` 逐位一致）。
const CODE_DERIVE_SUFFIX: &str = "|localsend-backup|v1";

/// 空特征码的确定性兜底（与 `identity.ts` 一致）：设备标识损坏时
/// 两端仍能算出同一个码，而不是前端崩溃。
const FALLBACK_STABLE_ID: &str = "unknown-device";

/// FNV-1a 32 位哈希（`identity.ts` 连接码派生算法的第一步）。
///
/// offset basis `0x811c9dc5`、prime `0x01000193`、32 位溢出乘法
/// （等价于 JS `Math.imul`）。独立成函数是为了能对上公开已知答案
/// （FNV-1a("a") = 0xe40c292c），而不是"自己算自己对"。
fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &b in data {
        hash ^= u32::from(b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// 生成 8 位连接码（与 `identity.ts::generateConnectionCode` **逐位一致**）。
///
/// 登记簿 M4：默认派生算法必须与 `identity.ts` 一致 ——
/// FNV-1a 32 + xorshift(13,17,5) + 31 字符字母表，输入
/// `stable_id + "|localsend-backup|v1"`，取 8 位。
/// `stable_id` 取**公开 deviceId**（不是任何秘密材料）。
///
/// `stable_id` 为空时走与 TS 相同的 `unknown-device` 确定性兜底。
///
/// 连接码是**秘密**（约 40bit 熵的加密密钥材料）：调用方不得把它送进
/// 任何网络载荷，只作 KDF 输入（[`derive_storage_key`]）与线下比对。
pub fn generate_connection_code(stable_id: &str) -> String {
    let stable = if stable_id.is_empty() {
        FALLBACK_STABLE_ID
    } else {
        stable_id
    };
    let input = format!("{stable}{CODE_DERIVE_SUFFIX}");
    // xorshift 逐位混合扩散 FNV 结果；JS 侧 `seed >>> 0` 使每一步都
    // 落在 u32 语义上，Rust 的 u32 移位/异或天然等价。
    let mut seed = fnv1a32(input.as_bytes());
    let mut code = String::with_capacity(CODE_LENGTH);
    for _ in 0..CODE_LENGTH {
        seed ^= seed.wrapping_shl(13);
        seed ^= seed >> 17;
        seed ^= seed.wrapping_shl(5);
        let idx = (seed % CODE_ALPHABET.len() as u32) as usize;
        code.push(CODE_ALPHABET.as_bytes()[idx] as char);
    }
    code
}

/// 连接码进程内缓存（登记簿 W6 / P24）。
///
/// 三代实测：接收端**每个文件事件**都要取一次本机连接码，未缓存时每文件
/// 一次磁盘读（Defender 实时扫描下 syscall 成本被放大成可见卡顿）。
/// 本类型把"取码"收敛为一次内存读。
///
/// 取值优先级（登记簿 M5 的兜底链）：
/// 1. [`Self::set`] 显式写入的码（prefs 持久化的码 / 服务启动时传入的码）；
/// 2. 未设置时按默认算法从 `stable_id`（公开 deviceId）派生并缓存。
///
/// [`Self::clear`] 是刷新接口：连接码刷新（`refreshCode`）后调用，下次读取
/// 重新派生。进程内只应有一个实例，与 `DeviceIdentity` 同生命周期。
#[derive(Debug, Default)]
pub struct ConnectionCodeCache {
    inner: Mutex<Option<String>>,
}

impl ConnectionCodeCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// 读取缓存中的连接码；未设置时按默认算法派生并缓存。
    ///
    /// `stable_id` 是公开 deviceId（M4 的派生输入）。派生是纯 CPU 计算
    /// （FNV + xorshift，微秒级），可安全地在锁内完成。
    pub fn get_or_derive(&self, stable_id: &str) -> String {
        let mut g = self.inner.lock().expect("连接码缓存锁不应被污染");
        if let Some(code) = g.clone() {
            return code;
        }
        let code = generate_connection_code(stable_id);
        *g = Some(code.clone());
        code
    }

    /// 显式写入连接码（prefs 持久化的码 / 服务传入的码），覆盖缓存。
    pub fn set(&self, code: impl Into<String>) {
        *self.inner.lock().expect("连接码缓存锁不应被污染") = Some(code.into());
    }

    /// 刷新接口：清空缓存。连接码刷新后调用，下次 `get_or_derive` 重新派生。
    pub fn clear(&self) {
        *self.inner.lock().expect("连接码缓存锁不应被污染") = None;
    }
}

/// 生成一个新的随机设备 ID（hex 编码，长度 `DEVICE_ID_LEN*2`）。
///
/// 设备 ID 是公开标识，**不保密**；持久化由调用方负责（写入本地配置）。
pub fn generate_device_id() -> String {
    let bytes: [u8; DEVICE_ID_LEN] = rand::random();
    hex::encode(bytes)
}

/// 把 hex 设备 ID 还原为字节（持久化存储用）
pub fn device_id_bytes(id: &str) -> Option<[u8; DEVICE_ID_LEN]> {
    let bytes = hex::decode(id).ok()?;
    bytes.try_into().ok()
}

/// V4 连接码规范化：只保留 `[A-Z0-9]`（小写统一转大写），其余字符全部丢弃。
///
/// 历史矛盾（登记簿 E8）：旧 `identity.ts:80` 只去 `[\s\-_]`、
/// `pairing.ts:259` 去所有 `[^A-Z0-9]`，`a.b` 在前者会保留为 `A.B`（非法）。
/// V4 统一为**严格版** —— 连接码用于网络协议线格式（KDF/HMAC 输入），
/// 宽松保留任何字符会让双端各自解析出不同的字节串 → 密钥永远对不上。
///
/// 幂等：`normalize(normalize(x)) == normalize(x)`。所有把用户输入连接码
/// 喂进 KDF/HMAC 的入口都必须先经过本函数；core 侧唯一输入边界
/// `HandshakeStore::set_pairing_code` 已统一处理，手机端实现必须同样规范化。
pub fn normalize_connection_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// L1：连接码 → 本地存储加密密钥。
///
/// 用于加密本地存储的 `pairing_secret`。**调用方必须把它放到 `spawn_blocking`
/// 里执行**（慢 KDF，约束 C8：绝不持锁做 600k 次 PBKDF2）。
pub fn derive_storage_key(connection_code: &str, device_id: &[u8]) -> [u8; 32] {
    kdf::derive_storage_key(connection_code, device_id)
}

/// L1 的可配迭代次数版本，见 [`kdf::derive_storage_key_with`]。
///
/// 生产路径一律用 [`derive_storage_key`]；这里存在只为了让测试不必每次
/// 烧掉 600k 次迭代（debug 构建下那是秒级开销，会把测试套件拖慢一个数量级）。
pub fn derive_storage_key_with(
    connection_code: &str,
    device_id: &[u8],
    iterations: u32,
) -> [u8; 32] {
    kdf::derive_storage_key_with(connection_code, device_id, iterations)
}

/// L2：握手阶段的 ECDH 共享秘密 → `pairing_secret`（长期存储）。
///
/// `extra_info` 承载 §4.3 的 `eph_pub ‖ static_pub ‖ 双 nonce`。
pub fn derive_pairing_secret(
    eph: &EphemeralKeyPair,
    peer_public: &[u8],
    connection_code: &str,
    extra_info: &[u8],
) -> Option<[u8; 32]> {
    let shared = eph.derive_shared(peer_public)?;
    Some(kdf::derive_pairing_secret(
        &shared,
        connection_code,
        extra_info,
    ))
}

/// 本机设备身份：公开 `device_id` + 长期静态 ECDSA 密钥对。
///
/// 整个进程只应有一个实例。持久化规则：
/// `device_id` 明文存；[`Self::signing_key_bytes`] **必须**先用 L1
/// `storage_key`（[`derive_storage_key`]）经 AEAD 加密后才可落盘。
pub struct DeviceIdentity {
    device_id: String,
    keypair: KeyPair,
}

impl DeviceIdentity {
    /// 首次启动：生成新的 deviceId + 静态密钥对
    pub fn generate() -> Self {
        Self {
            device_id: generate_device_id(),
            keypair: KeyPair::generate(),
        }
    }

    /// 从持久化数据恢复。
    ///
    /// `device_id` 必须是合法 hex 且长度正确 —— 否则 [`Self::beacon_prefix`]
    /// 无法工作，而 beacon 是在线性的唯一来源，静默降级会表现为"设备永远离线"。
    /// 因此这里宁可返回 `None` 让调用方重建身份，也不接受半残的 ID。
    pub fn restore(device_id: &str, signing_key: &[u8]) -> Option<Self> {
        device_id_bytes(device_id)?;
        Some(Self {
            device_id: device_id.to_string(),
            keypair: KeyPair::from_signing_bytes(signing_key)?,
        })
    }

    /// 公开设备标识（hex）
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// beacon 报文用的 deviceId 前 8 字节
    pub fn beacon_prefix(&self) -> [u8; DEVICE_ID_PREFIX_LEN] {
        let full = device_id_bytes(&self.device_id)
            .expect("device_id 在 generate/restore 时已校验，不可能非法");
        let mut prefix = [0u8; DEVICE_ID_PREFIX_LEN];
        prefix.copy_from_slice(&full[..DEVICE_ID_PREFIX_LEN]);
        prefix
    }

    /// 静态公钥（SEC1 压缩，33 字节）—— probe 响应的 `staticPub`
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.keypair.public_key_bytes()
    }

    /// 静态私钥（32 字节）。**敏感**：落盘前必须加密。
    pub fn signing_key_bytes(&self) -> Vec<u8> {
        self.keypair.signing_key_bytes()
    }

    /// 用静态私钥签名（握手层认证、解配对、吊销）
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.keypair.sign(msg)
    }
}

/// 手写 `Debug`：**绝不打印私钥**。
///
/// `#[derive(Debug)]` 会把整个密钥对塞进日志。传输/握手链路的日志量很大，
/// 一旦私钥进了日志文件，加密就等于没有 —— 这条必须在类型层面堵死。
impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_is_hex_and_reversible() {
        let id = generate_device_id();
        assert_eq!(id.len(), DEVICE_ID_LEN * 2);
        let bytes = device_id_bytes(&id).unwrap();
        assert_eq!(hex::encode(bytes), id);
    }

    #[test]
    fn storage_key_stable_and_code_dependent() {
        // 用低迭代次数：这里验证的是"派生随连接码变化且稳定"这条语义，
        // 而不是 600k 这个安全参数（那条由 `crypto::kdf` 里的编译期
        // `const _: () = assert!(PBKDF2_ITERATIONS >= 600_000)` 守住）。
        const ITERS: u32 = 1_000;
        let id = generate_device_id();
        let bytes = device_id_bytes(&id).unwrap();
        let a = derive_storage_key_with("1234-5678", &bytes, ITERS);
        let b = derive_storage_key_with("1234-5678", &bytes, ITERS);
        assert_eq!(a, b, "同一连接码+设备必须稳定派生");
        assert_ne!(a, derive_storage_key_with("0000-0000", &bytes, ITERS));
    }

    #[test]
    fn pairing_secret_derives_from_ecdh() {
        let a = EphemeralKeyPair::generate();
        let b = EphemeralKeyPair::generate();
        let sa = derive_pairing_secret(&a, &b.public_key_bytes(), "1234-5678", b"info").unwrap();
        let sb = derive_pairing_secret(&b, &a.public_key_bytes(), "1234-5678", b"info").unwrap();
        assert_eq!(sa, sb, "双端由各自 ECDH 必须得到相同的 pairing_secret");
    }

    #[test]
    fn identity_roundtrips_through_persistence() {
        let id = DeviceIdentity::generate();
        let restored = DeviceIdentity::restore(id.device_id(), &id.signing_key_bytes()).unwrap();
        assert_eq!(restored.device_id(), id.device_id());
        assert_eq!(restored.public_key_bytes(), id.public_key_bytes());
        assert_eq!(restored.beacon_prefix(), id.beacon_prefix());
    }

    #[test]
    fn restore_rejects_malformed_device_id() {
        let id = DeviceIdentity::generate();
        let key = id.signing_key_bytes();
        assert!(DeviceIdentity::restore("not-hex", &key).is_none());
        assert!(
            DeviceIdentity::restore("aabb", &key).is_none(),
            "长度不足应拒绝"
        );
    }

    #[test]
    fn beacon_prefix_is_first_eight_bytes_of_device_id() {
        let id = DeviceIdentity::generate();
        let full = device_id_bytes(id.device_id()).unwrap();
        assert_eq!(id.beacon_prefix(), full[..DEVICE_ID_PREFIX_LEN]);
    }

    /// 日志泄露私钥是不可逆的安全事故，用测试钉死。
    #[test]
    fn debug_never_leaks_private_key() {
        let id = DeviceIdentity::generate();
        let printed = format!("{id:?}");
        let secret_hex = hex::encode(id.signing_key_bytes());
        assert!(!printed.contains(&secret_hex), "Debug 输出泄露了私钥");
        assert!(printed.contains("<redacted>"));
        assert!(
            printed.contains(id.device_id()),
            "deviceId 是公开的，应保留便于排查"
        );
    }

    /// E8：严格版规范化的行为契约。旧 `identity.ts` 宽松版会留下 `a.b` → `A.B`
    /// （非法线格式），V4 统一为只保留 `[A-Z0-9]`。
    #[test]
    fn connection_code_normalization_strips_all_non_alnum() {
        assert_eq!(normalize_connection_code("1234-5678"), "12345678");
        assert_eq!(normalize_connection_code("a.b c_d"), "ABCD");
        assert_eq!(normalize_connection_code("AbC123"), "ABC123");
        assert_eq!(normalize_connection_code(" 9Zz-_. "), "9ZZ");
        assert_eq!(normalize_connection_code(""), "");
    }

    /// E8：规范化必须幂等 —— 两端无论规范化几次都得到同一字节串。
    #[test]
    fn connection_code_normalization_is_idempotent() {
        for raw in ["1234-5678", "a.b", " 9Zz ", "----", "A1B2C3"] {
            let once = normalize_connection_code(raw);
            assert_eq!(
                normalize_connection_code(&once),
                once,
                "对 {raw} 的规范化不幂等"
            );
        }
    }

    /// M4：连接码派生必须与 shared-core 的 `identity.ts` **逐位一致**。
    ///
    /// 向量由 `identity.ts::generateConnectionCode`（Node 直跑）产出，不是
    /// "自己算自己对"：算法里任何一步（FNV 常数、xorshift 轮次、字母表
    /// 顺序、域分隔后缀）改动，都会让某个向量失败。
    #[test]
    fn connection_code_matches_ts_vectors() {
        let cases = [
            ("", "DETN4A4Y"),
            ("unknown-device", "DETN4A4Y"),
            ("device-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "SHS46K5V"),
            ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "VWFEKCGA"),
            ("f47ac10b-58cc-4372-a567-0e02b2c3d479", "KG7SX6TD"),
            ("0123456789abcdef0123456789abcdef", "R6U6SJ99"),
            ("machine-123", "XXX7FU5S"),
            ("9f8c8d63-2c6d-4b6e-9a2e-123456789abc", "KMV8RTQZ"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                generate_connection_code(input),
                expected,
                "输入 {input:?} 的派生结果与 identity.ts 不一致"
            );
        }
    }

    /// FNV-1a 的公开已知答案：FNV-1a("a") == 0xe40c292c。
    ///
    /// 独立验证哈希原语本身，避免"两条链共用同一实现、互为印证"
    /// （E6 的教训：弱校验实现与标准对不上，往返测试照样通过）。
    #[test]
    fn fnv1a32_matches_public_known_answer() {
        assert_eq!(fnv1a32(b"a"), 0xe40c_292c);
    }

    /// W6/P24：进程内缓存 —— 同一进程内重复取码只派生一次，且缓存值
    /// 本身仍满足 M4 向量（防止缓存把错误算法固化下来）。
    #[test]
    fn connection_code_cache_derives_once_and_stays_stable() {
        let cache = ConnectionCodeCache::new();
        let stable = "device-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let code1 = cache.get_or_derive(stable);
        let code2 = cache.get_or_derive(stable);
        assert_eq!(code1, code2, "缓存未命中：同一输入两次结果不一致");
        assert_eq!(code1, "SHS46K5V", "缓存值必须仍满足 M4 向量");
    }

    /// W6/P24：显式写入的连接码优先于派生（prefs 持久化的码是权威）。
    #[test]
    fn connection_code_cache_set_overrides_derived() {
        let cache = ConnectionCodeCache::new();
        let stable = "machine-123";
        let _ = cache.get_or_derive(stable);
        cache.set("CUSTOMCD");
        assert_eq!(cache.get_or_derive(stable), "CUSTOMCD");
    }

    /// W6/P24：`clear` 是刷新接口 —— 连接码刷新后调用，下次读取重新派生。
    #[test]
    fn connection_code_cache_clear_recomputes() {
        let cache = ConnectionCodeCache::new();
        let stable = "machine-123";
        let initial = cache.get_or_derive(stable);
        cache.clear();
        assert_eq!(
            cache.get_or_derive(stable),
            initial,
            "clear 后应重新派生同一码"
        );
    }
}
