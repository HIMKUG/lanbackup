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

use crate::crypto::kdf;
use crate::crypto::sign::{EphemeralKeyPair, KeyPair};
use crate::presence::beacon::DEVICE_ID_PREFIX_LEN;

/// 设备 ID 长度（字节）。beacon 只用前 8 字节做局域网内区分。
pub const DEVICE_ID_LEN: usize = 16;

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
}
