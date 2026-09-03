//! 握手层签名与密钥协商（V4-ARCHITECTURE §4.2 / §六）
//!
//! **握手层不加密，只做 ECDSA P-256 认证**（§4.2 规则一）：
//! probe / challenge / verify 全部明文传输，用 ECDSA 签名保证 authenticity，
//! 连接码仍然只做 HKDF salt、**绝不上线**。
//!
//! 同时提供 ECDH P-256，用于派生 `pairing_secret`（§4.3 L2）。

use p256::ecdh::diffie_hellman;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};

/// 统一的 CSPRNG 取用点。
///
/// **必须与 `p256` 的 `rand_core` 世代一致**：p256 0.13 依赖 rand_core 0.6，
/// 因此这里只能用 rand 0.8 的 `ThreadRng`。曾经把 rand 升到 0.10，
/// `ThreadRng` 就不再满足 `CryptoRngCore`，全部密钥生成直接编译失败。
/// 版本约束的完整说明见 `Cargo.toml` 密码学段落。
fn csprng() -> rand::rngs::ThreadRng {
    rand::thread_rng()
}

/// 一对 ECDSA P-256 密钥（静态长期身份密钥）
pub struct KeyPair {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl KeyPair {
    /// 生成新的随机密钥对
    pub fn generate() -> Self {
        let mut rng = csprng();
        let signing = SigningKey::random(&mut rng);
        // ecdsa 0.16 的 `verifying_key()` 返回引用，需解引用复制一份持有
        let verifying = *signing.verifying_key();
        Self { signing, verifying }
    }

    /// 由 32 字节私钥还原
    pub fn from_signing_bytes(bytes: &[u8]) -> Option<Self> {
        let signing = SigningKey::from_slice(bytes).ok()?;
        let verifying = *signing.verifying_key();
        Some(Self { signing, verifying })
    }

    /// 静态公钥（SEC1 压缩编码，33 字节），用于 `/api/v4/probe` 交换
    ///
    /// 压缩编码是**线路格式**：33 字节而非未压缩的 65 字节，
    /// 两端必须一致，否则转写本里的 `server_static_pub` 字段算出的标签不符。
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying.to_encoded_point(true).as_bytes().to_vec()
    }

    /// 32 字节私钥（用于本地持久化；务必经 `kdf::derive_storage_key` 加密后再落盘）
    pub fn signing_key_bytes(&self) -> Vec<u8> {
        self.signing.to_bytes().to_vec()
    }

    /// 对消息签名（ECDSA P-256 / SHA-256），输出 64 字节固定长度 `r ‖ s`
    ///
    /// 显式标注 `Signature` 类型：`Signer` 对同一密钥有多个实现
    /// （固定长度 `Signature` 与 DER 编码的 `DerSignature`），不标注会推断不出来。
    /// 这里必须选固定长度那个 —— DER 是变长的，会破坏线路格式。
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing.sign(msg);
        sig.to_bytes().to_vec()
    }
}

/// 用公钥验证签名
pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_sec1_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(sig) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}

/// 生成一次性 ECDH 临时密钥对（用于握手密钥协商）
pub struct EphemeralKeyPair {
    secret: SecretKey,
}

impl EphemeralKeyPair {
    pub fn generate() -> Self {
        let mut rng = csprng();
        Self {
            secret: SecretKey::random(&mut rng),
        }
    }

    /// 临时公钥（SEC1 压缩，33 字节）
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.secret
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// 由对端临时公钥算出共享秘密（§4.3 L2 的 ECDH_shared）
    ///
    /// 调用方负责把 `shared` 喂给 [`crate::crypto::kdf::derive_pairing_secret`]。
    pub fn derive_shared(&self, peer_public: &[u8]) -> Option<[u8; 32]> {
        let peer = PublicKey::from_sec1_bytes(peer_public).ok()?;
        let shared = diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes());
        Some(out)
    }
}

/// 由已有私钥字节恢复临时密钥对（测试 / 重放场景）
pub fn ephemeral_from_bytes(bytes: &[u8]) -> Option<EphemeralKeyPair> {
    Some(EphemeralKeyPair {
        secret: SecretKey::from_slice(bytes).ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = KeyPair::generate();
        let msg = b"hello lanbackup";
        let sig = kp.sign(msg);
        assert!(verify(&kp.public_key_bytes(), msg, &sig));
        assert!(!verify(&kp.public_key_bytes(), b"tampered", &sig));
    }

    #[test]
    fn ecdh_is_symmetric() {
        let a = EphemeralKeyPair::generate();
        let b = EphemeralKeyPair::generate();
        let sa = a.derive_shared(&b.public_key_bytes()).unwrap();
        let sb = b.derive_shared(&a.public_key_bytes()).unwrap();
        assert_eq!(sa, sb, "ECDH 双端必须得到相同共享秘密");
    }

    #[test]
    fn key_pair_persists_via_bytes() {
        let kp = KeyPair::generate();
        let bytes = kp.signing_key_bytes();
        let restored = KeyPair::from_signing_bytes(&bytes).unwrap();
        let msg = b"persist";
        assert_eq!(kp.sign(msg), restored.sign(msg));
    }
}
