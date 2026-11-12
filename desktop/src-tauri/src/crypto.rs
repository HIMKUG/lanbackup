//! crypto.rs - 传输层 AES-256-GCM 加密
//!
//! 两层密钥体系（#8/#9 修复后）：
//!
//! | 密钥类型 | 派生方法 | 用途 |
//! |---------|---------|------|
//! | local_storage_key | SHA-256(连接码) | 本地 SQLite 配对记录加密 |
//! | session_key | PBKDF2(ECDH共享密钥, salt, 600k) | #8 DH 后所有 HTTP 传输加密 |
//! | connection_code 直接派生 | SHA-256(连接码) | cryptoVersion=1 兼容旧设备文件加密 |
//!
//! 加密格式（两端一致）：`LSBK(4) || nonce(12) || ciphertext || tag(16)`

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::KeyPair as _;
use sha2::{Sha256, Digest};
use p256::{SecretKey, PublicKey, EncodedPoint};
use p256::elliptic_curve::ecdh::diffie_hellman;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::rngs::OsRng;

use crate::db::AppError;

/// 当前协议版本（#13 协议版本协商）
#[allow(dead_code)]
pub const PROTOCOL_VERSION: &str = "1.1";
/// 最低兼容协议版本
#[allow(dead_code)]
pub const MIN_PROTOCOL_VERSION: &str = "1.0";
/// KDF 版本：1=SHA-256（原始），2=PBKDF2（加固，#9）
#[allow(dead_code)]
pub const KDF_VERSION: u32 = 2;
/// 加密版本：1=连接码直接派生，2=ECDH 密钥交换（#8）
#[allow(dead_code)]
pub const CRYPTO_VERSION: u32 = 2;
/// PBKDF2 迭代次数（OWASP 2023 建议下限，2026 年仍适用）
#[allow(dead_code)]
pub const PBKDF2_ITERATIONS: u32 = 600_000;

/// 魔数头：标记本应用的加密文件格式
pub const MAGIC: &[u8; 4] = b"LSBK";
/// AES-GCM 随机 nonce 长度（12 字节，推荐值）
pub const NONCE_LEN: usize = 12;
/// GCM 认证 tag 长度（16 字节）
pub const TAG_LEN: usize = 16;
/// 加密总开销（魔数 + nonce + tag，allow(dead_code)：#8 传输加密完成后使用）
#[allow(dead_code)]
pub const OVERHEAD: usize = MAGIC.len() + NONCE_LEN + TAG_LEN;

/// 由连接码派生 AES-256 密钥（KDF v1：SHA-256，兼容旧设备）。
///
/// 用途：本地 SQLite 配对记录加密（cryptoVersion=1 兼容）。
pub fn derive_local_storage_key(connection_code: &str) -> [u8; 32] {
    let d = digest(&SHA256, connection_code.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(d.as_ref());
    key
}

// ============================================================
// v3 密钥派生（方案.txt 三层结构定稿）
// ============================================================
//
// L1 本地存储密钥：PBKDF2-HMAC-SHA256(连接码, salt=SHA256(device_id), 600k)
//     —— 连接码 ~40bit 低熵，必须慢 KDF（HKDF 无法抗暴力）
//
// 注：L2 配对密钥 / L3 会话传输密钥的桌面本地派生（derive_pairing_secret_v3 /
// derive_transfer_key_v3）已随 V4 收敛进 core（`lanbackup_core::crypto::kdf`）而删除；
// 源码留档于 `backups/quarantine/region3-deadcode-2026-11-12/`。
//
// 双端必须共享同一套测试向量（RFC 5869 TC1 / PBKDF2 / P-256 交叉协商），
// 见 protocol/testvectors/。

/// L1 本地存储密钥（长期，派生自连接码；决策 方案.txt §2.1/§2.2）。
///
///   storage_key = PBKDF2-HMAC-SHA256(
///       password   = connection_code,          // 40bit 低熵口令 → 必须慢 KDF
///       salt       = SHA256(device_id),        // 每设备唯一，防彩虹表
///       iterations = 600_000,
///       dkLen      = 32
///   )
///
/// 为什么 PBKDF2 而非 HKDF：连接码 ~40bit，HKDF 无法抗离线暴力（§2.2 估算 PBKDF2-600k
/// 单核穷举约 1 万年）。Argon2id 更优但需 Bouncy Castle（+5MB），ROI 低，未来可换（接口不变）。
/// 用途：加密 paired_peers.pairing_secret 列 / 本地文件（cryptoVersion=2）。
pub const STORAGE_PBKDF2_ITERATIONS: u32 = 600_000;

pub fn derive_storage_key_v2(connection_code: &str, device_id: &[u8]) -> Result<[u8; 32], String> {
    let salt = Sha256::digest(device_id);
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(STORAGE_PBKDF2_ITERATIONS).unwrap(),
        &salt,
        connection_code.as_bytes(),
        &mut key,
    );
    Ok(key)
}

// ============================================================
// ECDH 密钥交换（#8 传输加密核心）
// ============================================================

/// 生成 ECDH 临时密钥对（P-256，allow(dead_code)：#8 传输加密完成后启用）
#[allow(dead_code)]
pub fn ecdh_generate_keypair() -> Result<(String, String), String> {
    let secret = SecretKey::random(&mut OsRng);
    let public_key = PublicKey::from_secret_scalar(&secret.to_nonzero_scalar());
    let encoded = EncodedPoint::from(public_key);
    let secret_bytes = secret.to_bytes();
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(&secret_bytes[..]);
    let priv_b64 = URL_SAFE_NO_PAD.encode(priv_bytes);
    let pub_b64 = URL_SAFE_NO_PAD.encode(encoded.as_ref());
    Ok((priv_b64, pub_b64))
}

/// 解析对方公钥（SEC1 uncompressed，base64url → PublicKey，allow(dead_code)：#8 传输加密完成后启用）
#[allow(dead_code)]
fn parse_peer_public_key(pub_b64: &str) -> Result<PublicKey, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(pub_b64)
        .map_err(|e| format!("公钥 base64 解码失败: {}", e))?;
    PublicKey::from_sec1_bytes(&bytes)
        .map_err(|e| format!("ECDH 公钥解析失败（P-256 SEC1）: {}", e))
}

/// 派生 ECDH 共享密钥字节（32 字节，allow(dead_code)：#8 传输加密完成后启用）
#[allow(dead_code)]
pub fn ecdh_derive_shared_secret(
    private_key_b64: &str,
    peer_public_key_b64: &str,
) -> Result<Vec<u8>, String> {
    let priv_bytes = URL_SAFE_NO_PAD
        .decode(private_key_b64)
        .map_err(|e| format!("私钥 base64 解码失败: {}", e))?;
    let secret = SecretKey::from_slice(&priv_bytes)
        .map_err(|e| format!("ECDH 私钥解析失败: {}", e))?;
    let peer_pub = parse_peer_public_key(peer_public_key_b64)?;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), peer_pub.as_affine());
    // shared_secret 固定 32 字节（p256 曲线阶）
    Ok(shared.raw_secret_bytes().to_vec())
}

/// 计算 SAS（Short Authentication String）：6 位数字（allow(dead_code)：#8 传输加密完成后启用）
///
/// 算法：SHA256( ECDH_raw_output ) 前 3 字节 → 大端序 u32 % 1_000_000 → 零填充 6 位。
///
/// SAS 直接绑定到 ECDH 原始输出（与 session_key 路径解耦）。
/// session_key 用 SHA256(ECDH_raw) 做 PBKDF2；SAS 用 SHA256(ECDH_raw) 校验——
/// 两者派生源都是 SHA256(ECDH_raw)，但用途独立，符合密码学惯例。
#[allow(dead_code)]
pub fn compute_sas(shared_secret: &[u8]) -> String {
    // N2 修正：SAS 直接对 ECDH_raw 做单层 SHA256，与 session_key 路径解耦
    let hash = digest(&SHA256, shared_secret);
    let hash_ref = hash.as_ref();
    let val = (u32::from(hash_ref[0]) << 16)
        | (u32::from(hash_ref[1]) << 8)
        | u32::from(hash_ref[2]);
    format!("{:06}", val % 1_000_000)
}

/// 派生 session_key（allow(dead_code)：#8 传输加密完成后启用）
#[allow(dead_code)]
pub fn derive_session_key(shared_secret: &[u8], salt: &[u8]) -> Result<[u8; 32], String> {
    if salt.len() < 16 {
        return Err("PBKDF2 salt 必须至少 16 字节".to_string());
    }
    // S2 安全修复：对 raw ECDH 输出先做 SHA-256，消除结构性偏差
    let uniform = digest(&SHA256, shared_secret);
    let mut dk = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
        salt,
        uniform.as_ref(),   // raw SHA-256 bytes（与 TS/Android 一致，不走 UTF-8 转换）
        &mut dk,
    );
    Ok(dk)
}

/// 判断数据是否为本应用加密格式（带魔数头，allow(dead_code)：#8 传输加密完成后启用）
#[allow(dead_code)]
pub fn is_encrypted(data: &[u8]) -> bool {
    data.len() >= MAGIC.len() && &data[..MAGIC.len()] == MAGIC
}

/// 加密明文，输出 `LSBK || nonce || ciphertext || tag`（allow(dead_code)：#8 传输加密完成后启用）
#[allow(dead_code)]
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|e| format!("密钥初始化失败: {e}"))?;
    let sealing_key = LessSafeKey::new(unbound);

    // 随机 nonce（与 Java/TS 端用同样的 12 字节规格）
    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| "生成 nonce 失败".to_string())?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| format!("加密失败: {e}"))?;

    let mut out = Vec::with_capacity(OVERHEAD + in_out.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    Ok(out)
}

/// 解密 `LSBK || nonce || ciphertext || tag`，返回明文（allow(dead_code)：#8 传输加密完成后启用）
#[allow(dead_code)]
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if !is_encrypted(ciphertext) {
        return Err("缺少 LSBK 魔数头，非本应用加密格式".to_string());
    }
    let body = &ciphertext[MAGIC.len()..];
    if body.len() < NONCE_LEN + TAG_LEN {
        return Err("密文长度不足（缺 nonce 或 tag）".to_string());
    }
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|e| format!("密钥初始化失败: {e}"))?;
    let opening_key = LessSafeKey::new(unbound);

    let (nonce_bytes, payload) = body.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| "nonce 长度非法".to_string())?;

    let mut in_out = payload.to_vec();
    // open_in_place 返回的切片不含尾部 tag，就是明文
    let plaintext = opening_key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| "解密失败：密钥不匹配或数据被篡改".to_string())?;
    Ok(plaintext.to_vec())
}

/// 计算文件的 SHA-256 摘要（GB 级大文件流式处理，不占内存，allow(dead_code)：未来文件完整性校验用）
#[allow(dead_code)]
pub fn calculate_sha256(path: &std::path::Path) -> Result<String, AppError> {
    let file = std::fs::File::open(path).map_err(|e| AppError(format!("打开文件失败: {e}")))?;
    let mut reader = std::io::BufReader::with_capacity(1024 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut reader, &mut buf).map_err(|e| AppError(format!("读取文件失败: {e}")))?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

// ============================================================
// ECDSA P-256 签名身份锚（新架构 §一/§二：非对称签名信任锚）
// ============================================================
// 说明：架构原文建议 Ed25519；移动端 minSdk=22 无法用原生 Ed25519（API 28+），
// 而两端已有完整 P-256 基础设施（桌面 ring / 移动端 java.security），
// 故采用 ECDSA P-256(SHA-256) 独立签名密钥（与现有 ECDH static_key 分离）。
// 公钥编码：SEC1 uncompressed（0x04||X||Y，65B）；签名编码：ASN.1 DER
// （ring ECDSA_P256_SHA256_ASN1 变体与 Java SHA256withECDSA 输出一致）。

/// 生成 ECDSA P-256 签名密钥对，返回 (pkcs8_priv_b64url, sec1_pub_b64url)。
/// 私钥为 PKCS#8 DER；公钥为 SEC1 uncompressed 点。私钥仅本机存储，绝不上线。
pub fn sig_generate_keypair() -> Result<(String, String), String> {
    let rng = ring::rand::SystemRandom::new();
    let doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rng,
    )
    .map_err(|e| format!("ECDSA 密钥生成失败: {e:?}"))?;
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        doc.as_ref(),
        &rng,
    )
    .map_err(|e| format!("ECDSA 密钥解析失败: {e:?}"))?;
    let priv_b64 = URL_SAFE_NO_PAD.encode(doc.as_ref());
    // ring 0.17：EcdsaKeyPair 经 KeyPair trait 暴露 public_key()，返回 SEC1 uncompressed 点
    let pub_bytes = key_pair.public_key().as_ref().to_vec();
    let pub_b64 = URL_SAFE_NO_PAD.encode(&pub_bytes);
    Ok((priv_b64, pub_b64))
}

/// 用 ECDSA 私钥（PKCS8 base64url）对 message 签名，返回 ASN.1 DER base64url。
pub fn sig_sign(pkcs8_priv_b64: &str, message: &[u8]) -> Result<String, String> {
    let priv_der = URL_SAFE_NO_PAD
        .decode(pkcs8_priv_b64)
        .map_err(|e| format!("私钥 base64 解码失败: {e}"))?;
    let rng = ring::rand::SystemRandom::new();
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &priv_der,
        &rng,
    )
    .map_err(|e| format!("私钥解析失败: {e:?}"))?;
    let sig = key_pair
        .sign(&rng, message)
        .map_err(|e| format!("签名失败: {e:?}"))?;
    Ok(URL_SAFE_NO_PAD.encode(sig.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_local_storage_key("AB3FXY12");
        let plaintext = b"hello backup, this is a test file content";
        let encrypted = encrypt(&key, plaintext).unwrap();
        // 密文 = 明文 + 魔数 + nonce + tag
        assert_eq!(encrypted.len(), plaintext.len() + OVERHEAD);
        assert!(is_encrypted(&encrypted), "加密输出应带魔数头");
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn same_code_same_key_different_nonce_different_ciphertext() {
        let key = derive_local_storage_key("AB3FXY12");
        let plaintext = b"same content";
        let a = encrypt(&key, plaintext).unwrap();
        let b = encrypt(&key, plaintext).unwrap();
        // 随机 nonce → 即使相同明文，密文也完全不同（防嗅探比对）
        assert_ne!(a, b);
        // 但都能正确解密
        assert_eq!(decrypt(&key, &a).unwrap(), plaintext);
        assert_eq!(decrypt(&key, &b).unwrap(), plaintext);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let key = derive_local_storage_key("AB3FXY12");
        let wrong_key = derive_local_storage_key("ZZZZZZZZ");
        let encrypted = encrypt(&key, b"secret").unwrap();
        assert!(decrypt(&wrong_key, &encrypted).is_err(), "错误密钥应解密失败");
    }

    #[test]
    fn tampered_data_fails_to_decrypt() {
        let key = derive_local_storage_key("AB3FXY12");
        let mut encrypted = encrypt(&key, b"integrity check").unwrap();
        // 篡改最后一个字节（tag 区域）
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;
        assert!(decrypt(&key, &encrypted).is_err(), "被篡改的数据应解密失败");
    }

    #[test]
    fn non_encrypted_data_returns_none() {
        let key = derive_local_storage_key("AB3FXY12");
        let plaintext = b"this is a plaintext file from another app";
        assert!(!is_encrypted(plaintext), "外部明文不应带魔数");
        assert!(decrypt(&key, plaintext).is_err(), "非本格式不应解密");
    }

    #[test]
    fn v3_storage_key_pbkdf2() {
        // L1：PBKDF2-600k(salt=SHA256(device_id))，确定性，且与 v1(SHA-256) 不同
        let device_id = b"device-uuid-1234567890";
        let v1 = derive_local_storage_key("AB3FXY12");
        let v2 = derive_storage_key_v2("AB3FXY12", device_id).unwrap();
        let v2b = derive_storage_key_v2("AB3FXY12", device_id).unwrap();
        assert_ne!(v1, v2);
        assert_eq!(v2, v2b);
        // 不同 device_id → salt 不同 → 密钥不同（防彩虹表）
        let v2c = derive_storage_key_v2("AB3FXY12", b"other-device-uuid").unwrap();
        assert_ne!(v2, v2c);
    }

    #[test]
    fn v3_pbkdf2_testvector_baseline() {
        // 双端 PBKDF2 向量基准（protocol/testvectors/pbkdf2_v3.json）：
        // password="NFNMPQRS" salt=0xa1b2...c5d6 iterations=600k dkLen=32
        let password = b"NFNMPQRS";
        let salt = hex::decode("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6").unwrap();
        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(STORAGE_PBKDF2_ITERATIONS).unwrap(),
            &salt,
            password,
            &mut key,
        );
        eprintln!("V3_PBKDF2_VECTOR_HEX={}", hex::encode(key));
    }

    // P-256 双端交叉协商测试向量（方案.txt §5.3，protocol/testvectors/p256_ecdh_cross_check.json）。
    // rust_priv+java_pub 与 java_priv+rust_pub 必须派生同一 shared，且匹配共享向量。
    #[test]
    fn v3_p256_ecdh_cross_check() {
        use base64::Engine as _;
        let b64 = |hexs: &str| -> String {
            let bytes = hex::decode(hexs).unwrap();
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        };
        let rust_priv = b64("2bb0b0c8c2875f23ad990a5210cb60e2b7c4041564d763825c78b8a406006058");
        let rust_pub = b64("04f6b78ecf719d2de5eda1ca388a9e342316d7f3d0b554bb6bbf79d327c6ca6eb1b42982bba3ea7be77d5097446e327086ff65c3a0bd72bc931763bc42070e4bb4");
        let java_priv = b64("e7674dcdef5530c1328778f1e7f0179486968bb1060c3c150d95bb084aa3b89a");
        let java_pub = b64("044e8cd455266a486fba6af216fabbc942c3ba4a1f505e8cac85d73481ab752af4e2616c3c990c59397587db45e7c2d28ab43ac3cf2cc82d9ca7642bf6e8275857");
        let expected = "db59d954cca702a9c57671c1fd8314507e954f480cc5a5634e380884f094d3e4";
        let s1 = hex::encode(ecdh_derive_shared_secret(&rust_priv, &java_pub).unwrap());
        let s2 = hex::encode(ecdh_derive_shared_secret(&java_priv, &rust_pub).unwrap());
        assert_eq!(s1, expected, "Rust 私钥 + Java 公钥共享密钥必须匹配向量");
        assert_eq!(s2, expected, "Java 私钥 + Rust 公钥共享密钥必须匹配向量");
        assert_eq!(s1, s2, "双端交叉共享必须一致");
    }
}