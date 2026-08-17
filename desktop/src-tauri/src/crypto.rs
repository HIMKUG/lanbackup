//! crypto.rs - 传输层 AES-256-GCM 加密
//!
//! 用两端已知的连接码派生密钥，对上传的文件内容做认证加密（机密性 + 完整性）。
//! 与 `shared-core/src/transfer.ts`、`LocalReceiverPlugin.java` 的加密格式完全一致：
//!
//! ```text
//! [4 字节魔数 "LSBK"][12 字节随机 nonce][AES-256-GCM 密文][16 字节 GCM tag]
//! ```
//!
//! - 魔数：接收端据此可靠区分「本应用加密文件」与「外部明文文件」（如官方 LocalSend 传的）。
//!   魔数匹配 → 必须解密（失败即报错）；不匹配 → 原样保存，不误伤外部明文。
//! - 密钥派生：`SHA-256(连接码)` → 32 字节 AES-256 密钥。
//!   连接码即配对凭据，两端在 UI 上互见：发送方用**接收方**的连接码加密，
//!   接收方用**自己**的连接码解密，无需额外交换密钥。
//!
//! 注：本项目启用**应用层**端到端 AES-GCM 加密（密钥=对方连接码，防局域网嗅探）；
//! 规格书"无加密"指不启用 TLS/HTTPS（`tls_config: None`），两者不矛盾。
//! 解密为流式 + 移动端硬件加速（ARMv8 Crypto Extensions），开销相对传输时间可接受。
//! 流式加密（多块格式）见 `encrypt_stream`/`decrypt_stream`——大文件不再整读内存。

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};

/// 魔数头：标记本应用的加密文件格式
pub const MAGIC: &[u8; 4] = b"LSBK";
/// AES-GCM 随机 nonce 长度（12 字节，推荐值）
pub const NONCE_LEN: usize = 12;
/// GCM 认证 tag 长度（16 字节）
pub const TAG_LEN: usize = 16;
/// 加密总开销（魔数 + nonce + tag）
pub const OVERHEAD: usize = MAGIC.len() + NONCE_LEN + TAG_LEN;

/// 由连接码派生 AES-256 密钥（SHA-256 摘要，32 字节）
pub fn derive_key(connection_code: &str) -> [u8; 32] {
    let d = digest(&SHA256, connection_code.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(d.as_ref());
    key
}

/// 判断数据是否为本应用加密格式（带魔数头）
pub fn is_encrypted(data: &[u8]) -> bool {
    data.len() >= MAGIC.len() && &data[..MAGIC.len()] == MAGIC
}

/// 加密明文，输出 `LSBK || nonce || ciphertext || tag`
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

/// 解密 `LSBK || nonce || ciphertext || tag`，返回明文
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

/// 多块流式加密格式版本号（魔数后 4 字节）：
/// `LSBK || 00 00 00 01 || block_size_le_u32 || (nonce12 || ct_len_le_u32 || ct || tag16)×N`
const STREAM_VERSION: [u8; 4] = [0, 0, 0, 1];

/// 流式加密默认块大小（8MB）：桌面端发送（upload_single 内嵌加密流）与加密落盘统一使用
pub const STREAM_ENC_BLOCK: usize = 8 * 1024 * 1024;

/// 流式格式头（12B）：`LSBK || 版本 || 块大小(LE u32)`
pub fn stream_header_bytes(block_size: usize) -> [u8; 12] {
    let mut h = [0u8; 12];
    h[..4].copy_from_slice(MAGIC);
    h[4..8].copy_from_slice(&STREAM_VERSION);
    h[8..12].copy_from_slice(&(block_size as u32).to_le_bytes());
    h
}

/// 流式密文的确定性输出大小（发送端 prepare-upload 需提前告知对端总量）：
/// 头 12B + 每块开销（nonce 12 + len 4 + tag 16 = 32B）+ 明文。
/// 前提：加密方凑满块才发（短读合并），块数 = ceil(明文 / 8MB)
pub fn enc_output_size(plain: u64) -> u64 {
    let blocks = plain.div_ceil(STREAM_ENC_BLOCK as u64);
    12 + blocks * (NONCE_LEN as u64 + 4 + TAG_LEN as u64) + plain
}

/// 密封一个流式块追加到 out：`nonce || len(明文长) || ct || tag`；
/// buf 传入明文、离开时原地变 ct+tag（ring 原地密封，零整块拷贝）
pub fn seal_stream_block(key: &[u8; 32], buf: &mut Vec<u8>, out: &mut Vec<u8>) -> Result<(), String> {
    let sealing_key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key).map_err(|e| format!("密钥初始化失败: {e}"))?,
    );
    seal_block(&sealing_key, buf, out)
}

fn seal_block(
    sealing_key: &LessSafeKey,
    buf: &mut Vec<u8>,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| "生成 nonce 失败".to_string())?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let plain_len = buf.len();
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::empty(), buf)
        .map_err(|e| e.to_string())?;
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&(plain_len as u32).to_le_bytes());
    out.extend_from_slice(buf);
    Ok(())
}

/// 流式加密已由 upload_single 内嵌加密流承担（crypto::seal_stream_block 逐块密封），
/// 桌面端不再需要落盘式整文件加密，故移除原 encrypt_stream。

/// 流式解密：自动识别多块（版本 0x00000001）与单块（手机端 CipherOutputStream 格式）两种格式。
/// 非 LSBK 开头 → 返回 Ok(false)（调用方按明文原样保留，不误伤外部文件）。
pub fn decrypt_stream<R: std::io::Read, W: std::io::Write>(
    key: &[u8; 32],
    reader: &mut R,
    writer: &mut W,
) -> Result<bool, String> {
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|e| format!("密钥初始化失败: {e}"))?;
    let opening_key = LessSafeKey::new(unbound);

    let mut head = [0u8; MAGIC.len()];
    let mut got = 0;
    while got < head.len() {
        let n = reader.read(&mut head[got..]).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        got += n;
    }
    if got < head.len() || &head != MAGIC {
        return Ok(false); // 非本应用加密格式
    }

    let mut ver = [0u8; 4];
    reader.read_exact(&mut ver).map_err(|e| e.to_string())?;
    if ver == STREAM_VERSION {
        // 多块流式格式：先读 4B 块大小字段（实际块长以每块 len 字段为准，此处仅对齐流位置）
        let mut bs = [0u8; 4];
        reader.read_exact(&mut bs).map_err(|e| e.to_string())?;
        // 密文缓冲跨块复用（原先每块一次 8MB 级堆分配）
        let mut in_out: Vec<u8> = Vec::new();
        loop {
            let mut nonce_bytes = [0u8; NONCE_LEN];
            match reader.read(&mut nonce_bytes) {
                Ok(0) => break, // EOF：正常结束
                Ok(n) if n < NONCE_LEN => return Err("流式密文 nonce 不完整".to_string()),
                Ok(_) => {}
                Err(e) => return Err(e.to_string()),
            }
            let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
                .map_err(|_| "nonce 长度非法".to_string())?;
            let mut clen = [0u8; 4];
            reader.read_exact(&mut clen).map_err(|e| e.to_string())?;
            let clen = u32::from_le_bytes(clen) as usize;
            in_out.clear();
            in_out.resize(clen + TAG_LEN, 0);
            reader.read_exact(&mut in_out).map_err(|e| e.to_string())?;
            let plain = opening_key
                .open_in_place(nonce, Aad::empty(), &mut in_out)
                .map_err(|_| "解密失败：密钥不匹配或数据被篡改".to_string())?;
            writer.write_all(plain).map_err(|e| e.to_string())?;
        }
        Ok(true)
    } else {
        // 单块格式（手机端 CipherOutputStream 流式 GCM）：ver 是 nonce 前 4 字节
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[..4].copy_from_slice(&ver);
        reader
            .read_exact(&mut nonce_bytes[4..])
            .map_err(|e| e.to_string())?;
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| "nonce 长度非法".to_string())?;
        let mut in_out = Vec::new();
        reader.read_to_end(&mut in_out).map_err(|e| e.to_string())?;
        if in_out.len() < TAG_LEN {
            return Err("密文长度不足（缺 tag）".to_string());
        }
        let plain = opening_key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| "解密失败：密钥不匹配或数据被篡改".to_string())?;
        writer.write_all(plain).map_err(|e| e.to_string())?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_key("AB3FXY12");
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
        let key = derive_key("AB3FXY12");
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
        let key = derive_key("AB3FXY12");
        let wrong_key = derive_key("ZZZZZZZZ");
        let encrypted = encrypt(&key, b"secret").unwrap();
        assert!(decrypt(&wrong_key, &encrypted).is_err(), "错误密钥应解密失败");
    }

    #[test]
    fn tampered_data_fails_to_decrypt() {
        let key = derive_key("AB3FXY12");
        let mut encrypted = encrypt(&key, b"integrity check").unwrap();
        // 篡改最后一个字节（tag 区域）
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;
        assert!(decrypt(&key, &encrypted).is_err(), "被篡改的数据应解密失败");
    }

    #[test]
    fn non_encrypted_data_returns_none() {
        let key = derive_key("AB3FXY12");
        let plaintext = b"this is a plaintext file from another app";
        assert!(!is_encrypted(plaintext), "外部明文不应带魔数");
        assert!(decrypt(&key, plaintext).is_err(), "非本格式不应解密");
    }

    #[test]
    fn upload_stream_roundtrip_and_size() {
        // 上传流（upload_single unfold）与 decrypt_stream 的往返不变量：
        // header + 逐块 seal_stream_block 的输出必须能被 decrypt_stream 还原，
        // 且总长恰等于 enc_output_size 的预计算值（prepare-upload 依赖该精确值）
        let key = derive_key("AB3FXY12");
        let plain: Vec<u8> = (0..(STREAM_ENC_BLOCK * 2 + 1234))
            .map(|i| (i % 251) as u8)
            .collect();
        let mut out = Vec::new();
        out.extend_from_slice(&stream_header_bytes(STREAM_ENC_BLOCK));
        let mut sent = 0usize;
        while sent < plain.len() {
            let end = (sent + STREAM_ENC_BLOCK).min(plain.len());
            let mut blk = plain[sent..end].to_vec();
            seal_stream_block(&key, &mut blk, &mut out).unwrap();
            sent = end;
        }
        assert_eq!(
            out.len() as u64,
            enc_output_size(plain.len() as u64),
            "预计算密文长度必须与实际输出一致"
        );
        let mut dec = Vec::new();
        let mut r = std::io::Cursor::new(&out);
        assert!(decrypt_stream(&key, &mut r, &mut dec).unwrap());
        assert_eq!(dec, plain);
    }

    #[test]
    fn seal_block_layout() {
        let key = derive_key("AB3FXY12");
        let mut blk = b"hello".to_vec();
        let mut out = Vec::new();
        seal_stream_block(&key, &mut blk, &mut out).unwrap();
        eprintln!("blk.len={} out.len={}", blk.len(), out.len());
        assert_eq!(blk.len(), 5 + TAG_LEN, "密封后 buf 应为 ct+tag");
        assert_eq!(out.len(), NONCE_LEN + 4 + 5 + TAG_LEN, "块输出应为 nonce+len+ct+tag");
    }

    #[test]
    fn upload_stream_empty_file_header_only() {
        // 空文件：上传流只输出 12B 格式头，解密得到空内容
        let key = derive_key("AB3FXY12");
        let out = stream_header_bytes(STREAM_ENC_BLOCK).to_vec();
        assert_eq!(out.len() as u64, enc_output_size(0));
        let mut dec = Vec::new();
        let mut r = std::io::Cursor::new(&out);
        assert!(decrypt_stream(&key, &mut r, &mut dec).unwrap());
        assert!(dec.is_empty());
    }
}