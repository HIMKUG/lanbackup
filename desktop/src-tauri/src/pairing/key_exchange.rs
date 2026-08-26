//! pairing/key_exchange.rs — 密钥协商（保留接口，#8 传输加密完成后启用）
//!
//! 本版本配对使用连接码直接验证，ECDH 密钥协商尚未接入。
//! 预留此模块供后续 #8 传输加密完成后实现完整的密钥协商流程。
//!
//! 故意标记 allow(dead_code)：#8/#9 重构完成后接线。

use crate::pairing::error::PairingError;

/// 生成临时 ECDH 密钥对（预留，allow(dead_code)：#8 传输加密完成后启用）
#[allow(dead_code)]
pub fn generate_ephemeral_keypair() -> Result<(), PairingError> {
    // TODO(#8): 实现 ECDH P-256 临时密钥对生成
    Ok(())
}

/// 执行 ECDH 密钥协商（预留，allow(dead_code)：#8 传输加密完成后启用）
#[allow(dead_code)]
pub fn derive_session_key(_public_key: &[u8]) -> Result<Vec<u8>, PairingError> {
    // TODO(#8): 实现 ECDH 共享密钥派生
    Ok(vec![])
}
