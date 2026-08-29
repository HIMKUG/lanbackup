//! 密码学原语
//!
//! 阶段 4.5 会在此落地握手层 ECDSA 签名 + 统一 AEAD 传输加密。
//! 当前先落地主算法依赖的 Merkle 校验原语（纯计算、可独立测试）。

pub mod merkle;

pub use merkle::{
    merkle_root, sha256_of, verify_piece, MerkleProof, MerkleRoot, MerkleTree,
};
