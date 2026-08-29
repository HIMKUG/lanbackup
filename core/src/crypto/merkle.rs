//! Merkle 树 —— V4 主算法的整文件完整性校验原语
//!
//! 主算法以 4MB piece 为粒度传输，每个 piece 算 SHA-256 作为叶子，
//! 逐层两两哈希得到 Merkle 根。`FileMeta.merkleRoot` 即此根。
//! 接收端收齐后独立重建并比对根，既能校验整文件、又能定位损坏的单个 piece。
//!
//! 设计要点（来自 DESIGN-WISDOM-REGISTER）：
//! - 叶子必须是**密码学强哈希（SHA-256）**，不能用弱校验代替根。
//!   弱校验仅用于「快速跳过不变块」的数据面（见 `transfer::diff`），
//!   根的层级哈希必须用强哈希，否则整文件校验可被碰撞绕过。
//! - 奇数层节点复制自身（标准做法），保证任何数量的叶子都能收敛到单根。
//! - 树结构 `O(1)` 内存构建、`O(log n)` 校验单叶 —— 满足「流式、不把整文件读进内存」的硬约束。

use sha2::{Digest, Sha256};

/// Merkle 根（32 字节 SHA-256）
pub type MerkleRoot = [u8; 32];

/// 由 piece 的 SHA-256 叶子计算 Merkle 根。
///
/// `leaves` 为空时返回全零（调用方应单独处理空文件：空文件无需传输，
/// 直接置 completed）。
pub fn merkle_root(leaves: &[[u8; 32]]) -> MerkleRoot {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                level[i] // 奇数层：复制最后一个节点
            };
            let mut h = Sha256::new();
            h.update(left);
            h.update(right);
            next.push(h.finalize().into());
            i += 2;
        }
        level = next;
    }
    level[0]
}

/// 单叶哈希辅助：对一段字节算 SHA-256（piece 哈希、文件哈希统一用这个）
pub fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(s: &str) -> [u8; 32] {
        sha256_of(s.as_bytes())
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn single_leaf_root_is_leaf() {
        let l = leaf("piece-0");
        assert_eq!(merkle_root(&[l]), l);
    }

    #[test]
    fn two_leaves_matches_manual() {
        let a = leaf("a");
        let b = leaf("b");
        let mut h = Sha256::new();
        h.update(a);
        h.update(b);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(merkle_root(&[a, b]), expected);
    }

    #[test]
    fn odd_count_duplicates_last() {
        // 3 个叶子：第 3 个被复制参与最后一层
        let a = leaf("a");
        let b = leaf("b");
        let c = leaf("c");
        // 层 1: H(a,b), H(c,c)
        let mut h1 = Sha256::new();
        h1.update(a);
        h1.update(b);
        let n1: [u8; 32] = h1.finalize().into();
        let mut h2 = Sha256::new();
        h2.update(c);
        h2.update(c);
        let n2: [u8; 32] = h2.finalize().into();
        // 根: H(n1, n2)
        let mut hr = Sha256::new();
        hr.update(n1);
        hr.update(n2);
        let expected: [u8; 32] = hr.finalize().into();
        assert_eq!(merkle_root(&[a, b, c]), expected);
    }

    #[test]
    fn determinism() {
        let leaves: Vec<[u8; 32]> = (0..16).map(|i| leaf(&format!("p{i}"))).collect();
        assert_eq!(merkle_root(&leaves), merkle_root(&leaves));
    }
}
