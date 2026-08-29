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

// ===== 可证明 Merkle：BEP-0052 proof / verify 补完（见 V4-ARCHITECTURE §3.4 问题3） =====

/// 单层哈希 `H(left ‖ right)`
fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// 可证明 Merkle 树：存储全部层级，支持对任意叶子生成证明并独立校验。
///
/// - 叶子即 piece 的 SHA-256（见模块文档「叶子必须是强哈希」）。
/// - 奇数层节点复制自身（BEP-0052 / DESIGN-WISDOM-REGISTER A16）。
/// - 树的层级 `O(n)` 内存构建、`O(log n)` 校验单叶 —— 满足「流式、不把整文件读进内存」的硬约束（C7/M6）。
pub struct MerkleTree {
    /// `levels[0]` = 叶子；`levels[last]` = `[root]`。空输入时为 `vec![vec![]]`。
    levels: Vec<Vec<[u8; 32]>>,
}

/// 单叶证明：从叶子到根的兄弟哈希序列（按层级自底向上排列）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub index: usize,
    pub siblings: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// 由叶子构建完整树（空输入视为无树，root = 全零，由调用方按空文件处理）
    pub fn build(leaves: &[[u8; 32]]) -> Self {
        if leaves.is_empty() {
            return MerkleTree {
                levels: vec![vec![]],
            };
        }
        let mut levels = vec![leaves.to_vec()];
        while levels.last().unwrap().len() > 1 {
            let cur = levels.last().unwrap();
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            let mut i = 0;
            while i < cur.len() {
                let left = cur[i];
                let right = if i + 1 < cur.len() {
                    cur[i + 1]
                } else {
                    cur[i]
                };
                next.push(hash_pair(left, right));
                i += 2;
            }
            levels.push(next);
        }
        MerkleTree { levels }
    }

    /// 根哈希
    pub fn root(&self) -> MerkleRoot {
        match self.levels.last() {
            Some(last) if !last.is_empty() => last[0],
            _ => [0u8; 32],
        }
    }

    /// 为第 `index` 个叶子生成证明（兄弟哈希链）。
    /// 奇数层末节点以自身为兄弟（复制自身），与 `build` 的构造保持一致。
    pub fn proof(&self, index: usize) -> MerkleProof {
        let mut siblings = Vec::new();
        let mut idx = index;
        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            let n = level.len();
            if n <= 1 {
                break;
            }
            let sibling = if idx.is_multiple_of(2) {
                if idx + 1 < n {
                    level[idx + 1]
                } else {
                    level[idx] // 奇数层末节点复制自身
                }
            } else {
                level[idx - 1]
            };
            siblings.push(sibling);
            idx /= 2;
        }
        MerkleProof { index, siblings }
    }
}

/// 校验单个叶子（piece）是否合法地属于 `root`，只需该叶子的哈希与其证明，
/// 无需持有完整树。接收端据此独立验证任意一块（BEP-0052 精髓：单 piece 可独立验证）。
pub fn verify_piece(index: usize, leaf: &[u8; 32], proof: &MerkleProof, root: &MerkleRoot) -> bool {
    let mut cur = *leaf;
    let mut idx = index;
    for sib in &proof.siblings {
        let (left, right) = if idx.is_multiple_of(2) {
            (cur, *sib)
        } else {
            (*sib, cur)
        };
        cur = hash_pair(left, right);
        idx /= 2;
    }
    cur == *root
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

    // ===== 可证明 Merkle（proof / verify）测试向量 =====

    fn build_leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| leaf(&format!("leaf-{i}"))).collect()
    }

    #[test]
    fn tree_root_matches_flat_root() {
        // 可证明树的 root 必须与既有的 merkle_root 一致（单一事实源）
        for n in [1usize, 2, 3, 4, 5, 7, 16] {
            let leaves = build_leaves(n);
            let tree = MerkleTree::build(&leaves);
            assert_eq!(tree.root(), merkle_root(&leaves), "n={n}");
        }
    }

    #[test]
    fn empty_tree_root_is_zero() {
        let tree = MerkleTree::build(&[]);
        assert_eq!(tree.root(), [0u8; 32]);
        // 空树的 proof 为空、verify 对任意 leaf 都失败（没有合法根）
        let proof = tree.proof(0);
        assert!(proof.siblings.is_empty());
    }

    #[test]
    fn verify_all_indices_in_small_tree() {
        // 3 片：逐一验证每个 index 的证明都能还原出 root
        let leaves = build_leaves(3);
        let tree = MerkleTree::build(&leaves);
        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i);
            assert!(verify_piece(i, leaf, &proof, &root), "index {i} 应校验通过");
        }
    }

    #[test]
    fn verify_rejects_tampered_leaf() {
        let leaves = build_leaves(4);
        let tree = MerkleTree::build(&leaves);
        let root = tree.root();
        let proof = tree.proof(1);
        // 用错误的叶子哈希去验：必须失败
        let wrong = sha256_of(b"NOT the real leaf-1");
        assert!(!verify_piece(1, &wrong, &proof, &root));
        // 但用正确叶子 + 篡改后的 root：也必须失败
        let proof_ok = tree.proof(1);
        let mut fake_root = root;
        fake_root[0] ^= 0xff;
        assert!(!verify_piece(1, &leaves[1], &proof_ok, &fake_root));
    }

    #[test]
    fn verify_handles_odd_last_node_duplication() {
        // 5 片：最后一层会出现奇数节点复制自身；末片 index=4 的 proof 必须正确
        let leaves = build_leaves(5);
        let tree = MerkleTree::build(&leaves);
        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i);
            assert!(
                verify_piece(i, leaf, &proof, &root),
                "index {i}（含奇数层复制）应校验通过"
            );
        }
    }

    #[test]
    fn proof_is_order_independent_of_sibling_rules() {
        // 同一 root，乱序/任意 index 的 proof 长度 = ceil(log2(n))
        let leaves = build_leaves(8);
        let tree = MerkleTree::build(&leaves);
        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i);
            assert_eq!(proof.siblings.len(), 3, "8 叶树 proof 深度应为 3");
            assert!(verify_piece(i, leaf, &proof, &root));
        }
    }
}
