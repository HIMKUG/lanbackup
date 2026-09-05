//! CSPRNG 会话/文件 ID 生成（登记簿 P26）
//!
//! P26：**sessionId / folderId 必须用 CSPRNG** —— 原 `Date.now() + Math.random()`
//! 生成的 sessionId 可预测，同网段攻击者能据此劫持会话；folderId 会在同一毫秒
//! 碰撞导致配置互相覆盖。
//!
//! V4 统一走 `rand::thread_rng()`（系统 CSPRNG 种子），输出 32 字节 → 64 位十六进制
//! 字符串（≈256 bit 熵）。配合 server 侧会话归属校验（知道 sessionId 也不能往别人
//! 的会话里塞文件），可预测性攻击面被完全关闭。

use rand::RngCore;

/// 会话/文件 ID 的字节数（32 字节 = 256 bit 熵）
const ID_BYTES: usize = 32;

const HEX: &[u8; 16] = b"0123456789abcdef";

fn random_hex() -> String {
    let mut buf = [0u8; ID_BYTES];
    rand::thread_rng().fill_bytes(&mut buf);
    let mut out = String::with_capacity(ID_BYTES * 2);
    for b in buf {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// 生成新会话 ID（CSPRNG，64 位十六进制）
pub fn new_session_id() -> String {
    random_hex()
}

/// 生成新文件 ID（CSPRNG，64 位十六进制）
pub fn new_file_id() -> String {
    random_hex()
}

#[cfg(test)]
mod tests {
    use super::{new_file_id, new_session_id, ID_BYTES};

    #[test]
    fn session_id_is_64_hex_chars() {
        let id = new_session_id();
        assert_eq!(id.len(), ID_BYTES * 2);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn file_id_is_64_hex_chars() {
        let id = new_file_id();
        assert_eq!(id.len(), ID_BYTES * 2);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn consecutive_ids_differ() {
        assert_ne!(new_session_id(), new_session_id());
        assert_ne!(new_file_id(), new_file_id());
    }

    #[test]
    fn no_collision_across_1000_generations() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(new_session_id()), "批量生成出现碰撞");
        }
        assert_eq!(seen.len(), 1000);
    }
}
