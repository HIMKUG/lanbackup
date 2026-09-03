//! challenge / revoke 令牌（紧凑 JWS，HS256）
//!
//! # 为什么 `exp` 不用来拒绝请求
//!
//! `protocol/README.md:24` 已经明确放弃了 `X-Timestamp ± 容差` 校验：
//! 局域网内两台设备的时钟差可以是几分钟（手机关了自动对时、桌面刚从休眠唤醒），
//! 任何基于绝对时间的拒绝逻辑都会变成"随机握手失败"。这类失败最难排查 ——
//! 用户看到的是"有时能连有时不能"，日志里只有一句 token expired。
//!
//! 所以本模块的 [`verify`] **只验签名，不因过期拒绝**，
//! 而是把 `expired` 作为一个事实报告出来供日志与告警使用。
//!
//! # 那重放靠什么防
//!
//! 靠 `jti` **一次性消费**（[`ConsumedTokens`]），而不是靠时间窗口。
//! 这是刻意的替换：一次性消费不依赖任何时钟，因此不受时钟差影响，
//! 安全性还更强 —— 时间窗口内可以无限重放，一次性消费连一次都不行。
//!
//! `exp` 于是退化为**卫生约束**：它的唯一作用是让 [`ConsumedTokens::prune`]
//! 知道什么时候可以安全地忘掉一个 `jti`，避免集合无限增长。

use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::crypto::{ct_eq, hmac_sha256};

/// challenge token 有效期（秒）。仅用于 `jti` 的清理时机，不用于拒绝。
pub const CHALLENGE_TTL_SECS: i64 = 300;

/// 吊销令牌有效期（秒，30 天）。
///
/// 对端离线时解配对必须仍能生效：本机把 `revokeToken` 留着，
/// 对端一旦上线就用它兜底解除。30 天覆盖"出差回来才开机"这种真实场景。
pub const REVOKE_TOKEN_TTL_SECS: i64 = 30 * 24 * 3600;

/// 固定的 JWS 头（`alg=HS256, typ=JWT`）。
///
/// **不解析对端送来的 `alg`**：那是 JWT 最经典的漏洞面
/// （`alg: none` 绕过、把 HS256 当 RS256 用公钥当密钥）。
/// 我们只认这一种，头部字节必须逐字节相等。
const HEADER_JSON: &[u8] = br#"{"alg":"HS256","typ":"JWT"}"#;

/// 令牌用途。域分隔，防止 challenge 令牌被当作吊销令牌使用。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    /// 路径 B 重连的 challenge
    Challenge,
    /// 解配对 / 吊销兜底
    Revoke,
}

/// 令牌载荷
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// 签发对象的 deviceId
    pub sub: String,
    /// 一次性标识（重放防护的真正依据）
    pub jti: String,
    /// 签发时间（Unix 秒）
    pub iat: i64,
    /// 过期时间（Unix 秒）。**卫生字段**：不用于拒绝，见模块文档。
    pub exp: i64,
    /// 绑定本次握手的随机数（hex）
    pub nonce: String,
    /// 用途
    pub kind: TokenKind,
}

impl Claims {
    /// 构造一个 challenge 令牌的载荷
    pub fn challenge(sub: &str, jti: &str, nonce: &str, now: i64) -> Self {
        Self {
            sub: sub.to_string(),
            jti: jti.to_string(),
            iat: now,
            exp: now + CHALLENGE_TTL_SECS,
            nonce: nonce.to_string(),
            kind: TokenKind::Challenge,
        }
    }

    /// 构造一个吊销令牌的载荷
    pub fn revoke(sub: &str, jti: &str, nonce: &str, now: i64) -> Self {
        Self {
            sub: sub.to_string(),
            jti: jti.to_string(),
            iat: now,
            exp: now + REVOKE_TOKEN_TTL_SECS,
            nonce: nonce.to_string(),
            kind: TokenKind::Revoke,
        }
    }
}

/// 验签结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    pub claims: Claims,
    /// 是否已过 `exp`。**报告事实，调用方不得据此拒绝请求**（见模块文档）。
    pub expired: bool,
}

/// 验签失败原因
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("令牌格式不合法：应为 header.payload.signature 三段")]
    Malformed,
    #[error("头部不是本实现认可的 HS256（不解析对端 alg，只认固定头）")]
    UnsupportedHeader,
    #[error("签名不符")]
    BadSignature,
    #[error("载荷不是合法 JSON 或缺字段")]
    BadPayload,
    #[error("令牌用途不符：期望 {expected:?}，实际 {actual:?}")]
    WrongKind {
        expected: TokenKind,
        actual: TokenKind,
    },
}

fn sign_bytes(secret: &[u8], input: &[u8]) -> Vec<u8> {
    hmac_sha256(secret, input).to_vec()
}

/// 签发一个紧凑 JWS
pub fn mint(secret: &[u8], claims: &Claims) -> String {
    let header = URL_SAFE_NO_PAD.encode(HEADER_JSON);
    let payload = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(claims).expect("Claims 全是标量与 String，序列化不会失败"));
    let signing_input = format!("{header}.{payload}");
    let sig = URL_SAFE_NO_PAD.encode(sign_bytes(secret, signing_input.as_bytes()));
    format!("{signing_input}.{sig}")
}

/// 验签并解析载荷。
///
/// **不因过期而失败** —— 过期与否由 [`VerifiedToken::expired`] 报告。
/// `expected_kind` 做用途校验：一个 challenge 令牌不能被当成吊销令牌使用。
pub fn verify(
    secret: &[u8],
    token: &str,
    now: i64,
    expected_kind: TokenKind,
) -> Result<VerifiedToken, TokenError> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(TokenError::Malformed);
    };

    // 固定头：逐字节比对，绝不解析对端声明的 alg
    if header != URL_SAFE_NO_PAD.encode(HEADER_JSON) {
        return Err(TokenError::UnsupportedHeader);
    }

    let provided = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|_| TokenError::Malformed)?;
    let signing_input = format!("{header}.{payload}");
    if !ct_eq(&sign_bytes(secret, signing_input.as_bytes()), &provided) {
        return Err(TokenError::BadSignature);
    }

    let raw = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| TokenError::BadPayload)?;
    let claims: Claims = serde_json::from_slice(&raw).map_err(|_| TokenError::BadPayload)?;

    if claims.kind != expected_kind {
        return Err(TokenError::WrongKind {
            expected: expected_kind,
            actual: claims.kind,
        });
    }

    Ok(VerifiedToken {
        expired: now > claims.exp,
        claims,
    })
}

/// 已消费的 `jti` 集合 —— 重放防护的**实际**承载者。
///
/// 与"时间窗口"方案的区别：窗口内可以无限重放，一次性消费连第二次都不行，
/// 而且完全不依赖时钟正确性。
#[derive(Debug, Clone, Default)]
pub struct ConsumedTokens {
    /// jti → 该令牌的 `exp`（到点即可安全遗忘）
    seen: HashMap<String, i64>,
}

impl ConsumedTokens {
    pub fn new() -> Self {
        Self::default()
    }

    /// 尝试消费一个令牌。返回 `true` 表示首次使用（放行）；
    /// `false` 表示重放（拒绝）。
    pub fn consume(&mut self, claims: &Claims) -> bool {
        // `Entry` 一次哈希完成"查 + 插"，避免 contains_key + insert 的竞态窗口
        match self.seen.entry(claims.jti.clone()) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(claims.exp);
                true
            }
        }
    }

    /// 清理已过期的记录。
    ///
    /// 这是 `exp` 唯一的实际用途。**必须周期性调用**：不清理的话集合随握手次数
    /// 单调增长，长期驻留的桌面端进程会缓慢泄漏内存。
    pub fn prune(&mut self, now: i64) {
        self.seen.retain(|_, exp| *exp >= now);
    }

    /// 当前记录条数（诊断/测试用）
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"pairing-secret";

    fn claims(now: i64) -> Claims {
        Claims::challenge("dev-1", "jti-1", "abcd", now)
    }

    #[test]
    fn mint_and_verify_roundtrip() {
        let c = claims(1000);
        let t = mint(SECRET, &c);
        let v = verify(SECRET, &t, 1000, TokenKind::Challenge).unwrap();
        assert_eq!(v.claims, c);
        assert!(!v.expired);
    }

    #[test]
    fn compact_form_has_three_segments() {
        let t = mint(SECRET, &claims(0));
        assert_eq!(t.split('.').count(), 3);
        assert!(!t.contains('='), "URL-safe 无填充编码不该出现 '='");
        assert!(
            !t.contains('+') && !t.contains('/'),
            "必须是 URL-safe 字母表"
        );
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let t = mint(SECRET, &claims(0));
        assert_eq!(
            verify(b"other", &t, 0, TokenKind::Challenge),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let t = mint(SECRET, &claims(0));
        let mut parts: Vec<&str> = t.split('.').collect();
        let forged = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&Claims::challenge("attacker", "jti-1", "abcd", 0)).unwrap(),
        );
        parts[1] = &forged;
        let forged_token = parts.join(".");
        assert_eq!(
            verify(SECRET, &forged_token, 0, TokenKind::Challenge),
            Err(TokenError::BadSignature)
        );
    }

    /// `alg: none` 与 alg 混淆是 JWT 最经典的漏洞面 —— 必须在头部就挡住。
    #[test]
    fn alg_none_is_rejected() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims(0)).unwrap());
        let token = format!("{header}.{payload}.");
        assert_eq!(
            verify(SECRET, &token, 0, TokenKind::Challenge),
            Err(TokenError::UnsupportedHeader)
        );
    }

    #[test]
    fn malformed_shapes_are_rejected() {
        for bad in ["", "a", "a.b", "a.b.c.d"] {
            assert_eq!(
                verify(SECRET, bad, 0, TokenKind::Challenge),
                Err(TokenError::Malformed),
                "{bad} 应判为格式错误"
            );
        }
    }

    /// **核心取舍**：过期只报告、不拒绝。双端时钟差不得导致握手失败。
    #[test]
    fn expired_token_still_verifies_but_is_flagged() {
        let t = mint(SECRET, &claims(1000));
        let v = verify(
            SECRET,
            &t,
            1000 + CHALLENGE_TTL_SECS + 1,
            TokenKind::Challenge,
        )
        .expect("过期不得导致验签失败 —— 时钟差会变成随机握手失败");
        assert!(v.expired, "过期事实必须被报告出来");
    }

    #[test]
    fn kind_confusion_is_rejected() {
        let t = mint(SECRET, &Claims::revoke("dev-1", "j", "n", 0));
        assert_eq!(
            verify(SECRET, &t, 0, TokenKind::Challenge),
            Err(TokenError::WrongKind {
                expected: TokenKind::Challenge,
                actual: TokenKind::Revoke,
            })
        );
    }

    #[test]
    fn revoke_token_ttl_is_thirty_days() {
        let c = Claims::revoke("dev-1", "j", "n", 0);
        assert_eq!(c.exp, REVOKE_TOKEN_TTL_SECS);
        assert_eq!(REVOKE_TOKEN_TTL_SECS, 2_592_000);
    }

    #[test]
    fn jti_can_only_be_consumed_once() {
        let mut store = ConsumedTokens::new();
        let c = claims(1000);
        assert!(store.consume(&c), "首次使用应放行");
        assert!(!store.consume(&c), "第二次必须拒绝 —— 这才是重放防护");
    }

    /// 一次性消费不依赖时钟：即使令牌"没过期"，重放照样被拒。
    #[test]
    fn replay_is_blocked_regardless_of_clock() {
        let mut store = ConsumedTokens::new();
        let t = mint(SECRET, &claims(1000));
        let v1 = verify(SECRET, &t, 1000, TokenKind::Challenge).unwrap();
        assert!(store.consume(&v1.claims));
        let v2 = verify(SECRET, &t, 1001, TokenKind::Challenge).unwrap();
        assert!(!v2.expired);
        assert!(!store.consume(&v2.claims), "未过期的令牌也不得重复使用");
    }

    #[test]
    fn prune_forgets_only_expired_entries() {
        let mut store = ConsumedTokens::new();
        store.consume(&Claims::challenge("d", "old", "n", 0)); // exp = 300
        store.consume(&Claims::challenge("d", "new", "n", 1000)); // exp = 1300
        assert_eq!(store.len(), 2);

        store.prune(1000);
        assert_eq!(store.len(), 1, "过期的 jti 应被遗忘，避免集合无限增长");

        // 被遗忘之后同一个 jti 可以再次使用 —— 这是安全的：
        // 令牌本身已过期，攻击者拿它也过不了业务层的其它检查。
        assert!(store.consume(&Claims::challenge("d", "old", "n", 2000)));
    }

    #[test]
    fn prune_keeps_entry_exactly_at_expiry_boundary() {
        let mut store = ConsumedTokens::new();
        store.consume(&Claims::challenge("d", "j", "n", 0)); // exp = 300
        store.prune(300);
        assert_eq!(store.len(), 1, "恰好等于 exp 的瞬间还不该遗忘");
        store.prune(301);
        assert!(store.is_empty());
    }
}
