//! 控制面端点（阶段 4 / 5：发现、配对、握手、双向信任对账）
//!
//! 全部复用 core 已有且经测试的基元：`identity` / `pairing::{machine,transcript,token,trust}`
//! / `crypto::{sign,kdf}` / `state::presence`。本文件只做**编排**，不新造密码学原语。
//!
//! 与移动端旧 53318 手写 TCP+HTTP 解析器彻底切割：控制面现在走与传输会话
//! 完全相同的 hyper 路由（`routes::ALL` 单一来源）。
//!
//! # 两条关键设计约束（改动前请先读）
//!
//! ## 1. `GET /api/v4/sync-status` 是纯读，绝不在其中改状态
//!
//! `routes.rs` 的 `query_endpoints_are_get_and_mutations_are_post` 已经把
//! sync-status 断言为查询端点。GET 会被代理和客户端库自动重试，
//! 把对账（会推进状态机、+1 信任版本号）放进 GET，等于默许
//! "网络抖一下就多推进一次状态机"。
//!
//! 所以职责这样切：
//! - **服务端**（[`handle_sync_status`]）只回答"我这边怎么看你"，不碰自己的记录；
//! - **调用方**拿到对端的回答后，用 [`reconcile_with_peer`] 在**本地**驱动状态机。
//!
//! 这也正好对上 `trust::reconcile(local, peer)` 的签名 —— 它要的 `peer`
//! 就是对端 GET 回来的 `SyncStatusResponse`。
//!
//! ## 2. probe 签发的 `serverNonce` 必须一次性消费
//!
//! 路径 A 的 HMAC 覆盖 `(deviceId, clientEph, clientNonce, serverNonce, serverStatic)`。
//! 如果服务端不校验 `serverNonce` 是不是自己刚发出去的，那么抓到一次成功握手的
//! `(nonce_c, nonce_s, hmac)` 三元组之后就能**永久重放** —— 攻击者自带一套
//! 早年抓的 nonce 即可反复配对成功。
//!
//! 因此 [`handle_probe`] 把签发的 nonce 记下，路径 A 校验时
//! [`HandshakeStore::take_nonce`] 一次性取走。防重放不依赖时钟
//! （和 `token::ConsumedTokens` 同一套思路）。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use http_body_util::Full;
use hyper::Response;
use tokio::sync::Mutex;

use crate::crypto::kdf::{self, sha256};
use crate::crypto::sign::{self as p256sign, EphemeralKeyPair};
use crate::dto::handshake::*;
use crate::dto::Presence;
use crate::error::ErrorCode;
use crate::pairing::machine::PairingEvent;
use crate::pairing::token::{self, Claims, ConsumedTokens, TokenKind};
use crate::pairing::transcript;
use crate::pairing::trust::{self, TrustRecord};
use crate::version::{Capabilities, DEFAULT_PORT, PROTOCOL_VERSION};

use super::{err_response, ok_json, parse_body, SessionStore};

/// probe 签发但尚未被消费的 nonce 上限。
///
/// 有上界才不会被"疯狂 probe"打成内存泄漏：满了就丢最旧的。
/// 丢掉的后果只是那次握手要重新 probe，不影响安全性。
const MAX_PENDING_NONCES: usize = 256;

// ── 编码小工具 ────────────────────────────────────────────────
fn b64u(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}
fn b64u_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}
fn hex_enc(b: &[u8]) -> String {
    hex::encode(b)
}
fn hex_dec(s: &str) -> Option<Vec<u8>> {
    hex::decode(s).ok()
}
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── 运行时存储 ────────────────────────────────────────────────

/// 本机视角下某个对端的完整记录。
#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub device_id: String,
    pub alias: String,
    /// 对端静态 ECDSA 公钥（SEC1 字节）—— 解配对/吊销签名验签用。
    ///
    /// **已知缺口**：路径 A/B 的握手请求只携带对端的 *临时* ECDH 公钥，
    /// 不携带其静态公钥。当前实现在握手时把临时公钥暂存于此；
    /// 真正的静态公钥交换需由协议 README 明确（见模块底部注释）。
    pub public_key: Vec<u8>,
    /// 由连接码派生的长期配对密钥（L2），用于 challenge 令牌的签发/验签。
    pub pairing_secret: Vec<u8>,
    /// 配对状态机记录（含信任版本号）
    pub trust: TrustRecord,
    /// 本端视角下对端的在线状态
    pub presence: Presence,
    /// 最近一次 `sync-status` 对账得到的对端视图
    pub last_peer_status: Option<SyncStatusResponse>,
}

impl PeerRecord {
    pub fn new(
        device_id: &str,
        alias: &str,
        public_key: Vec<u8>,
        pairing_secret: Vec<u8>,
        trust: TrustRecord,
    ) -> Self {
        Self {
            device_id: device_id.to_string(),
            alias: alias.to_string(),
            public_key,
            pairing_secret,
            trust,
            presence: Presence::Unknown,
            last_peer_status: None,
        }
    }
}

/// 已配对/已知对端的注册表（内存实现；生产换 rusqlite）。
#[derive(Default)]
pub struct PeerStore {
    inner: Mutex<HashMap<String, PeerRecord>>,
}

impl PeerStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 取对端记录（克隆）。不存在返回 `None`。
    pub async fn entry(&self, id: &str) -> Option<PeerRecord> {
        self.inner.lock().await.get(id).cloned()
    }

    /// 写入/覆盖对端记录。
    pub async fn put(&self, rec: PeerRecord) {
        self.inner.lock().await.insert(rec.device_id.clone(), rec);
    }

    /// 当前所有对端（诊断/测试）。
    pub async fn all(&self) -> Vec<PeerRecord> {
        self.inner.lock().await.values().cloned().collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakePhase {
    Pending,
    Done,
    Failed,
}

/// 一次进行中的握手（按 `requestId` 索引，支持幂等与状态查询）。
#[derive(Debug, Clone)]
pub struct HandshakeSession {
    pub device_id: String,
    pub client_nonce: String,
    pub server_nonce: String,
    pub pairing_secret: Vec<u8>,
    status: HandshakePhase,
    pub result: Option<PairingState>,
    pub error: Option<String>,
    /// 幂等：同一 requestId 直接回放已签发的 challenge
    pub challenge_response: Option<ChallengeResponse>,
}

/// 握手过程态：进行中的握手 + 一次性令牌防重放 + 用户线下输入的 6 位连接码。
#[derive(Default)]
pub struct HandshakeStore {
    inner: Mutex<HashMap<String, HandshakeSession>>,
    consumed: Mutex<ConsumedTokens>,
    /// probe 已签发、尚未被路径 A 消费的 serverNonce（见模块文档约束 2）
    issued_nonces: Mutex<HashSet<String>>,
    /// 用户在点"配对"时线下输入的 6 位连接码（绝不经过网络）。
    /// 首配（路径 A）验证 HMAC 时需要它派生密钥。
    pairing_code: Mutex<Option<String>>,
}

impl HandshakeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn set_pairing_code(&self, code: String) {
        *self.pairing_code.lock().await = Some(code);
    }

    pub async fn get_pairing_code(&self) -> Option<String> {
        self.pairing_code.lock().await.clone()
    }

    /// 记下一个刚签发的 serverNonce。超出上界时丢弃最旧的一个。
    async fn issue_nonce(&self, nonce: &str) {
        let mut g = self.issued_nonces.lock().await;
        if g.len() >= MAX_PENDING_NONCES {
            if let Some(victim) = g.iter().next().cloned() {
                g.remove(&victim);
            }
        }
        g.insert(nonce.to_string());
    }

    /// 一次性取走 nonce：成功返回 `true`，重复使用或伪造返回 `false`。
    pub async fn take_nonce(&self, nonce: &str) -> bool {
        self.issued_nonces.lock().await.remove(nonce)
    }

    pub async fn insert(&self, rid: &str, sess: HandshakeSession) {
        self.inner.lock().await.insert(rid.to_string(), sess);
    }

    pub async fn get(&self, rid: &str) -> Option<HandshakeSession> {
        self.inner.lock().await.get(rid).cloned()
    }

    /// 取已缓存的 challenge 响应（幂等用）。
    pub async fn cached_challenge(&self, rid: &str) -> Option<ChallengeResponse> {
        self.inner
            .lock()
            .await
            .get(rid)
            .and_then(|s| s.challenge_response.clone())
    }

    pub async fn mark_done(&self, rid: &str, state: PairingState) {
        let mut g = self.inner.lock().await;
        if let Some(s) = g.get_mut(rid) {
            s.status = HandshakePhase::Done;
            s.result = Some(state);
        }
    }

    /// 标记握手失败，并留下**可对外披露**的原因供 `handshake/status` 查询。
    pub async fn mark_failed(&self, rid: &str, reason: &str) {
        let mut g = self.inner.lock().await;
        if let Some(s) = g.get_mut(rid) {
            s.status = HandshakePhase::Failed;
            s.error = Some(reason.to_string());
        }
    }

    /// 一次性消费令牌 jti（真正的重放防护，不依赖时钟）。
    pub async fn consume_jti(&self, claims: &Claims) -> bool {
        self.consumed.lock().await.consume(claims)
    }

    pub async fn prune(&self, now: i64) {
        self.consumed.lock().await.prune(now);
    }
}

// ── 端点处理 ──────────────────────────────────────────────────

/// `GET /api/v4/probe` —— 设备信息 + 静态公钥 + 一次性 serverNonce + 能力位图。
pub async fn handle_probe(store: &Arc<SessionStore>, _path: &str) -> Response<Full<bytes::Bytes>> {
    let server_nonce = hex_enc(&rand::random::<[u8; 32]>());
    // 记下来：路径 A 校验时必须能证明这个 nonce 出自本机（模块文档约束 2）
    store.handshake.issue_nonce(&server_nonce).await;
    let resp = ProbeResponse {
        device_id: store.identity.device_id().to_string(),
        alias: store.alias.clone(),
        device_type: store.device_type,
        port: DEFAULT_PORT,
        protocol_version: PROTOCOL_VERSION,
        static_pub: b64u(&store.identity.public_key_bytes()),
        server_nonce,
        capabilities: Capabilities::all(),
        presence: Some(Presence::Online),
        endpoint: None,
    };
    ok_json(resp)
}

/// `POST /api/v4/handshake/challenge` —— 路径 B（重连）签发 challenge 令牌。
pub async fn handle_handshake_challenge(
    store: &Arc<SessionStore>,
    body: &[u8],
) -> Response<Full<bytes::Bytes>> {
    let req: ChallengeRequest = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    // 重连前提：对端已配对，本机持有其 pairing_secret
    let peer = match store.peers.entry(&req.device_id).await {
        Some(p) => p,
        None => return err_response(ErrorCode::UnknownDevice, "对端未配对，无法重连"),
    };
    // 已解除的设备**不得拿到新的 challenge 令牌**。
    //
    // 这一步和 `verify_path_b` 里的状态检查是刻意的双层防御，不是重复代码：
    // 这里防的是"给已解除的对端签发一个新令牌"（签出去就等于给了它一次
    // 尝试的凭据），那边防的是"令牌签发之后配对关系才被解除"的时间窗。
    // 少了这一层，解配对之后对端仍能不断拿到合法令牌，"解配对不彻底"复现。
    if !matches!(
        peer.trust.state,
        PairingState::Active | PairingState::Pending
    ) {
        return err_response(
            ErrorCode::Untrusted,
            &format!("配对关系已失效（当前 {:?}）：请重新配对", peer.trust.state),
        );
    }
    // 幂等：同一 requestId 直接回放已签发的 challenge。
    // 少了这一步，客户端超时重试会拿到第二个令牌，而第一个令牌的 jti
    // 已进入待消费集合 —— 于是"重试一次就必然失败一次"。
    if let Some(resp) = store.handshake.cached_challenge(&req.request_id).await {
        return ok_json(resp);
    }
    let server_eph = EphemeralKeyPair::generate();
    let server_nonce = hex_enc(&rand::random::<[u8; 32]>());
    let claims = Claims::challenge(
        &req.device_id,
        &req.request_id,
        &req.client_nonce,
        now_secs(),
    );
    let challenge_token = token::mint(&peer.pairing_secret, &claims);
    let resp = ChallengeResponse {
        challenge_token,
        server_eph_pub: b64u(&server_eph.public_key_bytes()),
        server_nonce: server_nonce.clone(),
        request_id: req.request_id.clone(),
    };
    store
        .handshake
        .insert(
            &req.request_id,
            HandshakeSession {
                device_id: req.device_id.clone(),
                client_nonce: req.client_nonce.clone(),
                server_nonce,
                pairing_secret: peer.pairing_secret.clone(),
                status: HandshakePhase::Pending,
                result: None,
                error: None,
                challenge_response: Some(resp.clone()),
            },
        )
        .await;
    ok_json(resp)
}

/// `POST /api/v4/handshake/verify` —— 路径 A 首配（HMAC）/ 路径 B 重连（challenge 令牌）。
pub async fn handle_handshake_verify(
    store: &Arc<SessionStore>,
    body: &[u8],
) -> Response<Full<bytes::Bytes>> {
    let req: VerifyRequest = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };

    if let Some(hmac) = &req.hmac {
        verify_path_a(store, &req, hmac).await
    } else if let Some(ct) = &req.challenge_token {
        verify_path_b(store, &req, ct).await
    } else {
        err_response(
            ErrorCode::BadRequest,
            "必须提供 hmac（路径 A）或 challengeToken（路径 B）",
        )
    }
}

/// 路径 A：首配。连接码 + 双 nonce 派生的 HMAC 认证。
async fn verify_path_a(
    store: &Arc<SessionStore>,
    req: &VerifyRequest,
    hmac: &str,
) -> Response<Full<bytes::Bytes>> {
    let code = match store.handshake.get_pairing_code().await {
        Some(c) => c,
        None => return err_response(ErrorCode::BadRequest, "未设置连接码，无法首配"),
    };
    let client_eph = match b64u_decode(&req.client_eph_pub) {
        Some(b) => b,
        None => return err_response(ErrorCode::BadRequest, "clientEphPub 非法 base64"),
    };
    let cn = match hex_dec(&req.client_nonce) {
        Some(b) => b,
        None => return err_response(ErrorCode::BadRequest, "clientNonce 非法 hex"),
    };
    let sn = match hex_dec(&req.server_nonce) {
        Some(b) => b,
        None => return err_response(ErrorCode::BadRequest, "serverNonce 非法 hex"),
    };
    // 先证明 serverNonce 出自本机 probe 且**未被用过**（模块文档约束 2）。
    // 放在验 HMAC 之前：nonce 不对就没必要做后面的密码学运算。
    if !store.handshake.take_nonce(&req.server_nonce).await {
        store
            .handshake
            .mark_failed(&req.request_id, "serverNonce 无效或已被使用")
            .await;
        return err_response(
            ErrorCode::HmacMismatch,
            "serverNonce 无效或已被使用（请重新 probe）",
        );
    }

    let server_static = store.identity.public_key_bytes();
    let key = transcript::path_a_key(&code, &cn, &sn);
    let tr = match transcript::path_a_transcript(
        &req.device_id,
        &client_eph,
        &cn,
        &sn,
        &server_static,
    ) {
        Some(t) => t,
        None => return err_response(ErrorCode::BadRequest, "transcript 构造失败"),
    };
    let provided = match hex_dec(hmac) {
        Some(b) => b,
        None => return err_response(ErrorCode::BadRequest, "hmac 非法 hex"),
    };
    if !transcript::verify_tag(&key, &tr, &provided) {
        store
            .handshake
            .mark_failed(&req.request_id, "路径 A HMAC 校验失败")
            .await;
        return err_response(
            ErrorCode::HmacMismatch,
            "路径 A HMAC 校验失败：连接码或随机数不符",
        );
    }

    // 派生稳定的长期配对密钥。
    //
    // **已知缺口（stopgap）**：路径 A/B 的 DTO（`VerifyRequest`/`VerifyResponse`）
    // 不携带服务端的 *临时* ECDH 公钥，两端无法完成真正的 ECDH 共享密钥协商。
    // 此处用连接码派生一个**稳定**的 `pairing_secret`，使重连（路径 B）的
    // challenge 令牌可以验证。真正的 ECDH 线格式需待协议 README 明确后替换 ——
    // 换的时候只动这三行，`kdf::derive_pairing_secret` 的调用形状不变。
    let pairing_secret =
        kdf::derive_pairing_secret(&sha256(code.as_bytes()), &code, b"lanbackup/v4/pairing/v1");

    // 状态机是唯一依据：None →(Initiate)→ Pending →(PeerConfirmed)→ Active。
    // 非法迁移会被 `apply` 拒绝，不会静默落地一个不该存在的状态。
    let mut trust = TrustRecord::new();
    if let Err(il) = trust.apply(PairingEvent::Initiate) {
        return err_response(ErrorCode::IllegalState, &il.to_string());
    }
    if let Err(il) = trust.apply(PairingEvent::PeerConfirmed) {
        return err_response(ErrorCode::IllegalState, &il.to_string());
    }

    store
        .peers
        .put(PeerRecord::new(
            &req.device_id,
            "",
            client_eph,
            pairing_secret.to_vec(),
            trust,
        ))
        .await;
    store
        .handshake
        .mark_done(&req.request_id, PairingState::Active)
        .await;
    ok_json(VerifyResponse {
        status: PairingState::Active,
        device_id: req.device_id.clone(),
        alias: None,
        capabilities: Capabilities::all(),
        request_id: req.request_id.clone(),
    })
}

/// 路径 B：重连。challenge 令牌认证（一次性 jti 防重放）。
async fn verify_path_b(
    store: &Arc<SessionStore>,
    req: &VerifyRequest,
    ct: &str,
) -> Response<Full<bytes::Bytes>> {
    let sess = match store.handshake.get(&req.request_id).await {
        Some(s) => s,
        None => return err_response(ErrorCode::NotFound, "未知 requestId"),
    };
    // 注意：这里**故意不因 `verified.expired` 拒绝**。
    // 局域网两端时钟差可达数分钟，按 exp 拒绝会变成"随机握手失败"；
    // 重放防护由下面的 jti 一次性消费承担（见 `pairing::token` 模块文档）。
    let verified = match token::verify(&sess.pairing_secret, ct, now_secs(), TokenKind::Challenge) {
        Ok(v) => v,
        Err(e) => {
            store
                .handshake
                .mark_failed(&req.request_id, "challenge 令牌无效")
                .await;
            return err_response(ErrorCode::TokenExpired, &format!("challenge 令牌无效：{e}"));
        }
    };
    if !store.handshake.consume_jti(&verified.claims).await {
        store
            .handshake
            .mark_failed(&req.request_id, "challenge 令牌已被消费")
            .await;
        return err_response(
            ErrorCode::IllegalState,
            "challenge 令牌已被消费（疑似重放）",
        );
    }
    // 路径 B 是**重连**，不是配对：必须已有对端记录。
    //
    // 不能在这里 `unwrap_or_else` 造一条新记录 —— 那等于"拿着令牌就能凭空
    // 变出一个受信设备"，把重连通道变成了绕过连接码的配对后门。
    // 未知设备一律 404：没有可重连的配对关系。
    let mut rec = match store.peers.entry(&req.device_id).await {
        Some(r) => r,
        None => {
            store
                .handshake
                .mark_failed(&req.request_id, "未知设备，无可重连的配对关系")
                .await;
            return err_response(ErrorCode::UnknownDevice, "未知设备：请先完成首次配对");
        }
    };
    // **重连不是状态迁移**。这是本函数最容易写错的一处：
    //
    // `Active + PeerConfirmed` 在状态机里是**非法**的（machine.rs 流转表里
    // `PeerConfirmed` 只接受 `Pending`）。已配对设备重连时它的信任状态本来
    // 就该是 `Active` —— `Active` 是重连的**前置条件**，不是重连的**结果**。
    // 对已 Active 的记录再发 `PeerConfirmed`，是把"证明身份"误当成"建立信任"。
    //
    // 于是分三种情形，各自有明确理由：
    match rec.trust.state {
        // 常态：已配对设备回来了。只更新在线状态，信任状态原样不动。
        PairingState::Active => {}
        // 首配的收尾在网络抖动中丢了（路径 A 的响应没送达，对端改走路径 B
        // 重试）。此时 `Pending → Active` 是流转表里的合法迁移，补齐即可。
        PairingState::Pending => {
            if let Err(il) = rec.trust.apply(PairingEvent::PeerConfirmed) {
                store
                    .handshake
                    .mark_failed(&req.request_id, "配对状态不允许重连")
                    .await;
                return err_response(ErrorCode::IllegalState, &il.to_string());
            }
        }
        // 已解除 / 解除中 / 未配对：**绝不允许旧令牌复活配对关系**。
        //
        // 这里刻意回 401 而不是 409：客户端拿到 401 才知道该**丢弃本地令牌
        // 并提示重新配对**；回 409 只会让它以为是暂时的状态冲突而不停重试，
        // 于是"解配对不彻底"的老毛病换个地方复现。
        other => {
            store
                .handshake
                .mark_failed(&req.request_id, "配对关系已失效")
                .await;
            return err_response(
                ErrorCode::Untrusted,
                &format!("配对关系已失效（当前 {other:?}）：请重新配对，旧令牌不再受信"),
            );
        }
    }
    rec.presence = Presence::Online;
    store.peers.put(rec).await;
    store
        .handshake
        .mark_done(&req.request_id, PairingState::Active)
        .await;
    ok_json(VerifyResponse {
        status: PairingState::Active,
        device_id: req.device_id.clone(),
        alias: None,
        capabilities: Capabilities::all(),
        request_id: req.request_id.clone(),
    })
}

/// `GET /api/v4/handshake/status` —— 按 requestId 查询握手结果（幂等补偿）。
pub async fn handle_handshake_status(
    store: &Arc<SessionStore>,
    path: &str,
) -> Response<Full<bytes::Bytes>> {
    let rid = match super::extract_query(path, "requestId") {
        Some(s) => s,
        None => return err_response(ErrorCode::BadRequest, "缺少 requestId 参数"),
    };
    // `done` 的语义是"已有结论"，失败也算结论 —— 否则客户端会对一个
    // 已经确定失败的握手无限轮询下去。
    let (done, status, error) = match store.handshake.get(&rid).await {
        Some(s) => (
            matches!(s.status, HandshakePhase::Done | HandshakePhase::Failed),
            s.result,
            s.error.clone(),
        ),
        None => (false, None, Some("unknown requestId".to_string())),
    };
    ok_json(HandshakeStatusResponse {
        request_id: rid,
        done,
        status,
        error,
    })
}

/// `GET /api/v4/sync-status` —— 回答对端"你还认我吗"。
///
/// **纯读**：只报告本机记录，不驱动状态机（原因见模块文档约束 1）。
/// 查询参数 `deviceId` 是**提问方**的设备 ID。
///
/// 对未知设备返回 200 + 显式否认（而不是 404）：对端需要一个可对账的回答，
/// 404 会让它的 `trust::reconcile` 无从下手，只能瞎猜是"网络问题"还是"被解绑了"。
pub async fn handle_sync_status(
    store: &Arc<SessionStore>,
    path: &str,
) -> Response<Full<bytes::Bytes>> {
    let asker = match super::extract_query(path, "deviceId") {
        Some(s) => s,
        None => return err_response(ErrorCode::BadRequest, "缺少 deviceId 参数"),
    };
    let (state, version) = match store.peers.entry(&asker).await {
        Some(r) => (r.trust.state, r.trust.trust_version),
        None => (PairingState::None, 0),
    };
    ok_json(SyncStatusResponse {
        device_id: store.identity.device_id().to_string(),
        // "你（提问方）是否仍被我视为已配对"
        you_are_paired_with_me: matches!(state, PairingState::Active),
        my_trust_version: version,
        status: state,
        presence: Presence::Online,
    })
}

/// 客户端侧对账：拿对端 `GET /sync-status` 的回答驱动**本机**状态机。
///
/// 这是模块文档约束 1 里"写"的那一半 —— 刻意留在调用方，
/// 使 GET 端点保持纯读、可安全重试。返回对账后的本机状态。
pub async fn reconcile_with_peer(
    store: &Arc<SessionStore>,
    peer_view: &SyncStatusResponse,
) -> Option<PairingState> {
    let mut rec = store.peers.entry(&peer_view.device_id).await?;
    let verdict = trust::reconcile(&rec.trust, peer_view);
    if let Some(ev) = verdict.recommended_event() {
        // 对账建议的事件仍要过状态机：`reconcile` 只给"建议"，
        // 合法性由 `apply` 说了算，两者不能互相取代。
        let _ = rec.trust.apply(ev);
    }
    rec.trust.note_peer_version(peer_view.my_trust_version);
    rec.last_peer_status = Some(peer_view.clone());
    rec.presence = peer_view.presence;
    let state = rec.trust.state;
    store.peers.put(rec).await;
    Some(state)
}

/// `POST /api/v4/unpair-request` —— 发起方向对端提出解配对（带 ECDSA 签名）。
pub async fn handle_unpair_request(
    store: &Arc<SessionStore>,
    body: &[u8],
) -> Response<Full<bytes::Bytes>> {
    let req: UnpairRequest = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    let mut rec = match store.peers.entry(&req.device_id).await {
        Some(r) => r,
        None => return err_response(ErrorCode::UnknownDevice, "对端未配对"),
    };
    let payload = match transcript::unpair_payload(&req.device_id, &req.request_id) {
        Some(p) => p,
        None => return err_response(ErrorCode::BadRequest, "payload 构造失败"),
    };
    let sig = match b64u_decode(&req.signature) {
        Some(s) => s,
        None => return err_response(ErrorCode::BadRequest, "signature 非法 base64"),
    };
    if !p256sign::verify(&rec.public_key, &payload, &sig) {
        return err_response(ErrorCode::Untrusted, "解配对请求签名验证失败");
    }
    let next = match rec.trust.apply(PairingEvent::LocalUnpair) {
        Ok(s) => s,
        Err(il) => return err_response(ErrorCode::IllegalState, &il.to_string()),
    };
    store.peers.put(rec).await;
    ok_json(serde_json::json!({"status": next, "requestId": req.request_id}))
}

/// `POST /api/v4/unpair` —— 收到对端的解配对通知（ECDSA 签名），本机进入 Revoked。
pub async fn handle_unpair(store: &Arc<SessionStore>, body: &[u8]) -> Response<Full<bytes::Bytes>> {
    let req: UnpairNotification = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    let mut rec = match store.peers.entry(&req.device_id).await {
        Some(r) => r,
        None => return err_response(ErrorCode::UnknownDevice, "对端未配对"),
    };
    let payload = match transcript::unpair_payload(&req.device_id, &req.request_id) {
        Some(p) => p,
        None => return err_response(ErrorCode::BadRequest, "payload 构造失败"),
    };
    let sig = match b64u_decode(&req.signature) {
        Some(s) => s,
        None => return err_response(ErrorCode::BadRequest, "signature 非法 base64"),
    };
    if !p256sign::verify(&rec.public_key, &payload, &sig) {
        return err_response(ErrorCode::Untrusted, "解配对通知签名验证失败");
    }
    let next = match rec.trust.apply(PairingEvent::PeerUnpair) {
        Ok(s) => s,
        Err(il) => return err_response(ErrorCode::IllegalState, &il.to_string()),
    };
    store.peers.put(rec).await;
    ok_json(serde_json::json!({"status": next, "requestId": req.request_id}))
}

/// `POST /api/v4/revoke-notify` —— 对端离线时的吊销兜底通知（带 revokeToken + 签名）。
pub async fn handle_revoke_notify(
    store: &Arc<SessionStore>,
    body: &[u8],
) -> Response<Full<bytes::Bytes>> {
    let req: RevokeNotify = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    let mut rec = match store.peers.entry(&req.device_id).await {
        Some(r) => r,
        None => return err_response(ErrorCode::UnknownDevice, "对端未配对"),
    };
    let payload = match transcript::revoke_payload(&req.device_id, &req.revoke_token) {
        Some(p) => p,
        None => return err_response(ErrorCode::BadRequest, "payload 构造失败"),
    };
    let sig = match b64u_decode(&req.signature) {
        Some(s) => s,
        None => return err_response(ErrorCode::BadRequest, "signature 非法 base64"),
    };
    if !p256sign::verify(&rec.public_key, &payload, &sig) {
        return err_response(ErrorCode::Untrusted, "吊销通知签名验证失败");
    }
    // 对端主动吊销 ⇒ 本机收尾为 Revoked（等同收到 PeerUnpair）
    let next = match rec.trust.apply(PairingEvent::PeerUnpair) {
        Ok(s) => s,
        Err(il) => return err_response(ErrorCode::IllegalState, &il.to_string()),
    };
    store.peers.put(rec).await;
    ok_json(serde_json::json!({
        "status": next,
        "revokeToken": req.revoke_token,
        "requestId": req.request_id,
    }))
}

/// `POST /api/v4/revoke-ack` —— 对端确认吊销，本机把 Revoking 收尾为 Revoked。
pub async fn handle_revoke_ack(
    store: &Arc<SessionStore>,
    body: &[u8],
) -> Response<Full<bytes::Bytes>> {
    let req: RevokeAck = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    let mut rec = match store.peers.entry(&req.device_id).await {
        Some(r) => r,
        None => return err_response(ErrorCode::UnknownDevice, "对端未配对"),
    };
    let next = match rec.trust.apply(PairingEvent::RevokeAcked) {
        Ok(s) => s,
        Err(il) => return err_response(ErrorCode::IllegalState, &il.to_string()),
    };
    store.peers.put(rec).await;
    ok_json(serde_json::json!({"status": next, "requestId": req.request_id}))
}

// ── 测试 ──────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sign::KeyPair;
    use http_body_util::BodyExt;
    use hyper::{Method, StatusCode};
    use serde_json::Value;

    const CODE: &str = "1234-5678";

    fn app() -> Arc<SessionStore> {
        SessionStore::new()
    }

    async fn body_bytes(r: Response<Full<bytes::Bytes>>) -> Vec<u8> {
        r.into_body().collect().await.unwrap().to_bytes().to_vec()
    }

    async fn body_json(r: Response<Full<bytes::Bytes>>) -> Value {
        serde_json::from_slice(&body_bytes(r).await).unwrap()
    }

    fn active_trust() -> TrustRecord {
        let mut t = TrustRecord::new();
        t.apply(PairingEvent::Initiate).unwrap();
        t.apply(PairingEvent::PeerConfirmed).unwrap();
        t
    }

    /// 走一遍真实的 probe，拿到本机签发的一次性 serverNonce。
    async fn probe_nonce(s: &Arc<SessionStore>) -> String {
        let v = body_json(handle_probe(s, "/api/v4/probe").await).await;
        v["serverNonce"].as_str().unwrap().to_string()
    }

    /// 构造一个合法的路径 A 请求（HMAC 用真实的 transcript 计算）。
    async fn path_a_request(s: &Arc<SessionStore>, device_id: &str, rid: &str) -> VerifyRequest {
        let server_nonce = probe_nonce(s).await;
        let client_nonce = hex_enc(&rand::random::<[u8; 32]>());
        let client_eph = EphemeralKeyPair::generate().public_key_bytes();
        let cn = hex_dec(&client_nonce).unwrap();
        let sn = hex_dec(&server_nonce).unwrap();
        let key = transcript::path_a_key(CODE, &cn, &sn);
        let tr = transcript::path_a_transcript(
            device_id,
            &client_eph,
            &cn,
            &sn,
            &s.identity.public_key_bytes(),
        )
        .unwrap();
        VerifyRequest {
            device_id: device_id.to_string(),
            client_eph_pub: b64u(&client_eph),
            client_nonce,
            server_nonce,
            hmac: Some(hex_enc(&transcript::tag(&key, &tr))),
            challenge_token: None,
            request_id: rid.to_string(),
        }
    }

    #[tokio::test]
    async fn probe_returns_identity_and_nonce() {
        let s = app();
        let r = handle_probe(&s, "/api/v4/probe").await;
        assert_eq!(r.status(), StatusCode::OK);
        let v = body_json(r).await;
        assert_eq!(v["deviceId"], s.identity.device_id());
        assert_eq!(v["serverNonce"].as_str().unwrap().len(), 64);
        assert_eq!(v["protocolVersion"], 4);
        assert_eq!(v["port"], DEFAULT_PORT);
        assert!(v["staticPub"].as_str().is_some());
    }

    #[tokio::test]
    async fn probe_nonces_are_unique_per_call() {
        let s = app();
        let a = probe_nonce(&s).await;
        let b = probe_nonce(&s).await;
        assert_ne!(a, b, "每次 probe 必须是新 nonce，否则路径 A 可被重放");
    }

    #[tokio::test]
    async fn route_dispatches_probe() {
        let s = app();
        let r = crate::server::route(&s, Method::GET, "/api/v4/probe", &[]).await;
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn path_a_verifies_hmac_and_pairs() {
        let s = app();
        s.handshake.set_pairing_code(CODE.to_string()).await;
        let req = path_a_request(&s, "peer-1", "rid-a").await;
        let r = handle_handshake_verify(&s, &serde_json::to_vec(&req).unwrap()).await;
        assert_eq!(r.status(), StatusCode::OK);
        let peer = s.peers.entry("peer-1").await.unwrap();
        assert_eq!(peer.trust.state, PairingState::Active);
        // 状态机走了 Initiate + PeerConfirmed 两步 ⇒ 版本号 2
        assert_eq!(peer.trust.trust_version, 2);
    }

    #[tokio::test]
    async fn path_a_rejects_wrong_hmac() {
        let s = app();
        s.handshake.set_pairing_code(CODE.to_string()).await;
        let server_nonce = probe_nonce(&s).await;
        let req = VerifyRequest {
            device_id: "peer-1".to_string(),
            client_eph_pub: b64u(&[1u8; 33]),
            client_nonce: hex_enc(&rand::random::<[u8; 32]>()),
            server_nonce,
            hmac: Some("deadbeef".to_string()),
            challenge_token: None,
            request_id: "rid-bad".to_string(),
        };
        let r = handle_handshake_verify(&s, &serde_json::to_vec(&req).unwrap()).await;
        // ErrorCode::HmacMismatch → 401
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert!(s.peers.entry("peer-1").await.is_none(), "失败不得落地对端");
    }

    /// 模块文档约束 2：抓到的 (nonce, hmac) 不能重放第二次。
    #[tokio::test]
    async fn path_a_rejects_replayed_server_nonce() {
        let s = app();
        s.handshake.set_pairing_code(CODE.to_string()).await;
        let req = path_a_request(&s, "peer-1", "rid-a").await;
        let bytes = serde_json::to_vec(&req).unwrap();
        assert_eq!(
            handle_handshake_verify(&s, &bytes).await.status(),
            StatusCode::OK
        );
        // 一字不改地重放同一个请求
        let replay = handle_handshake_verify(&s, &bytes).await;
        assert_eq!(
            replay.status(),
            StatusCode::UNAUTHORIZED,
            "serverNonce 必须一次性消费"
        );
    }

    #[tokio::test]
    async fn path_a_rejects_forged_server_nonce() {
        let s = app();
        s.handshake.set_pairing_code(CODE.to_string()).await;
        // 自造一个从未被 probe 签发的 nonce
        let mut req = path_a_request(&s, "peer-1", "rid-a").await;
        req.server_nonce = hex_enc(&[9u8; 32]);
        let r = handle_handshake_verify(&s, &serde_json::to_vec(&req).unwrap()).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn path_b_reconnect_with_challenge_token() {
        let s = app();
        s.handshake.set_pairing_code(CODE.to_string()).await;
        // 先用路径 A 建立配对
        let req_a = path_a_request(&s, "peer-1", "rid-a").await;
        assert_eq!(
            handle_handshake_verify(&s, &serde_json::to_vec(&req_a).unwrap())
                .await
                .status(),
            StatusCode::OK
        );

        // 路径 B：challenge → verify
        let ch = ChallengeRequest {
            device_id: "peer-1".to_string(),
            client_nonce: "cn-b".to_string(),
            request_id: "rid-b".to_string(),
        };
        let r = handle_handshake_challenge(&s, &serde_json::to_vec(&ch).unwrap()).await;
        assert_eq!(r.status(), StatusCode::OK);
        let v = body_json(r).await;
        let ct = v["challengeToken"].as_str().unwrap().to_string();

        let req_b = VerifyRequest {
            device_id: "peer-1".to_string(),
            client_eph_pub: b64u(&[2u8; 33]),
            client_nonce: "cn-b".to_string(),
            server_nonce: v["serverNonce"].as_str().unwrap().to_string(),
            hmac: None,
            challenge_token: Some(ct.clone()),
            request_id: "rid-b".to_string(),
        };
        let bytes_b = serde_json::to_vec(&req_b).unwrap();
        assert_eq!(
            handle_handshake_verify(&s, &bytes_b).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            s.peers.entry("peer-1").await.unwrap().trust.state,
            PairingState::Active
        );

        // jti 一次性消费：同一令牌再用一次必败（409 IllegalState）
        let replay = handle_handshake_verify(&s, &bytes_b).await;
        assert_eq!(replay.status(), StatusCode::CONFLICT);
    }

    /// 重连**不是**状态迁移：已 Active 的记录不得被再发一次 `PeerConfirmed`。
    ///
    /// 状态机里 `Active + PeerConfirmed` 是非法组合，若 handler 照发，
    /// 每一次正常重连都会变成 409 —— 已配对设备从此再也连不上。
    #[tokio::test]
    async fn path_b_reconnect_does_not_re_apply_peer_confirmed() {
        let s = app();
        s.peers
            .put(PeerRecord::new(
                "peer-1",
                "",
                vec![],
                vec![7u8; 32],
                active_trust(),
            ))
            .await;
        // 连续三次重连都必须成功，且状态恒为 Active
        for i in 0..3 {
            let rid = format!("rid-{i}");
            let ch = ChallengeRequest {
                device_id: "peer-1".to_string(),
                client_nonce: format!("cn-{i}"),
                request_id: rid.clone(),
            };
            let r = handle_handshake_challenge(&s, &serde_json::to_vec(&ch).unwrap()).await;
            assert_eq!(r.status(), StatusCode::OK, "第 {i} 次 challenge 失败");
            let v = body_json(r).await;
            let req_b = VerifyRequest {
                device_id: "peer-1".to_string(),
                client_eph_pub: b64u(&[2u8; 33]),
                client_nonce: format!("cn-{i}"),
                server_nonce: v["serverNonce"].as_str().unwrap().to_string(),
                hmac: None,
                challenge_token: Some(v["challengeToken"].as_str().unwrap().to_string()),
                request_id: rid,
            };
            assert_eq!(
                handle_handshake_verify(&s, &serde_json::to_vec(&req_b).unwrap())
                    .await
                    .status(),
                StatusCode::OK,
                "第 {i} 次重连被拒 —— 说明 handler 又对 Active 发了 PeerConfirmed"
            );
            let rec = s.peers.entry("peer-1").await.unwrap();
            assert_eq!(rec.trust.state, PairingState::Active);
            assert_eq!(rec.presence, Presence::Online);
        }
    }

    /// 路径 B 是重连而非配对：未知设备不得凭令牌"凭空"变成受信设备。
    #[tokio::test]
    async fn path_b_unknown_device_cannot_bootstrap_trust() {
        let s = app();
        // 先用一个已配对设备换出一个合法令牌
        s.peers
            .put(PeerRecord::new(
                "peer-1",
                "",
                vec![],
                vec![7u8; 32],
                active_trust(),
            ))
            .await;
        let ch = ChallengeRequest {
            device_id: "peer-1".to_string(),
            client_nonce: "cn".to_string(),
            request_id: "rid".to_string(),
        };
        let v = body_json(handle_handshake_challenge(&s, &serde_json::to_vec(&ch).unwrap()).await)
            .await;
        // 拿着这个令牌冒充另一个从未配对的 deviceId
        let req_b = VerifyRequest {
            device_id: "ghost".to_string(),
            client_eph_pub: b64u(&[2u8; 33]),
            client_nonce: "cn".to_string(),
            server_nonce: v["serverNonce"].as_str().unwrap().to_string(),
            hmac: None,
            challenge_token: Some(v["challengeToken"].as_str().unwrap().to_string()),
            request_id: "rid".to_string(),
        };
        let r = handle_handshake_verify(&s, &serde_json::to_vec(&req_b).unwrap()).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        assert!(
            s.peers.entry("ghost").await.is_none(),
            "未知设备被凭空建成了记录 —— 重连通道变成了绕过连接码的配对后门"
        );
    }

    /// 已解除的设备不得拿到新令牌（challenge 层的快速失败）。
    #[tokio::test]
    async fn revoked_peer_gets_no_new_challenge_token() {
        let s = app();
        let mut t = active_trust();
        t.apply(PairingEvent::PeerUnpair).unwrap(); // Active → Revoked
        assert_eq!(t.state, PairingState::Revoked);
        s.peers
            .put(PeerRecord::new("peer-1", "", vec![], vec![7u8; 32], t))
            .await;
        let ch = ChallengeRequest {
            device_id: "peer-1".to_string(),
            client_nonce: "cn".to_string(),
            request_id: "rid".to_string(),
        };
        let r = handle_handshake_challenge(&s, &serde_json::to_vec(&ch).unwrap()).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    /// 令牌签发**之后**才解除配对 —— verify 层必须兜住这个时间窗。
    ///
    /// 回 401（而不是 409）：客户端据此丢弃本地令牌并提示重新配对，
    /// 若回 409 它会当成暂时冲突继续重试，"解配对不彻底"就换个地方复现。
    #[tokio::test]
    async fn token_minted_before_unpair_is_rejected_at_verify() {
        let s = app();
        s.peers
            .put(PeerRecord::new(
                "peer-1",
                "",
                vec![],
                vec![7u8; 32],
                active_trust(),
            ))
            .await;
        let ch = ChallengeRequest {
            device_id: "peer-1".to_string(),
            client_nonce: "cn".to_string(),
            request_id: "rid".to_string(),
        };
        let v = body_json(handle_handshake_challenge(&s, &serde_json::to_vec(&ch).unwrap()).await)
            .await;
        // 令牌已签发，此刻用户在本机解除了配对
        let mut rec = s.peers.entry("peer-1").await.unwrap();
        rec.trust.apply(PairingEvent::PeerUnpair).unwrap();
        s.peers.put(rec).await;

        let req_b = VerifyRequest {
            device_id: "peer-1".to_string(),
            client_eph_pub: b64u(&[2u8; 33]),
            client_nonce: "cn".to_string(),
            server_nonce: v["serverNonce"].as_str().unwrap().to_string(),
            hmac: None,
            challenge_token: Some(v["challengeToken"].as_str().unwrap().to_string()),
            request_id: "rid".to_string(),
        };
        let r = handle_handshake_verify(&s, &serde_json::to_vec(&req_b).unwrap()).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            s.peers.entry("peer-1").await.unwrap().trust.state,
            PairingState::Revoked,
            "已解除的配对被旧令牌复活了"
        );
        // 失败原因可查，客户端不会无限轮询
        let st =
            body_json(handle_handshake_status(&s, "/api/v4/handshake/status?requestId=rid").await)
                .await;
        assert_eq!(st["done"], serde_json::json!(true));
    }

    /// 首配收尾丢包后改走路径 B 重试：`Pending → Active` 是合法迁移，应补齐。
    #[tokio::test]
    async fn path_b_completes_a_pending_pairing() {
        let s = app();
        let mut t = TrustRecord::new();
        t.apply(PairingEvent::Initiate).unwrap(); // None → Pending
        assert_eq!(t.state, PairingState::Pending);
        s.peers
            .put(PeerRecord::new("peer-1", "", vec![], vec![7u8; 32], t))
            .await;
        let ch = ChallengeRequest {
            device_id: "peer-1".to_string(),
            client_nonce: "cn".to_string(),
            request_id: "rid".to_string(),
        };
        let v = body_json(handle_handshake_challenge(&s, &serde_json::to_vec(&ch).unwrap()).await)
            .await;
        let req_b = VerifyRequest {
            device_id: "peer-1".to_string(),
            client_eph_pub: b64u(&[2u8; 33]),
            client_nonce: "cn".to_string(),
            server_nonce: v["serverNonce"].as_str().unwrap().to_string(),
            hmac: None,
            challenge_token: Some(v["challengeToken"].as_str().unwrap().to_string()),
            request_id: "rid".to_string(),
        };
        assert_eq!(
            handle_handshake_verify(&s, &serde_json::to_vec(&req_b).unwrap())
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            s.peers.entry("peer-1").await.unwrap().trust.state,
            PairingState::Active
        );
    }

    #[tokio::test]
    async fn path_b_rejects_token_signed_with_wrong_secret() {
        let s = app();
        s.peers
            .put(PeerRecord::new(
                "peer-1",
                "",
                vec![],
                vec![1u8; 32],
                active_trust(),
            ))
            .await;
        let ch = ChallengeRequest {
            device_id: "peer-1".to_string(),
            client_nonce: "cn".to_string(),
            request_id: "rid-b".to_string(),
        };
        handle_handshake_challenge(&s, &serde_json::to_vec(&ch).unwrap()).await;
        // 用另一把密钥自签一个 challenge 令牌
        let forged = token::mint(
            &[7u8; 32],
            &Claims::challenge("peer-1", "rid-b", "cn", now_secs()),
        );
        let req = VerifyRequest {
            device_id: "peer-1".to_string(),
            client_eph_pub: b64u(&[2u8; 33]),
            client_nonce: "cn".to_string(),
            server_nonce: "00".to_string(),
            hmac: None,
            challenge_token: Some(forged),
            request_id: "rid-b".to_string(),
        };
        let r = handle_handshake_verify(&s, &serde_json::to_vec(&req).unwrap()).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn verify_without_hmac_or_token_is_400() {
        let s = app();
        let req = VerifyRequest {
            device_id: "peer-1".to_string(),
            client_eph_pub: b64u(&[1u8; 33]),
            client_nonce: "cn".to_string(),
            server_nonce: "sn".to_string(),
            hmac: None,
            challenge_token: None,
            request_id: "rid".to_string(),
        };
        let r = handle_handshake_verify(&s, &serde_json::to_vec(&req).unwrap()).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn challenge_is_idempotent_by_request_id() {
        let s = app();
        s.peers
            .put(PeerRecord::new(
                "peer-1",
                "",
                vec![],
                vec![1u8; 32],
                active_trust(),
            ))
            .await;
        let ch = ChallengeRequest {
            device_id: "peer-1".to_string(),
            client_nonce: "cn".to_string(),
            request_id: "rid-idem".to_string(),
        };
        let a = body_json(handle_handshake_challenge(&s, &serde_json::to_vec(&ch).unwrap()).await)
            .await;
        let b = body_json(handle_handshake_challenge(&s, &serde_json::to_vec(&ch).unwrap()).await)
            .await;
        assert_eq!(
            a["challengeToken"], b["challengeToken"],
            "同 requestId 必须回放同一令牌，否则重试必然撞上 jti 已消费"
        );
    }

    #[tokio::test]
    async fn challenge_rejects_unknown_device() {
        let s = app();
        let ch = ChallengeRequest {
            device_id: "nobody".to_string(),
            client_nonce: "cn".to_string(),
            request_id: "rid".to_string(),
        };
        let r = handle_handshake_challenge(&s, &serde_json::to_vec(&ch).unwrap()).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn handshake_status_reports_unknown() {
        let s = app();
        let v =
            body_json(handle_handshake_status(&s, "/api/v4/handshake/status?requestId=nope").await)
                .await;
        assert_eq!(v["done"], false);
        assert!(v["error"].as_str().is_some());
    }

    /// 失败也是"有结论"：否则客户端会对已确定失败的握手无限轮询。
    #[tokio::test]
    async fn handshake_status_reports_failure_as_done() {
        let s = app();
        s.handshake.set_pairing_code(CODE.to_string()).await;
        let server_nonce = probe_nonce(&s).await;
        let req = VerifyRequest {
            device_id: "peer-1".to_string(),
            client_eph_pub: b64u(&[1u8; 33]),
            client_nonce: hex_enc(&rand::random::<[u8; 32]>()),
            server_nonce,
            hmac: Some("deadbeef".to_string()),
            challenge_token: None,
            request_id: "rid-f".to_string(),
        };
        // 先建一条握手记录（challenge 之外的路径 A 失败也要能被查询到），
        // 这里直接插入一条 Pending 记录模拟"客户端已开始握手"
        s.handshake
            .insert(
                "rid-f",
                HandshakeSession {
                    device_id: "peer-1".to_string(),
                    client_nonce: req.client_nonce.clone(),
                    server_nonce: req.server_nonce.clone(),
                    pairing_secret: vec![],
                    status: HandshakePhase::Pending,
                    result: None,
                    error: None,
                    challenge_response: None,
                },
            )
            .await;
        handle_handshake_verify(&s, &serde_json::to_vec(&req).unwrap()).await;
        let v = body_json(handle_handshake_status(&s, "/x?requestId=rid-f").await).await;
        assert_eq!(v["done"], true);
        assert!(v["error"].as_str().is_some());
    }

    #[tokio::test]
    async fn sync_status_is_pure_read() {
        let s = app();
        s.peers
            .put(PeerRecord::new(
                "peer-1",
                "",
                vec![],
                vec![],
                active_trust(),
            ))
            .await;
        let before = s.peers.entry("peer-1").await.unwrap();
        let v = body_json(handle_sync_status(&s, "/x?deviceId=peer-1").await).await;
        assert_eq!(v["youArePairedWithMe"], true);
        assert_eq!(v["status"], "active");
        assert_eq!(v["deviceId"], s.identity.device_id());
        // 关键：GET 不得改变任何本机状态（会被代理自动重试）
        let after = s.peers.entry("peer-1").await.unwrap();
        assert_eq!(before.trust, after.trust, "GET /sync-status 必须是纯读");
    }

    /// 未知设备返回 200 + 显式否认，而不是 404 —— 对端才能对账。
    #[tokio::test]
    async fn sync_status_denies_unknown_device_with_200() {
        let s = app();
        let r = handle_sync_status(&s, "/x?deviceId=nobody").await;
        assert_eq!(r.status(), StatusCode::OK);
        let v = body_json(r).await;
        assert_eq!(v["youArePairedWithMe"], false);
        assert_eq!(v["status"], "none");
    }

    #[tokio::test]
    async fn sync_status_requires_device_id() {
        let s = app();
        let r = handle_sync_status(&s, "/api/v4/sync-status").await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    /// 对端否认 ⇒ 本机降为 Revoking（而不是硬说成 Revoked，清理流程还要走）。
    #[tokio::test]
    async fn reconcile_with_peer_handles_denial() {
        let s = app();
        s.peers
            .put(PeerRecord::new(
                "peer-1",
                "",
                vec![],
                vec![],
                active_trust(),
            ))
            .await;
        let peer_view = SyncStatusResponse {
            device_id: "peer-1".to_string(),
            you_are_paired_with_me: false,
            my_trust_version: 3,
            status: PairingState::Revoked,
            presence: Presence::Online,
        };
        let state = reconcile_with_peer(&s, &peer_view).await;
        assert_eq!(state, Some(PairingState::Revoking));
        let rec = s.peers.entry("peer-1").await.unwrap();
        assert_eq!(rec.trust.state, PairingState::Revoking);
        assert_eq!(rec.trust.peer_trust_version, 3);
        assert_eq!(rec.presence, Presence::Online);
    }

    #[tokio::test]
    async fn reconcile_with_unknown_peer_is_none() {
        let s = app();
        let peer_view = SyncStatusResponse {
            device_id: "nobody".to_string(),
            you_are_paired_with_me: true,
            my_trust_version: 1,
            status: PairingState::Active,
            presence: Presence::Online,
        };
        assert_eq!(reconcile_with_peer(&s, &peer_view).await, None);
    }

    #[tokio::test]
    async fn unpair_flow_signs_and_advances_state() {
        let s = app();
        let kp = KeyPair::generate();
        s.peers
            .put(PeerRecord::new(
                "peer-1",
                "",
                kp.public_key_bytes(),
                vec![],
                active_trust(),
            ))
            .await;

        let rid = "ur-1";
        let sig = b64u(&kp.sign(&transcript::unpair_payload("peer-1", rid).unwrap()));
        let req = UnpairRequest {
            device_id: "peer-1".to_string(),
            signature: sig,
            request_id: rid.to_string(),
        };
        let r = handle_unpair_request(&s, &serde_json::to_vec(&req).unwrap()).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            s.peers.entry("peer-1").await.unwrap().trust.state,
            PairingState::Revoking
        );

        let sig2 = b64u(&kp.sign(&transcript::unpair_payload("peer-1", rid).unwrap()));
        let req2 = UnpairNotification {
            device_id: "peer-1".to_string(),
            revoke_token: None,
            signature: sig2,
            request_id: rid.to_string(),
        };
        let r2 = handle_unpair(&s, &serde_json::to_vec(&req2).unwrap()).await;
        assert_eq!(r2.status(), StatusCode::OK);
        assert_eq!(
            s.peers.entry("peer-1").await.unwrap().trust.state,
            PairingState::Revoked
        );
    }

    #[tokio::test]
    async fn unpair_rejects_bad_signature() {
        let s = app();
        let kp = KeyPair::generate();
        let other = KeyPair::generate();
        s.peers
            .put(PeerRecord::new(
                "peer-1",
                "",
                kp.public_key_bytes(),
                vec![],
                active_trust(),
            ))
            .await;
        // 用另一把密钥签名 → 验签必败
        let rid = "ur-2";
        let sig = b64u(&other.sign(&transcript::unpair_payload("peer-1", rid).unwrap()));
        let req = UnpairRequest {
            device_id: "peer-1".to_string(),
            signature: sig,
            request_id: rid.to_string(),
        };
        let r = handle_unpair_request(&s, &serde_json::to_vec(&req).unwrap()).await;
        // ErrorCode::Untrusted → 401
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        // 验签失败不得改状态
        assert_eq!(
            s.peers.entry("peer-1").await.unwrap().trust.state,
            PairingState::Active
        );
    }

    #[tokio::test]
    async fn revoke_notify_revokes_peer() {
        let s = app();
        let kp = KeyPair::generate();
        s.peers
            .put(PeerRecord::new(
                "peer-1",
                "",
                kp.public_key_bytes(),
                vec![],
                active_trust(),
            ))
            .await;
        let tok = "revtok";
        let sig = b64u(&kp.sign(&transcript::revoke_payload("peer-1", tok).unwrap()));
        let req = RevokeNotify {
            device_id: "peer-1".to_string(),
            revoke_token: tok.to_string(),
            signature: sig,
            request_id: "rv-1".to_string(),
        };
        let r = handle_revoke_notify(&s, &serde_json::to_vec(&req).unwrap()).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            s.peers.entry("peer-1").await.unwrap().trust.state,
            PairingState::Revoked
        );
    }

    #[tokio::test]
    async fn revoke_ack_closes_revoking() {
        let s = app();
        let mut trust = active_trust();
        trust.apply(PairingEvent::LocalUnpair).unwrap();
        assert_eq!(trust.state, PairingState::Revoking);
        s.peers
            .put(PeerRecord::new("peer-1", "", vec![], vec![], trust))
            .await;
        let req = RevokeAck {
            device_id: "peer-1".to_string(),
            revoke_token: "t".to_string(),
            pairing_revoked: true,
            request_id: "rv-2".to_string(),
        };
        let r = handle_revoke_ack(&s, &serde_json::to_vec(&req).unwrap()).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            s.peers.entry("peer-1").await.unwrap().trust.state,
            PairingState::Revoked
        );
    }

    /// 非法迁移必须 409，绝不静默 —— 对 Active 直接 RevokeAcked 是非法的。
    #[tokio::test]
    async fn revoke_ack_on_active_is_illegal() {
        let s = app();
        s.peers
            .put(PeerRecord::new(
                "peer-1",
                "",
                vec![],
                vec![],
                active_trust(),
            ))
            .await;
        let req = RevokeAck {
            device_id: "peer-1".to_string(),
            revoke_token: "t".to_string(),
            pairing_revoked: true,
            request_id: "rv-3".to_string(),
        };
        let r = handle_revoke_ack(&s, &serde_json::to_vec(&req).unwrap()).await;
        assert_eq!(r.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn control_endpoints_reject_unknown_device() {
        let s = app();
        let ack = RevokeAck {
            device_id: "nobody".to_string(),
            revoke_token: "t".to_string(),
            pairing_revoked: true,
            request_id: "r".to_string(),
        };
        assert_eq!(
            handle_revoke_ack(&s, &serde_json::to_vec(&ack).unwrap())
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn prune_forgets_expired_jti() {
        let s = app();
        let claims = Claims::challenge("peer-1", "jti-1", "cn", 0);
        assert!(s.handshake.consume_jti(&claims).await);
        assert!(
            !s.handshake.consume_jti(&claims).await,
            "同一 jti 不得二次消费"
        );
        // exp 已过很久 ⇒ prune 可以安全忘掉它（exp 只用于清理时机）
        s.handshake.prune(now_secs()).await;
        assert!(s.handshake.consume_jti(&claims).await);
    }

    #[tokio::test]
    async fn peers_all_lists_registered() {
        let s = app();
        s.peers
            .put(PeerRecord::new("a", "", vec![], vec![], active_trust()))
            .await;
        s.peers
            .put(PeerRecord::new("b", "", vec![], vec![], TrustRecord::new()))
            .await;
        let mut ids: Vec<String> = s
            .peers
            .all()
            .await
            .into_iter()
            .map(|p| p.device_id)
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["a", "b"]);
    }
}
