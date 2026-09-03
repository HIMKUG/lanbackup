//! V4 HTTP 服务（阶段 2.4）
//!
//! 用 hyper 1.x 直接实现 `/api/v4/*` 控制面。这是 V4 的全新协议表面，
//! 不依赖 localsend 的 v2 传输层（v2 将在后续阶段删除）。
//!
//! 设计要点（来自 V4-TRANSFER-MODULE.md / DESIGN-WISDOM-REGISTER）：
//! - **状态机是唯一依据**：每个写操作先过 `TransferState::transition`，
//!   非法迁移直接返回 409 + 可读原因，绝不静默。
//! - **锁粒度小**：`SessionStore` 只在每个请求内短暂持锁，重活（IO/加密）
//!   在锁外进行（对照 D1「绝不在调用方线程做重活」、避免死锁）。
//! - **错误统一信封**：所有失败走 `ErrorEnvelope`，前端一致处理。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use serde::Serialize;
use serde_json::json;
use tokio::sync::Mutex;

use crate::dto::session::{
    Algorithm, ChunkDiff, DegradeReason, DiffMismatch, FileMeta, PrepareRequest, PrepareResponse,
    ReceiptRequest, SessionRegisterRequest, SessionRegisterResponse, TaskListResponse, TaskReceipt,
    TaskStatus, TransferPhase, VerifyFileResponse,
};
use crate::dto::DeviceType;
use crate::error::ErrorCode;
use crate::identity::DeviceIdentity;
use crate::routes;
use crate::server::control::{HandshakeStore, PeerStore};
use crate::state::transfer::{TransferEvent, TransferState};
use crate::transfer::chunk::piece_count;

pub mod control;
pub mod sync_api;

/// 单个会话的运行时记录
pub struct SessionRecord {
    /// 发起这个会话的对端 deviceId（`session/register` 登记）。
    ///
    /// 必须记住"这个会话是谁的"，否则 `disconnect` 无法只收尾该设备名下的会话 ——
    /// 要么谁都不收（对端断开后会话永远悬在 `Transferring`，下次连上撞到旧会话），
    /// 要么全部收（A 设备断线顺手掐断 B 设备正在传的文件）。
    pub device_id: String,
    pub phase: TransferState,
    pub algorithm: Algorithm,
    /// 降级原因；未降级为 None
    pub degrade_reason: Option<DegradeReason>,
    /// 权威块位图版本号（每次对账/进度更新自增）
    pub bitmap_version: u64,
    /// prepare 阶段登记的文件
    pub files: HashMap<String, FileMeta>,
    /// 每文件已确认的 piece 集合（基础算法降级时据此换算进度）
    pub confirmed: HashMap<String, HashSet<u64>>,
    /// 每文件、每 piece **本端实际落盘后自算**的 SHA-256（hex）。
    ///
    /// 不能用 `files[..].piece_hashes` 代替 —— 那是**发送端声明**的期望值，
    /// 拿发送端的声明去和发送端的查询比对恒等成立，永远发现不了
    /// "本端写坏了一块"。要判 412（存在但内容不对）必须有本端自己的度量。
    pub piece_sha: HashMap<String, HashMap<u64, String>>,
    /// 接收端权威判定的任务终态（`session/receipt` 写入，`session/tasks` 读出）。
    ///
    /// 终态**单调不可回退**：数据在谁磁盘上谁说了算，且一旦确认就不接受
    /// 被后到的乱序回执踩回中间态（登记表 S1 的"三处防复活"同源教训）。
    pub receipts: HashMap<String, TaskReceipt>,
}

impl Default for SessionRecord {
    fn default() -> Self {
        Self {
            device_id: String::new(),
            phase: TransferState::Idle,
            algorithm: Algorithm::Advanced,
            degrade_reason: None,
            bitmap_version: 0,
            files: HashMap::new(),
            confirmed: HashMap::new(),
            piece_sha: HashMap::new(),
            receipts: HashMap::new(),
        }
    }
}

/// 服务端运行时状态：传输会话 + 控制面（身份 / 对端 / 握手）。
///
/// 传输会话与控制面共用一个 store，是刻意的：它们必须看到**同一份**配对状态。
/// 拆成两个 store 就会出现"控制面已解绑、传输面还在传"的窗口 ——
/// 这正是 V2 的老毛病（配对状态散落在多处，谁都不是权威）。
///
/// MVP 用内存实现；生产环境替换为 rusqlite 持久化（见阶段 TODO）。
pub struct SessionStore {
    inner: Mutex<HashMap<String, SessionRecord>>,
    /// 本机长期身份（P-256 静态密钥对）—— probe 公布的 `staticPub` 与
    /// 路径 A transcript 里绑定的服务端身份都取自这里。
    pub(crate) identity: DeviceIdentity,
    /// 设备显示名
    pub(crate) alias: String,
    pub(crate) device_type: DeviceType,
    /// 已知/已配对对端注册表（控制面）
    pub(crate) peers: PeerStore,
    /// 进行中的握手 + 一次性令牌 + 一次性 nonce + 线下连接码
    pub(crate) handshake: HandshakeStore,
    /// 本机清单 / 快照 / 目录映射（见 [`sync_api`]）
    pub(crate) sync: sync_api::SyncStore,
}

impl SessionStore {
    /// 用一把**新生成**的设备身份建 store。
    ///
    /// 注意：每次调用都是新身份。真实进程启动时应走 [`Self::with_identity`]
    /// 传入从加密存储恢复的身份（`DeviceIdentity::restore`），
    /// 否则重启一次就换个 deviceId，所有对端都会认为"这是台新设备"。
    pub fn new() -> Arc<Self> {
        Self::with_identity(DeviceIdentity::generate(), "lanbackup", DeviceType::Desktop)
    }

    pub fn with_identity(
        identity: DeviceIdentity,
        alias: &str,
        device_type: DeviceType,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
            identity,
            alias: alias.to_string(),
            device_type,
            peers: PeerStore::new(),
            handshake: HandshakeStore::new(),
            sync: sync_api::SyncStore::new(),
        })
    }

    /// 设置用户线下输入的连接码（路径 A 首配用）。绝不经过网络。
    pub async fn set_pairing_code(&self, code: impl Into<String>) {
        self.handshake.set_pairing_code(code.into()).await;
    }
}

fn ok_json(v: impl Serialize) -> Response<Full<bytes::Bytes>> {
    json_response(StatusCode::OK, &serde_json::to_value(v).unwrap())
}

fn json_response(status: StatusCode, v: &serde_json::Value) -> Response<Full<bytes::Bytes>> {
    json_response_with(status, v, &[])
}

/// 带额外响应头的 JSON 响应。
///
/// 416 必须带 `Content-Range: bytes */{total}`、206/200 必须带 `ETag`，
/// 这些头是协议语义的一部分，缺了发送端就没法判断"越界"还是"内容不对"。
fn json_response_with(
    status: StatusCode,
    v: &serde_json::Value,
    headers: &[(&str, String)],
) -> Response<Full<bytes::Bytes>> {
    let body = serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string());
    let mut b = Response::builder()
        .status(status)
        .header("content-type", "application/json");
    for (k, val) in headers {
        b = b.header(*k, val.clone());
    }
    b.body(Full::new(bytes::Bytes::from(body))).unwrap()
}

/// 强校验器格式（登记表 A12）：**必须带双引号、必须不带 `W/` 前缀**。
///
/// `W/` 是弱校验器（语义等价即可、字节可不同），而这里要的是字节级强校验。
/// 加了 `W/` 会让 `If-Range` 的语义发生变化，导致续传位置误判。
fn etag_of(sha256_hex: &str) -> String {
    format!("\"{sha256_hex}\"")
}

/// 解析对端传来的校验器：容忍带不带引号，但**显式拒绝弱校验器**。
///
/// 返回 `None` 表示对端给了 `W/` 前缀 —— 宁可 400 也不能默默按强校验处理，
/// 那会把"语义等价"当成"字节相同"，续传直接写错位置。
fn parse_validator(raw: &str) -> Option<String> {
    if raw.starts_with("W/") || raw.starts_with("w/") {
        return None;
    }
    Some(raw.trim_matches('"').to_string())
}

fn err_response(code: ErrorCode, reason: &str) -> Response<Full<bytes::Bytes>> {
    let env = crate::error::ErrorEnvelope::new(code, reason);
    json_response(
        StatusCode::from_u16(code.http_status()).unwrap(),
        &serde_json::to_value(env).unwrap(),
    )
}

/// 路由入口（纯函数，便于单测；hyper service 仅做 IO 包装）
pub async fn route(
    store: &Arc<SessionStore>,
    method: Method,
    path: &str,
    body: &[u8],
) -> Response<Full<bytes::Bytes>> {
    // 匹配时用「去掉查询串」的路径，查询参数由各 handler 自行解析
    let path_only = path.split_once('?').map(|(p, _)| p).unwrap_or(path);
    // 版本前缀交给 routes 的单一来源把关：`/api/v40/...` 必须落到 404，
    // 而不是被当成 `/api/v4/` 下的某个路径。前缀判断只有这一处，别处不得再手写。
    if routes::strip_prefix(path_only).is_none() {
        return not_found();
    }

    // 路径常量一律取自 routes：服务端与客户端必须对同一份清单，
    // 否则「两端代码看着都对、联调 404」会再次发生。
    match (method, path_only) {
        // ── 发现与配对（控制面，见 control.rs）──
        (Method::GET, routes::PROBE) => control::handle_probe(store, path).await,
        (Method::POST, routes::HANDSHAKE_CHALLENGE) => {
            control::handle_handshake_challenge(store, body).await
        }
        (Method::POST, routes::HANDSHAKE_VERIFY) => {
            control::handle_handshake_verify(store, body).await
        }
        (Method::GET, routes::HANDSHAKE_STATUS) => {
            control::handle_handshake_status(store, path).await
        }
        (Method::POST, routes::UNPAIR_REQUEST) => control::handle_unpair_request(store, body).await,
        (Method::POST, routes::UNPAIR) => control::handle_unpair(store, body).await,
        (Method::POST, routes::REVOKE_NOTIFY) => control::handle_revoke_notify(store, body).await,
        (Method::POST, routes::REVOKE_ACK) => control::handle_revoke_ack(store, body).await,
        (Method::GET, routes::SYNC_STATUS) => control::handle_sync_status(store, path).await,
        // ── 传输会话 ──
        (Method::POST, routes::SESSION_REGISTER) => handle_register(store, body).await,
        (Method::POST, routes::SESSION_PREPARE) => handle_prepare(store, body).await,
        (Method::GET, routes::SESSION_PHASE) => handle_phase(store, path).await,
        (Method::POST, routes::SESSION_HEARTBEAT) => handle_heartbeat(store, body).await,
        (Method::POST, routes::SESSION_ABORT) => handle_abort(store, body).await,
        (Method::POST, routes::SESSION_CHUNK) => handle_chunk(store, body).await,
        (Method::GET, routes::SESSION_DIFF) => handle_diff(store, path).await,
        (Method::GET, routes::SESSION_VERIFY) => handle_verify(store, path).await,
        (Method::POST, routes::SESSION_RECEIPT) => handle_receipt(store, body).await,
        (Method::GET, routes::SESSION_TASKS) => handle_tasks(store, path).await,
        // ── 清单与同步（见 sync_api.rs）──
        // manifest / chunk-status 是 GET：纯读、幂等，代理自动重试也不会改状态。
        (Method::GET, routes::MANIFEST) => sync_api::handle_manifest(store, path).await,
        (Method::GET, routes::CHUNK_STATUS) => sync_api::handle_chunk_status(store, path).await,
        (Method::POST, routes::SYNC_DIR) => sync_api::handle_sync_dir(store, body).await,
        (Method::POST, routes::MOVE_TO_DELETE) => {
            sync_api::handle_move_to_delete(store, body).await
        }
        (Method::POST, routes::DISCONNECT) => sync_api::handle_disconnect(store, body).await,
        _ => not_found(),
    }
}

fn not_found() -> Response<Full<bytes::Bytes>> {
    json_response(
        StatusCode::NOT_FOUND,
        &json!({"error": "unknown V4 endpoint"}),
    )
}

fn parse_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, String> {
    serde_json::from_slice(body).map_err(|e| format!("请求体解析失败: {e}"))
}

// ----------------------------------------------------------------
// 各端点处理
// ----------------------------------------------------------------

async fn handle_register(store: &Arc<SessionStore>, body: &[u8]) -> Response<Full<bytes::Bytes>> {
    let req: SessionRegisterRequest = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    // 会话 ID 必须非空（CSPRNG 生成，非空即可；更强校验在阶段 4.5 密钥层）
    if req.session_id.is_empty() {
        return err_response(ErrorCode::BadRequest, "sessionId 不能为空");
    }

    let rec = SessionRecord {
        // 记下归属设备：`disconnect` 靠它区分"该收尾的会话"和"别人的会话"
        device_id: req.device_id.clone(),
        phase: TransferState::Preparing, // 注册即进入 Preparing（Idle→Preparing）
        algorithm: Algorithm::Advanced,
        ..Default::default()
    };
    store.inner.lock().await.insert(req.session_id.clone(), rec);

    ok_json(SessionRegisterResponse {
        session_id: req.session_id,
        capabilities: crate::version::Capabilities::all(),
    })
}

async fn handle_prepare(store: &Arc<SessionStore>, body: &[u8]) -> Response<Full<bytes::Bytes>> {
    let req: PrepareRequest = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };

    let mut guard = store.inner.lock().await;
    let rec = match guard.get_mut(&req.session_id) {
        Some(r) => r,
        None => return err_response(ErrorCode::NotFound, "会话不存在"),
    };

    // 会话归属必须一致。sessionId 是 CSPRNG 生成的，但一旦泄漏（日志、抓包），
    // 不校验归属就等于"知道 sessionId 就能往别人的会话里塞文件"。
    // 同时这也守住了 `disconnect` 依赖的不变式：一个会话只属于一个设备。
    if rec.device_id != req.device_id {
        return err_response(
            ErrorCode::Untrusted,
            "sessionId 不属于该 deviceId：拒绝跨设备复用会话",
        );
    }

    // 协商：对端若无 CAP_ADVANCED 必须用基础算法（MVP 这里按请求声明，
    // 真实协商在阶段 4.5 密钥层完成；此处用算法字段演示降级入口）
    let mut tokens = HashMap::new();
    for (file_id, meta) in &req.files {
        rec.files.insert(file_id.clone(), meta.clone());
        rec.confirmed.insert(file_id.clone(), HashSet::new());
        // 上传 token 为纯字符串（不是对象，见 DTO 注释）
        tokens.insert(file_id.clone(), format!("tok:{file_id}"));
    }

    ok_json(PrepareResponse {
        session_id: req.session_id,
        files: tokens,
        capabilities: crate::version::Capabilities::all(),
    })
}

async fn handle_phase(store: &Arc<SessionStore>, rest: &str) -> Response<Full<bytes::Bytes>> {
    // GET /api/v4/session/phase?sessionId=xxx
    let session_id = match extract_query(rest, "sessionId") {
        Some(s) => s,
        None => return err_response(ErrorCode::BadRequest, "缺少 sessionId 参数"),
    };
    let guard = store.inner.lock().await;
    let rec = match guard.get(&session_id) {
        Some(r) => r,
        None => return err_response(ErrorCode::NotFound, "会话不存在"),
    };
    let payload = json!({
        "sessionId": session_id,
        "phase": to_phase(rec.phase),
        "algorithm": algo_name(rec.algorithm),
        "degradeReason": rec.degrade_reason.map(degrade_name),
        "bitmapVersion": rec.bitmap_version,
    });
    ok_json(payload)
}

async fn handle_heartbeat(store: &Arc<SessionStore>, body: &[u8]) -> Response<Full<bytes::Bytes>> {
    #[derive(serde::Deserialize)]
    struct Hb {
        #[serde(rename = "sessionId")]
        session_id: String,
        #[serde(rename = "bitmapVersion")]
        bitmap_version: u64,
    }
    let hb: Hb = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    let mut guard = store.inner.lock().await;
    let rec = match guard.get_mut(&hb.session_id) {
        Some(r) => r,
        None => return err_response(ErrorCode::NotFound, "会话不存在"),
    };
    // 心跳自增位图版本（真实场景：比对对端版本，不一致触发对账）
    rec.bitmap_version = rec.bitmap_version.max(hb.bitmap_version) + 1;
    let payload = json!({
        "sessionId": hb.session_id,
        "phase": to_phase(rec.phase),
        "bitmapVersion": rec.bitmap_version,
    });
    ok_json(payload)
}

async fn handle_abort(store: &Arc<SessionStore>, body: &[u8]) -> Response<Full<bytes::Bytes>> {
    #[derive(serde::Deserialize)]
    struct Abort {
        #[serde(rename = "sessionId")]
        session_id: String,
    }
    let a: Abort = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    let mut guard = store.inner.lock().await;
    let rec = match guard.get_mut(&a.session_id) {
        Some(r) => r,
        None => return err_response(ErrorCode::NotFound, "会话不存在"),
    };
    match rec.phase.transition(TransferEvent::Abort) {
        Ok(next) => {
            rec.phase = next;
            ok_json(json!({"sessionId": a.session_id, "phase": to_phase(next)}))
        }
        Err(il) => err_response(ErrorCode::IllegalState, il.reason),
    }
}

async fn handle_chunk(store: &Arc<SessionStore>, body: &[u8]) -> Response<Full<bytes::Bytes>> {
    #[derive(serde::Deserialize)]
    struct Chunk {
        #[serde(rename = "sessionId")]
        session_id: String,
        #[serde(rename = "fileId")]
        file_id: String,
        #[serde(rename = "pieceIndex")]
        piece_index: u64,
        /// 本端落盘后自算的该 piece SHA-256（hex）。可选：
        /// 基础算法降级路径不逐块算哈希，此时缺失是正常的。
        #[serde(default)]
        sha256: Option<String>,
    }
    let c: Chunk = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    let mut guard = store.inner.lock().await;
    let rec = match guard.get_mut(&c.session_id) {
        Some(r) => r,
        None => return err_response(ErrorCode::NotFound, "会话不存在"),
    };
    if !rec.files.contains_key(&c.file_id) {
        return err_response(ErrorCode::NotFound, "文件未登记");
    }
    // 首次分块：Preparing/Reconciling → Transferring（NegotiateBasic 路径的 MVP）
    if matches!(
        rec.phase,
        TransferState::Preparing | TransferState::Reconciling
    ) {
        let ev = if rec.algorithm == Algorithm::Advanced {
            TransferEvent::NegotiateAdvanced
        } else {
            TransferEvent::NegotiateBasic
        };
        match rec.phase.transition(ev) {
            Ok(next) => rec.phase = next,
            Err(il) => return err_response(ErrorCode::IllegalState, il.reason),
        }
        // Advanced 需先 Reconciled 才到 Transferring；MVP 直接走 NegotiateBasic 演示
        if rec.phase == TransferState::Reconciling {
            if let Ok(next) = rec.phase.transition(TransferEvent::Reconciled) {
                rec.phase = next;
            }
        }
    }
    rec.confirmed
        .entry(c.file_id.clone())
        .or_default()
        .insert(c.piece_index);
    if let Some(sha) = c.sha256.as_deref() {
        rec.piece_sha
            .entry(c.file_id.clone())
            .or_default()
            .insert(c.piece_index, sha.to_ascii_lowercase());
    }
    rec.bitmap_version += 1;
    ok_json(json!({
        "sessionId": c.session_id,
        "fileId": c.file_id,
        "pieceIndex": c.piece_index,
        "phase": to_phase(rec.phase),
        "bitmapVersion": rec.bitmap_version,
    }))
}

/// `GET /api/v4/session/diff` —— 块级差异查询。
///
/// **四态状态码**（登记表 A11，非显而易见，必须照此实现）：
///
/// | 状态码 | 含义 | 发送端动作 |
/// |---|---|---|
/// | 206 | 这一块我有，且强校验通过 | 跳过 |
/// | 412 | 这一块我有，但 SHA-256 不匹配（NACK），响应带 `expected`/`actual` | **只重传这一块** |
/// | 416 | `pieceIndex` 越界，响应带 `Content-Range: bytes * /{size}` | 停止，重新取清单 |
/// | 200 | 需要传，响应体是 [`ChunkDiff`] | 按 `ChunkDiff` 传 |
///
/// 关键是把「存在性」和「正确性」用两个不同状态码分开表达。只按"存在与否"
/// 判断的实现里，**上次传输中断留下的半截文件永远不会被修复** —— 它存在，
/// 于是每轮都被跳过。
///
/// 不带 `pieceIndex` 时返回整文件的 `ChunkDiff` 摘要，发送端只有一条解析路径。
async fn handle_diff(store: &Arc<SessionStore>, path: &str) -> Response<Full<bytes::Bytes>> {
    let session_id = match extract_query(path, "sessionId") {
        Some(s) => s,
        None => return err_response(ErrorCode::BadRequest, "缺少 sessionId 参数"),
    };
    let file_id = match extract_query(path, "fileId") {
        Some(s) => s,
        None => return err_response(ErrorCode::BadRequest, "缺少 fileId 参数"),
    };

    let guard = store.inner.lock().await;
    let rec = match guard.get(&session_id) {
        Some(r) => r,
        None => return err_response(ErrorCode::NotFound, "会话不存在"),
    };
    let meta = match rec.files.get(&file_id) {
        Some(m) => m,
        None => return err_response(ErrorCode::NotFound, "文件未登记"),
    };

    let total_pieces = piece_count(meta.size);
    let confirmed = rec.confirmed.get(&file_id);
    let local_sha = rec.piece_sha.get(&file_id);

    // 整文件校验器不匹配 → 文件已变，全量重传（A11 的 200 语义）
    let mut file_changed = false;
    if let Some(raw) = extract_query(path, "etag") {
        let Some(v) = parse_validator(&raw) else {
            return err_response(
                ErrorCode::BadRequest,
                "ETag 不得使用 W/ 弱校验器：续传需要字节级强校验",
            );
        };
        match meta.sha256.as_deref() {
            Some(known) if known.eq_ignore_ascii_case(&v) => {}
            // 本端不知道整文件哈希时不能断言"已变"，否则每轮都全量重传
            None => {}
            Some(_) => file_changed = true,
        }
    }

    // 单块查询：三种非 200 的结果都在这里产生
    if !file_changed {
        if let Some(raw_idx) = extract_query(path, "pieceIndex") {
            let idx: u64 = match raw_idx.parse() {
                Ok(i) => i,
                Err(_) => return err_response(ErrorCode::BadRequest, "pieceIndex 必须是整数"),
            };
            // 416：越界。必须带 Content-Range，否则发送端无从得知真实总长
            if idx >= total_pieces {
                return json_response_with(
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    &json!({"fileId": file_id, "totalPieces": total_pieces}),
                    &[("content-range", format!("bytes */{}", meta.size))],
                );
            }
            let have = confirmed.map(|c| c.contains(&idx)).unwrap_or(false);
            let expected = extract_query(path, "sha256").map(|s| s.to_ascii_lowercase());
            let actual = local_sha.and_then(|m| m.get(&idx)).cloned();

            if have {
                match (expected, actual) {
                    // 412：我有这一块，但内容不对 —— 只需重传这一块
                    (Some(e), Some(a)) if e != a => {
                        return json_response_with(
                            StatusCode::PRECONDITION_FAILED,
                            &serde_json::to_value(DiffMismatch {
                                expected: e,
                                actual: a,
                            })
                            .unwrap(),
                            &[],
                        );
                    }
                    // 206：强校验通过
                    (Some(_), Some(a)) => {
                        return json_response_with(
                            StatusCode::PARTIAL_CONTENT,
                            &json!({"fileId": file_id, "pieceIndex": idx}),
                            &[("etag", etag_of(&a))],
                        );
                    }
                    // 对端要求内容证明，但本端没有度量 —— **不能回 206**。
                    // 无法证明正确就当作需要重传：宁可多传一块，
                    // 不可假称正确（那是"损坏文件永不修复"的成因）。
                    (Some(_), None) => {}
                    // 对端没要求内容证明，只问存在性
                    (None, _) => {
                        return json_response_with(
                            StatusCode::PARTIAL_CONTENT,
                            &json!({"fileId": file_id, "pieceIndex": idx}),
                            &[],
                        );
                    }
                }
            }
        }
    }

    // 200：需要传。整文件摘要，四类语义各自成集合
    let mut missing = Vec::new();
    let mut matched = Vec::new();
    let mut mismatched = Vec::new();
    for idx in 0..total_pieces {
        let have = !file_changed && confirmed.map(|c| c.contains(&idx)).unwrap_or(false);
        if !have {
            missing.push(idx);
            continue;
        }
        // 发送端声明的 piece 哈希 vs 本端落盘自算的哈希：
        // 这两个来源不同，比对才有意义
        let declared = meta
            .piece_hashes
            .as_ref()
            .and_then(|v| v.get(idx as usize))
            .map(|s| s.to_ascii_lowercase());
        let local = local_sha.and_then(|m| m.get(&idx)).cloned();
        match (declared, local) {
            (Some(d), Some(l)) if d != l => mismatched.push(idx),
            _ => matched.push(idx),
        }
    }
    let complete = missing.is_empty() && mismatched.is_empty();
    let mut headers = Vec::new();
    if let Some(sha) = meta.sha256.as_deref() {
        headers.push(("etag", etag_of(sha)));
    }
    json_response_with(
        StatusCode::OK,
        &serde_json::to_value(ChunkDiff {
            file_id,
            session_id,
            missing_chunks: missing,
            matched_chunks: matched,
            mismatched_chunks: mismatched,
            file_complete: complete,
        })
        .unwrap(),
        &headers,
    )
}

/// `GET /api/v4/session/verify` —— 单文件整体校验。
///
/// 全部块到齐且无坏块 → 200 + `sha256`；否则 412 + `reason`。
///
/// 当会话内**所有**文件都通过时才推进状态机（`Transferring → Verifying →
/// Completed`）—— 按单个文件推进会让多文件会话在第一个文件完成时就宣告结束。
async fn handle_verify(store: &Arc<SessionStore>, path: &str) -> Response<Full<bytes::Bytes>> {
    let session_id = match extract_query(path, "sessionId") {
        Some(s) => s,
        None => return err_response(ErrorCode::BadRequest, "缺少 sessionId 参数"),
    };
    let file_id = match extract_query(path, "fileId") {
        Some(s) => s,
        None => return err_response(ErrorCode::BadRequest, "缺少 fileId 参数"),
    };

    let mut guard = store.inner.lock().await;
    let rec = match guard.get_mut(&session_id) {
        Some(r) => r,
        None => return err_response(ErrorCode::NotFound, "会话不存在"),
    };
    if !rec.files.contains_key(&file_id) {
        return err_response(ErrorCode::NotFound, "文件未登记");
    }

    if let Some(reason) = file_incomplete_reason(rec, &file_id) {
        return json_response_with(
            StatusCode::PRECONDITION_FAILED,
            &serde_json::to_value(VerifyFileResponse {
                file_id,
                sha256: None,
                reason: Some(reason),
            })
            .unwrap(),
            &[],
        );
    }

    // 全会话到齐才推进状态机
    let all_ids: Vec<String> = rec.files.keys().cloned().collect();
    if all_ids
        .iter()
        .all(|id| file_incomplete_reason(rec, id).is_none())
        && rec.phase == TransferState::Transferring
    {
        if let Ok(next) = rec.phase.transition(TransferEvent::BeginVerify) {
            rec.phase = next;
            if let Ok(done) = rec.phase.transition(TransferEvent::VerifyOk) {
                rec.phase = done;
            }
        }
    }

    let sha = rec.files.get(&file_id).and_then(|m| m.sha256.clone());
    ok_json(VerifyFileResponse {
        file_id,
        sha256: sha,
        reason: None,
    })
}

/// `POST /api/v4/session/receipt` —— 接收端回传任务终态。
///
/// **终态由接收端判定**：数据落在谁磁盘上谁知道。发送端心跳超时时不允许
/// 自行判定失败，必须查对端终态 —— 否则就会出现"一方认为可重试、
/// 另一方认为已完成"的经典分歧。
///
/// 终态**单调**：已确认的终态不接受被后到的乱序回执改写。重传/重连场景下
/// 回执乱序到达是常态，允许回退等于让"已完成"重新变成"传输中"。
async fn handle_receipt(store: &Arc<SessionStore>, body: &[u8]) -> Response<Full<bytes::Bytes>> {
    let req: ReceiptRequest = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    let mut guard = store.inner.lock().await;
    let rec = match guard.get_mut(&req.session_id) {
        Some(r) => r,
        None => return err_response(ErrorCode::NotFound, "会话不存在"),
    };

    let mut rejected = Vec::new();
    for t in req.tasks {
        if !rec.files.contains_key(&t.file_id) {
            rejected.push(t.file_id.clone());
            continue;
        }
        match rec.receipts.get(&t.file_id) {
            // 已是终态且新状态不同 → 拒绝回退，保留原终态
            Some(old) if old.status.is_terminal() && old.status != t.status => {
                rejected.push(t.file_id.clone());
            }
            _ => {
                rec.receipts.insert(t.file_id.clone(), t);
            }
        }
    }

    let payload = TaskListResponse {
        session_id: req.session_id,
        phase: to_phase(rec.phase),
        tasks: task_list(rec),
    };
    let mut v = serde_json::to_value(payload).unwrap();
    // 明确告知哪些回执被拒 —— 静默丢弃会让对端以为写入成功
    v["rejected"] = serde_json::to_value(rejected).unwrap();
    json_response(StatusCode::OK, &v)
}

/// `GET /api/v4/session/tasks` —— 逐文件终态查询（阶段 4 验收：每个文件终态可查）。
///
/// 没有回执的文件**不会缺席**：按本端已确认进度合成 `queued`/`transferring`，
/// 否则 UI 上会出现"文件既不在列表里也没报错"的黑洞。
async fn handle_tasks(store: &Arc<SessionStore>, path: &str) -> Response<Full<bytes::Bytes>> {
    let session_id = match extract_query(path, "sessionId") {
        Some(s) => s,
        None => return err_response(ErrorCode::BadRequest, "缺少 sessionId 参数"),
    };
    let guard = store.inner.lock().await;
    let rec = match guard.get(&session_id) {
        Some(r) => r,
        None => return err_response(ErrorCode::NotFound, "会话不存在"),
    };
    ok_json(TaskListResponse {
        session_id,
        phase: to_phase(rec.phase),
        tasks: task_list(rec),
    })
}

// ----------------------------------------------------------------
// 辅助
// ----------------------------------------------------------------

/// 文件未到齐的原因；到齐返回 `None`。
///
/// "缺块"和"有坏块"分开描述 —— 这两种情况的处置动作不同
/// （补传 vs 重传特定块），合并成一句"校验失败"会让排障退回猜谜。
fn file_incomplete_reason(rec: &SessionRecord, file_id: &str) -> Option<String> {
    let meta = rec.files.get(file_id)?;
    let total = piece_count(meta.size);
    let confirmed = rec.confirmed.get(file_id);
    let local_sha = rec.piece_sha.get(file_id);

    let missing = (0..total)
        .filter(|i| !confirmed.map(|c| c.contains(i)).unwrap_or(false))
        .count();
    if missing > 0 {
        return Some(format!("缺少 {missing}/{total} 个块"));
    }
    if let Some(declared) = meta.piece_hashes.as_ref() {
        let bad = (0..total)
            .filter(
                |i| match (declared.get(*i as usize), local_sha.and_then(|m| m.get(i))) {
                    (Some(d), Some(l)) => !d.eq_ignore_ascii_case(l),
                    _ => false,
                },
            )
            .count();
        if bad > 0 {
            return Some(format!("{bad} 个块 SHA-256 不匹配"));
        }
    }
    None
}

/// 合成任务列表：回执优先（接收端权威），其余按本端进度推断。
fn task_list(rec: &SessionRecord) -> Vec<TaskReceipt> {
    let mut out: Vec<TaskReceipt> = rec
        .files
        .iter()
        .map(|(file_id, meta)| {
            if let Some(r) = rec.receipts.get(file_id) {
                return r.clone();
            }
            let done = rec.confirmed.get(file_id).map(|c| c.len()).unwrap_or(0);
            let status = if done == 0 {
                TaskStatus::Queued
            } else {
                TaskStatus::Transferring
            };
            TaskReceipt {
                file_id: file_id.clone(),
                rel_path: meta.rel_path.clone(),
                status,
                size: None,
                mtime: None,
                final_name: None,
                reason: None,
            }
        })
        .collect();
    // HashMap 迭代序不稳定；固定排序，否则同一状态两次查询返回不同顺序
    out.sort_by(|a, b| a.file_id.cmp(&b.file_id));
    out
}

fn extract_query(rest: &str, key: &str) -> Option<String> {
    // rest 形如 "session/phase?sessionId=xxx"
    let q = rest.split_once('?')?.1;
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// 内部状态机态 → 线上阶段 DTO。
///
/// **只此一处映射**。此前 HTTP 层自己写了一份 `"idle"` / `"preparing"` 字面量，
/// 与 [`TransferPhase`] 的 serde 名各自演化 —— 那正是"两端代码看着都对、
/// 联调时字段值对不上"的成因。让线上字符串只能由 DTO 的 serde 产生，
/// 改名时编译器和 schema 会同时拦住（登记表 C10/E10）。
fn to_phase(p: TransferState) -> TransferPhase {
    match p {
        TransferState::Idle => TransferPhase::Idle,
        TransferState::Preparing => TransferPhase::Preparing,
        TransferState::Reconciling => TransferPhase::Reconciling,
        TransferState::Transferring => TransferPhase::Transferring,
        TransferState::Paused => TransferPhase::Paused,
        TransferState::Degrading => TransferPhase::Degrading,
        TransferState::Verifying => TransferPhase::Verifying,
        TransferState::Completed => TransferPhase::Completed,
        TransferState::Failed => TransferPhase::Failed,
        TransferState::Aborted => TransferPhase::Aborted,
    }
}

fn algo_name(a: Algorithm) -> &'static str {
    match a {
        Algorithm::Advanced => "advanced",
        Algorithm::Basic => "basic",
    }
}

/// 原因码取自 [`DegradeReason::code`] —— **不在此另写一份 match**，
/// 否则 HTTP 层与 UI/日志层会各说一套（登记表 E10）。
fn degrade_name(d: DegradeReason) -> &'static str {
    d.code()
}

/// 将 `Error` 转换为 HTTP 响应（留给上层 service 包装）
#[allow(dead_code)]
pub fn error_to_response(e: &crate::error::Error) -> Response<Full<bytes::Bytes>> {
    let env = e.to_envelope();
    json_response(
        StatusCode::from_u16(e.code().http_status()).unwrap(),
        &serde_json::to_value(env).unwrap(),
    )
}

// 让 `route` 在 hyper service 中可用：接受 `Request<impl Body>` 并取出字节
#[allow(dead_code)]
pub async fn serve_request(
    store: &Arc<SessionStore>,
    req: Request<hyper::body::Incoming>,
) -> Response<Full<bytes::Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return err_response(ErrorCode::BadRequest, "读取请求体失败"),
    };
    route(store, method, &path, &body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Method;

    fn body(v: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&v).unwrap()
    }

    #[tokio::test]
    async fn register_prepares_session() {
        let store = SessionStore::new();
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({
                "deviceId": "devA", "alias": "A", "sessionId": "s1"
            })),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let g = store.inner.lock().await;
        assert_eq!(g.get("s1").unwrap().phase, TransferState::Preparing);
    }

    #[tokio::test]
    async fn empty_session_id_rejected() {
        let store = SessionStore::new();
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({"deviceId":"d","alias":"a","sessionId":""})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn full_flow_register_prepare_chunk_phase_abort() {
        let store = SessionStore::new();
        // register
        route(
            &store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({"deviceId":"d","alias":"a","sessionId":"s1"})),
        )
        .await;
        // prepare
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/prepare",
            &body(serde_json::json!({
                "sessionId":"s1","deviceId":"d",
                "files":{"f1":{"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1}}
            })),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);

        // chunk #0 → 应推进到 Transferring
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/chunk",
            &body(serde_json::json!({"sessionId":"s1","fileId":"f1","pieceIndex":0})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let g = store.inner.lock().await;
        assert_eq!(g.get("s1").unwrap().phase, TransferState::Transferring);
        assert!(g
            .get("s1")
            .unwrap()
            .confirmed
            .get("f1")
            .unwrap()
            .contains(&0));
        drop(g);

        // phase 查询应反映 transferring
        let r = route(
            &store,
            Method::GET,
            "/api/v4/session/phase?sessionId=s1",
            &[],
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["phase"].as_str(), Some("transferring"));

        // abort → Aborted
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/abort",
            &body(serde_json::json!({"sessionId":"s1"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let g = store.inner.lock().await;
        assert_eq!(g.get("s1").unwrap().phase, TransferState::Aborted);
        drop(g);

        // 终态再 abort → 非法迁移，返回 409
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/abort",
            &body(serde_json::json!({"sessionId":"s1"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn abort_unknown_session_is_404() {
        let store = SessionStore::new();
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/abort",
            &body(serde_json::json!({"sessionId":"nope"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unknown_endpoint_404() {
        let store = SessionStore::new();
        let r = route(&store, Method::GET, "/api/v4/session/nope", &[]).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn non_v4_path_404() {
        let store = SessionStore::new();
        let r = route(&store, Method::GET, "/api/v3/probe", &[]).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    /// `routes::ALL` 里的每一条都必须真的接进了 `route()`。
    ///
    /// 这是"声明"与"接线"之间唯一的闸门。缺了它，一条端点可以在
    /// `routes.rs` 里堂堂正正地声明、被 CI 的清单一致性检查放行、
    /// 被 schema 导出、被客户端照着调 —— 而 `route()` 的 match 里
    /// 根本没有那一支，于是联调时得到一个 404。
    /// "两端代码看着都对、联调 404"正是 routes.rs 模块文档要消灭的那件事，
    /// 但清单一致性只对齐了**文档与常量**，从没验证过**常量与 match 分支**。
    ///
    /// 判据是"不返回 404"而非"返回 200"：各端点有各自的前置条件
    /// （缺参数 400、未配对 401、会话不存在 404……），这里只关心
    /// **请求有没有落到某个分支上**。用空 body + 无查询串去打，
    /// 期望的就是那些参数校验错误，唯一不可接受的是 `not_found()`
    /// 那句"unknown V4 endpoint"。
    #[tokio::test]
    async fn every_declared_route_is_actually_wired() {
        let store = SessionStore::new();
        for r in routes::ALL {
            let method = match r.method {
                routes::Method::Get => Method::GET,
                routes::Method::Post => Method::POST,
            };
            let resp = route(&store, method.clone(), r.path, &[]).await;
            let status = resp.status();
            let bytes = to_bytes(resp).await;
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains("unknown V4 endpoint"),
                "{} {} 在 routes::ALL 里声明了，却没接进 route() 的 match —— \
                 客户端照着常量调用会得到 404（状态码 {status}）",
                method.as_str(),
                r.path,
            );
        }
    }

    /// 会话归属校验：知道 sessionId 也不能往别人的会话里塞文件。
    ///
    /// 同时这也是 `disconnect` 依赖的不变式 ——
    /// 一个会话只属于一个设备，否则"断开 A"可能收尾了 B 的传输。
    #[tokio::test]
    async fn prepare_rejects_a_session_owned_by_another_device() {
        let store = SessionStore::new();
        route(
            &store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({"deviceId":"devA","alias":"A","sessionId":"s1"})),
        )
        .await;
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/prepare",
            &body(serde_json::json!({
                "sessionId":"s1","deviceId":"devB","files":{}
            })),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "devB 用 devA 的 sessionId 登记了文件"
        );
        // 越权请求不得留下痕迹
        let g = store.inner.lock().await;
        assert_eq!(g.get("s1").unwrap().device_id, "devA");
    }

    // ============================================================
    // 阶段 2.4 补齐的四个端点：diff / verify / receipt / tasks
    // ============================================================

    /// 测试用的固定 64 位十六进制 SHA-256（仅作占位，不要求真实哈希）
    const SHA: &str = "abcdef0000000000000000000000000000000000000000000000000000000001";

    /// 注册并 prepare 一个会话（files 是 `fileId -> FileMeta` 的 JSON 对象）
    async fn setup(store: &Arc<SessionStore>, sid: &str, files: serde_json::Value) {
        route(
            store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({"deviceId":"d","alias":"a","sessionId":sid})),
        )
        .await;
        route(
            store,
            Method::POST,
            "/api/v4/session/prepare",
            &body(serde_json::json!({"sessionId":sid,"deviceId":"d","files":files})),
        )
        .await;
    }

    #[tokio::test]
    async fn diff_missing_piece_returns_200_chunkdiff() {
        let store = SessionStore::new();
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1}
            }),
        )
        .await;
        let r = route(
            &store,
            Method::GET,
            "/api/v4/session/diff?sessionId=s1&fileId=f1",
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["missingChunks"].as_array().unwrap().len(), 1);
        assert_eq!(v["fileComplete"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn diff_confirmed_matching_sha_returns_206_with_quoted_etag() {
        let store = SessionStore::new();
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1,
                       "sha256": SHA, "pieceHashes":[SHA]}
            }),
        )
        .await;
        // 确认第 0 块，本端落盘自算 sha = SHA
        route(
            &store,
            Method::POST,
            "/api/v4/session/chunk",
            &body(serde_json::json!({"sessionId":"s1","fileId":"f1","pieceIndex":0,"sha256":SHA})),
        )
        .await;
        // 对端声明 sha == 本端实测 sha → 206 + 双引号 ETag（A12）
        let r = route(
            &store,
            Method::GET,
            &format!("/api/v4/session/diff?sessionId=s1&fileId=f1&pieceIndex=0&sha256={SHA}"),
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            r.headers()
                .get("etag")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
            format!("\"{SHA}\"")
        );
    }

    #[tokio::test]
    async fn diff_confirmed_mismatched_sha_returns_412() {
        let store = SessionStore::new();
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1,
                       "sha256": SHA, "pieceHashes":[SHA]}
            }),
        )
        .await;
        route(
            &store,
            Method::POST,
            "/api/v4/session/chunk",
            &body(serde_json::json!({"sessionId":"s1","fileId":"f1","pieceIndex":0,"sha256":SHA})),
        )
        .await;
        // 对端声明 sha 与本端实测不同 → 412 + DiffMismatch（A11 的"正确性"态）
        let other = "bbcdef0000000000000000000000000000000000000000000000000000000002";
        let r = route(
            &store,
            Method::GET,
            &format!("/api/v4/session/diff?sessionId=s1&fileId=f1&pieceIndex=0&sha256={other}"),
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::PRECONDITION_FAILED);
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["expected"].as_str(), Some(other));
        assert_eq!(v["actual"].as_str(), Some(SHA));
    }

    #[tokio::test]
    async fn diff_out_of_range_returns_416_with_content_range() {
        let store = SessionStore::new();
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1}
            }),
        )
        .await;
        let r = route(
            &store,
            Method::GET,
            "/api/v4/session/diff?sessionId=s1&fileId=f1&pieceIndex=1",
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            r.headers()
                .get("content-range")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
            "bytes */100"
        );
    }

    #[tokio::test]
    async fn diff_weak_etag_rejected_400() {
        let store = SessionStore::new();
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1,
                       "sha256": SHA, "pieceHashes":[SHA]}
            }),
        )
        .await;
        // W/ 弱校验器必须被拒（A12）：续传需要字节级强校验
        let r = route(
            &store,
            Method::GET,
            &format!("/api/v4/session/diff?sessionId=s1&fileId=f1&etag=W/{SHA}"),
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn verify_incomplete_returns_412_with_reason() {
        let store = SessionStore::new();
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1}
            }),
        )
        .await;
        let r = route(
            &store,
            Method::GET,
            "/api/v4/session/verify?sessionId=s1&fileId=f1",
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::PRECONDITION_FAILED);
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert!(v["reason"].as_str().unwrap().contains("缺少"));
    }

    #[tokio::test]
    async fn verify_complete_advances_to_completed() {
        let store = SessionStore::new();
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1,"sha256":SHA}
            }),
        )
        .await;
        // chunk 推到 Transferring 并确认全部块
        route(
            &store,
            Method::POST,
            "/api/v4/session/chunk",
            &body(serde_json::json!({"sessionId":"s1","fileId":"f1","pieceIndex":0,"sha256":SHA})),
        )
        .await;
        let r = route(
            &store,
            Method::GET,
            "/api/v4/session/verify?sessionId=s1&fileId=f1",
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["sha256"].as_str(), Some(SHA));
        // 全会话到齐才推进（避免单文件完成即宣告整会话结束）
        let g = store.inner.lock().await;
        assert_eq!(g.get("s1").unwrap().phase, TransferState::Completed);
    }

    #[tokio::test]
    async fn receipt_terminal_status_is_monotonic() {
        let store = SessionStore::new();
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1}
            }),
        )
        .await;
        // 第一次回执：Completed
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/receipt",
            &body(serde_json::json!({"sessionId":"s1","tasks":[
                {"fileId":"f1","relPath":"x","status":"completed"}
            ]})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        // 乱序回执：Failed 不得踩回已完成（S1 终态单调）
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/receipt",
            &body(serde_json::json!({"sessionId":"s1","tasks":[
                {"fileId":"f1","relPath":"x","status":"failed"}
            ]})),
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(
            v["rejected"].as_array().unwrap(),
            &vec![serde_json::json!("f1")]
        );
        let g = store.inner.lock().await;
        assert_eq!(
            g.get("s1").unwrap().receipts.get("f1").unwrap().status,
            TaskStatus::Completed
        );
    }

    #[tokio::test]
    async fn receipt_unknown_file_rejected() {
        let store = SessionStore::new();
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1}
            }),
        )
        .await;
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/receipt",
            &body(serde_json::json!({"sessionId":"s1","tasks":[
                {"fileId":"ghost","relPath":"x","status":"completed"}
            ]})),
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(
            v["rejected"].as_array().unwrap(),
            &vec![serde_json::json!("ghost")]
        );
    }

    #[tokio::test]
    async fn tasks_lists_all_files_even_without_receipt() {
        let store = SessionStore::new();
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f2": {"fileId":"f2","fileName":"y","relPath":"y","size":100,"mtime":1},
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1}
            }),
        )
        .await;
        let r = route(
            &store,
            Method::GET,
            "/api/v4/session/tasks?sessionId=s1",
            &[],
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        let tasks = v["tasks"].as_array().unwrap();
        assert_eq!(tasks.len(), 2);
        // 固定按 fileId 排序，避免两次查询返回不一致顺序
        assert_eq!(tasks[0]["fileId"].as_str(), Some("f1"));
        assert_eq!(tasks[1]["fileId"].as_str(), Some("f2"));
        assert_eq!(tasks[0]["status"].as_str(), Some("queued"));
    }

    #[tokio::test]
    async fn tasks_reflects_progress_when_chunks_confirmed() {
        let store = SessionStore::new();
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1}
            }),
        )
        .await;
        route(
            &store,
            Method::POST,
            "/api/v4/session/chunk",
            &body(serde_json::json!({"sessionId":"s1","fileId":"f1","pieceIndex":0})),
        )
        .await;
        let r = route(
            &store,
            Method::GET,
            "/api/v4/session/tasks?sessionId=s1",
            &[],
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["tasks"][0]["status"].as_str(), Some("transferring"));
    }

    // 辅助：把 Response 的 body 读成 Vec<u8>
    async fn to_bytes(r: Response<Full<bytes::Bytes>>) -> Vec<u8> {
        use http_body_util::BodyExt;
        r.into_body().collect().await.unwrap().to_bytes().to_vec()
    }
}
