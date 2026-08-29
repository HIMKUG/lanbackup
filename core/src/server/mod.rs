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
    Algorithm, DegradeReason, FileMeta, PrepareRequest, PrepareResponse, SessionRegisterRequest,
    SessionRegisterResponse,
};
use crate::error::ErrorCode;
use crate::state::transfer::{TransferEvent, TransferState};

/// 单个会话的运行时记录
pub struct SessionRecord {
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
}

impl Default for SessionRecord {
    fn default() -> Self {
        Self {
            phase: TransferState::Idle,
            algorithm: Algorithm::Advanced,
            degrade_reason: None,
            bitmap_version: 0,
            files: HashMap::new(),
            confirmed: HashMap::new(),
        }
    }
}

/// 内存会话存储（MVP；生产环境替换为 rusqlite 持久化，见阶段 TODO）
#[derive(Default)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, SessionRecord>>,
}

impl SessionStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

fn ok_json(v: impl Serialize) -> Response<Full<bytes::Bytes>> {
    json_response(StatusCode::OK, &serde_json::to_value(v).unwrap())
}

fn json_response(status: StatusCode, v: &serde_json::Value) -> Response<Full<bytes::Bytes>> {
    let body = serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(bytes::Bytes::from(body)))
        .unwrap()
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
    // 仅匹配 /api/v4/... 前缀
    let rest = match path.strip_prefix("/api/v4/") {
        Some(r) => r,
        None => return not_found(),
    };
    // 匹配时用「去掉查询串」的路径，查询参数由各 handler 自行解析
    let path_only = rest.split_once('?').map(|(p, _)| p).unwrap_or(rest);

    match (method, path_only) {
        (Method::POST, "session/register") => handle_register(store, body).await,
        (Method::POST, "session/prepare") => handle_prepare(store, body).await,
        (Method::GET, "session/phase") => handle_phase(store, rest).await,
        (Method::POST, "session/heartbeat") => handle_heartbeat(store, body).await,
        (Method::POST, "session/abort") => handle_abort(store, body).await,
        (Method::POST, "session/chunk") => handle_chunk(store, body).await,
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
        "phase": phase_name(rec.phase),
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
        "phase": phase_name(rec.phase),
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
            ok_json(json!({"sessionId": a.session_id, "phase": phase_name(next)}))
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
    if matches!(rec.phase, TransferState::Preparing | TransferState::Reconciling) {
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
    rec.bitmap_version += 1;
    ok_json(json!({
        "sessionId": c.session_id,
        "fileId": c.file_id,
        "pieceIndex": c.piece_index,
        "phase": phase_name(rec.phase),
        "bitmapVersion": rec.bitmap_version,
    }))
}

// ----------------------------------------------------------------
// 辅助
// ----------------------------------------------------------------

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

fn phase_name(p: TransferState) -> &'static str {
    match p {
        TransferState::Idle => "idle",
        TransferState::Preparing => "preparing",
        TransferState::Reconciling => "reconciling",
        TransferState::Transferring => "transferring",
        TransferState::Paused => "paused",
        TransferState::Degrading => "degrading",
        TransferState::Verifying => "verifying",
        TransferState::Completed => "completed",
        TransferState::Failed => "failed",
        TransferState::Aborted => "aborted",
    }
}

fn algo_name(a: Algorithm) -> &'static str {
    match a {
        Algorithm::Advanced => "advanced",
        Algorithm::Basic => "basic",
    }
}

fn degrade_name(d: DegradeReason) -> &'static str {
    match d {
        DegradeReason::PeerNoCapability => "PEER_NO_CAPABILITY",
        DegradeReason::InitFailed => "INIT_FAILED",
        DegradeReason::ReconcileFailed => "RECONCILE_FAILED",
        DegradeReason::RetryExhausted => "RETRY_EXHAUSTED",
        DegradeReason::ChunkRetryExhausted => "CHUNK_RETRY_EXHAUSTED",
        DegradeReason::VerifyFailed => "VERIFY_FAILED",
    }
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
        route(&store, Method::POST, "/api/v4/session/register",
            &body(serde_json::json!({"deviceId":"d","alias":"a","sessionId":"s1"}))).await;
        // prepare
        let r = route(&store, Method::POST, "/api/v4/session/prepare",
            &body(serde_json::json!({
                "sessionId":"s1","deviceId":"d",
                "files":{"f1":{"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1}}
            }))).await;
        assert_eq!(r.status(), StatusCode::OK);

        // chunk #0 → 应推进到 Transferring
        let r = route(&store, Method::POST, "/api/v4/session/chunk",
            &body(serde_json::json!({"sessionId":"s1","fileId":"f1","pieceIndex":0}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let g = store.inner.lock().await;
        assert_eq!(g.get("s1").unwrap().phase, TransferState::Transferring);
        assert!(g.get("s1").unwrap().confirmed.get("f1").unwrap().contains(&0));
        drop(g);

        // phase 查询应反映 transferring
        let r = route(&store, Method::GET, "/api/v4/session/phase?sessionId=s1", &[]).await;
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["phase"].as_str(), Some("transferring"));

        // abort → Aborted
        let r = route(&store, Method::POST, "/api/v4/session/abort",
            &body(serde_json::json!({"sessionId":"s1"}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let g = store.inner.lock().await;
        assert_eq!(g.get("s1").unwrap().phase, TransferState::Aborted);
        drop(g);

        // 终态再 abort → 非法迁移，返回 409
        let r = route(&store, Method::POST, "/api/v4/session/abort",
            &body(serde_json::json!({"sessionId":"s1"}))).await;
        assert_eq!(r.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn abort_unknown_session_is_404() {
        let store = SessionStore::new();
        let r = route(&store, Method::POST, "/api/v4/session/abort",
            &body(serde_json::json!({"sessionId":"nope"}))).await;
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

    // 辅助：把 Response 的 body 读成 Vec<u8>
    async fn to_bytes(r: Response<Full<bytes::Bytes>>) -> Vec<u8> {
        use http_body_util::BodyExt;
        r.into_body().collect().await.unwrap().to_bytes().to_vec()
    }
}
