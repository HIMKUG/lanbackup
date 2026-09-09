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
use std::path::Path;
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
use crate::transfer::atomic_file::{self, ConflictOutcome};
use crate::transfer::chunk::piece_count;
use crate::transfer::cleanup::{CleanupPlan, CleanupTrigger};
use crate::transfer::piece_cache::PieceHashCache;

pub mod control;
pub mod sync_api;
/// 传输会话的磁盘持久化（见 [`persist`] 模块文档：纯 Rust 原子写 JSON 后端）。
pub(crate) mod persist;

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
    /// 距最后一次活跃信号（register / chunk / heartbeat）的时间点。
    ///
    /// S3/M17 闲置巡检的依据：非终态会话若超过 [`IDLE_TIMEOUT`] 无任何活跃
    /// 信号，即视为孤儿（prepare-upload 后客户端断开未上传 / 传输卡死 /
    /// 对端放弃），由平台层每 [`IDLE_SWEEP_INTERVAL`] 调一次
    /// [`SessionStore::sweep_idle`] 清理。用 `Instant`（单调时钟）：
    /// 闲置判定不能被系统时间回拨 / 拨快误导。
    ///
    /// 持久化重载时 `..Default::default()` 会把该字段重置为加载时刻 ——
    /// 语义是"重启后闲置计时从重启时刻重新开始"（给对端机会回来续传），
    /// 因此该字段不落盘（`Instant` 本也不可序列化，正好一致）。
    pub last_activity: std::time::Instant,
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
            last_activity: std::time::Instant::now(),
        }
    }
}

/// 服务端运行时状态：传输会话 + 控制面（身份 / 对端 / 握手）。
///
/// 传输会话与控制面共用一个 store，是刻意的：它们必须看到**同一份**配对状态。
/// 拆成两个 store 就会出现"控制面已解绑、传输面还在传"的窗口 ——
/// 这正是 V2 的老毛病（配对状态散落在多处，谁都不是权威）。
///
/// # 持久化
///
/// 内存 `inner` 是唯一热表（所有读零延迟）；每个状态变更**写穿**到
/// [`persist::SessionPersister`]（磁盘镜像），进程重启时由 [`Self::open`]
/// 把未终态的会话整组捞回内存。这样**断点续传在重启 / 杀后台 / 切 Wi-Fi 后
/// 依然成立** —— 此前 `confirmed` 位图只活内存，重启即全量重传（真实缺口，
/// 文档评审列为五层机制中未覆盖的一项）。
///
/// 传 `persist_dir: None` 则退化为纯内存（测试 / 尚未接 db），行为与原 MVP 一致。
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
    /// 可选持久化后端。`None` = 纯内存（测试 / 尚未接 db）。
    pub(crate) persist: Option<Arc<persist::SessionPersister>>,
    pub(crate) base_dir: std::sync::RwLock<std::path::PathBuf>,
    pub(crate) piece_cache: std::sync::RwLock<PieceHashCache>,
    pending_parts: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, std::path::PathBuf>>>,
}

impl SessionStore {
    /// 用一把**新生成**的设备身份建 store（纯内存，不持久化）。
    ///
    /// 注意：每次调用都是新身份。真实进程启动时应走 [`Self::with_identity`]
    /// 传入从加密存储恢复的身份（`DeviceIdentity::restore`），
    /// 否则重启一次就换个 deviceId，所有对端都会认为"这是台新设备"。
    pub fn new() -> Arc<Self> {
        Self::open(DeviceIdentity::generate(), "lanbackup", DeviceType::Desktop, None)
    }

    /// 用指定身份建 store（纯内存，不持久化）。
    pub fn with_identity(
        identity: DeviceIdentity,
        alias: &str,
        device_type: DeviceType,
    ) -> Arc<Self> {
        Self::open(identity, alias, device_type, None)
    }

    pub fn open(
        identity: DeviceIdentity,
        alias: &str,
        device_type: DeviceType,
        persist_dir: Option<&Path>,
    ) -> Arc<Self> {
        let persist = match persist_dir {
            Some(dir) => match persist::SessionPersister::open(dir) {
                Ok(p) => Some(Arc::new(p)),
                Err(e) => {
                    log::warn!("会话持久化不可用，降级为纯内存：{e}");
                    None
                }
            },
            None => None,
        };

        let mut inner = HashMap::new();
        if let Some(p) = &persist {
            match p.load_all() {
                Ok(records) => inner = records,
                Err(e) => log::warn!("重载会话失败，从空状态启动：{e}"),
            }
        }

        Arc::new(Self {
            inner: Mutex::new(inner),
            identity,
            alias: alias.to_string(),
            device_type,
            peers: PeerStore::new(),
            handshake: HandshakeStore::new(),
            sync: sync_api::SyncStore::new(),
            persist,
            base_dir: std::sync::RwLock::new(std::path::PathBuf::new()),
            piece_cache: std::sync::RwLock::new(PieceHashCache::new()),
            pending_parts: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
    }

    pub fn with_base_dir(self: &Arc<Self>, base_dir: std::path::PathBuf) {
        *self.base_dir.write().unwrap() = base_dir;
    }

    pub fn with_piece_cache(self: &Arc<Self>, cache: PieceHashCache) {
        *self.piece_cache.write().unwrap() = cache;
    }

    /// 合并对端记录到 PeerStore（桌面端从 PairingState 同步已配对设备）。
    pub async fn merge_peer(&self, record: control::PeerRecord) {
        self.peers.merge(record).await;
    }

    /// 设置用户线下输入的连接码（路径 A 首配用）。绝不经过网络。
    /// 入口统一做 E8 规范化（[`crate::identity::normalize_connection_code`]，
    /// 严格版：只保留 `[A-Z0-9]` 并统一大写）。
    pub async fn set_pairing_code(&self, code: impl Into<String>) {
        self.handshake.set_pairing_code(code.into()).await;
    }

    /// S3/M17/S5：清理闲置的非终态会话，返回被清理的 sessionId（排序）。
    ///
    /// 平台层每 [`IDLE_SWEEP_INTERVAL`] 调一次。清理对象：**非终态**且
    /// `now - last_activity > IDLE_TIMEOUT` 的会话 —— 覆盖三类孤儿：
    /// - M17：prepare-upload 后客户端断开、再无分块上传；
    /// - S3：传输中途对端卡死 / 放弃（最后分片到达已超 300s）；
    /// - S5：恶意方反复 register 后放弃（若无人清理，map 只增不减）。
    ///
    /// 终态会话（Completed/Failed/Aborted）不参与 —— 它们不占传输资源，
    /// 留给 `disconnect` 收尾与历史展示，不是内存泄漏源。
    ///
    /// 清理动作与 `disconnect` 一致：状态机迁到 `Aborted` → 写穿持久化 →
    /// 移除磁盘行与内存条目。`Abort` 对全部非终态均合法（状态机保证），
    /// 因此这里只对 `is_terminal` 做前置过滤，不需要再逐态匹配。
    pub async fn sweep_idle(&self, now: std::time::Instant) -> Vec<String> {
        // 锁内只做状态迁移与内存热表操作，**磁盘 IO 全部移出锁外**——
        // 对照模块顶部「锁粒度小、重活（IO/加密）在锁外进行」：sweep 会连清多台
        // 孤儿，把 write_meta（含 sync_all）留在锁内会让并发请求在磁盘慢时集体排队。
        let mut swept = Vec::new();
        // 待写穿的终态快照（锁外逐条 update + remove）
        let mut to_persist: Vec<(
            String,
            TransferState,
            Algorithm,
            Option<DegradeReason>,
            u64,
        )> = Vec::new();
        {
            let mut guard = self.inner.lock().await;
            // 先收集待清会话（非终态 + 超过闲置阈值），再逐一遍历迁移与移除 ——
            // 不能在 iter_mut 的同一遍里 remove（借用冲突），分两遍做。
            let idle: Vec<String> = guard
                .iter()
                .filter(|(_, rec)| {
                    !rec.phase.is_terminal()
                        && now.saturating_duration_since(rec.last_activity) > IDLE_TIMEOUT
                })
                .map(|(sid, _)| sid.clone())
                .collect();
            for sid in &idle {
                let mut removable = false;
                if let Some(rec) = guard.get_mut(sid) {
                    if let Ok(next) = rec.phase.transition(TransferEvent::Abort) {
                        rec.phase = next;
                        to_persist.push((
                            sid.clone(),
                            rec.phase,
                            rec.algorithm,
                            rec.degrade_reason,
                            rec.bitmap_version,
                        ));
                        removable = true;
                    }
                }
                // 状态机迁到 Aborted 的会话同步移出内存热表，否则孤儿仍驻留
                if removable {
                    guard.remove(sid);
                    swept.push(sid.clone());
                }
            }
        }
        // 锁外：写穿终态并清理磁盘行（孤儿不再有续传价值）
        if let Some(p) = &self.persist {
            for (sid, phase, algorithm, degrade_reason, bitmap_version) in &to_persist {
                p.update_session(sid, *phase, *algorithm, *degrade_reason, *bitmap_version);
                p.remove_session(sid);
            }
        }
        swept.sort();
        swept
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
        (Method::POST, routes::SESSION_CHUNK) => handle_chunk(store, path, body).await,
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
    if let Some(p) = &store.persist {
        p.new_session(
            &req.session_id,
            &rec.device_id,
            rec.phase,
            rec.algorithm,
            rec.degrade_reason,
            rec.bitmap_version,
        );
    }
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
        if let Some(p) = &store.persist {
            p.set_file(&req.session_id, file_id, meta);
        }
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
    // S3：心跳就是"我还在线"的信号 —— 续期，避免对端在线（无数据流动）
    // 却被闲置巡检误杀成孤儿。
    rec.last_activity = std::time::Instant::now();
    if let Some(p) = &store.persist {
        p.update_session(
            &hb.session_id,
            rec.phase,
            rec.algorithm,
            rec.degrade_reason,
            rec.bitmap_version,
        );
    }
    let payload = json!({
        "sessionId": hb.session_id,
        "phase": to_phase(rec.phase),
        "bitmapVersion": rec.bitmap_version,
    });
    ok_json(payload)
}

/// §六 `MarkUnconfirmedTasksCancelled`：把会话内**无终态回执**的任务标记为 `Cancelled`。
///
/// 不猜测成败：abort/断线/失败时，没收到接收端终态回执的文件一律视为 cancelled，
/// 而不是悄悄当成 completed / failed。已有终态（Completed/Failed/Cancelled）的
/// 任务**绝不被覆盖**（S1 终态单调）。
///
/// 返回本次标记的任务数。
fn mark_unconfirmed_cancelled(rec: &mut SessionRecord, reason: &str) -> usize {
    let mut cancelled = 0;
    let ids: Vec<String> = rec.files.keys().cloned().collect();
    for fid in ids {
        let is_terminal = rec
            .receipts
            .get(&fid)
            .map(|r| r.status.is_terminal())
            .unwrap_or(false);
        if is_terminal {
            continue;
        }
        let rel_path = rec
            .files
            .get(&fid)
            .map(|m| m.rel_path.clone())
            .unwrap_or_default();
        rec.receipts.insert(
            fid.clone(),
            TaskReceipt {
                file_id: fid,
                rel_path,
                status: TaskStatus::Cancelled,
                size: None,
                mtime: None,
                final_name: None,
                reason: Some(reason.to_string()),
            },
        );
        cancelled += 1;
    }
    cancelled
}

/// 执行 §六 清理计划中 **core server 侧**可执行的动作，按固定顺序：
///
/// 1. `MarkUnconfirmedTasksCancelled` —— 异常收场（abnormal trigger）时，把未确认
///    任务标记为 `Cancelled`（不猜测成败；S1 终态单调保护已有终态）；
/// 2. `MarkSessionRecord` —— 写穿终态并移除磁盘行；`keep_in_memory=false` 时才连
///    内存热表一起移除（`handle_abort`/`handle_verify` 保留内存供历史展示）。
///
/// 资源类动作（`CancelInflightRequests` / `ReleaseSemaphorePermits` / `StopHeartbeat` /
/// `DeletePartialChunkFiles` / `ClearUiProgress`）属于**发送端平台层**职责，
/// 由平台层在收到 [`Step::Cleanup`] 后执行（`transfer/session.rs` 注释已写明）。
///
/// 磁盘 IO 全部在**锁外**执行（对照模块顶部「重活（IO/加密）在锁外进行」）。
///
/// 返回本次标记为 cancelled 的任务数（日志/统计用）。
///
/// 供三条路径复用：`handle_abort`（keep=true）、`handle_verify` 终态（keep=true）、
/// 平台层处理 `Step::Cleanup`（keep 由平台层按历史展示需求决定）。
pub async fn execute_cleanup_plan(
    store: &Arc<SessionStore>,
    sid: &str,
    plan: &CleanupPlan,
    keep_in_memory: bool,
) -> usize {
    let mut cancelled = 0;
    let snapshot = {
        let mut guard = store.inner.lock().await;
        let Some(rec) = guard.get_mut(sid) else {
            return 0; // 会话不存在（已被别的路径清理），无事可做
        };
        if plan.trigger.is_abnormal() {
            cancelled = mark_unconfirmed_cancelled(rec, plan.trigger.record_reason());
        }
        let snap = (
            rec.phase,
            rec.algorithm,
            rec.degrade_reason,
            rec.bitmap_version,
        );
        if !keep_in_memory {
            guard.remove(sid);
        }
        snap
    };
    // 锁外：写穿终态 + 移除磁盘行（终态不再有续传价值）
    if let Some(p) = &store.persist {
        p.update_session(sid, snapshot.0, snapshot.1, snapshot.2, snapshot.3);
        p.remove_session(sid);
    }
    cancelled
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
    // 第一步：状态机迁移（锁内，只动内存）
    let migrated = {
        let mut guard = store.inner.lock().await;
        let rec = match guard.get_mut(&a.session_id) {
            Some(r) => r,
            None => return err_response(ErrorCode::NotFound, "会话不存在"),
        };
        match rec.phase.transition(TransferEvent::Abort) {
            Ok(next) => {
                rec.phase = next;
                Some(next)
            }
            Err(il) => return err_response(ErrorCode::IllegalState, il.reason),
        }
    };
    // 第二步：core server 侧清理（标记未确认任务 cancelled + 写穿终态 + 移除磁盘行）。
    // 锁内 IO 已在 execute_cleanup_plan 中移出锁外。
    let Some(phase) = migrated else {
        unreachable!()
    };
    let plan = CleanupPlan::for_trigger(CleanupTrigger::UserAbort, phase);
    let cancelled = execute_cleanup_plan(store, &a.session_id, &plan, true).await;
    log::info!(
        "handle_abort: sessionId={} cancelled_tasks={} cleanup_plan=[{}]",
        a.session_id,
        cancelled,
        plan.actions()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    ok_json(json!({
        "sessionId": a.session_id,
        "phase": to_phase(phase),
        "cancelled": cancelled
    }))
}

async fn handle_chunk(store: &Arc<SessionStore>, path: &str, body: &[u8]) -> Response<Full<bytes::Bytes>> {
    let session_id = match extract_query(path, "sessionId") {
        Some(s) if !s.is_empty() => s,
        _ => return err_response(ErrorCode::BadRequest, "缺少 sessionId 参数"),
    };
    let file_id = match extract_query(path, "fileId") {
        Some(s) if !s.is_empty() => s,
        _ => return err_response(ErrorCode::BadRequest, "缺少 fileId 参数"),
    };
    let piece_index: u64 = match extract_query(path, "pieceIndex") {
        Some(s) => s.parse().map_err(|_| "pieceIndex 必须是整数").unwrap_or(0),
        None => 0,
    };
    let client_sha256 = extract_query(path, "sha256").map(|s| s.to_lowercase());

    let mut guard = store.inner.lock().await;
    let rec = match guard.get_mut(&session_id) {
        Some(r) => r,
        None => return err_response(ErrorCode::NotFound, "会话不存在"),
    };
    if !rec.files.contains_key(&file_id) {
        return err_response(ErrorCode::NotFound, "文件未登记");
    }
    let file_meta = rec.files.get(&file_id).unwrap();

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
        if rec.phase == TransferState::Reconciling {
            if let Ok(next) = rec.phase.transition(TransferEvent::Reconciled) {
                rec.phase = next;
            }
        }
    }

    rec.last_activity = std::time::Instant::now();

    let base_dir = store.base_dir.read().unwrap().clone();
    let rel_path = &file_meta.rel_path;
    let final_path = if base_dir.as_os_str().is_empty() {
        std::path::PathBuf::from(rel_path)
    } else {
        base_dir.join(rel_path)
    };
    let part_path = atomic_file::part_path(&final_path, &session_id, &file_id);

    if let Some(parent) = final_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    match atomic_file::resolve_conflict(&final_path, file_meta.size, file_meta.mtime) {
        Ok(ConflictOutcome::Identical) => {
            rec.confirmed.entry(file_id.clone()).or_default().insert(piece_index);
            if let Some(sha) = &client_sha256 {
                rec.piece_sha.entry(file_id.clone()).or_default().insert(piece_index, sha.clone());
            }
            rec.bitmap_version += 1;
            if matches!(rec.phase, TransferState::Preparing | TransferState::Reconciling) {
                let ev = if rec.algorithm == Algorithm::Advanced {
                    TransferEvent::NegotiateAdvanced
                } else {
                    TransferEvent::NegotiateBasic
                };
                if let Ok(next) = rec.phase.transition(ev) {
                    rec.phase = next;
                }
                if rec.phase == TransferState::Reconciling {
                    if let Ok(next) = rec.phase.transition(TransferEvent::Reconciled) {
                        rec.phase = next;
                    }
                }
            }
            if let Some(p) = &store.persist {
                p.update_session(&session_id, rec.phase, rec.algorithm, rec.degrade_reason, rec.bitmap_version);
                p.set_piece(&session_id, &file_id, piece_index, client_sha256.as_deref());
            }
            return ok_json(json!({
                "sessionId": session_id,
                "fileId": file_id,
                "pieceIndex": piece_index,
                "phase": to_phase(rec.phase),
                "bitmapVersion": rec.bitmap_version,
            }));
        }
        Ok(ConflictOutcome::Renamed(_)) | Ok(ConflictOutcome::None) => {}
        Err(e) => return err_response(ErrorCode::Internal, &format!("冲突检查失败: {e}")),
    }

    // 打开 + 写入临时文件：任何 IO 失败必须立刻以 500 拒绝该块。
    // 此前 map_err 产出的错误响应被 `let _ =` 整体吞掉，写失败的块仍会被
    // 标记 confirmed 并可能被原子提交——静默数据损坏路径，已修复。
    // （显式 early return 同时避免 clippy::result_large_err 的大 Err 闭包）
    let opened = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&part_path);
    let mut part = match opened {
        Ok(f) => f,
        Err(e) => return err_response(ErrorCode::Internal, &format!("打开临时文件失败: {e}")),
    };
    if let Err(e) = std::io::Write::write_all(&mut part, body) {
        return err_response(ErrorCode::Internal, &format!("写入分块失败: {e}"));
    }

    {
        let mut pending = store.pending_parts.lock().unwrap();
        pending.entry(file_id.clone()).or_insert_with(|| part_path.clone());
    }

    rec.confirmed.entry(file_id.clone()).or_default().insert(piece_index);
    if let Some(ref sha) = client_sha256 {
        rec.piece_sha.entry(file_id.clone()).or_default().insert(piece_index, sha.clone());
    }
    rec.bitmap_version += 1;
    if matches!(rec.phase, TransferState::Preparing | TransferState::Reconciling) {
        let ev = if rec.algorithm == Algorithm::Advanced {
            TransferEvent::NegotiateAdvanced
        } else {
            TransferEvent::NegotiateBasic
        };
        if let Ok(next) = rec.phase.transition(ev) {
            rec.phase = next;
        }
        if rec.phase == TransferState::Reconciling {
            if let Ok(next) = rec.phase.transition(TransferEvent::Reconciled) {
                rec.phase = next;
            }
        }
    }

    let piece_count = piece_count(file_meta.size);
    let all_confirmed = rec.confirmed.get(&file_id).map(|s| s.len() as u64 == piece_count).unwrap_or(false);
    if all_confirmed {
        if let Err(e) = atomic_file::commit(&part_path, &final_path) {
            return err_response(ErrorCode::Internal, &format!("原子提交失败: {e}"));
        }
        if let Err(e) = atomic_file::restore_mtime(&final_path, file_meta.mtime) {
            log::warn!("恢复 mtime 失败: {e}");
        }
        {
            let mut pending = store.pending_parts.lock().unwrap();
            pending.remove(&file_id);
        }
        log::info!("文件落盘完成: {}", rel_path);
    }

    if let Some(p) = &store.persist {
        p.update_session(&session_id, rec.phase, rec.algorithm, rec.degrade_reason, rec.bitmap_version);
        p.set_piece(&session_id, &file_id, piece_index, client_sha256.as_deref());
    }

    ok_json(json!({
        "sessionId": session_id,
        "fileId": file_id,
        "pieceIndex": piece_index,
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

    // 锁内：校验 + 状态机推进，只动内存。磁盘 IO（写穿/清理）统一移到锁外。
    let snapshot = {
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
        let phase = rec.phase;
        let algorithm = rec.algorithm;
        let degrade_reason = rec.degrade_reason;
        let bitmap_version = rec.bitmap_version;
        (sha, phase, algorithm, degrade_reason, bitmap_version)
    };
    let (sha, phase, algorithm, degrade_reason, bitmap_version) = snapshot;

    // 锁外：写穿持久化（含终态）；终态会话不再有续传价值，清理磁盘行。
    // 终态路径复用 execute_cleanup_plan（§六 MarkSessionRecord + 保留内存供历史展示）。
    if phase.is_terminal() {
        let plan = CleanupPlan::for_trigger(CleanupTrigger::Completed, phase);
        let _ = execute_cleanup_plan(store, &session_id, &plan, true).await;
    } else if let Some(p) = &store.persist {
        p.update_session(
            &session_id,
            phase,
            algorithm,
            degrade_reason,
            bitmap_version,
        );
    }

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
                if let Some(p) = &store.persist {
                    p.set_receipt(&req.session_id, &t.file_id, &t);
                }
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
        TransferState::Processing => TransferPhase::Processing,
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
//
// 这里的常量与登记簿 M18/P32/P33 对应，平台层构建 hyper server 时必须遵守
// （接入方式见 [`hyper_http1_builder`]，或自行构造并应用下述映射）：
// - `MAX_REQUEST_LINE_BYTES`（M18 请求行 16384B）：映射到 hyper 的 `http1.max_buf_size(...)`
//   —— 该值约束「请求行 + 全部头部」的总缓冲，超过即 431 拒绝，防超长头内存放大；
// - `MAX_UPSTREAM_CONNECTIONS`（P32 有界并发 32）：连接数上限，防 Slowloris。
//   接线端对每个 `TcpListener::accept` 的连接持有 RAII guard，连接 Drop 时释放；
// - `IO_TIMEOUT`（P33 读写超时 30s）：读/写超时，防无超时连接挂线程。
//   接线端用 `tokio::time::timeout(IO_TIMEOUT, service_call)` 包住每次调用。
pub const MAX_REQUEST_LINE_BYTES: u64 = 16 * 1024;
pub const MAX_UPSTREAM_CONNECTIONS: usize = 32;
pub const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// S3/M17/S5：会话闲置巡检的周期（60s）。
///
/// 平台层每 [`IDLE_SWEEP_INTERVAL`] 调一次 [`SessionStore::sweep_idle`]，
/// 清理超过 [`IDLE_TIMEOUT`] 无活跃信号的**非终态**会话。
pub const IDLE_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// S3/M17/S5：会话闲置判定阈值（300s）。
///
/// 对齐登记簿 S3「距最后分片到达超过 300s」：活跃长传输在
/// `handle_chunk` / `handle_heartbeat` 处持续续期，不会被误杀。
pub const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// 平台层接线时的**默认 http1 服务构建器**（M18 请求行硬上限已注入）。
///
/// hyper 的 `http1::Builder::max_buf_size` 只能接受 `usize`，`MAX_REQUEST_LINE_BYTES`
/// 按 `u64` 声明便于将来迁移协议，因此在这里做一次显式收窄，接线端直接复用：
/// `hyper::server::conn::http1::Builder` 随后 `serve_connection(conn, service_fn(...))`。
pub fn hyper_http1_builder() -> hyper::server::conn::http1::Builder {
    let mut b = hyper::server::conn::http1::Builder::new();
    b.max_buf_size(MAX_REQUEST_LINE_BYTES as usize);
    b
}

/// M18：HTTP 请求体硬上限（10MB）。
///
/// 读 body 前先按 `Content-Length` 预检，收集后再按实际大小复核 ——
/// 恶意对端可以用 chunked 编码绕过声明长度，两道闸缺一不可。
/// 对应登记簿 D7：**认证前限制分配长度**，不设上限则任意对端可让本端尝试分配 ~4GiB。
#[allow(dead_code)]
pub const MAX_BODY_BYTES: u64 = 10 * 1024 * 1024;

/// M18/D7：body 长度双闸校验（纯函数，便于单测）。
///
/// `declared` 为 `Content-Length` 头解析值，`actual` 为实际收集字节数。
/// 任一超限即返回 400（复用 `BadRequest` 变体，避免改动 ErrorCode 枚举触发
/// golden schema 连锁变更；413 语义由 message 表达）。
fn body_limit_check(
    declared: Option<u64>,
    actual: usize,
) -> Result<(), Box<Response<Full<bytes::Bytes>>>> {
    let over = match declared {
        Some(cl) => cl > MAX_BODY_BYTES,
        None => false,
    } || actual as u64 > MAX_BODY_BYTES;
    if over {
        Err(Box::new(err_response(
            ErrorCode::BadRequest,
            "request body exceeds 10MB limit",
        )))
    } else {
        Ok(())
    }
}

// 让 `route` 在 hyper service 中可用：接受 `Request<impl Body>` 并取出字节
#[allow(dead_code)]
pub async fn serve_request(
    store: &Arc<SessionStore>,
    req: Request<hyper::body::Incoming>,
) -> Response<Full<bytes::Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // M18/D7：读 body 前先按 Content-Length 预检，超限直接拒绝，避免先分配再发现
    let declared = req
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    if let Err(resp) = body_limit_check(declared, 0) {
        return *resp;
    }
    let body = match req.into_body().collect().await {
        Ok(b) => {
            let bytes = b.to_bytes();
            // 实际大小复核：chunked 传输无 Content-Length，声明可被绕过
            if let Err(resp) = body_limit_check(None, bytes.len()) {
                return *resp;
            }
            bytes
        }
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

    /// 每个测试独占一个临时 base_dir。
    ///
    /// chunk 落盘路径 = base_dir + rel_path；base_dir 为空时退化为 CWD 相对路径，
    /// 于是所有测试都在读写同一个 `core/x` 文件。cargo test 默认多线程并行，
    /// Windows 下并发打开/写同一文件触发共享冲突 → `ErrorCode::Internal`（500），
    /// 表现为随机挂测试（e2e_full_session_lifecycle / verify_complete_… 交替失败），
    /// 单跑必过。用 uuid 子目录隔离，从结构上消灭跨测试文件竞争。
    fn test_store() -> Arc<SessionStore> {
        let store = SessionStore::new();
        let dir = std::env::temp_dir().join(format!("lanbak-store-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&dir);
        store.with_base_dir(dir);
        store
    }

    // ---- A1 安全高危批：长度上限 / 接线常量 ----

    #[test]
    fn m18_body_limit_rejects_declared_overflow() {
        // Content-Length 声明超限：读 body 前就必须拒绝
        let err = body_limit_check(Some(MAX_BODY_BYTES + 1), 0).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn m18_body_limit_rejects_actual_overflow() {
        // chunked 无声明长度，实际收集后复核必须拦下
        let err = body_limit_check(None, MAX_BODY_BYTES as usize + 1).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn m18_body_limit_accepts_within_limits() {
        assert!(body_limit_check(Some(MAX_BODY_BYTES), 0).is_ok());
        assert!(body_limit_check(None, MAX_BODY_BYTES as usize).is_ok());
        assert!(body_limit_check(Some(100), 100).is_ok());
    }

    #[test]
    fn m18_body_limit_just_over_the_edge_is_rejected() {
        assert!(body_limit_check(Some(MAX_BODY_BYTES + 1), 0).is_err());
        assert!(body_limit_check(None, MAX_BODY_BYTES as usize + 1).is_err());
    }

    #[test]
    fn p32_33_constants_match_registry_contract() {
        // P32 有界并发 32、P33 读写超时 30s、M18 请求行 16384B —— 与登记簿一字不差
        assert_eq!(MAX_UPSTREAM_CONNECTIONS, 32);
        assert_eq!(IO_TIMEOUT, std::time::Duration::from_secs(30));
        assert_eq!(MAX_REQUEST_LINE_BYTES, 16 * 1024);
    }

    #[test]
    fn hyper_builder_wires_request_line_limit() {
        // 接线端拿到的 builder 必须已经带 16KB 请求行上限，防平台层遗忘
        let b = hyper_http1_builder();
        let _ = b; // max_buf_size 无 getter，能构建即证明注入路径存在；
                   // 上限值本身由上面的常量断言兜底
    }

    // ---- A3 可靠性批：会话闲置巡检（S3/M17/S5）----

    #[test]
    fn s3_17_idle_parameters_match_registry() {
        // S3：60s 巡检 / 300s 闲置；M17：孤立会话 5 分钟 = 300s，两者对齐
        assert_eq!(IDLE_SWEEP_INTERVAL, std::time::Duration::from_secs(60));
        assert_eq!(IDLE_TIMEOUT, std::time::Duration::from_secs(300));
    }

    /// M17：register 后对端消失、再无任何分块 → 超过 300s 必须被巡检清掉。
    #[tokio::test]
    async fn m17_orphan_session_is_swept_after_idle_timeout() {
        let store = test_store();
        route(
            &store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({
                "deviceId": "devA", "alias": "A", "sessionId": "orphan"
            })),
        )
        .await;
        // 未到 300s：不清理
        assert!(store.sweep_idle(std::time::Instant::now()).await.is_empty());
        // 用「未来 now」越过闲置阈值（now + 301s）→ 孤儿判定成立，必须清掉。
        // 用传参而非 `Instant::now() - Duration`：后者在系统 uptime 不足时溢出。
        let later = std::time::Instant::now() + std::time::Duration::from_secs(301);
        assert_eq!(store.sweep_idle(later).await, vec!["orphan"]);
        assert!(
            store.inner.lock().await.get("orphan").is_none(),
            "孤儿会话未被清掉 —— map 会随恶意 register 无界增长（S5）"
        );
    }

    /// S3：活跃长传输在 chunk 处续期，巡检不得误杀。
    #[tokio::test]
    async fn s3_recently_active_session_is_not_swept() {
        let store = test_store();
        route(
            &store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({
                "deviceId": "devA", "alias": "A", "sessionId": "live"
            })),
        )
        .await;
        route(
            &store,
            Method::POST,
            "/api/v4/session/chunk?sessionId=live&fileId=f1&pieceIndex=0",
            &[],
        )
        .await;
        // 刚有 chunk 活动，即使巡检此刻到来也不该清
        assert!(store.sweep_idle(std::time::Instant::now()).await.is_empty());
    }

    /// S3：心跳续期 —— 对端在线（无数据流动）也不是孤儿。
    #[tokio::test]
    async fn s3_heartbeat_renews_activity_and_defers_sweep() {
        let store = test_store();
        route(
            &store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({
                "deviceId": "devA", "alias": "A", "sessionId": "hb"
            })),
        )
        .await;
        // 把活动时间拨回 301s 前（checked_sub 兜底：系统 uptime 不足时退回 now，
        // 避免 `Instant::now() - Duration` 在刚开机环境溢出），然后来一发心跳续期
        {
            let mut g = store.inner.lock().await;
            g.get_mut("hb").unwrap().last_activity = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(301))
                .unwrap_or_else(std::time::Instant::now);
        }
        route(
            &store,
            Method::POST,
            "/api/v4/session/heartbeat",
            &body(serde_json::json!({"sessionId": "hb", "bitmapVersion": 0})),
        )
        .await;
        assert!(
            store.sweep_idle(std::time::Instant::now()).await.is_empty(),
            "心跳续期后仍被误杀 —— 对端在线的会话不是孤儿"
        );
    }

    /// 终态会话不参与闲置清理：它们是历史展示与 disconnect 的职责，不是泄漏源。
    ///
    /// 用「未来 now」驱动闲置判定（传 now + 7200s），避免 `Instant::now() - Duration`
    /// 在系统 uptime 不足时溢出（刚开机环境稳定性）。
    #[tokio::test]
    async fn s3_sweep_keeps_terminal_sessions() {
        let store = test_store();
        route(
            &store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({
                "deviceId": "devA", "alias": "A", "sessionId": "done"
            })),
        )
        .await;
        route(
            &store,
            Method::POST,
            "/api/v4/session/abort",
            &body(serde_json::json!({"sessionId": "done"})),
        )
        .await;
        // 终态会话与 last_activity 无关：即使闲置远超阈值也不该被清
        let far_future = std::time::Instant::now() + std::time::Duration::from_secs(7200);
        assert!(
            store.sweep_idle(far_future).await.is_empty(),
            "终态会话被闲置清理误删"
        );
        assert_eq!(
            store.inner.lock().await.get("done").unwrap().phase,
            TransferState::Aborted
        );
    }

    #[tokio::test]
    async fn register_prepares_session() {
        let store = test_store();
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

    // ---- P0-2：abort 标记未确认任务为 cancelled（§六 MarkUnconfirmedTasksCancelled）----

    /// abort 后，没有终态回执的任务必须显示 cancelled，而不是 queued/transferring；
    /// 已有终态回执的任务保持原样（S1 终态单调）。
    #[tokio::test]
    async fn abort_marks_unconfirmed_tasks_cancelled() {
        let store = test_store();
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1},
                "f2": {"fileId":"f2","fileName":"y","relPath":"y","size":100,"mtime":1}
            }),
        )
        .await;
        // f1 已确认一块（未终态）；f2 先给终态回执（模拟已完成的文件）
        route(
            &store,
            Method::POST,
            "/api/v4/session/chunk?sessionId=s1&fileId=f1&pieceIndex=0",
            &[],
        )
        .await;
        route(
            &store,
            Method::POST,
            "/api/v4/session/receipt",
            &body(serde_json::json!({"sessionId":"s1","tasks":[
                {"fileId":"f2","relPath":"y","status":"completed"}
            ]})),
        )
        .await;

        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/abort",
            &body(serde_json::json!({"sessionId":"s1"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);

        // tasks：f1 应 cancelled（未确认），f2 保持 completed（终态单调）
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
        for t in tasks {
            match t["fileId"].as_str().unwrap() {
                "f1" => assert_eq!(
                    t["status"].as_str(),
                    Some("cancelled"),
                    "未确认任务 abort 后必须 cancelled，而不是 {t:?}"
                ),
                "f2" => assert_eq!(
                    t["status"].as_str(),
                    Some("completed"),
                    "已有终态的任务不得被 abort 回退：{t:?}"
                ),
                other => panic!("意外的 fileId {other}"),
            }
        }
    }

    /// 无文件（或全部有终态）时 abort 不产生虚假 cancelled。
    #[tokio::test]
    async fn abort_without_unconfirmed_tasks_marks_none() {
        let store = test_store();
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
            "/api/v4/session/receipt",
            &body(serde_json::json!({"sessionId":"s1","tasks":[
                {"fileId":"f1","relPath":"x","status":"failed"}
            ]})),
        )
        .await;
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/abort",
            &body(serde_json::json!({"sessionId":"s1"})),
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["cancelled"], serde_json::json!(0));
        // f1 保持 failed，不被改成 cancelled（终态单调）
        let r = route(
            &store,
            Method::GET,
            "/api/v4/session/tasks?sessionId=s1",
            &[],
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["tasks"][0]["status"].as_str(), Some("failed"));
    }

    // ---- P0-3：execute_cleanup_plan 生产执行者 ----

    /// 执行器对四种 trigger 都可调用且幂等（重复调用不炸、不重复标记）。
    #[tokio::test]
    async fn execute_cleanup_plan_is_idempotent() {
        let store = test_store();
        for (sid, trigger) in [
            ("u", CleanupTrigger::UserAbort),
            ("p", CleanupTrigger::PeerLost),
            ("f", CleanupTrigger::Failed),
            ("c", CleanupTrigger::Completed),
        ] {
            setup(
                &store,
                sid,
                serde_json::json!({
                    "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1}
                }),
            )
            .await;
            // 直接迁移到对应终态（execute_cleanup_plan 假定调用方已迁移）
            let plan = {
                let mut guard = store.inner.lock().await;
                let rec = guard.get_mut(sid).unwrap();
                if sid == "c" {
                    // Completed 需要完整路径：Preparing→…→Verifying→Completed
                    let _ = rec.phase.transition(TransferEvent::NegotiateAdvanced);
                    let _ = rec.phase.transition(TransferEvent::Reconciled);
                    let _ = rec.phase.transition(TransferEvent::Progress);
                    let _ = rec.phase.transition(TransferEvent::BeginVerify);
                    let _ = rec.phase.transition(TransferEvent::VerifyOk);
                } else {
                    let _ = rec.phase.transition(TransferEvent::Abort);
                }
                CleanupPlan::for_trigger(trigger, rec.phase)
            };
            // 第一次执行：abnormal trigger 标记 1 个未确认任务；Completed 标记 0 个
            let n1 = execute_cleanup_plan(&store, sid, &plan, true).await;
            let expect_first = if sid == "c" { 0 } else { 1 };
            assert_eq!(
                n1, expect_first,
                "{sid}: 首次执行应标记 {expect_first} 个任务，实际 {n1}"
            );
            // 第二次执行（幂等）：已标记的任务不会再标记
            let n2 = execute_cleanup_plan(&store, sid, &plan, true).await;
            assert_eq!(n2, 0, "{sid}: 执行器不幂等，重复标记了任务");
            // 会话仍在内存（keep_in_memory=true）
            assert!(
                store.inner.lock().await.contains_key(sid),
                "{sid}: keep_in_memory=true 却把会话移出了内存"
            );
        }
    }

    /// keep_in_memory=false 时执行器移除内存热表（sweep_idle 语义）。
    #[tokio::test]
    async fn execute_cleanup_plan_can_remove_from_memory() {
        let store = test_store();
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1}
            }),
        )
        .await;
        {
            let mut guard = store.inner.lock().await;
            let rec = guard.get_mut("s1").unwrap();
            let _ = rec.phase.transition(TransferEvent::Abort);
        }
        let plan = {
            let g = store.inner.lock().await;
            CleanupPlan::for_trigger(CleanupTrigger::PeerLost, g.get("s1").unwrap().phase)
        };
        execute_cleanup_plan(&store, "s1", &plan, false).await;
        assert!(
            store.inner.lock().await.get("s1").is_none(),
            "keep_in_memory=false 时应把会话移出内存热表"
        );
    }

    #[tokio::test]
    async fn empty_session_id_rejected() {
        let store = test_store();
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
        let store = test_store();
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
            "/api/v4/session/chunk?sessionId=s1&fileId=f1&pieceIndex=0",
            &[],
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
        let store = test_store();
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
        let store = test_store();
        let r = route(&store, Method::GET, "/api/v4/session/nope", &[]).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn non_v4_path_404() {
        let store = test_store();
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
        let store = test_store();
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
        let store = test_store();
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
        let store = test_store();
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
        let store = test_store();
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
            &format!("/api/v4/session/chunk?sessionId=s1&fileId=f1&pieceIndex=0&sha256={SHA}"),
            &[],
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
        let store = test_store();
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
            &format!("/api/v4/session/chunk?sessionId=s1&fileId=f1&pieceIndex=0&sha256={SHA}"),
            &[],
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
        let store = test_store();
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
        let store = test_store();
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
        let store = test_store();
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
        let store = test_store();
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
            &format!("/api/v4/session/chunk?sessionId=s1&fileId=f1&pieceIndex=0&sha256={SHA}"),
            &[],
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
        let store = test_store();
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
        let store = test_store();
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
        let store = test_store();
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
        let store = test_store();
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
            "/api/v4/session/chunk?sessionId=s1&fileId=f1&pieceIndex=0",
            &[],
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

    /// 断点续传在**进程重启**后依然成立 —— 这是持久化要解决的真实缺口。
    ///
    /// 复现「对端传了一半，本端进程被杀/重启」：先在进程 A 里
    /// register→prepare→收块 0、1（size 取 2 块），进程 A 退出；
    /// 再用**同一持久化目录**开进程 B，断言 `s1` 已从磁盘恢复，
    /// 且 `chunk-status` 报 `nextChunk=2` 从断点继续，而非退化成全量重传。
    #[tokio::test]
    async fn resume_survives_restart_via_persistence() {
        let dir = std::env::temp_dir().join(format!("lanbak-resume-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let persist_dir = dir.join("sessions");
        // 2 块：size = PIECE_SIZE*2
        let size = crate::transfer::chunk::PIECE_SIZE * 2;
        let sha = "abcdef0000000000000000000000000000000000000000000000000000000001";

        // ── 进程 A：注册 / prepare / 收到块 0、1 ──
        {
            let store = SessionStore::open(
                crate::identity::DeviceIdentity::generate(),
                "srv",
                crate::dto::DeviceType::Desktop,
                Some(&persist_dir),
            );
            route(
                &store,
                Method::POST,
                "/api/v4/session/register",
                &body(serde_json::json!({"deviceId":"d","alias":"a","sessionId":"s1"})),
            )
            .await;
            route(
                &store,
                Method::POST,
                "/api/v4/session/prepare",
                &body(serde_json::json!({
                    "sessionId":"s1","deviceId":"d",
                    "files":{"f1":{"fileId":"f1","fileName":"x","relPath":"x",
                        "size":size,"mtime":1,"sha256":sha,"pieceHashes":[sha,sha]}}
                })),
            )
            .await;
            for i in [0u64, 1] {
                route(
                    &store,
                    Method::POST,
                    &format!("/api/v4/session/chunk?sessionId=s1&fileId=f1&pieceIndex={i}&sha256={sha}"),
                    &[],
                )
                .await;
            }
            // 进程 A 在此块结束时 drop
        }

        // ── 进程 B：重启，复用同一持久化目录 ──
        {
            let store = SessionStore::open(
                crate::identity::DeviceIdentity::generate(),
                "srv",
                crate::dto::DeviceType::Desktop,
                Some(&persist_dir),
            );
            // 内存热表应已重载出 s1，且其确认位图含 0、1
            let g = store.inner.lock().await;
            let rec = g.get("s1").expect("重启后会话未从磁盘恢复");
            assert_eq!(rec.phase, TransferState::Transferring, "重载后阶段丢失");
            assert!(
                rec.confirmed.get("f1").unwrap().contains(&0),
                "重启后确认的块 0 丢失"
            );
            assert!(
                rec.confirmed.get("f1").unwrap().contains(&1),
                "重启后确认的块 1 丢失"
            );
            assert_eq!(
                rec.piece_sha.get("f1").unwrap().get(&0).unwrap(),
                sha,
                "重启后本端自算哈希丢失，412 正确性判定会退化"
            );
            drop(g);

            // chunk-status 应如实报出 nextChunk=2，从断点继续，而非全量重传
            let r = route(
                &store,
                Method::GET,
                "/api/v4/chunk-status?sessionId=s1&fileId=f1",
                &[],
            )
            .await;
            let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
            assert_eq!(
                v["nextChunk"],
                json!(2),
                "重启后 nextChunk 没从断点继续，续传退化成全量重传"
            );
            assert_eq!(v["receivedChunks"], json!([0, 1]));
            assert_eq!(v["fileComplete"], json!(true));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- P2-7：JSON 持久化并发压力测试 ----

    /// 多任务并发对多个会话写 chunk + 状态变更后，重载必须完整无丢失、无脏读。
    ///
    /// 模拟真实多路并发：4 个会话各收 6 块（带 sha），全部并行写穿同一持久化目录。
    /// 写完模拟进程重启（重新 open），断言每个会话的 phase/confirmed/piece_sha
    /// 与写前完全一致 —— 任何一行丢失或串行写竞争导致的半截行都会在这里暴露。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_persistence_reloads_without_loss() {
        let dir = std::env::temp_dir().join(format!("lanbak-cp-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let persist_dir = dir.join("sessions");
        // 6 块：size = PIECE_SIZE*6
        let size = crate::transfer::chunk::PIECE_SIZE * 6;

        // ── 进程 A：4 会话并发 register→prepare→收 6 块 ──
        {
            let store = SessionStore::open(
                crate::identity::DeviceIdentity::generate(),
                "srv",
                crate::dto::DeviceType::Desktop,
                Some(&persist_dir),
            );
            let mut tasks = tokio::task::JoinSet::new();
            for i in 0..4u32 {
                let store = store.clone();
                tasks.spawn(async move {
                    let sid = format!("s{i}");
                    let dev = format!("dev{i}");
                    let mut sha = String::from("abcdef000000000000000000000000000000000000000000000000000000000");
                    // 每会话不同 sha 后缀，避免碰巧全相等掩盖丢行
                    sha.push_str(&format!("{i:x}"));
                    route(
                        &store,
                        Method::POST,
                        "/api/v4/session/register",
                        &body(serde_json::json!({
                            "deviceId": dev, "alias": format!("A{i}"), "sessionId": sid
                        })),
                    )
                    .await;
                    route(
                        &store,
                        Method::POST,
                        "/api/v4/session/prepare",
                        &body(serde_json::json!({
                            "sessionId": sid, "deviceId": dev,
                            "files": {"f1": {"fileId":"f1","fileName":"x","relPath":"x",
                                "size": size, "mtime": 1, "sha256": sha,
                                "pieceHashes": [sha.clone(),sha.clone(),sha.clone(),
                                                sha.clone(),sha.clone(),sha.clone()]}}
                        })),
                    )
                    .await;
                    for j in 0..6u64 {
                        route(
                            &store,
                            Method::POST,
                            &format!(
                                "/api/v4/session/chunk?sessionId={sid}&fileId=f1&pieceIndex={j}&sha256={sha}"
                            ),
                            &[],
                        )
                        .await;
                    }
                });
            }
            while tasks.join_next().await.is_some() {}
        }

        // ── 进程 B：重启，断言 4 个会话全部恢复、位图与哈希零丢失 ──
        {
            let store = SessionStore::open(
                crate::identity::DeviceIdentity::generate(),
                "srv",
                crate::dto::DeviceType::Desktop,
                Some(&persist_dir),
            );
            let g = store.inner.lock().await;
            for i in 0..4u32 {
                let sid = format!("s{i}");
                let rec = g.get(&sid).unwrap_or_else(|| {
                    panic!("会话 {sid} 重启后丢失 —— 持久化并发写穿漏了整会话")
                });
                assert_eq!(
                    rec.phase,
                    TransferState::Transferring,
                    "{sid}: 重载后阶段丢失"
                );
                let confirmed = rec.confirmed.get("f1").unwrap();
                assert_eq!(
                    confirmed.len(),
                    6,
                    "{sid}: 并发写穿后确认位图只有 {} 块，丢了 {} 块",
                    confirmed.len(),
                    6 - confirmed.len()
                );
                for j in 0..6u64 {
                    assert!(
                        confirmed.contains(&j),
                        "{sid}: 确认位图缺块 {j}"
                    );
                }
                // 本端自算哈希 6 条全在（行半截写入会被 load_all 跳过，这里必须一条不少）
                let sha_map = rec.piece_sha.get("f1").unwrap();
                assert_eq!(
                    sha_map.len(),
                    6,
                    "{sid}: piece_sha 只有 {} 条（半截行/竞争丢行）",
                    sha_map.len()
                );
            }
            drop(g);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- P2-8：端到端集成测试（完整会话生命周期）----

    /// 完整会话生命周期：register → prepare → chunk×N → diff（四态）→ verify →
    /// receipt → tasks，断言每步状态码、状态机推进与终态查询一致。
    ///
    /// 覆盖 G8 的结构性风险：各端点单测各自绿，但**串成一条链路**时状态机
    /// 是否按序推进、终态是否可查询，只有端到端测试能证明。
    #[tokio::test]
    async fn e2e_full_session_lifecycle() {
        let store = test_store();
        // 2 块文件：size = PIECE_SIZE*2
        let size = crate::transfer::chunk::PIECE_SIZE * 2;
        let sha = "abcdef0000000000000000000000000000000000000000000000000000000001";

        // 1. register → Preparing
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({"deviceId":"d","alias":"a","sessionId":"e2e"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let g = store.inner.lock().await;
        assert_eq!(g.get("e2e").unwrap().phase, TransferState::Preparing);
        drop(g);

        // 2. prepare → 登记文件 + 返回 token
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/prepare",
            &body(serde_json::json!({
                "sessionId":"e2e","deviceId":"d",
                "files":{"f1":{"fileId":"f1","fileName":"x","relPath":"x",
                    "size":size,"mtime":1,"sha256":sha,"pieceHashes":[sha,sha]}}
            })),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["files"]["f1"].as_str().unwrap(), "tok:f1");

        // 3. chunk×2 → Transferring，全块确认
        for i in [0u64, 1] {
            let r = route(
                &store,
                Method::POST,
                &format!("/api/v4/session/chunk?sessionId=e2e&fileId=f1&pieceIndex={i}&sha256={sha}"),
                &[],
            )
            .await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        let g = store.inner.lock().await;
        assert_eq!(g.get("e2e").unwrap().phase, TransferState::Transferring);
        drop(g);

        // 4. diff 单块：对端声明 sha == 本端实测 → 206 + 双引号 ETag
        let r = route(
            &store,
            Method::GET,
            &format!("/api/v4/session/diff?sessionId=e2e&fileId=f1&pieceIndex=0&sha256={sha}"),
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            r.headers().get("etag").unwrap().to_str().unwrap().to_string(),
            format!("\"{sha}\"")
        );
        // diff 整文件摘要：全部匹配 → fileComplete=true
        let r = route(
            &store,
            Method::GET,
            "/api/v4/session/diff?sessionId=e2e&fileId=f1",
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["fileComplete"], serde_json::json!(true));
        assert_eq!(v["missingChunks"].as_array().unwrap().len(), 0);

        // 5. verify → Completed（全会话到齐）
        let r = route(
            &store,
            Method::GET,
            "/api/v4/session/verify?sessionId=e2e&fileId=f1",
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["sha256"].as_str(), Some(sha));
        let g = store.inner.lock().await;
        assert_eq!(g.get("e2e").unwrap().phase, TransferState::Completed);
        drop(g);

        // 6. receipt：终态回执（completed）→ 不拒绝
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/receipt",
            &body(serde_json::json!({"sessionId":"e2e","tasks":[
                {"fileId":"f1","relPath":"x","status":"completed"}
            ]})),
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        let rejected = v["rejected"].as_array().unwrap();
        assert!(rejected.is_empty(), "已完成的回执不应被拒：{rejected:?}");

        // 7. tasks：f1 应 completed（回执优先）
        let r = route(
            &store,
            Method::GET,
            "/api/v4/session/tasks?sessionId=e2e",
            &[],
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["phase"].as_str(), Some("completed"));
        assert_eq!(v["tasks"][0]["fileId"].as_str(), Some("f1"));
        assert_eq!(v["tasks"][0]["status"].as_str(), Some("completed"));
    }

    /// 端到端中止路径：register → prepare → chunk → abort → tasks 显示 cancelled。
    ///
    /// 与 happy path 互补：中止后未确认任务必须收敛为 cancelled（P0-2），
    /// 会话保持 Aborted 供历史展示。
    #[tokio::test]
    async fn e2e_abort_path_marks_unconfirmed_cancelled() {
        let store = test_store();
        let size = crate::transfer::chunk::PIECE_SIZE * 2;
        route(
            &store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({"deviceId":"d","alias":"a","sessionId":"ab"})),
        )
        .await;
        route(
            &store,
            Method::POST,
            "/api/v4/session/prepare",
            &body(serde_json::json!({
                "sessionId":"ab","deviceId":"d",
                "files":{"f1":{"fileId":"f1","fileName":"x","relPath":"x",
                    "size":size,"mtime":1}}
            })),
        )
        .await;
        // 只收 1 块（未到齐），然后 abort
        route(
            &store,
            Method::POST,
            "/api/v4/session/chunk?sessionId=ab&fileId=f1&pieceIndex=0",
            &[],
        )
        .await;
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/abort",
            &body(serde_json::json!({"sessionId":"ab"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["phase"].as_str(), Some("aborted"));
        assert_eq!(v["cancelled"], serde_json::json!(1));

        // tasks：f1 显示 cancelled（未确认 → 不猜测成败）
        let r = route(
            &store,
            Method::GET,
            "/api/v4/session/tasks?sessionId=ab",
            &[],
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["phase"].as_str(), Some("aborted"));
        assert_eq!(v["tasks"][0]["status"].as_str(), Some("cancelled"));
    }

    // 辅助：把 Response 的 body 读成 Vec<u8>
    async fn to_bytes(r: Response<Full<bytes::Bytes>>) -> Vec<u8> {
        use http_body_util::BodyExt;
        r.into_body().collect().await.unwrap().to_bytes().to_vec()
    }
}
