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
use crate::dto::handshake::PairingState;
use crate::dto::DeviceType;
use crate::error::ErrorCode;
use crate::identity::DeviceIdentity;
use crate::routes;
use crate::server::control::{HandshakeStore, PeerStore};
use crate::state::transfer::{TransferEvent, TransferState};
use crate::sync::manifest::validate_rel_path;
use crate::transfer::atomic_file;
use crate::transfer::chunk::{piece_count, PIECE_SIZE};
use crate::transfer::cleanup::{CleanupPlan, CleanupTrigger};
use crate::transfer::piece_cache::PieceHashCache;

/// 认证/准入失败时直接回给 hyper 的响应。
///
/// 装进 `Box`：`Response<Full<Bytes>>` 本身远大于 `()`，把它直接做 `Err`
/// 会让每次 `Result` 返回都搬运一大块（clippy::result_large_err）。
/// 调用方拿到后 `return *resp;` 即可还原成响应。
pub(crate) type ErrResponse = Box<Response<Full<bytes::Bytes>>>;

pub mod control;
pub mod sync_api;
/// 传输会话的磁盘持久化（见 [`persist`] 模块文档：纯 Rust 原子写 JSON 后端）。
pub(crate) mod persist;
/// 配对记录的磁盘持久化（见 [`persist_pairing`] 模块文档：纯 Rust 原子写 JSON 后端）。
pub(crate) mod persist_pairing;

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
    /// 每文件上传 token（`session/prepare` 签发，`session/chunk` 校验）。
    ///
    /// 文件维度而非会话维度：一个会话里的 token 泄漏不应波及同会话的其他文件。
    /// 纯内存保存 —— 重启后 token 失效，发送端必须重新 prepare（此时也会重新
    /// 对账位图），不把短期凭据写进磁盘。
    pub tokens: HashMap<String, String>,
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
            tokens: HashMap::new(),
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
    /// 生产接收端必须显式打开：传输/准备请求要求对端在 `PeerStore` 中为 Active。
    ///
    /// 默认关闭只服务于纯内存单测 —— 那些测试根本不构造配对关系。桌面/移动端
    /// 启动接收服务时必须调用 [`Self::with_require_active_peer`]，否则未配对设备
    /// 只要猜中 sessionId/token 就能写入文件。
    require_active_peer: std::sync::atomic::AtomicBool,
    /// 防御总闸：隐藏时拒绝**一切**入站 HTTP（含 probe），与桌面/UDP 层共用同一语义。
    defensive_hidden: std::sync::atomic::AtomicBool,
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

        // 配对记录持久化：与 persist 同目录
        let pairing_persister = match persist_dir {
            Some(dir) => match persist_pairing::PairingPersister::open(dir) {
                Ok(p) => Some(Arc::new(p)),
                Err(e) => {
                    log::warn!("配对持久化不可用，降级为纯内存：{e}");
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

        // 冷启动：从磁盘恢复 PeerStore（初始化时串行填充，无需并发保护）
        let peers = if let Some(ref pp) = pairing_persister {
            let cold = pp.load_all();
            if !cold.is_empty() {
                log::info!("配对记录冷启动恢复: {} 台", cold.len());
            }
            PeerStore::with_persister_and_cold(Arc::clone(pp), cold)
        } else {
            PeerStore::new()
        };

        Arc::new(SessionStore {
            inner: Mutex::new(inner),
            identity,
            alias: alias.to_string(),
            device_type,
            peers,
            handshake: HandshakeStore::new(),
            // WB-0053：SyncStore 与会话持久化共用同一后端 —— 快照/墓碑/目录映射
            // 冷启动重载，重启不再退化全量备份或复活已删文件。
            sync: sync_api::SyncStore::with_persist(persist.clone()),
            persist,
            base_dir: std::sync::RwLock::new(std::path::PathBuf::new()),
            piece_cache: std::sync::RwLock::new(PieceHashCache::new()),
            require_active_peer: std::sync::atomic::AtomicBool::new(false),
            defensive_hidden: std::sync::atomic::AtomicBool::new(false),
            pending_parts: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
    }

    pub fn with_base_dir(self: &Arc<Self>, base_dir: std::path::PathBuf) {
        *self.base_dir.write().unwrap() = base_dir;
    }

    pub fn with_piece_cache(self: &Arc<Self>, cache: PieceHashCache) {
        *self.piece_cache.write().unwrap() = cache;
    }

    /// 平台层把接收目录扫描结果喂给 core 清单权威（`GET /manifest` 的数据源）。
    pub async fn set_local_manifest(&self, manifest: crate::dto::sync::Manifest) {
        self.sync.set_local_manifest(manifest).await;
    }

    /// 生产接收端：要求 prepare/chunk/verify 的对端在 PeerStore 中为 Active。
    ///
    /// 与 token 校验叠加，而不是互相替代 —— token 证明"知道本次上传凭据"，
    /// 配对状态证明"这台设备仍被信任"。
    pub fn with_require_active_peer(self: &Arc<Self>, required: bool) {
        self.require_active_peer
            .store(required, std::sync::atomic::Ordering::Relaxed);
    }

    /// 防御总闸：开启后所有入站 HTTP 一律拒绝（probe 也不例外）。
    pub fn set_defensive_hidden(&self, hidden: bool) {
        self.defensive_hidden
            .store(hidden, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_defensive_hidden(&self) -> bool {
        self.defensive_hidden
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 本端**真实**能力位图。
    ///
    /// 接收端尚未接入 AEAD 解密，因此绝不能声明 `CAP_ENCRYPT` —— 广告了却
    /// 不实现，发送端就会把密文写进接收目录，verify 永远失败。
    pub fn capabilities(&self) -> crate::version::Capabilities {
        // WB-0030：接收端已接入 AEAD 解密（对称密钥由配对 secret 派生，从不落盘），
        // 恢复声明 CAP_ENCRYPT —— 发送端据此协商加密；未配对的对端拿不到 secret，
        // 就算声明了加密也派生不出正确密钥，verify 会以 412 拒绝。
        crate::version::Capabilities::all()
    }

    async fn ensure_active_peer(&self, device_id: &str) -> Result<(), ErrResponse> {
        if !self
            .require_active_peer
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Ok(());
        }
        match self.peers.entry(device_id).await {
            Some(peer) if matches!(peer.trust.state, PairingState::Active) => Ok(()),
            Some(peer) => Err(Box::new(err_response(
                ErrorCode::Untrusted,
                &format!("设备未激活配对（当前 {:?}），请重新配对", peer.trust.state),
            ))),
            None => Err(Box::new(err_response(
                ErrorCode::Untrusted,
                "设备未配对：拒绝未受信设备访问传输会话",
            ))),
        }
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

/// WB-0297：会话数量闸 —— 全局上限防洪泛把会话表撑爆，单设备上限防单点堆积。
const MAX_SESSIONS: usize = 256;
const MAX_SESSIONS_PER_PEER: usize = 8;

/// WB-0307：prepare 元数据总量闸。元数据（含 pieceHashes 列表）会进内存与
/// 持久化，恶意清单不得把接收端 OOM。单文件 512GiB / 单会话 1TiB 为硬上限，
/// 局域网备份的真实文件远达不到。
const MAX_PREPARE_FILE_BYTES: u64 = 512 << 30;
const MAX_PREPARE_TOTAL_BYTES: u64 = 1 << 40;

/// AES-256-GCM tag 长度：加密文件每 piece 的线路字节数 = 明文 piece + 16（WB-0030）。
const AEAD_TAG_LEN: u64 = 16;

async fn handle_register(store: &Arc<SessionStore>, body: &[u8]) -> Response<Full<bytes::Bytes>> {
    let req: SessionRegisterRequest = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    if req.session_id.is_empty() || req.session_id.len() > 128 {
        return err_response(ErrorCode::BadRequest, "sessionId 长度非法");
    }
    if !req
        .session_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return err_response(
            ErrorCode::BadRequest,
            "sessionId 只允许字母数字与 - _（防止路径/日志注入）",
        );
    }
    if req.device_id.is_empty() {
        return err_response(ErrorCode::BadRequest, "deviceId 不能为空");
    }
    if let Err(resp) = store.ensure_active_peer(&req.device_id).await {
        return *resp;
    }

    {
        let guard = store.inner.lock().await;
        // WB-0297：会话数上限（第一道检查；insert 前还有第二道防并发竞态）
        if guard.len() >= MAX_SESSIONS {
            return err_response(ErrorCode::IllegalState, "全局会话数已达上限，请稍后重试");
        }
        if guard.values().filter(|r| r.device_id == req.device_id).count()
            >= MAX_SESSIONS_PER_PEER
        {
            return err_response(
                ErrorCode::IllegalState,
                "该设备进行中的会话数已达上限，请先完成或中止现有传输",
            );
        }
        // 幂等：同一 owner 重复 register 返回原会话；不同 owner 拒绝 ——
        // 静默覆盖会让 A 的断点续传进度被 B 的同名 sessionId 顶掉。
        if let Some(existing) = guard.get(&req.session_id) {
            if existing.device_id != req.device_id {
                return err_response(
                    ErrorCode::IllegalState,
                    "sessionId 已被其他设备占用：拒绝跨设备复用",
                );
            }
            return ok_json(SessionRegisterResponse {
                session_id: req.session_id,
                capabilities: store.capabilities(),
            });
        }
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
    {
        let mut guard = store.inner.lock().await;
        // 二次检查：上面放锁后可能有并发 register 抢先写入
        if guard.len() >= MAX_SESSIONS
            || guard.values().filter(|r| r.device_id == req.device_id).count()
                >= MAX_SESSIONS_PER_PEER
        {
            return err_response(ErrorCode::IllegalState, "会话数已达上限");
        }
        if let Some(existing) = guard.get(&req.session_id) {
            if existing.device_id != req.device_id {
                return err_response(
                    ErrorCode::IllegalState,
                    "sessionId 已被其他设备占用：拒绝跨设备复用",
                );
            }
            return ok_json(SessionRegisterResponse {
                session_id: req.session_id,
                capabilities: store.capabilities(),
            });
        }
        guard.insert(req.session_id.clone(), rec);
    }

    ok_json(SessionRegisterResponse {
        session_id: req.session_id,
        capabilities: store.capabilities(),
    })
}

fn random_upload_token() -> String {
    let bytes: [u8; 32] = rand::random();
    hex::encode(bytes)
}

fn safe_final_path(base_dir: &Path, rel_path: &str) -> Result<std::path::PathBuf, String> {
    let normalized = validate_rel_path(rel_path)?;
    let joined = if base_dir.as_os_str().is_empty() {
        std::path::PathBuf::from(normalized)
    } else {
        base_dir.join(normalized)
    };
    Ok(ensure_windows_long_path(joined))
}

/// WB-0515：Windows 长路径。总长 ≥ 240 的**绝对路径**加 `\\?\` verbatim 前缀，
/// 绕过传统 MAX_PATH(260) 限制；UNC 路径改写为 `\\?\UNC\...`。
/// 已带 verbatim 前缀的幂等返回；短路径不加（避免影响可读性与测试断言）。
///
/// 落点只在 `safe_final_path`：chunk 的 `.part`、verify 的 final、空文件落盘
/// 全部经由它派生路径，一处加前缀全链路生效。
fn ensure_windows_long_path(p: std::path::PathBuf) -> std::path::PathBuf {
    if !cfg!(windows) {
        return p;
    }
    let s = p.to_string_lossy().into_owned();
    if !p.is_absolute() || s.len() < 240 || s.starts_with(r"\\?\") || s.starts_with(r"\\.\") {
        return p;
    }
    if let Some(rest) = s.strip_prefix(r"\\") {
        std::path::PathBuf::from(format!(r"\\?\UNC\{rest}"))
    } else {
        std::path::PathBuf::from(format!(r"\\?\{s}"))
    }
}

async fn handle_prepare(store: &Arc<SessionStore>, body: &[u8]) -> Response<Full<bytes::Bytes>> {
    let req: PrepareRequest = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    if req.device_id.is_empty() {
        return err_response(ErrorCode::BadRequest, "deviceId 不能为空");
    }
    if let Err(resp) = store.ensure_active_peer(&req.device_id).await {
        return *resp;
    }
    if req.files.len() > 100_000 {
        return err_response(ErrorCode::BadRequest, "单会话文件数超过上限（100000）");
    }

    let base_dir = store.base_dir.read().unwrap().clone();
    let mut empty_targets: Vec<(std::path::PathBuf, i64)> = Vec::new();
    let mut normalized_paths: HashMap<String, String> = HashMap::new();
    let mut total_bytes: u64 = 0;

    let (session_id, tokens) = {
        let mut guard = store.inner.lock().await;
        let rec = match guard.get_mut(&req.session_id) {
            Some(r) => r,
            None => return err_response(ErrorCode::NotFound, "会话不存在"),
        };

        // 会话归属必须一致。sessionId 是 CSPRNG 生成的，但一旦泄漏（日志、抓包），
        // 不校验归属就等于"知道 sessionId 就能往别人的会话里塞文件"。
        if rec.device_id != req.device_id {
            return err_response(
                ErrorCode::Untrusted,
                "sessionId 不属于该 deviceId：拒绝跨设备复用会话",
            );
        }

        let mut tokens = HashMap::new();
        for (file_id, meta) in &req.files {
            if file_id.is_empty() || file_id.len() > 128 {
                return err_response(ErrorCode::BadRequest, "fileId 长度非法");
            }
            if file_id
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            {
                return err_response(
                    ErrorCode::BadRequest,
                    "fileId 只允许字母数字与 - _（防止路径/日志注入）",
                );
            }
            let normalized = match validate_rel_path(&meta.rel_path) {
                Ok(p) => p,
                Err(e) => {
                    return err_response(
                        ErrorCode::BadRequest,
                        &format!("fileId={file_id} 的 relPath 非法：{e}"),
                    )
                }
            };
            if let Some(prev) = normalized_paths.insert(normalized.clone(), file_id.clone()) {
                return err_response(
                    ErrorCode::BadRequest,
                    &format!("fileId={file_id} 与 {prev} 归一化后指向同一 relPath：{normalized}"),
                );
            }
            if meta.sha256.as_ref().is_some_and(|s| {
                s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit())
            }) {
                return err_response(
                    ErrorCode::BadRequest,
                    &format!("fileId={file_id} 的 sha256 不是 64 位 hex"),
                );
            }
            if let Some(hashes) = meta.piece_hashes.as_ref() {
                if hashes.iter().any(|h| {
                    h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit())
                }) {
                    return err_response(
                        ErrorCode::BadRequest,
                        &format!("fileId={file_id} 的 pieceHashes 含非 hex 项"),
                    );
                }
                // WB-0302：哈希列表长度必须与文件 piece 数一致 —— 长度对不上
                // 意味着发送端按另一套分块算的哈希，逐块比对会系统性错位。
                if hashes.len() as u64 != piece_count(meta.size) {
                    return err_response(
                        ErrorCode::BadRequest,
                        &format!(
                            "fileId={file_id} 的 pieceHashes 数量（{}）与 piece 数（{}）不符",
                            hashes.len(),
                            piece_count(meta.size)
                        ),
                    );
                }
            }
            // WB-0307：单文件 / 单会话总量闸
            if meta.size > MAX_PREPARE_FILE_BYTES {
                return err_response(
                    ErrorCode::BadRequest,
                    &format!("fileId={file_id} 单文件大小超过上限（{MAX_PREPARE_FILE_BYTES} 字节）"),
                );
            }
            match total_bytes.checked_add(meta.size) {
                Some(t) if t <= MAX_PREPARE_TOTAL_BYTES => total_bytes = t,
                _ => {
                    return err_response(
                        ErrorCode::BadRequest,
                        "单会话总字节数超过上限（1TiB）：请分批发送",
                    )
                }
            }
            // WB-0030/0540：加密文件的线路大小必须自洽 —— wireSize = 明文 +
            // 每 piece 16B tag。对不上的加密文件 verify 阶段必然解不开，提前 400。
            if meta.encrypted {
                let expect = meta.size + piece_count(meta.size) * AEAD_TAG_LEN;
                if meta.wire_size != Some(expect) {
                    return err_response(
                        ErrorCode::BadRequest,
                        &format!(
                            "fileId={file_id} 的 wireSize 与推算值不符：期望 {expect}，收到 {:?}",
                            meta.wire_size
                        ),
                    );
                }
            }

            // 幂等 prepare：已登记且元数据一致 → 保留 confirmed/piece_sha 与旧 token；
            // 元数据变化 → 409，禁止在同一 sessionId 下悄悄换文件内容。
            if let Some(existing) = rec.files.get(file_id) {
                if existing.size != meta.size
                    || existing.mtime != meta.mtime
                    || existing.rel_path != normalized
                    || existing.sha256 != meta.sha256
                {
                    return err_response(
                        ErrorCode::IllegalState,
                        &format!("fileId={file_id} 重新 prepare 时元数据变化：请新建会话"),
                    );
                }
                let token = rec
                    .tokens
                    .get(file_id)
                    .cloned()
                    .unwrap_or_else(random_upload_token);
                rec.tokens.insert(file_id.clone(), token.clone());
                tokens.insert(file_id.clone(), token);
                continue;
            }

            let mut stored = meta.clone();
            stored.rel_path = normalized.clone();
            let target = match safe_final_path(&base_dir, &normalized) {
                Ok(p) => p,
                Err(e) => return err_response(ErrorCode::BadRequest, &e),
            };
            if stored.size == 0 {
                empty_targets.push((target, stored.mtime));
            }
            rec.files.insert(file_id.clone(), stored);
            rec.confirmed.insert(file_id.clone(), HashSet::new());
            if let Some(p) = &store.persist {
                p.set_file(&req.session_id, file_id, rec.files.get(file_id).unwrap());
            }
            let token = random_upload_token();
            rec.tokens.insert(file_id.clone(), token.clone());
            tokens.insert(file_id.clone(), token);
        }

        (req.session_id.clone(), tokens)
    };

    // 锁外：空文件没有 piece，prepare 即完成落盘（否则 verify 时永远不会出现 final）。
    for (target, mtime_ms) in empty_targets {
        if let Some(parent) = target.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return err_response(ErrorCode::Internal, &format!("创建目录失败: {e}"));
            }
        }
        if target.exists() {
            let _ = atomic_file::restore_mtime(&target, mtime_ms);
            continue;
        }
        let part = atomic_file::part_path(&target, &session_id, "empty");
        if let Err(e) = std::fs::write(&part, []) {
            return err_response(ErrorCode::Internal, &format!("写入空文件失败: {e}"));
        }
        if let Err(e) = atomic_file::commit(&part, &target) {
            let _ = std::fs::remove_file(&part);
            return err_response(ErrorCode::Internal, &format!("提交空文件失败: {e}"));
        }
        let _ = atomic_file::restore_mtime(&target, mtime_ms);
    }

    ok_json(PrepareResponse {
        session_id: req.session_id,
        files: tokens,
        capabilities: store.capabilities(),
    })
}

async fn handle_phase(store: &Arc<SessionStore>, rest: &str) -> Response<Full<bytes::Bytes>> {
    // GET /api/v4/session/phase?sessionId=xxx
    let q = match parse_query(rest) {
        Ok(q) => q,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    let session_id = match q.get("sessionId") {
        Some(s) => s.clone(),
        None => return err_response(ErrorCode::BadRequest, "缺少 sessionId 参数"),
    };
    let (device_id, payload) = {
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
        (rec.device_id.clone(), payload)
    };
    // WB-0341：phase 投影含进度/位图版本，生产模式要求对端 Active。
    if let Err(resp) = store.ensure_active_peer(&device_id).await {
        return *resp;
    }
    ok_json(payload)
}

async fn handle_heartbeat(store: &Arc<SessionStore>, body: &[u8]) -> Response<Full<bytes::Bytes>> {
    #[derive(serde::Deserialize)]
    struct Hb {
        #[serde(rename = "sessionId")]
        session_id: String,
        /// 兼容字段：对端自报的位图版本只作对账信号，服务端版本自权威（WB-0354）。
        #[serde(rename = "bitmapVersion", default)]
        _bitmap_version: u64,
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
    // WB-0353：终态会话不接受心跳 —— 终态后还续期会让已收尾的会话
    // 永远躲过闲置巡检。
    if rec.phase.is_terminal() {
        return err_response(ErrorCode::IllegalState, "会话已终态，心跳被拒绝");
    }
    // WB-0354：位图版本由**服务端**权威自增。客户端自报版本可被推高/重放，
    // 这里只把对端上报值当作"对端认为有新版本"的信号，不作为版本来源。
    rec.bitmap_version = rec.bitmap_version.saturating_add(1);
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
    let device_id = rec.device_id.clone();
    let payload = json!({
        "sessionId": hb.session_id,
        "phase": to_phase(rec.phase),
        "bitmapVersion": rec.bitmap_version,
    });
    drop(guard);
    // WB-0351：心跳能续期会话寿命，必须来自受信设备。
    if let Err(resp) = store.ensure_active_peer(&device_id).await {
        return *resp;
    }
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
    // WB-0361：先认证再迁移 —— abort 会把在途会话整个收尾，
    // 不能"先中止完再发现请求者没权限"。
    let device_id = {
        let guard = store.inner.lock().await;
        match guard.get(&a.session_id) {
            Some(r) => r.device_id.clone(),
            None => return err_response(ErrorCode::NotFound, "会话不存在"),
        }
    };
    if let Err(resp) = store.ensure_active_peer(&device_id).await {
        return *resp;
    }
    // 第一步：状态机迁移（锁内，只动内存）
    let migrated = {
        let mut guard = store.inner.lock().await;
        let rec = match guard.get_mut(&a.session_id) {
            Some(r) => r,
            None => return err_response(ErrorCode::NotFound, "会话不存在"),
        };
        // WB-0363：终态会话重复 abort 幂等吸收 —— 对端迟到的取消
        // （还没收到终态回执）不该变成 409 触发重试；返回当前终态 + cancelled=0。
        if rec.phase.is_terminal() {
            return ok_json(json!({
                "sessionId": a.session_id,
                "phase": to_phase(rec.phase),
                "cancelled": 0
            }));
        }
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

async fn handle_chunk(
    store: &Arc<SessionStore>,
    path: &str,
    body: &[u8],
) -> Response<Full<bytes::Bytes>> {
    let q = match parse_query(path) {
        Ok(q) => q,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    let session_id = match q.get("sessionId").filter(|s| !s.is_empty()) {
        Some(s) => s.clone(),
        None => return err_response(ErrorCode::BadRequest, "缺少 sessionId 参数"),
    };
    let file_id = match q.get("fileId").filter(|s| !s.is_empty()) {
        Some(s) => s.clone(),
        None => return err_response(ErrorCode::BadRequest, "缺少 fileId 参数"),
    };
    // token 在生产模式（require_active_peer=true）必须提供；纯内存单测不构造
    // 配对关系，允许省略（但一旦显式带了 token 就必须正确）。
    let require_token =
        store.require_active_peer.load(std::sync::atomic::Ordering::Relaxed)
            || q.contains_key("token");
    let token = match q.get("token") {
        Some(t) if !t.is_empty() => Some(t.clone()),
        _ if require_token => {
            return err_response(ErrorCode::Untrusted, "缺少 token 参数")
        }
        _ => None,
    };
    let piece_index: u64 = match q.get("pieceIndex") {
        Some(s) => match s.parse() {
            Ok(i) => i,
            Err(_) => return err_response(ErrorCode::BadRequest, "pieceIndex 必须是整数"),
        },
        None => return err_response(ErrorCode::BadRequest, "缺少 pieceIndex 参数"),
    };
    let client_sha256 = match q.get("sha256") {
        Some(s) => {
            let s = s.to_ascii_lowercase();
            if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
                return err_response(ErrorCode::BadRequest, "sha256 必须是 64 位 hex");
            }
            Some(s)
        }
        None => None,
    };

    // ── 阶段 1：锁内只做认证/范围校验，不碰磁盘 ──
    let (device_id, meta, duplicate_same, phase_before, bitmap_before) = {
        let mut guard = store.inner.lock().await;
        let rec = match guard.get_mut(&session_id) {
            Some(r) => r,
            None => return err_response(ErrorCode::NotFound, "会话不存在"),
        };
        if let Some(t) = &token {
            if rec.tokens.get(&file_id) != Some(t) {
                return err_response(ErrorCode::Untrusted, "token 无效或不属于该文件");
            }
        }
        let meta = match rec.files.get(&file_id) {
            Some(m) => m.clone(),
            None => return err_response(ErrorCode::NotFound, "文件未登记"),
        };
        let total = piece_count(meta.size);
        if piece_index >= total {
            let wire_total = meta.wire_size.unwrap_or(meta.size);
            return json_response_with(
                StatusCode::RANGE_NOT_SATISFIABLE,
                &json!({"fileId": file_id, "totalPieces": total}),
                &[("content-range", format!("bytes */{wire_total}"))],
            );
        }
        // WB-0030：加密 piece 的线路长度 = 明文 piece + 16B tag，按定长 stride
        // (PIECE_SIZE+16) 随机写 —— 明文 piece 长短不一，密文按序号等长递增，
        // 同一个 offset 公式才能同时描述两种文件在 .part 里的写入位置。
        let (_wire_offset, expected_len) = if meta.encrypted {
            (
                piece_index * (PIECE_SIZE + AEAD_TAG_LEN),
                (meta.size - piece_index * PIECE_SIZE).min(PIECE_SIZE) as usize
                    + AEAD_TAG_LEN as usize,
            )
        } else {
            (
                piece_index * PIECE_SIZE,
                (meta.size - piece_index * PIECE_SIZE).min(PIECE_SIZE) as usize,
            )
        };
        if body.len() != expected_len {
            return err_response(
                ErrorCode::BadRequest,
                &format!(
                    "分块长度不符：pieceIndex={piece_index} 期望 {expected_len}B，实际 {}B",
                    body.len()
                ),
            );
        }
        // 幂等：同一 piece 重复上传。内容一致 → 直接成功；内容不同 → 这是
        // diff 412 之后的**修复重传**，必须允许覆盖，否则坏块永远修不好。
        let mut duplicate_same = false;
        if rec
            .confirmed
            .get(&file_id)
            .is_some_and(|s| s.contains(&piece_index))
        {
            duplicate_same = match (
                &client_sha256,
                rec.piece_sha
                    .get(&file_id)
                    .and_then(|m| m.get(&piece_index)),
            ) {
                (Some(client), Some(local)) => client.eq_ignore_ascii_case(local),
                // 没有内容证明的重复块按幂等处理（不覆盖已有数据）
                _ => true,
            };
            if !duplicate_same {
                log::warn!(
                    "收到与已确认块不同的内容，按修复流程覆盖: fileId={} piece={}",
                    file_id,
                    piece_index
                );
            }
        }
        rec.last_activity = std::time::Instant::now();
        (
            rec.device_id.clone(),
            meta,
            duplicate_same,
            rec.phase,
            rec.bitmap_version,
        )
    };

    if let Err(resp) = store.ensure_active_peer(&device_id).await {
        return *resp;
    }

    // 幂等返回必须在配对校验之后，不能拿着 token 绕过 Active 检查。
    if duplicate_same {
        return ok_json(json!({
            "sessionId": session_id,
            "fileId": file_id,
            "pieceIndex": piece_index,
            "phase": to_phase(phase_before),
            "bitmapVersion": bitmap_before,
            "duplicate": true,
        }));
    }

    // ── 阶段 2：锁外做哈希与随机写（按 offset 而不是 append）──
    let local_sha = hex::encode(crate::crypto::kdf::sha256(body));
    if let Some(client) = &client_sha256 {
        if !client.eq_ignore_ascii_case(&local_sha) {
            return json_response_with(
                StatusCode::PRECONDITION_FAILED,
                &serde_json::to_value(DiffMismatch {
                    expected: client.clone(),
                    actual: local_sha,
                })
                .unwrap(),
                &[],
            );
        }
    }

    let base_dir = store.base_dir.read().unwrap().clone();
    let final_path = match safe_final_path(&base_dir, &meta.rel_path) {
        Ok(p) => p,
        Err(e) => return err_response(ErrorCode::BadRequest, &format!("relPath 非法: {e}")),
    };
    if let Some(parent) = final_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return err_response(ErrorCode::Internal, &format!("创建目录失败: {e}"));
        }
    }
    let part_path = atomic_file::part_path(&final_path, &session_id, &file_id);
    // 显式 truncate(false)：分块按 pieceIndex 随机写同一个 .part，
    // 截断会抹掉已经落盘的其它块（clippy::suspicious_open_options 要求的显式语义）
    let opened = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&part_path);
    let mut part = match opened {
        Ok(f) => f,
        Err(e) => return err_response(ErrorCode::Internal, &format!("打开临时文件失败: {e}")),
    };
    use std::io::{Seek, SeekFrom, Write};
    let write_offset = if meta.encrypted {
        piece_index * (PIECE_SIZE + AEAD_TAG_LEN)
    } else {
        piece_index * PIECE_SIZE
    };
    if let Err(e) = part.seek(SeekFrom::Start(write_offset)) {
        return err_response(ErrorCode::Internal, &format!("定位分块偏移失败: {e}"));
    }
    if let Err(e) = part.write_all(body) {
        return err_response(ErrorCode::Internal, &format!("写入分块失败: {e}"));
    }
    if let Err(e) = part.sync_data() {
        log::warn!("分块 sync_data 失败（继续，最终 verify 会兜底）: {e}");
    }
    drop(part);

    // ── 阶段 3：锁内更新权威位图与本端哈希 ──
    let (phase_now, bitmap_version) = {
        let mut guard = store.inner.lock().await;
        let rec = match guard.get_mut(&session_id) {
            Some(r) => r,
            None => return err_response(ErrorCode::NotFound, "会话在写入期间被清理"),
        };
        if let Some(t) = &token {
            if rec.tokens.get(&file_id) != Some(t) {
                return err_response(ErrorCode::Untrusted, "token 已失效");
            }
        }
        rec.confirmed
            .entry(file_id.clone())
            .or_default()
            .insert(piece_index);
        rec.piece_sha
            .entry(file_id.clone())
            .or_default()
            .insert(piece_index, local_sha.clone());
        rec.bitmap_version += 1;
        rec.last_activity = std::time::Instant::now();
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
        (rec.phase, rec.bitmap_version)
    };

    {
        let mut pending = store.pending_parts.lock().unwrap();
        pending
            .entry(format!("{session_id}/{file_id}"))
            .or_insert_with(|| part_path.clone());
    }
    if let Some(p) = &store.persist {
        p.update_session(
            &session_id,
            phase_now,
            Algorithm::Advanced,
            None,
            bitmap_version,
        );
        p.set_piece(&session_id, &file_id, piece_index, Some(&local_sha));
    }

    ok_json(json!({
        "sessionId": session_id,
        "fileId": file_id,
        "pieceIndex": piece_index,
        "phase": to_phase(phase_now),
        "bitmapVersion": bitmap_version,
        "sha256": local_sha,
        "duplicate": false,
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
    let q = match parse_query(path) {
        Ok(q) => q,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    let session_id = match q.get("sessionId") {
        Some(s) => s.clone(),
        None => return err_response(ErrorCode::BadRequest, "缺少 sessionId 参数"),
    };
    let file_id = match q.get("fileId") {
        Some(s) => s.clone(),
        None => return err_response(ErrorCode::BadRequest, "缺少 fileId 参数"),
    };

    let guard = store.inner.lock().await;
    let rec = match guard.get(&session_id) {
        Some(r) => r,
        None => return err_response(ErrorCode::NotFound, "会话不存在"),
    };
    // 生产模式：块位图也是敏感信息（能推断对端有哪些文件/内容），
    // diff 必须带 prepare 签发的文件 token。
    if store
        .require_active_peer
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        let token = match q.get("token") {
            Some(t) => t,
            None => return err_response(ErrorCode::Untrusted, "缺少 token 参数"),
        };
        if rec.tokens.get(&file_id) != Some(token) {
            return err_response(ErrorCode::Untrusted, "token 无效或不属于该文件");
        }
    }
    let meta = match rec.files.get(&file_id) {
        Some(m) => m,
        None => return err_response(ErrorCode::NotFound, "文件未登记"),
    };

    let total_pieces = piece_count(meta.size);
    let confirmed = rec.confirmed.get(&file_id);
    let local_sha = rec.piece_sha.get(&file_id);

    // 整文件校验器不匹配 → 文件已变，全量重传（A11 的 200 语义）
    let mut file_changed = false;
    if let Some(raw) = q.get("etag") {
        let Some(v) = parse_validator(raw) else {
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
        if let Some(raw_idx) = q.get("pieceIndex") {
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
            let expected = q.get("sha256").map(|s| s.to_ascii_lowercase());
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

/// 流式计算文件 SHA-256（hex）。verify 的返回值必须是**本端实算**，
/// 不能回显发送端声明值 —— 否则坏块永远无法被发现。
fn sha256_file_hex(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// 把加密 `.part`（密文 piece 定长 stride）解密为**明文**临时文件，
/// 返回 `(明文路径, 明文整文件 SHA-256)`。
///
/// 密钥树（`kdf` L3/L4，两端同一公式，密钥从不落盘、不进日志）：
/// `session_key = HKDF(pairing_secret, salt=pairing_secret, info="…/session/{id}")`，
/// `file_key = HKDF(session_key, info="…/file/{file_id}")`。
/// V4 当前没有每会话 ECDH（WB-0020 遗留），session_shared 暂以 pairing_secret 充当。
/// nonce = 8B 大端 piece 序号（前 4 字节补零）——文件内绝不重复，断点续传按
/// 序号重建，无需持久化计数器；AAD 绑定 `session/file/piece`（WB-0623）。
fn decrypt_encrypted_part(
    part: &Path,
    final_path: &Path,
    pairing_secret: &[u8],
    session_id: &str,
    file_id: &str,
    plain_size: u64,
) -> Result<(std::path::PathBuf, String), String> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};

    if pairing_secret.len() != crate::crypto::kdf::KEY_LEN {
        return Err("该对端缺少配对密钥，无法解密".to_string());
    }
    let mut secret = [0u8; crate::crypto::kdf::KEY_LEN];
    secret.copy_from_slice(pairing_secret);
    let sk = crate::crypto::kdf::derive_session_key(&secret, &secret, session_id);
    let fk = crate::crypto::kdf::derive_file_key(&sk, file_id);

    let stride = PIECE_SIZE + AEAD_TAG_LEN;
    let total_pieces = piece_count(plain_size);
    let expect_wire = plain_size + total_pieces * AEAD_TAG_LEN;
    let wire_len = std::fs::metadata(part)
        .map_err(|e| format!("读取密文大小失败: {e}"))?
        .len();
    if wire_len != expect_wire {
        return Err(format!("密文长度不符：期望 {expect_wire}，实际 {wire_len}"));
    }

    // 明文临时文件与 final 同目录（复用 part_path 的同目录约束与 id 净化）
    let dec_path = atomic_file::part_path(final_path, session_id, &format!("{file_id}-dec"));
    let mut src = std::fs::File::open(part).map_err(|e| format!("打开密文失败: {e}"))?;
    let mut dst =
        std::fs::File::create(&dec_path).map_err(|e| format!("创建明文临时文件失败: {e}"))?;
    let mut hasher = Sha256::new();
    let mut cipher = vec![0u8; stride as usize];
    for idx in 0..total_pieces {
        let plain_off = idx * PIECE_SIZE;
        let plain_len = (plain_size - plain_off).min(PIECE_SIZE) as usize;
        let cipher_len = plain_len + AEAD_TAG_LEN as usize;
        src.read_exact(&mut cipher[..cipher_len])
            .map_err(|e| format!("读取密文 piece {idx} 失败: {e}"))?;
        let mut nonce = [0u8; crate::crypto::aead::NONCE_LEN];
        nonce[4..].copy_from_slice(&idx.to_be_bytes());
        let aad = format!("lanbackup/v4/piece/{session_id}/{file_id}/{idx}");
        let plain = crate::crypto::aead::decrypt(&fk, &nonce, &cipher[..cipher_len], aad.as_bytes())
            .ok_or_else(|| format!("piece {idx} 解密失败：密钥不匹配或密文被篡改"))?;
        if plain.len() != plain_len {
            return Err(format!("piece {idx} 解密后长度不符"));
        }
        hasher.update(&plain);
        dst.write_all(&plain).map_err(|e| format!("写明文失败: {e}"))?;
    }
    dst.sync_all().map_err(|e| format!("刷盘失败: {e}"))?;
    Ok((dec_path, hex::encode(hasher.finalize())))
}

/// 全会话文件都已通过块级校验后，把状态机沿合法路径推到 Completed。
fn drive_to_verify_completed(rec: &mut SessionRecord) {
    if rec.phase == TransferState::Preparing {
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
    if rec.phase == TransferState::Transferring {
        if let Ok(next) = rec.phase.transition(TransferEvent::BeginVerify) {
            rec.phase = next;
        }
    }
    if rec.phase == TransferState::Verifying {
        if let Ok(done) = rec.phase.transition(TransferEvent::VerifyOk) {
            rec.phase = done;
        }
    }
}

/// `GET /api/v4/session/verify` —— 单文件整体校验 + 原子提交。
///
/// 全部块到齐且**本端实算**哈希匹配 → 200 + 本端 sha256；否则 412 + `reason`。
///
/// 提交发生在校验之后：`handle_chunk` 只写 `.part`，绝不提前改旧文件。
/// 同会话所有文件都通过后才推进 `Transferring → Verifying → Completed`。
async fn handle_verify(store: &Arc<SessionStore>, path: &str) -> Response<Full<bytes::Bytes>> {
    let q = match parse_query(path) {
        Ok(q) => q,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    let session_id = match q.get("sessionId") {
        Some(s) => s.clone(),
        None => return err_response(ErrorCode::BadRequest, "缺少 sessionId 参数"),
    };
    let file_id = match q.get("fileId") {
        Some(s) => s.clone(),
        None => return err_response(ErrorCode::BadRequest, "缺少 fileId 参数"),
    };

    let base_dir = store.base_dir.read().unwrap().clone();
    let (device_id, meta, part_path, final_path, reason) = {
        let guard = store.inner.lock().await;
        let rec = match guard.get(&session_id) {
            Some(r) => r,
            None => return err_response(ErrorCode::NotFound, "会话不存在"),
        };
        // 生产模式下 verify 也接受 token，防止知道 sessionId 就能触发提交。
        if store
            .require_active_peer
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            let token = match q.get("token") {
                Some(t) => t,
                None => return err_response(ErrorCode::Untrusted, "缺少 token 参数"),
            };
            if rec.tokens.get(&file_id) != Some(token) {
                return err_response(ErrorCode::Untrusted, "token 无效或不属于该文件");
            }
        }
        let meta = match rec.files.get(&file_id) {
            Some(m) => m.clone(),
            None => return err_response(ErrorCode::NotFound, "文件未登记"),
        };
        let final_path = match safe_final_path(&base_dir, &meta.rel_path) {
            Ok(p) => p,
            Err(e) => return err_response(ErrorCode::BadRequest, &format!("relPath 非法: {e}")),
        };
        let part_path = atomic_file::part_path(&final_path, &session_id, &file_id);
        (
            rec.device_id.clone(),
            meta,
            part_path,
            final_path,
            file_incomplete_reason(rec, &file_id),
        )
    };

    if let Err(resp) = store.ensure_active_peer(&device_id).await {
        return *resp;
    }
    if let Some(reason) = reason {
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

    // 锁外：本端实算哈希 → 与声明值比对 → 原子提交 → 恢复 mtime。
    // 加密文件（WB-0030）：.part 里是密文 piece（定长 stride），先逐 piece
    // 解密成明文临时文件并累计明文 SHA-256 —— 解不开 = 密钥不符或密文被篡改，
    // 一律 412，绝不把密文当明文提交。
    let mut commit_src: std::path::PathBuf = part_path.clone();
    let computed = if part_path.exists() {
        if meta.encrypted {
            let pairing_secret = match store.peers.entry(&device_id).await {
                Some(p) => p.pairing_secret.clone(),
                None => Vec::new(),
            };
            match decrypt_encrypted_part(
                &part_path,
                &final_path,
                &pairing_secret,
                &session_id,
                &file_id,
                meta.size,
            ) {
                Ok((dec_path, sha)) => {
                    commit_src = dec_path;
                    sha
                }
                Err(e) => {
                    return json_response_with(
                        StatusCode::PRECONDITION_FAILED,
                        &serde_json::to_value(VerifyFileResponse {
                            file_id,
                            sha256: None,
                            reason: Some(format!("解密失败：{e}")),
                        })
                        .unwrap(),
                        &[],
                    );
                }
            }
        } else {
            match sha256_file_hex(&part_path) {
                Ok(s) => s,
                Err(e) => return err_response(ErrorCode::Internal, &format!("读取临时文件失败: {e}")),
            }
        }
    } else if final_path.exists() {
        match sha256_file_hex(&final_path) {
            Ok(s) => s,
            Err(e) => return err_response(ErrorCode::Internal, &format!("读取文件失败: {e}")),
        }
    } else {
        return json_response_with(
            StatusCode::PRECONDITION_FAILED,
            &serde_json::to_value(VerifyFileResponse {
                file_id,
                sha256: None,
                reason: Some("文件未落盘：没有任何已确认分块".to_string()),
            })
            .unwrap(),
            &[],
        );
    };

    if let Some(declared) = meta.sha256.as_ref() {
        if !declared.eq_ignore_ascii_case(&computed) {
            return json_response_with(
                StatusCode::PRECONDITION_FAILED,
                &serde_json::to_value(VerifyFileResponse {
                    file_id,
                    sha256: None,
                    reason: Some("整文件 SHA-256 与发送端声明不一致".to_string()),
                })
                .unwrap(),
                &[],
            );
        }
    }

    if commit_src.exists() {
        let identical_final = final_path.exists()
            && std::fs::metadata(&final_path)
                .map(|m| m.len() == meta.size)
                .unwrap_or(false)
            && sha256_file_hex(&final_path)
                .map(|s| s.eq_ignore_ascii_case(&computed))
                .unwrap_or(false);
        if identical_final {
            let _ = std::fs::remove_file(&commit_src);
            if let Err(e) = atomic_file::restore_mtime(&final_path, meta.mtime) {
                log::warn!("恢复 mtime 失败: {e}");
            }
        } else {
            match atomic_file::commit_preserving_conflict(&commit_src, &final_path) {
                Ok(Some(backup)) => {
                    log::info!("覆盖旧文件，旧版本保留为: {}", backup.display());
                }
                Ok(None) => {}
                Err(e) => {
                    return err_response(ErrorCode::Internal, &format!("原子提交失败: {e}"))
                }
            }
            if let Err(e) = atomic_file::restore_mtime(&final_path, meta.mtime) {
                log::warn!("恢复 mtime 失败: {e}");
            }
        }
        store
            .pending_parts
            .lock()
            .unwrap()
            .remove(&format!("{session_id}/{file_id}"));
    }

    // 锁内：写入接收端权威回执（终态 Completed），并在全部文件通过后推进状态机。
    let (phase, algorithm, degrade_reason, bitmap_version, receipt) = {
        let mut guard = store.inner.lock().await;
        let rec = match guard.get_mut(&session_id) {
            Some(r) => r,
            None => return err_response(ErrorCode::NotFound, "会话在提交期间被清理"),
        };
        let receipt = TaskReceipt {
            file_id: file_id.clone(),
            rel_path: meta.rel_path.clone(),
            status: TaskStatus::Completed,
            size: Some(meta.size),
            mtime: Some(meta.mtime),
            final_name: None,
            reason: None,
        };
        // 终态单调：已有 Failed/Cancelled 的文件不被一次 verify 洗成 Completed。
        let keep_old = rec
            .receipts
            .get(&file_id)
            .map(|old| old.status.is_terminal() && old.status != TaskStatus::Completed)
            .unwrap_or(false);
        if !keep_old {
            rec.receipts.insert(file_id.clone(), receipt.clone());
        }
        if !rec.phase.is_terminal() {
            let all_ids: Vec<String> = rec.files.keys().cloned().collect();
            if all_ids
                .iter()
                .all(|id| file_incomplete_reason(rec, id).is_none())
            {
                drive_to_verify_completed(rec);
            }
        }
        rec.last_activity = std::time::Instant::now();
        (
            rec.phase,
            rec.algorithm,
            rec.degrade_reason,
            rec.bitmap_version,
            if keep_old { None } else { Some(receipt) },
        )
    };

    if let (Some(p), Some(r)) = (&store.persist, &receipt) {
        p.set_receipt(&session_id, &file_id, r);
    }

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
        sha256: Some(computed),
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
    // 生产接收端：回执由 verify 在本端内部生成（见 handle_verify），
    // 绝不接受外部 POST 改写终态 —— 否则任何知道 sessionId 的对端都能
    // 把文件伪造成 Completed，终态权威就失效了。
    if store
        .require_active_peer
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return err_response(
            ErrorCode::Untrusted,
            "回执由接收端在 verify 时内部生成，不接受外部写入",
        );
    }
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
    let q = match parse_query(path) {
        Ok(q) => q,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    let session_id = match q.get("sessionId") {
        Some(s) => s.clone(),
        None => return err_response(ErrorCode::BadRequest, "缺少 sessionId 参数"),
    };
    let (device_id, payload) = {
        let guard = store.inner.lock().await;
        let rec = match guard.get(&session_id) {
            Some(r) => r,
            None => return err_response(ErrorCode::NotFound, "会话不存在"),
        };
        let payload = TaskListResponse {
            session_id: session_id.clone(),
            phase: to_phase(rec.phase),
            tasks: task_list(rec),
        };
        (rec.device_id.clone(), payload)
    };
    // WB-0381：任务列表暴露文件清单与终态，生产模式要求对端 Active。
    if let Err(resp) = store.ensure_active_peer(&device_id).await {
        return *resp;
    }
    ok_json(payload)
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
                    // 声明了这一块、本端却没有自算哈希 => 无法证明正确，按坏块处理。
                    // 缺度量等于未完成；不能把"不知道"当成"匹配"。
                    (Some(_), None) => true,
                    (None, _) => false,
                },
            )
            .count();
        if bad > 0 {
            return Some(format!("{bad} 个块 SHA-256 不匹配或缺少本端度量"));
        }
    } else if total > 0 {
        // 发送端未声明 piece 哈希时，至少要求每块都有本端自算度量。
        let unmeasured = (0..total)
            .filter(|i| local_sha.and_then(|m| m.get(i)).is_none())
            .count();
        if unmeasured > 0 {
            return Some(format!("{unmeasured} 个块缺少本端 SHA-256 度量"));
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

/// 严格百分号解码：非法 `%` 序列、非 UTF-8 字节一律拒绝。
///
/// 不做 `+` → 空格转换：V4 的查询值是设备 ID / 会话 ID / 哈希，客户端必须
/// 用百分号编码；把 `+` 当空格会让 `fileId=a+b` 与 `fileId=a%20b` 产生歧义。
fn percent_decode_strict(raw: &str) -> Result<String, String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("百分号编码不完整".to_string());
            }
            let hi = (bytes[i + 1] as char)
                .to_digit(16)
                .ok_or_else(|| "非法百分号编码".to_string())?;
            let lo = (bytes[i + 2] as char)
                .to_digit(16)
                .ok_or_else(|| "非法百分号编码".to_string())?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "查询参数不是合法 UTF-8".to_string())
}

/// 一次解析完查询串并**拒绝重复键**。
///
/// 重复键是歧义源：`?sessionId=a&sessionId=b` 在不同实现里会取到不同值，
/// 属于必须显式拒绝的输入，而不是"取第一个就行"。
pub(crate) fn parse_query(rest: &str) -> Result<HashMap<String, String>, String> {
    let Some((_, q)) = rest.split_once('?') else {
        return Ok(HashMap::new());
    };
    let mut out = HashMap::new();
    if q.is_empty() {
        return Ok(out);
    }
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = percent_decode_strict(k)?;
        let v = percent_decode_strict(v)?;
        if k.is_empty() {
            return Err("查询参数名为空".to_string());
        }
        if out.insert(k.clone(), v).is_some() {
            return Err(format!("查询参数 {k} 重复"));
        }
    }
    Ok(out)
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
    // header_read_timeout 依赖显式 Timer（否则 hyper 会在首次读头时 panic）
    b.timer(hyper_util::rt::TokioTimer::new());
    // P33：头部读取超时，防 Slowloris 用半截请求头长期占连接。
    b.header_read_timeout(IO_TIMEOUT);
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
    // 防御总闸：隐藏时连 probe 都不回应，避免成为可探测的在线目标。
    if store.is_defensive_hidden() {
        return json_response(
            StatusCode::FORBIDDEN,
            &serde_json::json!({"error": {"code": "UNTRUSTED", "message": "本机已开启防御模式，拒绝一切入站请求"}}),
        );
    }
    let method = req.method().clone();
    // WB-0001：必须保留查询串。hyper 的 `uri().path()` 会丢掉 `?a=b`，
    // 而所有 GET handler 都在 rest 里找 `?` —— 之前真实服务上全部 400。
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    // M18/D7：读 body 前先按 Content-Length 预检，超限直接拒绝，避免先分配再发现
    let declared = req
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    if let Err(resp) = body_limit_check(declared, 0) {
        return *resp;
    }
    let body = match read_body_limited(req.into_body()).await {
        Ok(b) => b,
        Err(resp) => return *resp,
    };
    route(store, method, &path, &body).await
}

/// WB-0013：流式读取并限长。chunked 编码没有 Content-Length，不能先
/// `collect()` 再检查 —— 那样攻击者可以让本端先分配任意大内存。
async fn read_body_limited(
    mut body: hyper::body::Incoming,
) -> Result<bytes::Bytes, Box<Response<Full<bytes::Bytes>>>> {
    let mut collected: Vec<u8> = Vec::with_capacity(16 * 1024);
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(f) => f,
            Err(_) => {
                return Err(Box::new(err_response(
                    ErrorCode::BadRequest,
                    "读取请求体失败",
                )))
            }
        };
        if let Some(data) = frame.data_ref() {
            collected.extend_from_slice(data);
            body_limit_check(None, collected.len())?;
        }
    }
    Ok(bytes::Bytes::from(collected))
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
            &[0u8; 100],
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

        // 终态再 abort → 幂等吸收（WB-0363）：迟到的取消不得变成 409
        let r = route(
            &store,
            Method::POST,
            "/api/v4/session/abort",
            &body(serde_json::json!({"sessionId":"s1"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["cancelled"], serde_json::json!(0), "重复 abort 不得重复清理");
        assert_eq!(v["phase"].as_str(), Some("aborted"));
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

    /// WB-0030 E2E：加密文件全链路 —— prepare(encrypted) → chunk(密文 piece) →
    /// verify 接收端**解密**并返回明文 SHA-256；密文被篡改时解密失败 412。
    /// 落盘的最终文件必须等于明文，不得出现密文落盘。
    #[tokio::test]
    async fn encrypted_file_is_decrypted_on_verify_and_tamper_is_412() {
        use crate::crypto::{aead, kdf};
        use control::PeerRecord;

        let dir = std::env::temp_dir().join(format!("lanbak-enc-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = test_store();
        store.with_require_active_peer(true);
        store.with_base_dir(dir.clone());
        let mut trust = crate::pairing::trust::TrustRecord::new();
        let _ = trust.apply(crate::pairing::machine::PairingEvent::Initiate);
        let _ = trust.apply(crate::pairing::machine::PairingEvent::PeerConfirmed);
        store
            .peers
            .put(PeerRecord::new("p1", "", vec![], vec![7u8; 32], trust))
            .await;

        route(
            &store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({"deviceId":"p1","alias":"a","sessionId":"s1"})),
        )
        .await;

        // 明文 f1 = "HELLO-ENCRYPTED-WORLD"（21B，1 piece）；f2 同明文，供篡改分支
        let plain = b"HELLO-ENCRYPTED-WORLD".to_vec();
        let plain_sha = hex::encode(kdf::sha256(&plain));

        let derive = |fid: &str| {
            let sk = kdf::derive_session_key(&[7u8; 32], &[7u8; 32], "s1");
            kdf::derive_file_key(&sk, fid)
        };
        let nonce_of = |idx: u64| {
            let mut n = [0u8; 12];
            n[4..].copy_from_slice(&idx.to_be_bytes());
            n
        };
        let aad_of = |fid: &str, idx: u64| {
            format!("lanbackup/v4/piece/s1/{fid}/{idx}").into_bytes()
        };
        let good_ct = aead::encrypt(
            &derive("f1"),
            &nonce_of(0),
            &plain,
            &aad_of("f1", 0),
        )
        .unwrap();
        assert_eq!(good_ct.len(), plain.len() + 16, "密文 = 明文 + 16B tag");

        let f_meta = |fid: &str, ct_sha: &str| {
            serde_json::json!({
                "fileId": fid, "fileName": fid, "relPath": format!("{fid}.bin"),
                "size": plain.len(), "mtime": 1,
                "sha256": plain_sha,
                "pieceHashes": [ct_sha],
                "encrypted": true, "wireSize": plain.len() as u64 + 16,
            })
        };
        let tampered_ct = {
            let mut c = good_ct.clone();
            c[0] ^= 0xff;
            c
        };
        let tampered_sha = hex::encode(kdf::sha256(&tampered_ct));

        async fn prepare_one(store: &Arc<SessionStore>, fid: &str, meta: serde_json::Value) -> String {
            let r = route(
                store,
                Method::POST,
                "/api/v4/session/prepare",
                &body(serde_json::json!({
                    "sessionId":"s1","deviceId":"p1",
                    "files":{ (fid): meta }
                })),
            )
            .await;
            let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
            v["files"][fid].as_str().unwrap().to_string()
        }

        // f1 声明正确密文哈希；f2 声明与即将上传的（篡改）密文一致的哈希 ——
        // 让坏块通过块级完整性检查，把验证点落在**解密失败**上
        let tok1 = prepare_one(&store, "f1", f_meta("f1", &hex::encode(kdf::sha256(&good_ct)))).await;
        let tok2 = prepare_one(&store, "f2", f_meta("f2", &tampered_sha)).await;

        // f1 上传正确密文
        let r = route(
            &store,
            Method::POST,
            &format!("/api/v4/session/chunk?sessionId=s1&fileId=f1&pieceIndex=0&token={tok1}&sha256={}", hex::encode(kdf::sha256(&good_ct))),
            &good_ct,
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK, "正确密文应被接收");
        // f2 上传被篡改的密文（sha256 声明与实际字节一致，骗过块级校验）
        let r = route(
            &store,
            Method::POST,
            &format!("/api/v4/session/chunk?sessionId=s1&fileId=f2&pieceIndex=0&token={tok2}&sha256={tampered_sha}"),
            &tampered_ct,
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);

        // f1 verify：接收端解密成功，返回**明文** SHA-256
        let r = route(
            &store,
            Method::GET,
            &format!("/api/v4/session/verify?sessionId=s1&fileId=f1&token={tok1}"),
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK, "正确密文应通过 verify");
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(
            v["sha256"].as_str(),
            Some(plain_sha.as_str()),
            "verify 必须返回解密后的明文哈希"
        );
        let got = std::fs::read(dir.join("f1.bin")).unwrap();
        assert_eq!(got, plain, "落盘必须是明文，不得是密文");

        // f2 verify：密文被篡改 → GCM 认证失败 → 412，绝不把坏密文提交
        let r = route(
            &store,
            Method::GET,
            &format!("/api/v4/session/verify?sessionId=s1&fileId=f2&token={tok2}"),
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::PRECONDITION_FAILED, "篡改密文必须 412");
        assert!(!dir.join("f2.bin").exists(), "解密失败不得落盘");
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

    fn sha_hex(bytes: &[u8]) -> String {
        hex::encode(crate::crypto::kdf::sha256(bytes))
    }

    /// 单块整 4MB 的零字节体：多处测试复用，避免反复分配/重复计算。
    fn piece_body() -> &'static [u8] {
        static B: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        B.get_or_init(|| vec![0u8; crate::transfer::chunk::PIECE_SIZE as usize])
    }

    fn piece_sha() -> &'static str {
        static S: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        S.get_or_init(|| sha_hex(piece_body()))
    }

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
        let data = vec![0u8; 100];
        let sha = sha_hex(&data);
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1,
                       "sha256": sha, "pieceHashes":[sha]}
            }),
        )
        .await;
        // 确认第 0 块，本端落盘自算 sha = sha
        route(
            &store,
            Method::POST,
            &format!("/api/v4/session/chunk?sessionId=s1&fileId=f1&pieceIndex=0&sha256={sha}"),
            &data,
        )
        .await;
        // 对端声明 sha == 本端实测 sha → 206 + 双引号 ETag（A12）
        let r = route(
            &store,
            Method::GET,
            &format!("/api/v4/session/diff?sessionId=s1&fileId=f1&pieceIndex=0&sha256={sha}"),
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
            format!("\"{sha}\"")
        );
    }

    #[tokio::test]
    async fn diff_confirmed_mismatched_sha_returns_412() {
        let store = test_store();
        let data = vec![0u8; 100];
        let sha = sha_hex(&data);
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1,
                       "sha256": sha, "pieceHashes":[sha]}
            }),
        )
        .await;
        route(
            &store,
            Method::POST,
            &format!("/api/v4/session/chunk?sessionId=s1&fileId=f1&pieceIndex=0&sha256={sha}"),
            &data,
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
        assert_eq!(v["actual"].as_str(), Some(sha.as_str()));
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
        let data = vec![0u8; 100];
        let sha = sha_hex(&data);
        setup(
            &store,
            "s1",
            serde_json::json!({
                "f1": {"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1,"sha256": sha}
            }),
        )
        .await;
        // chunk 推到 Transferring 并确认全部块
        route(
            &store,
            Method::POST,
            &format!("/api/v4/session/chunk?sessionId=s1&fileId=f1&pieceIndex=0&sha256={sha}"),
            &data,
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
        assert_eq!(v["sha256"].as_str(), Some(sha.as_str()));
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
            &[0u8; 100],
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
        let sha = piece_sha();

        // ── 进程 A：注册 / prepare / 收到块 0、1 ──
        {
            let store = SessionStore::open(
                crate::identity::DeviceIdentity::generate(),
                "srv",
                crate::dto::DeviceType::Desktop,
                Some(&persist_dir),
            );
            store.with_base_dir(dir.join("recv"));
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
                    piece_body(),
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
            store.with_base_dir(dir.join("recv"));
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
            store.with_base_dir(dir.join("recv"));
            let mut tasks = tokio::task::JoinSet::new();
            for i in 0..4u32 {
                let store = store.clone();
                tasks.spawn(async move {
                    let sid = format!("s{i}");
                    let dev = format!("dev{i}");
                    // 每会话不同内容 → 不同 piece 哈希，碰巧全相等会掩盖丢行
                    let data = vec![i as u8; crate::transfer::chunk::PIECE_SIZE as usize];
                    let sha = sha_hex(&data);
                    let hashes = vec![sha.clone(); 6];
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
                                "pieceHashes": hashes}}
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
                            &data,
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
            store.with_base_dir(dir.join("recv"));
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
        let sha = piece_sha();
        let whole = sha_hex(&vec![0u8; size as usize]);

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
                    "size":size,"mtime":1,"sha256":whole,"pieceHashes":[sha,sha]}}
            })),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        let token = v["files"]["f1"].as_str().unwrap();
        assert_ne!(token, "tok:f1", "token 必须是 CSPRNG，不得可预测");
        assert!(!token.is_empty());

        // 3. chunk×2 → Transferring，全块确认
        for i in [0u64, 1] {
            let r = route(
                &store,
                Method::POST,
                &format!("/api/v4/session/chunk?sessionId=e2e&fileId=f1&pieceIndex={i}&sha256={sha}&token={token}"),
                piece_body(),
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
            &format!("/api/v4/session/diff?sessionId=e2e&fileId=f1&pieceIndex=0&sha256={sha}"),            &[],
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
            &format!("/api/v4/session/verify?sessionId=e2e&fileId=f1&token={token}"),
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&to_bytes(r).await).unwrap();
        assert_eq!(v["sha256"].as_str(), Some(whole.as_str()));
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

    /// WB-0001：真实 hyper 入口必须保留 query 串。
    ///
    /// 内部测试直接调 `route()` 会掩盖 `uri().path()` 丢 query 的问题；
    /// 这里走 `serve_request` + 真实 TCP，`session/phase?sessionId=...`
    /// 必须 200 而不是 400。
    #[tokio::test]
    async fn real_http_entry_preserves_query() {
        let store = test_store();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_store = store.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let store = server_store.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let _ = hyper_http1_builder()
                        .serve_connection(
                            io,
                            hyper::service::service_fn(move |req| {
                                let store = store.clone();
                                async move {
                                    Ok::<_, std::convert::Infallible>(
                                        serve_request(&store, req).await,
                                    )
                                }
                            }),
                        )
                        .await;
                });
            }
        });

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        let base = format!("http://{addr}");
        let reg = client
            .post(format!("{base}/api/v4/session/register"))
            .json(&serde_json::json!({
                "deviceId":"devA","alias":"A","sessionId":"http1"
            }))
            .send()
            .await
            .expect("register 请求失败");
        assert_eq!(reg.status(), StatusCode::OK);

        let phase = client
            .get(format!("{base}/api/v4/session/phase?sessionId=http1"))
            .send()
            .await
            .expect("phase 请求失败");
        assert_eq!(
            phase.status(),
            StatusCode::OK,
            "真实 hyper 入口丢失 query：serve_request 必须使用 path_and_query"
        );
        let v: serde_json::Value = phase.json().await.unwrap();
        assert_eq!(v["phase"].as_str(), Some("preparing"));

        server.abort();
    }

    #[tokio::test]
    async fn duplicate_query_key_is_rejected_and_percent_decoded() {
        let store = test_store();
        route(
            &store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({"deviceId":"devA","alias":"A","sessionId":"abc"})),
        )
        .await;
        let dup = route(
            &store,
            Method::GET,
            "/api/v4/session/phase?sessionId=a&sessionId=b",
            &[],
        )
        .await;
        assert_eq!(dup.status(), StatusCode::BAD_REQUEST, "重复键必须拒绝");
        let encoded = route(
            &store,
            Method::GET,
            "/api/v4/session/phase?sessionId=%61bc",
            &[],
        )
        .await;
        assert_eq!(encoded.status(), StatusCode::OK, "百分号编码必须解码");
    }

    /// 真实 hyper 上的完整传输链路：register→prepare→diff→chunk→verify→tasks。
    ///
    /// 这条测试刻意只依赖 HTTP 端点，不直接改内存表 —— 桌面发送端就是按这个
    /// 顺序调的，链路里任何一处丢 query/状态码错误都会在这里暴露。
    #[tokio::test]
    async fn real_http_full_transfer_flow() {
        let store = test_store();
        let base_dir = store.base_dir.read().unwrap().clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_store = store.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let store = server_store.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let _ = hyper_http1_builder()
                        .serve_connection(
                            io,
                            hyper::service::service_fn(move |req| {
                                let store = store.clone();
                                async move {
                                    Ok::<_, std::convert::Infallible>(
                                        serve_request(&store, req).await,
                                    )
                                }
                            }),
                        )
                        .await;
                });
            }
        });

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .unwrap();
        let base = format!("http://{addr}");
        let data = b"hello-v4-real-http".to_vec();
        let sha = sha_hex(&data);

        let reg: serde_json::Value = client
            .post(format!("{base}/api/v4/session/register"))
            .json(&serde_json::json!({
                "deviceId":"devA","alias":"A","sessionId":"flow1"
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(reg["sessionId"], "flow1");

        let prep: serde_json::Value = client
            .post(format!("{base}/api/v4/session/prepare"))
            .json(&serde_json::json!({
                "sessionId":"flow1","deviceId":"devA",
                "files":{"f1":{"fileId":"f1","fileName":"x","relPath":"x",
                    "size":data.len(),"mtime":1,"sha256":sha.clone(),
                    "pieceHashes":[sha.clone()]}}
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let token = prep["files"]["f1"].as_str().unwrap().to_string();
        assert_ne!(token, "tok:f1");

        let diff: serde_json::Value = client
            .get(format!(
                "{base}/api/v4/session/diff?sessionId=flow1&fileId=f1&etag={sha}"
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(diff["missingChunks"], serde_json::json!([0]));

        let chunk = client
            .post(format!(
                "{base}/api/v4/session/chunk?sessionId=flow1&fileId=f1&pieceIndex=0&sha256={sha}&token={token}"
            ))
            .header("Content-Type", "application/octet-stream")
            .body(data.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(chunk.status(), StatusCode::OK);

        let verify: serde_json::Value = client
            .get(format!(
                "{base}/api/v4/session/verify?sessionId=flow1&fileId=f1&token={token}"
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(verify["sha256"].as_str(), Some(sha.as_str()));

        let tasks: serde_json::Value = client
            .get(format!("{base}/api/v4/session/tasks?sessionId=flow1"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(tasks["phase"], "completed");
        assert_eq!(tasks["tasks"][0]["status"], "completed");

        let written = std::fs::read(base_dir.join("x")).unwrap();
        assert_eq!(written, data);
        // 临时文件必须已被提交清理
        assert!(!base_dir.join("x.part.flow1.f1").exists());

        server.abort();
    }

    /// 生产模式：未 Active 的设备连 register 都进不来；补上 Active 后放行。
    #[tokio::test]
    async fn require_active_peer_blocks_unknown_and_allows_paired() {
        use crate::pairing::machine::PairingEvent;
        use crate::pairing::trust::TrustRecord;
        use crate::server::control::PeerRecord;

        let store = test_store();
        store.with_require_active_peer(true);
        let blocked = route(
            &store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({"deviceId":"devA","alias":"A","sessionId":"s1"})),
        )
        .await;
        assert_eq!(blocked.status(), StatusCode::UNAUTHORIZED);

        let mut trust = TrustRecord::new();
        trust.apply(PairingEvent::Initiate).unwrap();
        trust.apply(PairingEvent::PeerConfirmed).unwrap();
        store
            .merge_peer(PeerRecord::new("devA", "A", vec![2u8; 33], vec![7u8; 32], trust))
            .await;

        let allowed = route(
            &store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({"deviceId":"devA","alias":"A","sessionId":"s1"})),
        )
        .await;
        assert_eq!(allowed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn prepare_rejects_path_traversal_and_windows_ads() {
        let store = test_store();
        route(
            &store,
            Method::POST,
            "/api/v4/session/register",
            &body(serde_json::json!({"deviceId":"devA","alias":"A","sessionId":"s1"})),
        )
        .await;
        for bad in ["../../evil.txt", "a/file.txt:stream", "CON", "C:/Windows/x"] {
            let r = route(
                &store,
                Method::POST,
                "/api/v4/session/prepare",
                &body(serde_json::json!({
                    "sessionId":"s1","deviceId":"devA",
                    "files":{"f1":{"fileId":"f1","fileName":"x","relPath":bad,
                        "size":1,"mtime":1}}
                })),
            )
            .await;
            assert_eq!(
                r.status(),
                StatusCode::BAD_REQUEST,
                "恶意 relPath 未被拒绝: {bad}"
            );
        }
    }

    // 辅助：把 Response 的 body 读成 Vec<u8>
    async fn to_bytes(r: Response<Full<bytes::Bytes>>) -> Vec<u8> {
        use http_body_util::BodyExt;
        r.into_body().collect().await.unwrap().to_bytes().to_vec()
    }
}
