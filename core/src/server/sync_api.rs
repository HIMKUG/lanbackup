//! 清单与同步端点（V4-ARCHITECTURE.md §六 表三）
//!
//! 五个端点：`manifest` / `chunk-status` / `sync-dir` / `move-to-delete` / `disconnect`。
//!
//! # 三路对比为什么**不在**这里
//!
//! [`crate::sync::plan::decide`] 需要三份输入：本机当前清单、本机上次快照、
//! **对端**当前清单。服务端只有前两份 —— 第三份在发起端手里。
//! 所以对比发生在发起端（经 `ffi::sync_decide_json` 暴露），
//! 服务端的职责是**把自己那份清单如实交出去**，以及记录目录映射约定。
//!
//! 把 `decide` 塞进服务端会逼出一个"请把你的清单 POST 给我"的额外往返，
//! 而协议表里 `manifest` 是 GET —— 那等于在协议之外又造一套流程。
//!
//! # `delete/` 必须出现在清单里（最容易漏的一条）
//!
//! [`crate::sync::plan::decide`] 判断"对端是否有意删除"的唯一依据是
//! 对端清单里存不存在 `delete/<path>` 这个墓碑。因此本模块交出的清单
//! **必须包含** `delete/` 下的条目。
//!
//! 一旦把 `delete/` 过滤掉（看起来很合理 —— "回收站不是备份内容"），
//! 发起端就再也看不到墓碑，于是把用户刚删掉的文件判成 `heal_missing`
//! 并重新推上来 —— 备份工具复活用户删掉的东西，用户永远删不掉。
//! 这正是 `plan.rs` 模块文档里那条"墓碑调和自愈与不复活"的另一半。
//!
//! 于是 [`SyncStore::move_to_delete`] 采用"在清单内搬移条目"的模型
//! （`p` → `delete/p`），而不是另存一份墓碑集合：清单只有一个事实源，
//! GET `manifest` 自然就带上了墓碑。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use http_body_util::Full;
use hyper::Response;
use tokio::sync::Mutex;

use crate::dto::sync::{
    ChunkStatusResponse, DisconnectRequest, DisconnectResponse, Manifest, ManifestEntry,
    MoveToDeleteRequest, MoveToDeleteResponse, SyncDirRequest, SyncDirResponse, SyncStrategy,
};
use crate::dto::Presence;
use crate::error::ErrorCode;
use crate::pairing::machine::allows_transfer;
use crate::state::transfer::TransferEvent;
use crate::sync::manifest::{
    is_in_delete_dir, tombstone_path,
};
use crate::transfer::chunk::piece_count;

use super::{err_response, file_incomplete_reason, ok_json, parse_body, parse_query};
use crate::sync::manifest::validate_rel_path;
use super::{persist::SessionPersister, SessionStore};

/// 一个对端的目录映射约定（`sync-dir` 登记的内容）。
///
/// 需要 serde：持久化后端（`sync-dirs.json`）按设备存整表（WB-0416）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirMapping {
    /// 发起端的备份根标识
    pub root_id: String,
    /// 本端用于接收的目录名（已归一化，且已通过路径安全校验）
    pub target_dir: String,
    pub strategy: SyncStrategy,
}

#[derive(Default)]
struct SyncState {
    /// 本机当前清单（平台层扫描后推入）。**含 `delete/` 下的墓碑**。
    local: Manifest,
    /// 上次**成功**同步后的本机快照 —— 三路对比的第三路。
    snapshot: Option<Manifest>,
    /// deviceId → 目录映射
    dirs: HashMap<String, DirMapping>,
    /// `path → 原条目`：本会话内产生过的墓碑（WB-0426）。
    /// 平台重扫会把磁盘上的 `delete/` 文件带回清单，但"清单里有、磁盘上
    /// 本来就没有"的墓碑只有这里能兜住；每次推入新清单时合并回来。
    tombstones: HashMap<String, ManifestEntry>,
}

/// 假删除的三种结果。分开表达，是为了让响应能如实告诉对端"这条到底怎么了"。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoveOutcome {
    /// 已从 `p` 搬到 `delete/p`
    Moved(String),
    /// 已经在 `delete/` 下了 —— 幂等重放或对端重试
    AlreadyDeleted,
    /// 本端清单里没有这个文件，无可搬移
    NotFound,
}

/// 清单与同步的运行时状态（内存实现；生产换 rusqlite）。
#[derive(Default)]
pub struct SyncStore {
    inner: Mutex<SyncState>,
    /// S10：last-manifest 快照的写穿后端。`None` = 纯内存（测试 / 尚未接 db）。
    persist: Option<Arc<SessionPersister>>,
}

impl SyncStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 接持久化后端的构造。打开时重载三份冷数据：
    /// `last-manifest.json`（快照，三路对比第三路）、`tombstones.json`（墓碑，
    /// WB-0426）、`sync-dirs.json`(目录映射，WB-0416) ——
    /// 否则进程一重启，快照丢失退化为全量备份、墓碑丢失会复活用户删掉的文件。
    pub(crate) fn with_persist(persist: Option<Arc<SessionPersister>>) -> Self {
        let mut s = Self { inner: Mutex::default(), persist };
        if let Some(p) = &s.persist {
            let g = s.inner.get_mut();
            if let Some(m) = p.load_last_manifest() {
                // 快照只供三路对比读取，重载失败可接受（按首次同步处理）
                g.snapshot = Some(m);
            }
            let tombstones = p.load_tombstones();
            if !tombstones.is_empty() {
                // 重启后本地清单还是空的；先把墓碑合回去，等平台首次扫描推入时
                // `set_local_manifest` 会再合并一次（幂等）。
                for (k, v) in &tombstones {
                    g.local.files.insert(k.clone(), v.clone());
                }
                g.tombstones = tombstones;
            }
            let dirs = p.load_sync_dirs();
            if !dirs.is_empty() {
                g.dirs = dirs;
            }
        }
        s
    }

    /// 平台层推入一次扫描结果。传入的清单会被原样保存
    /// （调用方应先经 [`crate::sync::manifest::build_manifest`] 归一化），
    /// 并把本端产生过的墓碑合并回来（WB-0426）。
    pub async fn set_local_manifest(&self, m: Manifest) {
        let mut g = self.inner.lock().await;
        let mut m = m;
        for (p, e) in &g.tombstones {
            m.files.insert(p.clone(), e.clone());
        }
        g.local = m;
    }

    pub async fn local_manifest(&self) -> Manifest {
        self.inner.lock().await.local.clone()
    }

    /// 记录"本次同步已成功"的快照，供下一轮三路对比使用。
    ///
    /// S10：同步写穿到磁盘（失败只告警，绝不让同步流程报错 —— 持久化是增强，
    /// 不是正确性前提；下次成功同步会再覆盖）。
    pub async fn set_snapshot(&self, m: Manifest) {
        self.inner.lock().await.snapshot = Some(m.clone());
        if let Some(p) = &self.persist {
            p.write_last_manifest(&m);
        }
    }

    pub async fn snapshot(&self) -> Option<Manifest> {
        self.inner.lock().await.snapshot.clone()
    }

    pub async fn put_mapping(&self, device_id: &str, m: DirMapping) {
        let mut g = self.inner.lock().await;
        g.dirs.insert(device_id.to_string(), m);
        // WB-0416：写穿持久化。失败只告警 —— 映射是"约定"不是正确性前提，
        // 重启后丢失的代价是重新登记一次，不该让同步请求 500。
        if let Some(p) = &self.persist {
            p.write_sync_dirs(&g.dirs);
        }
    }

    pub async fn mapping(&self, device_id: &str) -> Option<DirMapping> {
        self.inner.lock().await.dirs.get(device_id).cloned()
    }

    /// 假删除：把清单里的 `normalized` 搬到 `delete/<normalized>`。
    ///
    /// **幂等**：已在 `delete/` 下的路径返回 [`MoveOutcome::AlreadyDeleted`]
    /// 而不是报错 —— 镜像模式会重试，报错会让"删除"这一步永远重试不过去；
    /// 而重复搬移会搬出 `delete/delete/...` 的嵌套（实测问题 5 的另一种形态）。
    pub async fn move_to_delete(&self, normalized: &str) -> MoveOutcome {
        if is_in_delete_dir(normalized) {
            return MoveOutcome::AlreadyDeleted;
        }
        let mut g = self.inner.lock().await;
        let tomb = tombstone_path(normalized);
        match g.local.files.remove(normalized) {
            Some(entry) => {
                g.local.files.insert(tomb.clone(), entry.clone());
                // WB-0426：记入墓碑集合并写穿 —— 重启后重扫合并，永不复活
                g.tombstones.insert(tomb.clone(), entry);
                if let Some(p) = &self.persist {
                    p.write_tombstones(&g.tombstones);
                }
                MoveOutcome::Moved(tomb)
            }
            // 源不在了但墓碑已存在 → 上一次已经搬完，属幂等重放
            None if g.local.files.contains_key(&tomb) => MoveOutcome::AlreadyDeleted,
            None => MoveOutcome::NotFound,
        }
    }
}

/// 对端是否可以进行同步类操作。
///
/// 判据统一走状态机的 [`allows_transfer`]，**不在这里另写 `== Active`** ——
/// 那会在状态机之外又生出一份"什么状态算可用"的判据（登记表 E10）。
///
/// 未配对设备一律 401：清单会暴露备份根下的完整文件列表与大小，
/// 是同网段可见的敏感信息，不能只靠"你猜不到端口"来保护。
async fn require_transferable(
    store: &Arc<SessionStore>,
    device_id: &str,
) -> Result<(), super::ErrResponse> {
    match store.peers.entry(device_id).await {
        Some(p) if allows_transfer(p.trust.state) => Ok(()),
        Some(p) => Err(Box::new(err_response(
            ErrorCode::Untrusted,
            &format!(
                "当前配对状态 {:?} 不允许同步操作：请先完成配对",
                p.trust.state
            ),
        ))),
        None => Err(Box::new(err_response(
            ErrorCode::UnknownDevice,
            "设备未配对：请先完成配对",
        ))),
    }
}

/// `GET /api/v4/manifest` —— 交出本端清单。**纯读**。
///
/// 含 `delete/` 下的墓碑（见模块文档）。
pub async fn handle_manifest(
    store: &Arc<SessionStore>,
    path: &str,
) -> Response<Full<bytes::Bytes>> {
    let q = match parse_query(path) {
        Ok(q) => q,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    let device_id = match q.get("deviceId") {
        Some(s) => s.clone(),
        None => return err_response(ErrorCode::BadRequest, "缺少 deviceId 参数"),
    };
    if let Err(resp) = require_transferable(store, &device_id).await {
        return *resp;
    }
    ok_json(store.sync.local_manifest().await)
}

/// `GET /api/v4/chunk-status` —— 单文件块状态。**纯读**。
///
/// 两个字段各自踩过一次坑，实现时必须照下面的语义来：
///
/// - `nextChunk` 是**第一个缺失块的下标**，不是"已收块数"。
///   三代实现的 Java 侧返回 `chunks.length()`：一旦块乱序到达
///   （并发上传的常态），已收 3 块而缺的是 0 号，它会回 3，
///   发送端从 3 号继续 —— 0/1/2 号永远补不上，文件永久残缺。
/// - `fileComplete` 必须真的会为 `true`。Java 侧此字段恒为 `false`，
///   于是发送端永远得不到"可以收尾了"的信号，只能靠超时猜。
///
/// 完整性判据复用 [`file_incomplete_reason`]，与 `session/verify`、
/// `session/diff` 同源 —— 三处各写一份"算不算完整"必然漂移。
pub async fn handle_chunk_status(
    store: &Arc<SessionStore>,
    path: &str,
) -> Response<Full<bytes::Bytes>> {
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
    // WB-0401：块状态与 diff 同源 —— 能推断文件大小与传输进度，生产模式必须
    // 带 prepare 签发的文件 token，不能"知道 sessionId 就能查"。
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

    let total = piece_count(meta.size);
    let confirmed = rec.confirmed.get(&file_id);
    let has = |i: &u64| confirmed.map(|c| c.contains(i)).unwrap_or(false);

    // HashSet 迭代序随机，必须排序：同一状态两次查询给出不同顺序，
    // 会让发送端的"下一块"决策在重试之间跳来跳去。
    let mut received: Vec<u64> = (0..total).filter(has).collect();
    received.sort_unstable();

    // 第一个缺失块；全到齐则指向 total（越过末尾 = 没有下一块要传了）
    let next_chunk = (0..total).find(|i| !has(i)).unwrap_or(total);
    let file_complete = file_incomplete_reason(rec, &file_id).is_none();

    ok_json(ChunkStatusResponse {
        received_chunks: received,
        next_chunk,
        file_complete,
    })
}

/// `POST /api/v4/sync-dir` —— 登记目录映射，并交出本端清单。
///
/// `targetDir` 会被拼进真实落盘路径，因此**必须过路径安全校验**：
/// 一个 `../../` 就能让对端指定把文件写到备份根之外。
///
/// 响应带上本端清单，是为了让发起端一次往返就能跑三路对比
/// （它已有本机当前清单与上次快照，缺的就是这一份）。
pub async fn handle_sync_dir(
    store: &Arc<SessionStore>,
    body: &[u8],
) -> Response<Full<bytes::Bytes>> {
    let req: SyncDirRequest = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    if let Err(resp) = require_transferable(store, &req.device_id).await {
        return *resp;
    }
    if req.root_id.is_empty() || req.root_id.len() > 128 {
        return err_response(ErrorCode::BadRequest, "rootId 长度非法（1..=128）");
    }

    let target = match validate_rel_path(&req.target_dir) {
        Ok(t) => t,
        Err(e) => {
            return err_response(
                ErrorCode::BadRequest,
                &format!("targetDir 不安全（{:?}）：{e}", req.target_dir),
            )
        }
    };
    // 接收目录不能是（或落在）假删除目录：那会让正常接收的文件与墓碑混在一起，
    // 下一轮对比就把刚收到的文件当成"用户已删除"。
    if is_in_delete_dir(&target) {
        return err_response(
            ErrorCode::BadRequest,
            "targetDir 不得使用 `delete/`：该目录是假删除专用，混用会让新收到的文件被当成墓碑",
        );
    }

    let mapping = DirMapping {
        root_id: req.root_id.clone(),
        target_dir: target.clone(),
        strategy: req.strategy,
    };
    store.sync.put_mapping(&req.device_id, mapping).await;

    ok_json(SyncDirResponse {
        device_id: req.device_id,
        root_id: req.root_id,
        target_dir: target,
        strategy: req.strategy,
        // 发起端据此跑 sync::plan::decide 的第三路
        peer_manifest: store.sync.local_manifest().await,
    })
}

/// `POST /api/v4/move-to-delete` —— 假删除（移入 `delete/`，**不真删**）。
///
/// 逐条给出结果而不是"全成功/全失败"：一批里既有能搬的、也有本端根本没有的，
/// 整批失败会让对端无从判断该重试哪些；静默成功则会掩盖路径被拒的事实。
pub async fn handle_move_to_delete(
    store: &Arc<SessionStore>,
    body: &[u8],
) -> Response<Full<bytes::Bytes>> {
    let req: MoveToDeleteRequest = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };
    // WB-0427：批量上限 —— 锁内逐条搬移，无上限的请求会把清单锁攥在手里。
    if req.rel_paths.len() > MAX_MOVE_PATHS {
        return err_response(
            ErrorCode::BadRequest,
            &format!("单批 relPaths 超过上限（{MAX_MOVE_PATHS}）"),
        );
    }
    if let Err(resp) = require_transferable(store, &req.device_id).await {
        return *resp;
    }

    let base_dir = store.base_dir.read().unwrap().clone();
    let mut moved = Vec::new();
    let mut skipped = Vec::new();
    let mut rejected = Vec::new();
    for raw in &req.rel_paths {
        // 不安全路径**显式上报**，不静默丢弃：删除动作作用在真实文件系统上，
        // 悄悄跳过会让用户以为删掉了。
        let p = match validate_rel_path(raw) {
            Ok(p) => p,
            Err(_) => {
                rejected.push(raw.clone());
                continue;
            }
        };
        // WB-0423：清单与磁盘必须同源。只改清单会让"已删除"停留在内存投影，
        // 磁盘文件还在 —— 重启后重扫把它带回清单，对端再把文件传回来。
        // 磁盘搬移失败必须显式 rejected，不得冒充 moved。
        if let Err(e) = move_file_to_delete_dir(&base_dir, &p) {
            log::warn!(
                "假删除磁盘搬移失败 device={} file={} : {e}",
                req.device_id,
                p
            );
            rejected.push(raw.clone());
            continue;
        }
        match store.sync.move_to_delete(&p).await {
            MoveOutcome::Moved(t) => moved.push(t),
            MoveOutcome::AlreadyDeleted | MoveOutcome::NotFound => skipped.push(p),
        }
    }
    // 输入顺序不定（对端可能来自 HashMap 迭代），排序保证同一请求同一响应
    moved.sort();
    skipped.sort();
    rejected.sort();

    ok_json(MoveToDeleteResponse {
        device_id: req.device_id,
        moved,
        skipped,
        rejected,
    })
}

/// 单批假删除路径数上限（WB-0427）。
const MAX_MOVE_PATHS: usize = 1000;

/// 把 `base_dir/<rel>` 物理搬入 `base_dir/delete/<rel>`（同盘 rename，原子）。
///
/// - 源不存在 → `Ok(())`：清单里的条目仍要搬成墓碑（对端需要知道"这是有意删除"）；
/// - 目标已存在 → `Ok(())`：上次已搬完（幂等重放）；
/// - 其余失败（占用/权限）→ `Err`：调用方必须报 rejected。
fn move_file_to_delete_dir(base_dir: &std::path::Path, rel: &str) -> std::io::Result<()> {
    let join = |p: &str| {
        if base_dir.as_os_str().is_empty() {
            PathBuf::from(p)
        } else {
            base_dir.join(p)
        }
    };
    let src = join(rel);
    if !src.exists() {
        return Ok(());
    }
    let dst = join("delete").join(rel);
    if dst.exists() {
        return Ok(());
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(&src, &dst)
}

/// `POST /api/v4/disconnect` —— 断开连接。
///
/// # 断开**不是**解配对
///
/// 这是本端点唯一需要想清楚的事。断开只表示"这条链路先不用了"：
/// 把在线状态置为离线、把进行中的会话按状态机收尾。
/// **配对状态一个字都不能动。**
///
/// 若顺手把 `trust` 也清掉，用户每次退出 App / 切个 Wi-Fi 都会掉配对，
/// 下次连接又要重新输连接码 —— 这就是三代那个"连一次要配一次"的体验。
/// 解除配对有专门的 `unpair` / `revoke-*` 端点，走签名与 ack，不在此处。
///
/// 终态会话不参与：对已 `Completed` 的会话再发 `Abort` 是非法迁移，
/// 会让"断开"这个必然成功的动作变成 409。
pub async fn handle_disconnect(
    store: &Arc<SessionStore>,
    body: &[u8],
) -> Response<Full<bytes::Bytes>> {
    let req: DisconnectRequest = match parse_body(body) {
        Ok(r) => r,
        Err(e) => return err_response(ErrorCode::BadRequest, &e),
    };

    // WB-0431：断开会中止该设备全部在途会话，必须先证明这是台受信设备 ——
    // 未配对/已吊销设备发来的 disconnect 一律拒绝。
    if let Err(resp) = require_transferable(store, &req.device_id).await {
        return *resp;
    }

    let mut rec = match store.peers.entry(&req.device_id).await {
        Some(r) => r,
        None => return err_response(ErrorCode::UnknownDevice, "未知设备"),
    };
    // 配对状态原样保留 —— 断开只动在线性
    let pairing_state = rec.trust.state;
    rec.presence = Presence::Offline;
    store.peers.put(rec).await;

    // 收尾该设备名下进行中的会话
    let mut aborted = Vec::new();
    let mut guard = store.inner.lock().await;
    for (sid, s) in guard.iter_mut() {
        if s.device_id != req.device_id || s.phase.is_terminal() {
            continue;
        }
        if let Ok(next) = s.phase.transition(TransferEvent::Abort) {
            s.phase = next;
            // 写穿持久化 + 清理终态会话的磁盘行
            if let Some(p) = &store.persist {
                p.update_session(
                    sid,
                    s.phase,
                    s.algorithm,
                    s.degrade_reason,
                    s.bitmap_version,
                );
                p.remove_session(sid);
            }
            aborted.push(sid.clone());
        }
    }
    drop(guard);
    aborted.sort();

    ok_json(DisconnectResponse {
        device_id: req.device_id,
        // 明确回传：断开之后配对关系仍在
        pairing_state,
        presence: Presence::Offline,
        aborted_sessions: aborted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::StatusCode;
    use serde_json::json;
    use crate::dto::handshake::PairingState;
    use crate::dto::sync::ManifestEntry;
    use crate::dto::DeviceType;
    use crate::identity::DeviceIdentity;
    use crate::pairing::machine::PairingEvent;
    use crate::pairing::trust::TrustRecord;
    use crate::server::control::PeerRecord;
    use crate::server::route;
    use crate::state::transfer::TransferState;
    use hyper::Method;

    fn app() -> Arc<SessionStore> {
        let s = SessionStore::with_identity(DeviceIdentity::generate(), "srv", DeviceType::Desktop);
        let dir = std::env::temp_dir().join(format!("lanbak-sync-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&dir);
        s.with_base_dir(dir);
        s
    }

    fn active_trust() -> TrustRecord {
        let mut t = TrustRecord::new();
        t.apply(PairingEvent::Initiate).unwrap();
        t.apply(PairingEvent::PeerConfirmed).unwrap();
        t
    }

    /// 登记一个 Active 对端
    async fn pair(s: &Arc<SessionStore>, id: &str) {
        s.peers
            .put(PeerRecord::new(
                id,
                "",
                vec![],
                vec![9u8; 32],
                active_trust(),
            ))
            .await;
    }

    fn entry(size: u64, mtime: i64) -> ManifestEntry {
        ManifestEntry { size, mtime }
    }

    #[tokio::test]
    async fn s10_last_manifest_survives_store_restart() {
        use crate::server::persist::SessionPersister;
        let dir = std::env::temp_dir().join(format!("lanbak-s10-{}", uuid::Uuid::new_v4()));
        let p = SessionPersister::open(&dir).unwrap();

        // 第一次"进程"：写快照
        let m1 = crate::sync::manifest::build_manifest(
            "srv",
            1700,
            [("a.txt".to_string(), entry(7, 8))],
        );
        p.write_last_manifest(&m1);

        // 第二次"进程"：from 同一目录重载，快照必须还在
        let p2 = SessionPersister::open(&dir).unwrap();
        let loaded = p2.load_last_manifest().expect("重载 last-manifest");
        assert_eq!(loaded.generated_at, 1700);
        assert_eq!(loaded.files.len(), 1);
        assert!(loaded.files.contains_key("a.txt"));

        // SyncStore 级验证：with_persist 后 snapshot 直接可用（不退化全量）
        let store = SyncStore::with_persist(Some(Arc::new(p2)));
        let snap = store.snapshot().await.expect("快照应被冷启动重载");
        assert_eq!(snap.files.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn seed_manifest(s: &Arc<SessionStore>, files: &[(&str, u64, i64)]) {
        let m = crate::sync::manifest::build_manifest(
            "srv",
            1700,
            files
                .iter()
                .map(|(p, sz, mt)| ((*p).to_string(), entry(*sz, *mt))),
        );
        s.sync.set_local_manifest(m).await;
    }

    async fn body_json(r: Response<Full<bytes::Bytes>>) -> serde_json::Value {
        use http_body_util::BodyExt;
        let b = r.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&b).unwrap()
    }

    fn bytes(v: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&v).unwrap()
    }

    // ── manifest ────────────────────────────────────────────────

    #[tokio::test]
    async fn manifest_requires_pairing() {
        let s = app();
        seed_manifest(&s, &[("a.txt", 1, 1)]).await;
        // 未配对设备不得列举备份内容
        let r = route(&s, Method::GET, "/api/v4/manifest?deviceId=ghost", &[]).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);

        // 已解除的设备同样不行
        let mut t = active_trust();
        t.apply(PairingEvent::PeerUnpair).unwrap();
        s.peers
            .put(PeerRecord::new("gone", "", vec![], vec![], t))
            .await;
        let r = route(&s, Method::GET, "/api/v4/manifest?deviceId=gone", &[]).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn manifest_missing_device_id_is_400() {
        let s = app();
        let r = route(&s, Method::GET, "/api/v4/manifest", &[]).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn manifest_returns_normalized_entries() {
        let s = app();
        pair(&s, "p1").await;
        seed_manifest(&s, &[(r".\photos\a.jpg", 10, 100)]).await;
        let v = body_json(route(&s, Method::GET, "/api/v4/manifest?deviceId=p1", &[]).await).await;
        assert_eq!(v["files"]["photos/a.jpg"]["size"], json!(10));
        assert_eq!(v["deviceCode"], json!("srv"));
    }

    /// 墓碑必须出现在交出去的清单里，否则发起端会把用户删掉的文件补回来。
    #[tokio::test]
    async fn manifest_exposes_tombstones_so_peer_does_not_resurrect() {
        let s = app();
        pair(&s, "p1").await;
        seed_manifest(&s, &[("photo.jpg", 100, 500)]).await;
        route(
            &s,
            Method::POST,
            "/api/v4/move-to-delete",
            &bytes(json!({"deviceId":"p1","relPaths":["photo.jpg"]})),
        )
        .await;

        let v = body_json(route(&s, Method::GET, "/api/v4/manifest?deviceId=p1", &[]).await).await;
        assert!(
            v["files"]["delete/photo.jpg"].is_object(),
            "清单里没有墓碑：发起端将把用户删掉的文件判为 heal_missing 并复活它"
        );
        assert!(v["files"]["photo.jpg"].is_null(), "原路径应已被搬走");

        // 用真实的三路对比验证"不复活"确实成立
        let local = crate::sync::manifest::build_manifest(
            "peer",
            1700,
            [("photo.jpg".to_string(), entry(100, 500))],
        );
        let peer: Manifest = serde_json::from_value(v).unwrap();
        let d = crate::sync::decide(&local, Some(&local), &peer, SyncStrategy::Archive);
        assert_eq!(d.tombstoned, vec!["photo.jpg"]);
        assert!(d.plan.heal_missing.is_empty());
        assert!(d.is_noop());
    }

    // ── chunk-status ────────────────────────────────────────────

    /// 建一个会话，文件大小取 `size`，并确认给定的块。
    async fn session_with(s: &Arc<SessionStore>, size: u64, confirm: &[u64]) {
        route(
            s,
            Method::POST,
            "/api/v4/session/register",
            &bytes(json!({"deviceId":"p1","alias":"a","sessionId":"s1"})),
        )
        .await;
        route(
            s,
            Method::POST,
            "/api/v4/session/prepare",
            &bytes(json!({
                "sessionId":"s1","deviceId":"p1",
                "files":{"f1":{"fileId":"f1","fileName":"x","relPath":"x","size":size,"mtime":1}}
            })),
        )
        .await;
        for i in confirm {
            let offset = i * crate::transfer::chunk::PIECE_SIZE;
            let len = (size - offset).min(crate::transfer::chunk::PIECE_SIZE) as usize;
            let data = vec![0u8; len];
            route(
                s,
                Method::POST,
                &format!("/api/v4/session/chunk?sessionId=s1&fileId=f1&pieceIndex={i}"),
                &data,
            )
            .await;
        }
    }

    /// `nextChunk` 必须是**第一个缺失块**，不是已收块数。
    ///
    /// 乱序到达时这两个数不同，取错就会跳过前面的洞，文件永久残缺。
    #[tokio::test]
    async fn next_chunk_is_first_missing_not_received_count() {
        let s = app();
        pair(&s, "p1").await;
        // 4 块；只收到 1、2、3，缺 0
        let size = crate::transfer::chunk::PIECE_SIZE * 3 + 1;
        session_with(&s, size, &[1, 2, 3]).await;
        let v = body_json(
            route(
                &s,
                Method::GET,
                "/api/v4/chunk-status?sessionId=s1&fileId=f1",
                &[],
            )
            .await,
        )
        .await;
        assert_eq!(
            v["nextChunk"],
            json!(0),
            "返回了已收块数而非第一个缺失块 —— 发送端会跳过 0 号，文件永久残缺"
        );
        assert_eq!(v["receivedChunks"], json!([1, 2, 3]));
        assert_eq!(v["fileComplete"], json!(false));
    }

    /// `fileComplete` 必须真的会为 true，否则发送端永远等不到收尾信号。
    #[tokio::test]
    async fn file_complete_becomes_true_and_next_chunk_passes_the_end() {
        let s = app();
        pair(&s, "p1").await;
        let size = crate::transfer::chunk::PIECE_SIZE * 2; // 恰好 2 块
        session_with(&s, size, &[0, 1]).await;
        let v = body_json(
            route(
                &s,
                Method::GET,
                "/api/v4/chunk-status?sessionId=s1&fileId=f1",
                &[],
            )
            .await,
        )
        .await;
        assert_eq!(v["fileComplete"], json!(true));
        assert_eq!(v["nextChunk"], json!(2), "全到齐时应指向越过末尾的下标");
        assert_eq!(v["receivedChunks"], json!([0, 1]));
    }

    #[tokio::test]
    async fn chunk_status_unknown_session_and_file_are_404() {
        let s = app();
        pair(&s, "p1").await;
        let r = route(
            &s,
            Method::GET,
            "/api/v4/chunk-status?sessionId=nope&fileId=f1",
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);

        session_with(&s, 100, &[]).await;
        let r = route(
            &s,
            Method::GET,
            "/api/v4/chunk-status?sessionId=s1&fileId=ghost",
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn chunk_status_requires_both_params() {
        let s = app();
        for p in [
            "/api/v4/chunk-status",
            "/api/v4/chunk-status?sessionId=s1",
            "/api/v4/chunk-status?fileId=f1",
        ] {
            assert_eq!(
                route(&s, Method::GET, p, &[]).await.status(),
                StatusCode::BAD_REQUEST,
                "{p} 缺参数却没报 400"
            );
        }
    }

    // ── sync-dir ────────────────────────────────────────────────

    #[tokio::test]
    async fn sync_dir_records_mapping_and_returns_peer_manifest() {
        let s = app();
        pair(&s, "p1").await;
        seed_manifest(&s, &[("a.txt", 3, 4)]).await;
        let v = body_json(
            route(
                &s,
                Method::POST,
                "/api/v4/sync-dir",
                &bytes(json!({
                    "deviceId":"p1","rootId":"root-1",
                    "targetDir":r".\Backup\Phone\","strategy":"mirror"
                })),
            )
            .await,
        )
        .await;
        assert_eq!(
            v["targetDir"],
            json!("Backup/Phone"),
            "targetDir 应已归一化"
        );
        assert_eq!(v["strategy"], json!("mirror"));
        assert_eq!(v["peerManifest"]["files"]["a.txt"]["size"], json!(3));

        let m = s.sync.mapping("p1").await.unwrap();
        assert_eq!(m.target_dir, "Backup/Phone");
        assert_eq!(m.root_id, "root-1");
        assert_eq!(m.strategy, SyncStrategy::Mirror);
    }

    /// `targetDir` 会被拼进真实落盘路径，穿越必须被拒。
    #[tokio::test]
    async fn sync_dir_rejects_traversal_target() {
        let s = app();
        pair(&s, "p1").await;
        for bad in ["../../etc", r"..\..\evil", "C:/Windows", ""] {
            let r = route(
                &s,
                Method::POST,
                "/api/v4/sync-dir",
                &bytes(json!({
                    "deviceId":"p1","rootId":"r","targetDir":bad,"strategy":"archive"
                })),
            )
            .await;
            assert_eq!(
                r.status(),
                StatusCode::BAD_REQUEST,
                "targetDir={bad:?} 竟被接受 —— 对端可写到备份根之外"
            );
            assert!(s.sync.mapping("p1").await.is_none(), "被拒仍写入了映射");
        }
    }

    #[tokio::test]
    async fn sync_dir_rejects_delete_dir_as_target() {
        let s = app();
        pair(&s, "p1").await;
        for bad in ["delete", "delete/sub", r"delete\sub"] {
            let r = route(
                &s,
                Method::POST,
                "/api/v4/sync-dir",
                &bytes(json!({
                    "deviceId":"p1","rootId":"r","targetDir":bad,"strategy":"archive"
                })),
            )
            .await;
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "targetDir={bad:?}");
        }
    }

    #[tokio::test]
    async fn sync_dir_requires_pairing() {
        let s = app();
        let r = route(
            &s,
            Method::POST,
            "/api/v4/sync-dir",
            &bytes(json!({
                "deviceId":"ghost","rootId":"r","targetDir":"d","strategy":"archive"
            })),
        )
        .await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    // ── move-to-delete ──────────────────────────────────────────

    #[tokio::test]
    async fn move_to_delete_is_idempotent_and_never_nests() {
        let s = app();
        pair(&s, "p1").await;
        seed_manifest(&s, &[("a.txt", 1, 1)]).await;
        let call = |paths: serde_json::Value| {
            let s = s.clone();
            async move {
                body_json(
                    route(
                        &s,
                        Method::POST,
                        "/api/v4/move-to-delete",
                        &bytes(json!({"deviceId":"p1","relPaths":paths})),
                    )
                    .await,
                )
                .await
            }
        };

        let v = call(json!(["a.txt"])).await;
        assert_eq!(v["moved"], json!(["delete/a.txt"]));

        // 重放同一请求：仍 200，且不得产生 delete/delete/a.txt
        let v = call(json!(["a.txt"])).await;
        assert_eq!(v["moved"], json!([]));
        assert_eq!(v["skipped"], json!(["a.txt"]));

        // 直接给已在 delete/ 下的路径同样不得嵌套
        let v = call(json!(["delete/a.txt"])).await;
        assert_eq!(v["moved"], json!([]));

        let m = s.sync.local_manifest().await;
        assert!(m.files.contains_key("delete/a.txt"));
        assert!(
            !m.files.contains_key("delete/delete/a.txt"),
            "出现了嵌套墓碑 delete/delete/…"
        );
        assert_eq!(m.files.len(), 1);
    }

    #[tokio::test]
    async fn move_to_delete_reports_unsafe_paths_instead_of_dropping_them() {
        let s = app();
        pair(&s, "p1").await;
        seed_manifest(&s, &[("ok.txt", 1, 1)]).await;
        let v = body_json(
            route(
                &s,
                Method::POST,
                "/api/v4/move-to-delete",
                &bytes(json!({
                    "deviceId":"p1",
                    "relPaths":["../escape.txt","ok.txt","C:/Windows/x","ghost.txt"]
                })),
            )
            .await,
        )
        .await;
        assert_eq!(v["moved"], json!(["delete/ok.txt"]));
        assert_eq!(v["rejected"], json!(["../escape.txt", "C:/Windows/x"]));
        // 本端没有的文件如实报 skipped，不冒充成功
        assert_eq!(v["skipped"], json!(["ghost.txt"]));
    }

    #[tokio::test]
    async fn move_to_delete_preserves_size_and_mtime() {
        let s = app();
        pair(&s, "p1").await;
        seed_manifest(&s, &[("a.txt", 123, 456)]).await;
        route(
            &s,
            Method::POST,
            "/api/v4/move-to-delete",
            &bytes(json!({"deviceId":"p1","relPaths":["a.txt"]})),
        )
        .await;
        let m = s.sync.local_manifest().await;
        let e = m.files.get("delete/a.txt").unwrap();
        assert_eq!((e.size, e.mtime), (123, 456), "墓碑丢了原始元数据");
    }

    #[tokio::test]
    async fn move_to_delete_requires_pairing() {
        let s = app();
        let r = route(
            &s,
            Method::POST,
            "/api/v4/move-to-delete",
            &bytes(json!({"deviceId":"ghost","relPaths":["a"]})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    // ── disconnect ──────────────────────────────────────────────

    /// 断开**不得**动配对状态 —— 否则切个 Wi-Fi 就要重新输连接码。
    #[tokio::test]
    async fn disconnect_keeps_the_pairing_intact() {
        let s = app();
        pair(&s, "p1").await;
        let v = body_json(
            route(
                &s,
                Method::POST,
                "/api/v4/disconnect",
                &bytes(json!({"deviceId":"p1"})),
            )
            .await,
        )
        .await;
        assert_eq!(v["pairingState"], json!("active"));
        assert_eq!(v["presence"], json!("offline"));

        let rec = s.peers.entry("p1").await.unwrap();
        assert_eq!(
            rec.trust.state,
            PairingState::Active,
            "断开把配对关系也清掉了 —— 这是「连一次要配一次」的成因"
        );
        assert_eq!(rec.presence, Presence::Offline);
    }

    #[tokio::test]
    async fn disconnect_aborts_only_live_sessions() {
        let s = app();
        pair(&s, "p1").await;
        pair(&s, "p2").await;
        session_with(&s, 100, &[]).await; // s1 属于 p1，处于 Preparing
                                          // 另建一个属于 p2 的会话，不应被 p1 的断开影响
        route(
            &s,
            Method::POST,
            "/api/v4/session/register",
            &bytes(json!({"deviceId":"p2","alias":"b","sessionId":"s2"})),
        )
        .await;
        // 再建一个已终态的会话，不得因非法迁移让整个断开失败
        route(
            &s,
            Method::POST,
            "/api/v4/session/register",
            &bytes(json!({"deviceId":"p1","alias":"a","sessionId":"s3"})),
        )
        .await;
        route(
            &s,
            Method::POST,
            "/api/v4/session/abort",
            &bytes(json!({"sessionId":"s3"})),
        )
        .await;

        let r = route(
            &s,
            Method::POST,
            "/api/v4/disconnect",
            &bytes(json!({"deviceId":"p1"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK, "终态会话让断开返回了非 200");
        let v = body_json(r).await;
        assert_eq!(v["abortedSessions"], json!(["s1"]));

        let g = s.inner.lock().await;
        assert_eq!(g.get("s1").unwrap().phase, TransferState::Aborted);
        assert_eq!(
            g.get("s2").unwrap().phase,
            TransferState::Preparing,
            "误伤了别的设备的会话"
        );
        assert_eq!(g.get("s3").unwrap().phase, TransferState::Aborted);
    }

    #[tokio::test]
    async fn disconnect_unknown_device_is_404() {
        let s = app();
        let r = route(
            &s,
            Method::POST,
            "/api/v4/disconnect",
            &bytes(json!({"deviceId":"ghost"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    /// 断开是幂等的：重复断开仍 200，且不产生新的 abort。
    #[tokio::test]
    async fn disconnect_is_idempotent() {
        let s = app();
        pair(&s, "p1").await;
        session_with(&s, 100, &[]).await;
        let first = body_json(
            route(
                &s,
                Method::POST,
                "/api/v4/disconnect",
                &bytes(json!({"deviceId":"p1"})),
            )
            .await,
        )
        .await;
        assert_eq!(first["abortedSessions"], json!(["s1"]));
        let second = body_json(
            route(
                &s,
                Method::POST,
                "/api/v4/disconnect",
                &bytes(json!({"deviceId":"p1"})),
            )
            .await,
        )
        .await;
        assert_eq!(second["abortedSessions"], json!([]));
        assert_eq!(second["pairingState"], json!("active"));
    }

    // ── 区域二：会话闸 / 生产模式认证 / 真实假删除 ───────────────

    /// WB-0297：单设备会话数上限 —— 第 9 个会话必须被拒，洪泛不得撑爆会话表；
    /// 其他设备不受影响。
    #[tokio::test]
    async fn register_enforces_per_peer_session_cap() {
        let s = app();
        pair(&s, "p1").await;
        for i in 0..8 {
            let r = route(
                &s,
                Method::POST,
                "/api/v4/session/register",
                &bytes(json!({"deviceId":"p1","alias":"a","sessionId":format!("cap-{i}")})),
            )
            .await;
            assert_eq!(r.status(), StatusCode::OK, "第 {} 个会话应成功", i + 1);
        }
        let r = route(
            &s,
            Method::POST,
            "/api/v4/session/register",
            &bytes(json!({"deviceId":"p1","alias":"a","sessionId":"cap-overflow"})),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::CONFLICT,
            "第 9 个会话必须被上限闸拒绝"
        );
        pair(&s, "p2").await;
        let r = route(
            &s,
            Method::POST,
            "/api/v4/session/register",
            &bytes(json!({"deviceId":"p2","alias":"b","sessionId":"p2-s1"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK, "上限按设备隔离，不得误伤他人");
    }

    /// WB-0302/0307：prepare 的大小与哈希数量闸。
    #[tokio::test]
    async fn prepare_enforces_size_and_hash_count_gates() {
        let s = app();
        pair(&s, "p1").await;
        route(
            &s,
            Method::POST,
            "/api/v4/session/register",
            &bytes(json!({"deviceId":"p1","alias":"a","sessionId":"s1"})),
        )
        .await;
        // 单文件超过 512GiB 上限
        let r = route(
            &s,
            Method::POST,
            "/api/v4/session/prepare",
            &bytes(json!({
                "sessionId":"s1","deviceId":"p1",
                "files":{"big":{"fileId":"big","fileName":"b","relPath":"b","size":549755813889i64,"mtime":1}}
            })),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "单文件超上限必须 400");

        // pieceHashes 数量与 piece 数不符（size=100 → 1 piece）
        let fake = "a".repeat(64);
        let r = route(
            &s,
            Method::POST,
            "/api/v4/session/prepare",
            &bytes(json!({
                "sessionId":"s1","deviceId":"p1",
                "files":{"f1":{"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1,
                                "pieceHashes":[fake, fake]}}
            })),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::BAD_REQUEST,
            "哈希数量与 piece 数不符必须 400，否则逐块比对系统性错位"
        );
    }

    /// WB-0353/0354：终态会话心跳被拒；位图版本由服务端权威自增。
    #[tokio::test]
    async fn heartbeat_rejects_terminal_and_version_is_server_authoritative() {
        let s = app();
        pair(&s, "p1").await;
        session_with(&s, 100, &[]).await;
        let v1 = body_json(
            route(
                &s,
                Method::POST,
                "/api/v4/session/heartbeat",
                &bytes(json!({"sessionId":"s1","bitmapVersion":999})),
            )
            .await,
        )
        .await;
        assert_eq!(
            v1["bitmapVersion"],
            json!(1),
            "客户端自报 999 不得推高服务端版本"
        );
        let v2 = body_json(
            route(
                &s,
                Method::POST,
                "/api/v4/session/heartbeat",
                &bytes(json!({"sessionId":"s1","bitmapVersion":0})),
            )
            .await,
        )
        .await;
        assert_eq!(v2["bitmapVersion"], json!(2), "重复心跳每次只 +1，重放不推进多格");

        route(
            &s,
            Method::POST,
            "/api/v4/session/abort",
            &bytes(json!({"sessionId":"s1"})),
        )
        .await;
        let r = route(
            &s,
            Method::POST,
            "/api/v4/session/heartbeat",
            &bytes(json!({"sessionId":"s1","bitmapVersion":5})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::CONFLICT, "终态会话不得靠心跳永生");
    }

    /// WB-0423/0426：假删除必须真的把磁盘文件搬进 delete/，
    /// 且墓碑在重启 + 重扫后仍在 —— 否则用户删掉的文件会被复活。
    #[tokio::test]
    async fn move_to_delete_moves_the_real_file_and_tombstone_survives_restart() {
        let dir = std::env::temp_dir().join(format!("lanbak-tomb-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = SessionStore::open(DeviceIdentity::generate(), "srv", DeviceType::Desktop, Some(&dir));
        s.with_base_dir(dir.clone());
        s.peers
            .put(PeerRecord::new("p1", "", vec![], vec![9u8; 32], active_trust()))
            .await;
        std::fs::write(dir.join("a.txt"), b"data").unwrap();
        seed_manifest(&s, &[("a.txt", 4, 1)]).await;

        let v = body_json(
            route(
                &s,
                Method::POST,
                "/api/v4/move-to-delete",
                &bytes(json!({"deviceId":"p1","relPaths":["a.txt"]})),
            )
            .await,
        )
        .await;
        assert_eq!(v["moved"], json!(["delete/a.txt"]));
        assert!(!dir.join("a.txt").exists(), "磁盘文件必须真的搬走，不得只改清单");
        assert!(dir.join("delete").join("a.txt").exists(), "文件应落在 delete/ 下");

        // 重启：新进程 + 平台重扫（假设重扫结果为空表）→ 墓碑必须由持久化兜底
        let s2 = SessionStore::open(DeviceIdentity::generate(), "srv", DeviceType::Desktop, Some(&dir));
        s2.peers
            .put(PeerRecord::new("p1", "", vec![], vec![9u8; 32], active_trust()))
            .await;
        let rescanned = crate::sync::manifest::build_manifest(
            "srv",
            1701,
            Vec::<(String, ManifestEntry)>::new(),
        );
        s2.set_local_manifest(rescanned).await;
        let v = body_json(
            route(&s2, Method::GET, "/api/v4/manifest?deviceId=p1", &[]).await,
        )
        .await;
        assert!(
            v["files"]["delete/a.txt"].is_object(),
            "重启后墓碑丢失：下一轮三路对比会把用户删掉的文件复活"
        );
    }

    /// WB-0431：disconnect 是清场动作，未配对 404、已吊销 401。
    #[tokio::test]
    async fn disconnect_rejects_untrusted_devices() {
        let s = app();
        let r = route(
            &s,
            Method::POST,
            "/api/v4/disconnect",
            &bytes(json!({"deviceId":"ghost"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);

        let mut t = active_trust();
        t.apply(PairingEvent::PeerUnpair).unwrap();
        s.peers
            .put(PeerRecord::new("revoked", "", vec![], vec![], t))
            .await;
        let r = route(
            &s,
            Method::POST,
            "/api/v4/disconnect",
            &bytes(json!({"deviceId":"revoked"})),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "已吊销设备不得通过 disconnect 清掉在途会话"
        );
    }

    /// WB-0401：生产模式下 chunk-status 必须带 prepare 签发的文件 token。
    #[tokio::test]
    async fn chunk_status_requires_file_token_in_production_mode() {
        let s = app();
        s.with_require_active_peer(true);
        pair(&s, "p1").await;
        route(
            &s,
            Method::POST,
            "/api/v4/session/register",
            &bytes(json!({"deviceId":"p1","alias":"a","sessionId":"s1"})),
        )
        .await;
        let pr = body_json(
            route(
                &s,
                Method::POST,
                "/api/v4/session/prepare",
                &bytes(json!({
                    "sessionId":"s1","deviceId":"p1",
                    "files":{"f1":{"fileId":"f1","fileName":"x","relPath":"x","size":100,"mtime":1}}
                })),
            )
            .await,
        )
        .await;
        let token = pr["files"]["f1"].as_str().unwrap().to_string();

        let r = route(
            &s,
            Method::GET,
            "/api/v4/chunk-status?sessionId=s1&fileId=f1",
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "无 token 不得查询块状态");
        let r = route(
            &s,
            Method::GET,
            &format!("/api/v4/chunk-status?sessionId=s1&fileId=f1&token={token}"),
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK, "带正确 token 应放行");
        let r = route(
            &s,
            Method::GET,
            "/api/v4/chunk-status?sessionId=s1&fileId=f1&token=wrong",
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }
}
