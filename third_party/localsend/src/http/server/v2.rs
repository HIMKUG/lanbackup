use crate::http::dto_v2::{
    ChunkDiffDtoV2, InfoResponseDtoV2, PrepareUploadRequestDtoV2, PrepareUploadResponseDtoV2,
    RegisterDtoV2, RegisterResponseDtoV2,
};
use crate::http::server::common::collect_to_json::CollectToJson;
use crate::http::server::common::error::AppError;
use crate::http::server::common::pin::check_pin;
use crate::http::server::common::query::parse_query;
use crate::http::server::common::response::{empty_body, full_body, BoxedBody, JsonResponse};
use crate::http::server::common::save::{FileTimestamps, FileUploadTarget, SaveResult};
use crate::http::server::common::session::{
    FileStatusV2, PendingSessionV2, SessionFileV2, SessionStateV2, UploadSessionV2,
};
use crate::http::server::PeerIp;
use crate::http::server::{common, AppState, RequestClientInfo, V2State};
use crate::model::discovery::PROTOCOL_VERSION_V2;
use crate::model::transfer::FileDto;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Events emitted by the v2 HTTP server that must be handled by the application.
#[derive(Debug)]
pub enum ServerEventV2 {
    /// A device registered itself via `POST /api/localsend/v2/register`.
    ///
    /// On TLS, this event is only emitted when `info.fingerprint` matches the
    /// SHA-256 fingerprint of the client certificate verified during the mTLS
    /// handshake, so the fingerprint cannot be spoofed.
    Register {
        /// The IP address of the remote device.
        ip: PeerIp,

        /// The device information sent by the remote device.
        info: RegisterDtoV2,
    },

    /// A sender requests to upload files via `POST /api/localsend/v2/prepare-upload`.
    ///
    /// The application must answer on `decision_tx`.
    /// Dropping `decision_tx` results in a 500 response.
    PrepareUpload {
        /// The session ID the upload session will have when the request is
        /// accepted. Pre-generated so the application can track the session
        /// consistently from the start.
        session_id: String,

        /// The IP address of the sender.
        ip: PeerIp,

        /// The device information of the sender.
        info: RegisterDtoV2,

        /// The SHA-256 fingerprint (uppercase hex) of the sender's client
        /// certificate verified during the mTLS handshake. Unlike
        /// `info.fingerprint`, this value cannot be spoofed.
        /// `None` when the server runs without TLS.
        cert_fingerprint: Option<String>,

        /// The offered files, mapped by file ID.
        files: HashMap<String, FileDto>,

        /// 加密 v2 扩展：发送端 ECDH 公钥（复杂加密协商用，None = 简单加密/不加密）。
        /// 应用侧据此生成接收端密钥对、派生 session_key，并通过决策返回接收端公钥。
        sender_ecdh_pub: Option<String>,

        /// Channel to send the decision (accept all, a subset, or decline).
        decision_tx: oneshot::Sender<PrepareUploadDecisionV2>,
    },

    /// An accepted file is being uploaded via `POST /api/localsend/v2/upload`.
    ///
    /// The application must answer on `target_tx` with where the file content
    /// should go (a stream to consume itself, a path, or a file descriptor).
    /// Dropping `target_tx` results in a 500 response.
    FileUpload {
        /// The session ID of the upload session.
        session_id: String,

        /// The ID of the file being uploaded.
        file_id: String,

        /// The metadata of the file being uploaded.
        file: FileDto,

        /// Channel to send the target the file content should be written to.
        target_tx: oneshot::Sender<FileUploadTarget>,
    },

    /// An upload session ended.
    SessionEnd {
        /// The session ID of the ended session.
        session_id: String,

        /// Why the session ended.
        reason: SessionEndReasonV2,
    },

    /// A prepare-upload request was aborted before a session was created,
    /// e.g. the sender disconnected while the application was still deciding.
    /// The `decision_tx` of the [ServerEventV2::PrepareUpload] with the same
    /// session ID is dead; answering it has no effect.
    PrepareUploadAborted {
        /// The session ID of the aborted prepare-upload request.
        session_id: String,
    },

    /// `POST /api/localsend/v2/cancel` was received for a session this server
    /// does not manage. This happens when the remote device cancels a transfer
    /// that this application is currently *sending* to it: the session ID is
    /// the one issued by the remote device during prepare-upload.
    ///
    /// The application must verify that `ip` matches the target of the
    /// send session before cancelling it.
    CancelReceived {
        /// The IP address of the remote device requesting the cancellation.
        ip: PeerIp,

        /// The session ID as known by the remote device.
        session_id: String,
    },
}

/// The application's decision for a prepare-upload request.
#[derive(Debug)]
pub enum PrepareUploadDecisionV2 {
    /// Accept the given file IDs (a subset of the offered files).
    /// An empty set responds with 204 (no file transfer needed).
    Accept(HashSet<String>),

    /// 加密 v2 扩展：接受文件，并返回接收端 ECDH 公钥（复杂加密协商用）。
    AcceptWithEcdh {
        /// Accepted file IDs (a subset of the offered files).
        ids: HashSet<String>,
        /// 接收端 ECDH 公钥（P-256 SEC1 uncompressed，base64url）。
        recv_ecdh_pub: String,
    },

    /// Decline the request (403).
    Decline,
}

/// Why an upload session ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionEndReasonV2 {
    /// All accepted files reached a final state (finished or failed).
    Finished,

    /// The sender cancelled the session via `POST /api/localsend/v2/cancel`.
    Cancelled,
}

pub(crate) async fn register(
    body: Incoming,
    state: AppState,
    client_info: RequestClientInfo,
) -> Result<JsonResponse<RegisterResponseDtoV2>, AppError> {
    let payload = body.collect_to_json::<RegisterDtoV2>().await?;

    // On TLS, only trust registrations whose claimed fingerprint is proven
    // by the client certificate of the mTLS handshake.
    let fingerprint_valid = match client_info.cert_fingerprint() {
        Some(cert_fingerprint) => payload.fingerprint.to_ascii_uppercase() == cert_fingerprint,
        None => true,
    };

    if let Some(v2) = &state.v2 {
        if fingerprint_valid {
            // Not awaited: registrations arrive in bursts (every device on the
            // network answers an announcement, and a peer scanning its subnet
            // registers with everyone), so the channel fills up easily. Waiting
            // would block this request handler — and every later one — until
            // the application catches up, which is what makes the device stop
            // answering `register` altogether.
            //
            // The event carries no responder, and peers repeat their
            // announcement, so a dropped registration is recoverable.
            if let Err(err) = v2.event_tx.try_send(ServerEventV2::Register {
                ip: client_info.ip,
                info: payload,
            }) {
                tracing::debug!("Dropped a register event: {err}");
            }
        } else {
            tracing::warn!(
                "Ignoring register from {}: claimed fingerprint does not match the client certificate",
                client_info.ip
            );
        }
    }

    let info = state.info.lock().await.clone();
    let download = state.web.is_some();

    Ok(JsonResponse {
        status: StatusCode::OK,
        body: RegisterResponseDtoV2 {
            alias: info.alias,
            version: PROTOCOL_VERSION_V2.to_string(),
            device_model: info.device_model,
            device_type: info.device_type,
            fingerprint: info.token,
            download,
        },
    })
}

pub(crate) async fn info(state: AppState) -> Result<JsonResponse<InfoResponseDtoV2>, AppError> {
    let info = state.info.lock().await.clone();
    let download = state.web.is_some();

    Ok(JsonResponse {
        status: StatusCode::OK,
        body: InfoResponseDtoV2 {
            alias: info.alias,
            version: PROTOCOL_VERSION_V2.to_string(),
            device_model: info.device_model,
            device_type: info.device_type,
            fingerprint: info.token,
            download,
        },
    })
}

pub(crate) async fn prepare_upload(
    req: Request<Incoming>,
    state: AppState,
    client_info: RequestClientInfo,
) -> Result<Response<BoxedBody>, AppError> {
    let v2 = require_v2(&state)?;
    let query = parse_query(req.uri().query());

    check_pin(
        v2.pin.as_deref(),
        &v2.pin_attempts,
        &query,
        client_info.ip.ip,
    )
    .await?;

    let payload = req
        .into_body()
        .collect_to_json::<PrepareUploadRequestDtoV2>()
        .await?;

    if payload.files.is_empty() {
        return Err(AppError::BadRequest("No files provided".to_string()));
    }

    let session_id = Uuid::new_v4().to_string();
    let cancelled = CancellationToken::new();

    // Claim the single session slot.
    {
        let mut slot = v2.session.lock().await;
        if slot.is_some() {
            return Err(AppError::Message(
                StatusCode::CONFLICT,
                "Blocked by another session".to_string(),
            ));
        }
        *slot = Some(SessionStateV2::Pending(PendingSessionV2 {
            session_id: session_id.clone(),
            sender_ip: client_info.ip,
            cancel: cancelled.clone(),
        }));
    }

    // Frees the slot again if this request is aborted before a session is created.
    let mut pending_guard = PendingSessionGuard::new(v2.clone(), session_id.clone());

    let (decision_tx, decision_rx) = oneshot::channel();
    let event = ServerEventV2::PrepareUpload {
        session_id: session_id.clone(),
        ip: client_info.ip,
        info: payload.info,
        cert_fingerprint: client_info.cert_fingerprint(),
        files: payload.files.clone(),
        sender_ecdh_pub: payload.ecdh_pub_key.clone(),
        decision_tx,
    };
    if v2.event_tx.send(event).await.is_err() {
        return Err(AppError::Status(StatusCode::INTERNAL_SERVER_ERROR));
    }

    // The sender may cancel the request while the application is deciding.
    // Returning with the guard still armed frees the slot and emits
    // [ServerEventV2::PrepareUploadAborted], like a dropped connection.
    let decision = tokio::select! {
        decision = decision_rx => {
            decision.map_err(|_| AppError::Status(StatusCode::INTERNAL_SERVER_ERROR))?
        }
        _ = cancelled.cancelled() => {
            return Err(AppError::Message(
                StatusCode::FORBIDDEN,
                "Cancelled by sender".to_string(),
            ));
        }
    };

    // 加密 v2 扩展：接收端 ECDH 公钥（仅复杂加密协商时返回）
    let mut recv_ecdh_pub: Option<String> = None;
    let accepted_ids = match decision {
        PrepareUploadDecisionV2::Decline => {
            pending_guard.clear().await;
            return Err(AppError::Message(
                StatusCode::FORBIDDEN,
                "Rejected".to_string(),
            ));
        }
        PrepareUploadDecisionV2::Accept(ids) => ids,
        PrepareUploadDecisionV2::AcceptWithEcdh { ids, recv_ecdh_pub: pub_b64 } => {
            recv_ecdh_pub = Some(pub_b64);
            ids
        }
    };

    // Scheduler v1：为携带 Merkle 扩展字段的大文件（清单文件）计算块差异 chunkDiff。
    // 仅当接收端配置了接收目录且存在清单文件时进行；逐块校验是同步磁盘 I/O，
    // 送入 spawn_blocking 避免阻塞 async worker。
    let chunk_diff = {
        let receive_dir = v2.receive_dir.clone();
        let sched_files: Vec<(String, FileDto)> = payload
            .files
            .iter()
            .filter(|(_, dto)| dto.piece_hashes.is_some() && dto.chunk_size.is_some())
            .map(|(id, dto)| (id.clone(), dto.clone()))
            .collect();
        if sched_files.is_empty() {
            None
        } else if let Some(dir) = receive_dir {
            let diffs = tokio::task::spawn_blocking(move || {
                let mut map = HashMap::new();
                for (id, dto) in sched_files {
                    if let Some(diff) = compute_chunk_diff(&dir, &dto) {
                        map.insert(id, diff);
                    }
                }
                map
            })
            .await
            .unwrap_or_default();
            if diffs.is_empty() {
                None
            } else {
                Some(diffs)
            }
        } else {
            None
        }
    };

    // 清单文件（piece_hashes 非空）仅用于协商 chunkDiff，不生成传输 token。
    let files: HashMap<String, SessionFileV2> = payload
        .files
        .into_iter()
        .filter(|(id, _)| accepted_ids.contains(id))
        .filter(|(_, dto)| dto.piece_hashes.is_none())
        .map(|(id, dto)| {
            let file = SessionFileV2 {
                dto,
                token: Uuid::new_v4().to_string(),
                status: FileStatusV2::Pending,
                attempts: 0,
            };
            (id, file)
        })
        .collect();

    if files.is_empty() {
        // Nothing to transfer.
        pending_guard.clear().await;
        let mut res = Response::new(empty_body());
        *res.status_mut() = StatusCode::NO_CONTENT;
        return Ok(res);
    }

    let tokens: HashMap<String, String> = files
        .iter()
        .map(|(id, file)| (id.clone(), file.token.clone()))
        .collect();

    {
        let mut slot = v2.session.lock().await;
        *slot = Some(SessionStateV2::Active(UploadSessionV2 {
            session_id: session_id.clone(),
            sender_ip: client_info.ip,
            files,
        }));
    }
    pending_guard.disarm();

    tracing::info!("Upload session created: {session_id}");

    Ok(JsonResponse {
        status: StatusCode::OK,
        body: PrepareUploadResponseDtoV2 {
            session_id,
            files: tokens,
            chunk_diff,
            ecdh_pub_key: recv_ecdh_pub,
        },
    }
    .into_response())
}

pub(crate) async fn upload(
    req: Request<Incoming>,
    state: AppState,
    client_info: RequestClientInfo,
) -> Result<Response<BoxedBody>, AppError> {
    let v2 = require_v2(&state)?;
    let query = parse_query(req.uri().query());

    let (Some(session_id), Some(file_id), Some(token)) = (
        query.get("sessionId"),
        query.get("fileId"),
        query.get("token"),
    ) else {
        return Err(AppError::Message(
            StatusCode::BAD_REQUEST,
            "Missing parameters".to_string(),
        ));
    };

    // Validate the request and mark the file as in progress.
    let file_dto = {
        let mut slot = v2.session.lock().await;
        let Some(SessionStateV2::Active(session)) = slot.as_mut() else {
            return Err(invalid_token_error());
        };
        if session.session_id != *session_id || session.sender_ip != client_info.ip {
            return Err(invalid_token_error());
        }
        let Some(file) = session.files.get_mut(file_id) else {
            return Err(invalid_token_error());
        };
        if file.token != *token || file.status == FileStatusV2::Finished {
            return Err(invalid_token_error());
        }
        if file.status != FileStatusV2::InProgress {
            file.status = FileStatusV2::InProgress;
            file.attempts = file.attempts.saturating_add(1);
        }
        file.dto.clone()
    };

    // Marks the file as failed if this request is aborted mid-transfer.
    let mut upload_guard = UploadGuard::new(v2.clone(), session_id.clone(), file_id.clone());

    let file_size = file_dto.size;
    let expected_sha256 = match v2.verify_checksums {
        true => file_dto.sha256.clone(),
        false => None,
    };
    let timestamps = match &file_dto.metadata {
        Some(metadata) => FileTimestamps {
            modified: metadata.modified_time(),
            accessed: metadata.accessed_time(),
        },
        None => FileTimestamps::default(),
    };
    let (target_tx, target_rx) = oneshot::channel::<FileUploadTarget>();

    let event = ServerEventV2::FileUpload {
        session_id: session_id.clone(),
        file_id: file_id.clone(),
        file: file_dto,
        target_tx,
    };
    if v2.event_tx.send(event).await.is_err() {
        upload_guard.finish(SaveResult::Failed).await;
        return Err(AppError::Status(StatusCode::INTERNAL_SERVER_ERROR));
    }

    let Ok(target) = target_rx.await else {
        upload_guard.finish(SaveResult::Failed).await;
        return Err(AppError::Status(StatusCode::INTERNAL_SERVER_ERROR));
    };

    let result = common::save::save_req_to_target(
        req,
        target,
        file_size,
        expected_sha256.as_deref(),
        timestamps,
    )
    .await;

    upload_guard.finish(result).await;

    match result {
        SaveResult::Success => Ok(Response::new(empty_body())),
        SaveResult::Failed => Err(AppError::Status(StatusCode::INTERNAL_SERVER_ERROR)),
        SaveResult::HashMismatch => Err(AppError::Message(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Checksum mismatch".to_string(),
        )),
    }
}

pub(crate) async fn cancel(
    req: Request<Incoming>,
    state: AppState,
    client_info: RequestClientInfo,
) -> Result<Response<BoxedBody>, AppError> {
    let v2 = require_v2(&state)?;
    let query = parse_query(req.uri().query());
    let session_id = query.get("sessionId");

    // A pending prepare-upload request: the sender does not know the session
    // ID yet (it is part of the response), so a cancel from the pending
    // sender's address is accepted without one.
    let pending_cancelled = {
        let slot = v2.session.lock().await;
        match slot.as_ref() {
            Some(SessionStateV2::Pending(pending))
                if pending.sender_ip == client_info.ip
                    && session_id.is_none_or(|id| *id == pending.session_id) =>
            {
                tracing::info!(
                    "Pending upload session cancelled by sender: {}",
                    pending.session_id
                );
                // The waiting prepare-upload handler frees the slot and
                // notifies the application.
                pending.cancel.cancel();
                true
            }
            _ => false,
        }
    };

    if pending_cancelled {
        return Ok(Response::new(empty_body()));
    }

    if let Some(session_id) = session_id {
        let cancelled = {
            let mut slot = v2.session.lock().await;
            match slot.as_ref() {
                Some(SessionStateV2::Active(session))
                    if session.session_id == *session_id && session.sender_ip == client_info.ip =>
                {
                    *slot = None;
                    true
                }
                _ => false,
            }
        };

        if cancelled {
            tracing::info!("Upload session cancelled by sender: {session_id}");
            let _ = v2
                .event_tx
                .send(ServerEventV2::SessionEnd {
                    session_id: session_id.clone(),
                    reason: SessionEndReasonV2::Cancelled,
                })
                .await;
        } else {
            // Not one of our upload sessions: the remote device may be
            // cancelling a transfer this application is sending to it.
            let _ = v2
                .event_tx
                .send(ServerEventV2::CancelReceived {
                    ip: client_info.ip,
                    session_id: session_id.clone(),
                })
                .await;
        }
    }

    Ok(Response::new(empty_body()))
}

fn require_v2(state: &AppState) -> Result<Arc<V2State>, AppError> {
    state
        .v2
        .clone()
        .ok_or(AppError::Status(StatusCode::NOT_FOUND))
}

fn invalid_token_error() -> AppError {
    AppError::Message(
        StatusCode::FORBIDDEN,
        "Invalid token or IP address".to_string(),
    )
}

/// Scheduler v1：对接收目录中已存在的目标文件逐块 SHA-256 校验，返回块差异。
///
/// - 文件不存在 → 全部块标记 missing（首次备份全量传输）
/// - 已存在 → 每块按 `chunk_size` 读取并与发送端 `piece_hashes[i]` 比对：
///   - 匹配 → 加入 `matched`，并把该块内容本地复制到 `.chunks/{pct}/{i}`
///     （合并阶段直接复用，发送端零重传，实现增量备份零传输）
///   - 不匹配 → 加入 `mismatched`（内容已变，需重传覆盖）
///   - 超出已有文件大小 → 加入 `missing`
pub(crate) fn compute_chunk_diff(dir: &Path, dto: &FileDto) -> Option<ChunkDiffDtoV2> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};

    let piece_hashes = dto.piece_hashes.as_ref()?;
    let chunk_size = dto.chunk_size.unwrap_or(0);
    if chunk_size == 0 || piece_hashes.is_empty() {
        return None;
    }

    let mut missing: Vec<u32> = Vec::new();
    let mut matched: Vec<u32> = Vec::new();
    let mut mismatched: Vec<u32> = Vec::new();

    let target = dir.join(&dto.file_name);
    match std::fs::File::open(&target) {
        Ok(mut f) => {
            let file_len = f.metadata().map(|m| m.len()).unwrap_or(0);
            for (i, expected) in piece_hashes.iter().enumerate() {
                let start = i as u64 * chunk_size;
                if start >= file_len {
                    missing.push(i as u32);
                    continue;
                }
                let len = ((start + chunk_size).min(file_len) - start) as usize;
                let mut buf = vec![0u8; len];
                if f.seek(SeekFrom::Start(start)).is_err() || f.read_exact(&mut buf).is_err() {
                    missing.push(i as u32);
                    continue;
                }
                let mut hasher = Sha256::new();
                hasher.update(&buf);
                let actual = crate::crypto::hash::to_hex(&hasher.finalize());
                if actual.eq_ignore_ascii_case(expected) {
                    matched.push(i as u32);
                    // 匹配块本地落盘到 .chunks/{pct}/{i}，供合并直接使用（零网络传输）
                    let part_dir = dir.join(".chunks").join(pct_encode(&dto.file_name));
                    if std::fs::create_dir_all(&part_dir).is_ok() {
                        let _ = std::fs::write(part_dir.join(i.to_string()), &buf);
                    }
                } else {
                    mismatched.push(i as u32);
                }
            }
        }
        Err(_) => {
            // 文件不存在：全部缺失
            missing.extend(0..piece_hashes.len() as u32);
        }
    }

    let file_complete = !piece_hashes.is_empty() && matched.len() == piece_hashes.len();
    Some(ChunkDiffDtoV2 {
        file_complete,
        missing_chunks: missing,
        matched_chunks: matched,
        mismatched_chunks: mismatched,
    })
}

/// Scheduler v1：pct 编码（与发送端 desktop transfer.rs::pct_encode 严格一致：
/// 保留 A-Z a-z 0-9 `-` `_` `.`，其余转大写 `%XX`）。
pub(crate) fn pct_encode(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => out.push(b as char),
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// Scheduler v1: GET /api/localsend/v2/file/{fileId}/diff — 探测接收端已存在文件的块并做 SHA-256 强校验。
///
/// 协议契约（与发送端 SchedulerHttpClient::get_diff 对齐，Range + If-Range）：
/// - 206 + Content-Range: 块存在且 ETag 匹配，返回块数据
/// - 412: 块存在但 SHA-256 不匹配（NACK）
/// - 416 + Content-Range: bytes */{total}: Range 不满足（块不存在/文件不存在）
/// - 200: 无 If-Range 条件（发送端未携带 ETag），视为文件已变
pub(crate) async fn file_diff(
    req: Request<Incoming>,
    state: AppState,
    client_info: RequestClientInfo,
) -> Result<Response<BoxedBody>, AppError> {
    use sha2::{Digest, Sha256};

    let v2 = require_v2(&state)?;
    let path = req.uri().path().to_string();
    let file_id = path
        .strip_prefix("/api/localsend/v2/file/")
        .and_then(|rest| rest.strip_suffix("/diff"))
        .unwrap_or("")
        .to_string();
    if file_id.is_empty() {
        return Err(AppError::Message(
            StatusCode::BAD_REQUEST,
            "Missing fileId".to_string(),
        ));
    }

    let session_id = req
        .headers()
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let range = req
        .headers()
        .get("range")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let if_range = req
        .headers()
        .get("if-range")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // 校验会话与文件（仅允许会话发送方 IP 探测）
    let file_name = {
        let slot = v2.session.lock().await;
        let Some(SessionStateV2::Active(session)) = slot.as_ref() else {
            return Err(invalid_token_error());
        };
        if session.session_id != session_id || session.sender_ip != client_info.ip {
            return Err(invalid_token_error());
        }
        let Some(file) = session.files.get(&file_id) else {
            return Err(invalid_token_error());
        };
        file.dto.file_name.clone()
    };

    // 解析 Range: bytes=start-end
    let (start, end) = parse_range(&range);

    // 读取接收目录中的目标文件（无接收目录或文件不存在 → 416）
    let Some(dir) = v2.receive_dir.clone() else {
        return Ok(diff_range_not_satisfiable(0));
    };
    let target = dir.join(&file_name);
    let file_len = match std::fs::metadata(&target) {
        Ok(m) => m.len(),
        Err(_) => return Ok(diff_range_not_satisfiable(0)),
    };
    if start >= file_len {
        return Ok(diff_range_not_satisfiable(file_len));
    }

    // 读取块
    let len = (end.min(file_len - 1) - start + 1) as usize;
    let mut buf = vec![0u8; len];
    {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = match std::fs::File::open(&target) {
            Ok(f) => f,
            Err(_) => return Ok(diff_range_not_satisfiable(file_len)),
        };
        if f.seek(SeekFrom::Start(start)).is_err() || f.read_exact(&mut buf).is_err() {
            return Ok(diff_range_not_satisfiable(file_len));
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(&buf);
    let actual = crate::crypto::hash::to_hex(&hasher.finalize());

    // 强校验：If-Range 为带双引号的 ETag（协议契约）
    let expected = if_range.trim();
    let expected = expected
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(expected);

    if !expected.is_empty() && expected != actual {
        // 412: 块存在但 SHA-256 不匹配（NACK）
        return Ok(JsonResponse {
            status: StatusCode::PRECONDITION_FAILED,
            body: serde_json::json!({
                "type": "chunk_nack",
                "expected": expected,
                "actual": actual,
            }),
        }
        .into_response());
    }

    if expected.is_empty() {
        // 200: 无 If-Range（发送端未携带强校验条件）→ 文件已变
        return Ok(JsonResponse {
            status: StatusCode::OK,
            body: serde_json::json!({ "type": "file_changed" }),
        }
        .into_response());
    }

    // 206: 块存在且 ETag 匹配，返回块数据
    let mut res = Response::new(full_body(buf));
    *res.status_mut() = StatusCode::PARTIAL_CONTENT;
    res.headers_mut().insert(
        hyper::http::header::CONTENT_RANGE,
        hyper::http::HeaderValue::from_str(&format!(
            "bytes {}-{}/{}",
            start,
            start + len as u64 - 1,
            file_len
        ))
        .map_err(|_| AppError::Status(StatusCode::INTERNAL_SERVER_ERROR))?,
    );
    res.headers_mut().insert(
        hyper::http::header::CONTENT_TYPE,
        hyper::http::HeaderValue::from_static("application/octet-stream"),
    );
    Ok(res)
}

/// 解析 `bytes=start-end` Range 头（缺省 end = u64::MAX）
fn parse_range(range: &str) -> (u64, u64) {
    let rest = range.strip_prefix("bytes=").unwrap_or("");
    let (s, e) = match rest.split_once('-') {
        Some((s, e)) => (s, e),
        None => (rest, ""),
    };
    let start = s.parse::<u64>().unwrap_or(0);
    let end = e.parse::<u64>().ok().unwrap_or(u64::MAX);
    (start, end)
}

/// 构造 416 Range Not Satisfiable 响应（带 Content-Range: bytes */{total}）
fn diff_range_not_satisfiable(total: u64) -> Response<BoxedBody> {
    let mut res = Response::new(full_body(
        format!("{{\"error\":\"range_not_satisfiable\",\"actualSize\":{total}}}"),
    ));
    *res.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
    res.headers_mut().insert(
        hyper::http::header::CONTENT_RANGE,
        hyper::http::HeaderValue::from_str(&format!("bytes */{total}"))
            .unwrap_or_else(|_| hyper::http::HeaderValue::from_static("bytes */0")),
    );
    res.headers_mut().insert(
        hyper::http::header::CONTENT_TYPE,
        hyper::http::HeaderValue::from_static("application/json"),
    );
    res
}

/// Frees a claimed `Pending` session slot unless a session was created.
///
/// The cleanup also runs on drop so the slot is not leaked
/// when the request future is cancelled (e.g. the sender disconnected
/// while the application was still deciding).
struct PendingSessionGuard {
    v2: Arc<V2State>,
    session_id: String,
    armed: bool,
}

impl PendingSessionGuard {
    fn new(v2: Arc<V2State>, session_id: String) -> Self {
        Self {
            v2,
            session_id,
            armed: true,
        }
    }

    /// Disarms the guard after the pending slot was replaced by an active session.
    fn disarm(&mut self) {
        self.armed = false;
    }

    /// Frees the pending slot immediately.
    async fn clear(&mut self) {
        self.armed = false;
        clear_pending_session(&self.v2).await;
    }
}

impl Drop for PendingSessionGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let v2 = self.v2.clone();
        let session_id = std::mem::take(&mut self.session_id);
        tokio::spawn(async move {
            clear_pending_session(&v2).await;
            // The application may still be waiting for a decision; tell it
            // that answering is pointless now.
            let _ = v2
                .event_tx
                .send(ServerEventV2::PrepareUploadAborted { session_id })
                .await;
        });
    }
}

async fn clear_pending_session(v2: &V2State) {
    let mut slot = v2.session.lock().await;
    if matches!(*slot, Some(SessionStateV2::Pending(_))) {
        *slot = None;
    }
}

/// Sets the final status of a file after an upload attempt.
///
/// The cleanup also runs on drop (as a failure) so the file is not stuck
/// in progress when the request future is cancelled mid-transfer.
struct UploadGuard {
    v2: Arc<V2State>,
    session_id: String,
    file_id: String,
    armed: bool,
}

impl UploadGuard {
    fn new(v2: Arc<V2State>, session_id: String, file_id: String) -> Self {
        Self {
            v2,
            session_id,
            file_id,
            armed: true,
        }
    }

    async fn finish(&mut self, result: SaveResult) {
        self.armed = false;
        finalize_file(&self.v2, &self.session_id, &self.file_id, result).await;
    }
}

impl Drop for UploadGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let v2 = self.v2.clone();
        let session_id = std::mem::take(&mut self.session_id);
        let file_id = std::mem::take(&mut self.file_id);
        tokio::spawn(async move {
            finalize_file(&v2, &session_id, &file_id, SaveResult::Failed).await;
        });
    }
}

/// How often an upload of the same file may be started, i.e. how often a
/// sender may retry a file after a checksum mismatch.
/// Senders must not retry more often than this (see the upload isolate).
const MAX_UPLOAD_ATTEMPTS: u8 = 3;

/// Sets the final status of a file and ends the session once all files are done.
///
/// A checksum mismatch resets the file to [FileStatusV2::Pending] (as long as
/// [MAX_UPLOAD_ATTEMPTS] is not exhausted) so the sender can retry the upload
/// with the same token; the session stays active in that case.
async fn finalize_file(v2: &V2State, session_id: &str, file_id: &str, result: SaveResult) {
    let session_ended = {
        let mut slot = v2.session.lock().await;
        let Some(SessionStateV2::Active(session)) = slot.as_mut() else {
            return;
        };
        if session.session_id != session_id {
            return;
        }
        if let Some(file) = session.files.get_mut(file_id) {
            if file.status == FileStatusV2::InProgress {
                file.status = match result {
                    SaveResult::Success => FileStatusV2::Finished,
                    SaveResult::HashMismatch if file.attempts < MAX_UPLOAD_ATTEMPTS => {
                        FileStatusV2::Pending
                    }
                    SaveResult::Failed | SaveResult::HashMismatch => FileStatusV2::Failed,
                };
            }
        }
        match session.is_complete() {
            true => {
                *slot = None;
                true
            }
            false => false,
        }
    };

    if session_ended {
        tracing::info!("Upload session finished: {session_id}");
        let _ = v2
            .event_tx
            .send(ServerEventV2::SessionEnd {
                session_id: session_id.to_string(),
                reason: SessionEndReasonV2::Finished,
            })
            .await;
    }
}
