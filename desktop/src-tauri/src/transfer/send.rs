//! 传输模块 - 发送端流程（V4 统一 piece 协议）
//!
//! 只走一条链路，不再有 tiny 私有打包 / `__chunked__` 分片路径 / 8MB 调度块：
//!
//! ```text
//! register → prepare → diff（整文件权威位图）→ chunk（pieceIndex + sha256）
//!          → verify（接收端实算 SHA-256）→ tasks（接收端终态）
//! ```
//!
//! 关键不变量：
//! - 每个 `fileId` 对应**一个逻辑文件**，落盘 `relPath` 与 prepare 声明一致；
//! - 分块大小固定为 core 的 `PIECE_SIZE`（4MB），最后一块按剩余长度收缩；
//! - 每一块请求都检查 HTTP 状态，4xx/5xx 绝不计成功；
//! - 终态只认接收端 `verify` + `tasks`，本地发送完成不算完成。

use super::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use lanbackup_core::dto::session::{
    FileMeta as CoreFileMeta, PrepareRequest, PrepareResponse, SessionRegisterRequest,
    SessionRegisterResponse, TaskListResponse, TaskStatus, VerifyFileResponse,
};
use lanbackup_core::transfer::chunk::{piece_count, PIECE_SIZE};
use lanbackup_core::version::{Capabilities, CAP_ENCRYPT};

const MAX_INFLIGHT_PIECES: usize = 4;
const MAX_RETRIES: u32 = 3;
const PROGRESS_INTERVAL_MS: u64 = 120;

#[derive(Clone)]
struct PreparedFile {
    file_id: String,
    rel_path: String,
    abs_path: PathBuf,
    size: u64,
    mtime_ms: i64,
    /// 加密文件 = **线路密文**逐 piece SHA-256；明文文件 = 明文 piece SHA-256
    piece_hashes: Vec<String>,
    whole_sha: String,
    /// 加密文件的 file key（kdf L4，由配对 secret 派生，仅存内存）
    enc_key: Option<[u8; 32]>,
}

pub async fn send_files(
    app: AppHandle,
    target_ip: String,
    target_port: u16,
    _target_code: String,
    files: Vec<SendFileItem>,
    encryption_mode: String,
    peer_id: Option<String>,
) -> Result<u64, AppError> {
    if files.is_empty() {
        return Ok(0);
    }
    crate::log_info!(
        "发送文件: 目标={}:{} 文件数={} 加密模式={} 配对设备={}",
        target_ip,
        target_port,
        files.len(),
        encryption_mode,
        peer_id.as_deref().unwrap_or("<未指定>")
    );

    // WB-0032：加密能力协商在 register 之后做（需要对端能力位 + 本机配对密钥）。
    // ecdh（每会话 ECDH 密钥协商）仍未实现，显式请求直接拒绝，绝不静默降级。
    if encryption_mode == "ecdh" {
        return Err(AppError(
            "ECDH 加密尚未实现：请使用兼容模式（已配对设备将自动启用 AEAD 加密）".to_string(),
        ));
    }
    let wants_encryption = encryption_mode == "simple" || encryption_mode == "auto";
    // 配对 secret：仅当指定来源设备（peerId）且本机存有其 32B 配对密钥时可用。
    // 密钥只在本进程内存中流转，不进日志（WB-0653）。
    let enc_secret: Option<[u8; 32]> = peer_id.as_deref().and_then(|pid| {
        let st = app.try_state::<PairingState>()?;
        let map = st.secrets.try_read().ok()?;
        let v = map.get(pid)?;
        if v.len() != 32 {
            crate::log_warn!("对端配对密钥长度异常（{}B），跳过加密协商", v.len());
            return None;
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(v);
        Some(k)
    });

    let session_id = hex::encode(rand::random::<[u8; 16]>());
    let cancel = tokio_util::sync::CancellationToken::new();
    {
        let st = app.state::<TransferState>();
        st.active_sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(session_id.clone(), cancel.clone());
    }
    if let Some(st) = app.try_state::<PairingState>() {
        st.transfer_count.fetch_add(1, Ordering::Relaxed);
    }

    let result = run_send(
        &app,
        SendTarget { ip: &target_ip, port: target_port },
        &session_id,
        files,
        &cancel,
        EncryptionPlan { wants: wants_encryption, secret: enc_secret },
    )
    .await;

    {
        let st = app.state::<TransferState>();
        st.active_sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&session_id);
    }
    if let Some(st) = app.try_state::<PairingState>() {
        st.transfer_count.fetch_sub(1, Ordering::Relaxed);
    }
    result
}

/// 发送目标（IP:端口）。
struct SendTarget<'a> {
    ip: &'a str,
    port: u16,
}

/// 加密协商输入（是否要求加密 + 已配对设备的 32B 密钥）。
struct EncryptionPlan {
    wants: bool,
    secret: Option<[u8; 32]>,
}

async fn run_send(
    app: &AppHandle,
    target: SendTarget<'_>,
    session_id: &str,
    files: Vec<SendFileItem>,
    cancel: &tokio_util::sync::CancellationToken,
    enc: EncryptionPlan,
) -> Result<u64, AppError> {
    let started = std::time::Instant::now();
    let base = format!("http://{}:{}", target.ip, target.port);
    let client = reqwest::Client::builder()
        // 不设全局 70s 超时：大文件会被整段传输时间一刀切。改为每请求超时。
        .connect_timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|e| AppError(format!("创建 HTTP 客户端失败: {e}")))?;

    // ── 1. 规范化 + 去重 + 单遍哈希 ──
    let mut seen = std::collections::HashSet::new();
    let mut items: Vec<SendFileItem> = Vec::new();
    for f in files {
        let normalized = lanbackup_core::sync::manifest::validate_rel_path(&f.rel_path)
            .map_err(|e| AppError(format!("非法相对路径 {:?}: {e}", f.rel_path)))?;
        if !seen.insert(normalized.clone()) {
            crate::log_warn!("发送列表存在重复 relPath，已忽略: {normalized}");
            continue;
        }
        items.push(SendFileItem {
            rel_path: normalized,
            abs_path: f.abs_path,
        });
    }
    if items.is_empty() {
        return Ok(0);
    }
    let total_files = items.len() as u64;

    // 必须 `.cloned()`：用 `iter()` 借用的闭包在 tauri `generate_handler!` 的
    // 高阶生命周期检查下报 "implementation of FnOnce is not general enough"。
    #[allow(clippy::redundant_iter_cloned)]
    let hashed = futures_util::stream::iter(items.iter().cloned().map(|item| {
        let path = PathBuf::from(&item.abs_path);
        async move {
            tokio::task::spawn_blocking(move || hash_file(&path))
                .await
                .map_err(|e| AppError(format!("哈希任务失败: {e}")))?
        }
    }))
    .buffer_unordered(4)
    .collect::<Vec<Result<(u64, i64, Vec<String>, String), AppError>>>()
    .await;

    let mut prepared: Vec<PreparedFile> = Vec::with_capacity(items.len());
    for (i, h) in hashed.into_iter().enumerate() {
        let (size, mtime_ms, piece_hashes, whole_sha) = h?;
        let item = &items[i];
        prepared.push(PreparedFile {
            file_id: format!("f{i}"),
            rel_path: item.rel_path.clone(),
            abs_path: PathBuf::from(&item.abs_path),
            size,
            mtime_ms,
            piece_hashes,
            whole_sha,
            enc_key: None,
        });
    }

    // ── 2. register（失败必须阻断：没有会话就没有后续端点）──
    let reg_req = SessionRegisterRequest {
        device_id: identity::get_device_id(app),
        alias: identity::get_device_name(app)?,
        session_id: session_id.to_string(),
    };
    let reg_resp = checked_json::<SessionRegisterResponse>(
        client
            .post(format!("{base}/api/v4/session/register"))
            .json(&reg_req)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await,
        "register",
    )
    .await?;
    let peer_caps = Capabilities::from_bits(reg_resp.capabilities.bits());
    // WB-0032/0650：协商默认一致 —— "用户要求加密 + 本机持有对端配对密钥 +
    // 对端声明 CAP_ENCRYPT"三者同时成立才加密；任一不成立走明文，但必须发出
    // 可见告警，绝不静默降级。
    let encrypt = enc.wants && enc.secret.is_some() && peer_caps.contains(CAP_ENCRYPT);
    if enc.wants && !encrypt {
        crate::log_warn!("加密条件不满足（缺配对密钥或对端不支持），本次为明文传输");
        let _ = app.emit(
            "send-warning",
            serde_json::json!({
                "code": "ENCRYPTION_DEGRADED",
                "message": "未能建立加密通道（缺配对密钥或对端不支持），本次为局域网明文传输"
            }),
        );
    }
    // 加密文件：prepare 必须携带**线路密文**的逐 piece 哈希 —— 对每个文件预演
    // 一次逐 piece 加密（nonce=序号，确定性派生），得到密文哈希；上传时按同一
    // 公式重加密，密文逐字节一致。
    if let Some(secret) = enc.secret.filter(|_| encrypt) {
        for pf in prepared.iter_mut() {
            let sk = lanbackup_core::crypto::kdf::derive_session_key(&secret, &secret, session_id);
            let fk = lanbackup_core::crypto::kdf::derive_file_key(&sk, &pf.file_id);
            let path = pf.abs_path.clone();
            let size = pf.size;
            let sid = session_id.to_string();
            let fid = pf.file_id.clone();
            pf.piece_hashes = tokio::task::spawn_blocking(move || {
                cipher_piece_hashes(&path, size, &sid, &fid, &fk)
            })
            .await
            .map_err(|e| AppError(format!("加密预演任务失败: {e}")))??;
            pf.enc_key = Some(fk);
        }
    }

    // ── 3. prepare：一个逻辑文件一条 meta ──
    let mut prepare_files = std::collections::HashMap::new();
    for pf in &prepared {
        // WB-0540：size/整文件哈希始终是明文语义；加密文件的 wireSize 单独承载
        // 线路字节数（明文 + 每 piece 16B GCM tag）。
        prepare_files.insert(
            pf.file_id.clone(),
            CoreFileMeta {
                file_id: pf.file_id.clone(),
                file_name: pf.rel_path.clone(),
                rel_path: pf.rel_path.clone(),
                size: pf.size,
                mtime: pf.mtime_ms,
                sha256: Some(pf.whole_sha.clone()),
                merkle_root: None,
                piece_hashes: Some(pf.piece_hashes.clone()),
                encrypted: encrypt,
                wire_size: if encrypt {
                    Some(pf.size + piece_count(pf.size) * 16)
                } else {
                    None
                },
            },
        );
    }
    let prepared_resp = checked_json::<PrepareResponse>(
        client
            .post(format!("{base}/api/v4/session/prepare"))
            .json(&PrepareRequest {
                session_id: session_id.to_string(),
                device_id: identity::get_device_id(app),
                files: prepare_files,
            })
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await,
        "prepare",
    )
    .await?;

    let accepted: Vec<PreparedFile> = prepared
        .into_iter()
        .filter(|pf| prepared_resp.files.contains_key(&pf.file_id))
        .collect();
    if accepted.is_empty() {
        return Err(AppError("接收端未接受任何文件".to_string()));
    }
    // 进度按线路字节数统计（加密文件 = 明文 + 每 piece 16B tag），与逐块累计一致
    let bytes_total: u64 = accepted
        .iter()
        .map(|pf| {
            if encrypt {
                pf.size + piece_count(pf.size) * 16
            } else {
                pf.size
            }
        })
        .sum();
    let bytes_sent = AtomicU64::new(0);
    let completed_files = AtomicU64::new(0);
    let last_emit = AtomicU64::new(0);

    // ── 4. 逐文件：diff → chunk → verify ──
    let mut verified: Vec<String> = Vec::new();
    for pf in &accepted {
        if cancel.is_cancelled() {
            return Err(AppError("发送已取消".to_string()));
        }
        let token = prepared_resp
            .files
            .get(&pf.file_id)
            .cloned()
            .unwrap_or_default();

        // 整文件 diff：接收端返回 missing/mismatched 两个集合。
        let diff_url = format!(
            "{base}/api/v4/session/diff?sessionId={}&fileId={}&etag={}&token={}",
            urlencoding::encode(session_id),
            urlencoding::encode(&pf.file_id),
            urlencoding::encode(&pf.whole_sha),
            urlencoding::encode(&token),
        );
        let diff: lanbackup_core::dto::session::ChunkDiff = checked_json(
            client
                .get(&diff_url)
                .timeout(std::time::Duration::from_secs(20))
                .send()
                .await,
            "diff",
        )
        .await?;

        let mut to_send: Vec<u64> = diff
            .missing_chunks
            .iter()
            .chain(diff.mismatched_chunks.iter())
            .copied()
            .collect();
        to_send.sort_unstable();
        to_send.dedup();
        let total_pieces = pf.piece_hashes.len() as u64;
        if let Some(bad) = to_send.iter().find(|i| **i >= total_pieces) {
            return Err(AppError(format!(
                "diff 返回越界 pieceIndex={bad}（文件 {} 共 {total_pieces} 块）",
                pf.rel_path
            )));
        }
        if !to_send.is_empty() {
            crate::log_debug!(
                "{}: 需要发送 {}/{} 块",
                pf.rel_path,
                to_send.len(),
                total_pieces
            );
        }

        upload_pieces(
            app,
            &client,
            &base,
            session_id,
            pf,
            &token,
            &to_send,
            &bytes_sent,
            bytes_total,
            &completed_files,
            total_files,
            &last_emit,
            started,
            cancel,
        )
        .await?;

        // verify：接收端实算 SHA-256，必须与我们声明的整文件哈希一致。
        let verify_url = format!(
            "{base}/api/v4/session/verify?sessionId={}&fileId={}&token={}",
            urlencoding::encode(session_id),
            urlencoding::encode(&pf.file_id),
            urlencoding::encode(&token),
        );
        let verify: VerifyFileResponse = checked_json(
            client
                .get(&verify_url)
                .timeout(std::time::Duration::from_secs(120))
                .send()
                .await,
            "verify",
        )
        .await?;
        match verify.sha256.as_deref() {
            Some(sha) if sha.eq_ignore_ascii_case(&pf.whole_sha) => {}
            other => {
                return Err(AppError(format!(
                    "接收端校验失败 {}: 期望 {}，返回 {:?}",
                    pf.rel_path, pf.whole_sha, other
                )))
            }
        }
        verified.push(pf.file_id.clone());
        completed_files.fetch_add(1, Ordering::Relaxed);
        emit_progress(
            app,
            ProgressSnapshot {
                sent_files: completed_files.load(Ordering::Relaxed),
                total_files,
                bytes: bytes_sent.load(Ordering::Relaxed),
                total_bytes: bytes_total,
                file_name: &pf.rel_path,
                stage: "verified",
                started,
            },
        );
    }

    // ── 5. tasks：终态以接收端回执为准 ──
    let tasks = fetch_tasks(&client, &base, session_id).await?;
    let mut confirmed = 0u64;
    for id in &verified {
        match tasks.tasks.iter().find(|t| &t.file_id == id) {
            Some(t) if t.status == TaskStatus::Completed => confirmed += 1,
            Some(t) => crate::log_warn!("文件 {id} 接收端终态为 {:?}，不计成功", t.status),
            None => crate::log_warn!("文件 {id} 不在接收端任务列表，不计成功"),
        }
    }

    let elapsed = started.elapsed().as_millis() as u64;
    crate::log_info!(
        "发送结束: 接收端确认 {confirmed}/{total_files} 文件，{}/{} 字节，耗时 {elapsed}ms",
        bytes_sent.load(Ordering::Relaxed),
        bytes_total
    );
    let _ = app.emit(
        "send-progress",
        serde_json::json!({
            "sent": confirmed,
            "total": total_files,
            "fileName": "",
            "stage": "done",
            "bytes": bytes_sent.load(Ordering::Relaxed),
            "totalBytes": bytes_total,
            "bytesSent": bytes_sent.load(Ordering::Relaxed),
            "elapsedMs": elapsed,
        }),
    );
    Ok(confirmed)
}

#[allow(clippy::too_many_arguments)]
async fn upload_pieces(
    app: &AppHandle,
    client: &reqwest::Client,
    base: &str,
    session_id: &str,
    pf: &PreparedFile,
    token: &str,
    indices: &[u64],
    bytes_sent: &AtomicU64,
    bytes_total: u64,
    completed_files: &AtomicU64,
    total_files: u64,
    last_emit: &AtomicU64,
    started: std::time::Instant,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<(), AppError> {
    let piece_hashes = pf.piece_hashes.clone();
    let path = pf.abs_path.clone();
    let size = pf.size;
    let file_name = pf.rel_path.clone();
    let enc_key = pf.enc_key;
    let fid = pf.file_id.clone();
    let sid = session_id.to_string();
    let chunk_url = format!(
        "{base}/api/v4/session/chunk?sessionId={}&fileId={}&token={}",
        urlencoding::encode(session_id),
        urlencoding::encode(&pf.file_id),
        urlencoding::encode(token),
    );

    futures_util::stream::iter(indices.iter().copied().map(|idx| {
        let client = client.clone();
        let chunk_url = chunk_url.clone();
        let path = path.clone();
        let piece_hashes = piece_hashes.clone();
        let file_name = file_name.clone();
        let sid = sid.clone();
        let fid = fid.clone();
        let cancel = cancel.clone();
        let app = app.clone();
        async move {
            if cancel.is_cancelled() {
                return Err(AppError("发送已取消".to_string()));
            }
            let offset = idx * PIECE_SIZE;
            let want = (size - offset).min(PIECE_SIZE) as usize;
            let data = tokio::task::spawn_blocking(move || read_piece(&path, offset, want))
                .await
                .map_err(|e| AppError(format!("读取分块任务失败: {e}")))??;
            // WB-0030：加密模式下先把明文 piece 加密成线路密文（nonce=序号，
            // 确定性派生，与 prepare 预演逐字节一致），再对**密文**做完整性比对
            let data = if let Some(fk) = enc_key {
                let mut nonce = [0u8; lanbackup_core::crypto::aead::NONCE_LEN];
                nonce[4..].copy_from_slice(&idx.to_be_bytes());
                let aad = format!("lanbackup/v4/piece/{sid}/{fid}/{idx}").into_bytes();
                lanbackup_core::crypto::aead::encrypt(&fk, &nonce, &data, &aad)
                    .ok_or_else(|| AppError("piece 加密失败".to_string()))?
            } else {
                data
            };
            let got = hex::encode(sha256_bytes(&data));
            if !piece_hashes[idx as usize].eq_ignore_ascii_case(&got) {
                return Err(AppError(format!(
                    "文件在传输期间发生变化：{} 块 {idx} 哈希不一致，请重试",
                    file_name
                )));
            }

            let mut attempt = 0u32;
            loop {
                if cancel.is_cancelled() {
                    return Err(AppError("发送已取消".to_string()));
                }
                let url = format!("{chunk_url}&pieceIndex={idx}&sha256={got}");
                let sent = client
                    .post(&url)
                    .header("Content-Type", "application/octet-stream")
                    .timeout(std::time::Duration::from_secs(60))
                    .body(data.clone())
                    .send()
                    .await;
                match sent {
                    Ok(resp) if resp.status().is_success() => break,
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        let snippet: String = body.chars().take(300).collect();
                        if status.is_client_error()
                            && status.as_u16() != 408
                            && status.as_u16() != 429
                        {
                            return Err(AppError(format!(
                                "分块 {idx} 被拒绝 HTTP {status}: {snippet}"
                            )));
                        }
                        if attempt >= MAX_RETRIES {
                            return Err(AppError(format!(
                                "分块 {idx} 重试耗尽 HTTP {status}: {snippet}"
                            )));
                        }
                    }
                    Err(e) => {
                        if attempt >= MAX_RETRIES {
                            return Err(AppError(format!("分块 {idx} 请求失败: {e}")));
                        }
                        crate::log_warn!("分块 {idx} 网络错误，准备重试: {e}");
                    }
                }
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_millis(
                    200u64.saturating_mul(attempt as u64),
                ))
                .await;
            }

            let now_bytes =
                bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed) + data.len() as u64;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let prev = last_emit.load(Ordering::Relaxed);
            if now.saturating_sub(prev) >= PROGRESS_INTERVAL_MS {
                last_emit.store(now, Ordering::Relaxed);
                emit_progress(
                    &app,
                    ProgressSnapshot {
                        sent_files: completed_files.load(Ordering::Relaxed),
                        total_files,
                        bytes: now_bytes,
                        total_bytes: bytes_total,
                        file_name: &file_name,
                        stage: "sending",
                        started,
                    },
                );
            }
            Ok(())
        }
    }))
    .buffer_unordered(MAX_INFLIGHT_PIECES)
    .try_collect::<Vec<()>>()
    .await
    .map(|_| ())
}

/// 一次进度事件的全部计数（打包传递，避免 8 个参数的调用点各写一遍字段名）。
struct ProgressSnapshot<'a> {
    sent_files: u64,
    total_files: u64,
    bytes: u64,
    total_bytes: u64,
    file_name: &'a str,
    stage: &'a str,
    started: std::time::Instant,
}

fn emit_progress(app: &AppHandle, p: ProgressSnapshot<'_>) {
    let ProgressSnapshot { sent_files, total_files, bytes, total_bytes, file_name, stage, started } = p;
    let _ = app.emit(
        "send-progress",
        serde_json::json!({
            "sent": sent_files,
            "total": total_files,
            "fileName": file_name,
            "stage": stage,
            "bytes": bytes,
            "totalBytes": total_bytes,
            "bytesSent": bytes,
            "elapsedMs": started.elapsed().as_millis() as u64,
        }),
    );
}

async fn fetch_tasks(
    client: &reqwest::Client,
    base: &str,
    session_id: &str,
) -> Result<TaskListResponse, AppError> {
    let url = format!(
        "{base}/api/v4/session/tasks?sessionId={}",
        urlencoding::encode(session_id)
    );
    let mut last: Option<AppError> = None;
    for attempt in 0..=MAX_RETRIES {
        match checked_json(
            client
                .get(&url)
                .timeout(std::time::Duration::from_secs(15))
                .send()
                .await,
            "tasks",
        )
        .await
        {
            Ok(v) => return Ok(v),
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(
                    200u64.saturating_mul(attempt as u64 + 1),
                ))
                .await;
            }
        }
    }
    Err(last.unwrap_or_else(|| AppError("tasks 查询失败".to_string())))
}

async fn checked_json<T: serde::de::DeserializeOwned>(
    resp: Result<reqwest::Response, reqwest::Error>,
    what: &str,
) -> Result<T, AppError> {
    let resp = resp.map_err(|e| AppError(format!("{what} 请求失败: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let snippet: String = body.chars().take(400).collect();
        return Err(AppError(format!("{what} 失败 HTTP {status}: {snippet}")));
    }
    resp.json::<T>()
        .await
        .map_err(|e| AppError(format!("{what} 响应解析失败: {e}")))
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// 单遍读取文件：返回 `(size, mtime_ms, 每 piece SHA-256, 整文件 SHA-256)`。
///
/// 读完后复核 size/mtime；发送期间被改写的文件不允许"带着旧哈希传新内容"。
fn hash_file(path: &Path) -> Result<(u64, i64, Vec<String>, String), AppError> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let meta = std::fs::metadata(path)
        .map_err(|e| AppError(format!("读取文件元数据失败 {}: {e}", path.display())))?;
    if !meta.is_file() {
        return Err(AppError(format!("不是普通文件: {}", path.display())));
    }
    let size = meta.len();
    let mtime_ms = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    let mut f = std::fs::File::open(path)
        .map_err(|e| AppError(format!("打开文件失败 {}: {e}", path.display())))?;
    let mut whole = Sha256::new();
    let mut pieces = Vec::with_capacity(size.div_ceil(PIECE_SIZE) as usize);
    let mut remaining = size;
    let mut buf = vec![0u8; PIECE_SIZE as usize];
    while remaining > 0 {
        let want = remaining.min(PIECE_SIZE) as usize;
        f.read_exact(&mut buf[..want])
            .map_err(|e| AppError(format!("读取文件失败 {}: {e}", path.display())))?;
        whole.update(&buf[..want]);
        let mut ph = Sha256::new();
        ph.update(&buf[..want]);
        pieces.push(hex::encode(ph.finalize()));
        remaining -= want as u64;
    }

    let after = std::fs::metadata(path)
        .map_err(|e| AppError(format!("复核文件元数据失败 {}: {e}", path.display())))?;
    let after_mtime = after
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    if after.len() != size || after_mtime != mtime_ms {
        return Err(AppError(format!(
            "文件在计算哈希期间发生变化，请重试: {}",
            path.display()
        )));
    }
    Ok((size, mtime_ms, pieces, hex::encode(whole.finalize())))
}

fn read_piece(path: &Path, offset: u64, len: usize) -> Result<Vec<u8>, AppError> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)
        .map_err(|e| AppError(format!("打开文件失败 {}: {e}", path.display())))?;
    f.seek(SeekFrom::Start(offset))
        .map_err(|e| AppError(format!("定位分块失败 {}: {e}", path.display())))?;
    let mut data = vec![0u8; len];
    f.read_exact(&mut data)
        .map_err(|e| AppError(format!("读取分块失败 {}: {e}", path.display())))?;
    Ok(data)
}

/// 加密预演：逐 piece 读明文 → AEAD 加密（nonce=序号，确定性）→ 返回**密文**的
/// SHA-256 列表。与接收端解密公式完全同源（kdf L3/L4 + nonce 绑定序号 +
/// AAD 绑定 session/file/piece），上传时按同一公式重加密，密文逐字节一致。
fn cipher_piece_hashes(
    path: &Path,
    size: u64,
    session_id: &str,
    file_id: &str,
    file_key: &[u8; 32],
) -> Result<Vec<String>, AppError> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)
        .map_err(|e| AppError(format!("打开文件失败 {}: {e}", path.display())))?;
    let mut out = Vec::with_capacity(size.div_ceil(PIECE_SIZE) as usize);
    let mut buf = vec![0u8; PIECE_SIZE as usize];
    let mut idx: u64 = 0;
    let mut remaining = size;
    while remaining > 0 {
        let want = remaining.min(PIECE_SIZE) as usize;
        f.read_exact(&mut buf[..want])
            .map_err(|e| AppError(format!("读取文件失败 {}: {e}", path.display())))?;
        let mut nonce = [0u8; lanbackup_core::crypto::aead::NONCE_LEN];
        nonce[4..].copy_from_slice(&idx.to_be_bytes());
        let aad = format!("lanbackup/v4/piece/{session_id}/{file_id}/{idx}").into_bytes();
        let ct = lanbackup_core::crypto::aead::encrypt(file_key, &nonce, &buf[..want], &aad)
            .ok_or_else(|| AppError("piece 加密失败".to_string()))?;
        out.push(hex::encode(sha256_bytes(&ct)));
        idx += 1;
        remaining -= want as u64;
    }
    Ok(out)
}
