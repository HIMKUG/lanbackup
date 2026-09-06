//! 传输模块 - 发送端流程（V4 协议版）
//!
//! 使用 V4 协议端点与接收端通信：
//! - POST /api/v4/session/register   会话注册
//! - POST /api/v4/session/prepare    上传准备，响应带 token
//! - POST /api/v4/session/chunk      分块上传
//! - GET  /api/v4/session/diff      块差异探测
//! - POST /api/v4/session/heartbeat 心跳
//! - POST /api/v4/session/abort     中止会话
//!
//! **调度核心**：使用 `lanbackup_core::transfer::SessionDriver` 作为唯一编排器。
//! Decision-IO 分离原则 —— SessionDriver 只做决策，desktop 负责所有 IO。

use super::*;

use lanbackup_core::dto::session::{
    SessionRegisterRequest, FileMeta as CoreFileMeta,
    PrepareRequest, PrepareResponse,
};
#[allow(unused_imports)]
use lanbackup_core::transfer::session::{SessionDriver, Step, Outcome, Applied, SessionError};
#[allow(unused_imports)]
use lanbackup_core::transfer::chunk::{ChunkPlan, PIECE_SIZE, BASIC_CHUNK_SIZE, PIECES_PER_BLOCK, strong_checksum, weak_checksum, PieceHash};
use lanbackup_core::version::{Capabilities, CAP_ADVANCED};

pub async fn send_files(
    app: AppHandle,
    target_ip: String,
    target_port: u16,
    target_code: String,
    files: Vec<SendFileItem>,
    encryption_mode: String,
) -> Result<u64, AppError> {
    crate::log_info!(
        "发送文件: 目标={target_ip}:{target_port} 文件数={} 加密={} 模式={}",
        files.len(),
        if target_code.is_empty() { "否" } else { "是" },
        encryption_mode
    );
    if files.is_empty() {
        return Ok(0);
    }

    let original_count = files.len();
    let files: Vec<SendFileItem> = {
        let mut seen: std::collections::HashMap<String, ()> = std::collections::HashMap::new();
        files.into_iter().filter(|f| {
            use std::collections::hash_map::Entry;
            match seen.entry(f.rel_path.clone()) {
                Entry::Vacant(e) => { e.insert(()); true }
                Entry::Occupied(_) => false,
            }
        }).collect()
    };
    if files.len() < original_count {
        crate::log_warn!("send_files: 去重前 {} 文件，去重后 {} 文件", original_count, files.len());
    }
    let started = std::time::Instant::now();

    let use_encryption = !target_code.is_empty();
    let mut ecdh_sender_pub: Option<String> = None;
    let mut ecdh_sender_priv: Option<(String, [u8; 32])> = None;
    if use_encryption && encryption_mode == "ecdh" {
        let (priv_b64, pub_b64) = crate::crypto::ecdh_generate_keypair()
            .map_err(|e| AppError(format!("ECDH 密钥生成失败: {e}")))?;
        let salt = crate::crypto::derive_local_storage_key(&target_code);
        ecdh_sender_pub = Some(pub_b64);
        ecdh_sender_priv = Some((priv_b64, salt));
    }
    let mut enc_key: Option<[u8; 32]> = if !use_encryption {
        None
    } else if encryption_mode == "ecdh" {
        None
    } else {
        Some(crate::crypto::derive_local_storage_key(&target_code))
    };

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(70))
        .build()
        .map_err(|e| AppError(format!("创建 HTTP 客户端失败: {e}")))?;

    let cancel = tokio_util::sync::CancellationToken::new();
    let device_name = identity::get_device_name(&app);
    let device_id = identity::get_device_id(&app);

    {
        let ip = target_ip.clone();
        let ready = tauri::async_runtime::spawn_blocking(move || {
            for _ in 0..10 {
                let addr = format!("{ip}:{target_port}");
                if let Ok(a) = addr.parse::<std::net::SocketAddr>() {
                    if std::net::TcpStream::connect_timeout(
                        &a,
                        std::time::Duration::from_millis(500),
                    ).is_ok() {
                        return true;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            false
        })
        .await
        .unwrap_or(false);
        if ready {
            crate::log_debug!("对端接收服务已就绪: {target_ip}:{target_port}");
        } else {
            crate::log_warn!("对端接收服务未就绪，继续尝试传输: {target_ip}:{target_port}");
        }
    }

    const CHUNK_SIZE: u64 = 8 * 1024 * 1024;
    const LARGE_THRESHOLD: u64 = 100 * 1024 * 1024;
    const TINY_BATCH_SIZE: usize = 20;
    let mut tiny: Vec<SendFileItem> = Vec::new();
    let mut normal: Vec<SendFileItem> = Vec::new();
    let mut large_legacy: Vec<(SendFileItem, u64)> = Vec::new();
    let mut sched_plans: Vec<(usize, SendFileItem, u64, crate::scheduler::FileManifest)> = Vec::new();
    let mut sched_counter = 0usize;
    for f in &files {
        let size = std::fs::metadata(&f.abs_path).map(|m| m.len()).unwrap_or(0);
        if size > 0 && size < 10 * 1024 {
            tiny.push(f.clone());
        } else if size > LARGE_THRESHOLD {
            if !use_encryption {
                let manifest = crate::scheduler::build_manifest(
                    format!("s{sched_counter}"),
                    f.rel_path.clone(),
                    std::path::Path::new(&f.abs_path),
                    CHUNK_SIZE,
                )?;
                sched_plans.push((sched_counter, f.clone(), size, manifest));
                sched_counter += 1;
            } else {
                large_legacy.push((f.clone(), size));
            }
        } else {
            normal.push(f.clone());
        }
    }
    let mut chunked_items: Vec<SendFileItem> = Vec::new();
    let mut sched_slices: Vec<(usize, usize, u32)> = Vec::new();
    if !large_legacy.is_empty() {
        let queries: Vec<_> = large_legacy
            .iter()
            .map(|(f, _)| {
                let ip = target_ip.clone();
                let rel = f.rel_path.clone();
                tauri::async_runtime::spawn_blocking(move || {
                    query_chunk_status(&ip, target_port, &rel)
                })
            })
            .collect();
        let results = futures_util::future::join_all(queries).await;
        for ((f, size), res) in large_legacy.iter().zip(results) {
            let status = match res {
                Ok(Ok(v)) => Ok(v),
                _ => Err(()),
            };
            match status {
                Ok(received) => {
                    let total = ((size + CHUNK_SIZE - 1) / CHUNK_SIZE) as u32;
                    let mut idx = 0u32;
                    let mut off = 0u64;
                    while off < *size {
                        if !received.contains(&idx) {
                            let chunk_size = (*size).min(off + CHUNK_SIZE) - off;
                            let width = total.to_string().len();
                            chunked_items.push(SendFileItem {
                                rel_path: format!(
                                    "__chunked__/{}/{:0width$}/{:0width$}",
                                    pct_encode(&f.rel_path),
                                    idx,
                                    total,
                                    width = width
                                ),
                                abs_path: f.abs_path.clone(),
                                offset: Some(off),
                                size: Some(chunk_size),
                            });
                        }
                        off += CHUNK_SIZE;
                        idx += 1;
                    }
                    if !received.is_empty() {
                        crate::log_info!(
                            "断点续传: {} 已收 {} 个分片，本次补传缺失分片",
                            f.rel_path,
                            received.len()
                        );
                    }
                }
                Err(_) => {
                    crate::log_warn!("分片状态查询失败，整文件传输: {}", f.rel_path);
                    normal.push(f.clone());
                }
            }
        }
    }
    for (plan_k, f, size, _m) in &sched_plans {
        let total = ((*size + CHUNK_SIZE - 1) / CHUNK_SIZE) as u32;
        let width = total.to_string().len();
        let mut idx = 0u32;
        let mut off = 0u64;
        while off < *size {
            let chunk_size = (*size).min(off + CHUNK_SIZE) - off;
            let gi = chunked_items.len();
            chunked_items.push(SendFileItem {
                rel_path: format!(
                    "__chunked__/{}/{:0width$}/{:0width$}",
                    pct_encode(&f.rel_path),
                    idx,
                    total,
                    width = width
                ),
                abs_path: f.abs_path.clone(),
                offset: Some(off),
                size: Some(chunk_size),
            });
            sched_slices.push((gi, *plan_k, idx));
            off += CHUNK_SIZE;
            idx += 1;
        }
    }

    let mut upload_items: Vec<SendFileItem> = Vec::with_capacity(files.len() + 1);
    let mut batch_tmp: Vec<PathBuf> = Vec::new();
    for chunk in tiny.chunks(TINY_BATCH_SIZE) {
        let tar = match pack_batch(chunk) {
            Ok(t) => t,
            Err(e) => {
                for t in &batch_tmp {
                    let _ = std::fs::remove_file(t);
                }
                return Err(e);
            }
        };
        let tmp = std::env::temp_dir().join(format!(
            "backup_batch_{}_{}_{}.tar",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            batch_tmp.len()
        ));
        std::fs::write(&tmp, &tar).map_err(AppError::from_display)?;
        batch_tmp.push(tmp.clone());
        upload_items.push(SendFileItem {
            rel_path: format!("__batch__.agg.{}", batch_tmp.len()),
            abs_path: tmp.to_string_lossy().to_string(),
            offset: None,
            size: None,
        });
    }
    upload_items.extend(chunked_items);
    upload_items.extend(normal.iter().cloned());
    let batch_count = batch_tmp.len();

    let sizes: Vec<u64> = upload_items
        .iter()
        .map(|f| {
            let plain = f.size.unwrap_or_else(|| std::fs::metadata(&f.abs_path).map(|m| m.len()).unwrap_or(0));
            if use_encryption {
                crate::crypto::enc_output_size(plain)
            } else {
                plain
            }
        })
        .collect();

    let session_id = uuid::Uuid::new_v4().to_string();

    let base_url = format!("http://{target_ip}:{target_port}");

    let reg_req = SessionRegisterRequest {
        device_id: device_id.clone(),
        alias: device_name.clone(),
        session_id: session_id.clone(),
    };
    match http_client
        .post(format!("{base_url}/api/v4/session/register"))
        .json(&reg_req)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                crate::log_info!("register 成功 对端={}:{}", target_ip, target_port);
            } else {
                crate::log_warn!("register 失败 status={}", resp.status().as_u16());
            }
        }
        Err(e) => crate::log_warn!("register 失败（不阻断传输）: {e}"),
    }

    let mut prepare_files: std::collections::HashMap<String, CoreFileMeta> = std::collections::HashMap::new();
    let mut file_size_map: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for (i, f) in upload_items.iter().enumerate() {
        let mtime = file_modified_millis(&f.abs_path).unwrap_or(0);
        let size = sizes[i];
        file_size_map.insert(format!("f{i}"), size);
        prepare_files.insert(format!("f{i}"), CoreFileMeta {
            file_id: format!("f{i}"),
            file_name: f.rel_path.clone(),
            rel_path: f.rel_path.clone(),
            size,
            mtime,
            sha256: None,
            merkle_root: None,
            piece_hashes: None,
        });
    }
    for (plan_k, f, _, m) in &sched_plans {
        let fid = format!("s{plan_k}");
        let mtime = file_modified_millis(&f.abs_path).unwrap_or(0);
        file_size_map.insert(fid.clone(), m.file_size);
        prepare_files.insert(fid.clone(), CoreFileMeta {
            file_id: fid,
            file_name: f.rel_path.clone(),
            rel_path: f.rel_path.clone(),
            size: m.file_size,
            mtime,
            sha256: Some(m.file_sha256.clone()),
            merkle_root: m.merkle_root.clone(),
            piece_hashes: Some(m.piece_hashes.clone()),
        });
    }
    let prepare_req = PrepareRequest {
        session_id: session_id.clone(),
        device_id: device_id.clone(),
        files: prepare_files,
    };
    let prepared: PrepareResponse = http_client
        .post(format!("{base_url}/api/v4/session/prepare"))
        .json(&prepare_req)
        .timeout(std::time::Duration::from_secs(70))
        .send()
        .await
        .map_err(|e| AppError(format!("准备上传失败: {e}")))?
        .json()
        .await
        .map_err(|e| AppError(format!("解析 prepare 响应失败: {e}")))?;

    if prepared.session_id.is_empty() {
        crate::log_info!("prepare 无响应（目标端未接受任何文件）");
        for t in &batch_tmp {
            let _ = std::fs::remove_file(t);
        }
        return Ok(0);
    }
    let response_session_id = prepared.session_id.clone();
    crate::log_info!(
        "prepare 成功 session={} 接受文件数={}",
        crate::logger::mask(&response_session_id),
        prepared.files.len()
    );

    if enc_key.is_none() && use_encryption {
        if let (Some((priv_b64, salt)), Some(pub_recv)) = (&ecdh_sender_priv, &ecdh_sender_pub) {
            let shared = crate::crypto::ecdh_derive_shared_secret(priv_b64, pub_recv)
                .map_err(|e| AppError(format!("ECDH 共享密钥派生失败: {e}")))?;
            enc_key = Some(
                crate::crypto::derive_session_key(&shared, salt)
                    .map_err(|e| AppError(format!("session_key 派生失败: {e}")))?,
            );
            crate::log_info!("ECDH 复杂加密协商完成，session_key 已派生");
        } else {
            crate::log_warn!("接收端未返回 ECDH 公钥，降级为简单加密");
            enc_key = Some(crate::crypto::derive_local_storage_key(&target_code));
        }
    }

    {
        let st = app.state::<TransferState>();
        let mut sessions = st.active_sessions.lock().unwrap_or_else(|p| p.into_inner());
        sessions.insert(response_session_id.clone(), cancel.clone());
    }

    let sched = app.state::<crate::scheduler::SendScheduler>();
    let store = app.state::<session_store::DesktopSessionStore>();
    let _peer_session_id = sched.add_peer(target_ip.clone(), target_port).await;
    sched.set_peer_state(&target_ip, target_port, crate::scheduler::SessionState::Sending).await;
    let session_files: Vec<session_store::FileManifest> = sched_plans
        .iter()
        .map(|(_, f, size, m)| session_store::FileManifest {
            id: m.file_id.clone(),
            file_name: f.rel_path.clone(),
            size: *size,
            sha256: m.file_sha256.clone(),
            merkle_root: m.merkle_root.clone(),
            piece_hashes: m.piece_hashes.clone(),
            chunk_size: Some(m.chunk_size),
        })
        .collect();
    let _ = store
        .create_session(session_store::SessionState {
            id: response_session_id.clone(),
            files: session_files,
            peers: vec![crate::scheduler::PeerInfo {
                peer_id: device_id.clone(),
                alias: device_name.clone(),
                ip: target_ip.clone(),
                port: target_port,
                status: crate::scheduler::PeerStatus::Connected,
            }],
            progress: std::collections::HashMap::new(),
            created_at: session_store_ts(),
            updated_at: session_store_ts(),
            status: session_store::SessionStatus::Active,
        })
        .await;

    let mut skip_global: std::collections::HashSet<usize> = std::collections::HashSet::new();
    if !sched_plans.is_empty() {
        crate::log_info!("Scheduler 差异同步: 接收端 chunkDiff 探测（V4 对端）");
        for (gi, plan_k, chunk_idx) in &sched_slices {
            let fid = format!("s{plan_k}");
            let matched = matches!(
                http_client
                    .get(format!(
                        "{base_url}/api/v4/session/diff?sessionId={}&fileId={}&chunkIndex={}&chunkSize={}",
                        urlencoding::encode(&response_session_id),
                        urlencoding::encode(&fid),
                        chunk_idx,
                        CHUNK_SIZE
                    ))
                    .send()
                    .await,
                Ok(resp) if resp.status().as_u16() == 206
            );
            if matched {
                skip_global.insert(batch_count + gi);
            }
        }
        if !skip_global.is_empty() {
            crate::log_info!(
                "Scheduler 差异同步: 跳过 {} 个已匹配分片",
                skip_global.len()
            );
        }
    }

    let sched_global: std::collections::HashSet<usize> =
        sched_slices.iter().map(|(gi, _, _)| batch_count + gi).collect();
    let sched_idx_map: std::collections::HashMap<usize, (usize, u32)> = sched_slices
        .iter()
        .map(|(gi, pk, ci)| (batch_count + gi, (*pk, *ci)))
        .collect();

    let negotiated_caps = Capabilities::from_bits(prepared.capabilities.bits());
    let use_advanced = negotiated_caps.contains(CAP_ADVANCED);
    let mut skip_pieces: std::collections::HashMap<String, Vec<u64>> = std::collections::HashMap::new();
    let mut skip_blocks: std::collections::HashMap<String, std::collections::HashSet<u64>> = std::collections::HashMap::new();

    if use_advanced {
        for (plan_k, _f, size, _manifest) in &sched_plans {
            let plan = ChunkPlan::new(*size, lanbackup_core::dto::session::Algorithm::Advanced);
            let confirmed = query_confirmed_pieces(&http_client, &base_url, &response_session_id, &format!("s{plan_k}"), plan.piece_count, PIECE_SIZE).await;
            if let Some(cp) = confirmed {
                let piece_count = plan.piece_count;
                let block_count = plan.block_count;
                let driver = SessionDriver::resume(plan, false, &cp);
                let step = driver.next_step();
                let key = format!("s{plan_k}");
                if let Step::SendPiece { .. } = step {
                    let mut cp_vec: Vec<u64> = cp.iter().copied().collect();
                    cp_vec.sort_unstable();
                    let blocks: std::collections::HashSet<u64> = cp.iter().map(|p| p / PIECES_PER_BLOCK).collect();
                    let skipped_pieces = cp.len();
                    let skipped_blocks = blocks.len();
                    skip_pieces.insert(key.clone(), cp_vec);
                    skip_blocks.insert(key, blocks);
                    crate::log_info!("SessionDriver: 跳过 {}/{} piece ({}/{} block)",
                        skipped_pieces, piece_count, skipped_blocks, block_count);
                } else if step.is_done() {
                    skip_pieces.insert(key.clone(), vec![]);
                    skip_blocks.insert(key, (0..block_count).collect());
                }
            } else {
                skip_pieces.insert(format!("s{plan_k}"), vec![]);
                skip_blocks.insert(format!("s{plan_k}"), std::collections::HashSet::new());
            }
        }
    }

    use std::sync::atomic::Ordering;
    let total_units = (upload_items.len() - skip_global.len()) as u64;
    let sent_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let planned_bytes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let sched_client = std::sync::Arc::new(crate::scheduler::SchedulerHttpClient::new()?);

    for (bi, f) in upload_items.iter().take(batch_count).enumerate() {
        let file_id = format!("f{bi}");
        let Some(token) = prepared.files.get(&file_id) else {
            continue;
        };
        let upload_size = sizes[bi];
        planned_bytes.fetch_add(upload_size, Ordering::Relaxed);
        crate::log_info!("批量聚合上传 tiny → {} ({}B)", f.rel_path, upload_size);
        let key = per_file_enc_key(&app, &target_ip, &file_id, enc_key);
        upload_single_with_retry(
            &http_client,
            target_ip.clone(),
            target_port,
            response_session_id.clone(),
            file_id,
            token.clone(),
            PathBuf::from(&f.abs_path),
            upload_size,
            None,
            None,
            key,
            cancel.clone(),
            app.clone(),
            f.rel_path.clone(),
            started,
            sent_counter.load(Ordering::Relaxed),
            total_units,
        )
        .await
        .map_err(|e| {
            for t in &batch_tmp {
                let _ = std::fs::remove_file(t);
            }
            e
        })?;
        sent_counter.fetch_add(1, Ordering::Relaxed);
    }

    let normal_units: Vec<(usize, &SendFileItem)> = upload_items
        .iter()
        .enumerate()
        .filter(|(i, _)| *i >= batch_count && !skip_global.contains(i))
        .collect();
    let mut futs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AppError>> + Send>>> =
        Vec::with_capacity(normal_units.len());
    for (i, f) in normal_units {
        let token = match prepared.files.get(&format!("f{i}")) {
            Some(t) => t.clone(),
            None => {
                crate::log_debug!("目标端未接受 {}，跳过", f.rel_path);
                continue;
            }
        };
        planned_bytes.fetch_add(sizes[i], Ordering::Relaxed);
        let sent_now = sent_counter.load(Ordering::Relaxed);
        let counter = sent_counter.clone();
        let app2 = app.clone();
        let ip = target_ip.clone();
        let sid = response_session_id.clone();
        let cancel2 = cancel.clone();
        let rel = f.rel_path.clone();
        let path = PathBuf::from(&f.abs_path);
        let size_i = sizes[i];
        let offset = f.offset;
        let csize = f.size;
        let client_ref = &http_client;

        if sched_global.contains(&i) {
            let (plan_k, chunk_idx) = *sched_idx_map.get(&i).unwrap_or(&(0, 0));
            let file_key = format!("s{plan_k}");
            if skip_blocks.get(&file_key).map(|s| s.contains(&(chunk_idx as u64))).unwrap_or(false) {
                let skipped_n = counter.load(Ordering::Relaxed);
                let _ = app2.emit(
                    "send-progress",
                    serde_json::json!({
                        "sent": skipped_n,
                        "total": total_units,
                        "fileName": f.rel_path,
                        "stage": "skipping",
                        "bytes": 0,
                        "totalBytes": 0,
                        "bytesSent": 0,
                        "elapsedMs": started.elapsed().as_millis() as u64,
                    }),
                );
                continue;
            }
            let pieces_total = sched_plans[plan_k].3.total_chunks;
            let file_id = format!("f{i}");
            let sc = sched_client.clone();
            let sched2 = sched.clone();
            let store2 = store.clone();
            let ip2 = target_ip.clone();
            let path2 = PathBuf::from(&f.abs_path);
            let off = offset.unwrap_or(0);
            let csize2 = csize.unwrap_or(0) as usize;
            let fname = f.rel_path.clone();
            let sem = sched2.global_chunks();
            let rb = sched2.retry_bucket();
            let counter2 = counter.clone();
            let app3 = app2.clone();
            futs.push(Box::pin(async move {
                let _permit = sem
                    .acquire_owned()
                    .await
                    .map_err(|_| AppError("调度器信号量关闭".to_string()))?;
                let data = {
                    use std::io::{Read, Seek, SeekFrom};
                    let mut file = std::fs::File::open(&path2)
                        .map_err(|e| AppError(format!("打开分片失败 {}: {e}", path2.display())))?;
                    file.seek(SeekFrom::Start(off))
                        .map_err(|e| AppError(format!("分片 seek 失败: {e}")))?;
                    let mut buf = vec![0u8; csize2];
                    file.read_exact(&mut buf)
                        .map_err(|e| AppError(format!("分片读取失败: {e}")))?;
                    buf
                };
                upload_scheduler_chunk(
                    &sc,
                    &ip2,
                    target_port,
                    &sid,
                    &file_id,
                    &token,
                    chunk_idx,
                    data,
                    &rb,
                    &store2,
                    &sid,
                    &fname,
                    size_i,
                    pieces_total,
                    &app3,
                    started,
                    sent_now,
                    total_units,
                )
                .await?;
                let n = counter2.fetch_add(1, Ordering::Relaxed) + 1;
                let _ = app3.emit(
                    "send-progress",
                    serde_json::json!({
                        "sent": n,
                        "total": total_units,
                        "fileName": "",
                        "stage": "sending",
                        "bytes": 0,
                        "totalBytes": 0,
                        "bytesSent": 0,
                        "elapsedMs": started.elapsed().as_millis() as u64,
                    }),
                );
                Ok::<(), AppError>(())
            }));
            continue;
        }

        let file_id = format!("f{i}");
        let key = per_file_enc_key(&app2, &ip, &file_id, enc_key);
        futs.push(Box::pin(async move {
            upload_single_with_retry(
                client_ref,
                ip,
                target_port,
                sid,
                file_id,
                token,
                path,
                size_i,
                offset,
                csize,
                key,
                cancel2,
                app2.clone(),
                rel,
                started,
                sent_now,
                total_units,
            )
            .await?;
            let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
            let _ = app2.emit(
                "send-progress",
                serde_json::json!({
                    "sent": n,
                    "total": total_units,
                    "fileName": "",
                    "stage": "sending",
                    "bytes": 0,
                    "totalBytes": 0,
                    "bytesSent": 0,
                    "elapsedMs": started.elapsed().as_millis() as u64,
                }),
            );
            Ok::<(), AppError>(())
        }));
    }
    let results: Result<Vec<()>, AppError> = futures_util::stream::iter(futs)
        .buffer_unordered(8)
        .try_collect()
        .await;
    if let Err(e) = results {
        sched.set_peer_state(&target_ip, target_port, crate::scheduler::SessionState::Error(e.to_string())).await;
        sched.remove_peer(&target_ip, target_port).await;
        let _ = store.fail_session(&response_session_id, Some(e.to_string())).await;
        for t in &batch_tmp {
            let _ = std::fs::remove_file(t);
        }
        return Err(e);
    }
    sched.set_peer_state(&target_ip, target_port, crate::scheduler::SessionState::Complete).await;
    sched.remove_peer(&target_ip, target_port).await;
    let _ = store.complete_session(&response_session_id).await;
    let sent = sent_counter.load(Ordering::Relaxed);
    let total_bytes = planned_bytes.load(Ordering::Relaxed);
    crate::log_info!("发送完成: 共发送 {sent}/{total_units} 个传输单元");

    if let Err(e) = app
        .state::<crate::AppState>()
        .db
        .add_transfer("out", &target_ip, sent, total_bytes, started.elapsed().as_millis() as u64)
    {
        crate::log_warn!("写入传输历史失败: {e}");
    }
    let _ = app.emit("transfers-updated", ());

    for t in &batch_tmp {
        let _ = std::fs::remove_file(t);
    }

    Ok(sent)
}

async fn upload_scheduler_chunk(
    client: &crate::scheduler::SchedulerHttpClient,
    ip: &str,
    port: u16,
    session_id: &str,
    file_id: &str,
    token: &str,
    chunk_index: u32,
    data: Vec<u8>,
    retry_bucket: &tokio::sync::Semaphore,
    store: &session_store::DesktopSessionStore,
    store_session_id: &str,
    file_name: &str,
    upload_size: u64,
    pieces_total: u32,
    app: &tauri::AppHandle,
    started: std::time::Instant,
    sent_so_far: u64,
    total_units: u64,
) -> Result<(), AppError> {
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        let _retry_permit = retry_bucket
            .acquire()
            .await
            .map_err(|_| AppError("调度器重试令牌桶关闭".to_string()))?;
        match client
            .upload_chunk(ip, port, session_id, file_id, token, chunk_index, data.clone())
            .await
        {
            Ok(crate::scheduler::UploadChunkResponse::Ok) => break,
            Ok(crate::scheduler::UploadChunkResponse::ChecksumFailed { reason }) => {
                crate::log_warn!("Scheduler 分片校验失败 {} 块{}: {}", file_name, chunk_index, reason);
                if attempts >= 3 {
                    return Err(AppError(format!("Scheduler 分片校验失败: {file_name} 块{chunk_index}")));
                }
            }
            Err(e) => {
                if attempts >= 3 {
                    return Err(e);
                }
                tokio::time::sleep(std::time::Duration::from_millis(300 * attempts as u64)).await;
            }
        }
    }
    let _ = store
        .update_progress(
            store_session_id,
            {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    file_id.to_string(),
                    crate::scheduler::TransferProgress {
                        file_id: file_id.to_string(),
                        sent_bytes: upload_size,
                        total_bytes: upload_size,
                        pieces_completed: chunk_index + 1,
                        pieces_total,
                        retry_count: attempts.saturating_sub(1),
                        last_error: None,
                    },
                );
                m
            },
        )
        .await;
    let _ = app.emit(
        "send-progress",
        serde_json::json!({
            "sent": sent_so_far + 1,
            "total": total_units,
            "fileName": file_name,
            "stage": "sending",
            "bytes": upload_size,
            "totalBytes": upload_size,
            "bytesSent": upload_size,
            "elapsedMs": started.elapsed().as_millis() as u64,
        }),
    );
    Ok(())
}

fn session_store_ts() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

async fn upload_single(
    client: &reqwest::Client,
    target_ip: String,
    target_port: u16,
    session_id: String,
    file_id: String,
    token: String,
    upload_path: PathBuf,
    upload_size: u64,
    offset: Option<u64>,
    chunk_size: Option<u64>,
    enc_key: Option<[u8; 32]>,
    _cancel: tokio_util::sync::CancellationToken,
    app: tauri::AppHandle,
    file_name: String,
    started: std::time::Instant,
    sent_so_far: u64,
    total_units: u64,
) -> Result<(), AppError> {
    crate::log_debug!("开始上传 {} ({}B)", file_name, upload_size);
    let mut file = tokio::fs::File::open(&upload_path)
        .await
        .map_err(|e| AppError(format!("打开文件失败 {}: {e}", upload_path.display())))?;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    if let Some(off) = offset {
        file.seek(std::io::SeekFrom::Start(off))
            .await
            .map_err(|e| AppError(format!("分片 seek 失败 {}: {e}", upload_path.display())))?;
    }
    let limited = file.take(chunk_size.unwrap_or(u64::MAX));
    let fname = file_name.clone();
    let mut bytes_sent = 0u64;
    let mut last_progress = std::time::Instant::now();
    let app2 = app.clone();
    let mut on_chunk = move |n: usize| {
        bytes_sent += n as u64;
        let now = std::time::Instant::now();
        if now.duration_since(last_progress).as_millis() >= 250 {
            last_progress = now;
            let _ = app2.emit(
                "send-progress",
                serde_json::json!({
                    "sent": sent_so_far,
                    "total": total_units,
                    "fileName": fname,
                    "stage": "sending",
                    "bytes": bytes_sent,
                    "totalBytes": upload_size,
                    "bytesSent": bytes_sent,
                    "elapsedMs": started.elapsed().as_millis() as u64,
                }),
            );
        }
    };
    let body = if let Some(k) = enc_key {
        let stream = futures_util::stream::unfold(
            (limited, k, false, 0u64, file_name.clone()),
            |(mut r, key, header_sent, blocks_out, probe_name)| async move {
                let mut buf = vec![0u8; crate::crypto::STREAM_ENC_BLOCK];
                let mut total = 0usize;
                while total < buf.len() {
                    match r.read(&mut buf[total..]).await {
                        Ok(0) => break,
                        Ok(n) => total += n,
                        Err(e) => return Some((Err(e), (r, key, header_sent, blocks_out, probe_name))),
                    }
                }
                if total == 0 {
                    if header_sent {
                        crate::log_debug!("加密流 EOF: {} 共产出 {blocks_out} 块", probe_name);
                        return None;
                    }
                    let out = crate::crypto::stream_header_bytes(crate::crypto::STREAM_ENC_BLOCK).to_vec();
                    return Some((Ok(out), (r, key, true, blocks_out + 1, probe_name)));
                }
                let mut out = Vec::with_capacity(12 + total + 32);
                if !header_sent {
                    out.extend_from_slice(&crate::crypto::stream_header_bytes(crate::crypto::STREAM_ENC_BLOCK));
                }
                buf.truncate(total);
                if blocks_out == 0 {
                    crate::log_debug!("加密流首块: {} {total}B", probe_name);
                }
                match crate::crypto::seal_stream_block(&key, &mut buf, &mut out) {
                    Ok(()) => Some((Ok(out), (r, key, true, blocks_out + 1, probe_name))),
                    Err(e) => Some((Err(std::io::Error::new(std::io::ErrorKind::Other, e)), (r, key, true, blocks_out + 1, probe_name))),
                }
            },
        )
        .map(move |chunk| {
            if let Ok(data) = &chunk {
                on_chunk(data.len());
            }
            chunk
        });
        reqwest::Body::wrap_stream(stream)
    } else {
        let stream = tokio_util::io::ReaderStream::with_capacity(limited, 256 * 1024).map(
            move |chunk| {
                if let Ok(data) = &chunk {
                    on_chunk(data.len());
                }
                chunk
            },
        );
        reqwest::Body::wrap_stream(stream)
    };

    let url = format!(
        "http://{target_ip}:{target_port}/api/v4/session/chunk?sessionId={}&fileId={}&token={}",
        urlencoding::encode(&session_id),
        urlencoding::encode(&file_id),
        urlencoding::encode(&token)
    );
    client
        .post(&url)
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .map_err(|e| AppError(format!("上传失败 {file_name}: {e}")))?;
    crate::log_debug!("上传完成 {file_name} ({}B)", upload_size);
    Ok(())
}

fn extract_status_code(err: &str) -> Option<u16> {
    err.split("statusCode")
        .nth(1)
        .and_then(|s| s.chars().filter(|c| c.is_ascii_digit()).take(3).collect::<String>().parse().ok())
}

async fn upload_single_with_retry(
    client: &reqwest::Client,
    target_ip: String,
    target_port: u16,
    session_id: String,
    file_id: String,
    token: String,
    upload_path: PathBuf,
    upload_size: u64,
    offset: Option<u64>,
    chunk_size: Option<u64>,
    enc_key: Option<[u8; 32]>,
    cancel: tokio_util::sync::CancellationToken,
    app: tauri::AppHandle,
    file_name: String,
    started: std::time::Instant,
    sent_so_far: u64,
    total_units: u64,
) -> Result<(), AppError> {
    const MAX_RETRIES: u32 = 5;
    let mut attempt = 0;
    loop {
        match upload_single(
            client,
            target_ip.clone(),
            target_port,
            session_id.clone(),
            file_id.clone(),
            token.clone(),
            upload_path.clone(),
            upload_size,
            offset,
            chunk_size,
            enc_key,
            cancel.clone(),
            app.clone(),
            file_name.clone(),
            started,
            sent_so_far,
            total_units,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                let err_str = e.0.as_str();
                let status = extract_status_code(err_str).unwrap_or(0);
                if !crate::scheduler::is_checksum_failure_retryable(status) {
                    crate::log_warn!("上传失败（不重试 status={}) {}", status, err_str);
                    return Err(e);
                }
                if attempt >= MAX_RETRIES {
                    crate::log_error!("上传重试耗尽（status={}) {}", status, err_str);
                    return Err(e);
                }
                let delay_ms = crate::scheduler::jittered_backoff_ms(attempt);
                crate::log_warn!(
                    "上传校验失败，重试 {}/{}（delay={}ms）: {}",
                    attempt + 1,
                    MAX_RETRIES,
                    delay_ms,
                    file_name
                );
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                attempt += 1;
            }
        }
    }
}

fn pack_batch(files: &[SendFileItem]) -> Result<Vec<u8>, AppError> {
    let mut out: Vec<u8> = Vec::new();
    for f in files {
        let data = std::fs::read(&f.abs_path)
            .map_err(|e| AppError(format!("读取小文件失败 {}: {e}", f.abs_path)))?;
        let name = f.rel_path.as_bytes();
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(&data);
    }
    Ok(out)
}

pub fn query_chunk_status(ip: &str, port: u16, rel_path: &str) -> Result<Vec<u32>, AppError> {
    let path = format!(
        "/api/v4/sync/chunk-status?encodedPath={}",
        pct_encode(rel_path)
    );
    let v = http_json_request(ip, port, "GET", &path, "")?;
    let received: Vec<u32> = v
        .get("receivedChunks")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|c| c.as_u64().map(|u| u as u32)).collect())
        .unwrap_or_default();
    crate::log_debug!(
        "chunk-status 查询: 对端={}:{} file={} → 已收 {} 片",
        ip, port,
        crate::logger::mask(rel_path),
        received.len()
    );
    Ok(received)
}

fn file_modified_millis(abs_path: &str) -> Option<i64> {
    std::fs::metadata(abs_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
}

async fn query_confirmed_pieces(
    client: &reqwest::Client,
    base_url: &str,
    session_id: &str,
    file_id: &str,
    piece_count: u64,
    piece_size: u64,
) -> Option<Vec<u64>> {
    let mut confirmed: Vec<u64> = Vec::new();
    let mut all_confirmed = true;
    for idx in 0..piece_count {
        let url = format!(
            "{}/api/v4/session/diff?sessionId={}&fileId={}&pieceIndex={}&pieceSize={}",
            base_url,
            urlencoding::encode(session_id),
            urlencoding::encode(file_id),
            idx,
            piece_size
        );
        match client.get(&url).send().await {
            Ok(resp) => {
                if resp.status() == reqwest::StatusCode::PARTIAL_CONTENT {
                    confirmed.push(idx);
                } else {
                    all_confirmed = false;
                    break;
                }
            }
            Err(_) => {
                all_confirmed = false;
                break;
            }
        }
    }
    if confirmed.is_empty() && all_confirmed && piece_count > 0 {
        return None;
    }
    Some(confirmed)
}
