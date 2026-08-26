//! 传输模块 - 发送端流程
//!
//! 纯文件拆分重构：本文件内容从原 transfer.rs 原样移入，逻辑零改动。
//! 通过 `use super::*` 访问 mod.rs 中的类型与外部 use。

use super::*;

/// 发送文件（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
///
/// 流程：register → prepare-upload（协商会话）→ 逐个上传（流式，不载入内存）。
/// 加密模式（encryption_mode）：
/// - "simple"：简单加密，key = SHA-256(连接码)（cryptoVersion=1，兼容旧设备）
/// - "ecdh"：复杂加密，prepare-upload 交换 ECDH 公钥 → session_key = PBKDF2(SHA256(ECDH_shared), SHA256(连接码), 600k)
/// - 其他/空：`target_code` 为空时不加密；否则按 "simple" 处理
/// 返回成功上传的文件数。
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

    // 同名相对路径去重：多选目录时若 relative path 相同，保留先出现的条目（用户先选=优先级高）
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
    // 加密 v2：ECDH 复杂加密的协商状态（发送端私钥 + salt，prepare-upload 后派生 session_key）
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
        None // prepare-upload 响应返回接收端公钥后派生
    } else {
        Some(crate::crypto::derive_local_storage_key(&target_code))
    };

    let client = LsHttpClientV2::try_new_without_cert()
        .map_err(|e| AppError(format!("初始化传输客户端失败: {e}")))?;
    let cancel = tokio_util::sync::CancellationToken::new();

    // 构造发送方设备信息（设备名 + 公开 deviceId，不暴露连接码）
    let device_name = identity::get_device_name(&app);
    let device_id = identity::get_device_id(&app);
    // 等待对端接收服务就绪（P2 硬升级：v2 问候 /verify 已删除，无法再触发对端拉起接收服务，
    // 改为直接轮询 TCP 接收端口。断网重连/对端重启后接收服务可能未监听，直接上传会
    // Failed to connect（「恢复按钮失败」的根因）；就绪前查清单还会拿到空清单误判全量重传）
    {
        let ip = target_ip.clone();
        let ready = tauri::async_runtime::spawn_blocking(move || {
            for _ in 0..10 {
                let addr = format!("{ip}:{target_port}");
                if let Ok(a) = addr.parse::<std::net::SocketAddr>() {
                    if std::net::TcpStream::connect_timeout(
                        &a,
                        std::time::Duration::from_millis(500),
                    )
                    .is_ok()
                    {
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
    let info = RegisterDtoV2 {
        alias: device_name.clone(),
        version: "2.2".to_string(),
        device_model: Some("Windows".to_string()),
        device_type: Some(DeviceType::Desktop),
        fingerprint: device_id.clone(),
        port: target_port,
        protocol: ProtocolType::Http,
        download: false,
    };

    // 文件分类（传输策略矩阵，见规格书）：
    // - tiny（<10KB 且非空）→ 每 20 个打包为 ustar tar 流，单会话聚合传输
    // - large/huge（>100MB）→ 8MB 分片续传（分片即独立文件单元）
    //   · 明文 → Scheduler 差异同步：构建 Merkle manifest，prepare-upload 携带扩展字段，
    //     接收端逐块校验已存在文件返回 chunkDiff，只传缺失/不匹配块（增量备份零传输）
    //   · 加密 → 断点续传：查 B 端已收分片只传缺失
    // - 其余（small/normal/empty）→ 单文件流式上传，upload 端点并发
    // - symlink/special 已在扫描阶段跳过；sparse/hardlink 桌面端按整文件传输（降级）
    const CHUNK_SIZE: u64 = 8 * 1024 * 1024; // 8MB 大分块（与接收端 merge_chunked 兼容）
    const LARGE_THRESHOLD: u64 = 100 * 1024 * 1024; // >100MB 视为大文件
    const TINY_BATCH_SIZE: usize = 20; // tiny 每批聚合数
    let mut tiny: Vec<SendFileItem> = Vec::new();
    let mut normal: Vec<SendFileItem> = Vec::new();
    // 加密大文件（走断点续传）
    let mut large_legacy: Vec<(SendFileItem, u64)> = Vec::new();
    // Scheduler 差异同步计划：(plan 下标, 原始文件, 大小, FileManifest)
    let mut sched_plans: Vec<(usize, SendFileItem, u64, crate::scheduler::FileManifest)> = Vec::new();
    let mut sched_counter = 0usize;
    for f in &files {
        let size = std::fs::metadata(&f.abs_path).map(|m| m.len()).unwrap_or(0);
        if size > 0 && size < 10 * 1024 {
            tiny.push(f.clone());
        } else if size > LARGE_THRESHOLD {
            if !use_encryption {
                // 明文大文件 → Scheduler 差异同步（分片 8MB 与 merge_chunked 对齐）
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
    // Scheduler 分片切片记录：(chunked_items 内索引, plan 下标, 块索引) —— prepare 后按 chunkDiff 过滤
    let mut sched_slices: Vec<(usize, usize, u32)> = Vec::new();
    if !large_legacy.is_empty() {
        // 加密大文件断点续传分片查询并行化：spawn_blocking 防止同步 HTTP 占住 async worker，
        // join_all 全部并发（原先逐文件串行、单次查询最长阻塞 ~4.5s）
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
                    // 查询失败（B 端不支持/不可达）→ 降级整文件传输
                    crate::log_warn!("分片状态查询失败，整文件传输: {}", f.rel_path);
                    normal.push(f.clone());
                }
            }
        }
    }
    // Scheduler 明文大文件：全量分片进传输计划（prepare 后按接收端 chunkDiff 过滤上传）
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
    // 上传单元列表：batch（tar 聚合）优先，其后是分片/普通文件
    let mut upload_items: Vec<SendFileItem> = Vec::with_capacity(files.len() + 1);
    let mut batch_tmp: Vec<PathBuf> = Vec::new();
    for chunk in tiny.chunks(TINY_BATCH_SIZE) {
        let tar = match pack_batch(chunk) {
            Ok(t) => t,
            Err(e) => {
                // P3-74：pack_batch 失败提前返回，先清理此前已写入的临时 batch tar
                for t in &batch_tmp {
                    let _ = std::fs::remove_file(t);
                }
                return Err(e);
            }
        };
        // 文件名必须唯一：同一毫秒内多个 batch 会冲突互相覆盖（致命），加序号区分
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

    // 流式加密的输出大小可精确预计算（头 12B + 每块 32B 开销 + 明文），
    // 因此加密完全在 upload 流内进行（upload_single 内嵌 LSBK 加密流），
    // 不再需要「全文读→写密文临时文件→上传再读」的三遍磁盘 IO 与双倍磁盘占用
    let sizes: Vec<u64> = upload_items
        .iter()
        .map(|f| {
            let plain = f
                .size
                .unwrap_or_else(|| std::fs::metadata(&f.abs_path).map(|m| m.len()).unwrap_or(0));
            if use_encryption {
                crate::crypto::enc_output_size(plain)
            } else {
                plain
            }
        })
        .collect();

    // 构建文件清单（size = 加密后大小 / 分片大小）
    let mut files_map: HashMap<String, FileDto> = HashMap::new();
    for (i, f) in upload_items.iter().enumerate() {
        let is_batch = i < batch_count;
        files_map.insert(
            format!("f{i}"),
            FileDto {
                id: format!("f{i}"),
                file_name: f.rel_path.clone(),
                size: sizes[i],
                file_type: if is_batch {
                    "application/x-batch-agg".to_string()
                } else {
                    infer_file_type(&f.rel_path)
                },
                sha256: None,
                preview: None,
                metadata: file_modified_rfc3339(&f.abs_path).map(|m| {
                    localsend::model::transfer::FileMetadata {
                        modified: Some(m),
                        accessed: None,
                    }
                }),
                protocol_extensions: None,
                merkle_root: None,
                piece_hashes: None,
                chunk_size: None,
            },
        );
    }
    // Scheduler v1：为明文大文件插入「清单文件」（仅用于协商，接收端不生成 token，
    // 而是据此逐块校验已存在文件并在响应中返回 chunkDiff）。清单文件名 = 正式相对路径，
    // 接收端用 `.chunks/{pct(正式路径)}/` 落盘匹配块，与 `__chunked__` 分片合并路径对齐。
    for (plan_k, f, _size, m) in &sched_plans {
        let fid = format!("s{plan_k}");
        files_map.insert(
            fid.clone(),
            FileDto {
                id: fid.clone(),
                file_name: f.rel_path.clone(),
                size: m.file_size,
                file_type: infer_file_type(&f.rel_path),
                sha256: Some(m.file_sha256.clone()),
                preview: None,
                metadata: file_modified_rfc3339(&f.abs_path).map(|mt| {
                    localsend::model::transfer::FileMetadata {
                        modified: Some(mt),
                        accessed: None,
                    }
                }),
                protocol_extensions: Some(m.protocol_extensions.clone()),
                merkle_root: m.merkle_root.clone(),
                piece_hashes: Some(m.piece_hashes.clone()),
                chunk_size: Some(m.chunk_size),
            },
        );
    }

    // 注册（通知对方本机在线；失败不阻断传输）
    let reg = client
        .register(ProtocolType::Http, &target_ip, target_port, info.clone())
        .await;
    match &reg {
        Ok(_) => crate::log_info!("register 成功 对端={}:{}", target_ip, target_port),
        Err(e) => crate::log_warn!("register 失败（不阻断传输）: {e}"),
    }

    // prepare-upload：协商会话（复杂加密时携带发送端 ECDH 公钥）
    let payload = PrepareUploadRequestDtoV2 {
        info,
        files: files_map,
        ecdh_pub_key: ecdh_sender_pub,
    };
    // Scheduler v1：用 SchedulerHttpClient 发送扩展 prepare-upload（body 含 merkle 清单 / ECDH 公钥），
    // 统一解析 session/tokens/chunkDiff/ecdhPubKey。
    let sched_client = std::sync::Arc::new(crate::scheduler::SchedulerHttpClient::new()?);
    let body = serde_json::to_value(&payload)
        .map_err(|e| AppError(format!("序列化 prepare-upload 失败: {e}")))?;
    let prepared = match sched_client
        .prepare_upload_extended(ProtocolType::Http, &target_ip, target_port, body)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            // P3-30：prepare 失败提前返回，须先清理已创建的 batch 临时 tar，避免磁盘积累
            for t in &batch_tmp {
                let _ = std::fs::remove_file(t);
            }
            return Err(AppError(format!("准备上传失败: {e}")));
        }
    };

    // 无文件被接受（目标端拒绝或 204：session_id 为空）
    if prepared.session_id.is_empty() {
        crate::log_info!("prepare-upload 无响应（目标端未接受任何文件）");
        // 清理临时文件（仅聚合 batch；加密已无临时文件）
        for t in &batch_tmp {
            let _ = std::fs::remove_file(t);
        }
        return Ok(0);
    }
    crate::log_info!(
        "prepare-upload 成功 session={} 接受文件数={}",
        crate::logger::mask(&prepared.session_id),
        prepared.files.len()
    );
    let response = &prepared;

    // 加密 v2 复杂加密：用响应中的接收端 ECDH 公钥派生 session_key（salt = SHA-256(连接码)，双方一致）。
    // 接收端未返回公钥（不支持 ECDH）→ 降级简单加密（连接码派生），保证兼容。
    if enc_key.is_none() && use_encryption {
        if let (Some((priv_b64, salt)), Some(pub_recv)) = (&ecdh_sender_priv, &response.ecdh_pub_key) {
            let shared = crate::crypto::ecdh_derive_shared_secret(priv_b64, pub_recv)
                .map_err(|e| AppError(format!("ECDH 共享密钥派生失败: {e}")))?;
            enc_key = Some(
                crate::crypto::derive_session_key(&shared, salt)
                    .map_err(|e| AppError(format!("session_key 派生失败: {e}")))?,
            );
            crate::log_info!("ECDH 复杂加密协商完成，session_key 已派生");
        } else {
            crate::log_warn!("接收端未返回 ECDH 公钥，降级为简单加密（连接码派生）");
            enc_key = Some(crate::crypto::derive_local_storage_key(&target_code));
        }
    }

    // cancel 链路 STEP 1：会话建立后登记 cancel token 到 active_sessions。
    // handle_cancel（auth.rs）从本表取 token 并 .cancel() → 发送循环真正中断；
    // 之前只登记空值 + emit 事件，发送循环不停，取消通知无效（BUG-取消不生效）。
    {
        let st = app.state::<TransferState>();
        let mut sessions = st
            .active_sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        sessions.insert(response.session_id.clone(), cancel.clone());
    }

    // Scheduler 差异同步引擎：全局并发调度器 + 会话持久化层（session_store）
    let sched = app.state::<crate::scheduler::SendScheduler>();
    let store = app.state::<session_store::DesktopSessionStore>();
    // SendScheduler：注册接收端会话并推进状态机（Preparing → Sending）
    let _peer_session_id = sched.add_peer(target_ip.clone(), target_port).await;
    sched.set_peer_state(&target_ip, target_port, crate::scheduler::SessionState::Sending).await;
    // session_store：创建会话（文件清单 = scheduler manifest）
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
            id: response.session_id.clone(),
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

    // Scheduler 差异同步：按接收端返回的 chunkDiff 跳过已匹配块（增量备份零传输）。
    // skip_global 记录要跳过的 upload_items 全局索引（batch 之后）。
    let mut skip_global: std::collections::HashSet<usize> = std::collections::HashSet::new();
    if let Some(diff_map) = &response.chunk_diff {
        for (gi, plan_k, chunk_idx) in &sched_slices {
            let fid = format!("s{plan_k}");
            let keep = diff_map.get(&fid).map_or(true, |d| {
                d.missing_chunks.contains(chunk_idx) || d.mismatched_chunks.contains(chunk_idx)
            });
            if !keep {
                skip_global.insert(batch_count + gi);
            }
        }
        if !skip_global.is_empty() {
            crate::log_info!(
                "Scheduler 差异同步: 跳过 {} 个已匹配分片（增量备份零传输）",
                skip_global.len()
            );
        }
    } else if !sched_plans.is_empty() {
        // Scheduler v1 降级：接收端未返回 chunkDiff（未配置接收目录/不支持扩展）时，
        // 用 get_diff 逐块探测接收端是否已有匹配块（206 = 跳过），结合接收端 /diff 端点。
        crate::log_info!("Scheduler 差异同步: 接收端未返回 chunkDiff，降级用 GET /diff 逐块探测");
        for (gi, plan_k, chunk_idx) in &sched_slices {
            let fid = format!("f{}", batch_count + gi);
            let manifest = &sched_plans[*plan_k].3;
            let piece = manifest
                .piece_hashes
                .get(*chunk_idx as usize)
                .cloned()
                .unwrap_or_default();
            let etag = crate::scheduler::format_etag(&piece);
            let matched = matches!(
                sched_client
                    .get_diff(
                        ProtocolType::Http,
                        &target_ip,
                        target_port,
                        &response.session_id,
                        &fid,
                        *chunk_idx,
                        CHUNK_SIZE,
                        &etag,
                    )
                    .await,
                Ok(crate::scheduler::DiffResponse::ChunkMatched { .. })
            );
            if matched {
                skip_global.insert(batch_count + gi);
            }
        }
        if !skip_global.is_empty() {
            crate::log_info!(
                "Scheduler 差异同步(get_diff): 跳过 {} 个已匹配分片",
                skip_global.len()
            );
        }
    }

    // scheduler 分片的全局索引与块索引映射（上传循环据此用 upload_chunk 而非流式 upload）
    let sched_global: std::collections::HashSet<usize> =
        sched_slices.iter().map(|(gi, _, _)| batch_count + gi).collect();
    let sched_idx_map: std::collections::HashMap<usize, (usize, u32)> = sched_slices
        .iter()
        .map(|(gi, pk, ci)| (batch_count + gi, (*pk, *ci)))
        .collect();

    // 第 2 遍：流式上传——加密在流内进行（upload_single 内嵌 LSBK 加密流），全程零临时文件。
    // batch tar 顺序上传；分片/普通文件用 buffer_unordered(8) 滚动并发：
    // 任何时刻保持 8 个在途，单个慢文件不再拖住整组（原先按组 join_all 的 convoy 问题）
    use std::sync::atomic::Ordering;
    let total_units = (upload_items.len() - skip_global.len()) as u64;
    let sent_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let planned_bytes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    // batch 文件（upload_items[0..batch_count]）顺序上传
    for (bi, f) in upload_items.iter().take(batch_count).enumerate() {
        let file_id = format!("f{bi}");
        let Some(token) = response.files.get(&file_id) else {
            continue;
        };
        let upload_size = sizes[bi];
        planned_bytes.fetch_add(upload_size, Ordering::Relaxed);
        crate::log_info!("批量聚合上传 tiny → {} ({}B)", f.rel_path, upload_size);
        // P6：v3 配对目标 → per-file transfer_key（batch tar 也按 file_id 派生）
        let key = per_file_enc_key(&app, &target_ip, &file_id, enc_key);
        upload_single_with_retry(
            &client,
            target_ip.clone(),
            target_port,
            response.session_id.clone(),
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
    // 分片/普通文件：滚动 8 并发（完成一个补位一个）；跳过 scheduler 已匹配分片
    let normal_units: Vec<(usize, &SendFileItem)> = upload_items
        .iter()
        .enumerate()
        .filter(|(i, _)| *i >= batch_count && !skip_global.contains(i))
        .collect();
    let mut futs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AppError>> + Send>>> =
        Vec::with_capacity(normal_units.len());
    for (i, f) in normal_units {
        let Some(token) = response.files.get(&format!("f{i}")).cloned() else {
            crate::log_debug!("目标端未接受 {}，跳过", f.rel_path);
            continue;
        };
        planned_bytes.fetch_add(sizes[i], Ordering::Relaxed);
        let sent_now = sent_counter.load(Ordering::Relaxed);
        let counter = sent_counter.clone();
        let app2 = app.clone();
        let ip = target_ip.clone();
        let sid = response.session_id.clone();
        let cancel2 = cancel.clone();
        let rel = f.rel_path.clone();
        let path = PathBuf::from(&f.abs_path);
        let size_i = sizes[i];
        let offset = f.offset;
        let csize = f.size;
        let client_ref = &client;
        // Scheduler 分片（明文大文件）：走 upload_chunk 分块上传（SendScheduler 信号量 + session_store 进度）
        if sched_global.contains(&i) {
            let (plan_k, chunk_idx) = *sched_idx_map.get(&i).unwrap_or(&(0, 0));
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
                // 全局分片信号量：限制并发分片数（SendScheduler 并发控制）
                let _permit = sem
                    .acquire_owned()
                    .await
                    .map_err(|_| AppError("调度器信号量关闭".to_string()))?;
                // 读分片数据（scheduler 仅明文大文件，无需加密）
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
                // 完成级进度事件（upload_scheduler_chunk 内已按块发字节级进度）
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
        // P6：v3 配对目标 → per-file transfer_key（普通文件按 file_id 派生）
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
            // 完成级进度事件：前端实时刷新文件数（字节级进度在 upload_single 流内 250ms 限频）
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
        // 失败：SendScheduler 移除 peer + session_store 标记失败
        sched.set_peer_state(&target_ip, target_port, crate::scheduler::SessionState::Error(e.to_string())).await;
        sched.remove_peer(&target_ip, target_port).await;
        let _ = store.fail_session(&response.session_id, Some(e.to_string())).await;
        for t in &batch_tmp {
            let _ = std::fs::remove_file(t);
        }
        return Err(e);
    }
    // 成功：SendScheduler 标记完成并移除 peer + session_store 标记完成
    sched.set_peer_state(&target_ip, target_port, crate::scheduler::SessionState::Complete).await;
    sched.remove_peer(&target_ip, target_port).await;
    let _ = store.complete_session(&response.session_id).await;
    let sent = sent_counter.load(Ordering::Relaxed);
    let total_bytes = planned_bytes.load(Ordering::Relaxed);
    crate::log_info!("发送完成: 共发送 {sent}/{total_units} 个传输单元");

    // 记录传输历史（SQLite）：方向=发送、对端、文件数、字节、耗时
    if let Err(e) = app
        .state::<crate::AppState>()
        .db
        .add_transfer("out", &target_ip, sent, total_bytes, started.elapsed().as_millis() as u64)
    {
        crate::log_warn!("写入传输历史失败: {e}");
    }
    // 通知前端刷新传输历史（发送方自己的记录也实时可见）
    let _ = app.emit("transfers-updated", ());

    // 清理临时文件（仅剩聚合 batch tar；加密路径已零临时文件）
    for t in &batch_tmp {
        let _ = std::fs::remove_file(t);
    }

    Ok(sent)
}

/// Scheduler 差异同步：单分片 upload_chunk 上传（含重试 + session_store 进度 + 字节级进度事件）。
/// 仅用于明文大文件分片（scheduler 与加密互斥），数据为明文块，无需加密。
#[allow(clippy::too_many_arguments)]
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
        // SendScheduler 重试令牌桶：限流在途重试（防止重试风暴）
        let _retry_permit = retry_bucket
            .acquire()
            .await
            .map_err(|_| AppError("调度器重试令牌桶关闭".to_string()))?;
        match client
            .upload_chunk(ProtocolType::Http, ip, port, session_id, file_id, token, chunk_index, data.clone())
            .await
        {
            Ok(crate::scheduler::UploadChunkResponse::Ok) => break,
            Ok(crate::scheduler::UploadChunkResponse::ChecksumFailed { reason }) => {
                crate::log_warn!(
                    "Scheduler 分片校验失败 {} 块{}: {}",
                    file_name,
                    chunk_index,
                    reason
                );
                if attempts >= 3 {
                    return Err(AppError(format!(
                        "Scheduler 分片校验失败: {file_name} 块{chunk_index}"
                    )));
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
    // session_store：更新该文件分片进度
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
    // 字节级进度事件（scheduler 分片为整块上传，进度按块粒度）
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

/// session_store 会话时间戳（unix 毫秒字符串，兼容 session_store::chrono_lite_now 的回退分支）
fn session_store_ts() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

/// 单个传输单元流式上传（含块级进度事件，250ms 限频）。
/// enc_key 存在时边读边加密（LSBK 多块流式，输出大小与 crypto::enc_output_size 预计算一致），
/// 全程零临时文件：加密不再有「全文读→写临时→再读」的三遍磁盘 IO。
/// 参数全部 owned：供并发任务 move 进 future，避免借用循环局部变量。
#[allow(clippy::too_many_arguments)]
async fn upload_single(
    client: &LsHttpClientV2,
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
    crate::log_debug!("开始上传 {} ({}B)", file_name, upload_size);
    let mut file = tokio::fs::File::open(&upload_path)
        .await
        .map_err(|e| AppError(format!("打开文件失败 {}: {e}", upload_path.display())))?;
    // 分片续传：seek 到 offset 并只读 size 字节（加密与明文都按明文区间读取，加密在流内进行）
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    if let Some(off) = offset {
        file.seek(std::io::SeekFrom::Start(off))
            .await
            .map_err(|e| AppError(format!("分片 seek 失败 {}: {e}", upload_path.display())))?;
    }
    let limited = file.take(chunk_size.unwrap_or(u64::MAX));
    // 块级进度：包装流，每 ~250ms 推送一次 send-progress（含已传/总字节，前端实时速率）
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
        // 流式加密：凑满 8MB 明文块（短读合并）→ GCM 原地密封 → 产出网络块；
        // 空文件仍输出 12B 格式头（与 encrypt_stream 行为一致，接收端可识别）
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
                        // 探针：加密流 EOF（首块何时产出是分片卡死排查关键）
                        crate::log_debug!("加密流 EOF: {} 共产出 {blocks_out} 块", probe_name);
                        return None; // 正常 EOF
                    }
                    let out = crate::crypto::stream_header_bytes(crate::crypto::STREAM_ENC_BLOCK)
                        .to_vec();
                    return Some((Ok(out), (r, key, true, blocks_out + 1, probe_name)));
                }
                let mut out = Vec::with_capacity(12 + total + 32);
                if !header_sent {
                    out.extend_from_slice(&crate::crypto::stream_header_bytes(
                        crate::crypto::STREAM_ENC_BLOCK,
                    ));
                }
                buf.truncate(total);
                // 探针：首块产出时刻（卡死时此日志缺失 → 卡在文件读取/首块之前）
                if blocks_out == 0 {
                    crate::log_debug!("加密流首块: {} {total}B", probe_name);
                }
                match crate::crypto::seal_stream_block(&key, &mut buf, &mut out) {
                    Ok(()) => Some((Ok(out), (r, key, true, blocks_out + 1, probe_name))),
                    Err(e) => Some((
                        Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                        (r, key, true, blocks_out + 1, probe_name),
                    )),
                }
            },
        )
        .map(move |chunk| {
            if let Ok(data) = &chunk {
                on_chunk(data.len());
            }
            chunk
        });
        localsend::reqwest::Body::wrap_stream(stream)
    } else {
        let stream = tokio_util::io::ReaderStream::with_capacity(limited, 256 * 1024).map(
            move |chunk| {
                if let Ok(data) = &chunk {
                    on_chunk(data.len());
                }
                chunk
            },
        );
        localsend::reqwest::Body::wrap_stream(stream)
    };
    client
        .upload(
            ProtocolType::Http,
            &target_ip,
            target_port,
            None,
            &session_id,
            &file_id,
            &token,
            body,
            cancel,
        )
        .await
        .map_err(|e| AppError(format!("上传失败 {file_name}: {e}")))?;
    crate::log_debug!("上传完成 {file_name} ({}B)", upload_size);
    Ok(())
}

// ============================================================
// scheduler v1 扩展：422 重试 + 指数退避
// ============================================================

/// 从错误字符串中提取 HTTP 状态码（用于判断是否 422 校验失败）
fn extract_status_code(err: &str) -> Option<u16> {
    // LocalSend 返回格式：JSON {"statusCode":422,...} 或 "statusCode":422
    err.split("statusCode")
        .nth(1)
        .and_then(|s| s.chars().filter(|c| c.is_ascii_digit()).take(3).collect::<String>().parse().ok())
}

/// 带重试的上传包装器：检测到 422 校验失败时，使用指数退避重试（最多 5 次）。
/// 其他错误直接返回。
async fn upload_single_with_retry(
    client: &LsHttpClientV2,
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
                // 提取状态码判断
                let status = extract_status_code(err_str).unwrap_or(0);

                // 仅 422/408/429/5xx 可重试
                if !is_checksum_failure_retryable(status) {
                    crate::log_warn!("上传失败（不重试 status={}) {}", status, err_str);
                    return Err(e);
                }

                if attempt >= MAX_RETRIES {
                    crate::log_error!("上传重试耗尽（status={}) {}", status, err_str);
                    return Err(e);
                }

                let delay_ms = jittered_backoff_ms(attempt);
                crate::log_warn!(
                    "上传 422 校验失败，重试 {}/{}（delay={}ms）: {}",
                    attempt + 1,
                    MAX_RETRIES,
                    delay_ms,
                    file_name
                );
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                attempt += 1;
                // 重试时重新打开文件（upload_single 内部会 seek 到 offset）
            }
        }
    }
}

// ============================================================
// ustar tar 打包/解包（手写实现，不引依赖）
// tiny 文件批量聚合：多个小文件打包为单一 tar 流，一次连接传输
// ============================================================

/// 把一批 tiny 文件打包为自定义聚合字节流（批次 ≤ 数百个 10KB 级文件，内存可接受）。
/// 格式（无对齐、无校验和、无 100 字符文件名限制）：
/// `[u32 LE 文件名长度][文件名][u64 LE 文件大小][文件内容]` 循环。
/// fileType 仍标记为 application/x-tar-batch（协议兼容），内容为上述自定义格式。
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

/// 查询 B 端大文件已收分片（GET 配对服务 /api/backup/v1/chunk-status，断点续传用）
pub fn query_chunk_status(ip: &str, port: u16, rel_path: &str) -> Result<Vec<u32>, AppError> {
    let path = format!(
        "/api/backup/v1/chunk-status?encodedPath={}",
        pct_encode(rel_path)
    );
    let v = http_json_request(ip, port + 1, "GET", &path, "")?;
    let received: Vec<u32> = v
        .get("receivedChunks")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|c| c.as_u64().map(|u| u as u32)).collect())
        .unwrap_or_default();
    // 探针：断点续传曾"已同步 0 个文件"（对端查询恒空），记录请求/响应供定位
    crate::log_debug!(
        "chunk-status 查询: 对端={}:{} file={} → 已收 {} 片",
        ip,
        port + 1,
        crate::logger::mask(rel_path),
        received.len()
    );
    Ok(received)
}
