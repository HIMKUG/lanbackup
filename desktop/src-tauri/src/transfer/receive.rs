//! 传输模块 - 接收端流程
//!
//! 纯文件拆分重构：本文件内容从原 transfer.rs 原样移入，逻辑零改动。
//! 通过 `use super::*` 访问 mod.rs 中的类型与外部 use。

use super::*;

/// 启动接收服务器（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
///
/// 启动后自动接受所有上传请求（备份场景无需逐文件确认），
/// 文件写入 `receive_dir`，同名且内容不同则自动重命名，永不覆盖。
pub async fn start_receiver(
    app: AppHandle,
    receive_dir: String,
    port: u16,
) -> Result<String, AppError> {
    crate::log_info!("启动接收服务器: 目录={receive_dir} 端口={port}");
    let state = app.state::<TransferState>();

    // 已有服务器在运行 → 先停止旧实例再以新目录启动。
    // 关键：用户重新选择接收目录时若不重启，文件会继续写入旧目录。
    {
        let stop_tx = state
            .stop_tx
            .lock()
            .map_err(|_| AppError::from_poison())?
            .take();
        if let Some(tx) = stop_tx {
            let _ = tx.send(());
        }
        let old_handle = state
            .server
            .lock()
            .map_err(|_| AppError::from_poison())?
            .take();
        if let Some(handle) = old_handle {
            handle.wait_stopped().await;
        }
    }

    let dir = PathBuf::from(&receive_dir);
    std::fs::create_dir_all(&dir).map_err(AppError::from_display)?;

    // 事件通道：服务器 → 本模块的事件循环
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<ServerEventV2>(64);
    // 停止通道：stop_receiver 触发
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

    // 本机设备信息：register/info 响应只携带 设备名 + 公开 deviceId，
    // 连接码只用于接收端解密（事件循环内按码缓存派生），绝不向请求方暴露
    let device_name = identity::get_device_name(&app);
    let device_id = identity::get_device_id(&app);
    crate::log_debug!(
        "接收服务器本机信息 名称={} 公开ID={}",
        device_name,
        crate::logger::mask(&device_id)
    );
    // 接收端解密在事件循环内进行（按连接码缓存派生密钥，见下方 cached_code）
    let info = ClientInfo {
        alias: device_name,
        version: "2.2".to_string(),
        device_model: Some("Windows".to_string()),
        device_type: Some(DeviceType::Desktop),
        token: device_id,
    };

    let v2_config = ServerConfigV2 {
        pin: None,
        // 关闭校验和验证：备份场景免去接收后哈希开销
        verify_checksums: false,
        event_tx,
        // Scheduler v1：接收目录，prepare-upload 阶段对携带 Merkle 扩展的大文件
        // 逐块校验已存在文件并返回 chunkDiff（增量备份零传输）
        receive_dir: Some(dir.clone()),
    };

    let handle = start_with_port(port, None, info, None, Some(v2_config), None, stop_rx)
        .await
        .map_err(|e| AppError(format!("启动接收服务器失败: {e}")))?;

    // 保存服务器状态
    *state
        .server
        .lock()
        .map_err(|_| AppError::from_poison())? = Some(handle);
    *state
        .stop_tx
        .lock()
        .map_err(|_| AppError::from_poison())? = Some(stop_tx);
    *state
        .receive_dir
        .lock()
        .map_err(|_| AppError::from_poison())? = Some(dir.clone());
    // P1：清理上次崩溃残留的 .tmp_* 临时分片（与 crate save.rs 原子写入配套），
    // 防积累占用磁盘；残留临时文件不会被 chunk-status 误判为已收完整分片
    let cleanup_dir = dir.clone();
    let _ = tauri::async_runtime::spawn_blocking(move || cleanup_stale_temp_files(&cleanup_dir)).await;
    // 自愈依据：服务器应运行 + 非停止意图（清掉上次停止残留的标记）
    state.receiver_should_run.store(true, Ordering::Relaxed);
    state.receiver_stop_intent.store(false, Ordering::Relaxed);

    // 事件循环：自动接受上传，决定每个文件的保存路径（含冲突重命名），写完后解密
    let event_dir = dir.clone();
    tauri::async_runtime::spawn(async move {
        // 接收会话累计：按会话聚合写入接收历史（文件数/字节/耗时）
        let mut recv_started: Option<std::time::Instant> = None;
        let mut recv_expected: Option<u64> = None;
        let mut recv_count: u64 = 0;
        let mut recv_bytes: u64 = 0;
        let mut recv_failed: u64 = 0;
        let mut recv_total: u64 = 0;
        // 接收超时兜底：会话中断（发送方崩溃/网络断开/文件缺失）时若 5 分钟无任何事件，
        // 强制落一条接收历史。注意：只 finalize 统计、不退出循环——服务器仍在监听，
        // 若 break 会导致"端口通但事件无人消费"的失聪状态（watchdog 仅探测 TCP 连通性，
        // 永远不会触发自愈）。空闲等待是接收端的正常稳态。
        let recv_timeout = std::time::Duration::from_secs(300);
        // 解密密钥缓存：连接码不变时逐文件零派生开销（原先每文件一次磁盘读 + SHA-256）；
        // 刷新连接码后自动重算，「刷新立即生效」语义不变
        let mut cached_code = identity::get_self_code(&app);
        let mut decrypt_key = crate::crypto::derive_local_storage_key(&cached_code);
        loop {
            let event = match tokio::time::timeout(recv_timeout, event_rx.recv()).await {
                Ok(Some(ev)) => ev,
                Ok(None) => break, // 发送方正常关闭通道
                Err(_) => {
                    crate::log_warn!("接收会话超时（5 分钟无事件），统计已落盘，继续监听");
                    finalize_receive(&app, &mut recv_started, &mut recv_count, &mut recv_bytes, &mut recv_failed);
                    continue;
                }
            };
            match event {
                ServerEventV2::PrepareUpload {
                    files,
                    decision_tx,
                    session_id,
                    ip,
                    info,
                    sender_ecdh_pub,
                    ..
                } => {
                    // 加密 v2 复杂加密协商：发送端携带 ECDH 公钥时，生成接收端密钥对、
                    // 派生 session_key（salt = SHA-256(本机连接码)，与发送端一致），
                    // 存入 ecdh_session_keys 供 FileUpload 解密；返回接收端公钥。
                    let mut recv_ecdh_pub: Option<String> = None;
                    if let Some(sender_pub) = sender_ecdh_pub {
                        if let Ok((priv_b64, pub_b64)) = crate::crypto::ecdh_generate_keypair() {
                            match crate::crypto::ecdh_derive_shared_secret(&priv_b64, &sender_pub)
                                .and_then(|shared| {
                                    let code = identity::get_self_code(&app);
                                    let salt = crate::crypto::derive_local_storage_key(&code);
                                    crate::crypto::derive_session_key(&shared, &salt)
                                }) {
                                Ok(sk) => {
                                    if let Ok(mut m) = app
                                        .state::<TransferState>()
                                        .ecdh_session_keys
                                        .lock()
                                    {
                                        m.insert(session_id.clone(), sk);
                                    }
                                    // A2：会话闲置清理——巡检式而非固定延时。
                                    // 每 60s 检查一次"距最后分片到达是否超过 300s"，
                                    // 活跃长传输在 FileUpload 处持续续期，不会被误杀；
                                    // 只有真正闲置（发送方异常中断）的会话才被回收。
                                    {
                                        if let Ok(mut m) = app
                                            .state::<TransferState>()
                                            .session_last_activity
                                            .lock()
                                        {
                                            m.insert(session_id.clone(), std::time::Instant::now());
                                        }
                                    }
                                    let sid = session_id.clone();
                                    let ap = app.clone();
                                    tauri::async_runtime::spawn(async move {
                                        loop {
                                            tokio::time::sleep(std::time::Duration::from_secs(
                                                crate::transfer::SESSION_SWEEP_INTERVAL_SECS,
                                            ))
                                            .await;
                                            let ts = ap.state::<crate::transfer::TransferState>();
                                            let idle_for = ts
                                                .session_last_activity
                                                .lock()
                                                .ok()
                                                .and_then(|m| m.get(&sid).map(|t| t.elapsed()));
                                            match idle_for {
                                                Some(idle) if idle.as_secs() >= crate::transfer::IDLE_SESSION_TTL_SECS => {
                                                    if let Ok(mut m) = ts.ecdh_session_keys.lock() { m.remove(&sid); }
                                                    if let Ok(mut m) = ts.v3_sender.lock() { m.remove(&sid); }
                                                    if let Ok(mut m) = ts.active_sessions.lock() { m.remove(&sid); }
                                                    if let Ok(mut m) = ts.session_last_activity.lock() { m.remove(&sid); }
                                                    crate::log_debug!("会话闲置自动清理: session_id={}", crate::logger::mask(&sid));
                                                    break;
                                                }
                                                Some(_) => continue, // 仍在活动 → 继续巡检
                                                None => break,       // 已被 SessionEnd/拒绝路径清理 → 任务退出
                                            }
                                        }
                                    });
                                    recv_ecdh_pub = Some(pub_b64);
                                    crate::log_info!(
                                        "收到 ECDH 复杂加密协商，session_key 已派生（{}）",
                                        crate::logger::mask(&session_id)
                                    );
                                }
                                Err(e) => crate::log_warn!("ECDH 协商失败: {e}"),
                            }
                        }
                    }
                    // 接收确认：通知前端弹窗（发送者/文件数/总大小），阻塞等待用户同意。
                    // 45 秒超时：已配对来源自动接受（备份场景），非配对默认拒绝（防未授权设备试探）
                    let ids: HashSet<String> = files.keys().cloned().collect();
                    let total_bytes: u64 = files.values().map(|f| f.size).sum();
                    crate::log_info!(
                        "收到 prepare-upload 请求（{} 个文件，{}B），等待用户确认",
                        ids.len(),
                        total_bytes
                    );
                    let approved = {
                        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
                        {
                            let st = app.state::<TransferState>();
                            // TTL 清理：每次插入前清理超时的旧条目（60s > 45s 超时）
                            st.cleanup_stale_approvals();
                            let now = std::time::Instant::now();
                            {
                                let mut m = st
                                    .pending_receive_approvals
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner());
                                m.insert(session_id.clone(), tx);
                            }
                            {
                                let mut t = st
                                    .pending_receive_times
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner());
                                t.insert(session_id.clone(), now);
                            }
                        }
                        let _ = app.emit(
                            "incoming-request",
                            serde_json::json!({
                                "sessionId": session_id,
                                "count": ids.len(),
                                "totalBytes": total_bytes,
                                "senderName": info.alias,
                                "senderIp": ip.to_string(),
                            }),
                        );
                        match tokio::time::timeout(std::time::Duration::from_secs(45), rx).await {
                            Ok(Ok(true)) => true,
                            Ok(Ok(false)) => false,
                            _ => is_trusted_sender(&app, &ip.to_string()), // 超时：配对来源自动接受
                        }
                    };
                    // 无论结果如何都清理 pending 表项（防 Sender 累积泄漏）
                    {
                        let st = app.state::<TransferState>();
                        let _ = st
                            .pending_receive_approvals
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&session_id);
                        let _ = st
                            .pending_receive_times
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&session_id);
                    }
                    if !approved {
                        crate::log_warn!("用户拒绝接收会话（{} 个文件）", ids.len());
                        // 拒绝/超时未批准的会话：同步清掉 ECDH 会话密钥，
                        // 否则恶意方反复发起请求再放弃 → map 无界增长
                        if recv_ecdh_pub.is_some() {
                            if let Ok(mut m) = app.state::<TransferState>().ecdh_session_keys.lock() {
                                m.remove(&session_id);
                            }
                        }
                        // A2：同步移除活动时间戳 → 闲置清理任务下次巡检即退出
                        if let Ok(mut m) = app.state::<TransferState>().session_last_activity.lock() {
                            m.remove(&session_id);
                        }
                        let _ = decision_tx.send(PrepareUploadDecisionV2::Decline);
                        continue;
                    }
                    // P6：发送方是 v3 配对设备（info.fingerprint = 发送方 device_id 且本机有
                    // 其 pairing_secret）→ 记录 session 的 sender，FileUpload 据此按 file_id
                    // 派生 per-file transfer_key 解密（方案.txt §6.3；会话结束由 SessionEnd 清理）
                    {
                        let sender_id = info.fingerprint.as_str();
                        if !sender_id.is_empty() {
                            let has_secret = app
                                .state::<PairingState>()
                                .secrets
                                .try_read()
                                .map(|m| m.contains_key(sender_id))
                                .unwrap_or(false);
                            if has_secret {
                                if let Ok(mut m) = app.state::<TransferState>().v3_sender.lock() {
                                    m.insert(session_id.clone(), sender_id.to_string());
                                }
                                // 注意：ecdh_session_keys 的超时清理已在上面 ECDH 注册处统一启动，
                                // 这里只注册 v3_sender（ecdh_session_keys 可能为空，但清理任务已存在）
                                crate::log_debug!(
                                    "P6 接收: v3 配对发送方 session={} deviceId={}",
                                    crate::logger::mask(&session_id),
                                    crate::logger::mask(sender_id)
                                );
                            }
                        }
                    }
                    let _ = if let Some(pub_b64) = recv_ecdh_pub {
                        decision_tx.send(PrepareUploadDecisionV2::AcceptWithEcdh {
                            ids,
                            recv_ecdh_pub: pub_b64,
                        })
                    } else {
                        decision_tx.send(PrepareUploadDecisionV2::Accept(ids))
                    };
                    // 会话累计：记录开始时间/期望文件数/总字节（接收历史按会话聚合）
                    recv_started = Some(std::time::Instant::now());
                    recv_expected = Some(files.len() as u64);
                    recv_count = 0;
                    recv_bytes = 0;
                    recv_total = total_bytes;
                }
                ServerEventV2::FileUpload {
                    file,
                    file_id,
                    target_tx,
                    session_id,
                    ..
                } => {
                    // A2：分片到达 = 会话仍活跃 → 续期（闲置清理任务据此跳过本会话）
                    if let Ok(mut m) = app.state::<TransferState>().session_last_activity.lock() {
                        m.insert(session_id.clone(), std::time::Instant::now());
                    }
                    // 大文件分片续传识别：fileName = __chunked__/{pct编码的正式路径}/{index}/{total}
                    // 分片写入 part 目录（不冲突重命名）；普通文件走冲突重命名
                    let chunked_meta: Option<(String, u32, u32)> = file
                        .file_name
                        .strip_prefix("__chunked__/")
                        .and_then(|rest| {
                            let parts: Vec<&str> = rest.split('/').collect();
                            if parts.len() == 3 {
                                let index = parts[1].parse::<u32>().ok()?;
                                let total = parts[2].parse::<u32>().ok()?;
                                Some((parts[0].to_string(), index, total))
                            } else {
                                None
                            }
                        });
                    // 计算目标路径（冲突 → 重命名），由服务器直接写入磁盘
                    let path = match &chunked_meta {
                        Some((pct, idx, _)) => event_dir
                            .join(".chunks")
                            .join(pct)
                            .join(idx.to_string()),
                        None => resolve_target_path(&event_dir, &file),
                    };
                    // File::create 不会创建父目录：先建目录层级，保证子目录文件可保存
                    // P0 修复：std::fs::create_dir_all 是阻塞 I/O，用 Arc 克隆后送入 spawn_blocking
                    if let Some(parent) = path.parent() {
                        let parent_arc = std::sync::Arc::new(parent.to_path_buf());
                        match tokio::task::spawn_blocking({
                            let p = parent_arc.clone();
                            move || std::fs::create_dir_all(&*p)
                        }).await {
                            Ok(Err(e)) => crate::log_error!("创建接收目录失败 {}: {e}", parent_arc.display()),
                            Err(e) => crate::log_warn!("创建目录任务失败: {e}"),
                            _ => {}
                        }
                    }
                    crate::log_debug!(
                        "接收文件 {} ({}B) → {}",
                        file.file_name,
                        file.size,
                        path.display()
                    );
                    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
                    let _ = target_tx.send(FileUploadTarget::Path {
                        path: path.clone(),
                        result_tx,
                        progress_tx: None,
                    });
                    // 等待服务器写入完成，然后解密
                    match result_rx.await {
                        Ok(Ok(())) => {
                            // 写入成功：尝试解密（本应用加密文件带 LSBK 魔数头）。
                            // P6 解密 key 优先级（方案.txt §6.3）+ 防御性多候选回退：
                            //   1) v3 配对发送方 → per-file transfer_key = HKDF(pairing_secret, file_id)
                            //   2) ECDH 复杂加密会话密钥（v2，按 session 关联）
                            //   3) 简单加密：本机连接码派生（码变化时才重派生）
                            //   4) 本机指纹码派生（v3-<deviceId前8>）——与手机端无 secret 时的
                            //      SHA-256(targetCode) 回退口径对齐，避免"密钥不匹配"全灭
                            // 候选密钥去重后依次尝试，命中任意一个即解密成功。
                            let mut candidate_keys: Vec<[u8; 32]> = Vec::with_capacity(4);
                            {
                                // 1) v3：session → sender device_id → pairing_secret → per-file key
                                let sender_id = app
                                    .state::<TransferState>()
                                    .v3_sender
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .get(&session_id)
                                    .cloned();
                                if let Some(sender_id) = sender_id {
                                    if let Ok(s) = app.state::<PairingState>().secrets.try_read() {
                                        if let Some(secret) = s.get(&sender_id).cloned() {
                                            if let Ok(k) = crate::crypto::derive_transfer_key_v3(
                                                &secret,
                                                file_id.as_bytes(),
                                            ) {
                                                candidate_keys.push(k);
                                            }
                                        }
                                    }
                                }
                            }
                            // 2) ECDH 会话密钥（v2 复杂加密）
                            if let Ok(m) = app.state::<TransferState>().ecdh_session_keys.lock() {
                                if let Some(k) = m.get(&session_id).copied() {
                                    if !candidate_keys.contains(&k) {
                                        candidate_keys.push(k);
                                    }
                                }
                            }
                            // 3) 连接码派生（v2 简单加密；码变化时才重派生）
                            {
                                let code = identity::get_self_code(&app);
                                if code != cached_code {
                                    cached_code = code;
                                    decrypt_key = crate::crypto::derive_local_storage_key(&cached_code);
                                }
                                if !candidate_keys.contains(&decrypt_key) {
                                    candidate_keys.push(decrypt_key);
                                }
                            }
                            // 4) 本机指纹码派生（与手机端 SHA-256(targetCode) 对齐）。
                            //    注意：此派生是 O(1)（仅 "v3-"+deviceId前8 做 SHA-256），
                            //    不遍历任何设备表，不存在"每失败一次扫全表"的性能问题。
                            {
                                let fp_code = identity::get_self_fingerprint_code(&app);
                                let fp_key = crate::crypto::derive_local_storage_key(&fp_code);
                                if !candidate_keys.contains(&fp_key) {
                                    candidate_keys.push(fp_key);
                                }
                            }
                            // 候选 key 顺序安全性说明（避免误判"第一个命中即错"）：
                            // 解密用的是 AES-256-GCM（认证加密），非正确 key 的 GCM tag 校验必然失败，
                            // 因此不可能出现"错 key 碰巧解出貌似合法明文"的情况——成功即代表 key 正确。
                            // 且 decrypt_stream 在解密前已校验 LSBK 魔数头（非本应用加密则原样保留），
                            // 魔数 + GCM 双重把关，顺序仅影响命中次序，不影响正确性。
                            // decrypt_file_in_place 是同步文件 I/O，必须 spawn_blocking 防止阻塞事件循环
                            let path_dec = path.clone();
                            let keys_dec = candidate_keys;
                            let decrypt_result = tokio::task::spawn_blocking(move || {
                                decrypt_file_in_place_multi(&keys_dec, &path_dec)
                            }).await;
                            // 解密失败的文件不计入成功计数；会话最终化时据此判定整体成败
                            let decrypt_ok = match decrypt_result {
                                Ok(Ok(true)) => {
                                    crate::log_debug!("文件解密完成: {}", path.display());
                                    true
                                }
                                Ok(Ok(false)) => {
                                    crate::log_debug!("文件非加密格式，原样保存: {}", path.display());
                                    true
                                }
                                Ok(Err(e)) => {
                                    crate::log_error!("文件解密失败 {}: {e}", path.display(), e = e);
                                    recv_failed += 1;
                                    false
                                }
                                Err(e) => {
                                    crate::log_error!("文件解密任务失败: {e}", e = e);
                                    recv_failed += 1;
                                    false
                                }
                            };
                            if !decrypt_ok {
                                // 解密失败：文件不可用，不计入成功接收；仍参与"会话是否到齐"判断，
                                // 以便尽快触发 finalize（而不是永远等待缺失文件）。
                                if let Some(expected) = recv_expected {
                                    if recv_count + recv_failed >= expected {
                                        finalize_receive(
                                            &app,
                                            &mut recv_started,
                                            &mut recv_count,
                                            &mut recv_bytes,
                                            &mut recv_failed,
                                        );
                                    }
                                }
                            }
                            if decrypt_ok {
                                // tiny 批量聚合：识别 x-batch-agg → 解包为独立文件，删除聚合本体
                                // spawn_blocking 包装：std::fs::read 是同步阻塞 I/O，必须移出 async 线程池
                                if file.file_type == "application/x-batch-agg" {
                                    let path_clone = path.clone();
                                    let dir_clone = event_dir.clone();
                                    match tokio::task::spawn_blocking(move || {
                                        let tar = std::fs::read(&path_clone)
                                            .map_err(|e| AppError(format!("读取批量 tar 失败: {e}")))?;
                                        unpack_batch(&tar, &dir_clone)
                                            .map_err(|e| AppError(format!("批量 tar 解包失败: {e}")))
                                    }).await {
                                        Ok(Ok(n)) => {
                                            crate::log_info!(
                                                "批量 tar 解包完成: {} 个成员（{}）",
                                                n,
                                                file.file_name
                                            );
                                            let _ = std::fs::remove_file(&path);
                                        }
                                        Ok(Err(e)) => crate::log_error!("批量 tar 解包失败: {}", e),
                                        Err(e) => crate::log_error!("批量 tar 解包线程失败: {}", e),
                                    }
                                }
                                // 大文件分片到齐 → 合并为正式文件（按 index 顺序流式拼接，删 part）
                                if let Some((pct, _idx, total)) = &chunked_meta {
                                    match merge_chunked(&event_dir, pct, *total) {
                                        Ok(true) => crate::log_info!(
                                            "分片合并完成: {} ({} 片)",
                                            pct_decode(pct),
                                            total
                                        ),
                                        Ok(false) => { /* 尚未到齐，等待后续分片 */ }
                                        Err(e) => crate::log_error!("分片合并失败: {e}"),
                                    }
                                }
                                // 保留发送端文件时间戳（增量锚点准确）
                                // P0 修复：set_file_mtime 内部 std::fs::File::open 是阻塞 I/O，clone 送入 spawn_blocking
                                if let Some(meta) = &file.metadata {
                                    if let Some(ts) = meta.modified.as_deref() {
                                        if let Some(secs) = parse_timestamp_secs(ts) {
                                            let path_log = path.clone();
                                            let path_clone = path.clone();
                                            match tokio::task::spawn_blocking(move || {
                                                set_file_mtime(&path_clone, secs)
                                            }).await {
                                                Ok(Err(e)) => crate::log_debug!(
                                                    "设置文件时间戳失败 {}: {e}",
                                                    path_log.display()
                                                ),
                                                Err(e) => crate::log_warn!("设置文件时间戳任务失败: {e}"),
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                // 接收会话累计：按实际成功写入且成功解密的文件累加字节
                                recv_bytes += file.size;
                                recv_count += 1;
                                // 接收进度事件：前端实时显示总量/已传/速率/剩余时间
                                let _ = app.emit(
                                    "receive-progress",
                                    serde_json::json!({
                                        "fileName": file.file_name,
                                        "receivedBytes": recv_bytes,
                                        "totalBytes": recv_total,
                                        "receivedCount": recv_count,
                                        "totalCount": recv_expected.unwrap_or(recv_count),
                                    }),
                                );
                                // 到齐判定：成功 + 失败 均计入"已收到"，防止解密失败拖住会话
                                if let Some(expected) = recv_expected {
                                    if recv_count + recv_failed >= expected {
                                        finalize_receive(
                                            &app,
                                            &mut recv_started,
                                            &mut recv_count,
                                            &mut recv_bytes,
                                            &mut recv_failed,
                                        );
                                    }
                                }
                            }
                        }
                        Ok(Err(e)) => crate::log_error!("接收文件写入失败: {e}"),
                        Err(_) => crate::log_warn!("接收文件写入通道关闭"),
                    }
                }
                ServerEventV2::SessionEnd { session_id, .. } => {
                    // 兜底：会话结束事件到达时若尚未按文件数完成，则落一条接收历史
                    finalize_receive(&app, &mut recv_started, &mut recv_count, &mut recv_bytes, &mut recv_failed);
                    // 加密 v2：会话结束清理 ECDH 会话密钥（防泄漏 + 防陈旧 key 残留）
                    if let Ok(mut m) = app.state::<TransferState>().ecdh_session_keys.lock() {
                        m.remove(&session_id);
                    }
                    // P6：会话结束清理 v3 发送方映射（防陈旧条目泄漏）
                    if let Ok(mut m) = app.state::<TransferState>().v3_sender.lock() {
                        m.remove(&session_id);
                    }
                    // A2：移除活动时间戳 → 闲置清理任务下次巡检发现 None 即自行退出
                    if let Ok(mut m) = app.state::<TransferState>().session_last_activity.lock() {
                        m.remove(&session_id);
                    }
                }
                _ => {
                    // Register / CancelReceived / PrepareUploadAborted：
                    // 备份场景无需处理，忽略（取消会清掉累计状态，由下次 PrepareUpload 重置）
                }
            }
        }
        crate::log_info!("接收服务器事件循环退出");
    });

    Ok(format!("接收服务器已启动，端口 {port}"))
}

/// 接收会话完成：落一条接收历史（含字节/耗时）并通知前端刷新
fn finalize_receive(
    app: &AppHandle,
    started: &mut Option<std::time::Instant>,
    count: &mut u64,
    bytes: &mut u64,
    failed: &mut u64,
) {
    let Some(s) = started.take() else {
        return;
    };
    let dur = s.elapsed().as_millis() as u64;
    let (c, b, f) = (*count, *bytes, *failed);
    *count = 0;
    *bytes = 0;
    *failed = 0;
    if f > 0 {
        // 有文件解密/写入失败：不当作纯成功落库，前端按失败展示
        crate::log_warn!("接收会话完成（含失败）: 成功 {c} 个文件 {b}B，失败 {f} 个，{dur}ms");
        if let Err(e) = app
            .state::<crate::AppState>()
            .db
            .add_transfer("in", "对方设备", c, b, dur)
        {
            crate::log_warn!("写入接收历史失败: {e}");
        }
        let _ = app.emit("transfers-updated", ());
        let _ = app.emit(
            "receive-complete",
            serde_json::json!({
                "count": c,
                "bytes": b,
                "durationMs": dur,
                "failed": f,
                "ok": false,
            }),
        );
        return;
    }
    crate::log_info!("接收会话完成: {c} 个文件 {b}B {dur}ms");
    if let Err(e) = app
        .state::<crate::AppState>()
        .db
        .add_transfer("in", "对方设备", c, b, dur)
    {
        crate::log_warn!("写入接收历史失败: {e}");
    }
    let _ = app.emit("transfers-updated", ());
    // 接收完成统计：前端进度框显示「备份完成」明细（文件数/总量/耗时）
    let _ = app.emit(
        "receive-complete",
        serde_json::json!({ "count": c, "bytes": b, "durationMs": dur, "failed": 0, "ok": true }),
    );
}

/// 发送方是否已配对（按 IP 匹配配对信任表；用于接收/配对确认超时自动策略）
fn is_trusted_sender(app: &AppHandle, ip: &str) -> bool {
    if ip.is_empty() {
        return false;
    }
    app.state::<PairingState>()
        .paired
        .lock()
        .map(|m| m.values().any(|p| p.get("ip").and_then(|v| v.as_str()) == Some(ip)))
        .unwrap_or(false)
}

/// 停止接收服务器（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
pub async fn stop_receiver(app: AppHandle) -> Result<(), AppError> {
    crate::log_info!("停止接收服务器");
    let state = app.state::<TransferState>();
    // 停止意图先置位：watchdog 在清理窗口内不把"端口即将关闭"判为异常退出
    state.receiver_stop_intent.store(true, Ordering::Relaxed);
    state.receiver_should_run.store(false, Ordering::Relaxed);

    // 触发停止信号（guard 在表达式结束即释放，避免跨 await）
    let stop_tx = state
        .stop_tx
        .lock()
        .map_err(|_| AppError::from_poison())?
        .take();
    if let Some(tx) = stop_tx {
        let _ = tx.send(());
    }
    // 取出 handle 后再 await，等待服务器任务结束、端口释放
    let handle = state
        .server
        .lock()
        .map_err(|_| AppError::from_poison())?
        .take();
    if let Some(handle) = handle {
        handle.wait_stopped().await;
    }
    *state
        .receive_dir
        .lock()
        .map_err(|_| AppError::from_poison())? = None;
    Ok(())
}

/// 清理接收目录下残留的 .tmp_* 临时文件（超过 1 小时未完成，如崩溃残留）。
/// 与 crate save.rs 的原子写入配套（P1）：残留临时文件不会被 chunk-status
/// 误判为已收完整分片（parse::<u32> 过滤），但会占磁盘，启动时清一次。
fn cleanup_stale_temp_files(dir: &std::path::Path) {
    let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    let mut stack: Vec<std::path::PathBuf> = vec![dir.to_path_buf()];
    let mut removed = 0usize;
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Some(name) = p.file_name().map(|s| s.to_string_lossy().into_owned()) {
                if name.starts_with(".tmp_") {
                    let stale = p
                        .metadata()
                        .and_then(|m| m.modified())
                        .map(|m| m < cutoff)
                        .unwrap_or(false);
                    if stale {
                        let _ = std::fs::remove_file(&p);
                        removed += 1;
                    }
                }
            }
        }
    }
    if removed > 0 {
        crate::log_info!("清理残留临时分片文件 {removed} 个（{}）", dir.display());
    }
}

/// 分片合并：`__chunked__/{pct}/` 下所有 part 按 index 顺序拼接为正式文件，删除 part 目录。
/// 全部到齐返回 true；未到齐返回 false（等待后续分片）。
/// 只增不删语义：目标已存在且大小一致 → 视为已备份跳过；大小不一致 → 冲突重命名。
fn merge_chunked(receive_dir: &Path, pct: &str, total: u32) -> Result<bool, AppError> {
    let part_dir = receive_dir.join(".chunks").join(pct);
    // 收集时一次 stat 缓存片长（原先校验一遍 + 求和再一遍 = 每片两次元数据查询）
    let mut parts: Vec<(u32, PathBuf, u64)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&part_dir) {
        for e in rd.flatten() {
            if let Ok(idx) = e.file_name().to_string_lossy().parse::<u32>() {
                let len = std::fs::metadata(e.path()).map(|m| m.len()).unwrap_or(0);
                parts.push((idx, e.path(), len));
            }
        }
    }
    if parts.len() != total as usize {
        return Ok(false); // 严格到齐：缺失或残留多于 total 都等待/失败（防旧版本残留拼接损坏）
    }
    parts.sort_by_key(|(i, _, _)| *i);
    // 校验索引必须恰好 0..total 且每片大小合法（前 total-1 片 = 8MB，最后片 ≤ 8MB）
    let mut expected: u64 = 0;
    for (k, (idx, _p, len)) in parts.iter().enumerate() {
        if *idx != k as u32 {
            crate::log_error!("分片索引不连续（应 {k} 实得 {idx}），放弃合并: {}", pct_decode(pct));
            let _ = std::fs::remove_dir_all(&part_dir);
            return Err(AppError("分片索引不连续，已清理".to_string()));
        }
        if *len == 0 || *len > 8 * 1024 * 1024 {
            crate::log_error!("分片大小异常（{}B），放弃合并: {}", len, pct_decode(pct));
            let _ = std::fs::remove_dir_all(&part_dir);
            return Err(AppError("分片大小异常，已清理".to_string()));
        }
        expected += len;
    }
    let real_name = sanitize_rel_path(&pct_decode(pct));
    if real_name.is_empty() {
        // 解码后无合法组件（纯穿越段/盘符）→ 清理分片并报错，绝不写 receive_dir 之外
        let _ = std::fs::remove_dir_all(&part_dir);
        return Err(AppError("分片目标路径非法，已清理".to_string()));
    }
    // 目标路径（冲突处理）
    let target = receive_dir.join(&real_name);
    let mut final_path = target;
    if final_path.exists() {
        let existing = std::fs::metadata(&final_path).map(|m| m.len()).unwrap_or(0);
        if existing == expected {
            // 已备份（大小一致）→ 清理 part 目录即可
            let _ = std::fs::remove_dir_all(&part_dir);
            return Ok(true);
        }
        // 冲突 → _MMDDhhmmss 重命名
        let mut candidate = rename_with_suffix(
            Path::new(&real_name),
            &format_mmddhhmmss(now_utc_secs()),
        );
        let mut counter = 1;
        while receive_dir.join(&candidate).exists() {
            candidate = rename_with_counter(&candidate, counter);
            counter += 1;
        }
        final_path = receive_dir.join(&candidate);
        crate::log_warn!("分片合并冲突重命名: {} → {}", real_name, candidate.display());
    }
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent).map_err(AppError::from_display)?;
    }
    // 1MB 缓冲手写复制：std::io::copy 默认 8KB 缓冲，GB 级分片合并时 syscall 数量爆炸
    {
        use std::io::{Read, Write};
        let mut out = std::fs::File::create(&final_path).map_err(AppError::from_display)?;
        let mut buf = vec![0u8; 1024 * 1024];
        for (_, p, _) in &parts {
            let mut f = std::fs::File::open(p).map_err(AppError::from_display)?;
            loop {
                let n = f.read(&mut buf).map_err(AppError::from_display)?;
                if n == 0 {
                    break;
                }
                out.write_all(&buf[..n]).map_err(AppError::from_display)?;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&part_dir);
    Ok(true)
}

/// 解密已写入磁盘的文件（原地替换）。
/// 返回 `Ok(true)` 表示已解密；`Ok(false)` 表示非本应用加密格式（原样保留）。
/// 单密钥版本：现由多候选版 `decrypt_file_in_place_multi` 取代，保留作单 key 便捷入口。
#[allow(dead_code)]
fn decrypt_file_in_place(key: &[u8; 32], path: &Path) -> Result<bool, String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).map_err(|e| format!("读取文件失败: {e}"))?;
    // 先 peek 魔数：非本应用加密格式 → 原样保留（不重写磁盘）
    let mut head = [0u8; 4];
    let got = f.read(&mut head).map_err(|e| e.to_string())?;
    if got < 4 || &head != crate::crypto::MAGIC {
        return Ok(false);
    }
    f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("dec_tmp");
    let decrypt_result = (|| -> Result<bool, String> {
        let mut w = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        crate::crypto::decrypt_stream(key, &mut f, &mut w)
    })();
    if let Err(e) = decrypt_result {
        // 失败清理临时文件：否则 .dec_tmp 残留累积（扫描器刻意排除该扩展名，用户不可见）
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.to_string()
    })?;
    Ok(true)
}

/// 多候选密钥解密：依次尝试 v3 HKDF / ECDH / 连接码 / 本机指纹码派生的密钥。
/// 命中任意一个即解密成功（防御：对端无配对 secret 时的回退口径与发送端对齐，
/// 避免手机端 SHA-256(targetCode) 与 PC 端 SHA-256(selfCode) 不一致导致"密钥不匹配"全灭）。
/// 返回 `Ok(true)` 已解密；`Ok(false)` 非本应用加密格式（原样保留）；`Err` 全部候选失败。
fn decrypt_file_in_place_multi(
    keys: &[[u8; 32]],
    path: &Path,
) -> Result<bool, String> {
    use std::io::{Read, Seek, SeekFrom};
    // 先 peek 魔数：非本应用加密格式 → 原样保留（不重写磁盘）
    {
        let mut f = std::fs::File::open(path).map_err(|e| format!("读取文件失败: {e}"))?;
        let mut head = [0u8; 4];
        let got = f.read(&mut head).map_err(|e| e.to_string())?;
        if got < 4 || &head != crate::crypto::MAGIC {
            return Ok(false);
        }
    }
    if keys.is_empty() {
        return Err("无可用解密密钥".to_string());
    }
    let mut last_err: Option<String> = None;
    for key in keys {
        let tmp = path.with_extension("dec_tmp");
        let result = (|| -> Result<bool, String> {
            let mut f = std::fs::File::open(path).map_err(|e| format!("读取文件失败: {e}"))?;
            f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            let mut w = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
            crate::crypto::decrypt_stream(key, &mut f, &mut w)
        })();
        match result {
            Ok(true) => {
                // 命中：临时解密文件原子替换正式文件
                if std::fs::rename(&tmp, path).is_err() {
                    let _ = std::fs::remove_file(&tmp);
                    return Err("重命名解密结果失败".to_string());
                }
                return Ok(true);
            }
            Ok(false) => {
                let _ = std::fs::remove_file(&tmp);
                return Ok(false); // 非加密格式（已在魔数预检拦截，理论上不出现）
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "解密失败：密钥不匹配或数据被篡改".to_string()))
}

/// 自定义聚合格式解包：读字节流，按成员 relPath 写入目标目录（防穿越 + 大小校验）。
/// 返回写入的成员数。
fn unpack_batch(bytes: &[u8], target_dir: &Path) -> Result<usize, AppError> {
    let mut off = 0usize;
    let mut count = 0usize;
    while off + 12 <= bytes.len() {
        let name_len = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
            as usize;
        off += 4;
        if off + name_len > bytes.len() {
            crate::log_warn!("batch 解包: 文件名越界，中断");
            break;
        }
        let name = String::from_utf8_lossy(&bytes[off..off + name_len]).into_owned();
        off += name_len;
        if off + 8 > bytes.len() {
            crate::log_warn!("batch 解包: 大小字段越界，中断");
            break;
        }
        let size = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap_or([0u8; 8]));
        off += 8;
        // checked_add：恶意成员 size 近 u64::MAX 时普通加法回绕可绕过越界检查
        let Some(need) = off.checked_add(size as usize) else {
            crate::log_warn!("batch 解包: 成员大小溢出，中断 {}", name);
            break;
        };
        if need > bytes.len() {
            crate::log_warn!("batch 解包: 成员数据越界，中断 {}", name);
            break;
        }
        let rel = sanitize_rel_path(&name);
        if !rel.is_empty() {
            let target = target_dir.join(&rel);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(AppError::from_display)?;
            }
            std::fs::write(&target, &bytes[off..need]).map_err(AppError::from_display)?;
            count += 1;
        }
        off = need;
    }
    Ok(count)
}
