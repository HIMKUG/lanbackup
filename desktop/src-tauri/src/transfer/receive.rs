//! 传输模块 - 接收端流程（V4 核心接入版）
//!
//! 接收端使用 hyper 1.x + tokio 启动 HTTP 服务器，
//! 通过 SessionStore::serve_request 处理 V4 协议请求。
//!
//! SessionStore 提供 /api/v4/session/* 路由，平台层负责 TCP 监听。
//! 使用 core 内置 persist（app_data_dir/sessions/），断点续传由 core 处理。
//!
//! 身份策略：使用 desktop 已有稳定 deviceId（FNV-1a 派生，固定不变）
//! 作为 core DeviceIdentity 的 deviceId 字段。P-256 静态密钥由 core 生成
//! 并缓存在内存中（进程级）。这确保了：同一台 desktop 重启后 deviceId 不变，
//! 对端可正确识别本机并续传已有会话。

use super::*;
use base64::Engine;
use lanbackup_core::server::{serve_request, SessionStore, hyper_http1_builder};
use lanbackup_core::dto::DeviceType;
use lanbackup_core::pairing::trust::TrustRecord;
use lanbackup_core::dto::handshake::PairingState as TrustPairingState;
use std::sync::Arc;

async fn sync_paired_peers_to_store(store: &Arc<SessionStore>, app: &AppHandle) {
    let pairing_state = app.state::<PairingState>();
    let paired = match pairing_state.paired.lock() {
        Ok(m) => m.clone(),
        Err(_) => {
            crate::log_warn!("sync_paired_peers_to_store: paired lock 获取失败");
            return;
        }
    };
    let secrets = pairing_state.secrets.blocking_read();

    for (device_id, record) in paired.iter() {
        let status = record
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let trust_state = match status {
            "ACTIVE" => TrustPairingState::Active,
            "PENDING" | "REVOKE_PENDING" => TrustPairingState::Pending,
            "REVOKED" | "DELETED" => TrustPairingState::Revoked,
            _ => {
                crate::log_debug!("sync_paired_peers_to_store: 跳过非活跃状态 deviceId={} status={}", device_id, status);
                continue;
            }
        };

        let alias = record
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let peer_public_key = record
            .get("peerPublicKey")
            .and_then(|v| v.as_str())
            .map(|s| {
                base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        let pairing_secret = secrets
            .get(device_id)
            .cloned()
            .unwrap_or_default();

        let trust = {
            let mut t = TrustRecord::new();
            let _ = t.apply(lanbackup_core::pairing::machine::PairingEvent::PeerConfirmed);
            t.state = trust_state;
            t
        };

        let peer_record = lanbackup_core::server::control::PeerRecord::new(
            device_id,
            &alias,
            peer_public_key,
            pairing_secret,
            trust,
        );

        store.merge_peer(peer_record).await;

        crate::log_debug!(
            "sync_paired_peers_to_store: 同步 deviceId={} alias={} state={:?}",
            device_id,
            alias,
            trust_state
        );
    }
    crate::log_info!(
        "配对状态已同步进 core PeerStore: {} 条（含非活跃）",
        paired.len()
    );
}

async fn refresh_manifest(store: &Arc<SessionStore>, dir: &Path) {
    let dir = dir.to_path_buf();
    match tokio::task::spawn_blocking(move || scan_manifest(&dir)).await {
        Ok(Ok(m)) => {
            let n = m.files.len();
            store.set_local_manifest(m).await;
            crate::log_debug!("接收目录清单已刷新: {n} 个文件");
        }
        Ok(Err(e)) => crate::log_warn!("扫描接收目录失败: {e}"),
        Err(e) => crate::log_warn!("扫描接收目录任务失败: {e}"),
    }
}

pub async fn start_receiver(
    app: AppHandle,
    receive_dir: String,
    port: u16,
) -> Result<String, AppError> {
    crate::log_info!("启动接收服务器(V4): 目录={receive_dir} 端口={port}");
    let state = app.state::<TransferState>();

    // WB-0117：单飞 —— 整个"停旧→建新→注册句柄"过程持锁，
    // 并发 start 不再互踩（第二个请求排队等待，看到的是停好旧服务的干净现场）
    let _lifecycle = state.lifecycle_lock.lock().await;
    {
        let old_handle = state.server.lock().map_err(|_| AppError::from_poison())?.take();
        if let Some(h) = old_handle {
            h.stop().await;
        }
    }

    let dir = PathBuf::from(&receive_dir);
    std::fs::create_dir_all(&dir).map_err(AppError::from_display)?;

    let alias = identity::get_device_name(&app)?;
    let device_id_hex = identity::get_device_id(&app);
    let app_data = app.path().app_data_dir().map_err(|e| AppError(format!("获取应用数据目录失败: {e}")))?;
    let persist_dir = app_data.join("sessions");

    // WB-0015/0016：恢复 core 身份必须用**签名私钥**（PKCS#8 DER），
    // 而不是公钥；base64 统一 URL_SAFE_NO_PAD（兼容历史 STANDARD 数据）。
    let (sig_priv_b64, _sig_pub_b64) = crate::transfer::get_or_create_sig_key(&app);
    if sig_priv_b64.is_empty() {
        return Err(AppError(
            "签名私钥不可用：拒绝用随机身份启动接收服务（否则重启即换设备）".to_string(),
        ));
    }
    let sig_priv_der = {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD
            .decode(&sig_priv_b64)
            .or_else(|_| STANDARD.decode(&sig_priv_b64))
            .map_err(|e| AppError(format!("签名私钥 base64 解码失败: {e}")))?
    };
    let identity = lanbackup_core::identity::DeviceIdentity::restore_from_pkcs8(
        &device_id_hex,
        &sig_priv_der,
    )
    .ok_or_else(|| {
        AppError(
            "签名私钥/设备 ID 无法恢复为 core 身份：请重置身份并重新配对".to_string(),
        )
    })?;
    let store = SessionStore::open(identity, &alias, DeviceType::Desktop, Some(&persist_dir));
    store.with_base_dir(receive_dir.clone().into());
    // 生产接收端：prepare/chunk/verify 拒绝未 Active 的设备
    store.with_require_active_peer(true);
    // WB-0017：生产必须把用户可见的连接码注入 core，否则路径 A 永远 400。
    store
        .set_pairing_code(
            crate::identity::get_self_code(&app)
                .map_err(|e| AppError(format!("读取连接码失败: {e}")))?,
        )
        .await;
    // 防御总闸跨重启保持：启动接收服务时把桌面标志灌进 core。
    store.set_defensive_hidden(state.defensive_hidden.load(Ordering::Relaxed));
    // WB-0054：把接收目录扫描成 core 清单，供 GET /manifest 与增量规划使用。
    refresh_manifest(&store, &dir).await;

    // Step2 收尾：将 PairingState.paired 中已配对的记录同步进 core PeerStore，
    // 使 v4 控制面（unpair-request / sync-status / revoke-ack）能够查询对端信息。
    // 已在 load_paired_from_db 中从 SQLite 恢复数据，此处仅作合并写入。
    sync_paired_peers_to_store(&store, &app).await;

    // 将 core SessionStore 注入全局状态，供 store.rs 的配对写操作同步写 core PeerStore
    if let Ok(mut ss) = app.state::<PairingState>().session_store.lock() {
        *ss = Some(Arc::clone(&store));
        crate::log_info!("core SessionStore 已注入 PairingState");
    }

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(());
    let listener = match tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await {
        Ok(l) => l,
        Err(e) => return Err(AppError(format!("端口绑定失败: {e}"))),
    };
    let actual_port = listener.local_addr().map(|a| a.port()).unwrap_or(port);

    let handle = Arc::new(V4ServerHandle {
        port: actual_port,
        stop_tx: stop_tx.clone(),
        stopped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    });

    {
        let mut server = state.server.lock().map_err(|_| AppError::from_poison())?;
        *server = Some(handle.clone());
    }
    {
        let mut tx_guard = state.stop_tx.lock().map_err(|_| AppError::from_poison())?;
        *tx_guard = Some(stop_tx);
    }
    {
        let mut dir_guard = state.receive_dir.lock().map_err(|_| AppError::from_poison())?;
        *dir_guard = Some(dir.clone());
    }
    state.receiver_should_run.store(true, Ordering::Relaxed);
    state.receiver_stop_intent.store(false, Ordering::Relaxed);

    let store_for_server = store.clone();
    let stopped = handle.stopped.clone();
    let manifest_dir = dir.clone();
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(
        lanbackup_core::server::MAX_UPSTREAM_CONNECTIONS,
    ));
    tokio::spawn(async move {
        crate::log_info!("[V4 Server] 开始监听 0.0.0.0:{actual_port}");
        let mut sweep_interval = tokio::time::interval(std::time::Duration::from_secs(60));
        let mut stop_rx = stop_rx.clone();
        loop {
            tokio::select! {
                biased;
                _ = stop_rx.changed() => {
                    crate::log_info!("[V4] 服务器收到停止信号");
                    break;
                }
                _ = sweep_interval.tick() => {
                    let _ = store_for_server.sweep_idle(std::time::Instant::now()).await;
                    refresh_manifest(&store_for_server, &manifest_dir).await;
                }
                accept_result = listener.accept() => {
                    if stopped.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    match accept_result {
                        Ok((stream, _addr)) => {
                            let permit = match conn_limit.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    crate::log_warn!(
                                        "连接数达到上限 {}，拒绝新连接（防 Slowloris）",
                                        lanbackup_core::server::MAX_UPSTREAM_CONNECTIONS
                                    );
                                    drop(stream);
                                    continue;
                                }
                            };
                            let store = store_for_server.clone();
                            let stopped = stopped.clone();
                            let mut conn_stop = stop_rx.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                let io = hyper_util::rt::TokioIo::new(stream);
                                let builder = hyper_http1_builder();
                                let serve = builder.serve_connection(io, hyper::service::service_fn(move |req| {
                                    let store = store.clone();
                                    async move { Ok::<_, std::convert::Infallible>(serve_request(&store, req).await) }
                                }));
                                // 停止信号必须能取消在途连接（而非只关 accept 循环）
                                tokio::select! {
                                    _ = conn_stop.changed() => {
                                        crate::log_debug!("[V4] 在途连接随服务停止被取消");
                                    }
                                    res = serve => {
                                        if let Err(e) = res {
                                            if !stopped.load(std::sync::atomic::Ordering::Relaxed) {
                                                crate::log_debug!("[V4] 连接处理错误: {e}");
                                            }
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            crate::log_error!("[V4] 接受连接失败: {e}");
                        }
                    }
                }
            }
        }
        crate::log_info!("[V4 Server] 监听循环退出");
    });

    crate::log_info!("接收服务器(V4)已启动: 端口={actual_port}");
    Ok(format!("{actual_port}"))
}

pub async fn stop_receiver(app: AppHandle) -> Result<(), AppError> {
    crate::log_info!("停止接收服务器");
    let state = app.state::<TransferState>();
    // WB-0119：与 start 互斥 —— 停止过程中穿插的 start 不会把刚停掉的服务
    // 又"救活"成半初始化状态
    let _lifecycle = state.lifecycle_lock.lock().await;
    state.receiver_stop_intent.store(true, Ordering::Relaxed);
    state.receiver_should_run.store(false, Ordering::Relaxed);

    {
        let handle = state.server.lock().map_err(|_| AppError::from_poison())?.take();
        if let Some(h) = handle {
            h.stop().await;
        }
    }
    {
        let mut dir = state.receive_dir.lock().map_err(|_| AppError::from_poison())?;
        *dir = None;
    }
    crate::log_info!("接收服务器已停止");
    Ok(())
}
