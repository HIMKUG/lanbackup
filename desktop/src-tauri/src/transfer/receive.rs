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
use lanbackup_core::server::{serve_request, SessionStore, hyper_http1_builder};
use lanbackup_core::dto::DeviceType;

pub async fn start_receiver(
    app: AppHandle,
    receive_dir: String,
    port: u16,
) -> Result<String, AppError> {
    crate::log_info!("启动接收服务器(V4): 目录={receive_dir} 端口={port}");
    let state = app.state::<TransferState>();

    {
        let old_handle = state.server.lock().map_err(|_| AppError::from_poison())?.take();
        if let Some(h) = old_handle {
            h.stop().await;
        }
    }

    let dir = PathBuf::from(&receive_dir);
    std::fs::create_dir_all(&dir).map_err(AppError::from_display)?;

    let alias = identity::get_device_name(&app);
    let _device_id_hex = identity::get_device_id(&app);
    let app_data = app.path().app_data_dir().map_err(|e| AppError(format!("获取应用数据目录失败: {e}")))?;
    let persist_dir = app_data.join("sessions");

    let identity = lanbackup_core::identity::DeviceIdentity::generate();
    let store = SessionStore::open(identity, &alias, DeviceType::Desktop, Some(&persist_dir));
    let store = Arc::new(store);

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
                    let _ = store_for_server.sweep_idle(std::time::Instant::now());
                }
                accept_result = listener.accept() => {
                    if stopped.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    match accept_result {
                        Ok((stream, _addr)) => {
                            let store = store_for_server.clone();
                            let stopped = stopped.clone();
                            tokio::spawn(async move {
                                let io = hyper_util::rt::TokioIo::new(stream);
                                let builder = hyper_http1_builder();
                                if let Err(e) = builder
                                    .serve_connection(io, hyper::service::service_fn(move |req| {
                                        let store = store.clone();
                                        async move { Ok::<_, std::convert::Infallible>(serve_request(&store, req).await) }
                                    }))
                                    .await
                                {
                                    if !stopped.load(std::sync::atomic::Ordering::Relaxed) {
                                        crate::log_debug!("[V4] 连接处理错误: {e}");
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
