//! 设备发现模块（局域网 multicast 广播）
//!
//! 复用 LocalSend core 的 multicast 模块：本机周期广播设备信息，
//! 同时监听同网段其他设备的广播，按 fingerprint 去重记录。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use localsend::model::discovery::{DeviceType, ProtocolType};
use localsend::multicast::{
    start, MulticastConfig, MulticastDevice, MulticastEvent, MulticastHandle,
    DEFAULT_MULTICAST_GROUP, DEFAULT_MULTICAST_GROUP_V6, DEFAULT_PORT,
};
use localsend::util::interface::InterfaceFilter;
use tauri::{AppHandle, Manager};

use crate::db::AppError;
use crate::identity;

/// 发现的设备信息（Tauri 命令返回值）
#[derive(serde::Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredDeviceInfo {
    pub alias: String,
    pub fingerprint: String,
    pub ip: String,
    pub port: u16,
    /// 最近一次被发现的时刻（epoch ms）：get_discovered_devices 按它剪枝，
    /// 停止广播/下线的设备在下一轮轮询中自动消失（发现表实时可用）
    pub last_seen: u64,
}

/// 设备发现全局状态
pub struct DiscoveryState {
    handle: Mutex<Option<Arc<MulticastHandle>>>,
    stop_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    devices: Arc<Mutex<Vec<DiscoveredDeviceInfo>>>,
    /// 子网扫描取消标志：stop_discovery 设为 true，subnet_scan 检测后提前退出
    scan_stop: Arc<AtomicBool>,
}

impl Default for DiscoveryState {
    fn default() -> Self {
        Self {
            handle: Mutex::new(None),
            stop_tx: Mutex::new(None),
            devices: Arc::new(Mutex::new(Vec::new())),
            scan_stop: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// 启动设备发现（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
///
/// `server_port` 为本机接收服务器的端口，广播给局域网内其他设备用于回连。
pub async fn start_discovery(app: AppHandle, server_port: u16) -> Result<String, AppError> {
    crate::log_info!("启动设备发现: 广播端口={DEFAULT_PORT} 服务器端口={server_port}");
    let state = app.state::<DiscoveryState>();
    if state
        .handle
        .lock()
        .map_err(|_| AppError::from_poison())?
        .is_some()
    {
        return Err(AppError("设备发现已在运行".to_string()));
    }

    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<MulticastEvent>(64);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

    // 本机设备信息（设备名 + 公开 deviceId 广播；连接码不参与广播，避免泄露）
    let device_name = identity::get_device_name(&app);
    let device_id = identity::get_device_id(&app);
    crate::log_info!(
        "本机广播信息: 名称={} 公开ID={}",
        device_name,
        crate::logger::mask(&device_id)
    );
    let config = MulticastConfig {
        group: DEFAULT_MULTICAST_GROUP,
        group_v6: Some(DEFAULT_MULTICAST_GROUP_V6),
        port: DEFAULT_PORT,
        interface_filter: InterfaceFilter {
            whitelist: None,
            blacklist: None,
        },
        device: MulticastDevice {
            alias: device_name,
            version: "2.2".to_string(),
            device_model: Some("Windows".to_string()),
            device_type: Some(DeviceType::Desktop),
            fingerprint: device_id,
            port: server_port,
            protocol: ProtocolType::Http,
            download: false,
        },
        event_tx,
    };

    let handle = start(config, stop_rx)
        .await
        .map_err(|e| AppError(format!("启动设备发现失败: {e}")))?;

    // 周期广播本机（LocalSend v2 multicast）：让手机端「扫描电脑」能发现本机。
    // 每 2 秒 announce 一次；stop_discovery 取走 handle 后循环自然退出。
    {
        let announce_app = app.clone();
        tauri::async_runtime::spawn(async move {
            loop {
                let handle = {
                    let st = announce_app.state::<DiscoveryState>();
                    st.handle.lock().ok().and_then(|g| g.as_ref().cloned())
                };
                let Some(handle) = handle else { break };
                handle.announce().await;
                tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
            }
            crate::log_info!("设备发现周期广播结束");
        });
    }

    *state
        .handle
        .lock()
        .map_err(|_| AppError::from_poison())? = Some(Arc::new(handle));

    // /24 子网探测（单播 TCP 兜底）：不依赖组播（部分路由器禁组播导致电脑找不到手机），
    // 探测各网段主机的配对服务 /info，配对/连接发现更可靠
    state.scan_stop.store(false, Ordering::Relaxed);
    {
        let scan_app = app.clone();
        let stop_flag = state.scan_stop.clone();
        std::thread::spawn(move || subnet_scan(scan_app, server_port, stop_flag));
    }
    *state
        .stop_tx
        .lock()
        .map_err(|_| AppError::from_poison())? = Some(stop_tx);
    state
        .devices
        .lock()
        .map_err(|_| AppError::from_poison())?
        .clear();

    // 事件循环：记录发现的设备（按 fingerprint 去重，每轮 announce 刷新存活时间）
    let devices = state.devices.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let MulticastEvent::Discovered { ip, message, .. } = event;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let info = DiscoveredDeviceInfo {
                alias: message.alias,
                fingerprint: message.fingerprint,
                ip: ip.to_string(),
                port: message.port,
                last_seen: now,
            };
            let mut list = devices.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(existing) = list.iter_mut().find(|d| d.fingerprint == info.fingerprint) {
                existing.last_seen = now;
            } else {
                crate::log_info!(
                    "发现设备 alias={} ip={} port={} fingerprint={}",
                    info.alias,
                    info.ip,
                    info.port,
                    crate::logger::mask(&info.fingerprint)
                );
                list.push(info);
            }
        }
        crate::log_info!("设备发现事件循环退出");
    });

    Ok(format!("设备发现已启动（端口 {DEFAULT_PORT}）"))
}

/// 停止设备发现（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
pub async fn stop_discovery(app: AppHandle) -> Result<(), AppError> {
    crate::log_info!("停止设备发现");
    let state = app.state::<DiscoveryState>();
    // 通知子网扫描线程提前退出
    state.scan_stop.store(true, Ordering::Relaxed);

    let stop_tx = state
        .stop_tx
        .lock()
        .map_err(|_| AppError::from_poison())?
        .take();
    if let Some(tx) = stop_tx {
        let _ = tx.send(());
    }
    let handle = state
        .handle
        .lock()
        .map_err(|_| AppError::from_poison())?
        .take();
    if let Some(handle) = handle {
        handle.wait_stopped().await;
    }
    Ok(())
}

/// 获取已发现的设备列表（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
/// 剪枝：8 秒内未再被发现的设备（停止广播/下线）自动清除，发现表实时可用
pub fn get_discovered_devices(app: AppHandle) -> Result<Vec<DiscoveredDeviceInfo>, AppError> {
    let state = app.state::<DiscoveryState>();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut list = state
        .devices
        .lock()
        .map_err(|_| AppError::from_poison())?;
    list.retain(|d| now.saturating_sub(d.last_seen) < 8000);
    Ok(list.clone())
}

/// 把探测到的设备并入发现列表（按 fingerprint 去重，刷新存活时间）
pub fn add_device(app: AppHandle, info: DiscoveredDeviceInfo) {
    let state = app.state::<DiscoveryState>();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut list = state.devices.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(existing) = list.iter_mut().find(|d| d.fingerprint == info.fingerprint) {
        existing.last_seen = now;
    } else {
        crate::log_info!(
            "发现设备(子网) alias={} ip={} port={}",
            info.alias,
            info.ip,
            info.port
        );
        list.push(info);
    }
}

/// /24 子网探测：单播 TCP 探测各主机配对服务（端口+1）的 /info。
/// 不依赖组播，提高配对/连接发现可靠性（与手机端子网探测对称）。
pub fn subnet_scan(app: AppHandle, port: u16, stop_flag: Arc<AtomicBool>) {
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return;
    };
    let mut targets: Vec<String> = Vec::new();
    for iface in ifaces {
        if iface.is_loopback() {
            continue;
        }
        if let std::net::IpAddr::V4(v4) = iface.ip() {
            let b = v4.octets();
            for h in 1..=254u8 {
                if h == b[3] {
                    continue;
                }
                targets.push(std::net::Ipv4Addr::new(b[0], b[1], b[2], h).to_string());
            }
        }
    }
    crate::log_info!(
        "子网探测: {} 个主机 (配对服务端口 {})",
        targets.len(),
        port + 1
    );
    // 有界工作池（64 线程）取代每 IP 一线程：254 个 OS 线程的栈内存与调度开销
    // 不再必要（探测是 1.5s 连接超时的纯阻塞 IO，64 并发足以饱和 /24 网段探测）
    use std::collections::VecDeque;
    let n_workers = targets.len().min(64);
    let queue = Arc::new(std::sync::Mutex::new(VecDeque::from(targets)));
    let mut workers = Vec::with_capacity(n_workers);
    for _ in 0..n_workers {
        let app = app.clone();
        let flag = stop_flag.clone();
        let q = queue.clone();
        workers.push(std::thread::spawn(move || loop {
            if flag.load(Ordering::Relaxed) {
                return;
            }
            let ip = q
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pop_front();
            let Some(ip) = ip else {
                return;
            };
            let Ok(v) = crate::transfer::http_json_request(
                &ip,
                port + 1,
                "GET",
                "/api/localsend/v2/info",
                "",
            ) else {
                return;
            };
            let fingerprint = v
                .get("fingerprint")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if fingerprint.is_empty() {
                return;
            }
            let self_id = crate::identity::get_device_id(&app);
            if fingerprint == self_id {
                return;
            }
            let info = DiscoveredDeviceInfo {
                alias: v
                    .get("alias")
                    .and_then(|x| x.as_str())
                    .unwrap_or(&ip)
                    .to_string(),
                fingerprint,
                ip: ip.clone(),
                port: v
                    .get("port")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(port as u64) as u16,
                last_seen: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
            };
            add_device(app.clone(), info);
        }));
    }
    for w in workers {
        let _ = w.join();
    }
    crate::log_info!("子网探测完成");
}
