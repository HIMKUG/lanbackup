#![allow(dead_code)]
//! 设备发现模块（Phase C：用 core presence + discovery 替换 LocalSend v2）
//!
//! 发现通路：
//! - 子网扫描：/24 单播探测 GET /api/v4/probe（不依赖组播）
//! - UDP beacon：core::presence::transport 的 BeaconEmitter + PresenceSocket（将来接入）

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager};
use crate::db::AppError;

/// 发现的设备信息（Tauri 命令返回值）
#[derive(serde::Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredDeviceInfo {
    pub alias: String,
    pub fingerprint: String,
    pub ip: String,
    pub port: u16,
    pub last_seen: u64,
}

/// 设备发现全局状态
struct V4DiscoveryState {
    stop_tx: Mutex<Option<Arc<AtomicBool>>>,
    devices: Arc<Mutex<Vec<DiscoveredDeviceInfo>>>,
    scan_stop: Arc<AtomicBool>,
}

impl Default for V4DiscoveryState {
    fn default() -> Self {
        Self {
            stop_tx: Mutex::new(None),
            devices: Arc::new(Mutex::new(Vec::new())),
            scan_stop: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub struct DiscoveryState(V4DiscoveryState);

impl Default for DiscoveryState {
    fn default() -> Self {
        Self(V4DiscoveryState::default())
    }
}

/// 启动设备发现
pub async fn start_discovery(app: AppHandle, server_port: u16) -> Result<String, AppError> {
    crate::log_info!("启动设备发现: 服务器端口={server_port}");
    app.state::<crate::transfer::TransferState>()
        .discoverable
        .store(true, Ordering::Relaxed);

    let state = app.state::<DiscoveryState>();
    if state.0.stop_tx.lock().ok().and_then(|g| g.as_ref().cloned()).is_some() {
        return Err(AppError("设备发现已在运行".to_string()));
    }

    let stop_flag = Arc::new(AtomicBool::new(false));
    {
        let mut g = state.0.stop_tx.lock().unwrap_or_else(|p| p.into_inner());
        *g = Some(stop_flag.clone());
    }

    state.0.scan_stop.store(false, Ordering::Relaxed);
    state.0.devices.lock().unwrap_or_else(|p| p.into_inner()).clear();

    let devices = state.0.devices.clone();
    let scan_app = app.clone();
    let stop_flag_inner = state.0.scan_stop.clone();

    std::thread::spawn(move || {
        subnet_scan_inner(scan_app, server_port, stop_flag_inner, devices);
    });

    Ok(format!("设备发现已启动"))
}

/// 停止设备发现
pub async fn stop_discovery(app: AppHandle) -> Result<(), AppError> {
    crate::log_info!("停止设备发现");
    app.state::<crate::transfer::TransferState>()
        .discoverable
        .store(false, Ordering::Relaxed);

    let state = app.state::<DiscoveryState>();
    state.0.scan_stop.store(true, Ordering::Relaxed);

    if let Some(stop) = state.0.stop_tx.lock().unwrap_or_else(|p| p.into_inner()).take() {
        stop.store(true, Ordering::Relaxed);
    }
    Ok(())
}

/// 获取已发现的设备列表
pub fn get_discovered_devices(app: AppHandle) -> Result<Vec<DiscoveredDeviceInfo>, AppError> {
    let state = app.state::<DiscoveryState>();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut list = state.0.devices.lock().unwrap_or_else(|p| p.into_inner());
    list.retain(|d| now.saturating_sub(d.last_seen) < 8000);
    Ok(list.clone())
}

pub fn add_device(app: AppHandle, info: DiscoveredDeviceInfo) {
    let state = app.state::<DiscoveryState>();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut list = state.0.devices.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(existing) = list.iter_mut().find(|d| d.fingerprint == info.fingerprint) {
        if existing.ip != info.ip {
            crate::log_warn!(
                "设备 IP 冲突 fingerprint={} 旧ip={} 新ip={}",
                crate::logger::mask(&info.fingerprint),
                existing.ip,
                info.ip
            );
            let _ = app.emit("device-suspicious", serde_json::json!({
                "fingerprint": info.fingerprint,
                "oldIp": existing.ip,
                "newIp": info.ip,
            }));
            existing.last_seen = now;
        } else {
            existing.last_seen = now;
        }
    } else {
        crate::log_info!(
            "发现设备 alias={} ip={} port={}",
            info.alias,
            info.ip,
            info.port
        );
        list.push(info);
    }
}

pub fn remove_by_ip(app: AppHandle, ip: &str) {
    let state = app.state::<DiscoveryState>();
    let mut list = state.0.devices.lock().unwrap_or_else(|p| p.into_inner());
    list.retain(|d| d.ip != ip);
    crate::log_info!("移除设备(by IP): {}", ip);
}

/// 子网扫描核心（内部实现，供 thread spawn 调用）
fn subnet_scan_inner(
    app: AppHandle,
    port: u16,
    stop_flag: Arc<AtomicBool>,
    devices: Arc<Mutex<Vec<DiscoveredDeviceInfo>>>,
) {
    let Ok(ifaces) = if_addrs::get_if_addrs() else { return; };
    let mut targets: Vec<String> = Vec::new();

    for iface in ifaces {
        if iface.is_loopback() { continue; }
        if let std::net::IpAddr::V4(v4) = iface.ip() {
            let b = v4.octets();
            for h in 1..=254u8 {
                if h == b[3] { continue; }
                targets.push(std::net::Ipv4Addr::new(b[0], b[1], b[2], h).to_string());
            }
        }
    }

    crate::log_info!("子网探测: {} 个主机 (端口 {})", targets.len(), port);

    use std::collections::VecDeque;
    let n_workers = targets.len().min(64);
    let queue = Arc::new(std::sync::Mutex::new(VecDeque::from(targets)));
    let mut workers = Vec::with_capacity(n_workers);

    for _ in 0..n_workers {
        let app = app.clone();
        let flag = stop_flag.clone();
        let q = queue.clone();
        let devs = devices.clone();

        workers.push(std::thread::spawn(move || loop {
            if flag.load(Ordering::Relaxed) { return; }
            let ip = q.lock().unwrap_or_else(|p| p.into_inner()).pop_front();
            let Some(ip) = ip else { return; };

            let Ok(v) = crate::transfer::http_json_request(
                &ip,
                port,
                "GET",
                "/api/v4/probe",
                "",
            ) else { continue };

            let device_id = v.get("deviceId")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if device_id.is_empty() { continue; }

            let self_id = crate::identity::get_device_id(&app);
            if device_id == self_id { continue; }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);

            let info = DiscoveredDeviceInfo {
                alias: v.get("alias").and_then(|x| x.as_str()).unwrap_or(&ip).to_string(),
                fingerprint: device_id,
                ip: ip.clone(),
                port: v.get("port").and_then(|x| x.as_u64()).unwrap_or(port as u64) as u16,
                last_seen: now,
            };

            let mut list = devs.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(existing) = list.iter_mut().find(|d| d.fingerprint == info.fingerprint) {
                existing.last_seen = now;
            } else {
                crate::log_info!("发现设备(子网) alias={} ip={} port={}", info.alias, info.ip, info.port);
                list.push(info);
            }
        }));
    }

    for w in workers { let _ = w.join(); }
    crate::log_info!("子网探测完成");
}

/// /24 子网探测（保持原有 API 签名，内部委托 subnet_scan_inner）
#[allow(dead_code)]
pub fn subnet_scan(app: AppHandle, port: u16, stop_flag: Arc<AtomicBool>) {
    let devices = app.state::<DiscoveryState>().0.devices.clone();
    subnet_scan_inner(app, port, stop_flag, devices);
}
