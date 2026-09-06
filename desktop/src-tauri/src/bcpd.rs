//! bcpd.rs — 常驻「加密存在」广播（加密存在 broadcast）
//!
//! 语义（用户明确的行为模型）：
//! - 发现服务（discoverable）：仅服务于配对流程。关闭时明文 probe 对一切设备返回空 id，
//!   已配对设备发现本机**不**走明文 probe，而是走本模块的常驻加密存在。
//! - 收件服务：仅作为接受收件的"锁"，与设备是否出现在局域网无关。
//! - 防御性总开关（defensive_hidden）：最高优先级总闸。隐藏时本机完全不在局域网出现
//!   （停发加密存在、拒绝一切入站），仅保留本机主动外连。
//! - 本模块：只要软件运行，就会常驻发送加密存在广播（除防御总闸隐藏之外），
//!   仅已配对设备能解析（HMAC 用双方共享 pairing_secret 校验），并据此驱动
//!   对端在线/离线（握手/心跳超时 → 立即报告离线）。
//!
//! 组播包明文暴露本机 deviceId（让对端识别"这是谁"），身份与状态握手走 HMAC 加密封装：
//!   接收方用自己的 deviceId 在 m[] 里匹配到 slot，再用 secrets[发送方deviceId]
//!   重算 HMAC(secret, 发送方deviceId||ts) 校验 → 通过即证明对方持有与本机共享的
//!   pairing_secret，是真实配对设备。未配对设备看不到任何可用的 slot/密钥，无法解析。

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand;
use ring::hmac;
use serde_json::{Value, json};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tauri::{AppHandle, Emitter, Manager};

use crate::identity;

/// 加密存在广播使用的组播组 / 端口（本协议专用，与 LocalSend v2 发现(224.0.0.167:53317) 隔离）
const BCPD_GROUP: &str = "239.255.42.42";
const BCPD_PORT: u16 = 53319;
/// 发送周期；离线判定超时 = 周期 × 4（约 12s），留 1 个周期余量防抖动误判
const BCPD_INTERVAL_MS: u64 = 3000;
const OFFLINE_TIMEOUT_MS: u64 = 12_000;
/// 防重放：只接受最近 N 秒内的包（同时用于 dedup，rcvd-set TTL = max(30s, OFFLINE_TIMEOUT_MS)）
const REPLAY_WINDOW_MS: u64 = 30_000;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| format!("base64url 解码失败: {e}"))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&k, data).as_ref().to_vec()
}

/// bcpd 运行时状态（由 lib.rs manage）
pub struct BcpdState {
    /// 发送方 deviceId → 最近一次收到其有效加密存在的时刻（epoch ms）
    last_seen: Mutex<HashMap<String, u64>>,
    /// 发送方 deviceId → 最近一次发出的在线状态（去抖，避免重复发事件）
    last_state: Mutex<HashMap<String, bool>>,
    /// 防重放：已处理过的 (sender_id|ts) 集合，TTL = REPLAY_WINDOW_MS
    rcvd_seen: Mutex<HashMap<String, u64>>,
}

impl Default for BcpdState {
    fn default() -> Self {
        Self {
            last_seen: Mutex::new(HashMap::new()),
            last_state: Mutex::new(HashMap::new()),
            rcvd_seen: Mutex::new(HashMap::new()),
        }
    }
}

/// 校验某个配对记录是否 ACTIVE（REVOKE_PENDING/REVOKED 不参与加密存在互扫）
fn is_active_peer(app: &AppHandle, peer_id: &str) -> bool {
    app.state::<crate::transfer::PairingState>()
        .paired
        .lock()
        .ok()
        .and_then(|m| m.get(peer_id).cloned())
        .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(String::from))
        .map(|s| s == "ACTIVE")
        .unwrap_or(false)
}

/// 构造加密存在包。无任何 ACTIVE 配对设备时返回 None（无人可解析，不发空包）。
fn build_beacon(app: &AppHandle, ts: u64) -> Option<String> {
    let self_id = identity::get_device_id(app);
    let ps = app.state::<crate::transfer::PairingState>();
    let secrets = ps.secrets.try_read().ok()?;
    if secrets.is_empty() {
        return None;
    }
    let digest_input: Vec<u8> = format!("{self_id}{ts}").into_bytes();
    let mut macs = Vec::new();
    for (peer_id, secret) in secrets.iter() {
        // 只对仍 ACTIVE 的配对设备封包，已解除/吊销的不再向其宣告存在
        if !is_active_peer(app, peer_id) {
            continue;
        }
        let h = b64url(&hmac_sha256(secret, &digest_input));
        macs.push(json!({ "p": peer_id, "h": h }));
    }
    if macs.is_empty() {
        return None;
    }
    Some(json!({ "t": "bcpd", "d": self_id, "ts": ts, "m": macs }).to_string())
}

/// 预解析一个收到的 bcpd 包：
/// 1. 类型必须是 bcpd；
/// 2. ts 必须在 REPLAY_WINDOW_MS 内（防重放）；
/// 3. (sender, ts) 未被重复处理过（dedup）；
/// 4. m[] 中必须存在 p == 本机 deviceId 的 slot；
/// 5. 用 secrets[发送方 deviceId] 重算 HMAC 必须匹配。
/// 通过返回 发送方设备Id，否则 None。
fn try_parse_and_auth(app: &AppHandle, text: &str) -> Option<String> {
    let v: Value = serde_json::from_str(text).ok()?;
    if v.get("t").and_then(|x| x.as_str()) != Some("bcpd") {
        return None;
    }
    let sender = v.get("d").and_then(|x| x.as_str())?;
    let ts = v.get("ts").and_then(|x| x.as_u64())?;

    // ── F4: 防重放时间戳校验 + dedup ────────────────────────────────────────────
    let now = now_ms();
    if now.saturating_sub(ts) > REPLAY_WINDOW_MS || ts > now + 60_000 {
        // ts 过老或过新（漂移超过 60s）→ 丢弃
        return None;
    }
    let key = format!("{sender}|{ts}");
    let bst = app.state::<BcpdState>();
    let mut rcvd = match bst.rcvd_seen.lock() {
        Ok(g) => g,
        Err(_) => return None, // poison: discard
    };
        // 清理过期条目（每次抽 10% 概率触发）
        if rand_ratio(0.1) {
            let cutoff = now.saturating_sub(REPLAY_WINDOW_MS.max(OFFLINE_TIMEOUT_MS));
            rcvd.retain(|_, &mut t| t > cutoff);
        }
        if rcvd.contains_key(&key) {
            return None; // 重放包
        }
        rcvd.insert(key, now);

    let self_id = identity::get_device_id(app);
    // 找到发给本机的 slot
    let slot_h = v
        .get("m")
        .and_then(|x| x.as_array())?
        .iter()
        .find(|e| e.get("p").and_then(|x| x.as_str()) == Some(self_id.as_str()))
        .and_then(|e| e.get("h").and_then(|x| x.as_str()))?;
    // 本机持有与该发送方共享的 pairing_secret 吗？
    let ps = app.state::<crate::transfer::PairingState>();
    let secret = ps.secrets.try_read().ok()?.get(sender).cloned()?;
    let digest_input: Vec<u8> = format!("{sender}{ts}").into_bytes();
    let expect = hmac_sha256(&secret, &digest_input);
    if b64url_decode(slot_h).ok()? != expect {
        return None;
    }
    Some(sender.to_string())
}

/// 按概率 threshold 随机返回 true（用于低频清理触发）
fn rand_ratio(threshold: f64) -> bool {
    threshold > 0.0 && {
        let r: u8 = rand::random();
        (r as f64 / 256.0) < threshold
    }
}

/// 单次有效包到达：登记 last_seen + 触发在线事件 + 刷新配对记录心跳。
fn mark_received(app: &AppHandle, sender: &str) {
    let now = now_ms();
    let bst = app.state::<BcpdState>();
    let mut seen = bst.last_seen.lock().unwrap_or_else(|p| p.into_inner());
    seen.insert(sender.to_string(), now);
    drop(seen);
    // 触碰配对记录 lastHeartbeat（与握手心跳一致，供持久化路径可见）
    if let Ok(mut m) = app.state::<crate::transfer::PairingState>().paired.lock() {
        if let Some(v) = m.get_mut(sender) {
            if let Some(o) = v.as_object_mut() {
                o.insert("lastHeartbeat".to_string(), json!(now));
            }
        }
    }
    // 去抖发在线事件
    let mut st = bst.last_state.lock().unwrap_or_else(|p| p.into_inner());
    let changed = st.insert(sender.to_string(), true) != Some(true);
    drop(st);
    if changed {
        crate::log_debug!("加密存在: {} 上线", crate::logger::mask(sender));
        let _ = app.emit("pair-presence", json!({ "deviceId": sender, "online": true }));
    }
}

/// 离线扫描：超过 OFFLINE_TIMEOUT 未收到某对端有效加密存在 → 立即报告离线。
fn sweep_offline(app: &AppHandle) {
    let now = now_ms();
    let bst = app.state::<BcpdState>();
    let expired: Vec<String> = {
        let mut seen = bst.last_seen.lock().unwrap_or_else(|p| p.into_inner());
        let mut out = Vec::new();
        let mut to_remove = Vec::new();
        for (id, last) in seen.iter() {
            if now.saturating_sub(*last) > OFFLINE_TIMEOUT_MS {
                to_remove.push(id.clone());
                out.push(id.clone());
            }
        }
        for id in &to_remove {
            seen.remove(id);
        }
        out
    };
    for id in expired {
        let mut st = bst.last_state.lock().unwrap_or_else(|p| p.into_inner());
        let changed = st.insert(id.clone(), false) != Some(false);
        drop(st);
        if changed {
            crate::log_info!("加密存在超时: {} 判定离线", crate::logger::mask(&id));
            let _ = app.emit("pair-presence", json!({ "deviceId": id, "online": false }));
        }
    }
}

/// 打开组播发送 socket（绑临时端口），关闭环路回显避免收到自己的包。
/// F6 注：当前版本绑定到 0.0.0.0，由 OS 路由决定出口网卡（多网卡场景下默认路由
/// 可能走虚拟网卡，导致对端收不到）。如需精确多网卡遍历，需启用 socket2 的
/// if_nameindex API（需 socket2 ≥ 0.4.5，本项目当前为 0.17）。当前保守方案够用。
fn open_sender() -> Option<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    sock.set_multicast_ttl_v4(1).ok()?;
    sock.set_multicast_loop_v4(false).ok()?;
    let bind = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    sock.bind(&SockAddr::from(bind)).ok()?;
    Some(sock)
}

/// 打开组播接收 socket：绑组播端口 + 加入组播组。
fn open_receiver() -> Option<std::net::UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    sock.set_reuse_address(true).ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(1000))).ok()?;
    let bind = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, BCPD_PORT);
    sock.bind(&SockAddr::from(bind)).ok()?;
    let group_ip: Ipv4Addr = BCPD_GROUP.parse().ok()?;
    sock.join_multicast_v4(&group_ip, &Ipv4Addr::UNSPECIFIED).ok()?;
    Some(sock.into())
}

/// 启动常驻加密存在广播（发送器 + 接收器 + 离线扫描）。
/// 仅受防御性总闸（defensive_hidden）约束；与发现/收件开关无关。
#[allow(unused_assignments)]
pub fn start_bcpd(app: AppHandle) {
    // —— 发送器：周期组播加密存在；F3: socket 失效后指数退避重建 ——
    {
        let send_app = app.clone();
        tauri::async_runtime::spawn(async move {
            let dst = SockAddr::from(SocketAddrV4::new(
                BCPD_GROUP.parse().unwrap_or(Ipv4Addr::UNSPECIFIED),
                BCPD_PORT,
            ));
            let mut attempt = 0u32;
            loop {
                // 尝试获取可用发送 socket；失败时等待后重试
                let Some(sock) = open_sender() else {
                    attempt += 1;
                    let backoff = std::cmp::min(3_000u64.wrapping_shl(attempt.min(10)), 30_000u64);
                    crate::log_warn!(
                        "加密存在发送器初始化失败（{}s 后重试，第 {} 次）",
                        backoff / 1000,
                        attempt
                    );
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    continue;
                };
                attempt = 0;
                loop {
                    let hidden = send_app
                        .state::<crate::transfer::TransferState>()
                        .defensive_hidden
                        .load(Ordering::Relaxed);
                    if !hidden {
                        let ts = now_ms();
                        if let Some(pkt) = build_beacon(&send_app, ts) {
                            if sock.send_to(pkt.as_bytes(), &dst).is_err() {
                                // socket 失效（Windows UDP 偶发性失效），退出内循环触发外层重建
                                break;
                            }
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(BCPD_INTERVAL_MS)).await;
                }
                // socket 失效后触发外层重试
                attempt = 1;
            }
        });
    }

    // —— 接收器：std 线程（阻塞 recv + 离线扫描）；F3: 重试退避 ——
    {
        let recv_app = app.clone();
        std::thread::spawn(move || {
            let mut attempt = 0u32;
            loop {
                match open_receiver() {
                    Some(sock) => {
                        crate::log_info!(
                            "加密存在接收器已就绪（组播 {}:{}）",
                            BCPD_GROUP,
                            BCPD_PORT
                        );
                        attempt = 0;
                        let mut buf = [0u8; 4096];
                        loop {
                            match sock.recv_from(&mut buf) {
                                Ok((n, _)) => {
                                    if let Ok(text) = std::str::from_utf8(&buf[..n]) {
                                        if let Some(sender) = try_parse_and_auth(&recv_app, text) {
                                            mark_received(&recv_app, &sender);
                                        }
                                    }
                                }
                                Err(_) => { /* recv 超时 → 走下扫逻辑 */ }
                            }
                            sweep_offline(&recv_app);
                        }
                    }
                    None => {
                        let _e = std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "receiver socket");
                        attempt += 1;
                        let backoff = std::cmp::min(3_000u64.wrapping_shl(attempt.min(10)), 30_000u64);
                        crate::log_warn!(
                            "加密存在接收器启动失败（组播不可用，{}s 后重试，第 {} 次）",
                            backoff / 1000,
                            attempt
                        );
                        std::thread::sleep(Duration::from_millis(backoff));
                    }
                }
            }
        });
    }
}