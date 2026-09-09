//! 传输模块 - 配对记录持久化（SQLite）与同步
//!
//! 纯文件拆分重构：本文件内容从原 transfer.rs 原样移入，逻辑零改动。
//! 通过 `use super::*` 访问 mod.rs 中的类型与外部 use。

use super::*;
use base64::Engine as _;

pub(crate) fn http_json_request(
    ip: &str,
    port: u16,
    method: &str,
    path: &str,
    body: &str,
) -> Result<serde_json::Value, AppError> {
    let start = std::time::Instant::now();
    let r = http_json_request_inner(ip, port, method, path, body);
    let ms = start.elapsed().as_millis();
    if r.is_ok() {
        if ms >= 800 {
            crate::log_warn!("HTTP 请求耗时 {ms}ms: {method} {ip}:{port}{path}");
        }
    } else {
        crate::log_debug!("HTTP 请求失败 {ms}ms: {method} {ip}:{port}{path}");
    }
    r
}

fn http_json_request_inner(
    ip: &str,
    port: u16,
    method: &str,
    path: &str,
    body: &str,
) -> Result<serde_json::Value, AppError> {
    // connect 1500ms, read 3000ms, write 3000ms, 无 X-Protocol-Version
    http_json_request_internal(ip, port, method, path, body, 1500, 3000, 3000, None)
}

/// sync_all_peers 的「连续 unknown」保护计数（进程内，不落库）：
/// 对端一次"unknown"可能是瞬时错乱/时钟偏差，直接吊销会把仍有效的配对 secret 清掉（数据面即刻失效）。
/// 只有连续 3 次 unknown 才触发弱最终一致性吊销；对端明确回「revoked+令牌」则即时吊销。
static SYNC_UNKNOWN_STRIKES: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, u32>>> =
    std::sync::OnceLock::new();
const SYNC_UNKNOWN_LIMIT: u32 = 3;

fn sync_unknown_strikes() -> &'static std::sync::Mutex<std::collections::HashMap<String, u32>> {
    SYNC_UNKNOWN_STRIKES.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// 全量配对快照（含 REVOKED/REVOKE_PENDING，带 deviceId）。
/// 仅供**持久化**使用 —— 状态机在进程重启后必须仍知道哪些设备被吊销/待吊销，
/// 否则对端上线同步时会因记录丢失被误判为"新设备"而可能重新配对复活。
/// 与 get_paired_peers（UI 列表，过滤掉非 ACTIVE）区别：绝不复用同一次过滤的列表。
fn all_paired_peers(app: &AppHandle) -> Vec<serde_json::Value> {
    let st = app.state::<PairingState>();
    let mut out = Vec::new();
    if let Ok(m) = st.paired.lock() {
        for (id, v) in m.iter() {
            let mut p = v.clone();
            p["deviceId"] = serde_json::json!(id);
            out.push(p);
        }
    }
    out
}

/// 本机被验证方记录的对端信任列表（双端配对同步）
pub fn get_paired_peers(app: AppHandle) -> Vec<serde_json::Value> {
    let start = std::time::Instant::now();
    let out = get_paired_peers_inner(&app);
    let ms = start.elapsed().as_millis();
    if ms >= 100 {
        crate::log_warn!("get_paired_peers 耗时 {ms}ms（疑似 SQLite 锁竞争）");
    }
    out
}

fn get_paired_peers_inner(app: &AppHandle) -> Vec<serde_json::Value> {
    let st = app.state::<PairingState>();
    let mut out = Vec::new();
    if let Ok(m) = st.paired.lock() {
        for (id, v) in m.iter() {
            // v5：REVOKED / REVOKE_PENDING 记录保留在状态机中供 sync-status 收敛，
            // 但对前端列表不可见——否则解除配对后 10s 内被 mergePeers 轮询拉回，
            // 表现为"无法解除配对"且解除后瞬间重新出现（2026-08-23 22:3x 实测，
            // 2026-08-26 补：REVOKE_PENDING 同样会被拉回，需一并过滤）。
            // 注意：解配对收敛由"对端 ACTIVE 侧 sync_all_peers 主动来问"驱动（§5.2），
            // 本机 REVOKE_PENDING/REVOKED 不做同步周期探测，过滤后不影响状态机收敛
            //（对端回 unknown 走连续 3 次弱最终一致性吊销兜底）。
            let status = v.get("status").and_then(|s| s.as_str());
            if status == Some("REVOKED") || status == Some("REVOKE_PENDING") {
                continue;
            }
            let mut p = v.clone();
            p["deviceId"] = serde_json::json!(id);
            out.push(p);
        }
    }
    out
}

/// 本端主动确认配对：把配对记录写入后端 paired map。
/// 关键：本端作为"验证方"配对成功时，后端 greet 校验查的是这个 map；
/// 不写入会导致对方问候本机时返回"未信任"，被误判为解除配对。
/// 前端在配对成功/启动时批量调用，进程重启后自动回填（自愈）。
pub fn confirm_paired(
    app: AppHandle,
    device_id: String,
    name: String,
    ip: String,
    port: u16,
    fingerprint: String,
    peer_public_key: String,
) -> Result<(), AppError> {
    // 先取已有记录快照：历史 IP 合并 + v5 信任锚保留都要用
    let existing = app
        .state::<PairingState>()
        .paired
        .lock()
        .ok()
        .and_then(|m| m.get(&device_id).cloned());
    let mut ips = vec![ip.clone()];
    // 合并已有历史 IP（避免 DHCP 场景下同一设备新 IP 丢失旧 IP）；跳过空串脏数据
    if let Some(e) = &existing {
        if let Some(existing_ips) = e.get("ips").and_then(|v| v.as_array()) {
            for eip in existing_ips {
                if let Some(s) = eip.as_str() {
                    if !s.is_empty() && !ips.iter().any(|x| x == s) {
                        ips.push(s.to_string());
                    }
                }
            }
        }
    }
    let mut peer = serde_json::json!({
        "name": name,
        "ip": ip,
        "ips": ips,
        "port": port,
        "fingerprint": fingerprint,
    });
    // v5 信任状态机：默认 ACTIVE + pairingTimestamp；peerPublicKey 非空时写入（配对信任锚）
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    if let Some(o) = peer.as_object_mut() {
        o.entry("status".to_string()).or_insert_with(|| serde_json::json!("ACTIVE"));
        o.entry("pairingTimestamp".to_string()).or_insert_with(|| serde_json::json!(now));
        if !peer_public_key.is_empty() {
            o.insert("peerPublicKey".to_string(), serde_json::json!(peer_public_key));
        }
        // 防复活（2026-08-26）：本命令整体覆盖 paired map 条目，若已有记录处于
        // REVOKE_PENDING/REVOKED（离线解配对等待同步），回填不得把它踩回 ACTIVE，
        // 否则启动自愈类批量调用会悄悄撤销解配对。真正的重新配对走 v3_pair 流程显式改状态。
        let prev_terminal = existing
            .as_ref()
            .and_then(|e| e.get("status"))
            .and_then(|s| s.as_str())
            .map(|s| s == "REVOKE_PENDING" || s == "REVOKED")
            .unwrap_or(false);
        if prev_terminal {
            if let Some(e) = existing.as_ref() {
                for key in ["status", "peerPublicKey", "pairingTimestamp", "lastHeartbeat", "pendingRevokeToken"] {
                    if let Some(v) = e.get(key) {
                        o.insert(key.to_string(), v.clone());
                    }
                }
            }
        }
    }
    if let Ok(mut m) = app.state::<PairingState>().paired.lock() {
        m.insert(device_id.clone(), peer);
    }
    crate::log_info!(
        "本端确认配对: deviceId={} name={}",
        crate::logger::mask(&device_id),
        name
    );
    persist_paired(&app);
    Ok(())
}

/// 本端全量同步配对记录到后端 paired map（merge 语义，v5 保留信任字段）。
/// 关键：后端 paired map 是 greet 校验依据；v5 后 peerPublicKey/status 等信任锚字段
/// 只能由配对流程写入（verify / v3_pair），前端全量同步**不得清空重建**——
/// 否则会抹掉 peerPublicKey 导致门禁（check_trusted）误拒已配对设备。
/// 语义：以传入 peers 更新 name/ip/port/fingerprint 等基础字段；已存在记录的
/// status/peerPublicKey/pairingTimestamp/lastHeartbeat/pendingRevokeToken 保留；新记录默认 ACTIVE。
pub fn sync_paired(app: AppHandle, peers: Vec<serde_json::Value>) -> Result<(), AppError> {
    use tauri::Emitter;
    let start = std::time::Instant::now();
    let peer_count = peers.len();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let st = app.state::<PairingState>();
    if let Ok(mut m) = st.paired.lock() {
        for p in peers {
            let Some(device_id) = p.get("deviceId").and_then(|d| d.as_str()).map(String::from) else {
                continue;
            };
            let preserved = m.get(&device_id).cloned();
            let mut peer = p.clone();
            if let Some(obj) = peer.as_object_mut() {
                obj.remove("deviceId");
            }
            if let Some(prev) = preserved {
                // 已存在 → 保留 v5 信任字段（前端不持有，防误清）
                if let Some(o) = peer.as_object_mut() {
                    for key in ["status", "peerPublicKey", "pairingTimestamp", "lastHeartbeat", "pendingRevokeToken"] {
                        if !o.contains_key(key) {
                            if let Some(v) = prev.get(key) {
                                o.insert(key.to_string(), v.clone());
                            }
                        }
                    }
                }
            } else {
                // 新记录 → 默认 ACTIVE
                if let Some(o) = peer.as_object_mut() {
                    o.entry("status".to_string()).or_insert_with(|| serde_json::json!("ACTIVE"));
                    o.entry("pairingTimestamp".to_string()).or_insert_with(|| serde_json::json!(now));
                }
            }
            // 防御（记录已有状态备份）：前端陈旧记录若把已吊销设备的信任字段抹掉/覆盖，
            // 这里仍以状态机记录的 REVOKED/REVOKE_PENDING 为准（preserved 已回填），
            // 并主动发 pair-unpaired 让前端 drop 该设备，杜绝"解配对后 10s 内被拉回复活"。
            let status = peer.as_object().and_then(|o| o.get("status")).and_then(|s| s.as_str());
            if status == Some("REVOKED") || status == Some("REVOKE_PENDING") {
                app.emit("pair-unpaired", serde_json::json!({ "deviceId": device_id.clone() })).ok();
            }
            m.insert(device_id, peer);
        }
    }
    // UI 轮询伴随调用（每 10s）：DEBUG 级别，避免心跳刷屏
    crate::log_debug!("配对记录已全量同步: {peer_count} 台");
    persist_paired(&app);
    let ms = start.elapsed().as_millis();
    if ms >= 100 {
        crate::log_warn!("sync_paired 耗时 {ms}ms（疑似 SQLite 落盘瓶颈）");
    }
    Ok(())
}

/// 将当前配对信任表落盘 SQLite（每次增删后调用；数据量极小，全量重写即可）。
/// P5b：同时把 v3 pairing_secret 用本机 L1 storage_key 加密后落库（方案.txt §2.1），
/// 重启后 load_paired_from_db 解密回填 → 路径B（重连）与 P6 数据面可跨进程取密钥。
pub fn persist_paired(app: &AppHandle) {
    // C2 修正（2026-08-26）：改用全量快照 all_paired_peers，而非 UI 过滤后的
    // get_paired_peers。此前用过滤列表 → REVOKED/REVOKE_PENDING 不入库，进程重启后
    // 状态机丢失吊销事实，前端陈旧记录经 sync_paired 会把设备重新激活（解配对复活）。
    let peers = all_paired_peers(app);
    let ps = app.state::<PairingState>();
    // C1 修正：短临界区只 clone 需要的 secrets，绝不持锁跨 PBKDF2——
    // 此前写锁横跨 encrypt_storage_secret（600k 轮迭代，数百 ms），
    // 接收路径 try_read 全部失败 → 活跃传输取不到 pairing_secret 解密失败；
    // try_write().unwrap() 在并发下还会 panic。现在：try_read 失败短暂重试后降级
    // 为"本轮不落密钥"（记录仍会落盘，下次配对变更时补上）。
    let device_ids: Vec<String> = peers
        .iter()
        .filter_map(|p| p.get("deviceId").and_then(|d| d.as_str()).map(String::from))
        .collect();
    let mut secret_map: std::collections::HashMap<String, Vec<u8>> = HashMap::new();
    for _ in 0..3 {
        match ps.secrets.try_read() {
            Ok(s) => {
                for id in &device_ids {
                    if let Some(sec) = s.get(id) {
                        secret_map.insert(id.clone(), sec.clone());
                    }
                }
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    // 加密在锁外进行（PBKDF2 只占本线程 CPU）
    let rows: Vec<(
        String,
        String,
        String,
        i64,
        String,
        String,
        Option<Vec<u8>>,
        Option<String>,
        String,
        Option<Vec<u8>>,
        i64,
        i64,
        Option<String>,
    )> = peers
        .iter()
        .filter_map(|p| {
            let manifest = p.get("lastManifest")
                .map(|m| serde_json::to_string(m).unwrap_or_else(|_| "{}".to_string()))
                .unwrap_or_else(|| "{}".to_string());
            let device_id = p.get("deviceId").and_then(|d| d.as_str())?.to_string();
            // P5b：v3 pairing_secret 加密落库（None = 无 v3 密钥的遗留记录）
            let secret_enc = secret_map
                .get(&device_id)
                .and_then(|s| encrypt_storage_secret(app, &device_id, s));
            // 3.3：历史 IP 列表落库（ips 数组缺失时回退当前 ip 单元素；
            // 过滤空串防止 [""] 之类的脏条目入库）
            let current_ip = p.get("ip").and_then(|v| v.as_str()).unwrap_or("");
            let mut ips: Vec<String> = p
                .get("ips")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            if ips.is_empty() && !current_ip.is_empty() {
                ips.push(current_ip.to_string());
            }
            // Vec<String> 序列化不会失败；万一失败写空数组占位（load 侧会回退单 ip）
            let ips_json = Some(serde_json::to_string(&ips).unwrap_or_else(|_| "[]".to_string()));
            // v5：信任状态机字段（status/peerPublicKey/pairingTimestamp/lastHeartbeat/pendingRevokeToken）
            let status = p.get("status").and_then(|s| s.as_str()).unwrap_or("ACTIVE").to_string();
            let peer_pub: Option<Vec<u8>> = p
                .get("peerPublicKey")
                .and_then(|k| k.as_str())
                .and_then(|s| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok());
            let pairing_ts = p.get("pairingTimestamp").and_then(|v| v.as_i64()).unwrap_or(0);
            let last_hb = p.get("lastHeartbeat").and_then(|v| v.as_i64()).unwrap_or(0);
            let pending_revoke = p
                .get("pendingRevokeToken")
                .filter(|v| !v.is_null())
                .map(|v| v.to_string());
            Some((
                device_id,
                p.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                p.get("ip").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                p.get("port").and_then(|n| n.as_u64()).unwrap_or(53317) as i64,
                p.get("fingerprint").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                manifest,
                secret_enc,
                ips_json,
                status,
                peer_pub,
                pairing_ts,
                last_hb,
                pending_revoke,
            ))
        })
        .collect();
    if let Err(e) = crate::db::save_paired_peers(&app, rows) {
        crate::log_warn!("配对记录落盘失败: {e}");
    }
}

/// 用本机 L1 storage_key（PBKDF2-600k(连接码, salt=SHA256(本机device_id))）加密 pairing_secret。
/// 加密/解密都是本机进行（方案.txt §2.1 L1：每设备唯一，防彩虹表）。
fn encrypt_storage_secret(app: &AppHandle, _peer_device_id: &str, secret: &[u8]) -> Option<Vec<u8>> {
    let code = identity::get_self_code(app);
    let my_id = identity::get_device_id(app);
    let key = crate::crypto::derive_storage_key_v2(&code, my_id.as_bytes()).ok()?;
    crate::crypto::encrypt(&key, secret).ok()
}

/// 解密 pairing_secret（base64 → 显式版本分发：v2=PBKDF2，失败回退 v1=SHA-256 兼容旧记录）。
fn decrypt_storage_secret(app: &AppHandle, _peer_device_id: &str, b64: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let data = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let code = identity::get_self_code(app);
    let my_id = identity::get_device_id(app);
    // v2：PBKDF2-600k（本轮写入一律 v2）
    if let Ok(key) = crate::crypto::derive_storage_key_v2(&code, my_id.as_bytes()) {
        if let Ok(plain) = crate::crypto::decrypt(&key, &data) {
            return Some(plain);
        }
    }
    // v1 回退：SHA-256(连接码)（历史遗留记录）
    let key = crate::crypto::derive_local_storage_key(&code);
    crate::crypto::decrypt(&key, &data).ok()
}

/// 启动时从 SQLite 恢复配对信任表（与前端 localStorage 互为镜像，双保险）。
/// P5b：同时解密 pairing_secret 回填 PairingState.secrets → 路径B（重连）与
/// P6 数据面（接收端按发送方 device_id 派生 per-file key）跨进程可用。
pub fn load_paired_from_db(app: &AppHandle) {
    match crate::db::load_paired_peers(app) {
        Ok(peers) => {
            let count = peers.len();
            let mut secret_restored = 0usize;
            let st = app.state::<PairingState>();
            // B1：从 SQLite 恢复本机静态 P-256 密钥（进程重启后路径A/B 继续用同一密钥）
            if let Ok(Some((priv_b64, pub_b64))) = crate::db::load_static_key(app) {
                let key = Some((priv_b64, pub_b64));
                if let Ok(mut k) = st.static_key.lock() {
                    if k.is_none() {
                        *k = key;
                        crate::log_info!("本机静态密钥已从数据库恢复");
                    }
                }
            }
            // P5b：解密 pairing_secret 回填（供 challenge 重连 / 数据面派生）
            if let Ok(mut s) = st.secrets.try_write() {
                if let Ok(mut m) = st.paired.lock() {
                    for p in &peers {
                        if let Some(device_id) = p.get("deviceId").and_then(|d| d.as_str()) {
                            let mut peer = p.clone();
                            if let Some(obj) = peer.as_object_mut() {
                                obj.remove("deviceId");
                                obj.remove("pairingSecretB64");
                                obj.remove("cryptoVersion");
                                // 3.3：ips 数组——DB 有历史记录则用之（跨重启保留），
                                // 空/缺失回退当前 ip 单元素（v4 之前的旧库兼容）
                                let ips = p
                                    .get("ips")
                                    .and_then(|v| v.as_array())
                                    .filter(|a| !a.is_empty())
                                    .map(|a| serde_json::Value::Array(a.clone()))
                                    .unwrap_or_else(|| {
                                        serde_json::json!([p.get("ip").and_then(|v| v.as_str()).unwrap_or("")])
                                    });
                                obj.insert("ips".to_string(), ips);
                            }
                            m.insert(device_id.to_string(), peer);
                        }
                    }
                }
                for p in &peers {
                    if let Some(device_id) = p.get("deviceId").and_then(|d| d.as_str()) {
                        if let Some(b64) = p.get("pairingSecretB64").and_then(|b| b.as_str()) {
                            if !b64.is_empty() {
                                if let Some(secret) = decrypt_storage_secret(app, device_id, b64) {
                                    s.insert(device_id.to_string(), secret);
                                    secret_restored += 1;
                                }
                            }
                        }
                    }
                }
            }
            crate::log_info!(
                "配对记录已从数据库恢复: {} 台（含 pairing_secret {} 条）",
                count,
                secret_restored
            );
        }
        Err(e) => crate::log_warn!("配对记录从数据库恢复失败: {e}"),
    }
}

/// 通知目标设备本机选择的备份目录名（POST /api/v4/sync-dir，直连对端 receive port）
pub fn send_sync_dir(
    ip: String,
    port: u16,
    direction: String,
    name: String,
) -> Result<bool, AppError> {
    let body = serde_json::json!({
        "deviceId": crate::identity::get_device_id_no_ctx(),
        "rootId": "default",
        "targetDir": name,
        "strategy": direction,
    }).to_string();
    let v = http_json_request(&ip, port, "POST", "/api/v4/sync-dir", &body)?;
    Ok(v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false))
}

/// 读取对方同步过来的目录名
#[allow(dead_code)]
pub fn get_synced_dir(app: AppHandle, direction: String) -> Option<serde_json::Value> {
    let st = app.state::<PairingState>();
    let name = st.synced_dirs.lock().ok()?.get(&direction).cloned()?;
    Some(serde_json::json!({ "name": name, "at": chrono_now_ms() }))
}

/// 当前毫秒时间戳（无 chrono 依赖，用 SystemTime）
fn chrono_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════
// v5 新架构：解配对客户端（在线/离线）+ 吊销同步 + 物理重置
// （新架构 §四 在线解配对 / §五 离线解配对 / §八 物理重置）
// 签名内容与 pairing/v3.rs 服务端严格对齐。
// ════════════════════════════════════════════════════════════════

/// 签名内容拼接：prefix || parts（UTF-8 字节）
fn sig_buf(prefix: &[u8], parts: &[&str]) -> Vec<u8> {
    let mut m = prefix.to_vec();
    for p in parts {
        m.extend_from_slice(p.as_bytes());
    }
    m
}

/// 当前毫秒时间戳字符串（签名 payload 用，双端一致）
fn sig_now_ts() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

/// 吊销令牌 nonce（32 字节随机 hex）
fn sig_rand_nonce() -> String {
    let b: [u8; 32] = rand::random();
    hex::encode(b)
}

/// 在线解配对：POST /api/v4/unpair-request（直连对端 receive port）。
/// 签名：frame(DOMAIN_UNPAIR, [deviceId, requestId])，由 core pairing::transcript::unpair_payload 构造。
pub fn unpair_request_remote(app: &AppHandle, ip: String, port: u16, _target_device_id: String) -> Result<serde_json::Value, AppError> {
    let my_id = crate::identity::get_device_id_no_ctx();
    let request_id = hex::encode(rand::random::<[u8; 16]>());
    let (sig_priv, _pub) = crate::transfer::get_or_create_sig_key(app);
    let payload = lanbackup_core::pairing::transcript::unpair_payload(&my_id, &request_id)
        .ok_or_else(|| AppError("unpair_payload 构造失败".to_string()))?;
    let signature = crate::crypto::sig_sign(&sig_priv, &payload).map_err(AppError::from_display)?;
    let body = serde_json::json!({
        "deviceId": my_id,
        "signature": signature,
        "requestId": request_id,
    })
    .to_string();
    crate::transfer::http_json_request(&ip, port, "POST", "/api/v4/unpair-request", &body)
}

/// A 上线状态同步：GET /api/v4/sync-status?deviceId=...（直连对端 receive port）。
/// 返回对端视角下"你还认我吗"的回答。
pub fn sync_peer_status(_app: &AppHandle, ip: String, port: u16, _target_device_id: String) -> Result<serde_json::Value, AppError> {
    let my_id = crate::identity::get_device_id_no_ctx();
    let path = format!("/api/v4/sync-status?deviceId={}", my_id);
    crate::transfer::http_json_request(&ip, port, "GET", &path, "")
}

/// A 收到吊销通知后确认：POST /api/v4/revoke-ack（直连对端 receive port）。
pub fn send_revoke_ack(app: &AppHandle, ip: String, port: u16, _target_device_id: String, token: &serde_json::Value) -> Result<serde_json::Value, AppError> {
    let my_id = crate::identity::get_device_id_no_ctx();
    let revoke_token = token.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
    let request_id = hex::encode(rand::random::<[u8; 16]>());
    let (sig_priv, _pub) = crate::transfer::get_or_create_sig_key(app);
    let payload = lanbackup_core::pairing::transcript::revoke_payload(&my_id, revoke_token)
        .ok_or_else(|| AppError("revoke_payload 构造失败".to_string()))?;
    let signature = crate::crypto::sig_sign(&sig_priv, &payload).map_err(AppError::from_display)?;
    let body = serde_json::json!({
        "deviceId": my_id,
        "revokeToken": revoke_token,
        "pairingRevoked": true,
        "signature": signature,
        "requestId": request_id,
    })
    .to_string();
    crate::transfer::http_json_request(&ip, port, "POST", "/api/v4/revoke-ack", &body)
}

/// 生成吊销令牌（本机为 issuer，target 为要解除的对方）
fn make_revoke_token(app: &AppHandle, target_device_id: &str) -> serde_json::Value {
    let issued_at = sig_now_ts();
    let nonce = sig_rand_nonce();
    let my_id = crate::identity::get_device_id_no_ctx();
    let (sig_priv, _pub) = crate::transfer::get_or_create_sig_key(app);
    let msg = sig_buf(b"localsend-v3/revoke", &[&my_id, target_device_id, &issued_at, &nonce]);
    let signature = crate::crypto::sig_sign(&sig_priv, &msg).unwrap_or_default();
    serde_json::json!({
        "issuerDeviceId": my_id,
        "targetDeviceId": target_device_id,
        "issuedAt": issued_at,
        "nonce": nonce,
        "signature": signature,
    })
}

/// 解除配对统一入口（在线/离线，§四/§五）：
/// 1) 先尝试直连对端发 unpair-request（在线路径，双方立即 REVOKED）
/// 2) 失败 → 本地 REVOKE_PENDING + 吊销令牌 + 删除 pairing_secret（数据面立即拒绝，等待对方上线同步）
pub fn unpair_peer(app: AppHandle, device_id: String) -> Result<serde_json::Value, AppError> {
    use tauri::Emitter as _;
    let record = {
        let st = app.state::<PairingState>();
        let m = st.paired.lock().map_err(|_| AppError::from_poison())?;
        m.get(&device_id)
            .cloned()
            .ok_or_else(|| AppError("未找到该设备的配对记录".to_string()))?
    };
    let ip = record.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let port = record.get("port").and_then(|v| v.as_u64()).unwrap_or(53317) as u16;
    // 1. 在线直连（对方可达 → 双方立即 REVOKED，§四）
    if !ip.is_empty() {
        if let Ok(resp) = unpair_request_remote(&app, ip.clone(), port, device_id.clone()) {
            if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                if let Ok(mut m) = app.state::<PairingState>().paired.lock() {
                    if let Some(v) = m.get_mut(&device_id) {
                        if let Some(o) = v.as_object_mut() {
                            o.insert("status".to_string(), serde_json::json!("REVOKED"));
                            o.remove("pendingRevokeToken");
                        }
                    }
                }
                if let Ok(mut s) = app.state::<PairingState>().secrets.try_write() {
                    s.remove(&device_id);
                }
                crate::transfer::persist_paired(&app);
                let _ = app.emit("pair-unpaired", serde_json::json!({ "deviceId": device_id }));
                crate::log_info!("在线解配对成功: deviceId={}", crate::logger::mask(&device_id));
                return Ok(serde_json::json!({ "status": "REVOKED", "mode": "online" }));
            }
        }
    }
    // 2. 离线路径：本地 REVOKE_PENDING + 吊销令牌 + 删除对称密钥（§5.1）
    let token = make_revoke_token(&app, &device_id);
    {
        if let Ok(mut m) = app.state::<PairingState>().paired.lock() {
            if let Some(v) = m.get_mut(&device_id) {
                if let Some(o) = v.as_object_mut() {
                    o.insert("status".to_string(), serde_json::json!("REVOKE_PENDING"));
                    o.insert("pendingRevokeToken".to_string(), token.clone());
                }
            }
        }
    }
    {
        if let Ok(mut s) = app.state::<PairingState>().secrets.try_write() {
            s.remove(&device_id);
        }
    }
    persist_paired(&app);
    crate::log_info!("离线解配对: deviceId={} → REVOKE_PENDING（等待对方上线同步）", crate::logger::mask(&device_id));
    Ok(serde_json::json!({ "status": "REVOKE_PENDING", "mode": "offline", "revokeToken": token }))
}

/// 上线状态同步（事件驱动，§5.2）：遍历所有已配对设备直连发 sync-status。
/// - 对端回 revoked+令牌 → 本机转 REVOKED + 发 revoke-ack
/// - 对端回 unknown → 对端不再认识本机 → 本机转 REVOKED（弱最终一致，§5.3）
/// - 对端回 ok → 更新 lastHeartbeat，无操作
pub fn sync_all_peers(app: AppHandle) -> Result<serde_json::Value, AppError> {
    use tauri::Emitter as _;
    let peers = get_paired_peers(app.clone());
    let mut revoked = 0usize;
    for p in &peers {
        let device_id = p.get("deviceId").and_then(|d| d.as_str()).unwrap_or("").to_string();
        if device_id.is_empty() {
            continue;
        }
        let ip = p.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if ip.is_empty() {
            continue;
        }
        let port = p.get("port").and_then(|v| v.as_u64()).unwrap_or(53317) as u16;
        let Ok(resp) = sync_peer_status(&app, ip.clone(), port, device_id.clone()) else {
            continue;
        };
        let status = resp.get("status").and_then(|s| s.as_str()).unwrap_or("unknown");
        if status == "revoked" {
            if let Some(token) = resp.get("revokeToken") {
                if !token.is_null() {
                    if let Ok(mut m) = app.state::<PairingState>().paired.lock() {
                        if let Some(v) = m.get_mut(&device_id) {
                            if let Some(o) = v.as_object_mut() {
                                o.insert("status".to_string(), serde_json::json!("REVOKED"));
                                o.remove("pendingRevokeToken");
                            }
                        }
                    }
                    if let Ok(mut s) = app.state::<PairingState>().secrets.try_write() {
                        s.remove(&device_id);
                    }
                    crate::transfer::persist_paired(&app);
                    let _ = send_revoke_ack(&app, ip.clone(), port, device_id.clone(), token);
                    if let Ok(mut m) = sync_unknown_strikes().lock() {
                        m.remove(&device_id);
                    }
                    revoked += 1;
                }
            }
        } else if status == "unknown" {
            // 对端不再认识本机 → 弱最终一致性。防御：连续 N 次 unknown 才吊销，
            // 避免一次瞬时错误清掉有效配对 secret（数据面即刻失效）。
            let mut strikes = 0u32;
            if let Ok(mut m) = sync_unknown_strikes().lock() {
                let n = m.entry(device_id.clone()).or_insert(0u32);
                *n += 1;
                strikes = *n;
            }
            if strikes >= SYNC_UNKNOWN_LIMIT {
                crate::log_warn!(
                    "连续 {} 次 unknown，吊销设备 deviceId={}",
                    strikes,
                    crate::logger::mask(&device_id)
                );
                if let Ok(mut m) = app.state::<PairingState>().paired.lock() {
                    if let Some(v) = m.get_mut(&device_id) {
                        if let Some(o) = v.as_object_mut() {
                            o.insert("status".to_string(), serde_json::json!("REVOKED"));
                            o.remove("pendingRevokeToken");
                        }
                    }
                }
                if let Ok(mut s) = app.state::<PairingState>().secrets.try_write() {
                    s.remove(&device_id);
                }
                crate::transfer::persist_paired(&app);
                if let Ok(mut m) = sync_unknown_strikes().lock() {
                    m.remove(&device_id);
                }
                revoked += 1;
            } else {
                crate::log_debug!(
                    "对端 unknown（第 {}/{} 次，暂不吊销）: deviceId={}",
                    strikes,
                    SYNC_UNKNOWN_LIMIT,
                    crate::logger::mask(&device_id)
                );
            }
        } else if status == "ok" {
            // 对端正常 → 重置连续计数
            if let Ok(mut m) = sync_unknown_strikes().lock() {
                m.remove(&device_id);
            }
        }
    }
    let _ = app.emit("paired-updated", ());
    crate::log_info!("上线状态同步完成: 处理 {} 台，吊销 {} 台", peers.len(), revoked);
    Ok(serde_json::json!({ "ok": true, "revoked": revoked }))
}

/// 物理重置（§八 兜底）：清空所有配对 + 重新生成 ECDSA 签名密钥。
/// 旧公钥作废 → 任何旧配对消息无法验签 → 彻底解除，无需通知对方。
pub fn reset_all_pairings(app: AppHandle) -> Result<(), AppError> {
    use tauri::Emitter as _;
    {
        if let Ok(mut m) = app.state::<PairingState>().paired.lock() {
            m.clear();
        }
    }
    {
        if let Ok(mut s) = app.state::<PairingState>().secrets.try_write() {
            s.clear();
        }
    }
    // 重新生成签名身份（覆盖旧密钥）
    let new_key = crate::crypto::sig_generate_keypair().map_err(AppError::from_display)?;
    crate::db::save_sig_key(&app, &new_key.0, &new_key.1)?;
    if let Ok(mut k) = app.state::<PairingState>().sig_key.lock() {
        *k = Some(new_key);
    }
    persist_paired(&app);
    crate::transfer::notify_peers_disconnect(&app);
    let _ = app.emit("paired-updated", ());
    crate::log_info!("物理重置：已清空所有配对并重新生成签名身份");
    Ok(())
}

/// 重置状态（用户主动「重置状态」，§八 兜底 + 全量清空）：
/// 清空全部配对/同步目录/对称密钥，并**重新生成 ECDH 静态身份 + ECDSA 签名身份**，
/// 让本机成为一个"全新设备"——旧身份密钥作废后，任何旧配对消息都无法验签/解密，
/// 对方端残留的信任记录也随之失效，无需逐台通知。
/// 注意：数据库业务表（devices/transfer_history/paired_peers/local_identity）的清空
/// 由命令层另行调用 db.reset_all()，本函数只负责内存态与身份密钥再生。
pub fn reset_all_state(app: &AppHandle) -> Result<(), AppError> {
    use tauri::Emitter;
    {
        if let Ok(mut m) = app.state::<PairingState>().paired.lock() { m.clear(); }
        if let Ok(mut s) = app.state::<PairingState>().secrets.try_write() { s.clear(); }
        if let Ok(mut d) = app.state::<PairingState>().synced_dirs.lock() { d.clear(); }
        if let Ok(mut k) = app.state::<PairingState>().static_key.lock() { *k = None; }
    }
    // 全新 ECDH 静态身份（重新生成并持久化；生成失败则显式失败，避免以空密钥运行）
    let sta = crate::crypto::ecdh_generate_keypair().map_err(AppError::from_display)?;
    crate::db::save_static_key(app, &sta.0, &sta.1)?;
    if let Ok(mut k) = app.state::<PairingState>().static_key.lock() { *k = Some((sta.0, sta.1)); }
    // 全新 ECDSA 签名身份（旧签名消息一律无法验签 → 旧信任锚失效）
    let sig = crate::crypto::sig_generate_keypair().map_err(AppError::from_display)?;
    crate::db::save_sig_key(app, &sig.0, &sig.1)?;
    if let Ok(mut k) = app.state::<PairingState>().sig_key.lock() { *k = Some(sig); }
    persist_paired(app);
    crate::transfer::notify_peers_disconnect(app);
    let _ = app.emit("paired-updated", ());
    let _ = app.emit("pair-unpaired", serde_json::json!({ "reset": true }));
    crate::log_info!("重置状态完成：已清空全部配对/同步/密钥并再生全新身份");
    Ok(())
}
