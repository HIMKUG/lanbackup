//! 传输模块 - v3 控制面客户端与 HTTP 请求工具
//!
//! 纯文件拆分重构：本文件内容从原 transfer.rs 原样移入，逻辑零改动。
//! - `http_json_request` / `v3_http_long`：原始 HTTP JSON 请求（客户端侧）
//! - v3 控制面：probe / handshake / verify / pair
//! - P6：按目标 IP 解析 pairing_secret → 派生 per-file transfer_key

use super::*;

/// 原始 HTTP JSON 请求（客户端侧：探测/验证/同步目录）
pub(crate) fn http_json_request(
    ip: &str,
    port: u16,
    method: &str,
    path: &str,
    body: &str,
) -> Result<serde_json::Value, AppError> {
    // 诊断埋点：记录 HTTP 请求耗时，慢请求（≥800ms）记警告——
    // 定位"UI 全局卡死"问题（同步命令阻塞 IPC 线程）
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

/// v3 控制面专用 HTTP 请求：可配置读超时（P0 修复——路径A 配对弹窗确认最长 45s，
/// 必须用长读超时，否则客户端 3s 就超时报"timeout"，见历史症状"配对 timeout/对方拒绝"）。
pub(crate) fn v3_http_long(
    ip: &str,
    port: u16,
    method: &str,
    path: &str,
    body: &str,
    read_ms: u64,
) -> Result<serde_json::Value, AppError> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let addr = (ip, port)
        .to_socket_addrs()
        .map_err(|e| AppError(format!("解析地址 {ip}:{port} 失败: {e}")))?
        .next()
        .ok_or_else(|| AppError(format!("无可用地址: {ip}:{port}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(1500))
        .map_err(|e| AppError(format!("连接 {ip}:{port} 失败: {e}")))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(read_ms)))
        .map_err(AppError::from_display)?;
    stream
        .set_write_timeout(Some(Duration::from_millis(5000)))
        .map_err(AppError::from_display)?;
    let self_device_id = crate::identity::get_device_id_no_ctx();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nX-Device-Id: {self_device_id}\r\nX-Protocol-Version: 3.0\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).map_err(AppError::from_display)?;
    let mut resp_buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut tmp = [0u8; 16 * 1024];
    loop {
        let n = stream.read(&mut tmp).map_err(AppError::from_display)?;
        if n == 0 {
            break;
        }
        resp_buf.extend_from_slice(&tmp[..n]);
        if resp_buf.len() > 64 * 1024 * 1024 {
            return Err(AppError("HTTP 响应超过 64MB 上限".to_string()));
        }
    }
    let text = String::from_utf8_lossy(&resp_buf);
    let json_part = text.splitn(2, "\r\n\r\n").nth(1)
        .ok_or_else(|| AppError("HTTP 响应缺少 body 分隔符".to_string()))?;
    // body 与 JSON 分隔之间可能有 HTTP 头尾部空白；trim 后解析。空 body 视为缺失。
    if json_part.trim().is_empty() {
        return Err(AppError("HTTP 响应 body 为空".to_string()));
    }
    serde_json::from_str(json_part).map_err(|e| AppError(format!("解析响应失败: {e}")))
}

fn http_json_request_inner(
    ip: &str,
    port: u16,
    method: &str,
    path: &str,
    body: &str,
) -> Result<serde_json::Value, AppError> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    // 关键：connect 必须设置超时！默认 TcpStream::connect 对不可达 IP 会触发 TCP
    // SYN 重试，可挂起 10~20 秒（表现为应用无响应且无日志）。
    let addr = (ip, port)
        .to_socket_addrs()
        .map_err(|e| AppError(format!("解析地址 {ip}:{port} 失败: {e}")))?
        .next()
        .ok_or_else(|| AppError(format!("无可用地址: {ip}:{port}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(1500))
        .map_err(|e| AppError(format!("连接 {ip}:{port} 失败: {e}")))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(3000)))
        .map_err(AppError::from_display)?;
    stream
        .set_write_timeout(Some(Duration::from_millis(3000)))
        .map_err(AppError::from_display)?;
    // 身份注入：配对服务敏感端点（/manifest /chunk-status /move-to-delete /sync-dir
    // 等）已启用 request_trusted 门禁，出站请求必须携带本机 deviceId 供对端查信任表，
    // 否则会被自己的门禁 403。多余的头对 /info 等开放端点无害。
    let self_device_id = crate::identity::get_device_id_no_ctx();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nX-Device-Id: {self_device_id}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).map_err(AppError::from_display)?;
    // 64MB 上限 + 预留容量：read_to_end 对异常对端无内存保护（正常清单响应为数 KB~数 MB）
    let mut resp_buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    {
        let mut tmp = [0u8; 16 * 1024];
        loop {
            let n = stream.read(&mut tmp).map_err(AppError::from_display)?;
            if n == 0 {
                break;
            }
            resp_buf.extend_from_slice(&tmp[..n]);
            if resp_buf.len() > 64 * 1024 * 1024 {
                return Err(AppError("HTTP 响应超过 64MB 上限".to_string()));
            }
        }
    }
    let text = String::from_utf8_lossy(&resp_buf);
    let json_part = text.splitn(2, "\r\n\r\n").nth(1)
        .ok_or_else(|| AppError("HTTP 响应缺少 body 分隔符".to_string()))?;
    if json_part.trim().is_empty() {
        return Err(AppError("HTTP 响应 body 为空".to_string()));
    }
    serde_json::from_str(json_part)
        .map_err(|e| AppError(format!("解析响应失败: {e}")))
}

// ────────────────────────────────────────────────────────────────
// v3 控制面客户端（方案.txt §三）：probe / handshake/challenge / handshake/verify
// ────────────────────────────────────────────────────────────────
// P2 硬升级：v2 /info 与 /verify（配对/问候/探测）已删除，探测/配对全部走 v3。

/// GET /api/v3/probe：发现对端 v3 能力（staticPub/serverNonce，路径A 配对材料）
pub fn v3_probe(ip: String, port: u16) -> Result<serde_json::Value, AppError> {
    http_json_request(&ip, port + 1, "GET", "/api/v3/probe", "")
}

/// POST /api/v3/handshake/challenge：重连（路径B）取 JWT + serverEphPub
pub fn v3_handshake_challenge(
    ip: String,
    port: u16,
    device_id: String,
) -> Result<serde_json::Value, AppError> {
    let body = serde_json::json!({ "deviceId": device_id }).to_string();
    http_json_request(&ip, port + 1, "POST", "/api/v3/handshake/challenge", &body)
}

/// POST /api/v3/handshake/verify：首次配对（路径A）/ 重连（路径B）。
/// 路径A 服务端弹窗确认最长 45s → 长读超时 60s（P0 修复）。
pub fn v3_handshake_verify(
    ip: String,
    port: u16,
    body: serde_json::Value,
) -> Result<serde_json::Value, AppError> {
    v3_http_long(&ip, port + 1, "POST", "/api/v3/handshake/verify", &body.to_string(), 60_000)
}

// —— v3 客户端小工具（与 crypto.rs / pairing/v3.rs 严格对齐） ——

fn v3_nonce_hex() -> String {
    let b: [u8; 32] = rand::random();
    hex::encode(b)
}

fn v3_b64url_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn v3_b64url_decode(s: &str) -> Result<Vec<u8>, AppError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| AppError(format!("base64url 解码失败: {e}")))
}

fn v3_hex_decode(s: &str) -> Result<Vec<u8>, AppError> {
    hex::decode(s).map_err(|e| AppError(format!("hex 解码失败: {e}")))
}

fn v3_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::sign(&k, data).as_ref().to_vec()
}

/// v3 首次配对（路径A，完整客户端流程）：probe → 生成临时密钥 → ECDH →
/// 派生 pairing_secret → HMAC → verify。返回 (响应, pairing_secret)——secret 供命令层持久化（路径B重连）。
/// 连接码仅在客户端本地参与派生（salt=H(code)），绝不上线（方案.txt §3.1 隐式验证）。
/// v5：verify 请求携带本机 ECDSA 签名公钥；approved 响应验签对端公钥（信任锚，防 MITM/身份伪造）。
pub fn v3_pair(app: AppHandle, ip: String, port: u16, code: String, name: String) -> Result<(serde_json::Value, Vec<u8>), AppError> {
    // 1. probe：取对端 staticPub + serverNonce
    let info = v3_probe(ip.clone(), port)?;
    let static_pub = info.get("staticPub").and_then(|v| v.as_str()).unwrap_or("");
    let server_nonce = info.get("serverNonce").and_then(|v| v.as_str()).unwrap_or("");
    if static_pub.is_empty() || server_nonce.is_empty() {
        return Err(AppError("probe 响应缺少 staticPub/serverNonce（对端可能未升级 v3）".to_string()));
    }
    // 2. 客户端临时 P-256 密钥对
    let (eph_priv, eph_pub) = crate::crypto::ecdh_generate_keypair().map_err(AppError::from_display)?;
    // 3. shared = P-256(client_eph_priv, server_static_pub)
    let shared = crate::crypto::ecdh_derive_shared_secret(&eph_priv, static_pub)
        .map_err(AppError::from_display)?;
    // 4. pairing_secret = HKDF(shared, salt=H(code), info=...公钥+双nonce)
    let client_nonce = v3_nonce_hex();
    let secret = crate::crypto::derive_pairing_secret_v3(
        &shared,
        &code,
        &v3_b64url_decode(&eph_pub)?,
        &v3_b64url_decode(static_pub)?,
        &v3_hex_decode(&server_nonce)?,
        &v3_hex_decode(&client_nonce)?,
    )
    .map_err(AppError::from_display)?;
    // 5. hmac = HMAC(pairing_secret, serverNonce || clientNonce)
    let mut sign_data = v3_hex_decode(&server_nonce)?;
    sign_data.extend_from_slice(&v3_hex_decode(&client_nonce)?);
    let hmac = v3_hmac_sha256(&secret, &sign_data);
    // 6. verify（携带本机 ECDSA 签名公钥，供对端存储信任锚）
    let (_sig_priv, my_sig_pub) = crate::transfer::get_or_create_sig_key(&app);
    let body = serde_json::json!({
        "deviceId": crate::identity::get_device_id_no_ctx(),
        "name": name,
        "clientEphPub": eph_pub,
        "clientPublicKey": my_sig_pub,
        "clientNonce": client_nonce,
        "serverNonce": server_nonce,
        "hmac": v3_b64url_encode(&hmac),
    });
    let resp = v3_handshake_verify(ip, port, body)?;
    // 7. v5 信任锚验签：验证对端确实持有与 publicKey 对应的私钥（防 MITM/身份伪造）
    let peer_pub = resp.get("publicKey").and_then(|k| k.as_str()).unwrap_or("");
    let peer_sig = resp.get("signature").and_then(|s| s.as_str()).unwrap_or("");
    let resp_device_id = resp.get("deviceId").and_then(|d| d.as_str()).unwrap_or("");
    if peer_pub.is_empty() || peer_sig.is_empty() {
        return Err(AppError("approved 响应缺少 publicKey/signature（对端未升级 v5 签名信任锚）".to_string()));
    }
    let verify_msg = {
        let mut m = b"localsend-v3/pair".to_vec();
        m.extend_from_slice(resp_device_id.as_bytes());
        m.extend_from_slice(crate::identity::get_device_id_no_ctx().as_bytes());
        m.extend_from_slice(client_nonce.as_bytes());
        m.extend_from_slice(server_nonce.as_bytes());
        m
    };
    if !crate::crypto::sig_verify(peer_pub, &verify_msg, peer_sig) {
        return Err(AppError("对端签名验证失败，疑似中间人攻击".to_string()));
    }
    Ok((resp, secret.to_vec()))
}

// ────────────────────────────────────────────────────────────────
// P6 数据面接线基础：按目标 IP 解析 v3 pairing_secret → 派生 transfer_key
// ────────────────────────────────────────────────────────────────

/// P6：按目标 IP 解析 v3 pairing_secret（paired 表 deviceId→ips 遍历匹配 → secrets 取密钥）。
/// 无 v3 配对记录返回 None（调用方回退 code 派生密钥，兼容旧路径）。
/// 3.3：支持多 IP 匹配（DHCP 环境下设备 IP 变化时仍能正确重连）。
fn pairing_secret_for_ip(app: &AppHandle, target_ip: &str) -> Option<Vec<u8>> {
    let st = app.state::<PairingState>();
    let device_id = {
        let paired = st.paired.lock().ok()?;
        paired
            .iter()
            .find(|(_, v)| {
                // 优先精确匹配单 ip 字段
                if v.get("ip").and_then(|i| i.as_str()) == Some(target_ip) {
                    return true;
                }
                // 3.3：遍历 ips 数组匹配（DHCP 场景）
                if let Some(ips) = v.get("ips").and_then(|arr| arr.as_array()) {
                    for ip_val in ips {
                        if ip_val.as_str() == Some(target_ip) {
                            return true;
                        }
                    }
                }
                false
            })
            .map(|(id, _)| id.clone())?
    };
    let secrets = st.secrets.try_read().ok()?;
    secrets.get(&device_id).cloned()
}

/// P6：为目标传输派生 v3 transfer_key（pairing_secret + file_id）。
/// 仅在有 v3 配对密钥时返回 Some；否则 None → 调用方保持 code 派生密钥（向后兼容）。
pub fn v3_transfer_key_for_target(app: &AppHandle, target_ip: &str, file_id: &[u8]) -> Option<[u8; 32]> {
    let secret = pairing_secret_for_ip(app, target_ip)?;
    crate::crypto::derive_transfer_key_v3(&secret, file_id).ok()
}

/// P6：逐文件加密密钥选择（方案.txt §6.3 每文件独立 transfer_key）。
/// - 目标已 v3 配对 → HKDF(pairing_secret, salt=file_id) 派生 per-file transfer_key
/// - 否则 → fallback（现有 enc_key：连接码派生 / ECDH 协商 session_key，兼容旧路径）
pub fn per_file_enc_key(
    app: &AppHandle,
    target_ip: &str,
    file_id: &str,
    fallback: Option<[u8; 32]>,
) -> Option<[u8; 32]> {
    if let Some(k) = v3_transfer_key_for_target(app, target_ip, file_id.as_bytes()) {
        Some(k)
    } else {
        fallback
    }
}

// ────────────────────────────────────────────────────────────────
// v4 控制面客户端（V4-ARCHITECTURE §4.2 路径 A：HMAC 认证）
// ────────────────────────────────────────────────────────────────
// 与 v3 的 ECDH 密钥派生完全不同：v4 用连接码 + 双 nonce 派生出 HMAC 密钥，
// transcript 用长度前缀帧防歧义。直连对端 receive port（53317），不用 port+1。

const DOMAIN_PATH_A_KEY: &[u8] = b"lanbackup/v4/handshake/path-a/key";
const DOMAIN_PATH_A: &[u8] = b"lanbackup/v4/handshake/path-a";

fn v4_frame(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let total = 2 + domain.len() + parts.iter().map(|p| 2 + p.len()).sum::<usize>();
    let mut out = Vec::with_capacity(total);
    for part in std::iter::once(domain).chain(parts.iter().copied()) {
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn v4_path_a_key(connection_code: &str, client_nonce: &[u8], server_nonce: &[u8]) -> [u8; 32] {
    let mut salt = Vec::with_capacity(
        DOMAIN_PATH_A_KEY.len() + client_nonce.len() + server_nonce.len(),
    );
    salt.extend_from_slice(DOMAIN_PATH_A_KEY);
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &salt);
    let tag = ring::hmac::sign(&k, connection_code.as_bytes());
    let mut result = [0u8; 32];
    result.copy_from_slice(tag.as_ref());
    result
}

fn v4_path_a_transcript(
    device_id: &str,
    client_eph_pub: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
    server_static_pub: &[u8],
) -> Vec<u8> {
    v4_frame(DOMAIN_PATH_A, &[
        device_id.as_bytes(),
        client_eph_pub,
        client_nonce,
        server_nonce,
        server_static_pub,
    ])
}

fn v4_nonce_hex() -> String {
    let b: [u8; 32] = rand::random();
    hex::encode(b)
}

fn v4_request_id() -> String {
    let b: [u8; 16] = rand::random();
    hex::encode(b)
}

/// v4 HTTP 辅助（直接复用 v3_http_long 的实现，不同超时参数）
fn v4_http_long(
    ip: &str,
    port: u16,
    method: &str,
    path: &str,
    body: &str,
    read_ms: u64,
) -> Result<serde_json::Value, AppError> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let addr = (ip, port)
        .to_socket_addrs()
        .map_err(|e| AppError(format!("解析地址 {ip}:{port} 失败: {e}")))?
        .next()
        .ok_or_else(|| AppError(format!("无可用地址: {ip}:{port}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(1500))
        .map_err(|e| AppError(format!("连接 {ip}:{port} 失败: {e}")))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(read_ms)))
        .map_err(AppError::from_display)?;
    stream
        .set_write_timeout(Some(Duration::from_millis(5000)))
        .map_err(AppError::from_display)?;
    let self_device_id = crate::identity::get_device_id_no_ctx();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nX-Device-Id: {self_device_id}\r\nX-Protocol-Version: 4.0\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).map_err(AppError::from_display)?;
    let mut resp_buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut tmp = [0u8; 16 * 1024];
    loop {
        let n = stream.read(&mut tmp).map_err(AppError::from_display)?;
        if n == 0 {
            break;
        }
        resp_buf.extend_from_slice(&tmp[..n]);
        if resp_buf.len() > 64 * 1024 * 1024 {
            return Err(AppError("HTTP 响应超过 64MB 上限".to_string()));
        }
    }
    let text = String::from_utf8_lossy(&resp_buf);
    let json_part = text.splitn(2, "\r\n\r\n").nth(1)
        .ok_or_else(|| AppError("HTTP 响应缺少 body 分隔符".to_string()))?;
    if json_part.trim().is_empty() {
        return Err(AppError("HTTP 响应 body 为空".to_string()));
    }
    serde_json::from_str(json_part).map_err(|e| AppError(format!("解析响应失败: {e}")))
}

/// GET /api/v4/probe（直连对端 receive port，不走 port+1）
pub fn v4_probe(ip: String, port: u16) -> Result<serde_json::Value, AppError> {
    v4_http_long(&ip, port, "GET", "/api/v4/probe", "", 3000)
}

/// v4 路径 A 配对（完整流程）：probe → 生成临时 ECDH 密钥 → HMAC 认证 → verify
///
/// 密钥派生：HMAC-SHA256(salt=DOMAIN_PATH_A_KEY || clientNonce || serverNonce, msg=connection_code)
/// Transcript：frame(DOMAIN_PATH_A, [deviceId, clientEphPub, clientNonce, serverNonce, serverStaticPub])
/// Tag：HMAC-SHA256(key, transcript) → hex
///
/// 直连对端 receive port（port 参数），60s 长读超时（服务端弹窗确认最长 45s）。
pub fn v4_pair(
    _app: AppHandle,
    ip: String,
    port: u16,
    code: String,
    name: String,
) -> Result<serde_json::Value, AppError> {
    // 1. probe：取对端 staticPub（base64）+ serverNonce（hex）+ deviceId
    let info = v4_probe(ip.clone(), port)?;
    let static_pub = info
        .get("staticPub")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let server_nonce = info
        .get("serverNonce")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let device_id = info
        .get("deviceId")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if static_pub.is_empty() || server_nonce.is_empty() || device_id.is_empty() {
        return Err(AppError(
            "probe 响应缺少 staticPub/serverNonce/deviceId（对端可能未升级 v4）".to_string(),
        ));
    }

    // 2. 客户端临时 P-256 ECDH 密钥对（用于 transcript 中的 clientEphPub）
    let (eph_priv, eph_pub) = crate::crypto::ecdh_generate_keypair()
        .map_err(AppError::from_display)?;
    let eph_pub_bytes = v3_b64url_decode(&eph_pub)?;
    let static_pub_bytes = v3_b64url_decode(static_pub)?;
    let client_nonce_bytes = v4_nonce_hex();
    let client_nonce_bytes_raw = hex::decode(&client_nonce_bytes)
        .map_err(|e| AppError(format!("clientNonce hex 解码失败: {e}")))?;
    let server_nonce_bytes_raw = hex::decode(server_nonce)
        .map_err(|e| AppError(format!("serverNonce hex 解码失败: {e}")))?;

    // 3. path_a_key = HMAC-SHA256(salt, connection_code)
    let key = v4_path_a_key(&code, &client_nonce_bytes_raw, &server_nonce_bytes_raw);

    // 4. path_a_transcript = frame(domain, [deviceId, clientEphPub, clientNonce, serverNonce, serverStaticPub])
    let transcript = v4_path_a_transcript(
        device_id,
        &eph_pub_bytes,
        &client_nonce_bytes_raw,
        &server_nonce_bytes_raw,
        &static_pub_bytes,
    );

    // 5. tag = HMAC-SHA256(key, transcript) → hex
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
    let tag = ring::hmac::sign(&k, &transcript);
    let tag_hex = hex::encode(tag.as_ref());

    // 6. verify：POST /api/v4/handshake/verify（60s 长读超时，等对端弹窗确认）
    let request_id = v4_request_id();
    let body = serde_json::json!({
        "deviceId": crate::identity::get_device_id_no_ctx(),
        "clientEphPub": eph_pub,
        "clientNonce": client_nonce_bytes,
        "serverNonce": server_nonce,
        "hmac": tag_hex,
        "requestId": request_id,
    });
    let resp = v4_http_long(&ip, port, "POST", "/api/v4/handshake/verify", &body.to_string(), 60_000)?;

    // 7. 解析 VerifyResponse 状态
    let status = resp
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    if status != "active" {
        return Err(AppError(format!("配对失败，状态: {status}")));
    }
    Ok(resp)
}
