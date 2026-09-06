//! v4 控制面客户端（直连对端 receive port，不走 port+1）
//!
//! 密钥派生：HMAC-SHA256(salt=DOMAIN_PATH_A_KEY || clientNonce || serverNonce, msg=connection_code)
//! Transcript：frame(DOMAIN_PATH_A, [deviceId, clientEphPub, clientNonce, serverNonce, serverStaticPub])
//! Tag：HMAC-SHA256(key, transcript) → hex

use tauri::{AppHandle, Manager};

use crate::db::AppError;

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

fn v3_b64url_decode(s: &str) -> Result<Vec<u8>, AppError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| AppError(format!("base64url 解码失败: {e}")))
}

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
/// 直连对端 receive port（port 参数），60s 长读超时（服务端弹窗确认最长 45s）。
pub fn v4_pair(
    _app: AppHandle,
    ip: String,
    port: u16,
    code: String,
    _name: String,
) -> Result<serde_json::Value, AppError> {
    let info = v4_probe(ip.clone(), port)?;
    let static_pub = info.get("staticPub").and_then(|v| v.as_str()).unwrap_or("");
    let server_nonce = info.get("serverNonce").and_then(|v| v.as_str()).unwrap_or("");
    let device_id = info.get("deviceId").and_then(|v| v.as_str()).unwrap_or("");
    if static_pub.is_empty() || server_nonce.is_empty() || device_id.is_empty() {
        return Err(AppError(
            "probe 响应缺少 staticPub/serverNonce/deviceId（对端可能未升级 v4）".to_string(),
        ));
    }

    let (_eph_priv, eph_pub) = crate::crypto::ecdh_generate_keypair()
        .map_err(AppError::from_display)?;
    let eph_pub_bytes = v3_b64url_decode(&eph_pub)?;
    let static_pub_bytes = v3_b64url_decode(static_pub)?;
    let client_nonce_bytes = v4_nonce_hex();
    let client_nonce_bytes_raw = hex::decode(&client_nonce_bytes)
        .map_err(|e| AppError(format!("clientNonce hex 解码失败: {e}")))?;
    let server_nonce_bytes_raw = hex::decode(server_nonce)
        .map_err(|e| AppError(format!("serverNonce hex 解码失败: {e}")))?;

    let key = v4_path_a_key(&code, &client_nonce_bytes_raw, &server_nonce_bytes_raw);
    let transcript = v4_path_a_transcript(
        device_id,
        &eph_pub_bytes,
        &client_nonce_bytes_raw,
        &server_nonce_bytes_raw,
        &static_pub_bytes,
    );

    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
    let tag = ring::hmac::sign(&k, &transcript);
    let tag_hex = hex::encode(tag.as_ref());

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

    let status = resp.get("status").and_then(|v| v.as_str()).unwrap_or("none");
    if status != "active" {
        return Err(AppError(format!("配对失败，状态: {status}")));
    }
    Ok(resp)
}

// ────────────────────────────────────────────────────────────────
// P6 数据面接线：按目标 IP 解析 pairing_secret → 派生 per-file transfer_key
// ────────────────────────────────────────────────────────────────

/// P6：按目标 IP 解析 pairing_secret（paired 表 deviceId→ips 遍历匹配 → secrets 取密钥）。
/// 无配对记录返回 None（调用方回退 code 派生密钥，兼容旧路径）。
fn pairing_secret_for_ip(app: &AppHandle, target_ip: &str) -> Option<Vec<u8>> {
    let st = app.state::<crate::transfer::PairingState>();
    let device_id = {
        let paired = st.paired.lock().ok()?;
        paired
            .iter()
            .find(|(_, v)| {
                if v.get("ip").and_then(|i| i.as_str()) == Some(target_ip) {
                    return true;
                }
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

/// P6：为目标传输派生 transfer_key（pairing_secret + file_id）。
/// 仅在有配对密钥时返回 Some；否则 None → 调用方保持 code 派生密钥（向后兼容）。
pub fn transfer_key_for_target(app: &AppHandle, target_ip: &str, file_id: &[u8]) -> Option<[u8; 32]> {
    let secret = pairing_secret_for_ip(app, target_ip)?;
    crate::crypto::derive_transfer_key_v3(&secret, file_id).ok()
}

/// 逐文件加密密钥选择（每文件独立 transfer_key）。
/// - 目标已配对 → HKDF(pairing_secret, salt=file_id) 派生 per-file transfer_key
/// - 否则 → fallback（现有 enc_key：连接码派生 / ECDH 协商 session_key，兼容旧路径）
pub fn per_file_enc_key(
    app: &AppHandle,
    target_ip: &str,
    file_id: &str,
    fallback: Option<[u8; 32]>,
) -> Option<[u8; 32]> {
    if let Some(k) = transfer_key_for_target(app, target_ip, file_id.as_bytes()) {
        Some(k)
    } else {
        fallback
    }
}
