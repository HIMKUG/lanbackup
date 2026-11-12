//! v4 控制面客户端（直连对端 receive port，不走 port+1）
//!
//! 密钥派生：HMAC-SHA256(salt=DOMAIN_PATH_A_KEY || clientNonce || serverNonce, msg=connection_code)
//! Transcript：frame(DOMAIN_PATH_A, [deviceId, clientEphPub, clientNonce, serverNonce, serverStaticPub])
//! Tag：HMAC-SHA256(key, transcript) → hex

use super::*;
use tauri::AppHandle;

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
    // connect 1500ms, write 5000ms, 带 X-Protocol-Version: 4.0
    http_json_request_internal(
        ip,
        port,
        method,
        path,
        body,
        &HttpRequestOptions { read_ms, write_ms: 5000, protocol_version: Some("4.0"), ..Default::default() },
    )
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
    // WB-0021：连接码是 KDF/HMAC 的线格式输入，入口必须与 core 用同一套
    // 严格规范化（只保留 [A-Z0-9] 并大写）。否则用户输入 `1234-5678`
    // 与接收端保存的 `12345678` 派生出的密钥永远不相等。
    let code = lanbackup_core::identity::normalize_connection_code(&code);
    if code.is_empty() {
        return Err(AppError("连接码不能为空".to_string()));
    }
    let info = v4_probe(ip.clone(), port)?;
    let static_pub = info.get("staticPub").and_then(|v| v.as_str()).unwrap_or("");
    let server_nonce = info.get("serverNonce").and_then(|v| v.as_str()).unwrap_or("");
    let device_id = info.get("deviceId").and_then(|v| v.as_str()).unwrap_or("");
    if static_pub.is_empty() || server_nonce.is_empty() || device_id.is_empty() {
        return Err(AppError(
            "probe 响应缺少 staticPub/serverNonce/deviceId（对端可能未升级 v4）".to_string(),
        ));
    }
    if device_id == crate::identity::get_device_id_no_ctx() {
        return Err(AppError("不能与本机自己配对".to_string()));
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
    // 服务端必须返回它自己的身份；返回我方 ID 说明对端把 deviceId 回显了，
    // 桌面若照此落库就会"把自己存成对端"。
    let resp_device = resp.get("deviceId").and_then(|v| v.as_str()).unwrap_or("");
    if resp_device != device_id {
        return Err(AppError(
            "verify 返回的 deviceId 与 probe 不一致：拒绝把未知身份存为对端".to_string(),
        ));
    }
    Ok(resp)
}
