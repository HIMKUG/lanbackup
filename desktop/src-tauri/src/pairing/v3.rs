#![allow(dead_code)]
//! pairing/v3.rs — v3 配对协议服务端实现（已废弃，仅保留用于 store.rs 辅助调用）
//!
//! v4 配对走 pairing/v4.rs（代理到 core server）；本文件保留部分 store.rs 的 v3 HTTP 调用
//!   GET  /api/v3/probe               → 发现 + staticPub + serverNonce（路径A 配对材料）
//!   POST /api/v3/handshake/challenge → 重连（路径B）：签发 challenge_token(JWT) + serverEphPub
//!   POST /api/v3/handshake/verify    → 首次配对（路径A）/ 重连（路径B）：验 HMAC → approved
//!
//! 设计要点：
//! - 手写轻量中间件链（版本检查/限流/日志），零框架依赖。
//! - 防重放靠构造（幂等）：每次握手 server_nonce/client_nonce 都是新的，派生的
//!   pairing_secret（路径A）或验证所用的 secret（路径B）与当前会话绑定，重放自然失败。
//! - verify 响应**绝不返回任何密钥**，只返回 { status:"approved", deviceId, capabilities }。
//! - 连接码验证是隐式的（路径A）：pairing_secret 的 salt=H(code)，双方用同一 code 才能算出
//!   同一 secret，客户端码错 → HMAC 不匹配 → 拒绝。连接码绝不上线。
//!
//! 注：pairing_secret 当前存内存（PairingState.secrets）；SQLite 持久化接线属 P5。

use crate::db::AppError;
use crate::identity;
use crate::transfer::PairingState;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use serde_json::json;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager};
use tokio::time::{sleep, Duration};

// ────────────────────────────────────────────────────────────────
// 工具函数
// ────────────────────────────────────────────────────────────────

fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| format!("base64url 解码失败: {e}"))
}

fn gen_nonce_hex() -> String {
    let b: [u8; 32] = rand::random();
    hex::encode(b)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&k, data).as_ref().to_vec()
}

fn err_json(code: &str, msg: &str, request_id: &str) -> (i32, String) {
    (
        400,
        json!({ "error": { "code": code, "message": msg, "requestId": request_id } }).to_string(),
    )
}

fn ok_json(v: serde_json::Value) -> (i32, String) {
    (200, v.to_string())
}

// ────────────────────────────────────────────────────────────────
// 设备静态密钥（P-256，SEC1 非压缩 base64url）
// ────────────────────────────────────────────────────────────────

/// 获取（或生成）设备静态密钥对 (priv_b64, pub_b64)。生成后缓存于 PairingState 并持久化到 SQLite。
/// 启动顺序：内存 cache → SQLite → 新生成并保存。
fn get_or_create_static_key(app: &AppHandle) -> (String, String) {
    // 1. 内存缓存优先
    if let Some(st) = app.try_state::<PairingState>() {
        if let Ok(k) = st.static_key.lock() {
            if let Some((p, u)) = k.as_ref() {
                return (p.clone(), u.clone());
            }
        }
    }
    // 2. SQLite 持久化恢复（local_identity 单行表）
    if let Ok(Some((priv_b64, pub_b64))) = crate::db::load_static_key(app) {
        let generated = (priv_b64, pub_b64);
        if let Some(st) = app.try_state::<PairingState>() {
            if let Ok(mut k) = st.static_key.lock() {
                *k = Some(generated.clone());
            }
        }
        return generated;
    }
    // 3. 无记录 → 生成并持久化
    let generated = crate::crypto::ecdh_generate_keypair().unwrap_or_default();
    // 保存到 SQLite（首次建表后立即持久化）
    let _ = crate::db::save_static_key(app, &generated.0, &generated.1);
    if let Some(st) = app.try_state::<PairingState>() {
        if let Ok(mut k) = st.static_key.lock() {
            *k = Some((generated.0.clone(), generated.1.clone()));
        }
    }
    generated
}

/// 构造「配对确认」签名内容（新架构 §二 信任锚）：
/// "localsend-v3/pair" || respDeviceId || clientDeviceId || clientNonce || serverNonce
fn sig_pair_msg(resp_device_id: &str, client_device_id: &str, client_nonce: &str, server_nonce: &str) -> Vec<u8> {
    let mut m = b"localsend-v3/pair".to_vec();
    m.extend_from_slice(resp_device_id.as_bytes());
    m.extend_from_slice(client_device_id.as_bytes());
    m.extend_from_slice(client_nonce.as_bytes());
    m.extend_from_slice(server_nonce.as_bytes());
    m
}

/// 读取 deviceId 的长期 pairing_secret（内存态；P5 接入 SQLite）
fn get_pairing_secret(app: &AppHandle, device_id: &str) -> Option<Vec<u8>> {
    let st = app.state::<PairingState>();
    st.secrets
        .try_read()
        .map(|m| m.get(device_id).cloned())
        .unwrap_or(None)
}

/// 写入 deviceId 的长期 pairing_secret（approved 同事务落库属 P5，此处先入内存）
fn put_pairing_secret(app: &AppHandle, device_id: &str, secret: &[u8]) {
    if let Ok(mut m) = app.state::<PairingState>().secrets.try_write() {
        m.insert(device_id.to_string(), secret.to_vec());
    }
}

// ────────────────────────────────────────────────────────────────
// 中间件链（手写轻量版）
// ────────────────────────────────────────────────────────────────

/// 版本检查：3.0 / 3.1 接受（3.1 = 新增 ECDSA 签名信任锚字段，向后兼容）
fn check_protocol_version(headers: &std::collections::HashMap<String, String>) -> bool {
    let v = headers
        .get("x-protocol-version")
        .map(|s| s.as_str())
        .unwrap_or("3.0");
    v == "3.0" || v == "3.1"
}

// ────────────────────────────────────────────────────────────────
// 端点处理器
// ────────────────────────────────────────────────────────────────

/// GET /api/v3/probe：无认证，返回设备信息 + 静态公钥 + serverNonce（路径A 配对材料）。
/// deviceId 门控：
/// - 仅「开始发现」期间返回真实 deviceId → 未配对陌生设备扫描时看不到本机（防成为信标）。
/// - 已配对设备的重连不依赖 probe 明文身份：改由常驻加密存在广播（bcpd，仅已配对设备
///   可解析 deviceId/HMAC）提供在线与身份来源，故此处不再对来源 IP 做白名单放行。
/// - 防御性总开关隐藏时对一切来源返回空身份（最高优先级，见下方）。
pub fn handle_probe(app: &AppHandle, _client_ip: &str) -> (i32, String) {
    // 防御性总开关：隐藏时不泄露任何身份信息（未配对/已配对设备均不可发现本机）
    if app
        .state::<crate::transfer::TransferState>()
        .defensive_hidden
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return ok_json(json!({
            "deviceId": "", "alias": "", "deviceType": "desktop", "port": 53317u16,
            "protocolVersion": "3.1", "staticPub": "", "publicKey": "", "serverNonce": "",
            "capabilities": {}
        }));
    }
    let name = identity::get_device_name(app);
    let id = identity::get_device_id(app);
    let discoverable = app
        .state::<crate::transfer::TransferState>()
        .discoverable
        .load(std::sync::atomic::Ordering::Relaxed);
    let reveal_id = discoverable;
    let (_priv, pub_b64) = get_or_create_static_key(app);
    let (_sig_priv, sig_pub) = crate::transfer::get_or_create_sig_key(app);
    ok_json(json!({
        "deviceId": if reveal_id { id } else { String::new() },
        "alias": name,
        "deviceType": "desktop",
        "port": 53317u16,
        "protocolVersion": "3.1",
        "staticPub": pub_b64,
        "publicKey": sig_pub,
        "serverNonce": gen_nonce_hex(),
        "capabilities": {
            "maxChunkSize": 262144,
            "supportedEncryption": ["aes-256-gcm"],
            "supportsResume": true,
        },
    }))
}

/// POST /api/v3/handshake/challenge（重连路径B）：签发 JWT + 服务端临时公钥
pub fn handle_challenge(app: &AppHandle, body: &str) -> (i32, String) {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return err_json("INVALID_REQUEST", "请求体不是合法 JSON", ""),
    };
    let device_id = v.get("deviceId").and_then(|d| d.as_str()).unwrap_or("");
    if device_id.is_empty() {
        return err_json("INVALID_REQUEST", "缺少 deviceId", "");
    }
    let secret = match get_pairing_secret(app, device_id) {
        Some(s) => s,
        None => {
            return err_json(
                "UNKNOWN_DEVICE",
                "未找到该设备的配对密钥，请先完成首次配对",
                "",
            )
        }
    };

    let (_, static_pub) = get_or_create_static_key(app);
    let server_nonce = gen_nonce_hex();
    let jti = uuid::Uuid::new_v4().to_string();
    let iat = now_secs();
    let payload = json!({
        "jti": jti,
        "deviceId": identity::get_device_id(app),
        "serverNonce": server_nonce,
        "staticPub": static_pub,
        "iat": iat,
        "exp": iat + 300, // 仅卫生约束（日志/时钟漂移），绝不用于拒绝（方案.txt §3.3）
    });
    let header_b64 = b64url(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    let payload_b64 = b64url(payload.to_string().as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = hmac_sha256(&secret, signing_input.as_bytes());
    let token = format!("{signing_input}.{}", b64url(&sig));

    // 本次握手临时公钥（服务端丢弃私钥；session_shared 由客户端派生，L3 transfer_key 在数据面协商）
    let (_eph_priv, eph_pub) = crate::crypto::ecdh_generate_keypair().unwrap_or_default();
    ok_json(json!({ "challengeToken": token, "serverEphPub": eph_pub }))
}

/// 校验 JWT：验签（用长期 pairing_secret）+ 提取 (serverNonce, jti)。
/// 同时检查 jti 防重放（同一 JWT 5 分钟内不可重复使用）。
/// 返回 jti 供调用方安排延迟清理——清理键必须与插入键一致（此前用 payload 段原文
/// 当 key，remove 永远删不到真实 jti，导致 used_jtis 无限增长）。
fn verify_jwt(token: &str, secret: &[u8], used_jtis: &mut HashSet<String>) -> Result<(String, String), String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("JWT 格式错误".to_string());
    }
    // payload 只解析一次：jti 提取与 serverNonce 提取共用
    let payload_bytes = b64url_decode(parts[1])?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("JWT payload 解析失败: {e}"))?;
    let jti = payload
        .get("jti")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // 防重放：检查 jti 是否已使用
    if !used_jtis.insert(jti.clone()) {
        return Err("JWT 已被使用（重放攻击）".to_string());
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = b64url_decode(parts[2])?;
    let expect = hmac_sha256(secret, signing_input.as_bytes());
    if sig != expect {
        used_jtis.remove(&jti); // 验签失败不占用 jti
        return Err("JWT 验签失败".to_string());
    }
    let server_nonce = payload
        .get("serverNonce")
        .and_then(|v| v.as_str())
        .map(String::from);
    match server_nonce {
        Some(sn) => Ok((sn, jti)),
        None => {
            used_jtis.remove(&jti); // 验签成功但缺关键字段 → 不占用 jti
            Err("JWT 缺少 serverNonce".to_string())
        }
    }
}

/// POST /api/v3/handshake/verify：路径A（首次配对）/ 路径B（重连）
pub fn handle_verify(app: &AppHandle, body: &str, client_ip: &str) -> (i32, String) {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return err_json("INVALID_REQUEST", "请求体不是合法 JSON", ""),
    };
    let device_id = v.get("deviceId").and_then(|d| d.as_str()).unwrap_or("");
    let client_eph_pub = v.get("clientEphPub").and_then(|d| d.as_str()).unwrap_or("");
    let client_nonce = v.get("clientNonce").and_then(|d| d.as_str()).unwrap_or("");
    let hmac_provided = v.get("hmac").and_then(|d| d.as_str()).unwrap_or("");
    let challenge_token = v.get("challengeToken").and_then(|d| d.as_str());
    if device_id.is_empty() || client_eph_pub.is_empty() || client_nonce.is_empty() || hmac_provided.is_empty() {
        return err_json("INVALID_REQUEST", "缺少必填字段", "");
    }
    let client_nonce_bytes = match hex::decode(client_nonce) {
        Ok(b) => b,
        Err(_) => return err_json("INVALID_REQUEST", "clientNonce 不是合法 hex", ""),
    };

    // —— 路径B：重连（携带 challengeToken，pairing_secret 从本地长期密钥取） ——
    if let Some(token) = challenge_token {
        let secret = match get_pairing_secret(app, device_id) {
            Some(s) => s,
            None => return err_json("UNKNOWN_DEVICE", "未找到该设备的配对密钥", ""),
        };
        let pairing_state = app.state::<PairingState>();
        let mut used_jtis = match pairing_state.used_jtis.lock() {
            Ok(h) => h,
            Err(_) => return err_json("INTERNAL_ERROR", "内部状态锁中毒", ""),
        };
        let (server_nonce, jti) = match verify_jwt(token, &secret, &mut used_jtis) {
            Ok(sn) => sn,
            Err(e) => return err_json("HMAC_MISMATCH", &e, ""),
        };
        drop(used_jtis); // 释放锁后再 spawn 异步清理
        // 异步清理：5 分钟后从 used_jtis 删除该 jti（防止内存无限增长）。
        // 键必须与 verify_jwt 插入的 jti claim 一致（不能是 token 的 payload 段原文）。
        {
            let app_clone = app.clone();
            tauri::async_runtime::spawn(async move {
                sleep(Duration::from_secs(300)).await;
                if let Ok(mut set) = app_clone.state::<PairingState>().used_jtis.lock() {
                    set.remove(&jti);
                    crate::log_debug!("jti 已过期清理: {}", crate::logger::mask(&jti));
                }
            });
        }
        let server_nonce_bytes = match hex::decode(&server_nonce) {
            Ok(b) => b,
            Err(_) => return err_json("INVALID_REQUEST", "serverNonce 非法", ""),
        };
        let mut sign_data = server_nonce_bytes;
        sign_data.extend_from_slice(&client_nonce_bytes);
        let expect = hmac_sha256(&secret, &sign_data);
        if !const_eq(&expect, &b64url_decode(hmac_provided).unwrap_or_default()) {
            crate::log_warn!("v3 verify(路径B) HMAC 不匹配 deviceId={}", crate::logger::mask(device_id));
            return err_json("HMAC_MISMATCH", "HMAC 验证失败", "");
        }
        crate::log_info!("v3 重连握手成功 deviceId={} from={}", crate::logger::mask(device_id), client_ip);
        let _ = app.emit("peer-connected", json!({ "deviceId": device_id }));
        return approved_response(app, device_id, device_id, &client_nonce, &server_nonce);
    }

    // —— 路径A：首次配对（无 challengeToken，serverNonce 由客户端回传 probe 的值） ——
    let server_nonce = v.get("serverNonce").and_then(|d| d.as_str()).unwrap_or("");
    if server_nonce.is_empty() {
        return err_json("INVALID_REQUEST", "首次配对缺少 serverNonce（须回传 probe 的值）", "");
    }
    let (server_priv, server_pub) = get_or_create_static_key(app);
    if server_priv.is_empty() {
        return err_json("INVALID_REQUEST", "静态密钥生成失败", "");
    }
    // ECDH：shared = P-256(server_static_priv, client_eph_pub)
    let shared = match crate::crypto::ecdh_derive_shared_secret(&server_priv, client_eph_pub) {
        Ok(s) => s,
        Err(e) => return err_json("INVALID_REQUEST", &format!("ECDH 失败: {e}"), ""),
    };
    let my_code = identity::get_self_code(app);
    let server_nonce_bytes = match hex::decode(&server_nonce) {
        Ok(b) => b,
        Err(_) => return err_json("INVALID_REQUEST", "serverNonce 非法", ""),
    };
    let client_pub_bytes = match b64url_decode(client_eph_pub) {
        Ok(b) => b,
        Err(_) => return err_json("INVALID_REQUEST", "clientEphPub 非法", ""),
    };
    let server_pub_bytes = match b64url_decode(&server_pub) {
        Ok(b) => b,
        Err(_) => return err_json("INVALID_REQUEST", "staticPub 非法", ""),
    };
    // 连接码隐式验证：双方用同一 code 才算出同一 pairing_secret（方案.txt §3.1）
    let pairing_secret = match crate::crypto::derive_pairing_secret_v3(
        &shared,
        &my_code,
        &client_pub_bytes,
        &server_pub_bytes,
        &server_nonce_bytes,
        &client_nonce_bytes,
    ) {
        Ok(s) => s,
        Err(e) => return err_json("INVALID_REQUEST", &e, ""),
    };
    let mut sign_data = server_nonce_bytes;
    sign_data.extend_from_slice(&client_nonce_bytes);
    let expect = hmac_sha256(&pairing_secret, &sign_data);
    if !const_eq(&expect, &b64url_decode(hmac_provided).unwrap_or_default()) {
        crate::log_warn!("v3 verify(路径A) HMAC 不匹配 deviceId={}（连接码可能错误）", crate::logger::mask(device_id));
        return err_json("INVALID_CODE", "连接码不正确或验证失败", "");
    }

    // HMAC 通过 → 该设备尚未配对（首次）→ 弹窗确认（被动方同意）→ approved + 落库
    let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("未知设备");
    // 探针：诊断"电脑端不停弹配对确认窗"——记录每次弹窗的来源与目标
    crate::log_info!(
        "配对确认弹窗发起: 来自={} deviceId={} name={}",
        client_ip,
        crate::logger::mask(device_id),
        name
    );
    if !confirm_pairing(app, device_id, name, client_ip) {
        return err_json("INVALID_CODE", "对方拒绝了配对请求", "");
    }
    // 记录配对 + 长期 pairing_secret + 对方 ECDSA 签名公钥（v5 信任锚：verify 请求携带 clientPublicKey）
    let client_public_key = v.get("clientPublicKey").and_then(|d| d.as_str()).unwrap_or("");
    {
        let st = app.state::<PairingState>();
        let mut m = st.paired.lock().unwrap_or_else(|p| p.into_inner());
        m.insert(
            device_id.to_string(),
            json!({
                "name": name,
                "ip": client_ip,
                "port": 53317u16,
                "fingerprint": "",
                "status": "ACTIVE",
                "peerPublicKey": client_public_key,
                "pairingTimestamp": now_ms(),
                "lastHeartbeat": now_ms(),
            }),
        );
    }
    put_pairing_secret(app, device_id, &pairing_secret);
    // P5b：approved 即刻落库（persist_paired 会带上刚写入的 pairing_secret），
    // 否则进程重启后 secrets 丢失 → 路径B（重连）失败
    crate::transfer::persist_paired(app);
    let _ = app.emit("paired-updated", ());
    let _ = app.emit("peer-connected", json!({ "deviceId": device_id }));
    crate::log_info!("v3 首次配对成功 deviceId={} name={} from={}", crate::logger::mask(device_id), name, client_ip);
    approved_response(app, device_id, device_id, &client_nonce, &server_nonce)
}

/// 配对确认弹窗：复用 TransferState.pending_pairing_approvals（与 v2 handle_verify_code 同模式）
fn confirm_pairing(app: &AppHandle, device_id: &str, name: &str, client_ip: &str) -> bool {
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    {
        let st = app.state::<crate::transfer::TransferState>();
        let mut m = st.pending_pairing_approvals.lock().unwrap_or_else(|p| p.into_inner());
        if m.contains_key(device_id) || m.len() >= 10 {
            return false;
        }
        m.insert(device_id.to_string(), tx);
    }
    let _ = app.emit(
        "pairing-request",
        json!({ "deviceId": device_id, "name": name, "ip": client_ip }),
    );
    let result = rx
        .recv_timeout(std::time::Duration::from_secs(45))
        .unwrap_or(false);
    if let Ok(mut m) = app.state::<crate::transfer::TransferState>().pending_pairing_approvals.lock() {
        m.remove(device_id);
    }
    result
}

/// approved 响应：带本机 ECDSA 公钥 + 本次握手签名（v5 信任锚）。
/// 客户端验签通过后才信任本机为「持私钥的实体」，并把 publicKey 存入配对记录。
fn approved_response(
    app: &AppHandle,
    _device_id: &str,
    client_device_id: &str,
    client_nonce: &str,
    server_nonce: &str,
) -> (i32, String) {
    let (sig_priv, sig_pub) = crate::transfer::get_or_create_sig_key(app);
    let msg = sig_pair_msg(&identity::get_device_id(app), client_device_id, client_nonce, server_nonce);
    let signature = crate::crypto::sig_sign(&sig_priv, &msg).unwrap_or_default();
    ok_json(json!({
        "status": "approved",
        "deviceId": identity::get_device_id(app),
        "publicKey": sig_pub,
        "signature": signature,
        "capabilities": {
            "maxChunkSize": 262144,
            "supportedEncryption": ["aes-256-gcm"],
            "supportsResume": true,
        },
    }))
}

/// 常数时间比较（避免时序侧信道）
fn const_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut x = 0u8;
    for (i, j) in a.iter().zip(b.iter()) {
        x |= i ^ j;
    }
    x == 0
}

// ────────────────────────────────────────────────────────────────
// 路由入口（由 auth.rs handle_pairing_conn 分发调用）
// ────────────────────────────────────────────────────────────────

/// 处理一条 v3 请求。返回 (status, json_body)。headers 供中间件使用。
pub fn route_v3(
    app: &AppHandle,
    method: &str,
    path: &str,
    body: &str,
    client_ip: &str,
    headers: &std::collections::HashMap<String, String>,
) -> Result<(i32, String), AppError> {
    if !check_protocol_version(headers) {
        return Ok(err_json("VERSION_UNSUPPORTED", "协议版本不受支持，请升级应用", ""));
    }
    match (method, path) {
        ("GET", "/api/v3/probe") => Ok(handle_probe(app, client_ip)),
        ("POST", "/api/v3/handshake/challenge") => Ok(handle_challenge(app, body)),
        ("POST", "/api/v3/handshake/verify") => Ok(handle_verify(app, body, client_ip)),
        // v5 新架构：在线/离线解配对 + 吊销同步（见 handle_* 实现）
        ("POST", "/api/v3/unpair-request") => Ok(handle_unpair_request(app, body)),
        ("POST", "/api/v3/sync-status") => Ok(handle_sync_status(app, body)),
        ("POST", "/api/v3/revoke-notify") => Ok(handle_revoke_notify(app, body)),
        ("POST", "/api/v3/revoke-ack") => Ok(handle_revoke_ack(app, body)),
        _ => Ok(err_json("NOT_FOUND", "not_found", "")),
    }
}

// ════════════════════════════════════════════════════════════════
// v5 新架构：在线/离线解配对 + 吊销同步（新架构 §四/§五/§六）
// ════════════════════════════════════════════════════════════════
// 全部消息用 ECDSA P-256 签名（对方公钥存于 paired 记录 peerPublicKey）。
// 吊销令牌（RevokeToken）：Ed25519→ECDSA 签名的吊销凭证，30 天有效期（§5.3）。
// REVOKE_PENDING 期间保留对方公钥（验签吊销同步），但拒绝数据面请求（见门禁）。

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 3 字段签名内容：kind ∈ {unpair-request, sync-status}
/// "localsend-v3/{kind}" || issuer || target || timestamp
fn sig_msg3(kind: &str, issuer: &str, target: &str, ts: &str) -> Vec<u8> {
    let mut m = format!("localsend-v3/{kind}").into_bytes();
    m.extend_from_slice(issuer.as_bytes());
    m.extend_from_slice(target.as_bytes());
    m.extend_from_slice(ts.as_bytes());
    m
}

/// 吊销令牌签名内容："localsend-v3/revoke" || issuer || target || issuedAt || nonce
fn sig_revoke_msg(issuer: &str, target: &str, issued_at: &str, nonce: &str) -> Vec<u8> {
    let mut m = b"localsend-v3/revoke".to_vec();
    m.extend_from_slice(issuer.as_bytes());
    m.extend_from_slice(target.as_bytes());
    m.extend_from_slice(issued_at.as_bytes());
    m.extend_from_slice(nonce.as_bytes());
    m
}

/// 吊销确认签名内容："localsend-v3/revoke-ack" || issuer || target || issuedAt || nonce
fn sig_ack_msg(issuer: &str, target: &str, issued_at: &str, nonce: &str) -> Vec<u8> {
    let mut m = b"localsend-v3/revoke-ack".to_vec();
    m.extend_from_slice(issuer.as_bytes());
    m.extend_from_slice(target.as_bytes());
    m.extend_from_slice(issued_at.as_bytes());
    m.extend_from_slice(nonce.as_bytes());
    m
}

/// 读取某个配对记录的副本（含 status/peerPublicKey/pendingRevokeToken）
fn peer_record(app: &AppHandle, device_id: &str) -> Option<serde_json::Value> {
    app.state::<PairingState>()
        .paired
        .lock()
        .ok()?
        .get(device_id)
        .cloned()
}

/// 将配对记录状态机推进到新状态并落盘；REVOKED 时清除吊销令牌（保留记录）。
/// pub(crate)：供 transfer/store.rs 客户端解配对逻辑复用。
pub(crate) fn set_peer_status(app: &AppHandle, device_id: &str, status: &str) {
    if let Ok(mut m) = app.state::<PairingState>().paired.lock() {
        if let Some(v) = m.get_mut(device_id) {
            if let Some(o) = v.as_object_mut() {
                o.insert("status".to_string(), serde_json::json!(status));
                if status == "REVOKED" {
                    o.remove("pendingRevokeToken");
                }
            }
        }
    }
    crate::transfer::persist_paired(app);
}

/// 删除某设备的对称配对密钥（secrets 内存 + 下次落盘一并清除）
/// pub(crate)：供 transfer/store.rs 客户端解配对逻辑复用。
pub(crate) fn delete_peer_secret(app: &AppHandle, device_id: &str) {
    if let Ok(mut s) = app.state::<PairingState>().secrets.try_write() {
        s.remove(device_id);
    }
    crate::transfer::persist_paired(app);
}

/// POST /api/v3/unpair-request：在线解配对（发起方→被动方，带签名）。
/// 验签通过 → 本机把 issuer 记录转 REVOKED + 删除 pairing_secret（§四 双方最终一致）。
pub fn handle_unpair_request(app: &AppHandle, body: &str) -> (i32, String) {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return err_json("INVALID_REQUEST", "请求体不是合法 JSON", ""),
    };
    let issuer = v.get("issuerDeviceId").and_then(|d| d.as_str()).unwrap_or("");
    let target = v.get("targetDeviceId").and_then(|d| d.as_str()).unwrap_or("");
    let timestamp = v.get("timestamp").and_then(|d| d.as_str()).unwrap_or("");
    let signature = v.get("signature").and_then(|d| d.as_str()).unwrap_or("");
    if issuer.is_empty() || target.is_empty() || signature.is_empty() {
        return err_json("INVALID_REQUEST", "缺少必填字段", "");
    }
    if target != identity::get_device_id(app) {
        return err_json("INVALID_REQUEST", "target 不是本机", "");
    }
    let Some(record) = peer_record(app, issuer) else {
        return err_json("UNKNOWN_DEVICE", "不认识该设备，拒绝解除", "");
    };
    let peer_pub = record.get("peerPublicKey").and_then(|k| k.as_str()).unwrap_or("");
    let msg = sig_msg3("unpair-request", issuer, target, timestamp);
    if peer_pub.is_empty() || !crate::crypto::sig_verify(peer_pub, &msg, signature) {
        return err_json("BAD_SIGNATURE", "签名验证失败", "");
    }
    set_peer_status(app, issuer, "REVOKED");
    delete_peer_secret(app, issuer);
    crate::log_info!("在线解配对生效: issuer={} → REVOKED", crate::logger::mask(issuer));
    let _ = app.emit("pair-unpaired", json!({ "deviceId": issuer }));
    ok_json(json!({ "ok": true, "status": "REVOKED" }))
}

/// POST /api/v3/sync-status：A 上线状态同步（§5.2）。
/// B 收到后：ACTIVE→回 ok（更新 lastHeartbeat）；REVOKE_PENDING→回吊销令牌；否则→unknown。
pub fn handle_sync_status(app: &AppHandle, body: &str) -> (i32, String) {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return err_json("INVALID_REQUEST", "请求体不是合法 JSON", ""),
    };
    let issuer = v.get("issuerDeviceId").and_then(|d| d.as_str()).unwrap_or("");
    let target = v.get("targetDeviceId").and_then(|d| d.as_str()).unwrap_or("");
    let timestamp = v.get("timestamp").and_then(|d| d.as_str()).unwrap_or("");
    let signature = v.get("signature").and_then(|d| d.as_str()).unwrap_or("");
    if issuer.is_empty() || target.is_empty() || signature.is_empty() {
        return err_json("INVALID_REQUEST", "缺少必填字段", "");
    }
    if target != identity::get_device_id(app) {
        return err_json("INVALID_REQUEST", "target 不是本机", "");
    }
    let Some(record) = peer_record(app, issuer) else {
        return ok_json(json!({ "ok": true, "status": "unknown" }));
    };
    let peer_pub = record.get("peerPublicKey").and_then(|k| k.as_str()).unwrap_or("");
    let msg = sig_msg3("sync-status", issuer, target, timestamp);
    if peer_pub.is_empty() || !crate::crypto::sig_verify(peer_pub, &msg, signature) {
        return ok_json(json!({ "ok": true, "status": "unknown" }));
    }
    let status = record.get("status").and_then(|s| s.as_str()).unwrap_or("ACTIVE").to_string();
    if status == "REVOKE_PENDING" {
        let token = record.get("pendingRevokeToken").cloned().unwrap_or(serde_json::Value::Null);
        return ok_json(json!({ "ok": true, "status": "revoked", "revokeToken": token }));
    }
    if status == "ACTIVE" {
        if let Ok(mut m) = app.state::<PairingState>().paired.lock() {
            if let Some(v) = m.get_mut(issuer) {
                if let Some(o) = v.as_object_mut() {
                    o.insert("lastHeartbeat".to_string(), json!(now_ms()));
                }
            }
        }
        return ok_json(json!({ "ok": true, "status": "ok" }));
    }
    ok_json(json!({ "ok": true, "status": "unknown" }))
}

/// POST /api/v3/revoke-notify：B 推送吊销令牌给 A（§5.2 步骤 3）。
/// A 验签通过 → 记录转 REVOKED + 删除 pairing_secret。
pub fn handle_revoke_notify(app: &AppHandle, body: &str) -> (i32, String) {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return err_json("INVALID_REQUEST", "请求体不是合法 JSON", ""),
    };
    let Some(token) = v.get("revokeToken") else {
        return err_json("INVALID_REQUEST", "缺少 revokeToken", "");
    };
    let token_issuer = token.get("issuerDeviceId").and_then(|d| d.as_str()).unwrap_or("");
    let token_target = token.get("targetDeviceId").and_then(|d| d.as_str()).unwrap_or("");
    let issued_at = token.get("issuedAt").and_then(|d| d.as_str()).unwrap_or("");
    let nonce = token.get("nonce").and_then(|d| d.as_str()).unwrap_or("");
    let token_sig = token.get("signature").and_then(|d| d.as_str()).unwrap_or("");
    if token_issuer.is_empty() || token_target.is_empty() || nonce.is_empty() || token_sig.is_empty() {
        return err_json("INVALID_REQUEST", "吊销令牌字段不完整", "");
    }
    if token_target != identity::get_device_id(app) {
        return err_json("INVALID_REQUEST", "target 不是本机", "");
    }
    let Some(record) = peer_record(app, token_issuer) else {
        return err_json("UNKNOWN_DEVICE", "不认识该设备，拒绝吊销", "");
    };
    let peer_pub = record.get("peerPublicKey").and_then(|k| k.as_str()).unwrap_or("");
    let msg = sig_revoke_msg(token_issuer, token_target, issued_at, nonce);
    if peer_pub.is_empty() || !crate::crypto::sig_verify(peer_pub, &msg, token_sig) {
        return err_json("BAD_SIGNATURE", "吊销令牌签名验证失败", "");
    }
    set_peer_status(app, token_issuer, "REVOKED");
    delete_peer_secret(app, token_issuer);
    crate::log_info!("离线吊销生效: issuer={} → REVOKED", crate::logger::mask(token_issuer));
    let _ = app.emit("pair-unpaired", json!({ "deviceId": token_issuer }));
    ok_json(json!({ "ok": true, "status": "REVOKED" }))
}

/// POST /api/v3/revoke-ack：A 确认吊销（§5.2 步骤 5）。
/// B 收到后：REVOKE_PENDING → REVOKED，删除吊销令牌。
pub fn handle_revoke_ack(app: &AppHandle, body: &str) -> (i32, String) {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return err_json("INVALID_REQUEST", "请求体不是合法 JSON", ""),
    };
    let issuer = v.get("issuerDeviceId").and_then(|d| d.as_str()).unwrap_or("");
    let target = v.get("targetDeviceId").and_then(|d| d.as_str()).unwrap_or("");
    let issued_at = v.get("issuedAt").and_then(|d| d.as_str()).unwrap_or("");
    let nonce = v.get("nonce").and_then(|d| d.as_str()).unwrap_or("");
    let signature = v.get("signature").and_then(|d| d.as_str()).unwrap_or("");
    if issuer.is_empty() || target.is_empty() || nonce.is_empty() || signature.is_empty() {
        return err_json("INVALID_REQUEST", "缺少必填字段", "");
    }
    if target != identity::get_device_id(app) {
        return err_json("INVALID_REQUEST", "target 不是本机", "");
    }
    let Some(record) = peer_record(app, issuer) else {
        return err_json("UNKNOWN_DEVICE", "不认识该设备", "");
    };
    let peer_pub = record.get("peerPublicKey").and_then(|k| k.as_str()).unwrap_or("");
    let msg = sig_ack_msg(issuer, target, issued_at, nonce);
    if peer_pub.is_empty() || !crate::crypto::sig_verify(peer_pub, &msg, signature) {
        return err_json("BAD_SIGNATURE", "ack 签名验证失败", "");
    }
    // 校验本机 pendingRevokeToken 与 ack 引用的令牌匹配（防伪造 ack）
    let pending_matches = record
        .get("pendingRevokeToken")
        .map(|t| {
            t.get("issuedAt").and_then(|x| x.as_str()) == Some(issued_at)
                && t.get("nonce").and_then(|x| x.as_str()) == Some(nonce)
        })
        .unwrap_or(false);
    if !pending_matches {
        return err_json("TOKEN_MISMATCH", "吊销令牌不匹配", "");
    }
    set_peer_status(app, issuer, "REVOKED");
    crate::log_info!("吊销已确认: issuer={} REVOKE_PENDING → REVOKED", crate::logger::mask(issuer));
    ok_json(json!({ "ok": true, "status": "REVOKED" }))
}
