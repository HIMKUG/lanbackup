//! pairing/auth.rs — 配对服务主路由 + 管理面/数据面辅助端点
//!
//! 配对服务在 pairing 端口（53318）接收 HTTP 请求，按路径代理到 core 的 v4 端点。
//! 探测走 /api/v4/probe，配对走 /api/v4/handshake/verify（首次）/ challenge+verify（重连）。
//! 本文件保留：接收回执 / 解除配对 / 断开 / 取消 / 目录同步 / 移动删除 / 清单 / 分片状态。

use crate::db::AppError;
use crate::identity;
use crate::transfer::{persist_paired, PairingState};
use std::io::{Read, Write};
use tauri::{AppHandle, Emitter, Manager};

// ═══════════════════════════════════════════════════════════════════════
// 主路由函数（< 50 行）
// ═══════════════════════════════════════════════════════════════════════

/// 处理单条配对服务连接（读请求 → 路由 → 回 JSON）
pub fn handle_pairing_conn(
    app: AppHandle,
    stream: &mut std::net::TcpStream,
) -> Result<(), AppError> {
    let client_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    crate::log_info!("配对服务: 新连接 from={}", client_ip);
    // 防御性总开关：隐藏时拒绝一切入站连接（含已配对凭证直连、连接码直连），仅保留本机主动外连
    if app
        .state::<crate::transfer::TransferState>()
        .defensive_hidden
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        crate::log_info!("防御性总开关隐藏中：拒绝入站连接 from={client_ip}");
        let body = r#"{"ok":false,"reason":"hidden"}"#;
        let resp = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
        return Ok(());
    }
    // 阶段 0: 读取完整 HTTP 请求
    let req = read_http_request(stream)?;

    let client_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();

    // 空请求直接返回
    if req.is_empty() {
        crate::log_info!("配对服务: 空请求 clientIp={}", client_ip);
        return Ok(());
    }

    // 阶段 1: 解析请求行 + 头部 + 路由分发
    // 返回 5 元组：额外返回带 query 的原始路径（用于 handle_chunk_status 解析 encodedPath 参数）
    let (method, path, path_raw, body, headers) = parse_request(&req);
    crate::log_info!(
        "配对服务: {} {} from={} bodyLen={}",
        method,
        path,
        client_ip,
        body.len()
    );

    // 信任校验：body.deviceId 优先，其次 X-Device-Id 头（GET 无 body 端点用）
    let request_trusted = || {
        let from_body = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("deviceId").and_then(|d| d.as_str()).map(String::from));
        let device_id = from_body.or_else(|| headers.get("x-device-id").cloned()).unwrap_or_default();
        check_trusted(&device_id, &app)
    };
    const FORBIDDEN: &str = r#"{"ok":false,"reason":"untrusted"}"#;

    let (status, json) = match (method.as_str(), path.as_str()) {
        ("POST", "/api/backup/v1/disconnect") => {
            if !request_trusted() { (403, FORBIDDEN.to_string()) } else { handle_disconnect(&app, &body) }
        }
        ("POST", "/api/backup/v1/move-to-delete") => {
            if !request_trusted() { (403, FORBIDDEN.to_string()) } else { handle_move_to_delete(&app, &body) }
        }
        ("POST", "/api/backup/v1/cancel") => {
            handle_cancel(&app, &body)
        }
        ("GET", "/api/backup/v1/chunk-status") => {
            if !request_trusted() { (403, FORBIDDEN.to_string()) } else { handle_chunk_status(&app, &path_raw) }
        }
        ("GET", "/api/backup/v1/manifest") => {
            if !request_trusted() { (403, FORBIDDEN.to_string()) } else { handle_manifest(&app) }
        }
        (m, p) if p.starts_with("/api/v4/") => {
            crate::pairing::v4::route_v4(&app, m, p, &body, &client_ip, &headers)
                .unwrap_or_else(|e| (500, format!(r#"{{"error":{{"code":"INVALID_REQUEST","message":"{e}","requestId":""}}}}"#)))
        }
        _ => (404, r#"{"error":"not_found"}"#.to_string()),
    };

    // 发送 HTTP 响应
    let resp = format!(
        "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        json.len(),
        json
    );
    stream
        .write_all(resp.as_bytes())
        .map_err(AppError::from_display)?;
    crate::log_info!("配对服务: 响应 {} to={} jsonLen={}", status, client_ip, json.len());
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// 阶段 0: 读取 HTTP 请求
// ═══════════════════════════════════════════════════════════════════════

/// 从已解析的 HTTP 头部字节提取 Content-Length（无则返回 0）。
/// 恶意/畸形值解析失败按 0 处理（调用方再结合整体长度判断完整性）。
fn parse_content_length(hdr_bytes: &[u8]) -> usize {
    String::from_utf8_lossy(hdr_bytes)
        .lines()
        .find_map(|l| {
            l.to_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0)
}

/// 循环读取直到完整 HTTP 请求（头部 \r\n\r\n + Content-Length body）
fn read_http_request(stream: &mut std::net::TcpStream) -> Result<String, AppError> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut search_from = 0usize;
    let mut hdr_end_opt: Option<usize> = None;

    loop {
        let n = stream.read(&mut tmp).map_err(AppError::from_display)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);

        if hdr_end_opt.is_none() {
            if let Some(rel) = buf[search_from..].windows(4).position(|w| w == b"\r\n\r\n") {
                hdr_end_opt = Some(search_from + rel);
            } else {
                search_from = buf.len().saturating_sub(3);
            }
        }

        if let Some(hdr_end) = hdr_end_opt {
            let cl = parse_content_length(&buf[..hdr_end]);
            // saturating_add：恶意 Content-Length: 18446744073709551615（usize::MAX）
            // 会使普通加法溢出——debug panic / release 回绕导致提前截断 body
            if buf.len() >= hdr_end.saturating_add(4).saturating_add(cl) {
                break;
            }
        }

        if buf.len() > 65536 {
            // 安全上限：超限即拒绝，避免把不完整请求（半截 body）交给上层解析。
            // 若头部已就绪但 body 未读完，此时 buf 是不完整请求，返回错误而非悄悄 break。
            let body_ready = hdr_end_opt.map_or(false, |hdr_end| {
                // 有 Content-Length 则校验 body 是否读够；无/为 0 视为无 body 即就绪
                let cl = parse_content_length(&buf[..hdr_end]);
                if cl == 0 {
                    true
                } else {
                    buf.len() >= hdr_end + 4 + cl
                }
            });
            if !body_ready {
                return Err(AppError("HTTP 请求超过 64KB 上限且 body 不完整".to_string()));
            }
            break; // 请求完整但超长，交由上层 Content-Length 处理
        }
    }

    if buf.is_empty() {
        return Ok(String::new());
    }

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

// ═══════════════════════════════════════════════════════════════════════
// 阶段 1: 解析请求行
// ═══════════════════════════════════════════════════════════════════════

fn parse_request(req: &str) -> (String, String, String, String, std::collections::HashMap<String, String>) {
    let mut lines = req.lines();
    let request_line = lines.next().unwrap_or("").to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path_raw = parts.next().unwrap_or("").to_string();
    // 剥离 query string 得到纯路径（用于路由匹配）
    let path = path_raw.split('?').next().unwrap_or("").to_string();

    let mut content_length = 0usize;
    // 头部小写键收集（信任校验需要读 X-Device-Id）
    let mut headers = std::collections::HashMap::new();
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
        if let Some(v) = line.to_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    let body_start = req.find("\r\n\r\n").map(|i| i + 4).unwrap_or(req.len());
    // body_end 用 saturating_add + min 双保险：防 Content-Length 超出实际 body
    let body_end = body_start.saturating_add(content_length).min(req.len());
    let body = if body_start < req.len() {
        String::from_utf8_lossy(&req.as_bytes()[body_start..body_end]).into_owned()
    } else {
        String::new()
    };

    (method, path, path_raw, body, headers)
}

// ═══════════════════════════════════════════════════════════════════════
// 路由分支：disconnect / move-to-delete / cancel / chunk-status / manifest
// （handle_file_receipt / handle_unpair / handle_sync_dir 已移除：旧版 v2 端点）
// ═══════════════════════════════════════════════════════════════════════

#[allow(dead_code)]
fn handle_file_receipt(app: &AppHandle, body: &str) -> (i32, String) {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        let file_name = v.get("fileName").and_then(|x| x.as_str()).unwrap_or("");
        crate::log_info!("收到文件回执: {file_name}");
        let _ = app.emit("file-receipt", serde_json::json!({ "fileName": file_name }));
    }
    (200, r#"{"ok":true}"#.to_string())
}

#[allow(dead_code)]
fn handle_unpair(app: &AppHandle, body: &str) -> (i32, String) {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(device_id) = v.get("deviceId").and_then(|d| d.as_str()) {
            if let Ok(mut m) = app.state::<PairingState>().paired.lock() {
                m.remove(device_id);
            }
            crate::log_info!(
                "收到解除配对: deviceId={}",
                crate::logger::mask(device_id)
            );
            let _ = app.emit(
                "pair-unpaired",
                serde_json::json!({ "deviceId": device_id }),
            );
            persist_paired(app);
        }
    }
    (200, r#"{"ok":true}"#.to_string())
}

fn handle_disconnect(app: &AppHandle, body: &str) -> (i32, String) {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(device_id) = v.get("deviceId").and_then(|d| d.as_str()) {
            crate::log_info!(
                "收到断开连接: deviceId={}",
                crate::logger::mask(device_id)
            );
            let _ = app.emit(
                "peer-disconnected",
                serde_json::json!({ "deviceId": device_id }),
            );
        }
    }
    (200, r#"{"ok":true}"#.to_string())
}

/// 处理取消传输请求（接收端确认取消）
/// 防御：仅放行「可信设备」或「本机当前活跃会话」发起的取消。
/// 手机端取消只携带 sessionId（不带 deviceId/头），若严格按可信校验，正常取消会一律 403，
/// 导致接收端点了取消但发送端毫无感知（对方仍在发送）。取消是非破坏性操作（仅停收发），
/// 按「活跃会话」放行是安全且必要的折中：攻击者需先掌握真实 sessionId（UUID）才能触发。
fn handle_cancel(app: &AppHandle, body: &str) -> (i32, String) {
    // P3-300：body 只解析一次，避免三次独立 serde_json::from_str
    let parsed = serde_json::from_str::<serde_json::Value>(body).ok();
    let get_str = |k: &str| parsed.as_ref().and_then(|v| v.get(k).and_then(|s| s.as_str()).map(String::from)).unwrap_or_default();
    let session_id: String = get_str("sessionId");
    // 可信设备（body.deviceId 或 X-Device-Id 头）→ 直接放行
    let from_body: String = get_str("deviceId");
    let trusted = !from_body.is_empty() && check_trusted(&from_body, app);
    // 活跃会话 → 放行（发送端把 session 登记在 active_sessions）
    let active = !session_id.is_empty()
        && app
            .state::<crate::transfer::TransferState>()
            .active_sessions
            .lock()
            .map(|m| m.contains_key(&session_id))
            .unwrap_or(false);
    if !trusted && !active {
        crate::log_warn!(
            "拒绝取消（无信任且无活跃会话）: sessionId={}",
            crate::logger::mask(&session_id)
        );
        return (403, r#"{"ok":false,"reason":"untrusted"}"#.to_string());
    }
    let file_id: String = get_str("fileId");
    crate::log_info!(
        "收到取消传输请求: sessionId={} fileId={}",
        crate::logger::mask(&session_id),
        crate::logger::mask(&file_id)
    );
    // 取消链路 STEP 2：取出该会话登记的 cancel token 并触发，真正中断发送循环；
    // 随后移除登记，避免重复取消。这才是"取消通知生效"的关键（发送循环轮询该 token）。
    if !session_id.is_empty() {
        if let Ok(mut sessions) = app.state::<crate::transfer::TransferState>().active_sessions.lock() {
            if let Some(token) = sessions.remove(&session_id) {
                token.cancel();
                crate::log_info!(
                    "已触发发送任务取消: sessionId={}",
                    crate::logger::mask(&session_id)
                );
            }
        }
    }
    let _ = app.emit(
        "transfer-cancelled",
        serde_json::json!({ "sessionId": session_id, "fileId": file_id }),
    );
    (200, r#"{"ok":true}"#.to_string())
}

#[allow(dead_code)]
fn handle_sync_dir(app: &AppHandle, body: &str) -> (i32, String) {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let (Some(dir), Some(name)) = (
            v.get("direction").and_then(|d| d.as_str()),
            v.get("name").and_then(|n| n.as_str()),
        ) {
            if let Ok(mut m) = app.state::<PairingState>().synced_dirs.lock() {
                m.insert(dir.to_string(), name.to_string());
            }
            crate::log_info!("配对服务: 收到目录同步 {dir} = {name}");
        }
    }
    (200, r#"{"ok":true}"#.to_string())
}

fn handle_move_to_delete(app: &AppHandle, body: &str) -> (i32, String) {
    let moved = crate::transfer::handle_move_to_delete(app, body);
    let json = serde_json::json!({ "ok": true, "moved": moved }).to_string();
    (200, json)
}

// ═══════════════════════════════════════════════════════════════════════
// 路由分支：chunk-status / manifest
// ═══════════════════════════════════════════════════════════════════════

fn handle_chunk_status(app: &AppHandle, path: &str) -> (i32, String) {
    let file = path
        .split('?')
        .nth(1)
        .unwrap_or("")
        .split('&')
        .find_map(|kv| kv.strip_prefix("encodedPath="))
        .unwrap_or("");

    let st = app.state::<crate::transfer::TransferState>();
    let dir = st.receive_dir.lock().map(|g| g.clone()).unwrap_or(None);
    let mut chunks: Vec<u32> = Vec::new();

    if let Some(d) = dir {
        let part_dir = std::path::Path::new(&d).join(".chunks").join(file);
        if let Ok(rd) = std::fs::read_dir(&part_dir) {
            for e in rd.flatten() {
                if let Ok(i) = e.file_name().to_string_lossy().parse::<u32>() {
                    chunks.push(i);
                }
            }
        }
    }

    chunks.sort();
    let mut next_chunk = 0u32;
    while (next_chunk as usize) < chunks.len() && chunks[next_chunk as usize] == next_chunk {
        next_chunk += 1;
    }

    let json = serde_json::json!({
        "receivedChunks": chunks,
        "nextChunk": next_chunk,
        "fileComplete": false,
    })
    .to_string();
    (200, json)
}

fn handle_manifest(app: &AppHandle) -> (i32, String) {
    let st = app.state::<crate::transfer::TransferState>();
    let dir = st.receive_dir.lock().map(|g| g.clone()).unwrap_or(None);
    match dir {
        Some(ref d) => {
            let mut entries = Vec::new();
            let _ = scan_dir_recursive(d.to_string_lossy().as_ref(), "", &mut entries);
            let mut files = serde_json::Map::new();
            for e in entries {
                files.insert(e.rel_path, serde_json::json!({"size": e.size, "mtime": e.mtime}));
            }
            let json = serde_json::json!({
                "generatedAt": chrono_now_ms() / 1000,
                "deviceCode": identity::get_device_id(app),
                "files": serde_json::Value::Object(files),
                "version": 1,
            })
            .to_string();
            (200, json)
        }
        None => {
            let json = serde_json::json!({
                "generatedAt": 0,
                "deviceCode": identity::get_device_id(app),
                "files": {},
                "version": 1,
                "available": false,
            })
            .to_string();
            (200, json)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 工具函数
// ═══════════════════════════════════════════════════════════════════════

/// 检查设备是否已配对且信任可用（数据面门禁，v5 增强）。
/// - status 必须 == ACTIVE（REVOKE_PENDING/REVOKED 拒绝数据面）
/// - peerPublicKey 必须存在（旧配对无签名信任锚 → 全部重新配对，用户已确认）
fn check_trusted(device_id: &str, app: &AppHandle) -> bool {
    if device_id.is_empty() {
        return false;
    }
    app.state::<PairingState>()
        .paired
        .lock()
        .map(|m| {
            m.get(device_id)
                .map(|p| {
                    let status = p.get("status").and_then(|s| s.as_str()).unwrap_or("ACTIVE");
                    let has_key = p
                        .get("peerPublicKey")
                        .and_then(|k| k.as_str())
                        .map(|s| !s.is_empty())
                        .unwrap_or(false);
                    status == "ACTIVE" && has_key
                })
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

// ═══════════════════════════════════════════════════════════════════════
// 目录扫描（供 manifest 使用，与 transfer.rs 中版本保持一致）
// ═══════════════════════════════════════════════════════════════════════

struct DirEntry {
    rel_path: String,
    size: u64,
    mtime: i64,
}

fn scan_dir_recursive(base: &str, prefix: &str, out: &mut Vec<DirEntry>) {
    let Ok(rd) = std::fs::read_dir(base) else { return };
    for entry in rd.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let rel = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", prefix, name)
        };
        if path.is_dir() {
            scan_dir_recursive(path.to_string_lossy().as_ref(), &rel, out);
        } else if let Ok(meta) = entry.metadata() {
            out.push(DirEntry {
                rel_path: rel,
                size: meta.len(),
                mtime: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            });
        }
    }
}

fn chrono_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
