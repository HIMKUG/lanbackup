//! pairing/v4.rs — v4 配对协议（Phase B）
//!
//! 设计策略：委托 core::server（53317 端口）处理所有 v4 配对端点。
//! desktop pairing 服务（53318）作为代理层，按协议版本分流。
//!
//! 委托的端点：
//!   GET  /api/v4/probe                  → core server
//!   POST /api/v4/handshake/challenge   → core server
//!   POST /api/v4/handshake/verify      → core server
//!   GET  /api/v4/handshake/status      → core server
//!
//! 注意：v4 配对依赖 core SessionStore 中的 peers/secrets，
//! desktop 需在启动时将配对状态同步到 core。

use crate::db::AppError;
use std::collections::HashMap;

pub fn route_v4(
    _app: &tauri::AppHandle,
    method: &str,
    path: &str,
    body: &str,
    _client_ip: &str,
    _headers: &HashMap<String, String>,
) -> Result<(i32, String), AppError> {
    let core_port = 53317u16;

    let proxy_path = match path {
        "/api/v4/probe" => path,
        "/api/v4/handshake/challenge" => path,
        "/api/v4/handshake/verify" => path,
        p if p.starts_with("/api/v4/handshake/status") => path,
        _ => return Ok((404, r#"{"error":"not_found"}"#.to_string())),
    };

    let ip = "127.0.0.1";
    let resp_json = crate::transfer::http_json_request(
        ip,
        core_port,
        method,
        proxy_path,
        body,
    ).map_err(|e| AppError(format!("委托 core server 失败: {}", e)))?;

    let status = 200;
    Ok((status, resp_json.to_string()))
}
