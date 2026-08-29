//! 发现与配对的 V4 DTO
//!
//! 端点（全部在 `DEFAULT_PORT` 上，消灭了原 53318 那套手写 TCP + HTTP 解析器）：
//! - `GET  /api/v4/probe`                 设备信息 + 静态公钥 + serverNonce + 能力位图
//! - `POST /api/v4/handshake/challenge`   重连（路径 B）：签发 JWT challenge
//! - `POST /api/v4/handshake/verify`      首配（路径 A）/ 重连：验 HMAC
//! - `GET  /api/v4/handshake/status`      按 requestId 查询握手结果
//! - `POST /api/v4/unpair-request`        请求解配对
//! - `POST /api/v4/unpair`                解配对通知（ECDSA 签名）
//! - `POST /api/v4/revoke-notify`         吊销通知
//! - `POST /api/v4/revoke-ack`            吊销确认
//! - `GET  /api/v4/sync-status`           **双向信任对账**

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{DeviceType, Endpoint, Presence};
use crate::version::Capabilities;

// ============================================================
// GET /api/v4/probe
// ============================================================

/// probe 响应。
///
/// 三代版本的响应里 `staticPub` 与 `publicKey` 两个字段并存且大小写不同，
/// V4 合并为单一的 `staticPub`。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProbeResponse {
    /// 设备公开标识（**不是连接码**）。
    ///
    /// 安全约束：连接码 = 加密密钥材料，绝不上线。广播与 info/probe 响应
    /// 一律只带公开 deviceId（原 `pairing.ts:1-11`、`backup.ts:187-188`）。
    #[serde(rename = "deviceId")]
    pub device_id: String,
    /// 设备显示名
    pub alias: String,
    #[serde(rename = "deviceType")]
    pub device_type: DeviceType,
    /// 服务端口
    pub port: u16,
    /// 协议版本，固定为 `PROTOCOL_VERSION`
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u32,
    /// 设备长期静态公钥（P-256，SEC1 未压缩，base64url）。
    ///
    /// 编码必须与 Java `Key.getEncoded()` / Rust `p256` crate 一致
    /// （原 `protocol/README.md:113`）。
    #[serde(rename = "staticPub")]
    pub static_pub: String,
    /// 服务端一次性随机数（32 字节 hex）。路径 A 配对的密钥材料之一。
    #[serde(rename = "serverNonce")]
    pub server_nonce: String,
    /// 能力位图（u32 位掩码）。取值见 `version::CAP_*` 常量。
    pub capabilities: Capabilities,
    /// 本端视角下**调用方**的在线状态
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence: Option<Presence>,
    /// 网络地址
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<Endpoint>,
}

// ============================================================
// POST /api/v4/handshake/challenge（路径 B：重连）
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ChallengeRequest {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    /// 客户端一次性随机数（32 字节 hex）
    #[serde(rename = "clientNonce")]
    pub client_nonce: String,
    /// 幂等键。重试必须复用同一 `requestId`，服务端据此去重
    /// （解决"握手发出去就失联，不知道成没成"）。
    #[serde(rename = "requestId")]
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ChallengeResponse {
    /// JWT challenge token，`exp = iat + 300`
    ///
    /// **注意**：`exp` 仅作卫生约束（日志/时钟漂移发现），
    /// 绝不用于拒绝请求 —— 原 `protocol/README.md:24` 明确放弃了
    /// `X-Timestamp ±容差` 校验，因为双端时钟差会导致握手失败。
    #[serde(rename = "challengeToken")]
    pub challenge_token: String,
    /// 服务端临时 ECDH 公钥（base64url）
    #[serde(rename = "serverEphPub")]
    pub server_eph_pub: String,
    #[serde(rename = "serverNonce")]
    pub server_nonce: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
}

// ============================================================
// POST /api/v4/handshake/verify（路径 A 首配 / 路径 B 重连）
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyRequest {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "clientEphPub")]
    pub client_eph_pub: String,
    #[serde(rename = "clientNonce")]
    pub client_nonce: String,
    #[serde(rename = "serverNonce")]
    pub server_nonce: String,
    /// 路径 A：HMAC 标签（用连接码派生的 secret 签名，连接码本身绝不上线）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
    /// 路径 B：`challenge` 阶段签发的 JWT
    #[serde(rename = "challengeToken", skip_serializing_if = "Option::is_none")]
    pub challenge_token: Option<String>,
    #[serde(rename = "requestId")]
    pub request_id: String,
}

/// 配对状态。
///
/// `Active` 不是一次确认永久有效 —— 需要周期性**双向对账**维持
/// （`GET /api/v4/sync-status`）。任一方说"不认"，本机即进入 `Revoking`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PairingState {
    /// 未配对
    None,
    /// 已发起，等对端确认
    Pending,
    /// 已配对且双向确认有效
    Active,
    /// 任一方发起解除，等待对端 ack
    Revoking,
    /// 已解除（终态）
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyResponse {
    pub status: PairingState,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// 协商后的能力（两端能力按位与）
    pub capabilities: Capabilities,
    #[serde(rename = "requestId")]
    pub request_id: String,
}

// ============================================================
// GET /api/v4/handshake/status
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HandshakeStatusResponse {
    #[serde(rename = "requestId")]
    pub request_id: String,
    /// 握手是否已完成
    pub done: bool,
    /// 完成后的配对状态；未完成时为空
    pub status: Option<PairingState>,
    /// 失败原因码；成功时为空
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============================================================
// 解配对与吊销
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UnpairRequest {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    /// ECDSA P-256 签名（ASN.1 DER base64url），用配对时交换的公钥验签
    pub signature: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UnpairNotification {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    /// 吊销令牌，30 天有效期。对端离线时用它兜底解除
    #[serde(rename = "revokeToken", skip_serializing_if = "Option::is_none")]
    pub revoke_token: Option<String>,
    pub signature: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RevokeNotify {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "revokeToken")]
    pub revoke_token: String,
    pub signature: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RevokeAck {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "revokeToken")]
    pub revoke_token: String,
    /// 对端是否已确认解除
    #[serde(rename = "pairingRevoked")]
    pub pairing_revoked: bool,
    #[serde(rename = "requestId")]
    pub request_id: String,
}

// ============================================================
// GET /api/v4/sync-status —— 双向信任对账
// ============================================================

/// 信任对账响应。
///
/// **问的不是"你在吗"，而是"你还认我吗"**。
///
/// 三代版本的问题：一方解除配对后，另一方弹出提示，**自己却仍然是配对的** ——
/// 因为配对状态是本机单方面记录，没有反向确认。
///
/// V4 规则：本机有效信任 = 本机记录 ∩ 对端确认。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SyncStatusResponse {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    /// 对端视角：我是否仍被对方视为已配对
    #[serde(rename = "youArePairedWithMe")]
    pub you_are_paired_with_me: bool,
    /// 本端信任版本号，每次配对状态变更 +1。
    /// 对端可据此判断自己的记录是否过期。
    #[serde(rename = "myTrustVersion")]
    pub my_trust_version: u64,
    /// 本端视角下对端的配对状态
    pub status: PairingState,
    /// 本端的在线状态
    pub presence: Presence,
}
