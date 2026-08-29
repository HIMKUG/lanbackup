//! V4 统一错误类型
//!
//! 统一错误信封对齐 `protocol/README.md`：
//! ```json
//! { "error": { "code": "...", "message": "...", "requestId": "..." } }
//! ```

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 错误码。取值沿用协议契约已有的错误码集合。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidRequest,
    InvalidCode,
    HmacMismatch,
    Untrusted,
    RateLimitExceeded,
    NotFound,
    VersionUnsupported,
    UnknownDevice,
    TokenExpired,
    /// 对端不具备请求的能力
    CapabilityUnsupported,
    /// 请求体格式/字段非法
    BadRequest,
    /// 当前状态不允许该操作（状态机拒绝迁移）
    IllegalState,
    /// 传输已中止（用户中止或连接断开）
    Aborted,
    /// 会话无进展超时
    Stalled,
    /// 内部错误
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::InvalidCode => "INVALID_CODE",
            Self::HmacMismatch => "HMAC_MISMATCH",
            Self::Untrusted => "UNTRUSTED",
            Self::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            Self::NotFound => "NOT_FOUND",
            Self::VersionUnsupported => "VERSION_UNSUPPORTED",
            Self::UnknownDevice => "UNKNOWN_DEVICE",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::CapabilityUnsupported => "CAPABILITY_UNSUPPORTED",
            Self::BadRequest => "BAD_REQUEST",
            Self::IllegalState => "ILLEGAL_STATE",
            Self::Aborted => "ABORTED",
            Self::Stalled => "STALLED",
            Self::Internal => "INTERNAL",
        }
    }

    /// 对应 HTTP 状态码
    pub fn http_status(self) -> u16 {
        match self {
            Self::InvalidRequest | Self::InvalidCode => 400,
            Self::Untrusted | Self::HmacMismatch | Self::TokenExpired => 401,
            Self::CapabilityUnsupported => 409,
            Self::BadRequest => 400,
            Self::IllegalState => 409,
            Self::RateLimitExceeded => 429,
            Self::NotFound | Self::UnknownDevice => 404,
            Self::VersionUnsupported => 426,
            Self::Aborted => 409,
            Self::Stalled => 408,
            Self::Internal => 500,
        }
    }
}

/// 线上传输的错误信封。
///
/// **注意**：`message` 只放可对外披露的信息。内部诊断细节走日志，
/// 不回传给对端 —— 避免给攻击者提供 oracle（原 `crypto.ts` verifyChallengeResponse
/// 就是"先比长度再逐字节、整体 try/catch 返回 false"而不抛具体原因）。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ErrorEnvelope {
    pub error: ErrorBody,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
    #[serde(rename = "requestId", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl ErrorEnvelope {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: ErrorBody {
                code,
                message: message.into(),
                request_id: None,
            },
        }
    }

    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.error.request_id = Some(id.into());
        self
    }
}

/// core 内部错误类型
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{code:?}: {message}")]
    Protocol { code: ErrorCode, message: String },

    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("序列化错误: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("数据库错误: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("HTTP 错误: {0}")]
    Http(#[from] hyper::Error),

    #[error("网络错误: {0}")]
    Network(#[from] reqwest::Error),

    #[error("密码学错误: {0}")]
    Crypto(String),

    #[error("非法状态迁移: {from} -> {to}")]
    InvalidTransition { from: &'static str, to: &'static str },

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn protocol(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Protocol {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Protocol { code, .. } => *code,
            _ => ErrorCode::Internal,
        }
    }

    /// 转为可对外传输的错误信封。
    /// 非协议错误的 message 会被替换为通用文案，避免泄漏内部细节。
    pub fn to_envelope(&self) -> ErrorEnvelope {
        match self {
            Self::Protocol { code, message } => ErrorEnvelope::new(*code, message.clone()),
            _ => ErrorEnvelope::new(ErrorCode::Internal, "内部错误"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
