//! pairing/error.rs — 配对模块错误类型

use std::fmt;
use std::io;

/// 配对阶段错误（部分变体为未来功能预留，允许 dead_code）
#[allow(dead_code)]
#[derive(Debug)]
pub enum PairingError {
    Io(io::Error),
    Json(serde_json::Error),
    InvalidHello(String),
    AuthFailed(String),
    SeqMismatch,
    UnknownDevice(String),
}

impl From<io::Error> for PairingError {
    fn from(e: io::Error) -> Self {
        PairingError::Io(e)
    }
}

impl From<serde_json::Error> for PairingError {
    fn from(e: serde_json::Error) -> Self {
        PairingError::Json(e)
    }
}

impl fmt::Display for PairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::InvalidHello(msg) => write!(f, "invalid hello: {msg}"),
            Self::AuthFailed(msg) => write!(f, "auth failed: {msg}"),
            Self::SeqMismatch => write!(f, "sequence mismatch"),
            Self::UnknownDevice(id) => write!(f, "unknown device: {id}"),
        }
    }
}

impl std::error::Error for PairingError {}
