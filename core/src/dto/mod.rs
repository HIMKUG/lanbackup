//! V4 协议 DTO —— 契约即代码
//!
//! 所有线上数据结构在此定义，并用 `schemars` 生成 JSON Schema 到
//! `protocol/schemas/v4/`。生成由 `src/bin/gen_schema.rs` 完成，CI 校验
//! "重新生成后 diff 为空"，因此 **schema 不可能与实现漂移**。
//!
//! 三代并存的教训：`protocol/schemas/` 下 9 份手写 JSON Schema 与实现
//! 已经对不上（例如 README 说 3.0、golden 写 3.1；README 说无
//! `pair/initiate` 端点，manifest.json 又列了它们）。手写契约必然漂移。

pub mod handshake;
pub mod session;
pub mod sync;

pub use handshake::*;
pub use session::*;
pub use sync::*;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 设备类型。取值沿用 LocalSend 生态的既有语义，便于与上游互通。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Mobile,
    Desktop,
    Web,
    Headless,
    Server,
}

/// 所有响应的公共信封字段。
///
/// 说明：`requestId` 用于全链路追踪（对齐 `protocol/README.md` 的
/// `X-Request-Id` 约定），错误响应由 `error::ErrorEnvelope` 单独定义。
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct RequestMeta {
    /// 全链路追踪 ID，由调用方生成，服务端原样回显
    #[serde(rename = "requestId", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// 设备上线的网络地址信息。
///
/// **多通道容错**（原 `pairing.ts:32-33`）：同一设备可能同时有多个 IP
/// （2.4G/5G 双频、有线+无线、路由器 DHCP 重分配），只记一个必然连不上。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Endpoint {
    /// 最近一次可达的 IP
    pub ip: String,
    /// 历史可达 IP，最近在前，最多 5 个
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ips: Option<Vec<String>>,
    /// 服务端口
    pub port: u16,
}

/// 在线性。
///
/// 由 UDP beacon 维护（周期 500ms，1.5s 未收到转 `Stale`，3s 转 `Offline`）。
/// **注意**：在线性是独立维度，与"是否已配对"分开 —— 三代并存的 bug 之一
/// 就是把两者混为一谈，导致"对方离线却可以连接"。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Presence {
    /// 尚未探测
    Unknown,
    /// 在线
    Online,
    /// 信号不稳定（1~2 个 beacon 周期未收到）
    Stale,
    /// 离线
    Offline,
}

impl Presence {
    /// 是否允许发起新传输。
    ///
    /// 只有 `Online` 可以 —— 这是 `V4-TRANSFER-MODULE.md` §3.2 门控的依据。
    pub fn allows_new_transfer(self) -> bool {
        matches!(self, Presence::Online)
    }

    /// 是否允许发起连接
    pub fn allows_connect(self) -> bool {
        matches!(self, Presence::Online)
    }
}
