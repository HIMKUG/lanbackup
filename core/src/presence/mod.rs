//! 在线性 beacon（V4-ARCHITECTURE §3.3-B / 阶段 4.3）
//!
//! 在线性是连接的前置门控：对方离线就**不能**连接（消灭「离线却能连接」）。
//! 0.5s TTL 太灵敏，用 HTTP 轮询不划算（唤醒移动端射频），故改用 **UDP presence beacon**。
//!
//! 本模块负责 **beacon 报文格式与认证**（`beacon`）、
//! **重放防护与在线性维护**（`tracker`），以及
//! **UDP 收发与多网卡/组播锁韧性**（`transport`）。
//!
//! 职责切分：
//!
//! | 模块 | 回答的问题 | 是否持有状态 | 是否触网 |
//! |---|---|---|---|
//! | `beacon` | 这个包是不是该设备签的？ | 否 | 否 |
//! | `state::presence` | 距上次 beacon 过了这么久，状态该是什么？ | 否 | 否 |
//! | `tracker` | 这个包是不是重放？在线性现在是什么？ | **是**（水位线 + 时钟） | 否 |
//! | `transport::BeaconEmitter` | 我下一个该发什么？ | **是**（`(ts,seq)` 单调） | 否 |
//! | `transport::PresenceSocket` | 往哪些地址发、怎么收？ | 是（套接字） | **是** |

pub mod beacon;
pub mod tracker;
pub mod transport;

pub use beacon::{
    sign_beacon, verify_beacon, BeaconPacket, AUTH_TAG_LEN, BEACON_LEN, DEVICE_ID_PREFIX_LEN,
};
pub use tracker::{BeaconVerdict, PresenceTracker, CLOCK_SKEW_TOLERANCE_SECS};
pub use transport::{
    beacon_targets, directed_broadcast, BeaconEmitter, MulticastGuard, NoopMulticastGuard,
    PresenceSocket, SendHealth, BEACON_INTERVAL_MS, MULTICAST_GROUP, PRESENCE_PORT,
    SOCKET_FAILURE_THRESHOLD,
};
