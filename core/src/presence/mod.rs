//! 在线性 beacon（V4-ARCHITECTURE §3.3-B / 阶段 4.3）
//!
//! 在线性是连接的前置门控：对方离线就**不能**连接（消灭「离线却能连接」）。
//! 0.5s TTL 太灵敏，用 HTTP 轮询不划算（唤醒移动端射频），故改用 **UDP presence beacon**。
//!
//! 本模块负责 **beacon 报文格式与认证**（`beacon`）以及
//! **重放防护与在线性维护**（`tracker`）—— 都是纯计算，可独立测试。
//! UDP 收发、Android `MulticastLock`、`WifiManager` 等传输层韧性问题见阶段 4 的网络栈。
//!
//! 职责切分：
//!
//! | 模块 | 回答的问题 | 是否持有状态 |
//! |---|---|---|
//! | `beacon` | 这个包是不是该设备签的？ | 否 |
//! | `state::presence` | 距上次 beacon 过了这么久，状态该是什么？ | 否 |
//! | `tracker` | 这个包是不是重放？在线性现在是什么？ | **是**（水位线 + 时钟） |

pub mod beacon;
pub mod tracker;

pub use beacon::{
    sign_beacon, verify_beacon, BeaconPacket, AUTH_TAG_LEN, BEACON_LEN, DEVICE_ID_PREFIX_LEN,
};
pub use tracker::{BeaconVerdict, PresenceTracker, CLOCK_SKEW_TOLERANCE_SECS};
