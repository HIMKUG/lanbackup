//! beacon 追踪器：把「报文认证」与「在线性状态机」接起来（V4-ARCHITECTURE §3.3-B）
//!
//! # 为什么需要这一层
//!
//! `presence::beacon` 只回答「这个包是不是该设备签的」（authenticity），
//! `state::presence` 只回答「距上次 beacon 过了这么久，状态该是什么」（纯函数）。
//! 两者都不持有状态，因此**都无法发现重放**。
//!
//! 缺了这一层会出现的实际后果：抓一个合法 beacon 反复重播，
//! 就能把一台已经离线（甚至已关机）的设备永久钉在 `Online`。
//! 而「在线」是连接的前置门控，于是又回到 V3 那个 bug ——
//! **离线设备却可以连接**。这正是 V4 要消灭的问题之一。
//!
//! # 重放判定规则
//!
//! 只有 `(ts, seq)` 字典序**严格递增**的 beacon 才被接受。
//!
//! 成立的前提是 `ts` 与 `seq` 都在 HMAC 认证载荷之内：攻击者无法伪造更大的值，
//! 只能重播**曾经见过**的包。而同一设备发出的包必然满足 `(ts, seq)` 单调递增，
//! 所以任何旧包都落在已见过的水位线之下，必然被拒。
//!
//! **设备重启**时 `seq` 归零，靠 `ts` 已经前进来放行（字典序首位比较）。
//! 唯一的例外是「同一秒内重启」——此时 `ts` 相等而 `seq` 倒退，会被拒一次；
//! 但下一秒的 beacon（`ts+1`）即被接受，而 TTL 是 3000ms，
//! 尚不足以掉到 `Offline`，因此对用户不可见。这个取舍是刻意的：
//! 宁可让重启的设备晚 1 秒被认出，也不放过任何一个重放包。

use crate::dto::Presence;
use crate::presence::beacon::{verify_beacon, BeaconPacket, DEVICE_ID_PREFIX_LEN};
use crate::state::presence as presence_sm;

/// 时钟偏移容忍窗口（秒）。
///
/// `seq` 单调性是重放防护的主力；`ts` 窗口是第二道闸，
/// 用来挡住「隔了很久才重播」的包（例如换了网络环境后回放）。
/// 局域网内双端时钟通常由同一个 NTP 源或路由器授时，30s 足够宽松。
pub const CLOCK_SKEW_TOLERANCE_SECS: i64 = 30;

/// 一次 beacon 的处理结论。
///
/// 拒绝原因分开建模，而不是统一返回 `false` —— 上层需要区分对待：
/// 认证失败可能是攻击，重放大多是组播重复包（正常现象，不该告警）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconVerdict {
    /// 接受，并刷新在线性
    Accepted { presence: Presence },
    /// HMAC 校验未通过：伪造、篡改，或密钥不对（配对已失效）
    RejectedAuth,
    /// `(ts, seq)` 未严格递增：重放，或组播/多网卡造成的重复包
    RejectedReplay { last: (u32, u32), got: (u32, u32) },
    /// 时间戳超出容忍窗口
    RejectedClockSkew { skew_secs: i64 },
}

/// 单个对端设备的 beacon 追踪器（每设备一个实例）。
///
/// 不含任何时钟调用：`now_unix` 与 `now_mono_ms` 都由调用方传入。
/// 这样整个模块保持可确定性测试，也避免在 core 里假定平台时钟 API。
#[derive(Debug, Clone)]
pub struct PresenceTracker {
    state: Presence,
    /// 已接受的最高水位线 `(ts, seq)`；`None` 表示尚未收到任何合法 beacon
    watermark: Option<(u32, u32)>,
    /// 上次接受 beacon 时的单调时钟读数（毫秒）
    last_accept_mono_ms: u64,
    /// 已认证的 deviceId 前缀（首个合法 beacon 确定后固定）
    device_id_prefix: Option<[u8; DEVICE_ID_PREFIX_LEN]>,
}

impl Default for PresenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl PresenceTracker {
    /// 新建追踪器：初始为 `Unknown`（从未收到过 beacon，区别于 `Offline`）
    pub fn new() -> Self {
        Self {
            state: Presence::Unknown,
            watermark: None,
            last_accept_mono_ms: 0,
            device_id_prefix: None,
        }
    }

    /// 当前在线性（不推进时间；要推进请先调 [`Self::tick`]）
    pub fn presence(&self) -> Presence {
        self.state
    }

    /// 已认证的 deviceId 前缀
    pub fn device_id_prefix(&self) -> Option<[u8; DEVICE_ID_PREFIX_LEN]> {
        self.device_id_prefix
    }

    /// 处理一个收到的 beacon 包。
    ///
    /// 顺序刻意如此：**先验 HMAC，再看 ts/seq**。
    /// 反过来的话，未认证的包就能影响水位线判断，等于给了攻击者一个
    /// 「用伪造包污染水位线、让真实包全被当成重放拒掉」的拒绝服务面。
    pub fn on_packet(
        &mut self,
        secret: &[u8],
        packet: &BeaconPacket,
        now_unix: u32,
        now_mono_ms: u64,
    ) -> BeaconVerdict {
        // 1) 认证：不可信的包一律不得影响任何内部状态
        let Some((prefix, ts, seq)) = verify_beacon(secret, packet) else {
            return BeaconVerdict::RejectedAuth;
        };

        // 2) 时钟窗口：挡住久远的重播
        let skew = i64::from(now_unix) - i64::from(ts);
        if skew.abs() > CLOCK_SKEW_TOLERANCE_SECS {
            return BeaconVerdict::RejectedClockSkew { skew_secs: skew };
        }

        // 3) 重放：(ts, seq) 必须严格递增
        if let Some(last) = self.watermark {
            if (ts, seq) <= last {
                return BeaconVerdict::RejectedReplay {
                    last,
                    got: (ts, seq),
                };
            }
        }

        // 4) 全部通过：抬高水位线并刷新在线性
        self.watermark = Some((ts, seq));
        self.last_accept_mono_ms = now_mono_ms;
        self.device_id_prefix = Some(prefix);
        self.state = presence_sm::on_beacon(self.state);
        BeaconVerdict::Accepted {
            presence: self.state,
        }
    }

    /// 按单调时钟推进在线性衰减（Online → Stale → Offline）。
    ///
    /// 用单调时钟而非墙钟：墙钟被 NTP 校正或用户改动时会跳变，
    /// 会让 TTL 判断瞬间误判为超时。
    pub fn tick(&mut self, now_mono_ms: u64) -> Presence {
        let elapsed = now_mono_ms.saturating_sub(self.last_accept_mono_ms);
        self.state = presence_sm::tick(self.state, elapsed);
        self.state
    }

    /// 设备被遗忘 / 解配对 / 会话重置。
    ///
    /// 水位线一并清空：重新配对后对端可能是全新实例（`seq` 从 0 开始），
    /// 留着旧水位线会把新设备的所有 beacon 判成重放。
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presence::beacon::sign_beacon;

    const S: &[u8] = b"pairing-secret";
    const DEV: [u8; 8] = [9, 8, 7, 6, 5, 4, 3, 2];

    fn accepted(v: &BeaconVerdict) -> bool {
        matches!(v, BeaconVerdict::Accepted { .. })
    }

    #[test]
    fn first_beacon_brings_online() {
        let mut t = PresenceTracker::new();
        assert_eq!(t.presence(), Presence::Unknown);

        let pkt = sign_beacon(S, &DEV, 1000, 1);
        let v = t.on_packet(S, &pkt, 1000, 0);
        assert_eq!(
            v,
            BeaconVerdict::Accepted {
                presence: Presence::Online
            }
        );
        assert_eq!(t.device_id_prefix(), Some(DEV));
    }

    #[test]
    fn replayed_packet_is_rejected() {
        let mut t = PresenceTracker::new();
        let pkt = sign_beacon(S, &DEV, 1000, 1);
        assert!(accepted(&t.on_packet(S, &pkt, 1000, 0)));

        // 同一个包再来一次 —— 这正是「把离线设备钉在 Online」的攻击手法
        let v = t.on_packet(S, &pkt, 1000, 500);
        assert_eq!(
            v,
            BeaconVerdict::RejectedReplay {
                last: (1000, 1),
                got: (1000, 1)
            }
        );
    }

    #[test]
    fn replay_cannot_prevent_offline_decay() {
        // 端到端验证「离线不可连接」不被重放绕过
        let mut t = PresenceTracker::new();
        let pkt = sign_beacon(S, &DEV, 1000, 1);
        t.on_packet(S, &pkt, 1000, 0);
        assert_eq!(t.presence(), Presence::Online);

        // 攻击者每 500ms 重播同一个包，试图维持 Online
        for mono in [500u64, 1000, 1500, 2000, 2500, 3000, 3500] {
            let v = t.on_packet(S, &pkt, 1000, mono);
            assert!(!accepted(&v), "重放包不得被接受（mono={mono}）");
            t.tick(mono);
        }
        // 水位线未被抬高 → TTL 照常到期
        assert_eq!(t.presence(), Presence::Offline);
    }

    #[test]
    fn seq_must_strictly_advance() {
        let mut t = PresenceTracker::new();
        assert!(accepted(&t.on_packet(
            S,
            &sign_beacon(S, &DEV, 1000, 5),
            1000,
            0
        )));

        // 倒退
        assert!(!accepted(&t.on_packet(
            S,
            &sign_beacon(S, &DEV, 1000, 4),
            1000,
            100
        )));
        // 相等
        assert!(!accepted(&t.on_packet(
            S,
            &sign_beacon(S, &DEV, 1000, 5),
            1000,
            200
        )));
        // 前进
        assert!(accepted(&t.on_packet(
            S,
            &sign_beacon(S, &DEV, 1000, 6),
            1000,
            300
        )));
    }

    #[test]
    fn device_restart_with_seq_reset_is_accepted_via_newer_ts() {
        let mut t = PresenceTracker::new();
        assert!(accepted(&t.on_packet(
            S,
            &sign_beacon(S, &DEV, 1000, 900),
            1000,
            0
        )));

        // 重启：seq 归零，但 ts 前进了 → 字典序首位比较放行
        let v = t.on_packet(S, &sign_beacon(S, &DEV, 1001, 0), 1001, 500);
        assert!(accepted(&v), "重启设备应被接受，实际 {v:?}");
    }

    #[test]
    fn forged_packet_does_not_touch_state() {
        let mut t = PresenceTracker::new();
        let good = sign_beacon(S, &DEV, 1000, 3);
        t.on_packet(S, &good, 1000, 0);

        // 用错密钥签一个「更高水位线」的包，企图污染水位线
        let forged = sign_beacon(b"attacker-secret", &DEV, 9999, 9999);
        assert_eq!(
            t.on_packet(S, &forged, 1000, 100),
            BeaconVerdict::RejectedAuth
        );

        // 水位线必须没被动过：真实设备的下一个包仍应正常接受
        let v = t.on_packet(S, &sign_beacon(S, &DEV, 1000, 4), 1000, 200);
        assert!(accepted(&v), "伪造包污染了水位线，实际 {v:?}");
    }

    #[test]
    fn stale_timestamp_rejected() {
        let mut t = PresenceTracker::new();
        // ts 比本地时间早 31s，超出 30s 窗口
        let old = sign_beacon(S, &DEV, 1000, 1);
        let v = t.on_packet(S, &old, 1031, 0);
        assert_eq!(v, BeaconVerdict::RejectedClockSkew { skew_secs: 31 });

        // 边界内（正好 30s）应放行
        let mut t2 = PresenceTracker::new();
        assert!(accepted(&t2.on_packet(S, &old, 1030, 0)));
    }

    #[test]
    fn future_timestamp_also_rejected() {
        let mut t = PresenceTracker::new();
        // 对端时钟快 31s
        let future = sign_beacon(S, &DEV, 1031, 1);
        assert_eq!(
            t.on_packet(S, &future, 1000, 0),
            BeaconVerdict::RejectedClockSkew { skew_secs: -31 }
        );
    }

    #[test]
    fn ttl_decay_uses_monotonic_clock() {
        let mut t = PresenceTracker::new();
        t.on_packet(S, &sign_beacon(S, &DEV, 1000, 1), 1000, 10_000);
        assert_eq!(t.tick(10_000), Presence::Online);
        assert_eq!(t.tick(11_499), Presence::Online);
        assert_eq!(t.tick(11_500), Presence::Stale);
        assert_eq!(t.tick(13_000), Presence::Offline);
    }

    #[test]
    fn beacon_recovers_from_stale() {
        let mut t = PresenceTracker::new();
        t.on_packet(S, &sign_beacon(S, &DEV, 1000, 1), 1000, 0);
        assert_eq!(t.tick(1600), Presence::Stale);

        // 新 beacon（seq 前进）应立刻恢复 Online
        let v = t.on_packet(S, &sign_beacon(S, &DEV, 1001, 2), 1001, 1700);
        assert_eq!(
            v,
            BeaconVerdict::Accepted {
                presence: Presence::Online
            }
        );
        assert_eq!(t.tick(1700), Presence::Online);
    }

    #[test]
    fn reset_clears_watermark_for_repairing() {
        let mut t = PresenceTracker::new();
        t.on_packet(S, &sign_beacon(S, &DEV, 5000, 900), 5000, 0);
        t.reset();
        assert_eq!(t.presence(), Presence::Unknown);

        // 重新配对后对端是全新实例：ts 更早、seq 归零也必须能接受
        let v = t.on_packet(S, &sign_beacon(S, &DEV, 4000, 0), 4000, 100);
        assert!(accepted(&v), "reset 后仍拒绝低水位线，实际 {v:?}");
    }
}
