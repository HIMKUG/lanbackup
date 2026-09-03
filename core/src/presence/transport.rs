//! presence 传输层：UDP 收发、多网卡、Android 组播锁（阶段 4 / W5、M22）
//!
//! # 分层
//!
//! 严格沿用 [`crate::transfer::session`] 的**决策与 IO 分离**：
//!
//! | 类型 | 性质 | 是否可确定性测试 |
//! |---|---|---|
//! | [`BeaconEmitter`] | 纯计算：下一个 beacon 该是什么 | 是 |
//! | [`beacon_targets`] / [`directed_broadcast`] | 纯计算：该往哪些地址发 | 是（地址计算部分） |
//! | [`PresenceSocket`] | 纯 IO：把字节送出去、收回来 | 否（需要真实网卡） |
//!
//! # 三条实测教训
//!
//! **W5 —— 只发组播是不够的。** 相当多的家用 AP 与企业 AP 默认丢弃或限速
//! IGMP 组播（尤其开了「AP 隔离」「组播优化」时），而定向广播往往还能过。
//! 反过来也有只放组播、拦广播的设备。因此 [`beacon_targets`] **同时**返回
//! 组播组与每张网卡的定向广播地址，任一条通路可达即可维持在线性。
//!
//! **M22 —— Android 必须持 `MulticastLock`。** Wi-Fi 芯片在省电态会在硬件层
//! 过滤掉组播/广播帧，应用层收不到任何包，表现为「锁屏几秒后对方全部离线」。
//! Rust 侧拿不到 `WifiManager`，因此抽象成 [`MulticastGuard`]，由 JNI 层实现。
//!
//! **多网卡不得因单卡失败而整体中断。** 双频 Wi-Fi、有线+无线共存时，
//! 某张网卡随时可能掉线（`ENETUNREACH`）。[`PresenceSocket::broadcast`] 因此
//! 逐目标发送、只统计成功数，绝不因为一个目标失败就放弃其余目标。

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;

use crate::presence::beacon::{sign_beacon, BeaconPacket, BEACON_LEN, DEVICE_ID_PREFIX_LEN};
use crate::version::DEFAULT_PORT;

/// presence 组播组。
///
/// 与 LocalSend 生态一致（`224.0.0.167`），属本地链路范围（`224.0.0.0/24`），
/// TTL=1 即可，天然不会被路由器转出局域网。
pub const MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 167);

/// presence 使用的 UDP 端口。
///
/// 与 HTTP 服务复用同一个号（`DEFAULT_PORT`）—— TCP 与 UDP 端口空间独立，
/// 不冲突。刻意不引入第二个端口常量：多一个数字就多一处配置漂移
/// （原实现的 53317/53318 双端口正是排障噩梦的来源）。
pub const PRESENCE_PORT: u16 = DEFAULT_PORT;

/// beacon 发送周期（毫秒）。与 `state::presence` 的 TTL 配套：
/// 1.5s 转 `Stale` = 允许连丢 2 个包，3s 转 `Offline` = 连丢 5 个。
pub const BEACON_INTERVAL_MS: u64 = 500;

/// 组播 TTL。本地链路组播固定 1 —— 大于 1 会把 presence 泄漏到上游网络。
pub const MULTICAST_TTL: u32 = 1;

/// 连续「整轮发送全败」多少次才判定套接字已死（W5）。
///
/// 取 3（= 1.5s）而不是 1：拔网线的瞬间单轮全败极其常见，
/// 见一次就重建会把**正常的网络抖动**变成持续的套接字抖动
/// （每 500ms 重建一次），代价远高于偶发丢一两个包。
/// 3 轮则稳稳落在「真的坏了」这一侧 —— 此时 beacon 周期 500ms、
/// 对端 1.5s 转 Stale，重建完还能赶在对端判离线之前恢复。
pub const SOCKET_FAILURE_THRESHOLD: usize = 3;

/// 发送健康度（纯计算，可确定性测试）。
///
/// W5 的核心判据：**Windows 上 UDP 套接字会偶发性整块失效** ——
/// `send_to` 开始对所有目标都返回错误，而网卡、路由、对端全是好的。
/// 把 ICMP 与路由表查一遍是白费功夫，重建套接字即可恢复。
///
/// 关键是**识别**它。若不做识别，现象是「跑着跑着所有设备都离线」，
/// 且重启进程就好，极难定位；日志里只会看到一堆 send_to 失败，
/// 与真正断网无从区分。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SendHealth {
    consecutive_failures: usize,
}

impl SendHealth {
    pub fn new() -> Self {
        Self::default()
    }

    /// 一轮发送结束后记账，`delivered` 为本轮成功送达的目标数。
    ///
    /// 判据是「整轮全败」而非「任一目标失败」：只要还有一条通路通着，
    /// 对端就仍能收到 beacon，套接字就是好的。
    pub fn on_round(&mut self, delivered: usize) {
        if delivered == 0 {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        } else {
            self.consecutive_failures = 0;
        }
    }

    pub fn consecutive_failures(&self) -> usize {
        self.consecutive_failures
    }

    /// 是否已判定为失效（触发重建）
    pub fn is_dead(&self) -> bool {
        self.consecutive_failures >= SOCKET_FAILURE_THRESHOLD
    }
}

// ============================================================
// 纯计算：下一个 beacon
// ============================================================

/// beacon 发号器（纯计算，每设备一个实例）。
///
/// 负责维护 `(ts, seq)` 的**严格单调**，这是对端
/// [`crate::presence::tracker::PresenceTracker`] 重放防护成立的前提：
/// 我们自己发出的包若不单调，会被对端当成重放丢掉，表现为「明明在发 beacon，
/// 对方却显示我离线」。
#[derive(Debug, Clone)]
pub struct BeaconEmitter {
    device_id_prefix: [u8; DEVICE_ID_PREFIX_LEN],
    seq: u32,
    last_ts: u32,
}

impl BeaconEmitter {
    /// `device_id_prefix` 取 [`crate::identity::DeviceIdentity::beacon_prefix`]
    pub fn new(device_id_prefix: [u8; DEVICE_ID_PREFIX_LEN]) -> Self {
        Self {
            device_id_prefix,
            seq: 0,
            last_ts: 0,
        }
    }

    /// 签出下一个 beacon。
    ///
    /// **墙钟回拨会被钳住**：`ts` 取 `max(now, 上次)`。NTP 校正把本机时钟往回拨
    /// 几秒是常态，若照抄回拨后的时间，`(ts, seq)` 就不再单调，对端会把我们
    /// 之后 30 秒（时钟容忍窗口）的全部 beacon 判为重放 —— 直接掉成离线。
    /// 钳住的代价只是 `ts` 短暂略微超前，仍在对端的 ±30s 容忍窗口内。
    ///
    /// 返回 `None` 仅在 `seq` 耗尽（`u32::MAX`）时发生：按 500ms 周期需要连续
    /// 运行 68 年。宁可停发也不回绕 —— 回绕会让水位线永久高于新包。
    pub fn emit(&mut self, pairing_secret: &[u8], now_unix: u32) -> Option<BeaconPacket> {
        let ts = now_unix.max(self.last_ts);
        let seq = self.seq.checked_add(1)?;
        self.seq = seq;
        self.last_ts = ts;
        Some(sign_beacon(pairing_secret, &self.device_id_prefix, ts, seq))
    }

    /// 当前序号（诊断用）
    pub fn seq(&self) -> u32 {
        self.seq
    }
}

// ============================================================
// 纯计算：往哪儿发
// ============================================================

/// 由 IP 与掩码算出定向广播地址（`ip | !netmask`）。
pub fn directed_broadcast(ip: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) | !u32::from(netmask))
}

/// 本机所有非回环 IPv4 网卡的 `(ip, netmask)`。
///
/// 回环被排除：往 `127.0.0.1` 发 presence 毫无意义，却会让"目标数 > 0"
/// 这个健康判据在完全断网时依然成立，掩盖真实故障。
pub fn local_ipv4_interfaces() -> Vec<(Ipv4Addr, Ipv4Addr)> {
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for iface in ifaces {
        if iface.is_loopback() {
            continue;
        }
        if let if_addrs::IfAddr::V4(v4) = iface.addr {
            out.push((v4.ip, v4.netmask));
        }
    }
    out
}

/// beacon 的全部发送目标，**组播优先**。
///
/// 顺序即优先级：组播最省电（一次发送、交换机复制），定向广播是 AP 拦组播时的
/// 兜底。全局广播 `255.255.255.255` 刻意**不加**：它会被绝大多数 AP 直接丢弃，
/// 却在某些安卓机型上触发 `EACCES`，白白污染日志。
pub fn beacon_targets(port: u16, group: Ipv4Addr) -> Vec<SocketAddr> {
    let mut targets = vec![SocketAddr::from((group, port))];
    for (ip, mask) in local_ipv4_interfaces() {
        let bcast = directed_broadcast(ip, mask);
        let addr = SocketAddr::from((bcast, port));
        if !targets.contains(&addr) {
            targets.push(addr);
        }
    }
    targets
}

// ============================================================
// 平台钩子：Android MulticastLock
// ============================================================

/// 组播锁抽象（M22）。
///
/// Android 需要 `WifiManager.createMulticastLock().acquire()`，否则 Wi-Fi 芯片
/// 在省电态于**硬件层**丢弃组播帧 —— 应用层完全收不到包，日志里一片安静，
/// 表现为「锁屏几秒后所有设备离线」。桌面端无此问题，用 [`NoopMulticastGuard`]。
///
/// 由 JNI/uniFFI 层实现，core 只负责在正确时机调用。
pub trait MulticastGuard: Send + Sync + std::fmt::Debug {
    /// 开始收发前获取。失败返回原因（调用方应告警但仍可继续尝试）。
    fn acquire(&self) -> Result<(), String>;
    /// 停止收发后释放。**必须释放**：持锁会显著增加待机耗电。
    fn release(&self);
}

/// 桌面端占位实现（无需组播锁）
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopMulticastGuard;

impl MulticastGuard for NoopMulticastGuard {
    fn acquire(&self) -> Result<(), String> {
        Ok(())
    }
    fn release(&self) {}
}

// ============================================================
// IO：真实 UDP 套接字
// ============================================================

/// presence 的 UDP 套接字。
///
/// 绑定 `0.0.0.0:port`，在**每张**网卡上加入组播组。
#[derive(Debug)]
pub struct PresenceSocket {
    socket: UdpSocket,
    targets: Vec<SocketAddr>,
    joined: usize,
    /// 重建套接字所需的两个参数（W5）—— bind 之后必须留着，否则死了就救不回来
    port: u16,
    group: Ipv4Addr,
    /// 发送健康度（W5）
    health: SendHealth,
    /// 组播锁（M22）。`None` 仅出现在 Drop 中临时取出时；正常运行恒为 `Some`。
    /// 桌面端为 [`NoopMulticastGuard`]，Android 端由 JNI 层经
    /// [`PresenceSocket::bind_with_guard`] 注入真实实现。
    guard: Option<Box<dyn MulticastGuard>>,
}

impl PresenceSocket {
    /// 绑定并加入组播组。
    ///
    /// 三个 socket 选项都不可省：
    /// - `SO_REUSEADDR`（Unix 上再加 `SO_REUSEPORT`）：**必须在 bind 之前设置**。
    ///   否则同一台机器上跑两个实例（桌面端 + 调试进程、或用户开了两个窗口）
    ///   第二个直接 `EADDRINUSE` 起不来。
    /// - `SO_BROADCAST`：不设则定向广播发送返回 `EACCES`，而组播被 AP 拦时
    ///   广播正是唯一通路。
    /// - `IP_MULTICAST_LOOP = true`：保留自环。收到自己的 beacon 无害
    ///   （本机不会为自己注册 tracker，验不过 HMAC 就丢），但关掉它会让
    ///   「同机双实例」的联调彻底收不到包。
    ///
    /// 绑定并加入组播组。桌面端使用 [`NoopMulticastGuard`]（无需组播锁）。
    ///
    /// 见 [`PresenceSocket::bind_with_guard`] 了解组播锁的获取时机与释放契约。
    pub fn bind(port: u16, group: Ipv4Addr) -> io::Result<Self> {
        Self::bind_with_guard(port, group, Box::new(NoopMulticastGuard))
    }

    /// 绑定并加入组播组，**并持有调用方提供的组播锁（M22）**。
    ///
    /// 成功绑定后立即 `acquire()`：组播锁必须在任何 send/recv **之前**取得，
    /// 否则 Wi-Fi 芯片在省电态会在硬件层丢弃组播帧，表现为「锁屏几秒后所有设备离线」。
    /// `acquire` 失败（如 Android 权限不足）**不致命**——仍尽量继续收发并告警，
    /// 让上层能提示用户开启权限，而不是整体起不来。
    ///
    /// 释放由 [`Drop`] 负责：套接字整个生命周期内始终持锁，收发两条路径都被覆盖。
    pub fn bind_with_guard(
        port: u16,
        group: Ipv4Addr,
        guard: Box<dyn MulticastGuard>,
    ) -> io::Result<Self> {
        Self::bind_with_guard_impl(port, group, guard, true)
    }

    /// 内部绑定实现。`acquire` 为 `true` 时在绑定时获取组播锁；为 `false` 时假定锁已由
    /// 调用方持有（如 [`Self::rebuild`] 重建时），不再重复获取——否则同一把锁会被
    /// acquire 两次，M22 语义被破坏（锁在 `Drop` 时仍只 release 一次，但计数错乱）。
    fn bind_with_guard_impl(
        port: u16,
        group: Ipv4Addr,
        guard: Box<dyn MulticastGuard>,
        acquire: bool,
    ) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
        socket.set_broadcast(true)?;
        socket.set_multicast_loop_v4(true)?;
        socket.set_multicast_ttl_v4(MULTICAST_TTL)?;
        socket.bind(&SockAddr::from(SocketAddr::from((
            Ipv4Addr::UNSPECIFIED,
            port,
        ))))?;
        socket.set_nonblocking(true)?;

        // 逐网卡加入组播组：只在默认路由那张卡上加入，双频/有线共存时
        // 另一张网段的设备就永远发现不了 —— 这是「有时能发现、有时不能」的根因。
        let mut joined = 0usize;
        for (ip, _) in local_ipv4_interfaces() {
            if socket.join_multicast_v4(&group, &ip).is_ok() {
                joined += 1;
            }
        }
        // 兜底：一张都没加上（容器/受限环境枚举不到网卡）时用 INADDR_ANY，
        // 让内核自己挑。失败也不致命 —— 定向广播通路仍然可用。
        if joined == 0
            && socket
                .join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)
                .is_ok()
        {
            joined = 1;
        }

        // M22：绑定时获取组播锁（仅当尚未持有时），失败仅告警不致命。
        if acquire {
            if let Err(e) = guard.acquire() {
                log::warn!(
                    "MulticastGuard acquire failed (beacon may be dropped by Wi-Fi chip in power-save): {e}"
                );
            }
        }

        let std_socket: std::net::UdpSocket = socket.into();
        Ok(Self {
            socket: UdpSocket::from_std(std_socket)?,
            targets: beacon_targets(port, group),
            joined,
            port,
            group,
            health: SendHealth::new(),
            guard: Some(guard),
        })
    }

    /// 成功加入组播组的网卡数。0 表示只能靠广播通路，应向用户告警。
    pub fn joined_interfaces(&self) -> usize {
        self.joined
    }

    /// 当前发送目标（组播在前）
    pub fn targets(&self) -> &[SocketAddr] {
        &self.targets
    }

    /// 本地绑定地址（诊断用）
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// 向所有目标发送一个 beacon，返回成功送达的目标数。
    ///
    /// **单个目标失败不中断其余目标**：某张网卡刚掉线会得到 `ENETUNREACH`，
    /// 若用 `?` 提前返回，同一轮里排在它后面的可用网卡就全被跳过 ——
    /// 表现为「拔掉网线后无线也发现不了设备」。
    ///
    /// 返回 0 说明一条通路都不通。
    ///
    /// 连续 [`SOCKET_FAILURE_THRESHOLD`] 轮返回 0 会触发**自动重建套接字**（W5），
    /// 无需调用方介入 —— 判据与动作都在这里，调用方只需照常调用。
    pub async fn broadcast(&mut self, packet: &BeaconPacket) -> usize {
        // W5：Windows 上 UDP 套接字会偶发性整块失效，重建即可恢复。
        // 吞掉 rebuild 的错误：bind 失败同样会体现为 delivered == 0 并在下一轮重试，
        // 让「发不出去」只有一个出口，调用方不必区分「坏了」与「建不起来」。
        if self.health.is_dead() {
            let _ = self.rebuild();
        }

        let bytes = packet.as_bytes();
        let mut ok = 0usize;
        for target in &self.targets {
            if self.socket.send_to(bytes, target).await.is_ok() {
                ok += 1;
            }
        }
        self.health.on_round(ok);
        ok
    }

    /// 重建套接字（重绑端口、重加组播组、重算目标）。
    ///
    /// 网卡会变（Wi-Fi 切换、热点开启、VPN 接入），所以目标列表也要重算 ——
    /// 只换 socket 不换 targets，会继续往已经不存在的网卡上发。
    ///
    /// 仅在成功时清零健康度：`bind` 一直失败时保持 dead，下一轮继续重试。
    /// 若失败也清零，就会退化成「每轮都重建一次」的热循环。
    pub fn rebuild(&mut self) -> io::Result<()> {
        // 保留原有组播锁（M22）：Android 的真实实现必须跨重建存活，
        // 否则锁随套接字一起丢，等于没持锁。
        let guard = self.guard.take();
        let fresh = match guard {
            // 锁已由调用方持有，重建时**不再重新 acquire**（否则同一把锁被 acquire 两次）。
            Some(g) => Self::bind_with_guard_impl(self.port, self.group, g, false)?,
            None => Self::bind(self.port, self.group)?,
        };
        *self = fresh;
        Ok(())
    }

    /// 当前发送健康度（诊断与告警用）
    pub fn health(&self) -> SendHealth {
        self.health
    }

    /// 收一个数据报。
    ///
    /// 返回 `Ok(None)` 表示收到了长度不符的包 —— 这是**正常现象**而非错误：
    /// 该端口上还有 LocalSend 的 JSON 公告等其它流量。把它当 `Err` 会让上层
    /// 误判为网络故障并触发无意义的重连。
    pub async fn recv(&self) -> io::Result<Option<(BeaconPacket, SocketAddr)>> {
        // 只读 BEACON_LEN+1 字节：多出的 1 字节用来识别"比 beacon 更长的包"，
        // 避免把一个长包的前 32 字节误当成合法 beacon。
        let mut buf = [0u8; BEACON_LEN + 1];
        let (n, from) = self.socket.recv_from(&mut buf).await?;
        Ok(BeaconPacket::from_bytes(&buf[..n]).map(|p| (p, from)))
    }
}

/// M22：套接字销毁时释放组播锁。**必须释放**——持锁会显著增加待机耗电。
///
/// 由 `bind_with_guard` 获取、`Drop` 释放，覆盖套接字整个生命周期内的收发两条路径。
impl Drop for PresenceSocket {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            guard.release();
        }
    }
}

/// 判断一个来源地址是否值得处理（过滤 IPv6 映射与自身回环噪声）
pub fn is_plausible_peer(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_unspecified(),
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presence::beacon::verify_beacon;
    use crate::presence::tracker::{BeaconVerdict, PresenceTracker};

    const SECRET: &[u8] = b"pairing-secret";
    const PREFIX: [u8; DEVICE_ID_PREFIX_LEN] = [1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn emitted_beacons_are_verifiable() {
        let mut e = BeaconEmitter::new(PREFIX);
        let pkt = e.emit(SECRET, 1000).unwrap();
        let (prefix, ts, seq) = verify_beacon(SECRET, &pkt).unwrap();
        assert_eq!(prefix, PREFIX);
        assert_eq!(ts, 1000);
        assert_eq!(seq, 1, "首个 beacon 的 seq 应为 1");
    }

    /// 发号器与对端追踪器的**端到端**契约：连续发出的包必须全部被接受。
    /// 这是 E10（文档表格必须有测试）在跨模块契约上的体现。
    #[test]
    fn consecutive_beacons_all_accepted_by_tracker() {
        let mut e = BeaconEmitter::new(PREFIX);
        let mut t = PresenceTracker::new();
        for i in 0..20u32 {
            let now = 1000 + i / 2; // 500ms 周期 → 每秒两个
            let pkt = e.emit(SECRET, now).unwrap();
            let v = t.on_packet(SECRET, &pkt, now, u64::from(i) * 500);
            assert!(
                matches!(v, BeaconVerdict::Accepted { .. }),
                "第 {i} 个 beacon 被拒：{v:?}"
            );
        }
    }

    /// NTP 把时钟往回拨，绝不能让我们的 beacon 被对端当成重放。
    #[test]
    fn wall_clock_rollback_does_not_break_monotonicity() {
        let mut e = BeaconEmitter::new(PREFIX);
        let mut t = PresenceTracker::new();

        let p1 = e.emit(SECRET, 2000).unwrap();
        assert!(matches!(
            t.on_packet(SECRET, &p1, 2000, 0),
            BeaconVerdict::Accepted { .. }
        ));

        // 本机时钟被回拨 5 秒；对端时钟没变（仍在 2000 附近）
        let p2 = e.emit(SECRET, 1995).unwrap();
        let v = t.on_packet(SECRET, &p2, 2000, 500);
        assert!(
            matches!(v, BeaconVerdict::Accepted { .. }),
            "时钟回拨后 beacon 被拒，本机会被误判离线：{v:?}"
        );
    }

    #[test]
    fn seq_exhaustion_stops_emitting_instead_of_wrapping() {
        let mut e = BeaconEmitter::new(PREFIX);
        e.seq = u32::MAX - 1;
        assert!(e.emit(SECRET, 10).is_some());
        assert_eq!(e.seq(), u32::MAX);
        assert!(e.emit(SECRET, 11).is_none(), "耗尽后必须停发，不得回绕");
    }

    #[test]
    fn directed_broadcast_matches_netmask() {
        assert_eq!(
            directed_broadcast(
                Ipv4Addr::new(192, 168, 1, 7),
                Ipv4Addr::new(255, 255, 255, 0)
            ),
            Ipv4Addr::new(192, 168, 1, 255)
        );
        assert_eq!(
            directed_broadcast(Ipv4Addr::new(10, 3, 200, 9), Ipv4Addr::new(255, 255, 0, 0)),
            Ipv4Addr::new(10, 3, 255, 255)
        );
        // /31 这类点对点链路也不能算错
        assert_eq!(
            directed_broadcast(
                Ipv4Addr::new(172, 16, 0, 4),
                Ipv4Addr::new(255, 255, 255, 252)
            ),
            Ipv4Addr::new(172, 16, 0, 7)
        );
    }

    #[test]
    fn multicast_target_comes_first_and_targets_are_unique() {
        let targets = beacon_targets(PRESENCE_PORT, MULTICAST_GROUP);
        assert_eq!(
            targets[0],
            SocketAddr::from((MULTICAST_GROUP, PRESENCE_PORT))
        );
        let mut seen = std::collections::HashSet::new();
        for t in &targets {
            assert!(seen.insert(*t), "目标重复会导致同一 beacon 发两遍：{t}");
        }
    }

    #[test]
    fn multicast_group_is_link_local_scope() {
        // 224.0.0.0/24 是本地链路范围，路由器不转发 —— presence 不该跨网段泄漏
        assert!(MULTICAST_GROUP.is_multicast());
        assert_eq!(MULTICAST_GROUP.octets()[..3], [224, 0, 0]);
        assert_eq!(MULTICAST_TTL, 1);
    }

    #[test]
    fn presence_port_reuses_http_port_constant() {
        // C10：不允许出现第二个端口数字
        assert_eq!(PRESENCE_PORT, DEFAULT_PORT);
    }

    #[test]
    fn beacon_interval_leaves_room_for_packet_loss() {
        // TTL 1500ms/3000ms 对应容忍连丢 2 个 / 5 个包
        assert_eq!(1500 / BEACON_INTERVAL_MS, 3);
        assert_eq!(3000 / BEACON_INTERVAL_MS, 6);
    }

    #[test]
    fn loopback_is_not_a_plausible_peer() {
        assert!(!is_plausible_peer(&"127.0.0.1:53317".parse().unwrap()));
        assert!(!is_plausible_peer(&"0.0.0.0:53317".parse().unwrap()));
        assert!(is_plausible_peer(&"192.168.1.9:53317".parse().unwrap()));
        assert!(!is_plausible_peer(&"[::1]:53317".parse().unwrap()));
    }

    /// W5 的全部判据集中在这三条：见一次全败不算坏、连续三次才算、
    /// 但只要还有一条通路通着就立刻恢复健康。
    #[test]
    fn a_single_failed_round_is_not_a_dead_socket() {
        let mut h = SendHealth::new();
        h.on_round(0);
        assert!(
            !h.is_dead(),
            "拔网线的瞬间全败很常见，见一次就重建会让网络抖动变成套接字抖动"
        );
        h.on_round(0);
        assert!(!h.is_dead());
        h.on_round(0);
        assert!(h.is_dead(), "连续 3 轮全败才判定套接字已死（W5）");
        assert_eq!(h.consecutive_failures(), 3);
    }

    #[test]
    fn one_delivered_target_resets_health() {
        let mut h = SendHealth::new();
        h.on_round(0);
        h.on_round(0);
        h.on_round(1);
        assert_eq!(
            h.consecutive_failures(),
            0,
            "只要还有一条通路通着，套接字就是好的"
        );
        assert!(!h.is_dead());
    }

    #[test]
    fn failure_counter_saturates_instead_of_overflowing() {
        let mut h = SendHealth::new();
        for _ in 0..100 {
            h.on_round(0);
        }
        assert!(h.is_dead());
        assert!(h.consecutive_failures() < usize::MAX);
    }

    #[test]
    fn noop_guard_is_always_ok() {
        let g = NoopMulticastGuard;
        assert!(g.acquire().is_ok());
        g.release();
    }

    /// M22 端到端验证：组播锁必须在 `bind_with_guard` 时 acquire，
    /// 并在 `PresenceSocket` 被 drop 时 release。这条测试锁死了「收发两条路径
    /// 全生命周期持锁」的契约，避免日后重构把锁的获取/释放时机改错。
    #[test]
    fn multicast_guard_acquired_on_bind_and_released_on_drop() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        #[derive(Clone, Debug)]
        struct RecordingGuard {
            acquired: Arc<AtomicUsize>,
            released: Arc<AtomicUsize>,
        }
        impl MulticastGuard for RecordingGuard {
            fn acquire(&self) -> Result<(), String> {
                self.acquired.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            fn release(&self) {
                self.released.fetch_add(1, Ordering::SeqCst);
            }
        }

        let acquired = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicUsize::new(0));
        let guard = RecordingGuard {
            acquired: acquired.clone(),
            released: released.clone(),
        };

        // `bind_with_guard` 内部经 `UdpSocket::from_std` 注册到 tokio reactor，
        // 必须在运行时上下文里调用；测试用 `current_thread` 运行时包住它。
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let sock = rt
            .block_on(async {
                PresenceSocket::bind_with_guard(49152, MULTICAST_GROUP, Box::new(guard))
            })
            .expect("绑定应成功");
        assert_eq!(
            acquired.load(Ordering::SeqCst),
            1,
            "bind_with_guard 必须立即 acquire 组播锁"
        );
        assert_eq!(
            released.load(Ordering::SeqCst),
            0,
            "add 发布前不应释放"
        );

        drop(sock);
        assert_eq!(
            released.load(Ordering::SeqCst),
            1,
            "PresenceSocket 销毁时必须 release 组播锁"
        );
    }

    /// M22 + Drop 重建：套接字重建（`rebuild`）必须保留原有的组播锁，
    /// 不能因借不到 guard 而丢锁。验证重建后总 acquire 次数仍为 1（未重复获取）、release 仍为 0。
    #[test]
    fn rebuild_preserves_multicast_guard() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        #[derive(Clone, Debug)]
        struct RecordingGuard {
            acquired: Arc<AtomicUsize>,
            released: Arc<AtomicUsize>,
        }
        impl MulticastGuard for RecordingGuard {
            fn acquire(&self) -> Result<(), String> {
                self.acquired.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            fn release(&self) {
                self.released.fetch_add(1, Ordering::SeqCst);
            }
        }

        let acquired = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicUsize::new(0));
        let guard = RecordingGuard {
            acquired: acquired.clone(),
            released: released.clone(),
        };

        // 同样需要 tokio 运行时上下文：`bind_with_guard` 与 `rebuild` 都会创建
        // `UdpSocket`（经 `from_std` 注册 reactor）。
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let sock = rt
            .block_on(async {
                let mut s =
                    PresenceSocket::bind_with_guard(49153, MULTICAST_GROUP, Box::new(guard))
                        .expect("绑定应成功");
                s.rebuild().expect("重建应成功");
                s
            });
        assert_eq!(acquired.load(Ordering::SeqCst), 1, "重建不得重新 acquire");
        assert_eq!(released.load(Ordering::SeqCst), 0);

        drop(sock);
        assert_eq!(released.load(Ordering::SeqCst), 1, "销毁时释放一次即可");
    }
}
