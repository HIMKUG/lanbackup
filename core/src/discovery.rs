//! 设备发现（阶段 5）：组播 + /24 子网探测
//!
//! # 为什么 beacon 之外还要主动探测
//!
//! [`crate::presence`] 的 beacon 是「我在」的**通告**，只有对端也在发、
//! 且报文通路不被丢，才收得到。至少三类真实场景靠 beacon 永远发现不了：
//!
//! 1. **冷启动**：我刚上线，对端的下一个 beacon 还没到。桌面端最多等 500ms，
//!    但移动端锁屏降频后发送周期常被拉长到数秒，首屏会长时间空白。
//! 2. **组播与广播同时被拦**：企业网络与公共 Wi-Fi 的「AP 隔离」正是如此，
//!    此时 W5 的双通路（组播+定向广播）**两条一起死**。
//! 3. **跨网段**：beacon 的 `MULTICAST_TTL = 1` 不出网段，而备份目标
//!    常常在另一个子网（手机走 2.4G、NAS 走有线 VLAN）。
//!
//! 本模块提供第二条通路：**逐个地址发 `GET /api/v4/probe`**。
//!
//! | 通路 | 单轮代价 | 覆盖 |
//! |---|---|---|
//! | 组播/广播 beacon（`presence`） | 每 500ms 一个包 | 同网段、组播未被拦 |
//! | 子网 HTTP 探测（本模块） | 每地址一次 GET | 同网段 + 可路由的邻网段 |
//!
//! # 为什么是 /24，而不是「按实际掩码扫」
//!
//! 文档 §五 写的是「/24 子网探测」。掩码比 /24 更宽时（`/8`、`/16` 在企业网
//! 与运营商级 NAT 后很常见），按实际掩码扫意味着 **一千六百万个地址** ——
//! 不是慢，是**永远扫不完**，而扫描本身会打满 ARP 表、触发交换机告警。
//!
//! 因此 [`scan_prefix`] 把掩码**收窄到至少 /24**：无论实际掩码多宽，
//! 每张网卡最多扫 254 个地址。这是能力上的自觉让步，不是遗漏 ——
//! 更宽的网段该靠路由与手工录入，不该靠暴力扫描。
//!
//! # 分层
//!
//! 沿用全 crate 的**决策与 IO 分离**：
//!
//! | 类型 | 性质 | 可确定性测试 |
//! |---|---|---|
//! | [`subnet_hosts`] / [`scan_targets`] / [`prioritize_known`] | 纯计算：该探谁、按什么顺序 | 是 |
//! | [`ProbeWave`] | 纯计算：并发窗口 | 是 |
//! | [`should_drop_self`] | 纯计算：发现结果自过滤（M34） | 是 |
//! | [`probe_one`] / [`probe_all`] | 纯 IO：真的发请求 | 否（需要网络） |

use std::collections::{BTreeSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::identity::DeviceIdentity;
use crate::routes;

/// 子网探测的掩码**下限**（即最多扫到 /24）。
///
/// 见模块文档的「为什么是 /24」：更宽的网段不该靠暴力扫描。
pub const SCAN_PREFIX_MIN: u32 = 24;

/// 一轮扫描的地址总量上限。
///
/// 254 × 4 张网卡。超过就截断 —— 截断是**静默**不了的，
/// 调用方应比对 [`scan_targets`] 的长度与网卡数自行判断是否需要告警。
pub const MAX_SCAN_HOSTS: usize = 1024;

/// 单个探测的超时。
///
/// 局域网 RTT 通常 < 5ms；700ms 足够覆盖一次 Wi-Fi 重传，
/// 又短到能让 254 个地址在 64 并发下于 3 秒内跑完一轮。
pub const PROBE_TIMEOUT_MS: u64 = 700;

/// 并发探测数。
///
/// 64 是实测的折中：再高会在家用路由器上把 ARP 表打满，
/// 表现为「一扫描，全家断网几秒」。
pub const PROBE_CONCURRENCY: usize = 64;

// ============================================================
// 纯计算：掩码与网段
// ============================================================

/// 掩码是否是连续的 `111...000`。
///
/// 非连续掩码（如 `255.0.255.0`）在 CIDR 体系里不合法，现实中只出现在
/// 手工配错或某些 ACL 场景。它的「网段」没有良定义，
/// 按它算主机范围会得出一堆毫无意义的地址，故一律识别并降级处理。
pub fn is_contiguous_netmask(nm: Ipv4Addr) -> bool {
    // 连续掩码取反后形如 0...011...1，即 2^k - 1，满足 (x & (x+1)) == 0
    let inv = !u32::from(nm);
    inv & (inv.wrapping_add(1)) == 0
}

/// 掩码的 CIDR 前缀长度；非连续掩码返回 `None`。
pub fn prefix_len(nm: Ipv4Addr) -> Option<u32> {
    if !is_contiguous_netmask(nm) {
        return None;
    }
    Some(u32::from(nm).count_ones())
}

/// 实际用于扫描的前缀长度：取 `max(掩码前缀, /24)`。
///
/// 非连续掩码按 /24 处理（它的前缀长度没有意义，但不能因此放弃这张网卡 ——
/// 用户配错了掩码，设备还是得能被发现）。
pub fn scan_prefix(nm: Ipv4Addr) -> u32 {
    prefix_len(nm)
        .unwrap_or(SCAN_PREFIX_MIN)
        .max(SCAN_PREFIX_MIN)
}

/// 枚举该网卡所在网段内**值得探测**的主机地址。
///
/// 排除三类：
/// - **网络号**与**广播地址**：广播地址上不会有 HTTP 服务，
///   而往它发包会被交换机复制到全网段，是纯粹的自伤。
/// - **本机自身**：自己探自己毫无意义，却会让「发现列表」里出现一个
///   永远连不上的自己。
///
/// `/31`、`/32`（点对点链路、单地址）没有可用主机位，返回空。
pub fn subnet_hosts(ip: Ipv4Addr, nm: Ipv4Addr) -> Vec<Ipv4Addr> {
    let p = scan_prefix(nm);
    if p >= 31 {
        return Vec::new();
    }
    let mask = u32::MAX << (32 - p);
    let net = u32::from(ip) & mask;
    let size = 1u32 << (32 - p);
    let first = net + 1;
    let last = net + size - 2; // 去掉广播地址
    (first..=last)
        .filter(|a| *a != u32::from(ip))
        .map(Ipv4Addr::from)
        .collect()
}

/// 由网卡列表算出全部探测目标：**去重**、**按 IP 数值升序**、**限量**。
///
/// 用 `BTreeSet` 而非 `Vec` + 排序：双网卡（有线+无线同网段）时同一地址
/// 会重复出现，而重复探测会白白翻倍一轮的耗时。
/// 升序是为了让多轮扫描的顺序稳定 —— 顺序抖动会让「扫到第几个」这类
/// 日志变得毫无参考价值。
pub fn scan_targets(ifaces: &[(Ipv4Addr, Ipv4Addr)], port: u16) -> Vec<SocketAddr> {
    let mut set: BTreeSet<u32> = BTreeSet::new();
    for (ip, nm) in ifaces {
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        for h in subnet_hosts(*ip, *nm) {
            if set.len() >= MAX_SCAN_HOSTS {
                break;
            }
            set.insert(u32::from(h));
        }
    }
    set.into_iter()
        .map(|a| SocketAddr::from((Ipv4Addr::from(a), port)))
        .collect()
}

/// 把历史已知设备的 IP **提到队首**，并保证不重复。
///
/// 已知设备（上次连过的、已配对的）命中率远高于盲扫：一轮 254 个地址里
/// 通常只有一两个是真的。把它们排在最前面，用户看到「设备上线」的延迟
/// 从「扫完一整轮」降到「第一个请求返回」。
///
/// `known` 里重复的地址只保留首次出现的位置（保序）。
pub fn prioritize_known(targets: &[SocketAddr], known: &[Ipv4Addr], port: u16) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::with_capacity(targets.len() + known.len());
    let mut seen: BTreeSet<Ipv4Addr> = BTreeSet::new();

    for ip in known {
        if ip.is_loopback() || ip.is_unspecified() || !seen.insert(*ip) {
            continue;
        }
        out.push(SocketAddr::from((*ip, port)));
    }
    for t in targets {
        if let SocketAddr::V4(v4) = t {
            if seen.insert(*v4.ip()) {
                out.push(*t);
            }
        }
    }
    out
}

// ============================================================
// 纯计算：并发窗口
// ============================================================

/// 探测并发窗口（纯状态机，不含 IO）。
///
/// 单独建模而非直接 `buffer_unordered(n)`，是为了让「并发上限」这条
/// 约束可以被**确定性测试**。ARP 打满这类故障只在真机上以「全家断网」
/// 的形式出现，单元测试抓不到，只能靠这里钉住。
#[derive(Debug, Clone)]
pub struct ProbeWave {
    pending: VecDeque<SocketAddr>,
    inflight: usize,
    concurrency: usize,
}

impl ProbeWave {
    pub fn new(targets: Vec<SocketAddr>, concurrency: usize) -> Self {
        Self {
            pending: targets.into(),
            inflight: 0,
            // 0 会让窗口永远取不到地址、循环直接空转退出（静默什么都没探）。
            // 与其留一个「什么都不做」的合法输入，不如兜底成 1。
            concurrency: concurrency.max(1),
        }
    }

    /// 取出本批可发送的地址（数量 = 空闲槽位数，可能少于 concurrency）。
    pub fn take(&mut self) -> Vec<SocketAddr> {
        let free = self.concurrency.saturating_sub(self.inflight);
        let mut out = Vec::with_capacity(free.min(self.pending.len()));
        for _ in 0..free {
            match self.pending.pop_front() {
                Some(a) => out.push(a),
                None => break,
            }
        }
        self.inflight += out.len();
        out
    }

    /// 归还 `n` 个槽位（无论成功失败都必须调用，否则窗口会永久泄漏）。
    pub fn complete(&mut self, n: usize) {
        self.inflight = self.inflight.saturating_sub(n);
    }

    /// 全部地址都已发出且已归还
    pub fn is_done(&self) -> bool {
        self.pending.is_empty() && self.inflight == 0
    }

    pub fn remaining(&self) -> usize {
        self.pending.len()
    }

    pub fn inflight(&self) -> usize {
        self.inflight
    }

    pub fn concurrency(&self) -> usize {
        self.concurrency
    }
}

// ============================================================
// IO：真的发请求
// ============================================================

/// 单个地址的探测结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    /// 返回 2xx —— 是 lanbackup V4 服务
    Reachable,
    /// 连上了但不对（别的 HTTP 服务 / 非 2xx）—— 不是我们的设备
    Foreign,
    /// 连不通（超时、拒绝、不可达）
    Unreachable,
}

impl ProbeResult {
    pub fn is_reachable(self) -> bool {
        matches!(self, ProbeResult::Reachable)
    }
}

/// 建一个适用于局域网探测的 HTTP 客户端。
///
/// **刻意关掉系统代理**：开发机上常挂着 HTTP 代理（Clash / 公司 PAC），
/// 若不关，对 `192.168.x.x` 的探测会被送去代理，全部超时 ——
/// 表现为「在本机怎么都扫不到设备」，而手机上一装就好。
///
/// 这是登记表里「环境差异导致的实现分叉」的典型：本机与真机行为不一致，
/// 且不一致的方向恰好让开发机看起来是坏的。
pub fn probe_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(PROBE_TIMEOUT_MS))
        .build()
        .map_err(|e| format!("构造探测客户端失败: {e}"))
}

/// 探测单个地址。
///
/// 用 [`routes::PROBE`] 常量而非字面量，避免与服务端再次漂移。
pub async fn probe_one(client: &reqwest::Client, addr: SocketAddr) -> (SocketAddr, ProbeResult) {
    let url = routes::url(&format!("http://{addr}"), routes::PROBE);
    let outcome = match client.get(url).send().await {
        Ok(resp) if resp.status().is_success() => ProbeResult::Reachable,
        Ok(_) => ProbeResult::Foreign,
        Err(_) => ProbeResult::Unreachable,
    };
    (addr, outcome)
}

/// 按并发窗口探测全部地址，返回按完成顺序排列的结果。
///
/// 顺序**不**保证与输入一致（哪个先返回就先入列），调用方需要稳定顺序时
/// 请自行排序 —— 排序是调用方的展示需求，不该让 IO 层为此串行等待。
pub async fn probe_all(
    client: &reqwest::Client,
    targets: Vec<SocketAddr>,
    concurrency: usize,
) -> Vec<(SocketAddr, ProbeResult)> {
    let mut wave = ProbeWave::new(targets, concurrency);
    let mut out = Vec::new();
    while !wave.is_done() {
        let batch = wave.take();
        if batch.is_empty() {
            break;
        }
        let n = batch.len();
        let futs: Vec<_> = batch.into_iter().map(|a| probe_one(client, a)).collect();
        out.extend(futures_util::future::join_all(futs).await);
        wave.complete(n);
    }
    out
}

/// 从探测结果中筛出可达地址并**排序**（IP 数值升序）。
pub fn reachable(results: &[(SocketAddr, ProbeResult)]) -> Vec<SocketAddr> {
    let mut v: Vec<SocketAddr> = results
        .iter()
        .filter(|(_, r)| r.is_reachable())
        .map(|(a, _)| *a)
        .collect();
    v.sort_unstable();
    v
}

// ============================================================
// 纯计算：发现结果自过滤（M34）
// ============================================================

/// 该 fingerprint 是否应被丢弃（不进入设备列表）。
///
/// M34 修复：设备广播/探测响应的 `fingerprint` 是**完整 deviceId**
/// （16 字节 hex），**不是** 8 位连接码。旧实现（Java `LocalReceiverPlugin`
/// 的 `selfCode` 参数）拿 fingerprint 与本地 8 位连接码比较 —— 两者长度不同、
/// 永不相等，于是设备**把自己扫进设备列表**（DESIGN-WISDOM-REGISTER M34）。
///
/// 自过滤必须拿 peer fingerprint 与本地 [`DeviceIdentity::device_id`]
/// （完整 ID）比较。函数以本地身份为参数（调用方注入），内部只读
/// `device_id`，在类型层面杜绝「拿连接码来比」的复发。
///
/// 空 fingerprint 同样丢弃：无身份的报文无法去重/识别，入列只会污染列表
/// （旧实现同样丢弃空值）。
pub fn should_drop_self(fingerprint: &str, local: &DeviceIdentity) -> bool {
    fingerprint.is_empty() || fingerprint == local.device_id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::DEFAULT_PORT;

    fn nm(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }
    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    // ── 掩码 ──────────────────────────────────────────────

    #[test]
    fn contiguous_netmasks_are_recognized() {
        assert!(is_contiguous_netmask(nm(255, 255, 255, 0)));
        assert!(is_contiguous_netmask(nm(255, 255, 0, 0)));
        assert!(is_contiguous_netmask(nm(255, 0, 0, 0)));
        assert!(is_contiguous_netmask(nm(255, 255, 255, 252)));
        assert!(is_contiguous_netmask(nm(0, 0, 0, 0)));
        assert!(is_contiguous_netmask(nm(255, 255, 255, 255)));
        // 非连续：中间断开
        assert!(!is_contiguous_netmask(nm(255, 0, 255, 0)));
        assert!(!is_contiguous_netmask(nm(255, 255, 0, 255)));
    }

    #[test]
    fn prefix_len_matches_cidr() {
        assert_eq!(prefix_len(nm(255, 255, 255, 0)), Some(24));
        assert_eq!(prefix_len(nm(255, 255, 0, 0)), Some(16));
        assert_eq!(prefix_len(nm(255, 255, 255, 252)), Some(30));
        assert_eq!(prefix_len(nm(0, 0, 0, 0)), Some(0));
        assert_eq!(prefix_len(nm(255, 0, 255, 0)), None, "非连续掩码无前缀长度");
    }

    /// 无论掩码多宽，扫描范围一律收窄到 /24 —— 否则 `/8` 是一千六百万个地址。
    #[test]
    fn scan_prefix_never_wider_than_24() {
        assert_eq!(scan_prefix(nm(255, 0, 0, 0)), 24, "/8 必须收窄到 /24");
        assert_eq!(scan_prefix(nm(255, 255, 0, 0)), 24, "/16 必须收窄到 /24");
        assert_eq!(scan_prefix(nm(255, 255, 255, 0)), 24);
        assert_eq!(scan_prefix(nm(255, 255, 255, 192)), 26, "比 /24 窄的应保留");
        // 非连续掩码：没有前缀长度可言，但不能放弃这张网卡
        assert_eq!(scan_prefix(nm(255, 0, 255, 0)), 24);
    }

    // ── 网段枚举 ──────────────────────────────────────────

    #[test]
    fn subnet_hosts_excludes_network_broadcast_and_self() {
        let hosts = subnet_hosts(ip(192, 168, 1, 7), nm(255, 255, 255, 0));
        assert_eq!(hosts.len(), 253, "254 个可用地址减去本机自己");
        assert!(!hosts.contains(&ip(192, 168, 1, 0)), "网络号不得探测");
        assert!(!hosts.contains(&ip(192, 168, 1, 255)), "广播地址不得探测");
        assert!(!hosts.contains(&ip(192, 168, 1, 7)), "本机不得探测自己");
        assert!(hosts.contains(&ip(192, 168, 1, 1)));
        assert!(hosts.contains(&ip(192, 168, 1, 254)));
    }

    /// `/8` 掩码也只扫本机所在 /24 —— 这是本模块最重要的收敛决策。
    #[test]
    fn wide_netmask_is_clamped_to_the_local_slash24() {
        let hosts = subnet_hosts(ip(10, 3, 200, 9), nm(255, 0, 0, 0));
        assert_eq!(hosts.len(), 253);
        assert!(hosts.iter().all(|h| h.octets()[..3] == [10, 3, 200]));
    }

    #[test]
    fn point_to_point_prefixes_have_no_hosts() {
        // /30 共 4 个地址：网络号 + 2 个可用 + 广播，再去掉本机自己 → 1 个
        assert_eq!(
            subnet_hosts(ip(10, 0, 0, 1), nm(255, 255, 255, 252)).len(),
            1
        );
        assert!(
            subnet_hosts(ip(10, 0, 0, 1), nm(255, 255, 255, 254)).is_empty(),
            "/31 无主机位"
        );
        assert!(
            subnet_hosts(ip(10, 0, 0, 1), nm(255, 255, 255, 255)).is_empty(),
            "/32 无主机位"
        );
    }

    #[test]
    fn loopback_interface_yields_no_targets() {
        let t = scan_targets(&[(ip(127, 0, 0, 1), nm(255, 0, 0, 0))], DEFAULT_PORT);
        assert!(t.is_empty(), "回环不是局域网，扫它只会得到自己");
    }

    #[test]
    fn overlapping_interfaces_are_deduplicated_and_sorted() {
        // 有线与无线恰好同网段
        let t = scan_targets(
            &[
                (ip(192, 168, 1, 7), nm(255, 255, 255, 0)),
                (ip(192, 168, 1, 42), nm(255, 255, 255, 0)),
            ],
            DEFAULT_PORT,
        );
        let ips: Vec<u32> = t
            .iter()
            .filter_map(|s| match s {
                SocketAddr::V4(v) => Some(u32::from(*v.ip())),
                _ => None,
            })
            .collect();
        let mut sorted = ips.clone();
        sorted.sort_unstable();
        assert_eq!(ips, sorted, "目标必须按 IP 数值升序");
        assert_eq!(
            ips.len(),
            ips.iter().collect::<BTreeSet<_>>().len(),
            "重复地址会翻倍一轮耗时"
        );
        assert!(ips.len() <= MAX_SCAN_HOSTS);
    }

    // ── 已知设备优先 ──────────────────────────────────────

    #[test]
    fn known_hosts_come_first_and_are_not_duplicated() {
        let targets = scan_targets(&[(ip(192, 168, 1, 7), nm(255, 255, 255, 0))], DEFAULT_PORT);
        let known = vec![
            ip(192, 168, 1, 200),
            ip(192, 168, 1, 200),
            ip(192, 168, 1, 9),
        ];
        // 已知设备里放一个不在扫描范围内的（另一个网段），它仍应被优先探测
        let out = prioritize_known(&targets, &[ip(10, 0, 0, 5)], DEFAULT_PORT);
        assert_eq!(
            out[0].ip(),
            ip(10, 0, 0, 5),
            "已知设备即使不在本网段也必须优先"
        );

        let out = prioritize_known(&targets, &known, DEFAULT_PORT);
        assert_eq!(out[0].ip(), ip(192, 168, 1, 200));
        assert_eq!(out[1].ip(), ip(192, 168, 1, 9), "重复的已知地址只保留一次");
        let all: BTreeSet<_> = out.iter().map(|s| s.ip()).collect();
        assert_eq!(all.len(), out.len(), "输出不得含重复地址");
    }

    #[test]
    fn prioritize_known_drops_loopback_and_unspecified() {
        let out = prioritize_known(&[], &[ip(127, 0, 0, 1), ip(0, 0, 0, 0)], DEFAULT_PORT);
        assert!(out.is_empty());
    }

    // ── 并发窗口 ──────────────────────────────────────────

    #[test]
    fn wave_never_exceeds_concurrency() {
        let targets: Vec<SocketAddr> = (1..=10u8)
            .map(|i| SocketAddr::from((ip(10, 0, 0, i), DEFAULT_PORT)))
            .collect();
        let mut w = ProbeWave::new(targets, 4);
        let b1 = w.take();
        assert_eq!(b1.len(), 4);
        assert_eq!(w.inflight(), 4);
        // 未归还槽位前，取不到新地址
        assert!(w.take().is_empty());
        w.complete(4);
        assert_eq!(w.take().len(), 4);
        w.complete(4);
        assert_eq!(w.take().len(), 2, "只剩 2 个");
        w.complete(2);
        assert!(w.is_done());
    }

    #[test]
    fn zero_concurrency_falls_back_to_one_instead_of_spinning() {
        let mut w = ProbeWave::new(vec![SocketAddr::from((ip(10, 0, 0, 1), DEFAULT_PORT))], 0);
        assert_eq!(w.concurrency(), 1);
        assert_eq!(w.take().len(), 1, "并发 0 若允许，扫描会静默什么都不做");
    }

    #[test]
    fn completing_more_than_inflight_does_not_underflow() {
        let mut w = ProbeWave::new(vec![], 4);
        w.complete(10);
        assert_eq!(w.inflight(), 0, "saturating_sub，不得下溢");
        assert!(w.is_done());
    }

    // ── 结果筛选 ──────────────────────────────────────────

    #[test]
    fn reachable_filters_and_sorts() {
        let r = vec![
            (
                SocketAddr::from((ip(10, 0, 0, 9), DEFAULT_PORT)),
                ProbeResult::Reachable,
            ),
            (
                SocketAddr::from((ip(10, 0, 0, 2), DEFAULT_PORT)),
                ProbeResult::Reachable,
            ),
            (
                SocketAddr::from((ip(10, 0, 0, 5), DEFAULT_PORT)),
                ProbeResult::Foreign,
            ),
            (
                SocketAddr::from((ip(10, 0, 0, 3), DEFAULT_PORT)),
                ProbeResult::Unreachable,
            ),
        ];
        assert_eq!(
            reachable(&r),
            vec![
                SocketAddr::from((ip(10, 0, 0, 2), DEFAULT_PORT)),
                SocketAddr::from((ip(10, 0, 0, 9), DEFAULT_PORT)),
            ]
        );
    }

    // ── 自过滤（M34） ─────────────────────────────────────

    /// 广播 fingerprint 恰好等于本地完整 deviceId → 必须被丢弃。
    ///
    /// 这正是旧实现的死穴：它拿 fingerprint 跟 8 位连接码比，永不相等，
    /// 于是设备把自己扫进设备列表。
    #[test]
    fn own_device_id_fingerprint_is_dropped() {
        let local = DeviceIdentity::generate();
        // 本地 identity 的完整 deviceId（32 hex 字符）作为"收到的广播 fingerprint"
        assert!(
            should_drop_self(local.device_id(), &local),
            "自己的 fingerprint（完整 deviceId）必须被过滤，不得进入设备列表"
        );
    }

    /// 对端设备的 fingerprint（合法 16 字节 hex）≠ 本地 deviceId → 必须保留。
    #[test]
    fn peer_device_id_fingerprint_is_kept() {
        let local = DeviceIdentity::generate();
        // 对端设备合法的完整 deviceId（16 字节 hex）
        let peer = "0123456789abcdef0123456789abcdef";
        assert_ne!(local.device_id(), peer);
        assert!(
            !should_drop_self(peer, &local),
            "对端设备的 fingerprint 必须保留"
        );
    }

    /// 空 fingerprint：无身份的报文无法识别/去重，同样丢弃（旧实现同此）。
    #[test]
    fn empty_fingerprint_is_dropped() {
        let local = DeviceIdentity::generate();
        assert!(should_drop_self("", &local));
    }

    /// 192.0.2.0/24 是 RFC 5737 的 TEST-NET-1，保证不可路由。
    ///
    /// 这条测试守的是「探测必须返回 Unreachable 而不是 panic / 挂死」：
    /// 一个超时的探测若不设 timeout，会一直挂着，把整个扫描卡死。
    #[tokio::test]
    async fn probing_a_blackhole_address_yields_unreachable() {
        // TLS provider 缺失时构造会失败，此时跳过而不是让测试假红
        let client = match probe_client() {
            Ok(c) => c,
            Err(_) => return,
        };
        let (addr, r) =
            probe_one(&client, SocketAddr::from((ip(192, 0, 2, 1), DEFAULT_PORT))).await;
        assert_eq!(addr.ip(), ip(192, 0, 2, 1));
        assert_eq!(r, ProbeResult::Unreachable);
    }

    #[tokio::test]
    async fn probe_all_drains_the_whole_wave() {
        let client = match probe_client() {
            Ok(c) => c,
            Err(_) => return,
        };
        let targets: Vec<SocketAddr> = (1..=5u8)
            .map(|i| SocketAddr::from((ip(192, 0, 2, i), DEFAULT_PORT)))
            .collect();
        let out = probe_all(&client, targets, 2).await;
        assert_eq!(out.len(), 5, "并发窗口必须把所有地址都发完");
    }

    #[test]
    fn scan_port_reuses_the_single_port_constant() {
        // C10：扫描目标也必须落在 DEFAULT_PORT 上
        let t = scan_targets(&[(ip(192, 168, 1, 7), nm(255, 255, 255, 0))], DEFAULT_PORT);
        assert!(t.iter().all(|s| s.port() == DEFAULT_PORT));
    }
}
