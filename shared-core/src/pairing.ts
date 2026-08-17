/**
 * pairing.ts - 配对信任记录（两端共用）
 *
 * 配对流程（自动配对 / 手动配对）：
 * 1. 扫描阶段：设备广播「设备名 + 公开 deviceId」（不是连接码）；
 * 2. 用户输入对方屏幕上显示的连接码 → 通过 /verify 端点让对方本地比对
 *    （连接码永不在网络上传输给第三方、也不在 register/info 响应中暴露）；
 * 3. 验证通过 → 生成信任记录（PairRecord，类似证书）持久化；
 * 4. 再次发现同一 deviceId → 自动信任，无需重新验证；
 * 5. 任一方手动「解除配对」→ 删除信任记录。
 */

/** 配对信任记录（“证书”） */
export interface PairRecord {
  /** 配对时的连接码（也是传输加密密钥），配对成功后获得 */
  fingerprint: string;
  /** 对方公开标识（announce/info 响应的 fingerprint，不泄露连接码） */
  deviceId: string;
  /** 对方设备名（如“小米17”“PC 1”） */
  name: string;
  /** 最近一次可达 IP */
  ip: string;
  /** 历史可达 IP（最近在前，最多 5 个）：多通道容错，WiFi 切换/IP 变化自动换地址 */
  ips?: string[];
  /** 接收端口 */
  port: number;
  /** 配对时间戳 */
  trustAt: number;
  /** 是否在线（后台轮询 ping 维护） */
  online: boolean;
  /** 是否已连接（对方问候本机/本机问候对方成功，实时会话状态） */
  connected?: boolean;
  /** 最近一次确认在线的时间戳 */
  lastSeen: number;
}

/** 持久化适配器（移动端用 Capacitor Filesystem，桌面端用 localStorage） */
export interface PairingStorage {
  load(): PairRecord[];
  save(records: PairRecord[]): void;
}

/** 配对管理器：信任记录的增删改查 + 在线状态维护 */
export class PairingManager {
  private records: PairRecord[] = [];

  constructor(private storage: PairingStorage) {
    try {
      this.records = storage.load() || [];
    } catch {
      this.records = [];
    }
  }

  /** 全部记录（按配对时间正序） */
  all(): PairRecord[] {
    return this.records;
  }

  /** 在线记录 */
  online(): PairRecord[] {
    return this.records.filter((r) => r.online);
  }

  byFingerprint(fp: string): PairRecord | undefined {
    return this.records.find((r) => r.fingerprint === fp);
  }

  byDeviceId(id: string): PairRecord | undefined {
    return this.records.find((r) => r.deviceId === id);
  }

  /** 新增或更新信任记录（按 fingerprint 或 deviceId 去重，保留历史 IP 列表） */
  upsert(rec: PairRecord): void {
    const i = this.records.findIndex(
      (r) => r.fingerprint === rec.fingerprint || (rec.deviceId && r.deviceId === rec.deviceId),
    );
    if (i >= 0) {
      const old = this.records[i];
      // 保留 old 的连接状态：mergePeers 的 upsert 不带 connected 字段，
      // 整体替换会清掉它，导致每轮巡检后对方问候又触发一次"已连接"提示。
      this.records[i] = {
        ...rec,
        connected: rec.connected ?? old.connected,
        ips: rec.ips?.length ? rec.ips : old.ips,
      };
    } else {
      this.records.push({ ...rec, ips: rec.ips?.length ? rec.ips : rec.ip ? [rec.ip] : [] });
    }
    this.persist();
  }

  /** 记录一次可达 IP（多通道容错：新 IP 加入历史列表，最近在前，最多 5 个） */
  rememberIp(fingerprint: string, ip: string): void {
    if (!ip) return;
    const r = this.byFingerprint(fingerprint);
    if (!r) return;
    if ((r.ips || []).includes(ip)) return; // 已记录，不重复写盘（500ms 轮询热路径）
    const ips = [ip, ...(r.ips || [r.ip]).filter((x) => x !== ip)].slice(0, 5);
    r.ips = ips;
    this.persist();
  }

  /** 解除配对 */
  remove(fingerprint: string): void {
    this.records = this.records.filter((r) => r.fingerprint !== fingerprint);
    this.persist();
  }

  /** 标记在线（更新 IP/端口/最近可见时间） */
  markOnline(fingerprint: string, ip: string, port: number): void {
    const r = this.byFingerprint(fingerprint);
    if (r) {
      if (r.online && r.ip === ip && r.port === port) return; // 状态无变化不写盘
      r.online = true;
      r.lastSeen = Date.now();
      r.ip = ip;
      r.port = port;
      this.persist();
    }
  }

  markOffline(fingerprint: string): void {
    const r = this.byFingerprint(fingerprint);
    if (r) {
      if (!r.online) return; // 已离线，不重复写盘
      r.online = false;
      r.connected = false; // 离线即未连接，保证状态实时准确
      this.persist();
    }
  }

  /** 标记连接状态（已连接/未连接），随问候与传输实时更新 */
  markConnected(fingerprint: string, connected: boolean): void {
    const r = this.byFingerprint(fingerprint);
    if (r) {
      if (r.connected === connected) return; // 状态无变化不写盘
      r.connected = connected;
      this.persist();
    }
  }

  private persist(): void {
    try {
      this.storage.save(this.records);
    } catch {
      // 存储不可用时仅内存保留
    }
  }
}

/** 规范化连接码：去分隔符、统一大写（与 Rust/Java 端一致） */
export function normalizeCode(code: string): string {
  return (code || '')
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '');
}
