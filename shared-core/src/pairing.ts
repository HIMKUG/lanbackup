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

import { logWarn } from './logger.js';

/** 配对信任记录（”证书”）。
 *
 * 密钥轮换（#11 + M2）：
 * - keyVersion 初始为 1（配对建立时），每次连接码刷新后 +1
 * - 传输加密使用 keyVersion 对应的密钥版本（多版本并存，滚动兼容）
 * - 发送方携带 keyVersion，接收方据此选择正确的密钥派生路径
 * - 旧密钥保留 7 天（previousKeys），用于解密历史传输数据，过期后物理删除
 */
export interface PairRecord {
  /** 配对时的连接码（也是传输加密密钥），配对成功后获得 */
  fingerprint: string;
  /** 对方公开标识（announce/info 响应的 fingerprint，不泄露连接码） */
  deviceId: string;
  /** 对方设备名（如”小米17””PC 1”） */
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
  /** 配对协商时的协议版本（用于密钥体系兼容性） */
  protocolVersion?: string;
  /** KDF 版本：1=SHA-256, 2=PBKDF2 */
  kdfVersion?: number;
  /** 加密版本：1=连接码直接派生, 2=ECDH */
  cryptoVersion?: number;
  /** PBKDF2 salt（配对时由发起方生成，编码在 QR Code 中传递） */
  salt?: string;
  /** 对方公钥（ECDH P-256，Base64 编码，用于 #8 传输加密） */
  peerPublicKey?: string;
  /** 密钥版本号（#11 密钥轮换）：每次连接码刷新后 +1，传输时携带以选择正确密钥派生路径 */
  keyVersion?: number;
  /** 旧密钥存档（M2：保留 7 天，过期自动清理）。
   *  每条记录含 version、fingerprint（连接码）、deprecatedAt（过期时间戳）。
   *  用途：连接码刷新后，已在传输中的文件仍能用旧密钥解密。 */
  previousKeys?: Array<{
    version: number;
    fingerprint: string;
    peerPublicKey?: string;
    deprecatedAt: number;
  }>;
  /** 最近一次同步完成的文件清单哈希（增量同步用），持久化到 SQLite 避免 App.vue 重启丢失 */
  lastManifest?: Record<string, string>;
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
    const idx = this.records.findIndex(
      (r) => r.fingerprint === rec.fingerprint || (rec.deviceId && r.deviceId === rec.deviceId)
    );
    if (idx >= 0) {
      const old = this.records[idx];
      // 合并字段：connected 取新的（若提供），ips 取新的（若有）或保留旧的
      this.records[idx] = this.mergeRecords(rec, old);
    } else {
      // 新增记录：确保 ips 有默认值
      const newRecord: PairRecord = {
        ...rec,
        ips: rec.ips?.length ? rec.ips : (rec.ip ? [rec.ip] : [])
      };
      this.records.push(newRecord);
    }
    this.persist();
  }

  /** 合并两条记录：新记录优先，保留旧记录的非空/扩展字段（防止升级丢失 previousKeys/lastManifest 等） */
  private mergeRecords(newRec: PairRecord, oldRec: PairRecord): PairRecord {
    return {
      ...newRec,
      // connected：若新记录未提供，保留旧值（避免巡检时覆盖已建立的连接状态）
      connected: newRec.connected ?? oldRec.connected,
      // ips：若新记录有内容用新的，否则保留旧的
      ips: newRec.ips?.length ? newRec.ips : oldRec.ips,
      // 扩展字段：新记录（多来自探测/巡检）可能不含这些持久化字段，缺失时保留旧值，
      // 避免连接码轮换密钥存档被误清导致历史数据无法解密
      previousKeys: newRec.previousKeys?.length ? newRec.previousKeys : oldRec.previousKeys,
      lastManifest: newRec.lastManifest ?? oldRec.lastManifest,
      peerPublicKey: newRec.peerPublicKey ?? oldRec.peerPublicKey,
    };
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

  /** 密钥轮换（#11 + M2）：连接码刷新后调用。
   *
   *  archive current key → update to new key → increment keyVersion.
   *  旧密钥保留 7 天（previousKeys），用于解密历史传输数据。
   *  此方法供主动方（发起传输的一方）在检测到 keyVersion 不匹配时调用。 */
  rotateKey(fingerprint: string, newFingerprint: string, newPeerPublicKey?: string): void {
    const r = this.byFingerprint(fingerprint);
    if (!r) return;
    // M2: archive current key before rotating
    const currentVersion = r.keyVersion ?? 1;
    const archiveEntry = {
      version: currentVersion,
      fingerprint: r.fingerprint,
      peerPublicKey: r.peerPublicKey,
      deprecatedAt: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days from now
    };
    r.previousKeys = [...(r.previousKeys ?? []), archiveEntry].slice(-5); // keep up to 5 old keys
    r.fingerprint = newFingerprint;
    r.keyVersion = currentVersion + 1;
    if (newPeerPublicKey !== undefined) {
      r.peerPublicKey = newPeerPublicKey;
    }
    this.persist();
  }

  /** 清理已过期的旧密钥（M2：启动时调用，删除 deprecatedAt < now 的条目） */
  cleanupExpiredKeys(): void {
    const now = Date.now();
    let changed = false;
    for (const r of this.records) {
      const before = r.previousKeys?.length ?? 0;
      r.previousKeys = (r.previousKeys ?? []).filter(k => k.deprecatedAt > now);
      if ((r.previousKeys?.length ?? 0) < before) changed = true;
    }
    if (changed) this.persist();
  }

  /** 尝试用当前密钥解密，失败则遍历 previousKeys（M2：解密历史传输数据时使用） */
  tryDecryptWithHistory<T>(
    fingerprint: string,
    decryptFn: (rec: PairRecord) => T | null,
  ): T | null {
    const r = this.byFingerprint(fingerprint);
    if (!r) return null;
    // try current key first
    const result = decryptFn(r);
    if (result !== null) return result;
    // try previous keys in order (newest first)
    const history = [...(r.previousKeys ?? [])].sort((a, b) => b.version - a.version);
    for (const old of history) {
      const oldRec: PairRecord = { ...r, fingerprint: old.fingerprint, peerPublicKey: old.peerPublicKey };
      const result2 = decryptFn(oldRec);
      if (result2 !== null) return result2;
    }
    return null;
  }

  private persist(): void {
    try {
      this.storage.save(this.records);
    } catch (e) {
      // 存储不可用时仅内存保留（配对记录仅在本次运行有效，重启后需重新配对）
      logWarn('pairing', '配对记录持久化失败，仅内存保留：重启后需重新配对', e as Error);
    }
  }
}

/** 规范化连接码：去分隔符、统一大写（与 Rust/Java 端一致） */
export function normalizeCode(code: string): string {
  return (code || '')
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '');
}
