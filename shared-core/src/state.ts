/**
 * state.ts - 状态文件（每配对设备一份）
 *
 * 手机端：为每个配对设备存一份 JSON，含设备连接码、锚点日期、全量清单、自动策略。
 * 电脑端：用 SQLite 加密存储（由 Tauri 后端实现），本模块定义数据结构。
 */

import { AnchorMap } from './anchor.js';
import { Manifest } from './manifest.js';
import { SyncStrategy } from './sync.js';

/** 自动策略 */
export type AutoPolicy = 'semi' | 'auto' | 'manual';

/** 单个配对设备的状态 */
export interface DeviceState {
  /** 配对设备的连接码 */
  connectionCode: string;
  /** 配对设备的显示名 */
  deviceName: string;
  /** 锚点（按子目录/文件索引） */
  anchors: AnchorMap;
  /** 上次全量清单（深度模式用） */
  lastManifest: Manifest;
  /** 自动策略 */
  autoPolicy: AutoPolicy;
  /** 增量同步策略（mirror=对端缺失自动补传 / archive=只增不删） */
  syncStrategy: SyncStrategy;
  /** 已知对端缺失的文件列表（relPath[]，避免 archive 策略下重复告警） */
  knownMissingOnPeer: string[];
  /** 冲突记录（接收端重命名时写入） */
  conflicts: ConflictRecord[];
  /** 最后备份成功时间（毫秒） */
  lastBackupAt: number | null;
  /** 最后锚点日期（毫秒，用于 UI 展示） */
  lastAnchorDate: number | null;
}

/** 冲突记录 */
export interface ConflictRecord {
  relPath: string;
  reason: string;
  resolvedAs: string;
  timestamp: number;
}

/** 状态文件根结构 */
export interface BackupState {
  /** 本机连接码 */
  selfConnectionCode: string;
  /** 本机显示名 */
  selfDeviceName: string;
  /** 版本号 */
  version: number;
  /** 配对设备列表（按连接码索引） */
  devices: Record<string, DeviceState>;
}

/** 当前状态文件版本 */
export const STATE_VERSION = 1;

/**
 * 迁移旧版本状态到当前版本。
 * 目前仅处理：缺失 version 字段的旧状态 → 补全为当前版本。
 * 未来版本结构变更时在此追加迁移逻辑。
 *
 * @param raw 从磁盘读出的原始状态（可能是旧版本）
 * @returns 迁移到当前版本的状态
 */
export function migrateState(raw: unknown): BackupState {
  const state = (raw ?? {}) as Partial<BackupState>;
  // 补全缺失字段，保证结构完整
  const migrated: BackupState = {
    selfConnectionCode: state.selfConnectionCode ?? '',
    selfDeviceName: state.selfDeviceName ?? '',
    version: STATE_VERSION,
    devices: state.devices ?? {},
  };
  // 逐设备补全缺失字段
  for (const code of Object.keys(migrated.devices)) {
    const d = migrated.devices[code] as Partial<DeviceState>;
    migrated.devices[code] = {
      connectionCode: d.connectionCode ?? code,
      deviceName: d.deviceName ?? '',
      anchors: d.anchors ?? {},
      lastManifest: d.lastManifest ?? {},
      autoPolicy: d.autoPolicy ?? 'semi',
      syncStrategy: (d.syncStrategy as SyncStrategy) ?? 'archive',
      knownMissingOnPeer: d.knownMissingOnPeer ?? [],
      conflicts: d.conflicts ?? [],
      lastBackupAt: d.lastBackupAt ?? null,
      lastAnchorDate: d.lastAnchorDate ?? null,
    };
  }
  return migrated;
}

/**
 * 创建空状态。
 * @param selfConnectionCode 本机连接码
 * @param selfDeviceName 本机显示名
 */
export function createEmptyState(selfConnectionCode: string, selfDeviceName: string): BackupState {
  return {
    selfConnectionCode,
    selfDeviceName,
    version: STATE_VERSION,
    devices: {},
  };
}

/**
 * 获取或创建某配对设备的状态。
 * @param state 状态根
 * @param connectionCode 配对设备连接码
 * @param deviceName 配对设备显示名
 */
export function getOrCreateDevice(
  state: BackupState,
  connectionCode: string,
  deviceName: string,
): DeviceState {
  let device = state.devices[connectionCode];
  if (!device) {
    device = {
      connectionCode,
      deviceName,
      anchors: {},
      lastManifest: {},
      autoPolicy: 'semi',
      syncStrategy: 'archive',
      knownMissingOnPeer: [],
      conflicts: [],
      lastBackupAt: null,
      lastAnchorDate: null,
    };
    state.devices[connectionCode] = device;
  }
  return device;
}

/**
 * 更新配对设备的自动策略。
 */
export function setAutoPolicy(
  state: BackupState,
  connectionCode: string,
  policy: AutoPolicy,
): void {
  const device = state.devices[connectionCode];
  if (device) {
    device.autoPolicy = policy;
  }
}

/**
 * 备份成功后更新状态：清单（=下次增量快照）、时间戳。
 * @param state 状态根
 * @param connectionCode 配对设备连接码
 * @param newManifest 更新后的全量清单
 * @param now 当前时间
 */
export function markBackupDone(
  state: BackupState,
  connectionCode: string,
  newManifest: Manifest,
  now: number,
): void {
  const device = state.devices[connectionCode];
  if (device) {
    device.lastManifest = newManifest;
    device.lastBackupAt = now;
    device.lastAnchorDate = now;
  }
}
