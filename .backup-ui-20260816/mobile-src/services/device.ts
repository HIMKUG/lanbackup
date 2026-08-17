/**
 * device.ts - 手机端设备身份与状态管理
 *
 * 首次启动基于本地 UUID 生成永久连接码，状态文件按配对设备分 JSON 存储。
 */

import { Filesystem, Directory, Encoding } from '@capacitor/filesystem';
import {
  generateConnectionCode,
  deviceDisplayName,
  BackupState,
  createEmptyState,
  getOrCreateDevice,
  setAutoPolicy,
  markBackupDone,
  migrateState,
  Manifest,
} from 'shared-core';
import { logger, maskSecret } from 'shared-core';

const STATE_KEY = 'backup_state.json';
const DEVICE_ID_KEY = 'device_id';

/** 获取或生成本机设备 ID（UUID，存本地，永久） */
export async function getDeviceId(): Promise<string> {
  try {
    const file = await Filesystem.readFile({
      path: DEVICE_ID_KEY,
      directory: Directory.Data,
      encoding: Encoding.UTF8,
    });
    logger.debug('device', `读取本机设备 ID: ${maskSecret(file.data as string)}`);
    return file.data as string;
  } catch {
    // 生成新 UUID
    const id = crypto.randomUUID();
    await Filesystem.writeFile({
      path: DEVICE_ID_KEY,
      data: id,
      directory: Directory.Data,
      encoding: Encoding.UTF8,
    });
    logger.info('device', `首次启动生成设备 ID: ${maskSecret(id)}`);
    return id;
  }
}

/** 获取本机连接码（基于设备 ID 哈希） */
export async function getSelfConnectionCode(): Promise<string> {
  const deviceId = await getDeviceId();
  const code = generateConnectionCode(deviceId);
  logger.info('device', `本机连接码: ${maskSecret(code)}`);
  return code;
}

/** 读取状态文件 */
export async function loadState(): Promise<BackupState> {
  try {
    const file = await Filesystem.readFile({
      path: STATE_KEY,
      directory: Directory.Data,
      encoding: Encoding.UTF8,
    });
    const state = migrateState(JSON.parse(file.data as string));
    logger.info('device', `读取状态文件成功，配对设备 ${Object.keys(state.devices).length} 台`);
    return state;
  } catch (e) {
    logger.warn('device', '状态文件不存在或损坏，创建新状态', e);
    const code = await getSelfConnectionCode();
    const state = createEmptyState(code, deviceDisplayName(code));
    await saveState(state);
    return state;
  }
}

/** 保存状态文件 */
export async function saveState(state: BackupState): Promise<void> {
  try {
    await Filesystem.writeFile({
      path: STATE_KEY,
      data: JSON.stringify(state),
      directory: Directory.Data,
      encoding: Encoding.UTF8,
    });
    logger.debug('device', `保存状态文件成功，配对设备 ${Object.keys(state.devices).length} 台`);
  } catch (e) {
    // 存储失败不阻断：已完成的备份不应被报成失败（配额/磁盘满时降级为警告）
    logger.warn('device', '保存状态文件失败（不影响备份结果）', e);
  }
}

/** 获取或创建配对设备状态 */
export async function ensureDevice(
  state: BackupState,
  connectionCode: string,
  deviceName: string,
): Promise<void> {
  getOrCreateDevice(state, connectionCode, deviceName);
  await saveState(state);
  logger.info('device', `配对设备已登记: ${deviceName} (${maskSecret(connectionCode)})`);
}

/** 更新配对设备自动策略 */
export async function updatePolicy(
  state: BackupState,
  connectionCode: string,
  policy: 'semi' | 'auto' | 'manual',
): Promise<void> {
  setAutoPolicy(state, connectionCode, policy);
  await saveState(state);
  logger.info('device', `更新自动策略: ${policy} (${maskSecret(connectionCode)})`);
}

/** 备份完成后更新状态 */
export async function completeBackup(
  state: BackupState,
  connectionCode: string,
  manifest: Manifest,
): Promise<void> {
  markBackupDone(state, connectionCode, manifest, Date.now());
  await saveState(state);
  logger.info(
    'device',
    `备份完成状态已更新: 清单 ${Object.keys(manifest).length} 条 (${maskSecret(connectionCode)})`,
  );
}
