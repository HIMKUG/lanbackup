/**
 * discovery.ts - 局域网设备发现
 *
 * 两端打开 App → 同局域网 → 通过连接码互相发现并握手。
 * 局域网自动发现后匹配连接码，匹配成功即视为信任设备，可直接自动连接。
 *
 * 注意：本模块定义发现逻辑的接口与状态机。
 * 实际的 UDP 广播/组播由平台层实现（Capacitor 插件 / Tauri 命令），
 * 因为 WebView 环境无法直接绑定 UDP socket。
 */

import { codesMatch, isValidConnectionCode } from './identity.js';
import { logger, maskSecret } from './logger.js';

/** 发现的设备 */
export interface DiscoveredDevice {
  /** 设备 IP */
  ip: string;
  /** 设备端口 */
  port: number;
  /** 设备显示名 */
  alias: string;
  /** 设备连接码（若已通过 register 获取） */
  connectionCode?: string;
  /** 是否已配对（连接码匹配成功） */
  paired: boolean;
  /** 最后发现时间（毫秒） */
  lastSeen: number;
}

/** 发现回调 */
export interface DiscoveryCallbacks {
  /** 发现新设备 */
  onDeviceFound: (device: DiscoveredDevice) => void;
  /** 设备离线 */
  onDeviceLost: (ip: string) => void;
}

/**
 * 判断设备是否已配对：连接码匹配成功。
 * @param device 发现的设备
 * @param selfCode 本机连接码
 * @param pairedCodes 已配对设备的连接码集合
 */
export function isPaired(
  device: DiscoveredDevice,
  pairedCodes: Set<string>,
): boolean {
  if (!device.connectionCode) return false;
  for (const code of pairedCodes) {
    if (codesMatch(device.connectionCode, code)) return true;
  }
  return false;
}

/**
 * 设备发现管理器。
 * 平台层负责实际广播/组播，本类负责状态维护与配对判断。
 */
export class DiscoveryManager {
  private devices = new Map<string, DiscoveredDevice>();
  private pairedCodes: Set<string>;
  private callbacks: DiscoveryCallbacks;

  constructor(pairedCodes: Set<string>, callbacks: DiscoveryCallbacks) {
    this.pairedCodes = pairedCodes;
    this.callbacks = callbacks;
  }

  /**
   * 平台层上报发现的设备。
   */
  reportDevice(device: DiscoveredDevice): void {
    const key = `${device.ip}:${device.port}`;
    const existing = this.devices.get(key);
    // 校验连接码格式，非法值置为 undefined，避免污染配对状态
    const connectionCode =
      device.connectionCode && isValidConnectionCode(device.connectionCode)
        ? device.connectionCode
        : undefined;
    const updated: DiscoveredDevice = {
      ...(existing ?? device),
      ...device,
      connectionCode,
      paired: isPaired({ ...device, connectionCode }, this.pairedCodes),
      lastSeen: Date.now(),
    };
    this.devices.set(key, updated);
    const pairedTag = updated.paired ? '已配对' : '未配对';
    if (!existing) {
      logger.info(
        'discovery',
        `发现新设备 ${updated.alias} ${updated.ip}:${updated.port} ` +
          `连接码=${maskSecret(updated.connectionCode ?? '')} ${pairedTag}`,
      );
    } else {
      logger.debug(
        'discovery',
        `设备上报更新 ${updated.alias} ${updated.ip}:${updated.port} ${pairedTag}`,
      );
    }
    this.callbacks.onDeviceFound(updated);
  }

  /**
   * 平台层上报设备离线。
   */
  reportDeviceLost(ip: string): void {
    for (const [key, device] of this.devices) {
      if (device.ip === ip) {
        this.devices.delete(key);
        logger.info('discovery', `设备离线 ${device.alias} ${device.ip}:${device.port}`);
        this.callbacks.onDeviceLost(ip);
      }
    }
  }

  /**
   * 获取所有已发现的设备。
   */
  allDevices(): DiscoveredDevice[] {
    return Array.from(this.devices.values());
  }

  /**
   * 获取已配对的设备。
   */
  pairedDevices(): DiscoveredDevice[] {
    return this.allDevices().filter((d) => d.paired);
  }

  /**
   * 清理超时未见的设备（平台层定时调用）。
   * @param timeoutMs 超时阈值（毫秒），默认 30 秒
   */
  prune(timeoutMs: number = 30000): void {
    const now = Date.now();
    for (const [key, device] of this.devices) {
      if (now - device.lastSeen > timeoutMs) {
        this.devices.delete(key);
        logger.info(
          'discovery',
          `设备超时清理 ${device.alias} ${device.ip}:${device.port}（${now - device.lastSeen}ms 未见）`,
        );
        this.callbacks.onDeviceLost(device.ip);
      }
    }
  }
}
