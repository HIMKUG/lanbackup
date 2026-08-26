/**
 * anchor.ts - 锚点管理
 *
 * 快速模式：锚点只存在手机端本地（按配对设备分文件存）。
 * 锚点粒度：每个子目录 + 每个文件，按日期排序。
 * 记录上次备份成功的最新文件修改日期。
 */

import { logger } from './logger.js';

/** 单个文件/子目录的锚点 */
export interface AnchorEntry {
  /** 相对路径（目录以 / 结尾） */
  relPath: string;
  /** 上次备份成功时的最新 mtime（毫秒） */
  lastMtime: number;
}

/** 锚点集合：按相对路径索引 */
export type AnchorMap = Record<string, AnchorEntry>;

/**
 * 更新锚点：记录某路径上次备份成功时的最新 mtime。
 * 只增不删：已存在的锚点若新 mtime 更大则更新，否则保留。
 */
export function updateAnchor(anchors: AnchorMap, relPath: string, mtime: number): AnchorMap {
  const existing = anchors[relPath];
  if (!existing || mtime > existing.lastMtime) {
    logger.debug(
      'anchor',
      `锚点更新 ${relPath}: ${existing ? existing.lastMtime : '无'} → ${mtime}`,
    );
    return { ...anchors, [relPath]: { relPath, lastMtime: mtime } };
  }
  return anchors;
}

/**
 * 批量更新锚点（一次备份成功后调用）。
 * @param anchors 现有锚点
 * @param entries 本次成功备份的文件（相对路径 + mtime）
 */
export function updateAnchors(anchors: AnchorMap, entries: AnchorEntry[]): AnchorMap {
  let result = anchors;
  for (const entry of entries) {
    result = updateAnchor(result, entry.relPath, entry.lastMtime);
  }
  return result;
}

/**
 * 获取某路径的锚点 mtime，不存在返回 null。
 */
export function getAnchorMtime(anchors: AnchorMap, relPath: string): number | null {
  const entry = anchors[relPath];
  // lastMtime <= 0 视为无效锚点（未初始化或损坏数据）
  return entry && entry.lastMtime > 0 ? entry.lastMtime : null;
}

/**
 * 判断某文件是否在锚点之后（即需要扫描）。
 * 文件 mtime > 锚点 mtime 才需要扫描；等于或小于则跳过。
 */
export function isAfterAnchor(anchors: AnchorMap, relPath: string, mtime: number): boolean {
  const anchorMtime = getAnchorMtime(anchors, relPath);
  if (anchorMtime === null) return true; // 无锚点 → 需要扫描
  return mtime > anchorMtime;
}

/**
 * 计算本次扫描的日期区间（用于 UI 展示）。
 * @param anchors 现有锚点
 * @param now 当前时间（毫秒）
 * @returns { from, to } 区间，from 为最早锚点日期，to 为当前日期
 */
export function scanDateRange(anchors: AnchorMap, now: number): { from: number; to: number } {
  let earliest = now;
  for (const key of Object.keys(anchors)) {
    const mtime = anchors[key].lastMtime;
    if (mtime < earliest) earliest = mtime;
  }
  return { from: earliest, to: now };
}
