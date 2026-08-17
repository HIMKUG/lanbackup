/**
 * manifest.ts - 全量清单生成与 Diff
 *
 * 深度模式：全量遍历目录，生成「相对路径 + 大小 + mtime」清单，
 * 与上一次全量清单 Diff，找出真实新增/变更文件。
 */

import { logger, summarizeList } from './logger.js';

/** 清单中的单个文件条目 */
export interface ManifestEntry {
  /** 相对路径（相对备份根目录），用 / 分隔 */
  relPath: string;
  /** 文件大小（字节） */
  size: number;
  /** 最后修改时间（Unix 毫秒时间戳） */
  mtime: number;
}

/** 全量清单：按相对路径索引的条目集合 */
export type Manifest = Record<string, ManifestEntry>;

/** Diff 结果 */
export interface ManifestDiff {
  /** 新增的文件（相对路径列表） */
  added: string[];
  /** 变更的文件（相对路径列表，大小或 mtime 变化） */
  changed: string[];
  /** 需要传输的文件 = added + changed */
  toTransfer: string[];
}

/**
 * 生成清单条目。
 * @param relPath 相对路径
 * @param size 文件大小
 * @param mtime 最后修改时间（毫秒）
 */
export function makeEntry(relPath: string, size: number, mtime: number): ManifestEntry {
  return { relPath, size, mtime };
}

/**
 * 规范化相对路径：统一用 / 分隔，去掉开头的 ./ 和结尾的 /。
 */
export function normalizeRelPath(relPath: string): string {
  let p = relPath.replace(/\\/g, '/');
  p = p.replace(/^\.\//, '');
  p = p.replace(/\/+$/, '');
  return p;
}

/**
 * 对比两份清单，找出新增和变更的文件。
 * 只增不删：旧清单有、新清单没有的文件（被删除的）不参与传输。
 *
 * @param prev 上一次的全量清单（可能为空）
 * @param curr 本次的全量清单
 */
export function diffManifests(prev: Manifest, curr: Manifest): ManifestDiff {
  const added: string[] = [];
  const changed: string[] = [];

  for (const relPath of Object.keys(curr)) {
    const cur = curr[relPath];
    const old = prev[relPath];

    if (!old) {
      // 旧清单没有 → 新增
      added.push(relPath);
    } else if (old.size !== cur.size || old.mtime !== cur.mtime) {
      // 大小或 mtime 变化 → 变更
      changed.push(relPath);
    }
    // 相同 → 跳过
  }

  const diff: ManifestDiff = {
    added,
    changed,
    toTransfer: [...added, ...changed],
  };

  logger.info(
    'manifest',
    `清单 Diff: 上次=${Object.keys(prev).length} 条, 本次=${Object.keys(curr).length} 条 → ` +
      `新增=${added.length}, 变更=${changed.length}, 需传输=${diff.toTransfer.length}`,
  );
  if (added.length > 0) {
    logger.debug('manifest', `新增文件: ${summarizeList(added)}`);
  }
  if (changed.length > 0) {
    logger.debug('manifest', `变更文件: ${summarizeList(changed)}`);
  }
  return diff;
}

/**
 * 从文件列表构建清单（供调用方传入已扫描的文件）。
 * @param entries 文件条目数组
 */
export function buildManifest(entries: ManifestEntry[]): Manifest {
  const manifest: Manifest = {};
  for (const entry of entries) {
    manifest[normalizeRelPath(entry.relPath)] = entry;
  }
  return manifest;
}
