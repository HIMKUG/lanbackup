/**
 * scan.ts - 扫描引擎（核心差异点）
 *
 * 扫描决策逻辑只在发送端做，接收端只负责收。
 * 快速模式（默认）：只扫「上次锚点日期 → 当前日期」区间。
 * 深度模式（手动）：全量遍历 + 清单 Diff。
 */

import { AnchorMap, isAfterAnchor, scanDateRange } from './anchor.js';
import { Manifest, ManifestDiff, diffManifests } from './manifest.js';
import { logger } from './logger.js';

/** 扫描模式 */
export type ScanMode = 'quick' | 'deep';

/** 扫描到的文件条目 */
export interface ScannedFile {
  /** 相对路径 */
  relPath: string;
  /** 文件大小（字节） */
  size: number;
  /** 最后修改时间（毫秒） */
  mtime: number;
}

/** 扫描结果 */
export interface ScanResult {
  /** 需要传输的文件 */
  files: ScannedFile[];
  /** 本次扫描的日期区间（快速模式） */
  dateRange?: { from: number; to: number };
  /** 深度模式的 Diff 结果 */
  diff?: ManifestDiff;
}

/**
 * 快速模式扫描决策。
 * 只返回「mtime > 锚点」的文件。
 *
 * @param anchors 现有锚点
 * @param allFiles 本次遍历到的所有文件（由平台层提供）
 * @param now 当前时间（毫秒）
 */
export function quickScan(anchors: AnchorMap, allFiles: ScannedFile[], now: number): ScanResult {
  const files = allFiles.filter((f) => isAfterAnchor(anchors, f.relPath, f.mtime));
  const range = scanDateRange(anchors, now);
  logger.info(
    'scan',
    `快速扫描完成: 遍历 ${allFiles.length} 条, 锚点 ${Object.keys(anchors).length} 个, ` +
      `需传输 ${files.length} 条, 日期区间 [${new Date(range.from).toISOString()}, ${new Date(range.to).toISOString()}]`,
  );
  return {
    files,
    dateRange: range,
  };
}

/**
 * 深度模式扫描决策。
 * 全量遍历 + 与上次全量清单 Diff。
 *
 * @param prevManifest 上一次的全量清单
 * @param allFiles 本次遍历到的所有文件（由平台层提供）
 */
export function deepScan(prevManifest: Manifest, allFiles: ScannedFile[]): ScanResult {
  const currManifest: Manifest = {};
  for (const f of allFiles) {
    currManifest[f.relPath] = { relPath: f.relPath, size: f.size, mtime: f.mtime };
  }
  const diff = diffManifests(prevManifest, currManifest);

  // 只返回需要传输的文件
  const files = diff.toTransfer.map((relPath: string) => currManifest[relPath]);

  logger.info(
    'scan',
    `深度扫描完成: 遍历 ${allFiles.length} 条, 上次清单 ${Object.keys(prevManifest).length} 条, ` +
      `新增=${diff.added.length}, 变更=${diff.changed.length}, 需传输=${files.length}`,
  );
  return { files, diff };
}

/**
 * 统一扫描入口。
 * @param mode 扫描模式
 * @param anchors 现有锚点（快速模式用）
 * @param prevManifest 上次全量清单（深度模式用）
 * @param allFiles 本次遍历到的所有文件
 * @param now 当前时间
 */
export function scan(
  mode: ScanMode,
  anchors: AnchorMap,
  prevManifest: Manifest,
  allFiles: ScannedFile[],
  now: number,
): ScanResult {
  if (mode === 'quick') {
    return quickScan(anchors, allFiles, now);
  }
  return deepScan(prevManifest, allFiles);
}

// ============================================================
// 文件分类器（传输策略矩阵的输入，见传输层优化规格书）
// ============================================================

/** 文件类别：按大小 + 平台元数据（lstat/stat/SEEK_HOLE）分类 */
export type FileClass =
  | 'tiny' // < 10KB，数量极多 → tar 聚合
  | 'small' // 10KB - 1MB
  | 'normal' // 1MB - 100MB ← 主力场景
  | 'large' // 100MB - 1GB
  | 'huge' // > 1GB
  | 'sparse' // 含空洞的大文件（平台层 SEEK_HOLE 检测）
  | 'symlink' // 符号链接（平台层 lstat 检测）
  | 'hardlink' // 硬链接（平台层 ino 分组）
  | 'special' // 设备文件/管道/套接字（平台层 lstat 检测）
  | 'empty'; // size = 0

/** 分类后的文件条目（扩展平台元数据） */
export interface ClassifiedFile extends ScannedFile {
  cls: FileClass;
  /** symlink 专用：链接目标 */
  linkTarget?: string;
  /** hardlink 专用：inode */
  inode?: number;
  /** 重复文件去重用：size + ':' + mtime */
  contentSignature?: string;
}

/** 按字节数分类（业界阈值：10KB / 1MB / 100MB / 1GB） */
export function classifySize(size: number): FileClass {
  if (size < 10 * 1024) return 'tiny';
  if (size < 1024 * 1024) return 'small';
  if (size < 100 * 1024 * 1024) return 'normal';
  if (size < 1024 * 1024 * 1024) return 'large';
  return 'huge';
}

/**
 * 文件分类器。
 * @param info 文件信息（relPath/size/mtime）
 * @param flags 平台层检测结果（lstat/stat/SEEK_HOLE 由平台层提供；不提供则按大小分类）
 */
export function classifyFile(
  info: ScannedFile,
  flags?: { symlink?: boolean; special?: boolean; inode?: number; sparse?: boolean },
): FileClass {
  if (flags?.symlink) return 'symlink';
  if (flags?.special) return 'special';
  if (info.size === 0) return 'empty';
  // 稀疏仅在大型文件中值得单独处理（>100MB）
  if (flags?.sparse && info.size >= 100 * 1024 * 1024) return 'sparse';
  return classifySize(info.size);
}

/**
 * 跨平台文件名比较键：统一 NFC 规范化。
 * 仅用于清单对比（判断"是否同一文件"），存储/传输始终保留原样字节。
 * macOS APFS/HFS+ 强制 NFD，NTFS/ext4 原样保留——同一 "café.txt" 字节不同但显示相同。
 */
export function normalizeForCompare(filename: string): string {
  try {
    return (filename || '').normalize('NFC');
  } catch {
    return filename || '';
  }
}

/** 重复文件初步签名：size + ':' + mtime（毫秒），仅作预分组，不做内容哈希 */
export function contentSignature(info: ScannedFile): string {
  return `${info.size}:${info.mtime}`;
}
