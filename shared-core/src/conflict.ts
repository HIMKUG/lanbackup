/**
 * conflict.ts - 冲突检测与重命名
 *
 * 唯一规则：目标端存在同名文件且大小/mtime 不一致 → 绝不覆盖、绝不弹窗问。
 * 由接收端算力负责重命名。
 * 规则：`原文件名_MMDDhhmmss.扩展名`，例 `IMG_001_0815234500.jpg`。
 */

import { logger } from './logger.js';


// 最大重命名尝试次数，防止无限循环
const MAX_RENAME_ATTEMPTS = 1000;

/** 目标端已存在的文件信息 */
export interface ExistingFile {
  /** 文件名（含扩展名） */
  name: string;
  /** 文件大小（字节） */
  size: number;
  /** 最后修改时间（毫秒） */
  mtime: number;
}

/** 待写入的文件信息 */
export interface IncomingFile {
  /** 文件名（含扩展名） */
  name: string;
  /** 文件大小（字节） */
  size: number;
  /** 最后修改时间（毫秒） */
  mtime: number;
}

/**
 * 判断是否冲突：目标端存在同名文件，且大小或 mtime 不一致。
 * 同名且大小/mtime 完全一致 → 视为已存在，不冲突（跳过）。
 */
export function isConflict(existing: ExistingFile | undefined, incoming: IncomingFile): boolean {
  if (!existing) return false;
  return existing.size !== incoming.size || existing.mtime !== incoming.mtime;
}

/**
 * 生成冲突重命名后的文件名。
 * 规则：`原文件名_MMDDhhmmss.扩展名`
 * 例：`IMG_001.jpg` + mtime → `IMG_001_0815234500.jpg`
 *
 * @param originalName 原文件名（含扩展名）
 * @param mtime 文件最后修改时间（毫秒），用于生成 MMDDhhmmss
 */
export function conflictRename(originalName: string, mtime: number): string {
  const dot = originalName.lastIndexOf('.');
  const base = dot > 0 ? originalName.slice(0, dot) : originalName;
  const ext = dot > 0 ? originalName.slice(dot) : '';

  const d = new Date(mtime);
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  const hh = String(d.getHours()).padStart(2, '0');
  const mi = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  const stamp = `${mm}${dd}${hh}${mi}${ss}`;

  return `${base}_${stamp}${ext}`;
}

/**
 * 计算最终写入文件名。
 * 若冲突，则重命名；否则用原名。
 * 若重命名后仍冲突（极小概率），追加序号。
 */
export function resolveFileName(
  existing: Record<string, ExistingFile>,
  incoming: IncomingFile,
): string {
  return logger.startActiveSpan('conflict.resolveFileName', (span) => {
    span.setAttributes({
      'file.name': incoming.name,
      'file.size': incoming.size,
    });

    const current = existing[incoming.name];
    if (!isConflict(current, incoming)) {
      span.setAttribute('conflict.detected', false);
      span.end();
      return incoming.name;
    }

    span.setAttribute('conflict.detected', true);

    let candidate = conflictRename(incoming.name, incoming.mtime);
    let counter = 1;
    while (existing[candidate] && isConflict(existing[candidate], incoming) && counter <= MAX_RENAME_ATTEMPTS) {
      const dot = candidate.lastIndexOf('.');
      const base = dot > 0 ? candidate.slice(0, dot) : candidate;
      const ext = dot > 0 ? candidate.slice(dot) : '';
      candidate = `${base}_${counter}${ext}`;
      counter++;
      if (counter > MAX_RENAME_ATTEMPTS) break;
    }

    span.setAttribute('conflict.attempt_count', counter);
    span.setAttribute('conflict.final_name', candidate);

    logger.warn(
      'conflict',
      `冲突重命名: ${incoming.name}（大小=${incoming.size}, mtime=${incoming.mtime}）→ ${candidate}`,
    );
    span.end();
    return candidate;
  });
}
