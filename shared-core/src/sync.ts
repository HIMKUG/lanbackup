/**
 * sync.ts - 局域网单向增量备份算法（三路对比）
 *
 * 核心设计（技术白皮书）：
 * - 判据：mtime + size（读取元数据，0 磁盘 I/O；避免手机端弱 CPU 算几亿个块哈希）
 * - 三路对比：A当前 vs A上次(快照) vs B当前(对端清单)，同时回答：
 *   A 新增了什么、A 修改了什么、B 缺了什么
 * - 策略（区别在是否补传"对端缺失"）：
 *   archive（默认）——只增不删：新增/变更/残留（B 端 size 不一致）照传，
 *     B 端已删除的文件不自动补回（删除视为有意，仅告警）
 *   mirror ——完整镜像：补传全部对端缺失（自愈），并清理 B 端多余文件（删除语义，需用户显式开启）
 * - 锚点：上次清单 lastManifest 即快照，无需单独的锚点文件
 */

import { logger } from './logger.js';
import type { Manifest } from './manifest.js';
import { normalizeForCompare, type ScannedFile } from './scan.js';

/** 增量同步策略 */
export type SyncStrategy = 'archive' | 'mirror';

/** B 端清单（GET /api/backup/v1/manifest 响应） */
export interface PeerManifest {
  /** 生成时间（Unix 秒） */
  generatedAt: number;
  /** 对端设备公开标识（确认清单归属） */
  deviceCode: string;
  /** 文件映射表：relPath → {size, mtime} */
  files: Record<string, { size: number; mtime: number }>;
  /** 清单版本号 */
  version: number;
}

/** 增量规划结果 */
export interface SyncPlan {
  /** 需要传输的文件（新增 ∪ 变更 ∪ 残留；镜像模式额外补对端缺失） */
  toTransfer: ScannedFile[];
  /** 本端新增 */
  added: string[];
  /** 本端变更（size/mtime 变化） */
  modified: string[];
  /** 对端缺失（A有 B无） */
  missingOnPeer: string[];
  /** 本次新增缺失（subset of missingOnPeer，不在 knownMissingOnPeer 中） */
  newMissingOnPeer: string[];
  /** 对端多余文件（B有 A无；镜像模式移动到 delete 文件夹假删除，保持目录一致） */
  peerExtra: string[];
  /** 未变化（不参与传输） */
  unchanged: number;
}

/**
 * 三路对比增量规划。
 * @param current 本次扫描的 A 端当前清单（metadata-only）
 * @param prev 上次成功备份的快照（A 上次；空对象=首次备份全量）
 * @param peer B 端当前清单（获取失败传 null → 退化为两路对比）
 * @param strategy 增量策略（archive=只增不删，不补对端缺失 / mirror=完整镜像，补缺口并清理对端多余）
 * @param knownMissingOnPeer 已知对端缺失列表（archive 下用于过滤重复告警）
 */
export function planIncremental(
  current: ScannedFile[],
  prev: Manifest | undefined,
  peer: PeerManifest | null,
  strategy: SyncStrategy,
  knownMissingOnPeer: string[] = [],
): SyncPlan {
  const prevMap = prev ?? {};
  const added: string[] = [];
  const modified: string[] = [];
  let unchanged = 0;

  // NFC 规范化比较键：macOS 存 NFD、Windows/Linux 存 NFC，同一文件字节不同。
  // 仅用于清单对比判断"是否同一文件"，存储/传输始终保留原样（见 scan.ts normalizeForCompare）。
  const nfcPrev = new Map<string, Manifest[string]>();
  for (const [k, v] of Object.entries(prevMap)) nfcPrev.set(normalizeForCompare(k), v);
  const nfcPeer = peer?.files ? new Map<string, { size: number; mtime: number }>() : null;
  if (nfcPeer) {
    for (const [k, v] of Object.entries(peer!.files)) nfcPeer.set(normalizeForCompare(k), v);
  }

  // current 每文件只 normalize 一次，供两路对比复用（大清单省一半以上 NFC 计算）
  const curNorm = new Map<string, string>();
  for (const f of current) curNorm.set(f.relPath, normalizeForCompare(f.relPath));

  // 两路对比：A当前 vs A上次
  for (const f of current) {
    const old = nfcPrev.get(curNorm.get(f.relPath)!);
    if (!old) {
      added.push(f.relPath);
    } else if (old.size !== f.size || old.mtime !== f.mtime) {
      modified.push(f.relPath);
    } else {
      unchanged++;
    }
  }

  // 第三路：A当前 vs B当前 → 对端缺失（两类，语义不同）：
  // - absent（B 端不存在该文件）：归档模式不补传（只增不删，B 端删除视为有意），仅告警；
  //   镜像模式补传（自愈）
  // - mismatched（B 端存在但 size 不一致 = 残留/损坏/部分传输）：视为"变更"，两种模式都补传
  // 已知限制：同 path 同 size 但内容被篡改/损坏的文件无法用 size 检测（需 SHA-256 内容哈希，
  // 超出本期 scope；当前仅按 size 判定，见传输层改造报告 M1）
  const missingOnPeer: string[] = []; // absent：B 端不存在
  const mismatchedOnPeer: string[] = []; // 残留/损坏：B 端存在但 size 不一致
  if (nfcPeer) {
    for (const f of current) {
      const remote = nfcPeer.get(curNorm.get(f.relPath)!);
      if (!remote) {
        missingOnPeer.push(f.relPath);
      } else if (remote.size !== f.size) {
        mismatchedOnPeer.push(f.relPath);
      }
    }
  }

  // 「新增缺失」= 本轮新发现的对端缺失（镜像模式将补传；归档模式仅告警）
  // 用 Set 避免 O(M×K) 二次方（首次镜像/大规模缺失时卡死主线程）
  const knownMissingSet = new Set(knownMissingOnPeer);
  const newMissingOnPeer = missingOnPeer.filter(p => !knownMissingSet.has(p));
  if (newMissingOnPeer.length > 0) {
    logger.warn(
      'sync',
      `对端新增缺失 ${newMissingOnPeer.length} 个文件: ` +
        newMissingOnPeer.slice(0, 10).join(', ') + (newMissingOnPeer.length > 10 ? '…' : ''),
    );
  }

  // 对端多余文件（B有 A无）：镜像模式移动到 delete 文件夹假删除，保持目录一致
  const curNormSet = new Set(curNorm.values());
  const peerExtra: string[] = [];
  if (peer?.files) {
    for (const k of Object.keys(peer.files)) {
      // 对端假删除区（delete/）不参与多余判定：moveToDelete 后文件留在 delete 文件夹，
      // 若仍算多余会无限弹镜像确认（问题5 死循环）
      if (k.startsWith('delete/') || k.startsWith('delete\\')) continue;
      if (!curNormSet.has(normalizeForCompare(k))) peerExtra.push(k);
    }
  }

  // 传输列表：
  // 归档：新增 ∪ 变更 ∪ 残留 ∪ 已备份但对端删除（自愈补全——之前备份过、对端误删/清理的文件重新推送，
  //       保证备份完整；从未备份过的对端文件仍不补，尊重"只增不删"）
  // 镜像：新增 ∪ 变更 ∪ 残留 ∪ 对端缺失（全量自愈补全）
  const toTransferSet = new Set<string>([...added, ...modified, ...mismatchedOnPeer]);
  for (const p of missingOnPeer) {
    if (strategy === 'mirror' || nfcPrev.has(curNorm.get(p)!)) toTransferSet.add(p);
  }
  const toTransfer = current.filter((f) => toTransferSet.has(f.relPath));

  logger.info(
    'sync',
    `增量规划: 当前=${current.length} 上次=${Object.keys(prevMap).length} ` +
      `对端=${peer ? Object.keys(peer.files).length : 0} 新增=${added.length} ` +
      `变更=${modified.length} 对端缺失=${missingOnPeer.length} ` +
      `残留=${mismatchedOnPeer.length}（新增缺失=${newMissingOnPeer.length}）` +
      `需传输=${toTransfer.length} 策略=${strategy}`,
  );
  return { toTransfer, added, modified, missingOnPeer, newMissingOnPeer, peerExtra, unchanged };
}
