/**
 * scheduler.ts - 多接收端并发 + 块校验调度器（localsend-scheduler v1）
 *
 * 架在 LocalSend v2 之上：数据通道完全走官方 POST /upload，
 * 新增协议层负责 capability 协商、per-chunk SHA-256 校验、Merkle 树验证、全局并发控制。
 *
 * 协议声明：localsend-scheduler v1 是基于 LocalSend v2 握手 + 自定义扩展字段的新协议，
 * 非 LocalSend 官方协议。接收端不支持时自动降级为纯 LocalSend v2。
 */

// ============================================================
// 协议类型（localsend-scheduler v1）
// 注意：FileManifest、TransferPhase 等类型已移至 session-store.ts
// 本文件仅保留调度器内部使用的类型
// ============================================================

// 从 session-store.ts 导入统一类型
import { FileManifest } from './session-store.js';
import { logger } from './logger.js';

/** 差异分析结果 */
export interface ChunkDiff {
  fileId: string;
  sessionId: string;
  missingChunks: number[]; // 接收端完全没有的块
  matchedChunks: number[]; // 弱校验 + 强校验都匹配的块
  mismatchedChunks: number[]; // 弱校验命中但 SHA-256 不匹配的块
  fileComplete: boolean; // 所有块都已到齐且校验通过
}

/** 传输阶段状态机 */
type TransferPhase =
  | 'idle'
  | 'preparing'
  | 'diffing'
  | 'sending'
  | 'verifying'
  | 'paused'
  | 'complete'
  | 'aborted'
  | { error: string };

/** 单个文件的传输状态 */
export interface FileTransferState {
  manifest: FileManifest;
  diff?: ChunkDiff;
  sentChunks: Set<number>;
  ackedChunks: Set<number>;
  nackedChunks: Set<number>;
  failedChunks: Set<number>;
  state: TransferPhase;
}

/** 单个接收端会话（发送端视角） */
export interface PeerSession {
  peerIp: string;
  peerPort: number;
  sessionId: string;
  state: TransferPhase;
  files: Map<string, FileTransferState>;
  createdAt: number;
  lastHeartbeat: number;
}

// ============================================================
// Merkle 哈希树（对齐 BEP-0052）
// ============================================================

/** Merkle 树节点 */
type MerkleNode = { type: 'leaf'; hash: Uint8Array } | { type: 'internal'; hash: Uint8Array };

/**
 * Merkle 哈希树（BitTorrent v2 BEP-0052 兼容）
 * - Leaf层（16KiB block SHA-256）
 * - Piece层（4MB piece 的 Merkle 根）
 * - Root层（Merkle 树根）
 */
export class MerkleTree {
  private pieceHashes: Uint8Array[]; // 每个 piece 的哈希（字节）
  private rootHash: Uint8Array; // 整棵树的根哈希
  private pieceSize: number; // piece 大小（= 传输分片大小 = 4MB）

  constructor(pieceHashes: Uint8Array[], pieceSize: number) {
    this.pieceHashes = pieceHashes;
    this.pieceSize = pieceSize;
    this.rootHash = pieceHashes.length > 0 ? MerkleTree.computeRoot(pieceHashes) : new Uint8Array(32);
  }

  /** 从 hex 字符串数组构建 Merkle 树 */
  static fromHexHashes(pieceHashesHex: string[], pieceSize: number): MerkleTree {
    const pieceHashes = pieceHashesHex
      .map(h => hexToBytes(h))
      .filter((h): h is Uint8Array => h !== null);
    return new MerkleTree(pieceHashes, pieceSize);
  }

  /** 计算一组哈希的 Merkle 根（两两串联 SHA-256） */
  private static computeRoot(hashes: Uint8Array[]): Uint8Array {
    if (hashes.length === 0) return new Uint8Array(32);
    if (hashes.length === 1) return hashes[0];

    let level = hashes.slice();
    while (level.length > 1) {
      const nextLevel: Uint8Array[] = [];
      for (let i = 0; i < level.length; i += 2) {
        if (i + 1 < level.length) {
          // 两两配对
          const combined = new Uint8Array(level[i].length + level[i + 1].length);
          combined.set(level[i], 0);
          combined.set(level[i + 1], level[i].length);
          nextLevel.push(sha256(combined));
        } else {
          // 奇数：复制自身（按 BEP-0052 填充规则）
          const combined = new Uint8Array(level[i].length * 2);
          combined.set(level[i], 0);
          combined.set(level[i], level[i].length);
          nextLevel.push(sha256(combined));
        }
      }
      level = nextLevel;
    }
    return level[0];
  }

  /** 获取 Merkle 根（hex string） */
  rootHex(): string {
    return bytesToHex(this.rootHash);
  }

  /** 获取所有 piece 哈希（hex string） */
  pieceHashesHex(): string[] {
    return this.pieceHashes.map(h => bytesToHex(h));
  }
}

// ============================================================
// 双校验（弱校验 xxHash64 快筛 + 强校验 SHA-256）
// ============================================================

/** xxHash64 弱校验（用于快速排除，非加密） */
export function weakChecksum(data: Uint8Array): bigint {
  // 使用简单的 64 位哈希算法
  let hash = BigInt(0);
  const prime1 = BigInt('11400714785074694791');
  const prime2 = BigInt('14029467366897019727');
  const prime3 = BigInt('1609587929392839161');
  const prime4 = BigInt('9650019240527522597');
  const prime5 = BigInt('2870177450012600261');

  const len = data.length;
  let offset = 0;

  // 处理前 32 字节
  while (offset + 32 <= len) {
    let v1 = prime1 + prime2 * BigInt(data[offset]) + prime3 * BigInt(data[offset + 1]);
    let v2 = prime2 + prime3 * BigInt(data[offset + 4]) + prime4 * BigInt(data[offset + 5]);
    let v3 = prime3 + prime4 * BigInt(data[offset + 8]) + prime5 * BigInt(data[offset + 9]);
    let v4 = prime4 + prime5 * BigInt(data[offset + 12]) + prime1 * BigInt(data[offset + 13]);
    hash ^= v1 + v2 + v3 + v4;
    hash = (hash << BigInt(41)) | (hash >> BigInt(23));
    hash = (hash * prime1) ^ (v1 << BigInt(41)) ^ (v2 << BigInt(23));
    offset += 16;
  }

  // 处理剩余字节
  while (offset < len) {
    hash ^= BigInt(data[offset]) * prime5;
    hash = (hash << BigInt(11)) | (hash >> BigInt(53));
    hash = hash * prime1;
    offset++;
  }

  // 混合
  hash ^= hash >> BigInt(33);
  hash = hash * prime2;
  hash ^= hash >> BigInt(33);
  hash = hash * prime3;
  hash ^= hash >> BigInt(33);

  return hash;
}

// ============================================================
// 指数退避 + 全抖动（AWS 标准）
// ============================================================

/**
 * 计算第 n 次重试的退避延迟（毫秒）
 * delay = random(0, min(64000, 1000 * 2^n))
 */
export function jitteredBackoffMs(retryCount: number): number {
  const cap = 64000;
  const base = 1000;
  const exponential = base * Math.pow(2, Math.min(retryCount, 5));
  const ceiling = Math.min(exponential, cap);
  return Math.floor(Math.random() * (ceiling + 1));
}

/** 判断某错误码是否可重试 */
export function isRetryableStatus(statusCode: number): boolean {
  return [408, 429, 500, 502, 503, 504].includes(statusCode);
}

/** 判断 422（校验失败）是否可重试（业务语义：可重试） */
export function isChecksumFailureRetryable(statusCode: number): boolean {
  return statusCode === 422 || isRetryableStatus(statusCode);
}

// ============================================================
// ETag 格式化工具（协议契约：双引号强校验器）
// ============================================================

/**
 * 将 SHA-256 hex string 格式化为带双引号的 ETag
 * 协议契约：ETag / If-Range 必须为带双引号的 SHA-256 字符串，不加 W/ 前缀
 */
export function formatEtag(sha256Hex: string): string {
  return `"${sha256Hex}"`;
}

/** 解析带双引号的 ETag（去掉引号） */
export function parseEtag(etag: string): string | null {
  const trimmed = etag.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1);
  }
  return null;
}

// ============================================================
// TransferScheduler（全局调度器）
// ============================================================

/** 全局调度器：管理多个 PeerSession 并发传输 */
export class TransferScheduler {
  private peers: Map<string, PeerSession> = new Map();
  private maxConcurrentReceivers: number;
  private concurrentChunksPerPeer: number;
  private globalChunksPermits: number;
  private retryPermits: number;

  constructor(
    maxConcurrentReceivers = 3,
    concurrentChunksPerPeer = 4
  ) {
    this.maxConcurrentReceivers = maxConcurrentReceivers;
    this.concurrentChunksPerPeer = concurrentChunksPerPeer;
    this.globalChunksPermits = maxConcurrentReceivers * concurrentChunksPerPeer;
    this.retryPermits = 4; // 最多 4 个在途重试
  }

  /** 注册一个接收端会话 */
  addPeer(ip: string, port: number): string {
    const key = `${ip}:${port}`;
    const sessionId = generateSessionId();
    const session: PeerSession = {
      peerIp: ip,
      peerPort: port,
      sessionId,
      state: 'idle',
      files: new Map(),
      createdAt: Date.now(),
      lastHeartbeat: Date.now(),
    };
    this.peers.set(key, session);
    return sessionId;
  }

  /** 获取一个 PeerSession */
  getPeer(ip: string, port: number): PeerSession | undefined {
    const key = `${ip}:${port}`;
    return this.peers.get(key);
  }

  /** 移除一个 PeerSession */
  removePeer(ip: string, port: number): void {
    const key = `${ip}:${port}`;
    this.peers.delete(key);
  }

  /** 获取当前所有活跃会话数 */
  activePeerCount(): number {
    return this.peers.size;
  }

  /** 标记会话状态 */
  setPeerState(ip: string, port: number, state: TransferPhase): void {
    const session = this.getPeer(ip, port);
    if (session) {
      session.state = state;
    }
  }

  /** 更新心跳 */
  touchPeer(ip: string, port: number): void {
    const session = this.getPeer(ip, port);
    if (session) {
      session.lastHeartbeat = Date.now();
    }
  }

  /** 获取超时会话并标记为 paused */
  checkTimeouts(timeoutMs: number): string[] {
    const timedOut: string[] = [];
    const now = Date.now();
    for (const [key, session] of this.peers) {
      if (now - session.lastHeartbeat > timeoutMs && session.state !== 'paused') {
        session.state = 'paused';
        timedOut.push(key);
      }
    }
    return timedOut;
  }

  /** 全局信号量引用 */
  getGlobalChunksPermits(): number {
    return this.globalChunksPermits;
  }

  getRetryPermits(): number {
    return this.retryPermits;
  }

  getMaxConcurrentReceivers(): number {
    return this.maxConcurrentReceivers;
  }

  getConcurrentChunksPerPeer(): number {
    return this.concurrentChunksPerPeer;
  }
}

// ============================================================
// FileManifest 构建工具
// ============================================================

/**
 * 从文件数据构建 FileManifest（scheduler v1 协议用）
 */
export function buildSchedulerManifest(
  fileId: string,
  fileName: string,
  fileSize: number,
  chunkSize: number
): FileManifest {
  return logger.startActiveSpan('scheduler.buildManifest', (span) => {
    span.setAttributes({
      'file.id': fileId,
      'file.name': fileName,
      'file.size': fileSize,
      'file.chunk_size': chunkSize,
      'file.is_large': fileSize > 100 * 1024 * 1024,
    });

    const manifest: FileManifest = {
      id: fileId,
      fileName,
      size: fileSize,
      chunkSize,
      sha256: '',
      merkleRoot: undefined,
      pieceHashes: [],
    };

    span.end();
    return manifest;
  });
}

/**
 * 大文件（>100MB）才需要 Merkle 树，小文件直接返回 null
 */
export function buildManifestIfNeeded(
  fileId: string,
  fileName: string,
  fileSize: number
): FileManifest | null {
  const LARGE_THRESHOLD = 100 * 1024 * 1024; // 100MB
  const CHUNK_SIZE = 4 * 1024 * 1024; // 4MB = piece size

  if (fileSize > LARGE_THRESHOLD) {
    return buildSchedulerManifest(fileId, fileName, fileSize, CHUNK_SIZE);
  }
  return null;
}

// ============================================================
// 工具函数
// ============================================================

/** 生成会话 ID（P2-PF6：改用 CSPRNG 的 randomUUID，替代可预测的 Math.random） */
function generateSessionId(): string {
  // Web Crypto 可用时用随机 UUID；极端旧环境回退（非加密用途，仅保障唯一性）
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return 'sess_' + crypto.randomUUID().replace(/-/g, '').slice(0, 13);
  }
  return 'sess_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

/** 计算 SHA-256（8KB 缓冲区） */
function sha256(data: Uint8Array): Uint8Array {
  // 使用 Web Crypto API（异步）
  // 实际使用时通过 sha256HexAsync 调用
  return sha256Sync(data);
}

/**
 * SHA-256 同步实现
 * 浏览器环境：SubtleCrypto 是纯异步 API，本函数抛出错误，强制使用 sha256HexAsync()
 * Node.js 环境：使用 crypto.createHash
 */
function sha256Sync(data: Uint8Array): Uint8Array {
  // 浏览器环境：SubtleCrypto 是纯异步 API，无同步实现
  // 必须在浏览器中使用 crypto.subtle.digest('SHA-256', data) 并 await 结果
  // 本函数在浏览器中抛出错误，强制使用 sha256HexAsync()
  if (typeof globalThis.crypto !== 'undefined' && 'subtle' in globalThis.crypto) {
    throw new Error('SHA-256 is async in browser environment. Use sha256HexAsync() instead.');
  }
  // Node.js 环境：使用真的 SHA-256
  try {
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256');
    hash.update(Buffer.from(data));
    return new Uint8Array(hash.digest());
  } catch (e) {
    throw new Error('SHA-256 computation failed in Node.js: ' + (e as Error).message);
  }
}

/**
 * 计算 SHA-256 并返回 hex 字符串（异步，推荐用于生产环境）
 */
export async function sha256HexAsync(data: Uint8Array): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data as BufferSource);
  const hashArray = new Uint8Array(hashBuffer);
  return bytesToHex(hashArray);
}

/** 计算 SHA-256 并返回 hex 字符串（同步，仅用于 Node.js 或开发测试） */
export function sha256HexSync(data: Uint8Array): string {
  const hash = sha256Sync(data);
  return bytesToHex(hash);
}

/** bytesToHex */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** hexToBytes */
function hexToBytes(hex: string): Uint8Array | null {
  try {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
  } catch {
    return null;
  }
}

// ============================================================
// HTTP 响应类型
// ============================================================

/** GET /diff 响应 */
export type DiffResponse =
  | { type: 'matched'; data: Uint8Array }
  | { type: 'checksumMismatch'; expected: string; actual: string }
  | { type: 'rangeNotSatisfiable'; actualTotalSize: number }
  | { type: 'fileChanged' };

/** prepare-upload 响应（扩展） */
export interface SchedulerPrepareResponse {
  sessionId: string;
  files: Map<string, string>; // fileId -> token
  chunkDiff?: Map<string, ChunkDiff>; // scheduler v1 扩展
}

// ============================================================
// 分片级失败用户交互（M1）
// chunk 连续失败 3 次 → 询问用户选择：重试 / 跳过文件 / 中止
// ============================================================

/** 用户对分片反复失败的选择（M1 + R2 修正）：
 *  - 'skip_file'：跳过当前文件，继续下一个
 *  - 'abort'：中止整次传输
 *  成功时 uploadChunkWithRetryUI 返回 null（不在此类型中）*/
export type ChunkFailureAction = 'skip_file' | 'abort';

/** 分片失败时的用户交互回调（M1）。
 *  弹窗询问用户选择，返回 Promise<ChunkFailureAction>。
 *  默认实现：直接返回 'abort'（CI/无 UI 环境）。*/
export interface ChunkFailureHandler {
  onChunkRetryExhausted(
    fileId: string,
    fileName: string,
    chunkIndex: number,
    errors: string[],
  ): Promise<ChunkFailureAction>;
}

/** 默认分片失败处理器（无 UI 环境使用，直接 abort） */
export const defaultChunkFailureHandler: ChunkFailureHandler = {
  async onChunkRetryExhausted() {
    return 'abort';
  },
};

/** 带用户交互的 chunk 上传包装器（M1 + R2 修正）。
 *  分片重试达到 maxRetries 次后，调用 handler.onChunkRetryExhausted() 询问用户。
 *
 *  @returns null 表示上传成功；ChunkFailureAction 表示达到最大重试次数后用户的选择
 */
export async function uploadChunkWithRetryUI(
  uploadChunkFn: () => Promise<void>,
  handler: ChunkFailureHandler,
  fileId: string,
  fileName: string,
  chunkIndex: number,
  maxRetries = 3,
): Promise<ChunkFailureAction | null> {
  const errors: string[] = [];
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      await uploadChunkFn();
      return null; // R2 修正：成功返回 null，不返回 'retry'
    } catch (err) {
      errors.push(`${attempt}: ${(err as Error).message ?? String(err)}`);
    }
  }
  // 达到最大重试次数，询问用户
  return handler.onChunkRetryExhausted(fileId, fileName, chunkIndex, errors);
}

// ============================================================
// 续传降级策略（#20）
// 检测对方是否支持 scheduler v1（通过响应头 X-Scheduler-Version），
// 不支持时自动降级为 LocalSend v2 纯文件级续传（全量 SHA-256 校验）。
// ============================================================

/** 调度器版本协商 */
export type SchedulerVersion = 0 | 1;

/** 降级策略配置（#20） */
export const DEGRADATION_STRATEGY = {
  /** 对方不支持 scheduler v1 时的兜底策略 */
  fallback: 'file-level' as const,
  /** 心跳超时阈值（毫秒）：超过则认为对方已断开，触发续传降级 */
  heartbeatTimeoutMs: 5 * 60 * 1000,
  /** 连续心跳失败次数阈值：超过则触发降级或中止 */
  maxHeartbeatFailures: 3,
  /** scheduler v1 特征头（对方返回则表明支持） */
  versionHeader: 'X-Scheduler-Version',
  /** scheduler v1 版本号（双方必须完全匹配才启用） */
  v1Version: '1',
} as const;

/** 从 HTTP 响应头检测对方调度器版本 */
export function detectPeerSchedulerVersion(headers: Record<string, string>): SchedulerVersion {
  const version = headers[DEGRADATION_STRATEGY.versionHeader.toLowerCase()];
  if (version === DEGRADATION_STRATEGY.v1Version) return 1;
  return 0;
}

/** 判断是否应该降级：peer 支持 scheduler v1 则不需要降级 */
export function shouldDegrade(peerVersion: SchedulerVersion): boolean {
  return peerVersion === 0;
}

/** 续传降级包装器：传入 scheduler v1 完整传输函数，降级时执行 v0 兜底逻辑。
 *
 * 降级后的 v0 行为：
 * - prepare-upload 时跳过 chunk-diff 协商（对方不支持）
 * - 文件级续传：按 16MB 分块，整体 SHA-256 匹配则跳过该块
 * - 校验失败时全量重传（无法定位到具体分片）
 *
 * @param fullTransferFn scheduler v1 完整传输函数（返回 Promise<void>）
 * @param degradedFn scheduler v0 降级兜底函数（返回 Promise<void>）
 * @param peerVersion 对端调度器版本
 */
export async function withDegradedResume(
  fullTransferFn: () => Promise<void>,
  degradedFn: () => Promise<void>,
  peerVersion: SchedulerVersion,
): Promise<void> {
  if (shouldDegrade(peerVersion)) {
    logger.info('scheduler', `续传降级：对方不支持 scheduler v1，降级为文件级续传`);
    return degradedFn();
  }
  return fullTransferFn();
}

/** 生成降级后的分块策略（v0 文件级）。
 *  大文件按 16MB 分块，每块独立 SHA-256 校验，校验通过则跳过。
 */
export function buildDegradedChunkPlan(fileSize: number, checkedRanges: Map<number, boolean>): { offset: number; length: number }[] {
  const CHUNK_SIZE = 16 * 1024 * 1024; // 16MB
  const plan: { offset: number; length: number }[] = [];
  let offset = 0;
  while (offset < fileSize) {
    const chunkIndex = Math.floor(offset / CHUNK_SIZE);
    // 如果这个分块已校验通过（peer 存有完整文件），跳过
    if (checkedRanges.get(chunkIndex) === true) {
      offset += CHUNK_SIZE;
      continue;
    }
    const length = Math.min(CHUNK_SIZE, fileSize - offset);
    plan.push({ offset, length });
    offset += CHUNK_SIZE;
  }
  return plan;
}

/** 上传块响应 */
export type UploadChunkResponse =
  | { type: 'ok' }
  | { type: 'checksumFailed'; reason: string };
