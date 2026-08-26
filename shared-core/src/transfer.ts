/**
 * transfer.ts - HTTP 传输协议（TS 重写 LocalSend v2.2）
 *
 * 手机端用 TS 重写 LocalSend v2.2 协议，协议兼容，可与原版互传。
 * 电脑端直接复用 Rust crate，本模块仅作为手机端实现。
 *
 * 协议端点：
 * - POST /api/localsend/v2/register      设备注册/发现
 * - POST /api/localsend/v2/prepare-upload 准备上传（协商会话）
 * - POST /api/localsend/v2/upload         上传文件
 * - POST /api/localsend/v2/cancel         取消
 * - GET  /api/localsend/v2/info           设备信息
 *
 * 安全版本字段（#13 协议版本协商）：
 * - version: 当前协议版本
 * - minVersion: 最低兼容版本
 * - kdfVersion: KDF 版本（1=SHA-256, 2=PBKDF2）
 * - cryptoVersion: 加密版本（1=连接码直接派生, 2=ECDH）
 */

import { logger, maskSecret, summarizeList } from './logger.js';
import { SpanStatusCode } from '@opentelemetry/api';
import { jitteredBackoffMs, isChecksumFailureRetryable, formatEtag, parseEtag } from './scheduler.js';
import {
  PROTOCOL_VERSION,
  MIN_PROTOCOL_VERSION,
  KDF_VERSION,
  CRYPTO_VERSION,
  PBKDF2_ITERATIONS,
} from './identity.js';

/** 加密格式：LSBK(4) || nonce(12) || ciphertext+tag —— 与 Rust/Java 端一致 */
const MAGIC = new Uint8Array([0x4c, 0x53, 0x42, 0x4b]); // "LSBK"
const NONCE_LEN = 12;
/** 加密总开销（魔数 + nonce + GCM tag） */
export const ENCRYPT_OVERHEAD = 32;

/**
 * 由连接码派生 AES-256-GCM 密钥（PBKDF2，#9 KDF 加固）。
 *
 * Salt 来源：配对时由发起方生成随机 32 字节，编码在 QR Code 中传递。
 * 两端用相同的 password + salt 派生出相同的密钥。
 *
 * 用途（#9 修复后的定位）：
 * - 用于本地存储加密（SQLite/SharedPreferences 中的配对记录加密）
 * - 用于 ECDH 共享密钥的二次派生（ECDH_shared → PBKDF2 → session_key）
 * - 不再用于传输加密（#8 完成后传输加密完全来自 ECDH）
 *
 * @param password 密钥派生密码（连接码或 DH 共享密钥）
 * @param salt 盐值（配对时传递，32 字节 Base64 编码）
 */
async function deriveKeyPBKDF2(password: string | Uint8Array, salt: string): Promise<[CryptoKey, Uint8Array]> {
  const saltBytes = Uint8Array.from(atob(salt), c => c.charCodeAt(0));

  // 导入 password 为 PBKDF2 密钥材料
  const keyBytes = password instanceof Uint8Array ? password : new TextEncoder().encode(password);
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );

  return [key, saltBytes];
}

/**
 * AES-256-GCM 加密（Web Crypto），输出 `LSBK || nonce || ciphertext || tag`。
 * 与 desktop/src-tauri/src/crypto.rs、LocalReceiverPlugin.java 的格式完全一致。
 *
 * @param plaintext 要加密的明文
 * @param key AES-256 密钥（从 deriveKeyPBKDF2 派生）
 */
async function encryptWithKey(plaintext: ArrayBuffer, key: CryptoKey): Promise<Blob> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plaintext);
  const out = new Uint8Array(MAGIC.length + NONCE_LEN + ciphertext.byteLength);
  out.set(MAGIC, 0);
  out.set(nonce, MAGIC.length);
  out.set(new Uint8Array(ciphertext), MAGIC.length + NONCE_LEN);
  return new Blob([out]);
}

/**
 * AES-256-GCM 解密。
 * @param ciphertext 密文（LSBK 格式）
 * @param key AES-256 密钥
 */
async function decryptWithKey(ciphertext: ArrayBuffer, key: CryptoKey): Promise<ArrayBuffer> {
  const data = new Uint8Array(ciphertext);
  if (data.length < MAGIC.length + NONCE_LEN) throw new Error('密文长度不足');
  const nonce = data.slice(MAGIC.length, MAGIC.length + NONCE_LEN);
  const ct = data.slice(MAGIC.length + NONCE_LEN);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct);
}

/**
 * 加密数据（兼容性封装）。
 * @param plaintext 明文
 * @param targetCode 连接码（KDF v1 兼容）或 DH 共享密钥（KDF v2）
 * @param salt PBKDF2 salt（KDF v2），KDF v1 时传空字符串
 */
export async function encryptData(plaintext: ArrayBuffer, targetCode: string, salt = ''): Promise<Blob> {
  if (KDF_VERSION === 2 && salt) {
    const [key] = await deriveKeyPBKDF2(targetCode, salt);
    return encryptWithKey(plaintext, key);
  }
  // KDF v1 兼容路径（#9 修复前的老设备）
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(targetCode));
  const key = await crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['encrypt']);
  return encryptWithKey(plaintext, key);
}

/**
 * 解密数据（兼容性封装）。
 */
export async function decryptData(ciphertext: ArrayBuffer, targetCode: string, salt = ''): Promise<ArrayBuffer> {
  if (KDF_VERSION === 2 && salt) {
    const [key] = await deriveKeyPBKDF2(targetCode, salt);
    return decryptWithKey(ciphertext, key);
  }
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(targetCode));
  const key = await crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['decrypt']);
  return decryptWithKey(ciphertext, key);
}

/** 协议类型 */
export type ProtocolType = 'http' | 'https';

/** 设备信息（register 请求体，字段与 LocalSend core `RegisterDtoV2` 对齐，camelCase）
 *  #13 协议版本协商：新增 version/minVersion/kdfVersion/cryptoVersion 字段
 */
export interface RegisterDto {
  alias: string;
  deviceModel: string;
  deviceType: string;
  fingerprint: string;
  protocol: 'http' | 'https';
  /** 本机监听端口（协议必填，缺失会被接收端 400 拒绝） */
  port: number;
  download: boolean;
  version: string;
  /** 最低兼容协议版本 */
  minVersion?: string;
  /** KDF 版本：1=SHA-256, 2=PBKDF2 */
  kdfVersion?: number;
  /** 加密版本：1=连接码直接派生, 2=ECDH */
  cryptoVersion?: number;
}

/** register 响应（字段与 LocalSend core `RegisterResponseDtoV2` 对齐） */
export interface RegisterResponseDto {
  alias: string;
  version: string;
  deviceModel?: string;
  deviceType?: string;
  fingerprint: string;
  download: boolean;
  /** 服务端返回的 KDF 版本（用于客户端判断兼容性） */
  kdfVersion?: number;
  /** 服务端返回的加密版本 */
  cryptoVersion?: number;
}

/** 单个文件元数据 */
export interface FileMeta {
  id: string;
  fileName: string;
  size: number;
  fileType: string;
  sha256?: string;
  preview?: string;
  /** 文件修改时间（RFC3339），接收端据此保留 mtime，保证增量锚点准确 */
  metadata?: { modified: string };
  /** scheduler v1 扩展：支持的扩展协议 */
  protocolExtensions?: string[];
  /** scheduler v1 扩展：Merkle 树根 */
  merkleRoot?: string;
  /** scheduler v1 扩展：每个 piece 的 SHA-256 */
  pieceHashes?: string[];
  /** scheduler v1 扩展：分片大小（= piece 大小 = 4MB） */
  chunkSize?: number;
}

/** prepare-upload 请求体 */
export interface PrepareUploadRequestDto {
  info: RegisterDto;
  /** 以 fileId 为 key 的字典（LocalSend v2.2 协议要求） */
  files: Record<string, FileMeta>;
}

/** prepare-upload 响应（LocalSend v2.2：files 值是纯字符串 token） */
export interface PrepareUploadResponseDto {
  sessionId: string;
  files: Record<string, string>;
}

/** 传输进度回调 */
export type ProgressCallback = (sentBytes: number, totalBytes: number) => void;

/** 默认请求超时（毫秒） */
const DEFAULT_TIMEOUT = 30000;

/** 带超时的 fetch 封装，超时后中止并抛出可读错误 */
async function fetchWithTimeout(
  url: string,
  init: RequestInit = {},
  timeoutMs: number = DEFAULT_TIMEOUT,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') {
      throw new Error(`请求超时（${timeoutMs}ms）`);
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/** 从错误响应中提取诊断信息（LocalSend 返回 JSON 错误体） */
async function errorDetail(res: Response): Promise<string> {
  try {
    const text = await res.text();
    if (!text) return `HTTP ${res.status}`;
    try {
      const json = JSON.parse(text);
      return json.message || json.error || text;
    } catch {
      return text;
    }
  } catch {
    return `HTTP ${res.status}`;
  }
}

/** 传输客户端 */
export class TransferClient {
  private baseUrl: string;
  /** 目标设备连接码（非空则对上传内容做 AES-256-GCM 加密） */
  private targetCode: string;

  constructor(protocol: ProtocolType, ip: string, port: number, targetCode = '') {
    this.baseUrl = `${protocol}://${ip}:${port}`;
    this.targetCode = targetCode;
  }

  /**
   * 注册设备（发现阶段）。
   */
  async register(payload: RegisterDto): Promise<RegisterResponseDto> {
    const url = `${this.baseUrl}/api/localsend/v2/register`;
    logger.debug(
      'transfer',
      `register → ${url} alias=${payload.alias} 指纹=${maskSecret(payload.fingerprint)}`,
    );
    try {
      const res = await fetchWithTimeout(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      logger.info('transfer', `register ← ${res.status} (${url})`);
      if (!res.ok) throw new Error(`register failed: ${await errorDetail(res)}`);
      return res.json();
    } catch (e) {
      logger.error('transfer', `register 失败 (${url})`, e);
      throw e;
    }
  }

  /**
   * 准备上传（协商会话）。
   * @returns sessionId 和每个文件的 token
   */
  async prepareUpload(payload: PrepareUploadRequestDto): Promise<PrepareUploadResponseDto> {
    const url = `${this.baseUrl}/api/localsend/v2/prepare-upload`;
    const names = Object.values(payload.files).map((f) => f.fileName);
    logger.debug(
      'transfer',
      `prepare-upload → ${url} 文件 ${names.length} 个: ${summarizeList(names)}`,
    );
    try {
      const res = await fetchWithTimeout(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (res.status === 204) {
        // 无文件需要传输
        logger.info('transfer', `prepare-upload ← 204 无文件需要传输`);
        return { sessionId: '', files: {} };
      }
      logger.info('transfer', `prepare-upload ← ${res.status} (${url})`);
      if (!res.ok) throw new Error(`prepare-upload failed: ${await errorDetail(res)}`);
      return res.json();
    } catch (e) {
      logger.error('transfer', `prepare-upload 失败 (${url})`, e);
      throw e;
    }
  }

  /**
   * 上传单个文件。
   * @param sessionId 会话 ID
   * @param fileId 文件 ID
   * @param token 文件 token
   * @param content 文件内容（Blob）
   * @param onProgress 进度回调
   */
  async upload(
    sessionId: string,
    fileId: string,
    token: string,
    content: Blob,
    onProgress?: ProgressCallback,
  ): Promise<void> {
    // 加密（若需要）先于 span 完成，避免 await 问题
    let body = content;
    if (this.targetCode) {
      try {
        const plaintext = await content.arrayBuffer();
        body = await encryptData(plaintext, this.targetCode);
        logger.debug('transfer', `upload 加密完成: ${content.size}B → ${body.size}B`);
      } catch (e) {
        const err = new Error(`上传前加密失败: ${(e as Error).message}`);
        logger.error('transfer', 'upload 加密失败', err);
        throw err;
      }
    }

    return logger.startActiveSpan('transfer.upload', (span) => {
      span.setAttributes({
        'file.id': fileId,
        'file.size': content.size,
        'session.id': maskSecret(sessionId),
        'upload.encrypted': Boolean(this.targetCode),
      });

      const url = `${this.baseUrl}/api/localsend/v2/upload?sessionId=${encodeURIComponent(
        sessionId,
      )}&fileId=${encodeURIComponent(fileId)}&token=${encodeURIComponent(token)}`;
      logger.debug(
        'transfer',
        `upload → ${url} fileId=${fileId} 大小=${content.size}B 加密=${
          this.targetCode ? '是' : '否'
        } 会话=${maskSecret(sessionId)}`,
      );

      return new Promise<void>((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', url);
        xhr.setRequestHeader('Content-Type', 'application/octet-stream');
        xhr.timeout = DEFAULT_TIMEOUT;
        // #26 进度节流：200ms 间隔限制，避免过频回调导致 UI 卡顿
        let lastProgressMs = 0;
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable && onProgress) {
            const now = performance.now();
            if (now - lastProgressMs >= 200) {
              lastProgressMs = now;
              onProgress(e.loaded, e.total);
            }
          }
        };
        xhr.onload = () => {
          if (xhr.status === 200) {
            logger.info('transfer', `upload ← 200 fileId=${fileId} 完成`);
            span.end();
            resolve();
          } else {
            const err = new Error(`upload failed: ${xhr.status}`);
            logger.error('transfer', `upload ← ${xhr.status} fileId=${fileId}`, err);
            span.setStatus({ code: SpanStatusCode.ERROR, message: 'HTTP_FAIL' });
            span.recordException(err);
            span.end();
            reject(err);
          }
        };
        xhr.onerror = () => {
          const err = new Error('upload network error');
          logger.error('transfer', `upload 网络错误 fileId=${fileId}`, err);
          span.setStatus({ code: SpanStatusCode.ERROR, message: 'HTTP_FAIL' });
          span.recordException(err);
          span.end();
          reject(err);
        };
        xhr.ontimeout = () => {
          const err = new Error(`upload timeout (${DEFAULT_TIMEOUT}ms)`);
          logger.error('transfer', `upload 超时 fileId=${fileId}`, err);
          span.setStatus({ code: SpanStatusCode.ERROR, message: 'TIMEOUT' });
          span.recordException(err);
          span.end();
          reject(err);
        };
        xhr.send(body);
      });
    });
  }

  /**
   * 取消传输会话。
   */
  async cancel(sessionId: string): Promise<void> {
    const url = `${this.baseUrl}/api/localsend/v2/cancel?sessionId=${encodeURIComponent(sessionId)}`;
    logger.debug('transfer', `cancel → ${url} 会话=${maskSecret(sessionId)}`);
    try {
      const res = await fetchWithTimeout(url, { method: 'POST' });
      logger.info('transfer', `cancel ← ${res.status}`);
      if (!res.ok) throw new Error(`cancel failed: ${await errorDetail(res)}`);
    } catch (e) {
      logger.error('transfer', `cancel 失败`, e);
      throw e;
    }
  }

  // ============================================================
  // scheduler v1 扩展协议
  // ============================================================

  /**
   * scheduler v1: GET /file/{fileId}/diff - 探测块是否存在 + SHA-256 校验
   * 协议契约：
   * - 206 + Content-Range: 块存在且 ETag 匹配
   * - 412: 块存在但 SHA-256 不匹配（NACK）
   * - 416 + Content-Range: bytes * /{total}: Range 不满足
   * - 200: ETag 不匹配（文件已变），需全量重传
   */
  async getDiff(
    sessionId: string,
    fileId: string,
    chunkIndex: number,
    chunkSize: number,
    etag: string, // 带双引号的 ETag
  ): Promise<{ status: number; data?: Uint8Array; expected?: string; actual?: string; actualTotalSize?: number }> {
    const rangeStart = chunkIndex * chunkSize;
    const rangeEnd = rangeStart + chunkSize - 1;
    const url = `${this.baseUrl}/api/localsend/v2/file/${fileId}/diff?sessionId=${encodeURIComponent(sessionId)}&range=bytes=${rangeStart}-${rangeEnd}&ifRange=${encodeURIComponent(etag)}`;
    logger.debug('transfer', `GET /diff → ${url}`);

    try {
      const res = await fetchWithTimeout(url, { method: 'GET' });
      const status = res.status;

      if (status === 416) {
        // 解析 Content-Range 获取 actualTotalSize
        const contentRange = res.headers.get('Content-Range');
        const totalSizeMatch = contentRange?.match(/bytes \*\/(\d+)/);
        const actualTotalSize = totalSizeMatch ? parseInt(totalSizeMatch[1], 10) : 0;
        logger.info('transfer', `GET /diff ← 416 Range Not Satisfiable, total=${actualTotalSize}`);
        return { status, actualTotalSize };
      }

      if (status === 412) {
        // SHA-256 不匹配
        const body = await res.json();
        logger.info('transfer', `GET /diff ← 412 NACK: expected=${body.expected}, actual=${body.actual}`);
        return { status, expected: body.expected, actual: body.actual };
      }

      if (status === 206) {
        // 块存在且匹配
        const data = new Uint8Array(await res.arrayBuffer());
        logger.info('transfer', `GET /diff ← 206 matched, data=${data.length}B`);
        return { status, data };
      }

      if (status === 200) {
        // 文件已变
        logger.info('transfer', `GET /diff ← 200 file changed`);
        return { status };
      }

      throw new Error(`GET /diff 未知响应: ${status}`);
    } catch (e) {
      logger.error('transfer', `GET /diff 失败`, e);
      throw e;
    }
  }

  /**
   * scheduler v1: GET /file/{fileId}/verify - 整体文件校验
   */
  async fileVerify(sessionId: string, fileId: string): Promise<{ status: number; sha256?: string; success?: boolean }> {
    const url = `${this.baseUrl}/api/localsend/v2/file/${fileId}/verify?sessionId=${encodeURIComponent(sessionId)}`;
    logger.debug('transfer', `GET /verify → ${url}`);

    try {
      const res = await fetchWithTimeout(url, { method: 'GET' });
      const status = res.status;

      if (status === 200) {
        const body = await res.json();
        logger.info('transfer', `GET /verify ← 200 sha256=${body.sha256}`);
        return { status, sha256: body.sha256, success: body.success };
      }

      if (status === 404) {
        logger.info('transfer', `GET /verify ← 404 file not found`);
        return { status, success: false };
      }

      if (status === 422) {
        const body = await res.json();
        logger.info('transfer', `GET /verify ← 422 verification failed: ${body.reason}`);
        return { status, success: false };
      }

      throw new Error(`GET /verify 未知响应: ${status}`);
    } catch (e) {
      logger.error('transfer', `GET /verify 失败`, e);
      throw e;
    }
  }

  /**
   * scheduler v1: POST /session/heartbeat - 心跳保活
   */
  async sessionHeartbeat(sessionId: string): Promise<void> {
    const url = `${this.baseUrl}/api/localsend/v2/session/heartbeat`;
    const body = JSON.stringify({ sessionId });
    logger.debug('transfer', `POST /heartbeat → ${url}`);

    try {
      const res = await fetchWithTimeout(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      if (!res.ok) {
        logger.warn('transfer', `POST /heartbeat ← ${res.status}`);
      }
    } catch (e) {
      logger.error('transfer', `POST /heartbeat 失败`, e);
      // 心跳失败不阻断传输
    }
  }

  /**
   * scheduler v1: POST /session/abort - 中止会话
   */
  async sessionAbort(sessionId: string): Promise<void> {
    const url = `${this.baseUrl}/api/localsend/v2/session/abort`;
    const body = JSON.stringify({ sessionId });
    logger.debug('transfer', `POST /abort → ${url}`);

    try {
      const res = await fetchWithTimeout(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      logger.info('transfer', `POST /abort ← ${res.status}`);
    } catch (e) {
      logger.error('transfer', `POST /abort 失败`, e);
    }
  }

  /**
   * 上传单个文件（带 scheduler v1 422 重试 + 指数退避）
   * @param maxRetries 最大重试次数（默认 5）
   */
  async uploadWithRetry(
    sessionId: string,
    fileId: string,
    token: string,
    content: Blob,
    onProgress?: ProgressCallback,
    maxRetries = 5,
  ): Promise<void> {
    // maxRetries 上限检查，防止 Infinity 或负数
    const safeMaxRetries = Math.max(0, Math.min(maxRetries, 100));
    for (let attempt = 0; attempt <= safeMaxRetries; attempt++) {
      try {
        await this.upload(sessionId, fileId, token, content, onProgress);
        return; // 成功
      } catch (e) {
        const err = e as Error;
        // 提取状态码
        const statusMatch = err.message.match(/status[\s:=]*(\d{3})/i);
        const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;

        // 仅 422/408/429/5xx 可重试
        if (!isChecksumFailureRetryable(status)) {
          logger.error('transfer', `upload 失败（不重试 status=${status}): ${err.message}`);
          throw e;
        }

        if (attempt >= safeMaxRetries) {
          logger.error('transfer', `upload 重试耗尽（status=${status}): ${err.message}`);
          throw e;
        }

        const delayMs = jitteredBackoffMs(attempt);
        logger.warn('transfer', `upload 422 校验失败，重试 ${attempt + 1}/${safeMaxRetries}（delay=${delayMs}ms）: ${err.message}`);
        await new Promise(resolve => setTimeout(resolve, delayMs));
        // 重试时会重新读取文件内容并上传
      }
    }
  }
}

// ============================================================
// tiny 文件批量聚合规划（传输层优化规格书 P0）
// ============================================================

import { classifyFile, type ScannedFile } from './scan.js';

/**
 * tiny 文件批量聚合规划：把 tiny 文件按每批 batchSize 个划分批次。
 * 每批打包为单一 ustar tar 流，经一个 prepare-upload + 一个 upload 传输，
 * 消除海量小文件的逐文件握手开销（万次握手 → 1 次连接）。
 * tar 字节打包由平台层实现（desktop Rust tar_pack_tiny / Java unpackTarBatch）。
 * @param files 扫描到的文件（含 tiny）
 * @param batchSize 每批成员数（50-100 为工程平衡点）
 */
export function planTinyBatches(
  files: ScannedFile[],
  batchSize = 75,
): { batch: ScannedFile[]; batchTarSize: number }[] {
  const tiny = files.filter((f) => classifyFile(f) === 'tiny');
  const batches: { batch: ScannedFile[]; batchTarSize: number }[] = [];
  for (let i = 0; i < tiny.length; i += batchSize) {
    const batch = tiny.slice(i, i + batchSize);
    // ustar 头 512B/成员 + 数据 512 对齐 + 结尾两个零块 1024B
    let tarSize = 1024;
    for (const f of batch) {
      tarSize += 512 + Math.ceil(f.size / 512) * 512;
    }
    batches.push({ batch, batchTarSize: tarSize });
  }
  return batches;
}

// ============================================================
// 传输单元抽象与规划（性能规格书 P0/P1）
// ============================================================

/** 传输策略配置（局域网 100MB/s+、RTT 1-3ms 的工程参数） */
export const TRANSFER_CONFIG = {
  /** 8MB 大分块：协议头开销与单分片失败重传成本的最优平衡 */
  CHUNK_SIZE: 8 * 1024 * 1024,
  /** 电脑→手机 8 路文件并发 */
  CONCURRENT_FILES_DESKTOP: 8,
  /** 手机→电脑 8 路文件并发（8 核+ 16 线程设备） */
  CONCURRENT_FILES_MOBILE: 8,
  /** 单文件内分片并发（预留） */
  CONCURRENT_CHUNKS_PER_FILE: 2,
  /** <10KB 为 tiny */
  TINY_THRESHOLD: 10 * 1024,
  /** tiny 每 20 个聚合为一个 batch */
  TINY_BATCH_SIZE: 20,
  /** >100MB 为大文件（分片续传） */
  LARGE_THRESHOLD: 100 * 1024 * 1024,
} as const;

export type TransferUnitKind = 'single' | 'chunk' | 'batch';

export interface TransferUnit {
  /** {sessionId}:{fileId}:{index} */
  unitId: string;
  fileId: string;
  kind: TransferUnitKind;
  index: number;
  offset: number;
  size: number;
  sha256?: string;
  batchMembers?: { relPath: string; size: number; mtime: number }[];
}

export interface FileTransferPlan {
  sessionId: string;
  fileId: string;
  fileName: string;
  totalSize: number;
  totalUnits: number;
  units: TransferUnit[];
  fileSha256?: string;
  isChunked: boolean;
}

/**
 * 单文件传输规划：
 * - tiny（<10KB）→ batch 单元（平台层把多个 tiny 聚合为 tar 流，单连接传输）
 * - small/normal → single 单元（整文件流式）
 * - large/huge（>100MB）→ chunk 单元数组（8MB 分片，断点续传）
 * 平台层据此调度（桌面 Rust send_files；手机端大文件按降级策略整传）。
 */
export function planFileTransfer(
  file: { relPath: string; size: number; mtime: number },
  fileId: string,
  sessionId: string,
): FileTransferPlan {
  const { CHUNK_SIZE, TINY_THRESHOLD, LARGE_THRESHOLD } = TRANSFER_CONFIG;
  if (file.size > 0 && file.size < TINY_THRESHOLD) {
    return {
      sessionId,
      fileId,
      fileName: file.relPath,
      totalSize: file.size,
      totalUnits: 1,
      units: [
        {
          unitId: `${sessionId}:${fileId}:0`,
          fileId,
          kind: 'batch',
          index: 0,
          offset: 0,
          size: file.size,
          batchMembers: [{ relPath: file.relPath, size: file.size, mtime: file.mtime }],
        },
      ],
      isChunked: false,
    };
  }
  if (file.size > LARGE_THRESHOLD) {
    const total = Math.ceil(file.size / CHUNK_SIZE);
    const units: TransferUnit[] = [];
    for (let i = 0; i < total; i++) {
      const offset = i * CHUNK_SIZE;
      const size = Math.min(CHUNK_SIZE, file.size - offset);
      units.push({
        unitId: `${sessionId}:${fileId}:${i}`,
        fileId,
        kind: 'chunk',
        index: i,
        offset,
        size,
      });
    }
    return {
      sessionId,
      fileId,
      fileName: file.relPath,
      totalSize: file.size,
      totalUnits: total,
      units,
      isChunked: true,
    };
  }
  return {
    sessionId,
    fileId,
    fileName: file.relPath,
    totalSize: file.size,
    totalUnits: 1,
    units: [
      { unitId: `${sessionId}:${fileId}:0`, fileId, kind: 'single', index: 0, offset: 0, size: file.size },
    ],
    isChunked: false,
  };
}
