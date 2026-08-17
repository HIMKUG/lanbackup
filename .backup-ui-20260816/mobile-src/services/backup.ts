/**
 * backup.ts - 手机端备份服务
 *
 * 整合：三路对比增量扫描（A当前 vs A上次 vs B当前）→ 传输（LocalSend 协议）→ 状态更新。
 * 手机端作为发送端时，扫描决策在本地做；作为接收端时，只负责收。
 *
 * 增量算法（与 shared-core sync.ts 一致）：
 * - 判据：mtime + size（零哈希开销，metadata-only 扫描）
 * - 三路对比：A当前 - A上次 = 新增/变更；A当前 - B当前 = 对端缺失（mirror 自动补传）
 * - 锚点：上次清单 lastManifest 即快照，无需单独的锚点文件
 */

import {
  Manifest,
  buildManifest,
  planIncremental,
  SyncStrategy,
  PeerManifest,
  RegisterDto,
  FileMeta,
  logger,
  ENCRYPT_OVERHEAD,
} from 'shared-core';
import { walkDirectory, PlatformFile, BackupRoot } from './filesystem';
import {
  streamUploadFile,
  prepareUploadNative,
  cancelSessionNative,
  getPeerManifest,
  getSelfCode,
  onUploadProgress,
  moveToDelete,
  getChunkStatus,
  greetDevice,
  pingDevice,
} from './receiver';
import { deviceDisplayName } from 'shared-core';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** 连接类错误（对端接收服务未启动/正在拉起/网络瞬断）：可短暂重试 */
function isConnectError(e: unknown): boolean {
  const msg = e instanceof Error ? e.message : String(e);
  return /Failed to connect|timed out|timeout|unreachable|ECONNREFUSED|error sending request|network/i.test(msg);
}

/** 带重试的执行（仅连接类错误重试；其余立即抛出） */
async function withRetry<T>(fn: () => Promise<T>, attempts: number, delayMs: number): Promise<T> {
  let lastErr: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (e) {
      lastErr = e;
      if (!isConnectError(e)) throw e;
      logger.warn('backup', `连接类失败（第 ${i + 1}/${attempts} 次），${delayMs}ms 后重试`, e);
      await sleep(delayMs);
    }
  }
  throw lastErr;
}

/** 备份进度回调 */
export interface BackupProgress {
  current: number;
  total: number;
  fileName: string;
  /** 已发送字节（原生流式上传块级进度，实时更新） */
  bytesSent?: number;
  /** 当前文件总字节 */
  totalBytes?: number;
}

/** 备份结果（含历史记录所需字节与耗时，以及更新后的对端缺失列表） */
export interface BackupResult {
  manifest: Manifest;
  sent: number;
  bytes: number;
  durationMs: number;
  knownMissingOnPeer: string[];
}

/** 根据文件名推断 LocalSend 文件类型 */
function inferFileType(fileName: string): string {
  const ext = fileName.split('.').pop()?.toLowerCase() ?? '';
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'heic', 'bmp'].includes(ext)) return 'image';
  if (['mp4', 'mov', 'avi', 'mkv', 'webm', '3gp'].includes(ext)) return 'video';
  if (['mp3', 'wav', 'aac', 'flac', 'ogg', 'm4a'].includes(ext)) return 'audio';
  return 'file';
}

/**
 * 手机端作为发送端：三路对比增量扫描 + 传输。
 * @param root 备份根目录
 * @param prevManifest 上次全量清单（=增量快照）
 * @param strategy 增量策略
 * @param selfDeviceId 本机公开设备标识（fingerprint，非加密密钥）
 * @param selfName 本机设备名（唤醒问候携带）
 * @param targetIp 目标设备 IP
 * @param targetPort 目标设备端口
 * @param targetCode 目标设备连接码（非空则加密）
 * @param onProgress 进度回调
 */
export async function sendBackup(
  root: BackupRoot,
  prevManifest: Manifest,
  strategy: SyncStrategy,
  selfDeviceId: string,
  selfName: string,
  targetIp: string,
  targetPort: number,
  targetCode: string,
  knownMissingOnPeer: string[],
  onProgress?: (p: BackupProgress) => void,
): Promise<BackupResult> {
  const t0 = performance.now();
  logger.info(
    'backup',
    `sendBackup 开始: 策略=${strategy} 目标=${targetIp}:${targetPort} 加密=${
      targetCode ? '是' : '否'
    } 上次清单=${Object.keys(prevManifest).length} 条`,
  );

  // 0. 唤醒对端接收服务：连接问候（非 probe）触发对端 peer-connected → 自动拉起其接收服务器。
  // 断网重连/对端重启后，对端 53317 常处于未监听状态（配对服务 53318 常驻所以清单查询仍能成功，
  // 但 prepare-upload 走 53317 会被拒连——「恢复按钮 Failed to connect」的根因）。
  // 问候可达时再等接收端口就绪：对端拉起需 1-2s，就绪前查清单会拿到空清单 → 误判全量重传。
  try {
    await greetDevice({ ip: targetIp, port: targetPort, deviceId: selfDeviceId, name: selfName });
    for (let i = 0; i < 8; i++) {
      try {
        await pingDevice({ ip: targetIp, port: targetPort });
        break;
      } catch {
        await sleep(500);
      }
    }
  } catch {
    logger.warn('backup', '唤醒问候失败（对端可能离线），继续尝试传输');
  }

  // 1. 遍历目录（metadata-only，不读文件内容）
  const walked: PlatformFile[] = await walkDirectory(root.uri);
  // 发送根目录名作为 relPath 第一级：接收端在接收目录下重建「发送文件夹名/...」结构，
  // 与接收目录下已有的子目录平级（如接收 A、发送 A → 接收目录/A/... + 接收目录/b/c）
  const allFiles: PlatformFile[] = walked.map((f) => ({
    ...f,
    relPath: `${root.name}/${f.relPath}`,
  }));
  const t1 = performance.now();
  logger.info('backup', `遍历目录完成: ${allFiles.length} 个文件, 耗时 ${(t1 - t0).toFixed(0)}ms`);

  // 2. 获取 B 端清单（三路对比的第三路；失败退化为两路对比，不阻断）
  let peer: PeerManifest | null = null;
  try {
    peer = await getPeerManifest({ ip: targetIp, port: targetPort });
    logger.info('backup', `对端清单: ${Object.keys(peer.files).length} 个文件`);
  } catch (e) {
    logger.warn('backup', '对端清单获取失败（本次仅做本端增量对比）', e);
  }

  // 3. 三路对比：A当前 vs A上次 vs B当前
  const plan = planIncremental(allFiles, prevManifest, peer, strategy, knownMissingOnPeer);
  const t2 = performance.now();
  logger.info(
    'backup',
    `增量规划完成: 需传输 ${plan.toTransfer.length} 个文件, 耗时 ${(t2 - t1).toFixed(0)}ms`,
  );

  if (plan.toTransfer.length === 0) {
    logger.info('backup', '没有需要传输的文件，结束');
    return { manifest: buildManifest(allFiles), sent: 0, bytes: 0, durationMs: performance.now() - t0, knownMissingOnPeer: plan.missingOnPeer };
  }

  // 4. 传输（全部走原生 HTTP，绕开 WebView CORS 限制）
  // 用 Java 原生 getSelfCode()（与屏幕显示的码一致），不用 TS getSelfConnectionCode()
  // （后者从 Capacitor Filesystem UUID 生成，可能与 Java SharedPreferences UUID 不同）
  const selfCode = await getSelfCode();

  // 安全：info.fingerprint 用公开 deviceId，不用连接码（=加密密钥）
  // 连接码通过明文 HTTP 传输会暴露加密密钥给局域网嗅探者
  const info: RegisterDto = {
    alias: deviceDisplayName(selfCode),
    deviceModel: 'Android',
    deviceType: 'mobile',
    fingerprint: selfDeviceId,
    protocol: 'http',
    port: targetPort,
    download: true,
    version: '0.1.0',
  };

  // 多块 GCM 流式格式（与 Java streamUpload / Rust decrypt_stream 一致）：
  // LSBK(4)+ver(4)+blockSize(4) 头 + 每块(nonce12+ctLen4+tag16) 开销。
  // 上传长度必须按此精确上报——接收端（localsend 服务端）按声明的 size 硬校验 written == size。
  const chunkOverhead = (s: number): number => {
    const BLOCK = 8 * 1024 * 1024;
    const blocks = s > 0 ? Math.ceil(s / BLOCK) : 0;
    return s + 12 + 32 * blocks;
  };
  let totalBytes = 0;
  // 大文件分片：> 8MB 拆分为 __chunked__/{pct}/{idx}/{total} 条目（与 Rust 发送端一致），
  // 断点续传时查询对端已收分片，只传缺失部分
  const CHUNK_SIZE = 8 * 1024 * 1024;
  const files: FileMeta[] = [];
  const fileByRel = new Map<string, FileMeta>();
  const chunkMap = new Map<string, { fileId: string; offset: number; size: number }[]>();
  for (const f of plan.toTransfer) {
    if (f.size > CHUNK_SIZE) {
      const pct = encodeURIComponent(f.relPath);
      const total = Math.ceil(f.size / CHUNK_SIZE);
      const chunks: { fileId: string; offset: number; size: number }[] = [];
      for (let idx = 0; idx < total; idx++) {
        const chunkSize = Math.min(CHUNK_SIZE, f.size - idx * CHUNK_SIZE);
        const id = `f${files.length}`;
        const size = targetCode ? chunkOverhead(chunkSize) : chunkSize;
        const fm: FileMeta = {
          id,
          fileName: `__chunked__/${pct}/${idx}/${total}`,
          size,
          fileType: 'application/octet-stream',
          metadata: { modified: new Date(f.mtime).toISOString() },
        };
        files.push(fm);
        if (idx === 0) fileByRel.set(f.relPath, fm);
        chunks.push({ fileId: id, offset: idx * CHUNK_SIZE, size: chunkSize });
        totalBytes += size;
      }
      chunkMap.set(f.relPath, chunks);
    } else {
      const id = `f${files.length}`;
      const size = targetCode ? chunkOverhead(f.size) : f.size;
      const fm: FileMeta = {
        id,
        fileName: f.relPath,
        size,
        fileType: inferFileType(f.relPath),
        metadata: { modified: new Date(f.mtime).toISOString() },
      };
      files.push(fm);
      fileByRel.set(f.relPath, fm);
      totalBytes += size;
    }
  }

  // 5. prepare-upload 协商会话（原生 HTTP，绕开 CORS；files 为以 fileId 为 key 的字典）。
  // 连接类失败重试 3 次：对端接收服务可能刚被唤醒问候拉起、端口尚未绑定完成
  const filesMap: Record<string, FileMeta> = {};
  for (const fm of files) filesMap[fm.id] = fm;
  const prepared = await withRetry(
    () =>
      prepareUploadNative({
        targetIp,
        targetPort,
        body: JSON.stringify({ info, files: filesMap }),
      }),
    3,
    2000,
  );
  const t3 = performance.now();
  logger.info('backup', `prepare-upload 完成: ${files.length} 个文件, 耗时 ${(t3 - t2).toFixed(0)}ms`);

  // 6. 逐个上传（原生流式加密上传；失败时取消会话，避免接收端残留）
  let sent = 0;
  // 累计已传字节（8 路并发下 JS 单线程自增安全）：进度按整体字节显示，而非当前文件
  let completedBytes = 0;
  // 块级进度：原生 streamUpload 每 ~500ms 推送当前文件已传/总字节。
  // 8 路并发下按 relPath 建索引映射，避免共享可变变量导致进度错乱。
  let unsubUpload: (() => void) | null = null;
  const idxByRel = new Map<string, number>();
  try {
    unsubUpload = await onUploadProgress((p) => {
      const idx = idxByRel.get(p.relPath);
      if (idx !== undefined && onProgress) {
        onProgress({
          current: idx,
          total: plan.toTransfer.length,
          fileName: p.relPath,
          bytesSent: completedBytes + p.bytesSent,
          totalBytes,
        });
      }
    });
    // 上传：每批 8 个并发（手机 8 核+ 16 线程；LocalSend upload 端点可并行，SAF 多线程读取安全）
    // 注意：slice 步长必须与 i 步长一致（i += 8 → slice(i, i + 8)），否则中间文件被跳过，
    // 接收端因永远收不齐文件而卡在"接收中"（曾误写 i+3 导致 85 个只传 33 个）
    for (let i = 0; i < plan.toTransfer.length; i += 8) {
      const batch = plan.toTransfer.slice(i, i + 8);
      let batchSent = 0;
      await Promise.all(
        batch.map(async (f, j) => {
          const idx = i + j;
          idxByRel.set(f.relPath, idx + 1);
          // SAF 读取必须用原始相对路径（不带发送根目录名前缀），否则文件不存在
          const origRel = f.relPath.startsWith(root.name + '/')
            ? f.relPath.slice(root.name.length + 1)
            : f.relPath;
          const chunks = chunkMap.get(f.relPath);
          if (chunks) {
            // 大文件分片：查询对端已收分片，跳过，只传缺失部分（断点续传）
            let received: number[] = [];
            try {
              const r = await getChunkStatus({ ip: targetIp, port: targetPort, encodedPath: encodeURIComponent(f.relPath) });
              received = r.receivedChunks || [];
            } catch {
              // 查询失败则全传
            }
            for (const c of chunks) {
              if (received.includes(c.offset / CHUNK_SIZE)) continue;
              const raw = prepared.files[c.fileId];
              const token = typeof raw === 'string' ? raw : (raw as { token?: string } | undefined)?.token;
              if (!token) continue;
              await streamUploadFile({
                uri: root.uri,
                relPath: origRel,
                targetIp,
                targetPort,
                sessionId: prepared.sessionId,
                fileId: c.fileId,
                token,
                targetCode: targetCode || '',
                offset: c.offset,
                size: c.size,
              });
              completedBytes += c.size;
            }
            batchSent++;
            onProgress?.({
              current: idx + 1,
              total: plan.toTransfer.length,
              fileName: f.relPath,
              bytesSent: completedBytes,
              totalBytes,
            });
            logger.debug('backup', `大文件分片完成 ${idx + 1}/${plan.toTransfer.length}: ${f.relPath}`);
          } else {
            // 普通文件：整文件上传
            const fileMeta = fileByRel.get(f.relPath)!;
            // LocalSend v2.2 协议：prepare-upload 响应 files 的值是"纯字符串 token"（非对象）。
            // 兼容对象/字符串两种形态，避免取 .token 得到 undefined 导致全部文件被跳过。
            const raw = prepared.files[fileMeta.id];
            const token = typeof raw === 'string' ? raw : (raw as { token?: string } | undefined)?.token;
            if (!token) {
              logger.warn('backup', `目标端未接受 ${f.relPath}，跳过`);
              return;
            }
            // 流式上传：原生分块读 + 多块 AES-GCM 加密 + HTTP 流式 POST，大文件内存 O(8MB)
            await streamUploadFile({
              uri: root.uri,
              relPath: origRel,
              targetIp,
              targetPort,
              sessionId: prepared.sessionId,
              fileId: fileMeta.id,
              token,
              targetCode: targetCode || '',
            });
            batchSent++;
            completedBytes += fileMeta.size;
            // 文件完成：补一个最终进度（保证文件级 UI 也即时更新）
            onProgress?.({
              current: idx + 1,
              total: plan.toTransfer.length,
              fileName: f.relPath,
              bytesSent: completedBytes,
              totalBytes,
            });
            logger.debug('backup', `文件上传完成 ${idx + 1}/${plan.toTransfer.length}: ${f.relPath}`);
          }
        }),
      );
      sent += batchSent;
    }
  } catch (e) {
    logger.error('backup', `上传失败（已发送 ${sent}/${plan.toTransfer.length}），取消会话`, e);
    try {
      await cancelSessionNative({ targetIp, targetPort, sessionId: prepared.sessionId });
    } catch {
      // 忽略取消失败
    }
    throw e;
  } finally {
    if (unsubUpload) unsubUpload();
  }
  const t4 = performance.now();
  logger.info('backup', `传输完成: ${sent}/${plan.toTransfer.length} 个文件, 耗时 ${(t4 - t3).toFixed(0)}ms`);

  // 7. 更新清单（=下次备份的 A 上次快照）
  const newManifest = buildManifest(allFiles);
  logger.info(
    'backup',
    `sendBackup 完成: 共 ${sent} 个文件 ${totalBytes}B, 总耗时 ${(performance.now() - t0).toFixed(0)}ms`,
  );
  // 镜像模式：对端多余文件移动到其 delete 文件夹（假删除，保持目录一致）
  if (strategy === 'mirror' && plan.peerExtra.length > 0) {
    try {
      await moveToDelete({ ip: targetIp, port: targetPort, files: plan.peerExtra });
    } catch (e) {
      logger.warn('backup', '镜像模式移动多余文件失败', e);
    }
  }
  return { manifest: newManifest, sent, bytes: totalBytes, durationMs: performance.now() - t0, knownMissingOnPeer: plan.missingOnPeer };
}
