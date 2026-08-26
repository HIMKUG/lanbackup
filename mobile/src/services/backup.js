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
import { buildManifest, planIncremental, logger, } from 'shared-core';
import { walkDirectory } from './filesystem';
import { streamUploadFile, prepareUploadNative, cancelSessionNative, getPeerManifest, getSelfCode, onUploadProgress, moveToDelete, getChunkStatus, } from './receiver';
import { deviceDisplayName } from 'shared-core';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** 连接类错误（对端接收服务未启动/正在拉起/网络瞬断）：可短暂重试 */
function isConnectError(e) {
    const msg = e instanceof Error ? e.message : String(e);
    return /Failed to connect|timed out|timeout|unreachable|ECONNREFUSED|error sending request|network/i.test(msg);
}
/** 带重试的执行（仅连接类错误重试；其余立即抛出） */
async function withRetry(fn, attempts, delayMs) {
    let lastErr;
    for (let i = 0; i < attempts; i++) {
        try {
            return await fn();
        }
        catch (e) {
            lastErr = e;
            if (!isConnectError(e))
                throw e;
            logger.warn('backup', `连接类失败（第 ${i + 1}/${attempts} 次），${delayMs}ms 后重试`, e);
            await sleep(delayMs);
        }
    }
    throw lastErr;
}
/**
 * Rust percent-encoding 子集（与 Rust percent_encoding 库保留字符一致）。
 * 修复：Rust pct_encode 保留 A-Za-z0-9-_.~，TS encodeURIComponent 额外保留 !~*'()。
 * 差异字符 !~'() 会导致 getChunkStatus 查询路径与接收端分片目录名不匹配。
 */
function rustPctEncode(path) {
    const SAFE = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~');
    let encoded = '';
    for (const ch of path) {
        if (SAFE.has(ch)) {
            encoded += ch;
        }
        else {
            encoded += '%' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');
        }
    }
    return encoded;
}
/** 根据文件名推断 LocalSend 文件类型 */
function inferFileType(fileName) {
    const ext = fileName.split('.').pop()?.toLowerCase() ?? '';
    if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'heic', 'bmp'].includes(ext))
        return 'image';
    if (['mp4', 'mov', 'avi', 'mkv', 'webm', '3gp'].includes(ext))
        return 'video';
    if (['mp3', 'wav', 'aac', 'flac', 'ogg', 'm4a'].includes(ext))
        return 'audio';
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
 * @param onMirrorConfirm 镜像清理确认（收到真实多余文件数，返回是否执行；不注入则默认执行）
 */
export async function sendBackup(root, prevManifest, strategy, selfDeviceId, selfName, targetIp, targetPort, targetCode, targetFingerprint, knownMissingOnPeer, onProgress, onMirrorConfirm) {
    const t0 = performance.now();
    logger.info('backup', `sendBackup 开始: 策略=${strategy} 目标=${targetIp}:${targetPort} 加密=${targetCode ? '是' : '否'} 上次清单=${Object.keys(prevManifest).length} 条`);
    // P2 硬升级：v2 问候（greetDevice）/ 探测（pingDevice）已删除，无法再触发对端拉起接收服务。
    // 对端接收服务就绪由 prepare-upload 的 withRetry 重试兜底（连接类失败自动重试 3 次）。
    // 1. 遍历目录（metadata-only，不读文件内容）
    const walked = await walkDirectory(root.uri);
    // 发送根目录名作为 relPath 第一级：接收端在接收目录下重建「发送文件夹名/...」结构，
    // 与接收目录下已有的子目录平级（如接收 A、发送 A → 接收目录/A/... + 接收目录/b/c）
    const allFiles = walked.map((f) => ({
        ...f,
        relPath: `${root.name}/${f.relPath}`,
    }));
    const t1 = performance.now();
    logger.info('backup', `遍历目录完成: ${allFiles.length} 个文件, 耗时 ${(t1 - t0).toFixed(0)}ms`);
    // 2. 获取 B 端清单（三路对比的第三路；失败退化为两路对比，不阻断）
    let peer = null;
    try {
        peer = await getPeerManifest({ ip: targetIp, port: targetPort });
        logger.info('backup', `对端清单: ${Object.keys(peer.files).length} 个文件`);
    }
    catch (e) {
        logger.warn('backup', '对端清单获取失败（本次仅做本端增量对比）', e);
    }
    // 3. 三路对比：A当前 vs A上次 vs B当前
    // BUG FIX: knownMissingOnPeer 可能被意外序列化为非数组，强制转换避免 Set 构造失败
    const safeKnownMissing = Array.isArray(knownMissingOnPeer)
        ? knownMissingOnPeer
        : (knownMissingOnPeer != null ? Object.values(knownMissingOnPeer) : []);
    const plan = planIncremental(allFiles, prevManifest, peer, strategy, safeKnownMissing);
    const t2 = performance.now();
    logger.info('backup', `增量规划完成: 需传输 ${plan.toTransfer.length} 个文件, 耗时 ${(t2 - t1).toFixed(0)}ms`);
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
    const info = {
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
    // P2-PF7：参数明确命名为 fileSize，消除与外层变量的遮蔽歧义。
    // 空文件也返回 12（LSBK+ver+blockSize 头长度），是真实存在的协议开销，非误判。
    const chunkOverhead = (fileSize) => {
        const BLOCK = 8 * 1024 * 1024;
        const blocks = fileSize > 0 ? Math.ceil(fileSize / BLOCK) : 0;
        return fileSize + 12 + 32 * blocks;
    };
    let totalBytes = 0;
    // 大文件分片：> 8MB 拆分为 __chunked__/{pct}/{idx}/{total} 条目（与 Rust 发送端一致），
    // 断点续传时查询对端已收分片，只传缺失部分
    const CHUNK_SIZE = 8 * 1024 * 1024;
    const files = [];
    const fileByRel = new Map();
    const chunkMap = new Map();
    for (const f of plan.toTransfer) {
        if (f.size > CHUNK_SIZE) {
            const pct = rustPctEncode(f.relPath);
            const total = Math.ceil(f.size / CHUNK_SIZE);
            const chunks = [];
            for (let idx = 0; idx < total; idx++) {
                const chunkSize = Math.min(CHUNK_SIZE, f.size - idx * CHUNK_SIZE);
                const id = `f${files.length}`;
                const size = targetCode ? chunkOverhead(chunkSize) : chunkSize;
                const fm = {
                    id,
                    fileName: `__chunked__/${pct}/${idx}/${total}`,
                    size,
                    fileType: 'application/octet-stream',
                    metadata: { modified: new Date(f.mtime).toISOString() },
                };
                files.push(fm);
                if (idx === 0)
                    fileByRel.set(f.relPath, fm);
                chunks.push({ fileId: id, offset: idx * CHUNK_SIZE, size: chunkSize });
                totalBytes += size;
            }
            chunkMap.set(f.relPath, chunks);
        }
        else {
            const id = `f${files.length}`;
            const size = targetCode ? chunkOverhead(f.size) : f.size;
            const fm = {
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
    const filesMap = {};
    for (const fm of files)
        filesMap[fm.id] = fm;
    const prepared = await withRetry(() => prepareUploadNative({
        targetIp,
        targetPort,
        body: JSON.stringify({ info, files: filesMap }),
    }), 3, 2000);
    const t3 = performance.now();
    logger.info('backup', `prepare-upload 完成: ${files.length} 个文件, 耗时 ${(t3 - t2).toFixed(0)}ms`);
    // 6. 逐个上传（原生流式加密上传；失败时取消会话，避免接收端残留）
    let sent = 0;
    // 防御：用已成功去重集合统计 sent，避免重试路径重复计数导致 sent > 计划数（曾出现 191/183）
    const sentRels = new Set();
    // 累计已传字节（8 路并发下 JS 单线程自增安全）：进度按整体字节显示，而非当前文件
    let completedBytes = 0;
    // 块级进度：原生 streamUpload 每 ~500ms 推送当前文件已传/总字节。
    // 8 路并发下按 relPath 建索引映射，避免共享可变变量导致进度错乱。
    let unsubUpload = null;
    const idxByRel = new Map();
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
            logger.info('backup', `上传批次 ${i / 8 + 1}: 文件 ${batch.map(f => f.relPath).join(', ')}`);
            let batchSent = 0;
            // 单文件上传（含分片重试逻辑）
            async function uploadOneFile(f, idx) {
                idxByRel.set(f.relPath, idx + 1);
                const origRel = f.relPath.startsWith(root.name + '/')
                    ? f.relPath.slice(root.name.length + 1)
                    : f.relPath;
                const chunks = chunkMap.get(f.relPath);
                if (chunks) {
                    // 大文件分片：查询对端已收分片，跳过已收部分（断点续传）
                    let receivedSet = new Set();
                    try {
                        const r = await getChunkStatus({ ip: targetIp, port: targetPort, encodedPath: rustPctEncode(f.relPath) });
                        receivedSet = new Set((r.receivedChunks || []).map(Number));
                        logger.debug('backup', `分片查询完成 ${f.relPath} 已收=${receivedSet.size} 总=${chunks.length}`);
                    }
                    catch (e) {
                        logger.warn('backup', `分片查询失败（全传）${f.relPath}`, e);
                    }
                    let sentChunks = 0;
                    for (const c of chunks) {
                        if (receivedSet.has(c.offset / CHUNK_SIZE))
                            continue;
                        const raw = prepared.files[c.fileId];
                        const token = typeof raw === 'string' ? raw : raw?.token;
                        if (!token)
                            throw new Error(`prepare-upload 未返回 token：${f.relPath} fileId=${c.fileId}`);
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
                        sentChunks++;
                    }
                    if (sentChunks > 0) {
                        batchSent++;
                        sentRels.add(f.relPath);
                        sent = sentRels.size;
                        onProgress?.({
                            current: idx + 1,
                            total: plan.toTransfer.length,
                            fileName: f.relPath,
                            bytesSent: completedBytes,
                            totalBytes,
                        });
                    }
                    logger.debug('backup', `大文件分片上传完成 ${f.relPath} 发送=${sentChunks}/${chunks.length} 片`);
                }
                else {
                    const fileMeta = fileByRel.get(f.relPath);
                    const raw = prepared.files[fileMeta.id];
                    const token = typeof raw === 'string' ? raw : raw?.token;
                    if (!token) {
                        logger.warn('backup', `目标端未接受 ${f.relPath}，跳过`);
                        return false;
                    }
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
                    sentRels.add(f.relPath);
                    sent = sentRels.size;
                    completedBytes += fileMeta.size;
                    onProgress?.({
                        current: idx + 1,
                        total: plan.toTransfer.length,
                        fileName: f.relPath,
                        bytesSent: completedBytes,
                        totalBytes,
                    });
                    logger.debug('backup', `文件上传完成 ${idx + 1}/${plan.toTransfer.length}: ${f.relPath}`);
                }
                return true;
            }
            // 第一轮：全部并发上传
            const results = await Promise.allSettled(batch.map((f, j) => uploadOneFile(f, i + j)));
            // 失败文件重试（最多 2 次，指数退避）
            const failedFiles = results
                .map((r, k) => ({ r, f: batch[k] }))
                .filter(({ r }) => r.status === 'rejected')
                .map(({ f, r }) => ({ f, e: r.reason }));
            for (let retry = 0; retry < 2 && failedFiles.length > 0; retry++) {
                const delay = 500 * Math.pow(2, retry);
                logger.warn('backup', `第 ${retry + 1} 轮重试 ${failedFiles.length} 个失败文件，${delay}ms 后重试`);
                await sleep(delay);
                // 防御：先快照文件引用再清空数组，避免重试回调里 failedFiles[k] 已为 undefined（原 bug）
                const toRetry = failedFiles.slice();
                failedFiles.length = 0;
                const retryResults = await Promise.allSettled(toRetry.map(({ f }) => uploadOneFile(f, i + batch.indexOf(f))));
                retryResults.forEach((r, k) => {
                    const orig = toRetry[k];
                    if (r.status === 'rejected') {
                        logger.error('backup', `重试失败: ${orig?.f?.relPath ?? '?'}`, r.reason);
                        if (orig)
                            failedFiles.push({ f: orig.f, e: r.reason });
                    }
                    else if (r.value) {
                        batchSent++;
                        // 去重：仅当该文件尚未计入成功时才累加 sent
                        if (orig && !sentRels.has(orig.f.relPath)) {
                            sentRels.add(orig.f.relPath);
                            sent = sentRels.size;
                        }
                    }
                });
            }
            if (failedFiles.length > 0) {
                // 防御：有文件最终失败则整体中止并取消会话，绝不"报成功但数据不全/全毁"（BUG-3）
                const failedPaths = failedFiles.map(({ f }) => f?.relPath ?? '?').join(', ');
                logger.error('backup', `${failedFiles.length} 个文件最终失败，中止发送: ${failedPaths}`);
                try {
                    await cancelSessionNative({ targetIp, targetPort, sessionId: prepared.sessionId });
                }
                catch {
                    // 忽略取消失败
                }
                throw new Error(`发送失败：${failedFiles.length} 个文件最终上传失败（${failedPaths}），已取消会话`);
            }
            sent += batchSent;
        }
    }
    catch (e) {
        logger.error('backup', `上传失败（已发送 ${sent}/${plan.toTransfer.length}），取消会话`, e);
        try {
            await cancelSessionNative({ targetIp, targetPort, sessionId: prepared.sessionId });
        }
        catch {
            // 忽略取消失败
        }
        throw e;
    }
    finally {
        if (unsubUpload)
            unsubUpload();
    }
    const t4 = performance.now();
    logger.info('backup', `传输完成: ${sent}/${plan.toTransfer.length} 个文件, 耗时 ${(t4 - t3).toFixed(0)}ms`);
    // 7. 更新清单（=下次备份的 A 上次快照）
    const newManifest = buildManifest(allFiles);
    logger.info('backup', `sendBackup 完成: 共 ${sent} 个文件 ${totalBytes}B, 总耗时 ${(performance.now() - t0).toFixed(0)}ms`);
    // 镜像模式：对端多余文件移动到其 delete 文件夹（假删除，保持目录一致）。
    // P0 披露：移动对端文件前必须确认（确认函数由上层注入，展示真实多余文件数）；取消则跳过清理
    if (strategy === 'mirror' && plan.peerExtra.length > 0) {
        // 探针：用户报告"增量模式仍弹镜像确认"——记录策略实际值与来源字段，定位覆盖链
        logger.info('backup', `镜像确认触发: strategy=${strategy} peerExtra=${plan.peerExtra.length} prevManifest=${!!prevManifest}`);
        // 防御：count 必须是数字（历史上曾出现过 [object Object] 传入确认弹窗）
        const ok = onMirrorConfirm ? await onMirrorConfirm(Number(plan.peerExtra.length)) : true;
        if (ok) {
            try {
                await moveToDelete({ ip: targetIp, port: targetPort, files: plan.peerExtra });
            }
            catch (e) {
                logger.warn('backup', '镜像模式移动多余文件失败', e);
            }
        }
        else {
            logger.info('backup', `镜像清理被用户取消：${plan.peerExtra.length} 个多余文件保留在对端`);
        }
    }
    return { manifest: newManifest, sent, bytes: totalBytes, durationMs: performance.now() - t0, knownMissingOnPeer: plan.missingOnPeer };
}
