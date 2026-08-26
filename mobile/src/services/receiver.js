/**
 * receiver.ts - 手机端原生插件封装（LocalReceiver）
 *
 * 覆盖三类能力：
 * 1. 接收服务：LocalSend v2 HTTP 接收端（文件写入 SAF 目录）
 * 2. 设备发现：组播监听 + /24 子网探测（扫描电脑）
 * 3. 配对与目录同步：设备信息（设备名/公开 ID）、ping 在线状态、
 *    连接码验证（/verify，连接码只在设备本地比对，不暴露）、
 *    目录映射同步（/sync-dir）
 *
 * 所有原生调用都经 logger.withTimeout 包裹：插件卡死也会被记入日志，
 * 而不是静默无反馈。
 */
import { registerPlugin } from '@capacitor/core';
import { logger, maskSecret } from 'shared-core';
const LocalReceiver = registerPlugin('LocalReceiver');
const LocalDevice = registerPlugin('LocalReceiver');
export const LocalScanner = registerPlugin('LocalReceiver');
export const LocalDirectory = registerPlugin('LocalReceiver');
const LocalUpload = registerPlugin('LocalReceiver');
// ---------------------------------------------------------------- 接收服务
export async function startReceiver(options) {
    logger.info('receiver', `启动接收服务: 端口=${options.port} 本机码=${maskSecret(options.selfCode)}`);
    try {
        const res = await logger.withTimeout(LocalReceiver.start(options), 15000, 'receiver', '启动接收服务（原生插件无响应）', 'PLUGIN_FAIL');
        logger.info('receiver', `接收服务已启动: 实际端口=${res.port}`);
        return res;
    }
    catch (e) {
        logger.error('receiver', '启动接收服务失败', e);
        throw e;
    }
}
export async function stopReceiver() {
    logger.info('receiver', '停止接收服务');
    try {
        await logger.withTimeout(LocalReceiver.stop(), 10000, 'receiver', '停止接收服务', 'PLUGIN_FAIL');
        logger.info('receiver', '接收服务已停止');
    }
    catch (e) {
        logger.error('receiver', '停止接收服务失败', e);
        throw e;
    }
}
export async function isReceiverRunning() {
    try {
        const { running } = await logger.withTimeout(LocalReceiver.isRunning(), 5000, 'receiver', '查询接收服务状态', 'PLUGIN_FAIL');
        return running;
    }
    catch (e) {
        logger.warn('receiver', '查询接收服务状态失败（按未运行处理）', e);
        return false;
    }
}
// ---------------------------------------------------------------- 设备信息与配对
export async function getDeviceInfo() {
    return logger.withTimeout(LocalDevice.getDeviceInfo(), 8000, 'device', '读取本机设备信息', 'PLUGIN_FAIL');
}
export async function setDeviceName(name) {
    await logger.withTimeout(LocalDevice.setDeviceName({ name }), 8000, 'device', '保存设备名称', 'PLUGIN_FAIL');
}
export async function getSelfCode() {
    const res = await logger.withTimeout(LocalDevice.getSelfCode(), 8000, 'device', '读取本机连接码', 'PLUGIN_FAIL');
    return res.code || '';
}
/** v3 探测对端（GET /api/v3/probe，P2 硬升级替代 v2 /info）：返回对端公开信息 */
export async function v3Probe(options) {
    return logger.withTimeout(LocalDevice.v3Probe(options), 5000, 'device', `v3 探测 ${options.ip}:${options.port}`, 'HTTP_FAIL');
}
export async function refreshCode() {
    const res = await logger.withTimeout(LocalDevice.refreshCode(), 8000, 'device', '刷新本机连接码', 'PLUGIN_FAIL');
    return res.code || '';
}
/** 对方连接本机时的实时通知（native v3 层 peer-connected 事件）。
 *  P2 硬升级：v2 问候 /verify 与内部事件发射器已删除，仅监听原生事件。 */
export async function onPeerConnected(cb) {
    const handle = await LocalDevice.addListener('peer-connected', (e) => cb({ deviceId: e.deviceId || '', name: e.name || '', port: e.port }));
    return () => handle.remove();
}
/** 前端响应接收确认弹窗：接受 / 拒绝接收会话 */
export async function resolveIncoming(sessionId, accept) {
    await logger.withTimeout(LocalDevice.resolveIncoming({ sessionId, accept }), 8000, 'receiver', `响应接收确认 ${accept ? '接受' : '拒绝'}`, 'PLUGIN_FAIL');
}
/** 前端响应「配对确认」弹窗：同意/拒绝配对请求（对方填写了本机连接码） */
export async function resolvePairing(deviceId, accept) {
    await logger.withTimeout(LocalDevice.resolvePairing({ deviceId, accept }), 8000, 'pair', `响应配对确认 ${accept ? '同意' : '拒绝'}`, 'PLUGIN_FAIL');
}
/** 对方请求与本机配对（主动方填写了本机连接码）：弹窗确认是否同意 */
export async function onPairingRequest(cb) {
    const handle = await LocalDevice.addListener('pairing-request', (e) => cb({ deviceId: e.deviceId || '', name: e.name || '', ip: e.ip || '' }));
    return () => {
        handle.remove();
    };
}
/** 对方发起接收会话（prepare-upload）：前端弹"是否同意接收"确认框 */
export async function onIncomingRequest(cb) {
    const handle = await LocalDevice.addListener('incoming-request', (ev) => {
        const e = (ev ?? {});
        cb({
            sessionId: e.sessionId || '',
            count: e.count || 0,
            totalBytes: e.totalBytes || 0,
            senderIp: e.senderIp || '',
            senderName: e.senderName || '',
        });
    });
    return () => {
        handle.remove();
    };
}
/** 接收进度（电脑→手机）：累计字节 / 会话总字节 / 已完成文件数 */
export async function onReceiveProgress(cb) {
    const handle = await LocalDevice.addListener('receive-progress', (e) => cb({
        sessionId: e.sessionId || '',
        fileName: e.fileName || '',
        receivedBytes: e.receivedBytes || 0,
        totalBytes: e.totalBytes || 0,
        receivedCount: e.receivedCount || 0,
        totalCount: e.totalCount || 0,
    }));
    return () => {
        handle.remove();
    };
}
/** 发送进度（手机→电脑，原生流式上传）：当前文件已传 / 总字节 */
export async function onUploadProgress(cb) {
    const handle = await LocalDevice.addListener('upload-progress', (e) => cb({ relPath: e.relPath || '', bytesSent: e.bytesSent || 0, totalBytes: e.totalBytes || 0 }));
    return () => {
        handle.remove();
    };
}
export async function getPairedPeers() {
    const res = await logger.withTimeout(LocalDevice.getPairedPeers(), 8000, 'device', '读取双端配对记录', 'PLUGIN_FAIL');
    return res.peers || [];
}
/** 查询对端 IP 是否已有真实配对密钥（PairingStore 存在非空 secret）。
 *  用于自动恢复/同步前门禁：避免未配对仍向仅发现的设备推送数据（BUG-4）。 */
export async function isPeerPaired(ip) {
    if (!ip)
        return false;
    try {
        const res = await logger.withTimeout(LocalDevice.isPeerPaired({ ip }), 8000, 'device', '查询对端配对状态', 'PLUGIN_FAIL');
        return !!res?.paired;
    }
    catch {
        return false; // 查询失败按未配对处理（安全侧）
    }
}
/** 本端主动确认配对：回填原生 pairedPeers（对端问候校验依据，重启自愈） */
export async function confirmPaired(options) {
    await logger.withTimeout(LocalDevice.confirmPaired(options), 8000, 'device', `回填配对记录 ${options.name}`, 'PLUGIN_FAIL');
}
/** 全量同步配对记录到原生（清空后重建，杜绝解除残留导致的横跳） */
export async function setPairedPeers(peers) {
    await logger.withTimeout(LocalDevice.setPairedPeers({ peers }), 8000, 'device', `全量同步配对记录 ${peers.length} 台`, 'PLUGIN_FAIL');
}
export async function sendUnpair(options) {
    return logger.withTimeout(LocalDevice.sendUnpair(options), 8000, 'device', `通知解除配对 → ${options.ip}:${options.port}`, 'HTTP_FAIL');
}
/** 通知对方断开连接（仅清除对方"已连接"状态，不解除配对） */
export async function sendDisconnect(options) {
    return logger.withTimeout(LocalDevice.sendDisconnect(options), 8000, 'device', `通知断开连接 → ${options.ip}:${options.port}`, 'HTTP_FAIL');
}
/** 镜像模式：通知目标设备把多余文件移动到其 <接收目录>/delete/ 下（假删除） */
export async function moveToDelete(options) {
    return logger.withTimeout(LocalDevice.moveToDelete(options), 15000, 'device', `镜像模式移动多余文件 → ${options.ip}:${options.port}（${options.files.length} 个）`, 'HTTP_FAIL');
}
/** 断点续传：查询目标设备大文件已收分片索引（跳过已收分片，只传缺失部分） */
export async function getChunkStatus(options) {
    const r = await logger.withTimeout(LocalDevice.getChunkStatus(options), 8000, 'device', `查询分片状态 → ${options.ip}:${options.port} path=${options.encodedPath}`, 'HTTP_FAIL');
    logger.debug('device', `分片状态结果 → ${options.ip}:${options.port} path=${options.encodedPath} 已收=${r.receivedChunks.length} 片: [${r.receivedChunks.join(',')}]`);
    return r;
}
export async function sendSyncDir(options) {
    return logger.withTimeout(LocalDevice.sendSyncDir(options), 8000, 'device', `同步目录信息 → ${options.ip}:${options.port} (${options.direction})`, 'HTTP_FAIL');
}
export async function getSyncedDir(direction) {
    return logger.withTimeout(LocalDevice.getSyncedDir({ direction }), 8000, 'device', `读取对方同步的目录信息 (${direction})`, 'PLUGIN_FAIL');
}
/** 设置防御性总开关：hidden=true 本机局域网完全隐藏（已配对设备也无法发现本机） */
export async function setDefensiveHidden(hidden) {
    const r = await logger.withTimeout(LocalDevice.setDefensiveHidden({ hidden }), 6000, 'device', `设置防御性总开关 (${hidden})`, 'PLUGIN_FAIL');
    return r.hidden;
}
/** 查询防御性总开关状态 */
export async function getDefensiveHidden() {
    const r = await logger.withTimeout(LocalDevice.getDefensiveHidden(), 6000, 'device', '查询防御性总开关', 'PLUGIN_FAIL');
    return r.hidden;
}
/** 常驻加密存在广播在线/离线实时通知（已配对设备在线状态来源） */
export async function onPairPresence(cb) {
    const handle = await LocalDevice.addListener('pair-presence', (e) => cb({ deviceId: e.deviceId || '', online: !!e.online }));
    return () => {
        handle.remove();
    };
}
/** 对方验证本机码通过时的实时通知（返回取消函数） */
export async function onPairedUpdated(cb) {
    const handle = await LocalDevice.addListener('paired-updated', () => cb());
    return () => {
        handle.remove();
    };
}
/** 对方解除配对时的实时通知（即时删除本地配对，不再依赖轮询/问候） */
export async function onPairUnpaired(cb) {
    const handle = await LocalDevice.addListener('pair-unpaired', (e) => cb(e.deviceId || ''));
    return () => {
        handle.remove();
    };
}
/** 对方主动断开连接时的实时通知（清除"已连接"状态，回到在线状态） */
export async function onPeerDisconnected(cb) {
    const handle = await LocalDevice.addListener('peer-disconnected', (e) => cb(e.deviceId || ''));
    return () => {
        handle.remove();
    };
}
/** 本机正在接收对方文件（接收方实时反馈，让被同步方感知；带字节数） */
export async function onFileReceived(cb) {
    const handle = await LocalDevice.addListener('file-received', (e) => cb({ fileName: e.fileName || '', bytes: e.bytes }));
    return () => {
        handle.remove();
    };
}
/** 对方确认已收到本机发送的文件（发送方回执） */
export async function onFileReceipt(cb) {
    const handle = await LocalDevice.addListener('file-receipt', (e) => cb(e.fileName || ''));
    return () => {
        handle.remove();
    };
}
/** 获取对端接收目录的当前清单（三路对比增量备份：B 端清单） */
export async function getPeerManifest(options) {
    const r = await logger.withTimeout(LocalDevice.getPeerManifest(options), 8000, 'backup', `获取对端清单 ${options.ip}:${options.port}`, 'HTTP_FAIL');
    logger.info('backup', `对端清单已获取 ${options.ip}:${options.port} 文件数=${Object.keys(r.files).length}`);
    return r;
}
/** 本机整批接收完成（接收历史：文件数/字节/耗时） */
export async function onReceiveComplete(cb) {
    const handle = await LocalDevice.addListener('receive-complete', (e) => cb({ count: e.count || 0, bytes: e.bytes || 0, durationMs: e.durationMs || 0 }));
    return () => {
        handle.remove();
    };
}
// ---------------------------------------------------------------- 扫描
export async function startScan(options) {
    logger.info('receiver', `启动局域网扫描: 端口=${options.port} 广播=${options.announce ? '是' : '否'}`);
    await logger.withTimeout(LocalScanner.startScan(options), 10000, 'receiver', '启动局域网扫描', 'PLUGIN_FAIL');
}
export async function stopScan() {
    await logger.withTimeout(LocalScanner.stopScan(), 10000, 'receiver', '停止局域网扫描', 'PLUGIN_FAIL');
}
export async function getScanResults() {
    const res = await logger.withTimeout(LocalScanner.getScanResults(), 8000, 'receiver', '获取扫描结果', 'PLUGIN_FAIL');
    return res.devices;
}
/** 流式上传单个文件（手机 → 电脑）：分块读 SAF + AES-GCM 加密 + HTTP 流式 POST */
export async function streamUploadFile(options) {
    logger.debug('receiver', `流式上传: ${options.relPath} → ${options.targetIp}:${options.targetPort}`);
    const res = await logger.withTimeout(LocalUpload.streamUpload(options), 1800000, // 大文件 30 分钟上限；原生层有 120s 读超时，分块持续刷新
    'receiver', `流式上传 ${options.relPath}`, 'HTTP_FAIL');
    if (!res.ok) {
        throw new Error(`流式上传失败: ${options.relPath}`);
    }
}
/** 原生 prepare-upload（绕开 WebView CORS 限制） */
export async function prepareUploadNative(options) {
    return logger.withTimeout(LocalUpload.prepareUploadTo(options), 30000, 'receiver', `prepare-upload → ${options.targetIp}:${options.targetPort}`, 'HTTP_FAIL');
}
/** Java 原生层日志探针（NativeLogBridge 读 logcat 桥接，转发到前端 logger 进入导出日志）。
 *  payload 兼容两种形态：单条 {level,module,msg}（INFO+ 立即发）与批量 {batch:[...]}（DEBUG 攒批）。 */
export async function onJavaLog(cb) {
    const handle = await LocalDevice.addListener('java-log', (e) => {
        const any = e;
        if (Array.isArray(any.batch)) {
            for (const item of any.batch) {
                cb({ level: item.level || 'debug', module: item.module || 'java', msg: item.msg || '' });
            }
        }
        else {
            cb({ level: any.level || 'debug', module: any.module || 'java', msg: any.msg || '' });
        }
    });
    return () => handle.remove();
}
/** 回放原生日志环形缓冲（冷启动窗口 WebView 未就绪时桥接器发出的日志），一次性补进前端 logger */
export async function dumpNativeLogs() {
    try {
        const res = await LocalDevice.dumpNativeLogs();
        const logs = res?.logs;
        if (!Array.isArray(logs))
            return [];
        return logs.map((l) => ({ level: l.level || 'debug', module: l.module || 'java', msg: l.msg || '' }));
    }
    catch {
        return [];
    }
}
/** v5 信任状态巡检（sync-status）：对每台已配对设备查询对方视角的信任状态——
 *  revoked（对方已吊销本机）→ 本机同步解除并清密钥；
 *  unknown（对方不认识本机，单向残留）→ 本机清除记录；
 *  ok → 刷新心跳。结果经 pair-unpaired 事件实时通知前端。 */
export async function syncAllPeersV3() {
    return logger.withTimeout(LocalDevice.syncAllPeers(), 30000, 'pair', '信任状态巡检', 'PLUGIN_FAIL');
}
/** v3 主动配对客户端（补全 P2 硬升级缺失功能）：输入对端 IP + 连接码发起配对。
 *  前提：对端已开启发现服务（否则 probe 返回空 deviceId → 拒绝）。 */
export async function pairClientV3(options) {
    const res = await LocalDevice.v3PairClient(options);
    return { status: res?.status || 'error', deviceId: res?.deviceId, alias: res?.alias, message: res?.message };
}
/** 原生取消会话（绕开 WebView CORS 限制） */
export async function cancelSessionNative(options) {
    await logger.withTimeout(LocalUpload.cancelSessionTo(options), 10000, 'receiver', '取消传输会话', 'HTTP_FAIL');
}
