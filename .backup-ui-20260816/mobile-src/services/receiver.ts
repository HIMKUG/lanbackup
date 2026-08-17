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
import { registerPlugin, type PluginListenerHandle } from '@capacitor/core';
import { logger, maskSecret } from 'shared-core';

/** 接收服务插件 */
interface LocalReceiverPlugin {
  /** 启动接收服务器，文件写入 rootUri 指定的 SAF 目录 */
  start(options: {
    port: number;
    rootUri: string;
    selfCode: string;
  }): Promise<{ ok: boolean; port: number }>;
  /** 停止接收服务器 */
  stop(): Promise<void>;
  /** 查询是否在运行 */
  isRunning(): Promise<{ running: boolean }>;
}

/** 设备信息 / 配对 / 目录同步插件 */
interface DevicePlugin {
  /** 本机设备信息：设备名、机型、公开 deviceId */
  getDeviceInfo(): Promise<{ name: string; model: string; deviceId: string }>;
  /** 修改本机设备名（持久化） */
  setDeviceName(options: { name: string }): Promise<void>;
  /** 本机连接码（未刷新过返回空串，前端用设备号默认算法兜底） */
  getSelfCode(): Promise<{ code: string }>;
  /** 刷新本机连接码：随机生成并持久化，旧码立即失效 */
  refreshCode(): Promise<{ code: string }>;
  /** 探测目标设备在线状态（GET /info，返回其公开信息） */
  pingDevice(options: { ip: string; port: number }): Promise<{
    alias: string;
    fingerprint: string;
    port: number;
  }>;
  /**
   * 向目标提交连接码验证 / 连接问候（POST /verify）。
   * code 非空=配对验证；code 空=连接问候（校验本机是否仍被目标信任）。
   * 携带本机 deviceId/name/myCode，目标验证通过后记录双端配对。
   */
  verifyDevice(options: {
    ip: string;
    port: number;
    code: string;
    deviceId?: string;
    name?: string;
    myCode?: string;
    myPort?: number;
    /** 状态探测：只查对方是否信任本机，不触发"已连接"事件 */
    probe?: boolean;
  }): Promise<{ ok: boolean; reason?: string }>;
  /** 前端响应「配对确认」弹窗：同意/拒绝配对请求 */
  resolvePairing(options: { deviceId: string; accept: boolean }): Promise<void>;
  /** 本机被验证方记录的对端信任列表（双端配对同步） */
  getPairedPeers(): Promise<{
    peers: {
      deviceId: string;
      name: string;
      ip: string;
      port: number;
      fingerprint: string;
      at: number;
    }[];
  }>;
  /** 本端主动确认配对：回填原生 pairedPeers（对端问候校验依据，重启自愈） */
  confirmPaired(options: {
    deviceId: string;
    name: string;
    ip: string;
    port: number;
    fingerprint: string;
  }): Promise<void>;
  /** 全量同步配对记录到原生（清空后重建，杜绝解除残留导致的横跳） */
  setPairedPeers(options: {
    peers: {
      deviceId: string;
      name: string;
      ip: string;
      port: number;
      fingerprint: string;
    }[];
  }): Promise<void>;
  /** 通知对方解除配对（POST /unpair） */
  sendUnpair(options: { ip: string; port: number; deviceId: string }): Promise<{ ok: boolean }>;
  /** 通知对方断开连接（POST /api/backup/v1/disconnect，仅清除已连接状态） */
  sendDisconnect(options: { ip: string; port: number; deviceId: string }): Promise<{ ok: boolean }>;
  moveToDelete(options: { ip: string; port: number; files: string[] }): Promise<{ ok: boolean }>;
  getChunkStatus(options: { ip: string; port: number; encodedPath: string }): Promise<{ receivedChunks: number[] }>;
  /** 前端响应接收确认弹窗：接受 / 拒绝接收会话（解除原生 prepare-upload 阻塞等待） */
  resolveIncoming(options: { sessionId: string; accept: boolean }): Promise<void>;
  /** 通知目标设备本机选择的备份目录名（POST /sync-dir） */
  sendSyncDir(options: {
    ip: string;
    port: number;
    direction: string;
    name: string;
  }): Promise<{ ok: boolean }>;
  /** 读取对方同步过来的备份目录名 */
  getSyncedDir(options: { direction: string }): Promise<{ name: string | null; at: number | null }>;
  /** 获取对端接收目录的当前清单（GET 对方配对服务 /api/backup/v1/manifest，三路对比增量备份用） */
  getPeerManifest(options: {
    ip: string;
    port: number;
  }): Promise<{ generatedAt: number; deviceCode: string; files: Record<string, { size: number; mtime: number }>; version: number }>;
  /** 对方验证本机码通过 / 连接问候本机 / 解除配对 / 文件事件时触发（实时状态） */
  addListener(
    eventName:
      | 'paired-updated'
      | 'peer-connected'
      | 'peer-disconnected'
      | 'pair-unpaired'
      | 'file-received'
      | 'file-receipt'
      | 'receive-complete'
      | 'incoming-request'
      | 'pairing-request'
      | 'receive-progress'
      | 'upload-progress',
    listener: (e: {
      deviceId?: string;
      name?: string;
      fileName?: string;
      bytes?: number;
      count?: number;
      durationMs?: number;
      sessionId?: string;
      totalBytes?: number;
      senderIp?: string;
      ip?: string;
      receivedBytes?: number;
      receivedCount?: number;
      totalCount?: number;
      relPath?: string;
      bytesSent?: number;
    }) => void,
  ): Promise<PluginListenerHandle>;
}

/** 扫描插件 */
interface ScannerPlugin {
  /** announce=true 配对模式（同时广播自己）；false 仅监听/探测（自动连接用） */
  startScan(options: { port: number; selfCode: string; announce: boolean }): Promise<void>;
  stopScan(): Promise<void>;
  getScanResults(): Promise<{
    devices: { alias: string; fingerprint: string; ip: string; port: number }[];
  }>;
}

/** 流式上传插件（手机 → 电脑，分块读+加密+流式 POST，内存 O(1)；绕开 CORS） */
interface UploadPlugin {
  streamUpload(options: {
    uri: string;
    relPath: string;
    targetIp: string;
    targetPort: number;
    sessionId: string;
    fileId: string;
    token: string;
    targetCode: string;
  }): Promise<{ ok: boolean }>;
  /** 原生 prepare-upload（WebView fetch 受 CORS 限制，必须原生） */
  prepareUploadTo(options: {
    targetIp: string;
    targetPort: number;
    body: string;
  }): Promise<{ sessionId: string; files: Record<string, { token: string }> }>;
  /** 原生取消会话 */
  cancelSessionTo(options: { targetIp: string; targetPort: number; sessionId: string }): Promise<void>;
}

const LocalReceiver = registerPlugin<LocalReceiverPlugin>('LocalReceiver');
const LocalDevice = registerPlugin<DevicePlugin>('LocalReceiver');
export const LocalScanner = registerPlugin<ScannerPlugin>('LocalReceiver');

/** SAF 目录选择与遍历（供 filesystem.ts 备份目录扫描使用，同一原生插件） */
interface DirectoryPickerPlugin {
  /** 通过 SAF 选择备份根目录，返回持久化 content:// tree URI */
  pickDirectory(): Promise<{ uri: string }>;
  /** 列出目录子项 */
  readdir(options: {
    uri: string;
    relPath: string;
  }): Promise<{ files: { name: string; type: 'directory' | 'file'; size: number; mtime: number }[] }>;
  /** 读取文件内容为 base64 */
  readFile(options: { uri: string; relPath: string }): Promise<{ data: string }>;
  /** 文件状态 */
  stat(options: {
    uri: string;
    relPath: string;
  }): Promise<{ type: string; size: number; mtime: number }>;
}

export const LocalDirectory = registerPlugin<DirectoryPickerPlugin>('LocalReceiver');
const LocalUpload = registerPlugin<UploadPlugin>('LocalReceiver');

// ---------------------------------------------------------------- 接收服务

export async function startReceiver(options: {
  port: number;
  rootUri: string;
  selfCode: string;
}): Promise<{ ok: boolean; port: number }> {
  logger.info(
    'receiver',
    `启动接收服务: 端口=${options.port} 本机码=${maskSecret(options.selfCode)}`,
  );
  try {
    const res = await logger.withTimeout(
      LocalReceiver.start(options),
      15000,
      'receiver',
      '启动接收服务（原生插件无响应）',
      'PLUGIN_FAIL',
    );
    logger.info('receiver', `接收服务已启动: 实际端口=${res.port}`);
    return res;
  } catch (e) {
    logger.error('receiver', '启动接收服务失败', e);
    throw e;
  }
}

export async function stopReceiver(): Promise<void> {
  logger.info('receiver', '停止接收服务');
  try {
    await logger.withTimeout(LocalReceiver.stop(), 10000, 'receiver', '停止接收服务', 'PLUGIN_FAIL');
    logger.info('receiver', '接收服务已停止');
  } catch (e) {
    logger.error('receiver', '停止接收服务失败', e);
    throw e;
  }
}

export async function isReceiverRunning(): Promise<boolean> {
  try {
    const { running } = await logger.withTimeout(
      LocalReceiver.isRunning(),
      5000,
      'receiver',
      '查询接收服务状态',
      'PLUGIN_FAIL',
    );
    return running;
  } catch (e) {
    logger.warn('receiver', '查询接收服务状态失败（按未运行处理）', e);
    return false;
  }
}

// ---------------------------------------------------------------- 设备信息与配对

export async function getDeviceInfo(): Promise<{ name: string; model: string; deviceId: string }> {
  return logger.withTimeout(
    LocalDevice.getDeviceInfo(),
    8000,
    'device',
    '读取本机设备信息',
    'PLUGIN_FAIL',
  );
}

export async function setDeviceName(name: string): Promise<void> {
  await logger.withTimeout(
    LocalDevice.setDeviceName({ name }),
    8000,
    'device',
    '保存设备名称',
    'PLUGIN_FAIL',
  );
}

export async function pingDevice(options: {
  ip: string;
  port: number;
}): Promise<{ alias: string; fingerprint: string; port: number }> {
  return logger.withTimeout(
    LocalDevice.pingDevice(options),
    5000,
    'device',
    `探测设备在线状态 ${options.ip}:${options.port}`,
    'HTTP_FAIL',
  );
}

export async function getSelfCode(): Promise<string> {
  const res = await logger.withTimeout(
    LocalDevice.getSelfCode(),
    8000,
    'device',
    '读取本机连接码',
    'PLUGIN_FAIL',
  );
  return res.code || '';
}

export async function refreshCode(): Promise<string> {
  const res = await logger.withTimeout(
    LocalDevice.refreshCode(),
    8000,
    'device',
    '刷新本机连接码',
    'PLUGIN_FAIL',
  );
  return res.code || '';
}

export async function verifyDevice(options: {
  ip: string;
  port: number;
  code: string;
  deviceId?: string;
  name?: string;
  myCode?: string;
  myPort?: number;
  /** 状态探测：只查对方是否信任本机，不触发"已连接"事件 */
  probe?: boolean;
}): Promise<{ ok: boolean; reason?: string }> {
  // 状态探测（连接问候）每 500ms 一次，不记日志避免刷屏；仅真实验证（带码）记录
  if (options.code) {
    logger.debug('device', `验证连接码 → ${options.ip}:${options.port}（码已脱敏）`);
  }
  return logger.withTimeout(
    LocalDevice.verifyDevice(options),
    8000,
    'device',
    `${options.code ? '连接码验证' : '连接问候'} ${options.ip}:${options.port}`,
    'HTTP_FAIL',
  );
}

/** 连接问候：校验本机是否仍被目标信任（防绕过设备码直接连接） */
export async function greetDevice(options: {
  ip: string;
  port: number;
  deviceId: string;
  name: string;
}): Promise<{ ok: boolean }> {
  return verifyDevice({
    ip: options.ip,
    port: options.port,
    code: '',
    deviceId: options.deviceId,
    name: options.name,
  });
}

/** 状态探测（probe）：只查对方是否信任本机，不触发"已连接"事件（配对准时同步/自愈用） */
export async function probeDevice(options: {
  ip: string;
  port: number;
  deviceId: string;
  name: string;
}): Promise<{ ok: boolean }> {
  return verifyDevice({
    ip: options.ip,
    port: options.port,
    code: '',
    deviceId: options.deviceId,
    name: options.name,
    probe: true,
  });
}

/** 前端响应接收确认弹窗：接受 / 拒绝接收会话 */
export async function resolveIncoming(sessionId: string, accept: boolean): Promise<void> {
  await logger.withTimeout(
    LocalDevice.resolveIncoming({ sessionId, accept }),
    8000,
    'receiver',
    `响应接收确认 ${accept ? '接受' : '拒绝'}`,
    'PLUGIN_FAIL',
  );
}

/** 前端响应「配对确认」弹窗：同意/拒绝配对请求（对方填写了本机连接码） */
export async function resolvePairing(deviceId: string, accept: boolean): Promise<void> {
  await logger.withTimeout(
    LocalDevice.resolvePairing({ deviceId, accept }),
    8000,
    'pair',
    `响应配对确认 ${accept ? '同意' : '拒绝'}`,
    'PLUGIN_FAIL',
  );
}

/** 对方请求与本机配对（主动方填写了本机连接码）：弹窗确认是否同意 */
export async function onPairingRequest(
  cb: (r: { deviceId: string; name: string; ip: string }) => void,
): Promise<() => void> {
  const handle = await LocalDevice.addListener('pairing-request', (e) =>
    cb({ deviceId: e.deviceId || '', name: e.name || '', ip: e.ip || '' }),
  );
  return () => {
    handle.remove();
  };
}

/** 对方发起接收会话（prepare-upload）：前端弹"是否同意接收"确认框 */
export async function onIncomingRequest(
  cb: (r: { sessionId: string; count: number; totalBytes: number; senderIp: string }) => void,
): Promise<() => void> {
  const handle = await LocalDevice.addListener('incoming-request', (e) =>
    cb({
      sessionId: e.sessionId || '',
      count: e.count || 0,
      totalBytes: e.totalBytes || 0,
      senderIp: e.senderIp || '',
    }),
  );
  return () => {
    handle.remove();
  };
}

/** 接收进度（电脑→手机）：累计字节 / 会话总字节 / 已完成文件数 */
export async function onReceiveProgress(
  cb: (r: {
    sessionId: string;
    fileName: string;
    receivedBytes: number;
    totalBytes: number;
    receivedCount: number;
    totalCount: number;
  }) => void,
): Promise<() => void> {
  const handle = await LocalDevice.addListener('receive-progress', (e) =>
    cb({
      sessionId: e.sessionId || '',
      fileName: e.fileName || '',
      receivedBytes: e.receivedBytes || 0,
      totalBytes: e.totalBytes || 0,
      receivedCount: e.receivedCount || 0,
      totalCount: e.totalCount || 0,
    }),
  );
  return () => {
    handle.remove();
  };
}

/** 发送进度（手机→电脑，原生流式上传）：当前文件已传 / 总字节 */
export async function onUploadProgress(
  cb: (r: { relPath: string; bytesSent: number; totalBytes: number }) => void,
): Promise<() => void> {
  const handle = await LocalDevice.addListener('upload-progress', (e) =>
    cb({ relPath: e.relPath || '', bytesSent: e.bytesSent || 0, totalBytes: e.totalBytes || 0 }),
  );
  return () => {
    handle.remove();
  };
}

export async function getPairedPeers(): Promise<
  { deviceId: string; name: string; ip: string; port: number; fingerprint: string; at: number }[]
> {
  const res = await logger.withTimeout(
    LocalDevice.getPairedPeers(),
    8000,
    'device',
    '读取双端配对记录',
    'PLUGIN_FAIL',
  );
  return res.peers || [];
}

/** 本端主动确认配对：回填原生 pairedPeers（对端问候校验依据，重启自愈） */
export async function confirmPaired(options: {
  deviceId: string;
  name: string;
  ip: string;
  port: number;
  fingerprint: string;
}): Promise<void> {
  await logger.withTimeout(
    LocalDevice.confirmPaired(options),
    8000,
    'device',
    `回填配对记录 ${options.name}`,
    'PLUGIN_FAIL',
  );
}

/** 全量同步配对记录到原生（清空后重建，杜绝解除残留导致的横跳） */
export async function setPairedPeers(
  peers: { deviceId: string; name: string; ip: string; port: number; fingerprint: string }[],
): Promise<void> {
  await logger.withTimeout(
    LocalDevice.setPairedPeers({ peers }),
    8000,
    'device',
    `全量同步配对记录 ${peers.length} 台`,
    'PLUGIN_FAIL',
  );
}

export async function sendUnpair(options: {
  ip: string;
  port: number;
  deviceId: string;
}): Promise<{ ok: boolean }> {
  return logger.withTimeout(
    LocalDevice.sendUnpair(options),
    8000,
    'device',
    `通知解除配对 → ${options.ip}:${options.port}`,
    'HTTP_FAIL',
  );
}

/** 通知对方断开连接（仅清除对方"已连接"状态，不解除配对） */
export async function sendDisconnect(options: {
  ip: string;
  port: number;
  deviceId: string;
}): Promise<{ ok: boolean }> {
  return logger.withTimeout(
    LocalDevice.sendDisconnect(options),
    8000,
    'device',
    `通知断开连接 → ${options.ip}:${options.port}`,
    'HTTP_FAIL',
  );
}

/** 镜像模式：通知目标设备把多余文件移动到其 <接收目录>/delete/ 下（假删除） */
export async function moveToDelete(options: {
  ip: string;
  port: number;
  files: string[];
}): Promise<{ ok: boolean }> {
  return logger.withTimeout(
    LocalDevice.moveToDelete(options),
    15000,
    'device',
    `镜像模式移动多余文件 → ${options.ip}:${options.port}（${options.files.length} 个）`,
    'HTTP_FAIL',
  );
}

/** 断点续传：查询目标设备大文件已收分片索引（跳过已收分片，只传缺失部分） */
export async function getChunkStatus(options: {
  ip: string;
  port: number;
  encodedPath: string;
}): Promise<{ receivedChunks: number[] }> {
  return logger.withTimeout(
    LocalDevice.getChunkStatus(options),
    8000,
    'device',
    `查询分片状态 → ${options.ip}:${options.port}`,
    'HTTP_FAIL',
  );
}

export async function sendSyncDir(options: {
  ip: string;
  port: number;
  direction: string;
  name: string;
}): Promise<{ ok: boolean }> {
  return logger.withTimeout(
    LocalDevice.sendSyncDir(options),
    8000,
    'device',
    `同步目录信息 → ${options.ip}:${options.port} (${options.direction})`,
    'HTTP_FAIL',
  );
}

export async function getSyncedDir(direction: string): Promise<{
  name: string | null;
  at: number | null;
}> {
  return logger.withTimeout(
    LocalDevice.getSyncedDir({ direction }),
    8000,
    'device',
    `读取对方同步的目录信息 (${direction})`,
    'PLUGIN_FAIL',
  );
}

/** 对方验证本机码通过时的实时通知（返回取消函数） */
export async function onPairedUpdated(cb: () => void): Promise<() => void> {
  const handle = await LocalDevice.addListener('paired-updated', () => cb());
  return () => {
    handle.remove();
  };
}

/** 对方连接问候本机时的实时通知（让被连方感知"已连接"） */
export async function onPeerConnected(
  cb: (p: { deviceId: string; name: string }) => void,
): Promise<() => void> {
  const handle = await LocalDevice.addListener('peer-connected', (e) =>
    cb({ deviceId: e.deviceId || '', name: e.name || '' }),
  );
  return () => {
    handle.remove();
  };
}

/** 对方解除配对时的实时通知（即时删除本地配对，不再依赖轮询/问候） */
export async function onPairUnpaired(cb: (deviceId: string) => void): Promise<() => void> {
  const handle = await LocalDevice.addListener('pair-unpaired', (e) => cb(e.deviceId || ''));
  return () => {
    handle.remove();
  };
}

/** 对方主动断开连接时的实时通知（清除"已连接"状态，回到在线状态） */
export async function onPeerDisconnected(cb: (deviceId: string) => void): Promise<() => void> {
  const handle = await LocalDevice.addListener('peer-disconnected', (e) => cb(e.deviceId || ''));
  return () => {
    handle.remove();
  };
}

/** 本机正在接收对方文件（接收方实时反馈，让被同步方感知；带字节数） */
export async function onFileReceived(
  cb: (p: { fileName: string; bytes?: number }) => void,
): Promise<() => void> {
  const handle = await LocalDevice.addListener('file-received', (e) =>
    cb({ fileName: e.fileName || '', bytes: e.bytes }),
  );
  return () => {
    handle.remove();
  };
}

/** 对方确认已收到本机发送的文件（发送方回执） */
export async function onFileReceipt(cb: (fileName: string) => void): Promise<() => void> {
  const handle = await LocalDevice.addListener('file-receipt', (e) => cb(e.fileName || ''));
  return () => {
    handle.remove();
  };
}

/** 获取对端接收目录的当前清单（三路对比增量备份：B 端清单） */
export async function getPeerManifest(options: {
  ip: string;
  port: number;
}): Promise<{ generatedAt: number; deviceCode: string; files: Record<string, { size: number; mtime: number }>; version: number }> {
  return logger.withTimeout(
    LocalDevice.getPeerManifest(options),
    8000,
    'backup',
    `获取对端清单 ${options.ip}:${options.port}`,
    'HTTP_FAIL',
  );
}

/** 本机整批接收完成（接收历史：文件数/字节/耗时） */
export async function onReceiveComplete(
  cb: (s: { count: number; bytes: number; durationMs: number }) => void,
): Promise<() => void> {
  const handle = await LocalDevice.addListener('receive-complete', (e) =>
    cb({ count: e.count || 0, bytes: e.bytes || 0, durationMs: e.durationMs || 0 }),
  );
  return () => {
    handle.remove();
  };
}

// ---------------------------------------------------------------- 扫描

export async function startScan(options: {
  port: number;
  selfCode: string;
  announce: boolean;
}): Promise<void> {
  logger.info(
    'receiver',
    `启动局域网扫描: 端口=${options.port} 广播=${options.announce ? '是' : '否'}`,
  );
  await logger.withTimeout(LocalScanner.startScan(options), 10000, 'receiver', '启动局域网扫描', 'PLUGIN_FAIL');
}

export async function stopScan(): Promise<void> {
  await logger.withTimeout(LocalScanner.stopScan(), 10000, 'receiver', '停止局域网扫描', 'PLUGIN_FAIL');
}

export async function getScanResults(): Promise<
  { alias: string; fingerprint: string; ip: string; port: number }[]
> {
  const res = await logger.withTimeout(
    LocalScanner.getScanResults(),
    8000,
    'receiver',
    '获取扫描结果',
    'PLUGIN_FAIL',
  );
  return res.devices;
}

/** 流式上传单个文件（手机 → 电脑）：分块读 SAF + AES-GCM 加密 + HTTP 流式 POST */
export async function streamUploadFile(options: {
  uri: string;
  relPath: string;
  targetIp: string;
  targetPort: number;
  sessionId: string;
  fileId: string;
  token: string;
  targetCode: string;
  /** 分片续传：起始字节偏移（0 = 从头） */
  offset?: number;
  /** 分片续传：本片字节数（0/缺省 = 到文件尾） */
  size?: number;
}): Promise<void> {
  logger.debug('receiver', `流式上传: ${options.relPath} → ${options.targetIp}:${options.targetPort}`);
  const res = await logger.withTimeout(
    LocalUpload.streamUpload(options),
    1800000, // 大文件 30 分钟上限；原生层有 120s 读超时，分块持续刷新
    'receiver',
    `流式上传 ${options.relPath}`,
    'HTTP_FAIL',
  );
  if (!res.ok) {
    throw new Error(`流式上传失败: ${options.relPath}`);
  }
}

/** 原生 prepare-upload（绕开 WebView CORS 限制） */
export async function prepareUploadNative(options: {
  targetIp: string;
  targetPort: number;
  body: string;
}): Promise<{ sessionId: string; files: Record<string, { token: string }> }> {
  return logger.withTimeout(
    LocalUpload.prepareUploadTo(options),
    30000,
    'receiver',
    `prepare-upload → ${options.targetIp}:${options.targetPort}`,
    'HTTP_FAIL',
  );
}

/** 原生取消会话（绕开 WebView CORS 限制） */
export async function cancelSessionNative(options: {
  targetIp: string;
  targetPort: number;
  sessionId: string;
}): Promise<void> {
  await logger.withTimeout(
    LocalUpload.cancelSessionTo(options),
    10000,
    'receiver',
    '取消传输会话',
    'HTTP_FAIL',
  );
}
