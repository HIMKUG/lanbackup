<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted, reactive } from 'vue';
import { gsap } from 'gsap';
import { CodeBoxes, GlassDock, GlassFilters, GlassModal, GlassScrollbar, GlassSeg, GlassSwitch, IpBoxes, LiquidGlass, AppIcon, installGlowHover, setBlurInterval, useAutoResume, useSyncTasks, type SyncTask } from 'shared-ui';
import { Filesystem, Directory, Encoding } from '@capacitor/filesystem';
import {
  requestStoragePermission,
  pickBackupRoot,
  writeFileContent,
  type BackupRoot,
} from './services/filesystem';
import { getSelfConnectionCode, loadState, completeBackup } from './services/device';
import { sendBackup } from './services/backup';
import {
  startReceiver,
  stopReceiver,
  isReceiverRunning,
  getDeviceInfo,
  setDeviceName,
  getSelfCode,
  refreshCode,
  v3Probe,
  getPairedPeers,
  isPeerPaired,
  sendUnpair,
  sendDisconnect,
  sendSyncDir,
  onPairedUpdated,
  onPeerConnected,
  onPeerDisconnected,
  onPairUnpaired,
  onFileReceived,
  onFileReceipt,
  onReceiveComplete,
  onIncomingRequest,
  cancelSessionNative,
  onJavaLog,
  dumpNativeLogs,
  onReceiveProgress,
  onPairingRequest,
  resolveIncoming,
  resolvePairing,
  pairClientV3,
  syncAllPeersV3,
  setPairedPeers,
  startScan,
  stopScan,
  getScanResults,
  getDefensiveHidden,
  setDefensiveHidden,
  onPairPresence,
} from './services/receiver';
import {
  migrateState,
  getOrCreateDevice,
  PairingManager,
  normalizeCode,
  normalizeConfig,
  parseConfig,
  stringifyConfig,
  genFolderId,
  type BackupState,
  type PairRecord,
  type PairingStorage,
  type SyncStrategy,
  type AppConfig,
  type DeviceRole,
  type SendFolder,
  logger,
  logFileName,
} from 'shared-core';

/** 扫描到的设备（原生 getScanResults 返回） */
interface ScannedDevice {
  alias: string;
  fingerprint: string;
  ip: string;
  port: number;
}

type Page = 'devices' | 'backup' | 'history' | 'settings';

// ---------- 基础状态 ----------
const selfCode = ref('');
const state = ref<BackupState | null>(null);
const deviceInfo = ref({ name: '', model: '', deviceId: '' });
const currentPage = ref<Page>('backup');
const darkMode = ref<boolean>(
  (() => {
    try {
      const saved = localStorage.getItem('lanbackup_dark');
      if (saved !== null) return saved === 'true';
    } catch {
      // 忽略
    }
    // 未手动设置过 → 跟随系统偏好
    return typeof window !== 'undefined' && !!window.matchMedia?.('(prefers-color-scheme: dark)').matches;
  })(),
);
const errorMsg = ref('');
const notice = ref('');
let mm: ReturnType<typeof gsap.matchMedia> | null = null;
let unsubLog: (() => void) | null = null;
let unlistenPairMobile: (() => void) | null = null;
let unlistenPeerMobile: (() => void) | null = null;
let unlistenDisconnectMobile: (() => void) | null = null;
let unlistenPresenceMobile: (() => void) | null = null;
let unlistenUnpairMobile: (() => void) | null = null;
let unlistenFileRecvMobile: (() => void) | null = null;
let unlistenFileReceiptMobile: (() => void) | null = null;
let unlistenReceiveComplete: (() => void) | null = null;
let unlistenIncomingMobile: (() => void) | null = null;
let unlistenPairingMobile: (() => void) | null = null;
let unlistenRecvMobile: (() => void) | null = null;
// "已连接本机"提示去抖：同一设备 30 秒内不重复提示，且仅状态变化时提示
const connectNoticeAt = new Map<string, number>();
// bcpd 确认在线的设备集合（fingerprint → 已通过 HMAC 加密存在验证）。
// 接入此集合的设备在 connectPeer 时跳过 deviceId 比对（bcpd 的 HMAC 验证比明文 ID 更强）。
const bcpdConfirmedOnline = new Set<string>();

/** 消息队列：多条提示并行堆叠显示，每条 4.2 秒后自动移除 */
interface ToastItem {
  id: number;
  kind: 'ok' | 'error';
  text: string;
}
const toasts = ref<ToastItem[]>([]);
let toastSeq = 0;
function pushToast(kind: 'ok' | 'error', text: string) {
  const id = ++toastSeq;
  toasts.value.push({ id, kind, text });
  // 最多同时 3 条：超出时最旧的立即移除，避免遮挡过多区域
  if (toasts.value.length > 3) toasts.value = toasts.value.slice(-3);
  setTimeout(() => {
    toasts.value = toasts.value.filter((t) => t.id !== id);
  }, 4200);
}

// 兼容旧赋值点：notice/errorMsg 一被写入就入队并立即清空，显示交给 toasts
watch([notice, errorMsg], ([n, em]) => {
  if (n) {
    pushToast('ok', n);
    notice.value = '';
  }
  if (em) {
    pushToast('error', em);
    errorMsg.value = '';
  }
});

// ---------- 配对 ----------
const pairingStorage: PairingStorage = {
  load: () => {
    try {
      return JSON.parse(localStorage.getItem('lanbackup_pairings') || '[]');
    } catch {
      return [];
    }
  },
  save: (r) => {
    try {
      localStorage.setItem('lanbackup_pairings', JSON.stringify(r));
    } catch {
      // 忽略
    }
  },
};
const pairMgr = new PairingManager(pairingStorage);
const pairings = ref<PairRecord[]>([]);
const discovered = ref<ScannedDevice[]>([]);
const scanRunning = ref(false);
const scanRounds = ref(0);
const scanElapsedSec = ref(0);
let scanStartedAt = 0;
let scanTimer: ReturnType<typeof setInterval> | null = null;
let pingTimer: ReturnType<typeof setInterval> | null = null;
let mergeTimer: ReturnType<typeof setInterval> | null = null;
/** v5 信任状态巡检定时器（sync-status 周期收敛：对方已解除配对时本机自动感知） */
let trustTimer: ReturnType<typeof setInterval> | null = null;
const pairingTarget = ref<ScannedDevice | null>(null);
const codeInput = ref('');
const manualIp = ref('');
const manualPort = ref(53317);
const manualCode = ref('');
/** 配对方式：自动（广播发现）/ 手动（IP+连接码） */
const pairMode = ref<'auto' | 'manual'>('auto');

/** 配对设备三态文案（已连接 / 在线 / 离线） */
function pairStatus(p: PairRecord): string {
  if (p.connected) return '已连接';
  if (p.online) return '在线';
  if (discovered.value.some((d) => d.fingerprint === p.fingerprint)) return '疑似离线';
  return '离线';
}

/** 软过期：30 天以上未在线且当前离线 → 提示"可能已失效"（不自动删除，用户可手动解除） */
function isStale(p: PairRecord): boolean {
  return !p.online && p.lastSeen > 0 && Date.now() - p.lastSeen > 30 * 24 * 3600 * 1000;
}

function refreshPairings() {
  const next = pairMgr.all().map((r) => ({ ...r }));
  // 脏检查：500ms 轮询下无变化不替换数组，避免设备列表每帧全量重渲染
  if (JSON.stringify(next) !== JSON.stringify(pairings.value)) {
    pairings.value = next;
  }
  // 同步对象引用跟随：防止下拉绑定的旧对象在数组整体替换后漂移，
  // 导致"同步对象被清空/显示为空"
  if (targetDevice.value) {
    const fp = targetDevice.value.fingerprint;
    targetDevice.value = pairMgr.byFingerprint(fp) ?? null;
  }
}

// ---------- 备份目录盒子 ----------
const boxP2c = ref<BackupRoot | null>(null); // 手机→电脑：本机源目录
const boxC2p = ref<BackupRoot | null>(null); // 电脑→手机：本机接收目录
const targetDevice = ref<PairRecord | null>(null);
const targetDropdownOpen = ref(false);
const scanning = ref(false);
const syncStrategy = ref<SyncStrategy>('archive');
const progress = ref<{ current: number; total: number; fileName: string; bytesSent?: number; totalBytes?: number } | null>(null);
const lastReceipt = ref('');
/** 接收进度（电脑→手机，原生块级事件） */
const recvProgress = ref<{ fileName: string; receivedBytes: number; totalBytes: number; receivedCount: number; totalCount: number } | null>(null);
/** 接收确认弹窗（电脑→手机 prepare-upload）；senderName 由原生载荷透传（缺失回退 IP） */
const incomingReq = ref<{ sessionId: string; count: number; totalBytes: number; senderIp: string; senderName?: string } | null>(null);
/** 当前收件来源（取消收件时通知对端停止传输）：ip/port/sessionId */
const currentRecvSource = ref<{ ip: string; port: number; sessionId: string } | null>(null);
/** 镜像确认防重放：fingerprint → 上次询问时刻（5 分钟内不重复弹窗）。
 *  持久化到 localStorage（BUG-9 复盘：纯内存 Map 重启即失效，杀进程重启可再次触发弹窗）。
 *  仅保留 24h 内记录，避免无限增长。 */
const MIRROR_ASKED_KEY = 'lanbackup_mirror_asked_at';
function loadMirrorAskedAt(): [string, number][] {
  try {
    const raw = localStorage.getItem(MIRROR_ASKED_KEY);
    if (raw) {
      const obj = JSON.parse(raw) as Record<string, number>;
      const now = Date.now();
      return Object.entries(obj).filter(([, ts]) => now - ts < 24 * 60 * 60 * 1000);
    }
  } catch {
    /* 解析失败按空处理 */
  }
  return [];
}
const mirrorAskedAt = new Map<string, number>(loadMirrorAskedAt());
function persistMirrorAskedAt() {
  try {
    localStorage.setItem(MIRROR_ASKED_KEY, JSON.stringify(Object.fromEntries(mirrorAskedAt)));
  } catch {
    /* 持久化失败不影响主流程 */
  }
}
/** 配对确认弹窗（对方填写了本机连接码请求配对） */
const pairingReq = ref<{ deviceId: string; name: string; ip: string } | null>(null);
/** 备份完成统计（进度框完成态显示） */
const progressDone = ref<{ direction: string; count: number; bytes: number; durationMs: number } | null>(null);
/** 发送速率 / 剩余时间（由进度事件差分计算） */
const rateInfo = ref({ rate: 0, etaSec: 0 });
let lastRateSample = { t: 0, bytes: 0 };
const transfers = ref<
  { id?: string; direction: string; peer: string; fileCount: number; bytes: number; durationMs: number; createdAt: number }[]
>([]);
const serverRunning = ref(false);
/** 防御性总开关：hidden=true 时本机在局域网完全隐藏（已配对设备也无法发现本机，仅保留本机主动外连） */
const defensiveHidden = ref(false);

// 速率/大小格式化 + 传输历史（localStorage 持久化，最多 200 条，与桌面端一致）
function fmtRate(bytes: number, ms: number): string {
  const kbps = ms > 0 ? bytes / 1024 / (ms / 1000) : 0;
  return kbps >= 1024 ? `${(kbps / 1024).toFixed(1)} MB/s` : `${kbps.toFixed(0)} KB/s`;
}
function fmtBytes(b: number): string {
  if (b <= 0) return '—';
  if (b >= 1024 * 1024 * 1024) return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
  if (b >= 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`;
  if (b >= 1024) return `${(b / 1024).toFixed(0)} KB`;
  return `${b} B`;
}
/** 剩余时间（分+秒，与桌面端 fmtRemain 同格式） */
function fmtEta(sec: number): string {
  if (sec < 1) return '即将完成';
  if (sec < 60) return `${Math.ceil(sec)} 秒`;
  return `${Math.floor(sec / 60)} 分 ${Math.ceil(sec % 60)} 秒`;
}
function loadTransfers() {
  try {
    transfers.value = JSON.parse(localStorage.getItem('lanbackup_history') || '[]');
  } catch {
    transfers.value = [];
  }
}
function pushTransfer(direction: string, peer: string, fileCount: number, bytes: number, durationMs: number) {
  // 唯一 id：同一秒多条记录也能拿到稳定 key（createdAt-direction 会碰撞）
  const rec = {
    id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
    direction,
    peer,
    fileCount,
    bytes,
    durationMs,
    createdAt: Date.now(),
  };
  const list = [rec, ...transfers.value].slice(0, 200);
  transfers.value = list;
  try {
    localStorage.setItem('lanbackup_history', JSON.stringify(list));
  } catch {
    // 忽略
  }
}
function persistTransfers() {
  try {
    localStorage.setItem('lanbackup_history', JSON.stringify(transfers.value));
  } catch {
    // 忽略
  }
}
function deleteTransfer(i: number) {
  transfers.value.splice(i, 1);
  persistTransfers();
  notice.value = '已删除该条传输记录';
}
function clearAllTransfers() {
  askConfirm({
    title: '清空传输记录',
    message: `将删除全部 ${transfers.value.length} 条传输记录，不可恢复。`,
    danger: true,
    action: () => {
      transfers.value = [];
      try {
        localStorage.removeItem('lanbackup_history');
      } catch {
        // 忽略
      }
      notice.value = '传输记录已清空';
    },
  });
}

/** 传输记录按时间分组：近1天/近7天/近30天/更早；默认只展开最近一个非空组，其余折叠 */
interface HistGroup {
  key: string;
  label: string;
  items: (typeof transfers.value)[number][];
}
const historyGroups = computed<HistGroup[]>(() => {
  const DAY = 86400000;
  const now = Date.now();
  const defs = [
    { key: 'd1', label: '近 1 天', max: 1 * DAY },
    { key: 'd7', label: '近 7 天', max: 7 * DAY },
    { key: 'm1', label: '近 30 天', max: 30 * DAY },
    { key: 'older', label: '1 个月以前', max: Infinity },
  ];
  const sorted = [...transfers.value].sort((a, b) => b.createdAt - a.createdAt);
  const groups: HistGroup[] = [];
  let lower = 0;
  for (const d of defs) {
    const items = sorted.filter((t) => {
      const age = now - t.createdAt;
      return age > lower && age <= d.max;
    });
    if (items.length) groups.push({ key: d.key, label: d.label, items });
    lower = d.max;
  }
  return groups;
});
const openHistGroup = ref('');
watch(
  historyGroups,
  (gs) => {
    if (!gs.some((g) => g.key === openHistGroup.value)) openHistGroup.value = gs[0]?.key ?? '';
  },
  { immediate: true },
);
function toggleHistGroup(k: string) {
  openHistGroup.value = openHistGroup.value === k ? '' : k;
}
const serverPort = ref(53317);

// ---------- 角色模型配置（接收端/发送端/自由模式，与设备形态解耦） ----------
/** 应用配置 */
const appConfig = ref<AppConfig>(normalizeConfig(null));
/** 当前角色（快捷绑定 appConfig.role） */
const role = ref<DeviceRole>('sender');
/** 角色展示名（状态总览卡） */
const roleName = computed(() => (role.value === 'receiver' ? '收件' : role.value === 'sender' ? '发件' : '双向'));

/** 底部 Dock：页面定义 + 状态气泡文案 */
const pageNames: Record<Page, string> = { devices: '设备', backup: '同步', history: '记录', settings: '设置' };
const dockTabs: { id: Page; icon: string; label: string }[] = [
  { id: 'devices', icon: 'devices', label: '设备' },
  { id: 'backup', icon: 'sync', label: '同步' },
  { id: 'history', icon: 'history', label: '记录' },
  { id: 'settings', icon: 'settings', label: '设置' },
];
const dockStatusTitle = computed(() => pageNames[currentPage.value]);
const dockStatusSub = computed(() => (serverRunning.value ? '收件服务运行中' : '收件服务已停止'));

/** 二级确认弹窗：所有“是否确认”统一走这里（重置码/清记录/清日志/解除/断开/镜像预检） */
interface ConfirmAsk {
  title: string;
  message?: string;
  danger?: boolean;
  action: () => void;
  /** 取消回调（异步确认用） */
  cancel?: () => void;
}
const confirmAsk = ref<ConfirmAsk | null>(null);
function askConfirm(a: ConfirmAsk) {
  confirmAsk.value = a;
}
function runConfirm() {
  const a = confirmAsk.value;
  confirmAsk.value = null;
  a?.action();
}
function cancelConfirm() {
  const a = confirmAsk.value;
  confirmAsk.value = null;
  a?.cancel?.();
}
/** 异步确认（镜像预检等需等待用户选择的场景）：确认 resolve(true)，取消 resolve(false) */
function askConfirmAsync(a: { title: string; message?: string; danger?: boolean }): Promise<boolean> {
  return new Promise((resolve) => {
    confirmAsk.value = { ...a, action: () => resolve(true), cancel: () => resolve(false) };
  });
}

/* 页面切换：常驻 v-show 用 GSAP 时间线管理淡入淡出，高度永不塌缩，Dock 永不抖动 */
const pageRef = ref<HTMLElement | null>(null);
let lastPageIdx = 1; // 初始在同步页
const reduceMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;
watch(currentPage, (np, op) => {
  if (!op) { lastPageIdx = dockTabs.findIndex((t) => t.id === np); return; }
  window.scrollTo(0, 0);
  const root = pageRef.value;
  if (!root) return;
  /* 自愈：所有页先回到干净隐藏态（杀补间 / 清 inline / 加回 page-off）。
     旧版从不回加 page-off，旧页淡出后 visibility:hidden 仍占文档流把新页推下一屏，
     且中断的过渡会残留 absolute 定位——这就是记录/设置页顶部大量空隙的根因 */
  root.querySelectorAll<HTMLElement>('.page-inner').forEach((el) => {
    gsap.killTweensOf(el);
    el.style.position = '';
    el.style.left = '';
    el.style.right = '';
    el.style.top = '';
    el.style.display = '';
    el.style.opacity = '';
    el.style.visibility = '';
    el.style.transform = '';
    el.classList.add('page-off');
  });
  const oldEl = root.querySelector<HTMLElement>(`[data-page="${op}"]`);
  const newEl = root.querySelector<HTMLElement>(`[data-page="${np}"]`);
  if (!oldEl || !newEl) return;
  const idx = dockTabs.findIndex((t) => t.id === np);
  const dir = idx >= lastPageIdx ? 40 : -40;
  lastPageIdx = idx;
  newEl.classList.remove('page-off');
  if (reduceMotion()) return;
  /* 旧页临时可见做离场动画（absolute 脱离文档流，避免与新页高度叠加） */
  oldEl.classList.remove('page-off');
  oldEl.style.display = 'flex';
  gsap.killTweensOf([oldEl, newEl]);
  gsap.set(oldEl, { position: 'absolute', left: 0, right: 0, top: 0 });
  gsap.set(newEl, { autoAlpha: 0, x: dir });
  const tl = gsap.timeline();
  tl.to(oldEl, {
    autoAlpha: 0,
    x: -dir * 0.7,
    duration: 0.25,
    ease: 'power2.in',
    onComplete: () => {
      oldEl.classList.add('page-off');
      oldEl.style.position = '';
      oldEl.style.left = '';
      oldEl.style.right = '';
      oldEl.style.top = '';
      oldEl.style.display = '';
      oldEl.style.opacity = '';
      oldEl.style.visibility = '';
      oldEl.style.transform = '';
    },
  });
  tl.to(newEl, { autoAlpha: 1, x: 0, duration: 0.45, ease: 'power3.out', onComplete: () => gsap.set(newEl, { clearProps: 'opacity,visibility,transform' }) }, 0.2);
});

/* 全局悬浮呼吸：所有控件与玻璃大框的「抬起+发光」统一由 GSAP 事件委托驱动 */
installGlowHover(gsap);

// ---------- 同步任务（任务化暂停/恢复） ----------
const { tasks, createTask, updateTask, pauseTask, completeTask, failTask, removeTask } = useSyncTasks();
const activeTaskId = ref('');
function taskStateText(s: SyncTask['state']): string {
  return s === 'running' ? '进行中' : s === 'paused' ? '已暂停' : s === 'completed' ? '已完成' : '失败';
}
/** 唤醒任务对端：对齐本机同步目标（恢复/重试共用）。
 *  P2 硬升级：v2 问候（greetDevice）已删除，接收服务就绪由 sendBackup 内 prepare-upload 重试兜底 */
async function wakePeerFor(t: SyncTask) {
  if (t.peerIp && t.peerPort && deviceInfo.value) {
    const rec = t.peerFingerprint ? pairMgr.byFingerprint(t.peerFingerprint) : null;
    if (rec) selectTarget(rec);
  }
}
/** 恢复 = 重新执行同步（增量规划通过接收端清单自动跳过已完成文件，文件级续传）。
 *  先按任务记录的对端做唤醒问候：触发对端拉起接收服务 + 对齐同步目标（断网前上下文） */
async function resumeTaskAction() {
  const pending = tasks.value.find((t: SyncTask) => t.state === 'paused');
  if (pending) await wakePeerFor(pending);
  runBackup();
}
/** 重试失败任务：与恢复同路径（唤醒对端后重新执行同步） */
async function retryTaskAction(t: SyncTask) {
  await wakePeerFor(t);
  runBackup();
}

// ---------- 断网自动重连 + 暂停任务自动恢复 ----------
// 断网时任务标记暂停；网络恢复后自动问候任务记录的对端（问候成功 = 对端可达，
// 且其接收服务已被 peer-connected 拉起），随后自动恢复任务（增量 + 分片状态跳过已完成部分）
const autoResume = useAutoResume({
  isBusy: () => scanning.value || !!activeTaskId.value,
  getPending: () => tasks.value.find((t: SyncTask) => t.state === 'paused' && t.peerIp && t.peerPort),
  verifyPeer: async (t) => {
    if (!t.peerIp || !t.peerPort) return false;
    try {
      // P2 硬升级：v2 问候（greetDevice）已删除，改 v3 probe 探测对端配对服务可达
      await v3Probe({ ip: t.peerIp, port: t.peerPort });
      return true;
    } catch {
      return false;
    }
  },
  onReconnect: (t) => {
    const rec = t.peerFingerprint ? pairMgr.byFingerprint(t.peerFingerprint) : null;
    if (rec) {
      pairMgr.markOnline(rec.fingerprint, t.peerIp!, t.peerPort!);
      pairMgr.markConnected(rec.fingerprint, true);
      refreshPairings();
      selectTarget(rec);
    }
  },
  onResume: async (t) => {
    // 防御门禁（BUG-4）：自动恢复前校验对端是否真实配对（有 secret）。
    // 清数据/未配对状态下，仅"被发现"的设备不得触发自动同步推送数据。
    if (t.peerIp) {
      const paired = await isPeerPaired(t.peerIp).catch(() => false);
      if (!paired) {
        pushToast('warn', `「${t.peer}」尚未与本机完成配对，已跳过自动恢复`);
        logger.warn('ui', `自动恢复被门禁拦截：对端未配对 peer=${t.peer}(${t.peerIp})`);
        return;
      }
    }
    runBackup();
  },
  notify: (text) => pushToast('ok', text),
  logInfo: (msg) => logger.info('ui', msg),
});
/* 发送进度 → 任务进度联动 */
watch(progress, (p) => {
  if (activeTaskId.value && p) {
    updateTask(activeTaskId.value, { sentCount: p.current, fileCount: p.total, bytes: p.bytesSent || 0, totalBytes: p.totalBytes || 0 });
  }
});

/** 配置卡呼吸灯：收件=目录+服务双全→绿，其余→灰。发件=目标设备在线→绿，其余→灰
    （黄色已移除：停止/离线是常态不是警告，红黄仅留给真正的异常） */
const recvDot = computed<'on' | ''>(() => {
  return boxC2p.value && serverRunning.value ? 'on' : '';
});
const sendDot = computed<'on' | ''>(() => {
  return targetDevice.value?.online ? 'on' : '';
});

/** 收件启动中标记：只在真正发起启动的瞬间置位，避免服务闪烁时误现“启用中” */
const recvStarting = ref(false);
watch(serverRunning, (r) => {
  if (r) recvStarting.value = false;
});

/** 一键开启收件：未选目录先引导选择，然后确保收件服务运行。
    仅在服务运行中拦截——receiverEnabled 为真但服务已停（常见状态）时仍可再次开启 */
async function oneClickReceive() {
  if (serverRunning.value) return;
  if (!boxC2p.value) {
    await pickBoxC2p();
    if (!boxC2p.value) return;
  }
  receiverEnabled.value = true;
  recvStarting.value = true;
  persistConfig();
  try {
    await startReceiverSafe(boxC2p.value);
  } finally {
    recvStarting.value = false;
  }
}

/** 一键关闭收件：停用收件并停止服务 */
function oneClickCloseReceive() {
  receiverEnabled.value = false;
  persistConfig();
  if (serverRunning.value) onStopReceiver();
}

/** 手动连接输入保留到成功连接或手动清空（离开页面不再丢失用户输入） */

/** 卡片/面板离场：先收高度（0.5s），接近缩完时缓慢淡出（0.2s），
    兄弟项在高度动画期间连续上移到位（margin 收拢到 0，不再有 gap 残留跳闪） */
function cardLeave(el: Element, done: () => void) {
  const node = el as HTMLElement;
  node.style.transition = 'none';
  if (reduceMotion()) {
    node.style.opacity = '0';
    done();
    return;
  }
  const tl = gsap.timeline({
    onComplete: () => {
      node.style.height = '';
      node.style.marginBottom = '';
      node.style.opacity = '';
      node.style.transform = '';
      node.style.visibility = '';
      node.style.overflow = '';
      done();
    },
  });
  tl.to(node, { height: 0, marginBottom: 0, duration: 0.5, ease: 'power3.inOut' })
    .to(node, { autoAlpha: 0, scaleY: 0.94, duration: 0.2, ease: 'power2.in' }, 0.35);
}

/** 卡片/面板入场：从 0 高度向下拉长展开（仅用于扫描块/发现列表/连接码区，不设 margin） */
function cardEnter(el: Element, done: () => void) {
  const node = el as HTMLElement;
  node.style.transition = 'none';
  if (reduceMotion()) {
    done();
    return;
  }
  const h = node.offsetHeight;
  gsap.set(node, { height: 0, autoAlpha: 0 });
  gsap.to(node, {
    height: h,
    autoAlpha: 1,
    duration: 0.5,
    ease: 'power3.inOut',
    onComplete: () => {
      node.style.height = '';
      node.style.opacity = '';
      node.style.transform = '';
      node.style.visibility = '';
      done();
    },
  });
}

/** 收发件配置卡离场：高度+内边距收拢到 0，并用负 margin 抵消容器 gap，
    兄弟卡被高度动画连续推上移且最终位置与移除后一致（无尾部跳闪） */
function cardListLeave(el: Element, done: () => void) {
  const node = el as HTMLElement;
  node.style.transition = 'none';
  if (reduceMotion()) {
    node.style.opacity = '0';
    done();
    return;
  }
  gsap.timeline({
    onComplete: () => {
      node.style.height = '';
      node.style.marginBottom = '';
      node.style.paddingTop = '';
      node.style.paddingBottom = '';
      node.style.borderTopWidth = '';
      node.style.borderBottomWidth = '';
      node.style.opacity = '';
      node.style.transform = '';
      node.style.visibility = '';
      node.style.overflow = '';
      done();
    },
  })
    .to(node, { height: 0, paddingTop: 0, paddingBottom: 0, borderTopWidth: 0, borderBottomWidth: 0, marginBottom: -14, duration: 0.2, ease: 'power2.inOut' })
    .to(node, { autoAlpha: 0, duration: 0.1, ease: 'power2.in' }, 0.12);
}

/** 列表项移除：
    对删除项施加 SVG feTurbulence 流体烟雾滤镜（颗粒漂移 + displacement 形变 + 雾化），
    同时持续抖动 turbulence 的 baseFrequency，让内容如烟雾般融化飘散；再收拢高度。
    prefers-reduced-motion 时降级为纯收拢。 */
async function smokeDissolve(row: HTMLElement) {
  if (reduceMotion()) {
    gsap.set(row, { autoAlpha: 0, height: 0, paddingTop: 0, paddingBottom: 0, borderTopWidth: 0, borderBottomWidth: 0 });
    return;
  }
  // ① 把行文本拆成独立「字符粒子」，每个粒子各自向右上飘散成烟
  spawnSmokeChars(row);
  // ② 原行及时收拢淡出（字符粒子在 fixed 层独立冒烟，不受行消失影响）
  await new Promise<void>((res) => {
    gsap.to(row, { height: 0, paddingTop: 0, paddingBottom: 0, borderTopWidth: 0, borderBottomWidth: 0, opacity: 0, duration: 0.25, ease: 'power2.inOut', onComplete: () => res() });
  });
}

/** 拆分文本为独立「字符粒子」，配合 feTurbulence 流体滤镜 + 每粒子独特轨迹向右上扩散 */
function spawnSmokeChars(row: HTMLElement) {
  try {
    const chars = [...(row.innerText || '')].filter((c) => !/\s/.test(c));
    if (!chars.length) { gsap.set(row, { autoAlpha: 0 }); return; }
    const r = row.getBoundingClientRect();
    const st = getComputedStyle(row);
    const fs = parseFloat(st.fontSize) || 14;
    const cols = Math.max(4, Math.floor(r.width / fs));
    const charW = r.width / cols;
    // 共享 feTurbulence 驱动：全局流体抖动，给每个粒子统一的烟雾颗粒质感
    const turb = document.getElementById('smoke-turb');
    let frames = 0;
    const intv = setInterval(() => {
      if (!turb) return;
      frames += 0.2;
      turb.setAttribute('baseFrequency', `${0.03 + 0.005 * Math.cos((frames * Math.PI) / 180)} ${0.03 + 0.005 * Math.sin((frames * Math.PI) / 180)}`);
    }, 16);
    chars.forEach((ch, i) => {
      const col = i % cols;
      const rwi = Math.floor(i / cols);
      const cx = r.left + charW * col + charW / 2;
      const cy = r.top + 6 + rwi * fs * 1.2;
      const s = document.createElement('span');
      s.className = 'smoke-char';
      s.textContent = ch;
      s.style.left = `${cx}px`;
      s.style.top = `${cy}px`;
      s.style.color = 'transparent'; // 仅靠灰色烟阴影显形，更「灰」更「散」
      s.style.fontSize = `${fs}px`;
      s.style.fontFamily = st.fontFamily;
      s.style.fontWeight = st.fontWeight;
      s.style.filter = 'url(#smoke-filter)';
      document.body.appendChild(s);
      gsap.set(s, { xPercent: -50, yPercent: -50 });
      // 整体同批次飘散（无 delay）；偶数字符镜像（skewX 反转、scale 更大）
      const mirror = i % 2 === 0;
      const tx = 190 + Math.random() * 70; // 右上位移（x 正、y 负）
      const ty = -(100 + Math.random() * 50);
      gsap
        .timeline({ defaults: { ease: 'power1.in' }, onComplete: () => s.remove() })
        .set(s, { textShadow: '0 0 6px rgba(205,207,214,0.28)' })
        .to(s, { textShadow: '0 0 40px rgba(212,214,222,0.6)', duration: 0.8 })
        .to(
          s,
          {
            x: tx,
            y: ty,
            rotation: -40,
            skewX: mirror ? -70 : 70,
            scale: mirror ? 2 : 1.5,
            textShadow: '0 0 16px rgba(212,214,222,0.22)',
            autoAlpha: 0,
            duration: 1.4,
          },
          0.2,
        );
    });
    setTimeout(() => clearInterval(intv), 1900);
  } catch (e) {
    console.error('烟雾字符生成失败', e);
  }
}

/** TransitionGroup 离场钩子：烟雾消散后交还控制权，兄弟项由 move 类平滑回位 */
function listLeave(el: Element, done: () => void) {
  smokeDissolve(el as HTMLElement).then(done);
}

/** 历史分组离场：高度收拢 + 淡出（删除组内最后一条记录时整组平滑消失，不再瞬间消失） */
function groupLeave(el: Element, done: () => void) {
  const node = el as HTMLElement;
  node.style.transition = 'none';
  if (reduceMotion()) {
    node.style.opacity = '0';
    done();
    return;
  }
  gsap.to(node, {
    height: 0,
    autoAlpha: 0,
    duration: 0.35,
    ease: 'power2.inOut',
    onComplete: () => {
      node.style.height = '';
      node.style.opacity = '';
      node.style.visibility = '';
      done();
    },
  });
}
const roleDesc = computed(() =>
  role.value === 'receiver' ? '接收他人推送的文件' : role.value === 'sender' ? '推送本机文件夹' : '收发并存',
);
/** 上次同步摘要（状态总览卡底部） */
const lastSyncText = computed(() => {
  const t = [...transfers.value].sort((a, b) => b.createdAt - a.createdAt)[0];
  if (!t) return '';
  const dir = t.direction === 'out' ? '发件' : '收件';
  return `上次同步：${dir} ${t.fileCount} 个文件 · ${fmtBytes(t.bytes)} · ${new Date(t.createdAt).toLocaleString()}`;
});
/** 接收端启用开关 */
const receiverEnabled = ref(false);
/** 接收端默认开启：应用启动自动进入接收状态 */
const autoStartReceiver = ref(false);
/** 接收端配置区折叠 */
const recvPanelCollapsed = ref(true); // 收件区配置默认折叠
const sendPanelCollapsed = ref(true); // 发件区配置默认折叠
/** 发送端：多文件夹列表（手机端 SAF 限制，实际单文件夹，但模型与桌面端一致） */
const senderFolders = ref<SendFolder[]>([]);
/** 临时文件夹（会话级，重启清空；点选新增，与永久文件夹一起参与本次同步） */
const sessionFolders = ref<SendFolder[]>([]);
/** 本次同步跳过集合（行内开关：勾选=参与，取消=本次跳过；不写回永久配置） */
const syncSkip = reactive(new Set<string>());
/** 自动接收开关：开启后收到的文件全自动保存，无需人工确认（localStorage 持久化） */
const autoAcceptReceive = ref(localStorage.getItem('auto_accept_receive') === '1');
function toggleAutoAcceptReceive() {
  autoAcceptReceive.value = !autoAcceptReceive.value;
  try { localStorage.setItem('auto_accept_receive', autoAcceptReceive.value ? '1' : '0'); } catch { /* 忽略 */ }
}
/** 本次实际发送的文件夹 = 启用的永久文件夹（未被跳过）+ 全部临时文件夹（未被跳过） */
const effectiveSendFolders = computed(() => {
  const out: SendFolder[] = [];
  for (const f of senderFolders.value) if (f.enabled && !syncSkip.has(f.id)) out.push(f);
  for (const f of sessionFolders.value) if (!syncSkip.has(f.id)) out.push(f);
  return out;
});

function loadAppConfig() {
  try {
    const raw = localStorage.getItem('lanbackup_config');
    appConfig.value = parseConfig(raw);
  } catch {
    appConfig.value = normalizeConfig(null);
  }
  applyConfigToState();
}

function applyConfigToState() {
  const c = appConfig.value;
  role.value = c.role;
  receiverEnabled.value = c.receiver.enabled;
  autoStartReceiver.value = c.receiver.autoStartReceiver;
  senderFolders.value = c.sender.folders.map((f) => ({ ...f }));
  syncStrategy.value = c.sender.strategy;
  // 恢复接收目录（boxC2p）
  if (c.receiver.receiveDir) {
    try {
      const p = JSON.parse(localStorage.getItem('lanbackup_box_c2p') || 'null');
      if (p?.uri) boxC2p.value = p;
      else boxC2p.value = { uri: c.receiver.receiveDir, name: '接收目录', persisted: true };
    } catch {
      boxC2p.value = { uri: c.receiver.receiveDir, name: '接收目录', persisted: true };
    }
  }
  // 恢复发送目录（boxP2c）—— 兼容旧版单目录
  if (senderFolders.value.length === 0) {
    try {
      const p = JSON.parse(localStorage.getItem('lanbackup_box_p2c') || 'null');
      if (p?.uri) {
        boxP2c.value = p;
        senderFolders.value.push({ id: genFolderId(), name: p.name || '手机源目录', path: p.uri, enabled: true });
      }
    } catch {
      // 忽略
    }
  }
}

function persistConfig() {
  const c = appConfig.value;
  c.role = role.value;
  c.receiver.enabled = receiverEnabled.value;
  c.receiver.autoStartReceiver = autoStartReceiver.value;
  c.receiver.receiveDir = boxC2p.value?.uri || '';
  c.sender.folders = senderFolders.value.map((f) => ({ ...f }));
  c.sender.strategy = syncStrategy.value;
  c.sender.targetPeerId = targetDevice.value?.fingerprint;
  try {
    localStorage.setItem('lanbackup_config', stringifyConfig(c));
  } catch {
    // 忽略
  }
}

function setRole(r: DeviceRole) {
  role.value = r;
  persistConfig();
}

/** 同步方向可多选：同时开启收件+发件 = 双向（free）；至少保留一项 */
function toggleRoleDir(dir: 'receive' | 'send') {
  const recv = role.value === 'receiver' || role.value === 'free';
  const send = role.value === 'sender' || role.value === 'free';
  const nr = dir === 'receive' ? !(recv && send) : recv;
  const ns = dir === 'send' ? !(send && recv) : send;
  setRole(nr && ns ? 'free' : nr ? 'receiver' : 'sender');
}

function toggleReceiverEnabled() {
  receiverEnabled.value = !receiverEnabled.value;
  persistConfig();
  // 启用且目录已配 → 立即进入接收状态；停用 → 停止接收服务
  if (receiverEnabled.value) {
    if (boxC2p.value && !serverRunning.value) {
      startReceiverSafe(boxC2p.value);
    }
  } else if (serverRunning.value) {
    onStopReceiver();
  }
}

function toggleAutoStartReceiver() {
  autoStartReceiver.value = !autoStartReceiver.value;
  persistConfig();
}

function toggleRecvPanel() {
  recvPanelCollapsed.value = !recvPanelCollapsed.value;
}

function toggleSendPanel() {
  sendPanelCollapsed.value = !sendPanelCollapsed.value;
}

/** 发送文件夹：添加（手机端 SAF 单目录选择） */
async function addSendFolder() {
  try {
    const root = await pickBackupRoot();
    if (!root) return;
    const name = root.name || '文件夹';
    senderFolders.value.push({ id: genFolderId(), name, path: root.uri, enabled: true });
    // 同步到 boxP2c 兼容旧版引用
    boxP2c.value = root;
    persistBox('lanbackup_box_p2c', root);
    persistConfig();
    notice.value = `已添加发送文件夹：${name}`;
    // 通知目标设备（电脑）本机源目录名
    const t = targetDevice.value;
    if (t) {
      try {
        await sendSyncDir({ ip: t.ip, port: t.port, direction: 'phone-to-pc', name });
        logger.info('pair', `已同步源目录名到 ${t.name}`);
      } catch (e) {
        logger.warn('pair', '同步目录名失败（目标可能离线）', e);
      }
    }
  } catch (e) {
    errorMsg.value = `选择目录失败: ${(e as Error).message}`;
  }
}

function removeSendFolder(id: string) {
  senderFolders.value = senderFolders.value.filter((f) => f.id !== id);
  syncSkip.delete(id);
  if (senderFolders.value.length === 0) {
    boxP2c.value = null;
    persistBox('lanbackup_box_p2c', null);
  }
  persistConfig();
}

/** 永久文件夹移除（统一走确认弹窗，防误删） */
async function confirmRemoveSendFolder(f: SendFolder) {
  const ok = await askConfirmAsync({
    title: '移除永久文件夹',
    message: `将「${f.name}」从永久发件配置中移除？此操作不可恢复。`,
    danger: true,
  });
  if (!ok) return;
  removeSendFolder(f.id);
}

/** 临时文件夹：点选新增（会话级，重启清空） */
async function addSessionFolder() {
  try {
    const root = await pickBackupRoot();
    if (!root) return;
    sessionFolders.value.push({ id: 'tmp_' + genFolderId(), name: root.name || '文件夹', path: root.uri, enabled: true });
  } catch (e) {
    errorMsg.value = `选择临时文件夹失败: ${(e as Error).message}`;
  }
}

/** 临时文件夹：移除（仅本次会话，直接移除不弹窗） */
function removeSessionFolder(id: string) {
  sessionFolders.value = sessionFolders.value.filter((f) => f.id !== id);
  syncSkip.delete(id);
}

function toggleSendFolder(id: string) {
  const f = senderFolders.value.find((x) => x.id === id);
  if (f) {
    f.enabled = !f.enabled;
    persistConfig();
  }
}

function setStrategy(s: SyncStrategy) {
  syncStrategy.value = s;
  persistConfig();
}

/** 安全启动接收服务（去重，避免重复调用） */
async function startReceiverSafe(root: BackupRoot) {
  if (scanning.value) return;
  try {
    const res = await startReceiver({
      port: 53317,
      rootUri: root.uri,
      selfCode: selfCode.value,
    });
    serverRunning.value = true;
    serverPort.value = res.port;
  } catch (e) {
    logger.warn('receiver', '启动接收服务失败', e);
  }
}

// ---------- 设置 ----------
const deviceNameInput = ref('');
const debugSummary = ref(logger.summary());
const debugEnabled = ref(true);
/** 画面质量（低/中/高），默认高 */
const qualityLevel = ref('high');
try {
  const saved = localStorage.getItem('quality_level');
  if (saved === 'low' || saved === 'medium' || saved === 'high') qualityLevel.value = saved;
} catch { /* 忽略 */ }
function setQuality(v: string) {
  qualityLevel.value = v;
  try { localStorage.setItem('quality_level', v); } catch { /* 忽略 */ }
}
/* 画面质量切换 → <html> 打标 + 玻璃模糊采样频率（壁纸视频本身不锁帧，全帧率播放） */
/** 玻璃模糊采样频率：高=12fps(83ms) / 中=3fps(333ms) / 低=0(停止采样，无玻璃) */
function syncWallpaper() {
  const interval = qualityLevel.value === 'high' ? 83 : qualityLevel.value === 'medium' ? 333 : 0;
  setBlurInterval(interval);
  // 低画质视觉优化（已确认）：视频暂停为静止帧（0fps），省解码开销；切回中/高恢复播放
  const v = document.querySelector<HTMLVideoElement>('video.wallpaper-video');
  if (v) {
    if (qualityLevel.value === 'low') v.pause();
    else if (v.paused) v.play();
  }
}

watch(qualityLevel, (v) => {
  document.documentElement.classList.toggle('quality-low', v === 'low');
  document.documentElement.classList.toggle('quality-medium', v === 'medium');
  document.documentElement.classList.toggle('quality-high', v === 'high');
  syncWallpaper();
}, { immediate: true });
/** 调试模式开关：关闭后不记录任何日志（含错误），减少 I/O 提升性能；持久化到 localStorage */
function setDebug(v: boolean) {
  debugEnabled.value = v;
  logger.setDebugEnabled(v);
  try {
    localStorage.setItem('lanbackup_debug', String(v));
  } catch {
    // 忽略
  }
}
/* 选中策略：调试关闭时全局禁选中（仅输入框与调试日志例外）；开启后任意可选中 */
watch(debugEnabled, (v) => document.documentElement.classList.toggle('debug-on', v), { immediate: true });
/** 复制到剪贴板（clipboard API + execCommand 双保险），成功后 toast 提示 */
async function copyText(text: string, okMsg: string) {
  if (!text) return; // 空值不复制也不弹提示（自信息未就绪时静默）
  try {
    await navigator.clipboard.writeText(text);
    pushToast('ok', okMsg);
  } catch {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      pushToast('ok', okMsg);
    } catch {
      errorMsg.value = '复制失败，请手动选择复制';
    }
  }
}

const verifying = ref(false);
const showLogPreview = ref(false);
const logPreviewText = ref('');
let nameSaveTimer: ReturnType<typeof setTimeout> | null = null;

const percent = computed(() =>
  progress.value ? Math.round((progress.value.current / progress.value.total) * 100) : 0,
);
/** 发送进度百分比：优先按字节（块级事件），否则按文件数 */
const progressPercent = computed(() => {
  const p = progress.value;
  if (!p) return 0;
  if (p.bytesSent !== undefined && p.totalBytes && p.totalBytes > 0) {
    return p.bytesSent / p.totalBytes;
  }
  return p.current / Math.max(1, p.total);
});
const percentText = computed(() => Math.round(progressPercent.value * 100));
/** 就绪状态（同步操作卡常驻按钮用）：目标设备 + 至少一个启用文件夹 */
const sendFolderCount = computed(() => senderFolders.value.filter((f) => f.enabled).length);
const syncReady = computed(() => !!targetDevice.value && effectiveSendFolders.value.length > 0);
const runHintText = computed(() => {
  if (scanning.value) return '同步进行中，可离开此页；进度与任务都会记录在下方';
  if (!targetDevice.value) return '未就绪 · 请选择目标设备';
  if (effectiveSendFolders.value.length === 0) return '未就绪 · 请添加发件文件夹（永久或临时）';
  return `就绪 · ${effectiveSendFolders.value.length} 个文件夹 → ${targetDevice.value.name}`;
});
/** 同步列表面板：永久配置 + 临时会话文件夹 */
const syncList = computed(() => [...senderFolders.value, ...sessionFolders.value]);
/** 是否为永久配置文件夹 */
function isPermanentFolder(f: SendFolder) {
  return senderFolders.value.some((x) => x.id === f.id);
}
/** 行内开关：切换本次是否参与同步（不写回永久配置） */
function toggleSyncInclude(id: string) {
  if (syncSkip.has(id)) syncSkip.delete(id);
  else syncSkip.add(id);
}
/** 移除：永久文件夹走确认弹窗（从永久配置删除）；临时文件夹直接移除（本次会话） */
function removeFolderFromSync(f: SendFolder) {
  if (isPermanentFolder(f)) confirmRemoveSendFolder(f);
  else removeSessionFolder(f.id);
}
/** 开始同步按钮文案（按模式） */
const runBtnLabel = computed(() => {
  if (scanning.value) return '同步进行中...';
  if (role.value === 'receiver') return autoAcceptReceive.value ? '自动接收：开' : '自动接收：关';
  return '开始同步';
});
/** 开始同步按钮就绪态（只收件时随自动接收：关=灰 / 开=青） */
const runBtnReady = computed(() => (role.value === 'receiver' ? autoAcceptReceive.value : syncReady));
/** 接收进度百分比 */
const recvPercent = computed(() =>
  recvProgress.value && recvProgress.value.totalBytes > 0
    ? recvProgress.value.receivedBytes / recvProgress.value.totalBytes
    : 0,
);
/** 发送速率差分：每次进度事件与上一次的字节差 / 时间差 */
watch(progress, (p) => {
  const now = Date.now();
  if (p && p.bytesSent !== undefined && p.bytesSent > 0) {
    const dt = (now - lastRateSample.t) / 1000;
    if (lastRateSample.t > 0 && dt > 0.2) {
      const rate = (p.bytesSent - lastRateSample.bytes) / dt;
      if (rate >= 0 && rate < 500 * 1024 * 1024) {
        const total = p.totalBytes || 1;
        rateInfo.value = {
          rate,
          etaSec: rate > 0 ? (total - p.bytesSent) / rate : 0,
        };
      }
    }
    lastRateSample = { t: now, bytes: p.bytesSent };
  }
});

// ---------- 主题 ----------
function applyTheme() {
  document.documentElement.classList.toggle('dark', darkMode.value);
  try {
    localStorage.setItem('lanbackup_dark', String(darkMode.value));
  } catch {
    // 忽略
  }
  // 状态栏主题色跟随（Android WebView 尊重 theme-color）
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', darkMode.value ? '#0a0a0c' : '#f2f2f7');
}
watch(darkMode, applyTheme, { immediate: true });

// ---------- 初始化 ----------
onMounted(async () => {
  /* 初始页激活：去掉 page-off（在首帧绘制前执行，无闪烁） */
  pageRef.value?.querySelector<HTMLElement>(`[data-page="${currentPage.value}"]`)?.classList.remove('page-off');
  window.addEventListener('keydown', onGlobalEsc);
  syncWallpaper(); /* 中档壁纸 3fps 采样在挂载后启动 */
  applyTheme();
  // 恢复调试模式开关（默认开启；关闭后不记录日志）
  try {
    const d = localStorage.getItem('lanbackup_debug');
    if (d !== null) {
      debugEnabled.value = d === 'true';
      logger.setDebugEnabled(debugEnabled.value);
    }
  } catch {
    // 忽略
  }
  unsubLog = logger.subscribe(() => {
    debugSummary.value = logger.summary();
  });
  mm = gsap.matchMedia();
  mm.add('(prefers-reduced-motion: reduce)', () => {
    gsap.set('.glow-blob', { autoAlpha: 1 });
  });
  mm.add('(prefers-reduced-motion: no-preference)', () => {
    gsap.to('.glow-blob-1', { x: 90, y: 60, duration: 18, yoyo: true, repeat: -1, ease: 'sine.inOut' });
    gsap.to('.glow-blob-2', { x: -80, y: -50, duration: 22, yoyo: true, repeat: -1, ease: 'sine.inOut' });
  });
  try {
    await requestStoragePermission();
    // 连接码：刷新过的码优先，否则按设备号默认算法
    selfCode.value = (await getSelfCode()) || (await getSelfConnectionCode());
    state.value = migrateState(await loadState());
    try {
      deviceInfo.value = await getDeviceInfo();
      deviceNameInput.value = deviceInfo.value.name;
    } catch (e) {
      logger.warn('device', '读取设备信息失败', e);
    }
// 恢复盒子与配对
      try {
        const p = JSON.parse(localStorage.getItem('lanbackup_box_p2c') || 'null');
        if (p?.uri) boxP2c.value = p;
      } catch {
        // 忽略
      }
      try {
        const p = JSON.parse(localStorage.getItem('lanbackup_box_c2p') || 'null');
        if (p?.uri) boxC2p.value = p;
      } catch {
        // 忽略
      }
      // 加载角色模型配置
      loadAppConfig();
      // 接收端默认开启：角色为接收端/自由模式 + 开关开启 + 目录已配 → 自动进入接收状态
      if ((role.value === 'receiver' || role.value === 'free') && receiverEnabled.value && autoStartReceiver.value && boxC2p.value && !serverRunning.value) {
        await startReceiverSafe(boxC2p.value);
      }
      // 已配置过接收目录 → 自动恢复常驻接收服务（电脑随时可推，无需手机端手动操作）
      if (boxC2p.value && !serverRunning.value) {
      try {
        const res = await startReceiver({
          port: 53317,
          rootUri: boxC2p.value.uri,
          selfCode: selfCode.value,
        });
        serverRunning.value = true;
        serverPort.value = res.port;
      } catch (e) {
        logger.warn('receiver', '自动启动接收服务失败', e);
      }
    }
    refreshPairings();
    // 连接是显式会话：重启后统一复位为"未连接"（回到状态3），避免陈旧已连接状态不对称
    for (const r of pairMgr.all()) {
      if (r.connected) pairMgr.markConnected(r.fingerprint, false);
    }
    refreshPairings();
    const online = pairings.value.filter((p) => p.online);
    if (online.length > 0) targetDevice.value = online[0];
    else if (pairings.value.length > 0) targetDevice.value = pairings.value[0];
    try {
      serverRunning.value = await isReceiverRunning();
    } catch {
      serverRunning.value = false;
    }
    // 读取防御性总开关的持久化状态（隐藏=完全不可见）
    try {
      defensiveHidden.value = await getDefensiveHidden();
    } catch (e) {
      logger.warn('pair', '读取防御性总开关失败', e);
      defensiveHidden.value = false;
    }
    loadTransfers();
    // 对方验证本机码通过时实时刷新（被配对场景立即显示，不等轮询）
    try {
      unlistenPairMobile = await onPairedUpdated(() => {
        mergePeers();
      });
    } catch (e) {
      logger.warn('pair', '监听配对事件失败', e);
    }
    // 对方连接本机 → 标记已连接（去抖提示，让被连方实时感知）
    try {
      unlistenPeerMobile = await onPeerConnected(async (p) => {
        let rec = pairMgr.byDeviceId(p.deviceId);
        if (!rec) {
          // 配对成功瞬间的事件顺序竞态：paired-updated → mergePeers 需过桥取数（异步），
          // peer-connected 常先到达 → 记录未入列 → "已连接"标记静默丢失。
          // 此处补拉一次原生配对表再标记。
          await mergePeers();
          rec = pairMgr.byDeviceId(p.deviceId);
        }
        if (rec) {
          const wasConnected = !!rec.connected;
          pairMgr.markOnline(rec.fingerprint, rec.ip, rec.port);
          pairMgr.markConnected(rec.fingerprint, true);
          refreshPairings();
          // 已配对设备穿透隐藏连接：接收服务未运行时自动拉起（断点续传/收件可用）
          if (!serverRunning.value && boxC2p.value) {
            startReceiverSafe(boxC2p.value);
          }
          const now = Date.now();
          const last = connectNoticeAt.get(rec.fingerprint) || 0;
          if (!wasConnected && now - last > 30000) {
            connectNoticeAt.set(rec.fingerprint, now);
            notice.value = `「${rec.name}」已连接本机`;
          }
        }
      });
    } catch (e) {
      logger.warn('pair', '监听连接事件失败', e);
    }
    // 对方主动断开连接 → 清除"已连接"状态（回到在线）
    try {
      unlistenDisconnectMobile = await onPeerDisconnected((deviceId) => {
        const rec = pairMgr.byDeviceId(deviceId);
        if (rec) {
          pairMgr.markConnected(rec.fingerprint, false);
          refreshPairings();
          notice.value = `「${rec.name}」已断开连接`;
        }
      });
    } catch (e) {
      logger.warn('pair', '监听断开连接事件失败', e);
    }
    // 常驻加密存在广播：已配对设备在线/离线（独立于收件/发现服务，仅防御总闸影响）。
    // 收到有效加密存在(含HMAC) → 在线；连续收不到(约12s) → 立即离线（与桌面端一致）
    try {
      unlistenPresenceMobile = await onPairPresence(({ deviceId, online }) => {
        const rec = pairMgr.byDeviceId(deviceId);
        if (!rec) return;
        if (online) {
          // bcpd HMAC 验证比明文 deviceId 更强：接入集合后 connectPeer 跳过 deviceId 比对
          bcpdConfirmedOnline.add(rec.fingerprint);
          pairMgr.markOnline(rec.fingerprint, rec.ip, rec.port);
          rejectCount.delete(rec.fingerprint);
          probeSkip.delete(rec.fingerprint);
        } else {
          bcpdConfirmedOnline.delete(rec.fingerprint);
          pairMgr.markOffline(rec.fingerprint);
        }
        refreshPairings();
      });
    } catch (e) {
      logger.warn('pair', '监听加密存在广播失败', e);
    }
    // 对方解除配对 → 即时删除本地配对（不再依赖轮询误判）
    try {
      unlistenUnpairMobile = await onPairUnpaired((deviceId) => {
        const rec = pairMgr.byDeviceId(deviceId);
        if (rec) {
          pairMgr.remove(rec.fingerprint);
          rejectCount.delete(rec.fingerprint);
          connectNoticeAt.delete(rec.fingerprint);
          refreshPairings();
          notice.value = `「${rec.name}」已解除与本机的配对`;
        }
      });
    } catch (e) {
      logger.warn('pair', '监听解除配对事件失败', e);
    }
    // 本机正在接收对方文件（让被同步方实时知道，带大小）
    try {
      unlistenFileRecvMobile = await onFileReceived((p) => {
        notice.value = `正在接收：${p.fileName}` + (p.bytes ? `（${fmtBytes(p.bytes)}）` : '');
      });
    } catch (e) {
      logger.warn('pair', '监听文件接收事件失败', e);
    }
    // 对方确认已收到本机发送的文件（发送回执）
    try {
      unlistenFileReceiptMobile = await onFileReceipt((fileName) => {
        lastReceipt.value = fileName;
        notice.value = `对方已确认接收：${fileName}`;
      });
    } catch (e) {
      logger.warn('pair', '监听文件回执事件失败', e);
    }
    // 整批接收完成 → 写入接收历史（文件数/字节/耗时，与发送历史同构）+ 进度框「备份完成」
    try {
      unlistenReceiveComplete = await onReceiveComplete((s) => {
        const peerName = targetDevice.value?.name || '对方设备';
        pushTransfer('in', peerName, s.count, s.bytes, s.durationMs);
        progressDone.value = { direction: 'in', count: s.count, bytes: s.bytes, durationMs: s.durationMs };
        recvProgress.value = null;
        notice.value = `已接收 ${s.count} 个文件（${fmtBytes(s.bytes)}，${(s.durationMs / 1000).toFixed(1)} 秒）`;
      });
    } catch (e) {
      logger.warn('pair', '监听接收完成事件失败', e);
    }
    // 配对确认弹窗（对方填写了本机连接码请求配对）
    try {
      unlistenPairingMobile = await onPairingRequest((r) => {
        pairingReq.value = r;
      });
    } catch (e) {
      logger.warn('pair', '监听配对请求失败', e);
    }
    // 接收确认弹窗（电脑→手机）：prepare-upload 时原生请求用户同意
    try {
      unlistenIncomingMobile = await onIncomingRequest((r) => {
        // 记录当前收件来源：取消收件时通知对端（电脑）停止传输（自动接收分支同样记录）
        currentRecvSource.value = { ip: r.senderIp, port: 53318, sessionId: r.sessionId };
        // 自动接收开关开启 → 免确认直接接收；否则弹窗人工确认
        if (autoAcceptReceive.value) {
          resolveIncoming(r.sessionId, true)
            .then(() => { notice.value = `已自动接收 ${r.count} 个文件`; })
            .catch((e) => { errorMsg.value = `自动接收失败: ${(e as Error).message}`; });
        } else {
          incomingReq.value = r;
        }
      });
    } catch (e) {
      logger.warn('pair', '监听接收确认请求失败', e);
    }
    // Java 原生层日志探针 → 前端 logger（NativeLogBridge 读 logcat 统一桥接，全部 Java 模块进入导出日志）
    const handleJavaLog = (l: { level: string; module: string; msg: string }) => {
      const msg = `[native:${l.module}] ${l.msg}`;
      if (l.level === 'error') logger.error('native', msg);
      else if (l.level === 'warn') logger.warn('native', msg);
      else logger.debug('native', msg);
    };
    try {
      unlistenJavaLogMobile = await onJavaLog(handleJavaLog);
      // 冷启动窗口（WebView 就绪前）桥接器发出的日志前端收不到，注册监听后回放环形缓冲补齐
      dumpNativeLogs().then((logs) => logs.forEach(handleJavaLog)).catch(() => {});
    } catch (e) {
      logger.warn('pair', '监听原生日志探针失败', e);
    }
    // 接收进度（电脑→手机）：累计字节 / 总字节，前端实时显示总量/速率/剩余
    try {
      unlistenRecvMobile = await onReceiveProgress((p) => {
        recvProgress.value = p;
      });
    } catch (e) {
      logger.warn('pair', '监听接收进度失败', e);
    }
    // 后台自动连接：无论本地是否已有配对记录都启动巡检
    // （空记录时也会合并对方记录本机的信任信息，消除信息差）
    startAutoConnect();
    // 断网自动重连 + 暂停任务自动恢复（有暂停任务且对端恢复可达时自动续传）
    autoResume.start();
  } catch (e) {
    logger.error('init', '初始化失败', e);
    errorMsg.value = `初始化失败: ${(e as Error).message}`;
  }
});

onUnmounted(() => {
  mm?.revert();
  window.removeEventListener('keydown', onGlobalEsc);
  autoResume.stop();
  if (scanTimer) clearInterval(scanTimer);
  if (pingTimer) clearInterval(pingTimer);
  if (mergeTimer) clearInterval(mergeTimer);
  if (trustTimer) clearInterval(trustTimer);
  if (nameSaveTimer) clearTimeout(nameSaveTimer);
  document.removeEventListener('visibilitychange', onVisibilityChange);
  if (unlistenPairMobile) unlistenPairMobile();
  if (unlistenPeerMobile) unlistenPeerMobile();
  if (unlistenDisconnectMobile) unlistenDisconnectMobile();
  if (unlistenPresenceMobile) unlistenPresenceMobile();
  if (unlistenUnpairMobile) unlistenUnpairMobile();
  if (unlistenFileRecvMobile) unlistenFileRecvMobile();
  if (unlistenFileReceiptMobile) unlistenFileReceiptMobile();
  if (unlistenReceiveComplete) unlistenReceiveComplete();
  if (unlistenIncomingMobile) unlistenIncomingMobile();
  if (unlistenJavaLogMobile) unlistenJavaLogMobile();
  if (unlistenPairingMobile) unlistenPairingMobile();
  if (unlistenRecvMobile) unlistenRecvMobile();
  if (unsubLog) unsubLog();
});

// ---------- 配对模式（广播自己，供对方发现） ----------
async function startDeviceScanFn() {
  if (scanRunning.value) return;
  try {
    await startScan({ port: 53317, selfCode: selfCode.value, announce: true });
    scanRunning.value = true;
    discovered.value = [];
    scanRounds.value = 0;
    scanElapsedSec.value = 0;
    scanStartedAt = Date.now();
    scanTimer = setInterval(async () => {
      scanRounds.value++;
      scanElapsedSec.value = Math.round((Date.now() - scanStartedAt) / 1000);
      try {
        const list = await getScanResults();
        discovered.value = list;
        // 已配对设备再次被发现 → 只记忆新 IP，不置在线：在线状态必须由 verify 探测确认，
        // 扫描到 ≠ 建立通信（否则隐藏设备会被误标在线）
        for (const d of list) {
          const rec = pairMgr.byDeviceId(d.fingerprint);
          if (rec) {
            pairMgr.rememberIp(rec.fingerprint, d.ip);
          }
        }
        refreshPairings();
      } catch (e) {
        logger.error('receiver', '获取扫描结果失败', e);
      }
    }, 1500);
  } catch (e) {
    errorMsg.value = `启动扫描失败: ${(e as Error).message}`;
  }
}

async function stopDeviceScanFn() {
  scanRunning.value = false;
  scanRounds.value = 0;
  scanElapsedSec.value = 0;
  discovered.value = []; // 停止配对后已搜索到的设备消失（此时无法再配对）
  if (scanTimer) clearInterval(scanTimer);
  try {
    await stopScan();
  } catch (e) {
    logger.error('receiver', '停止扫描失败', e);
  }
}

// 点击发现列表中的设备：已配对 → 提示；未配对 → 弹出连接码输入
function onDiscoveredClick(d: ScannedDevice) {
  if (pairMgr.byDeviceId(d.fingerprint)) {
    notice.value = `「${d.alias}」已配对，无需重新验证`;
    return;
  }
  pairingTarget.value = d;
  codeInput.value = '';
}

// 确认配对（v3 客户端已补全：本机输入对端连接码主动发起；对端将弹出确认窗口）
async function confirmPair() {
  const t = pairingTarget.value;
  if (!t) return;
  if (!codeInput.value.trim()) {
    errorMsg.value = '请输入对方屏幕上显示的连接码';
    return;
  }
  verifying.value = true;
  errorMsg.value = '';
  try {
    const r = await pairClientV3({ ip: t.ip, port: t.port, code: codeInput.value.trim(), name: deviceInfo.value.name || '手机' });
    if (r.status !== 'approved') {
      errorMsg.value = r.message || '配对失败';
      return;
    }
    pairingTarget.value = null;
    codeInput.value = '';
    notice.value = `配对成功：${t.alias}`;
    logger.info('pair', `v3 主动配对成功 alias=${t.alias} ip=${t.ip}`);
    refreshPairings();
    mergePeers();
  } catch (e) {
    logger.error('pair', 'v3 主动配对失败', e);
    errorMsg.value = `配对失败: ${(e as Error).message}`;
  } finally {
    verifying.value = false;
  }
}

function cancelPair() {
  pairingTarget.value = null;
  codeInput.value = '';
}

// 手动配对（v3 客户端已补全：IP + 对端连接码主动发起）
async function manualPair() {
  if (!manualIp.value.trim() || !manualCode.value.trim()) {
    errorMsg.value = '请填写目标 IP 与连接码';
    return;
  }
  verifying.value = true;
  errorMsg.value = '';
  try {
    const r = await pairClientV3({ ip: manualIp.value.trim(), port: manualPort.value, code: manualCode.value.trim(), name: deviceInfo.value.name || '手机' });
    if (r.status !== 'approved') {
      errorMsg.value = r.message || '配对失败';
      return;
    }
    notice.value = `配对成功：${r.alias || manualIp.value.trim()}`;
    logger.info('pair', `v3 手动配对成功 ip=${manualIp.value.trim()}`);
    refreshPairings();
    mergePeers();
  } catch (e) {
    logger.error('pair', 'v3 手动配对失败', e);
    errorMsg.value = `配对失败: ${(e as Error).message}`;
  } finally {
    verifying.value = false;
  }
}

// 解除配对（双端：通知对方删除信任，防单向残留）
async function removePairing(fp: string) {
  const rec = pairMgr.byFingerprint(fp);
  if (rec) {
    // 解除通知重试 3 次：对方短暂不可达也能收到，强制其同步解除（白名单双向生效）
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await sendUnpair({ ip: rec.ip, port: rec.port, deviceId: deviceInfo.value.deviceId });
        break;
      } catch (e) {
        if (attempt < 2) await new Promise((r) => setTimeout(r, 1000));
        else logger.warn('pair', '解除配对通知失败（对方可能离线）', e);
      }
    }
  }
  pairMgr.remove(fp);
  rejectCount.delete(fp);
  connectNoticeAt.delete(fp);
  refreshPairings();
  if (targetDevice.value?.fingerprint === fp) {
    targetDevice.value = pairings.value[0] ?? null;
  }
  // 同步清空原生信任表：否则 mergePeers 会从原生把已解除设备拉回，造成状态反复跳动
  await confirmAllPairs();
  notice.value = '已解除配对';
}

// ---------- 后台自动连接（配对与连接分离） ----------
// 启动时：不广播配对，仅监听/探测找到已配对设备；
// 状态侦测 2 次/秒（只探测可达性），信任同步 10 秒一次。
let autoConnecting = false;
// 误删防抖已移除：配对记录只在显式解除/收到对端解除时删除，绝不因轮询失败自动删除
const rejectCount = new Map<string, number>();
// 失败退避：完全不可达设备降频探测（每 10 轮 ≈5s 一次），成功即恢复 500ms
const probeSkip = new Map<string, number>();

async function startAutoConnect() {
  if (autoConnecting) return;
  autoConnecting = true;
  // 本端确认的配对回填原生 pairedPeers（对端问候校验依据；重启后自愈）
  await confirmAllPairs();
  // 注意：此处不调 startScan——自动连接只需对「已配对设备」做问候巡检（greetAll）
  // 和双端信任同步（mergePeers），不需要发现新设备。曾在此启动扫描，导致：
  // ① app 一启动就占用 UDP 53317 组播 socket，用户手动扫描时 bind 连环 already bound；
  // ② discoverable 被常驻置 true——手机未开任何服务也能被对端 probe 发现（在线状态泄露）。
  greetAll();
  if (pingTimer) clearInterval(pingTimer);
  pingTimer = setInterval(greetAll, 500); // 状态侦测：2 次/秒，无感感知上下线
  if (mergeTimer) clearInterval(mergeTimer);
  mergeTimer = setInterval(async () => {
    await mergePeers();
  }, 10000); // 双端信任同步：10 秒一次足够
  // v5 信任巡检（补全 greetAll 缺口）：v3 probe 只有可达性语义，无法感知
  // "对方已解除配对"。每 30s 一轮 sync-status，revoked/unknown 经
  // pair-unpaired 事件自动删除本机记录（状态机最终一致，§5.3 弱最终一致）。
  if (trustTimer) clearInterval(trustTimer);
  trustTimer = setInterval(() => {
    syncAllPeersV3().catch(() => {});
  }, 30000);
  // 后台降级省电：切后台状态侦测降至 5s，回前台恢复 500ms
  document.addEventListener('visibilitychange', onVisibilityChange);
}

// 后台/前台切换：调整状态侦测频率（省电）
function onVisibilityChange() {
  if (pingTimer) clearInterval(pingTimer);
  pingTimer = setInterval(greetAll, document.hidden ? 5000 : 500);
}

// 把本地配对记录全量同步到原生（清空后重建，杜绝解除残留导致的横跳）
async function confirmAllPairs() {
  const peers = pairMgr.all().map((rec) => ({
    deviceId: rec.deviceId,
    name: rec.name,
    ip: rec.ip,
    port: rec.port,
    fingerprint: rec.fingerprint,
  }));
  try {
    await setPairedPeers(peers);
  } catch (e) {
    logger.warn('pair', '同步配对记录到原生失败', e);
  }
}

async function mergePeers() {
  // 双端配对同步：合并对方记录本机的信任信息（消除"一端有已配对、另一端没有"）
  try {
    const peers = await getPairedPeers();
    let added = 0;
    for (const p of peers) {
      const existing = pairMgr.byDeviceId(p.deviceId);
      // v3 配对记录无连接码概念（fingerprint 为空串）：此前直接 continue 导致
      // 配对成功的设备永远不进"我的设备"列表。用 deviceId 派生本地指纹兜底。
      const fp = p.fingerprint || existing?.fingerprint || `v3-${(p.deviceId || '').slice(0, 8)}`;
      if (fp === 'v3-' && !existing) continue; // deviceId 也缺失：无法登记，跳过
      if (!existing) added++;
      pairMgr.upsert({
        fingerprint: fp,
        deviceId: p.deviceId,
        name: p.name,
        ip: p.ip,
        port: p.port,
        trustAt: existing?.trustAt ?? Date.now(),
        online: existing?.online ?? false,
        lastSeen: existing?.lastSeen ?? Date.now(),
      });
    }
    refreshPairings();
    if (added > 0) {
      notice.value = `检测到 ${added} 台设备已与本机配对`;
    }
    // 合并到新对端后回填原生，确保对端问候校验通过
    confirmAllPairs();
  } catch (e) {
    logger.warn('pair', '合并双端配对记录失败', e);
  }
}

// 状态侦测（2 次/秒）：probe 只查对方是否信任本机，不触发"已连接"；
// - 可达且互信 → 在线（状态3）
// - 可达但不信任（对方已解除/从未配对）→ 连续 5 次（约 10 秒）后删除记录（状态1，单向残留自愈）
// - 完全不可达 → 离线（状态2，保留记录）
/* in-flight 守卫：慢探测时轮询不叠发，避免多轮状态互相覆盖 */
let greetInFlight = false;
async function greetAll(force = false) {
  if (!force && greetInFlight) return;
  greetInFlight = true;
  try {
    const recs = pairMgr.all();
    await Promise.all(
    recs.map(async (rec) => {
      // 退避：不可达设备跳过本轮探测（保持上次离线状态），每 10 轮 ≈5s 再探一次
      const skip = probeSkip.get(rec.fingerprint) || 0;
      if (skip > 0) {
        probeSkip.set(rec.fingerprint, skip - 1);
        return;
      }
      const ips = rec.ips?.length ? rec.ips : [rec.ip];
      let ok = false;
      for (const ip of ips) {
        try {
          // P2 硬升级：v2 信任探测（probeDevice）已删除，改 v3 probe 探测对端配对服务可达。
          // v3 probe 无「信任校验」语义（v2 ok=false 用于检测对方已解除配对），该能力暂缺
          await v3Probe({ ip, port: rec.port });
          pairMgr.markOnline(rec.fingerprint, ip, rec.port);
          pairMgr.rememberIp(rec.fingerprint, ip);
          rejectCount.delete(rec.fingerprint);
          probeSkip.delete(rec.fingerprint);
          ok = true;
          break;
        } catch {
          // 该 IP 不可达，尝试下一个
        }
      }
      if (!ok) {
        // 完全不可达 → 离线（状态2：记录永久保留）+ 降频（5s 后再探）
        pairMgr.markOffline(rec.fingerprint);
        probeSkip.set(rec.fingerprint, 9);
      }
    }),
  );
  refreshPairings();
  } finally {
    greetInFlight = false;
  }
}

// 连接（显式）：v3 probe 探测对端可达 + 校验对端 deviceId 与目标一致后置为已连接。
// P2 硬升级后：v3Probe 返回对端公开 deviceId，必须与配对记录中的 deviceId 一致才算"同一台已授权设备"。
// 若对端 deviceId 缺失/与目标不符（IP 复用/清除数据重建身份/未配对伪造响应），拒绝置位"已连接"，
// 避免单方面握手分裂。守卫为严格匹配：deviceId 缺失一律按失败处理，不跳过校验。
async function connectPeer(p: PairRecord) {
  const ips = p.ips?.length ? p.ips : [p.ip];
  let ok = false;
  // 守卫：目标记录必须存在 deviceId（否则本机无可信身份可校验）；若 bcpd 已通过
  // HMAC 确认该设备在线，则跳过 deviceId 比对（bcpd 验证 > 明文 ID 匹配）。
  if (!p.deviceId) {
    logger.warn('ui', `连接守卫：配对记录缺少 deviceId，拒绝握手确认 peer=${p.name}`);
    pairMgr.markOffline(p.fingerprint);
    errorMsg.value = `连接失败：${p.name}（配对记录缺少设备身份）`;
    return;
  }
  const trustedByBcpd = bcpdConfirmedOnline.has(p.fingerprint);
  for (const ip of ips) {
    try {
      const info = await v3Probe({ ip, port: p.port });
      if (trustedByBcpd) {
        // bcpd HMAC 已验证对端持有共享 secret，跳过 deviceId 比对，直接信任
        pairMgr.markOnline(p.fingerprint, ip, p.port);
        pairMgr.rememberIp(p.fingerprint, ip);
        pairMgr.markConnected(p.fingerprint, true);
        ok = true;
        break;
      }
      // 守卫（严格）：无 bcpd 信任背书时，必须明文 deviceId 匹配才放行
      if (!info.deviceId || info.deviceId !== p.deviceId) {
        logger.warn(
          'ui',
          `连接守卫：对端 deviceId 缺失或不符（IP=${ip}，got=${info.deviceId || '(空)'}），拒绝握手确认`,
        );
        continue; // 尝试下一 IP；全部不符则下方进入"连接失败"
      }
      pairMgr.markOnline(p.fingerprint, ip, p.port);
      pairMgr.rememberIp(p.fingerprint, ip);
      pairMgr.markConnected(p.fingerprint, true);
      ok = true;
      break;
    } catch {
      // 尝试下一个 IP
    }
  }
  refreshPairings();
  if (ok) {
    notice.value = `已连接：${p.name}`;
  } else {
    pairMgr.markOffline(p.fingerprint);
    errorMsg.value = `连接失败：${p.name}（对方不在线、未配对或设备身份不匹配）`;
  }
}

// 断开（显式）：本地清除已连接状态 + 通知对方同步清除（双方回到"在线"）
async function disconnectPeer(p: PairRecord) {
  pairMgr.markConnected(p.fingerprint, false);
  try {
    await sendDisconnect({ ip: p.ip, port: p.port, deviceId: deviceInfo.value.deviceId });
  } catch {
    // 对方可能离线；本地已断开
  }
  refreshPairings();
  notice.value = `已断开与「${p.name}」的连接`;
}

// 断开 / 解除：二级确认弹窗
function confirmUnpair(fp: string) {
  const rec = pairMgr.byFingerprint(fp);
  askConfirm({
    title: '解除配对',
    message: `解除后「${rec?.name || '该设备'}」将失去信任关系，需要重新配对才能再次连接。`,
    danger: true,
    action: () => removePairing(fp),
  });
}

function confirmDisconnect(fp: string) {
  const rec = pairMgr.byFingerprint(fp);
  askConfirm({
    title: '断开连接',
    message: `断开与「${rec?.name || '该设备'}」的连接？之后可随时重新连接。`,
    action: () => {
      if (rec) disconnectPeer(rec);
    },
  });
}

// 接收确认弹窗响应：接受/拒绝（解除原生 prepare-upload 阻塞等待）
async function acceptIncoming(accept: boolean) {
  const r = incomingReq.value;
  if (!r) return;
  incomingReq.value = null;
  try {
    await resolveIncoming(r.sessionId, accept);
    notice.value = accept ? `已同意接收 ${r.count} 个文件` : '已拒绝接收';
  } catch (e) {
    errorMsg.value = `响应接收确认失败: ${(e as Error).message}`;
  }
}

/** Esc 关闭顶层弹窗：收件/配对请求 = 拒绝，确认弹窗 = 取消（不触发任何破坏性动作） */
function onGlobalEsc(e: KeyboardEvent) {
  if (e.key !== 'Escape') return;
  if (incomingReq.value) acceptIncoming(false);
  else if (pairingReq.value) acceptPairing(false);
  else if (confirmAsk.value) cancelConfirm();
}

/** 手动连接端口校验：失焦钳制到 1-65535（空/非法回默认 53317） */
function clampManualPort() {
  const n = Math.floor(Number(manualPort.value) || 0);
  manualPort.value = n >= 1 && n <= 65535 ? n : 53317;
}

// 配对确认弹窗响应：同意/拒绝（解除原生 verifyCode 阻塞等待）
async function acceptPairing(accept: boolean) {
  const r = pairingReq.value;
  if (!r) return;
  pairingReq.value = null;
  try {
    await resolvePairing(r.deviceId, accept);
    notice.value = accept ? `已同意与「${r.name}」配对` : `已拒绝与「${r.name}」配对`;
    // 问题3：同意连接后停止扫描与广播（双方已配对，不再需要被发现/继续扫描）
    if (accept) await stopDeviceScanFn();
  } catch (e) {
    errorMsg.value = `响应配对确认失败: ${(e as Error).message}`;
  }
}

/** 防御性总开关：切换本机完全隐藏/可见。隐藏=不发送加密存在、探针不泄露身份，
 *  已配对设备同样无法发现本机（仅保留本机主动外连）。与桌面端 set_defensive 对称。 */
async function setDefensive(hidden: boolean) {
  defensiveHidden.value = hidden;
  try {
    await setDefensiveHidden(hidden);
    notice.value = hidden ? '本机已在局域网完全隐藏' : '本机已设为可见模式';
  } catch (e) {
    logger.error('pair', '切换防御开关失败', e);
    defensiveHidden.value = !hidden;
  }
}

// ---------- 备份目录盒子 ----------
function persistBox(key: string, box: BackupRoot | null) {
  try {
    if (box) localStorage.setItem(key, JSON.stringify(box));
    else localStorage.removeItem(key);
  } catch {
    // 忽略
  }
}

async function pickBoxP2c() {
  try {
    const root = await pickBackupRoot();
    if (!root) return;
    boxP2c.value = root;
    persistBox('lanbackup_box_p2c', root);
    if (root.persisted === false) {
      notice.value = `${root.name} 已选择，但授权未能持久化：重启后需重新选择此目录`;
    } else {
      notice.value = `手机→电脑 源目录：${root.name}`;
    }
    // 通知目标设备（电脑）本机源目录名
    const t = targetDevice.value;
    if (t) {
      try {
        await sendSyncDir({ ip: t.ip, port: t.port, direction: 'phone-to-pc', name: root.name });
        logger.info('pair', `已同步源目录名到 ${t.name}`);
      } catch (e) {
        logger.warn('pair', '同步目录名失败（目标可能离线）', e);
      }
    }
  } catch (e) {
    errorMsg.value = `选择目录失败: ${(e as Error).message}`;
  }
}

async function pickBoxC2p() {
  try {
    const root = await pickBackupRoot();
    if (!root) return;
    boxC2p.value = root;
    persistBox('lanbackup_box_c2p', root);
    if (root.persisted === false) {
      notice.value = `${root.name} 已选择，但授权未能持久化：重启后需重新选择此目录`;
    } else {
      notice.value = `电脑→手机 接收目录：${root.name}`;
    }
    receiverEnabled.value = true; // 选择接收目录即启用接收端
    persistConfig();
    // 选择/切换接收目录后立即重启常驻接收服务
    if (boxC2p.value) {
      await startReceiverSafe(boxC2p.value);
      if (serverRunning.value) {
        notice.value = `${root.name} 已就绪，接收服务运行中（端口 ${serverPort.value}）。电脑端可直接开始同步。`;
      }
    }
  } catch (e) {
    errorMsg.value = `选择目录失败: ${(e as Error).message}`;
  }
}

// 选择同步对象
function selectTarget(p: PairRecord) {
  targetDevice.value = { ...p };
  // 加载该设备的对端缺失列表；注意：不再用设备历史策略覆盖当前 UI 选择（BUG-9）。
  // 否则用户选了「增量(archive)」后，选设备/重连会静默切回该设备历史存的「镜像(mirror)」，
  // 导致"增量模式仍弹镜像确认"。同步策略一律以 UI 当前选择为准。
  if (state.value) {
    const device = getOrCreateDevice(state.value, p.fingerprint, p.name);
    void device; // 仅确保设备记录存在（用于对端缺失列表）
  }
}

// ---------- 执行备份 ----------
// ---------- 开始同步按钮：模式感知（点击 / 长按1.7s 白光填满后触发） ----------
/** 长按1.7s完成后的动作（进入对应状态）：只收→切换自动接收；只发/双向→发件 */
function longPressSyncAction() {
  if (role.value === 'receiver') toggleAutoAcceptReceive();
  else runBackup();
}
/** 点击（短按）动作：只发→立即发件；只收/双向→切换自动接收 */
function clickSyncAction() {
  if (role.value === 'sender') runBackup();
  else toggleAutoAcceptReceive();
}
const longPressActive = ref(false);
let longPressTimer: ReturnType<typeof setTimeout> | null = null;
function onSyncPressStart() {
  if (scanning.value) return;
  longPressActive.value = true;
  longPressTimer = setTimeout(() => {
    longPressTimer = null;
    longPressActive.value = false;
    longPressSyncAction();
  }, 1700);
}
function onSyncPressEnd() {
  const triggered = !longPressTimer; // 定时器已触发=长按完成，动作已执行
  if (longPressTimer) { clearTimeout(longPressTimer); longPressTimer = null; }
  longPressActive.value = false;
  // 短按：仅双向=切换自动接收；单向无动作
  if (!triggered && role.value === 'free') clickSyncAction();
}
function onSyncPressCancel() {
  if (longPressTimer) { clearTimeout(longPressTimer); longPressTimer = null; }
  longPressActive.value = false;
}

async function runBackup() {
  if (scanning.value) return;
  const t = targetDevice.value;
  if (!t) {
    errorMsg.value = '请先在「设备」页完成连接，并在「同步」页选择目标设备';
    return;
  }
  const hasSend = effectiveSendFolders.value.length > 0;
  const hasRecv = receiverEnabled.value && !!boxC2p.value;
  if (!hasRecv && !hasSend) {
    errorMsg.value = '请至少配置一个备份方向（接收目录或发送文件夹）';
    return;
  }
  errorMsg.value = '';
  notice.value = '';
  // 镜像模式确认（P0 披露）改为运行时：sendBackup 规划出对端多余文件时按真实数量弹确认
  // （0 个多余文件不打扰）；取消则跳过清理，传输正常完成
  scanning.value = true;
  progress.value = null;
  // 任务化：创建同步任务（断网时标记暂停，恢复时重新执行并跳过已完成文件；
  // 记录对端连接目标，供断网自动重连与恢复按钮定向）
  const task = createTask({
    direction: 'send',
    peer: t.name,
    peerIp: t.ip,
    peerPort: t.port,
    peerFingerprint: t.fingerprint,
    fileCount: 0,
    totalBytes: 0,
  });
  activeTaskId.value = task.id;
  try {
    logger.info('ui', `开始同步: 对象=${t.name}(${t.ip}:${t.port}) 接收=${hasRecv ? boxC2p.value?.name : '无'} 源=${senderFolders.value.filter((f) => f.enabled).map((f) => f.name).join(',') || '无'}`);
    // 接收方向：电脑可推送文件到本机（选目录时已启动；此处兜底）
    if (hasRecv && !serverRunning.value) {
      await startReceiverSafe(boxC2p.value!);
    }
    // 发送方向：把手机目录推送到电脑（三路对比增量，只传新增/变更/对端缺失）
    if (hasSend) {
      const enabled = effectiveSendFolders.value;
      for (const folder of enabled) {
        // 构造 BackupRoot 对象
        const root: BackupRoot = { uri: folder.path, name: folder.name, persisted: true };
        const device = getOrCreateDevice(state.value!, t.fingerprint, t.name);
        device.syncStrategy = syncStrategy.value;
        // [镜像守卫诊断] 记录 mode 来源：UI 当前值 vs 设备历史值，定位"增量却弹镜像"
        // 是否因设备历史 syncStrategy 覆盖 UI，或历史残留 mirror
        logger.info(
          'ui',
          `策略来源: UI=${syncStrategy.value} 设备历史=${device.syncStrategy} ` +
            `对象=${t.name}(${t.fingerprint})`,
        );
        const r = await sendBackup(
          root,
          device.lastManifest,
          device.syncStrategy,
          deviceInfo.value.deviceId,
          deviceInfo.value.name,
          t.ip,
          t.port,
          t.fingerprint,
          device.knownMissingOnPeer,
          (p) => (progress.value = p),
          // 镜像运行时确认：展示真实多余文件数；取消则保留对端多余文件。
          // 防重放：无论确认还是取消，5 分钟内不再打扰（自动重试循环曾因"仅确认才记录"每轮重弹）
          async (count) => {
            const cnt = Array.isArray(count) ? count.length : Number(count) || 0;
            const last = mirrorAskedAt.get(t.fingerprint) || 0;
            if (Date.now() - last < 5 * 60 * 1000) return true; // 本周期已询问过，不再打扰
            const ok = await askConfirmAsync({
              title: '镜像模式确认',
              message: `镜像模式会把「${t.name}」上 ${cnt} 个多余文件移入其 delete 文件夹，确认继续？`,
              danger: true,
            });
            mirrorAskedAt.set(t.fingerprint, Date.now()); // 确认/取消都记录，防重弹
            persistMirrorAskedAt(); // 持久化，重启后仍防重弹（BUG-9 复盘）
            return ok;
          },
          // 手机唤醒电脑成功后，立即更新本地连接状态（修复"PC已显示已连接但手机不显示"的单向握手问题）
          (fp) => {
            const rec = pairMgr.byFingerprint(fp);
            if (rec) {
              pairMgr.markOnline(rec.fingerprint, t.ip, t.port);
              pairMgr.markConnected(rec.fingerprint, true);
            }
          },
        );
        device.knownMissingOnPeer = r.knownMissingOnPeer;
        await completeBackup(state.value!, t.fingerprint, r.manifest);
        pushTransfer('out', t.name, r.sent, r.bytes, Math.round(r.durationMs));
        progressDone.value = { direction: 'out', count: r.sent, bytes: r.bytes, durationMs: Math.round(r.durationMs) };
        notice.value =
          `已推送 ${r.sent} 个文件到电脑（${t.name}` +
          (r.bytes > 0 ? `，${fmtBytes(r.bytes)}，${(r.durationMs / 1000).toFixed(1)} 秒` : '') +
          `）` +
          (serverRunning.value ? `；接收服务运行中（端口 ${serverPort.value}）` : '');
      }
      // 防御：任务最终统计以 sendBackup 返回值为准并显式回填后标记完成。
      // 自动恢复/跳过已完成文件时，progress 事件可能未触发，曾出现
      // "任务显示同步中 0%/0 文件，但历史记录完整"（BUG-9）——此处兜底修正。
      updateTask(task.id, {
        sentCount: r.sent,
        fileCount: r.sent,
        bytes: r.bytes,
        totalBytes: r.bytes,
      });
      completeTask(task.id);
      activeTaskId.value = '';
    }
  } catch (e) {
    // 网络类错误 → 暂停任务（断网自动重连 + 恢复按钮可续传）；其他错误 → 失败（重试按钮）
    activeTaskId.value = '';
    logger.error('ui', '备份执行失败', e);
    const msg = (e as Error).message || String(e);
    if (/prepare-upload|register|error sending request|Failed to fetch|network|streamUpload/i.test(msg)) {
      pauseTask(task.id, msg);
      errorMsg.value = `同步失败（${msg}）。请确认目标设备（电脑）已选择接收目录并启动接收服务。`;
    } else {
      failTask(task.id, msg);
      errorMsg.value = `同步失败：${msg}`;
    }
  } finally {
    scanning.value = false;
  }
}

async function onStopReceiver() {
  try {
    await stopReceiver();
    serverRunning.value = false;
    notice.value = '收件服务已停止';
  } catch (e) {
    errorMsg.value = `停止接收服务失败: ${(e as Error).message}`;
  }
}

/** 手动取消收件：分两步——①本地停止接收服务（无条件先行，与对端无关）；②通知对端取消会话。
 *  通知对端（电脑）的 handle_cancel 会 cancel 发送 token → 强制停止其发送。
 *  本地停止与通知为两个独立职责，通知失败不影响本地停止；错误提示按两者成败组合，避免误导。 */
async function cancelReceive() {
  const src = currentRecvSource.value;

  // Step 1：本地停止接收服务（无条件执行，捕获自己是否成功，不因通知失败而跳)
  let localStopped = true;
  if (serverRunning.value) {
    try {
      await stopReceiver();
      serverRunning.value = false;
    } catch (e) {
      localStopped = false;
      errorMsg.value = `停止本机接收服务失败: ${(e as Error).message}`;
    }
  }

  // Step 2：通知对端取消（独立于本地停止；失败只影响"对端是否停"提示，不阻塞）
  let notified = false;
  if (src) {
    try {
      await cancelSessionNative({ targetIp: src.ip, targetPort: src.port, sessionId: src.sessionId });
      notified = true;
    } catch {
      notified = false;
    }
  }

  currentRecvSource.value = null;
  recvProgress.value = null;

  // 组合提示：本地停止与对端通知各自的成败
  if (src) {
    if (localStopped && notified) {
      notice.value = `已取消收件，并已通知「${src.ip}」停止传输`;
    } else if (localStopped && !notified) {
      // 本地已停，但对端未知 → 用 errorMsg 明确"对端可能仍在发送"
      errorMsg.value = `已停止本机接收，但未能通知对端取消（对端可能离线或未识别）——对端可能仍在继续发送，请在对端手动停止`;
    } else if (!localStopped && notified) {
      errorMsg.value = `未能完全停止本机接收服务（已通知「${src.ip}」停止）——请在设置中确认接收服务已关闭`;
    } else {
      errorMsg.value = `停止本机接收服务失败，且未能通知对端「${src.ip}」取消——请手动检查两端状态`;
    }
  } else if (!localStopped) {
    errorMsg.value = `停止本机接收服务失败，请手动确认`;
  } else {
    notice.value = '已取消收件';
  }
}

// ---------- 设置 ----------
// 设备名：输入后自动保存（去抖 800ms），失焦立即保存；清空则回退当前名
watch(deviceNameInput, (v) => {
  const name = v.trim();
  if (!name || name === deviceInfo.value.name) return;
  if (nameSaveTimer) clearTimeout(nameSaveTimer);
  nameSaveTimer = setTimeout(() => saveDeviceName(name), 800);
});

function flushDeviceName() {
  if (nameSaveTimer) clearTimeout(nameSaveTimer);
  const name = deviceNameInput.value.trim();
  if (!name) {
    deviceNameInput.value = deviceInfo.value.name;
    return;
  }
  if (name !== deviceInfo.value.name) saveDeviceName(name);
}

async function saveDeviceName(name: string) {
  try {
    await setDeviceName(name);
    deviceInfo.value.name = name;
    notice.value = `设备名已更新：${name}`;
    logger.info('device', `设备名更新为 ${name}`);
  } catch (e) {
    errorMsg.value = `保存设备名失败: ${(e as Error).message}`;
  }
}

// 刷新设备码：二级确认弹窗（防误触使全部配对失效）
function refreshSelfCode2() {
  askConfirm({
    title: '重置连接码',
    message: '重置后旧码立即失效，已配对设备需重新连接。',
    danger: true,
    action: refreshSelfCode,
  });
}

// 刷新设备码：随机生成并持久化，旧码立即失效（对方需重新配对）
async function refreshSelfCode() {
  try {
    const code = await refreshCode();
    selfCode.value = code;
    notice.value = `连接码已刷新：${code}。旧码已失效，已配对设备需重新连接。`;
    logger.info('device', '本机设备码已刷新');
  } catch (e) {
    errorMsg.value = `重置连接码失败: ${(e as Error).message}`;
  }
}

// 扫描模式已移除：增量同步自动对比两端清单（见 shared-core sync.ts）

// 清空日志缓冲与统计（二级确认弹窗）
function clearLogs() {
  askConfirm({
    title: '清空日志',
    message: `将清空全部 ${logger.size()} 条日志与统计。`,
    danger: true,
    action: () => {
      logger.clear();
      debugSummary.value = logger.summary();
      notice.value = '日志已清空';
    },
  });
}

// 日志预览：可滚动、可复制
function openLogPreview() {
  logPreviewText.value = logger.export();
  showLogPreview.value = true;
}

async function copyLogPreview() {
  try {
    await navigator.clipboard.writeText(logPreviewText.value);
    notice.value = '日志已复制到剪贴板';
  } catch {
    // 降级：隐藏 textarea + execCommand
    try {
      const ta = document.createElement('textarea');
      ta.value = logPreviewText.value;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      notice.value = '日志已复制到剪贴板';
    } catch {
      errorMsg.value = '复制失败，请手动选择复制';
    }
  }
}

// 导出日志：Documents → SAF 备份目录 → 沙盒
async function exportLogs() {
  const content = logger.export();
  const name = logFileName();
  logger.info('debug', `导出日志: ${name}, ${logger.size()} 条`);
  try {
    try {
      await Filesystem.mkdir({ path: 'BackupLogs', directory: Directory.Documents, recursive: true });
    } catch {
      // 已存在
    }
    await Filesystem.writeFile({
      path: `BackupLogs/${name}`,
      data: content,
      directory: Directory.Documents,
      encoding: Encoding.UTF8,
    });
    notice.value = `日志已导出到：文档/BackupLogs/${name}`;
    return;
  } catch (e) {
    logger.warn('debug', '写入 文档/BackupLogs 失败，尝试 SAF 目录', e);
  }
  if (boxP2c.value || boxC2p.value) {
    try {
      const uri = (boxP2c.value ?? boxC2p.value)!.uri;
      await writeFileContent(uri, `BackupLogs/${name}`, content);
      notice.value = `日志已导出到备份目录：BackupLogs/${name}`;
      return;
    } catch (e) {
      logger.warn('debug', '写入 SAF 备份目录失败，尝试沙盒', e);
    }
  }
  try {
    await Filesystem.writeFile({
      path: name,
      data: content,
      directory: Directory.Data,
      encoding: Encoding.UTF8,
    });
    notice.value = `日志已导出到应用沙盒（需 adb 查看）：${name}`;
  } catch (e) {
    logger.error('debug', '导出日志最终失败', e);
    errorMsg.value = `导出日志失败: ${(e as Error).message}`;
  }
}
</script>

<template>
  <!--
    DIRECTION CONTRACT — Glass Command Deck（玻璃总览台）
    THESIS: 首屏状态总览优先，拒绝配置堆积；一屏回答「角色 / 收件服务 / 目标设备」三问。
    OWN-WORLD: 液态玻璃材质 + 翡翠青强调色；玻璃卡、状态格、分段角色选择、底部 tab 居中窄栏。
    STORY: 打开即见本机状态 → 切换角色 → 配置收件/发件 → 立即同步 → 实时进度。
    FIRST VIEWPORT: 大状态卡（角色分段 + 三状态格 + 上次同步摘要），下方收件区/发件区，底部导航。
    FORM: grounded 方向 5（玻璃框架内），seed key bdc30699。
    FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, and DESIGN.md
  -->
  <!-- 壁纸放在 app-shell 内用绝对定位叠在内容底下（不依赖负 z-index，Android 兼容） -->
  <GlassFilters />

  <!-- 自绘悬浮滚动条（主页面已隐藏原生滚动条） -->
  <GlassScrollbar />

  <div class="app-shell">
    <video class="wallpaper-video" src="/wallpaper.webm" autoplay muted loop playsinline></video>
    <div class="glow-blob glow-blob-1"></div>
    <div class="glow-blob glow-blob-2"></div>
    <!-- 顶部 -->
    <header class="app-header">
      <div class="header-row">
        <h1>局域网备份</h1>
        <button class="theme-btn" :title="darkMode ? '切换到浅色' : '切换到深色'" :aria-label="darkMode ? '切换到浅色' : '切换到深色'" @click="darkMode = !darkMode">{{ darkMode ? '🌙' : '☀️' }}</button>
      </div>
      <div class="header-code">
        <button class="code-copy" title="点击复制连接码" aria-label="点击复制连接码" @click="copyText(selfCode, '连接码已复制')">
          连接码：<strong>{{ selfCode }}</strong>
        </button>
        <button class="mini-btn" title="重置连接码" aria-label="重置连接码" @click="refreshSelfCode2">
          <svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><path d="M13.5 8a5.5 5.5 0 1 1-1.62-3.9" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M12.3 1.6v2.9H9.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </button>
        <span class="header-name">{{ deviceInfo.name || '本机' }}</span>
      </div>
    </header>

    <!-- 消息队列：多条提示堆叠显示，互不遮挡 -->
    <div class="toast-stack" role="status" aria-live="polite">
      <TransitionGroup name="toast-drop" tag="div">
        <!-- P1-UA2：错误 toast 用 role=alert（assertive）立即播报 -->
        <p v-for="t in toasts" :key="t.id" class="toast" :class="{ error: t.kind === 'error' }" :role="t.kind === 'error' ? 'alert' : undefined">{{ t.text }}</p>
      </TransitionGroup>
    </div>

    <main class="pages">
      <div class="page" ref="pageRef">
      <!-- ========== 设备页 ========== -->
      <section class="page-inner page-off" :data-page="'devices'">
        <!-- 配对（自动 / 手动 合一，按方式切换） -->
        <LiquidGlass :corner-radius="24" padding="14px 16px">
          <h2 class="glass-card-title">连接新设备</h2>
          <GlassSeg
            v-model="pairMode"
            label="连接方式"
            :options="[
              { id: 'auto', label: '自动发现' },
              { id: 'manual', label: '手动连接' },
            ]"
            class="mt-xs"
          />

          <!-- 自动配对 / 手动配对：CSS grid 0fr↔1fr 双块伸缩（可中断且总能收敛，高速切换不卡） -->
          <div class="pair-blocks">
            <div class="pair-block" :class="{ closed: pairMode !== 'auto' }">
              <div class="pair-block-inner">
            <p class="muted mt-sm">两端都点击「开始发现」，即可互相找到对方（只广播设备名，不暴露连接码）</p>
            <div class="row">
              <button v-if="!scanRunning" class="glass-btn primary" @click="startDeviceScanFn">开始发现</button>
              <button v-else class="glass-btn danger" @click="stopDeviceScanFn">停止发现</button>
            </div>
            <Transition name="card-pop" @enter="cardEnter" @leave="cardLeave">
            <div v-if="scanRunning" class="scanner-status">
              <span class="scanner-pulse" aria-hidden="true"></span>
              <span>搜索设备中：第 {{ scanRounds }} 轮 · {{ scanElapsedSec }} 秒 · 发现 {{ discovered.length }} 台</span>
            </div>
            </Transition>
            <Transition name="card-pop" @enter="cardEnter" @leave="cardLeave">
            <div v-if="discovered.length" class="device-list">
              <div
                v-for="d in discovered"
                :key="d.fingerprint + d.ip"
                v-memo="[d.fingerprint + d.ip]"
                class="device-item"
                role="button"
                tabindex="0"
                @click="onDiscoveredClick(d)"
                @keydown.enter.prevent="onDiscoveredClick(d)"
              >
                <div class="device-main">
                  <strong>{{ d.alias }}</strong>
                  <span class="muted" style="margin: 0">{{ d.ip }}:{{ d.port }}</span>
                </div>
                <span v-if="pairMgr.byDeviceId(d.fingerprint)" class="paired-badge">已配对 ✓</span>
              </div>
            </div>
            </Transition>
            <Transition name="card-pop" @enter="cardEnter" @leave="cardLeave">
            <div v-if="pairingTarget" class="mt-sm">
              <p class="muted">连接「{{ pairingTarget.alias }}」：请输入对方设备屏幕上显示的连接码</p>
              <CodeBoxes v-model="codeInput" label="对方连接码" @keyup.enter="confirmPair" />
              <div class="row">
                <button class="glass-btn primary" :disabled="verifying" @click="confirmPair">{{ verifying ? '验证中...' : '确认连接' }}</button>
                <button class="glass-btn" @click="cancelPair" :disabled="verifying">取消</button>
              </div>
            </div>
            </Transition>
            </div>
            </div>
            <div class="pair-block" :class="{ closed: pairMode !== 'manual' }">
              <div class="pair-block-inner">
            <p class="muted mt-sm">已知对方 IP / 端口 / 连接码时，直接连接</p>
            <IpBoxes v-model="manualIp" label="对方 IP" />
            <input class="glass-input" v-model.number="manualPort" type="number" min="1" max="65535" placeholder="端口（默认 53317）" @blur="clampManualPort" />
            <CodeBoxes v-model="manualCode" label="对方连接码" @keyup.enter="manualPair" />
            <button class="glass-btn primary" :disabled="verifying" @click="manualPair">{{ verifying ? '验证中...' : '连接设备' }}</button>
              </div>
            </div>
          </div>
        </LiquidGlass>

        <!-- 已配对设备（三状态：已连接 / 在线 / 离线；另有 疑似离线 软过期提示） -->
        <LiquidGlass :corner-radius="24" padding="14px 16px">
          <h2 class="glass-card-title">我的设备（{{ pairings.length }}）</h2>
          <p v-if="pairings.length === 0" class="muted">暂无已连接设备。完成连接后，每次运行会自动寻找对方。</p>
          <TransitionGroup v-else name="lg-list" tag="div" class="device-list" @leave="listLeave">
            <div v-for="p in pairings" :key="p.fingerprint" class="paired-row">
              <span class="status-dot" :class="{ on: p.online }"></span>
              <div class="device-main">
                <strong>{{ p.name }}</strong>
                <span class="muted" style="margin: 0">{{ p.ip }}:{{ p.port }} · <span :title="pairStatus(p) === '疑似离线' ? '能发现该设备但无法与之通信' : undefined">{{ pairStatus(p) }}</span><template v-if="isStale(p)">（可能已失效）</template></span>
              </div>
              <div class="btn-group">
                <button class="glass-btn small copy-ip" title="复制地址（用于手动连接）" aria-label="复制地址" @click="copyText(p.ip + ':' + p.port, '地址已复制')">
                  <svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><rect x="5.5" y="5.5" width="8" height="8" rx="1.6" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M10.5 5.5v-1.4a1.6 1.6 0 0 0-1.6-1.6H4.1a1.6 1.6 0 0 0-1.6 1.6v4.8a1.6 1.6 0 0 0 1.6 1.6h1.4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>
                </button>
                <template v-if="p.connected">
                  <button class="glass-btn small" @click="confirmDisconnect(p.fingerprint)">断开</button>
                  <button class="glass-btn small danger" @click="confirmUnpair(p.fingerprint)">解除</button>
                </template>
                <template v-else-if="p.online">
                  <button class="glass-btn small" @click="connectPeer(p)" :disabled="verifying">连接</button>
                  <button class="glass-btn small danger" @click="confirmUnpair(p.fingerprint)">解除</button>
                </template>
                <button v-else class="glass-btn small danger" @click="confirmUnpair(p.fingerprint)">解除</button>
              </div>
            </div>
          </TransitionGroup>
        </LiquidGlass>

        <!-- 本机状态（设备页最下端；不含收件/发件方向按钮） -->
        <LiquidGlass :corner-radius="24" padding="16px 18px">
          <div class="status-head">
            <h2 class="glass-card-title" style="margin: 0">本机状态</h2>
            <span class="status-chip" :class="{ on: serverRunning }">{{ serverRunning ? '收件服务运行中' : '收件服务已停止' }}</span>
          </div>
          <div class="status-grid">
            <div class="status-cell" :class="{ off: !serverRunning }">
              <span class="status-cell-label">收件服务</span>
              <span class="status-cell-value"><span class="status-dot" :class="{ on: serverRunning }"></span>{{ serverRunning ? '运行中' : '已停止' }}</span>
              <span class="status-cell-sub">{{ serverRunning ? '端口 ' + serverPort : '未开启 · 见设置页收件区配置' }}</span>
            </div>
            <div class="status-cell" :class="{ off: !targetDevice }">
              <span class="status-cell-label">目标设备</span>
              <span class="status-cell-value">{{ targetDevice ? targetDevice.name : '未选择' }}</span>
              <span class="status-cell-sub">{{ targetDevice ? pairStatus(targetDevice) : '在「同步」页选择目标设备' }}</span>
            </div>
          </div>
          <p v-if="lastSyncText" class="last-sync">{{ lastSyncText }}</p>
        </LiquidGlass>

      </section>
      <section class="page-inner page-off" :data-page="'backup'">
        <!-- 开始同步（常驻首屏，不随角色隐藏：方向 + 策略 + 目标设备 + 文件夹列表 + 同步按钮） -->
        <LiquidGlass :corner-radius="24" padding="18px 16px">
          <div class="status-head">
            <h2 class="glass-card-title" style="margin: 0">开始同步</h2>
            <span class="status-chip" :class="{ on: syncReady }">{{ syncReady ? '就绪' : '未就绪' }}</span>
          </div>
          <!-- 同步方向（收件 / 发件，可多选 = 双向） -->
          <div class="role-seg" role="group" aria-label="同步方向（可多选）">
            <button class="glass-chip" :class="{ on: role === 'receiver' || role === 'free' }" :aria-pressed="role === 'receiver' || role === 'free'" @click="toggleRoleDir('receive')"><AppIcon name="download" :size="13" /> 收件</button>
            <button class="glass-chip" :class="{ on: role === 'sender' || role === 'free' }" :aria-pressed="role === 'sender' || role === 'free'" @click="toggleRoleDir('send')"><AppIcon name="upload" :size="13" /> 发件</button>
          </div>
          <!-- 策略小标记（配置入口在设置页） -->
          <p class="strategy-marker mt-xs"><span class="mini-chip">{{ syncStrategy === 'mirror' ? '镜像' : '增量' }}</span><span class="muted" style="margin: 0">同步策略</span></p>
          <!-- 目标设备 -->
          <div class="dd mt-xs" :class="{ open: targetDropdownOpen }" @click.stop>
            <button class="glass-input dd-trigger" type="button" @click="targetDropdownOpen = !targetDropdownOpen">
              <span class="dd-label">{{ targetDevice ? targetDevice.name + '（' + pairStatus(targetDevice) + '）' : '选择目标设备' }}</span>
              <span class="dd-caret">▾</span>
            </button>
            <Transition name="drop-down">
            <div v-if="targetDropdownOpen" class="dd-panel">
              <div class="dd-list">
              <div
                v-for="p in pairings"
                :key="p.fingerprint"
                class="dd-item"
                role="button"
                tabindex="0"
                @click="selectTarget(p); targetDropdownOpen = false"
                @keydown.enter.prevent="selectTarget(p); targetDropdownOpen = false"
              >
                <span class="status-dot" :class="{ on: p.online }"></span>
                <span class="dd-name">{{ p.name }}</span>
                <span class="dd-status">{{ pairStatus(p) }}</span>
              </div>
              <div v-if="pairings.length === 0" class="dd-empty">还没有配对设备，请先到「设备」页连接</div>
              </div>
            </div>
            </Transition>
          </div>
          <div v-if="targetDropdownOpen" class="dd-backdrop" @click="targetDropdownOpen = false"></div>

          <!-- 本次同步文件夹（选好目标设备后内联展开：永久配置 + 临时新增） -->
          <div v-if="targetDevice" class="sync-folder-panel mt-md">
            <div class="sync-folder-head">
              <p class="muted" style="margin: 0">本次同步文件夹（{{ syncList.length }}）</p>
              <span class="muted" style="margin: 0; font-size: 11px">永久自动参与 · 取消勾选即本次跳过</span>
            </div>
            <TransitionGroup name="lg-list" tag="div" class="device-list" @leave="listLeave">
              <div v-for="f in syncList" :key="f.id" class="paired-row">
                <span class="status-dot" :class="{ on: !syncSkip.has(f.id) }"></span>
                <div class="device-main">
                  <strong>{{ f.name }}<span v-if="isPermanentFolder(f)" class="perm-tag">永久</span></strong>
                  <span class="muted" style="margin: 0">{{ f.path }}</span>
                </div>
                <label class="sync-toggle" :title="syncSkip.has(f.id) ? '本次跳过（点击参与）' : '参与本次同步（点击跳过）'">
                  <input type="checkbox" :checked="!syncSkip.has(f.id)" @change="toggleSyncInclude(f.id)" />
                  <span class="sync-toggle-ui" aria-hidden="true"></span>
                </label>
                <button class="glass-btn small danger" :title="isPermanentFolder(f) ? '从永久配置移除' : '移除（本次会话）'" :aria-label="isPermanentFolder(f) ? '从永久配置移除' : '移除本次会话'" @click="removeFolderFromSync(f)"><AppIcon name="close" :size="11" /></button>
              </div>
            </TransitionGroup>
            <div class="drop-zone mt-xs" role="button" tabindex="0" @click="addSessionFolder" @keydown.enter.prevent="addSessionFolder">
              <span>＋ 选择临时文件夹（本次会话，重启清空）</span>
            </div>
          </div>

          <!-- 开始同步按钮：点击按模式（收=开关自动接收 / 发=发件）；双向长按1.7s 白光填满后发件 -->
          <button
            class="glass-btn primary run-btn"
            :class="{ ready: runBtnReady, loading: scanning, hold: longPressActive }"
            :disabled="scanning || (role === 'sender' && !syncReady)"
            @pointerdown="onSyncPressStart"
            @pointerup="onSyncPressEnd"
            @pointerleave="onSyncPressCancel"
            @pointercancel="onSyncPressCancel"
          >
            <span class="hold-fill" aria-hidden="true"></span>
            <span class="hold-label">{{ runBtnLabel }}</span>
          </button>
          <p class="run-hint">{{ runHintText }}</p>
        </LiquidGlass>

        <!-- 进度（发件 / 收件） -->
        <Transition name="fade-slide" mode="out-in">
          <LiquidGlass v-if="scanning" key="progress" :corner-radius="24" padding="14px 16px">
            <h2 class="glass-card-title">同步进行中...</h2>
            <div
              class="progress-track"
              role="progressbar"
              aria-label="同步进度"
              aria-valuemin="0"
              aria-valuemax="100"
              :aria-valuenow="percentText"
            >
              <div
                class="progress-fill"
                :class="{ indeterminate: !progress }"
                :style="progress ? { transform: 'scaleX(' + progressPercent + ')' } : undefined"
              ></div>
            </div>
            <p class="muted">
              <span class="percent-num">{{ percentText }}</span>%
              {{ progress ? (' - ' + progress.fileName) : ' · 扫描中...' }}
            </p>
            <p v-if="progress && progress.bytesSent !== undefined && progress.totalBytes" class="muted">
              {{ fmtBytes(progress.bytesSent) }} / {{ fmtBytes(progress.totalBytes) }}
              <template v-if="rateInfo.rate > 0">
                · {{ fmtRate(rateInfo.rate, 1000) }}
                <template v-if="rateInfo.etaSec > 0"> · 剩余 {{ fmtEta(rateInfo.etaSec) }}</template>
              </template>
            </p>
          </LiquidGlass>
          <LiquidGlass v-else-if="recvProgress" key="recv" :corner-radius="24" padding="14px 16px">
            <h2 class="glass-card-title">收件中...</h2>
            <div
              class="progress-track"
              role="progressbar"
              aria-label="收件进度"
              aria-valuemin="0"
              aria-valuemax="100"
              :aria-valuenow="Math.round(recvPercent * 100)"
            >
              <div class="progress-fill" :style="{ transform: 'scaleX(' + recvPercent + ')' }"></div>
            </div>
            <p class="muted">
              {{ recvProgress.fileName }} · {{ recvProgress.receivedCount }}/{{ recvProgress.totalCount }} 个文件 ·
              {{ fmtBytes(recvProgress.receivedBytes) }} / {{ fmtBytes(recvProgress.totalBytes) }}
            </p>
            <div class="row mt-sm">
              <button class="glass-btn small danger" @click="cancelReceive">取消收件</button>
            </div>
          </LiquidGlass>
        </Transition>

        <!-- 同步任务列表（任务化暂停/恢复：断网暂停，恢复时跳过已完成文件续传） -->
        <LiquidGlass v-if="tasks.length" :corner-radius="24" padding="14px 16px">
          <h2 class="glass-card-title">同步任务（{{ tasks.length }}）</h2>
          <div class="device-list">
            <div v-for="t in tasks" :key="t.id" class="paired-row">
              <span class="status-dot" :class="{ on: t.state === 'running' || t.state === 'completed', failed: t.state === 'failed' }"></span>
              <div class="device-main">
                <strong>{{ t.direction === 'send' ? '发送 →' : '接收 ←' }} {{ t.peer }} · {{ taskStateText(t.state) }}</strong>
                <span class="muted" style="margin: 0">{{ t.sentCount }}/{{ t.fileCount }} 个文件 · {{ fmtBytes(t.bytes) }} / {{ fmtBytes(t.totalBytes) }}</span>
                <span v-if="t.error" class="task-error">{{ t.state === 'failed' ? '失败原因：' : '暂停原因：' }}{{ t.error }}</span>
              </div>
              <div class="btn-group">
                <button v-if="t.state === 'paused'" class="glass-btn small primary" @click="resumeTaskAction()">恢复</button>
                <button v-else-if="t.state === 'failed'" class="glass-btn small primary" @click="retryTaskAction(t)">重试</button>
                <button class="glass-btn small" title="移除任务记录" aria-label="移除任务记录" @click="removeTask(t.id)"><AppIcon name="close" :size="11" /></button>
              </div>
            </div>
          </div>
        </LiquidGlass>

        <!-- 同步完成统计 -->
        <LiquidGlass v-if="progressDone" key="done" :corner-radius="24" padding="14px 16px">
          <div class="history-head">
            <h2 class="glass-card-title" style="margin: 0">同步完成</h2>
            <button class="glass-btn small" @click="progressDone = null">关闭</button>
          </div>
          <p class="muted" style="margin-bottom: 0">
            <template v-if="progressDone.count === 0">已是最新，无需同步</template>
            <template v-else>
              {{ progressDone.direction === 'out' ? '已发送' : '已接收' }} {{ progressDone.count }} 个文件 ·
              {{ fmtBytes(progressDone.bytes) }} ·
              {{ progressDone.durationMs > 0 ? (progressDone.durationMs / 1000).toFixed(1) + ' 秒' : '—' }} ·
              {{ progressDone.bytes > 0 && progressDone.durationMs > 0 ? fmtRate(progressDone.bytes, progressDone.durationMs) : '—' }}
            </template>
          </p>
        </LiquidGlass>
      </section>
      <!-- ========== 历史页 ========== -->
      <section class="page-inner page-off" :data-page="'history'">
        <LiquidGlass :corner-radius="24" padding="14px 16px">
          <div class="history-head">
            <h2 class="glass-card-title" style="margin: 0">传输记录（{{ transfers.length }} 条）</h2>
            <button v-if="transfers.length" class="glass-btn small danger" @click="clearAllTransfers">清空记录</button>
          </div>
          <p v-if="transfers.length === 0" class="muted">暂无传输记录。完成一次同步后这里会显示方向、文件数、大小、耗时与速率。</p>
          <TransitionGroup v-else name="lg-list" tag="div" class="hist-groups" @leave="groupLeave">
            <div v-for="g in historyGroups" :key="g.key" class="hist-group">
              <button class="hist-group-head" @click="toggleHistGroup(g.key)">
                <strong>{{ g.label }}（{{ g.items.length }}）</strong>
                <span class="hist-caret" :class="{ open: openHistGroup === g.key }" aria-hidden="true">⌄</span>
              </button>
              <div class="panel-collapse" :class="{ closed: openHistGroup !== g.key }">
                <div class="panel-collapse-inner">
                  <TransitionGroup name="lg-list" tag="div" class="device-list mt-xs" @leave="listLeave">
                    <div v-for="(t, i) in g.items" :key="t.id || t.createdAt + '-' + t.direction + '-' + i" class="paired-row">
                      <div class="device-main">
                        <strong><span class="hist-dir">{{ t.direction === 'out' ? '发送' : '接收' }}</span> · {{ t.fileCount }} 个文件 · {{ t.bytes > 0 ? fmtBytes(t.bytes) : '—' }}</strong>
                        <span class="muted hist-sub" style="margin: 0">{{ t.durationMs > 0 ? (t.durationMs / 1000).toFixed(1) + ' 秒' : '—' }}<template v-if="t.durationMs > 0 && t.bytes > 0"> · {{ fmtRate(t.bytes, t.durationMs) }}</template></span>
                        <span class="muted hist-sub" style="margin: 0">{{ new Date(t.createdAt).toLocaleString() }}</span>
                      </div>
                      <button class="glass-btn small" title="删除这条记录" aria-label="删除这条记录" @click="deleteTransfer(transfers.indexOf(t))"><AppIcon name="close" :size="11" /></button>
                    </div>
                  </TransitionGroup>
                </div>
              </div>
            </div>
          </TransitionGroup>
        </LiquidGlass>
      </section>

      <!-- ========== 设置页 ========== -->
      <section class="page-inner page-off" :data-page="'settings'">
        <LiquidGlass :corner-radius="24" padding="14px 16px">
          <h2 class="glass-card-title">设备信息</h2>
          <p class="muted">本机公开标识：{{ deviceInfo.deviceId ? deviceInfo.deviceId.slice(0, 8) + '…' : '' }} · 机型 {{ deviceInfo.model }}</p>
          <input class="glass-input" v-model="deviceNameInput" placeholder="设备名（如 小米17）" @blur="flushDeviceName" />
          <p class="muted">输入后自动保存；重置连接码请点顶部连接码旁的刷新按钮</p>
        </LiquidGlass>

        <!-- 自动收件：与「调试」同构（标题+开关同排），独立成卡，与桌面端一致 -->
        <LiquidGlass :corner-radius="24" padding="14px 16px">
          <div class="history-head">
            <h2 class="glass-card-title" style="margin: 0">自动收件</h2>
            <GlassSwitch :model-value="autoStartReceiver" label="启动时自动开启收件" @update:model-value="toggleAutoStartReceiver" />
          </div>
          <p class="muted">启动后自动开启收件服务，随时接收对方推送</p>
        </LiquidGlass>

        <!-- 同步策略：增量 / 镜像（从同步页移入设置页） -->
        <LiquidGlass :corner-radius="24" padding="14px 16px">
          <h2 class="glass-card-title">同步策略</h2>
          <GlassSeg
            v-model="syncStrategy"
            label="同步策略"
            :options="[
              { id: 'archive', label: '增量' },
              { id: 'mirror', label: '镜像' },
            ]"
            @update:model-value="setStrategy"
          />
          <p v-if="syncStrategy === 'mirror'" class="muted">镜像：对端多余文件将被移入其 delete 文件夹；增量仅发送差异文件</p>
        </LiquidGlass>

        <!-- 发件区配置：永久文件夹（持久化，重启保留，默认每次参与同步） -->
        <LiquidGlass :corner-radius="24" padding="14px 16px">
          <h2 class="glass-card-title">发件区配置</h2>
          <p class="muted">永久发件文件夹：程序关闭后仍保留，默认每次都参与同步</p>
          <TransitionGroup name="lg-list" tag="div" class="device-list" @leave="listLeave">
            <div v-for="f in senderFolders" :key="f.id" class="paired-row">
              <span class="status-dot" :class="{ on: f.enabled }"></span>
              <div class="device-main">
                <strong>{{ f.name }}</strong>
                <span class="muted" style="margin: 0">{{ f.path }}</span>
              </div>
              <button class="glass-btn small" @click="toggleSendFolder(f.id)">{{ f.enabled ? '禁用' : '启用' }}</button>
              <button class="glass-btn small danger" title="移除文件夹" aria-label="移除文件夹" @click="confirmRemoveSendFolder(f)"><AppIcon name="close" :size="11" /></button>
            </div>
          </TransitionGroup>
          <div class="drop-zone mt-xs" role="button" tabindex="0" @click="addSendFolder" @keydown.enter.prevent="addSendFolder">
            <span>＋ 选择永久发送文件夹</span>
          </div>
        </LiquidGlass>

        <!-- 收件区配置：收件目录 + 收件服务开关（从同步页迁移） -->
        <LiquidGlass :corner-radius="24" padding="14px 16px">
          <h2 class="glass-card-title">收件区配置</h2>
          <p class="muted">收件目录（保存电脑推送的文件）</p>
          <div class="root-row" :class="{ checked: boxC2p }" role="button" tabindex="0" @click="pickBoxC2p" @keydown.enter.prevent="pickBoxC2p">
            <span class="root-check">{{ boxC2p ? '✓' : '＋' }}</span>
            <span class="root-name">{{ boxC2p ? boxC2p.name : '选择收件目录' }}</span>
          </div>
          <div class="row mt-sm">
            <span class="muted" style="margin: 0; flex: 1">收件服务</span>
            <button v-if="serverRunning" class="glass-btn small danger" @click="oneClickCloseReceive">一键关闭</button>
            <button v-else-if="receiverEnabled && recvStarting" class="glass-btn small" disabled>启用中…</button>
            <button v-else class="glass-btn small primary" @click="oneClickReceive">一键开启</button>
          </div>
          <p v-if="!boxC2p" class="muted synced-hint mt-xs">⚠ 对方将无法推送文件到本机——请先选择收件目录并开启收件服务</p>
        </LiquidGlass>

        <LiquidGlass :corner-radius="24" padding="14px 16px">
          <div class="history-head">
            <h2 class="glass-card-title" style="margin: 0">调试</h2>
            <GlassSwitch :model-value="debugEnabled" label="调试模式" @update:model-value="setDebug" />
          </div>
          <p class="muted" :class="{ 'log-has-error': debugSummary.error > 0 }">
            日志 {{ logger.size() }} 条 · <strong class="stat-error">错误 {{ debugSummary.error }}</strong> · <strong class="stat-warn">警告 {{ debugSummary.warn }}</strong>
          </p>
          <div class="row">
            <button class="glass-btn small" @click="exportLogs">导出日志</button>
            <button class="glass-btn small" @click="openLogPreview">预览日志</button>
            <button class="glass-btn small danger" @click="clearLogs">清空日志</button>
          </div>
          <Transition name="fade-slide">
            <div v-if="showLogPreview" class="log-preview">
            <div class="log-preview-head">
              <span class="muted" style="margin: 0; flex: 1">日志预览（{{ logger.size() }} 条）</span>
              <button class="glass-btn small" @click="copyLogPreview">复制</button>
              <button class="glass-btn small" @click="showLogPreview = false">关闭</button>
            </div>
            <pre class="log-preview-body">{{ logPreviewText }}</pre>
            </div>
          </Transition>
        </LiquidGlass>

        <LiquidGlass :corner-radius="24" padding="14px 16px">
          <h2 class="glass-card-title">画面质量</h2>
          <GlassSeg
            v-model="qualityLevel"
            label="画面质量"
            :options="[
              { id: 'low', label: '低' },
              { id: 'medium', label: '中' },
              { id: 'high', label: '高（更耗电）' },
            ]"
            @update:model-value="setQuality"
          />
        </LiquidGlass>

        <LiquidGlass :corner-radius="24" padding="14px 16px">
          <h2 class="glass-card-title">关于</h2>
          <div class="about-dev">
            <img class="dev-avatar" src="/avatar.jpg" alt="HIMKUG" />
            <div class="dev-info">
              <strong>开发者：HIMKUG</strong>
              <a href="https://space.bilibili.com/401121508" target="_blank" rel="noreferrer">哔哩哔哩主页 ↗</a>
            </div>
          </div>
          <p class="muted mt-sm">局域网备份工具 · 版本 0.1.0</p>
        </LiquidGlass>
      </section>
        </div>
    </main>

    <!-- 接收确认弹窗（电脑→手机 prepare-upload） -->
    <div v-if="incomingReq" class="incoming-overlay" role="dialog" aria-modal="true" aria-label="收件请求">
      <div class="incoming-card">
        <h3 class="glass-card-title">收件请求</h3>
        <p class="muted">来自「{{ incomingReq.senderName || incomingReq.senderIp }}」请求发送 {{ incomingReq.count }} 个文件</p>
        <p class="muted">共 {{ fmtBytes(incomingReq.totalBytes) }}，是否同意接收？</p>
        <div class="row mt-sm">
          <button class="glass-btn danger" @click="acceptIncoming(false)">拒绝</button>
          <button class="glass-btn primary" @click="acceptIncoming(true)">接受</button>
        </div>
      </div>
    </div>

    <!-- 配对确认弹窗（对方填写了本机连接码请求配对） -->
    <div v-if="pairingReq" class="incoming-overlay" role="dialog" aria-modal="true" aria-label="连接请求">
      <div class="incoming-card">
        <h3 class="glass-card-title">连接请求</h3>
        <p class="muted">「{{ pairingReq.name }}」（{{ pairingReq.ip }}）正确填写了本机连接码，请求与你连接</p>
        <p class="muted">是否同意连接？</p>
        <div class="row mt-sm">
          <button class="glass-btn danger" @click="acceptPairing(false)">拒绝</button>
          <button class="glass-btn primary" @click="acceptPairing(true)">同意</button>
        </div>
      </div>
    </div>

    <!-- 二级确认弹窗（重置码 / 清记录 / 清日志 / 解除 / 断开） -->
    <GlassModal
      :open="!!confirmAsk"
      :title="confirmAsk?.title || ''"
      :message="confirmAsk?.message"
      :danger="confirmAsk?.danger"
      @confirm="runConfirm"
      @cancel="cancelConfirm"
    />

    <!-- 底部 Dock：悬浮多气泡液态玻璃（向下滚动收缩 / 轻点状态气泡向上展开） -->
    <GlassDock v-model="currentPage" :tabs="dockTabs" :status-title="dockStatusTitle" :status-sub="dockStatusSub" :status-on="role === 'receiver' ? autoAcceptReceive : serverRunning" :dual="role === 'free'" :on-sync-long-press="longPressSyncAction" :on-sync-click="toggleAutoAcceptReceive">
      <template #panel>
        <h3 class="dock-panel-title">本机状态</h3>
        <div class="dock-panel-grid">
          <div class="dock-kv"><span>角色</span><strong>{{ roleName }} · {{ roleDesc }}</strong></div>
          <div class="dock-kv"><span>收件服务</span><strong>{{ serverRunning ? '运行中 · 端口 ' + serverPort : '已停止' }}</strong></div>
          <div class="dock-kv"><span>目标设备</span><strong>{{ targetDevice ? targetDevice.name : '未选择' }}</strong></div>
          <div class="dock-kv code-kv" role="button" tabindex="0" title="点击复制连接码" @click="copyText(selfCode, '连接码已复制')" @keydown.enter="copyText(selfCode, '连接码已复制')"><span>连接码</span><strong class="self-code">{{ selfCode }}</strong></div>
        </div>
        <p v-if="lastSyncText" class="dock-panel-sync">{{ lastSyncText }}</p>
        <div class="dock-visibility">
          <div class="dock-visibility-info">
            <strong>{{ defensiveHidden ? '本机已完全隐藏' : serverRunning ? '本机可见中' : '未配对设备无法发现本机' }}</strong>
            <small v-if="defensiveHidden">防御性总开关已开启：所有设备（含已配对）均无法发现或连接本机，仅本机可主动外连</small>
            <small v-else-if="serverRunning">局域网内设备可以发现并向你推送文件；已配对设备始终可凭凭证发现/连接</small>
            <small v-else>未配对设备无法发现本机；已配对设备仍可凭加密凭证发现/连接</small>
          </div>
          <button class="glass-btn small" :class="{ danger: defensiveHidden }" @click="setDefensive(!defensiveHidden)">{{ defensiveHidden ? '设为可见' : '设为隐藏' }}</button>
        </div>
      </template>
    </GlassDock>
  </div>
</template>
