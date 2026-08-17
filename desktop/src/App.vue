<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue';
import { gsap } from 'gsap';
import { CodeBoxes, GlassDock, GlassFilters, GlassModal, GlassScrollbar, GlassSeg, GlassSwitch, IpBoxes, LiquidGlass, installGlowHover, setBlurInterval, useAutoResume, useSyncTasks, type SyncTask } from 'shared-ui';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { useTauriListener } from './composables/useTauriListener';
import {
  createEmptyState,
  getOrCreateDevice,
  markBackupDone,
  migrateState,
  buildManifest,
  planIncremental,
  PairingManager,
  normalizeCode,
  type BackupState,
  type PeerManifest,
  type PairRecord,
  type PairingStorage,
  type SyncStrategy,
  type DeviceRole,
  type SendFolder,
  type AppConfig,
  normalizeConfig,
  genFolderId,
  logger,
} from 'shared-core';

// Tauri 命令封装（在浏览器环境降级）
const isTauri = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (isTauri) {
    const { invoke } = await import('@tauri-apps/api/core');
    return invoke<T>(cmd, args);
  }
  throw new Error('当前不在 Tauri 环境，无法调用后端命令');
}

async function openDirectory(): Promise<string | null> {
  if (isTauri) {
    const { open } = await import('@tauri-apps/plugin-dialog');
    const result = await open({ directory: true, multiple: false });
    return typeof result === 'string' ? result : null;
  }
  return null;
}

/** 多选目录（发送文件夹批量添加用） */
async function openDirectories(): Promise<string[]> {
  if (isTauri) {
    const { open } = await import('@tauri-apps/plugin-dialog');
    const result = await open({ directory: true, multiple: true });
    if (Array.isArray(result)) return result.filter((x): x is string => typeof x === 'string');
    return typeof result === 'string' ? [result] : [];
  }
  return [];
}

/** 发现的设备（Rust multicast 返回值，fingerprint = 对方公开 deviceId） */
interface DiscoveredDevice {
  alias: string;
  fingerprint: string;
  ip: string;
  port: number;
}

/** 探测结果 */
interface PingedDevice {
  alias: string;
  fingerprint: string;
  port: number;
}

type Page = 'devices' | 'backup' | 'history' | 'settings';

const STATE_KEY = 'desktop_backup_state';

// ---------- 基础状态 ----------
const selfInfo = ref({ name: '', id: '', code: '' });
// 备份页为主页：应用启动默认进入备份 Tab
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
const lastResult = ref('');

// ---------- 配对 ----------
const pairingStorage: PairingStorage = {
  load: () => {
    try {
      return JSON.parse(localStorage.getItem('desktop_pairings') || '[]');
    } catch {
      return [];
    }
  },
  save: (r) => {
    try {
      localStorage.setItem('desktop_pairings', JSON.stringify(r));
    } catch {
      // 忽略
    }
  },
};
const pairMgr = new PairingManager(pairingStorage);
const pairings = ref<PairRecord[]>([]);
const discovered = ref<DiscoveredDevice[]>([]);
const scanRunning = ref(false);
const scanRounds = ref(0);
const scanElapsedSec = ref(0);
let scanStartedAt = 0;
const verifying = ref(false);
let pollTimer: ReturnType<typeof setInterval> | null = null;
let pingTimer: ReturnType<typeof setInterval> | null = null;
let mergeTimer: ReturnType<typeof setInterval> | null = null;
const pairingTarget = ref<DiscoveredDevice | null>(null);
const codeInput = ref('');
const manualIp = ref('');
const manualPort = ref(53317);
const manualCode = ref('');
/** 配对方式：自动（广播发现）/ 手动（IP+连接码） */
const pairMode = ref<'auto' | 'manual'>('auto');

// ---------- 备份盒子 ----------
/** 角色模型：设备形态与角色解耦（接收端/发送端/自由模式） */
const appConfig = ref<AppConfig>(normalizeConfig(null));
/** 当前角色（快捷绑定 appConfig.role） */
const role = ref<DeviceRole>('sender');
/** 角色展示名（状态总览卡） */
const roleName = computed(() => (role.value === 'receiver' ? '收件' : role.value === 'sender' ? '发件' : '双向'));

/** 底部 Dock：页面定义 + 状态气泡文案 */
const pageNames: Record<Page, string> = { devices: '设备', backup: '同步', history: '记录', settings: '设置' };
const dockTabs: { id: Page; icon: string; label: string }[] = [
  { id: 'devices', icon: '📡', label: '设备' },
  { id: 'backup', icon: '💾', label: '同步' },
  { id: 'history', icon: '🕘', label: '记录' },
  { id: 'settings', icon: '⚙️', label: '设置' },
];
const dockStatusTitle = computed(() => pageNames[currentPage.value]);
const dockStatusSub = computed(() => (serverRunning.value ? '收件服务运行中' : '收件服务已停止'));

/** 自定义标题栏窗口控制（decorations: false 后由应用自绘） */
const appWin = getCurrentWindow();

/** 标题栏拖拽：标题区空白处按住左键即可拖动窗口（按钮/输入不触发） */
function onHeaderDrag(e: MouseEvent) {
  if (e.button !== 0) return;
  const t = e.target as HTMLElement;
  if (t.closest('button, input, a, select, textarea')) return;
  appWin.startDragging();
}

/** 一键开启收件：未选目录先引导选择，然后确保收件服务运行。
    仅在服务运行中拦截——receiverEnabled 为真但服务已停（常见状态）时仍可再次开启 */
async function oneClickReceive() {
  if (serverRunning.value) return;
  if (!boxP2c.value) {
    await pickBoxP2c();
    if (!boxP2c.value) return;
  }
  receiverEnabled.value = true;
  recvStarting.value = true;
  persistConfig();
  try {
    await startServer(boxP2c.value);
  } finally {
    recvStarting.value = false;
  }
}

/** 一键关闭收件：停用收件并停止服务 */
function oneClickCloseReceive() {
  receiverEnabled.value = false;
  persistConfig();
  if (serverRunning.value) stopServer();
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
    .to(node, { height: 0, paddingTop: 0, paddingBottom: 0, borderTopWidth: 0, borderBottomWidth: 0, marginBottom: -16, duration: 0.45, ease: 'power3.inOut' })
    .to(node, { autoAlpha: 0, duration: 0.18, ease: 'power2.in' }, 0.28);
}

/** 列表项移除：文字先隐去，整框化作灰色烟雾随风飘散；
    同时高度收拢到 0，兄弟项被高度动画连续推上移（非瞬移） */
async function smokeDissolve(row: HTMLElement) {
  /* 动效减弱：不做粒子与补间，直接终态（done 由调用方在微任务后触发） */
  if (reduceMotion()) {
    gsap.set(row, { autoAlpha: 0, height: 0, paddingTop: 0, paddingBottom: 0, borderTopWidth: 0, borderBottomWidth: 0 });
    return;
  }
  /* 此刻元素仍在文档流原位置，读取真实坐标（不要再被 absolute 拖到容器顶部） */
  const rect = row.getBoundingClientRect();
  const kids = [...row.children] as HTMLElement[];
  gsap.to(kids, { autoAlpha: 0, y: -4, duration: 0.22, ease: 'power2.in', stagger: 0.03 });
  const n = 22;
  for (let i = 0; i < n; i++) {
    const p = document.createElement('span');
    p.className = 'smoke-puff';
    const size = 14 + Math.random() * 22;
    p.style.width = size + 'px';
    p.style.height = size + 'px';
    p.style.left = rect.left + (i / n) * rect.width + (Math.random() - 0.5) * 16 + 'px';
    p.style.top = rect.top + rect.height / 2 + (Math.random() - 0.5) * rect.height * 0.6 + 'px';
    document.body.appendChild(p);
    gsap.fromTo(
      p,
      { autoAlpha: 0.55, scale: 0.4 },
      {
        autoAlpha: 0,
        scale: 1.7,
        x: 60 + Math.random() * 100,
        y: (Math.random() - 0.35) * 44,
        duration: 1.1 + Math.random() * 0.7,
        delay: Math.random() * 0.15,
        ease: 'power2.out',
        onComplete: () => p.remove(),
      },
    );
  }
  await Promise.all([
    gsap.to(row, { autoAlpha: 0, duration: 0.2, ease: 'power2.in' }),
    new Promise<void>((res) => {
      gsap.to(row, { height: 0, paddingTop: 0, paddingBottom: 0, borderTopWidth: 0, borderBottomWidth: 0, duration: 0.45, ease: 'power3.inOut', onComplete: () => res() });
    }),
  ]);
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

/** 二级确认弹窗：所有“是否确认”统一走这里（重置码/清记录/清日志/解除/断开/镜像清理） */
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
/** 异步确认（镜像清理等需等待用户选择的场景）：确认 resolve(true)，取消 resolve(false) */
function askConfirmAsync(a: { title: string; message?: string; danger?: boolean }): Promise<boolean> {
  return new Promise((resolve) => {
    confirmAsk.value = { ...a, action: () => resolve(true), cancel: () => resolve(false) };
  });
}
/** 镜像清理确认中（进度卡切换文案，避免「同步进行中…」误导等待确认的用户） */
const mirrorConfirming = ref(false);

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
/** 问候对端（连接问候触发其 peer-connected → 自动拉起接收服务）；verify_device 返回可达标志 */
async function greetPeer(ip: string, port: number): Promise<boolean> {
  const r = await invoke<{ ok: boolean }>('verify_device', {
    ip,
    port,
    code: '',
    deviceId: selfInfo.value.id,
    name: selfInfo.value.name,
    myCode: '',
    probe: false,
  });
  return !!r?.ok;
}
/** 呼醒任务对端：问候触发其拉起接收服务 + 对齐本机同步目标（恢复/重试共用） */
async function wakePeerFor(t: SyncTask) {
  if (t.peerIp && t.peerPort) {
    try {
      await greetPeer(t.peerIp, t.peerPort);
    } catch {
      // 对端离线：交给 send_files 的唤醒重试与错误提示
    }
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
  verifyPeer: (t) => greetPeer(t.peerIp!, t.peerPort!),
  onReconnect: (t) => {
    const rec = t.peerFingerprint ? pairMgr.byFingerprint(t.peerFingerprint) : null;
    if (rec) {
      pairMgr.markOnline(rec.fingerprint, t.peerIp!, t.peerPort!);
      pairMgr.markConnected(rec.fingerprint, true);
      refreshPairings();
      selectTarget(rec);
    }
  },
  onResume: () => runBackup(),
  notify: (text) => pushToast('ok', text),
  logInfo: (msg) => logger.info('ui', msg),
});
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
/** 接收端：接收目录（与 appConfig.receiver.receiveDir 同步） */
const boxP2c = ref(''); // 手机→电脑：本机接收目录
/** 接收端配置 */
const receiverEnabled = ref(false);
const autoStartReceiver = ref(false);
/** 接收端配置区折叠（窄栏仅状态灯） */
const recvPanelCollapsed = ref(true); // 收件区配置默认折叠
const sendPanelCollapsed = ref(true); // 发件区配置默认折叠
/** 发送端：多文件夹列表 */
const senderFolders = ref<SendFolder[]>([]);
const boxC2p = ref(''); // 兼容旧引用：当前发送文件夹（folders 为空时用）
const targetDevice = ref<PairRecord | null>(null);
const targetDropdownOpen = ref(false);
const scanning = ref(false);
const syncStrategy = ref<SyncStrategy>('archive'); // 与 appConfig.sender.strategy 同步
const progressInfo = ref<{
  sent: number;
  total: number;
  fileName?: string;
  stage?: string;
  bytes?: number;
  elapsedMs?: number;
  /** 当前文件已传 / 总字节（块级进度事件） */
  bytesSent?: number;
  totalBytes?: number;
} | null>(null);
/* 发送进度 → 任务进度联动 */
watch(progressInfo, (p) => {
  if (activeTaskId.value && p) {
    updateTask(activeTaskId.value, { sentCount: p.sent, fileCount: p.total, bytes: p.bytes || 0 });
  }
});
/** 就绪状态（同步操作卡常驻按钮用）：目标设备 + 至少一个启用文件夹 */
const sendFolderCount = computed(() => senderFolders.value.filter((f) => f.enabled).length);
const syncReady = computed(() => !!targetDevice.value && sendFolderCount.value > 0);
const runHintText = computed(() => {
  if (scanning.value) return '同步进行中，可离开此页；进度与任务都会记录在下方';
  if (!targetDevice.value) return '未就绪 · 请选择目标设备';
  if (sendFolderCount.value === 0) return '未就绪 · 请在发件区添加文件夹';
  return `就绪 · ${sendFolderCount.value} 个文件夹 → ${targetDevice.value.name}`;
});
/** 发送进度百分比（字节优先，文件数兜底；进度条 aria 与大数字共用） */
const sendProgressPct = computed(() => {
  const p = progressInfo.value;
  if (!p) return 0;
  if (p.totalBytes && p.bytesSent !== undefined) return Math.min(100, Math.round((p.bytesSent / p.totalBytes) * 100));
  if (p.total > 0) return Math.min(100, Math.round((p.sent / p.total) * 100));
  return 0;
});
/** 接收进度（手机→电脑，Rust 事件循环按文件级推送） */
const recvProgress = ref<{ fileName: string; receivedBytes: number; totalBytes: number; receivedCount: number; totalCount: number } | null>(null);
/** 接收确认弹窗（手机→电脑 prepare-upload） */
const incomingReq = ref<{ sessionId: string; count: number; totalBytes: number; senderName: string; senderIp: string } | null>(null);
/** 配对确认弹窗（对方填写了本机连接码请求配对） */
const pairingReq = ref<{ deviceId: string; name: string; ip: string } | null>(null);
/** 备份完成统计（进度框完成态显示） */
const progressDone = ref<{ direction: string; count: number; bytes: number; durationMs: number } | null>(null);
/** 发送累计字节/耗时（send-progress 组级事件，完成统计用） */
const lastSendStat = ref({ bytes: 0, elapsedMs: 0 });

async function acceptIncoming(accept: boolean) {
  const r = incomingReq.value;
  if (!r) return;
  incomingReq.value = null;
  try {
    await invoke('resolve_incoming', { sessionId: r.sessionId, accept });
    lastResult.value = accept ? `已同意接收 ${r.count} 个文件` : '已拒绝接收';
  } catch (e) {
    logger.error('receiver', '响应接收确认失败', e);
  }
}

async function acceptPairing(accept: boolean) {
  const r = pairingReq.value;
  if (!r) return;
  pairingReq.value = null;
  try {
    await invoke('resolve_pairing', { deviceId: r.deviceId, accept });
    lastResult.value = accept ? `已同意与「${r.name}」配对` : `已拒绝与「${r.name}」配对`;
  } catch (e) {
    logger.error('pair', '响应配对确认失败', e);
  }
}

/** 发现服务开关：开启需已选择接收目录 */
async function toggleService() {
  if (serverRunning.value) {
    await stopServer();
  } else {
    if (!boxP2c.value) {
      errorMsg.value = '请先选择「手机→电脑」接收目录';
      return;
    }
    await startServer(boxP2c.value);
  }
}
const transfers = ref<
  { id: number; direction: string; peer: string; fileCount: number; bytes: number; durationMs: number; createdAt: number }[]
>([]);
const serverRunning = ref(false);

/** 配置卡呼吸灯：收件=目录+服务双全→绿，其余→灰。发件=目标设备在线→绿，其余→灰
    （黄色已移除：停止/离线是常态不是警告，红黄仅留给真正的异常） */
const recvDot = computed<'on' | ''>(() => {
  return boxP2c.value && serverRunning.value ? 'on' : '';
});
const sendDot = computed<'on' | ''>(() => {
  return targetDevice.value?.online ? 'on' : '';
});

/** 收件启动中标记：只在真正发起启动的瞬间置位，避免服务闪烁时误现“启用中” */
const recvStarting = ref(false);
watch(serverRunning, (r) => {
  if (r) recvStarting.value = false;
});

// 速率/大小格式化
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
/** 剩余时间估算（按当前速率） */
function fmtRemain(p: { bytes?: number; elapsedMs?: number; totalBytes?: number; bytesSent?: number }): string {
  if (!p.bytes || !p.elapsedMs || p.totalBytes === undefined || p.bytesSent === undefined) return '…';
  const rate = p.bytes / Math.max(1, p.elapsedMs / 1000);
  if (rate <= 0) return '…';
  const remain = (p.totalBytes - p.bytesSent) / rate;
  if (remain < 1) return '即将完成';
  if (remain < 60) return `${Math.ceil(remain)} 秒`;
  return `${(remain / 60).toFixed(1)} 分钟`;
}
async function loadTransfers() {
  try {
    transfers.value = await invoke('get_transfers', { limit: 200 });
  } catch {
    // 忽略
  }
}
async function deleteTransfer(id: number) {
  try {
    await invoke('delete_transfer', { id });
    await loadTransfers();
    lastResult.value = '已删除该条传输记录';
  } catch (e) {
    logger.error('ui', '删除传输历史失败', e);
  }
}
function clearAllTransfers() {
  askConfirm({
    title: '清空传输记录',
    message: `将删除全部 ${transfers.value.length} 条传输记录，不可恢复。`,
    danger: true,
    action: () => {
      invoke('clear_transfers')
        .then(() => {
          lastResult.value = '传输记录已清空';
          loadTransfers();
        })
        .catch((e) => logger.error('ui', '清空传输历史失败', e));
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
    localStorage.setItem('desktop_debug', String(v));
  } catch {
    // 忽略
  }
}
/* 选中策略：调试关闭时全局禁选中（仅输入框与调试日志例外）；开启后任意可选中 */
watch(debugEnabled, (v) => document.documentElement.classList.toggle('debug-on', v), { immediate: true });
const showLogPreview = ref(false);
const logPreviewText = ref('');
let nameSaveTimer: ReturnType<typeof setTimeout> | null = null;
let unlistenDrag: (() => void) | null = null;

let mm: ReturnType<typeof gsap.matchMedia> | null = null;
let unsubLog: (() => void) | null = null;
const { track } = useTauriListener();

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

// 兼容旧赋值点：lastResult/errorMsg 一被写入就入队并立即清空，显示交给 toasts
watch([lastResult, errorMsg], ([lr, em]) => {
  if (lr) {
    pushToast('ok', lr);
    lastResult.value = '';
  }
  if (em) {
    pushToast('error', em);
    errorMsg.value = '';
  }
});

function applyTheme() {
  document.documentElement.classList.toggle('dark', darkMode.value);
  try {
    localStorage.setItem('lanbackup_dark', String(darkMode.value));
  } catch {
    // 忽略
  }
  // 浏览器/系统 UI 主题色跟随（状态栏、窗口底色）
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', darkMode.value ? '#0a0a0c' : '#f2f2f7');
}
watch(darkMode, applyTheme, { immediate: true });

/** 配对设备三态文案（已连接 / 在线 / 离线；能搜索到但无法通信 → 疑似离线） */
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
  // 同步对象引用跟随：防止下拉绑定的旧对象在数组整体替换后漂移
  if (targetDevice.value) {
    const fp = targetDevice.value.fingerprint;
    targetDevice.value = pairMgr.byFingerprint(fp) ?? null;
  }
}

// ---------- 角色模型配置（发送端/接收端/自由模式，与设备形态解耦） ----------
async function loadAppConfig() {
  try {
    const raw = await invoke<unknown>('get_config');
    appConfig.value = normalizeConfig(raw);
  } catch {
    appConfig.value = normalizeConfig(null);
  }
  applyConfigToState();
}

function applyConfigToState() {
  const c = appConfig.value;
  role.value = c.role;
  boxP2c.value = c.receiver.receiveDir;
  receiverEnabled.value = c.receiver.enabled;
  autoStartReceiver.value = c.receiver.autoStartReceiver;
  senderFolders.value = c.sender.folders.map((f) => ({ ...f }));
  syncStrategy.value = c.sender.strategy;
}

async function persistConfig() {
  const c = appConfig.value;
  c.role = role.value;
  c.receiver.receiveDir = boxP2c.value;
  c.receiver.enabled = receiverEnabled.value;
  c.receiver.autoStartReceiver = autoStartReceiver.value;
  c.sender.folders = senderFolders.value.map((f) => ({ ...f }));
  c.sender.strategy = syncStrategy.value;
  c.sender.targetPeerId = targetDevice.value?.fingerprint;
  try {
    await invoke('set_config', { config: JSON.parse(JSON.stringify(c)) });
  } catch (e) {
    logger.warn('config', '保存配置失败', e);
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
    if (boxP2c.value && !serverRunning.value) startServer(boxP2c.value);
  } else if (serverRunning.value) {
    stopServer();
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

/** 发送文件夹：多选添加（Tauri 对话框支持多选目录） */
async function addSendFolder() {
  const dirs = await openDirectories();
  if (!dirs.length) return;
  for (const dir of dirs) {
    const name = dir.split(/[\\/]/).filter(Boolean).pop() || '文件夹';
    senderFolders.value.push({ id: genFolderId(), name, path: dir, enabled: true });
  }
  persistConfig();
}

function removeSendFolder(id: string) {
  senderFolders.value = senderFolders.value.filter((f) => f.id !== id);
  persistConfig();
}

/** 拖拽添加文件夹（浏览器 fallback 到点击选择；Tauri 原生拖拽由 window 事件处理） */
async function onDropFolders(_e: DragEvent) {
  await addSendFolder();
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

/** 读取本地备份状态（与手机端 JSON 同构），不存在则创建 */
function loadState(): BackupState {
  try {
    const raw = localStorage.getItem(STATE_KEY);
    if (raw) return migrateState(JSON.parse(raw));
  } catch {
    // 损坏 → 重建
  }
  const s = createEmptyState(selfInfo.value.code, selfInfo.value.name);
  saveState(s);
  return s;
}

function saveState(s: BackupState): void {
  try {
    localStorage.setItem(STATE_KEY, JSON.stringify(s));
  } catch (e) {
    // 存储失败不阻断（已完成的备份不应被报成失败）
    logger.warn('device', '保存状态失败（不影响本次备份结果）', e);
  }
}

/** Esc 关闭顶层弹窗：收件/配对请求 = 拒绝，确认弹窗 = 取消（不触发任何破坏性动作） */
function onGlobalEsc(e: KeyboardEvent) {
  if (e.key !== 'Escape') return;
  if (incomingReq.value) acceptIncoming(false);
  else if (pairingReq.value) acceptPairing(false);
  else if (confirmAsk.value) cancelConfirm();
}

onMounted(async () => {
  applyTheme();
  window.addEventListener('keydown', onGlobalEsc);
  /* 初始页激活：去掉 page-off（在首帧绘制前执行，无闪烁） */
  pageRef.value?.querySelector<HTMLElement>(`[data-page="${currentPage.value}"]`)?.classList.remove('page-off');
  syncWallpaper(); /* 中档壁纸 3fps 采样在挂载后启动 */
  // 恢复调试模式开关（默认开启；关闭后不记录日志）
  try {
    const d = localStorage.getItem('desktop_debug');
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
    gsap.to('.glow-blob-1', { x: 100, y: 70, duration: 20, yoyo: true, repeat: -1, ease: 'sine.inOut' });
    gsap.to('.glow-blob-2', { x: -90, y: -60, duration: 24, yoyo: true, repeat: -1, ease: 'sine.inOut' });
  });
  try {
    selfInfo.value = await invoke<{ name: string; id: string; code: string }>('get_self_info');
    deviceNameInput.value = selfInfo.value.name;
  } catch {
    selfInfo.value = { name: 'PC', id: '', code: 'BROWSER-DEV' };
  }
  try {
    await loadAppConfig();
  } catch {
    // 忽略
  }
  // 接收端默认开启：角色为接收端/自由模式 + 开关开启 + 目录已配 → 自动进入接收状态（无需确认）
  if ((role.value === 'receiver' || role.value === 'free') && receiverEnabled.value && autoStartReceiver.value && boxP2c.value && !serverRunning.value) {
    await startServer(boxP2c.value);
  }
  refreshPairings();
  // 连接是显式会话：重启后统一复位为"未连接"（回到状态3），避免陈旧已连接状态不对称
  for (const r of pairMgr.all()) {
    if (r.connected) pairMgr.markConnected(r.fingerprint, false);
  }
  refreshPairings();
  const online = pairings.value.filter((p) => p.online);
  targetDevice.value = online[0] ?? pairings.value[0] ?? null;
  loadState();
  // 后台自动连接：无论本地是否已有配对记录都启动巡检
  // （空记录时也会合并对方记录本机的信任信息，消除信息差）
  startAutoConnect();
  // 断网自动重连 + 暂停任务自动恢复（有暂停任务且对端恢复可达时自动续传）
  autoResume.start();
  loadTransfers();
  // 实时事件监听（useTauriListener 统一管理生命周期，卸载自动清理）：
  // 1) 对方验证本机码成功 → 立即刷新已配对设备
  // 2) 传输进度事件 → 实时刷新进度条
  if (isTauri) {
    try {
      const { listen } = await import('@tauri-apps/api/event');
      track(await listen('paired-updated', () => mergePeers()));
      track(
        await listen('send-progress', (e) => {
          const p = e.payload as {
            sent: number;
            total: number;
            fileName?: string;
            stage?: string;
            bytes?: number;
            elapsedMs?: number;
            bytesSent?: number;
            totalBytes?: number;
          };
          progressInfo.value = p;
          if (p.bytes && p.elapsedMs) {
            lastSendStat.value = { bytes: p.bytes, elapsedMs: p.elapsedMs };
          }
        }),
      );
      // 接收确认弹窗（手机→电脑 prepare-upload）
      track(
        await listen('incoming-request', (e) => {
          incomingReq.value = e.payload as { sessionId: string; count: number; totalBytes: number; senderName: string; senderIp: string };
        }),
      );
      // 配对确认弹窗（对方填写了本机连接码请求配对）
      track(
        await listen('pairing-request', (e) => {
          pairingReq.value = e.payload as { deviceId: string; name: string; ip: string };
        }),
      );
      // 接收完成统计（进度框「备份完成」明细）
      track(
        await listen('receive-complete', (e) => {
          const p = e.payload as { count: number; bytes: number; durationMs: number };
          progressDone.value = { direction: 'in', count: p.count, bytes: p.bytes, durationMs: p.durationMs };
          recvProgress.value = null;
        }),
      );
      // 传输历史变化（发送完成 / 接收会话完成）→ 实时刷新历史列表
      track(
        await listen('transfers-updated', () => {
          loadTransfers();
        }),
      );
      // 接收进度（手机→电脑）：实时显示总量/已传/文件数
      track(
        await listen('receive-progress', (e) => {
          recvProgress.value = e.payload as {
            fileName: string;
            receivedBytes: number;
            totalBytes: number;
            receivedCount: number;
            totalCount: number;
          };
        }),
      );
      // 对方连接本机 → 标记已连接（去抖提示，让被连方实时感知）
      const connectNoticeAt = new Map<string, number>();
      track(
        await listen('peer-connected', (e) => {
          const p = e.payload as { deviceId: string; name: string };
          const rec = pairMgr.byDeviceId(p.deviceId);
          if (rec) {
            const wasConnected = !!rec.connected;
            pairMgr.markOnline(rec.fingerprint, rec.ip, rec.port);
            pairMgr.markConnected(rec.fingerprint, true);
            refreshPairings();
            // 已配对设备穿透隐藏连接：接收服务未运行时自动拉起（断点续传/收件可用）
            if (!serverRunning.value && boxP2c.value) {
              startServer(boxP2c.value);
            }
            const now = Date.now();
            const last = connectNoticeAt.get(rec.fingerprint) || 0;
            if (!wasConnected && now - last > 30000) {
              connectNoticeAt.set(rec.fingerprint, now);
              lastResult.value = `「${rec.name}」已连接本机`;
            }
          }
        }),
      );
      // 对方主动断开连接 → 清除"已连接"状态（回到在线）
      track(
        await listen('peer-disconnected', (e) => {
          const deviceId = (e.payload as { deviceId: string }).deviceId;
          const rec = pairMgr.byDeviceId(deviceId);
          if (rec) {
            pairMgr.markConnected(rec.fingerprint, false);
            refreshPairings();
            lastResult.value = `「${rec.name}」已断开连接`;
          }
        }),
      );
      // 对方解除配对 → 即时删除本地配对
      track(
        await listen('pair-unpaired', (e) => {
          const deviceId = (e.payload as { deviceId: string }).deviceId;
          const rec = pairMgr.byDeviceId(deviceId);
          if (rec) {
            pairMgr.remove(rec.fingerprint);
            rejectCount.delete(rec.fingerprint);
            refreshPairings();
            lastResult.value = `「${rec.name}」已解除与本机的配对`;
          }
        }),
      );
      // 接收服务器异常退出后被 Rust watchdog 自动重启（serverRunning 无感保持 true）
      track(
        await listen('receiver-auto-restart', () => {
          pushToast('ok', '接收服务已自动恢复（曾异常退出）');
        }),
      );
      // 对方确认已收到本机发送的文件（发送回执，让发送方审查同步结果）
      track(
        await listen('file-receipt', (e) => {
          const fileName = (e.payload as { fileName: string }).fileName;
          lastResult.value = `对方已确认接收：${fileName}`;
          loadTransfers();
        }),
      );
      // 拖拽添加文件夹（Tauri 2 原生拖拽事件）
      if (isTauri) {
        try {
          const { getCurrentWindow } = await import('@tauri-apps/api/window');
          unlistenDrag = await getCurrentWindow().onDragDropEvent((event) => {
            if (event.payload.type === 'drop') {
              for (const p of event.payload.paths) {
                const name = p.split(/[\\/]/).filter(Boolean).pop() || '文件夹';
                senderFolders.value.push({ id: genFolderId(), name, path: p, enabled: true });
              }
              persistConfig();
            }
          });
        } catch (e) {
          logger.warn('ui', '拖拽监听失败', e);
        }
      }
    } catch (e) {
      logger.warn('pair', '监听 Tauri 事件失败', e);
    }
  }
});

onUnmounted(() => {
  mm?.revert();
  window.removeEventListener('keydown', onGlobalEsc);
  autoResume.stop();
  if (pollTimer) clearInterval(pollTimer);
  if (pingTimer) clearInterval(pingTimer);
  if (mergeTimer) clearInterval(mergeTimer);
  if (nameSaveTimer) clearTimeout(nameSaveTimer);
  document.removeEventListener('visibilitychange', onVisibilityChange);
  if (unlistenDrag) unlistenDrag();
  if (unsubLog) unsubLog();
});

// ---------- 后台自动连接（配对与连接分离） ----------
// 启动时不广播配对；状态侦测 2 次/秒（只探测可达性），信任同步 10 秒一次。
let autoConnecting = false;
// 误删防抖已移除：配对记录只在显式解除/收到对端解除时删除，绝不因轮询失败自动删除
const rejectCount = new Map<string, number>();
// 失败退避：完全不可达设备降频探测（每 10 轮 ≈5s 一次），成功即恢复 500ms——
// 避免不可达设备每 500ms 触发 1.5s connect 超时占用探测线程
const probeSkip = new Map<string, number>();

async function startAutoConnect() {
  if (autoConnecting) return;
  autoConnecting = true;
  // 本端确认的配对回填后端 paired map（后端 greet 校验依据；重启后自愈）
  await confirmAllPairs();
  await greetAll(true);
  if (pingTimer) clearInterval(pingTimer);
  pingTimer = setInterval(greetAll, 500); // 状态侦测：2 次/秒，无感感知上下线
  if (mergeTimer) clearInterval(mergeTimer);
  mergeTimer = setInterval(async () => {
    await mergePeers();
  }, 10000); // 双端信任同步：10 秒一次足够
  // 后台降级省电：切后台状态侦测降至 5s，回前台恢复 500ms
  document.addEventListener('visibilitychange', onVisibilityChange);
}

// 后台/前台切换：调整状态侦测频率（省电）
function onVisibilityChange() {
  if (pingTimer) clearInterval(pingTimer);
  pingTimer = setInterval(greetAll, document.hidden ? 5000 : 500);
}

// 把本地配对记录全量同步到后端（清空后重建，杜绝解除残留导致的横跳）
async function confirmAllPairs() {
  const peers = pairMgr.all().map((rec) => ({
    deviceId: rec.deviceId,
    name: rec.name,
    ip: rec.ip,
    port: rec.port,
    fingerprint: rec.fingerprint,
  }));
  try {
    await invoke('sync_paired', { peers });
  } catch (e) {
    logger.warn('pair', '同步配对记录到后端失败', e);
  }
}

async function mergePeers() {
  try {
    const peers = await invoke<
      { deviceId: string; name: string; ip: string; port: number; fingerprint: string }[]
    >('get_paired_peers');
    let added = 0;
    for (const p of peers) {
      const existing = pairMgr.byDeviceId(p.deviceId);
      const fp = p.fingerprint || existing?.fingerprint || '';
      if (!fp && !existing) continue;
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
      lastResult.value = `检测到 ${added} 台设备已与本机配对`;
    }
    // 合并到新对端后回填后端，确保对端问候校验通过
    confirmAllPairs();
  } catch (e) {
    logger.warn('pair', '合并双端配对记录失败', e);
  }
}

// 状态侦测（2 次/秒）：verify probe 只查对方是否信任本机，不触发"已连接"；
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
      let reachable = false;
      for (const ip of ips) {
        try {
          const r = await invoke<{ ok: boolean; reason?: string }>('verify_device', {
            ip,
            port: rec.port,
            code: '',
            deviceId: selfInfo.value.id,
            name: selfInfo.value.name,
            myCode: '',
            probe: true,
          });
          reachable = true;
          if (r.ok) {
            pairMgr.markOnline(rec.fingerprint, ip, rec.port);
            pairMgr.rememberIp(rec.fingerprint, ip);
            rejectCount.delete(rec.fingerprint);
            probeSkip.delete(rec.fingerprint);
            ok = true;
            break;
          }
        } catch {
          // 该 IP 不可达，尝试下一个
        }
      }
      if (ok) {
        // 在线且互信
      } else if (reachable) {
        // 对方可达但明确不信任本机 → 判定为已解除配对
        pairMgr.markOffline(rec.fingerprint);
        const n = (rejectCount.get(rec.fingerprint) || 0) + 1;
        rejectCount.set(rec.fingerprint, n);
        if (n >= 5) {
          pairMgr.remove(rec.fingerprint);
          rejectCount.delete(rec.fingerprint);
          // 同步清空后端信任表：否则 mergeTimer 的 mergePeers 会从后端把已解除设备拉回，
          // 造成「已配对 → 对方已解除」无限循环
          confirmAllPairs();
          lastResult.value = `「${rec.name}」已不再与本机配对（对方已解除），已从列表移除`;
        }
      } else {
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

// 连接（显式）：信任校验成功后置为已连接；对方同时收到 peer-connected 同步置位
async function connectPeer(p: PairRecord) {
  const ips = p.ips?.length ? p.ips : [p.ip];
  let ok = false;
  for (const ip of ips) {
    try {
      const r = await invoke<{ ok: boolean; reason?: string }>('verify_device', {
        ip,
        port: p.port,
        code: '',
        deviceId: selfInfo.value.id,
        name: selfInfo.value.name,
        myCode: '',
      });
      if (r.ok) {
        pairMgr.markOnline(p.fingerprint, ip, p.port);
        pairMgr.rememberIp(p.fingerprint, ip);
        pairMgr.markConnected(p.fingerprint, true);
        ok = true;
        break;
      }
    } catch {
      // 尝试下一个 IP
    }
  }
  refreshPairings();
  if (ok) {
    lastResult.value = `已连接：${p.name}`;
  } else {
    pairMgr.markOffline(p.fingerprint);
    errorMsg.value = `连接失败：${p.name}（对方不在线或已解除配对）`;
  }
}

// 断开（显式）：本地清除已连接状态 + 通知对方同步清除（双方回到"在线"）
async function disconnectPeer(p: PairRecord) {
  pairMgr.markConnected(p.fingerprint, false);
  try {
    await invoke('send_disconnect', { ip: p.ip, port: p.port, deviceId: selfInfo.value.id });
  } catch {
    // 对方可能离线；本地已断开
  }
  refreshPairings();
  lastResult.value = `已断开与「${p.name}」的连接`;
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

// ---------- 自动配对（multicast 扫描） ----------
async function startDiscovery() {
  if (scanRunning.value) return;
  errorMsg.value = '';
  try {
    const res = await invoke<string>('start_discovery', { serverPort: 53317 });
    scanRunning.value = true;
    discovered.value = [];
    scanRounds.value = 0;
    scanElapsedSec.value = 0;
    scanStartedAt = Date.now();
    lastResult.value = res;
    pollTimer = setInterval(async () => {
      scanRounds.value++;
      scanElapsedSec.value = Math.round((Date.now() - scanStartedAt) / 1000);
      try {
        const list = await invoke<DiscoveredDevice[]>('get_discovered_devices');
        discovered.value = list;
        for (const d of list) {
          const rec = pairMgr.byDeviceId(d.fingerprint);
          if (rec) {
            // 只记忆新 IP，不置在线：在线状态必须由 verify 探测（greetAll）确认，
            // 扫描到 ≠ 建立通信（否则隐藏设备会被误标在线）
            pairMgr.rememberIp(rec.fingerprint, d.ip);
          }
        }
        refreshPairings();
      } catch (e) {
        logger.error('receiver', '获取发现设备失败', e);
      }
    }, 1500);
  } catch (e) {
    logger.error('receiver', '启动设备发现失败', e);
    errorMsg.value = (e as Error).message;
  }
}

async function stopDiscovery() {
  scanRunning.value = false;
  scanRounds.value = 0;
  scanElapsedSec.value = 0;
  discovered.value = []; // 停止配对后已搜索到的设备消失
  if (pollTimer) clearInterval(pollTimer);
  try {
    await invoke('stop_discovery');
  } catch (e) {
    logger.error('receiver', '停止设备发现失败', e);
  }
}

function onDiscoveredClick(d: DiscoveredDevice) {
  if (pairMgr.byDeviceId(d.fingerprint)) {
    lastResult.value = `「${d.alias}」已配对，无需重新验证`;
    return;
  }
  pairingTarget.value = d;
  codeInput.value = '';
}

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
    const r = await invoke<{ ok: boolean; reason?: string }>('verify_device', {
      ip: t.ip,
      port: t.port,
      code: codeInput.value.trim(),
      deviceId: selfInfo.value.id,
      name: selfInfo.value.name,
      myCode: selfInfo.value.code,
    });
    if (!r.ok) {
      errorMsg.value = r.reason === 'rejected' ? '对方拒绝了配对请求' : '连接码不正确，配对失败';
      return;
    }
    const fp = normalizeCode(codeInput.value);
    pairMgr.upsert({
      fingerprint: fp,
      deviceId: t.fingerprint,
      name: t.alias,
      ip: t.ip,
      port: t.port,
      trustAt: Date.now(),
      online: true,
      lastSeen: Date.now(),
    });
    pairingTarget.value = null;
    codeInput.value = '';
    // 配对成功：立即停止配对扫描并清空发现列表
    stopDiscovery();
    discovered.value = [];
    refreshPairings();
    if (!targetDevice.value) targetDevice.value = pairMgr.byFingerprint(fp) ?? null;
    lastResult.value = `配对成功：${t.alias}`;
    logger.info('pair', `配对成功 alias=${t.alias} ip=${t.ip}`);
    // 立即合并对方记录本机的信任信息（手机端此时已记录电脑）+ 本端回填后端
    mergePeers();
    confirmAllPairs();
  } catch (e) {
    logger.error('pair', '配对验证失败', e);
    errorMsg.value = `配对失败: ${(e as Error).message}`;
  } finally {
    verifying.value = false;
  }
}

function cancelPair() {
  pairingTarget.value = null;
  codeInput.value = '';
}

async function manualPair() {
  if (!manualIp.value.trim() || !manualCode.value.trim()) {
    errorMsg.value = '请填写目标 IP 与连接码';
    return;
  }
  verifying.value = true;
  errorMsg.value = '';
  try {
    const r = await invoke<{ ok: boolean; reason?: string }>('verify_device', {
      ip: manualIp.value.trim(),
      port: manualPort.value,
      code: manualCode.value.trim(),
      deviceId: selfInfo.value.id,
      name: selfInfo.value.name,
      myCode: selfInfo.value.code,
    });
    if (!r.ok) {
      errorMsg.value = r.reason === 'rejected' ? '对方拒绝了配对请求' : '连接码不正确，配对失败';
      return;
    }
    const info = await invoke<PingedDevice>('ping_device', {
      ip: manualIp.value.trim(),
      port: manualPort.value,
    });
    const fp = normalizeCode(manualCode.value);
    pairMgr.upsert({
      fingerprint: fp,
      deviceId: info.fingerprint,
      name: info.alias,
      ip: manualIp.value.trim(),
      port: manualPort.value,
      trustAt: Date.now(),
      online: true,
      lastSeen: Date.now(),
    });
    refreshPairings();
    if (!targetDevice.value) targetDevice.value = pairMgr.byFingerprint(fp) ?? null;
    lastResult.value = `手动配对成功：${info.alias}`;
    logger.info('pair', `手动配对成功 alias=${info.alias} ip=${manualIp.value}`);
    mergePeers();
    confirmAllPairs();
  } catch (e) {
    logger.error('pair', '手动配对失败', e);
    errorMsg.value = `手动配对失败: ${(e as Error).message}`;
  } finally {
    verifying.value = false;
  }
}

/** 手动连接端口校验：失焦钳制到 1-65535（空/非法回默认 53317） */
function clampManualPort() {
  const n = Math.floor(Number(manualPort.value) || 0);
  manualPort.value = n >= 1 && n <= 65535 ? n : 53317;
}

// 解除配对（双端：通知对方删除信任，防单向残留）
async function removePairing(fp: string) {
  const rec = pairMgr.byFingerprint(fp);
  if (rec) {
    // 解除通知重试 3 次：对方短暂不可达也能收到，强制其同步解除（白名单双向生效）
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await invoke('send_unpair', { ip: rec.ip, port: rec.port, deviceId: selfInfo.value.id });
        break;
      } catch (e) {
        if (attempt < 2) await new Promise((r) => setTimeout(r, 1000));
        else logger.warn('pair', '解除配对通知失败（对方可能离线）', e);
      }
    }
  }
  pairMgr.remove(fp);
  rejectCount.delete(fp);
  refreshPairings();
  if (targetDevice.value?.fingerprint === fp) {
    targetDevice.value = pairings.value[0] ?? null;
  }
  // 同步清空后端信任表：否则 mergePeers 会从后端把已解除设备拉回，造成状态反复跳动
  await confirmAllPairs();
  lastResult.value = '已解除配对';
}

// ---------- 备份盒子 ----------
async function pickBoxP2c() {
  const dir = await openDirectory();
  if (dir) {
    boxP2c.value = dir;
    receiverEnabled.value = true; // 选择接收目录即启用接收端
    lastResult.value = `接收目录：${dir}`;
    // 切换接收目录时自动重启接收服务器（Rust 端已支持先停旧实例再以新目录启动）
    if (serverRunning.value) await stopServer();
    await startServer(dir);
    persistConfig();
  }
}

/** 发送文件夹：多选添加（多目录聚合发送） */
async function pickBoxC2p() {
  await addSendFolder();
}

function selectTarget(p: PairRecord) {
  targetDevice.value = { ...p };
  // 加载该设备的同步策略与对端缺失列表
  const state = loadState();
  const device = getOrCreateDevice(state, p.fingerprint, p.name);
  syncStrategy.value = device.syncStrategy;
  persistConfig();
}

// ---------- 接收服务器 ----------
async function startServer(receiveDir: string) {
  if (scanning.value) return;
  if (!receiveDir) {
    errorMsg.value = '请先选择「手机→电脑」接收目录';
    return;
  }
  scanning.value = true;
  errorMsg.value = '';
  lastResult.value = '';
  try {
    const res = await invoke<string>('start_receiver', { receiveDir, port: 53317 });
    serverRunning.value = true;
    serverPort.value = 53317;
    lastResult.value = res;
  } catch (e) {
    logger.error('receiver', '启动接收服务器失败', e);
    errorMsg.value = (e as Error).message;
  } finally {
    scanning.value = false;
  }
}

async function stopServer() {
  try {
    await invoke('stop_receiver');
    serverRunning.value = false;
    lastResult.value = '收件服务已停止';
  } catch (e) {
    logger.error('receiver', '停止接收服务器失败', e);
    errorMsg.value = (e as Error).message;
  }
}

/** 手动取消收件：停止接收服务（中断当前会话）并清空进度 */
async function cancelReceive() {
  recvProgress.value = null;
  if (serverRunning.value) await stopServer();
  lastResult.value = '已取消收件';
}

// ---------- 发送 ----------
async function sendAllFolders(): Promise<number> {
  const state = loadState();
  const device = getOrCreateDevice(state, targetDevice.value!.fingerprint, targetDevice.value!.name);
  device.syncStrategy = syncStrategy.value;
  // 唤醒对端接收服务：连接问候（非 probe）触发对端 peer-connected → 自动拉起其接收服务器，
  // 然后等接收端口可连（对端拉起需 1-2s；就绪前查清单会拿到空清单 → 误判全量重传 + 冲突重命名）
  try {
    await greetPeer(targetDevice.value!.ip, targetDevice.value!.port);
    for (let i = 0; i < 8; i++) {
      try {
        if (await invoke<boolean>('probe_peer_port', { ip: targetDevice.value!.ip, port: targetDevice.value!.port })) break;
      } catch {
        // 探测命令异常按未就绪处理
      }
      await new Promise((r) => setTimeout(r, 500));
    }
  } catch {
    // 对端离线：由后续 send_files 的唤醒与报错兜底
  }
  // 多目录聚合：每个发送文件夹扫描 + 根目录名前缀，合并后一次三路对比
  const allFiles: { relPath: string; size: number; mtime: number }[] = [];
  const absByRel = new Map<string, string>();
  for (const f of senderFolders.value) {
    if (!f.enabled) continue;
    const rootName = f.name || f.path.split(/[\\/]/).filter(Boolean).pop() || 'folder';
    const scanned = await invoke<{ relPath: string; size: number; mtime: number }[]>('scan_directory', {
      dir: f.path,
    });
    // 发送根目录名作为 relPath 第一级：接收端在接收目录下重建「发送文件夹名/...」结构
    for (const item of scanned) {
      const rel = `${rootName}/${item.relPath}`;
      allFiles.push({ relPath: rel, size: item.size, mtime: item.mtime });
      absByRel.set(rel, `${f.path}/${item.relPath}`);
    }
  }
  if (allFiles.length === 0) return 0;
  // 三路对比增量：A当前(本次扫描) vs A上次(lastManifest) vs B当前(对端清单)
  let peer: PeerManifest | null = null;
  try {
    peer = await invoke<PeerManifest>('get_peer_manifest', {
      ip: targetDevice.value!.ip,
      port: targetDevice.value!.port,
    });
  } catch {
    peer = null; // 对端清单获取失败 → 退化为两路对比，不阻断
  }
  const plan = planIncremental(allFiles, device.lastManifest, peer, device.syncStrategy, device.knownMissingOnPeer);
  // 更新对端缺失列表（即使无事可传，也要反映当前实际缺失状态）
  device.knownMissingOnPeer = plan.missingOnPeer;
  // 镜像模式：对端多余文件移动到其 delete 文件夹（假删除，保持目录一致）。
  // P0 披露：移动对端文件前必须确认；取消则只跳过清理，正常传输不受影响
  if (device.syncStrategy === 'mirror' && plan.peerExtra.length > 0) {
    mirrorConfirming.value = true;
    try {
      const ok = await askConfirmAsync({
        title: '镜像模式确认',
        message: `即将把「${targetDevice.value!.name}」上 ${plan.peerExtra.length} 个多余文件移入其 delete 文件夹。`,
        danger: true,
      });
      if (ok) {
        try {
          await invoke('move_to_delete', { ip: targetDevice.value!.ip, port: targetDevice.value!.port, files: plan.peerExtra });
        } catch (e) {
          logger.warn('sync', '镜像模式移动多余文件失败', e);
        }
      } else {
        lastResult.value = `已跳过镜像清理：${plan.peerExtra.length} 个多余文件保留在对端`;
      }
    } finally {
      mirrorConfirming.value = false;
    }
  }
  if (plan.toTransfer.length === 0) {
    saveState(state);
    return 0;
  }
  // 传输 relPath 带发送根目录名前缀；本地读取用各文件夹原始路径（absByRel 映射）
  const files = plan.toTransfer.map((f) => ({
    relPath: f.relPath,
    absPath: absByRel.get(f.relPath) || '',
  }));
  const sent = await invoke<number>('send_files', {
    targetIp: targetDevice.value!.ip,
    targetPort: targetDevice.value!.port,
    targetCode: targetDevice.value!.fingerprint,
    files,
  });
  const newManifest = buildManifest(allFiles);
  markBackupDone(state, targetDevice.value!.fingerprint, newManifest, Date.now());
  saveState(state);
  return sent;
}

// ---------- 执行备份 ----------
async function runBackup() {
  if (scanning.value) return;
  const t = targetDevice.value;
  if (!t) {
    errorMsg.value = '请先在「设备」页完成连接，并在「同步」页选择目标设备';
    return;
  }
  const hasSend = senderFolders.value.some((f) => f.enabled);
  const hasRecv = receiverEnabled.value && !!boxP2c.value;
  if (!hasRecv && !hasSend) {
    errorMsg.value = '请至少配置一个备份方向（接收目录或发送文件夹）';
    return;
  }
  errorMsg.value = '';
  lastResult.value = '';
  progressInfo.value = null;
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
    logger.info('ui', `开始同步: 对象=${t.name}(${t.ip}:${t.port}) 接收=${hasRecv ? boxP2c.value : '无'} 源=${senderFolders.value.filter((f) => f.enabled).map((f) => f.name).join(',') || '无'}`);
    // 接收方向：启动接收服务器（仅在未运行时启动，避免重启中断正在接收的文件）
    if (hasRecv && !serverRunning.value) {
      await startServer(boxP2c.value);
      if (errorMsg.value) {
        failTask(task.id, errorMsg.value);
        activeTaskId.value = '';
        return;
      }
    }
    // 发送方向：多文件夹聚合推送到手机
    if (hasSend) {
      scanning.value = true;
      const sent = await sendAllFolders();
      scanning.value = false;
      completeTask(task.id);
      activeTaskId.value = '';
      progressDone.value = {
        direction: 'out',
        count: sent,
        bytes: lastSendStat.value.bytes,
        durationMs: lastSendStat.value.elapsedMs,
      };
      lastResult.value =
        serverRunning.value
          ? `已向 ${t.name} 推送 ${sent} 个文件；接收服务器运行中（端口 ${serverPort.value}）`
          : `已向 ${t.name} 推送 ${sent} 个文件`;
    }
  } catch (e) {
    // 网络类错误 → 暂停任务（断网自动重连 + 恢复按钮可续传）；其他错误 → 失败（重试按钮）
    activeTaskId.value = '';
    logger.error('ui', '备份执行失败', e);
    const msg = (e as Error).message || String(e);
    if (/prepare-upload|register|error sending request|Failed to fetch|network/i.test(msg)) {
      pauseTask(task.id, msg);
      errorMsg.value = `同步失败（${msg}）。请确认目标端已启用接收并保持发现服务运行。`;
    } else {
      failTask(task.id, msg);
      errorMsg.value = `同步失败：${msg}`;
    }
  } finally {
    scanning.value = false;
  }
  loadTransfers(); // 同步结束后刷新传输历史
}

// ---------- 设置 ----------
// 设备名：输入后自动保存（去抖 800ms），失焦立即保存；清空则回退当前名
watch(deviceNameInput, (v) => {
  const name = v.trim();
  if (!name || name === selfInfo.value.name) return;
  if (nameSaveTimer) clearTimeout(nameSaveTimer);
  nameSaveTimer = setTimeout(() => saveDeviceName(name), 800);
});

function flushDeviceName() {
  if (nameSaveTimer) clearTimeout(nameSaveTimer);
  const name = deviceNameInput.value.trim();
  if (!name) {
    deviceNameInput.value = selfInfo.value.name;
    return;
  }
  if (name !== selfInfo.value.name) saveDeviceName(name);
}

async function saveDeviceName(name: string) {
  try {
    await invoke('set_self_name', { name });
    selfInfo.value.name = name;
    lastResult.value = `设备名已更新：${name}`;
    logger.info('device', `设备名更新为 ${name}`);
  } catch (e) {
    logger.error('device', '保存设备名失败', e);
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
    const code = await invoke<string>('refresh_self_code');
    selfInfo.value.code = code;
    lastResult.value = `连接码已刷新：${code}。旧码已失效，已配对设备需重新连接。`;
    logger.info('device', '本机设备码已刷新');
  } catch (e) {
    errorMsg.value = `重置连接码失败: ${(e as Error).message}`;
  }
}

// 扫描模式已移除：增量同步自动对比两端清单（见 shared-core sync.ts）

async function exportLogs() {
  errorMsg.value = '';
  try {
    const path = await invoke<string>('export_logs', { extraLines: logger.export() });
    lastResult.value = `日志已导出：${path}`;
  } catch (e) {
    logger.error('debug', '导出日志失败', e);
    errorMsg.value = `导出日志失败: ${(e as Error).message}`;
  }
}

// 日志预览：可滚动、可复制
function openLogPreview() {
  logPreviewText.value = logger.export();
  showLogPreview.value = true;
}

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

async function copyLogPreview() {
  try {
    await navigator.clipboard.writeText(logPreviewText.value);
    lastResult.value = '日志已复制到剪贴板';
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
      lastResult.value = '日志已复制到剪贴板';
    } catch {
      errorMsg.value = '复制失败，请手动选择复制';
    }
  }
}

// 清空日志缓冲与统计（二级确认弹窗）
function clearLogs() {
  askConfirm({
    title: '清空日志',
    message: `将清空全部 ${logger.size()} 条日志与统计。`,
    danger: true,
    action: () => {
      logger.clear();
      debugSummary.value = logger.summary();
      lastResult.value = '日志已清空';
    },
  });
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
  <!-- 窗口裁切容器：壁纸/纱罩/光斑全部裁进整窗圆角。
       （fixed 子元素不受 body 的 overflow 裁切，必须集中到同一容器内裁） -->
  <div class="window-clip" aria-hidden="true">
    <div class="window-bg"></div>
    <video class="wallpaper-video" src="/wallpaper.webm" autoplay muted loop playsinline></video>
    <div class="glow-blob glow-blob-1"></div>
    <div class="glow-blob glow-blob-2"></div>
  </div>

  <!-- 全局液态玻璃折射滤镜（#glass-distortion） -->
  <GlassFilters />

  <!-- 自绘悬浮滚动条（主页面已隐藏原生滚动条） -->
  <GlassScrollbar />

  <!-- 液态玻璃标题栏：标题 + 窗口控制；整条栏可拖动（按钮除外），分界线之下不可拖动 -->
  <header class="titlebar" @mousedown="onHeaderDrag">
    <h1>局域网备份</h1>
    <div class="titlebar-actions">
      <button class="win-btn" :title="darkMode ? '切换到浅色' : '切换到深色'" :aria-label="darkMode ? '切换到浅色' : '切换到深色'" @click="darkMode = !darkMode">{{ darkMode ? '🌙' : '☀️' }}</button>
      <button class="win-btn" aria-label="最小化" title="最小化" @click="appWin.minimize()"><span class="g-min" aria-hidden="true"></span></button>
      <button class="win-btn close" aria-label="关闭" title="关闭" @click="appWin.close()"><span class="g-x" aria-hidden="true"></span></button>
    </div>
  </header>

  <div class="app-shell">
    <!-- 连接码行：普通内容区（不可拖动），点击连接码即复制 -->
    <div class="app-codebar">
      <button class="code-copy" title="点击复制连接码" aria-label="点击复制连接码" @click="copyText(selfInfo.code, '连接码已复制')">
        连接码：<strong class="self-code">{{ selfInfo.code }}</strong>
      </button>
      <button class="mini-btn" title="重置连接码" aria-label="重置连接码" @click="refreshSelfCode2">
        <svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><path d="M13.5 8a5.5 5.5 0 1 1-1.62-3.9" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M12.3 1.6v2.9H9.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </button>
      <span class="header-name">{{ selfInfo.name || '本机' }}</span>
    </div>

    <!-- 消息队列：多条提示堆叠显示，互不遮挡 -->
    <div class="toast-stack" role="status" aria-live="polite">
      <TransitionGroup name="toast-drop" tag="div">
        <p v-for="t in toasts" :key="t.id" class="toast" :class="{ error: t.kind === 'error' }">{{ t.text }}</p>
      </TransitionGroup>
    </div>

    <main class="pages">
      <div class="page" ref="pageRef">
      <!-- ========== 设备页 ========== -->
      <section class="page-inner page-off" :data-page="'devices'">
        <!-- 配对（自动 / 手动 合一，按方式切换） -->
        <LiquidGlass :corner-radius="26" padding="16px 18px">
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
            <p class="muted mt-xs">两端都点击「开始发现」，即可互相找到对方（只广播设备名，不暴露连接码）</p>
            <div class="row">
              <button v-if="!scanRunning" class="glass-btn primary" @click="startDiscovery">开始发现</button>
              <button v-else class="glass-btn danger" @click="stopDiscovery">停止发现</button>
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
            <p class="muted mt-xs">已知对方 IP / 端口 / 连接码时，直接连接</p>
            <IpBoxes v-model="manualIp" label="对方 IP" />
            <input class="glass-input" v-model.number="manualPort" type="number" min="1" max="65535" placeholder="端口（默认 53317）" @blur="clampManualPort" />
            <CodeBoxes v-model="manualCode" label="对方连接码" @keyup.enter="manualPair" />
            <button class="glass-btn primary" :disabled="verifying" @click="manualPair">{{ verifying ? '验证中...' : '连接设备' }}</button>
              </div>
            </div>
          </div>
        </LiquidGlass>

        <!-- 已配对设备（三状态：已连接 / 在线 / 离线；另有 疑似离线 软过期提示） -->
        <LiquidGlass :corner-radius="26" padding="16px 18px">
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

      </section>

      <!-- ========== 同步页（主页：状态总览 + 收发配置） ========== -->
      <section class="page-inner page-off" :data-page="'backup'">
        <!-- 本机状态总览 -->
        <LiquidGlass :corner-radius="26" padding="20px 18px">
          <div class="status-head">
            <h2 class="glass-card-title" style="margin: 0">本机状态</h2>
            <span class="status-chip" :class="{ on: serverRunning }">{{ serverRunning ? '收件服务运行中' : '收件服务已停止' }}</span>
          </div>
          <div class="role-seg" role="group" aria-label="同步方向（可多选）">
            <button class="glass-chip" :class="{ on: role === 'receiver' || role === 'free' }" :aria-pressed="role === 'receiver' || role === 'free'" @click="toggleRoleDir('receive')">📥 收件</button>
            <button class="glass-chip" :class="{ on: role === 'sender' || role === 'free' }" :aria-pressed="role === 'sender' || role === 'free'" @click="toggleRoleDir('send')">📤 发件</button>
          </div>
          <div class="status-grid">
            <div class="status-cell" :class="{ off: !serverRunning }">
              <span class="status-cell-label">收件服务</span>
              <span class="status-cell-value"><span class="status-dot" :class="{ on: serverRunning }"></span>{{ serverRunning ? '运行中' : '已停止' }}</span>
              <span class="status-cell-sub">{{ serverRunning ? '端口 ' + serverPort : '未开启 · 见收件区配置' }}</span>
            </div>
            <div class="status-cell" :class="{ off: !targetDevice }">
              <span class="status-cell-label">目标设备</span>
              <span class="status-cell-value">{{ targetDevice ? targetDevice.name : '未选择' }}</span>
              <span class="status-cell-sub">{{ targetDevice ? pairStatus(targetDevice) : '在下方选择目标设备' }}</span>
            </div>
          </div>
          <p v-if="lastSyncText" class="last-sync">{{ lastSyncText }}</p>
        </LiquidGlass>

        <!-- 同步操作（常驻首屏：目标 + 策略 + 立即同步，3 秒内回答「点哪个按钮开始同步」） -->
        <LiquidGlass v-if="role === 'sender' || role === 'free'" key="sync-action" :corner-radius="26" padding="20px 18px">
          <div class="status-head">
            <h2 class="glass-card-title" style="margin: 0">开始同步</h2>
            <span class="status-chip" :class="{ on: syncReady }">{{ syncReady ? '就绪' : '未就绪' }}</span>
          </div>
          <div class="dd" :class="{ open: targetDropdownOpen }" @click.stop>
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

          <GlassSeg
            v-model="syncStrategy"
            label="同步策略"
            :options="[
              { id: 'archive', label: '增量' },
              { id: 'mirror', label: '镜像' },
            ]"
            class="mt-md"
          />
          <p v-if="syncStrategy === 'mirror'" class="mirror-hint">镜像：对端多余文件将被移入其 delete 文件夹</p>
          <button
            class="glass-btn primary run-btn"
            :class="{ ready: syncReady }"
            @click="runBackup"
            :disabled="scanning || !syncReady"
          >
            {{ scanning ? '同步进行中...' : '立即同步' }}
          </button>
          <p class="run-hint">{{ runHintText }}</p>
        </LiquidGlass>

        <!-- 收件区/发件区配置：与历史记录同款 TransitionGroup 排列（lg-list 进出场 + 高度收拢离场） -->
        <TransitionGroup name="lg-list" tag="div" class="card-list" @leave="cardListLeave">
        <LiquidGlass v-if="role === 'receiver' || role === 'free'" key="recv-card" :corner-radius="26" padding="16px 18px">
          <div class="recv-header" @click="toggleRecvPanel">
            <span class="status-dot" :class="{ on: recvDot === 'on' }"></span>
            <h2 class="glass-card-title" style="margin: 0; flex: 1">📥 收件区配置</h2>
            <button class="glass-btn small" @click.stop="toggleRecvPanel">{{ recvPanelCollapsed ? '展开' : '折叠' }}</button>
          </div>
          <div class="panel-collapse" :class="{ closed: recvPanelCollapsed }">
            <div class="panel-collapse-inner">
              <p class="muted">收件目录（保存对方推送的文件）</p>
              <div class="root-row" :class="{ checked: boxP2c }" role="button" tabindex="0" @click="pickBoxP2c" @keydown.enter.prevent="pickBoxP2c">
                <span class="root-check">{{ boxP2c ? '✓' : '＋' }}</span>
                <span class="root-name">{{ boxP2c ? boxP2c : '选择收件目录' }}</span>
              </div>
              <div class="row mt-md">
                <span class="muted" style="margin: 0; flex: 1">收件服务</span>
                <button v-if="serverRunning" class="glass-btn small danger" @click="oneClickCloseReceive">一键关闭</button>
                <button v-else-if="receiverEnabled && recvStarting" class="glass-btn small" disabled>启用中…</button>
                <button v-else class="glass-btn small primary" @click="oneClickReceive">一键开启</button>
              </div>
            </div>
          </div>
        </LiquidGlass>

        <!-- 发件区配置（发件 / 双向），默认折叠：仅文件夹管理，同步入口常驻上方「开始同步」卡 -->
        <LiquidGlass v-if="role === 'sender' || role === 'free'" key="send-card" :corner-radius="26" padding="16px 18px">
          <div class="recv-header" @click="toggleSendPanel">
            <span class="status-dot" :class="{ on: sendDot === 'on' }"></span>
            <h2 class="glass-card-title" style="margin: 0; flex: 1">📤 发件区配置</h2>
            <span class="folder-count">{{ sendFolderCount }}/{{ senderFolders.length }} 个文件夹</span>
            <button class="glass-btn small" @click.stop="toggleSendPanel">{{ sendPanelCollapsed ? '展开' : '折叠' }}</button>
          </div>
          <div class="panel-collapse" :class="{ closed: sendPanelCollapsed }">
            <div class="panel-collapse-inner">
              <p class="muted">发件内容（本机文件夹，可添加多个）</p>
              <TransitionGroup name="lg-list" tag="div" class="device-list" @leave="listLeave">
                <div v-for="f in senderFolders" :key="f.id" class="paired-row">
                  <span class="status-dot" :class="{ on: f.enabled }"></span>
                  <div class="device-main">
                    <strong>{{ f.name }}</strong>
                    <span class="muted" style="margin: 0">{{ f.path }}</span>
                  </div>
                  <button class="glass-btn small" @click="toggleSendFolder(f.id)">{{ f.enabled ? '禁用' : '启用' }}</button>
                  <button class="glass-btn small danger" title="移除文件夹" @click="removeSendFolder(f.id)">✕</button>
                </div>
              </TransitionGroup>
              <div
                class="drop-zone mt-xs"
                role="button"
                tabindex="0"
                @click="addSendFolder"
                @keydown.enter.prevent="addSendFolder"
                @dragover.prevent
                @drop.prevent="onDropFolders"
              >
                <span>＋ 点击选择文件夹（可多选）或拖拽到此处</span>
              </div>
            </div>
          </div>
        </LiquidGlass>
        </TransitionGroup>

        <!-- 进度（发件 / 收件） -->
        <Transition name="fade-slide" mode="out-in">
          <LiquidGlass v-if="scanning" key="progress" :corner-radius="26" padding="16px 18px">
            <h2 class="glass-card-title">{{ mirrorConfirming ? '等待确认...' : '同步进行中...' }}</h2>
            <div class="progress-top">
              <span class="percent-num">{{ sendProgressPct }}%</span>
              <span v-if="progressInfo && progressInfo.bytes && progressInfo.elapsedMs" class="muted" style="margin: 0">{{ fmtRate(progressInfo.bytes, progressInfo.elapsedMs) }} · 剩余 {{ fmtRemain(progressInfo) }}</span>
            </div>
            <div
              class="progress-track"
              role="progressbar"
              aria-label="同步进度"
              aria-valuemin="0"
              aria-valuemax="100"
              :aria-valuenow="sendProgressPct"
            >
              <div
                class="progress-fill"
                :class="{ indeterminate: !progressInfo }"
                :style="
                  progressInfo
                    ? { transform: 'scaleX(' + (progressInfo.totalBytes && progressInfo.bytesSent !== undefined ? progressInfo.bytesSent / progressInfo.totalBytes : progressInfo.sent / Math.max(1, progressInfo.total)) + ')' }
                    : undefined
                "
              ></div>
            </div>
            <p v-if="progressInfo" class="muted">
              正在发送：{{ progressInfo.fileName || '...' }}（{{ progressInfo.sent }}/{{ progressInfo.total }} 个文件）
              <template v-if="progressInfo.bytesSent !== undefined && progressInfo.totalBytes">
                · {{ fmtBytes(progressInfo.bytesSent) }} / {{ fmtBytes(progressInfo.totalBytes) }}
                <template v-if="progressInfo.bytes && progressInfo.elapsedMs">
                  · {{ fmtRate(progressInfo.bytes, progressInfo.elapsedMs) }} · 剩余 {{ fmtRemain(progressInfo) }}
                </template>
              </template>
              <template v-else-if="progressInfo.bytes && progressInfo.elapsedMs">
                · {{ fmtRate(progressInfo.bytes, progressInfo.elapsedMs) }}
              </template>
            </p>
            <p v-else class="muted">正在扫描 / 启动同步，请稍候...</p>
          </LiquidGlass>
          <LiquidGlass v-else-if="recvProgress" key="recv" :corner-radius="26" padding="16px 18px">
            <h2 class="glass-card-title">收件中...</h2>
            <div class="progress-top">
              <span class="percent-num">{{ recvProgress.totalBytes ? Math.min(100, Math.round((recvProgress.receivedBytes / recvProgress.totalBytes) * 100)) : 0 }}%</span>
              <span class="muted" style="margin: 0">{{ recvProgress.receivedCount }}/{{ recvProgress.totalCount }} 个文件</span>
            </div>
            <div
              class="progress-track"
              role="progressbar"
              aria-label="收件进度"
              aria-valuemin="0"
              aria-valuemax="100"
              :aria-valuenow="recvProgress.totalBytes ? Math.min(100, Math.round((recvProgress.receivedBytes / recvProgress.totalBytes) * 100)) : 0"
            >
              <div
                class="progress-fill"
                :style="{ transform: 'scaleX(' + (recvProgress.totalBytes ? recvProgress.receivedBytes / recvProgress.totalBytes : 0) + ')' }"
              ></div>
            </div>
            <p class="muted">
              {{ recvProgress.fileName }} · {{ recvProgress.receivedCount }}/{{ recvProgress.totalCount }} 个文件 ·
              {{ fmtBytes(recvProgress.receivedBytes) }} / {{ fmtBytes(recvProgress.totalBytes) }}
            </p>
            <div class="row mt-xs">
              <button class="glass-btn small danger" @click="cancelReceive">取消收件</button>
            </div>
          </LiquidGlass>
        </Transition>

        <!-- 同步任务列表（任务化暂停/恢复：断网暂停，恢复时跳过已完成文件续传） -->
        <LiquidGlass v-if="tasks.length" :corner-radius="26" padding="16px 18px">
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
                <button class="glass-btn small" title="移除任务记录" @click="removeTask(t.id)">✕</button>
              </div>
            </div>
          </div>
        </LiquidGlass>

        <!-- 同步完成统计 -->
        <LiquidGlass v-if="progressDone" key="done" :corner-radius="26" padding="16px 18px">
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
        <LiquidGlass :corner-radius="26" padding="16px 18px">
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
                    <div v-for="t in g.items" :key="t.id" class="paired-row">
                      <div class="device-main">
                        <strong><span class="hist-dir">{{ t.direction === 'out' ? '发送' : '接收' }}</span> · {{ t.fileCount }} 个文件 · {{ fmtBytes(t.bytes) }}</strong>
                        <span class="muted hist-sub" style="margin: 0">{{ (t.durationMs / 1000).toFixed(1) }} 秒<template v-if="t.durationMs > 0 && t.bytes > 0"> · {{ fmtRate(t.bytes, t.durationMs) }}</template></span>
                        <span class="muted hist-sub" style="margin: 0">{{ new Date(t.createdAt).toLocaleString() }}</span>
                      </div>
                      <button class="glass-btn small" title="删除这条记录" @click="deleteTransfer(t.id)">✕</button>
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
        <LiquidGlass :corner-radius="26" padding="16px 18px">
          <h2 class="glass-card-title">设备信息</h2>
          <p class="muted">本机公开标识：{{ selfInfo.id ? selfInfo.id.slice(0, 8) + '…' : '' }}</p>
          <input class="glass-input" v-model="deviceNameInput" placeholder="设备名（如 PC 1）" @blur="flushDeviceName" />
          <p class="muted">输入后自动保存；重置连接码请点顶部连接码旁的 ↻</p>
          <div class="row mt-xs">
            <span class="muted" style="margin: 0; flex: 1">启动时自动开启收件</span>
            <GlassSwitch :model-value="autoStartReceiver" label="启动时自动开启收件" @update:model-value="toggleAutoStartReceiver" />
          </div>
        </LiquidGlass>

        <LiquidGlass :corner-radius="26" padding="16px 18px">
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

        <LiquidGlass :corner-radius="26" padding="16px 18px">
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

        <LiquidGlass :corner-radius="26" padding="16px 18px">
          <h2 class="glass-card-title">关于</h2>
          <div class="about-dev">
            <img class="dev-avatar" src="/avatar.jpg" alt="HIMKUG" />
            <div class="dev-info">
              <strong>开发者：HIMKUG</strong>
              <a href="https://space.bilibili.com/401121508" target="_blank" rel="noreferrer">哔哩哔哩主页 ↗</a>
            </div>
          </div>
          <p class="muted mt-xs">局域网备份工具 · 版本 0.1.0</p>
        </LiquidGlass>
      </section>
        </div>
    </main>

    <!-- 接收确认弹窗（手机→电脑 prepare-upload） -->
    <div v-if="incomingReq" class="incoming-overlay" role="dialog" aria-modal="true" aria-label="收件请求">
      <div class="incoming-card">
        <h3 class="glass-card-title">收件请求</h3>
        <p class="muted">来自「{{ incomingReq.senderName || incomingReq.senderIp }}」请求发送 {{ incomingReq.count }} 个文件</p>
        <p class="muted">共 {{ fmtBytes(incomingReq.totalBytes) }}，是否同意接收？</p>
        <div class="row mt-md">
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
        <div class="row mt-md">
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
    <GlassDock v-model="currentPage" :tabs="dockTabs" :status-title="dockStatusTitle" :status-sub="dockStatusSub" :status-on="serverRunning">
      <template #panel>
        <h3 class="dock-panel-title">本机状态</h3>
        <div class="dock-panel-grid">
          <div class="dock-kv"><span>角色</span><strong>{{ roleName }} · {{ roleDesc }}</strong></div>
          <div class="dock-kv"><span>收件服务</span><strong>{{ serverRunning ? '运行中 · 端口 ' + serverPort : '已停止' }}</strong></div>
          <div class="dock-kv"><span>目标设备</span><strong>{{ targetDevice ? targetDevice.name : '未选择' }}</strong></div>
          <div class="dock-kv code-kv" role="button" tabindex="0" title="点击复制连接码" @click="copyText(selfInfo.code || '', '连接码已复制')" @keydown.enter="copyText(selfInfo.code || '', '连接码已复制')"><span>连接码</span><strong class="self-code">{{ selfInfo.code || '—' }}</strong></div>
        </div>
        <p v-if="lastSyncText" class="dock-panel-sync">{{ lastSyncText }}</p>
        <div class="dock-visibility">
          <div class="dock-visibility-info">
            <strong>{{ serverRunning ? '本机可见中' : '未配对设备无法发现本机' }}</strong>
            <small>{{ serverRunning ? '局域网内设备可以发现并向你推送文件' : '未配对设备无法发现本机；已配对设备仍可连接' }}</small>
          </div>
          <button class="glass-btn small" :class="{ danger: serverRunning }" @click="toggleService">{{ serverRunning ? '设为隐藏' : '设为可见' }}</button>
        </div>
      </template>
    </GlassDock>
  </div>
</template>
