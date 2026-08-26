<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted, reactive } from 'vue';
import { gsap } from 'gsap';
import { CodeBoxes, GlassDock, GlassFilters, GlassModal, GlassScrollbar, GlassSeg, GlassSwitch, IpBoxes, LiquidGlass, AppIcon, installGlowHover, setBlurInterval, useAutoResume, useSyncTasks, type SyncTask } from 'shared-ui';
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
  DiscoveryManager,
  normalizeCode,
  type BackupState,
  type PeerManifest,
  type PairRecord,
  type PairingStorage,
  type SyncStrategy,
  type DeviceRole,
  type SendFolder,
  type AppConfig,
  type DiscoveredDevice,
  normalizeConfig,
  genFolderId,
  logger,
} from 'shared-core';

// 启动探针（性能优化：默认关闭）。诊断启动卡顿时改为 true 重新构建，
// 探针点保留在代码中无需重写；与 Rust 端 PROBE_ENABLED（lib.rs）共用时间线，
// 输出 %TEMP%\tauri_debug_log.txt。
const ENABLE_FE_PROBE = false;

// Tauri 命令封装（在浏览器环境降级）
const isTauri = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

function feProbe(msg: string) {
  if (!ENABLE_FE_PROBE || !isTauri) return;
  invoke('fe_probe', { msg }).catch(() => {});
}

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (isTauri) {
    const { invoke } = await import('@tauri-apps/api/core');
    return invoke<T>(cmd, args);
  }
  throw new Error('当前不在 Tauri 环境，无法调用后端命令');
}

// ---------- 悬浮球表情驱动（现代化行为化：App 只发「状态语义」，球端行为机自演） ----------
// 兜底单脸表：仅在行为机不可用时降级（正常走 ball_set_state → 球端脚本）
const BALL_FACE_FALLBACK: Record<string, string> = {
  boot: '05', idle: '02', lonely: '12', syncing: '32',
  receiving: '31', success: '10', failure: '21',
  discovering: '40', found: '03', pairing: '37', solving: '30', loading: '05',
  scanning: '35',
  // 一次性提示类（兜底单脸）
  toast_confused: '11', toast_surprise: '13', toast_shy: '14',
  toast_satisfied: '19', toast_puzzled: '20', toast_online: '36',
  toast_denied: '38', toast_reply: '39', toast_listen: '35', toast_stop: '41',
};
/** 持续态（不自动回落闲置）：由球端脚本自行收尾 */
const BALL_PERSISTENT = new Set(['syncing', 'receiving', 'success', 'failure', 'idle']);
/** 发现态（scanning/discovering）：进入后由发现流程自行在适当时机收回，不依赖 30s 回落 */
let ballIdleTimer: ReturnType<typeof setTimeout> | null = null;
/** 已发过「发现到设备」标记（0→>0 时只喷一次） */
let ballFoundEmitted = false;

/**
 * 向悬浮球发出一个「状态」。
 * 主路径：invoke ball_set_state → ball 行为机按脚本演出（交替/循环/随机/定时）。
 * 兜底：若行为机不可用，回退到单个表情 id。
 */
function emitBall(state: keyof typeof BALL_FACE_FALLBACK & string, _tips?: string) {
  if (!isTauri) return;
  invoke('ball_set_state', { state }).catch(() => {
    // 兜底：指令失败时直接推单表情 id
    const id = BALL_FACE_FALLBACK[state];
    if (id) invoke('ball_emit_emotion', { emotionId: id, tips: _tips ?? '' }).catch(() => {});
  });
  // 30s 闲置回落：非持续态若无新状态，则回到 idle（=休眠随机组）。持续态(同步/接收/完成/失败/闲置)不干预
  if (BALL_PERSISTENT.has(state)) {
    if (state === 'idle' && ballIdleTimer) { clearTimeout(ballIdleTimer); ballIdleTimer = null; }
  } else {
    if (ballIdleTimer) clearTimeout(ballIdleTimer);
    ballIdleTimer = setTimeout(() => emitBall('idle'), 30000);
  }
}

/* 无可用目标/未连接 → 悬浮球「落寞/无奈」提示（配对数归零且不在扫描/同步时触发）
   注意：必须放在 pairings 声明之后，否则 Vue 首次求值 getter 触发 TDZ */
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
// DiscoveredDevice is now imported from shared-core (has connected?, paired, lastSeen fields)

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
/** 连接状态管理器：将 peer-connected/disconnected 事件同步到 discovered 列表 */
const discovery = new DiscoveryManager(new Set(), {
  onDeviceFound: (d) => {
    // discovered 由 poll 轮询 shared-core 状态填充；这里只处理已存在设备的连接状态更新
    const idx = discovered.value.findIndex((x) => x.ip === d.ip && x.port === d.port);
    if (idx >= 0) {
      discovered.value[idx] = { ...discovered.value[idx], ...d };
    }
  },
  onDeviceLost: () => {},
});
const pairings = ref<PairRecord[]>([]);
/* 无可用目标/未连接 → 悬浮球「落寞/无奈」提示（配对数归零且不在扫描/同步时触发） */
watch(
  () => pairings.value.length,
  (n) => {
    if (isTauri && n === 0 && !scanRunning.value && !scanning.value) emitBall('lonely');
  },
);
const discovered = ref<DiscoveredDevice[]>([]);
const scanRunning = ref(false);
const scanRounds = ref(0);
const scanElapsedSec = ref(0);
let scanStartedAt = 0;
const verifying = ref(false);
let pollTimer: ReturnType<typeof setInterval> | null = null;
let pingTimer: ReturnType<typeof setInterval> | null = null;
let mergeTimer: ReturnType<typeof setInterval> | null = null;
/** v5 信任状态巡检定时器（sync-status 周期收敛） */
let trustTimer: ReturnType<typeof setInterval> | null = null;
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
  { id: 'devices', icon: 'devices', label: '设备' },
  { id: 'backup', icon: 'sync', label: '同步' },
  { id: 'history', icon: 'history', label: '记录' },
  { id: 'settings', icon: 'settings', label: '设置' },
];
const dockStatusTitle = computed(() => pageNames[currentPage.value]);
const dockStatusSub = computed(() => (serverRunning.value ? '收件服务运行中' : '收件服务已停止'));

/** 自定义标题栏窗口控制（decorations: false 后由应用自绘；浏览器预览无 Tauri 运行时置空） */
const appWin = isTauri ? getCurrentWindow() : null;

/** 标题栏拖拽：标题区空白处按住左键即可拖动窗口（按钮/输入不触发） */
function onHeaderDrag(e: MouseEvent) {
  if (e.button !== 0) return;
  const t = e.target as HTMLElement;
  if (t.closest('button, input, a, select, textarea')) return;
  appWin?.startDragging();
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
  /* 离场快于入场（animate.md）；常规状态变更 150–250ms，不让用户等编排 */
  tl.to(node, { height: 0, marginBottom: 0, duration: 0.18, ease: 'power2.inOut' })
    .to(node, { autoAlpha: 0, scaleY: 0.96, duration: 0.1, ease: 'power2.in' }, 0.1);
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
    duration: 0.28,
    ease: 'power3.out', // 自信到达：自然减速 ≈ cubic-bezier(0.16,1,0.3,1)
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
    .to(node, { height: 0, paddingTop: 0, paddingBottom: 0, borderTopWidth: 0, borderBottomWidth: 0, marginBottom: -16, duration: 0.2, ease: 'power2.inOut' })
    .to(node, { autoAlpha: 0, duration: 0.1, ease: 'power2.in' }, 0.12);
}

/** 列表项移除：
    对删除项施加 SVG feTurbulence 流体烟雾滤镜（颗粒漂移 + disolicement 形变 + 雾化），
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
    logger.error('ui', '烟雾字符生成失败', e);
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
    duration: 0.22,
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
const { tasks, createTask, updateTask, pauseTask, completeTask, failTask, removeTask, markDialogShown, isDialogShown } = useSyncTasks();
const activeTaskId = ref('');
/** 镜像确认持久化防重放（BUG-9 复盘）：按目标 fingerprint 键控 + localStorage 持久化，
 *  重启/自动恢复新建任务后仍不重弹（taskId 级 isDialogShown 每次新任务即失效）。
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
function markMirrorAsked(fp: string) {
  mirrorAskedAt.set(fp, Date.now());
  try {
    localStorage.setItem(MIRROR_ASKED_KEY, JSON.stringify(Object.fromEntries(mirrorAskedAt)));
  } catch {
    /* 持久化失败不影响主流程 */
  }
}
function mirrorAlreadyAsked(fp: string): boolean {
  const last = mirrorAskedAt.get(fp) || 0;
  return Date.now() - last < 5 * 60 * 1000;
}
function taskStateText(s: SyncTask['state']): string {
  return s === 'running' ? '进行中' : s === 'paused' ? '已暂停' : s === 'completed' ? '已完成' : '失败';
}
/** 探测对端接收服务可达（P2 硬升级：v2 问候 /verify 与 3-Way 握手已删除，
 *  改由 TCP 直连接收端口判断；接收服务就绪由 send_files 内部轮询兜底） */
async function greetPeer(ip: string, port: number): Promise<boolean> {
  try {
    return await invoke<boolean>('probe_peer_port', { ip, port });
  } catch {
    return false;
  }
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
/** 防御性总开关：hidden=true 时本机在局域网完全隐藏（拒绝一切入站，仅保留本机主动外连） */
const defensiveHidden = ref(false);
/** 接收端配置区折叠（窄栏仅状态灯） */
const recvPanelCollapsed = ref(true); // 收件区配置默认折叠
const sendPanelCollapsed = ref(true); // 发件区配置默认折叠
/** 发送端：多文件夹列表（永久配置，持久化，重启保留） */
const senderFolders = ref<SendFolder[]>([]);
/** 临时文件夹（会话级，重启清空；点选/拖拽新增，与永久文件夹一起参与本次同步） */
const sessionFolders = ref<SendFolder[]>([]);
/** 本次同步跳过集合（行内开关：勾选=参与，取消=本次跳过；不写回永久配置） */
const syncSkip = reactive(new Set<string>());
/** 自动接收开关：开启后收到的文件全自动保存，无需人工确认（localStorage 持久化） */
const autoAcceptReceive = ref(localStorage.getItem('auto_accept_receive') === '1');
function toggleAutoAcceptReceive() {
  autoAcceptReceive.value = !autoAcceptReceive.value;
  try { localStorage.setItem('auto_accept_receive', autoAcceptReceive.value ? '1' : '0'); } catch { /* 忽略 */ }
}
const boxC2p = ref(''); // 兼容旧引用：当前发送文件夹（folders 为空时用）
const targetDevice = ref<PairRecord | null>(null);
const targetDropdownOpen = ref(false);
const scanning = ref(false);
const syncStrategy = ref<SyncStrategy>('archive'); // 与 appConfig.sender.strategy 同步
/** 本次实际发送的文件夹 = 启用的永久文件夹（未被跳过）+ 全部临时文件夹（未被跳过） */
const effectiveSendFolders = computed(() => {
  const out: SendFolder[] = [];
  for (const f of senderFolders.value) if (f.enabled && !syncSkip.has(f.id)) out.push(f);
  for (const f of sessionFolders.value) if (!syncSkip.has(f.id)) out.push(f);
  return out;
});
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
/** 两个确认弹窗的根元素引用（Tab 焦点陷阱用；此前模板引用了未声明的 overlayRef） */
const incomingOverlayRef = ref<HTMLDivElement | null>(null);
const pairingOverlayRef = ref<HTMLDivElement | null>(null);
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
    // 接受 → 进入接收状态（球端自行演出）；拒绝 → 拒绝/受限表情
    if (accept) emitBall('receiving');
    else emitBall('toast_denied');
  } catch (e) {
    logger.error('receiver', '响应接收确认失败', e);
  }
}

async function acceptPairing(accept: boolean) {
  const r = pairingReq.value;
  if (!r) return;
  // 先清引用再 invoke：防止双击并发触发两次 resolve_pairing（与 acceptIncoming 同模式）
  pairingReq.value = null;
  try {
    await invoke('resolve_pairing', { deviceId: r.deviceId, accept });
    lastResult.value = accept ? `已同意与「${r.name}」配对` : `已拒绝与「${r.name}」配对`;
    // 同意 → 满意；拒绝 → 拒绝/受限
    emitBall(accept ? 'toast_satisfied' : 'toast_denied');
    // 问题3：同意连接后停止设备发现（双方已配对，不再需要继续扫描）
    if (accept) stopDiscovery();
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

/* --------------------------------------------------------------
   调试模式占位数据
   开关开启「瞬间」生成可变占位副本；关闭「瞬间」全部清除。
   开启期间可自由删除/禁用/解除这些占位，不影响真实配置。
   -------------------------------------------------------------- */
const debugEnabled = ref(true);
const DBG_TARGET: PairRecord = {
  fingerprint: 'debug-target', deviceId: 'debug-target', name: '调试目标设备',
  ip: '192.168.1.99', port: 53317, trustAt: Date.now(), online: true, connected: true, lastSeen: Date.now(),
};
const DBG_PAIRED: PairRecord[] = [
  { fingerprint: 'debug-p1', deviceId: 'debug-p1', name: '调试设备 A', ip: '192.168.1.101', port: 53317, trustAt: Date.now(), online: true, connected: true, lastSeen: Date.now() },
  { fingerprint: 'debug-p2', deviceId: 'debug-p2', name: '调试设备 B', ip: '192.168.1.102', port: 53317, trustAt: Date.now(), online: true, connected: false, lastSeen: Date.now() },
  { fingerprint: 'debug-p3', deviceId: 'debug-p3', name: '调试设备 C', ip: '192.168.1.103', port: 53317, trustAt: Date.now(), online: false, connected: false, lastSeen: Date.now() },
];
const DBG_SEND: SendFolder[] = [
  { id: 'debug-sf1', name: '调试发送夹 A', path: 'D:\\调试发送夹A', enabled: true },
  { id: 'debug-sf2', name: '调试发送夹 B', path: 'D:\\调试发送夹B', enabled: true },
  { id: 'debug-sf3', name: '调试发送夹 C', path: 'D:\\调试发送夹C', enabled: false },
];
const DBG_RECV = 'D:\\调试收件夹';
const DBG_TRANSFERS: (typeof transfers.value)[number][] = Array.from({ length: 10 }, (_, i) => ({
  id: 900000 + i,
  direction: i % 2 ? 'receive' : 'send',
  peer: i % 2 ? '调试设备 B' : '调试目标设备',
  fileCount: 3 + i,
  bytes: 1048576 * (20 + i * 7),
  durationMs: 4000 + i * 900,
  createdAt: Date.now() - i * 30 * 86400000,
}));
// 可变占位容器（删除/禁用直接改这些 ref）
const debugTargetDev = ref<PairRecord | null>(null);
const debugPairedDevs = ref<PairRecord[]>([]);
const debugSendFolders = ref<SendFolder[]>([]);
const debugRecvDir = ref('');
const debugTransfers = ref<(typeof transfers.value)[number][]>([]);

function seedDebugData() {
  if (!debugTargetDev.value) debugTargetDev.value = { ...DBG_TARGET };
  if (!debugPairedDevs.value.length) debugPairedDevs.value = DBG_PAIRED.map((x) => ({ ...x }));
  if (!debugSendFolders.value.length) debugSendFolders.value = DBG_SEND.map((x) => ({ ...x }));
  if (!debugRecvDir.value) debugRecvDir.value = DBG_RECV;
  if (!debugTransfers.value.length) debugTransfers.value = DBG_TRANSFERS.map((x) => ({ ...x }));
}
function clearDebugData() {
  debugTargetDev.value = null;
  debugPairedDevs.value = [];
  debugSendFolders.value = [];
  debugRecvDir.value = '';
  debugTransfers.value = [];
  // 关闭时若正选中调试目标，清空选择
  if (targetDevice.value?.fingerprint === 'debug-target') targetDevice.value = null;
}
/** 移除调试收件目录占位（收件区配置卡上的 × 按钮；此前模板引用了未定义的处理器） */
function resetDebugRecv() {
  debugRecvDir.value = '';
}
watch(debugEnabled, (v) => {
  if (v) seedDebugData();
  else clearDebugData();
}, { immediate: true });

/** 目标设备下拉（debug 时置顶 1 个占位调试设备） */
const targetOptions = computed(() => (debugEnabled.value && debugTargetDev.value ? [debugTargetDev.value, ...pairings.value] : pairings.value));
/** 我的设备列表（debug 时前置占位已配对设备） */
const pairedList = computed(() => (debugEnabled.value ? [...debugPairedDevs.value, ...pairings.value] : pairings.value));
/** 发件区文件夹列表（debug 时后置占位文件夹） */
const displaySenderFolders = computed(() => (debugEnabled.value ? [...debugSendFolders.value, ...senderFolders.value] : senderFolders.value));
/** 收件目录显示（debug 时展示占位目录） */
const displayRecvDir = computed(() => ((debugEnabled.value && debugRecvDir.value) ? debugRecvDir.value : boxP2c.value));
/** 传输记录（debug 时后置占位历史） */
const displayTransfers = computed(() => (debugEnabled.value ? [...debugTransfers.value, ...transfers.value] : transfers.value));
/** 是否为调试占位文件夹 */
function isDebugFolder(id: string) {
  return id.startsWith('debug-sf');
}

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
  // 调试占位记录：仅从 debug 可变副本移除，不调后端
  if (debugEnabled.value && id >= 900000) {
    debugTransfers.value = debugTransfers.value.filter((t) => t.id !== id);
    lastResult.value = '已删除该条传输记录';
    return;
  }
  // 乐观移除：先从本地数组删除触发 Vue TransitionGroup 离场动画，后端同步最终一致
  const idx = transfers.value.findIndex((t) => t.id === id);
  if (idx === -1) return;
  const [removed] = transfers.value.splice(idx, 1);
  try {
    await invoke('delete_transfer', { id });
    lastResult.value = '已删除该条传输记录';
  } catch (e) {
    // 回滚：后端删除失败则恢复本地记录
    transfers.value.splice(idx, 0, removed);
    logger.error('ui', '删除传输历史失败', e);
  }
}
function clearAllTransfers() {
  const n = displayTransfers.value.length;
  askConfirm({
    title: '清空传输记录',
    message: `将删除全部 ${n} 条传输记录，不可恢复。`,
    danger: true,
    action: () => {
      // 调试占位记录随关闭一并清空
      if (debugEnabled.value) debugTransfers.value = [];
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
  const sorted = [...displayTransfers.value].sort((a, b) => b.createdAt - a.createdAt);
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
/** 加密强度：simple=简单加密（连接码派生，兼容旧设备）/ ecdh=复杂加密（ECDH 密钥协商） */
const encryptionMode = ref<'simple' | 'ecdh'>('simple');
const debugSummary = ref(logger.summary());
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
/** 悬浮球开关：是否显示悬浮球（localStorage 持久化，默认开启） */
const ballEnabled = ref(true);
try {
  const saved = localStorage.getItem('ball_enabled');
  if (saved !== null) ballEnabled.value = saved === 'true';
} catch { /* 忽略 */ }
function setBallEnabled(v: boolean) {
  ballEnabled.value = v;
  try { localStorage.setItem('ball_enabled', String(v)); } catch { /* 忽略 */ }
  // 联动后端：启用状态 + 显隐同时生效
  invoke('set_ball_enabled', { enabled: v }).catch(() => {});
  invoke('set_ball_visible', { visible: v }).catch(() => {});
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
    localStorage.setItem('desktop_debug', String(v));
  } catch {
    // 忽略
  }
  // 同步到后端 Rust logger（release build 下 debug_enabled 默认为 false，
  // 必须由前端显式开启才能让 log_debug! 输出；debug build 无需调用也已开启）
  // P3-143：记录失败，避免前端日志已切换但后端静默未生效的「不一致」无法定位
  invoke('set_debug_mode', { enabled: v }).catch((e) => {
    console.warn('[set_debug_mode] 后端同步失败:', e);
  });
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
  // 最多同时 2 条：超出时最旧的立即移除，保持右上角窄条不遮挡内容
  if (toasts.value.length > 2) toasts.value = toasts.value.slice(-2);
  // 错误比成功信息多停留（评审 P1：错误信息 4.2s 蒸发 → 留足读取与恢复时间）
  const dur = kind === 'error' ? 6000 : 3600;
  setTimeout(() => {
    toasts.value = toasts.value.filter((t) => t.id !== id);
  }, dur);
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
    // 调试目标不在真实配对表中：保留选择，避免刷新后被切回「未选择」
    if (fp === 'debug-target') { /* 保持调试目标 */ }
    else targetDevice.value = pairMgr.byFingerprint(fp) ?? null;
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
  encryptionMode.value = c.encryption === 'ecdh' ? 'ecdh' : 'simple';
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
  c.encryption = encryptionMode.value;
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
  syncSkip.delete(id);
  persistConfig();
}

/** 永久文件夹移除（统一走确认弹窗，防误删） */
async function confirmRemoveSendFolder(f: SendFolder) {
  const ok = await askConfirmAsync({
    title: f.name.startsWith('调试') ? '移除调试文件夹' : '移除永久文件夹',
    message: `将「${f.name}」移除？${isDebugFolder(f.id) ? '（调试占位，关闭调试后自动恢复）' : '此操作不可恢复。'}`,
    danger: true,
  });
  if (!ok) return;
  // 调试占位文件夹：仅移除可变副本
  if (isDebugFolder(f.id)) {
    debugSendFolders.value = debugSendFolders.value.filter((x) => x.id !== f.id);
    syncSkip.delete(f.id);
    return;
  }
  removeSendFolder(f.id);
}

/** 临时文件夹：点选新增（会话级，重启清空） */
async function addSessionFolder() {
  const dirs = await openDirectories();
  if (!dirs.length) return;
  for (const dir of dirs) {
    const name = dir.split(/[\\/]/).filter(Boolean).pop() || '文件夹';
    sessionFolders.value.push({ id: 'tmp_' + genFolderId(), name, path: dir, enabled: true });
  }
}

/** 临时文件夹：移除（仅本次会话，直接移除不弹窗） */
function removeSessionFolder(id: string) {
  sessionFolders.value = sessionFolders.value.filter((f) => f.id !== id);
  syncSkip.delete(id);
}

/** 临时文件夹：拖拽新增（浏览器 fallback 到点击选择） */
async function onDropSessionFolders() {
  await addSessionFolder();
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
  // JS 存活心跳：每秒打一次探针，用于判定冻结时 JS 线程是"死亡"还是"卡在某个调用"
  let feBeat = 0;
  const feBeatTimer = setInterval(() => feProbe(`FE 心跳 #${++feBeat}`), 1000);
  feProbe('mounted 入口');
  applyTheme();
  window.addEventListener('keydown', onGlobalEsc);
  // 悬浮球：应用启动首演 boot（加载苏醒 → 就绪）
  emitBall('boot');
  /* 初始页激活：去掉 page-off（在首帧绘制前执行，无闪烁） */
  pageRef.value?.querySelector<HTMLElement>(`[data-page="${currentPage.value}"]`)?.classList.remove('page-off');
  syncWallpaper(); /* 中档壁纸 3fps 采样在挂载后启动 */
  feProbe('主题+壁纸 完成');
  // 恢复调试模式开关（默认开启；关闭后不记录日志）
  try {
    const d = localStorage.getItem('desktop_debug');
    if (d !== null) {
      debugEnabled.value = d === 'true';
      logger.setDebugEnabled(debugEnabled.value);
      // 同步到后端 Rust logger（release build 下 debug_enabled 默认为 false）
      invoke('set_debug_mode', { enabled: debugEnabled.value }).catch(() => {});
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
  feProbe('get_self_info 完成');
  // 读取防御性总开关的持久化状态（隐藏=完全不可见，拒绝一切入站）
  try {
    defensiveHidden.value = await invoke<boolean>('get_defensive');
  } catch {
    defensiveHidden.value = false;
  }
  feProbe('get_defensive 完成');
  try {
    await loadAppConfig();
  } catch {
    // 忽略
  }
  feProbe('配置加载完成');
  // 接收端默认开启：角色为接收端/自由模式 + 开关开启 + 目录已配 → 自动进入接收状态（无需确认）
  if ((role.value === 'receiver' || role.value === 'free') && receiverEnabled.value && autoStartReceiver.value && boxP2c.value && !serverRunning.value) {
    await startServer(boxP2c.value);
  }
  feProbe('接收服务自启判断完成');
  refreshPairings();
  // 连接是显式会话：重启后统一复位为"未连接"（回到状态3），避免陈旧已连接状态不对称
  for (const r of pairMgr.all()) {
    if (r.connected) pairMgr.markConnected(r.fingerprint, false);
  }
  refreshPairings();
  const online = pairings.value.filter((p) => p.online);
  targetDevice.value = online[0] ?? pairings.value[0] ?? null;
  loadState();
  feProbe('本地状态恢复完成');
  // 后台自动连接：延迟到页面首帧渲染完成后执行，避免网络超时阻塞首帧。
  // 页面渲染不被卡住（用户立即看到界面），后台任务在渲染完成后运行。
  setTimeout(() => {
    feProbe('startAutoConnect 延迟启动');
    startAutoConnect();
  }, 0);
  // 断网自动重连 + 暂停任务自动恢复（有暂停任务且对端恢复可达时自动续传）
  autoResume.start();
  loadTransfers();
  feProbe('autoResume+transfers 完成');
  // 实时事件监听（useTauriListener 统一管理生命周期，卸载自动清理）：
  // 1) 对方验证本机码成功 → 立即刷新已配对设备
  // 2) 传输进度事件 → 实时刷新进度条
  if (isTauri) {
    feProbe('事件监听注册开始');
    try {
      const { listen: tauriListen } = await import('@tauri-apps/api/event');
      // 包装：每个事件监听注册完成后打探针（定位 IPC/主线程卡死的具体事件）
      const listen = async <T>(event: string, cb: (e: { payload: T }) => void): Promise<() => void> => {
        const un = await tauriListen<T>(event, cb);
        feProbe(`监听 ${event} ✓`);
        return un;
      };
      // Rust 端日志通过事件实时推送到前端 shared-core logger 显示
      track(
        await listen('rust_log_event', (e) => {
          const p = e.payload as { ts: number; level: string; module: string; message: string };
          logger.report(p.level as 'DEBUG' | 'INFO' | 'WARN' | 'ERROR', '[rust] ' + p.module, p.message);
        }),
      );
      // 启动时主动拉取历史日志（弥补启动前的日志缺口）
      invoke<{ ts: number; level: string; module: string; message: string }[]>('get_rust_logs').then((logs) => {
        for (const entry of logs) {
          if (entry.ts && entry.level && entry.module !== undefined && entry.message !== undefined) {
            logger.report(entry.level as 'DEBUG' | 'INFO' | 'WARN' | 'ERROR', '[rust] ' + entry.module, entry.message);
          }
        }
      }).catch(() => {});
      feProbe('rust 日志桥接完成');
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
          const req = e.payload as { sessionId: string; count: number; totalBytes: number; senderName: string; senderIp: string };
          // 自动接收开关开启 → 免确认直接接收；否则弹窗人工确认
          if (autoAcceptReceive.value) {
            invoke('resolve_incoming', { sessionId: req.sessionId, accept: true })
              .then(() => { lastResult.value = `已自动接收 ${req.count} 个文件`; })
              .catch((err) => logger.error('receiver', '自动接收失败', err));
          } else {
            incomingReq.value = req;
            // 收到收件请求 → 悬浮球惊讶（有人要发文件给我）
            emitBall('toast_surprise');
          }
        }),
      );
      // 配对确认弹窗（对方填写了本机连接码请求配对）
      track(
        await listen('pairing-request', (e) => {
          pairingReq.value = e.payload as { deviceId: string; name: string; ip: string };
          // 收到配对请求 → 悬浮球害羞（有人想连接我）
          emitBall('toast_shy');
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
            discovery.updateConnectionStatus(rec.ip, rec.port, true);
            refreshPairings();
            // 已配对设备穿透隐藏连接：接收服务未运行时自动拉起（断点续传/收件可用）
            if (!serverRunning.value && boxP2c.value) {
              startServer(boxP2c.value);
            }
            const now = Date.now();
            const last = connectNoticeAt.get(rec.fingerprint) || 0;
            if (!wasConnected && now - last > 30000) {
              connectNoticeAt.set(rec.fingerprint, now);
              // P3-135：防止 peer-connected 无限增长（配对记录反复出现），超上限清理最旧
              if (connectNoticeAt.size > 200) {
                const oldest = [...connectNoticeAt.entries()].sort((a, b) => a[1] - b[1])[0];
                if (oldest) connectNoticeAt.delete(oldest[0]);
              }
              lastResult.value = `「${rec.name}」已连接本机`;
              // 对方上线连接本机 → 悬浮球联网加载（信号往返）
              emitBall('toast_online');
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
            discovery.updateConnectionStatus(rec.ip, rec.port, false);
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
      // 常驻加密存在广播：已配对设备在线/离线（独立于发现/收件服务，仅防御总闸影响）。
      // 收到有效加密存在(含HMAC) → 在线；连续收不到(约12s) 或握手失败 → 立即离线
      track(
        await listen('pair-presence', (e) => {
          const { deviceId, online } = e.payload as { deviceId: string; online: boolean };
          const rec = pairMgr.byDeviceId(deviceId);
          if (!rec) return;
          if (online) {
            pairMgr.markOnline(rec.fingerprint, rec.ip, rec.port);
            rejectCount.delete(rec.fingerprint);
            probeSkip.delete(rec.fingerprint);
          } else {
            pairMgr.markOffline(rec.fingerprint);
          }
          refreshPairings();
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
      // 可疑设备（同一指纹 IP 突变 → 疑似僵尸设备/劫持）：询问用户是否移除
      track(
        await listen('device-suspicious', (e) => {
          const p = e.payload as { fingerprint: string; oldIp: string; newIp: string };
          const rec = pairMgr.byFingerprint(p.fingerprint);
          const name = rec?.name ?? discovered.value.find((d) => d.fingerprint === p.fingerprint)?.alias ?? '未知设备';
          askConfirmAsync({
            title: '检测到可疑设备',
            message: `「${name}」的 IP 从 ${p.oldIp} 变为 ${p.newIp}。这可能意味着对方更换了网络，或设备被冒充（劫持）。是否将其从列表中移除？`,
            danger: true,
          }).then((ok) => {
            if (!ok) return;
            // 从发现列表移除（按指纹）
            discovered.value = discovered.value.filter((d) => d.fingerprint !== p.fingerprint);
            // 同步清理后端发现缓存（否则下次 get_discovered_devices 又会带回该设备）
            invoke('remove_device', { ip: p.oldIp }).catch(() => {});
            // 已配对则解除配对
            const paired = pairMgr.byFingerprint(p.fingerprint);
            if (paired) {
              pairMgr.remove(paired.fingerprint);
              refreshPairings();
            }
            lastResult.value = `已移除可疑设备「${name}」`;
          });
        }),
      );
      // 对方取消传输（接收端收到 sender 取消）：清理接收进度/确认弹窗并提示
      track(
        await listen('transfer-cancelled', (e) => {
          const p = e.payload as { sessionId: string; fileId: string };
          if (incomingReq.value?.sessionId === p.sessionId) {
            incomingReq.value = null;
          }
          recvProgress.value = null;
          if (activeTaskId.value) {
            pauseTask(activeTaskId.value, '对方已取消传输');
            activeTaskId.value = '';
          }
          pushToast('ok', p.fileId ? `对方取消了传输：${p.fileId}` : '对方已取消传输');
          lastResult.value = '对方已取消传输';
          // 对方中途取消 → 悬浮球困惑（好好的怎么取消了）
          emitBall('toast_puzzled');
        }),
      );
      // 悬浮球拖入文件夹 → 只同步这一个文件夹到已连接设备
      track(
        await listen('ball:drop-folder', (e) => {
          const path = (e.payload as { path?: string })?.path;
          if (path) handleDropSync(path);
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
  feProbe('事件监听注册完成（onMounted 结束）');
  clearInterval(feBeatTimer); // 诊断完成，停止 JS 心跳
});

onUnmounted(() => {
  mm?.revert();
  window.removeEventListener('keydown', onGlobalEsc);
  autoResume.stop();
  if (pollTimer) clearInterval(pollTimer);
  if (pingTimer) clearInterval(pingTimer);
  if (mergeTimer) clearInterval(mergeTimer);
  if (trustTimer) clearInterval(trustTimer);
  if (nameSaveTimer) clearTimeout(nameSaveTimer);
  if (ballIdleTimer) clearTimeout(ballIdleTimer); // 悬浮球 30s 闲置回落链
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
  // v5 信任巡检：v3 probe 只有可达性语义，无法感知"对方已解除配对"。
  // 每 30s 一轮 sync-status，revoked/unknown 时后端发 pair-unpaired 事件自动删除本机记录。
  if (trustTimer) clearInterval(trustTimer);
  trustTimer = setInterval(() => {
    invoke<{ ok?: boolean }>('sync_all_peers').catch(() => {});
  }, 30000);
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
  const peers = pairMgr.all().map((rec) => {
    // 设备记录按 fingerprint 存于持久化状态（getOrCreateDevice 写入）；
    // 桌面端无 `devices` ref，用 loadState() 读取，避免配对后 `devices is not defined` 崩溃
    const dev = loadState().devices[rec.fingerprint];
    return {
      deviceId: rec.deviceId,
      name: rec.name,
      ip: rec.ip,
      port: rec.port,
      fingerprint: rec.fingerprint,
      lastManifest: dev?.lastManifest ?? {},
    };
  });
  try {
    await invoke('sync_paired', { peers });
  } catch (e) {
    logger.warn('pair', '同步配对记录到后端失败', e);
  }
}

interface PairedPeerRecord {
  deviceId: string; name: string; ip: string; port: number;
  fingerprint: string; lastManifest?: Record<string, string>;
}

async function mergePeers() {
  try {
    const peers = await invoke<PairedPeerRecord[]>('get_paired_peers');
    let added = 0;
    for (const p of peers) {
      const existing = pairMgr.byDeviceId(p.deviceId);
      const fp = p.fingerprint || existing?.fingerprint || '';
      if (!fp && !existing) continue;
      if (!existing) added++;
      const rec = {
        fingerprint: fp,
        deviceId: p.deviceId,
        name: p.name,
        ip: p.ip,
        port: p.port,
        trustAt: existing?.trustAt ?? Date.now(),
        online: existing?.online ?? false,
        lastSeen: existing?.lastSeen ?? Date.now(),
        lastManifest: p.lastManifest,
      };
      pairMgr.upsert(rec);
      // 写回持久化设备记录（getOrCreateDevice 存于 state.devices[fp]）
      const dev = loadState().devices[fp];
      if (dev && p.lastManifest) dev.lastManifest = p.lastManifest;
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

// 状态侦测（2 次/秒）：TCP probe 只负责「可达性 + IP 自愈」，
// 已配对设备的 online/offline 状态完全由 bcpd（加密存在广播）驱动，
// greetAll 不得覆盖 bcpd sweep 产生的离线状态（避免双源打架导致的状态抖动）。
// 未配对设备（扫描发现但尚未完成配对）的 online 态仍由 greetAll 维护。
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
          // 兜底：探测被退避跳过期间，若仍显示在线但 lastSeen 已过期（>10s，
          // 远超 500ms 探测周期）→ 强制离线，避免"手机已离线但电脑仍显示在线"
          if (rec.online && Date.now() - (rec.lastSeen || 0) > 10_000) {
            pairMgr.markOffline(rec.fingerprint);
          }
          return;
        }
        const ips = rec.ips?.length ? rec.ips : [rec.ip];
        let ok = false;
        for (const ip of ips) {
          try {
            await invoke('v3_probe', { ip, port: rec.port });
            // 已配对设备（deviceId 非空）：online 态由 bcpd 全权驱动，greetAll 只更新 IP；
            // 未配对设备：online 态仍由 greetAll 维护（扫描发现的临时设备）。
            if (!rec.deviceId) {
              pairMgr.markOnline(rec.fingerprint, ip, rec.port);
            }
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

// 连接（显式）：探测对端可达后置为已连接（P2 硬升级：v2 问候 /verify 已删除，
// 改用 v3 probe 探测配对服务；对方已解除配对检测暂缺）
async function connectPeer(p: PairRecord) {
  const ips = p.ips?.length ? p.ips : [p.ip];
  let ok = false;
  for (const ip of ips) {
    try {
      await invoke('v3_probe', { ip, port: p.port });
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
    lastResult.value = `已连接：${p.name}`;
    // 主动连接成功 → 满意
    emitBall('toast_satisfied');
  } else {
    pairMgr.markOffline(p.fingerprint);
    errorMsg.value = `连接失败：${p.name}（对方不在线或已解除配对）`;
    // 连接失败 → 疑惑（对方怎么连不上）
    emitBall('toast_confused');
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

// 关于卡：点击整卡打开开发者主页
function openDevHome() {
  window.open('https://space.bilibili.com/401121508', '_blank', 'noopener,noreferrer');
}

// 断开 / 解除：二级确认弹窗
function confirmUnpair(fp: string) {
  const rec = pairMgr.byFingerprint(fp);
  askConfirm({
    title: '解除配对',
    message: `解除后「${rec?.name || '该设备'}」将失去信任关系，需要重新配对才能再次连接。`,
    danger: true,
    action: () => {
      // 调试占位设备：确认后仅移除可变副本，不调后端
      if (fp.startsWith('debug-p')) debugPairedDevs.value = debugPairedDevs.value.filter((p) => p.fingerprint !== fp);
      else removePairing(fp);
    },
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
  // 防重入标志必须在 await 之前置位：invoke 窗口期内快速二次点击会
  // 双通守卫 → 后端双实例 + pollTimer 句柄被覆盖泄漏（旧 interval 永失引用）
  if (scanRunning.value) return;
  scanRunning.value = true;
  errorMsg.value = '';
  try {
    const res = await invoke<string>('start_discovery', { serverPort: 53317 });
    discovered.value = [];
    scanRounds.value = 0;
    scanElapsedSec.value = 0;
    scanStartedAt = Date.now();
    lastResult.value = res;
    // v5 事件驱动上线同步：向所有已配对设备直连发 sync-status（§5.2），
    // 若对方曾单方面吊销本机（REVOKE_PENDING），此处收到吊销令牌并本地解除
    invoke<{ ok?: boolean }>('sync_all_peers').catch(() => {});
    // 点击「开始发现」后，悬浮球才进入检索（扫描）状态
    emitBall('discovering');
    pollTimer = setInterval(async () => {
      scanRounds.value++;
      scanElapsedSec.value = Math.round((Date.now() - scanStartedAt) / 1000);
      try {
        const list = await invoke<DiscoveredDevice[]>('get_discovered_devices');
        discovered.value = list;
        // 发现到设备 → 好奇表情（0→>0 时喷一次）
        if (list.length && !ballFoundEmitted) { ballFoundEmitted = true; emitBall('found'); }
        else if (!list.length) { ballFoundEmitted = false; }
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
    scanRunning.value = false; // 启动失败回滚防重入标志，允许重试
  }
}

async function stopDiscovery() {
  scanRunning.value = false;
  scanRounds.value = 0;
  scanElapsedSec.value = 0;
  discovered.value = []; // 停止配对后已搜索到的设备消失
  // 停止发现后悬浮球退出检索，回到空闲
  emitBall('idle');
  if (pollTimer) clearInterval(pollTimer);
  try {
    await invoke('stop_discovery');
  } catch (e) {
    logger.error('receiver', '停止设备发现失败', e);
  }
}

/** 防御性总开关：切换本机完全隐藏/可见。隐藏=拒绝一切入站连接，仅保留本机主动外连 */
async function setDefensive(hidden: boolean) {
  defensiveHidden.value = hidden;
  try {
    await invoke('set_defensive', { hidden });
    lastResult.value = hidden ? '本机已在局域网完全隐藏（拒绝一切入站连接）' : '本机已设为可见模式';
  } catch (e) {
    logger.error('receiver', '切换防御开关失败', e);
    defensiveHidden.value = !hidden;
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
    // v3 首次配对（路径A）：加密全在 Rust 层（v3_pair）；服务端弹窗确认最长 45s → 客户端长读超时 60s
    const r = await invoke<{ status?: string; deviceId?: string; error?: { code?: string; message?: string } }>('v3_pair', {
      ip: t.ip,
      port: t.port,
      code: codeInput.value.trim(),
      name: selfInfo.value.name,
    });
    if (r?.status !== 'approved') {
      errorMsg.value = r?.error?.code === 'INVALID_CODE' ? '连接码不正确，配对失败' : (r?.error?.message || '配对失败');
      return;
    }
    const fp = normalizeCode(codeInput.value);
    pairMgr.upsert({
      fingerprint: fp,
      deviceId: r.deviceId || t.fingerprint,
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
    // v3 首次配对（路径A）：加密全在 Rust 层（v3_pair）
    const r = await invoke<{ status?: string; deviceId?: string; error?: { code?: string; message?: string } }>('v3_pair', {
      ip: manualIp.value.trim(),
      port: manualPort.value,
      code: manualCode.value.trim(),
      name: selfInfo.value.name,
    });
    if (r?.status !== 'approved') {
      errorMsg.value = r?.error?.code === 'INVALID_CODE' ? '连接码不正确，配对失败' : (r?.error?.message || '配对失败');
      return;
    }
    // P2 硬升级：ping_device（v2 /info）已删除，改用 v3_probe 取对端别名（deviceId 用 v3_pair 返回值）
    let peerAlias = manualIp.value.trim();
    let peerDeviceId = r.deviceId || '';
    try {
      const probe = await invoke<{ deviceId?: string; alias?: string }>('v3_probe', {
        ip: manualIp.value.trim(),
        port: manualPort.value,
      });
      peerAlias = probe.alias || peerAlias;
      peerDeviceId = probe.deviceId || peerDeviceId;
    } catch {
      // probe 失败不阻断配对（v3_pair 已成功）
    }
    const fp = normalizeCode(manualCode.value);
    pairMgr.upsert({
      fingerprint: fp,
      deviceId: peerDeviceId,
      name: peerAlias,
      ip: manualIp.value.trim(),
      port: manualPort.value,
      trustAt: Date.now(),
      online: true,
      lastSeen: Date.now(),
    });
    refreshPairings();
    if (!targetDevice.value) targetDevice.value = pairMgr.byFingerprint(fp) ?? null;
    lastResult.value = `手动配对成功：${peerAlias}`;
    logger.info('pair', `手动配对成功 alias=${peerAlias} ip=${manualIp.value}`);
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

// 解除配对（v5：在线直连签名解绑 / 对方离线 → REVOKE_PENDING + 吊销令牌）
async function removePairing(fp: string) {
  const rec = pairMgr.byFingerprint(fp);
  if (rec) {
    try {
      // v5 统一入口：先尝试在线直连（双方立即 REVOKED）；失败则本地 REVOKE_PENDING + 吊销令牌
      const r = await invoke<{ status?: string; mode?: string }>('unpair_peer', { deviceId: rec.deviceId });
      if (r?.mode === 'offline') {
        lastResult.value = '对方离线，已单方面解除，等待对方上线同步';
      }
    } catch (e) {
      logger.warn('pair', '解除配对失败', e);
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
  if (lastResult.value !== '对方离线，已单方面解除，等待对方上线同步') lastResult.value = '已解除配对';
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
  // 加载该设备的对端缺失列表；不再用设备历史策略覆盖当前 UI 选择（BUG-9），
  // 避免用户选了「增量(archive)」后，选设备/重连被静默切回「镜像(mirror)」而弹镜像确认。
  const state = loadState();
  const device = getOrCreateDevice(state, p.fingerprint, p.name);
  void device; // 仅确保设备记录存在
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
    emitBall('receiving', '收件服务运行中');
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
    emitBall('idle');  // 收件服务停止，主动收回 idle
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
// folders 参数用于「拖文件夹到悬浮球」：只同步指定的那一个文件夹（runBackup 透传）
async function sendAllFolders(taskId: string, folders?: SendFolder[]): Promise<number> {
  const state = loadState();
  const device = getOrCreateDevice(state, targetDevice.value!.fingerprint, targetDevice.value!.name);
  device.syncStrategy = syncStrategy.value;
  // [镜像守卫诊断] 记录 mode 来源：UI 当前值 vs 设备历史值（定位"增量却弹镜像"）
  logger.info('sync', `策略来源: UI=${syncStrategy.value} 设备历史=${device.syncStrategy} 对象=${device.name}(${device.fingerprint})`);
  // 唤醒对端接收服务：连接问候触发对端自动拉起接收服务器，
  // 探针就绪前查清单会拿到空清单 → 误判全量重传 + 冲突重命名
  let portReady = false;
  try {
    await greetPeer(targetDevice.value!.ip, targetDevice.value!.port);
    for (let i = 0; i < 8; i++) {
      try {
        if (await invoke<boolean>('probe_peer_port', { ip: targetDevice.value!.ip, port: targetDevice.value!.port })) {
          portReady = true;
          break;
        }
      } catch {
        // 探测命令异常按未就绪处理
      }
      await new Promise((r) => setTimeout(r, 500));
    }
  } catch (e) {
    // 对端离线或不可达
    throw new Error(`无法连接「${targetDevice.value!.name}」(${targetDevice.value!.ip})：对方未响应，请确认目标端已启用接收服务`);
  }
  if (!portReady) {
    throw new Error(`「${targetDevice.value!.name}」(${targetDevice.value!.ip}) 的接收服务未就绪，请稍后重试`);
  }
  // 多目录聚合：每个发送文件夹扫描 + 根目录名前缀，合并后一次三路对比
  // folders 参数用于「拖文件夹到悬浮球」：只同步指定的那一个文件夹
  const sendSrc = folders ?? effectiveSendFolders.value;
  const allFiles: { relPath: string; size: number; mtime: number }[] = [];
  const absByRel = new Map<string, string>();
  for (const f of sendSrc) {
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
  // 防重放：指纹级持久化防重弹（taskId 级 isDialogShown 在每次自动恢复新建任务后会失效，
  // 导致"增量模式仍弹镜像确认"——BUG-9 复盘后改按目标指纹 + localStorage 记录）
  if (device.syncStrategy === 'mirror' && plan.peerExtra.length > 0 && !mirrorAlreadyAsked(targetDevice.value!.fingerprint)) {
    mirrorConfirming.value = true;
    try {
      const ok = await askConfirmAsync({
        title: '镜像模式确认',
        message: `即将把「${targetDevice.value!.name}」上 ${plan.peerExtra.length} 个多余文件移入其 delete 文件夹。`,
        danger: true,
      });
      // 无论确认还是取消都记录，防重弹；taskId 级标志同步置位
      markMirrorAsked(targetDevice.value!.fingerprint);
      markDialogShown(taskId);
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
    // 即使无事可传，扫描结果本身也是一次有效的 manifest 快照
    const newManifest = buildManifest(allFiles);
    markBackupDone(state, targetDevice.value!.fingerprint, newManifest, Date.now());
    // 必须写回 devices 记录：confirmAllPairs 从这里读取落库，
    // 否则永远存空对象（循环空写），重启后增量规划仍退化为全量
    device.lastManifest = newManifest;
    saveState(state);
    confirmAllPairs();
    return 0;
  }
  // 传输 relPath 带发送根目录名前缀；本地读取用各文件夹原始路径（absByRel 映射）
  const files = plan.toTransfer.map((f) => ({
    relPath: f.relPath,
    absPath: absByRel.get(f.relPath) || '',
  }));
  emitBall('syncing', `正在传输 ${files.length} 个文件…`);
  const sent = await invoke<number>('send_files', {
    targetIp: targetDevice.value!.ip,
    targetPort: targetDevice.value!.port,
    targetCode: targetDevice.value!.fingerprint,
    files,
    encryptionMode: encryptionMode.value,
  });
  const newManifest = buildManifest(allFiles);
  markBackupDone(state, targetDevice.value!.fingerprint, newManifest, Date.now());
  // 同上：写回 devices 记录供 confirmAllPairs 落库（防循环空写）
  device.lastManifest = newManifest;
  saveState(state);
  // 新增：同步完成后将 lastManifest 写入 SQLite，下次 App.vue 重启或 mergePeers 可直接恢复
  confirmAllPairs();
  emitBall('idle');  // 同步结束，主动收回 idle
  return sent;
}

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
/** 长按计时与发光状态：单向/双向均长按1.7s=动作（收=切自动接收 / 发=发件）；双向短按=切自动接收 */
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

// ---------- 执行备份 ----------
async function runBackup(onlyFolders?: SendFolder[]) {
  if (scanning.value) return;
  const t = targetDevice.value;
  if (!t) {
    errorMsg.value = '请先在「设备」页完成连接，并在「同步」页选择目标设备';
    return;
  }
  // onlyFolders 参数用于「拖文件夹到悬浮球」：只同步指定的那一个文件夹
  const sendSrc = onlyFolders ?? effectiveSendFolders.value;
  const hasSend = sendSrc.length > 0;
  const hasRecv = receiverEnabled.value && !!boxP2c.value;
  if (!hasRecv && !hasSend) {
    errorMsg.value = '请至少配置一个备份方向（接收目录或发送文件夹）';
    return;
  }
  errorMsg.value = '';
  lastResult.value = '';
  progressInfo.value = null;
  emitBall('scanning', '正在准备同步…');
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
    // 发送方向：多文件夹聚合推送到手机（onlyFolders 时只同步指定的一个）
    if (hasSend) {
      scanning.value = true;
      const sent = await sendAllFolders(task.id, onlyFolders);
      scanning.value = false;
      completeTask(task.id);
      activeTaskId.value = '';
      emitBall('success', `已推送 ${sent} 个文件`);
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
    emitBall('failure', msg);
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

/** 拖文件夹到悬浮球 → 找一个已配对设备，只同步拖入的那一个文件夹 */
async function handleDropSync(path: string) {
  if (!isTauri) return;
  const dev = pairings.value.find((p) => p.connected) ?? pairings.value[0];
  if (!dev) {
    pushToast('error', '没有可用的已配对设备，无法同步');
    emitBall('toast_confused');
    return;
  }
  if (!targetDevice.value || targetDevice.value.fingerprint !== dev.fingerprint) {
    targetDevice.value = dev;
  }
  const name = path.split(/[\\/]/).filter(Boolean).pop() || 'folder';
  const folder: SendFolder = { id: `drop-${Date.now()}`, name, path, enabled: true };
  emitBall('success'); /* 接住文件夹：先开心一下 */
  pushToast('ok', `开始同步「${name}」→ ${dev.name}`);
  // 延迟片刻让「开心」演出，再进入扫描/同步
  setTimeout(() => {
    runBackup([folder]).catch(() => {});
  }, 900);
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

// 重置状态：二次确认（删除全部程序数据，不可撤销）
function requestResetAll() {
  resetting.value = false;
  askConfirm({
    title: '重置状态',
    message: '将删除本机全部数据：所有配对设备、传输历史、同步记录与本机身份密钥，且不可撤销。确定继续？',
    danger: true,
    action: () => {
      askConfirm({
        title: '再次确认重置',
        message: '此操作不可撤销。确认后本机将变成一台「全新设备」，所有旧配对立即失效，需重新配对才能传输。',
        danger: true,
        action: resetAll,
      });
    },
  });
}
const resetting = ref(false);
async function resetAll() {
  if (resetting.value) return;
  resetting.value = true;
  try {
    await invoke('reset_all_state');
    // 清空前端所有配对/设备状态（后端已清库，前端镜像同步清空）
    for (const r of pairMgr.all()) pairMgr.remove(r.fingerprint);
    pairings.value = [];
    targetDevice.value = null;
    // 本机身份已是全新设备，重新拉取
    selfInfo.value = await invoke<{ name: string; id: string; code: string }>('get_self_info');
    // 清空本机持久化的设备/传输记录
    localStorage.removeItem(STATE_KEY);
    saveState(createEmptyState(selfInfo.value.code, selfInfo.value.name));
    lastResult.value = '已重置：全部数据清除完成，本机已生成全新身份';
    logger.info('reset', '程序全部数据已重置');
  } catch (e) {
    errorMsg.value = `重置失败: ${(e as Error).message}`;
    logger.error('reset', '重置失败', e);
  } finally {
    resetting.value = false;
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

  <!-- 删除烟雾流体滤镜：feTurbulence(颗粒漂移) + feDisplacementMap(流体形变) + blur(雾化)
       由 smokeDissolve 在删除项离场时应用，并持续抖动 baseFrequency 制造烟雾感 -->
  <svg class="smoke-filter-svg" width="0" height="0" aria-hidden="true" focusable="false">
    <filter id="smoke-filter" x="-40%" y="-80%" width="180%" height="260%">
      <feTurbulence id="smoke-turb" type="fractalNoise" baseFrequency="0.028" numOctaves="4" seed="7" result="n" />
      <feDisplacementMap in="SourceGraphic" in2="n" scale="22" />
      <feGaussianBlur stdDeviation="2.6" />
    </filter>
  </svg>

  <!-- 自绘悬浮滚动条（主页面已隐藏原生滚动条） -->
  <GlassScrollbar />

  <!-- 液态玻璃标题栏：标题 + 窗口控制；整条栏可拖动（按钮除外），分界线之下不可拖动 -->
  <header class="titlebar" @mousedown="onHeaderDrag">
    <h1>局域网备份</h1>
    <div class="titlebar-actions">
      <button class="win-btn" :title="darkMode ? '切换到浅色' : '切换到深色'" :aria-label="darkMode ? '切换到浅色' : '切换到深色'" @click="darkMode = !darkMode">{{ darkMode ? '🌙' : '☀️' }}</button>
      <button class="win-btn" aria-label="最小化" title="最小化" @click="appWin?.minimize()"><span class="g-min" aria-hidden="true"></span></button>
      <button class="win-btn close" aria-label="关闭" title="关闭" @click="appWin?.close()"><span class="g-x" aria-hidden="true"></span></button>
    </div>
  </header>

  <div class="app-shell">
    <!-- 连接码行：普通内容区（不可拖动），点击连接码即复制 -->
    <div class="app-codebar">
      <button class="code-copy" title="点击复制连接码" aria-label="点击复制连接码" @click="copyText(selfInfo.code, '连接码已复制')">
        连接码：<strong class="self-code">{{ selfInfo.code }}</strong><span class="copy-hint">点击复制</span>
      </button>
      <button class="mini-btn" title="重置连接码" aria-label="重置连接码" @click="refreshSelfCode2">
        <svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><path d="M13.5 8a5.5 5.5 0 1 1-1.62-3.9" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M12.3 1.6v2.9H9.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </button>
      <span class="header-name">{{ selfInfo.name || '本机' }}</span>
    </div>

    <!-- 消息队列：多条提示堆叠显示，互不遮挡 -->
    <div class="toast-stack" role="status" aria-live="polite">
      <TransitionGroup name="toast-drop" tag="div">
        <!-- P1-UA2：错误 toast 用 role=alert（assertive）立即播报，普通提示用 status（polite） -->
        <p v-for="t in toasts" :key="t.id" class="toast" :class="{ error: t.kind === 'error' }" :role="t.kind === 'error' ? 'alert' : undefined">{{ t.text }}</p>
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
          <h2 class="glass-card-title">我的设备（{{ pairedList.length }}）</h2>
          <p v-if="pairedList.length === 0" class="muted">暂无已连接设备。完成连接后，每次运行会自动寻找对方。</p>
          <TransitionGroup v-else name="lg-list" tag="div" class="device-list" @leave="listLeave">
            <div v-for="p in pairedList" :key="p.fingerprint" class="paired-row">
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
        <LiquidGlass :corner-radius="26" padding="18px 20px">
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

      <!-- ========== 同步页（主页：状态总览 + 收发配置） ========== -->
      <section class="page-inner page-off" :data-page="'backup'">
        <!-- 开始同步（常驻首屏，不随角色隐藏：方向 + 策略 + 目标设备 + 文件夹列表 + 同步按钮） -->
        <LiquidGlass :corner-radius="26" padding="20px 18px">
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
                v-for="p in targetOptions"
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
              <div v-if="targetOptions.length === 0" class="dd-empty">还没有配对设备，请先到「设备」页连接</div>
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
            <div class="drop-zone mt-xs" role="button" tabindex="0" @click="addSessionFolder" @keydown.enter.prevent="addSessionFolder" @dragover.prevent @drop.prevent="onDropSessionFolders">
              <span>＋ 点击选择或拖拽新增临时文件夹（本次会话，重启清空）</span>
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
          <TransitionGroup name="lg-list" tag="div" class="device-list" @leave="listLeave">
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
          </TransitionGroup>
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
            <h2 class="glass-card-title" style="margin: 0">传输记录（{{ displayTransfers.length }} 条）</h2>
            <button v-if="displayTransfers.length" class="glass-btn small danger" @click="clearAllTransfers">清空记录</button>
          </div>
          <p v-if="displayTransfers.length === 0" class="muted">暂无传输记录。完成一次同步后这里会显示方向、文件数、大小、耗时与速率。</p>
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
                      <button class="glass-btn small" title="删除这条记录" aria-label="删除这条记录" @click="deleteTransfer(t.id)"><AppIcon name="close" :size="11" /></button>
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
        <LiquidGlass :corner-radius="26" padding="18px 20px">
          <h2 class="glass-card-title">设备信息</h2>
          <p class="muted">本机公开标识：{{ selfInfo.id ? selfInfo.id.slice(0, 8) + '…' : '' }}</p>
          <input class="glass-input" v-model="deviceNameInput" placeholder="设备名（如 PC 1）" @blur="flushDeviceName" />
          <p class="muted">输入后自动保存；重置连接码请点顶部连接码旁的刷新按钮</p>
        </LiquidGlass>

        <!-- 悬浮球：是否在桌面显示悬浮球（持久化，默认开启） -->
        <LiquidGlass :corner-radius="26" padding="18px 20px">
          <div class="history-head">
            <h2 class="glass-card-title" style="margin: 0">悬浮球</h2>
            <GlassSwitch :model-value="ballEnabled" label="显示悬浮球" @update:model-value="setBallEnabled" />
          </div>
          <p class="muted">开启后在桌面显示悬浮球，实时反馈同步 / 接收状态；关闭即隐藏</p>
        </LiquidGlass>

        <!-- 自动收件：与「调试」同构（标题+开关同排），独立成卡，避免设备信息卡过长 -->
        <LiquidGlass :corner-radius="26" padding="18px 20px">
          <div class="history-head">
            <h2 class="glass-card-title" style="margin: 0">自动收件</h2>
            <GlassSwitch :model-value="autoStartReceiver" label="启动时自动开启收件" @update:model-value="toggleAutoStartReceiver" />
          </div>
          <p class="muted">启动后自动开启收件服务，随时接收对方推送</p>
        </LiquidGlass>

        <!-- 加密传输：分段选择 + 一句话说明，独立成卡 -->
        <LiquidGlass :corner-radius="26" padding="18px 20px">
          <h2 class="glass-card-title">加密传输</h2>
          <GlassSeg
            v-model="encryptionMode"
            label="加密强度"
            :options="[
              { id: 'simple', label: '简单' },
              { id: 'ecdh', label: '复杂' },
            ]"
            @update:model-value="persistConfig"
          />
          <p class="muted">复杂（ECDH）需两端支持，密钥协商更安全；简单基于连接码派生</p>
        </LiquidGlass>

        <!-- 同步策略：增量 / 镜像（从同步页移入设置页） -->
        <LiquidGlass :corner-radius="26" padding="18px 20px">
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
        <LiquidGlass :corner-radius="26" padding="18px 20px">
          <h2 class="glass-card-title">发件区配置</h2>
          <p class="muted">永久发件文件夹：程序关闭后仍保留，默认每次都参与同步</p>
          <TransitionGroup name="lg-list" tag="div" class="device-list" @leave="listLeave">
            <div v-for="f in displaySenderFolders" :key="f.id" class="paired-row">
              <span class="status-dot" :class="{ on: f.enabled }"></span>
              <div class="device-main">
                <strong>{{ f.name }}<span v-if="debugEnabled && isDebugFolder(f.id)" class="perm-tag">调试</span></strong>
                <span class="muted" style="margin: 0">{{ f.path }}</span>
              </div>
              <button class="glass-btn small" @click="toggleSendFolder(f.id)">{{ f.enabled ? '禁用' : '启用' }}</button>
              <button class="glass-btn small danger" title="移除文件夹" aria-label="移除文件夹" @click="confirmRemoveSendFolder(f)"><AppIcon name="close" :size="11" /></button>
            </div>
          </TransitionGroup>
          <div class="drop-zone mt-xs" role="button" tabindex="0" @click="addSendFolder" @keydown.enter.prevent="addSendFolder" @dragover.prevent @drop.prevent="onDropFolders">
            <span>＋ 点击选择文件夹（可多选，永久保存）或拖拽到此处</span>
          </div>
        </LiquidGlass>

        <!-- 收件区配置：收件目录 + 收件服务开关（从同步页迁移） -->
        <LiquidGlass :corner-radius="26" padding="18px 20px">
          <h2 class="glass-card-title">收件区配置</h2>
          <p class="muted">收件目录（保存对方推送的文件）</p>
          <div class="root-row" :class="{ checked: displayRecvDir }" role="button" tabindex="0" @click="pickBoxP2c" @keydown.enter.prevent="pickBoxP2c">
            <span class="root-check">{{ displayRecvDir ? '✓' : '＋' }}</span>
            <span class="root-name">{{ displayRecvDir || '选择收件目录' }}</span>
            <button v-if="debugEnabled && debugRecvDir" class="glass-btn small danger root-del" title="移除调试收件目录" aria-label="移除调试收件目录" @click.stop="resetDebugRecv"><AppIcon name="close" :size="11" /></button>
          </div>
          <div class="row mt-md">
            <span class="muted" style="margin: 0; flex: 1">收件服务</span>
            <button v-if="serverRunning" class="glass-btn small danger" @click="oneClickCloseReceive">一键关闭</button>
            <button v-else-if="receiverEnabled && recvStarting" class="glass-btn small" disabled>启用中…</button>
            <button v-else class="glass-btn small primary" @click="oneClickReceive">一键开启</button>
          </div>
        </LiquidGlass>

        <LiquidGlass :corner-radius="26" padding="18px 20px">
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

        <LiquidGlass :corner-radius="26" padding="18px 20px">
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

        <!-- 重置状态：危险操作，删除程序全部数据 -->
        <LiquidGlass :corner-radius="26" padding="18px 20px">
          <h2 class="glass-card-title danger-title">重置状态</h2>
          <p class="muted">删除本机全部数据：所有配对设备、传输历史、同步记录与本机身份密钥，恢复为全新设备。此操作不可撤销。</p>
          <div class="row">
            <button class="glass-btn danger" :disabled="resetting" @click="requestResetAll">
              {{ resetting ? '重置中…' : '重置状态' }}
            </button>
          </div>
        </LiquidGlass>

        <LiquidGlass :corner-radius="26" padding="18px 20px">
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
    <div v-if="incomingReq" class="incoming-overlay" role="dialog" aria-modal="true" aria-label="收件请求" ref="incomingOverlayRef" tabindex="-1" @keydown="(e) => { if (e.key === 'Tab') { e.preventDefault(); const btns = incomingOverlayRef?.querySelectorAll<HTMLElement>('button:not(:disabled)'); if (btns?.length) btns[0]?.focus(); } }">
      <div class="incoming-card">
        <h3 class="glass-card-title">收件请求</h3>
        <p class="muted">来自「{{ incomingReq.senderName || incomingReq.senderIp }}」请求发送 {{ incomingReq.count }} 个文件</p>
        <p class="muted">共 {{ fmtBytes(incomingReq.totalBytes) }}，是否同意接收？</p>
        <div class="row mt-md">
          <button class="glass-btn danger" autofocus @click="acceptIncoming(false)">拒绝</button>
          <button class="glass-btn primary" @click="acceptIncoming(true)">接受</button>
        </div>
      </div>
    </div>

    <!-- 配对确认弹窗（对方填写了本机连接码请求配对） -->
    <div v-if="pairingReq" class="incoming-overlay" role="dialog" aria-modal="true" aria-label="连接请求" ref="pairingOverlayRef" tabindex="-1" @keydown="(e) => { if (e.key === 'Tab') { e.preventDefault(); const btns = pairingOverlayRef?.querySelectorAll<HTMLElement>('button:not(:disabled)'); if (btns?.length) btns[0]?.focus(); } }">
      <div class="incoming-card">
        <h3 class="glass-card-title">连接请求</h3>
        <p class="muted">「{{ pairingReq.name }}」（{{ pairingReq.ip }}）正确填写了本机连接码，请求与你连接</p>
        <p class="muted">是否同意连接？</p>
        <div class="row mt-md">
          <button class="glass-btn danger" autofocus @click="acceptPairing(false)">拒绝</button>
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
          <div class="dock-kv code-kv" role="button" tabindex="0" title="点击复制连接码" @click="copyText(selfInfo.code || '', '连接码已复制')" @keydown.enter="copyText(selfInfo.code || '', '连接码已复制')"><span>连接码</span><strong class="self-code">{{ selfInfo.code || '—' }}</strong></div>
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
