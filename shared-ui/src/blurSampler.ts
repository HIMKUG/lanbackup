/**
 * 全局模糊采样器（shared-ui 内部模块，不导出）：
 * 壁纸视频保持全帧率播放（不锁帧），液态玻璃卡片的模糊由内部 canvas
 * 按 3fps(中)/12fps(高) 采样绘制——backdrop-filter 无法限频，canvas 是
 * 唯一能"只采样 N 帧背景"的技术手段。
 *
 * 性能优化（已与用户确认）：
 *  - D：页面不可见（切后台/窗口最小化）时暂停采样定时器，恢复可见后重建
 *  - E：滚动期间（html.lg-is-scrolling）降频到约 1/3，停下立即恢复
 */

/** wrapper → draw 回调 */
const cards = new Map<HTMLElement, () => void>();

let timer: ReturnType<typeof setInterval> | null = null;
let baseMs = 0; // 由 setBlurInterval 设定的基准间隔（0 = 停止采样）
let scrolling = false; // 滚动状态（html.lg-is-scrolling 类）
let currentMs = 0; // 当前生效间隔（用于比较是否需重建定时器）

/** 当前生效间隔：滚动时降频到约 1/3（至少 200ms 防止过度降帧） */
function effectiveMs(): number {
  if (baseMs <= 0) return 0;
  return scrolling ? Math.max(200, baseMs * 3) : baseMs;
}

function updateTimer() {
  const ms = effectiveMs();
  // P2-UA5：用户偏好减少动效时，完全不启动高频采样（CSS 静态模糊已够用），
  // 降低 CPU/电量消耗，同时避免背地里高频重绘与用户的 motion 偏好相悖。
  const reduceMotion = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  // 无可采样卡片 / 后台不可见 / 停止采样 / 偏好减少动效 → 清掉定时器
  if (cards.size === 0 || document.hidden || ms <= 0 || reduceMotion) {
    if (timer) {
      clearInterval(timer);
      timer = null;
      currentMs = 0;
    }
    return;
  }
  if (timer && currentMs === ms) return; // 同频不动
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
  currentMs = ms;
  timer = setInterval(() => {
    for (const draw of cards.values()) draw();
  }, ms);
}

/** 注册一张卡片的模糊绘制（quality 变化时 setBlurInterval 重设频率） */
export function registerBlurCard(wrapper: HTMLElement, draw: () => void): void {
  cards.set(wrapper, draw);
  updateTimer();
}

export function unregisterBlurCard(wrapper: HTMLElement): void {
  cards.delete(wrapper);
  updateTimer();
}

/** 由 App 按画面质量设置采样间隔：高=12fps(83ms) / 中=3fps(333ms) / 低=0(停止) */
export function setBlurInterval(ms: number): void {
  baseMs = ms;
  updateTimer();
  if (effectiveMs() > 0) {
    // 立即画一帧，避免切换档位后背景空白
    for (const draw of cards.values()) draw();
  }
}

// ── 性能优化 D：页面不可见时暂停采样，恢复可见时重建定时器 ──
if (typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', updateTimer);
}

// ── 性能优化 E：滚动期间（html.lg-is-scrolling）降频采样，停下恢复 ──
if (typeof document !== 'undefined' && document.documentElement) {
  const rootEl = document.documentElement;
  const mo = new MutationObserver(() => {
    const s = rootEl.classList.contains('lg-is-scrolling');
    if (s !== scrolling) {
      scrolling = s;
      updateTimer();
    }
  });
  mo.observe(rootEl, { attributes: true, attributeFilter: ['class'] });
}
