/**
 * 全局模糊采样器（shared-ui 内部模块，不导出）：
 * 壁纸视频保持全帧率播放（不锁帧），液态玻璃卡片的模糊由内部 canvas
 * 按 3fps(中)/5fps(高) 采样绘制——backdrop-filter 无法限频，canvas 是
 * 唯一能"只采样 N 帧背景"的技术手段。
 */

/** wrapper → draw 回调 */
const cards = new Map<HTMLElement, () => void>();

let timer: ReturnType<typeof setInterval> | null = null;
let currentMs = 0;

function updateTimer() {
  if (cards.size === 0) {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    return;
  }
  if (timer && currentMs > 0) return; // 已有同频定时器
  if (timer) clearInterval(timer);
  if (currentMs > 0) {
    timer = setInterval(() => {
      for (const draw of cards.values()) draw();
    }, currentMs);
  }
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

/** 由 App 按画面质量设置采样间隔：高=5fps(200ms) / 中=3fps(333ms) / 低=0(停止) */
export function setBlurInterval(ms: number): void {
  currentMs = ms;
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
  updateTimer();
  if (ms > 0) {
    // 立即画一帧，避免切换档位后背景空白
    for (const draw of cards.values()) draw();
  }
}
