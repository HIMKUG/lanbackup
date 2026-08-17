/**
 * 全局 GSAP 悬浮呼吸系统（一镜到底）：
 * 事件委托挂到 document，所有控件与玻璃大框获得连续、非线性的
 * 「抬起 + 发光」悬浮动画——power3.out 抬起、elastic 呼吸回落、
 * 按压快压慢弹。被管理的元素加 .glow-hover-mgr 禁用 CSS 过渡，避免与 GSAP 打架。
 *
 * shared-ui 不依赖 gsap 包：由应用把自己的 gsap 实例传进来。
 */
export interface GsapLike {
  to(targets: unknown, vars: Record<string, unknown>): unknown;
  set(targets: unknown, vars: Record<string, unknown>): unknown;
  killTweensOf(targets: unknown): void;
}

/** 参与呼吸悬浮的全部控件（大框 + 小控件） */
const HOVERABLE = [
  '.liquidGlass-wrapper',
  '.glass-btn',
  '.glass-chip',
  '.gseg',
  '.gswitch',
  '.dock-tab',
  '.dock-status',
  '.win-btn',
  '.mini-btn',
  '.theme-btn',
  '.root-row',
  '.device-item',
  '.dd-trigger',
  '.hist-group-head',
  '.codebox',
  '.ipbox',
  '.status-cell',
  '.dock-kv',
].join(',');

const isBig = (el: HTMLElement) => el.classList.contains('liquidGlass-wrapper');

export function installGlowHover(gsap: GsapLike): () => void {
  if (typeof window === 'undefined') return () => {};
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return () => {};

  const hovered = new WeakSet<HTMLElement>();

  function targetOf(e: Event): HTMLElement | null {
    const el = (e.target as HTMLElement | null)?.closest<HTMLElement>(HOVERABLE);
    if (!el) return null;
    if ((el as HTMLButtonElement).disabled) return null;
    return el;
  }

  /** 元素的原始阴影（首次悬浮时记录，回落后恢复并由 CSS 变量继续接管） */
  function baseShadow(el: HTMLElement): string {
    if (!el.dataset.glowShadow) el.dataset.glowShadow = getComputedStyle(el).boxShadow;
    return el.dataset.glowShadow;
  }

  function onOver(e: PointerEvent) {
    if (e.pointerType !== 'mouse') return;
    const el = targetOf(e);
    if (!el || hovered.has(el)) return;
    if (e.relatedTarget && el.contains(e.relatedTarget as Node)) {
      hovered.add(el);
      return;
    }
    hovered.add(el);
    el.classList.add('glow-hover-mgr');
    const big = isBig(el);
    gsap.killTweensOf(el);
    gsap.to(el, {
      y: big ? -4 : -3,
      scale: big ? 1.004 : 1.02,
      boxShadow: `${baseShadow(el)}, ${big ? '0 0 34px rgba(255,255,255,0.18)' : '0 0 22px rgba(13,148,136,0.28)'}`,
      duration: 0.55,
      ease: 'power3.out',
      overwrite: 'auto',
    });
  }

  function onOut(e: PointerEvent) {
    const el = targetOf(e);
    if (!el || !hovered.has(el)) return;
    if (e.relatedTarget && el.contains(e.relatedTarget as Node)) return;
    hovered.delete(el);
    gsap.killTweensOf(el);
    gsap.to(el, {
      y: 0,
      scale: 1,
      boxShadow: el.dataset.glowShadow || 'none',
      duration: 0.9,
      ease: 'elastic.out(1, 0.5)',
      overwrite: 'auto',
      onComplete: () => {
        el.style.boxShadow = '';
        el.style.transform = '';
      },
    });
  }

  function onDown(e: PointerEvent) {
    const el = targetOf(e);
    if (!el) return;
    gsap.to(el, {
      scale: isBig(el) ? 0.985 : 0.95,
      y: 0,
      duration: 0.12,
      ease: 'power2.out',
      overwrite: 'auto',
    });
  }

  function onUp(e: PointerEvent) {
    const el = targetOf(e);
    if (!el) return;
    gsap.to(el, {
      scale: hovered.has(el) ? (isBig(el) ? 1.004 : 1.02) : 1,
      y: hovered.has(el) ? (isBig(el) ? -4 : -3) : 0,
      duration: 0.6,
      ease: 'elastic.out(1, 0.5)',
      overwrite: 'auto',
    });
  }

  document.addEventListener('pointerover', onOver);
  document.addEventListener('pointerout', onOut);
  document.addEventListener('pointerdown', onDown);
  document.addEventListener('pointerup', onUp);

  return () => {
    document.removeEventListener('pointerover', onOver);
    document.removeEventListener('pointerout', onOut);
    document.removeEventListener('pointerdown', onDown);
    document.removeEventListener('pointerup', onUp);
  };
}
