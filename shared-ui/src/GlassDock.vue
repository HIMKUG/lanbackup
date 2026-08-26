<template>
  <div
    class="dock"
    :class="{
      'is-collapsed': collapsed && !expanded,
      'is-expanded': expanded,
      'is-scrolled': scrolled,
    }"
  >
    <!-- 展开态的压暗层：点击收起 -->
    <div class="dock-backdrop" aria-hidden="true" @click="expanded = false"></div>

    <!-- 展开面板（Apple Music “正在播放”位：轻点状态气泡向上展开） -->
    <div class="dock-panel-wrap">
      <div class="dock-panel" role="dialog" aria-label="状态面板">
        <div class="dock-panel-inner">
          <slot name="panel" />
        </div>
      </div>
    </div>

    <!-- 双气泡结构：导航气泡 + 状态气泡 -->
    <div class="dock-row">
      <div ref="navRef" class="dock-bubble dock-nav" role="tablist" aria-label="页面导航">
        <span ref="gliderRef" class="dock-tab-glider" aria-hidden="true"></span>
        <button
          v-for="t in tabs"
          :key="t.id"
          class="dock-tab"
          :class="{ active: modelValue === t.id }"
          role="tab"
          :aria-selected="modelValue === t.id"
          :tabindex="modelValue === t.id ? 0 : -1"
          @click="$emit('update:modelValue', t.id)"
          @keydown.left.prevent="onTabKey(-1)"
          @keydown.right.prevent="onTabKey(1)"
        >
          <span class="tab-icon" aria-hidden="true"><AppIcon :name="(t.icon as never)" :size="30" /></span>
          <span class="tab-label">{{ t.label }}</span>
        </button>
      </div>

      <button
        class="dock-bubble dock-status"
        :class="{ 'is-dual': dual, hold: statusHolding }"
        :aria-expanded="expanded"
        aria-label="展开状态面板"
        @pointerdown="onStatusDown"
        @pointerup="onStatusUp"
        @pointerleave="onStatusCancel"
        @pointercancel="onStatusCancel"
      >
        <span class="hold-fill" aria-hidden="true"></span>
        <span class="status-dot" :class="{ on: statusOn }" aria-hidden="true"></span>
        <span class="dock-status-text">
          <strong>{{ statusTitle }}</strong>
          <small>{{ statusSub }}</small>
        </span>
        <span class="dock-caret" aria-hidden="true">⌃</span>
        <!-- 双向模式：右 1/4 热区点击展开面板（与左 3/4 同步动作分离） -->
        <span v-if="dual" class="status-panel-zone" aria-hidden="true" @pointerdown.stop @click.stop="expanded = true"></span>
      </button>
    </div>
  </div>
</template>

<script setup lang="ts" generic="T extends string">
import { nextTick, onMounted, onUnmounted, ref, watch } from 'vue';
import AppIcon from './AppIcon.vue';

interface DockTab {
  id: T;
  icon: string;
  label: string;
}

const props = withDefaults(
  defineProps<{
    tabs: DockTab[];
    modelValue: T;
    statusTitle?: string;
    statusSub?: string;
    statusOn?: boolean;
    /** 双向模式（收+发都开）：状态按钮左3/4=同步动作 / 右1/4=展开面板 */
    dual?: boolean;
    /** 长按1.7s进入状态（只收→切换自动接收；只发/双向→发件） */
    onSyncLongPress?: () => void;
    /** 双向模式左3/4点击：切换自动接收 */
    onSyncClick?: () => void;
  }>(),
  { statusTitle: '', statusSub: '', statusOn: false, dual: false },
);

/** 状态按钮：单向/双向都支持长按1.7s=动作（收=切换自动接收 / 发=发件）；点击=展开状态面板 */
const statusHolding = ref(false);
let statusTimer: ReturnType<typeof setTimeout> | null = null;
function onStatusDown() {
  if (statusTimer) return;
  statusHolding.value = true;
  statusTimer = setTimeout(() => {
    statusTimer = null;
    statusHolding.value = false;
    props.onSyncLongPress?.();
  }, 1700);
}
function onStatusUp() {
  if (statusTimer) { clearTimeout(statusTimer); statusTimer = null; }
  if (!statusHolding.value) return;
  statusHolding.value = false;
  // 短按（未满1.7s）：点击展开面板
  expanded.value = !expanded.value;
}
function onStatusCancel() {
  if (statusTimer) { clearTimeout(statusTimer); statusTimer = null; }
  statusHolding.value = false;
}

const emit = defineEmits<{ 'update:modelValue': [value: T] }>();

/** P1-UA3：tablist 键盘导航（roving tabindex）。dir=-1 上一项 / 1 下一项，循环滚动 */
function onTabKey(dir: number) {
  const idx = props.tabs.findIndex((t) => t.id === props.modelValue);
  if (idx < 0) return;
  const next = props.tabs[(idx + dir + props.tabs.length) % props.tabs.length];
  if (next) {
    // 用事件对象代理：实际由父组件监听 update:modelValue 更新高亮；focus 由 tabindex 变化驱动
    emit('update:modelValue', next.id);
    // roving: 下一轮 focus 到新激活项（等 DOM 渲染）
    void nextTick(() => {
      navRef.value?.querySelector<HTMLElement>('.dock-tab.active')?.focus();
    });
  }
}

const expanded = ref(false);
const collapsed = ref(false);
const scrolled = ref(false);

/* 页签指示器（glider）：激活底色平滑滑到目标页签；
   Dock 自身宽度变化（滚动收缩/恢复）时逐帧跟随，绝不错位 */
const navRef = ref<HTMLElement | null>(null);
const gliderRef = ref<HTMLElement | null>(null);
let followRaf = 0;

/** 测量激活页签位置并立刻应用（无动画） */
function applyGlider() {
  const g = gliderRef.value;
  if (!g) return;
  const active = navRef.value?.querySelector<HTMLElement>('.dock-tab.active');
  if (!active) {
    g.style.opacity = '0';
    return;
  }
  g.style.opacity = '1';
  g.style.width = active.offsetWidth + 'px';
  g.style.transform = `translateX(${active.offsetLeft}px)`;
}

/** 动画滑动（页面切换，Dock 宽度不变时） */
function glideToActive() {
  const g = gliderRef.value;
  if (!g) return;
  g.style.transition = '';
  nextTick(applyGlider);
  // 若期间 Dock 宽度也在变（如展开态切页），动画结束后校正一次
  setTimeout(applyGlider, 560);
}

/** 逐帧跟随模式：Dock 宽度动画期间（收缩/恢复）每帧重算，与页签完全同步 */
function followActive(durationMs = 560) {
  const g = gliderRef.value;
  if (!g) return;
  cancelAnimationFrame(followRaf);
  g.style.transition = 'none';
  const start = performance.now();
  const step = () => {
    applyGlider();
    if (performance.now() - start < durationMs) followRaf = requestAnimationFrame(step);
    else g.style.transition = '';
  };
  followRaf = requestAnimationFrame(step);
}

/** 供父组件收起展开面板（如面板内“管理设备”按钮） */
function collapsePanel() {
  expanded.value = false;
}

defineExpose({ collapsePanel });

/* 滚动感知（Apple Music iOS 26 行为）：
   - 向下滚动 → Dock 收缩为极窄图标栏，把可视区域还给内容
   - 向上滚动 → 恢复完整形态
   - 同时给 <html> 打标：lg-is-scrolling（控件着色增强）/ lg-is-scrolled（玻璃阴影分离） */
let lastY = 0;
let scrollIdleTimer: ReturnType<typeof setTimeout> | null = null;

function onScroll() {
  const y = window.scrollY;
  const dy = y - lastY;
  scrolled.value = y > 8;
  if (!expanded.value) {
    if (dy > 4 && y > 80) collapsed.value = true;
    else if (dy < -4) collapsed.value = false;
  }
  lastY = y;
  const root = document.documentElement;
  root.classList.add('lg-is-scrolling');
  root.classList.toggle('lg-is-scrolled', scrolled.value);
  if (scrollIdleTimer) clearTimeout(scrollIdleTimer);
  scrollIdleTimer = setTimeout(() => root.classList.remove('lg-is-scrolling'), 220);
}

function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape' && expanded.value) expanded.value = false;
}

/* 切换页面时收起面板，指示器滑到新页签 */
watch(
  () => props.modelValue,
  () => {
    expanded.value = false;
    nextTick(glideToActive);
  },
);

/* 收缩/展开引起页签宽度变化 → 逐帧跟随重算指示器位置 */
watch(collapsed, () => nextTick(() => followActive()));

onMounted(() => {
  lastY = window.scrollY;
  nextTick(applyGlider);
  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('keydown', onKeydown);
  window.addEventListener('resize', onResizeListener);
});

onUnmounted(() => {
  window.removeEventListener('scroll', onScroll);
  window.removeEventListener('keydown', onKeydown);
  window.removeEventListener('resize', onResizeListener);
  cancelAnimationFrame(followRaf);
  if (scrollIdleTimer) clearTimeout(scrollIdleTimer);
  document.documentElement.classList.remove('lg-is-scrolling', 'lg-is-scrolled');
});

function onResizeListener() {
  applyGlider();
}
</script>
