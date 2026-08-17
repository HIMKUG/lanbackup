<template>
  <!-- 自绘悬浮滚动条：主页面隐藏原生滚动条后由它接管。
       悬浮在内容之上（不占布局宽度），滚动时淡入、停止后淡出，可拖动。 -->
  <div v-if="thumbH < trackH" class="gscroll" :class="{ dragging }" aria-hidden="true">
    <div
      ref="thumbRef"
      class="gscroll-thumb"
      :style="{ height: thumbH + 'px', transform: 'translateY(' + thumbY + 'px)', opacity: visible ? 1 : 0 }"
      @pointerdown="onThumbDown"
    ></div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';

const visible = ref(false);
const dragging = ref(false);
const thumbRef = ref<HTMLElement | null>(null);

const viewH = ref(0);
const scrollH = ref(0);
const scrollY = ref(0);

/* 轨道长度与 CSS 内边距保持一致（上 30 + 下 96） */
const trackH = computed(() => Math.max(0, viewH.value - 126));
const thumbH = computed(() => {
  const ratio = viewH.value / Math.max(1, scrollH.value);
  /* 能长能短：按内容比例伸缩，但封顶 45% 轨道长、保底 28px */
  return Math.min(Math.round(trackH.value * 0.45), Math.max(28, Math.round(ratio * trackH.value)));
});
const maxScroll = computed(() => Math.max(1, scrollH.value - viewH.value));
const thumbY = computed(() => (scrollY.value / maxScroll.value) * Math.max(0, trackH.value - thumbH.value));

let hideTimer: ReturnType<typeof setTimeout> | null = null;
let dragOffset = 0;
let rafId = 0;

function measure() {
  viewH.value = window.innerHeight;
  scrollH.value = document.documentElement.scrollHeight;
  scrollY.value = window.scrollY;
}

function show() {
  visible.value = true;
  if (hideTimer) clearTimeout(hideTimer);
  hideTimer = setTimeout(() => {
    if (!dragging.value) visible.value = false;
  }, 900);
}

/* rAF 节流：滚动事件高频触发时不重复读布局（scrollHeight 会强制布局） */
function onScroll() {
  if (rafId) return;
  rafId = requestAnimationFrame(() => {
    rafId = 0;
    measure();
    show();
  });
}

function onResize() {
  measure();
}

function onThumbDown(e: PointerEvent) {
  dragging.value = true;
  dragOffset = e.clientY - thumbY.value;
  (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
}

function onThumbMove(e: PointerEvent) {
  if (!dragging.value) return;
  const t = Math.max(0, trackH.value - thumbH.value);
  const y = Math.max(0, Math.min(t, e.clientY - dragOffset));
  window.scrollTo(0, (y / Math.max(1, t)) * maxScroll.value);
}

function onThumbUp() {
  dragging.value = false;
  show();
}

onMounted(() => {
  measure();
  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onResize);
  window.addEventListener('pointermove', onThumbMove);
  window.addEventListener('pointerup', onThumbUp);
});

onUnmounted(() => {
  window.removeEventListener('scroll', onScroll);
  window.removeEventListener('resize', onResize);
  window.removeEventListener('pointermove', onThumbMove);
  window.removeEventListener('pointerup', onThumbUp);
  if (hideTimer) clearTimeout(hideTimer);
  if (rafId) cancelAnimationFrame(rafId);
});
</script>
