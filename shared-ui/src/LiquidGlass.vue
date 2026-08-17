<template>
  <!-- 液态玻璃四层：canvas 模糊底（按 3/5fps 采样视频帧，壁纸本身不锁帧）/
       tint(半透明着色) / shine(镜面高光) / text(内容) -->
  <div class="liquidGlass-wrapper" :style="{ borderRadius: cornerRadius + 'px', padding }">
    <canvas ref="blurCanvas" class="liquidGlass-blur" aria-hidden="true"></canvas>
    <div class="liquidGlass-tint" aria-hidden="true"></div>
    <div class="liquidGlass-shine" aria-hidden="true"></div>
    <div class="liquidGlass-text">
      <slot />
    </div>
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue';
import { registerBlurCard, unregisterBlurCard } from './blurSampler';

withDefaults(
  defineProps<{
    cornerRadius?: number;
    padding?: string;
  }>(),
  { cornerRadius: 18, padding: '14px 16px' },
);

const blurCanvas = ref<HTMLCanvasElement | null>(null);

/** 把视频当前帧中本卡背后的区域模糊后画到 canvas（每 333/200ms 由采样器调用） */
function drawBlur() {
  const c = blurCanvas.value;
  if (!c) return;
  const video = document.querySelector<HTMLVideoElement>('video.wallpaper-video');
  if (!video || video.readyState < 2 || !video.videoWidth) return;
  const wrapper = c.parentElement as HTMLElement;
  const r = wrapper.getBoundingClientRect();
  if (r.width < 1 || r.height < 1) return;
  const vw = video.videoWidth;
  const vh = video.videoHeight;
  const dw = window.innerWidth;
  const dh = window.innerHeight;
  // object-fit: cover 的裁剪映射：视频显示区域 = 视口
  const scale = Math.max(dw / vw, dh / vh);
  const dispW = vw * scale;
  const dispH = vh * scale;
  const ox = (dw - dispW) / 2;
  const oy = (dh - dispH) / 2;
  const dpr = Math.min(window.devicePixelRatio || 1, 2); // 上限 2x，控制 canvas 内存
  const cw = Math.max(1, Math.round(r.width * dpr));
  const ch = Math.max(1, Math.round(r.height * dpr));
  if (c.width !== cw || c.height !== ch) {
    c.width = cw;
    c.height = ch;
  }
  const sx = (r.left - ox) / scale;
  const sy = (r.top - oy) / scale;
  const sw = r.width / scale;
  const sh = r.height / scale;
  const ctx = c.getContext('2d');
  if (!ctx) return;
  ctx.filter = 'blur(6px) saturate(1.4)';
  ctx.clearRect(0, 0, cw, ch);
  try {
    ctx.drawImage(video, sx, sy, sw, sh, 0, 0, cw, ch);
  } catch {
    // 视口外/越界：留空
  }
  ctx.filter = 'none';
}

onMounted(() => {
  if (blurCanvas.value) registerBlurCard(blurCanvas.value, drawBlur);
});

onBeforeUnmount(() => {
  if (blurCanvas.value) unregisterBlurCard(blurCanvas.value);
});
</script>
