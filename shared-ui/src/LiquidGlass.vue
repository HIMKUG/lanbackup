<template>
  <!-- 液态玻璃四层（照搬示例 index.html 结构）：
       canvas(视频采样底座) / effect(backdrop-filter+SVG折射，盖在 canvas 之上) /
       tint(半透明着色) / shine(镜面高光) / text(内容) -->
  <div class="liquidGlass-wrapper" :style="{ borderRadius: cornerRadius + 'px', padding }">
    <canvas ref="blurCanvas" class="liquidGlass-blur" aria-hidden="true"></canvas>
    <div class="liquidGlass-effect" aria-hidden="true"></div>
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

/** 把视频当前帧中本卡背后的区域模糊后画到 canvas（每 333/200ms 由采样器调用）。
    高画质下 canvas 被 CSS display:none 隐藏（offsetParent 为 null），直接跳过不采样 */
function drawBlur() {
  const c = blurCanvas.value;
  if (!c) return;
  if (c.offsetParent === null) return;
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
  const dpr = 1; // 性能优化（已确认）：分辨率上限 1x——小卡片模糊背景 1x/2x 肉眼难辨，绘制/内存省~75%
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
