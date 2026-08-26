<template>
  <!-- #12 SAS 6位数字展示：配对握手完成后、配对确认前显示 -->
  <!-- 格式：123 456（每3位空格分隔），字号加大，固定宽度字体防跳动 -->
  <div class="sas-display" role="status" aria-label="配对安全码">
    <span class="sas-label">{{ label }}</span>
    <span class="sas-digits" aria-live="off">{{ formattedSas }}</span>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

const props = withDefaults(
  defineProps<{
    /** 6位 SAS 字符串（来自 computeSas） */
    sas: string;
    /** 标签文字 */
    label?: string;
  }>(),
  { label: '安全码' },
);

/** 每3位空格分隔：123456 → "123 456" */
const formattedSas = computed(() => {
  const s = (props.sas || '000000').padStart(6, '0');
  return s.slice(0, 3) + ' ' + s.slice(3, 6);
});
</script>

<style scoped>
.sas-display {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  padding: 16px 24px;
  background: rgba(255, 255, 255, 0.06);
  border-radius: 12px;
  border: 1px solid rgba(255, 255, 255, 0.12);
}

.sas-label {
  font-size: 12px;
  color: rgba(255, 255, 255, 0.55);
  text-transform: uppercase;
  letter-spacing: 0.1em;
}

.sas-digits {
  font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 32px;
  font-weight: 700;
  letter-spacing: 0.15em;
  color: #ffffff;
  /* 固定宽度：防止数字变化时宽度跳动 */
  min-width: 7.5ch;
  text-align: center;
}
</style>
