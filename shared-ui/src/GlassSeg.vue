<template>
  <!-- N 档分段选择：竖分割线，滑块颜色随选中档位切换（可选） -->
  <div class="gseg" role="radiogroup" :aria-label="label || '分段选择'">
    <span class="gseg-glider" :style="gliderStyle" aria-hidden="true"></span>
    <button
      v-for="(o, i) in options"
      :key="o.id"
      type="button"
      class="gseg-item"
      :class="{ active: modelValue === o.id }"
      role="radio"
      :aria-checked="modelValue === o.id"
      :tabindex="modelValue === o.id ? 0 : -1"
      @click="$emit('update:modelValue', o.id)"
      @keydown.left.prevent="onKey(-1)"
      @keydown.right.prevent="onKey(1)"
      @keydown.up.prevent="onKey(-1)"
      @keydown.down.prevent="onKey(1)"
    >
      {{ o.label }}
    </button>
    <span
      v-for="i in options.length - 1"
      :key="'d' + i"
      class="gseg-divider"
      :style="{ left: `calc(${i} * (100% - 8px) / ${options.length} + 4px)` }"
      aria-hidden="true"
    ></span>
  </div>
</template>

<script setup lang="ts" generic="T extends string">
import { computed } from 'vue';

const props = defineProps<{
  options: { id: T; label: string; color?: string }[];
  modelValue: T;
  label?: string;
}>();

const emit = defineEmits<{ 'update:modelValue': [value: T] }>();

/** P2-UA7：radiogroup 键盘导航（左右/上下切档，循环），roving tabindex */
function onKey(dir: number) {
  const idx = props.options.findIndex((o) => o.id === props.modelValue);
  if (idx < 0) return;
  const next = props.options[(idx + dir + props.options.length) % props.options.length];
  if (next) emit('update:modelValue', next.id);
}

/** 当前选中项下标 */
const activeIdx = computed(() => {
  const i = props.options.findIndex((o) => o.id === props.modelValue);
  return i >= 0 ? i : 0;
});

/** 档位数 */
const n = computed(() => props.options.length);

/** 滑块宽度 ≈ 每档宽度（扣除容器两侧 padding 8px 后均分） */
const gliderWidth = computed(() => {
  // glider 宽度 = (100% - 8px) / n
  // 用 CSS calc 表达，避免硬编码 px
  return `calc((100% - 8px) / ${n.value})`;
});

/** 滑块颜色：优先使用选项中定义的 color，否则 fallback 青色 */
const gliderColor = computed(() => {
  const opt = props.options[activeIdx.value];
  return opt?.color || 'linear-gradient(135deg, rgba(13,148,136,.62), rgba(13,148,136,.4))';
});

/** 滑块样式：宽度 + 位置平移 + 背景色 */
const gliderStyle = computed(() => ({
  width: gliderWidth.value,
  transform: `translateX(${activeIdx.value * 100}%)`,
  background: gliderColor.value,
}));
</script>