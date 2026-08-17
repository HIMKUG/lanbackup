<template>
  <!-- 4 段式 IP 输入：点已预置好，引导分段填写；仅数字、自动进格、退格回退、每段 0-255 -->
  <div class="ipboxes" role="group" :aria-label="label">
    <template v-for="(seg, i) in segs" :key="i">
      <input
        :ref="(el) => setBox(i, el)"
        class="ipbox"
        :value="seg"
        maxlength="3"
        inputmode="numeric"
        autocomplete="off"
        spellcheck="false"
        :placeholder="'0'"
        @input="onInput(i, $event)"
        @blur="onBlur(i, $event)"
        @keydown="onKey(i, $event)"
        @paste.prevent="onPaste(i, $event)"
      />
      <span v-if="i < 3" class="ipbox-dot" aria-hidden="true">.</span>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, ref } from 'vue';

const props = withDefaults(defineProps<{ modelValue: string; label?: string }>(), { label: 'IP 地址' });
const emit = defineEmits<{ 'update:modelValue': [v: string] }>();

const boxes = ref<(HTMLInputElement | null)[]>([]);
function setBox(i: number, el: unknown) {
  boxes.value[i] = (el as HTMLInputElement) ?? null;
}

const segs = computed(() => {
  const parts = props.modelValue.split('.');
  return [0, 1, 2, 3].map((i) => (parts[i] ?? '').replace(/\D/g, '').slice(0, 3));
});

function clampSeg(s: string) {
  if (!s) return '';
  const n = Math.min(255, parseInt(s, 10));
  return String(n);
}

function commit(next: string[], focusIdx?: number) {
  emit('update:modelValue', next.join('.'));
  if (focusIdx !== undefined) {
    nextTick(() => {
      const el = boxes.value[focusIdx];
      el?.focus();
      if (el && el.value) el.select();
    });
  }
}

function onInput(i: number, e: Event) {
  const el = e.target as HTMLInputElement;
  const raw = el.value.replace(/\D/g, '').slice(0, 3);
  const next = [...segs.value];
  next[i] = raw;
  // 填满 3 位自动跳下一段
  commit(next, raw.length === 3 && i < 3 ? i + 1 : undefined);
}

function onBlur(i: number, e: Event) {
  const el = e.target as HTMLInputElement;
  const clamped = clampSeg(el.value);
  if (clamped !== el.value) {
    const next = [...segs.value];
    next[i] = clamped;
    commit(next);
  }
}

function onKey(i: number, e: KeyboardEvent) {
  if (e.key === 'Backspace' && !segs.value[i] && i > 0) {
    const next = [...segs.value];
    next[i - 1] = '';
    commit(next, i - 1);
    e.preventDefault();
  } else if ((e.key === '.' || e.key === 'ArrowRight') && i < 3) {
    boxes.value[i + 1]?.focus();
  } else if (e.key === 'ArrowLeft' && i > 0) {
    boxes.value[i - 1]?.focus();
  }
}

function onPaste(i: number, e: ClipboardEvent) {
  const text = (e.clipboardData?.getData('text') || '').replace(/\D/g, '').slice(0, 12);
  if (!text) return;
  const next = [...segs.value];
  const chunks = text.match(/.{1,3}/g) ?? [];
  for (let k = 0; k < chunks.length && i + k < 4; k++) next[i + k] = clampSeg(chunks[k]);
  commit(next, Math.min(i + chunks.length, 3));
}
</script>
