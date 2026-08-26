<template>
  <!-- 固定 8 格连接码输入：只允许字母/数字，自动大写、自动进格、退格回退、支持粘贴分发 -->
  <div class="codeboxes" role="group" :aria-label="label">
    <input
      v-for="(ch, i) in chars"
      :key="i"
      :ref="(el) => setBox(i, el)"
      class="codebox"
      :value="ch"
      :placeholder="PLACEHOLDER[i] ?? ''"
      maxlength="2"
      inputmode="text"
      autocomplete="off"
      spellcheck="false"
      @input="onInput(i, $event)"
      @keydown="onKey(i, $event)"
      @focus="onFocus"
      @paste.prevent="onPaste(i, $event)"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, ref } from 'vue';

/** 8 格占位提示：每格一个字，提示用户在此输入连接码 */
const PLACEHOLDER = '请在此输入连接码';

const props = withDefaults(
  defineProps<{ modelValue: string; length?: number; label?: string }>(),
  { length: 8, label: '连接码' },
);
const emit = defineEmits<{ 'update:modelValue': [v: string] }>();

const boxes = ref<(HTMLInputElement | null)[]>([]);
function setBox(i: number, el: unknown) {
  boxes.value[i] = (el as HTMLInputElement) ?? null;
}

/** 只保留大写字母与数字（非法符号直接不允许填写） */
function sanitize(s: string) {
  return s.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
}

const chars = computed(() => {
  const arr = sanitize(props.modelValue).slice(0, props.length).split('');
  while (arr.length < props.length) arr.push('');
  return arr;
});

function commit(next: string[], focusIdx?: number) {
  emit('update:modelValue', next.join(''));
  if (focusIdx !== undefined) {
    nextTick(() => {
      const el = boxes.value[focusIdx];
      el?.focus();
      el?.select();
    });
  }
}

function onInput(i: number, e: Event) {
  const el = e.target as HTMLInputElement;
  const raw = sanitize(el.value);
  const next = [...chars.value];
  if (raw.length <= 1) {
    next[i] = raw;
    /* 强制回写 DOM：非法字符被滤空时 Vue 认为绑定值没变不会重渲染，
       输入框会残留标点（“能填非法字符/不自动换格”的根因） */
    el.value = next[i];
    commit(next, raw ? Math.min(i + 1, props.length - 1) : undefined);
  } else {
    // 一次输入多字符（自动填充/输入法）：顺着往后分发
    for (let k = 0; k < raw.length && i + k < props.length; k++) next[i + k] = raw[k];
    el.value = next[i];
    commit(next, Math.min(i + raw.length, props.length - 1));
  }
}

function onKey(i: number, e: KeyboardEvent) {
  if (e.key === 'Backspace' && !chars.value[i] && i > 0) {
    const next = [...chars.value];
    next[i - 1] = '';
    commit(next, i - 1);
    e.preventDefault();
  } else if (e.key === 'ArrowLeft' && i > 0) {
    boxes.value[i - 1]?.focus();
  } else if (e.key === 'ArrowRight' && i < props.length - 1) {
    boxes.value[i + 1]?.focus();
  }
}

function onPaste(i: number, e: ClipboardEvent) {
  const text = sanitize(e.clipboardData?.getData('text') || '').slice(0, props.length);
  if (!text) return;
  const next = [...chars.value];
  for (let k = 0; k < text.length && i + k < props.length; k++) next[i + k] = text[k];
  commit(next, Math.min(i + text.length, props.length - 1));
}

function onFocus(e: FocusEvent) {
  (e.target as HTMLInputElement).select();
}
</script>
