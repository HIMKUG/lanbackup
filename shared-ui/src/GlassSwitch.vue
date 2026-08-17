<template>
  <!-- 类苹果开关（iOS Switch）：玻璃轨道 + 弹性滑块 -->
  <button
    type="button"
    class="gswitch"
    :class="{ on: modelValue }"
    role="switch"
    :aria-checked="modelValue"
    :aria-label="label || '开关'"
    @click="$emit('update:modelValue', !modelValue)"
  >
    <span class="gswitch-knob" aria-hidden="true"></span>
  </button>
</template>

<script setup lang="ts">
defineProps<{ modelValue: boolean; label?: string }>();
defineEmits<{ 'update:modelValue': [v: boolean] }>();
</script>
