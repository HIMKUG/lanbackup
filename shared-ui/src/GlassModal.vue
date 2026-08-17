<template>
  <!-- 二级确认弹窗：玻璃卡片 + 弹性入场（所有“是否确认”统一走这里） -->
  <Transition name="modal-pop">
    <div v-if="open" class="gmodal-overlay" @click.self="$emit('cancel')">
      <div class="gmodal" role="alertdialog" :aria-label="title">
        <h3 class="gmodal-title">{{ title }}</h3>
        <p v-if="message" class="gmodal-msg">{{ message }}</p>
        <slot />
        <div class="gmodal-actions">
          <button type="button" class="glass-btn small" @click="$emit('cancel')">{{ cancelText }}</button>
          <button type="button" class="glass-btn small" :class="{ danger }" @click="$emit('confirm')">{{ confirmText }}</button>
        </div>
      </div>
    </div>
  </Transition>
</template>

<script setup lang="ts">
withDefaults(
  defineProps<{
    open: boolean;
    title: string;
    message?: string;
    danger?: boolean;
    confirmText?: string;
    cancelText?: string;
  }>(),
  { message: '', danger: false, confirmText: '确认', cancelText: '取消' },
);

defineEmits<{ confirm: []; cancel: [] }>();
</script>
