/**
 * useTauriListener.ts - Tauri 事件监听器生命周期管理
 *
 * 统一登记所有 listen() 返回的销毁函数，组件卸载时自动全部清理，
 * 避免 Rust 持续向已销毁组件推送事件造成内存泄漏。
 */
import { onUnmounted } from 'vue';
import type { UnlistenFn } from '@tauri-apps/api/event';

export function useTauriListener() {
  const cleanups: UnlistenFn[] = [];

  /** 登记一个监听器销毁函数（组件卸载时自动调用） */
  function track(fn: UnlistenFn): void {
    cleanups.push(fn);
  }

  onUnmounted(() => {
    while (cleanups.length) {
      const fn = cleanups.pop();
      try {
        fn?.();
      } catch {
        // 忽略清理异常
      }
    }
  });

  return { track };
}
