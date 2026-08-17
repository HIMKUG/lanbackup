import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { fileURLToPath, URL } from 'node:url';

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      'shared-core': fileURLToPath(new URL('../shared-core/src/index.ts', import.meta.url)),
    },
  },
  server: {
    host: true,
    port: 5173,
  },
  build: {
    // 代码分割：vue/gsap 独立 chunk，命中长缓存，减少首屏解析体积
    rollupOptions: {
      output: {
        manualChunks: {
          vue: ['vue', 'gsap'],
        },
      },
    },
  },
});
