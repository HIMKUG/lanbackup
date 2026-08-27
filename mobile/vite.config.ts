import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { VueMcp } from 'vite-plugin-vue-mcp';
import { fileURLToPath, URL } from 'node:url';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [vue(), VueMcp(), tailwindcss()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
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
