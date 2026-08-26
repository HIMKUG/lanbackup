import { createApp } from 'vue';
import App from './App.vue';
import './style.css';
import { logger, initTelemetry } from 'shared-core';

// Debug 调度器：安装全局错误捕获（未捕获异常 / 未处理 Promise 拒绝），
// 并恢复上次持久化的日志。任何模块漏报的错误都会在这里兜底。
logger.setDevice('phone');
initTelemetry('phone'); // 初始化 OpenTelemetry（必须在 installGlobalHandlers 之前）
logger.installGlobalHandlers();

const app = createApp(App);
// Vue 渲染/生命周期错误也统一上报到日志，随「导出日志」落盘
app.config.errorHandler = (err, _instance, info) => {
  logger.errorCode(
    'vue',
    `Vue 错误 (${info}): ${err instanceof Error ? err.message : String(err)}`,
    'VUE_ERROR',
    err,
  );
};

app.mount('#app');
