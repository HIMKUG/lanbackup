/**
 * shared-core 入口
 * 局域网备份工具共享核心（纯 TS，两端复用）
 */

export * from './identity.js';
export * from './config.js';
export * from './manifest.js';
export * from './anchor.js';
export * from './conflict.js';
export * from './scan.js';
export * from './sync.js';
export * from './state.js';
export * from './transfer.js';
export * from './discovery.js';
export * from './pairing.js';
export * from './chunks.js';
export * from './autopolicy.js';
export * from './logger.js';
export * from './scheduler.js';
export * from './session-store.js';
export * from './crypto.js';
export { initTelemetry, getTracer, currentTraceId, setTelemetryEnabled, isTelemetryEnabled, shutdownTelemetry } from './telemetry.js';