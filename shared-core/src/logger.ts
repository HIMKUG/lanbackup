/**
 * logger.ts - 全链路 Debug 模块（两端共用）
 *
 * 架构：各模块调用 logger.debug/info/warn/error 上报 → DebugDispatcher 统一调度：
 * 1. 时间戳 + 级别 + 模块 + 消息 + 结构化错误码（code）+ 堆栈，写入环形缓冲；
 * 2. 统计 ERROR/WARN 次数并实时通知订阅者（UI 可显示错误徽标）；
 * 3. installGlobalHandlers() 侦测未捕获异常 / 未处理 Promise 拒绝；
 * 4. withTimeout() 侦测「卡死无返回」的静默失败；
 * 5. persist()/restore() 把最近日志持久化到 localStorage；
 * 6. export() 输出带摘要头部的完整日志，含 trace_id；
 * 7. startActiveSpan() 包裹函数并创建 OTel Span。
 *
 * 敏感信息（连接码/指纹/token）用 maskSecret 脱敏。
 */

import { getTracer, currentTraceId, setTelemetryEnabled, isTelemetryEnabled } from './telemetry.js';
import { SpanStatusCode } from '@opentelemetry/api';

/** OTel Span 的方法子集，供 startActiveSpan 回调使用 */
interface SpanLike {
  setAttribute(key: string, value: unknown): void;
  setAttributes(attrs: Record<string, unknown>): void;
  setStatus(opts: { code: SpanStatusCode; message?: string }): void;
  recordException(err: Error): void;
  end(code?: LogCode): void;
}

/** 日志级别 */
export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

/** 结构化错误码 */
export type LogCode =
  | 'TIMEOUT'
  | 'PLUGIN_FAIL'
  | 'HTTP_FAIL'
  | 'SAF_CANCELLED'
  | 'SAF_FAIL'
  | 'UNCAUGHT'
  | 'VUE_ERROR'
  | 'INIT_FAIL'
  | 'RUNTIME';

/** 环形缓冲区上限（条） */
export const MAX_LOG_ENTRIES = 2000;

/** 单条堆栈上限（字符） */
const MAX_STACK_CHARS = 4000;

/** 缓冲中的单条日志 */
export interface LogEntry {
  ts: number;
  level: LogLevel;
  module: string;
  message: string;
  code?: LogCode;
  stack?: string;
  traceId?: string;
}

/** 日志级别统计 */
export interface LogSummary {
  debug: number;
  info: number;
  warn: number;
  error: number;
}

/** 时间戳格式化：YYYY-MM-DD HH:mm:ss.SSS（本地时区） */
export function formatLogTimestamp(ts: number): string {
  const d = new Date(ts);
  const pad = (n: number, len = 2) => String(n).padStart(len, '0');
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`
  );
}

/** 脱敏 */
export function maskSecret(secret: string): string {
  if (!secret) return '';
  if (secret.length <= 4) return '****';
  return `${secret.slice(0, 2)}****${secret.slice(-2)}`;
}

/** 列表摘要 */
export function summarizeList(items: string[], max = 20): string {
  if (items.length === 0) return '[]';
  if (items.length <= max) return `[${items.join(', ')}]`;
  return `[${items.slice(0, max).join(', ')}, ...共 ${items.length} 条]`;
}

/** 从任意 unknown 提取可读错误描述 */
export function describeError(error: unknown): { message: string; stack?: string } {
  if (error instanceof Error) {
    return { message: error.message, stack: error.stack ?? undefined };
  }
  if (typeof error === 'string') return { message: error };
  try {
    return { message: JSON.stringify(error) };
  } catch {
    return { message: String(error) };
  }
}

/**
 * Debug 调度器：接收所有模块上报，统一记录、统计、持久化、导出。
 */
export class DebugDispatcher {
  private entries: LogEntry[] = [];
  private minLevel: LogLevel = 'DEBUG';
  private readonly maxEntries = MAX_LOG_ENTRIES;
  private readonly maxBytes = 512 * 1024;
  private handlersInstalled = false;
  private counts: LogSummary = { debug: 0, info: 0, warn: 0, error: 0 };
  private totalBytes = 0;
  private readonly persistKey = 'lanbackup_debug_log';
  private listeners = new Set<() => void>();
  onError: (() => void) | null = null;

  /** 调试模式总开关：关闭后 DEBUG/INFO/WARN 日志不记录，
   * 但 ERROR 日志仍会记录并持久化（确保关键错误不丢失） */
  private _enabled = true;

  /** 设置调试模式（false = 关闭 DEBUG/INFO/WARN；ERROR 始终记录） */
  setDebugEnabled(v: boolean): void {
    this._enabled = v;
    setTelemetryEnabled(v);
  }

  get debugEnabled(): boolean {
    return this._enabled;
  }

  private deviceTag = '';

  setDevice(tag: string): void {
    this.deviceTag = tag;
  }

  get device(): string {
    return this.deviceTag;
  }

  setMinLevel(level: LogLevel): void {
    this.minLevel = level;
  }

  private order(level: LogLevel): number {
    switch (level) {
      case 'DEBUG': return 0;
      case 'INFO': return 1;
      case 'WARN': return 2;
      case 'ERROR': return 3;
    }
  }

  /**
   * 核心上报入口
   * 规则：_enabled=false 时，ERROR 仍记录（但不输出到 console），其他级别丢弃
   */
  report(
    level: LogLevel,
    module: string,
    message: string,
    opts: { error?: unknown; code?: LogCode } = {},
  ): void {
    // ERROR 级别永远记录（即使 debug 模式关闭），确保关键错误持久化
    const isError = level === 'ERROR';
    if (!this._enabled && !isError) return;
    if (!isError && this.order(level) < this.order(this.minLevel)) return;

    let msg = message;
    let stack: string | undefined;
    if (opts.error !== undefined) {
      const { message: errMsg, stack: errStack } = describeError(opts.error);
      msg = `${message} | ${errMsg}`;
      if (errStack) {
        stack = errStack.length > MAX_STACK_CHARS ? errStack.slice(0, MAX_STACK_CHARS) : errStack;
      }
    }

    const entry: LogEntry = {
      ts: Date.now(),
      level,
      module,
      message: msg,
      code: opts.code,
      stack,
      traceId: currentTraceId(),
    };

    this.entries.push(entry);
    this.counts[level.toLowerCase() as 'debug' | 'info' | 'warn' | 'error']++;
    this.totalBytes += msg.length + (stack?.length ?? 0);

    if (this.entries.length > this.maxEntries) {
      const overflow = this.entries.length - this.maxEntries;
      const removed = this.entries.splice(0, overflow);
      for (const old of removed) this.totalBytes -= old.message.length + (old.stack?.length ?? 0);
    }
    while (this.totalBytes > this.maxBytes && this.entries.length > 1) {
      const old = this.entries.shift()!;
      this.totalBytes -= old.message.length + (old.stack?.length ?? 0);
    }

    // 仅在 debug 模式开启时输出到 console
    if (this._enabled) {
      const line = this.format(entry);
      switch (level) {
        case 'DEBUG': console.debug(line); break;
        case 'INFO': console.info(line); break;
        case 'WARN': console.warn(line); break;
        case 'ERROR': console.error(line); break;
      }
    }

    for (const fn of this.listeners) fn();
    if (isError && this.onError) this.onError();
    // ERROR 和 WARN 都需要持久化
    if (isError || level === 'WARN') this.persist();
  }

  debug(module: string, message: string): void {
    this.report('DEBUG', module, message);
  }

  info(module: string, message: string): void {
    this.report('INFO', module, message);
  }

  warn(module: string, message: string, error?: unknown): void {
    this.report('WARN', module, message, { error });
  }

  error(module: string, message: string, error?: unknown): void {
    this.report('ERROR', module, message, { error, code: 'RUNTIME' });
  }

  errorCode(module: string, message: string, code: LogCode, error?: unknown): void {
    this.report('ERROR', module, message, { error, code });
  }

  /**
   * 包裹函数并创建 OTel Span。
   * Promise 返回路径：Span 生命周期由调用方（XHR 回调）负责 end。
   * ⚠️ 维护者注意：务必在每条 XHR 分支（含错误分支）调用 span.end()，
   * 否则 Span 泄漏。未来新增 XHR 分支时此处 catch 无法兜底。
   */
  startActiveSpan<T>(name: string, fn: (span: SpanLike) => T): T {
    const tracer = getTracer();
    return tracer.startActiveSpan(name, (span) => {
      try {
        const result = fn({
          setAttribute: (key: string, value: unknown) => span.setAttribute(key, value as string | number | boolean),
          setAttributes: (attrs: Record<string, unknown>) => span.setAttributes(attrs as Record<string, string | number | boolean>),
          setStatus: (opts: { code: SpanStatusCode; message?: string }) => {
            span.setStatus(opts);
          },
          recordException: (err: Error) => span.recordException(err),
          end: (code?: LogCode) => {
            span.setStatus({
              code: code ? SpanStatusCode.ERROR : SpanStatusCode.OK,
              message: code ?? undefined,
            });
            span.end();
          },
        });

        if (!(result instanceof Promise)) {
          span.end();
        }
        return result;
      } catch (err) {
        span.recordException(err as Error);
        span.setStatus({ code: SpanStatusCode.ERROR });
        span.end();
        throw err;
      }
    });
  }

  /** 侦测「卡死无返回」的静默失败：为异步操作加超时（插件调用无响应等）。 */
  withTimeout<T>(
    promise: Promise<T>,
    ms: number,
    module: string,
    desc: string,
    code: LogCode = 'TIMEOUT',
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        const err = new Error(`操作超时（${ms}ms 无响应）: ${desc}`);
        this.report('ERROR', module, err.message, { error: err, code });
        reject(err);
      }, ms);
      promise.then(
        (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        (e) => {
          clearTimeout(timer);
          reject(e);
        },
      );
    });
  }

  /** 安装全局错误捕获（幂等）：未捕获异常、未处理 Promise 拒绝。 */
  installGlobalHandlers(): void {
    if (this.handlersInstalled || typeof window === 'undefined') return;
    this.handlersInstalled = true;
    this.restore();
    window.addEventListener('error', (e) => {
      this.report('ERROR', 'global', `未捕获异常: ${e.message} (${e.filename}:${e.lineno})`, {
        error: e.error,
        code: 'UNCAUGHT',
      });
    });
    window.addEventListener('unhandledrejection', (e) => {
      const reason = e.reason;
      const msg =
        reason instanceof Error ? `未处理 Promise 拒绝: ${reason.message}` : `未处理 Promise 拒绝: ${String(reason)}`;
      this.report('ERROR', 'global', msg, { error: reason, code: 'UNCAUGHT' });
    });
  }

  /** 订阅变化（返回取消函数），供 UI 实时刷新统计 */
  subscribe(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  /** 当前级别统计 */
  summary(): LogSummary {
    return { ...this.counts };
  }

  /** 是否有错误 */
  hasErrors(): boolean {
    return this.counts.error > 0;
  }

  /** 格式化单条日志（导出格式）：含错误码、trace_id 与堆栈 */
  format(entry: LogEntry): string {
    const code = entry.code ? ` <${entry.code}>` : '';
    const device = this.deviceTag ? ` [${this.deviceTag}]` : '';
    const trace = entry.traceId ? ` {${entry.traceId}}` : '';
    let line = `[${formatLogTimestamp(entry.ts)}] [${entry.level}] [${entry.module}]${code}${device}${trace} ${entry.message}\n`;
    if (entry.stack) line += `\n    ${entry.stack.replace(/\n/g, '\n    ')}`;
    return line;
  }

  /** 导出完整日志：摘要头部（含设备标签）+ 全部条目 */
  export(): string {
    const c = this.counts;
    const head =
      '==== 局域网备份 Debug 日志 ====\n' +
      `设备: ${this.deviceTag || '未知'}\n` +
      `导出时间: ${formatLogTimestamp(Date.now())}\n` +
      `缓冲条目: ${this.entries.length}\n` +
      `级别统计: DEBUG=${c.debug} INFO=${c.info} WARN=${c.warn} ERROR=${c.error}\n` +
      '----------------------------------------\n';
    return head + this.entries.map((e) => this.format(e)).join('\n') + '\n';
  }

  /** 当前缓冲条数 */
  size(): number {
    return this.entries.length;
  }

  /** 清空缓冲与统计（导出后可调用） */
  clear(): void {
    this.entries = [];
    this.counts = { debug: 0, info: 0, warn: 0, error: 0 };
    this.totalBytes = 0;
    try {
      localStorage.removeItem(this.persistKey);
    } catch {
      // 忽略
    }
    for (const fn of this.listeners) fn();
  }

  /** 持久化最近日志到 localStorage（跨重启保留，防止进程被杀丢日志） */
  persist(): void {
    try {
      const tail = this.entries.slice(-300);
      localStorage.setItem(this.persistKey, JSON.stringify(tail));
    } catch {
      // 存储满等异常忽略
    }
  }

  /** 恢复上次持久化的日志（重启后仍可导出历史） */
  restore(): void {
    try {
      const raw = localStorage.getItem(this.persistKey);
      if (!raw) return;
      const saved = JSON.parse(raw) as LogEntry[];
      if (!Array.isArray(saved)) return;
      const known = new Set(this.entries.map((e) => `${e.ts}|${e.module}|${e.message}`));
      for (const e of saved) {
        const key = `${e.ts}|${e.module}|${e.message}`;
        if (!known.has(key)) {
          this.entries.push(e);
          this.totalBytes += e.message.length + (e.stack?.length ?? 0);
          const lv = e.level.toLowerCase() as 'debug' | 'info' | 'warn' | 'error';
          this.counts[lv]++;
        }
      }
      while (this.entries.length > this.maxEntries) {
        const old = this.entries.shift()!;
        this.totalBytes -= old.message.length + (old.stack?.length ?? 0);
      }
    } catch {
      // 损坏数据忽略
    }
  }
}

/** 全局单例（shared-core / mobile / desktop 前端共用同一缓冲） */
export const logger = new DebugDispatcher();

/** 便捷函数（保持旧调用兼容） */
export function logDebug(module: string, message: string): void {
  logger.debug(module, message);
}
export function logInfo(module: string, message: string): void {
  logger.info(module, message);
}
export function logWarn(module: string, message: string, error?: unknown): void {
  logger.warn(module, message, error);
}
export function logError(module: string, message: string, error?: unknown): void {
  logger.error(module, message, error);
}

/** 生成日志文件名：debug_<设备>_YYYYMMDD_HHmmss.log */
export function logFileName(now: Date = new Date(), tag: string = logger.device): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  const safe = (tag || 'device').replace(/[\\/:*?"<>|]/g, '_');
  return (
    `debug_${safe}_${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}_` +
    `${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}.log`
  );
}
