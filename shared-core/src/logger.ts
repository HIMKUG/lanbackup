/**
 * logger.ts - 全链路 Debug 模块（两端共用）
 *
 * 架构：各模块调用 logger.debug/info/warn/error 上报 → DebugDispatcher 统一调度：
 * 1. 时间戳 + 级别 + 模块 + 消息 + 结构化错误码（code）+ 堆栈，写入环形缓冲；
 * 2. 统计 ERROR/WARN 次数并实时通知订阅者（UI 可显示错误徽标）；
 * 3. installGlobalHandlers() 侦测未捕获异常 / 未处理 Promise 拒绝；
 * 4. withTimeout() 侦测「卡死无返回」的静默失败（插件调用无响应等），
 *    这是本次 SAF 目录选择失败的根因场景：Promise 永不 settle，旧日志一无所获；
 * 5. persist()/restore() 把最近日志持久化到 localStorage，App 重启后仍可导出；
 * 6. export() 输出带摘要头部的完整日志，供手机端/电脑端写入日志文件。
 *
 * 敏感信息（连接码/指纹/token）用 maskSecret 脱敏，日志文件可放心随工单分享。
 */

/** 日志级别 */
export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

/** 结构化错误码（调度器据此归类问题） */
export type LogCode =
  | 'TIMEOUT' // 操作超时（插件/网络未响应）
  | 'PLUGIN_FAIL' // 原生插件调用失败
  | 'HTTP_FAIL' // 网络请求失败
  | 'SAF_CANCELLED' // 用户取消（如目录选择）
  | 'SAF_FAIL' // SAF 文件操作失败
  | 'UNCAUGHT' // 未捕获异常 / 未处理 Promise 拒绝
  | 'VUE_ERROR' // Vue 渲染/生命周期错误
  | 'INIT_FAIL' // 初始化失败
  | 'RUNTIME'; // 其他运行时错误

/** 环形缓冲区上限（条） */
export const MAX_LOG_ENTRIES = 2000;

/** 单条堆栈上限（字符），防止超大堆栈撑爆导出文件 */
const MAX_STACK_CHARS = 4000;

/** 缓冲中的单条日志 */
export interface LogEntry {
  /** Unix 毫秒时间戳 */
  ts: number;
  level: LogLevel;
  /** 模块名（如 'transfer'、'filesystem'、'receiver'、'ui'、'global'） */
  module: string;
  message: string;
  /** 结构化错误码，便于检索归类 */
  code?: LogCode;
  /** 错误堆栈（截断后） */
  stack?: string;
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

/**
 * 脱敏：只保留前 2 + 后 2 字符，中间打码。
 * 用于连接码、设备指纹、会话 token 等配对凭据，避免日志泄露。
 */
export function maskSecret(secret: string): string {
  if (!secret) return '';
  if (secret.length <= 4) return '****';
  return `${secret.slice(0, 2)}****${secret.slice(-2)}`;
}

/**
 * 列表摘要：条目少时全量展示，多时只展示前 max 条。
 * 用于日志中展示「文件列表」，避免超大清单撑爆日志。
 */
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
  private readonly maxBytes = 512 * 1024; // 缓冲总字节上限（防内存溢出）
  private handlersInstalled = false;
  private counts: LogSummary = { debug: 0, info: 0, warn: 0, error: 0 };
  private totalBytes = 0;
  private readonly persistKey = 'lanbackup_debug_log';
  private listeners = new Set<() => void>();
  /** ERROR 出现时的回调（UI 可据此弹提示） */
  onError: (() => void) | null = null;
  /** 调试模式总开关：关闭后所有日志（含 WARN/ERROR）都不记录、不持久化，提升性能 */
  private enabled = true;

  /** 设置调试模式（false = 完全关闭日志；持久化由调用方负责） */
  setDebugEnabled(v: boolean): void {
    this.enabled = v;
  }

  /** 当前调试模式状态 */
  get debugEnabled(): boolean {
    return this.enabled;
  }
  /** 设备标签（'手机' / '电脑'），由两端启动时设置，随每条日志与文件名标注 */
  private deviceTag = '';

  /** 设置设备标签（日志条目与导出文件名都会携带，便于区分移动端/桌面端） */
  setDevice(tag: string): void {
    this.deviceTag = tag;
  }

  /** 当前设备标签 */
  get device(): string {
    return this.deviceTag;
  }

  /** 设置最低输出级别（低于该级别的日志不输出、不入缓冲） */
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
   * 核心上报入口：所有模块统一经此上报，调度器负责落缓冲、统计、通知、持久化。
   * @param level 级别
   * @param module 模块名
   * @param message 人类可读描述（说明发生了什么、如何影响用户）
   * @param opts.code 结构化错误码
   * @param opts.error 原始错误对象（自动提取 message + stack）
   */
  report(
    level: LogLevel,
    module: string,
    message: string,
    opts: { error?: unknown; code?: LogCode } = {},
  ): void {
    // 调试模式关闭 → 完全跳过（热路径零开销，含 WARN/ERROR）
    if (!this.enabled) return;
    if (this.order(level) < this.order(this.minLevel)) return;

    let msg = message;
    let stack: string | undefined;
    if (opts.error !== undefined) {
      const { message: errMsg, stack: errStack } = describeError(opts.error);
      msg = `${message} | ${errMsg}`;
      if (errStack) {
        stack = errStack.length > MAX_STACK_CHARS ? errStack.slice(0, MAX_STACK_CHARS) : errStack;
      }
    }

    const entry: LogEntry = { ts: Date.now(), level, module, message: msg };
    if (opts.code) entry.code = opts.code;
    if (stack) entry.stack = stack;

    this.entries.push(entry);
    this.counts[level.toLowerCase() as 'debug' | 'info' | 'warn' | 'error']++;
    this.totalBytes += msg.length + (stack?.length ?? 0);

    // 环形缓冲：超条数或超字节丢弃最旧。用一次 splice 批量移除，
    // 避免逐条 shift() 的 O(n) 内存移动（单次大溢出只做一次 memmove）
    if (this.entries.length > this.maxEntries) {
      const overflow = this.entries.length - this.maxEntries;
      const removed = this.entries.splice(0, overflow);
      for (const old of removed) this.totalBytes -= old.message.length + (old.stack?.length ?? 0);
    }
    while (this.totalBytes > this.maxBytes && this.entries.length > 1) {
      const old = this.entries.shift()!;
      this.totalBytes -= old.message.length + (old.stack?.length ?? 0);
    }

    const line = this.format(entry);
    switch (level) {
      case 'DEBUG': console.debug(line); break;
      case 'INFO': console.info(line); break;
      case 'WARN': console.warn(line); break;
      case 'ERROR': console.error(line); break;
    }

    // 通知订阅者（UI 刷新错误徽标）
    for (const fn of this.listeners) fn();
    if (level === 'ERROR' && this.onError) this.onError();
    // 错误/警告出现时持久化，避免进程被杀丢日志
    if (level === 'ERROR' || level === 'WARN') this.persist();
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

  /** 带错误码的报错（模块能明确归类问题时使用） */
  errorCode(module: string, message: string, code: LogCode, error?: unknown): void {
    this.report('ERROR', module, message, { error, code });
  }

  /**
   * 侦测「卡死无返回」的静默失败：为异步操作加超时。
   * 超时未 settle → 上报 ERROR(TIMEOUT) 并 reject，调用方可提示用户。
   * 用于包裹原生插件调用、网络请求等可能永久挂起的操作。
   */
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

  /**
   * 安装全局错误捕获（幂等）：未捕获异常、未处理 Promise 拒绝。
   * 由两端 main.ts 调用一次；任何模块漏报的错误都会在这里被兜底捕获。
   */
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

  /** 格式化单条日志（导出格式）：含错误码与堆栈、设备标签 */
  format(entry: LogEntry): string {
    const code = entry.code ? ` <${entry.code}>` : '';
    const device = this.deviceTag ? ` [${this.deviceTag}]` : '';
    let line = `[${formatLogTimestamp(entry.ts)}] [${entry.level}] [${entry.module}]${code}${device} ${entry.message}`;
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
      // 只合并尚未记录的条目（按 ts 去重粗判）
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

/** 生成日志文件名：debug_<设备>_YYYYMMDD_HHmmss.log（设备标签默认取 logger.device） */
export function logFileName(now: Date = new Date(), tag: string = logger.device): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  const safe = (tag || 'device').replace(/[\\/:*?"<>|]/g, '_');
  return (
    `debug_${safe}_${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}_` +
    `${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}.log`
  );
}
