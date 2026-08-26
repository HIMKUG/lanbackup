/**
 * 断网自动重连看门狗：有 paused 任务且对端恢复可达时自动恢复同步
 * （增量规划 + 分片状态自动跳过已完成部分，文件级续传）。
 * 纯逻辑（5s 轮询 + in-flight 防重入），平台差异由调用方参数化——
 * 桌面端问候走 Tauri invoke，移动端走 greetDevice，UI 对齐也各有不同。
 */
import type { SyncTask } from './useSyncTasks';

export interface AutoResumeOptions {
  /** 忙时跳过本轮（同步中或已有活动任务） */
  isBusy: () => boolean;
  /** 返回待恢复的暂停任务（paused 且带对端连接目标）；无则本轮跳过 */
  getPending: () => SyncTask | undefined;
  /** 问候对端：可达且接收服务已被拉起 → true */
  verifyPeer: (t: SyncTask) => Promise<boolean>;
  /** 重连成功后对齐配对状态/目标设备（markOnline/selectTarget 等） */
  onReconnect: (t: SyncTask) => void;
  /** 重连成功后重新执行同步 */
  onResume: (t: SyncTask) => void;
  notify: (text: string) => void;
  logInfo: (msg: string) => void;
}

export function useAutoResume(opts: AutoResumeOptions) {
  let timer: ReturnType<typeof setInterval> | null = null;
  let inFlight = false;
  let isResuming = false;

  async function tick() {
    if (inFlight || opts.isBusy() || isResuming) return;
    const pending = opts.getPending();
    if (!pending) return;
    inFlight = true;
    try {
      const ok = await opts.verifyPeer(pending);
      if (!ok) return;
      // verifyPeer 成功后二次检查：onResume 会触发新一轮同步，
      // 在它把 isBusy 置 true 之前不要再次进入（防止 verifyPeer 成功后
      // 到 onResume 设置扫描标志之间隙被下一轮 tick 钻空子重复触发）
      if (isResuming || opts.isBusy()) return;
      isResuming = true;
      opts.onReconnect(pending);
      opts.notify(`已自动重连「${pending.peer}」，正在恢复同步任务`);
      opts.logInfo(`自动重连成功，恢复任务: 对端=${pending.peer}(${pending.peerIp}:${pending.peerPort})`);
      opts.onResume(pending);
    } catch {
      // 对端仍不可达：下一轮（5s）再试
    } finally {
      inFlight = false;
      isResuming = false;
    }
  }

  function start() {
    if (!timer) timer = setInterval(tick, 5000);
  }

  function stop() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  return { start, stop };
}