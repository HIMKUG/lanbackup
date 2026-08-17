/**
 * 同步任务管理（任务化暂停/恢复）
 * 每次收发都是一个带 ID 的任务：断网时标记 paused，恢复时重新执行同步，
 * 增量规划会通过接收端清单自动跳过已完成文件（文件级续传）。
 * 任务状态持久化到 localStorage，重启不丢。
 */
import { ref, watch } from 'vue';

export interface SyncTask {
  id: string;
  direction: 'send' | 'receive';
  peer: string;
  /** 对端连接目标（断网自动重连/恢复按钮定向用；旧记录可能缺失） */
  peerIp?: string;
  peerPort?: number;
  peerFingerprint?: string;
  state: 'running' | 'paused' | 'completed' | 'failed';
  /** 失败/暂停原因（failed 与 paused 态展示 + 重试/恢复提示用） */
  error?: string;
  fileCount: number;
  sentCount: number;
  bytes: number;
  totalBytes: number;
  createdAt: number;
  updatedAt: number;
}

const STORAGE_KEY = 'lanbackup_sync_tasks';
const MAX_TASKS = 20;

function load(): SyncTask[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return JSON.parse(raw) as SyncTask[];
  } catch {
    // 损坏忽略
  }
  return [];
}

export function useSyncTasks() {
  const tasks = ref<SyncTask[]>(load());
  watch(tasks, (v) => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(v.slice(0, MAX_TASKS)));
    } catch {
      // 忽略
    }
  }, { deep: true });

  function createTask(t: {
    direction: 'send' | 'receive';
    peer: string;
    peerIp?: string;
    peerPort?: number;
    peerFingerprint?: string;
    fileCount: number;
    totalBytes: number;
  }): SyncTask {
    const task: SyncTask = {
      id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
      direction: t.direction,
      peer: t.peer,
      peerIp: t.peerIp,
      peerPort: t.peerPort,
      peerFingerprint: t.peerFingerprint,
      state: 'running',
      fileCount: t.fileCount,
      sentCount: 0,
      bytes: 0,
      totalBytes: t.totalBytes,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    tasks.value = [task, ...tasks.value].slice(0, MAX_TASKS);
    return task;
  }

  function updateTask(id: string, patch: Partial<SyncTask>) {
    const t = tasks.value.find((x) => x.id === id);
    if (t) {
      Object.assign(t, patch, { updatedAt: Date.now() });
    }
  }

  function pauseTask(id: string, reason?: string) {
    updateTask(id, { state: 'paused', error: reason });
  }

  function completeTask(id: string) {
    updateTask(id, { state: 'completed' });
  }

  function failTask(id: string, reason?: string) {
    updateTask(id, { state: 'failed', error: reason || '未知原因' });
  }

  function removeTask(id: string) {
    tasks.value = tasks.value.filter((x) => x.id !== id);
  }

  return { tasks, createTask, updateTask, pauseTask, completeTask, failTask, removeTask };
}
