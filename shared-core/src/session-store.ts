/**
 * session-store.ts - 会话状态持久化接口定义
 *
 * 定义统一的 ISessionStore 接口，平台特定实现：
 * - Android: DataStore + SQLite（AndroidSessionStore）
 * - Desktop: tauri-plugin-store（DesktopSessionStore）
 *
 * 三层状态分离：
 * - 热状态（内存）：活跃传输的实时进度，进程死亡即丢失
 * - 温状态（DataStore / tauri-plugin-store）：会话元数据，重启后可恢复
 * - 冷状态（SQLite）：历史传输记录，持久化归档
 */

// ============================================================
// 类型定义
// ============================================================

/** 传输进度 */
export interface TransferProgress {
  fileId: string;
  sentBytes: number;
  totalBytes: number;
  piecesCompleted: number;
  piecesTotal: number;
  retryCount: number;
  lastError?: string;
}

/** 对端信息 */
export interface PeerInfo {
  peerId: string;
  alias: string;
  ip: string;
  port: number;
  status: 'connected' | 'disconnected';
}

/** 文件清单项（对应 scheduler.ts FileManifest） */
export interface FileManifest {
  id: string;
  fileName: string;
  size: number;
  sha256: string;
  merkleRoot?: string;
  pieceHashes?: string[];
  chunkSize?: number;
}

/** 会话状态 */
export interface SessionState {
  id: string;
  files: FileManifest[];
  peers: PeerInfo[];
  progress: Record<string, TransferProgress>;
  createdAt: string;
  updatedAt: string;
  status: 'active' | 'completed' | 'aborted' | 'failed';
}

// ============================================================
// ISessionStore 接口
// ============================================================

/**
 * 会话存储接口抽象
 *
 * 统一接口，平台特定实现：
 * - Android: AndroidSessionStore（DataStore 温状态 + SQLite 冷状态）
 * - Desktop: DesktopSessionStore（tauri-plugin-store 温状态 + 内存热状态）
 */
export interface ISessionStore {
  /** 创建新会话 */
  createSession(session: SessionState): Promise<void>;

  /** 更新会话进度（部分更新） */
  updateSession(sessionId: string, updates: Partial<SessionState>): Promise<void>;

  /** 获取指定会话 */
  getSession(sessionId: string): Promise<SessionState | null>;

  /** 列出所有会话 */
  listSessions(): Promise<SessionState[]>;

  /** 删除会话 */
  deleteSession(sessionId: string): Promise<void>;

  /** 获取活跃会话（status='active'） */
  getActiveSession(): Promise<SessionState | null>;

  /** 设置活跃会话 ID */
  setActiveSession(sessionId: string | null): Promise<void>;

  /** 批量更新进度（原子操作） */
  updateProgress(sessionId: string, progress: Record<string, TransferProgress>): Promise<void>;

  /** 标记会话完成 */
  completeSession(sessionId: string): Promise<void>;

  /** 标记会话失败 */
  failSession(sessionId: string, error?: string): Promise<void>;
}

// ============================================================
// 工具函数
// ============================================================

/** 创建新会话（带默认值） */
export function createDefaultSession(sessionId: string): SessionState {
  const now = new Date().toISOString();
  return {
    id: sessionId,
    files: [],
    peers: [],
    progress: {},
    createdAt: now,
    updatedAt: now,
    status: 'active',
  };
}

/** 更新会话的 updatedAt 时间戳 */
export function touchSession(session: SessionState): SessionState {
  return {
    ...session,
    updatedAt: new Date().toISOString(),
  };
}
