/**
 * config.ts - 应用配置模型（角色解耦）
 *
 * 设备形态（手机/电脑）与角色（发送端/接收端/自由模式）完全解耦：
 * 任意设备可担任任意角色，支持任意设备间的备份（A→B、B→A、A→A、B→B）。
 * 本模块只定义配置结构与规范化，持久化由平台层提供：
 * - 桌面端：Tauri 命令 get_config/set_config（存 app_data_dir/config.json）
 * - 手机端：localStorage（lanbackup_config）
 */

/** 设备角色 */
export type DeviceRole = 'receiver' | 'sender' | 'free';

/** 接收端配置 */
export interface ReceiverConfig {
  /** 接收端是否启用（自由模式下与发送端并存） */
  enabled: boolean;
  /** 接收文件夹（保存他人推送的文件） */
  receiveDir: string;
  /** 接收端默认开启：应用启动自动进入接收状态（目录已配时） */
  autoStartReceiver: boolean;
}

/** 单个发送文件夹 */
export interface SendFolder {
  id: string;
  name: string;
  path: string;
  enabled: boolean;
}

/** 发送端配置 */
export interface SenderConfig {
  enabled: boolean;
  /** 可配置多个发送文件夹 */
  folders: SendFolder[];
  /** 增量策略 */
  strategy: 'archive' | 'mirror';
  /** 同步对象（已配对设备指纹） */
  targetPeerId?: string;
}

/** 应用配置根 */
export interface AppConfig {
  role: DeviceRole;
  receiver: ReceiverConfig;
  sender: SenderConfig;
}

/** 默认配置：发送端（兼容旧版"电脑默认可发送"行为） */
export const DEFAULT_CONFIG: AppConfig = {
  role: 'sender',
  receiver: { enabled: false, receiveDir: '', autoStartReceiver: false },
  sender: { enabled: true, folders: [], strategy: 'archive', targetPeerId: undefined },
};

/** 生成发送文件夹唯一 id */
export function genFolderId(): string {
  // CSPRNG 消除 Date.now()+Math.random() 的毫秒内碰撞风险；旧环境回退原实现
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `f_${crypto.randomUUID()}`;
  }
  return `f_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * 规范化任意输入为完整 AppConfig（缺省字段补默认值；角色非法回退 sender）。
 * 供两端从持久化存储读出后调用，容忍旧版本/损坏数据。
 */
export function normalizeConfig(raw: unknown): AppConfig {
  const r = (raw ?? {}) as Partial<AppConfig>;
  const receiver = (r.receiver ?? {}) as Partial<ReceiverConfig>;
  const sender = (r.sender ?? {}) as Partial<SenderConfig>;
  const role: DeviceRole = r.role === 'receiver' || r.role === 'sender' || r.role === 'free' ? r.role : 'sender';
  const folders = Array.isArray(sender.folders)
    ? sender.folders
        .filter((f): f is SendFolder => !!f && typeof f === 'object' && typeof f.path === 'string' && f.path.trim() !== '')
        .map((f, i) => ({
          id: typeof f.id === 'string' && f.id ? f.id : `${i}_${genFolderId()}`,
          name: typeof f.name === 'string' ? f.name : '',
          // P3-227：图标/展示保留原始路径，但过滤已排除纯空白
          path: f.path,
          enabled: f.enabled !== false,
        }))
    : [];
  return {
    role,
    receiver: {
      enabled: receiver.enabled === true,
      receiveDir: typeof receiver.receiveDir === 'string' ? receiver.receiveDir : '',
      autoStartReceiver: receiver.autoStartReceiver === true,
    },
    sender: {
      enabled: sender.enabled !== false,
      folders,
      strategy: sender.strategy === 'mirror' ? 'mirror' : 'archive',
      targetPeerId: typeof sender.targetPeerId === 'string' ? sender.targetPeerId : undefined,
    },
  };
}

/** 从字符串（localStorage）解析配置 */
export function parseConfig(json: string | null): AppConfig {
  if (!json) return { ...DEFAULT_CONFIG, role: DEFAULT_CONFIG.role };
  try {
    return normalizeConfig(JSON.parse(json));
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

/** 序列化为字符串（localStorage 用） */
export function stringifyConfig(config: AppConfig): string {
  return JSON.stringify(config);
}

/** 复制配置（避免共享引用） */
export function cloneConfig(config: AppConfig): AppConfig {
  try {
    // structuredClone is faster and handles Date objects correctly
    return structuredClone(config);
  } catch {
    // Fallback for environments where structuredClone throws
    return normalizeConfig(JSON.parse(JSON.stringify(config)));
  }
}
