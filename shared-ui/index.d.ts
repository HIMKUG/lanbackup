/**
 * shared-ui 类型声明
 *
 * 运行时实现见 src/index.ts（由 Vite 编译），此文件仅为 TypeScript 提供类型入口，
 * 避免 vue-tsc 深入检查独立目录的 .vue 源码时发生 vue 模块解析失败。
 * LiquidGlass 声明为宽松类型，模板中直接使用即可。
 */

export interface MousePosition {
  x: number;
  y: number;
}

export interface GlassSize {
  width: number;
  height: number;
}

export type DisplacementMode = "standard" | "polar";
export type PositioningMode = "fixed" | "relative";

export interface LiquidGlassProps {
  displacementScale?: number;
  blurAmount?: number;
  saturation?: number;
  aberrationIntensity?: number;
  elasticity?: number;
  cornerRadius?: number;
  overLight?: boolean;
  mode?: DisplacementMode;
  positioning?: PositioningMode;
  globalMousePos?: MousePosition;
  mouseOffset?: MousePosition;
  mouseContainer?: HTMLElement | null;
  className?: string;
  padding?: string;
  style?: Record<string, any>;
  onClick?: () => void;
}

/** LiquidGlass 组件（运行时为 Vue SFC） */
export declare const LiquidGlass: any;

/** GlassFilters：全局 #glass-distortion SVG 折射滤镜宿主（页面挂一次） */
export declare const GlassFilters: any;

/** GlassSeg：胶囊分段选择（竖分割线 + 滑动玻璃气泡） */
export declare const GlassSeg: any;

/** GlassSwitch：类苹果开关 */
export declare const GlassSwitch: any;

/** GlassModal：二级确认弹窗（open/title/message/danger + confirm/cancel） */
export declare const GlassModal: any;

/** GlassScrollbar：主页面自绘悬浮滚动条（隐藏原生滚动条后接管） */
export declare const GlassScrollbar: any;

/** CodeBoxes：固定 8 格连接码输入（仅字母数字，自动进格） */
export declare const CodeBoxes: any;

/** IpBoxes：4 段式 IP 输入（点预置，自动进格） */
export declare const IpBoxes: any;

/** GlassDock 页签定义 */
export interface DockTabItem {
  id: string;
  icon: string;
  label: string;
}

/**
 * GlassDock 底部悬浮多气泡玻璃 Dock（运行时为 Vue SFC）：
 * v-model 当前页 id；#panel 插槽为展开态面板内容；
 * statusTitle/statusSub/statusOn 驱动状态气泡；自动监听滚动收缩/恢复。
 */
export declare const GlassDock: any;

/** useLiquidGlass composable */
export declare function useLiquidGlass(): {
  displacementMap: string;
  polarDisplacementMap: string;
  generateId: () => string;
  isFirefox: () => boolean;
};

/** 全局 GSAP 悬浮呼吸系统（传入应用的 gsap 实例） */
export interface GsapLike {
  to(targets: unknown, vars: Record<string, unknown>): unknown;
  set(targets: unknown, vars: Record<string, unknown>): unknown;
  killTweensOf(targets: unknown): void;
}

export declare function installGlowHover(gsap: GsapLike): () => void;

/** 设置玻璃模糊采样频率（高=5fps/中=3fps/低=0；壁纸视频本身不锁帧） */
export declare function setBlurInterval(ms: number): void;

/** 同步任务（任务化暂停/恢复） */
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

export declare function useSyncTasks(): {
  tasks: import('vue').Ref<SyncTask[]>;
  createTask(t: {
    direction: 'send' | 'receive';
    peer: string;
    peerIp?: string;
    peerPort?: number;
    peerFingerprint?: string;
    fileCount: number;
    totalBytes: number;
  }): SyncTask;
  updateTask(id: string, patch: Partial<SyncTask>): void;
  pauseTask(id: string, reason?: string): void;
  completeTask(id: string): void;
  failTask(id: string, reason?: string): void;
  removeTask(id: string): void;
};

/** 断网自动重连看门狗（5s 轮询；忙时跳过，对端可达自动恢复 paused 任务） */
export interface AutoResumeOptions {
  isBusy: () => boolean;
  getPending: () => SyncTask | undefined;
  verifyPeer: (t: SyncTask) => Promise<boolean>;
  onReconnect: (t: SyncTask) => void;
  onResume: (t: SyncTask) => void;
  notify: (text: string) => void;
  logInfo: (msg: string) => void;
}

export declare function useAutoResume(opts: AutoResumeOptions): {
  start: () => void;
  stop: () => void;
};

export default LiquidGlass;
