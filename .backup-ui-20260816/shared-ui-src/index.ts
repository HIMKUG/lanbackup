/**
 * shared-ui 入口
 * 液态玻璃材质照搬 lucasromerodb/liquid-glass-effect-macos（effect/tint/shine/text 四层
 * + 全局 #glass-distortion 折射滤镜），liquid.css 随本模块注入。
 */
import './liquid.css';
import LiquidGlass from './LiquidGlass.vue';
import GlassFilters from './GlassFilters.vue';
import GlassDock from './GlassDock.vue';
import GlassSeg from './GlassSeg.vue';
import GlassSwitch from './GlassSwitch.vue';
import GlassModal from './GlassModal.vue';
import GlassScrollbar from './GlassScrollbar.vue';
import CodeBoxes from './CodeBoxes.vue';
import IpBoxes from './IpBoxes.vue';

export { LiquidGlass, GlassFilters, GlassDock, GlassSeg, GlassSwitch, GlassModal, GlassScrollbar, CodeBoxes, IpBoxes };
export { installGlowHover, type GsapLike } from './useGlowHover';
export { setBlurInterval } from './blurSampler';
export { useLiquidGlass } from './useLiquidGlass';
export { useSyncTasks, type SyncTask } from './useSyncTasks';
export default LiquidGlass;

// 类型导出
export type {
  LiquidGlassProps,
  MousePosition,
  GlassSize,
  DisplacementMode,
  PositioningMode,
} from './types';
