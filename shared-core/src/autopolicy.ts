/**
 * autopolicy.ts - 自动策略
 *
 * 出厂默认：半自动（发现已配对电脑在线 + 同 Wi-Fi → 弹窗询问是否备份）。
 * 支持切换：纯自动（静默传）/ 纯手动（点按钮才传）。
 */

import { AutoPolicy } from './state.js';
import { logger } from './logger.js';

/** 策略决策结果 */
export type PolicyDecision = 'ask' | 'auto' | 'none';

/**
 * 根据自动策略 + 环境状态，决定本次是否触发备份。
 *
 * @param policy 自动策略
 * @param pairedOnline 已配对设备是否在线
 * @param sameWifi 是否同 Wi-Fi
 * @returns 'ask' = 弹窗询问（半自动）；'auto' = 静默执行（纯自动）；'none' = 不触发
 */
export function decidePolicy(
  policy: AutoPolicy,
  pairedOnline: boolean,
  sameWifi: boolean,
): PolicyDecision {
  // 设备不在线或不同 Wi-Fi → 不触发
  if (!pairedOnline || !sameWifi) {
    logger.debug(
      'autopolicy',
      `策略决策: policy=${policy} pairedOnline=${pairedOnline} sameWifi=${sameWifi} → none`,
    );
    return 'none';
  }

  let decision: PolicyDecision;
  switch (policy) {
    case 'auto':
      decision = 'auto'; // 纯自动：静默传
      break;
    case 'semi':
      decision = 'ask'; // 半自动：弹窗询问
      break;
    case 'manual':
    default:
      decision = 'none'; // 纯手动：点按钮才传
      break;
  }
  logger.info(
    'autopolicy',
    `策略决策: policy=${policy} pairedOnline=${pairedOnline} sameWifi=${sameWifi} → ${decision}`,
  );
  return decision;
}

/**
 * 判断是否同 Wi-Fi。
 * 通过比较两端 IP 的网段前缀来判断。
 * 默认按 /24 网段比较（家庭/小型办公网络）。
 * 可通过 prefixLen 参数调整网段长度（如 /16 用于大型企业网络）。
 *
 * @param selfIp 本机局域网 IP
 * @param peerIp 对端局域网 IP
 * @param prefixLen 网段前缀长度（1-32），默认 24
 */
export function isSameWifi(selfIp: string, peerIp: string, prefixLen = 24): boolean {
  if (!selfIp || !peerIp) return false;
  const selfParts = selfIp.split('.');
  const peerParts = peerIp.split('.');
  if (selfParts.length !== 4 || peerParts.length !== 4) return false;
  // 按 prefixLen 比较前若干段（每段 8 位）
  const segments = Math.ceil(prefixLen / 8);
  for (let i = 0; i < segments; i++) {
    if (selfParts[i] !== peerParts[i]) return false;
  }
  return true;
}
