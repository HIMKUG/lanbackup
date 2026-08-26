/**
 * identity.ts - 设备身份与连接码
 *
 * 每台设备首次启动，基于系统稳定特征码计算一个永久 8 位连接码。
 * 连接码由不分大小写的字母和数字组成（去掉易混淆字符），共 31^8 种可能。
 * 连接码是哈希后的展示码，不暴露原始特征码。
 *
 * 协议版本常量（与 Rust/Java 端一致）：
 * - PROTOCOL_VERSION: 当前协议版本
 * - MIN_PROTOCOL_VERSION: 最低兼容版本
 * - KDF_VERSION: KDF 版本（1=SHA-256, 2=PBKDF2）
 * - CRYPTO_VERSION: 加密版本（1=连接码直接派生, 2=ECDH）
 */

// 去掉易混淆字符（0/O、1/I/L 等），保证可读性
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const CODE_LENGTH = 8;

/** 当前协议版本 */
export const PROTOCOL_VERSION = '1.1';
/** 最低兼容协议版本 */
export const MIN_PROTOCOL_VERSION = '1.0';
/** KDF 版本：1=SHA-256（原始），2=PBKDF2（加固） */
export const KDF_VERSION = 2;
/** 加密版本：1=连接码直接派生，2=ECDH 密钥交换 */
export const CRYPTO_VERSION = 2;
/** PBKDF2 迭代次数（OWASP 2023 建议下限，2026 年适用） */
export const PBKDF2_ITERATIONS = 600000;

import { logger, maskSecret } from './logger.js';

/**
 * 生成 8 位连接码。
 * 基于系统稳定特征码（电脑 MachineGuid/machine-id，手机本地 UUID）哈希得到。
 * 使用 FNV-1a 哈希 + 多次迭代，保证同一特征码永远得到同一连接码。
 *
 * 注意：哈希输入按 UTF-8 字节处理，与 Rust 端 identity.rs 的 `.bytes()` 完全一致，
 * 确保两端对同一特征码生成相同连接码。
 *
 * @param stableId 系统稳定特征码
 * @returns 8 位连接码（大写字母+数字）
 */
export function generateConnectionCode(stableId: string): string {
  // P3-315：与 Rust 端对齐——空 stableId 走确定性兜底而非抛异常，避免设备标识损坏时前端崩溃
  const stable = stableId && stableId.length > 0 ? stableId : 'unknown-device';
  // 记录输入特征（脱敏：不落盘完整特征码）
  logger.debug(
    'identity',
    `generateConnectionCode 输入特征: 长度=${stable.length} 前缀=${maskSecret(stable)}`,
  );
  // FNV-1a 32-bit 哈希，迭代多次以充分扩散
  let hash = 0x811c9dc5;
  const input = stable + '|localsend-backup|v1';
  // 按 UTF-8 字节遍历，与 Rust 端 input.bytes() 一致
  const bytes = new TextEncoder().encode(input);
  for (let i = 0; i < bytes.length; i++) {
    hash ^= bytes[i];
    hash = Math.imul(hash, 0x01000193);
  }

  // 用哈希值做种子，生成 8 位码
  let seed = hash >>> 0;
  let code = '';
  for (let i = 0; i < CODE_LENGTH; i++) {
    // 用 xorshift 生成伪随机序列
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    seed = seed >>> 0;
    code += CODE_ALPHABET[seed % CODE_ALPHABET.length];
  }
  logger.info('identity', `连接码生成完成: ${maskSecret(code)}（哈希种子=${(hash >>> 0).toString(16)}）`);
  return code;
}

/**
 * 规范化连接码：转大写、去空格、去分隔符。
 * 用户输入时可能带空格或小写，统一规范化后再比较。
 */
export function normalizeConnectionCode(code: string): string {
  return code.replace(/[\s\-_]/g, '').toUpperCase();
}

/**
 * 校验连接码格式是否合法（8 位，仅含字母数字）。
 */
export function isValidConnectionCode(code: string): boolean {
  const normalized = normalizeConnectionCode(code);
  if (normalized.length !== CODE_LENGTH) return false;
  return /^[A-Z0-9]+$/.test(normalized);
}

/**
 * 比较两个连接码是否匹配（不区分大小写）。
 */
export function codesMatch(a: string, b: string): boolean {
  return normalizeConnectionCode(a) === normalizeConnectionCode(b);
}

/**
 * 生成设备显示名（可选，用于 UI 展示）。
 * 基于连接码生成一个简短可读的名字，如 "Backup-AB3F"。
 */
export function deviceDisplayName(connectionCode: string): string {
  const code = normalizeConnectionCode(connectionCode);
  return `Backup-${code.slice(0, 4)}`;
}
