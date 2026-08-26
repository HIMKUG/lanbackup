/**
 * crypto.ts - ECDH 密钥交换与 session_key 派生（#8 传输加密核心）
 *
 * 协议版本：
 * - cryptoVersion = 2（ECDH 密钥交换）
 *
 * 密钥派生层次：
 *   原始特征码 → 连接码（UI 显示用，不参与加密）
 *   ECDH 共享密钥 → PBKDF2(salt, 600k) → session_key（传输加密）
 *   原始特征码 → PBKDF2(salt, 600k) → local_storage_key（本地存储加密，#9）
 *
 * QR Code 格式：LANBACKUP_V1|<base64(pubKey_32B)>|<base64(salt_32B)>|<base64(challenge_16B)>
 *
 * SAS 计算：SHA256(shared_secret_bytes) → 前 3 字节 → u32 % 1_000_000 → 零填充 6 位字符串
 */

import { PBKDF2_ITERATIONS } from './identity.js';

/** ECDH P-256 曲线参数（Web Crypto NIST P-256） */
const EC_PARAMS = { name: 'ECDH', namedCurve: 'P-256' };
/** AES-256-GCM 参数 */
const AES_GCM_PARAMS = { name: 'AES-GCM', length: 256 };
/** nonce 长度（GCM 推荐 12 字节） */
const NONCE_LEN = 12;

/**
 * 生成 ECDH 密钥对（P-256）。
 * @returns [publicKey (JWK JSON string), privateKey (CryptoKey)]
 */
export async function ecdhGenerateKeyPair(): Promise<[string, CryptoKey]> {
  const keyPair = await crypto.subtle.generateKey(EC_PARAMS, true, ['deriveBits']);
  const pubKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  return [JSON.stringify(pubKeyJwk), keyPair.privateKey];
}

/**
 * 从 JWK JSON 字符串重建 CryptoKey 公钥对象。
 * @param pubKeyJson 公钥 JWK JSON 字符串
 */
export async function ecdhImportPublicKey(pubKeyJson: string): Promise<CryptoKey> {
  const jwk = JSON.parse(pubKeyJson);
  return crypto.subtle.importKey('jwk', jwk, EC_PARAMS, true, []);
}

/**
 * 导出本端公钥为 base64 字符串（用于 QR Code 编码）。
 * @param privateKey 本端私钥 CryptoKey
 */
export async function ecdhExportPublicKeyBase64(privateKey: CryptoKey): Promise<string> {
  const pubKey = await crypto.subtle.exportKey('jwk', privateKey);
  const raw = uint8ArrayToBase64Url(exportRawKey(pubKey));
  return raw;
}

/** 从 JWK 导出原始字节（x||y 拼接，P-256 公钥 64 字节） */
function exportRawKey(jwk: JsonWebKey): Uint8Array {
  const x = base64UrlDecode(jwk.x!);
  const y = base64UrlDecode(jwk.y!);
  const out = new Uint8Array(64);
  out.set(x, 0);
  out.set(y, 32);
  return out;
}

/**
 * 派生 ECDH 共享密钥字节（x||y 拼接，共 64 字节）。
 * @param privateKey 本端私钥
 * @param peerPubKeyJwkJson 对方公钥 JWK JSON 字符串
 */
export async function ecdhDeriveSharedKey(
  privateKey: CryptoKey,
  peerPubKeyJwkJson: string,
): Promise<Uint8Array> {
  const peerPubKey = await ecdhImportPublicKey(peerPubKeyJwkJson);
  const bits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerPubKey },
    privateKey,
    256,
  );
  return new Uint8Array(bits);
}

/**
 * 计算 SAS（Short Authentication String）：6 位数字。
 *
 * 算法：SHA256( ECDH_raw_output ) 前 3 字节 → 大端序 u32 % 1_000_000 → 零填充 6 位。
 *
 * SAS 直接绑定到 ECDH 原始输出（与 session_key 路径解耦）。
 * session_key 用 SHA256(ECDH_raw) 做 PBKDF2；SAS 用 SHA256(ECDH_raw) 校验——两者派生源
 * 都是 SHA256(ECDH_raw)，但用途独立，符合密码学惯例。
 *
 * @param sharedSecret ECDH 共享密钥的原始输出（32 字节，p256 X 坐标）
 */
export async function computeSas(sharedSecret: Uint8Array): Promise<string> {
  // N2 修正：SAS 直接对 ECDH_raw 做单层 SHA256，与 session_key 路径解耦
  const hash = await sha256(sharedSecret);
  const val = (hash[0] << 16) | (hash[1] << 8) | hash[2];
  return String(val % 1_000_000).padStart(6, '0');
}

/**
 * 派生 session_key：SHA256(ECDH_raw_output) → PBKDF2(sha256ed, salt, 600k) → 32 字节。
 *
 * P-256 ECDH 的原始输出是未压缩点的 X 坐标（32 字节），有结构性偏差
 *（X 坐标不是均匀随机字节序列）。为安全起见，先对 raw output 做 SHA-256
 * 得到均匀的 32 字节，再送入 PBKDF2。三端（TS/Rust/Android）均采用此方案。
 *
 * @param sharedSecret ECDH 共享密钥的原始输出（32 字节，p256 X 坐标）
 * @param salt 配对发起方生成的随机 32 字节（base64 编码）
 */
export async function deriveSessionKey(
  sharedSecret: Uint8Array,
  salt: string,
): Promise<CryptoKey> {
  // S2 安全修复：对 raw ECDH 输出先做 SHA-256，消除结构性偏差
  const uniformKey = await sha256(sharedSecret);
  const saltBytes = base64UrlDecode(salt);
  if (saltBytes.length < 16) throw new Error('PBKDF2 salt must be at least 16 bytes');
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    uniformKey,
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    AES_GCM_PARAMS,
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * AES-256-GCM 加密：输出 `LSBK || nonce || ciphertext || tag`（与 Rust/Java 格式一致）。
 * @param plaintext 明文 ArrayBuffer
 * @param sessionKey 加密密钥
 */
export async function encryptSession(
  plaintext: ArrayBuffer,
  sessionKey: CryptoKey,
): Promise<Blob> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    sessionKey,
    plaintext,
  );
  const MAGIC = new Uint8Array([0x4c, 0x53, 0x42, 0x4b]); // "LSBK"
  const out = new Uint8Array(MAGIC.length + NONCE_LEN + ciphertext.byteLength);
  out.set(MAGIC, 0);
  out.set(nonce, MAGIC.length);
  out.set(new Uint8Array(ciphertext), MAGIC.length + NONCE_LEN);
  return new Blob([out]);
}

/**
 * AES-256-GCM 解密（LSBK 格式）。
 * @param ciphertext 密文 ArrayBuffer
 * @param sessionKey 解密密钥
 */
export async function decryptSession(
  ciphertext: ArrayBuffer,
  sessionKey: CryptoKey,
): Promise<ArrayBuffer> {
  const data = new Uint8Array(ciphertext);
  if (data.length < 4 + NONCE_LEN) throw new Error('密文长度不足');
  const nonce = data.slice(4, 4 + NONCE_LEN);
  const ct = data.slice(4 + NONCE_LEN);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, sessionKey, ct);
}

/**
 * 用 session_key 加密 challenge：验证对方持有相同的 shared_secret。
 * AES-GCM(shared_secret, challenge) → ciphertext（发给对方验证）。
 *
 * @param challenge 16 字节随机挑战
 * @param sessionKey 加密密钥
 */
export async function encryptChallenge(
  challenge: Uint8Array,
  sessionKey: CryptoKey,
): Promise<Blob> {
  return encryptSession(challenge.buffer, sessionKey);
}

/**
 * 验证 challenge 响应：解密并比对原 challenge。
 * @param encryptedChallenge 加密的挑战响应
 * @param originalChallenge 原始 16 字节挑战
 * @param sessionKey 解密密钥
 * @returns 验证是否通过
 */
export async function verifyChallengeResponse(
  encryptedChallenge: ArrayBuffer,
  originalChallenge: Uint8Array,
  sessionKey: CryptoKey,
): Promise<boolean> {
  try {
    const decrypted = await decryptSession(encryptedChallenge, sessionKey);
    const dec = new Uint8Array(decrypted);
    if (dec.length !== originalChallenge.length) return false;
    for (let i = 0; i < dec.length; i++) {
      if (dec[i] !== originalChallenge[i]) return false;
    }
    return true;
  } catch {
    return false;
  }
}

// ============================================================
// QR Code 解析与编码
// ============================================================

/** QR Code 前缀（防其他 QR 干扰） */
const QR_PREFIX = 'LANBACKUP_V1|';

/**
 * 解析 QR Code 内容，提取 ECDH 公钥、salt、challenge。
 * @param qrContent QR Code 扫描结果
 * @returns [pubKeyBase64, saltBase64, challengeBase64]
 */
export function parseQrContent(qrContent: string): [string, string, string] {
  if (!qrContent.startsWith(QR_PREFIX)) {
    throw new Error('无效的 QR Code 格式（不是 LAN Backup 配对码）');
  }
  const parts = qrContent.slice(QR_PREFIX.length).split('|');
  if (parts.length !== 3) {
    throw new Error('QR Code 字段数不正确');
  }
  return [parts[0], parts[1], parts[2]];
}

/**
 * 构建 QR Code 内容（Desktop 发起方调用）。
 * @param pubKeyBase64 本机 ECDH 公钥（base64url）
 * @param saltBase64 随机 salt（base64url）
 * @param challengeBase64 随机 challenge（base64url）
 */
export function buildQrContent(
  pubKeyBase64: string,
  saltBase64: string,
  challengeBase64: string,
): string {
  return `${QR_PREFIX}${pubKeyBase64}|${saltBase64}|${challengeBase64}`;
}

// ============================================================
// 工具函数
// ============================================================

/** 生成随机字节（base64url 编码） */
export function randomBase64Url(byteCount: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteCount));
  return uint8ArrayToBase64Url(bytes);
}

/** Uint8Array → base64url 字符串 */
function uint8ArrayToBase64Url(arr: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/** base64url → Uint8Array */
function base64UrlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const paddedLen = Math.ceil(padded.length / 4) * 4;
  const padded2 = padded.padEnd(paddedLen, '=');
  return Uint8Array.from(atob(padded2), c => c.charCodeAt(0));
}

/**
 * SHA-256 同步实现（仅用于 SAS 计算的少量数据）。
 * 内部使用 Web Crypto 同步构造（浏览器无同步 API，用异步但只处理 64 字节数据）。
 */
async function sha256Async(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return new Uint8Array(buf);
}

/** SHA-256（异步，供 SAS 计算） */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return new Uint8Array(buf);
}
