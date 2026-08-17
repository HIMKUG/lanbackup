/**
 * filesystem.ts - Android 文件系统访问层
 *
 * 重点：Capacitor WebView 默认只能访问 App 私有目录，读不到外部 SD 卡/公共存储。
 * 本模块封装 Capacitor Filesystem 插件，处理：
 * 1. 存储权限申请（Android 10+ READ_MEDIA_*，Android 13+ 细分）
 * 2. 通过 Storage Access Framework（SAF）让用户选目录，拿到持久化 URI
 * 3. 目录遍历 + 文件读取（相对路径 + 大小 + mtime）
 */

import { Filesystem, Directory, Encoding } from '@capacitor/filesystem';
import type { ScannedFile } from 'shared-core';
import { logger } from 'shared-core';
import { LocalDirectory } from './receiver';

/** 扫描到的文件条目（复用 shared-core 的 ScannedFile，避免重复定义） */
export type PlatformFile = ScannedFile;

/** 备份根目录（用户通过 SAF 选择的目录） */
export interface BackupRoot {
  /** SAF 持久化 URI */
  uri: string;
  /** 显示名 */
  name: string;
  /** 授权是否已持久化（false 表示重启后需重新授权） */
  persisted?: boolean;
}

const ROOT_KEY = 'backup_roots';

/**
 * 请求存储权限。
 * Android 13+ 需要 READ_MEDIA_IMAGES/VIDEO/AUDIO，Android 10-12 需要 READ_EXTERNAL_STORAGE。
 * 通过 Capacitor 的权限 API 请求。
 */
export async function requestStoragePermission(): Promise<boolean> {
  try {
    // @capacitor/filesystem 的 requestPermissions 会处理存储权限
    const result = await Filesystem.requestPermissions();
    // Android 部分机型返回 'limited'（部分媒体授权），同样视为可用
    const granted =
      result.publicStorage === 'granted' || (result.publicStorage as string) === 'limited';
    logger.info('filesystem', `存储权限请求结果: ${granted ? '已授予' : '未授予'} (${result.publicStorage})`);
    return granted;
  } catch (e) {
    // 某些平台不支持 requestPermissions，返回 false 让调用方感知
    logger.warn('filesystem', '存储权限请求失败（平台不支持）', e);
    return false;
  }
}

/**
 * 从 SAF tree URI 中解析出可读的目录显示名。
 * SAF tree URI 格式: content://<authority>/tree/<documentId>
 * documentId 示例: "primary:/Documents" 或 URL 编码的 "primary%3A%2FDocuments"
 * 提取逻辑: 去掉 volume 前缀, 取最后一段路径作为目录名。
 */
function extractDirName(uri: string): string | null {
  const match = uri.match(/\/tree\/(.+)$/);
  if (!match) return null;
  const docId = decodeURIComponent(match[1]);
  // "primary:/path/to/dir" → 去掉 "primary:" 前缀, 取最后一段
  const path = docId.replace(/^[^:]+:/, '').replace(/^\/+/, '');
  if (!path) return null;
  const last = path.split('/').pop() || '';
  return last || null;
}

/**
 * 让用户通过 SAF 选择一个备份目录, 返回持久化 URI。
 * 这是读取 SD 卡/公共存储的关键: SAF 授予的 URI 可持久化, App 重启后仍可访问。
 *
 * 失败分类：
 * - 用户取消 → 返回 null（静默, 不视为错误）；
 * - 插件卡死/超时 → 上报 ERROR(TIMEOUT) 并抛出, UI 显示明确错误,
 *   避免"点完没反应"的静默失败。
 */
export async function pickBackupRoot(): Promise<BackupRoot | null> {
  let res: { uri: string; persisted?: boolean } | null = null;
  try {
    // 系统目录选择器是用户交互：浏览时间不可控（可能超过 20s），
    // 短超时会误报"操作超时"并丢弃用户最终的选择。
    // 用 5 分钟兜底：仅真正卡死（插件未路由结果）才会超时报错并留日志。
    res = await logger.withTimeout(
      LocalDirectory.pickDirectory(),
      300000,
      'filesystem',
      'SAF 选择备份目录（文件选择器未返回结果）',
      'PLUGIN_FAIL',
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes('超时')) {
      // 卡死：withTimeout 已上报 ERROR, 这里抛出让 UI 提示用户
      throw e;
    }
    // 用户取消文件选择器：正常路径, 不记错误
    logger.info('filesystem', '用户未选择备份目录');
    return null;
  }
  if (!res?.uri) {
    logger.info('filesystem', '用户未选择备份目录');
    return null;
  }
  const name = extractDirName(res.uri) || '备份目录';
  const root: BackupRoot = { uri: res.uri, name, persisted: res.persisted !== false };
  await saveRoot(root);
  logger.info('filesystem', `已选择备份目录: ${root.name} (${root.uri})`);
  return root;
}

/** 保存备份根目录列表 */
async function saveRoot(root: BackupRoot): Promise<void> {
  const roots = await getRoots();
  if (!roots.some((r) => r.uri === root.uri)) {
    roots.push(root);
    await Filesystem.writeFile({
      path: ROOT_KEY,
      data: JSON.stringify(roots),
      directory: Directory.Data,
      encoding: Encoding.UTF8,
    });
  }
}

/** 获取已保存的备份根目录列表 */
export async function getRoots(): Promise<BackupRoot[]> {
  try {
    const file = await Filesystem.readFile({
      path: ROOT_KEY,
      directory: Directory.Data,
      encoding: Encoding.UTF8,
    });
    return JSON.parse(file.data as string) as BackupRoot[];
  } catch {
    return [];
  }
}

/** 移除一个备份根目录（用户取消勾选/删除时调用） */
export async function removeRoot(uri: string): Promise<void> {
  const roots = await getRoots();
  const next = roots.filter((r) => r.uri !== uri);
  await Filesystem.writeFile({
    path: ROOT_KEY,
    data: JSON.stringify(next),
    directory: Directory.Data,
    encoding: Encoding.UTF8,
  });
}

/**
 * 内部残留名（不进入备份清单）：
 * - __chunked__/.chunks：大文件分片目录（旧版发送端曾把分片落盘到源目录，接收端也用 .chunks 暂存）
 * - __batch__ 前缀：琐碎文件 tar 聚合临时文件
 * - .dec_tmp 后缀：接收端解密临时文件
 * 与桌面端 scan_dir_recursive 的排除规则保持一致，否则分片残留会被当作源文件重新上传，
 * 污染对端 .chunks 状态并破坏三路对比（实测 111 个分片残留混进 293 条清单）。
 */
function isInternalEntry(name: string, type: 'directory' | 'file'): boolean {
  if (type === 'directory') return name === '__chunked__' || name === '.chunks';
  return name.startsWith('__batch__') || name.endsWith('.dec_tmp');
}

/**
 * 递归遍历目录，生成文件清单。
 * @param rootUri 备份根目录 URI
 * @param dirPath 当前目录相对路径（空 = 根）
 * @param result 结果数组（递归累加）
 */
export async function walkDirectory(
  rootUri: string,
  dirPath = '',
  result: PlatformFile[] = [],
): Promise<PlatformFile[]> {
  logger.debug('filesystem', `遍历目录: ${dirPath || '(根)'}`);
  // 原生 SAF 插件遍历（Capacitor filesystem 的 readdir 不支持 content:// tree）
  const { files } = await LocalDirectory.readdir({ uri: rootUri, relPath: dirPath });

  // 同级子目录并行遍历（每目录一次 JNI 往返，串行时目录越多延迟越线性叠加）
  const subTasks: Promise<unknown>[] = [];
  for (const entry of files) {
    if (isInternalEntry(entry.name, entry.type)) continue;
    const relPath = dirPath ? `${dirPath}/${entry.name}` : entry.name;
    if (entry.type === 'directory') {
      subTasks.push(walkDirectory(rootUri, relPath, result));
    } else if (entry.type === 'file') {
      result.push({
        relPath,
        size: entry.size ?? 0,
        mtime: entry.mtime ?? 0,
      });
    }
  }
  await Promise.all(subTasks);
  logger.debug('filesystem', `目录遍历完成: ${dirPath || '(根)'} 累计 ${result.length} 条`);
  return result;
}

/**
 * 读取单个文件为 Blob（用于上传）。
 * @param rootUri 备份根目录 URI（SAF tree）
 * @param relPath 相对路径
 */
export async function readFileAsBlob(rootUri: string, relPath: string): Promise<Blob> {
  logger.debug('filesystem', `读取文件开始: ${relPath}`);
  const { data } = await LocalDirectory.readFile({ uri: rootUri, relPath });
  const blob = base64ToBlob(data);
  logger.debug('filesystem', `读取文件完成: ${relPath} (${blob.size}B)`);
  return blob;
}

/** base64 转 Blob */
function base64ToBlob(base64: string): Blob {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new Blob([bytes]);
}

/** Blob 转 base64（用于 Filesystem.writeFile） */
export function blobToBase64(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      // dataUrl 形式 → 去掉前缀只留 base64 部分
      const comma = result.indexOf(',');
      resolve(comma >= 0 ? result.slice(comma + 1) : result);
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(blob);
  });
}

/**
 * 确保目录存在（递归创建缺失层级）。
 * 接收端保存文件前调用，重建发送端的目录结构。
 */
export async function ensureDirectory(rootUri: string, relDir: string): Promise<void> {
  if (!relDir) return;
  // 逐级创建，避免 SAF 下一次性创建多级失败
  const parts = relDir.split('/');
  let cur = rootUri;
  for (const part of parts) {
    cur = `${cur}/${part}`;
    try {
      await Filesystem.mkdir({ path: cur, recursive: false });
    } catch {
      // 目录已存在时 mkdir 抛错，忽略即可
    }
  }
}

/**
 * 写入文件内容（用于接收端保存文件）。
 * @param rootUri 备份根目录 URI
 * @param relPath 相对路径（含目录层级）
 * @param data 文件内容（base64 / dataUrl / Blob）
 */
export async function writeFileContent(
  rootUri: string,
  relPath: string,
  data: string | Blob,
): Promise<void> {
  const rel = relPath.replace(/^\/+/, '');
  logger.debug('filesystem', `写入文件开始: ${rel}`);
  // 确保父目录存在
  const slash = rel.lastIndexOf('/');
  if (slash > 0) {
    await ensureDirectory(rootUri, rel.slice(0, slash));
  }
  const content = typeof data === 'string' ? data : await blobToBase64(data);
  await Filesystem.writeFile({
    path: `${rootUri}/${rel}`,
    data: content,
    recursive: true,
  });
  logger.debug('filesystem', `写入文件完成: ${rel}`);
}

/** 检查文件是否存在 */
export async function fileExists(rootUri: string, relPath: string): Promise<boolean> {
  try {
    const stat = await Filesystem.stat({ path: `${rootUri}/${relPath}` });
    return stat.type === 'file';
  } catch {
    return false;
  }
}
