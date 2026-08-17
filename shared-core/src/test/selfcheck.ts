/**
 * 共享核心自检（ponytail: 非平凡逻辑留一个可运行的自检）
 * 用 node:assert 验证核心逻辑，无框架。
 * 运行：node --test dist/test/selfcheck.js
 */

import assert from 'node:assert';
import { test } from 'node:test';

import {
  generateConnectionCode,
  normalizeConnectionCode,
  isValidConnectionCode,
  codesMatch,
} from '../identity.js';
import { diffManifests, buildManifest, makeEntry } from '../manifest.js';
import { updateAnchors, isAfterAnchor, scanDateRange } from '../anchor.js';
import { isConflict, conflictRename, resolveFileName } from '../conflict.js';
import { quickScan, deepScan } from '../scan.js';
import { createEmptyState, getOrCreateDevice, markBackupDone, migrateState } from '../state.js';
import { decidePolicy, isSameWifi } from '../autopolicy.js';
import {
  DebugDispatcher,
  maskSecret,
  logFileName,
  formatLogTimestamp,
  MAX_LOG_ENTRIES,
} from '../logger.js';
import { RegisterDto } from '../transfer.js';

test('连接码：同一特征码生成同一连接码，且为 8 位字母数字', () => {
  const code1 = generateConnectionCode('machine-guid-abc');
  const code2 = generateConnectionCode('machine-guid-abc');
  assert.strictEqual(code1, code2, '同一特征码应生成同一连接码');
  assert.strictEqual(code1.length, 8, '连接码应为 8 位');
  assert.ok(isValidConnectionCode(code1), '连接码应合法');
});

test('连接码：空特征码应抛错', () => {
  assert.throws(() => generateConnectionCode(''), '空特征码应抛错');
});

test('连接码：非 ASCII 特征码生成合法连接码（UTF-8 编码一致性）', () => {
  const code = generateConnectionCode('设备-中文-测试');
  assert.strictEqual(code.length, 8, '非 ASCII 特征码也应生成 8 位码');
  assert.ok(isValidConnectionCode(code), '非 ASCII 特征码生成的码应合法');
});

test('连接码：不同特征码生成不同连接码', () => {
  const a = generateConnectionCode('device-a');
  const b = generateConnectionCode('device-b');
  assert.notStrictEqual(a, b, '不同特征码应生成不同连接码');
});

test('连接码：规范化与匹配（不区分大小写）', () => {
  assert.strictEqual(normalizeConnectionCode(' ab3f-xy12 '), 'AB3FXY12');
  assert.ok(codesMatch('ab3fxy12', 'AB3FXY12'), '大小写应匹配');
  assert.ok(!codesMatch('ab3fxy12', 'AB3FXY13'), '不同码不应匹配');
});

test('清单 Diff：新增与变更', () => {
  const prev = buildManifest([
    makeEntry('a.txt', 100, 1000),
    makeEntry('b.txt', 200, 2000),
  ]);
  const curr = buildManifest([
    makeEntry('a.txt', 100, 1000), // 相同 → 跳过
    makeEntry('b.txt', 300, 2000), // 大小变 → 变更
    makeEntry('c.txt', 50, 3000), // 新增
  ]);
  const diff = diffManifests(prev, curr);
  assert.deepStrictEqual(diff.added, ['c.txt']);
  assert.deepStrictEqual(diff.changed, ['b.txt']);
  assert.deepStrictEqual(diff.toTransfer.sort(), ['b.txt', 'c.txt']);
});

test('锚点：只增不删，mtime 更新', () => {
  let anchors = {};
  anchors = updateAnchors(anchors, [{ relPath: 'a.txt', lastMtime: 1000 }]);
  assert.ok(isAfterAnchor(anchors, 'a.txt', 2000), '新文件应扫描');
  assert.ok(!isAfterAnchor(anchors, 'a.txt', 1000), '等于锚点不扫描');
  assert.ok(!isAfterAnchor(anchors, 'a.txt', 500), '早于锚点不扫描');
  assert.ok(isAfterAnchor(anchors, 'b.txt', 0), '无锚点应扫描');
});

test('冲突：同名且大小/mtime 不一致 → 冲突', () => {
  const existing = { name: 'IMG_001.jpg', size: 100, mtime: 1000 };
  assert.ok(isConflict(existing, { name: 'IMG_001.jpg', size: 200, mtime: 1000 }), '大小不同冲突');
  assert.ok(isConflict(existing, { name: 'IMG_001.jpg', size: 100, mtime: 2000 }), 'mtime不同冲突');
  assert.ok(!isConflict(existing, { name: 'IMG_001.jpg', size: 100, mtime: 1000 }), '完全一致不冲突');
  assert.ok(!isConflict(undefined, { name: 'IMG_001.jpg', size: 100, mtime: 1000 }), '不存在不冲突');
});

test('冲突重命名：原名_MMDDhhmmss.扩展名', () => {
  const mtime = new Date(2026, 7, 15, 8, 23, 45).getTime(); // 2026-08-15 08:23:45
  const renamed = conflictRename('IMG_001.jpg', mtime);
  assert.strictEqual(renamed, 'IMG_001_0815082345.jpg');
});

test('resolveFileName：冲突时重命名，不覆盖', () => {
  const existing = {
    'IMG_001.jpg': { name: 'IMG_001.jpg', size: 100, mtime: 1000 },
  };
  const incoming = { name: 'IMG_001.jpg', size: 200, mtime: new Date(2026, 7, 15, 8, 23, 45).getTime() };
  const result = resolveFileName(existing, incoming);
  assert.notStrictEqual(result, 'IMG_001.jpg', '不应覆盖原名');
  assert.ok(result.startsWith('IMG_001_'), '应重命名');
});

test('快速扫描：只返回锚点之后的文件', () => {
  const anchors = updateAnchors({}, [{ relPath: 'a.txt', lastMtime: 1000 }]);
  const allFiles = [
    { relPath: 'a.txt', size: 100, mtime: 500 }, // 早于锚点 → 跳过
    { relPath: 'b.txt', size: 200, mtime: 2000 }, // 新文件 → 扫描
  ];
  const result = quickScan(anchors, allFiles, 3000);
  assert.strictEqual(result.files.length, 1);
  assert.strictEqual(result.files[0].relPath, 'b.txt');
  assert.ok(result.dateRange, '应返回日期区间');
});

test('深度扫描：全量 Diff', () => {
  const prev = buildManifest([makeEntry('a.txt', 100, 1000)]);
  const allFiles = [
    { relPath: 'a.txt', size: 100, mtime: 1000 }, // 相同 → 跳过
    { relPath: 'b.txt', size: 200, mtime: 2000 }, // 新增 → 扫描
  ];
  const result = deepScan(prev, allFiles);
  assert.strictEqual(result.files.length, 1);
  assert.strictEqual(result.files[0].relPath, 'b.txt');
});

test('状态：创建、获取设备、备份完成更新', () => {
  const state = createEmptyState('SELFCODE', 'Backup-SELF');
  const device = getOrCreateDevice(state, 'PAIRCODE', 'Backup-PAIR');
  assert.strictEqual(device.autoPolicy, 'semi', '默认半自动');
  assert.strictEqual(state.devices['PAIRCODE'], device);

  const manifest = buildManifest([makeEntry('a.txt', 100, 1000)]);
  markBackupDone(state, 'PAIRCODE', manifest, 5000);
  assert.strictEqual(state.devices['PAIRCODE'].lastBackupAt, 5000);
  assert.strictEqual(state.devices['PAIRCODE'].lastAnchorDate, 5000);
});

test('状态：迁移旧版本状态，补全缺失字段', () => {
  // 模拟旧版本状态（缺 version、缺设备字段）
  const raw = {
    selfConnectionCode: 'OLDCODE',
    devices: {
      PAIRCODE: { connectionCode: 'PAIRCODE' }, // 缺 deviceName/anchors 等
    },
  };
  const migrated = migrateState(raw);
  assert.strictEqual(migrated.version, 1, '应补全为当前版本');
  assert.strictEqual(migrated.selfDeviceName, '', '缺失字段应补空');
  const d = migrated.devices['PAIRCODE'];
  assert.strictEqual(d.deviceName, '', '设备缺失字段应补空');
  assert.deepStrictEqual(d.anchors, {}, '锚点应补空对象');
  assert.strictEqual(d.autoPolicy, 'semi', '策略应补默认值');
  assert.strictEqual(d.lastBackupAt, null, '时间应补 null');
});

test('自动策略：半自动弹窗、纯自动静默、纯手动不触发', () => {
  assert.strictEqual(decidePolicy('semi', true, true), 'ask', '半自动+在线+同WiFi → 询问');
  assert.strictEqual(decidePolicy('auto', true, true), 'auto', '纯自动+在线+同WiFi → 静默');
  assert.strictEqual(decidePolicy('manual', true, true), 'none', '纯手动 → 不触发');
  assert.strictEqual(decidePolicy('semi', false, true), 'none', '设备不在线 → 不触发');
  assert.strictEqual(decidePolicy('semi', true, false), 'none', '不同WiFi → 不触发');
});

test('同 Wi-Fi 判断：比较 /24 网段', () => {
  assert.ok(isSameWifi('192.168.1.5', '192.168.1.100'), '同网段 → 同WiFi');
  assert.ok(!isSameWifi('192.168.1.5', '192.168.2.100'), '不同网段 → 不同WiFi');
  assert.ok(!isSameWifi('', '192.168.1.100'), '空IP → 不同WiFi');
});

test('同 Wi-Fi 判断：可配置网段长度（/16）', () => {
  assert.ok(isSameWifi('192.168.1.5', '192.168.2.100', 16), '/16 同网段 → 同WiFi');
  assert.ok(!isSameWifi('192.168.1.5', '192.169.2.100', 16), '/16 不同网段 → 不同WiFi');
});

test('Logger：格式、环形缓冲上限、export 拼接', () => {
  const l = new DebugDispatcher();
  l.clear();
  l.info('test', 'hello');
  l.warn('test', 'warn msg');
  l.error('test', 'boom', new Error('boom detail'));
  const out = l.export();
  // 堆栈含换行，按日志行前缀（时间戳 + 级别）计数
  const lines = out.split('\n').filter((s: string) => s.startsWith('[') && /\[(DEBUG|INFO|WARN|ERROR)\]/.test(s));
  assert.strictEqual(lines.length, 3, '应有 3 条日志');
  // 格式：[YYYY-MM-DD HH:mm:ss.SSS] [LEVEL] [Module] Message
  assert.match(lines[0], /^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\] \[INFO\] \[test\] hello$/);
  assert.match(lines[1], /\[WARN\] \[test\] warn msg/);
  // 错误应附带堆栈
  assert.match(lines[2], /\[ERROR\] \[test\](?: <\w+>)? boom \| boom detail/);
  assert.ok(lines[2].includes('boom detail'));
});

test('Logger：环形缓冲丢弃最旧', () => {
  const l = new DebugDispatcher();
  l.clear();
  for (let i = 0; i < MAX_LOG_ENTRIES + 50; i++) {
    l.debug('test', `msg-${i}`);
  }
  assert.strictEqual(l.size(), MAX_LOG_ENTRIES, '缓冲应限制在上限内');
  const out = l.export();
  assert.ok(out.includes('msg-50'), '应保留最新的');
  assert.ok(!out.includes('msg-0'), '最旧的应被丢弃');
});

test('Logger：脱敏与文件名', () => {
  assert.strictEqual(maskSecret('ABCD1234'), 'AB****34', '只保留前2后2');
  assert.strictEqual(maskSecret('ab'), '****', '过短全打码');
  assert.match(formatLogTimestamp(1755239025123), /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$/);
  assert.match(logFileName(), /^debug_\w+_\d{8}_\d{6}\.log$/);
});

test('RegisterDto：必须包含协议必填的 port 字段（LocalSend 服务端缺它返回 400）', () => {
  const info: RegisterDto = {
    alias: 'Backup-AB3F',
    deviceModel: 'Android',
    deviceType: 'mobile',
    fingerprint: 'FINGERPRINT',
    protocol: 'http',
    port: 53317,
    download: true,
    version: '0.1.0',
  };
  const json = JSON.stringify(info);
  assert.ok(json.includes('"port":53317'), '序列化应包含 port 字段');
});
