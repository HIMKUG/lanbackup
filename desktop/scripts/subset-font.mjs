/**
 * 字体子集化：苹方黑体 TTF → woff2（GB2312 符号区 + 一级汉字 + ASCII + 常用符号）。
 * 只打包子集，不打包完整字体。产出：public/fonts/app-font.woff2
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import subsetFont from 'subset-font';

const SRC = 'D:/code/tools/docs/苹方黑体-中黑-简.ttf';

let text = '';
// ASCII 可打印
for (let c = 0x20; c <= 0x7e; c++) text += String.fromCharCode(c);
// GBK/GB2312 符号区（全角标点、圆圈数字、罗马数字等）
const dec = new TextDecoder('gbk');
for (let b = 0xa1; b <= 0xa9; b++) {
  for (let c2 = 0xa1; c2 <= 0xfe; c2++) {
    try {
      text += dec.decode(new Uint8Array([b, c2]));
    } catch {
      // 非法组合跳过
    }
  }
}
// GB2312 一级汉字（常用 3755 字）
for (let b = 0xb0; b <= 0xd7; b++) {
  for (let c2 = 0xa1; c2 <= 0xfe; c2++) {
    try {
      text += dec.decode(new Uint8Array([b, c2]));
    } catch {
      // 非法组合跳过
    }
  }
}
// 界面用到的额外符号
text += '→✓✕＋⚠·↗⌃⌄▾─…—';

const unique = [...new Set(text)].join('');
console.log('subset chars:', unique.length);

const buf = readFileSync(SRC);
const out = await subsetFont(buf, unique, { targetFormat: 'woff2' });
mkdirSync('public/fonts', { recursive: true });
writeFileSync('public/fonts/app-font.woff2', out);
console.log('woff2 bytes:', out.length);
