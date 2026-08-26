/* ============================================================
 * ball-scripts.js —— 悬浮球【行为机】
 * 把「程序状态」翻译成一段可播放的「表情脚本」。
 *
 * 现代化行为化驱动：状态只是一个键，具体"演什么、演多久、怎么演"
 * 都由脚本表 + 可中断播放器决定。App 端只发语义状态，球端自演。
 *
 * 节点语法：
 *   "02"                   2 位数字 => 表情 id，停留 STEP_DEFAULT
 *   "idle"               非数字串 => 引用另一状态脚本
 *   { id, dur? }                   单个表情（可指定停留 ms）
 *   [ a, b, c ]                   顺序播放每个子节点
 *   { t:'seq', list }             显式顺序
 *   { t:'pick', opts }            随机选一个子节点播放
 *   { t:'alt', opts, ms }         opts 内表情安 x ms 循环轮流
 *   { t:'rep', n, node }          把 node 重复 n 次
 * ============================================================ */

window.BallScript = (function () {
  'use strict';

  // ---------- 全局节奏 ----------
  var STEP_DEFAULT = 2600;   // 一般表情单次停留
  var TOAST_HOLD = 3000;     // 一次性提示停留（播完回退回）

  // ---------- 播放器：可中断的异步状态机 ----------
  function makeEngine(apply) {
    var runId = 0;

    function halt() { runId++; }

    function start(stateKey) {
      var my = ++runId;
      var script = SCRIPTS[stateKey];
      if (!script) {
        // 未定义状态：不把状态键当表情 id 误播，回落到就绪，避免无效表情
        if (stateKey) apply('02');
        return;
      }
      play(script, my).catch(function () {});
    }

    function sleep(ms) {
      return new Promise(function (r) { setTimeout(r, ms); });
    }

    function alive(my) { return my === runId; }

    async function play(node, my) {
      var x = normalize(node);
      if (!alive(my)) return;
      switch (x.t) {
        case 'face':
          apply(x.id);
          await sleep(x.dur || STEP_DEFAULT);
          break;
        case 'seq':
          for (var i = 0; i < x.list.length; i++) {
            if (!alive(my)) return;
            if (x.list[i] != null) await play(x.list[i], my);
          }
          break;
        case 'rep': {
          var c, n = x.n || 1, d = x.dur || STEP_DEFAULT;
          for (c = 0; c < n; c++) {
            if (!alive(my)) return;
            await play({ t: 'face', id: x.id, dur: d }, my);
          }
          break;
        }
        case 'pick':
          await play(x.opts[(Math.random() * x.opts.length) | 0], my);
          break;
        case 'alt': {
          var ids = x.opts, ms = x.ms || STEP_DEFAULT, i = 0;
          await new Promise(function (resolve) {
            (function loop() {
              if (!alive(my)) { resolve(); return; }
              apply(ids[i % ids.length]);
              i++;
              setTimeout(loop, ms);
            })();
          });
          break;
        }
        case 'ref': {
          var sub = SCRIPTS[x.s];
          if (sub) await play(sub, my);
          break;
        }
        default:
          break;
      }
    }

    return { start: start, halt: halt };
  }

  // ---------- 归一化 ----------
  function normalize(node) {
    if (typeof node === 'string') {
      return /^\d\d$/.test(node) ? { t: 'face', id: node } : { t: 'ref', s: node };
    }
    if (Array.isArray(node)) return { t: 'seq', list: node };
    return node; // 已是 { t: ... }
  }

  // ---------- 状态脚本表 ----------
  var SCRIPTS = {
    // 启动 / 加载（启动只表现“苏醒 → 就绪”，不进入扫描；扫描仅在点击“开始发现”后触发）
    boot:      [ '01', '07', '02' ],           // 唤醒 → 抖动苏醒 → 就绪稳定
    loading:   '05',                           // 真正的加载中（耗时跨端场景才短暂显示）
    ready:     '02',                           // 就绪稳定态

    // 发现 / 配对
    discovering: { t: 'alt', opts: ['40', '35'], ms: 2600 }, // 检索资料 ⇄ 等待输入
    found:    '03',                            // 发现到设备 → 好奇
    pairing:  { t:'seq', list: ['37', '35', '37'] }, // 复述回忆 → 等待输入 → 复述回忆

    // 工作
    solving:  '30',                            // 差异计算 → 思考中
    scanning: { t:'seq', list: [ { id:'05', dur:1400 }, '40' ] }, // 加载苏醒 → 检索资料
    syncing:  { t: 'alt', opts: ['16', '32'], ms: 2400 },   // 专注 ⇄ 忙碌 交替
    receiving: { t: 'seq', list: [            // 接收全流程：连接 → 忙碌 → 慌张 → 持续交替
                { t:'rep', n:2, id:'36', dur:1200 },   // 联网加载 ×2
                { t:'alt', opts:['31','32'], ms:2200 }, // 接收任务 ⇄ 忙碌
                { id:'17', dur:1500 },                  // 慌张（密集处理）
                { t:'alt', opts:['31','39','32'], ms:2400 } // 接收/回复/忙碌 持续交替（持续态）
              ] },

    // 结果
    success:  { t: 'seq', list: [
                { t: 'rep', n: 3, id: '33', dur: 700 },
                { id: '10', dur: 30000 },
                'idle'
              ] },                             // 33 ×3 → 开心30s → 休眠
    failure:  { t: 'seq', list: ['34', '34', '34', '21'] }, // 出错×3 → 生气保持

    // 空闲 / 休眠（组合动作，把 00-07 生命周期表情都用上）
    idle:     { t: 'pick', opts: [
                { t:'seq', list: ['00', '01'] },   // 睡眠 → 唤醒
                { t:'seq', list: ['06', '07'] },   // 休眠 → 抖动唤醒
                { t:'seq', list: ['04', '07'] },   // 发呆 → 抖动唤醒
                { t:'seq', list: ['02', '02'] },   // 待机放空
                { t:'seq', list: ['00', '07', '02'] }
              ] },
    idleWake: { t: 'pick', opts: ['12', '15'] },  // 偶发不睡（失落/疲惫）
    lonely:   { t: 'pick', opts: [
                '12',                             // 失落
                '15',                             // 疲惫
                '18',                             // 无奈
                { t:'seq', list: ['12', '15', '18'] }
              ] },                                // 无目标/未连接

    // 一次性提示（播完自动回空闲；覆盖所有情绪类表情）
    toast_confused:  { t:'seq', list: [{ id:'11', dur: TOAST_HOLD }, 'idle'] },
    toast_surprise:  { t:'seq', list: [{ id:'13', dur: TOAST_HOLD }, 'idle'] },
    toast_shy:       { t:'seq', list: [{ id:'14', dur: TOAST_HOLD }, 'idle'] },
    toast_satisfied: { t:'seq', list: [{ id:'19', dur: TOAST_HOLD }, 'idle'] },
    toast_puzzled:   { t:'seq', list: [{ id:'20', dur: TOAST_HOLD }, 'idle'] },
    toast_online:    { t:'seq', list: [{ id:'36', dur: TOAST_HOLD }, 'idle'] },
    toast_denied:    { t:'seq', list: [{ id:'38', dur: TOAST_HOLD }, 'idle'] },
    toast_reply:     { t:'seq', list: [{ id:'39', dur: TOAST_HOLD }, 'idle'] },
    toast_stop:      { t:'seq', list: [{ id:'41', dur: TOAST_HOLD }, 'idle'] },
    toast_listen:    { t:'seq', list: [{ id:'35', dur: TOAST_HOLD }, 'idle'] }
  };

  return {
    create: makeEngine,
    scripts: SCRIPTS,
    state: function (k) { return SCRIPTS[k] || null; }
  };
})();