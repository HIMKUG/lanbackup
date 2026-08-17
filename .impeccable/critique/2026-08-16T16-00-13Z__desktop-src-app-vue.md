---
target: 整个风格（desktop+mobile+shared-ui）
total_score: 20
max_score: 40
na_heuristics: 
p0_count: 1
p1_count: 3
timestamp: 2026-08-16T16-00-13Z
slug: desktop-src-app-vue
---
# Critique — 局域网备份 全风格（desktop + mobile + shared-ui）

Method: dual-agent (A: agent_f82ae9b0 · B: agent_37fb1b80)

## Design Health Score: 20/40 (Acceptable)

| # | Heuristic | Score | Key Issue |
|---|-----------|-------|-----------|
| 1 | Visibility of System Status | 3 | failTask 从未调用，失败显示为「已暂停」；桌面进度无百分比 |
| 2 | Match System / Real World | 2 | 镜像策略无解释却移动对方文件；端口 53317 直接暴露；一个服务四个名字 |
| 3 | User Control and Freedom | 2 | 镜像移动对端文件零确认；历史行删除无撤销；GlassModal 无 Esc/焦点陷阱 |
| 4 | Consistency and Standards | 2 | 双端漂移：ETA 单位、历史上限 100/200、0 B vs —、百分比仅手机 |
| 5 | Error Prevention | 2 | 镜像静默移动；端口输入无校验；IpBoxes 粘贴损坏 IP |
| 6 | Recognition Rather Than Recall | 3 | 设备下拉含状态良好；设为可见/隐藏藏在折叠 dock 面板 |
| 7 | Flexibility and Efficiency | 2 | 无键盘快捷键；user-select:none 阻止复制 ip:port |
| 8 | Aesthetic and Minimalist Design | 2 | 动画预算错配：22 粒烟雾庆祝删历史；壁纸全帧率；字号阶梯仅 1.5px 跨度 |
| 9 | Error Recovery | 1 | 原始异常文本进 toast 4.2s 后蒸发；任务行无原因无重试 |
| 10 | Help and Documentation | 1 | 无 onboarding、无增量/镜像解释、无帮助面 |

## Design Specificity
判定：generic——无关产品可原样复用。玻璃配方整体移植自第三方 CodePen（liquid.css:2）；壁纸/模糊系统零语义工作（不随传输状态变化）；已连接与在线共用同一绿色脉冲；最大字号 14.5px 无排版声音。

## Priority Issues
- [P0] 镜像模式零披露移动对端文件（desktop/src/App.vue:1596-1602）
- [P1] 立即同步 CTA 藏在默认折叠面板内，首屏无操作入口（App.vue:431-432, 2080-2087）
- [P1] 失败态伪装为暂停，错误信息 4.2s 蒸发（App.vue:1671, 682-684, 2145-2153）
- [P1] 设备行/目录行/下拉项纯 div，键盘与读屏不可达（App.vue:1906-1912, 2011, 2043, 2067）
- [P2] 双端漂移（百分比/ETA/上限/空值/弹窗信息）
- [P2] 全局 user-select:none 阻止复制连接信息（style.css:33-36）
- [P2] IpBoxes 粘贴 192.168.1.5 → 192.168.15（IpBoxes.vue:89-96）
- [P3] 画质分段高=红色语义颠倒（App.vue:2248-2252）；服务名漂移

## Detector (B)
monotonous-spacing ×2：desktop/src/App.vue (~12px 11/15=73%)、mobile/src/App.vue (~12px 11/16=69%)，均判 stands。reduced-motion 存在（CSS+JS，但 GSAP smoke/card 动画未纳入）；prefers-reduced-transparency 全仓库 0 匹配。浏览器可视化：子代理无浏览器后端，主会话截图仅 5KB 空壳（web 预览无 Tauri IPC 非代表性），以 CLI 检测器为准。

## Personas
- Alex：手动连接输入离开页面即被清空（App.vue:190-196）；ip:port 不可复制；IpBoxes 粘贴损坏
- Jordan：首屏无操作按钮；增量/镜像零解释；「端口（默认 53317）」术语直露；疑似离线无解释
- Sam：focus-visible 样式存在但对 div 控件永不触发；toast 无 aria-live；无 progressbar 角色；触控目标 22-30px < 44px；reduced-transparency 无降级

## Run Notes
slug desktop-src-app-vue；无 ignore 列表；A/B 隔离并行；检测器 exit=2（2 findings）；浏览器可视化失败（子代理无浏览器；主会话 web 渲染空壳）——回退信号：CLI 检测器 + 源码级评审；live-server 未启动；vite dev 已停止（端口 5199 已清理）。

## 用户决定
重排首屏层级（结构级）；跳过 4 张截图解析（视觉接口限流）；修复范围 = 全部批次 1-5。
