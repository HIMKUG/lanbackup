# 设计智慧登记表

> 用途：V4 重构的**防遗忘清单**。
> 来源：通读 shared-core（TS）、desktop/src-tauri（Rust）、mobile（Java + TS）三端全部注释后的挖掘结果。
> 用法：每完成一个 V4 阶段，回来把对应条目的「状态」从 ⬜ 改为 ✅ 或 ⚠️（有意识替换/废弃，需写明理由）。
>
> **原则：没有一条可以在不填写「V4 落地位置」的情况下被删除。**

状态图例：⬜ 待落地 · ✅ 已落地 · ⚠️ 有意识变更（必须写理由） · ➖ 不适用

---

## 零、P0 —— 丢了就会重蹈覆辙

这些条目对应的都是**曾经真实发生过、且极难复现**的故障。

### 0.1 Windows / 杀软环境（最不可复现，最容易丢失）

| # | 经验 | 原始位置 | V4 落地位置 | 状态 |
|---|---|---|---|---|
| W1 | **绝不写盘符根目录** —— 根目录高频写入是杀软 HIPS 的典型触发特征，曾导致整个进程被 360 挂起、窗口瞬间"无响应"。诊断文件一律写 `%TEMP%` | `lib.rs:49-50,275`; `main.rs:5` | core 日志与探针路径规范 | ⬜ |
| W2 | **`reg.exe` 子进程可能被杀软 hook 到无限期不退出**，必须 2s 超时 + `kill()` 强杀 + `"unknown-machine"` 兜底（因为 `Database::open` 在主线程调用） | `identity.rs:12-13,42-60` | core 设备标识获取 | ⬜ |
| W3 | **OTLP/gRPC（tonic）连接会持有 Windows 加载器锁**，挂起即连锁锁死主线程。症状：主线程永久阻塞、窗口无响应，**但进程其余部分与 WebView2 渲染正常**。复用条件：专用线程 + connect timeout + 地址可配置 | `lib.rs:123-127` | 遥测层（若保留） | ⬜ |
| W4 | **`reg.exe` 必须 `CREATE_NO_WINDOW(0x08000000)`**，否则配对/启动时闪黑框 | `identity.rs:22-23` | — | ⬜ |
| W5 | **Windows UDP socket 会偶发性失效**，必须检测 `send_to` 失败并重建 socket，不能当网络问题处理 | `bcpd.rs:296-299` | core presence/beacon | ⬜ |
| W6 | **Defender 实时扫描下每次 syscall 都不便宜** → 连接码必须进程内缓存 | `identity.rs:145-148` | core identity | ⬜ |
| W7 | 路径穿越必须按 `/` 和 `\` **双切分**：Windows 下 `a\..\..\evil` 作为单组件可绕过纯 `/` 切分 | `util.rs:58` | core path 安全 | ⬜ |
| W8 | 必须过滤含 `:` 的组件 —— 盘符 `C:` 与 NTFS 备用数据流，`Path::join` 遇盘符会**整体替换前缀** | `util.rs:59` | core path 安全 | ⬜ |
| W9 | **Windows 大小写不敏感** → 必须做大小写冲突检测，否则 `Photo.jpg` 与 `photo.JPG` 互相覆盖 | `util.rs:108-110` | core 冲突处理 | ⬜ |
| W10 | 导出日志**固定英文前缀**，避免设备名含中文造成解码问题 | `logger.rs:458` | core 日志 | ⬜ |

### 0.2 死锁 / 挂起 / 卡死

| # | 经验 | 原始位置 | V4 落地位置 | 状态 |
|---|---|---|---|---|
| D1 | **绝不在调用方线程直接 `app.emit()`** —— emit 需向主线程派发 WebView2 eval，多工作线程并发派发会形成跨线程消息死锁，症状为整进程瞬间冻结而 WebView2 子进程照常渲染动画。解法：mpsc + 单一派发线程 + 批量合并 | `logger.rs:478-500,529-543` | core → UI 事件桥 | ⬜ |
| D2 | **绝不持锁做 PBKDF2** —— 600k 轮数百 ms 会让接收路径 `try_read` 全部失败（活跃传输取不到 pairing_secret 解密失败），`try_write().unwrap()` 并发下还会 panic。解法：短临界区 clone + 锁外加密 + 失败降级为"本轮不落密钥" | `store.rs:226-249` | core 密钥持久化 | ⬜ |
| D3 | **`TcpStream::connect` 必须设超时** —— 默认对不可达 IP 触发 SYN 重试，可挂起 10~20 秒**且无任何日志** | `transfer/v3.rs:99-100` | core 网络层 | ⬜ |
| D4 | **配对端口绝不做 port+1 回退** —— 双端全部硬编码 `(接收端口+1)`，静默换端口会让本机"启动成功"但对端全部不可达，**比绑定失败更难排查**。端口占用时重试同一端口（120ms × 5） | `mod.rs:308-311` | core 服务启动 | ⬜ |
| D5 | **同步 Tauri 命令在 IPC 主线程执行**，网络/DB 阻塞会占住主线程 → 窗口事件循环卡死。全部改 `run_blocking`；配 UI 主线程心跳看门狗（500ms 投递 / 1500ms 超时告警） | `lib.rs:299-308`; `mod.rs:485-543` | core 命令层 | ⬜ |
| D6 | **接收超时只 finalize 统计、绝不 break 出循环** —— break 会造成"端口通但事件无人消费"的失聪态，而 watchdog 只探 TCP 连通性，**永远不会触发自愈**。空闲等待是接收端的正常稳态 | `receive.rs:112-116` | core 接收循环 | ⬜ |
| D7 | **认证前必须限制分配长度** —— 流式密文的 `clen` 取自密文流且在 GCM 认证之前分配，不设上限则任意对端可让本端尝试分配 ~4GiB，**无需知道密钥** | `crypto.rs:413-419` | core 加解密 | ⬜ |
| D8 | **固定长度头必须循环读满** —— 单次 `read` 不保证填满缓冲（TcpStream 分段 / BufReader 边界），否则合法密文被**间歇性**误杀 | `crypto.rs:389-391` | core 流读取 | ⬜ |
| D9 | **跨 await 不持锁**；guard 在表达式结束即释放；`drop()` 释放锁后再 spawn | `transfer/schedule.rs`（peer_chunk 取 Arc 即释锁，许可 RAII 归还） | core 并发规范 | ✅ |
| D10 | **`tokio::sync::RwLock` 而非 `std::sync::Mutex`**（在 tokio 上下文访问的状态），否则阻塞调度器 | `mod.rs:237-239` | core 状态容器 | ⬜ |
| D11 | **release 配置 `panic=abort`** → 越界 panic 直接杀死进程。日志解析等字符串操作全程用 `strip_prefix`/`find`，绝不做裸切片 | `logger.rs:562-563` | core 编码规范 | ⬜ |
| D12 | **setup 闭包必须立即返回**，所有耗时/阻塞初始化异步化，否则 OS 将窗口标记为"未响应" | `lib.rs:134-137` | 桌面端启动 | ⬜ |

### 0.3 状态机 / 业务逻辑（踩坑密度最高）

| # | 经验 | 原始位置 | V4 落地位置 | 状态 |
|---|---|---|---|---|
| S1 | **解配对必须三处防复活**：① REVOKED/REVOKE_PENDING 对 UI 列表不可见（否则解除后 10s 内被轮询拉回，**2026-08-23 22:3x 实测**；REVOKE_PENDING 同样会被拉回，**2026-08-26 补充**）② `confirm_paired` 回填不得把终态踩回 ACTIVE ③ persist 必须用**全量快照**而非 UI 过滤列表 | `store.rs:53-59,123-125,221-223` | 配对生命周期状态机 | ⬜ |
| S2 | **连续 3 次 unknown 才吊销** —— 对端一次 unknown 可能是瞬时错乱/时钟偏差，直接吊销会把仍有效的 pairing_secret 清掉（**数据面即刻失效**）。对端明确回「revoked + 令牌」则即时吊销 | `store.rs:9-14,632-660` | 配对对账 | ⬜ |
| S3 | **会话闲置清理必须巡检式而非固定延时** —— 每 60s 检查"距最后分片到达是否超过 300s"，活跃长传输在 FileUpload 处**持续续期**，不会被误杀 | `receive.rs:161-164,337` | 会话状态机 | ⬜ |
| S4 | **解密失败也必须计入"会话是否到齐"**，以便尽快触发 finalize，而不是永远等待缺失文件 | `receive.rs:484-498,569` | 会话 finalize | ⬜ |
| S5 | **拒绝/超时未批准的会话必须同步清掉 ECDH 会话密钥**，否则恶意方反复发起请求再放弃 → map 无界增长 | `receive.rs:275-276` | 会话清理 | ⬜ |
| S6 | **jti 清理键必须与插入键一致** —— 此前用 payload 段原文当 key，`remove` 永远删不到真实 jti，导致 `used_jtis` 无限增长 | `pairing/v3.rs:241-242` | 握手防重放 | ⬜ |
| S7 | **验签失败 / 缺关键字段不占用 jti**，防攻击者耗尽 jti 空间 | `pairing/v3.rs:265,275` | 握手防重放 | ⬜ |
| S8 | **`sync_paired` 不得清空重建信任锚字段**（peerPublicKey/status 只能由配对流程写入），否则门禁 `check_trusted` 误拒已配对设备 | `store.rs:154-159` | 前端↔core 同步契约 | ⬜ |
| S9 | **`mergeRecords` 逐字段合并，新记录缺字段时保留旧值** —— 后台巡检/UDP 探测产生的记录字段不全，覆盖写会**清空 previousKeys**，连接码刷新后历史数据永久无法解密 | `pairing.ts:125-138` | 配对记录合并 | ⬜ |
| S10 | **`lastManifest` 必须持久化** —— 曾存在 Vue 组件状态里，App 重启后丢失 → **每次重启都退化成全量备份** | `pairing.ts:65-66` | 增量快照存储 | ⬜ |
| S11 | **上一版本密钥滚动解密**（`previousKeys` 保留 7 天 / 最多 5 个，按 version 降序尝试）—— 连接码刷新后，已在传输中的文件仍能用旧密钥解密 | `pairing.ts:15-22,191-246` | 密钥轮换 | ⬜ |
| S12 | **UDP 广播不得覆盖 WebSocket 连接状态** —— 两个状态源写同一对象，用 `?? existing ?? false` 三级 fallback | `discovery.ts:85-93` | 设备状态合并 | ⬜ |
| S13 | **严格到齐才合并分片**（缺失或残留多于 total 都等待/失败），防旧版本残留拼接损坏 | `receive.rs:763-764` | 分片合并 | ⬜ |
| S14 | **空 sessionId 必须显式告警**（后续 upload 全部失败且根因丢失）；**files 字段解析失败不能静默变空 map**（会伪装成"接受了 0 个"照常推进） | `scheduler.rs:769-772,779-780` | 上传准备 | ⬜ |

---

## 一、P1 —— 算法与协议的非显而易见设计

| # | 经验 | 原始位置 | V4 落地位置 | 状态 |
|---|---|---|---|---|
| A1 | **macOS NFD vs Windows/Linux NFC 归一化**：同一 `café.txt` 字节不同但显示相同。不归一化 → macOS 备份的文件在 Windows 端每次判为"新增+对端缺失"，**无限重传**。仅用于清单比对，**存储/传输保留原样** | `sync.ts:72-79`; `scan.ts:197-208` | core sync | ⬜ |
| A2 | **NFC 归一化每文件只做一次**，两路对比复用（大清单省一半以上计算） | `sync.ts:81-83` | core sync | ⬜ |
| A3 | **archive（默认）只增不删**：B 端已删除的文件不自动补回（删除视为有意，仅告警）；mirror 才补传并清理（**需用户显式开启**）。备份工具不能复活用户手动删掉的文件 | `sync.ts:9-11` | core sync 策略 | ⬜ |
| A4 | **archive 的"自愈补全"第三条规则**：只补**上次快照里存在过**的对端缺失文件（判据 `nfcPrev.has(p)`）—— 之前备份过、对端误删的重新推送；从未备份过的仍不补 | `sync.ts:140-147` | core sync 策略 | ⬜ |
| A5 | **`delete/` 前缀必须排除出 peerExtra 判定** —— moveToDelete 后文件仍留在 delete 文件夹，若仍算"对端多余"会导致**镜像模式无限弹确认框**（问题5 死循环） | `sync.ts:131-137` | core sync 策略 | ⬜ |
| A6 | **"对端有这个文件但 size 不一致"归为「变更」而非「缺失」** —— 这是上次传输中断留下的半截文件，两类语义不同、处置策略也不同。只按"存在与否"判断则损坏文件永不修复 | `sync.ts:97-100` | core sync 策略 | ⬜ |
| A7 | **增量判据用 mtime + size，不用内容哈希** —— 手机端 CPU 弱，相册几万文件算哈希会把扫描从秒级拖到分钟级。已知限制：同 path 同 size 但内容损坏的文件检测不出来 | `sync.ts:5,101-102` | core sync | ⬜ |
| A8 | **接收端必须保留发送端 mtime（RFC3339）** —— 一旦被重置为写入时间，A 端三路对比会**永久误判为变更，每次全量重传**。这是整条增量链路的命脉 | `transfer.ts:187`; `receive.rs:535-536` | core 接收 | ⬜ |
| A9 | **tiny 文件 ustar tar 聚合**：<10KB 文件按批打包为单一 tar 流，一次 prepare-upload + 一次 upload。**万次握手 → 1 次连接**。batchSize 50-100 为工程平衡点 | `transfer.ts:626-650` | core 批量传输 | ⬜ |
| A10 | **局域网专用工程参数**：CHUNK 8MB（协议头开销 vs 单分片失败重传成本的最优平衡，针对 100MB/s+ / RTT 1-3ms）、并发 8、TINY 10KB、LARGE 100MB。**公网/跨城场景下全部不适用** | `transfer.ts:656-672`（V4 采用 4MB piece + 16MB basic，属既定设计取舍，待实测调参） | core 传输参数 | ⚠️ |
| A11 | **GET /diff 四态状态码**：206=存在且 ETag 匹配 / 412=存在但 SHA-256 不匹配（NACK）/ 416=Range 越界（带 `Content-Range: bytes */{total}`）/ 200=ETag 不匹配文件已变需全量重传。**把"存在性"和"正确性"用两个状态码分开表达** | `transfer.ts:438-445` | V4 路由契约 | ⬜ |
| A12 | **ETag 必须带双引号且不加 `W/` 前缀** —— `W/` 是弱校验器（内容等价但字节可不同），这里要字节级强校验，加 `W/` 会让 `If-Range` 语义变化导致误判 | `scheduler.rs:209-228` | V4 路由契约 | ⬜ |
| A13 | **全局信号量 12（=3 接收端 × 4 块）+ 重试独立配额 4** —— 全局而非每 peer 独立（防多接收端总并发爆炸）；**重试必须单独配额**，否则失败重试吃光许可，正常分片全部饿死 | `transfer/schedule.rs` | core 并发控制 | ✅ |
| A14 | **全抖动退避（AWS 标准）**：`random(0, min(64000, 1000 * 2^n))`，n 上限 5。防惊群 | `transfer/schedule.rs::full_jitter_backoff_ms` | core 重试 | ✅ |
| A15 | **422 刻意视为可重试** —— 违背 HTTP 惯例，因为本协议里 422 = 块 SHA-256 校验失败，重传大概率成功 | `scheduler.rs:204-207` | core 重试判定 | ⬜ |
| A16 | **Merkle 奇数节点复制自身而非补零**（BEP-0052 规定）。填错规则会与标准实现根哈希不一致 | `crypto/merkle.rs`（含 proof/verify 补完） | core merkle | ✅ |
| A17 | **Merkle 三层结构**：Leaf 16KiB / Piece 4MB / Root。容易在实现时混为两层 | `crypto/merkle.rs`（piece 级叶子，16KiB 子层校验待补） | core merkle | ⚠️ |
| A18 | **冲突处理：绝不覆盖、绝不弹窗**，由接收端按 `原名_MMDDhhmmss.扩展名` 重命名。局域网备份常在无人值守时跑，弹窗会挂死流程。宁可多一份副本，不可静默丢数据 | `conflict.ts:1-7` | core 冲突处理 | ⬜ |
| A19 | **冲突的幂等跳过**：同名且 size/mtime 完全一致 → 视为已存在不冲突（否则上次中断重试会产生 `_0815234500` 副本） | `conflict.ts:35-42` | core 冲突处理 | ⬜ |
| A20 | **心跳失败不阻断传输**（catch 只 log 不 rethrow）—— 心跳是尽力而为，心跳失败 ≠ 传输失败，否则弱网抖动会误杀大传输 | `transfer.ts:533-554` | core 心跳 | ⬜ |
| A21 | **能力协商用显式响应头而非版本号猜测**，且要求**完全匹配**才启用 —— 宁可降级也不让半兼容的实现跑出静默数据损坏 | `scheduler.ts:539-560` | V4 能力位图 | ⬜ |
| A22 | **header key 必须 lowercase 后取** —— Node 全小写 / 浏览器保留原样 | `scheduler.ts:562-567` | core HTTP | ⬜ |
| A23 | **形态与角色完全解耦**：任意设备可担任任意角色，支持 A→B / B→A / A→A / B→B。**不能假设"电脑=发送端、手机=接收端"** | `config.ts:1-9` | V4 架构前提 | ⬜ |
| A24 | **Windows 路径归一化**：统一 `/` 分隔，去掉开头 `./` 和结尾 `/`（平台层可能返回 `.\sub\file.txt`） | `manifest.ts:43-51` | core manifest | ⬜ |
| A25 | **只增不删**：旧清单有、新清单没有的文件不参与传输（与 archive 策略呼应） | `manifest.ts:53-59` | core manifest | ⬜ |
| A26 | **扫描决策只在发送端做，接收端只负责收**（接收端往往是手机，算力弱） | `scan.ts:1-8` | V4 架构前提 | ⬜ |
| A27 | **chokidar 启动时已存在的文件不触发 `add`** → 必须用一次全量镜像扫描补偿，否则首屏文件**永久漏备份** | `scan.ts:94-100` | core 文件监听 | ⬜ |
| A28 | **文件分类的平台检测手段**：稀疏文件用 `SEEK_HOLE`、符号链接用 `lstat`（不能用 `stat`，会被解析成目标）、硬链接用 inode 分组 | `scan.ts:147-158` | core 扫描 | ⬜ |
| A29 | **分类判定顺序有讲究**：`empty` 必须在 `sparse` 之前（否则 0 字节空洞文件误判为 sparse）；sparse 需 `size >= 100MB` 才值得单独处理 | `scan.ts:185-194` | core 扫描 | ⬜ |

---

## 二、P1 —— 移动端 / Android 硬 won 经验

| # | 经验 | 原始位置 | V4 落地位置 | 状态 |
|---|---|---|---|---|
| M1 | **所有网络调用必须走原生，绝不走 WebView fetch/XHR** —— 目标端无 CORS 头，会被浏览器拦截，表现为"手机端从没同步成功"。这是整个手机端架构的根因 | `LocalReceiverPlugin.java:2117-2122`; `receiver.ts:172` | core（Rust 天然在原生侧） | ✅ 架构上已满足 |
| M2 | **连接码绝不上线**：不进广播、不进 register/info 响应、不进任何响应体。明文 HTTP 下会暴露加密密钥给局域网嗅探者 | `L1163,L3231`; `backup.ts:187-188`; `protocol/README.md:27,59,98` | V4 握手 | ⬜ |
| M3 | **`fingerprint` 一律用公开 deviceId，不用连接码** | `L1171,L3236` | V4 发现 | ⬜ |
| M4 | **连接码默认派生算法必须与 `identity.ts` 逐位一致**：FNV-1a 32（`0x811c9dc5` / `0x01000193`，int 溢出即 32 位乘法 ≡ `Math.imul`）+ xorshift(13,17,5) + 字母表 31 字符，输入 `deviceId + "\|localsend-backup\|v1"`，取 8 位 | `L534-552`; `identity.ts:32-42` | core identity | ⬜ |
| M5 | **接收服务未启动时也要有有效本机码**（兜底链：prefs → 服务传入 → 派生默认码），否则电脑端输入本机码验证会永远失败 | `L515-532` | core identity | ⬜ |
| M6 | **IO 全程流式、内存 O(1)**：网络流 → 缓存临时文件 → 流式解密 → SAF，缓冲 64/128KB，**禁止整文件读入**（曾修复 800MB 文件 OOM） | `L2370-2374`; `L2944-2946` | core 传输 | ⬜ |
| M7 | **发送端中途断开必须判定失败并 throw**，否则**半截数据被当作完整文件保存** | `L2420-2421` | core 接收 | ⬜ |
| M8 | **分片落盘路径只能到 `{pct}/{index}`，total 段绝不能进路径**（否则目录结构错乱导致合并失败）；且**分片路径不参与冲突重命名** | `L1989-1998`; `L2826` | core 分片 | ⬜ |
| M9 | **percent-encoding 必须用 Rust 子集**（保留 `A-Za-z0-9-_.~`，编码 `!~*'()`）—— TS `encodeURIComponent` 额外保留 `!~*'()`，差异会导致查询路径与分片目录名不匹配 | `backup.ts:61-77` | core 编码 | ⬜ |
| M10 | **内部文件排除规则**：`__chunked__`、`.chunks`、`__batch__*`、`.dec_tmp`。实测 **111 个分片残留混进 293 条清单**，污染三路对比 | `filesystem.ts:152-163`; `L1067` | core 扫描 | ⬜ |
| M11 | **进度事件限频 500ms**（接收与发送都是），否则 WebView 桥接被打爆 → UI 卡顿/ANR | `L2316,L2379-2412` | core 事件 | ⬜ |
| M12 | **每连接独立线程，accept 循环只 accept**；配对弹窗（最长阻塞 45s）绝不能占 accept 线程 | `L345-350,L841-849` | core 服务器 | ⬜ |
| M13 | **启动配对服务用原子 CAS，不用 check-then-act**（P1 修复：消除检查-执行竞态） | `L807` | core 服务启动 | ⬜ |
| M14 | **verify 的 `probe` 标志必须透传** —— 漏传会导致手机端轮询被对方误认为连接问候 → **连接状态不对称（电脑已连接、手机在线）** | `L479-481` | V4 probe | ⬜ |
| M15 | **本端作为验证方配对成功后，必须回写原生信任表**，否则对端问候本机时返回"未信任"，被误判为解除配对 | `L598-603` | V4 配对 | ⬜ |
| M16 | **配对信任表持久化用"清空后重建"而非 merge** —— 只增不删会导致已解除配对的残留继续被信任，造成**状态横跳** | `L628-631` | core 配对存储 | ⬜ |
| M17 | **孤立会话 5 分钟自动清理**（prepare-upload 后客户端断开未上传） | `L1872-1873` | core 会话清理 | ⬜ |
| M18 | **HTTP 输入三道硬上限**：请求行 16384B、body 10MB、tar 单成员 100MB | `L3450-3465,L3002-3006` | core HTTP | ⬜ |
| M19 | **SAF tree URI 必须 `takePersistableUriPermission`**，否则重启后目录不可用 | `L1494-1503` | Android 平台层 | ⬜ |
| M20 | **SAF 无跨目录 rename** → 移动用"复制 + 删除"实现假删除 | `L1642-1693` | Android 平台层 | ⬜ |
| M21 | **用 `DocumentFile` 遍历，不手工拼 documentId** —— 规避部分 ROM（国产）上 URI 解析失败 | `L1508-1510,L1617-1631` | Android 平台层 | ⬜ |
| M22 | **组播收发都要持 `WifiManager.MulticastLock`（`setReferenceCounted(false)`）** —— 部分 ROM 会过滤 outgoing 组播包。**Java 的广播路径就漏了这把锁** | `L1272-1278`; 对比 `L1092-1138` | Android beacon | ⬜ |
| M23 | **前台服务 + 通知渠道 + `FOREGROUND_SERVICE` / `POST_NOTIFICATIONS` 权限** —— 当前 manifest 完全缺失，Java 无任何 Service。手机切后台后 ServerSocket 随时被系统回收 | manifest 全缺 | Android 平台层（**新增**） | ⬜ |
| M24 | **`WAKE_LOCK` + 电池优化豁免** —— Doze 下 socket 被断，长传中断 | 缺失 | Android 平台层（**新增**） | ⬜ |
| M25 | **补齐 `ANDROID_PERMISSIONS.md` 要求的存储权限**（`READ_EXTERNAL_STORAGE maxSdk=32` + `READ_MEDIA_*`）—— 文档要求"手动编辑 manifest"，**这一步从未执行** | `ANDROID_PERMISSIONS.md:44-54` vs manifest | Android 平台层（**新增**） | ⬜ |
| M26 | **切后台降频省电**：状态侦测 500ms（前台）→ 5000ms（后台），回前台恢复 | `App.vue:1655-1663` | core presence | ⬜ |
| M27 | **已配对设备再次被发现 → 只记忆新 IP，不置在线** —— 在线状态必须由 verify 探测确认，扫描到 ≠ 建立通信（否则隐藏设备会被误标在线） | `App.vue:1494-1495` | 在线性状态机 | ⬜ |
| M28 | **探针不完全可达设备降频**（每 10 轮 ≈5s 一次），成功即恢复 500ms | `App.vue:1629-1630` | core presence | ⬜ |
| M29 | **误删防抖已移除**：配对记录只在显式解除/收到对端解除时删除，**绝不因轮询失败自动删除** | `App.vue:1627` | 配对对账 | ⬜ |
| M30 | **冷启动日志回放**：WebView 就绪前原生侧产生的日志前端收不到，需环形缓冲 + 注册监听后回放 | `receiver.ts:753-779`; `App.vue:1429` | core 日志桥 | ⬜ |
| M31 | **解除配对通知重试 3 次** —— 对方短暂不可达也能收到，强制其同步解除 | `App.vue:1596-1607` | 配对解绑 | ⬜ |
| M32 | **取消收件两步走**：① 本地停止（无条件先行）② 通知对端；通知失败不影响本地停止，四种成败组合各有独立文案 | `App.vue:2150-2192` | 中止流程 | ⬜ |
| M33 | **已知缺失的 8 个 TS 契约方法**：`v3Probe`、`v3PairClient`、`syncAllPeers`、`isPeerPaired`、`setDefensiveHidden`/`getDefensiveHidden`、`dumpNativeLogs`、事件 `java-log`、`pair-presence` —— Java 从未实现 | `receiver.ts` vs Java 全 0 命中 | core（必须补齐） | ⬜ |
| M34 | **扫描自过滤失效（现存 bug）**：广播的 fingerprint 是 UUID，但自过滤拿它跟 8 位连接码比，永不相等 → **手机会把自己扫进设备列表** | `L1318,L1400,L1443` vs `App.vue:1482` | core 发现（**修复**） | ⬜ |
| M35 | **分块 Base64 必须按 3 的倍数分块** —— 8192 不是 3 的倍数，每块独立编码会各自追加 `=` 填充，拼接后是非法 Base64（当前为潜伏地雷） | `L1573-1583` | core 编码（**避免重犯**） | ⬜ |
| M36 | **上传长度必须精确上报** —— 接收端按声明的 size **硬校验 written == size**；空文件也返回 12 字节头，是真实开销非误判 | `backup.ts:200-209` | core 上传 | ⬜ |
| M37 | **并发切片步长必须与索引步长一致**（`i += 8` 对 `slice(i, i+8)`）—— 曾误写 `i+3` 导致 85 个只传 33 个 | `backup.ts:295-297` | core 批量 | ⬜ |
| M38 | **用已成功去重集合统计进度**，避免重试路径重复计数（曾出现 191/183） | `backup.ts:274` | core 进度 | ⬜ |
| M39 | **有文件最终失败则整体中止**，绝不"报成功但数据不全" | `backup.ts:423-433` | 任务终态 | ⬜ |
| M40 | **设备标识双份地雷**：TS 从 Capacitor Filesystem UUID 生成，Java 从 SharedPreferences UUID 生成，**两套独立 UUID**。必须用 Java 侧口径 | `backup.ts:182-185`; `device.ts:48-54` | core identity（**统一**） | ⬜ |

---

## 三、P2 —— 性能与工程实践

| # | 经验 | 原始位置 | V4 落地位置 | 状态 |
|---|---|---|---|---|
| P1 | **三层状态分离**：热（内存，进程死即失）/ 温（可恢复的会话元数据）/ 冷（SQLite 历史）。**把实时进度写 SQLite 会拖垮传输** | `session-store.ts:8-12` | core 状态分层 | ⬜ |
| P2 | **状态无变化不写盘** —— 500ms 巡检热路径，三个状态更新方法全部加短路 | `pairing.ts:141-189` | core 持久化 | ⬜ |
| P3 | **日志双上限**：条数 2000 + 字节 512KB，双约束缺一不可（只限条数会被大堆栈撑爆，只限字节会让数组操作变慢） | `logger.ts:192-204` | core 日志 | ⬜ |
| P4 | **ERROR 日志在 debug 关闭时仍记录并持久化**（但不输出 console）—— 用户关掉 debug（刷屏/性能），崩溃信息仍要能事后导出 | `logger.ts:120-122,159,167-169` | core 日志 | ⬜ |
| P5 | **只存最近 300 条到 localStorage** —— Android/iOS 会随时杀后台进程，内存日志全丢 | `logger.ts:385-393` | core 日志 | ⬜ |
| P6 | **日志恢复用 `ts\|module\|message` 组合 key 去重** —— 否则恢复的日志被二次计数，ERROR 徽标显示错误 | `logger.ts:396-419` | core 日志 | ⬜ |
| P7 | **实时文件日志 + 同步 flush** —— 程序完全无响应/崩溃时，日志仍已在磁盘，用户可直接复制文件，无需经 UI 导出 | `logger.rs:1-12,259-260` | core 日志 | ⬜ |
| P8 | **日志折叠但 WARN/ERROR 永不折叠** —— 正常态压缩 ~99%，故障态 100% 保真 | `logger.rs:47-52,193` | core 日志 | ⬜ |
| P9 | **traceparent 只注入局域网段**（正则限定 192.168./10./172.16-31.）—— 避免向外部域名泄漏 trace 信息 + 避免 CORS 预检失败 | `telemetry.ts:120-129` | core 遥测 | ⬜ |
| P10 | 遥测关闭时返回 **Proxy 实现的 noop tracer**，调用点零改动，未来新增任何方法都不会崩 | `telemetry.ts:135-174` | core 遥测 | ⬜ |
| P11 | **SQLite 每操作独立连接 + WAL** 优于 `Mutex<Connection>`（后者串行化读写；WAL 下读不阻塞写；open ~100µs 可忽略） | `db.rs:49-51` | core 存储 | ⬜ |
| P12 | **UPSERT 冲突分支必须用 `excluded.<列名>`** 显式限定，否则误伤同表其他列（ECDH 静态密钥 vs ECDSA 签名密钥） | `db.rs:466-469,482-486` | core 存储 | ⬜ |
| P13 | **不播种 zeroblob 占位行** —— 会让 load 误判为有效密钥（曾导致静态密钥永不写入） | `db.rs:123-125,726` | core 存储 | ⬜ |
| P14 | **cargo test 并行会共享同一 SQLite 文件**（仅用 pid 不够）→ 追加 AtomicU64 自增序号 | `db.rs:626-634` | core 测试 | ⬜ |
| P15 | **流式加密：密文长度可确定性预计算** → 在 upload 流内逐块密封，省掉"全文读 → 写密文临时文件 → 上传再读"的三遍磁盘 IO 与双倍磁盘占用 | `send.rs:284-286`; `crypto.rs:317-323` | core 加解密 | ⬜ |
| P16 | **密文缓冲跨块复用**（原先每块一次 8MB 级堆分配）；**Merkle 叶块缓冲循环外复用**（大文件节省数十万次分配） | `crypto.rs:386`; `scheduler.rs:249-250` | core 内存 | ⬜ |
| P17 | **Merkle 构建与整文件 SHA-256 同一次 I/O 顺带算**，避免二次全量读 | `scheduler.rs:251-252,585-594` | core merkle | ⬜ |
| P18 | **分片合并用 1MB 手写缓冲** —— `std::io::copy` 默认 8KB，GB 级合并 syscall 数量爆炸；且收集时**一次 stat 缓存片长**（原先每片两次元数据查询） | `receive.rs:753,814` | core 分片 | ⬜ |
| P19 | **上传并发 `buffer_unordered(8)` 滚动** —— 原先按组 `join_all` 有 convoy 问题，单个慢文件拖住整组 | `send.rs:544` | core 并发 | ⬜ |
| P20 | **子网扫描 64 有界工作池** —— 254 个 OS 线程的栈内存与调度开销不必要（探测是 1.5s 超时的纯阻塞 IO） | `discovery.rs:324-325` | core 发现 | ⬜ |
| P21 | **子网扫描失败用 `continue` 而非 `return`** —— 曾误用 return，64 线程池随失败迅速枯竭 | `discovery.rs:346` | core 发现 | ⬜ |
| P22 | **子网扫描启动顺序**：先清空设备缓存、再 spawn 线程。反序会抹掉扫描头几秒的结果 | `discovery.rs:146-147` | core 发现 | ⬜ |
| P23 | **MachineGuid `OnceLock` 缓存** —— `reg query` 是一次进程创建（10~50ms），一次子网扫描最多 254 个并发 reg.exe | `identity.rs:96-99` | core identity | ⬜ |
| P24 | **连接码进程内缓存** —— 接收端每个文件事件都要取码，此前每文件一次磁盘读 | `identity.rs:145-148` | core identity | ⬜ |
| P25 | **CSPRNG + 拒绝采样消除模偏差**（248 = 31×8，丢弃 ≥248 的字节）；同一毫秒内多次调用不再产出相同码 | `identity.rs:198-209` | core identity | ⬜ |
| P26 | **sessionId / folderId 必须用 CSPRNG** —— 曾用 `Date.now() + Math.random()`，sessionId 可预测意味着同网段攻击者能劫持会话；folderId 会在同一毫秒碰撞导致配置互相覆盖 | `scheduler.ts:391-397`; `config.ts:57-63` | core ID 生成 | ⬜ |
| P27 | **`maxRetries` 必须夹紧**（`Math.max(0, Math.min(n, 100))`）—— 传 `Infinity` 会让循环永不退出 | `transfer.ts:588-589` | core 重试 | ⬜ |
| P28 | **大数组分帧处理**（每帧 100 条约 1-2ms）—— 清单构建会阻塞主线程，**且顺序与结果必须与同步版完全一致** | `chunks.ts:1-10` | core 批处理 | ⬜ |
| P29 | **knownMissing 过滤必须用 Set** —— 用 `Array.includes` 在首次镜像几万文件时是 O(n²)，直接卡死 UI | `sync.ts:116-119` | core sync | ⬜ |
| P30 | **阻塞 I/O 一律 `spawn_blocking`**：`create_dir_all` / `fs::read` / `set_file_mtime` / 同步 HTTP / 阻塞 connect | 多处 | core 并发规范 | ⬜ |
| P31 | **非阻塞日志发送**：`log()` 只 `tx.send()`，绝不阻塞、绝不派发 | `logger.rs:484-485` | core 日志 | ⬜ |
| P32 | **配对连接有界并发 32 + RAII guard**，防 Slowloris（无超时 + 无线程上限 = 局域网任意主机可用半个 HTTP 头挂住线程） | `mod.rs:357-364` | core 服务器 | ⬜ |
| P33 | **读/写超时 30s** 防 Slowloris | `mod.rs:357-360` | core 服务器 | ⬜ |
| P34 | **batch tar 文件名必须加序号** —— 同一毫秒内多个 batch 会冲突互相覆盖（**致命**） | `send.rs:261` | core 批量 | ⬜ |
| P35 | **不可读目录条目跳过而非中止整个扫描**；**符号链接不跟随**（rsync -a 隐含 -l）；**特殊文件跳过**（rsync -D 需 root） | `util.rs:339-345,360-363,375-377` | core 扫描 | ⬜ |
| P36 | **崩溃残留 `.tmp_*` 与 `.dec_tmp` 必须清理** —— 后者扫描器刻意排除该扩展名，**用户不可见的隐形泄漏** | `receive.rs:94-98,715-717,854` | core 清理 | ⬜ |
| P37 | **解密候选 key 多版本依次尝试，顺序不影响正确性**（GCM tag + LSBK 魔数双重把关），防止后人"优化"成只试第一个 | `receive.rs:452-456` | core 加解密 | ⬜ |
| P38 | **手机端无 mtime 时 identical 判定退化为仅按大小** | `util.rs:161-162` | core 冲突 | ⬜ |

---

## 四、V4 文档中需要修正的事实错误

挖掘过程中发现的、与我此前 V4 文档**直接矛盾**的事实：

| # | 我此前的错误判断 | 事实 | 处置 |
|---|---|---|---|
| E1 | 「保留 `AndroidSessionStore` / `SessionDatabase`（SAF 写入仍需 Java）」 | 这两个类**零调用方**，与 SAF 写入毫无关系，是孤儿代码 | 改为：删除，仅保留其「热/温/冷 + 脏标记批量刷盘」的**设计模式** |
| E2 | 隐含假设 Java 是"一份能跑的完整实现，需用 Rust 重写" | Java 是**停在 v2 阶段的残骸**；`receiver.ts` 声明的 8 个方法在 Java 中不存在；`protocol/README.md:5` 明确 v3 硬升级不兼容 v2 端点 | 改为：这次不是平移重写，是**补齐一个从未真正实现的契约**。Rust 实现须对齐 `receiver.ts` 而非 Java |
| E3 | 认为 golden file 校验在生效 | `golden/manifest.json` 的 `schemaHash` 是 `PENDING_FIRST_CAPTURE`，`capturedAt` 为 null —— **从未回填，校验事实上未生效** | 契约即代码（schemars）必须同时回填 schemaHash |
| E4 | 未发现协议目录自相矛盾 | README 说 3.0，golden 写 3.1；README 说"无 pair/initiate 端点"，manifest.json 的 endpoints 又列了它们 | V4 路由表定稿时一次性清理 |
| E5 | 未发现扫描自过滤失效 | 广播 fingerprint 是 UUID，自过滤却拿它跟 8 位连接码比，永不相等 → 手机把自己扫进设备列表 | 列入 M34 修复 |
| E6 | 未发现弱校验实现与注释不符 | `scheduler.ts` 注释写 xxHash64，但常量 `PRIME64_4 = 9650019240527522597` 与标准 xxHash64（`9650029242287828579`）不同，轮函数也非标准 —— **不是标准 xxHash64** | ✅ 已统一：V4 弃用含糊的 xxHash64，改用无歧义的 **Adler-32** 作为弱校验（`transfer/chunk.rs::weak_checksum`），根除「常量对不上 → 弱校验永不命中」风险；强校验仍由 SHA-256 担责 |
| E7 | 未发现分块大小四处不一致 | `transfer.ts:196` 4MB / `transfer.ts:659` 8MB / `scheduler.ts:601` 16MB / 我文档里「小文件 <16MB 跳过 diff」 | ✅ 常量源已统一：`PIECE_SIZE`(4MiB)/`BASIC_CHUNK_SIZE`(16MiB) 单一来源 + 编译期对齐断言（`transfer/chunk.rs`）。另：「小文件跳过 diff」与「tiny tar 聚合」的冲突见 A9，仍待定 |
| E8 | 未发现两个连接码规范化函数行为不同 | `identity.ts:80` 只去 `[\s\-_]`，`pairing.ts:259` 去所有 `[^A-Z0-9]`。`a.b` 在前者保留为 `A.B`（非法） | V4 统一为一个 |
| E9 | 未发现 `TINY_BATCH_SIZE = 20` 与注释「50-100 为工程平衡点」矛盾 | `transfer.ts:669` vs `transfer.ts:632,636` | V4 统一 |

---

## 五、使用方式

**每完成一个 V4 阶段，执行以下检查：**

1. 打开本文件，筛选该阶段涉及的模块
2. 逐条确认：已落地 → ✅；有意识变更 → ⚠️ 并写理由；未处理 → 保持 ⬜
3. **任何一条从 ⬜ 直接消失（既未标记 ✅ 也未标记 ⚠️）都是事故**

⚠️ 标记必须包含：原做法、新做法、为什么这样改是安全的。这三条缺一不可 —— 未来的人（包括你自己半年后）需要能判断这次变更是深思熟虑还是又一次遗忘。
