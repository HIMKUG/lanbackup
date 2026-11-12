# Windows 后端重构施工文档（1080 个原子施工项）

> 交付对象：**同一个 AI** 连续执行。禁止把本清单拆给多个互不知情的执行者；允许用工具并行读/测，但架构裁决、跨端契约、最终合并必须由同一执行者负责。
> 审查范围：Windows 桌面后端 `desktop/src-tauri` + 共享 Rust 核心 `core` + 协议 `protocol` + 必须联动的前端 `desktop/src`、`shared-core`、移动端契约 `mobile`。
> 审查方式：以当前代码为准，静态逐模块阅读 + 定向证据扫描；未把旧设计文档当作事实源。本文是施工蓝图，不是“已修复”声明。
> 基线：`72ca43c`；工作树已有用户并行改动 `desktop/src-tauri/src/transfer/{mod,receive,store}.rs`（G5 core 写穿尝试）。必须保留其“消除 drift”的意图，但按下文重建为单一权威，不得简单回滚或覆盖。

## 0. 执行契约（先读，违反即停工）

1. **先读完整本文，再建任务清单**。按 WB 编号顺序施工；同一根因的落点必须一起改，禁止只修一个调用点。
2. **批量读写**：每批先读目标文件及直接调用方，再一次性修改该批闭环；不要逐条截图式汇报。关键节点只报告批次结果与阻塞。
3. **改核心/配置前先备份**到 `backups/<批次>/`；不永久删除文件，废弃代码移入 `backups/quarantine/` 并记录来源。不得覆盖用户未提交改动；发现新脏改先读 diff 再合并。
4. **新依赖/新 feature/安全降级必须先过决策闸 D1-D5**；未获批准不得引入 PAKE、SQLCipher、DPAPI 绑定、OTel exporter 等新运行时依赖。
5. **前端/协议/移动端必须一起看**：任何 DTO、端口、事件、错误码、配对/传输语义变更，同批修改 `desktop/src/App.vue`、`shared-core`、`protocol/schemas`、`mobile` 对应调用；否则该批不算完成。
6. **验收以真实入口为准**：必须走 hyper `serve_request`/Tauri command/前端 invoke，不得只调用内部 `route()` 或纯函数就宣称端到端通过。
7. **命令加 timeout 护栏**；Rust 构建统一 `CARGO_TARGET_DIR=D:/code/tools/6a7f5d5699c44b33268ede69/cargo-target`。本机已见 gcc/clang，旧文档“无 C 工具链”不可直接采信，先探测再决定。
8. **不信任旧完成标记**：`AI-HANDOFF.md`、`NEXT-STEP-PLAN.md`、`protocol/README.md`、`core/src/lib.rs` 多处与当前代码矛盾；每批完成后用代码证据回填，不得沿用“已闭合”。
9. **安全底线**：连接码、私钥、pairing_secret、token 不得进日志/前端 localStorage/网络明文响应；认证不得只凭 deviceId 字符串；写盘不得未经路径闸；失败不得静默当成功。
10. **完成定义**：1080 项逐项标记 done/blocked/obsolete（obsolete 必须给代码证据）；P0 全清零；Windows CI 全绿；真实 Windows→Windows、Windows→Android、Android→Windows 三条链路通过；前端构建与后端测试同绿。

## 1. 基线证据

- Rust 后端文件 78 个，总行数 32184；Tauri 注册命令 48 个；V4 路由常量 24 个；测试属性约 core 484 + desktop 40 + integration 1；schema 目录 46 个 JSON（45 schema + golden）。
- 当前 Windows 接收主链：`desktop/src-tauri/src/transfer/receive.rs:101` 建 `core::server::SessionStore`，`core/src/server/mod.rs:1397 serve_request` 收 HTTP。
- 当前发送主链：`desktop/src-tauri/src/transfer/send.rs:28 send_files` 自行 register/prepare/chunk/diff，未完整驱动 `SessionDriver`。
- 遗留并行链：53318 手写 HTTP `desktop/src-tauri/src/pairing/auth.rs:18`；自定义 bcpd `desktop/src-tauri/src/bcpd.rs:265`；桌面自有 scheduler/session_store/crypto/db 与 core 重复。
- 前端仍把连接码当 fingerprint 存 localStorage：`desktop/src/App.vue:141-157,2012,2080`；配对/状态/配置多源镜像。
- 移动端 Java 仍主要是 LocalSend v2 + 53318：`mobile/local-receiver/android/src/main/java/com/backup/mobile/LocalReceiverPlugin.java:1785-1843,2213-2277`；与桌面 V4 主链不兼容。
- 构建/CI：仅 Android workflow `.github/workflows/local-receiver-android.yml`，无 Windows/core 门禁；pnpm CI 9 与 `shared-core/package.json:31` packageManager 11 不一致；tracked Android build 产物 1331 个。

## 2. 顶层判决（必须重构，不是局部修补）

1. **真实 HTTP 入口丢 query**：`serve_request` 用 `req.uri().path()`，而 handlers 用 `extract_query` 找 `?`；chunk/diff/verify/phase/tasks/manifest/sync-status/handshake-status 在真实服务上大面积 400。内部测试直接调 `route()` 掩盖了它。
2. **发送分块协议与服务端不匹配**：`upload_single` 整文件 POST 且不带 pieceIndex/sha256；`upload_scheduler_chunk` 带 chunkIndex 但服务端只读 pieceIndex；服务端按 4MB piece 计数，>4MB 文件永远凑不齐或超 10MB body 闸；客户端又不检查 HTTP status，失败被当成功。
3. **首配不可用且不安全**：生产从不调用 `set_pairing_code`；路径 A 用连接码确定性派生“长期密钥”，无用户确认、无真正 ECDH、无速率限制；VerifyResponse 回显客户端 deviceId，桌面可能把自己存成对端。
4. **身份恢复必错**：desktop 把签名公钥 base64url 用 STANDARD 解码，再把公钥字节传给 `DeviceIdentity::restore` 当私钥；core 期望 32B 私钥，结果每次重建随机身份。
5. **加密链路断裂**：desktop 加密上传，core 接收端不解密；`decrypt_stream` 仅 `#[cfg(test)]`；ECDH 分支拿自己的公钥当对端公钥；密钥派生/签名格式 desktop 与 core 两套且互不兼容。
6. **信任门禁可伪造**：legacy `check_trusted` 只看 paired map 中字符串与公钥非空；core `require_transferable` 只看 deviceId 对应 Active；无请求签名/会话 token 证明。
7. **存储多权威**：PairingState.paired(JSON Value) + SQLite + core PeerStore JSON + DesktopSessionStore + 前端 localStorage 互相写穿/回填；吊销可复活、密钥可丢、重启漂移。
8. **落盘路径未上闸**：core `handle_chunk` 直接 `base_dir.join(rel_path)`，未调用 `is_safe_rel_path`；Windows 绝对路径/盘符/ADS/保留名/大小写冲突可越界或破坏。
9. **校验是假校验**：服务端把客户端 sha 当本端 piece_sha；verify 返回发送端声明 sha；Merkle 未用于接收验证；冲突检查在收块前就把旧文件改名。
10. **生命周期失控**：watchdog/配对线程/bcpd/cursor/logger 无统一取消；stop_pairing_server 只 drop 原 listener 而线程持 clone；receiver 重启不等待旧任务退出；active_sessions/transfer_count 从不维护。

## 3. 目标架构（施工终态）

```text
Vue/App.vue ── typed invoke/events ── desktop/src-tauri（薄适配层）
                                      ├─ commands：输入校验/权限/投影，不写业务状态机
                                      ├─ windows platform：路径/DPAPI/防火墙/托盘/生命周期
                                      └─ storage adapter：实现 core trait（SQLite 权威）
lanbackup-core（唯一协议/算法/状态权威）
  ├─ identity/trust/pairing：随机 deviceId + 长期签名密钥 + 可验证配对
  ├─ server：单端口 53317 hyper；24 V4 路由；统一认证/错误/限流/超时
  ├─ transfer：SessionDriver 真正驱动 prepare/reconcile/send/verify/receipt/cleanup
  ├─ persistence trait：会话/位图/回执/清单快照；平台注入后端
  └─ presence/discovery：core beacon + 受控子网探测；桌面不得另造 bcpd
protocol：Rust DTO 生成 schema + golden + 真实 HTTP conformance
shared-core：只留 UI 编排/配置/日志桥；删除 V2 传输与配对权威
mobile：同一 V4 契约；Java 仅平台 IO，协议经 core/生成绑定
```

终态不变量：一个 deviceId 权威；一个配对状态机；一个会话状态机；一个端口；一个路径安全闸；一个加密格式；一个错误信封；一个进度/终态来源；前端只读投影+事件，不再全量回写信任表。

## 4. 施工批次与门禁

| 批次 | 编号 | 主题 | 出门门禁 |
|---|---|---|---|
| B0 | 施工前 | 基线快照/备份/探测工具链/记录脏改 | 备份清单 + cargo metadata + 当前测试基线 |
| B1 | WB-0001..0100 | 架构权威与致命链路 | P0 复现用例先红后绿；真实 HTTP 入口测试 |
| B2 | WB-0101..0200 | 48 个 Tauri 命令契约 | 命令 typed DTO、权限、错误、事件联动 |
| B3 | WB-0201..0440 | 24 端点逐项矩阵 | 每端点认证/校验/状态/幂等/错误/持久化/限流/日志/契约/跨端 10 项 |
| B4 | WB-0441..0560 | 传输/文件/Windows IO | 大文件、乱序、断点、崩溃、长路径、UNC、ADS、占用重试 |
| B5 | WB-0561..0680 | 配对/加密/身份 | 重新配对迁移、MITM/重放/吊销、密钥不落明文 |
| B6 | WB-0681..0780 | 持久化/DB/配置 | 单权威迁移、事务、损坏恢复、并发写、重置一致性 |
| B7 | WB-0781..0860 | 发现/在线/网络 | 多网卡、AP 隔离、休眠唤醒、防火墙、限流、自愈 |
| B8 | WB-0861..0940 | 日志/错误/可观测 | core log 桥接、脱敏、有界队列、轮转、requestId 贯穿 |
| B9 | WB-0941..1020 | 前端/shared-core/mobile/protocol 联动 | 三端契约一致、无 V2 权威、无 localStorage 秘密 |
| B10 | WB-1021..1080 | CI/测试/发布/文档清理 | Windows CI、schema golden、E2E、故障注入、发布验收 |

## 5. 决策闸（给执行 AI 的默认推荐；需用户批准才偏离）

- D1 本地秘密保护：**推荐 Windows DPAPI（CurrentUser）保护安装级随机 storage key**；需把既有 windows 传递依赖提升为直接 feature，先问用户。未批准时用 app_data ACL + 随机安装密钥，并明确“同用户恶意进程可读”的降级风险；禁止继续用可推导连接码当存储密钥。
- D2 首配协议：短期保留“连接码+双 nonce+HMAC+一次性 serverNonce+用户确认+失败限流+配对后作废连接码”，不得宣称抗离线抓包；长期 PAKE（SPAKE2/OPAQUE）属新依赖，单独批准。禁止继续把连接码派生值伪装成 ECDH 长期密钥。
- D3 兼容策略：**V4 only，破坏性迁移，强制重新配对**；删除/隔离 V2/V3/53318 权威，不做静默降级。旧数据只读迁移可迁移项，不可迁移项显式标记并提示重新配对。
- D4 tiny 聚合：默认**先取消自定义 `__batch__`/`__chunked__` 私有格式**，逐文件走统一 piece；若恢复聚合，必须实现并测试真实 ustar tar + 接收端解包 + 路径闸，不得只改扩展名。
- D5 存储后端：桌面已有 rusqlite 且本机有 C 编译器，推荐 **SQLite 作为桌面权威持久化，core 定义 trait/纯逻辑**；core JSON persister 降为测试/无 DB  fallback。移除或 feature-gate core 未使用的 rusqlite，避免“纯 Rust”假声明。

## 6. 条目格式与矩阵缩写

- 每条：`WB-编号 [优先级] 证据落点 → 施工动作；验收/联动`。优先级：P0=数据损坏/安全/主链不可用；P1=可靠性/架构；P2=维护/性能；P3=打磨。
- 路径缩写：`desktop/xxx.rs`/`desktop/transfer/...` 指 `desktop/src-tauri/src/...`；`core/xxx.rs` 指 `core/src/...`；`desktop/App.vue` 指 `desktop/src/App.vue`；`mobile Java` 指 `mobile/local-receiver/android/src/main/java/com/backup/mobile/LocalReceiverPlugin.java`。Cargo/配置/前端文件按仓库相对路径。
- B3 端点矩阵后缀：A=认证与所有权，V=输入/路径/范围校验，S=状态机门禁，I=幂等/重放，E=错误信封/HTTP 语义，P=持久化/恢复，L=限流/超时/资源上限，O=日志/requestId/指标，C=真实 HTTP 契约测试，X=前端/移动端联动。
- B2 命令后缀：①=输入/异步/错误/权限契约；②=前端事件/状态/投影联动。
- 条目是原子施工/验收项，不是 1080 个独立严重漏洞；同一根因在不同端点/命令/平台的落点分别编号，便于同一 AI 不漏改。

## 7. 施工清单

### B1 架构权威与致命链路（WB-0001..0100）

- WB-0001 [P0] core/src/server/mod.rs:1402 用 uri.path() 丢 query→保留 path_and_query 并统一解析；真实 hyper 带参端点回归；联动 send.rs/util.rs/Java。
- WB-0002 [P0] core/src/server/mod.rs:1269 extract_query 不解 percent/重复键→用 http/url 解析一次并拒绝歧义；编码路径用例；联动移动端 encodedPath。
- WB-0003 [P0] desktop/transfer/send.rs:943 upload URL 不带 pieceIndex/sha256→按 core piece 协议逐块上传；≤4MB/>4MB/加密三组 E2E；联动 core handle_chunk。
- WB-0004 [P0] desktop/transfer/send.rs:949 send 后不查 status→error_for_status+解析 ErrorEnvelope；4xx/5xx 不得计成功；联动前端进度/历史。
- WB-0005 [P0] desktop/scheduler.rs:468 传 chunkIndex 而 core 读 pieceIndex→统一 pieceIndex/blockIndex 契约；乱序/续传测试；联动 shared-core scheduler。
- WB-0006 [P0] core/server/mod.rs:721 handle_chunk 不校验 token/归属→每块校验 upload token+session owner+配对 Active；伪造 token 401；联动 prepare。
- WB-0007 [P0] core/server/mod.rs:511 token=`tok:{fileId}` 可预测→CSPRNG 一次性/会话绑定 token；重放/跨会话测试；联动 DTO/schema。
- WB-0008 [P0] core/server/mod.rs:828 append 写块且忽略索引→按 offset 随机写 .part，校验长度/索引/哈希后 confirmed；乱序/重复/缺口测试。
- WB-0009 [P0] core/server/mod.rs:838 把 client_sha 当本端 piece_sha→落盘后自算 SHA-256；篡改块 412/verify 失败；联动 diff/verify。
- WB-0010 [P0] core/server/mod.rs:860 收齐即 commit，未 verify→先整体/Merkle 校验再 commit；坏块不得进最终文件；联动 SessionDriver。
- WB-0011 [P0] core/server/mod.rs:765 base_dir.join(rel_path) 未安全闸→normalize+is_safe_rel_path+Windows 扩展闸；越界用例全拒；联动 sync_api/manifest。
- WB-0012 [P0] core/sync/manifest.rs:45 只拒 `..`/两字符盘符→补 UNC、ADS、保留名、尾点/空格、控制符、长度；Windows 路径矩阵测试。
- WB-0013 [P0] core/server/mod.rs:1397 body 先 collect 再查实际上限→流式限长读取，超限即断；chunked 无 CL 攻击测试；联动 hyper builder。
- WB-0014 [P0] desktop/transfer/receive.rs:183 未接 MAX_UPSTREAM_CONNECTIONS/IO_TIMEOUT→接入连接闸/超时/优雅停机；Slowloris 测试。
- WB-0015 [P0] desktop/transfer/receive.rs:133 把公钥当私钥 restore→持久化并恢复 32B 签名私钥；重启身份不变测试；联动 identity/db。
- WB-0016 [P0] desktop/transfer/receive.rs:130 base64url 用 STANDARD 解码→统一 URL_SAFE_NO_PAD；含 -/_ 密钥回归；联动 core sign。
- WB-0017 [P0] core/server/control.rs:550 生产未 set_pairing_code→启动/刷新码注入 core；首配 E2E；联动 identity.refresh_self_code。
- WB-0018 [P0] core/server/control.rs:613 连接码确定性派生长期 secret→按 D2 重做首配密钥；抓包重放/离线穷举风险标注；联动 desktop v4.rs。
- WB-0019 [P0] core/server/control.rs:640 VerifyResponse.device_id 回显客户端→返回服务端身份并分离 peerDeviceId/selfDeviceId；桌面不得存自己为对端。
- WB-0020 [P0] desktop/transfer/v4.rs:109 生成 eph 私钥后丢弃且不派生 secret→完整握手密钥协商并安全存储；重启重连测试。
- WB-0021 [P0] desktop/transfer/v4.rs:119 code 未 normalize→入口统一 core normalize；带分隔符/小写用例；联动 shared-core 两个 normalize。
- WB-0022 [P0] core/server/control.rs:545 路径 A 无用户确认→接入 pairing-request/resolve_pairing 或明确自动策略；拒绝/超时测试；联动 App.vue。
- WB-0023 [P0] desktop/pairing/auth.rs:441 check_trusted 只查字符串→请求签名/会话 token 认证；伪造 deviceId 401；联动 core require_transferable。
- WB-0024 [P0] core/server/sync_api.rs:180 require_transferable 无身份证明→认证上下文注入；manifest/move/delete/disconnect 全覆盖。
- WB-0025 [P0] core/server/control.rs:928 revoke-ack 不验签且 DTO 无 signature→补签名/令牌校验；伪造 ack 不得终态；联动 store.rs。
- WB-0026 [P0] desktop/transfer/store.rs:647 make_revoke_token 用 v3 裸拼接→改用 core transcript/token；双端验签向量；联动 protocol。
- WB-0027 [P0] desktop/transfer/store.rs:679 在线解配对期待 ok，core 返回 status→统一响应 DTO；在线/离线分支测试。
- WB-0028 [P0] core/server/control.rs:850 用临时 ECDH 公钥验 ECDSA→配对交换长期签名公钥；解配对/吊销验签 E2E。
- WB-0029 [P0] desktop/crypto.rs:479 ring DER/65B 公钥 vs core/crypto/sign.rs:61 raw64/33B→统一到 core 签名格式；跨端验签向量。
- WB-0030 [P0] desktop/crypto.rs:360 decrypt_stream 仅测试→接收生产解密接入 core AEAD；加密上传落盘明文校验；联动 mobile。
- WB-0031 [P0] desktop/transfer/send.rs:379 ECDH 用自己公钥当对端→使用对端 ephemeral/static 公钥；错误公钥必须失败；联动 DTO。
- WB-0032 [P0] desktop/transfer/send.rs:62 target_code 非空即加密但接收不解→加密能力协商默认一致；明文/密文标记入 DTO；不得静默降级。
- WB-0033 [P0] desktop/transfer/send.rs:231 tiny 自定义 pack 冒充 tar→按 D4 取消或真实 ustar；接收端解包/路径闸测试。
- WB-0034 [P0] desktop/transfer/send.rs:173 `__chunked__` 私有分片路径→统一到 logical fileId+pieceIndex；接收端不得落内部目录。
- WB-0035 [P0] desktop/transfer/send.rs:333 大文件同时 prepare s{k} 整文件与 f{i} 分片→一逻辑文件一条 meta；重复落盘/冲突测试。
- WB-0036 [P0] desktop/transfer/send.rs:482 SessionDriver::resume 后 next_step 仍是 Prepare→真正 feed Prepared/Initialized/Reconciled；断点跳过测试。
- WB-0037 [P0] desktop/transfer/send.rs:1078 query_confirmed_pieces 遇首个缺口即 break→拉完整权威位图；缺口后续块不得漏传。
- WB-0038 [P0] desktop/transfer/send.rs:1118 读失败返回空 vec 仍缓存哈希→IO 错误上抛且不缓存；损坏/占用文件不得假校验。
- WB-0039 [P0] desktop/transfer/send.rs:306 用密文 size 算明文 piece→哈希/分块基于明文字节，密文长度单独字段；加密大文件测试。
- WB-0040 [P0] desktop/transfer/send.rs:729 发送完成即 complete_session→以接收端 verify/receipt/tasks 为终态；部分拒绝不得更新全量快照。
- WB-0041 [P0] desktop/src/App.vue:2322 sent<total 仍 markBackupDone→仅对接收端确认完成文件更新快照；跳过/失败文件下轮重试。
- WB-0042 [P0] core/server/mod.rs:1100 verify 返回声明 sha→返回本端实算 sha；无 sha 不得 200；联动 FileMeta 可选策略。
- WB-0043 [P0] core/server/mod.rs:1210 file_incomplete_reason 缺 local hash 也算完整→缺度量=未完成；重传/412 测试。
- WB-0044 [P0] core/transfer/atomic_file.rs:87 mtime 期望 ns 但 DTO 是 ms→统一毫秒/纳秒类型；FAT 2s 容差测试；联动 restore_mtime。
- WB-0045 [P0] core/transfer/atomic_file.rs:93 收块前先把旧文件改名→改为新文件验证后原子替换/保留旧文件；崩溃不得丢旧版本。
- WB-0046 [P0] core/transfer/atomic_file.rs:197 copy_delete 直接写 final→非原子降级必须显式告警/平台限制；Windows 默认同目录 rename。
- WB-0047 [P0] core/server/mod.rs:833 pending_parts 以 file_id 为键→改为 (session_id,file_id)；跨会话同 fileId 不互踩。
- WB-0048 [P0] core/server/mod.rs:471 register 可覆盖既有会话→重复注册幂等返回原会话，不同 owner 拒绝；重启恢复测试。
- WB-0049 [P0] core/server/mod.rs:479 prepare 不迁移状态/重置 confirmed→状态机门禁+不可覆盖已确认进度；重复 prepare 幂等。
- WB-0050 [P0] core/server/mod.rs:1139 receipt 可任意写 completed→仅接收端权威/校验通过后生成；客户端回执不得伪造终态。
- WB-0051 [P0] core/server/sync_api.rs:390 disconnect 无认证且锁内 IO→认证+锁外清理；只收该 owner 会话；联动 CleanupPlan。
- WB-0052 [P0] core/server/sync_api.rs:332 move_to_delete 只改内存清单→平台真实假删除+清单同源；重启后墓碑仍在；联动桌面接收目录。
- WB-0053 [P0] core/server/mod.rs:216 SyncStore::new 未接 with_persist→注入同一 persister；last-manifest 重启恢复测试。
- WB-0054 [P0] desktop/transfer/receive.rs 未 set_local_manifest→扫描接收目录喂 core；manifest 非空且含 delete/；联动 App.vue 增量。
- WB-0055 [P0] desktop/src/App.vue:2264 manifest 失败退化为全量→区分未授权/未就绪/真空清单；不得静默全量+冲突副本。
- WB-0056 [P0] desktop/transfer/mod.rs:376 stop_pairing_server drop 原 listener 无效→统一取消/关闭 clone；端口释放测试。
- WB-0057 [P0] desktop/transfer/receive.rs:110 停旧服务不等待退出→JoinHandle+取消在途请求+flush；重启竞态测试。
- WB-0058 [P0] desktop/transfer/mod.rs:511 watchdog 只 TCP connect→健康检查走 /probe+服务状态；端口被占不得误判健康。
- WB-0059 [P0] desktop/lib.rs:898 set_defensive 只改内存且 core 不读→持久化+core 入站总闸；隐藏时 53317/53318/UDP 全拒。
- WB-0060 [P0] core/server/control.rs:432 probe 忽略 discoverable/hidden→按策略返回空/403；发现开关与防御总闸分层测试。
- WB-0061 [P1] desktop/transfer/mod.rs:99 TransferState 字段多权威且 dead_code→收缩为运行时句柄；业务状态归 core；编译期禁 dead 权威字段。
- WB-0062 [P1] desktop/transfer/mod.rs:222 PairingState.paired Value→ typed PeerRecord 投影；禁止前端写信任字段；联动 B6。
- WB-0063 [P1] desktop/transfer/store.rs:78 sync_paired_to_core 异步 fire-forget→改为 awaited 事务/命令队列；写后读一致测试。
- WB-0064 [P1] desktop/transfer/store.rs:131 手工 trust.state 赋值绕过状态机→所有迁移走 TrustRecord::apply；非法迁移测试。
- WB-0065 [P1] desktop/transfer/receive.rs:74 同样手工改 trust.state→复用映射函数；REVOKE_PENDING 不得映射成 Pending 丢失语义。
- WB-0066 [P1] desktop/transfer/store.rs:275 sync_paired 新记录默认 ACTIVE→前端同步只读投影；新信任必须来自配对流程。
- WB-0067 [P1] desktop/transfer/store.rs:190 confirm_paired 可注入公钥/ACTIVE→改为配对结果确认，不接受任意信任锚。
- WB-0068 [P1] desktop/src/App.vue:1716 confirmAllPairs 全量回写后端→删除回写权威；后端事件驱动前端投影。
- WB-0069 [P1] desktop/src/App.vue:1742 mergePeers 把后端列表回写 pairMgr 再 confirm→单向数据流；循环同步测试。
- WB-0070 [P1] desktop/transfer/store.rs:51 SYNC_UNKNOWN_STRIKES 进程级 static→纳入 core 对账状态/持久化策略；重启/多设备隔离测试。
- WB-0071 [P1] core/pairing/trust.rs:137 reconcile 与 desktop sync_all_peers 两套判据→桌面调用 core reconcile；unknown 三次策略入 core。
- WB-0072 [P1] core/server/control.rs:810 reconcile_with_peer 无生产调用→接线到 sync-status 客户端流程；GET 纯读不变。
- WB-0073 [P1] desktop/transfer/store.rs:727 sync_all_peers 串行阻塞→core 异步并发+超时+退避；多 peer 不卡 UI。
- WB-0074 [P1] desktop/lib.rs:299 run_blocking 包所有命令→按 IO/async 分类；网络命令用 async reqwest，DB 用 spawn_blocking；主线程 watchdog 回归。
- WB-0075 [P1] desktop/lib.rs:617 confirm_paired 同步命令做 PBKDF2/锁→异步化且去重 KDF；UI 响应测试。
- WB-0076 [P1] desktop/transfer/mod.rs:257 get_or_create_sig_key 失败 unwrap_or_default 空密钥→显式错误/重试；不得落空密钥。
- WB-0077 [P1] desktop/db.rs:470 save_sig_key 可覆盖有效密钥→仅初始化/显式重置可覆盖；重置事务化。
- WB-0078 [P1] desktop/transfer/store.rs:854 reset_all_state 多步非事务→停服务→清 core/DB/前端投影→再生身份；中途失败可恢复。
- WB-0079 [P1] desktop/lib.rs:570 reset_all_state 删 config 忽略错误→统一重置报告；失败不得宣称全新身份。
- WB-0080 [P1] desktop/transfer/mod.rs:284 notify_peers_disconnect channel 接收端丢弃→实现退出通知或移除死通道；退出 E2E。
- WB-0081 [P1] desktop/lib.rs:84 Builder 无 RunEvent::Exit 清理→统一 shutdown：取消任务/flush/释放端口/通知 peer。
- WB-0082 [P1] desktop/ball.rs:264 关闭直接 exit(0)→走 graceful shutdown；传输中关闭需确认/后台收尾。
- WB-0083 [P1] desktop/transfer/send.rs:393 active_sessions 插入后从不删除→RAII guard 清理；取消/完成/失败全路径测试。
- WB-0084 [P1] desktop/transfer/mod.rs:225 transfer_count 从不增减→由会话生命周期维护；刷新码门禁测试。
- WB-0085 [P1] desktop/identity.rs:178 refresh_self_code 写盘失败仍返回新码→写穿成功才失效旧码；旧密钥滚动保留。
- WB-0086 [P1] desktop/transfer/store.rs:446 storage key 随连接码刷新变化→存储密钥与连接码解耦；刷新后旧 secret 可解密。
- WB-0087 [P1] desktop/transfer/store.rs:336 persist_paired 每 peer 600k KDF→缓存 storage key/批量加密；10s 轮询不得烧 CPU。
- WB-0088 [P1] desktop/transfer/store.rs:352 try_read 失败本轮不落密钥→不得静默丢密钥；重试/队列/错误上报。
- WB-0089 [P1] desktop/db.rs:343 save_paired_peers 全删全插→增量 UPSERT+事务；并发快照不得丢 secret/吊销。
- WB-0090 [P1] desktop/transfer/store.rs:490 load try_write 失败整表不恢复→启动恢复必须可靠；失败进入降级 UI 而非空配对。
- WB-0091 [P1] core/server/persist_pairing.rs:44 明文 pairing_secret JSON→按 D1 加密/ACL；磁盘扫描无秘密。
- WB-0092 [P1] core/server/control.rs:197 persist_write 锁外快照可乱序覆盖→单写者队列/版本号；并发写后读一致。
- WB-0093 [P1] core/server/persist.rs:228 pieces append 无 sync/记录校验→WAL/校验和/截断恢复；崩溃注入测试。
- WB-0094 [P1] core/server/persist.rs:185 read_meta 损坏用 blank 重建→隔离损坏文件并告警；不得把空 meta 写回覆盖。
- WB-0095 [P1] core/server/persist.rs:109 sid 直接拼文件名→sid 格式闸/哈希文件名；路径穿越测试。
- WB-0096 [P1] desktop/session_store.rs:159 直接 write JSON 非原子→并入 core/SQLite 权威；崩溃恢复测试。
- WB-0097 [P1] desktop/scheduler.rs:282 与 core TransferScheduler 重复→桌面使用 core 调度；全局/peer/retry 配额一致。
- WB-0098 [P1] desktop/crypto.rs 与 core/crypto 两套→删除桌面密码学权威，仅保留平台密钥保护；跨端向量统一。
- WB-0099 [P1] desktop/bcpd.rs 与 core/presence 两套→迁移到 core beacon；格式/端口/重放/在线 TTL 统一。
- WB-0100 [P1] desktop/pairing/auth.rs 53318 遗留路由→V4 only 后隔离；移动端同批切换；端口释放/防火墙规则更新。

### B2 Tauri 命令契约（WB-0101..0200）

- WB-0101 [P2] fe_probe① lib.rs:309 任意字符串进探针→限长/脱敏/发布禁用；不得成为日志注入面。
- WB-0102 [P2] fe_probe② App.vue:39 探针默认关但仍可 invoke→前后端同一 feature 闸；发布构建移除注册。
- WB-0103 [P0] get_self_code① lib.rs:314 同步返回秘密且日志留种子→只返回显示码、禁种子日志；存储秘密分离。
- WB-0104 [P0] get_self_code② App.vue:1356 把 code 存 selfInfo/前端状态→前端只持展示态；不得进 localStorage/日志。
- WB-0105 [P0] refresh_self_code① lib.rs:326 同步写盘/通知→异步事务+传输中拒绝；失败保留旧码。
- WB-0106 [P1] refresh_self_code② App.vue:2513 刷新后只改 code 不清密钥→触发 core 密钥滚动/重新配对提示。
- WB-0107 [P1] get_self_info① lib.rs:388 同步读注册表/文件→缓存+异步；返回 typed SelfInfo。
- WB-0108 [P1] get_self_info② App.vue:2552 重置后重拉身份→事件 self-info-updated 替代轮询重拉。
- WB-0109 [P1] set_self_name① lib.rs:405 名称无限长/控制符→长度/字符闸+原子写；同步 core alias。
- WB-0110 [P2] set_self_name② App.vue:2490 防抖保存无失败回滚→失败恢复输入并提示；alias 事件广播。
- WB-0111 [P1] get_device_state① lib.rs:339 connection_code 作键暴露秘密→改 deviceId 键；typed 状态 DTO。
- WB-0112 [P1] get_device_state② shared-core/src/state.ts:16 按连接码索引→迁移 deviceId 索引；旧数据只读迁移。
- WB-0113 [P1] save_device_state① lib.rs:360 任意 Value 落库→schema 校验/大小限/字段白名单；拒绝信任字段。
- WB-0114 [P1] save_device_state② App.vue 状态镜像→后端权威投影；前端不得覆盖配对/吊销字段。
- WB-0115 [P2] get_all_devices① lib.rs:752 返回连接码列表→返回 deviceId/别名投影；秘密不出 IPC。
- WB-0116 [P2] get_all_devices② 前端设备选择→按 deviceId 绑定；旧 code 键迁移提示。
- WB-0117 [P0] start_receiver① lib.rs:765 目录/端口未校验且可并发重启→路径闸+单飞状态机+实际端口返回。
- WB-0118 [P1] start_receiver② App.vue:2176 固定 53317/返回字符串当提示→typed ReceiverStatus；端口冲突可读错误。
- WB-0119 [P0] stop_receiver① lib.rs:786 不取消在途/不清 session_store→graceful stop+会话 abort+资源释放。
- WB-0120 [P1] stop_receiver② App.vue:2189 停止即 serverRunning=false→以后端 stopped 事件为准；失败保持运行态。
- WB-0121 [P0] send_files① lib.rs:799 文件列表/加密模式字符串无闸→typed SendRequest+能力协商+取消令牌。
- WB-0122 [P0] send_files② App.vue:2315 返回 unit 数当文件数→返回逐文件终态；前端按 receipt 更新快照。
- WB-0123 [P1] scan_directory① lib.rs:837 任意目录递归无深度/取消→授权根+深度/数量上限+取消；junction 不跟随。
- WB-0124 [P1] scan_directory② App.vue:2246 扫描结果直接组 relPath→后端返回规范 relPath/文件身份；前端不再拼绝对路径。
- WB-0125 [P0] get_peer_manifest① lib.rs:851 无认证/错误吞成 null→认证+错误分类；空清单与失败分离。
- WB-0126 [P1] get_peer_manifest② App.vue:2260 失败退化全量→UI 显示“清单不可用”并允许取消；不得静默全量。
- WB-0127 [P1] start_discovery① lib.rs:868 重复启动错误/一次性扫描→core 发现服务生命周期；可重启/可停止。
- WB-0128 [P1] start_discovery② App.vue:1915 轮询 get_discovered_devices→事件驱动增量；扫描进度/截断告警。
- WB-0129 [P1] stop_discovery① lib.rs:885 两个 stop flag 不一致→单一 CancellationToken；线程退出确认。
- WB-0130 [P2] stop_discovery② App.vue:1964 停止后列表不清→后端发 discovery-stopped；前端清理临时设备。
- WB-0131 [P2] get_discovered_devices① lib.rs:923 同步锁克隆 Vec→投影快照/增量事件；TTL 与 core presence 一致。
- WB-0132 [P2] get_discovered_devices② App.vue:1930 1.5s 轮询→事件+低频兜底；后台降频。
- WB-0133 [P0] set_defensive① lib.rs:898 只改 AtomicBool→持久化+core 入站/广播总闸；重启保持。
- WB-0134 [P1] set_defensive② App.vue:1974 开关无后端确认→以 defensive-changed 事件回执；失败回滚 UI。
- WB-0135 [P1] get_defensive① lib.rs:916 读内存默认 false→读持久化配置；与 set 同源。
- WB-0136 [P2] get_defensive② App.vue:1364 启动拉取失败默认 false→失败进入安全默认/提示；不得假称可见。
- WB-0137 [P2] remove_device① lib.rs:941 按 IP 删除可误删多设备→按 deviceId/fingerprint；IP 变更不丢信任。
- WB-0138 [P1] remove_device② App.vue:1602 可疑设备只清缓存→解除信任走 unpair_peer；发现缓存与信任分离。
- WB-0139 [P1] probe_peer_port① lib.rs:418 TCP connect 即认为服务→V4 probe+身份校验；超时/代理禁用。
- WB-0140 [P1] probe_peer_port② App.vue:574 greetPeer 仅端口可达→连接必须走 handshake/认证；不得标记 connected。
- WB-0141 [P1] v4_probe① lib.rs:430 返回任意 JSON→typed ProbeResponse+版本/能力校验；错误信封。
- WB-0142 [P1] v4_probe② App.vue:1806 轮询 probe 消耗 serverNonce→发现用轻量 probe，配对才取 nonce；分离端点/参数。
- WB-0143 [P0] v4_pair① lib.rs:441 配对后手工补 paired map→core 返回完整配对结果并事务落库；不得前端补信任。
- WB-0144 [P0] v4_pair② App.vue:2002 用 r.deviceId 可能是自己→以 probe 服务端身份为准；自配对拒绝。
- WB-0145 [P0] unpair_peer① lib.rs:543 在线/离线分支语义漂移→core UnpairRetry+签名/ack；返回 typed 终态。
- WB-0146 [P1] unpair_peer② App.vue:2117 无论成败都 remove→按后端终态更新；REVOKE_PENDING 显示待收敛。
- WB-0147 [P1] sync_all_peers① lib.rs:555 串行网络阻塞→core 异步对账+限流；返回逐 peer 结果。
- WB-0148 [P1] sync_all_peers② App.vue:1703 30s 定时器→后端事件驱动对账；前端只订阅 trust-updated。
- WB-0149 [P0] reset_all_pairings① lib.rs:562 清表/再生密钥非事务→停传输→吊销/清 core→再生身份；失败可恢复。
- WB-0150 [P1] reset_all_pairings② 前端确认文案→明确旧配对失效/需重新配对；事件清空投影。
- WB-0151 [P0] reset_all_state① lib.rs:570 多存储删除顺序不一致→统一 reset 编排器；DB/core/config/前端同事务语义。
- WB-0152 [P1] reset_all_state② App.vue:2542 前端随后清 localStorage→后端 reset-completed 事件驱动；失败不清前端。
- WB-0153 [P1] send_disconnect① lib.rs:597 无认证/返回 bool 吞错→签名 disconnect+typed 结果；只断连接不解配对。
- WB-0154 [P1] send_disconnect② App.vue:1865 本地先清 connected→本地停止无条件+通知独立结果；四态文案用 core CancelOutcome。
- WB-0155 [P0] move_to_delete① lib.rs:586 期待 moved 数字而 core 返回数组→typed MoveResult；逐路径 moved/skipped/rejected。
- WB-0156 [P1] move_to_delete② App.vue:2287 镜像确认按 fingerprint 永久防重弹→按清单版本/路径集合确认；变更后可再确认。
- WB-0157 [P0] resolve_incoming① lib.rs:481 pending map 无生产写入→core prepare 审批流接入；超时/拒绝/重复响应测试。
- WB-0158 [P1] resolve_incoming② App.vue:1450 自动接收仅前端开关→策略入后端配置；后端执行自动/人工审批。
- WB-0159 [P0] resolve_pairing① lib.rs:515 pending map 无生产写入→core 首配审批接入；requestId 防重放。
- WB-0160 [P1] resolve_pairing② App.vue:1466 弹窗只 deviceId/name/ip→显示公钥指纹/SAS/来源；拒绝后清理会话。
- WB-0161 [P1] get_paired_peers① lib.rs:608 JoinError 吞成空列表→错误上抛；typed 投影不含秘密。
- WB-0162 [P1] get_paired_peers② App.vue:1744 10s 轮询→trust-projection 事件；版本化快照防抖。
- WB-0163 [P0] confirm_paired① lib.rs:617 同步且可写信任锚→改为配对结果确认命令；异步/权限/审计。
- WB-0164 [P1] confirm_paired② mobile receiver.ts:67 同名回填接口→三端统一“确认配对结果”语义；禁止任意 ACTIVE。
- WB-0165 [P0] sync_paired① lib.rs:644 前端全量写信任表→删除权威写入口；仅允许 UI 元数据投影更新。
- WB-0166 [P1] sync_paired② App.vue:1731 启动/合并回写→改为请求快照；后端单权威。
- WB-0167 [P1] send_sync_dir① lib.rs:663 direction/name 字符串无枚举→typed SyncDirRequest+路径闸；响应含 peerManifest。
- WB-0168 [P1] send_sync_dir② mobile receiver.ts:93 旧 direction/name→同批切 V4 DTO；目录映射持久化。
- WB-0169 [P1] get_synced_dir① lib.rs:678 读内存 dead map→core SyncStore 持久化投影；重启可恢复。
- WB-0170 [P2] get_synced_dir② 前端目录名展示→事件 dir-mapping-updated；不得轮询死接口。
- WB-0171 [P2] get_transfers① lib.rs:688 limit 钳制 1..100 但前端传 200→统一分页 DTO；返回总数/游标。
- WB-0172 [P2] get_transfers② App.vue:907 历史全量拉→分页/增量事件；大历史不卡 UI。
- WB-0173 [P1] clear_transfers① lib.rs:698 无确认/审计→命令层审计日志+前端二次确认；不影响会话位图。
- WB-0174 [P2] clear_transfers② App.vue:941 清后局部刷新→transfers-cleared 事件；统计卡同步。
- WB-0175 [P2] delete_transfer① lib.rs:708 id 无所有权/存在性反馈→返回 deleted bool；参数化 SQL 已保持。
- WB-0176 [P2] delete_transfer② App.vue:924 删除行→行级事件；失败行内提示。
- WB-0177 [P0] get_config① lib.rs:719 读失败一律空对象→区分缺失/损坏/权限；损坏备份并告警。
- WB-0178 [P1] get_config② shared-core/src/config.ts:44 缺 encryption/autoAccept 字段→补 typed AppConfig；前后端同 schema。
- WB-0179 [P0] set_config① lib.rs:734 任意 Value 直接 write→schema 校验+原子写+版本迁移；拒绝未知危险字段。
- WB-0180 [P1] set_config② App.vue:1172 JSON.parse(JSON.stringify) 绕类型→typed invoke；保存失败回滚 UI。
- WB-0181 [P1] set_debug_mode① lib.rs:950 任意窗口可开 release debug→权限/持久化/自动过期；脱敏不随 debug 关闭。
- WB-0182 [P1] set_debug_mode② App.vue:1051 前后端开关分离→debug-state 事件同源；localStorage 只存偏好。
- WB-0183 [P1] get_debug_mode① lib.rs:956 返回 cfg! 而非运行时→返回 logger 实际状态；测试覆盖 release。
- WB-0184 [P2] get_debug_mode② App.vue:1334 启动只读 localStorage→以后端状态为准；冲突将后端覆盖前端。
- WB-0185 [P2] ball_emit_emotion① lib.rs:963 任意 emotion/tips→白名单/限长；球窗口不存在返回状态。
- WB-0186 [P2] ball_emit_emotion② ball.rs:138 状态只在窗口存在时更新→BallState 与事件一致；重建窗口恢复状态。
- WB-0187 [P2] ball_set_state① lib.rs:970 状态字符串无枚举→typed BallState；非法状态拒绝。
- WB-0188 [P2] ball_set_state② App.vue:76 失败回退单表情→后端统一行为机；前端不再兜底猜表情。
- WB-0189 [P1] set_ball_enabled① lib.rs:978 启用状态不持久化→配置权威；启动恢复；禁用停 cursor 轮询。
- WB-0190 [P2] set_ball_enabled② App.vue:1017 enabled/visible 双命令竞态→单命令设置期望态；事件回执。
- WB-0191 [P2] set_ball_visible① lib.rs:991 与 enabled 语义重叠→合并可见性状态机；非法组合拒绝。
- WB-0192 [P2] set_ball_visible② ball.rs:163 show/hide 错误忽略→返回结果；失败 UI 提示。
- WB-0193 [P1] export_logs① logger.rs:452 extra_lines 无限/同秒覆盖→限长/唯一文件名/原子写；导出前脱敏扫描。
- WB-0194 [P1] export_logs② App.vue:2571 导出含前端日志→统一日志桥与 requestId；导出摘要含版本/平台。
- WB-0195 [P1] get_rust_logs① logger.rs:550 解析文本回 JSON→直接存结构化 LogEntry；避免二次解析丢 ts。
- WB-0196 [P1] get_rust_logs② App.vue:1421 启动补日志与事件重复→按 seq 去重；有界回放。
- WB-0197 [P1] 命令注册 lib.rs:215 手写 48 项→按模块生成/清单测试；新增命令必须登记 schema/权限。
- WB-0198 [P1] 命令错误 AppError 纯字符串→统一 CommandError{code,message,requestId,retryable}；前端按 code 分支。
- WB-0199 [P1] 命令权限 capabilities/default.json main/ball 同权→分窗口能力；危险命令仅 main；球窗口最小权限。
- WB-0200 [P1] 事件契约散落字符串→建立 events.ts/rust 事件清单+payload schema；前后端编译期/测试对齐。

### B3-V4 端点矩阵上半（WB-0201..0320）

- WB-0201 [P1] probe·A control.rs:432 匿名即发配对 nonce→拆分发现 probe 与配对 challenge；匿名只给公开信息；联动发现/配对。
- WB-0202 [P1] probe·V control.rs:440 port 固定 DEFAULT_PORT→返回实际监听端口/endpoint；多端口测试；联动 discovery.rs。
- WB-0203 [P1] probe·S control.rs:445 presence 恒 Online→由 core presence/防御闸推导；hidden/discoverable 矩阵。
- WB-0204 [P1] probe·I control.rs:433 每次 probe 都占 nonce→发现 probe 不签发一次性 nonce；配对请求才签发。
- WB-0205 [P2] probe·E control.rs:436 无 requestId/版本头→统一响应 meta；错误信封；契约测试。
- WB-0206 [P2] probe·P control.rs:432 身份/alias 来自 store 快照→alias 改名后投影一致；重启身份不变。
- WB-0207 [P0] probe·L control.rs:64 nonce 满随机驱逐→按来源限流+TTL 队列；洪泛不得踢掉合法握手。
- WB-0208 [P2] probe·O control.rs:432 无结构化日志→记录来源/版本/能力但脱敏；requestId 贯穿。
- WB-0209 [P1] probe·C dto/handshake.rs:29 schema 与 README approved/active 漂移→真实 HTTP 校验响应；golden 更新。
- WB-0210 [P1] probe·X desktop/discovery.rs:198 只取 deviceId/alias→typed ProbeResponse；mobile v3Probe 同批迁移。
- WB-0211 [P0] challenge·A control.rs:461 只凭 deviceId 发令牌→要求已配对+请求认证/限流；未知设备不得取令牌。
- WB-0212 [P1] challenge·V control.rs:456 clientNonce/requestId 无长度格式→32B hex/UUID 闸；畸形 400。
- WB-0213 [P1] challenge·S control.rs:471 Pending 也发 challenge→明确 Pending 重连策略；Revoking/Revoked 拒绝。
- WB-0214 [P0] challenge·I control.rs:483 cached_challenge 不绑定 deviceId→同 requestId 跨设备不得回放；幂等测试。
- WB-0215 [P2] challenge·E control.rs:463 UnknownDevice 404 与 Untrusted 401 混用→统一错误码语义；前端分支。
- WB-0216 [P1] challenge·P control.rs:501 HandshakeSession 不落盘→重启后 requestId 可查询/明确失效；TTL 清理。
- WB-0217 [P0] challenge·L control.rs:72 64 会话满驱逐最旧→按来源令牌桶+TTL；恶意 requestId 不得挤掉合法会话。
- WB-0218 [P2] challenge·O control.rs:494 签发令牌无审计→记录 jti/requestId 摘要；不得落令牌本体。
- WB-0219 [P1] challenge·C token.rs:58 Claims 与 README JWT 字段不一致→生成 schema/向量；双端解析一致。
- WB-0220 [P1] challenge·X desktop/v4.rs 未走路径 B→实现重连客户端；mobile 同契约；重连 E2E。
- WB-0221 [P0] verify·A control.rs:545 路径 A 无用户确认/速率限制→D2 审批+失败退避；错误码不得 oracle。
- WB-0222 [P0] verify·V control.rs:554 公钥/nonce/hmac 只解码不验长度曲线→P-256 点/32B nonce/64hex 闸；畸形用例。
- WB-0223 [P0] verify·S control.rs:618 新建 trust 直接 Initiate→PeerConfirmed→已有 Revoked 记录不得复活；Repair 显式流程。
- WB-0224 [P0] verify·I control.rs:568 take_nonce 后失败不恢复→requestId 幂等结果缓存；超时重试同一 requestId 不得二次配对。
- WB-0225 [P1] verify·E control.rs:573 HmacMismatch 与 BadRequest 泄漏阶段→统一认证失败文案；内部原因只日志。
- WB-0226 [P0] verify·P control.rs:626 peers.put 与 handshake.mark_done 非原子→事务/单写者；崩溃后状态一致。
- WB-0227 [P0] verify·L control.rs:545 无失败计数→按 IP/deviceId 限流+连接码尝试上限；暴力测试。
- WB-0228 [P1] verify·O control.rs:638 mark_done 无 requestId 上下文→结构化审计；配对成功/失败事件。
- WB-0229 [P0] verify·C control.rs:640 响应缺服务端公钥/密钥协商结果→DTO 补全并生成 schema；真实 HTTP 向量。
- WB-0230 [P0] verify·X desktop/transfer/v4.rs:141 只判断 status→处理 pending/rejected/timeout；App.vue 弹窗/错误联动。
- WB-0231 [P1] status·A control.rs:751 任意 requestId 可查→绑定来源/认证或不可枚举 ID；越权查询测试。
- WB-0232 [P1] status·V control.rs:755 requestId 未解码校验→query 解析统一；缺失/畸形 400。
- WB-0233 [P1] status·S control.rs:761 unknown 返回 done=false→区分 unknown/expired/pending；客户端停止无限轮询。
- WB-0234 [P1] status·I control.rs:750 GET 纯读保持→重复查询不改状态；并发查询测试。
- WB-0235 [P2] status·E control.rs:767 error 字符串直接外泄→错误码+可披露文案；内部细节日志。
- WB-0236 [P1] status·P control.rs:86 终态宽限 300s→宽限/清理可配置且持久化策略；重启后语义明确。
- WB-0237 [P1] status·L control.rs:397 prune_sessions 无生产调用→接入定时清理；内存有界测试。
- WB-0238 [P2] status·O control.rs:751 查询无指标→pending/done/expired 计数；日志脱敏。
- WB-0239 [P1] status·C dto/handshake.rs:160 done/status/error 组合无约束→schema oneOf/测试；真实 HTTP。
- WB-0240 [P1] status·X desktop/App.vue 配对超时补偿→前端按 requestId 查询一次再决定重试；mobile 同步。
- WB-0241 [P0] unpair-request·A control.rs:850 用错公钥格式验签→长期签名公钥+core 格式；伪造签名 401。
- WB-0242 [P1] unpair-request·V control.rs:834 requestId/signature 无长度闸→限长/格式；畸形 400。
- WB-0243 [P1] unpair-request·S control.rs:853 Active→Revoking 合法→重复请求幂等；终态不得回退。
- WB-0244 [P1] unpair-request·I control.rs:842 requestId 未消费→一次性/幂等结果；重放测试。
- WB-0245 [P1] unpair-request·E control.rs:858 返回 status 无 ok→typed UnpairResponse；desktop 不再猜 ok。
- WB-0246 [P1] unpair-request·P control.rs:857 put 后无清理调度→触发会话 abort/密钥删除事务；重启收敛。
- WB-0247 [P1] unpair-request·L control.rs:830 无重试/限流→UnpairRetry 策略入 core；洪泛限流。
- WB-0248 [P2] unpair-request·O control.rs:850 验签失败无审计→安全事件日志；告警阈值。
- WB-0249 [P1] unpair-request·C transcript.rs:116 payload 向量→跨 Rust/Java/TS 签名向量；golden。
- WB-0250 [P1] unpair-request·X desktop/transfer/store.rs:602 签名构造→改用 core identity.sign；mobile sendUnpair 迁移。
- WB-0251 [P0] unpair·A control.rs:879 通知验签同公钥缺陷→认证上下文+长期公钥；伪造通知拒绝。
- WB-0252 [P1] unpair·V control.rs:863 revokeToken 可选但被忽略→校验令牌或移除字段；schema 一致。
- WB-0253 [P1] unpair·S control.rs:882 PeerUnpair→Revoked→Revoking/Active 矩阵；终态单调。
- WB-0254 [P1] unpair·I control.rs:871 requestId 重放→消费/幂等；重复通知不重复清理。
- WB-0255 [P2] unpair·E control.rs:887 响应缺配对终态投影→返回 trustVersion/presence；前端更新。
- WB-0256 [P1] unpair·P control.rs:886 吊销后 secret 未清→PeerStore 清理密钥/会话；磁盘无残留。
- WB-0257 [P1] unpair·L control.rs:862 无来源限流→按 peer 限流；离线兜底不洪泛。
- WB-0258 [P2] unpair·O control.rs:882 状态迁移无事件→trust-updated 事件；日志 requestId。
- WB-0259 [P1] unpair·C dto/handshake.rs:187 与 unpair-request 形状重叠→明确两 endpoints 语义或合并；契约测试。
- WB-0260 [P1] unpair·X mobile Java /v2/unpair→切 V4 签名通知；桌面 legacy 路由隔离。
- WB-0261 [P0] revoke-notify·A control.rs:911 验签 payload 只 deviceId+token→绑定 issuer/target/时间/nonce；伪造拒绝。
- WB-0262 [P1] revoke-notify·V control.rs:895 revokeToken 无 TTL/格式→core token 校验；过期/错 kind 拒绝。
- WB-0263 [P1] revoke-notify·S control.rs:915 PeerUnpair→Revoked→本地 Revoking 时 ack 语义矩阵。
- WB-0264 [P0] revoke-notify·I control.rs:903 token nonce 未消费→一次性 jti；重放测试。
- WB-0265 [P2] revoke-notify·E control.rs:920 返回 token 原样→不得回显敏感令牌；返回状态摘要。
- WB-0266 [P1] revoke-notify·P control.rs:919 吊销令牌未持久化→离线兜底可恢复；30 天清理。
- WB-0267 [P1] revoke-notify·L control.rs:891 无重试策略→UnpairRetry RevokeNotify 通道；失败交对账。
- WB-0268 [P2] revoke-notify·O control.rs:911 安全事件→审计日志/告警；脱敏 token。
- WB-0269 [P1] revoke-notify·C token.rs:87 revoke claims 向量→跨端验签/过期卫生测试。
- WB-0270 [P1] revoke-notify·X desktop/transfer/store.rs:701 本地 token JSON→改 core token 字符串/DTO；mobile 同步。
- WB-0271 [P0] revoke-ack·A control.rs:928 完全无签名→补 signature 校验；伪造 ack 不得终态。
- WB-0272 [P1] revoke-ack·V dto/handshake.rs:210 DTO 缺 signature→补字段/schema；pairingRevoked=false 分支。
- WB-0273 [P1] revoke-ack·S control.rs:940 只 Revoking→Revoked→Active 收到 ack 应幂等/拒绝矩阵。
- WB-0274 [P1] revoke-ack·I control.rs:932 requestId/token 未消费→幂等；重复 ack 不重复事件。
- WB-0275 [P2] revoke-ack·E control.rs:945 非法迁移 409→前端显示已收敛而非错误；错误码细化。
- WB-0276 [P1] revoke-ack·P control.rs:944 终态后 secret/会话清理→事务；重启不复活。
- WB-0277 [P1] revoke-ack·L control.rs:928 无超时兜底→RevokeTimeout/对账兜底；30 天策略。
- WB-0278 [P2] revoke-ack·O control.rs:940 终态审计→trust-updated/日志；requestId。
- WB-0279 [P1] revoke-ack·C 真实 HTTP 签名向量→Rust/Java 一致；golden 更新。
- WB-0280 [P1] revoke-ack·X desktop/transfer/store.rs:627 发送 signature 但 DTO 无→同批修 DTO/服务端/前端。
- WB-0281 [P0] sync-status·A control.rs:784 任意 deviceId 查信任→认证提问方；不得泄漏第三方信任。
- WB-0282 [P1] sync-status·V control.rs:788 deviceId query 未解码→统一 query；畸形 400。
- WB-0283 [P1] sync-status·S control.rs:799 youArePaired 只 Active→Revoking 中间态语义与 trust.rs 一致。
- WB-0284 [P1] sync-status·I control.rs:777 GET 纯读→重试不改版本；并发读测试。
- WB-0285 [P2] sync-status·E control.rs:794 unknown 返回 200+None→明确 unknown 语义；客户端三次策略入 core。
- WB-0286 [P1] sync-status·P control.rs:793 trustVersion 持久化→重启版本不回退；对账缓存一致。
- WB-0287 [P1] sync-status·L control.rs:784 无轮询限流→按 peer 限流；前端 30s 轮询迁移后端。
- WB-0288 [P2] sync-status·O control.rs:810 reconcile 无日志→对账 verdict 指标；告警 PeerDenies。
- WB-0289 [P1] sync-status·C dto/handshake.rs:235 字段与 README 16 端点漂移→routes::ALL 生成 golden；真实 HTTP。
- WB-0290 [P1] sync-status·X desktop/transfer/store.rs:727 自写对账→调用 core reconcile_with_peer；mobile syncAllPeers 同步。
- WB-0291 [P0] register·A mod.rs:444 无配对/认证即可开会话→Active 配对+会话 token；未知设备 401。
- WB-0292 [P1] register·V mod.rs:450 sessionId 只非空→CSPRNG 格式/长度；alias 限长；畸形 400。
- WB-0293 [P1] register·S mod.rs:457 直接 Preparing 不 transition→Idle→Register 状态机；非法重复注册矩阵。
- WB-0294 [P0] register·I mod.rs:471 insert 覆盖旧会话→同 owner 幂等返回；异 owner 拒绝；重启恢复。
- WB-0295 [P2] register·E mod.rs:473 capabilities all→按本机真实能力协商；错误信封。
- WB-0296 [P1] register·P mod.rs:461 先写盘后内存→单写者事务；写盘失败不得半会话。
- WB-0297 [P0] register·L mod.rs:444 会话数无上限→全局/per-peer 会话上限+闲置清理；洪泛测试。
- WB-0298 [P2] register·O mod.rs:471 无 session 创建指标→结构化日志/计数；requestId。
- WB-0299 [P1] register·C dto/session.rs:157 请求/响应 schema→真实 HTTP 注册 E2E；golden。
- WB-0300 [P1] register·X desktop/transfer/send.rs:285 失败不阻断→注册失败必须停止；前端显示不可传。
- WB-0301 [P0] prepare·A mod.rs:494 只比 deviceId 字符串→会话 token/签名；跨设备复用拒绝。
- WB-0302 [P0] prepare·V mod.rs:504 relPath/size/mtime/hash 无闸→路径安全/大小上限/哈希格式/文件数上限；恶意清单测试。
- WB-0303 [P1] prepare·S mod.rs:479 不检查 phase/不迁移→Preparing→Reconciling/Transferring 协商；重复 prepare 矩阵。
- WB-0304 [P0] prepare·I mod.rs:506 重置 confirmed→幂等保留已确认位图；重试不得丢进度。
- WB-0305 [P1] prepare·E mod.rs:514 拒绝文件无原因→逐文件 accepted/rejected+reason；前端可显示。
- WB-0306 [P1] prepare·P mod.rs:507 每文件 set_file 读改写 meta→批量事务写；崩溃恢复一致。
- WB-0307 [P0] prepare·L mod.rs:503 files HashMap 无上限→文件数/总字节/单文件上限；内存保护。
- WB-0308 [P2] prepare·O mod.rs:511 token 生成无审计→记录 file 数/字节摘要；不得落 token。
- WB-0309 [P1] prepare·C dto/session.rs:224 PrepareResponse files 字符串→真实 HTTP+schema；移动端 token 对象兼容移除。
- WB-0310 [P0] prepare·X desktop/transfer/send.rs:353 不审批直接 prepare→接入 incoming-request/自动策略；App.vue 弹窗联动。
- WB-0311 [P0] chunk·A mod.rs:721 token/owner/配对全缺→每块认证；伪造/跨会话 401。
- WB-0312 [P0] chunk·V mod.rs:730 pieceIndex 解析失败默认 0→严格整数/范围/长度/sha 格式；越界 416。
- WB-0313 [P1] chunk·S mod.rs:746 只 Preparing/Reconciling 迁移→allows_transfer+phase 门禁；终态后写块拒绝。
- WB-0314 [P0] chunk·I mod.rs:828 重复块 append→同索引同哈希幂等；不同哈希 409/412；乱序测试。
- WB-0315 [P1] chunk·E mod.rs:826 IO 错误 500 含路径→对外通用文案；内部日志带路径摘要。
- WB-0316 [P0] chunk·P mod.rs:874 confirmed 写盘与 .part 不一致→位图来自实际落盘+offset；崩溃恢复测试。
- WB-0317 [P0] chunk·L mod.rs:1397 10MB 闸与 8MB 块/加密开销冲突→按协议 piece 上限流式限长；加密块测试。
- WB-0318 [P2] chunk·O mod.rs:871 落盘完成日志明文 relPath→路径摘要/脱敏；进度指标。
- WB-0319 [P0] chunk·C 无 chunk 响应 schema→补 DTO/schema；真实 HTTP 小/大/加密/乱序矩阵。
- WB-0320 [P0] chunk·X desktop/send.rs/scheduler.rs/mobile streamUpload→统一 pieceIndex/哈希/加密头；三端 E2E。

### B3-V4 端点矩阵下半（WB-0321..0440）

- WB-0321 [P0] diff·A mod.rs:904 知 sessionId 即可查位图→owner/token 认证；越权 401。
- WB-0322 [P1] diff·V mod.rs:948 pieceIndex/etag/sha 格式→严格解析；弱 ETag 400；越界 416+Content-Range。
- WB-0323 [P1] diff·S mod.rs:914 终态会话仍可 diff→终态只读快照/明确 409；状态矩阵。
- WB-0324 [P1] diff·I mod.rs:960 GET 纯读→重复查询一致；位图版本单调。
- WB-0325 [P1] diff·E mod.rs:979 206 无 expected 比对也通过→缺度量不得 206；四态语义测试。
- WB-0326 [P0] diff·P mod.rs:926 local_sha 来自客户端→本端实算/持久化；重启后 412 能定位坏块。
- WB-0327 [P1] diff·L mod.rs:1007 整文件循环 total_pieces→大文件分页/位图压缩；内存上限。
- WB-0328 [P2] diff·O mod.rs:904 无对账指标→missing/matched/mismatch 计数；requestId。
- WB-0329 [P1] diff·C dto/session.rs:245 200/206/412/416 多形状→oneOf schema+真实 HTTP 四态测试。
- WB-0330 [P0] diff·X desktop/transfer/send.rs:438 用 chunkIndex/chunkSize 旧参数→统一 pieceIndex/pieceSize/etag；mobile getDiff 迁移。
- WB-0331 [P0] verify·A mod.rs:1052 无 owner 认证→会话 token；越权校验拒绝。
- WB-0332 [P1] verify·V mod.rs:1055 sessionId/fileId 解码校验→统一 query；缺失 400。
- WB-0333 [P1] verify·S mod.rs:1091 全会话到齐才 Completed→多文件/部分拒绝矩阵；不得首文件完成即终态。
- WB-0334 [P1] verify·I mod.rs:1052 GET 却推进状态→改 POST 或 GET 只读+独立 commit；幂等语义明确。
- WB-0335 [P0] verify·E mod.rs:1124 返回声明 sha→实算 sha；失败 412+原因；不得假 200。
- WB-0336 [P0] verify·P mod.rs:1111 终态清理磁盘行但内存保留→终态快照/历史策略一致；重启可查询或明确过期。
- WB-0337 [P1] verify·L mod.rs:1062 锁内遍历所有文件→快照锁外校验；大清单不阻塞。
- WB-0338 [P2] verify·O mod.rs:1093 状态迁移无审计→verify 结果/耗时指标；requestId。
- WB-0339 [P1] verify·C dto/session.rs:288 VerifyFileResponse→真实 HTTP 成功/缺块/坏块测试。
- WB-0340 [P0] verify·X desktop/send.rs 从未调用 verify→SessionDriver Verify 步骤接线；前端终态来自 verify/receipt。
- WB-0341 [P1] phase·A mod.rs:521 无 owner→认证；越权 401。
- WB-0342 [P1] phase·V mod.rs:523 query 解码→统一解析；缺失 400。
- WB-0343 [P1] phase·S mod.rs:532 phase/algorithm/degrade 映射→DTO serde 单一来源；状态矩阵。
- WB-0344 [P1] phase·I mod.rs:521 GET 纯读→重复查询一致；bitmapVersion 单调。
- WB-0345 [P2] phase·E mod.rs:532 手写 json 而非 PhaseResponse→用 DTO；schema 校验。
- WB-0346 [P1] phase·P mod.rs:537 bitmapVersion 持久化→重启不回退；重载测试。
- WB-0347 [P2] phase·L mod.rs:521 轮询无限→限流/缓存 ETag；前端降频。
- WB-0348 [P2] phase·O mod.rs:521 无指标→phase 分布/对账次数；日志脱敏。
- WB-0349 [P1] phase·C dto/session.rs:304 PhaseResponse→真实 HTTP schema；golden。
- WB-0350 [P1] phase·X 前端任务恢复→按 phase 决定重试/新会话；shared-core 状态枚举对齐。
- WB-0351 [P0] heartbeat·A mod.rs:542 无 owner/token→认证；伪造心跳不得续期。
- WB-0352 [P1] heartbeat·V mod.rs:543 本地 Hb 忽略 DTO phase→用 HeartbeatRequest；bitmapVersion 范围校验。
- WB-0353 [P1] heartbeat·S mod.rs:560 任意态都续期→终态拒绝/幂等；Paused 恢复语义。
- WB-0354 [P1] heartbeat·I mod.rs:560 version=max+1 可被客户端推高→服务端权威版本；重放心跳不推进。
- WB-0355 [P2] heartbeat·E mod.rs:573 手写 json→HeartbeatResponse DTO；错误信封。
- WB-0356 [P1] heartbeat·P mod.rs:564 每次心跳写 meta→节流/批量写；磁盘寿命测试。
- WB-0357 [P1] heartbeat·L mod.rs:542 无频率限制→每会话最小间隔；洪泛限流。
- WB-0358 [P2] heartbeat·O mod.rs:563 last_activity 无指标→超时/续期计数；日志采样。
- WB-0359 [P1] heartbeat·C dto/session.rs:322 phase 必填→真实 HTTP 契约；版本对账测试。
- WB-0360 [P0] heartbeat·X desktop/send.rs 无心跳任务→SessionDriver/平台心跳接线；超时 Paused/恢复 E2E。
- WB-0361 [P0] abort·A mod.rs:673 知 sessionId 即可中止→owner/签名认证；越权 401。
- WB-0362 [P1] abort·V mod.rs:674 本地 Abort 忽略 reason→用 AbortRequest；reason 限长/脱敏。
- WB-0363 [P1] abort·S mod.rs:690 终态 Abort 非法→幂等返回已终态；状态矩阵。
- WB-0364 [P1] abort·I mod.rs:704 重复 abort 清理→幂等；cancelled 计数第二次 0。
- WB-0365 [P2] abort·E mod.rs:714 响应无 reason→typed AbortResponse；前端文案用 core CleanupTrigger。
- WB-0366 [P0] abort·P mod.rs:704 只清 core 内存/磁盘→平台取消在途/临时文件/UI 进度；CleanupPlan 全执行。
- WB-0367 [P1] abort·L mod.rs:673 无锁外 IO→清理锁外；并发 abort/chunk 测试。
- WB-0368 [P2] abort·O mod.rs:705 日志 sessionId 明文→摘要；取消原因指标。
- WB-0369 [P1] abort·C dto/session.rs:411 AbortRequest→真实 HTTP 中止/重复/越权测试。
- WB-0370 [P0] abort·X desktop/pairing/auth.rs:286 legacy cancel→切 V4 abort；App.vue cancelReceive 两步走。
- WB-0371 [P0] receipt·A mod.rs:1139 客户端可写终态→接收端内部生成/签名回执；伪造 completed 拒绝。
- WB-0372 [P1] receipt·V mod.rs:1151 tasks 无数量/字段校验→上限/relPath 一致性/size/mtime 校验。
- WB-0373 [P1] receipt·S mod.rs:1158 终态单调保持→非终态→终态需校验证据；状态矩阵。
- WB-0374 [P1] receipt·I mod.rs:1165 同终态重复写盘→幂等不重复写；乱序拒绝列表稳定。
- WB-0375 [P1] receipt·E mod.rs:1177 rejected 注入非 schema 字段→TaskListResponse 补 rejected 或独立 DTO；schema。
- WB-0376 [P1] receipt·P mod.rs:1162 set_receipt 读改写→批量事务；崩溃恢复终态一致。
- WB-0377 [P1] receipt·L mod.rs:1151 大 tasks 数组→限长；锁外写盘。
- WB-0378 [P2] receipt·O mod.rs:1165 终态无事件→task-receipt 事件；前端历史刷新。
- WB-0379 [P1] receipt·C dto/session.rs:370 TaskReceipt→真实 HTTP 终态单调测试。
- WB-0380 [P0] receipt·X desktop/send.rs 不查 tasks→发送完成前拉取接收端终态；App.vue 按文件更新快照。
- WB-0381 [P1] tasks·A mod.rs:1185 无 owner→认证；越权 401。
- WB-0382 [P1] tasks·V mod.rs:1186 query 解码→统一解析；缺失 400。
- WB-0383 [P1] tasks·S mod.rs:1247 无回执按进度猜→queued/transferring/cancelled 与状态机一致；终态后不得 transferring。
- WB-0384 [P1] tasks·I mod.rs:1185 GET 纯读→排序稳定；重复查询一致。
- WB-0385 [P2] tasks·E mod.rs:1195 TaskListResponse→错误信封；空会话语义。
- WB-0386 [P1] tasks·P mod.rs:1244 receipts 重载→重启终态可查；宽限策略。
- WB-0387 [P2] tasks·L mod.rs:1239 大文件列表→分页/摘要；内存上限。
- WB-0388 [P2] tasks·O mod.rs:1185 无指标→终态分布；日志脱敏。
- WB-0389 [P1] tasks·C dto/session.rs:399→真实 HTTP 多文件/abort/完成矩阵。
- WB-0390 [P0] tasks·X 前端进度/历史→以 tasks 为唯一终态投影；shared-core session-store 对齐。
- WB-0391 [P0] manifest·A sync_api.rs:203 只 deviceId→认证；未配对不得枚举文件。
- WB-0392 [P1] manifest·V sync_api.rs:207 query 解码→统一解析；缺失 400。
- WB-0393 [P1] manifest·S sync_api.rs:211 allows_transfer→Revoking/Revoked 拒绝；在线性独立。
- WB-0394 [P1] manifest·I sync_api.rs:203 GET 纯读→清单版本/ETag；重复读一致。
- WB-0395 [P1] manifest·E sync_api.rs:214 空清单与未扫描不分→available/generatedAt/version 明确；前端不误判全量。
- WB-0396 [P0] manifest·P sync_api.rs:115 local 由平台推入→接收目录扫描持久化；重启含 delete/ 墓碑。
- WB-0397 [P1] manifest·L sync_api.rs:119 克隆整清单→大清单分页/流式；内存上限。
- WB-0398 [P2] manifest·O sync_api.rs:203 无扫描指标→文件数/耗时/截断告警。
- WB-0399 [P1] manifest·C dto/sync.rs:59 Manifest→真实 HTTP+golden；delete/ 墓碑用例。
- WB-0400 [P0] manifest·X desktop/src/App.vue:2260/shared-core sync.ts→消费 V4 Manifest；不再用 legacy PeerManifest 形状。
- WB-0401 [P0] chunk-status·A sync_api.rs:230 无 owner→认证；越权 401。
- WB-0402 [P1] chunk-status·V sync_api.rs:234 sessionId/fileId→统一 query；缺失 400。
- WB-0403 [P1] chunk-status·S sync_api.rs:243 终态会话→返回完整快照/明确过期；状态矩阵。
- WB-0404 [P1] chunk-status·I sync_api.rs:263 nextChunk 第一个缺口→乱序/缺口/全齐测试；不得返回已收数。
- WB-0405 [P1] chunk-status·E sync_api.rs:266 fileComplete 用 incomplete_reason→缺哈希不得 true；四态联动。
- WB-0406 [P0] chunk-status·P sync_api.rs:254 confirmed 重载→重启续传索引一致；.part offset 联动。
- WB-0407 [P2] chunk-status·L sync_api.rs:259 大文件 received 数组→位图/分页；上限。
- WB-0408 [P2] chunk-status·O sync_api.rs:230 无指标→续传命中率；日志采样。
- WB-0409 [P1] chunk-status·C dto/sync.rs:131→真实 HTTP 乱序/缺口/完成测试。
- WB-0410 [P0] chunk-status·X desktop/transfer/send.rs:1050 调 /sync/chunk-status 不存在→改 V4 端点；mobile getChunkStatus 同步。
- WB-0411 [P0] sync-dir·A sync_api.rs:288 只 deviceId→认证；未配对拒绝。
- WB-0412 [P0] sync-dir·V sync_api.rs:292 targetDir 路径闸→Windows 扩展闸；rootId/strategy 枚举；越界 400。
- WB-0413 [P1] sync-dir·S sync_api.rs:304 delete/ 拒绝保持→映射变更不影响进行中会话；策略切换语义。
- WB-0414 [P1] sync-dir·I sync_api.rs:316 重复 put→幂等；返回映射版本。
- WB-0415 [P1] sync-dir·E sync_api.rs:318 响应无 schema→补 SyncDirResponse DTO；peerManifest 形状一致。
- WB-0416 [P1] sync-dir·P sync_api.rs:138 dirs 不落盘→持久化映射；重启恢复。
- WB-0417 [P1] sync-dir·L sync_api.rs:280 无大小限→targetDir/rootId 限长；请求体上限。
- WB-0418 [P2] sync-dir·O sync_api.rs:316 映射变更审计→日志/事件；脱敏路径。
- WB-0419 [P1] sync-dir·C dto/sync.rs:153 请求只有→补响应 schema；真实 HTTP。
- WB-0420 [P1] sync-dir·X desktop/transfer/store.rs:539/mobile sendSyncDir→统一 V4 DTO；前端目录名投影。
- WB-0421 [P0] move-to-delete·A sync_api.rs:340 只 deviceId→认证+mirror 策略授权；伪造删除拒绝。
- WB-0422 [P0] move-to-delete·V sync_api.rs:348 路径闸不足→Windows 扩展闸；relPaths 上限；rejected 显式。
- WB-0423 [P0] move-to-delete·S sync_api.rs:355 只改清单→真实文件假删除+清单同源；失败不得报 moved。
- WB-0424 [P1] move-to-delete·I sync_api.rs:156 AlreadyDeleted 幂等→重复请求不嵌套 delete/delete；测试。
- WB-0425 [P1] move-to-delete·E sync_api.rs:365 moved 数组 vs desktop 期待数字→typed MoveResult；逐路径结果。
- WB-0426 [P0] move-to-delete·P sync_api.rs:161 内存清单重启丢→墓碑持久化；重启不复活。
- WB-0427 [P1] move-to-delete·L sync_api.rs:347 大批量锁内逐条→批量事务/锁外 IO；上限。
- WB-0428 [P2] move-to-delete·O sync_api.rs:360 排序保持→删除审计日志；用户确认记录。
- WB-0429 [P1] move-to-delete·C 请求有 schema 响应无→补响应 schema；真实 HTTP 假删除 E2E。
- WB-0430 [P0] move-to-delete·X desktop/transfer/mod.rs:384 legacy files 字段→切 relPaths/V4；App.vue 镜像确认联动。
- WB-0431 [P0] disconnect·A sync_api.rs:399 无认证→签名/会话认证；伪造断开拒绝。
- WB-0432 [P1] disconnect·V sync_api.rs:394 deviceId 校验→格式闸；缺失 400。
- WB-0433 [P1] disconnect·S sync_api.rs:404 不动 trust 保持→只 presence Offline+该 owner 会话 abort；矩阵。
- WB-0434 [P1] disconnect·I sync_api.rs:390 重复断开→幂等；abortedSessions 第二次空。
- WB-0435 [P2] disconnect·E sync_api.rs:434 响应无 schema→DisconnectResponse DTO；错误信封。
- WB-0436 [P1] disconnect·P sync_api.rs:418 锁内写盘→锁外 CleanupPlan；崩溃恢复一致。
- WB-0437 [P1] disconnect·L sync_api.rs:410 遍历全会话→按 owner 索引；大会话表不阻塞。
- WB-0438 [P2] disconnect·O sync_api.rs:405 presence 变更事件→peer-disconnected 统一；日志。
- WB-0439 [P1] disconnect·C dto/sync.rs:189 请求只有→补响应 schema；真实 HTTP。
- WB-0440 [P1] disconnect·X desktop/store.rs send_disconnect/mobile→统一 V4；前端连接态投影。

### B4 传输、文件与 Windows IO（WB-0441..0560）

- WB-0441 [P0] core/transfer/session.rs:275 resume 后仍 Preparing→提供 resume 后正确 Step；断点续传纯状态测试。
- WB-0442 [P0] core/transfer/session.rs:425 Prepared 后留在 Preparing 等 InitAdvanced→平台必须 feed Initialized；E2E 驱动循环。
- WB-0443 [P1] core/transfer/session.rs:507 BlockSent 不写 confirmed→基础块完成换算 piece；降级进度测试。
- WB-0444 [P1] core/transfer/session.rs:774 terminate 终态再 abort 报错→幂等吸收迟到取消；状态矩阵。
- WB-0445 [P1] core/transfer/session.rs:410 now_unix u32→u64/Time 类型；2106/回拨测试。
- WB-0446 [P1] core/transfer/session.rs:683 absorb_confirmed 静默丢越界→非法位图报错/对账；恶意 peer 测试。
- WB-0447 [P1] core/transfer/session.rs:819 expect_front 只队首→并发在途结果按 index 归并或明确串行；并发契约。
- WB-0448 [P1] core/transfer/session.rs:390 Degrading 返回 Done→内部瞬态不得暴露 Done；降级 E2E。
- WB-0449 [P1] core/transfer/session.rs:326 outcome Failed/Aborted 一律 Inconclusive→区分算法失败与用户取消；降级记忆测试。
- WB-0450 [P1] core/transfer/session.rs:52 Step 无 fileId/sessionId→多文件调度上下文入 Step；平台不再猜。
- WB-0451 [P1] core/transfer/chunk.rs:86 ChunkPlan.algorithm 与 driver.algorithm 可分叉→单一算法来源；降级一致性。
- WB-0452 [P1] core/transfer/chunk.rs:103 piece_range assert 越界→Result/范围闸；网络输入不得 panic。
- WB-0453 [P2] core/transfer/chunk.rs:205 weak_checksum 每字节取模→分块累加/标准 Adler；性能基准。
- WB-0454 [P1] core/transfer/chunk.rs:256 compute_chunk_diff 未用 weak→弱筛仅优化不改正确性；双校验测试。
- WB-0455 [P1] core/transfer/chunk.rs:175 blocks_to_pieces 可切回主算法→与会话内不回切 invariant 对齐；删除/限测试用途。
- WB-0456 [P1] core/transfer/degrade.rs:318 AlreadyBasic 吸收所有信号→基础失败必须能 Fail；兜底失败 E2E。
- WB-0457 [P1] core/transfer/degrade.rs:534 streak 无饱和→saturating_add；洪泛信号测试。
- WB-0458 [P1] core/transfer/degrade.rs:496 restore 不校验 streak/prefer 组合→非法持久化数据规范化；迁移测试。
- WB-0459 [P1] core/transfer/degrade.rs:481 记忆不序列化但平台需持久化→提供显式投影 DTO；桌面落库。
- WB-0460 [P1] core/transfer/degrade.rs:665 progress_text 重传数=wasted→pending/wasted 文案准确；UI 快照测试。
- WB-0461 [P1] core/transfer/schedule.rs:72 先全局后 peer 可占全局等 peer→按固定顺序/尝试释放；死锁/饥饿测试。
- WB-0462 [P1] core/transfer/schedule.rs:62 peer_chunk map 无清理→peer 移除/TTL；长期运行内存测试。
- WB-0463 [P1] core/transfer/schedule.rs:51 with_limits 0 许可→参数校验；不得永久挂起。
- WB-0464 [P2] core/transfer/schedule.rs:153 full_jitter 0..exp 与文档含上限→统一区间；向量测试。
- WB-0465 [P1] desktop/scheduler.rs:294 硬编码 3/4/12→用 core 常量/配置；多接收端压测。
- WB-0466 [P1] desktop/scheduler.rs:301 add_peer 同 IP:port 覆盖→deviceId+sessionId 键；并发会话测试。
- WB-0467 [P1] desktop/scheduler.rs:342 check_timeouts 用 find(':') 拆 IPv6→SocketAddr/结构化键；IPv6 测试。
- WB-0468 [P1] desktop/scheduler.rs:387 hash_file_sha256 读错返空哈希→错误上抛；不得缓存假哈希。
- WB-0469 [P1] desktop/scheduler.rs:231 Merkle 奇数提升 vs core 复制→统一 BEP 规则；跨端根向量。
- WB-0470 [P1] desktop/scheduler.rs:173 piece 哈希=16K 块根 vs core piece SHA→统一叶子定义；大文件向量。
- WB-0471 [P0] core/transfer/atomic_file.rs:142 part_path 未限最终路径→先安全闸再 part；Windows 越界矩阵。
- WB-0472 [P0] core/transfer/atomic_file.rs:177 commit_rename 前未 fsync part→写后 sync_all 再 rename；崩溃注入。
- WB-0473 [P1] core/transfer/atomic_file.rs:163 choose_commit_mode 文本父目录比较→规范化/同卷判断；跨卷测试。
- WB-0474 [P1] core/transfer/atomic_file.rs:197 copy_delete 非原子→Windows 禁用或显式降级；读取窗口告警。
- WB-0475 [P1] core/transfer/atomic_file.rs:218 committed_bytes 吞错误→区分不存在/权限/IO；续传不得盲从 0。
- WB-0476 [P1] core/transfer/atomic_file.rs:230 restore_mtime 负值钳 0→保留合法负时间/显式错误；1970 前文件测试。
- WB-0477 [P1] core/transfer/atomic_file.rs:98 conflict_rename_path 同秒碰撞→计数器/唯一后缀；并发冲突测试。
- WB-0478 [P0] core/transfer/atomic_file.rs:87 size+mtime 判 identical→加内容哈希/版本；同大小同 mtime 损坏不得跳过。
- WB-0479 [P1] core/transfer/atomic_file.rs:245 write_committed 失败留 part→清理/恢复策略；残留扫描。
- WB-0480 [P1] core/transfer/cleanup.rs:197 is_residue_name 不认 `.part.*`→纳入本应用 part 模式；不得误删用户文件。
- WB-0481 [P0] core/transfer/cleanup.rs:212 sweep_into 跟随目录符号链接→不跟随 reparse/junction；越界清理测试。
- WB-0482 [P1] core/transfer/cleanup.rs:206 sweep_residue 同步递归→spawn_blocking/取消/深度上限；大目录不卡。
- WB-0483 [P1] core/transfer/cleanup.rs:141 顺序 MarkSessionRecord 在 CancelTasks 前→按文档先标未确认再记录；执行器测试。
- WB-0484 [P1] core/server/mod.rs:639 execute_cleanup_plan 跳过资源动作→平台执行器补齐；取消/许可/心跳 E2E。
- WB-0485 [P1] core/transfer/cancel.rs:114 feed 乱序返回 None 静默→Result 错误；调用方不得吞。
- WB-0486 [P1] desktop/src/App.vue:2202 cancelReceive 停整个服务→按会话 abort；服务保持可用；两步走文案。
- WB-0487 [P1] desktop/transfer/send.rs:847 _cancel 未检查→每块/每次重试 select 取消；取消延迟测试。
- WB-0488 [P1] desktop/transfer/send.rs:709 try_collect 首错即停→收集逐文件结果/取消在途；部分成功快照正确。
- WB-0489 [P1] desktop/transfer/send.rs:555 futs 先全建含 8MB data→惰性流式/信号量内读；内存峰值测试。
- WB-0490 [P1] desktop/transfer/send.rs:624 vec![0;csize] 网络输入大小→本地上限/分块读；OOM 防护。
- WB-0491 [P1] desktop/transfer/send.rs:80 upload_single 70s 总超时→按块 idle timeout；大文件慢网测试。
- WB-0492 [P1] desktop/transfer/send.rs:960 extract_status_code 解析字符串→typed HttpError；不得正则猜状态。
- WB-0493 [P1] desktop/transfer/send.rs:985 MAX_RETRIES=5 与 core 3 不一致→统一 retry 常量；降级测试。
- WB-0494 [P1] desktop/transfer/send.rs:1021 重试用握手退避→core chunk_backoff；热路径延迟测试。
- WB-0495 [P1] desktop/transfer/send.rs:768 retry_bucket 首次也占→仅重试占独立配额；正常块不被饿死。
- WB-0496 [P1] desktop/transfer/send.rs:507 total_units 含被拒绝/跳过→以 accepted 计划计算；进度不得 <100 假完成。
- WB-0497 [P1] desktop/transfer/send.rs:869 进度按密文 bytes→明文/密文双计数；UI 百分比准确。
- WB-0498 [P1] desktop/transfer/send.rs:583 skipping 事件 bytes=0→累计字节正确；跳过也推进总进度。
- WB-0499 [P1] desktop/transfer/send.rs:791 update_progress 每块覆盖整文件→累计 sentBytes/pieces；并发写测试。
- WB-0500 [P1] desktop/session_store.rs:255 update_progress 全量 persist→节流/增量 WAL；磁盘 IO 基准。
- WB-0501 [P0] desktop/transfer/util.rs:349 scan_directory 无授权根→命令层校验用户选择根；不得任意读盘。
- WB-0502 [P1] desktop/transfer/util.rs:362 递归无深度→深度/条目上限+取消；深树栈溢出测试。
- WB-0503 [P0] desktop/transfer/util.rs:393 只查 is_symlink→Windows junction/reparse 不跟随；越界扫描测试。
- WB-0504 [P1] desktop/transfer/util.rs:397 内部文件过滤旧模式→统一 core 残留/内部命名；不得漏 .part。
- WB-0505 [P1] desktop/transfer/util.rs:380 to_string_lossy 文件名→OsString/UTF-8 策略；非 UTF-8 文件显式报告。
- WB-0506 [P1] desktop/transfer/util.rs:419 mtime  pre-epoch unwrap_or0→保留负时间/错误；1970 前测试。
- WB-0507 [P1] desktop/transfer/util.rs:19 pct_encode 不保留 ~ 与 mobile 不一致→统一 RFC3986 子集；跨端向量。
- WB-0508 [P1] desktop/transfer/util.rs:36 pct_decode lossy→严格 UTF-8/拒绝非法；路径不得替换字符。
- WB-0509 [P0] desktop/transfer/util.rs:55 sanitize_rel_path 静默丢 `..`→拒绝而非改写；与 core 闸一致。
- WB-0510 [P0] desktop/transfer/util.rs:68 resolve_target_path 空 rel 可落根→空/非法路径拒绝；Windows 矩阵。
- WB-0511 [P1] desktop/transfer/util.rs:91 大小写冲突全目录扫描→目标文件名查询/索引；大目录性能。
- WB-0512 [P1] desktop/transfer/util.rs:129 identical 只看 size/mtime→内容哈希/版本；损坏文件不得跳过。
- WB-0513 [P1] desktop/transfer/util.rs:226 set_file_mtime 只写权限→Windows 必要权限/错误处理；只读文件测试。
- WB-0514 [P1] desktop/transfer/util.rs:241 format_mmddhhmmss 失败全零→唯一后缀兜底；冲突测试。
- WB-0515 [P0] Windows 长路径：接收/扫描/part 未统一 `\\?\` 策略→>260 路径 E2E；UNC 长路径。
- WB-0516 [P0] Windows ADS：`file.txt:stream` 未拒→路径闸拒绝流语法；落盘测试。
- WB-0517 [P0] Windows 保留名 CON/NUL/COM1 未拒→按段拒绝/转义策略；不得打开设备。
- WB-0518 [P1] Windows 尾点/空格规范化差异→发送/接收同一规范化；碰撞测试。
- WB-0519 [P1] Windows 文件占用 ERROR_SHARING_VIOLATION→有限退避重试/跳过报告；杀软占用测试。
- WB-0520 [P1] Windows 替换只读/系统属性→commit 前属性处理/显式拒绝；不得静默覆盖。
- WB-0521 [P1] Windows 跨卷接收目录→同目录 part+同卷 rename；跨卷配置拒绝/降级告警。
- WB-0522 [P1] Windows 网络盘/UNC 断连→IO 错误分类/会话 Paused；重连后续传。
- WB-0523 [P1] Windows OneDrive/云占位文件→召回策略/跳过标记；扫描不得触发大规模下载。
- WB-0524 [P1] Windows 硬链接→扫描 identity 分组/不重复传；接收不保留硬链接语义需声明。
- WB-0525 [P1] Windows 稀疏文件→SEEK_HOLE/FSCTL 检测或按普通流；不得膨胀磁盘。
- WB-0526 [P1] Windows 权限/ACL→接收目录写权限预检；失败可读错误。
- WB-0527 [P1] Windows 防火墙→首次监听提示/规则文档；入站仅专用网络可选。
- WB-0528 [P1] Windows 休眠/唤醒→网络变化事件重建 socket/对账；唤醒续传 E2E。
- WB-0529 [P1] Windows 多用户同机→单实例按用户会话；端口/存储隔离。
- WB-0530 [P1] Windows 高 DPI/多显示器 ball→物理/逻辑坐标统一；缩放回归。
- WB-0531 [P1] desktop/transfer/send.rs:124 metadata 失败 size=0→错误上抛/跳过报告；不得传空文件。
- WB-0532 [P1] desktop/transfer/send.rs:47 去重只看 relPath 字符串→规范化/大小写/文件身份；碰撞报告。
- WB-0533 [P1] desktop/transfer/send.rs:241 batch_tmp 用时间戳命名→CSPRNG 临时名；并发/清理测试。
- WB-0534 [P1] desktop/transfer/send.rs:250 小文件全读内存→批大小字节上限；流式打包。
- WB-0535 [P1] desktop/transfer/send.rs:1036 pack_batch 长度 u32/u64 无上限→格式闸/真实 tar；恶意大文件名测试。
- WB-0536 [P1] desktop/transfer/send.rs:125 tiny 阈值 10KB 与 core 一致但 batch20→用 core TINY_BATCH_SIZE 或取消聚合。
- WB-0537 [P1] desktop/transfer/send.rs:116 LARGE_THRESHOLD 本地常量→core 常量；分类矩阵测试。
- WB-0538 [P1] desktop/transfer/send.rs:267 sizes 用 unwrap_or(0)→错误分类；空文件单独路径。
- WB-0539 [P1] core/server/mod.rs:858 piece_count(0)=0 但 handle_chunk 需块→空文件 prepare 即完成/专用路径；空文件 E2E。
- WB-0540 [P1] 加密文件 size 字段语义→明文字节/密文字节分离 DTO；哈希基于明文；跨端测试。
- WB-0541 [P1] core/transfer/piece_cache.rs:64 Windows dev=0/inode=creation_time→volume serial+file index 或路径+版本；同卷碰撞测试。
- WB-0542 [P1] core/transfer/piece_cache.rs:105 缓存无上限→LRU/字节上限；长期运行内存测试。
- WB-0543 [P1] core/transfer/piece_cache.rs:116 read_piece 空数据也哈希→错误上抛不缓存；占用文件测试。
- WB-0544 [P1] core/transfer/piece_cache.rs:35 mtime+size 键内容同 mtime 变化→强校验兜底/显式 invalidate；篡改测试。
- WB-0545 [P1] desktop/transfer/send.rs:301 每次 send 新建 cache→应用级共享有界缓存；命中率指标。
- WB-0546 [P1] core/crypto/merkle.rs:147 verify_piece 不绑定 proof.index/树大小→校验 index/proof 长度/叶数；伪造证明测试。
- WB-0547 [P1] core/crypto/merkle.rs:59 hash_pair 无叶/内节点域分隔→BEP-0052 前缀；第二原像测试。
- WB-0548 [P1] core/crypto/merkle.rs:23 空树全零→空文件专用语义；不得与普通根混淆。
- WB-0549 [P1] core/server/mod.rs 接收未用 Merkle proof→每 piece 校验 proof/root；坏块定位。
- WB-0550 [P1] desktop/scheduler.rs:146 MerkleTree::new 过滤非法 hex 静默→错误上抛；清单不得短少。
- WB-0551 [P1] 传输并发：buffer_unordered(8) 与 core 12/4→单一调度器；压测 CPU/内存/网络。
- WB-0552 [P1] 磁盘 IO 在 tokio worker：core handle_chunk std::fs→spawn_blocking/专用 IO 池；延迟基准。
- WB-0553 [P1] 全局 SessionStore inner Mutex 跨 IO→按会话分片锁/actor；并发会话压测。
- WB-0554 [P1] 大清单 HashMap 克隆→Arc 快照/增量；内存基准。
- WB-0555 [P1] 进度事件每 250ms/文件→组级聚合节流；前端渲染帧率测试。
- WB-0556 [P1] 历史 add_transfer 同步 DB 在 async→spawn_blocking；失败不阻断但告警。
- WB-0557 [P1] 临时文件清理只在正常路径→RAII/启动 sweep；崩溃残留测试。
- WB-0558 [P1] 接收目录变更时旧会话 base_dir→会话绑定 root 版本；切换目录不得写旧根。
- WB-0559 [P1] 文件名冲突策略入 DTO→finalName 回执；前端显示冲突副本。
- WB-0560 [P1] 传输完成判据统一→core 提供 session_summary；桌面/前端不再各自算。

### B5 配对、加密与身份（WB-0561..0680）

- WB-0561 [P0] desktop/identity.rs:221 deviceId=FNV(MachineGuid) 可推导/碰撞→随机安装 deviceId 持久化；MachineGuid 仅兜底特征。
- WB-0562 [P0] desktop/identity.rs:39 unknown-machine 兜底同码→兜底随机安装 ID；不得全网相同身份。
- WB-0563 [P0] desktop/identity.rs:137 日志输出哈希种子可逆推连接码→删除种子日志；脱敏审计测试。
- WB-0564 [P0] desktop/identity.rs:106 默认连接码由公开特征确定性生成→首次随机 CSPRNG 码；默认码不来自 deviceId。
- WB-0565 [P1] desktop/identity.rs:155 self_code.txt 明文→按 D1 保护；前端只展示。
- WB-0566 [P1] desktop/identity.rs:233 config_dir 失败回 temp→错误上抛；不得把身份写公共 temp。
- WB-0567 [P1] desktop/identity.rs:15/reg.exe 解析本地化输出→Windows API 注册表读取或严格解析；超时/拒绝测试。
- WB-0568 [P1] desktop/identity.rs:49 kill 后不 wait→回收子进程；不得留僵尸/句柄。
- WB-0569 [P1] desktop/identity.rs:269 db_encryption_key 每次启动 600k→缓存/安装密钥；启动延迟基准。
- WB-0570 [P0] desktop/db.rs:76 PRAGMA key 无 SQLCipher 却称加密→按 D1/D5 真实加密或明确明文+ACL；不得假安全。
- WB-0571 [P1] desktop/identity.rs:254 set_device_name 无长度/字符→闸+原子写；alias 同步 core。
- WB-0572 [P1] core/identity.rs:83 generate_connection_code 公开 ID 派生秘密→仅兼容旧展示；新配对用随机码。
- WB-0573 [P1] core/identity.rs:131 ConnectionCodeCache expect 锁→毒锁策略/错误；不得 panic 主链。
- WB-0574 [P1] core/identity.rs:175 normalize 保留所有 A-Z0-9 但字母表去混淆→输入 0/O/1/I/L 映射策略明确；跨端向量。
- WB-0575 [P1] core/identity.rs:243 restore 只验 deviceId 长度→校验私钥曲线/公钥匹配；损坏身份显式重建流程。
- WB-0576 [P0] core/identity.rs:271 signing_key_bytes 公开导出→限制 crate/平台存储接口；日志 Debug 已脱敏保持。
- WB-0577 [P1] core/identity.rs:224 DeviceIdentity 无 serde→平台持久化投影 DTO；私钥加密落盘。
- WB-0578 [P1] desktop/transfer/receive.rs:133 restore 失败生成新身份→启动失败/修复 UI；不得静默换身份。
- WB-0579 [P1] desktop/db.rs:494 load_sig_key 只查长度→曲线验证/公钥匹配；脏数据隔离。
- WB-0580 [P1] desktop/db.rs:445 save_static_key 无条件覆盖→仅初始化/重置；审计。
- WB-0581 [P1] desktop/transfer/mod.rs:229 static_key/sig_key 双缓存→core identity 单权威；桌面只缓存句柄。
- WB-0582 [P1] 身份重置：deviceId 不变但密钥变→明确“新身份”是否换 deviceId；对端旧记录吊销。
- WB-0583 [P1] 设备别名与身份分离→alias 变更不影响 trust；probe 投影测试。
- WB-0584 [P1] 多 Windows 用户/克隆镜像→安装 ID 不随镜像克隆；首次启动检测。
- WB-0585 [P1] 身份备份/恢复→导出加密备份/恢复后配对可用；用户确认。
- WB-0586 [P1] 连接码展示分组/大小写→UI 规范化但秘密原始字节一致；输入向量。
- WB-0587 [P1] 连接码刷新与旧传输→KeyRing 保留旧 key；刷新门禁 transfer_count 真实。
- WB-0588 [P1] 连接码刷新通知→core disconnect/re-pair 事件；不得只 mpsc 死通道。
- WB-0589 [P1] 配对记录 fingerprint 字段混用连接码/公钥指纹→DTO 分离 codeFingerprint/keyFingerprint；前端迁移。
- WB-0590 [P1] 公钥指纹展示→SHA-256 公钥短码/SAS；用户可核对。
- WB-0591 [P0] core/server/control.rs:613 所有 peer 同 code 派生同 secret→每配对独立高熵 secret；跨 peer 令牌复用拒绝。
- WB-0592 [P0] core/pairing/token.rs:204 consume 只按 jti→按 (kind,sub,jti)；跨设备/用途 DoS 测试。
- WB-0593 [P0] core/pairing/token.rs:143 verify 忽略 exp 且 prune 按墙钟→过期令牌不得复活；单调清理/最大寿命。
- WB-0594 [P0] core/server/control.rs:662 path B 不比对 claims.sub/nonce 与 sess→绑定校验；令牌挪用拒绝。
- WB-0595 [P1] core/pairing/token.rs:130 mint 无 token 大小上限→verify 前限长；内存防护。
- WB-0596 [P1] core/pairing/token.rs:44 固定头好→保持不解析 alg；模糊测试。
- WB-0597 [P1] core/server/control.rs:295 issued_nonces HashSet 无 TTL→时间戳+来源限流；过期清理。
- WB-0598 [P1] core/server/control.rs:321 满员随机驱逐→FIFO/LRU 按签发时间；合法握手不被踢。
- WB-0599 [P1] core/server/control.rs:483 cached_challenge 幂等响应含 secret?→确保响应不含密钥；只回放公开部分。
- WB-0600 [P1] core/server/control.rs:501 HandshakeSession 存 pairing_secret→最小化/零化/TTL；内存审计。
- WB-0601 [P1] core/server/control.rs:397 prune_sessions 未接线→定时任务；内存有界。
- WB-0602 [P1] core/server/control.rs:424 consumed.prune 未接线→定时清理；重启后重放策略。
- WB-0603 [P0] 握手重放跨重启→consumed/nonce 持久化或短期一次性码；重启重放测试。
- WB-0604 [P1] core/pairing/transcript.rs:91 path_a_key salt 裸拼接→固定长度已保证但入向量；域分隔测试。
- WB-0605 [P1] core/pairing/transcript.rs:50 frame u16 长度→超限拒绝；模糊测试。
- WB-0606 [P1] desktop/transfer/v4.rs:15 v4_frame 重复实现→用 core transcript；跨端向量。
- WB-0607 [P1] desktop/transfer/v4.rs:25 path_a_key 重复→core；删除桌面密码学。
- WB-0608 [P1] core/pairing/machine.rs:96 Revoked→Repair→None→重新配对必须用户显式；UI 流程。
- WB-0609 [P1] core/pairing/machine.rs:167 should_emit_beacon 含 Revoking→与 bcpd 只 ACTIVE 不一致；统一策略。
- WB-0610 [P1] core/pairing/trust.rs:70 trust_version saturating→溢出策略/重置生命周期；不得静默停增。
- WB-0611 [P1] core/pairing/trust.rs:77 note_peer_version max→回滚攻击检测/告警；版本单调。
- WB-0612 [P1] core/pairing/trust.rs:166 ResendUnpair 无执行者→平台重发通知；收敛 E2E。
- WB-0613 [P1] core/pairing/unpair.rs:128 feed settled 后 debug_assert→release 也返回错误；不得 UB/静默。
- WB-0614 [P1] core/pairing/unpair.rs:11 注释 24h vs token 30d→统一 TTL 文档/代码。
- WB-0615 [P1] desktop/transfer/store.rs:701 离线吊销立即删 secret→在途会话收尾/旧密钥解密策略；不得数据损坏。
- WB-0616 [P1] 吊销后会话→core 自动 abort 该 peer 会话；前端进度清理。
- WB-0617 [P1] 配对审批策略→autoAccept 仅接收文件，配对默认人工；配置入后端。
- WB-0618 [P1] 配对请求显示来源 IP/公钥指纹→防钓鱼；用户拒绝限流。
- WB-0619 [P1] 配对成功事件→paired-updated 含投影版本；前端不再 merge 回写。
- WB-0620 [P1] 配对失败原因→错误码映射 UI 文案；不得泄漏 oracle。
- WB-0621 [P0] desktop/crypto.rs:56 SHA256(code) 传输密钥→淘汰；D2 后高熵会话密钥。
- WB-0622 [P0] desktop/crypto.rs:150 storage key=PBKDF2(code)→安装随机密钥；连接码刷新不丢数据。
- WB-0623 [P0] desktop/crypto.rs:327 seal_stream_block 随机 nonce 无 AAD→core AEAD+AAD(session/file/index)；重排/重放测试。
- WB-0624 [P0] desktop/crypto.rs:301 LSBK 流格式与 core aead 不一致→单一格式/版本；跨端向量。
- WB-0625 [P1] desktop/crypto.rs:320 enc_output_size 空文件也 12B→与接收端/DTO 一致；空文件加密测试。
- WB-0626 [P1] desktop/crypto.rs:418 clen+TAG 溢出→checked_add；恶意头测试。
- WB-0627 [P1] desktop/crypto.rs:430 单块兼容路径 read_to_end 无上限→限长；DoS 测试。
- WB-0628 [P1] desktop/crypto.rs:253 encrypt 随机 nonce 碰撞概率→计数器 nonce+每文件 key；重用检测。
- WB-0629 [P1] core/crypto/aead.rs:25 encrypt 返回 Option 吞错→Result/CryptoError；调用方不得静默。
- WB-0630 [P1] core/crypto/aead.rs:17 每消息新建 LessSafeKey→密钥上下文复用；性能基准。
- WB-0631 [P1] core/crypto/kdf.rs:98 session info 字符串拼接→长度前缀/固定格式；跨端向量。
- WB-0632 [P1] core/crypto/kdf.rs:105 file key salt 空→按设计文档 L4；向量钉死。
- WB-0633 [P1] core/crypto/kdf.rs:66 derive_storage_key_with 公开低迭代→测试 feature 隔离；生产不得调用低值。
- WB-0634 [P1] core/crypto/kdf.rs:122 expect→常量保证但改 Result/const assert；审计。
- WB-0635 [P1] core/crypto/sign.rs:61 raw64 签名→与 Java/TS 统一；DER 转换层明确。
- WB-0636 [P1] core/crypto/sign.rs:48 压缩公钥 vs DTO 注释未压缩→统一线路编码；schema/向量。
- WB-0637 [P1] core/crypto/sign.rs:108 ECDH 不检查 contributory/零共享→p256 已验点；零共享拒绝测试。
- WB-0638 [P1] core/crypto/keyring.rs:33 derive Debug 泄密钥→手写 redacted；日志扫描。
- WB-0639 [P1] core/crypto/keyring.rs:65 同版本换 key 不入历史→版本必须单调或保留旧 key；轮换测试。
- WB-0640 [P1] core/crypto/keyring.rs:83 prune 未来 created_at 丢弃→时钟回拨策略；单调生日。
- WB-0641 [P1] core/crypto/keyring.rs:118 decrypt 按版本排序非 current first→明确 keyId 路由；不得逐 key oracle 放大。
- WB-0642 [P1] core/crypto/keyring.rs:110 is_empty 语义错→改名 has_previous；测试。
- WB-0643 [P1] core/crypto/mod.rs:40 手写 ct_eq→subtle/已审计常量时间；编译器审计。
- WB-0644 [P1] core/crypto/mac.rs:46 expect→HMAC 任意 key 保证但 Result 统一；审计。
- WB-0645 [P1] core/crypto/id.rs:18 手写 hex→hex crate/常量时间无关；统一工具。
- WB-0646 [P1] desktop/crypto.rs:216 compute_sas 未用→配对 SAS 展示或删除；不得死代码假安全。
- WB-0647 [P1] desktop/crypto.rs:90 derive_pairing_secret_v3 info 裸拼接→core transcript frame；向量。
- WB-0648 [P1] desktop/crypto.rs:125 derive_transfer_key_v3 salt=file_id→与 core L3/L4 不一致→统一密钥树。
- WB-0649 [P1] 加密能力 CAP_ENCRYPT 广告但未实现→能力位真实；协商失败不得假加密。
- WB-0650 [P1] 明文降级→用户显式配置+UI 标记+HMAC 完整性；默认不降级。
- WB-0651 [P1] 密钥零化→secret 类型 Drop zeroize（需依赖批准）或最小化克隆；审计。
- WB-0652 [P1] 密钥克隆过多→Arc<KeyHandle> 减少复制；内存审计。
- WB-0653 [P1] 私钥日志→Debug/Display 全红acted；grep 测试。
- WB-0654 [P1] token 日志→只落 jti 摘要；导出扫描。
- WB-0655 [P1] 连接码日志→mask 不留 4/8 字符；短码全掩码。
- WB-0656 [P1] 前端 localStorage 秘密→迁移后端；启动清理旧 desktop_pairings 秘密字段。
- WB-0657 [P1] self_code.txt/device_name.txt 原子写→临时+rename；崩溃恢复。
- WB-0658 [P1] 密钥文件 ACL→当前用户 only；安装时设置。
- WB-0659 [P1] DPAPI 绑定→CurrentUser 熵+安装 ID；换机恢复策略。
- WB-0660 [P1] SQLCipher 决策→若启用需 OpenSSL/构建门禁；不得半启用 PRAGMA key。
- WB-0661 [P1] 加密格式版本协商→DTO cryptoVersion/alg；旧格式只读迁移。
- WB-0662 [P1] 跨端测试向量→HKDF/PBKDF2/P256/AEAD/签名/Merkle 全量 golden。
- WB-0663 [P1] Java SHA256withECDSA DER→与 core raw64 转换；双向验签测试。
- WB-0664 [P1] WebCrypto ECDH→shared-core V2 删除后仅 UI；不再实现协议加密。
- WB-0665 [P1] 随机源统一→rand OsRng/getrandom；不得 Math.random 用于安全 ID。
- WB-0666 [P1] UUID sessionId→core new_session_id 64hex；前端/移动端统一。
- WB-0667 [P1] requestId→CSPRNG/UUID；贯穿 HTTP/IPC/日志。
- WB-0668 [P1] nonce 长度→32B 固定；hex/base64 编码单一。
- WB-0669 [P1] base64 版本→core/desktop base64 0.21/0.23 统一； workspace 依赖。
- WB-0670 [P1] pbkdf2 版本→desktop 0.13/core 0.12 世代冲突→统一 digest 世代。
- WB-0671 [P1] ring+p256 双密码栈→签名/ECDH 归 core 单栈；ring 仅 AEAD 或统一 RustCrypto。
- WB-0672 [P1] 密码学错误→统一 CryptoError；不得 String 到处传。
- WB-0673 [P1] 模糊测试→握手 DTO/token/路径/加密头 cargo-fuzz（依赖批准）或 proptest。
- WB-0674 [P1] 已知答案测试→RFC5869/PBKDF2/P256 向量不只打印不断言。
- WB-0675 [P1] desktop/crypto.rs:723 PBKDF2 向量只 eprintln→assert  expected；CI 门禁。
- WB-0676 [P1] 安全审计门禁→cargo audit/deny（依赖批准）；CI 阻断高危。
- WB-0677 [P1] 威胁模型文档→同网段攻击者/抓包/恶意 peer/本机用户边界；不得假称 TLS。
- WB-0678 [P1] 无 TLS 决策→局域网明文 HTTP 但应用层认证/加密；probe 公开信息最小化。
- WB-0679 [P1] 配对后连接码作废→一次性/轮换；旧码尝试限流。
- WB-0680 [P1] 重新配对迁移→旧 V2/V3 记录标记 legacy；用户确认后 Repair；不得自动 ACTIVE。

### B6 持久化、数据库与配置（WB-0681..0780）

- WB-0681 [P0] desktop/db.rs:115 迁移无事务→每版本 BEGIN/COMMIT+user_version 同事务；中断恢复测试。
- WB-0682 [P0] desktop/db.rs:156 重复 ALTER 靠忽略→按 pragma_table_info 检测；旧库/新库/半迁移矩阵。
- WB-0683 [P1] desktop/db.rs:60 SCHEMA_VERSION u32→PRAGMA 读取 i64 校验；降级版本拒绝启动。
- WB-0684 [P1] desktop/db.rs:168 每操作 PRAGMA journal_mode=WAL→打开时一次；连接池/每操作 busy_timeout。
- WB-0685 [P1] desktop/db.rs:52 Database.key 无效占位→按 D1/D5 真实密钥或移除假字段。
- WB-0686 [P1] desktop/db.rs:79 建表与迁移混在一个 batch→schema 模块/版本脚本；可测试。
- WB-0687 [P1] desktop/db.rs:97 paired_peers 列冗余 static_pub/manifest→按权威模型重构；迁移映射。
- WB-0688 [P0] desktop/db.rs:367 全删全插配对→UPSERT+删除差集；并发/崩溃不丢吊销。
- WB-0689 [P1] desktop/db.rs:343 13 元组参数→PeerRow struct；编译期防列序错。
- WB-0690 [P1] desktop/db.rs:393 SELECT 列序注释维护→结构化 row 映射/常量列名；测试。
- WB-0691 [P1] desktop/db.rs:397 manifest 损坏默认 {}→隔离/告警；不得静默丢快照。
- WB-0692 [P1] desktop/db.rs:405 ips JSON 损坏默认 []→校验数组/元素 IP；脏数据报告。
- WB-0693 [P1] desktop/db.rs:413 pending_revoke 损坏 Null→令牌校验/隔离；吊销不复活。
- WB-0694 [P1] desktop/db.rs:240 历史保留注释 50 实际 200→统一常量/配置；分页测试。
- WB-0695 [P1] desktop/db.rs:267 DELETE NOT IN 子查询→按 id 阈值删除；索引/性能。
- WB-0696 [P1] desktop/db.rs:254 file_count/bytes as i64→checked 转换/上限；溢出测试。
- WB-0697 [P1] desktop/db.rs:316 reset_all 无事务→单事务；失败回滚。
- WB-0698 [P1] desktop/db.rs:329 delete_transfer 不报存在性→返回 rows_affected；UI 反馈。
- WB-0699 [P1] desktop/db.rs:178 get_device 错误分类→NotFound vs DB 错误；前端提示。
- WB-0700 [P1] desktop/db.rs:216 save_device state 无限大→大小/ schema 闸；DB 膨胀防护。
- WB-0701 [P1] SQLite 索引→transfer_history(created_at), paired_peers(status)；查询计划测试。
- WB-0702 [P1] SQLite foreign_keys/check→status 枚举 CHECK；port 范围；脏数据拒绝。
- WB-0703 [P1] SQLite 连接池→r2d2/每线程连接上限（依赖批准）或单写者+多读；压测。
- WB-0704 [P1] SQLite busy_timeout 3000→统一策略/重试；SQLITE_BUSY 测试。
- WB-0705 [P1] SQLite WAL checkpoint→退出/定时 checkpoint；wal 文件膨胀测试。
- WB-0706 [P1] SQLite 备份→重置/迁移前自动备份；恢复演练。
- WB-0707 [P1] SQLite 损坏→integrity_check 启动抽检；损坏隔离/恢复 UI。
- WB-0708 [P1] DB 路径→app_data 权威；不得 temp 兜底。
- WB-0709 [P1] DB 秘密列→pairing_secret 加密 BLOB；磁盘扫描无明文。
- WB-0710 [P1] DB 日志→SQL 参数脱敏；不得落 secret/token。
- WB-0711 [P0] core/server/persist.rs:161 write_meta 读改写无版本→单写者/事务；并发 set_file/set_receipt 不丢。
- WB-0712 [P0] core/server/persist.rs:241 pieces append 两次 write→单行一次写+校验和；半行恢复测试。
- WB-0713 [P1] core/server/persist.rs:247 append 无 sync→按策略 flush/sync；崩溃丢块上限明确。
- WB-0714 [P1] core/server/persist.rs:337 重放跳过坏行→记录损坏位置/隔离；不得静默丢确认。
- WB-0715 [P1] core/server/persist.rs:349 重放不校验 file_id/piece 范围→恶意日志不得污染位图。
- WB-0716 [P1] core/server/persist.rs:280 remove_session 忽略错误→告警/重试；残留清理。
- WB-0717 [P1] core/server/persist.rs:289 load_all 终态清理→策略可配置；历史查询需求明确。
- WB-0718 [P1] core/server/persist.rs:130 last-manifest.tmp 固定名→唯一 tmp/并发写锁；并发测试。
- WB-0719 [P1] core/server/persist.rs:135 rename 后未 sync 目录→Windows/POSIX 持久化语义；崩溃测试。
- WB-0720 [P1] core/server/persist.rs:100 open 只建目录→权限/磁盘空间预检；失败降级明确。
- WB-0721 [P1] core/server/persist.rs:69 MetaFile 无 schema_version→版本迁移；旧文件兼容。
- WB-0722 [P1] core/server/persist.rs:82 PieceLine 无 seq/checksum→WAL 记录校验；截断恢复。
- WB-0723 [P1] core/server/persist.rs:109 sid 文件名→格式闸/哈希；穿越测试。
- WB-0724 [P1] core/server/persist.rs:185 read_meta blank→返回 Result；不得 blank 覆盖。
- WB-0725 [P1] core/server/persist.rs:49 失败只 warn→健康状态投影；UI 显示续传不可用。
- WB-0726 [P0] core/server/persist_pairing.rs:110 tmp 固定+并发 persist→单写者队列；最后写版本单调。
- WB-0727 [P0] core/server/persist_pairing.rs:128 损坏返回空→隔离备份+告警；吊销记录不得丢。
- WB-0728 [P1] core/server/persist_pairing.rs:40 PeerRecordJson snake_case→与 DTO camelCase 投影分离/版本。
- WB-0729 [P1] core/server/persist_pairing.rs:62 presence 字符串 JSON→枚举直接 serde；脏值拒绝。
- WB-0730 [P1] core/server/persist_pairing.rs:49 last_peer_status 不持久化→对账缓存策略明确；重启不误判。
- WB-0731 [P1] core/server/persist_pairing.rs:90 open 建 dir 父目录→路径权限；app_data 权威。
- WB-0732 [P1] core/server/control.rs:197 persist_write 每次全量→增量/节流；大会友表性能。
- WB-0733 [P1] core/server/control.rs:231 merge 空值保留→吊销/删密钥需显式 tombstone；不得“只增不丢”保活。
- WB-0734 [P1] core/server/control.rs:245 trust 默认判等→版本号/状态迁移显式；非法覆盖拒绝。
- WB-0735 [P1] core/server/mod.rs:167 open 失败降内存→健康事件；用户知道重启丢进度。
- WB-0736 [P1] core/server/mod.rs:190 load_all 与 PeerStore 恢复顺序→先身份/信任后会话；启动一致性。
- WB-0737 [P1] core/server/mod.rs:216 SyncStore 未接 persist→同 persister；快照恢复。
- WB-0738 [P1] core/server/sync_api.rs:127 set_snapshot 锁内写盘→锁外；并发同步测试。
- WB-0739 [P1] core/server/sync_api.rs:105 load_last_manifest 损坏 None→告警/首次同步提示。
- WB-0740 [P1] core/server/sync_api.rs:138 dirs 无持久化→映射落库；重启恢复。
- WB-0741 [P0] desktop/session_store.rs:104 与 core sessions 双权威→删除/合并；只留 core 投影。
- WB-0742 [P1] desktop/session_store.rs:159 tokio::fs::write 非原子→core/SQLite 事务；崩溃测试。
- WB-0743 [P1] desktop/session_store.rs:172 create_session 不设 active_id→接口语义一致或删除死字段。
- WB-0744 [P1] desktop/session_store.rs:284 fail_session 丢 error→记录原因；UI 可见。
- WB-0745 [P1] desktop/session_store.rs:309 时间戳有时 ISO 有时毫秒字符串→统一 RFC3339/epoch；迁移。
- WB-0746 [P1] desktop/session_store.rs:330 测试用全局 temp→每测试唯一目录；并行不互踩。
- WB-0747 [P1] desktop/lib.rs:117 启动同步建 DesktopSessionStore→异步/可失败降级；主线程不卡。
- WB-0748 [P1] desktop/lib.rs:719 config.json 读失败空→损坏备份/默认+告警；不得静默重置。
- WB-0749 [P0] desktop/lib.rs:734 set_config 非原子写→tmp+sync+rename；崩溃恢复。
- WB-0750 [P0] desktop/lib.rs:734 config 任意 JSON→typed AppConfig/schema；未知字段拒绝/迁移。
- WB-0751 [P1] shared-core/src/config.ts:70 normalizeConfig 丢未知字段→版本化迁移；encryption/autoAccept 入 schema。
- WB-0752 [P1] shared-core/src/config.ts:58 genFolderId Math.random 兜底→CSPRNG/错误；不得可预测 ID。
- WB-0753 [P1] config 角色与 receiver/sender enabled 冗余→单一角色派生或明确约束；非法组合拒绝。
- WB-0754 [P1] config receiveDir 变更→会话 root 版本/重启服务；旧会话不得写新根。
- WB-0755 [P1] config sender.folders 路径→授权根列表；扫描/发送只允许列表内。
- WB-0756 [P1] config strategy mirror→后端校验用户确认记录；不得仅前端 localStorage。
- WB-0757 [P1] config autoStartReceiver→后端启动策略；前端只投影。
- WB-0758 [P1] config defensiveHidden→持久化；启动先于监听。
- WB-0759 [P1] config debugEnabled→后端权威；自动过期/脱敏。
- WB-0760 [P1] config ballEnabled→后端权威；启动恢复。
- WB-0761 [P1] config 版本字段→schemaVersion；迁移脚本/回滚备份。
- WB-0762 [P1] config 大小上限→防 IPC/磁盘膨胀；模糊测试。
- WB-0763 [P1] config 并发写→单写者/版本 CAS；最后写不丢更新。
- WB-0764 [P1] config 导出/导入→脱敏/校验；用户确认。
- WB-0765 [P1] 前端 STATE_KEY localStorage→迁移后端 DeviceState；旧数据只读导入。
- WB-0766 [P1] 前端 desktop_pairings→迁移后端 PeerStore；清理秘密字段。
- WB-0767 [P1] 前端 auto_accept_receive→并入 AppConfig；后端执行。
- WB-0768 [P1] 前端 mirrorAskedAt→后端确认审计；按清单版本失效。
- WB-0769 [P1] 重置状态→DB/core/config/前端投影/临时文件统一编排；部分失败报告。
- WB-0770 [P1] 重置身份→旧配对吊销通知/本地 tombstone；不得只删行。
- WB-0771 [P1] 旧 V2/V3 数据迁移→只迁移可验证字段；不可迁移标记 legacy。
- WB-0772 [P1] 迁移 dry-run→报告将丢字段/需重新配对；用户确认。
- WB-0773 [P1] 迁移备份→backups/migration-<ts>/；恢复命令。
- WB-0774 [P1] 迁移幂等→重复启动不重复迁；版本标记。
- WB-0775 [P1] 存储健康投影→命令 get_storage_health；UI 显示降级。
- WB-0776 [P1] 磁盘满→写失败分类/暂停会话；不得假完成。
- WB-0777 [P1] 权限拒绝→可读错误/选择新目录；不得 temp 兜底。
- WB-0778 [P1] 持久化指标→写延迟/失败率/队列长度；日志采样。
- WB-0779 [P1] 持久化故障注入→只读目录/满盘/杀进程/半行 WAL 测试。
- WB-0780 [P1] 存储层 trait→core 定义 IdentityStore/PeerStore/SessionStore/ConfigStore；桌面 SQLite 实现；测试内存实现。

### B7 发现、在线性与网络（WB-0781..0860）

- WB-0781 [P0] desktop/bcpd.rs:265 自定义组播与 core presence 不兼容→迁移 core beacon；三端同格式/端口。
- WB-0782 [P0] desktop/bcpd.rs:153 dedup 先于 HMAC→认证后才记水位；伪造包不得拒真包。
- WB-0783 [P0] desktop/bcpd.rs:327 接收不查 defensive_hidden→隐藏时停收/不发射；总闸矩阵。
- WB-0784 [P1] desktop/bcpd.rs:165 收包不查 is_active_peer→吊销/Revoking 策略与 core 一致。
- WB-0785 [P1] desktop/bcpd.rs:102 HMAC 无域分隔/版本→core beacon 格式；跨端向量。
- WB-0786 [P1] desktop/bcpd.rs:115 JSON beacon 暴露完整 deviceId 列表→最小化公开前缀/隐私策略。
- WB-0787 [P1] desktop/bcpd.rs:325 4096 缓冲→beacon 定长/上限；多 peer 不超包。
- WB-0788 [P1] desktop/bcpd.rs:146 随机清理 rcvd_seen→确定性 TTL/上限；内存测试。
- WB-0789 [P1] desktop/bcpd.rs:135 墙钟回放窗口→单调水位+时钟偏移；NTP 回拨测试。
- WB-0790 [P1] desktop/bcpd.rs:241 open_sender 无广播兜底→core 组播+定向广播；AP 隔离测试。
- WB-0791 [P1] desktop/bcpd.rs:258 join INADDR_ANY→逐网卡加入；多网卡/虚拟网卡过滤。
- WB-0792 [P1] desktop/bcpd.rs:253 Windows SO_REUSEADDR→语义审计/单实例；双实例测试。
- WB-0793 [P1] desktop/bcpd.rs:297 send_to 失败即重建→core SendHealth 3 轮阈值；抖动测试。
- WB-0794 [P1] desktop/bcpd.rs:337 sweep 每包触发→定时 tick；CPU 基准。
- WB-0795 [P1] desktop/bcpd.rs:190 lastHeartbeat 不落库→core presence 投影/持久化策略。
- WB-0796 [P1] desktop/bcpd.rs:37 12s 离线 vs core 3s→统一 TTL；UI 语义。
- WB-0797 [P1] desktop/discovery.rs:74 一次性扫描线程→core 周期/事件驱动发现；可停止。
- WB-0798 [P1] desktop/discovery.rs:57 stop_tx 与 scan_stop 双 flag→单 CancellationToken；退出确认。
- WB-0799 [P1] desktop/discovery.rs:230 扫描结束不清 stop_tx→状态复位；重复启动测试。
- WB-0800 [P1] desktop/discovery.rs:164 忽略 netmask→core scan_targets；/31//32/非连续掩码测试。
- WB-0801 [P1] desktop/discovery.rs:161 不过滤虚拟/链路本地→网卡策略/用户选择；VPN 场景。
- WB-0802 [P1] desktop/discovery.rs:175 64 线程阻塞→core async buffer_unordered；资源上限。
- WB-0803 [P1] desktop/discovery.rs:190 用 legacy http_json_request→core probe_client no_proxy/超时。
- WB-0804 [P1] desktop/discovery.rs:105 TTL 8s 短于扫描→按 core presence/扫描周期；早结果不过期。
- WB-0805 [P1] desktop/discovery.rs:116 IP 冲突只告警不更新→多 IP 设备投影/可疑认证；DHCP 测试。
- WB-0806 [P1] desktop/discovery.rs:216 port 从响应取→验证实际端口/范围；恶意响应测试。
- WB-0807 [P1] core/discovery.rs:286 probe_one 只看 2xx→校验 ProbeResponse/协议版本；外国 200 不得入列。
- WB-0808 [P1] core/discovery.rs:300 probe_all 批内 join_all→真正滑动窗口；慢主机不拖批。
- WB-0809 [P1] core/discovery.rs:300 无取消→CancellationToken；停止发现即时。
- WB-0810 [P1] core/discovery.rs:144 MAX_SCAN_HOSTS 静默截断→返回 truncated 标志；UI 告警。
- WB-0811 [P1] core/discovery.rs:162 prioritize_known 可超上限/混端口→容量/端口策略；已知设备优先测试。
- WB-0812 [P1] core/discovery.rs:275 probe_client 无连接池限制→max idle/超时；扫描资源测试。
- WB-0813 [P1] core/presence/transport.rs:191 beacon_targets 每次枚举网卡→缓存+网络变化刷新；唤醒测试。
- WB-0814 [P1] core/presence/transport.rs:403 rebuild 失败丢 guard→保留旧 guard/锁；重建失败测试。
- WB-0815 [P1] core/presence/transport.rs:307 bind 同端口旧 socket 未关→关闭旧句柄再重建；Windows 双收测试。
- WB-0816 [P1] core/presence/transport.rs:316 加入所有网卡含虚拟→过滤策略；多网卡测试。
- WB-0817 [P1] core/presence/transport.rs:143 emit seq 耗尽停发→轮换/重启策略；长期运行。
- WB-0818 [P1] core/presence/tracker.rs:115 时钟窗口 30s→与 beacon 周期/TTL 配套；偏移测试。
- WB-0819 [P1] core/presence/tracker.rs:131 首个合法包固定 prefix→prefix 碰撞/完整 ID 校验；伪造测试。
- WB-0820 [P1] core/presence/beacon.rs:23 8B 前缀碰撞→完整 ID 映射/碰撞处理；大网络测试。
- WB-0821 [P1] core/presence/beacon.rs:63 HMAC 无域分隔→格式版本/域；跨端向量。
- WB-0822 [P1] core/state/presence.rs:30 tick Offline sink→beacon 恢复路径已测；重置语义。
- WB-0823 [P1] core/state/connection.rs:65 Connecting DisconnectRequest 直 Disconnected→清理在途握手；取消测试。
- WB-0824 [P1] core/state/connection.rs:68 Connected 只 PeerPresenceDropped→Stale 策略明确；UI 门控。
- WB-0825 [P1] core/state/policy.rs:123 can_disconnect 非 Online 禁断→Lost 时允许清理/重连策略；按钮矩阵。
- WB-0826 [P1] core/state/policy.rs:138 can_start_transfer 不查 presence/pairing→上下文含 trust/presence；非法点击拒绝。
- WB-0827 [P1] core/state/policy.rs:61 Verdict reason &'static str→本地化/错误码分离；UI 不硬编码中文。
- WB-0828 [P1] desktop/src/App.vue:1836 connectPeer 仅 probe 即 connected→必须 handshake/认证；连接态来自 core。
- WB-0829 [P1] desktop/src/App.vue:1694 500ms greetAll→后端 presence 事件；前端不高频探测。
- WB-0830 [P1] desktop/src/App.vue:1712 visibilitychange 重复 add→注册一次/卸载清理；定时器泄漏测试。
- WB-0831 [P1] desktop/transfer/util.rs:287 http_json_request_internal 手写 HTTP→reqwest/core 客户端；状态/chunked/超时正确。
- WB-0832 [P1] desktop/transfer/util.rs:302 ToSocketAddrs 阻塞/无代理策略→async 解析/no_proxy；LAN 代理测试。
- WB-0833 [P1] desktop/transfer/util.rs:321 Host 头 ip 未括 IPv6→SocketAddr 格式化；IPv6 测试。
- WB-0834 [P1] desktop/transfer/util.rs:321 method/path/header 可注入→ typed Request builder；CRLF 拒绝。
- WB-0835 [P1] desktop/transfer/util.rs:338 响应 lossy/不查 status→typed 响应/错误信封；非 JSON 处理。
- WB-0836 [P1] desktop/transfer/util.rs:334 64MB 响应上限→按端点限长；流式解析。
- WB-0837 [P1] desktop/pairing/v4.rs:37 代理 53317 硬编码→单端口后删除代理；路由测试。
- WB-0838 [P1] desktop/pairing/v4.rs:45 代理恒 200→透传状态/错误；404/401 测试。
- WB-0839 [P1] desktop/pairing/auth.rs:103 响应行 `{status} OK`→正确 reason phrase；HTTP 语义测试。
- WB-0840 [P1] desktop/pairing/auth.rs:121 Content-Length 重复/非法→hyper 解析；走私测试。
- WB-0841 [P1] desktop/pairing/auth.rs:163 完整但超 64KB 仍放行→硬拒绝；上限测试。
- WB-0842 [P1] desktop/pairing/auth.rs:96 错误 JSON 字符串插值→serde 序列化；注入测试。
- WB-0843 [P1] desktop/pairing/auth.rs:361 encodedPath 未解码→统一 query/path 闸；穿越测试。
- WB-0844 [P1] desktop/pairing/auth.rs:394 fileComplete 恒 false→删除 legacy；V4 chunk-status 替代。
- WB-0845 [P1] desktop/pairing/auth.rs:474 manifest 扫描跟随 symlink→core 扫描/路径闸；内部文件过滤。
- WB-0846 [P1] desktop/transfer/mod.rs:292 pairing_port +1 溢出→单端口后删除；u16 checked 测试。
- WB-0847 [P1] desktop/transfer/mod.rs:334 PairConnGuard 毒锁不减计数→Semaphore/RAII 可靠；毒锁测试。
- WB-0848 [P1] desktop/transfer/mod.rs:340 读写超时 30s 但 verify 60s→按端点超时；审批长请求测试。
- WB-0849 [P1] desktop/transfer/receive.rs:154 bind 0.0.0.0→可配置绑定/防火墙；仅 LAN 接口选项。
- WB-0850 [P1] desktop/transfer/receive.rs:158 actual_port fallback 请求 port→local_addr 失败即错误；端口 0 策略。
- WB-0851 [P1] 网络变化→Windows 通知/网卡枚举刷新；socket 重建/对账。
- WB-0852 [P1] 代理→LAN 客户端 no_proxy；系统代理不得劫持 192.168。
- WB-0853 [P1] IPv6→明确支持/拒绝策略；SocketAddr/Host/multicast 一致。
- WB-0854 [P1] 端口冲突→可读错误/释放指引；不得静默换端口破坏对端。
- WB-0855 [P1] 连接上限→core MAX_UPSTREAM_CONNECTIONS 接入；Slowloris/洪泛测试。
- WB-0856 [P1] IO 超时→每请求 timeout+graceful shutdown；挂起连接测试。
- WB-0857 [P1] HTTP keep-alive→Connection close 策略统一；连接复用性能。
- WB-0858 [P1] 请求头→X-Protocol-Version/X-Device-Id/X-Request-Id 强制/校验；缺失策略。
- WB-0859 [P1] 版本协商→PROTOCOL_VERSION u32 与 desktop "4.0" 字符串统一；软降级矩阵。
- WB-0860 [P1] 网络错误分类→connect/timeout/TLS/HTTP/协议错误 typed；前端 retryable 标记。

### B8 日志、错误与可观测性（WB-0861..0940）

- WB-0861 [P0] core 使用 log crate 但桌面未实现 logger→安装 log::Log 桥；core warn/error 必须可见。
- WB-0862 [P1] desktop/ball.rs:113 log::info 无 subscriber→统一桥/删除混用；日志不得丢。
- WB-0863 [P0] desktop/logger.rs:133 init_file truncate 旧日志→启动轮转保留崩溃现场；不得清证据。
- WB-0864 [P1] desktop/logger.rs:118 init_file 在 DB 之后→最早期初始化日志入缓冲/启动后 flush。
- WB-0865 [P1] desktop/logger.rs:272 println GUI 无控制台→条件 console/调试器；发布不 stdout 阻塞。
- WB-0866 [P1] desktop/logger.rs:282 每日志锁文件→异步有界 writer；背压/丢弃策略。
- WB-0867 [P1] desktop/logger.rs:527 mpsc 无界→bounded channel+丢弃计数；洪泛测试。
- WB-0868 [P1] desktop/logger.rs:534 batch 后逐条 emit→批量事件/节流；WebView 负载测试。
- WB-0869 [P1] desktop/logger.rs:311 按字符串 contains 判 WARN→按 LogLevel flush；消息含 [WARN] 不误刷。
- WB-0870 [P1] desktop/logger.rs:284 轮转失败 guard=None 永久停写→重试/降级告警；磁盘恢复测试。
- WB-0871 [P1] desktop/logger.rs:294 remove_file 旧备份→按用户规则移备份/轮转命名；不得永久删证据。
- WB-0872 [P1] desktop/logger.rs:375 timestamp now_local 失败 UTC→明确时区偏移字段；跨时区测试。
- WB-0873 [P1] desktop/logger.rs:604 parse_timestamp 当 UTC→本地时间解析/直接存 epoch；日志 ts 准确。
- WB-0874 [P1] desktop/logger.rs:550 get_rust_logs 解析文本→结构化缓冲直接投影；seq 去重。
- WB-0875 [P1] desktop/logger.rs:195 全局折叠槽跨模块→按 (level,module,message) 键；并发日志不丢。
- WB-0876 [P1] desktop/logger.rs:513 sweeper 线程无停止→shutdown 取消；退出 flush。
- WB-0877 [P1] desktop/logger.rs:409 panic hook 无默认 hook/backtrace→保留默认/崩溃文件；release abort 策略审计。
- WB-0878 [P1] desktop/src-tauri/Cargo.toml:83 panic=abort→评估 unwind/崩溃上报；FFI guard 有效性。
- WB-0879 [P1] desktop/transfer/mod.rs:453 UI watchdog 永久线程→可停止/指标化；误报阈值自适应。
- WB-0880 [P1] desktop/lib.rs:53 探针写 temp 固定名→诊断 feature/唯一路径；发布零开销。
- WB-0881 [P1] desktop/main.rs:9 启动删探针文件→轮转/备份；不得清崩溃证据。
- WB-0882 [P0] 日志脱敏：路径/文件名/alias/IP 全量落盘→分级脱敏/用户同意；导出扫描 needle。
- WB-0883 [P0] token 在 URL query：send.rs:944→ Authorization 头/不日志 URL；抓包/日志测试。
- WB-0884 [P1] logger.mask 留前2后2→短码全掩/秘密不落部分；连接码 8 位不得留4。
- WB-0885 [P1] 日志导出 extra_lines→限长/脱敏/结构化合并；不得任意写大盘。
- WB-0886 [P1] 日志文件名同秒覆盖→唯一 seq/原子写；并发导出测试。
- WB-0887 [P1] 日志目录 Documents 可能 OneDrive→app_local_logs 默认；用户选择导出目录。
- WB-0888 [P1] 日志保留策略→大小/天数/份数上限；清理审计。
- WB-0889 [P1] 日志级别→release 默认 INFO/WARN；debug 自动过期；ERROR 始终。
- WB-0890 [P1] 日志 requestId→HTTP/IPC/会话贯穿；错误可关联。
- WB-0891 [P1] 日志结构化→LogEntry{seq,ts,level,module,code,requestId,sessionId摘要}；不再文本解析。
- WB-0892 [P1] 日志事件 schema→rust_log_event payload 版本化；前端 zod/typed。
- WB-0893 [P1] 前端 logger.report 重复 Rust 日志→按 seq 去重；启动回放不双计。
- WB-0894 [P1] shared-core/src/logger.ts:217 每条日志通知全部 listener→节流/批量；UI 帧率。
- WB-0895 [P1] shared-core/src/logger.ts:220 WARN/ERROR 每条 localStorage→节流/后端持久化；配额测试。
- WB-0896 [P1] shared-core/src/logger.ts:400 restore 不校验 level→schema 校验；脏日志不得 NaN 计数。
- WB-0897 [P1] shared-core/src/logger.ts:249 startActiveSpan Promise 不 end→自动 finally/包装；span 泄漏测试。
- WB-0898 [P1] shared-core/src/telemetry.ts:50 默认 enabled true→默认关闭/显式同意；隐私。
- WB-0899 [P1] shared-core/src/telemetry.ts:30 localhost OTLP→无 collector 不初始化/不打包重依赖；bundle 分析。
- WB-0900 [P1] shared-core/src/telemetry.ts:121 向 LAN 传播 trace header→对端协议支持/脱敏；不得泄漏路径。
- WB-0901 [P1] OTel 依赖版本混杂 0.57/1.30→统一/移除未用 instrumentation；依赖审计。
- WB-0902 [P1] zone.js 全局 patch→评估移除/按需；性能/冲突测试。
- WB-0903 [P1] desktop/lib.rs:123 OTLP 注释历史坑→若恢复必须独立线程/超时/配置；不得主线程网络。
- WB-0904 [P1] 指标→会话数/吞吐/重试/降级/持久化失败/在线数；本地诊断页。
- WB-0905 [P1] 健康命令→get_backend_health 投影服务/存储/网络/版本；前端设置页。
- WB-0906 [P1] 错误信封→core ErrorEnvelope 全端点统一；not_found 不得 {"error":"..."} 裸字符串。
- WB-0907 [P1] core/server/mod.rs:429 not_found→ErrorEnvelope+requestId；契约测试。
- WB-0908 [P1] core/error.rs:154 code() 非 Protocol 全 Internal→Io/Db/Network 映射可重试；日志内部细节。
- WB-0909 [P1] core/error.rs:163 to_envelope 泄漏 Protocol message→message 白名单/可披露标记。
- WB-0910 [P1] desktop/db.rs:20 AppError(String)→CommandError code/retryable/requestId；前端按码处理。
- WB-0911 [P1] desktop/pairing/error.rs:9 PairingError dead variants→删除/接入；不得预留假架构。
- WB-0912 [P1] HTTP 状态语义→413 用 BadRequest 表达→补 ErrorCode/状态；schema golden。
- WB-0913 [P1] 422 校验失败→core 用 412/409 与 scheduler 422 不一致→统一错误码矩阵。
- WB-0914 [P1] 重试判定→按错误码/retryable 而非字符串 regex；测试。
- WB-0915 [P1] 用户文案→core 错误码→前端 i18n 映射；不得后端中文硬编码到 UI。
- WB-0916 [P1] 安全事件→认证失败/路径拒绝/吊销/重放 单独审计等级；告警阈值。
- WB-0917 [P1] 崩溃现场→panic/abort 前 flush 日志/最小 dump；用户导出。
- WB-0918 [P1] 启动失败→lib.rs:269 写 temp 日志→app_data 崩溃目录/事件查看器；可读错误。
- WB-0919 [P1] 单实例回调→show/unminimize 错误忽略→日志/焦点策略；Windows 前台限制。
- WB-0920 [P1] 托盘/球日志→统一 module tag；不得 log crate 与自定义分裂。
- WB-0921 [P1] 日志采样→高频进度/心跳采样；WARN/ERROR 全量。
- WB-0922 [P1] 日志时钟→epoch+单调 seq；墙钟回拨不乱序。
- WB-0923 [P1] 日志隐私扫描→导出前 needle 扫描连接码/token/私钥；CI 测试。
- WB-0924 [P1] 日志 PII 状态→设置页显示“日志含路径/设备名”开关；默认脱敏。
- WB-0925 [P1] 前端全局错误→main.ts errorHandler 与 window error 去重；同一错误不双报。
- WB-0926 [P1] withTimeout→超时后原 promise 仍跑→AbortController/取消令牌；不得假取消。
- WB-0927 [P1] 事件丢失→关键事件 seq+快照兜底；前端重连补拉。
- WB-0928 [P1] 事件命名→ball:*/rust_log_event/peer-* 统一清单；版本化。
- WB-0929 [P1] 事件 payload→typed schema；前端不得 as 强转。
- WB-0930 [P1] 事件权限→球窗口只收 ball 事件；危险事件仅 main。
- WB-0931 [P1] 诊断开关→PROBE_ENABLED 编译期→运行时诊断 feature；发布剥离。
- WB-0932 [P1] watchdog 误报→主线程阻塞指标/阈值配置；不得日志洪泛。
- WB-0933 [P1] 接收 watchdog→健康探针/重启次数上限/退避；失败 UI 告警。
- WB-0934 [P1] 服务状态事件→receiver-started/stopped/degraded；前端不猜。
- WB-0935 [P1] 版本信息→build commit/协议版本/平台入日志头；排障可复现。
- WB-0936 [P1] 依赖版本→日志头 Cargo.lock hash/pnpm lock hash；环境差异。
- WB-0937 [P1] 错误上报用户同意→本地导出默认；外发 telemetry 显式开启。
- WB-0938 [P1] 日志测试→脱敏/轮转/背压/崩溃恢复/结构化解析；CI。
- WB-0939 [P1] 可观测验收→制造断网/满盘/坏块/伪造 token，日志可定位 requestId。
- WB-0940 [P1] 文档→日志位置/级别/导出/隐私写用户文档；旧 D:\ 根路径注释清理。

### B9 前端、shared-core、移动端与协议联动（WB-0941..1020）

- WB-0941 [P0] desktop/src/App.vue:141 localStorage 存连接码 fingerprint→迁移后端投影；旧秘密清理。
- WB-0942 [P0] desktop/src/App.vue:2012 fp=normalizeCode(输入码)→fingerprint 改公钥指纹；code 不入持久化。
- WB-0943 [P0] desktop/src/App.vue:1716 confirmAllPairs 回写信任→删除；后端单权威事件投影。
- WB-0944 [P0] desktop/src/App.vue:2322 发送返回即更新全量快照→按接收端逐文件终态更新；失败下轮重试。
- WB-0945 [P1] desktop/src/App.vue:44 invoke 无 typed 命令表→生成 TS client/命令清单；编译期防漂移。
- WB-0946 [P1] desktop/src/App.vue:1408 listen as 强转→事件 payload schema/zod；非法 payload 拒绝。
- WB-0947 [P1] desktop/src/App.vue:1453 autoAcceptReceive 前端执行→后端策略；前端只设置。
- WB-0948 [P1] desktop/src/App.vue:1511 peer-connected 自动拉起接收→后端策略/用户授权；不得隐藏时拉起。
- WB-0949 [P1] desktop/src/App.vue:1545 pair-unpaired 直接 remove→按 trust 投影 REVOKED/REVOKE_PENDING；显示收敛态。
- WB-0950 [P1] desktop/src/App.vue:1589 device-suspicious 仅清缓存→认证失败/公钥变更触发安全流程；不得只按 IP。
- WB-0951 [P1] desktop/src/App.vue:1694 500ms 轮询→后端 presence 事件；后台/前台策略统一。
- WB-0952 [P1] desktop/src/App.vue:1702 30s sync_all_peers→后端对账服务；前端订阅结果。
- WB-0953 [P1] desktop/src/App.vue:1836 connectPeer probe 即 connected→core ConnectionState；握手成功才 Connected。
- WB-0954 [P1] desktop/src/App.vue:1865 disconnect 本地先清→两步走结果投影；失败文案。
- WB-0955 [P1] desktop/src/App.vue:2117 removePairing 无论成败 remove→按后端终态；pending 显示待收敛。
- WB-0956 [P1] desktop/src/App.vue:2176 start_receiver 返回字符串→typed ReceiverStatus；实际端口/健康。
- WB-0957 [P1] desktop/src/App.vue:2202 cancelReceive 停服务→会话级 abort；服务保持。
- WB-0958 [P1] desktop/src/App.vue:2246 scan_directory 前端拼 absPath→后端返回授权文件 handle/relPath；防越界。
- WB-0959 [P1] desktop/src/App.vue:2267 planIncremental 前端算→core sync.decide 投影；前端只展示/确认。
- WB-0960 [P1] desktop/src/App.vue:2274 mirror 确认 localStorage→后端审计/清单版本；变更后可再确认。
- WB-0961 [P1] desktop/src/App.vue:2287 move_to_delete 忽略结果→逐路径结果 UI；rejected 显示。
- WB-0962 [P1] desktop/src/App.vue:2315 encryptionMode 字符串→能力协商/后端策略；不得假 ECDH。
- WB-0963 [P1] desktop/src/App.vue:1158 c.encryption 不在 AppConfig→补 schema/类型；vue-tsc 门禁。
- WB-0964 [P1] desktop/src/App.vue:1290 loadState 每次 JSON.parse→后端投影/缓存；大状态不卡。
- WB-0965 [P1] desktop/src/App.vue:1302 saveState 失败只 warn→后端权威；前端失败不丢备份快照。
- WB-0966 [P1] desktop/src/App.vue:2542 resetAll 前端清 localStorage→后端 reset 事件驱动；失败不清。
- WB-0967 [P1] desktop/src/App.vue:2515 refreshSelfCode 显示新码→后端确认/旧码失效/密钥滚动事件。
- WB-0968 [P1] desktop/src/App.vue:2571 exportLogs extraLines→统一日志桥；导出脱敏。
- WB-0969 [P1] desktop/src/App.vue:1633 ball:drop-folder 任意 path→后端授权根校验；不得直接同步任意路径。
- WB-0970 [P1] desktop/src/App.vue:1642 onDragDropEvent 添加文件夹→路径闸/用户确认；持久化后端。
- WB-0971 [P1] desktop/src/composables/useTauriListener.ts:22 清理异常忽略→日志/调试警告；泄漏检测。
- WB-0972 [P1] desktop/src/main.ts:10 initTelemetry 默认→显式同意/默认关；bundle 减重。
- WB-0973 [P1] desktop/vite.config.ts:7 VueMcp 发布→仅 dev；生产移除。
- WB-0974 [P1] desktop/package.json:8 build 无 vue-tsc→加 typecheck 门禁；CI 阻断。
- WB-0975 [P1] desktop/src-tauri/tauri.conf.json:28 CSP http://* + unsafe-inline→收紧 connect-src/脚本；Tauri IPC 安全。
- WB-0976 [P1] desktop/src-tauri/tauri.conf.json:13 withGlobalTauri→评估关闭；最小暴露。
- WB-0977 [P1] desktop/src-tauri/Cargo.toml:15 devtools release→仅 debug feature；发布安全。
- WB-0978 [P1] desktop/src-tauri/capabilities/default.json:5 main/ball 同权→分窗口能力；危险命令仅 main。
- WB-0979 [P1] shared-core/src/transfer.ts:2 V2 LocalSend 客户端→删除/隔离；移动端切 V4 core。
- WB-0980 [P1] shared-core/src/scheduler.ts:141 自造 xxHash64→删除；core Adler/SHA 权威。
- WB-0981 [P1] shared-core/src/scheduler.ts:113 奇数复制 vs desktop 提升→core Merkle 向量统一。
- WB-0982 [P1] shared-core/src/scheduler.ts:397 Math.random sessionId→core CSPRNG；不得安全 ID 兜底。
- WB-0983 [P1] shared-core/src/scheduler.ts:416 require('crypto') ESM→删除同步哈希；WebCrypto/core。
- WB-0984 [P1] shared-core/src/sync.ts:60 planIncremental 与 core decide 分叉→迁移 core；旧函数只读兼容期标记。
- WB-0985 [P1] shared-core/src/sync.ts:90 mtime 严格相等 vs core 2s 容差→统一容差；FAT 测试。
- WB-0986 [P1] shared-core/src/sync.ts:135 delete 前缀大小写/反斜杠→core normalize；墓碑测试。
- WB-0987 [P1] shared-core/src/manifest.ts:46 normalize 不拒 `..`→core 安全闸；前端不处理不可信路径。
- WB-0988 [P1] shared-core/src/identity.ts:20 PROTOCOL_VERSION '1.1'→删除/生成自 core version。
- WB-0989 [P1] shared-core/src/identity.ts:80 normalizeConnectionCode 宽松→core 严格版；向量。
- WB-0990 [P1] shared-core/src/identity.ts:72 日志种子→删除；脱敏。
- WB-0991 [P1] shared-core/src/pairing.ts:23 PairRecord 含连接码/previousKeys→后端投影 DTO；秘密不出 IPC。
- WB-0992 [P1] shared-core/src/pairing.ts:106 upsert 按 fingerprint 或 deviceId→deviceId 权威；公钥指纹分离。
- WB-0993 [P1] shared-core/src/pairing.ts:196 rotateKey 前端管密钥→core KeyRing；前端只投影版本。
- WB-0994 [P1] shared-core/src/discovery.ts:24 connectionCode 字段→删除；发现只公开 deviceId。
- WB-0995 [P1] shared-core/src/discovery.ts:78 key ip:port→deviceId+endpoint；多 IP 投影。
- WB-0996 [P1] shared-core/src/state.ts:16 DeviceState 按连接码→deviceId；迁移。
- WB-0997 [P1] shared-core/src/session-store.ts:50 与 core DTO 分叉→生成类型/投影；删除平行权威。
- WB-0998 [P1] shared-core/src/config.ts:44 AppConfig 缺字段→与后端 schema 同源生成。
- WB-0999 [P1] shared-core/src/scan.ts:202 normalizeForCompare 只 NFC→Windows 大小写/规范化策略与 core 一致。
- WB-1000 [P1] shared-core/src/anchor.ts:64 mtime>anchor 漏同毫秒变更→core 清单/哈希策略；锚点迁移。
- WB-1001 [P1] shared-core/src/test/selfcheck.ts:178 只测 V2 port→改 V4 契约/核心投影测试；删除旧权威测试。
- WB-1002 [P1] shared-core/package.json:13 OTel 重依赖→按需/移除；bundle 门禁。
- WB-1003 [P1] mobile/src/services/receiver.ts:35 v3PairClient/v3Probe→V4 typed 接口；同批迁移。
- WB-1004 [P1] mobile/src/services/receiver.ts:177 prepareUploadTo token 对象→V4 字符串 token；schema。
- WB-1005 [P0] mobile/src/services/backup.ts:264 LocalSend v2 prepare→V4 register/prepare/chunk；桌面兼容断裂必须同改。
- WB-1006 [P0] mobile/src/services/backup.ts:211 __chunked__ 私有格式→统一 pieceIndex；桌面接收同契约。
- WB-1007 [P1] mobile/src/services/backup.ts:66 rustPctEncode 手写→core/生成编码；跨端向量。
- WB-1008 [P1] mobile/src/services/backup.ts:205 chunkOverhead 与 Rust 空文件不一致→统一加密格式；空文件测试。
- WB-1009 [P1] mobile/src/services/backup.ts:298 8 路并发硬编码→core 调度/设备能力；压测。
- WB-1010 [P0] mobile Java LocalReceiverPlugin.java:1785 V2 接收路由→V4 core/生成绑定；Java 仅 SAF IO。
- WB-1011 [P0] mobile Java:2213 getPeerManifest 打 53318 legacy→V4 manifest 53317 认证；桌面同改。
- WB-1012 [P1] mobile Java:486 /v2/verify 连接码明文比对→V4 HMAC/审批；不得明文码上线。
- WB-1013 [P1] mobile Java:104 MULTICAST_PORT 53317 JSON announce→core beacon 32B；三端一致。
- WB-1014 [P1] mobile Java LanBackupCore.java:13 .so 未打包降级→构建/打包门禁；不得静默 Java 协议分叉。
- WB-1015 [P1] mobile/local-receiver/android/build.gradle:33 无 jniLibs/Rust 构建→接入 core .so 构建/ABI；CI。
- WB-1016 [P1] core/platform/android.rs:67 forget GlobalRef 泄漏→生命周期释放；JNI 审计。
- WB-1017 [P1] core/ffi.rs:486 Arc::from_raw 消费调用方 Arc→改为 Arc::clone 入参/ owning handle；不得 UAF。
- WB-1018 [P1] core/ffi.rs:487 tokio::spawn 无 runtime→显式 runtime/handle；无 runtime 错误码。
- WB-1019 [P1] protocol/README.md:37 16 端点旧表→由 routes::ALL 生成 24 端点；golden 同步。
- WB-1020 [P1] protocol/schemas/v4/golden-manifest.json endpoints 旧→gen_schema 从 routes::ALL 生成；CI 阻断漂移。

### B10 CI、测试、发布与文档收口（WB-1021..1080）

- WB-1021 [P0] .github/workflows 仅 Android→新增 windows-latest：core/desktop fmt/clippy/test/schema/前端 typecheck/build。
- WB-1022 [P1] CI paths 不含 core/desktop/protocol→后端变更必须触发 Windows/core 门禁。
- WB-1023 [P1] CI pnpm/action-setup version 9 vs packageManager 11→统一版本；corepack/pnpm frozen。
- WB-1024 [P1] CI pnpm install 无 --frozen-lockfile→锁文件门禁；不得漂移。
- WB-1025 [P1] pnpm-workspace.yaml allowBuilds→与 pnpm 版本字段一致；构建脚本审批。
- WB-1026 [P1] 无 Cargo workspace→core/desktop 共享锁/依赖版本；评估 workspace 迁移。
- WB-1027 [P1] 两套 Cargo.lock 重复 reqwest/base64/pbkdf2/if-addrs→统一版本/世代；cargo tree 审计。
- WB-1028 [P1] core/Cargo.toml:65 rusqlite 未用却 bundled→移除/feature-gate；纯 Rust 声明真实。
- WB-1029 [P1] core/Cargo.toml:25 reqwest 0.13 vs desktop 0.12→统一；TLS 死重审计。
- WB-1030 [P1] desktop/src-tauri/Cargo.toml:39 tokio full→按需 features；编译时间/体积基准。
- WB-1031 [P1] desktop/src-tauri/Cargo.toml:82 release panic=abort/strip→崩溃诊断策略；符号保留/分离。
- WB-1032 [P1] desktop/src-tauri/Cargo.toml:89 分级优化注释称框架 s 但全局 3→按实测配置；体积/速度基准。
- WB-1033 [P1] desktop/src-tauri/.cargo/config.toml:6 x86-64-v2→最低 CPU 声明/运行检测；老机器启动失败处理。
- WB-1034 [P1] 无 rust-toolchain→钉稳定版本/组件；CI 本地一致。
- WB-1035 [P1] cargo fmt/clippy 门禁→-D warnings；desktop 40 测试纳入 CI。
- WB-1036 [P0] 真实 HTTP E2E→hyper bind 临时端口跑 24 端点；不得只调 route()。
- WB-1037 [P0] 传输黄金路径→小/大/加密/乱序/断点/重启/取消/坏块/冲突 E2E。
- WB-1038 [P0] 配对黄金路径→首配审批/错码/重放/重连/解配对/离线吊销/重启收敛。
- WB-1039 [P1] 故障注入→满盘/只读/占用/半行 WAL/杀进程/断网/时钟回拨。
- WB-1040 [P1] 属性测试→路径闸/状态机/位图换算/Merkle/退避；proptest（依赖批准）。
- WB-1041 [P1] 模糊测试→HTTP DTO/token/加密头/路径；不得 panic 跨 FFI。
- WB-1042 [P1] 并发测试→多会话/多 peer/重启重叠/写穿乱序；loom/压力（依赖批准）。
- WB-1043 [P1] 性能基准→扫描/哈希/吞吐/内存/启动；回归门禁。
- WB-1044 [P1] schema conformance→每端点请求/响应/错误真实 HTTP 校验；golden hash。
- WB-1045 [P1] core/tests/schema_conformance.rs 只验 meta-schema→补实例向量/端点形状。
- WB-1046 [P1] gen_schema.rs:278 golden endpoints 手写→routes::ALL 生成；数量/方法一致。
- WB-1047 [P1] gen_schema --golden 不先生成 schema→先 check/generate 再 hash；CI 顺序。
- WB-1048 [P1] 响应 schema 缺口→chunk/phase/heartbeat/abort/sync-dir/move/disconnect 补 DTO。
- WB-1049 [P1] 前端类型生成→schema→TS 类型/命令 client；不得手写漂移。
- WB-1050 [P1] 移动端契约测试→Java/Kotlin 对同一向量；CI Gradle 不 || true。
- WB-1051 [P1] Android CI 路径 mobile/android vs local-receiver→确认 gradlew 路径/产物；修复断裂。
- WB-1052 [P1] tracked mobile/build 1331 产物→按安全流程移出版本控制/备份；gitignore 生效。
- WB-1053 [P1] core/x* 测试残留→清理流程/测试临时目录；不得污染仓库。
- WB-1054 [P1] desktop/gen/schemas tracked→生成物策略明确；CI 校验而非手改。
- WB-1055 [P1] third_party/localsend 未用→确认无构建引用后隔离/归档；不得假称复用。
- WB-1056 [P1] 发布构建→NSIS 签名/版本/升级策略；未签名告警。
- WB-1057 [P1] 升级迁移→旧版本数据备份/迁移/回滚；用户提示重新配对。
- WB-1058 [P1] 单实例→升级/多用户/端口占用；第二实例唤起测试。
- WB-1059 [P1] 退出清理→端口/临时文件/在途会话/日志 flush；崩溃恢复。
- WB-1060 [P1] 防火墙/杀软→文档/首次运行提示；不得写盘符根目录。
- WB-1061 [P1] 依赖审计→cargo audit/deny/pnpm audit（依赖批准）；高危阻断。
- WB-1062 [P1] 许可证→第三方/ vendored 许可证清单；发布合规。
- WB-1063 [P1] SBOM/版本→构建嵌入 commit/lock hash；日志可追。
- WB-1064 [P1] AI-HANDOFF.md 旧完成标记→按代码证据重写；不得再称 V2 已清。
- WB-1065 [P1] NEXT-STEP-PLAN.md G5 状态→以单权威终态回填；旧 helper 合并记录标 obsolete。
- WB-1066 [P1] V4-ARCHITECTURE.md/README→端点/密钥/签名/编码以生成契约为准；旧矛盾清除。
- WB-1067 [P1] DESIGN-WISDOM-REGISTER→保留实测教训但标记已修复/废弃；不得当现状。
- WB-1068 [P1] core/src/lib.rs:70 “全部阶段已落地”→按真实接线状态回填；禁止假完成。
- WB-1069 [P1] 模块注释“纯文件拆分零改动”→重构后更新职责；不得误导。
- WB-1070 [P1] allow(dead_code) 74 处→逐项删除/接线/隔离；CI 禁止新增无解释 dead 权威。
- WB-1071 [P1] TODO/预留 key_exchange.rs→删除空实现；不得返回 Ok(vec![]) 假密钥。
- WB-1072 [P1] 测试计数口径→cargo test 实际输出入文档；不得沿用 482 旧数。
- WB-1073 [P1] 验收脚本→一键 Windows 后端门禁；timeout 护栏/日志归档。
- WB-1074 [P1] 三端联调矩阵→Win→Win、Win→Android、Android→Win；版本/能力/加密组合。
- WB-1075 [P1] 用户验收→配对/发送/接收/断点/取消/解配对/重置/日志导出；前端真实操作。
- WB-1076 [P1] 安全验收→伪造 deviceId/token/路径/重放/明文秘密扫描全拒绝。
- WB-1077 [P1] 数据验收→坏块不得 commit、旧文件不得提前改名、快照只含确认文件。
- WB-1078 [P1] 回归验收→前端构建/后端测试/schema/移动端 CI 同绿；P0 用例全过。
- WB-1079 [P1] 交付报告→1080 项状态表、剩余风险、决策闸批准记录、测试证据。
- WB-1080 [P1] 最终复扫→按本文 P0 关键词/路径/秘密/旧端点再扫一遍；无 V2/V3 权威残留才交付。

## 8. 最终验收清单（执行 AI 必须逐项给证据）

- [ ] 真实 hyper 入口：24 端点带 query/头/错误信封全部通过；`serve_request` 不再丢 query。
- [ ] 传输：≤4MB、>4MB、>100MB、加密、乱序、重复、缺口、断点重启、坏块、冲突重命名、取消全部 E2E。
- [ ] 配对：首配审批、错码限流、重放拒绝、重连、在线解配对、离线吊销、重启收敛、重置身份全部 E2E。
- [ ] 安全：伪造 deviceId/token/路径/ADS/UNC/保留名/重放/明文秘密扫描全部拒绝；日志/前端/磁盘无连接码与私钥明文。
- [ ] 存储：单权威；SQLite/core/前端投影一致；崩溃/满盘/只读/半行 WAL 恢复；重置事务化。
- [ ] Windows：长路径、UNC、占用重试、多网卡、休眠唤醒、防火墙、高 DPI、单实例、退出清理通过。
- [ ] 跨端：Windows/Android/前端/shared-core/protocol 同契约；V2/V3/53318 权威已隔离；移动端不再明文连接码上线。
- [ ] CI：Windows/core/desktop/前端/schema/Android 全绿；pnpm/Cargo 锁一致；无 tracked 构建产物。
- [ ] 文档：旧完成标记按代码证据回填；本文 1080 项状态表与剩余风险随交付提交。

---

## 9. 四分区执行计划（2026-11-09 划分）

按“难度 × 主链风险”从高到低分为四区，区域一先施工：

| 区域 | 对应批次 | 项数 | 内容 |
|---|---|---|---|
| **区域一（最难/最重要）** | B1 WB-0001..0100 | 100 | 真实 HTTP 入口、分块/校验协议、身份恢复、首配、路径闸、会话生命周期 |
| 区域二 | B3 + B4 WB-0201..0560 | 360 | 24 端点逐项矩阵；大文件/断点/Windows IO |
| 区域三 | B5 + B6 WB-0561..0780 | 220 | 配对/加密/身份；持久化/DB/配置 |
| 区域四 | B2 + B7 + B8 + B9 + B10 WB-0101..0200、0781..1080 | 400 | 命令契约、发现/网络、日志、前端/mobile、CI/文档 |

## 10. 区域一（B1）施工状态

基线：core `cargo test --lib` 482 passed；本轮结束 core **490 passed / 0 failed**（新增 8 条真实 HTTP/路径/身份/信任测试），desktop **40 passed / 0 failed**。
构建环境：rsproxy 镜像 SSL 不通，使用隔离 `CARGO_HOME=G:/devhome/cargo-qoder` + 官方 index 缓存；`CARGO_TARGET_DIR=D:/code/tools/6a7f5d5699c44b33268ede69/cargo-target`。

### 10.1 已完成（DONE）

- WB-0001 `serve_request` 改用 `path_and_query`；真实 hyper 测试 `real_http_entry_preserves_query` 通过。
- WB-0002 core `parse_query`：严格 percent 解码、重复键拒绝、UTF-8 校验；`duplicate_query_key_is_rejected_and_percent_decoded` 覆盖。
- WB-0003 发送端统一 `pieceIndex + sha256` 上传；删除整文件 POST 路径。
- WB-0004 register/prepare/diff/chunk/verify/tasks 全部检查 HTTP 状态并解析错误体（`checked_json`），4xx/5xx 不计成功。
- WB-0005 私有 scheduler 分块路径从发送主链移除（`desktop/scheduler.rs` 仅剩 B4 待迁移，不再参与发送）。
- WB-0006 `chunk` 校验每文件 CSPRNG token；生产模式校验 Active 配对；`require_active_peer_blocks_unknown_and_allows_paired` 覆盖。
- WB-0007 token 改为 32B CSPRNG（`random_upload_token`），不再 `tok:{fileId}`。
- WB-0008 `.part` 按 `pieceIndex*PIECE_SIZE` 随机写；严格校验索引/长度/重复块；坏块允许修复覆盖。
- WB-0009 每块落盘后本端自算 SHA-256，并与客户端声明比对（412）。
- WB-0010 `handle_chunk` 不再 commit；`handle_verify` 整文件实算 SHA 后才原子提交。
- WB-0011/0012 `validate_rel_path`：拒绝 `..`、绝对路径/UNC、盘符、ADS 冒号、Windows 保留名、尾点/尾空格、控制符、非法字符、超长段；prepare/chunk/verify/sync-api 全部接入。
- WB-0013 请求体改为 `frame()` 流式限长，10MB 上限不依赖 Content-Length。
- WB-0014 接收服务接入 32 连接信号量、hyper 头部读取超时（TokioTimer）、停止信号取消在途连接。
- WB-0015 桌面用 PKCS#8 私钥恢复 core 身份（`DeviceIdentity::restore_from_pkcs8`），失败拒绝启动而非静默换身份。
- WB-0016 base64 统一 URL_SAFE_NO_PAD，兼容旧 STANDARD 数据。
- WB-0017 `start_receiver` 注入 `get_self_code` 到 core；首配不再永远 400。
- WB-0018 `pairing_secret` 改为服务端 CSPRNG，不再由连接码确定性派生。
- WB-0019 `VerifyResponse.device_id` 返回服务端身份；桌面校验 probe/verify 一致并拒绝自配对。
- WB-0021 桌面 `v4_pair` 使用 core `normalize_connection_code`。
- WB-0023 遗留 53318 `check_trusted` 链路不再启动（V4 only）。
- WB-0032 加密传输不再静默降级：ECDH 显式拒绝；simple 走明文并发出 `send-warning`；core 能力位不再广告 CAP_ENCRYPT。
- WB-0033/0034/0035 删除 `__batch__`/`__chunked__`/tiny 私有打包；一个逻辑文件一条 prepare meta。
- WB-0036/0037 删除 `SessionDriver`/逐块 206 探测的旧发送链；整文件 diff 返回完整 missing/mismatched。
- WB-0038 文件哈希/分块读取错误全部上抛；读后复核 size/mtime 防“旧哈希传新内容”。
- WB-0039 分块哈希基于明文字节（加密路径已显式停用）。
- WB-0040 发送终态以接收端 verify + tasks 为准；返回接收端确认文件数。
- WB-0041 App.vue 仅在 `sent === files.length` 时更新全量快照。
- WB-0042 verify 返回本端实算整文件 SHA-256。
- WB-0043 `file_incomplete_reason` 把“缺本端度量”视为未完成。
- WB-0044 `restore_mtime` 统一按毫秒（DTO 单位）。
- WB-0045 旧文件只在 verify 通过后由 `commit_preserving_conflict` 保留副本并替换。
- WB-0047 `pending_parts` 键改为 `(sessionId, fileId)`。
- WB-0048 register 同 owner 幂等、异 owner 拒绝。
- WB-0049 prepare 幂等保留 confirmed；元数据变化 409。
- WB-0050 生产模式拒绝外部 receipt 写终态，回执由 `handle_verify` 内部生成。
- WB-0054 接收端扫描接收目录并喂 core 清单（启动 + 60s 刷新）。
- WB-0055 App.vue 清单不可用时明确确认，取消则不同步；不再静默全量。
- WB-0056 遗留 53318 配对服务不再启动。
- WB-0058 watchdog 改为真实 `/probe` + deviceId 校验；防御隐藏时跳过。
- WB-0059 防御总闸进入 core `serve_request`（隐藏时 403 一切入站），启动时由桌面注入。
- WB-0076/0083/0084/0085 签名密钥失败不落空值；active_sessions/transfer_count 在发送全路径维护；连接码刷新写盘失败保留旧码。
- WB-0100 桌面端 53318 遗留路由隔离（服务不启动；mobile 切换在区域四）。

### 10.2 部分完成（PARTIAL）

- WB-0020 路径 A 仍未做真正的 ECDH 协商（当前为 HMAC + 服务端本地随机 secret）；需 DTO 交换静态/临时公钥（区域三）。
- WB-0022 首配已有连接码校验、一次性 nonce、失败限流（5 次/60s），但**接收端 UI 确认弹窗**尚未接入（`resolve_pairing` 在区域二）。
- WB-0024 `manifest/move/delete/disconnect` 仍以 deviceId 为身份，尚未接入签名/会话令牌（区域二）。
- WB-0029 core 与桌面现在共享同一 PKCS#8 密钥材料，但桌面遗留 ring DER 签名与 core raw64 线路格式尚未统一（区域三）。
- WB-0046 跨目录 `commit_copy_delete` 仍非原子（Windows 默认同目录 rename；跨卷降级待区域二）。
- WB-0057 停止服务会取消在途连接，但未 Join 等待/flush 全部任务（区域二）。
- WB-0060 防御总闸已拦一切入站；`discoverable` 与 probe presence 分层尚未实现（区域二）。

### 10.3 未完成 / 阻塞（BLOCKED，属区域二/三）

- WB-0025..0028 解配对/吊销签名与 DTO：需 `signature` 字段、长期静态公钥交换、raw64 跨端向量。
- WB-0030/0031 接收端 AEAD 解密与真正 ECDH：B5（D1/D2 决策 + DTO cryptoVersion）。
- WB-0051/0052 `disconnect`/`move-to-delete` 真实认证与假删除落盘：B3/B4。
- WB-0053 `SyncStore` 持久化：B6。
- WB-0061..0075 配对/信任/调度权威收敛：B2/B6。（其中 `PeerStore::merge` 已加“吊销不得被旧快照复活”守卫，WB-0064 降为 PARTIAL）
- WB-0077..0082、0086..0099 重置事务、密钥环、存储写穿、bcpd：B5/B6/B7。

### 10.4 本轮新增验收测试

- `server::tests::real_http_entry_preserves_query`
- `server::tests::real_http_full_transfer_flow`（真实 hyper 全链路 register→prepare→diff→chunk→verify→tasks + 落盘校验）
- `server::tests::require_active_peer_blocks_unknown_and_allows_paired`
- `server::tests::prepare_rejects_path_traversal_and_windows_ads`
- `sync::manifest::tests::windows_hostile_paths_are_rejected`
- `identity::tests::restore_from_pkcs8_matches_the_same_key`
- `server::tests::duplicate_query_key_is_rejected_and_percent_decoded`
- `server::control::tests::merge_never_resurrects_revoked_peer`

## 11. 区域二/三/四施工状态（2026-11-09 第二轮执行）

基线：区域一结束 core 490 passed。本轮结束 **core 498 passed / 0 failed / 1 ignored**（新增 8 条），desktop **40 passed / 0 failed**；schema golden 已按 `gen_schema` → `--golden` → `--check` 顺序重生成，45 份 schema 与实现一致（指纹 `65654b6b…`）。
构建注意：core 与 desktop 共享 `CARGO_TARGET_DIR` 时偶发**跨包指纹污染**（表现为 hyper_util 版本冲突 / serde derive "缺失"两种假错误）；定点 `cargo clean -p lanbackup-core` 后消失。后续 CI 用独立 target 目录即可避免。
备份：`backups/region2-b3b4/`（mod.rs / sync_api.rs / persist.rs / atomic_file.rs / dto/sync.rs 改动前副本）。

### 11.1 已完成（DONE）

**B3 端点矩阵（core）**
- WB-0292/0297 `register`：sessionId 字符集闸已有；新增全局 `MAX_SESSIONS=256` 与单设备 `MAX_SESSIONS_PER_PEER=8` 双闸（insert 前后双重检查防竞态）。测试 `register_enforces_per_peer_session_cap`。
- WB-0302/0307 `prepare`：单文件 512GiB / 单会话 1TiB 总量闸；`pieceHashes` 数量必须等于 `piece_count(size)`。测试 `prepare_enforces_size_and_hash_count_gates`。
- WB-0341/0351/0361/0381 `phase`/`heartbeat`/`abort`/`tasks`：统一接入 `ensure_active_peer`（abort 先认证后迁移）。
- WB-0353/0354 `heartbeat`：终态会话 409 拒绝；位图版本改**服务端权威自增**，客户端自报值仅作对账信号。测试 `heartbeat_rejects_terminal_and_version_is_server_authoritative`。
- WB-0363 `abort`：终态会话重复 abort 幂等吸收（200 + cancelled=0），不再 409。旧断言已按新契约更新。
- WB-0391/0401/0411/0421/0431 `sync_api`：manifest/chunk-status/sync-dir/move-to-delete/disconnect 全部走 `require_transferable`；chunk-status 生产模式要求 prepare 签发的文件 token（与 diff 同源）。测试 `disconnect_rejects_untrusted_devices`、`chunk_status_requires_file_token_in_production_mode`。
- WB-0415/0425/0435 新增 `SyncDirResponse` / `MoveToDeleteResponse` / `DisconnectResponse` typed DTO（含 JsonSchema），三处手写 `json!` 移除。
- WB-0417/0427 `sync-dir` rootId 长度闸；`move-to-delete` 单批 ≤1000。

**B4 传输/文件/Windows IO**
- WB-0423/0426 `move-to-delete` 真实落盘：磁盘文件同盘 rename 进 `delete/`，失败显式 rejected；墓碑持久化 `tombstones.json`，重启 + 重扫后合并回清单。测试 `move_to_delete_moves_the_real_file_and_tombstone_survives_restart`。
- WB-0416 目录映射写穿 `sync-dirs.json`，重启恢复。
- WB-0472 `commit_rename` rename 前 `sync_all`；WB-0477 冲突副本同秒撞名 `-2/-3` 序号；WB-0476 `restore_mtime` 保留 1970 前负值（超范围显式报错）；WB-0474 `commit_copy_delete` 降级显式告警。
- WB-0515 `safe_final_path` 接入 `ensure_windows_long_path`（绝对路径 ≥240 字符加 `\\?\`，UNC 走 `\\?\UNC\`），chunk/verify/空文件全链路生效。
- WB-0501/0502/0503/0504 桌面 `scan_dir_recursive`：深度 ≤32 / 条目 ≤20 万（触顶上抛不静默截断）、symlink 与 junction 不跟随、core `*.part.<sid>.<fid>` 临时文件过滤。
- WB-0095/0723 持久化 sid 文件名兜底闸 `sanitize_sid`；WB-0718 持久化临时文件名进程内唯一化（`write_json_atomic`）。

**B5 配对/加密/身份**
- **WB-0030/0031 接收端 AEAD 解密端到端打通**（推翻上一轮"加密停用"决策，见 11.3）：`handle_verify` 对 `encrypted` 文件逐 piece 解密（定长 stride `PIECE_SIZE+16`），明文 SHA-256 比对后才原子提交；密文篡改/密钥缺失一律 412，绝不落密文。测试 `encrypted_file_is_decrypted_on_verify_and_tamper_is_412`。
- WB-0032/0540 `FileMeta` 新增 `encrypted` / `wireSize`；`size`/整文件 sha 保持明文语义，`pieceHashes` 在加密文件上为线路密文哈希；prepare 校验 `wireSize = size + piece_count×16`。
- 发送端（desktop/send.rs）：`peerId` 入参 → 从 `PairingState.secrets` 取 32B 配对 secret → prepare 预演逐 piece 加密得密文哈希 → 上传时同公式重加密（nonce=8B 大端序号，AAD=`lanbackup/v4/piece/{session}/{file}/{index}`，kdf L3/L4）。能力协商三条件缺一即明文 + 可见 `send-warning`（WB-0650 不静默降级）。
- WB-0649 `capabilities()` 恢复声明 `CAP_ENCRYPT`（接收端已真实实现解密）。
- WB-0592 `ConsumedTokens` 消费键改 `(kind, sub, jti)`；WB-0593 jti 保留期 = `exp + 30d`，封死"过期被 prune 遗忘再重放"窗口；WB-0595 verify 限长 4KiB。测试 3 条新增。
- WB-0431 disconnect 认证（未配对 404 / 已吊销 401）。

**B2 命令契约（部分）**
- `send_files` 新增 `peer_id: Option<String>` 参数（typed IPC），App.vue 传 `targetDevice.deviceId`（WB-0121 部分）。

**B10 CI/契约**
- WB-1021/1022 新增 `.github/workflows/windows-ci.yml`：core fmt/clippy(-D warnings)/test/schema-check 阻断，desktop test 阻断；desktop clippy 与 frontend job 暂非阻断（原因见文件注释）。
- WB-1019/1020/1046/1047 golden 按 routes::ALL 生成链路已运行：45 份 schema + 指纹重生成，`--check` 通过。

### 11.2 部分完成（PARTIAL）

- WB-0019/0055 前端仍持有旧投影逻辑（App.vue 大改属 B9，本轮只动了 send_files 调用点）。
- WB-0020 路径 A 无每会话 ECDH：当前 AEAD 密钥由配对 secret 经 L3/L4 派生（两端同公式），`session_shared` 暂以 pairing_secret 充当 —— 代码注释已标注；真正 ECDH 需 DTO 加静态公钥交换。
- WB-0046/0521 跨卷 commit 仍非原子（显式告警已加，Windows 默认同目录 rename 不受影响）。
- WB-0057 停服取消在途连接已做，Join 等待/flush 未做。
- WB-0093/0712 pieces 追加日志无逐行校验和/seq（半行重放跳过已有）；加校验和属格式变更，需同步迁移旧日志，未在本轮做。
- WB-0622 存储密钥与连接码解耦：涉及既有 DB 记录迁移语义，需用户确认迁移策略后实施。
- WB-1035 fmt 门禁：core fmt --check 在 CI 中暂为非阻断（历史格式欠账，未跑全仓格式化以避免区域一 diff 噪声）。

### 11.3 对区域一决策的修正（重要）

上一轮把加密链路整体停用（simple→明文+警告、ecdh→拒绝、`CAP_ENCRYPT` 摘除）。本轮修正：**对称 AEAD 加密已端到端实现并默认参与协商**——已配对设备 + 对端声明 `CAP_ENCRYPT` + 用户要求加密三者同时成立即加密；`ecdh` 模式仍显式拒绝（等 WB-0020 ECDH 接入）。配套行为变化见 11.5。

### 11.4 未完成 / 阻塞（下一轮起点）

- **决策闸未批准**：D1 DPAPI/SQLCipher（WB-0570/0659/0660）、PAKE（WB-0022 长期方案）、cargo-fuzz/proptest（WB-0673/1040）、cargo-audit/deny（WB-0676/1061）——按执行契约第 4 条不引入。
- **B5/B6 剩余**：WB-0561..0568（deviceId 随机化/注册表读取）、WB-0589..0590（fingerprint 分离）、WB-0656..0658（localStorage 秘密清理/原子写/ACL）、WB-0662..0680（跨端向量/威胁模型）、WB-0681..0710（SQLite 迁移事务族）、WB-0711..0741（persist 单写者族——本轮已完成 723/718/0416/0426，其余待做）、WB-0748..0780（config 原子写/typed AppConfig 族）。
- **B2 剩余**：WB-0103..0200 命令契约主体（除 send_files peerId 外未动）。
- **B7/B8 未动**：WB-0781..0860（bcpd→core beacon 迁移、发现限流族）、WB-0861..0940（日志桥/脱敏/requestId 族）。
- **B9 未动**：mobile Java V4 切换（WB-1005/1006/1010/1011 P0）、shared-core 清理族、App.vue 投影族。mobile 仍走 53318/V2，与桌面 V4 不兼容的现状未变。
- **B4 剩余**：WB-0441..0448（core SessionDriver 状态机——桌面发送链已不用它，生产风险降级为 P2）、WB-0465..0470（桌面 scheduler 常量统一）、WB-0480..0484（cleanup 执行器）、WB-0519..0531（Windows 文件占用/云占位/多用户矩阵）。
- **B10 剩余**：WB-1036..1043（三链路 E2E/故障注入/属性测试）、WB-1050..1063（Android CI/发布/SBOM）、WB-1064..1072（旧文档回填/allow(dead_code) 清理——desktop 仍有 31 个 dead_code 警告来自隔离的 53318 遗留）。

### 11.5 本轮新增行为变化（升级须知）

1. **加密传输恢复**：已配对设备间 "simple" 模式现在真加密（AES-256-GCM，nonce=piece 序号，AAD 绑定 session/file/piece）；对端不支持时明文 + 可见告警。**接收端必须同步升级**，否则对端加密协商会被能力位挡下（自动落明文 + 告警，不会传坏数据）。
2. **chunk-status 生产模式要求 token**（与 diff/verify 一致）；旧 mobile 直接查询将得到 401，B9 迁移后恢复。
3. **disconnect 需配对信任**：未配对 404、已吊销 401；重复 abort 幂等返回 200。
4. **心跳版本服务端权威**：客户端自报 bitmapVersion 不再生效；终态会话心跳 409。
5. **会话/文件上限**：全局 256 会话、单设备 8 会话、单文件 512GiB、单会话 1TiB、单批假删除 1000 路径、扫描深度 32/条目 20 万。
6. **准备请求新增字段**：`encrypted` / `wireSize`（明文文件可不传，默认 false/None）；`pieceHashes` 长度必须等于 piece 数。
7. **协议 schema 已重生成**（45 份 + golden 指纹），跨端字段以 `protocol/schemas/v4` 为准。

## 12. 第三轮自主迭代：工业级结构现代化（2026-11-10）

基线：第二轮结束 core 498 / desktop 40。本轮结束 **core 498 passed / 0 failed / 1 ignored**、desktop **41 passed / 0 failed**（净 +1：删 4 个推导码旧测试、增 5 个随机身份测试）、schema `--check` 45 项一致。

### 12.1 已完成（DONE）

**工程结构（WB-1026/1027/1033/1034）**
- **Cargo workspace 统一**：新建根 `Cargo.toml`（members = core + desktop/src-tauri，exclude third_party），desktop 的 `[profile.*]`（LTO/panic=abort/分级优化）整体迁至根，core 的冗余 profile 段删除；单一根 `Cargo.lock`（551 包），依赖版本世代从此一处管理。成员旧锁文件成为死文件（未删除，待 git 清理流程处理，WB-1052 同批）。
- `rust-toolchain.toml` 钉版 `1.99.1` + rustfmt/clippy 组件（CI 与本地同编译器）。
- `.cargo/config.toml` 上收到根（x86-64-v2 基线从仓库根构建同样生效；desktop 子目录同名配置保留为就近覆盖，内容一致）。
- 根 profile 清理 4 个失效包规格（h2/rustls 族，新解析图已不含）。

**身份与秘密（WB-0561/0562/0563/0564/0566/0568/0569/0571、0103/0107）**
- **deviceId 改为随机安装标识**：首次启动 CSPRNG 32 hex → `device_id.txt` 持久化；MachineGuid 派生仅作磁盘故障降级 + 显式告警。同源镜像/克隆机不再共享身份。
- **初始连接码改 CSPRNG 随机**：删除 `generate_code`（FNV+xorshift 推导）及其"哈希种子"日志 —— 推导码与种子日志两个漏洞面同时消灭。`refresh_self_code` 本就随机，语义不变。
- `config_dir` 失败上抛，不再静默落公共 temp；`get_self_code`/`refresh_self_code`/`get_self_info`/`get_device_name` 全部 Result 化，错误穿透到 IPC。
- `set_device_name` 增加长度（1..=64B）与控制符闸；`db_encryption_key` PBKDF2-600k 进程内缓存（每次启动不再烧 600k 迭代）；reg.exe 超时 kill 后 wait 回收子进程。
- 新增测试 5 条（随机码字符集/唯一性、deviceId 落盘跨 init 不变、随机初始码只播种一次、设备名校验）。

**持久化一致性（WB-0711/0726/0727、0681/0682/0683）**
- `SessionPersister` **单写者锁** + `MetaFile.rev` 单调修订号：`set_file`/`update_session`/`set_receipt`/`set_piece` 的读改写全程持锁，并发不再丢更新；meta 临时文件名进程内唯一。
- `PairingPersister`：临时文件名唯一化（并发 persist 不再互踩）；**损坏隔离** —— 坏 `paired_peers.json` 改名为 `.corrupt.<seq>` 留档（吊销记录/secret 不被静默销毁）后从空启动 + error 日志。
- SQLite 迁移**每版本一个事务**（BEGIN IMMEDIATE + DDL + user_version 同事务）；manifest 列缺失改 `pragma_table_info` 检测，删除"报错忽略"补丁；**降级打开拒绝**（库版本 > 程序版本直接报错保护数据）。
- 备注：`save_paired_peers` 复查确认已是单事务全量重写（WB-0688 的崩溃一致性已满足），UPSERT+差集优化降为 P2 待做。

**命令契约与生命周期（WB-0117/0119、0425/0435、0749/0750/0762/0763、0177/0179）**
- **typed AppConfig**：`AppConfig/AppRole/ReceiverConfig/SenderConfig/SendFolder/SyncStrategyCfg`（serde camelCase，与 shared-core `config.ts` 字段一一对应）；`get_config` 返回 typed（损坏返回默认 + error 日志，**不再用空对象覆盖回写**）；`set_config` 大小闸 64KiB + 枚举校验 + **原子写**（唯一临时名 → sync → rename）。
- `TransferState.lifecycle_lock`（tokio Mutex）：start/stop receiver 全程单飞，并发重启不再互踩；stop 与 start 互斥。
- **两个真实响应解析 bug 修复**：`move_to_delete` 读 `moved` 数组长度（此前 `as_u64` 恒 0，前端镜像确认永远以为没删东西）；`send_disconnect` 读 typed `DisconnectResponse.presence`（此前读不存在的 `ok` 字段恒 false，前端把每次断开都当失败）。

### 12.2 部分完成（PARTIAL）

- WB-0125 manifest 认证由 core `require_transferable` 承担；"错误吞成 null"的前端半边（App.vue 2260）待 B9。
- WB-0622 存储密钥与连接码解耦：本轮身份随机化已切断"连接码派生身份"，但 storage_key 仍 PBKDF2(连接码)；彻底解耦需既有库迁移策略，维持待用户确认。
- WB-0688 UPSERT+删除差集（当前单事务全量重写已保证崩溃安全）。
- WB-0567 reg.exe 本地化输出解析（超时/兜底已加固，注册表 API 直读需要 winreg 类依赖，属 D7 决策）。

### 12.3 升级须知（本轮新增行为变化）

1. **旧 deviceId 将失效**：已装设备升级后首次启动生成全新随机 deviceId —— 旧配对记录按 deviceId 关联，需要**重新配对**（与 D3 破坏性迁移策略一致）。连接码不变（沿用已持久化的 self_code.txt）。
2. `get_self_code`/`get_self_info`/`get_device_name` 失败现在返回错误而非假数据；前端对应调用应有 catch。
3. `config.json` 损坏时返回默认配置且**保留原文件**；`role`/`strategy` 非法值 set_config 直接 400。
4. 数据库版本高于程序时拒绝启动（报错信息含升级指引）。
5. workspace 统一后：构建入口建议从仓库根 `cargo build -p backup-desktop`；`desktop/src-tauri/Cargo.lock` 与 `core/Cargo.lock` 已废（根锁为准）。
