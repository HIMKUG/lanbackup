# Core 加固执行计划（Core Hardening Plan）

> 定位：V4 core 的「补漏洞」主线计划，对齐 `DESIGN-WISDOM-REGISTER.md` 中尚未在 core 落地的条目。
> 创建：2026-09-06（经用户确认后全量推进，A0→A1→A2→A3→A4）。
> 完成标记：每批完成后在下方勾选并回填登记簿。

## 前提：现状核对结论（2026-09-06 已用代码核实）

| 登记簿条目 | core 实际状态 | 处置 |
|---|---|---|
| E3 golden schema | ✅ 已解决（迁移到 `protocol/schemas/v4/golden-manifest.json`，schemaHash 为真实 SHA-256） | 登记簿回填 |
| A8 mtime 保留 | ✅ 已落地（`transfer/atomic_file.rs::restore_mtime` 契约 + DTO `FileMeta.mtime`） | 登记簿回填 |
| W7/W8 路径穿越 | ✅ 已落地（`sync/manifest.rs::is_safe_rel_path` 否决 `..` 段 + 盘符 `:` 冒号组件） | 登记簿回填 |
| M22 组播锁 | ✅ 核心层已闭环（`platform/android.rs` + JNI 落点）；.so 打包/Kotlin 声明属 mobile/ 集成 | 登记簿回填（⚠️ 写理由） |
| S10 lastManifest 持久化 | ❌ 无实现 | A2-1 补 |
| M2 连接码不上线 | ⚠️ `dto/sync.rs` 存在 `deviceCode` 字段，需排查是否泄漏进响应体 | A2-2 补 |
| D7/D8/M18 长度上限 | ❌ server 无 Content-Length 上限 | A1 补 |
| S11 密钥轮换 | ❌ crypto 无 previousKeys 机制 | A2-5 补 |

## A0 · 盘点与登记簿回填（前置小步）

- [ ] 回填 E3 / A8 / W7 / W8 → ✅
- [ ] 回填 M22 → ⚠️（核心闭环，mobile/ 集成待做）
- [ ] 产出精确《core 缺口清单》，作为 A1–A4 输入

## A1 · 安全高危批（独立可交付）

> **执行偏差记录（2026-09-06 已核实）**：
> - D3 在 core 已天然满足 —— `discovery.rs::probe_client` 设全请求 700ms 超时（含 connect），回填 ✅；
> - D7 等价落地为 HTTP body 10MB 双闸（core 为块级 AEAD，无流式 clen 分配），回填 ✅；
> - D8 在 core 不适用（hyper 读 HTTP + 整块 AEAD，无手写固定头流读取），回填 ⚠️；
> - M18 三项：body 10MB ✅ 落地；请求行 16384B 以 `MAX_REQUEST_LINE_BYTES`/`hyper_http1_builder` 注入；tar 单成员 100MB 属 mobile/ 集成（core 无 tar 路径），随 D 手机接入落地；
> - P32/P33 以常量 + 接线文档交付（并发闸/超时闸在接入端 hyper server 装配），回填 ⚠️；
> - P26 新增 `crypto/id.rs`（`new_session_id`/`new_file_id`，32 字节 CSPRNG → 64 hex）。

| # | 条目 | 落点 | 测试 |
|---|---|---|---|
| A1-1 | D7 认证前长度上限 + M18 body 10MB | `server/mod.rs::body_limit_check`（Content-Length 预检 + 实际大小复核双闸） | ✅ 4 条（声明超限/实际超限/边界内/边界外） |
| A1-2 | M18 请求行 16384B / tar 单成员 100MB | `server/mod.rs`：`MAX_REQUEST_LINE_BYTES` + `hyper_http1_builder`；tar 归 mobile/ | ✅ 接线断言 2 条（常量契约/注入路径） |
| A1-3 | D8 固定头循环读满 | —（V4 用 hyper + 整块 AEAD，core 无手写流读取） | 登记簿回填 ⚠️ |
| A1-4 | P32/P33 有界并发 32 + 读写超时 30s | `MAX_UPSTREAM_CONNECTIONS` / `IO_TIMEOUT` 常量 + 接线文档 | ✅ 常量断言并入 A1-2 |
| A1-5 | D3 connect 超时 | `discovery.rs::probe_client`（700ms 全请求超时，已存在） | 登记簿回填 ✅ |
| A1-6 | P26 CSPRNG（sessionId/folderId） | `crypto/id.rs::new_session_id` / `new_file_id` | ✅ 4 条（长度/字符集/差异/无碰撞） |

**验收**：`cargo test --lib` 全绿（420 passed）、`cargo clippy --lib --tests -- -D warnings` 干净 —— **已达标**。

- [x] 完成

## A2 · 数据正确性批

> **执行偏差记录（2026-09-06 已核实）**：
> - A11/A12（diff 四态 + ETag 双引号）在 core 已天然满足 —— `server/mod.rs::handle_diff`
>   全四态 + `etag_of`/`parse_validator`，回填 ✅；
> - A6（size 不一致 = 残留）在 core 已实现 —— `sync/plan.rs::decide` 单列 `residual` 并入
>   uploads，回填 ✅；
> - M2 补强：`device_code` 字段重命名为 `device_id` + `build_manifest` 参数改名 + 新增
>   序列化契约测试 `serialized_manifest_has_no_extra_code_field` 锁住 wire schema。

| # | 条目 | 落点 | 测试 |
|---|---|---|---|
| A2-1 | S10 lastManifest 持久化 | `server/persist.rs::write_last_manifest` / `load_last_manifest`（临时文件 + sync_all + 原子 rename） | ✅ `s10_last_manifest_survives_store_restart`（两轮进程模拟） |
| A2-2 | M2 连接码不进响应体 | 全量排查 DTO + `dto/sync.rs` 重命名 + 注释；`build_manifest` 参数改名 | ✅ `serialized_manifest_has_no_extra_code_field`（顶层键集合锁死） |
| A2-3 | A11/A12 GET /diff 四态 + ETag 双引号 | `server/mod.rs::handle_diff`（206/412/416/200）+ `etag_of`/`parse_validator` | ✅ 5 条（200 摘要/206 匹配/412 NACK/416 越界/W/ 拒绝） |
| A2-4 | A18/A19 冲突处理（绝不覆盖、幂等跳过） | `transfer/atomic_file.rs::resolve_conflict` → `ConflictOutcome` | ✅ 冲突重命名/幂等跳过测试 |
| A2-5 | S11 密钥轮换（previousKeys 7 天/5 个） | `crypto/keyring.rs::KeyRing`（rotate/prune/降序解密） | ✅ 旧密钥解密回退测试 |
| A2-6 | A6 size 不一致 = 变更非缺失 | `sync/plan.rs::decide`（residual 单列） | ✅ `size_mismatch_on_peer_is_residual` |

**验收**：`cargo test --lib` 全绿（433 passed）、`cargo clippy --lib --tests -- -D warnings` 干净 —— **已达标**。

- [x] 完成

## A3 · 可靠性批

> **执行偏差记录（2026-09-06 已核实）**：
> - S3/M17 实现中挖出两个真实 bug 并同批修复：① `handle_heartbeat` 原未续期
>   `last_activity`，在线会话会被闲置巡检误杀（心跳就是"我还在线"的信号）；
>   ② `sweep_idle` 原只把孤儿会话迁到 `Aborted` 却不移出内存热表，泄漏依旧。
>   测试 `s3_heartbeat_renews_activity_and_defers_sweep` / `m17_orphan_session_is_swept_after_idle_timeout`
>   锁死两条路径。
> - S5 落地为握手会话**有界管理**：`HandshakeStore::insert` 满员驱逐（64，优先赶走
>   最旧 Pending）+ `prune_sessions` 过期清理（Pending TTL=challenge TTL，终态宽限
>   300s 后移除）。会话内 `pairing_secret` 随之释放，无密钥滞留。
> - M32 实现中修正顺序契约：`CancelTwoStep::feed` 只接受 `next()` 指出的那一步，
>   乱序上报直接拒绝（原实现先喂 `NotifyPeer` 会提前占用槽位）。
> - P36 已落地为 `transfer/cleanup.rs::is_residue_name` + `sweep_residue`（递归删、
>   尽力而为、目录本身不删）。

| # | 条目 | 落点 | 测试 |
|---|---|---|---|
| A3-1 | S3/M17 会话闲置巡检（60s/300s） | `server/mod.rs::IDLE_SWEEP_INTERVAL`/`IDLE_TIMEOUT`/`sweep_idle` + `handle_chunk`/`handle_heartbeat` 续期 | ✅ 闲置清理/心跳续期/终态保留计时测试 |
| A3-2 | M31 解除配对重试 3 次 | `pairing/unpair.rs::UnpairRetry`（request→revoke-notify 通道切换） | ✅ 重试/放弃测试 |
| A3-3 | M32 取消收件两步走 | `transfer/cancel.rs::CancelTwoStep` | ✅ 四成败组合/乱序拒绝测试 |
| A3-4 | S5 拒绝会话清理 ECDH 密钥 | `server/control.rs::HandshakeStore`（满员驱逐 + prune_sessions） | ✅ 无界增长防护/过期清理测试 |
| A3-5 | P36 崩溃残留 `.tmp_*` 清理 | `transfer/cleanup.rs::sweep_residue` | ✅ 残留清理测试 |

**验收**：`cargo test --lib` 全绿（460 passed）、`cargo clippy --lib --tests -- -D warnings` 干净 —— **已达标**。

- [x] 完成

## A4 · 契约收尾（穿插）

> **执行记录（2026-09-06 A4 已落地）**：
> - E4：`protocol/README.md` 重写为 V4 契约 —— 版本统一为 4（对齐 core `PROTOCOL_VERSION`）、
>   端口 53317、端点表对齐 `schemas/v4/golden-manifest.json` 的 16 个 `/api/v4/*` 端点；
>   v2/v3/v5 残留文件（`protocol/golden/` 全目录 + `schemas/` 根下 9 个旧 schema 含
>   v5-unpair）已删除，README 内「3.0 vs 3.1」「无 pair/initiate vs manifest 列出」矛盾消除。
> - E8：core 采用严格版连接码规范化 —— `identity.rs::normalize_connection_code`
>   （只保留 `[A-Z0-9]` 并统一大写，幂等测试），输入边界 `HandshakeStore::set_pairing_code`
>   统一调用；`path_a_request` 测试同步演示客户端同规则。
> - E9：`version.rs::TINY_BATCH_SIZE = 75`（50-100 平衡区间中值），注释改写为 V4 决策说明。

- [x] E4 协议目录矛盾清理（v2/v3 残留文件已删除）
- [x] E8/E9 连接码规范化、TINY_BATCH 统一
- [x] 登记簿「每阶段回填」机制固化

## 后续方向（C/D 简纲，本次不执行）

- **C 桌面接入 core**：desktop `Cargo.toml` 加 `lanbackup-core` → 删 `localsend` + V2 模块 → 命令层改调 core DTO/FFI → 移除 rusqlite 依赖。
- **D 手机接入 core**：补 M33 契约 + JNI 桥 `.so` + SAF（M19–M21）+ 前台服务（M23）/WakeLock（M24）。
