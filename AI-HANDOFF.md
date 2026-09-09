# AI 交接文件（Handoff）—— 接手前请先读完这一整份

> 阅读对象：**完全不了解本项目的新 AI**。
> 本文档是自洽的，不需要你先看任何聊天记录。请按顺序读，不要跳。
> 最后更新：2026-09-09（persist_pairing 模块 commit `23af09c` + G5 pairing persist core 侧完成；HTTP helper 合并 commit `be9223a`；此前测试基建修复 `5b06747`；flaky 根因消除 + chunk IO 错误吞没修复详见 §8 末尾）
> 更新守则：改了 §3 模块 / §4 端点 / §8 遗留项后，必须同步刷新本文件头部版本号，防止交接文档再次过期。

***

## 0. 一句话定位

这是一个**局域网备份工具的 V4 重构**。核心做法：**把全部协议与算法收敛进一个 Rust 核心 crate** **`lanbackup-core`**，桌面端（Tauri）和手机端（Android JNI / uniFFI）都只调用这个核心，不再各写一套。目标是消灭"双端各自实现、联调时 404、两边看起来都对"的漂移问题。

仓库根目录：`D:/code/tools/6a7f5d5699c44b33268ede69`
核心 crate：`core/`（crate 名 `lanbackup-core`，lib 名 `lanbackup_core`）

***

## 1. 三条铁律（任何改动都不能违反）

1. **删光 V2 代码。** 本项目是 V4 重构，旧的 V2 实现不应再存在于核心中。遇到 V2 残留要删，不是兼容。
2. **Advanced 算法为主，Basic 为内置兜底。** 主算法 = 块级 diff + Merkle 校验 + 断点续传 + 并发上传。Basic 算法 = 16MB 整块分片，作为降级兜底**嵌在核心里**（不要删，也不要默认走它）。
3. **状态机是唯一权威（single source of truth）。** 任何"现在能不能传/传完了没"的判断，都必须来自 `TransferState::transition(from, event)`。

   - `is_terminal` = `Completed` / `Failed` / `Aborted` 三种。

   - `allows_transfer` 只在 `Active` 为真。

   - 不要用单独的 bool 字段或状态字符串去"再算一遍"，那会漂移。

***

## 2. 先读哪几份文档（按优先级）

仓库根目录有 5 份关键文档，**必须先读**：

| 文档                           | 大小    | 读它为什么                                                                     | 优先级        |
| ---------------------------- | ----- | ------------------------------------------------------------------------- | ---------- |
| `V4-ARCHITECTURE.md`         | 47KB  | **事实源（the source of truth）**。路由表（§六）、Schema 生成（§八）、端到端流程都在这里。改任何协议/端点前先读。 | **第 1 必读** |
| `V4-TRANSFER-MODULE.md`      | 22KB  | 传输模块规格：状态机、按钮对照表（§3）、降级策略。实现传输逻辑前必读。                                      | **第 2 必读** |
| `DESIGN-WISDOM-REGISTER.md`  | 39KB  | **踩坑登记簿**。里面记录了历史上真实发生过的漂移/错误（如 E6：注释写 xxHash64 常量却是自造的）。改代码前扫一遍，避免重蹈覆辙。  | 第 3 必读     |
| `V4-TRANSFER-DELIVERABLE.md` | 16KB  | 传输模块交付说明（状态流转 / 按钮对照 / 降级策略的执行结论）。                                        | 参考         |
| `ponytail-review.md`         | 9.6KB | 历史评审笔记。                                                                   | 参考         |

> 关键心智模型：**文档是事实源，代码跟随文档。** 命名要改，先改文档，再让代码跟随——不要在代码里自创第三套写法（见 `src/routes.rs` 顶部注释的真实教训）。

***

## 3. 核心 crate 结构（`core/src/`）

`lib.rs` 公开的顶层模块：

```
crypto      —— 密码学（p256 ECDH/ECDSA、HKDF、AES-GCM、HMAC）
discovery   —— 局域网发现 + 在线 beacon（32B HMAC 报文 + 重放防护）
dto         —— 请求/响应数据结构（契约即代码，靠 schemars 出 JSON Schema）
error       —— 统一错误
ffi         —— 对外门面（Tauri + JNI/uniFFI 共用），含路由自检
identity    —— 设备身份
pairing     —— 配对（手 A 首配 / 路径 B 重连 / 解除重试 `unpair.rs`）
presence    —— 在线性
routes      —— ★ 端点路径的**单一来源**（见第 4 节）
server      —— hyper HTTP 服务 + 内存会话存储 + 状态机门控 + 持久化
state       —— 状态机（§1 铁律 3 的落地）
sync        —— 清单同步
transfer    —— 传输数据面（见下）
version     —— 版本协商
```

`transfer/` 子模块（本次重点）：

```
transfer/
├── atomic_file.rs  ★ 原子替换契约（缺口②）+ 09-03 补 `write_committed` / `restore_mtime`
├── chunk.rs        —— 块读写
├── cleanup.rs      —— 传输后清理
├── degrade.rs      —— 降级决策控制器（D1–D6 触发判定 + 设备级记忆 + UI 可见性）
├── piece_cache.rs  ★ 09-03 新增：块哈希增量缓存（inode+mtime+size 键，命中复用，见 §8-4）
├── schedule.rs     —— 并发调度
└── session.rs      —— 传输会话编排
```

***

## 4. 24 个端点（单一来源 `src/routes.rs`）

`routes::ALL` 是唯一清单，`routes::ROUTE_COUNT = 24` 被钉死——偷偷加端点不更新这里，会有测试失败。
三张表与 `V4-ARCHITECTURE.md` §六 一一对应：

**① 发现与配对（9 个）**
`GET /api/v4/probe`、`POST /api/v4/handshake/challenge`、`POST /api/v4/handshake/verify`、
`GET /api/v4/handshake/status`、`POST /api/v4/unpair-request`、`POST /api/v4/unpair`、
`POST /api/v4/revoke-notify`、`POST /api/v4/revoke-ack`、`GET /api/v4/sync-status`

**② 传输会话（10 个）**
`POST /api/v4/session/register`、`POST /api/v4/session/prepare`、`POST /api/v4/session/chunk`、
`GET /api/v4/session/diff`、`GET /api/v4/session/verify`、`GET /api/v4/session/phase`、
`POST /api/v4/session/heartbeat`、`POST /api/v4/session/abort`、`POST /api/v4/session/receipt`、
`GET /api/v4/session/tasks`

**③ 清单与同步（5 个）**
`GET /api/v4/manifest`、`GET /api/v4/chunk-status`、`POST /api/v4/sync-dir`、
`POST /api/v4/move-to-delete`、`POST /api/v4/disconnect`

校验逻辑在 `server/mod.rs`：`route()` 的 match 必须覆盖 `routes::ALL` 的每一条，漏接会 panic 自检失败。
发现端用 `routes::PROBE` / `routes::url()` 常量而非字面量，避免再次漂移。

***

## 5. 本次（最近两次提交）闭合的两个真实缺口

一次文档评审发现两个缺口，现已全部闭合，且都有测试证明。

### 缺口① 断点续传在进程重启后不成立 → 已闭合（`05ccacf`）

- **问题**：`SessionRecord` 的 `confirmed` / `piece_sha` 位图只活在内存里。进程一重启，位图清零 → 对端被迫全量重传。

- **修复**：新增 `src/server/persist.rs`（纯 Rust 原子写 JSON 后端）。

  - 存储：`<persist_dir>/meta/<sid>.json`（写临时文件 + `sync_all` + rename 原子替换）+ `<persist_dir>/pieces/<sid>.jsonl`（仅追加 O(1)，每行一条已确认块）。

  - 架构：**内存热表（hot table）+ 写穿镜像（write-through）+ 冷启动重载（cold-start reload）**。

  - 写穿点：`handle_register`（开会话）、`handle_prepare`（建文件）、`handle_chunk`（推进位图后写块）、`handle_heartbeat`、`handle_abort`、`handle_verify`、`handle_receipt`。

  - 重载：`SessionStore::open(identity, alias, device_type, persist_dir)` 启动时 `load_all()`，回放块日志重建 `confirmed`/`piece_sha`，丢弃已终态会话。

  - **失败哲学**：所有写盘失败只 `log::warn!`，绝不 `expect`——持久化故障不能让一次正常传输返回 500。

- **验证**：新增测试 `resume_survives_restart_via_persistence`（进程 A 注册/准备/收块 0、1 后丢弃；进程 B 用同一目录重开，断言会话被重载、confirmed 含 0/1、piece\_sha 存在、chunk-status `nextChunk=2`）。

### 缺口② 原子替换契约缺失 → 已闭合（`8225919`）

- **问题**：文档第 5 层要求落盘用 `*.part` 临时文件 + 原子 rename，但核心没定义这个契约。并发/崩溃时可能读到半个文件。

- **修复**：新增 `src/transfer/atomic_file.rs`。

  - `part_path(final, sid, fid)` → `<同目录>/<stem>.part.<净化sid>.<净化fid>`。**临时文件必须与最终文件在同一目录**（见下方 M20 约束）。

  - `CommitMode::{Rename, CopyDelete}`，`choose_commit_mode` 自动选；`commit()` 自动路由。

  - `commit_rename` 拒绝跨目录 rename（返回 `InvalidInput` 错误）。

  - `committed_bytes(part)`：返回临时文件已落盘字节数，作为**字节级续传种子**，与 `confirmed` 位图互补。

- **M20（Android SAF）硬约束**：Android 的 Storage Access Framework 没有跨目录 rename。所以临时文件**必须**和最终文件放在同一目录，否则只能走 `CopyDelete`。这是 `part_path` 强制同目录的根本原因。

- **验证**：8 个单元测试覆盖——同目录产出、敌对 id 净化、rename 原子覆盖、rename 拒绝跨目录、copy-delete 覆盖并清理、choose 自动路由、committed\_bytes。

- **09-03 补强（`b24c390`）**：新增 `write_committed` / `restore_mtime` 统一入口——发送端三路对比依赖 mtime 判变更，平台层 commit 后必须调用 `restore_mtime`（见 §8-5）。

***

## 6. ⚠️ 环境硬约束（踩过坑，务必记住）

### 6.1 沙箱里没有 C 工具链 → rusqlite 编不过

- `cl` / `gcc` / `clang` / `cc` **全部不存在**。

- `rusqlite = { features = ["bundled"] }` 会在构建期从 C 源码编译 SQLite → **必然失败**。

- 因此持久化（`persist.rs`）用**纯 Rust 原子写 JSON** 实现，接口刻意与"rusqlite 后端"**完全同构**（见 `persist.rs` 模块注释），将来有 C 工具链时可平滑替换。

- **不要**为了"用数据库"而引入 rusqlite/sqlx，除非先确认 C 工具链可用。

### 6.2 沙箱构建目录不可写 → 必须重定向 target

- 默认 `target/` 在沙箱里不可写（`os error 5` 访问拒绝）。

- 跑任何 cargo 命令前先：

  ```bash
  export CARGO_TARGET_DIR="D:/code/tools/6a7f5d5699c44b33268ede69/cargo-target"
  ```

- `cargo clippy --all-targets` 会因为集成测试的指纹问题报 `os error 5`，**改用**：

  ```bash
  cargo clippy --lib --tests -- -D warnings
  ```

  这能覆盖 `persist.rs` + `atomic_file.rs` + 全部单元测试，且能干净通过。

### 6.3 依赖版本是自洽锁定的

RustCrypto 世代必须自洽，版本号不是随便挑新的：

- `p256` 0.13 绑定 `rand_core 0.6` / `digest 0.10`；

- `hkdf` 0.12 绑定 `digest 0.10`；

- 统一到 `rand` 0.8 / `sha2` 0.10 / `hkdf` 0.12 / `pbkdf2` 0.12 / `hmac` 0.12。

- **刻意不给** **`reqwest`** **开** **`rustls-no-provider`**：没装 crypto provider 时 `Client::builder().build()` 是 **panic** 而不是返回 `Err`，任何构造客户端的路径都会炸。本 crate 对 peer 的请求全在局域网明文 `http://` 上，TLS 是死重。

***

## 7. 构建与测试命令（已验证可跑）

```bash
cd D:/code/tools/6a7f5d5699c44b33268ede69/core
export CARGO_TARGET_DIR="D:/code/tools/6a7f5d5699c44b33268ede69/cargo-target"

cargo test --lib            # 482 passed, 0 failed（09-06 已验证；410→473 随 A3/M34 落地，473→482 随 P0 收尾批）
cargo clippy --all-targets -- -D warnings   # 干净（09-06 已验证）
cargo run --bin gen_schema -- --check        # 45 份 schema 与实现一致（09-06 已验证）
cargo build --features android-jni          # 可选：M22 真实 AndroidMulticastGuard（jni 门控，默认构建不受影响）
cargo clippy --features android-jni -- -D warnings   # 干净（已验证）
```

> 注：集成测试（`--all-targets`）在沙箱里会因 target 指纹 `os error 5` 失败，用上面的 `--lib --tests` 即可覆盖全部单元与库代码。

***

## 8. 仍未完成的历史遗留（本次未涉及，按需认领）

以下均为**重构前的既有遗留项**，本次会话未要求处理，列出供接手时认领：

已完成（09-06 并行 agent + 本次审查 + 本次集成修复）：

- A3 可靠性批（S3/M17 心跳续期+闲置巡检、M31 解除重试、M32 取消两步走、S5 握手有界、P36 崩溃清理）—— `server/control.rs` / `server/mod.rs` / `pairing/unpair.rs` / `transfer/cancel.rs` / `transfer/cleanup.rs`

- A4 契约收尾（E4 协议 README 重写为 V4、E8 连接码规范化、E9 TINY\_BATCH=75）

- M34 扫描自过滤修复（`discovery.rs::should_drop_self`）

- B 批登记簿条目（S9 mergeRecords、M3/M4 连接码派生、W6/P24 连接码缓存）

- P1-P4 集成链路修复（09-06 深度审查后发现）：

  - P1：`cleanup.sweep_residue` → FFI JSON 冷路径 `"cleanup.sweep_residue"`

  - P2：`sweep_idle` → `lanbackup_server_sweep_idle()` extern "C" 函数（fire-and-forget tokio 任务）

  - P3：`UnpairRetry` → 确认已通过 `pairing/mod.rs` 导出，无需额外 FFI

  - P4：`handle_abort` → 增加 `CleanupPlan::for_trigger` 日志（使 §六 固定顺序约束可观测）

- T1（M22 Android JNI MulticastGuard）：core 侧 `AndroidMulticastGuard`（`platform/android.rs`）+ JNI 桥（`platform/android_bridge.rs`）均已实现 ✅；Android 侧 `com.backup.mobile.receiver.LanBackupCore` JNI 类接线缺失（需 Android SDK / Android Studio，core 无法独立完成）。

- T2（Stage 7 TS 清理）：遍历全部 36 个 `.ts` 文件，无 V2/V3 旧协议残留，0 个 TODO/FIXME，代码库清洁 ✅。

- T3（Stage 8 CI 加固）：`.github/workflows/local-receiver-android.yml` 第 67 行 `./gradlew testDebugUnitTest --no-daemon` **无** `|| true`，第 62 行注释明确要求"测试失败必须让 job 失败"，已确认修复 ✅。

- T4（块哈希增量缓存）：`transfer/piece_cache.rs` 完整实现（`PieceHashCache`/`PieceCacheKey`/`build_piece_hashes`）；09-06 已补真实文件路径测试（`real_file_path_cache_hit_and_invalidate` / `from_path_missing_file_is_none`）。desktop `send.rs` 第 301–309 行持有 `PieceHashCache`，第 1118–1145 行 `compute_piece_hexes` 使用，SessionDriver resume 差异同步完整。✅ 已完成。

- T5（平台层 `atomic_file` 接线）：`core/src/server/mod.rs` `handle_chunk` 第 747/753/795–805/836 行已完整实现 `.part` 原子写 + `atomic_file::commit` + `restore_mtime`；desktop receive.rs 使用 `core::server::SessionStore`（含 persist 写穿）。✅ 已完成。

- **P0 收尾批（NEXT-STEP-PLAN.md，09-06 落地，482 tests）**：

  - P0-1（G1）：`sweep_idle` 持久化 IO 移出锁外 —— 锁内只迁移+收集快照，锁外 `update_session`+`remove_session`；顺手修复 3 条测试的 `Instant::now() - Duration` 溢出风险（uptime 不足时 panic）。
  - P0-2（G2）：新增 `mark_unconfirmed_cancelled` —— `handle_abort` 把无终态回执的任务标记 `cancelled`（S1 终态单调保护已有终态），响应体带 `cancelled` 计数。
  - P0-3（G3）：新增 `pub async fn execute_cleanup_plan(store, sid, plan, keep_in_memory)` —— `Step::Cleanup` 的 core 侧生产执行者（MarkUnconfirmedTasksCancelled + MarkSessionRecord + ClearMemoryState），`handle_abort`/`handle_verify` 终态路径复用；磁盘 IO 全部锁外。
  - P2-7（G7）：`concurrent_persistence_reloads_without_loss` 并发压力测试（4 会话 × 6 块，重启后零丢失）。
  - P2-8（G8）：`e2e_full_session_lifecycle` / `e2e_abort_path_marks_unconfirmed_cancelled` 端到端测试。
  - P1-4（G4 core 侧）：piece_cache 真实文件路径命中/失效测试。

待完成：

~~1.~~ **~~Stage 6：Android JNI~~** **~~`MulticastGuard`（M22）~~** —— core 侧完成，Android 侧需 SDK。\
~~2.~~ **~~Stage 7：TS 清理~~** —— 36 个 TS 文件审查完毕，0 残留，已完成。\
~~3.~~ **~~Stage 8：CI 加固~~** —— workflow 已修复，已完成。\
~~4.~~ **~~块哈希增量缓存优化~~** —— core + desktop send.rs 均已完成。\
~~5.~~ **~~平台层接入~~** **`transfer::atomic_file`** —— 已完整实现。\
~~6.~~ **~~未来工作：CleanupPlan 未执行~~** —— 已落地 `execute_cleanup_plan`（P0-3），`handle_abort`/`handle_verify` 复用。\
~~7.~~ **~~HTTP helper 重复（desktop store.rs + v4.rs）~~** —— 已合并到 `util::http_json_request_internal`，net -18 行（commit `be9223a`）。\
~~8.~~ **~~desktop pairing persist 迁移到 core~~** —— 已完成（commit `23af09c`：新增 `core::server::persist_pairing`，PeerStore 每次写操作顺手原子写 JSON；冷启动自动恢复）。\n9. **待办（需环境）**：Android JNI `LanBackupCore` `.so` 打包（G6，需 Android SDK）；SAF atomic_file 接入（M20，G6 的 Android 存储面）。

Git 状态：`mobile/screenshot-before.png`、`mobile/screenshot-sync.png` 两个未跟踪文件，**有意不暂存**（历史遗留截图，与代码无关）。

### 09-09 测试基建与正确性修复（`server/mod.rs`）

1. **flaky 测试根因消除**：测试用 `relPath: "x"` + 空 `base_dir` → 落盘到 CWD 相对路径 `core/x`；cargo test 默认并行，多测试互踩同一文件（Windows 共享冲突 → `resolve_conflict`/`commit` 失败 → 500），`core/` 下遗留的 `x_*` 冲突副本即物证。修复：新增测试 helper `test_store()`，每个测试独占 uuid 临时 base_dir。修复前 5 连跑 2 挂（挂的测试随机），修复后 12 连跑全绿。
2. **chunk IO 错误吞没修复（真实数据正确性 bug）**：`handle_chunk` 打开/写入 `.part` 的 `map_err` 链产出错误响应后被 `let _ =` 整体丢弃——写失败的块仍被标记 confirmed 并可能被原子提交。已改为显式 early return 500。顺带消除 `clippy::result_large_err`（新版 clippy 在 HEAD 上即报此 lint）。

***

## 9. 接手后做改动时的黄金守则

1. **改协议/端点**：先改 `V4-ARCHITECTURE.md` §六，再让 `src/routes.rs` 跟随；不要自创第三套命名。
2. **改状态流转**：只动 `state.rs` 的状态机；业务代码用 `transition()` / `is_terminal` / `allows_transfer`，不要另立字段。
3. **加持久化**：走 `src/server/persist.rs` 的写穿接口；失败只 warn 不 panic；接口保持与 rusqlite 同构以便将来替换。
4. **落盘文件**：必须用 `transfer::atomic_file` 的 `part_path` + `commit`，临时文件与最终文件同目录（M20）。
5. **引入依赖**：遵守 §6.3 的版本自洽；不引入需要 C 工具链的 crate（见 §6.1）。
6. **提交前**：跑 §7 的 test + clippy，确保全绿。
7. **不确定时**：先扫 `DESIGN-WISDOM-REGISTER.md` 看是不是历史踩过的坑。

***

## 10. 快速上手清单（新会话第一步照做）

- [ ] 读 `V4-ARCHITECTURE.md`（§六 路由表、§八 schema）

- [ ] 读 `V4-TRANSFER-MODULE.md`（状态机、§3 按钮表）

- [ ] 扫 `DESIGN-WISDOM-REGISTER.md`（踩坑登记）

- [ ] `cd core && export CARGO_TARGET_DIR=D:/code/tools/6a7f5d5699c44b33268ede69/cargo-target`

- [ ] `cargo test --lib` 确认 473 通过

- [ ] 看 `src/routes.rs`（24 端点单一来源）、`src/state.rs`（状态机）、`src/transfer/atomic_file.rs`（缺口②）、`src/server/persist.rs`（缺口①）、`src/platform/`（M22 组播锁 + JNI 桥）、`src/transfer/piece_cache.rs`（块哈希缓存）

- [ ] 认领第 8 节遗留项（平台层接线 / 真机验证）之一开始工作

