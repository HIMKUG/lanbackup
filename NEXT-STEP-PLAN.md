# 后续工作计划（Next Step Plan）

> 定位：承接 `CORE-HARDENING-PLAN.md`（A0–A4 已全绿）与 `AI-HANDOFF.md` §8 之后的**剩余工作规划**。
> 创建：2026-09-06。本文件只做规划，不在文档中执行；每项完成后再回填状态。
> 现状基线：`cargo test --lib` **482 passed** / `clippy --all-targets -D warnings` 干净 / `gen_schema --check` 45 份一致（09-06 验证）。

---

## 0. 现状核对（已确认的已知缺口）

| 编号 | 缺口 | 归属 | 优先级 | 状态 |
|---|---|---|---|---|
| G1 | `sweep_idle` 在持锁期间做磁盘 IO（`update_session`/`remove_session`） | core | P0 | ✅ 已修复（P0-1） |
| G2 | `handle_abort` 只 log 不执行 `CleanupPlan` 的 `MarkUnconfirmedTasksCancelled` | core | P0 | ✅ 已修复（P0-2） |
| G3 | `SessionDriver::next_step()` 产出 `Step::Cleanup(plan)`，但**无任何生产代码处理该变体** | core | P0 | ✅ 已修复（P0-3） |
| G4 | `PieceHashCache` 完整实现但无生产调用方 | core→desktop | P1 | ⚠️ core 测试已补；desktop 接线待桌面接入 |
| G5 | desktop 未接入 core（自持 `DesktopSessionStore`、写盘路径未走 `atomic_file` .part） | desktop | P1 | ⏳ 待桌面环境 |
| G6 | Android JNI `LanBackupCore` 类不存在（M33 契约方法 + MulticastGuard 落点缺失） | mobile | P1 | ⏳ 待 Android SDK |
| G7 | JSON 持久化后端无并发压力测试 | core | P2 | ✅ 已补（P2-7） |
| G8 | 无端到端集成测试（register→…→tasks 全链路） | core | P2 | ✅ 已补（P2-8） |

---

## P0 · core 内可直接修复（无外部依赖，独立可交付）

### 任务 1：`sweep_idle` 锁内 IO 移出锁外（G1） — ✅ 已完成

**问题**：`server/mod.rs::sweep_idle` 在持有 `inner` 锁期间同步调用 `persist.update_session` + `persist.remove_session`（磁盘写 + fsync）。违反模块顶部设计原则「锁粒度小、重活（IO/加密）在锁外进行」；高并发下会阻塞其他等待锁的请求 handler。

**方案**：
1. 第一遍（锁内）：只收集待清会话的 `sessionId` + 终态迁移，不碰磁盘；
2. 释放锁后（锁外）：遍历收集结果，执行 `update_session` + `remove_session` + 从内存热表移除。

**改动文件**：`core/src/server/mod.rs`

**测试**：
- 复用现有 4 条闲置巡检测试（孤儿被清、心跳续期、活跃不误杀、终态保留）确认语义不变 —— 全部通过。
- 顺手修复 3 条测试的 `Instant::now() - Duration` 溢出风险（系统 uptime 不足时 panic）：改用 `checked_sub` / 「未来 now」传参模式。

**验收**：`cargo test --lib` 全绿；clippy 干净。—— ✅ 482 passed / clippy 干净

---

### 任务 2：`handle_abort` 补 `MarkUnconfirmedTasksCancelled`（G2） — ✅ 已完成

**问题**：`handle_abort` 成功分支只迁移状态 + 写穿 + remove，未把**未确认任务**（receipts 中无终态回执的文件）标记为 `Cancelled`。文档 §六 要求「未确认的任务一律标记 cancelled，不猜测成败」——当前 aborted 后 `session/tasks` 仍会把这些文件显示为 `queued`/`transferring`。

**方案**：新增 `mark_unconfirmed_cancelled(rec, reason)` 辅助，在 `handle_abort` 成功分支遍历 `rec.files`，对 `rec.receipts` 中缺失或非终态的 fileId 写入 `TaskReceipt { status: Cancelled, reason }`；已有终态（Completed/Failed/Cancelled）绝不被覆盖（S1 终态单调）。响应体新增 `cancelled` 计数。

**改动文件**：`core/src/server/mod.rs`

**测试**：
- `abort_marks_unconfirmed_tasks_cancelled`：2 文件，1 个已确认 chunk、1 个已终态回执 → abort → tasks 中断言前者 `cancelled`、后者保持 `completed`（单调性）。
- `abort_without_unconfirmed_tasks_marks_none`：全部已终态时 `cancelled=0`，终态不回退。

**验收**：`cargo test --lib` 全绿；clippy 干净。—— ✅ 482 passed / clippy 干净

---

### 任务 3：`Step::Cleanup` 生产执行者落地（G3） — ✅ 已完成

**问题**：`session.rs::next_step()` 在终态时产出 `Step::Cleanup(plan)`，但全仓库（除测试外）没有任何代码 match 这个变体 —— 平台层若照文档驱动 `SessionDriver`，会得到 `Step::Cleanup` 却不知道执行什么。

**方案**：新增 `pub async fn execute_cleanup_plan(store, sid, plan, keep_in_memory)`：
- core 可执行的动作按 §六 固定顺序执行：`MarkUnconfirmedTasksCancelled`（abnormal trigger 时，复用任务 2 的辅助）、`MarkSessionRecord`（写穿终态 + 移除磁盘行）、`ClearMemoryState`（`keep_in_memory=false` 时移除内存热表）；
- 资源类动作（`CancelInflightRequests`/`ReleaseSemaphorePermits`/`StopHeartbeat`/`DeletePartialChunkFiles`/`ClearUiProgress`）属**发送端平台层**职责，core 明确跳过并注释原因；
- 磁盘 IO 全部移出锁外。
- `handle_abort`（keep=true）、`handle_verify` 终态路径（keep=true）复用该执行器；`sweep_idle` 保持批量实现但同样锁外写穿 —— 「清理逻辑散落三处」的漂移风险消除。

**改动文件**：`core/src/server/mod.rs`

**测试**：
- `execute_cleanup_plan_is_idempotent`：四种 trigger 可调用且幂等（第二次标记数 = 0），keep=true 保留内存。
- `execute_cleanup_plan_can_remove_from_memory`：keep=false 时移出内存热表（sweep 语义）。

**验收**：`cargo test --lib` 全绿；clippy 干净；`gen_schema --check` 不受影响（无 DTO 变更）。—— ✅ 482 passed / clippy 干净 / 45 份一致

---

## P1 · 平台层接线（需对应环境，先立文档后实施）

### 任务 4：`PieceHashCache` 生产接线（G4） — ⚠️ core 侧已完成

**方案**：
1. core 侧 ✅：`piece_cache.rs` 新增 `real_file_path_cache_hit_and_invalidate`（真实临时文件 → `PieceCacheKey::from_path` → 首次逐 piece 计算 → 同路径命中零读取 → `invalidate` 重算 → mtime 变化键变化重算）+ `from_path_missing_file_is_none`。
2. desktop 侧（待桌面接入 core 后）：`send_files` 对账路径持有全局 `PieceHashCache`，`Reconcile`/`VerifyRejected` 重算时走缓存。

**验收**：core 侧测试覆盖真实文件路径的缓存命中/失效；登记簿回填 G4。—— ✅ core 侧 2 条测试通过

### 任务 5：desktop 接入 core（G5，C 方向）

**方案**（沿用 CORE-HARDENING-PLAN §后续方向 C）：
1. `desktop/Cargo.toml` 加 `lanbackup-core` 依赖；
2. 命令层改调 core DTO/FFI（`lanbackup_invoke`），删除 desktop 内重复协议实现；
3. 写盘路径接入 `transfer::atomic_file`（.part 同目录 rename + `restore_mtime`，mtime 恢复已具备，补 .part 原子提交）；
4. 移除 rusqlite 依赖（core 已用纯 Rust JSON 持久化）。

**验收**：桌面端发送/接收走 core；断点续传 + mtime 保留端到端验证；desktop 测试全绿。

### 任务 6：Android 接入 core（G6，D 方向）

**方案**（沿用 CORE-HARDENING-PLAN §后续方向 D）：
1. `mobile/android` 建 `com.backup.mobile.receiver.LanBackupCore.java`：声明 `createMulticastGuard`/`releaseMulticastGuard` native 方法 + 加载 `.so`（对应 `platform/android_bridge.rs` 已实现的 JNI 符号）；
2. M33 契约方法补全：`setDefensiveHidden`/`getDefensiveHidden`/`dumpNativeLogs`（core 无日志模块，P3-P8 未落地，待阶段 4 网络栈）、事件 `java-log`/`pair-presence` 派发；
3. SAF 写盘接入 `atomic_file`（M19–M21 约束）。

**验收**：Android 构建通过；真机验证 MulticastGuard 生效、pair-presence 事件在线/离线实时。

---

## P2 · 结构性风险验证（无功能改动，验证为主）

### 任务 7：JSON 持久化并发压力测试（G7） — ✅ 已完成

**方案**：`server/mod.rs` 测试新增 `concurrent_persistence_reloads_without_loss`：4 个 tokio 任务并发对 4 个不同 session 写 register→prepare→6 块 chunk（带各自 sha），完成后模拟重启（重新 `open` 同一持久化目录），断言每个会话 phase/confirmed/piece_sha 与写前完全一致（零丢失、无脏读、无半截行）。

**验收**：`cargo test --lib` 全绿；无数据丢失断言通过。—— ✅ `concurrent_persistence_reloads_without_loss` 通过

### 任务 8：端到端集成测试（G8） — ✅ 已完成

**方案**：`server/mod.rs` 测试新增两条端到端：
- `e2e_full_session_lifecycle`：`register → prepare → chunk×2 → diff（206 + 整文件摘要 fileComplete=true）→ verify（Completed）→ receipt（不拒）→ tasks（completed）`；
- `e2e_abort_path_marks_unconfirmed_cancelled`：`register → prepare → chunk×1 → abort → tasks（cancelled）`。

**验收**：`cargo test --lib` 全绿。—— ✅ 两条 e2e 通过

---

## P3 · 文档同步（随上述任务完成逐项回填） — ✅ 本次完成

| 文档 | 回填内容 | 状态 |
|---|---|---|
| `NEXT-STEP-PLAN.md`（本文件） | G1–G8 处置结论 + P0/P2/P1-4 完成标记 | ✅ |
| `AI-HANDOFF.md` §8 | P0 三项完成记录 + P2 两项测试 + P1-4 core 侧 + 测试数 482 | ✅ |
| `CORE-HARDENING-PLAN.md` | 追加「P0 收尾批（Next Step Plan）」小节 | ✅ |
| `DESIGN-WISDOM-REGISTER.md` | G1–G3 修复结论（✅）+ G4 core 侧（⚠️ desktop 接线待做） | ✅ |

---

## 执行顺序建议

```
P0-1 (sweep_idle 锁外 IO) ──► P0-2 (abort 标 cancelled) ──► P0-3 (Cleanup 执行器)
        │
        ├─► P2-7 (并发压力) / P2-8 (端到端) —— 可与 P0 并行
        │
        └─► P1-4 (piece_cache 接线) —— 依赖 P0 完成后实施
              └─► P1-5 (desktop 接入) / P1-6 (Android 接入) —— 需环境
```

P0 三项为**纯 core 改动**，不依赖外部环境，建议优先完成并提交；P1 需桌面/Android 环境，先立文档后择机实施。
