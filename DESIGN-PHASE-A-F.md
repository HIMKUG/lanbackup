# LAN Backup 推进到可直接应用的详细设计方案

> 本文档将推进 desktop + mobile 到 production-ready 状态，全部协议统一为 v4

---

## 核心问题诊断

**现状**：core 是完美的协议孤岛（482 测试通过），但 desktop 和 mobile 几乎未连接到 core。

| 层面 | 当前状态 | 问题 |
|------|----------|------|
| Desktop 发送 | 自建 v4 请求，绕过 SessionDriver | 未使用 core 决策引擎 |
| Desktop 配对 | v3 协议 | 应升级到 v4 |
| Desktop 发现 | LocalSend v2 multicast + v3 probe | 应替换为 core presence/discovery |
| Desktop 存储 | rusqlite + session_store.rs | 应分层：core 协议状态 + 平台 UI 状态 |
| Mobile | 100% v2 手写协议 | 应通过 JNI 连接 core |
| core atomic_file | 零调用方 | 应连接到服务端 |
| core piece_cache | 零调用方 | 应连接到发送端 |

---

## 架构决策

| 编号 | 决策 | 理由 |
|------|------|------|
| D1 | 发送侧使用 SessionDriver 作为唯一调度器 | 决策与 IO 分离，核心价值所在 |
| D2 | 配对使用 core 纯计算 + desktop HTTP 客户端 | core pairing 模块无 IO，平台负责网络 |
| D3 | 发现替换为 core presence + discovery | 统一协议栈，消除 LocalSend v2 依赖 |
| D4 | 持久化分层：core 管协议状态，rusqlite 管 UI 状态 | 保持平台特性，core 不绑定存储后端 |
| D5 | Mobile = JNI bridge + 协议替换 | Android 需要 JNI，不能直接调用 Rust |

---

## 六阶段实施计划

```
Phase A ──────────────────────────► Phase B ──────────────────────────► Phase F
  │                                    │                                 │
  │                                    │                                 │
  ▼                                    ▼                                 ▼
Phase D                              Phase C
```

### Phase A: 发送侧接入 core SessionDriver（最高优先级）

**目标**：desktop 发送完全通过 SessionDriver，删除 scheduler.rs 协议层

**涉及文件**：
- `desktop/src-tauri/src/transfer/send.rs` — **重写**
- `desktop/src-tauri/src/transfer/scheduler.rs` — **删除**

**改造要点**：
1. 导入 `lanbackup_core::transfer::{SessionDriver, Step, Outcome, ChunkPlan, compute_chunk_diff}`
2. 删除自建 DTO（`SessionRegisterRequest` 等），改用 core DTO
3. 替换 `active_sessions` Map 为 `SessionDriver` 实例
4. 实现 `next_step() → Step → 执行 IO → feed(Outcome)` 循环
5. `prepare_files()` 构建 `ChunkPlan` 后调用 `driver.start(plan, prefer_basic)`
6. 删除 `scheduler.rs` 中所有协议逻辑

**验证**：发送端 desktop ↔ 接收端 desktop v4 完整流程

---

### Phase B: 配对升级到 v4 协议

**目标**：删除 v3 配对代码，使用 core pairing 纯计算

**涉及文件**：
- `desktop/src-tauri/src/pairing/v3.rs` — **删除**
- `desktop/src-tauri/src/transfer/v3.rs` — **删除**
- `desktop/src-tauri/src/pairing/auth.rs` — **改造路由**
- `desktop/src-tauri/src/transfer/store.rs` — **删除 v3/v2 客户端函数**
- `desktop/src-tauri/src/transfer/mod.rs` — **删除 v3 re-export**

**改造要点**：
1. 导入 `lanbackup_core::pairing::{transition, Claims, mint}`
2. `v3_probe` → 使用 core `discovery` 模块的 probe
3. `v3_handshake_*` → 使用 core `pairing` 状态机 + desktop HTTP
4. `v3_pair` → 使用 core pairing transcript + token
5. 删除所有 `#[allow(dead_code)]` v3 函数（不再需要）

---

### Phase C: 发现模块替换为 core presence + discovery

**目标**：消除 LocalSend v2 multicast 和 v3 probe

**涉及文件**：
- `desktop/src-tauri/src/bcpd.rs` — **删除**
- `desktop/src-tauri/src/discovery.rs` — **删除 LocalSend v2 部分**
- `desktop/src-tauri/Cargo.toml` — **删除 `localsend` 依赖**

**改造要点**：
1. 使用 core `presence` 模块的 UDP beacon（HMAC + M22 multicast guard）
2. 使用 core `discovery` 模块的 scan_targets
3. 删除 `bcpd.rs` 中 LocalSend v2 multicast 代码
4. 删除 `localsend` Cargo 依赖

---

### Phase D: core atomic_file 和 piece_cache 接入

**目标**：core 的可靠写入和增量缓存真正发挥作用

**涉及文件**：
- `core/src/server/mod.rs` — **接入 atomic_file**
- `desktop/src-tauri/src/transfer/send.rs` — **接入 piece_cache**

**改造要点**：
1. `atomic_file`：服务端接收 chunk 时使用 `.part` 临时文件 + rename
2. `piece_cache`：发送端 reconciliation 后缓存 piece hash，resume 时使用

---

### Phase E: Mobile 通过 JNI 连接 core

**目标**：Android 使用 core v4 协议

**涉及文件**：
- `mobile/android/app/src/main/java/com/example/lanbackup/LanBackupCore.java` — **新增 JNI 类**
- `mobile/android/app/src/main/cpp/lanbackup_jni.cpp` — **新增 JNI 桥接**
- `mobile/android/app/src/main/java/.../LocalReceiverPlugin.java` — **改造/替换**

**改造要点**：
1. 创建 `LanBackupCore.java`：封装所有 JNI 调用
2. `native_init()`, `native_invoke(json)`, `native_vec_free(ptr)`
3. 实现 `FFI` cold path 调用 `lanbackup_invoke()`
4. 替换 `LocalReceiverPlugin.java` 中的 v2 协议为 core v4
5. Mobile 发送端：使用 core SessionDriver（通过 JNI）

---

### Phase F: 最终验收门

**目标**：所有协议统一 v4，无残留

**验收条件**：
- [ ] `rg "api/v2"` = 0（在 desktop/mobile 源码中）
- [ ] `rg "api/v3"` = 0（在 desktop 源码中）
- [ ] `rg "localsend::"` = 0（类型导入，非字符串字面量）
- [ ] core `atomic_file` 有调用方
- [ ] core `piece_cache` 有调用方
- [ ] Mobile 使用 v4 协议（不是 v2）
- [ ] E2E 测试通过（desktop ↔ desktop, desktop ↔ mobile）
- [ ] `cargo test --lib` = 0 failed

---

## 风险矩阵

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| SessionDriver FFI 内存管理泄漏 | 低 | 高 | 使用 CVec + vec_free |
| JNI 调用性能瓶颈 | 中 | 中 | 批量操作，减少 JNI 调用次数 |
| 删除 v2/v3 导致已配对设备失效 | 高 | 中 | 保留向后兼容分支，或提示用户重新配对 |
| atomic_file 并发写入冲突 | 低 | 高 | core 已处理，测试验证 |

---

## 依赖关系

- Phase A → Phase B（发送端连好后，配对才有意义）
- Phase A → Phase D（发送端需要 piece_cache）
- Phase B → Phase C（配对升级后才能替换发现模块）
- Phase C + D → Phase F（验收门）
- Phase E 独立（Mobile JNI 不依赖 desktop 完成）

---

## 推荐执行顺序

1. **Phase A** — 最高价值，无外部依赖，仅需 Rust 环境
2. **Phase B** — 依赖 Phase A，但改动独立
3. **Phase D** — 可与 Phase B 并行，修改 core 内部
4. **Phase C** — 依赖 Phase B
5. **Phase E** — 需要 Android SDK，可与 desktop 并行
6. **Phase F** — 最终门

---

*文档生成时间：2026-09-06*
*文档版本：v1.0*
