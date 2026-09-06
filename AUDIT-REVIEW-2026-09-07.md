# 全面深入审查报告 —— LAN Backup 距"可直接应用"的差距

> 审查日期：2026-09-07
> 审查范围：desktop（Tauri）+ core（lanbackup-core）+ 前端（App.vue）
> 审查方式：代码级逐文件核对，对照 `DESIGN-PHASE-A-F.md` / `AI-HANDOFF.md` / `NEXT-STEP-PLAN.md` 验收标准

---

## 0. 一句话结论

**当前代码处于"core 协议完备 + desktop 半接入"的中间态，且 Phase B 的服务端切换造成了配对全链路断裂。** 距离可直接应用，存在 **3 个 P0 级功能断裂**、**4 个 P1 架构分裂**、**5 个 P2 未完成项**。core 本身是可信的（482 测试全绿），问题全部集中在 desktop 的接入层。

---

## 1. 当前实际架构（与设计目标对比）

### 设计目标（DESIGN-PHASE-A-F.md）

```
core（协议+算法唯一实现）
  ├── SessionDriver  ──→ desktop 发送（决策与 IO 分离）
  ├── server/route() ──→ desktop 接收 + 配对（单一 HTTP 服务）
  ├── presence       ──→ desktop 发现
  └── pairing 纯计算  ──→ desktop 配对
desktop = 纯 IO 层（网络、磁盘、UI）
```

### 实际现状（审查发现）

```
desktop 内并存两套 HTTP 服务、两套身份、两套信任表：

┌─ 接收服务 53317（core hyper）
│    SessionStore（identity=每次重启随机 generate()）
│      ├─ peers 表（空：从未写入）
│      ├─ secrets 表（空：从未写入）
│      └─ /api/v4/* 全部端点（含配对）✅
│
└─ 配对服务 53318（desktop 手写 TCP+HTTP auth.rs）
       ├─ /api/backup/v1/*  （desktop 自实现，v2 时代遗留）❌
       ├─ /api/v4/probe|handshake  （代理到 127.0.0.1:53317）⚠️
       └─ /api/v3/*         （路由已删 → 404）❌

desktop PairingState（paired/secrets，rusqlite 持久化）── 与 core peers 表零互通
前端 App.vue ── 配对走 v3_pair / v3_probe（服务端已删 v3 → 404）
```

**核心矛盾**：core 的 `PeerStore`/`HandshakeStore`/`persist.rs` 是完备的配对状态机，但 desktop 从未把 `PairingState`（rusqlite）同步进去；前端配对又走已被删除的 v3 路由。三条链路互相不通。

---

## 2. P0 —— 已断裂的功能（不改无法使用）

### P0-1 配对全链路断裂（最严重）

| 环节 | 现状 | 后果 |
|---|---|---|
| 前端 [App.vue](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src/App.vue) L2002/L2057 | `invoke('v3_pair')` | 调 v3 协议 |
| 命令层 [lib.rs](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src-tauri/src/lib.rs) L236-239 | 注册 `v3_probe/v3_handshake_challenge/v3_handshake_verify/v3_pair` | 无任何 v4 配对命令 |
| 客户端 [v3.rs](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src-tauri/src/transfer/v3.rs) L155-175 | 打 `/api/v3/probe`、`/api/v3/handshake/*` 到对端 53318 | — |
| 服务端 [auth.rs](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src-tauri/src/pairing/auth.rs) | **v3 路由已删除** | **对端返回 404** |

**结论**：新设备配对、重连配对全部 404，配对功能当前完全不可用。

同时 `v3_probe`（前端 L1806/L1841/L2071）用于在线状态探测与 `connectPeer`，同样全部失败 → **已配对设备的"在线/连接"状态也无法刷新**（仅 bcpd 能驱动在线态，但 bcpd 依赖已有 secrets，新配对进不来）。

### P0-2 解配对 / 状态同步 / 吊销断裂

[store.rs](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src-tauri/src/transfer/store.rs) 三个对外端点函数仍打 v3 路径，对端 404：

- L493 `unpair_request_remote` → `POST /api/v3/unpair-request`
- L511 `sync_peer_status` → `POST /api/v3/sync-status`
- L530 `send_revoke_ack` → `POST /api/v3/revoke-ack`

前端 [App.vue](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src/App.vue) L1703/L1923 `sync_all_peers`、L2117 `unpair_peer` 全部经此路径 → **解除配对、吊销、对账全部失败**。

core 侧对应 v4 端点全部就绪（[routes.rs](file:///d:/code/tools/6a7f5d5699c44b33268ede69/core/src/routes.rs)）：`/api/v4/unpair-request`、`/api/v4/sync-status`、`/api/v4/revoke-ack`，仅需 desktop 切换。

### P0-3 断开连接 / 文件清单 / 分片状态走 v2 时代端点

[mod.rs](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src-tauri/src/transfer/mod.rs)：

- L427 `send_unpair` → `POST /api/localsend/v2/unpair`（**v2 残留**）
- L443 `send_disconnect` → `POST /api/backup/v1/disconnect`（前端 L1868 调用）
- L556 `get_peer_manifest` → `GET /api/backup/v1/manifest`（前端 L2260 调用）

[store.rs](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src-tauri/src/transfer/store.rs) L430 `send_sync_dir` → `POST /api/localsend/v2/sync-dir`（**v2 残留**）。

其中 `/api/backup/v1/*` 由 [auth.rs](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src-tauri/src/pairing/auth.rs) L80-94 自实现（`handle_disconnect`/`handle_manifest`/`handle_chunk_status`/`handle_move_to_delete`/`handle_cancel`），与 core 的 `/api/v4/disconnect`、`/api/v4/manifest`、`/api/v4/chunk-status`、`/api/v4/move-to-delete` **双实现并存**，且其 `check_trusted` 查的是 desktop `PairingState`（与 core peers 表不一致）。

---

## 3. P1 —— 架构分裂（能跑但不可靠）

### P1-1 设备身份未接线：指纹每次重启漂移

[receive.rs](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src-tauri/src/transfer/receive.rs) L41：

```rust
let identity = lanbackup_core::identity::DeviceIdentity::generate(); // 每次随机
```

文件头注释明确写"应使用 desktop 已有稳定 deviceId（FNV-1a 派生）"，但实现是 `generate()`。后果：
- core `probe` 返回的 `deviceId`/指纹每次重启都变
- 对端已配对记录永远匹配不上 → 续传、bcpd 识别、信任对账全部失效
- 配对（即便修复 P0-1）跨重启即失效

desktop 侧已有稳定身份：[identity.rs](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src-tauri/src/identity.rs) `get_device_id()`（FNV-1a 派生）+ `get_or_create_sig_key`（持久化 P-256 签名密钥），但从未喂给 core `SessionStore`。

### P1-2 core 与 desktop 双信任表、零同步

- core：`SessionStore.peers`（`PeerStore`）+ `persist.rs`（JSON）—— 空表，从未写入
- desktop：`PairingState.paired/secrets` + rusqlite（store.rs）—— 前端数据源

[v4.rs](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src-tauri/src/pairing/v4.rs) L13 自认："desktop 需在启动时将配对状态同步到 core"——**未实现**。

即使前端切到 v4 配对，core 的 `handle_probe`/`handle_handshake_verify` 也拿不到 desktop 已有配对记录，已配对设备无法被识别为已配对。

### P1-3 双 HTTP 服务并存、v4 代理端口依赖 53318

- `discovery.rs` 子网扫描 [L189-195](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src-tauri/src/discovery.rs) 探测 `port + 1`（=53318，配对端口），而 v4 的 `/api/v4/probe` 正确位置是接收端口 **53317**
- 对端若只开接收服务（53317）未开配对服务（53318），子网扫描扫不到
- v4 代理（53318 → 127.0.0.1:53317）依赖"接收服务固定 53317"这一隐式假设，前端 L2176 `start_receiver(port: 53317)` 恰好成立，但端口是硬编码，无配置链路

### P1-4 bcpd 是自建实现，未用 core presence

[bcpd.rs](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src-tauri/src/bcpd.rs) 自建 UDP 组播 + ring hmac + 独立 `BcpdState`，密钥来自 desktop `PairingState.secrets`（v3 时代）。core 已有 `presence` 模块（BeaconEmitter/PresenceSocket）但未被使用。bcpd 能工作的前提是 PairingState.secrets 有数据——而 P0-1 断裂后新配对进不来，存量 secret 也只能继续服务旧设备。

---

## 4. P2 —— 未完成项（设计已声明但未落地）

### P2-1 SessionDriver 未被真正驱动（Phase A 只完成"跳过计算"）

[send.rs](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src-tauri/src/transfer/send.rs)：

- L22 导入 `SessionDriver` 带 `#[allow(unused_imports)]`
- L475-491 `SessionDriver::resume()` 仅用于**计算跳过哪些 piece**（断点续传跳过）
- 实际传输循环是自写 `upload_single_with_retry`（L514+），**没有** `next_step() → Step → IO → feed(Outcome)` 决策循环

设计文档 Phase A 目标"发送完全通过 SessionDriver，删除 scheduler.rs 协议层"**未达成**：`scheduler.rs` 的 `build_manifest`/`SchedulerHttpClient`/`SendScheduler` 仍在生产路径被大量使用。

### P2-2 piece_cache 计算了但从未使用（死代码）

[send.rs](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src-tauri/src/transfer/send.rs) L386-393：

```rust
let mut piece_hex_cache: HashMap<String, Vec<String>> = HashMap::new();
for (i, f) in normal.iter().enumerate() {
    if let Some(hexes) = compute_piece_hexes(...) {
        piece_hex_cache.insert(file_id, hexes);
    }
}
// 之后：piece_hex_cache 从未被读取
```

prepare 请求中 normal 文件的 `piece_hashes: None`（L313-316），sched_plans 用 scheduler 自算的 `m.piece_hashes`（L330），都不经缓存。`compute_piece_hexes` 每次仍会全量重读文件 → **缓存零收益**。

### P2-3 v2/v3 残留代码量

- `api/v3` 字面量：34 处（desktop 源码）
- `api/v2` 字面量：2 处（store.rs L430、mod.rs L427）
- `localsend` 字面量：21 处（其中签名域前缀 `localsend-v3/*`、`localsend-backup|v1` 等属协议常量，可保留；但 v2 端点调用必须删）
- [pairing/v3.rs](file:///d:/code/tools/6a7f5d5699c44b33268ede69/desktop/src-tauri/src/pairing/v3.rs) 整文件（约 700 行）服务端实现已无路由引用，仅 store.rs 调其 `set_peer_status`/`delete_peer_secret`（这俩是内存操作，可内联到 store.rs 后删除整文件）
- `cargo check` 43 个 dead-code 警告（v3 + scheduler）

### P2-4 Phase E（Mobile JNI）未开始

`AI-HANDOFF.md` §8 记录：core 侧 `platform/android.rs`（AndroidMulticastGuard）+ `platform/android_bridge.rs`（JNI 桥）已完成，但 Android 侧 `LanBackupCore.java` 缺失，需 Android SDK。**完全未动**。

### P2-5 文档滞后

- `DESIGN-PHASE-A-F.md` 仍标注 Phase B/C/D 为"进行中"（未回填完成状态）
- `AI-HANDOFF.md` 头部"最后更新"停留在 09-06，§8 未记录本次 Phase B/C/D 提交（`1a5aca7`）
- 本次审查发现的实际断裂（P0-1/P0-2）文档中无记录

---

## 5. 按 Phase 验收对照表

| 验收项（DESIGN-PHASE-A-F.md Phase F） | 状态 | 证据 |
|---|---|---|
| `rg "api/v2"` = 0（desktop/mobile 源码） | ❌ 2 处 | store.rs:430、mod.rs:427 |
| `rg "api/v3"` = 0（desktop 源码） | ❌ 34 处 | transfer/v3.rs、store.rs、lib.rs、App.vue |
| `rg "localsend::"` = 0 | ✅ | Cargo.toml 已删依赖，无类型导入 |
| core `atomic_file` 有调用方 | ✅ | server/mod.rs handle_chunk 接入 |
| core `piece_cache` 有调用方 | ⚠️ 伪调用方 | send.rs 计算后未使用（死代码） |
| Mobile 使用 v4 协议 | ❌ 未开始 | Phase E 未做 |
| E2E 测试通过（desktop↔desktop） | ❌ 无法通过 | 配对 404 |
| `cargo test --lib` = 0 failed | ✅ core 482 通过 | — |

---

## 6. 修复路径建议（依赖排序）

```
第一步（打通配对，P0-1/P1-1 联动）：
  ├─ receive.rs：用 desktop 稳定 deviceId + 持久化签名密钥构造 core identity
  ├─ 新增 v4 配对命令（v4_probe / v4_pair），直连对端 53317 /api/v4/*
  └─ App.vue：v3_pair → v4_pair、v3_probe → v4_probe

第二步（打通管理面，P0-2/P0-3）：
  ├─ store.rs：unpair_request_remote / sync_peer_status / send_revoke_ack 切 /api/v4/*
  ├─ mod.rs：send_disconnect → /api/v4/disconnect、get_peer_manifest → /api/v4/manifest
  ├─ store.rs：send_sync_dir → /api/v4/sync-dir、mod.rs send_unpair 删除（v4 有 /api/v4/unpair）
  └─ 配对状态启动时同步进 core（PeerStore 种子），关闭 53318 的 /api/backup/v1/*

第三步（收尾 Phase A/C）：
  ├─ send.rs：SessionDriver 真正驱动 next_step/feed 循环
  ├─ piece_cache 喂进 PrepareRequest
  ├─ discovery.rs：扫描目标端口 53318 → 53317
  ├─ bcpd.rs 评估切 core presence
  └─ 删除 v3 残留 + 43 个 dead-code 警告清零

第四步（Phase E + F）：Mobile JNI（需 Android SDK）；验收门回归
```

---

## 7. 风险与优先级建议

| 风险 | 影响 | 建议 |
|---|---|---|
| 配对断裂已上线 | 用户无法配对新设备 | 第一步立即修 |
| identity 随机漂移 | 即使配对修好，重启即失效 | 与第一步联动修 |
| 双信任表 | 对账/吊销行为不可预测 | 第二步收敛到 core |
| bcpd 依赖 v3 secrets | 存量设备退化 | 第三步评估 |
| SessionDriver 未驱动 | 高级 diff 逻辑部分失效（跳块依赖自实现） | 第三步补 |

**最低可用（MVP）门槛**：第一步 + 第二步 完成后，桌面端"发现 → 配对 → 发送 → 接收 → 解配对"全链路可用；第三步是性能/正确性完善；第四步决定手机端是否可连。
