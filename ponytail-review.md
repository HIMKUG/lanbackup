# ponytail-review 结果

> 此文件由 ponytail-review 维护，每次审查后更新。
> 审查范围：实际代码（非 git diff），聚焦过度工程化、冗余抽象、未使用代码。

生成时间：2026-08-27
审查版本：master 分支最新提交

---

## 📊 统计摘要

| 类别 | 数量 |
|------|------|
| 可删除代码行数（Rust） | ~100 行 |
| 可删除代码行数（TypeScript） | ~8 行 |
| 问题文件数 | 6 个 |
| 总计可删 | **~108 行** |

---

## 🔴 crypto.rs（Rust，~42 行可删）

**文件路径：** `desktop/src-tauri/src/crypto.rs`

### 问题 1：derive_local_storage_key_pbkdf2 无调用方（~15 行）

```rust
#[allow(dead_code)]
pub fn derive_local_storage_key_pbkdf2(...) -> ... { ... }
```

grep 验证：全代码库无任何调用方。

**建议：** 删除（约 15 行）。

### 问题 2：CryptoVersion 枚举未使用（~20 行）

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[allow(dead_code)]
pub enum CryptoVersion { ... }

impl CryptoVersion {
    pub fn from_u32(v: u32) -> Option<Self> { ... }
    pub fn as_u32(&self) -> u32 { ... }
}
```

注释称"dispatch 层已删除"，该枚举仅内部转换用，无实际调用方。

**建议：** 删除 CryptoVersion 枚举及相关方法（约 20 行）。

### 问题 3：P6 ChunkNonce 说明注释块（~7 行）

```rust
// P6: ChunkNonce：每块唯一 nonce = session_nonce || chunk_index（64bit）
// session_nonce 在每次传输开始时随机生成，chunk_index 从 0 递增。
// ...
```

这是纯说明性注释，代码中无 P6 标记的实际实现。

**建议：** 删除注释块（约 7 行）。

### ✅ 已移除（经验证为误报）

以下原报告问题经 grep 调用方验证为**活跃代码**，已从删除清单移除：

| 代码段 | 验证结果 |
|--------|----------|
| `derive_pairing_secret_v3` | ✅ pairing/v3.rs L372, transfer/v3.rs L225 调用 |
| `derive_transfer_key_v3` | ✅ transfer/v3.rs L309, transfer/receive.rs L413 调用 |
| `OVERHEAD` | ✅ crypto.rs L326 `encrypt()` 函数使用 |

**结论：** crypto.rs 实际可删约为 42 行（原报告 75 行为误算）。

---

## 🔴 scheduler.rs（Rust，~60 行可删）

**文件路径：** `desktop/src-tauri/src/scheduler.rs`

### 核心问题：大量类型标记 #[allow(dead_code)]

以下类型均标记 `#[allow(dead_code)]`，无一被外部调用：

| 类型 | 行数 | 调用方 |
|------|------|--------|
| `FileManifest` | ~80 | 无 |
| `ChunkDiff` | ~60 | 无 |
| `SessionState` | ~40 | 无 |
| `FileTransferState` | ~50 | 无 |
| `PeerSession` | ~60 | 无 |
| `PeerInfo` | ~30 | 无 |
| `PeerStatus` | ~20 | 无 |
| `MerkleNode` | ~40 | 无 |
| `MerkleTree` | ~100 | 无 |
| `SendScheduler` | ~150 | 无 |
| `SchedulerHttpClient` | ~50 | 无 |

**仅有的 3 个实用函数（保留）：**

```rust
pub fn jittered_backoff_ms(attempt: u32, base_ms: u32, max_ms: u32) -> u32
pub fn is_retryable_status(status: u16) -> bool
pub fn is_checksum_failure_retryable(code: i32) -> bool
```

**建议：** 删除除上述 3 个函数外的全部内容（约 600 行）。

---

## 🟡 lib.rs（Rust，~35 行可删）

**文件路径：** `desktop/src-tauri/src/lib.rs`

### 问题 1：PROBE_ENABLED = false（约 1 行）

```rust
const PROBE_ENABLED: bool = false;
```

### 问题 2：probe! 宏定义（约 20 行）

```rust
macro_rules! probe {
    ($($arg:tt)*) => {};
}
```

当 `PROBE_ENABLED = false` 时，该宏为空语句。

### 问题 3：probe! 调用点（约 10 行）

全文多处 `probe!("...")` 调用，因宏为空而成为 no-op。

### 问题 4：OpenTelemetry 禁用说明注释块（约 5 行）

```rust
// 注意：OpenTelemetry 在本项目中被禁用（未调用 initTelemetry）。
```

**建议：** 删除 PROBE_ENABLED、probe! 宏及所有调用、禁用注释（约 35 行）。

---

## 🟢 discovery.ts（TypeScript，~8 行可删）

**文件路径：** `shared-core/src/discovery.ts`

### 问题：syncableDevices() 是 connectedDevices() 的重复实现

```typescript
// L164-166
connectedDevices(): DiscoveredDevice[] {
  return this.allDevices().filter((d) => d.paired && d.connected);
}

// L171-173（与上面完全相同）
syncableDevices(): DiscoveredDevice[] {
  return this.allDevices().filter((d) => d.paired && d.connected);
}
```

grep 验证：`syncableDevices` 无任何外部调用方。

**建议：** 删除 `syncableDevices()` 方法（约 8 行）。

---

## 🟡 discovery.rs（Rust，~5 行可删）

**文件路径：** `desktop/src-tauri/src/discovery.rs`

### 问题：P3 发现层抽象已删除的说明注释（约 5 行）

```rust
// P3 发现层抽象已删除（mDNS 从未实现）。
// 所有发现逻辑直接调用本模块自由函数：start_discovery / stop_discovery ...
// 如将来需多后端，在此处恢复 Discovery trait + MulticastDiscovery + active_backend。
```

这是解释"未实现功能"的注释，本身是噪音。

**建议：** 删除 L396-398（约 5 行）。

---

## 🟡 session_store.rs（Rust，~15 行可删）

**文件路径：** `desktop/src-tauri/src/session_store.rs`

### 问题：chrono_lite_now() 未被使用

```rust
#[allow(dead_code)]
fn chrono_lite_now() -> String { ... }
```

grep 验证：`chrono_lite_now` 无任何外部调用方（send.rs 中的 `session_store_ts()` 是独立实现）。

**建议：** 删除（约 15 行）。

---

## 🟡 autopolicy.ts（TypeScript，生产环境 ~0 行可删）

**文件路径：** `shared-core/src/autopolicy.ts`

### 说明：decidePolicy / isSameWifi 仅在测试中被调用

```typescript
// 仅被 shared-core/src/test/selfcheck.ts 调用
// desktop/App.vue 和 mobile/App.vue 均无调用
```

这两个函数设计用于生产环境的自动备份策略决策，但当前未被实际集成。只在测试中出现，属于"设计好了但未落地"的功能。

**建议：** 确认是否计划在生产代码中使用。若否，可删除整个文件。

---

## ✅ 确认保留（经验证为在用代码）

以下代码经 grep 验证有实际调用方，**不可删除**：

| 文件 | 代码段 | 验证结果 |
|------|--------|----------|
| `crypto.rs` | `sig_generate_keypair`, `sig_sign`, `sig_verify` | pairing/v3.rs, transfer/store.rs, transfer/v3.rs 调用 |
| `crypto.rs` | `derive_pairing_secret_v3` | pairing/v3.rs L372, transfer/v3.rs L225 调用 |
| `crypto.rs` | `derive_transfer_key_v3` | transfer/v3.rs L309, transfer/receive.rs L413 调用 |
| `crypto.rs` | `derive_session_key_v3`, `derive_storage_key_v2` | transfer 模块调用 |
| `crypto.rs` | `OVERHEAD` | crypto.rs L326 `encrypt()` 使用 |
| `identity.rs` | `db_encryption_key()` | db.rs:71 调用 |
| `identity.rs` | `db_encryption_key_legacy()` | migration helper，保留供参考 |
| `identity.rs` | `get_self_fingerprint_code()` | pairing/v3.rs 调用 |
| `session_store.rs` | `DesktopSessionStore` | lib.rs 实例化，transfer/send.rs 调用 |
| `session_store.rs` | `create_session`, `FileManifest`, `SessionState` | transfer/send.rs:440+ 调用 |
| `pairing.ts` | `keyVersion`, `cryptoVersion`, `previousKeys` | rotateKey/tryDecryptWithHistory 方法内使用 |
| `pairing.ts` | `PairingManager` | desktop/mobile App.vue 调用 |
| `logger.ts` | `startActiveSpan` | conflict.ts, scan.ts 调用 |
| `logger.ts` | `initTelemetry` | desktop/main.ts, mobile/main.ts 调用 |
| `scan.ts` | `scanForMirrorMode` | scan.ts:135 调用 |
| `scan.ts` | `classifyFile`, `classifySize` | transfer.ts 调用 |
| `scan.ts` | `isAfterAnchor`, `scanDateRange` | scan.ts 自身 quickScan 调用 |
| `anchor.ts` | `updateAnchor`, `updateAnchors`, `getAnchorMtime` | scan.ts quickScan 使用 |
| `sync.ts` | `planIncremental`, `SyncPlan` | desktop/App.vue:2267, mobile/backup.ts:170 调用 |
| `identity.ts` | `PROTOCOL_VERSION`, `KDF_VERSION`, `CRYPTO_VERSION`, `PBKDF2_ITERATIONS` | transfer.ts 调用 |
| `config.ts` | `normalizeConfig`, `parseConfig`, `stringifyConfig` | desktop/mobile App.vue 调用 |

---

## 📋 删除清单汇总

| 文件 | 删除行数 | 删除内容 |
|------|----------|----------|
| `crypto.rs` | ~42 | derive_local_storage_key_pbkdf2, CryptoVersion, P6注释 |
| `scheduler.rs` | ~600 | 全部类型定义，仅保留 3 个工具函数 |
| `lib.rs` | ~35 | PROBE_ENABLED、probe! 宏及所有调用、禁用注释 |
| `discovery.ts` | ~8 | syncableDevices() 方法 |
| `discovery.rs` | ~5 | P3 发现层抽象注释 |
| `session_store.rs` | ~15 | chrono_lite_now() |
| **合计** | **~705 行** | |

---

## 🔍 审查方法说明

本次审查采用以下验证策略：

1. **静态分析**：识别所有 `#[allow(dead_code)]` 标记
2. **调用方grep**：对每个疑似死代码的目标进行全代码库搜索
3. **交叉验证**：对"可能在用"的代码扩大搜索范围确认
4. **功能依赖链**：识别被其他模块实际使用的功能（如 ECDSA 签名、session_store 持久化）
5. **对抗式审查**：对报告中的每项发现进行调用方验证，排除误报

### 对抗式审查发现

| 原报告问题 | 审查结论 |
|------------|----------|
| `derive_pairing_secret_v3` 无调用方 | ❌ 误报：pairing/v3.rs L372, transfer/v3.rs L225 调用 |
| `derive_transfer_key_v3` 无调用方 | ❌ 误报：transfer/v3.rs L309, transfer/receive.rs L413 调用 |
| `OVERHEAD` 常量未使用 | ❌ 误报：crypto.rs L326 `encrypt()` 使用 |
| `derive_local_storage_key_pbkdf2` | ✅ 确认死代码，无调用方 |
| `CryptoVersion` 枚举 | ✅ 确认死代码，无调用方 |
| P6 注释块 | ✅ 确认纯注释，无代码实现 |

---

*最后更新：2026-08-27*
