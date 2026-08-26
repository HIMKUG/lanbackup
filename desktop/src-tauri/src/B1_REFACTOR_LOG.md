# B1 重构执行日志

## 目标
将 `transfer.rs` 中 381 行巨型函数 `handle_pairing_conn` 拆分为 `pairing/` 子模块。

## 文件变更清单

| 文件 | 操作 |
|------|------|
| `lib.rs` | 添加 `pub(crate) mod pairing;` |
| `transfer.rs` | 删除 381 行旧函数，替换为 delegation stub；添加 `greeting_seq` 到 `PairingState`；`receive_dir` 改为 `pub(crate)`；`handle_move_to_delete` 改为 `pub(crate)` |
| `pairing/mod.rs` | 已存在，确认内容 |
| `pairing/error.rs` | 手动实现 `From<io::Error>` 和 `From<serde_json::Error>`，移除 `#[from]` 属性（需要 `derive(Error)`宏） |
| `pairing/types.rs` | 已存在 |
| `pairing/auth.rs` | 完全重写，补完所有路由分支 + helper 函数 |
| `pairing/key_exchange.rs` | 已存在（空壳） |
| `pairing/session.rs` | 已存在（空壳） |

## 编译结果
✅ `cargo check` 通过（0 errors，78 warnings）

## 执行步骤 — 完成记录

### Step 1: 读取所有相关文件（当前状态）
- [x] 读取 `lib.rs` 确认当前模块声明
- [x] 读取 `transfer.rs` 中 `handle_pairing_conn` 函数（约 line 1979-2360）
- [x] 读取 `pairing/mod.rs`
- [x] 读取 `pairing/error.rs`
- [x] 读取 `pairing/types.rs`
- [x] 读取 `pairing/auth.rs`
- [x] 读取 `pairing/key_exchange.rs`
- [x] 读取 `pairing/session.rs`

### Step 2: 分析旧函数逻辑，映射到各模块
- [x] 识别 `handle_pairing_conn` 中的所有 HTTP 路由分支
- [x] 识别辅助函数依赖（`http_json_request`, `notify_peers_disconnect`, `ping_device` 等）

### Step 3: 完善 `pairing/auth.rs`
- [x] 将 `handle_pairing_conn` 主函数骨架移入
- [x] 实现 `handle_info`、`handle_verify_code`、`handle_greeting` 等 handler
- [x] 实现 `handle_file_receipt`、`handle_unpair`、`handle_disconnect`、`handle_sync_dir`
- [x] 实现 `handle_move_to_delete`、`handle_chunk_status`、`handle_manifest`
- [x] 实现 `parse_hello`、`check_trusted`、`generate_echo`、`verify_greeting_response`

### Step 4: 完善 `pairing/types.rs`
- [x] 补充必要的类型定义

### Step 5: 更新 `pairing/mod.rs`
- [x] 确认导出内容正确

### Step 6: 修改 `lib.rs`
- [x] 添加 `pub(crate) mod pairing;`

### Step 7: 修改 `transfer.rs`
- [x] 删除 381 行旧函数
- [x] 替换为调用 `crate::pairing::handle_pairing_conn`
- [x] 添加 `greeting_seq: Mutex<HashMap<String, u32>>` 到 `PairingState`
- [x] `receive_dir` 改为 `pub(crate)`
- [x] `handle_move_to_delete` 改为 `pub(crate)`

### Step 8: 编译验证
- [x] `cargo check` 通过

## 关键架构决策

1. **模块可见性**：`pairing/` 声明为 `pub(crate)` 允许 `lib.rs` 访问，但对外隐藏
2. **State 访问分离**：`pending_pairing_approvals` 在 `TransferState`，`paired`/`synced_dirs`/`greeting_seq` 在 `PairingState`
3. **AppError 桥接**：auth.rs 导入 `crate::db::AppError`，通过 `map_err(AppError(...))` 桥接 `PairingError`
4. **Traits 导入**：`use tauri::{Manager, Emitter}` 使 `app.state()` 和 `app.emit()` 可用
5. **错误类型**：pairing 模块内部用 `PairingError`，对外暴露统一 `AppError`

## 剩余未解决问题

- `stop_pairing_server` 在 transfer.rs 中未被使用（warning），pairing 模块重构后可能不再需要
- 原 transfer.rs 中的 `http_json_request`/`ping_device`/`notify_peers_disconnect` 等辅助函数未迁移（仍保留在 transfer.rs 中）
- greeting_seq 的 seq 生成使用 `rand::random()`（Rust内置），未使用 `ThreadLocalRandom`（Java端用的）
