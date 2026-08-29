# Vendored: localsend core

## 来源

| 项 | 值 |
|---|---|
| 上游项目 | LocalSend（Rust core） |
| 本地快照位置 | `D:/code/tools/docs/localsend-main/packages/core` |
| 上游版本 | `localsend v0.1.0`（`Cargo.toml`） |
| 上游 toolchain | `rust-toolchain.toml` → `1.97.1` |
| vendor 时间 | 2026-08-29 |

**上游快照不是 git 仓库**（是解包的源码目录），因此无法用 `git subtree` 保留上游历史。
这里采用 vendor 复制 + 本文件记录溯源信息。

## 为什么 vendor

原先 `desktop/src-tauri/Cargo.toml` 用 `path = "../../../docs/localsend-main/packages/core"`
指向**仓库外**目录。后果：

- 换机器 clone 后 `cargo build` 直接失败
- 上游不在版本控制下，本地修改不可见、不可回溯
- 无版本锁定

vendor 进仓库后，构建自包含、修改可提交、变更可追溯。

## 本地修改

**e17c1f2（vendor 时）**：删除 `examples/stress_send.rs` 及其 `[[example]]` 声明 ——
压测二进制对本项目无用，且会拖慢 `cargo test`。

其余文件保持上游原样。**后续任何修改都必须在本表登记。**

## V4 计划中的处置

按 `V4-ARCHITECTURE.md` §九，V4 只要它的 **HTTP 管道**，不要它的**协议层**：

保留：
- `http/server/common/*` —— hyper 请求处理、JSON 收集、错误响应、文件落盘
- `util/` —— base64 / filename / interface / time
- `model/discovery.rs` —— DeviceType / ProtocolType
- `multicast/socket.rs` —— 组播 socket

删除（阶段 2 执行）：
- `http/server/v2.rs`、`http/client/v2.rs`、`http/dto_v2.rs` —— V2 协议层
- `http/server/v3.rs`、`http/client/v3.rs` —— 上游 v3，与本项目无关
- `http/server/web.rs` —— 未使用
- `webrtc/` —— 未使用
- mTLS / 证书相关（`rcgen` / `rustls` / `client_cert_verifier`）
- `download` / `show` / `prepare-download` —— 未使用

## 修改登记表

| 提交 | 修改 | 理由 |
|---|---|---|
| （vendor 时） | 删 `examples/stress_send.rs` + `[[example]]` | 压测二进制无用，拖慢测试 |
