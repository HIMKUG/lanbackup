# V4 文件传输模块 —— 交付说明

> 本文是 `V4-TRANSFER-MODULE.md`（设计）对应的**实现交付说明**。
> 所有表格均与代码逐项对应，并标注了源码位置，便于核验「文档写一套、代码跑另一套」的漂移。
> 代码位置：`core/src/`（单 crate `lanbackup-core`，桌面端 Tauri 与移动端 JNI/uniFFI 共用）。
>
> 测试基线：179 个单元测试全绿，`cargo clippy --all-targets -D warnings` 干净。

---

## 一、状态流转说明（Transfer 状态机）

### 1.1 十个状态

| 状态 | 含义 |
|---|---|
| `Idle` | 无会话 |
| `Preparing` | `POST /api/v4/session/prepare`，协商能力 / 初始化主算法 |
| `Reconciling` | `GET /api/v4/session/diff` 拉取对端权威块位图 |
| `Transferring` | 收发 piece / block（主算法 piece 4 MiB，基础算法 block 16 MiB） |
| `Paused` | 心跳超时，保留已确认进度，等待恢复对账 |
| `Degrading` | 降级动作执行中的瞬态（清理在途 → 重建基础块计划 → 复用对齐进度） |
| `Verifying` | 整体校验（Merkle / 强校验） |
| `Completed` / `Failed` / `Aborted` | 三个终态，单调不可回退 |

### 1.2 状态迁移总图

```
                                    ┌──────────────────────────────────┐
                                    ↓                                  │
idle ──Register──> preparing ──┬─[有 CAP_ADVANCED]─> reconciling ──> transferring ──> verifying ──> completed
                            │                                              │  ↑(校验失败≤2)         │
                            ├─[无 CAP_ADVANCED / 初始化失败]─────────────────┘  │                   │
                            │                                     [重传坏块] ──┘                   │
                            └─[握手重试耗尽]──> failed                                                  │
                                                                                                     │
   transferring ──[心跳超时]──> paused ──[对账成功]──> transferring                                       │
                                     └──[对账失败>3]──> degrading ──> transferring(basic) ─────────────┘
   transferring ──[连续块失败>3]──> degrading ──> transferring(basic)
   verifying ──[校验失败>2]──> degrading ──> transferring(basic)

   任意非终态 ──[用户中止]──> aborted
   任意非终态 ──[连接断开]──> aborted（原因 CONNECTION_LOST）
   任意非终态 ──[不可恢复错误]──> failed
```

### 1.3 完整迁移表（取自 `core/src/state/transfer.rs` 的 `transition()`）

| 当前态 | 事件 | 目标态 | 设计依据 |
|---|---|---|---|
| `Idle` | `Register` | `Preparing` | T1 |
| `Preparing` | `NegotiateAdvanced` | `Reconciling` | T2（对端有 `CAP_ADVANCED`） |
| `Preparing` | `NegotiateBasic` | `Transferring` | T3 / **D1**（对端无能力，一步到位 basic） |
| `Preparing` | `Degrade` | `Degrading` | D2（初始化失败，由 `events_for` 产出该事件） |
| `Preparing` | `RetryExhausted` | `Failed` | T6（握手重试耗尽，**不是降级**） |
| `Preparing` | `Fail` | `Failed` | T20（基础算法初始化失败） |
| `Preparing` | `Abort` / `PeerLost` | `Aborted` | T21 / T22 |
| `Preparing` | `ForceReset` | `Idle` | 会话重置 |
| `Reconciling` | `Reconciled` | `Transferring` | T7（**用对端位图覆盖本地推测**） |
| `Reconciling` | `ReconcileFailed` | `Degrading` | D3 / T9 |
| `Reconciling` | `Degrade` | `Degrading` | D2 fallback |
| `Reconciling` | `Fail` | `Failed` | T20 |
| `Reconciling` | `Abort` / `PeerLost` | `Aborted` | T21 / T22 |
| `Reconciling` | `ForceReset` | `Idle` | |
| `Transferring` | `Progress` | `Transferring` | 进度推进 |
| `Transferring` | `HeartbeatTimeout` | `Paused` | T10 |
| `Transferring` | `ChunkRetryExhausted` | `Degrading` | D5 / T14 |
| `Transferring` | `BeginVerify` | `Verifying` | T15（队列排空） |
| `Transferring` | `Degrade` | `Degrading` | D2/D5 通用入口 |
| `Transferring` | `Fail` | `Failed` | T24（停滞）或基础块重试耗尽 |
| `Transferring` | `Abort` / `PeerLost` | `Aborted` | T21 / T22 |
| `Transferring` | `ForceReset` | `Idle` | |
| `Paused` | `Retry` | `Preparing` | 恢复（带已确认进度） |
| `Paused` | `Degrade` | `Degrading` | **D4 / T12**（注意：走降级而非 failed） |
| `Paused` | `Fail` | `Failed` | T20 |
| `Paused` | `Abort` / `PeerLost` | `Aborted` | |
| `Paused` | `ForceReset` | `Idle` | |
| `Degrading` | `DegradeComplete` | `Transferring` | T19（basic 就绪，复用对齐进度） |
| `Degrading` | `Fail` | `Failed` | T20（兜底的兜底没有了） |
| `Degrading` | `Abort` / `PeerLost` | `Aborted` | |
| `Degrading` | `ForceReset` | `Idle` | |
| `Verifying` | `VerifyOk` | `Completed` | T16 |
| `Verifying` | `VerifyRetry` | `Transferring` | **T17**（仍有额度，回传输态重传坏块） |
| `Verifying` | `VerifyFailed` | `Degrading` | D6 / T18 |
| `Verifying` | `Fail` | `Failed` | T20 |
| `Verifying` | `Abort` / `PeerLost` | `Aborted` | |
| `Verifying` | `ForceReset` | `Idle` | |
| `Completed` | `ForceReset` | `Idle` | |
| `Failed` | `Retry` | `Preparing` | 显式重试开启新尝试 |
| `Failed` / `Aborted` | `ForceReset` | `Idle` | |

> **关键修正（相对文档 T12 的歧义）：** 旧实现把 `(Paused, RetryExhausted) => Failed`，
> 与文档「暂停后降级而非判死」矛盾。已改为 `(Paused, Degrade) => Degrading`——
> 放弃等于白扔已确认进度。对应测试：`paused_retry_exhausted_degrades_rather_than_fails`。

### 1.4 三条不变量（由代码强制）

1. **状态只由 `TransferState::transition` 改**：会话编排器 `SessionDriver` 没有任何 `state = ...` 直接赋值，全部经 `apply()` 走状态机（`state_is_only_ever_changed_through_the_state_machine` 测试重放事件序列做交叉验证）。
2. **降不降级只由 `DegradeController` 说**：编排器把信号喂给控制器，把 `DegradeAction::events` 喂给状态机，自己不判阈值。
3. **非法输入必报错、绝不静默**：`SessionDriver::feed` 对迟到响应、算法错配、终态再喂一律返回带中文文案的 `SessionError`。

---

## 二、状态 × 按钮可用性对照表

> 来源：`core/src/state/policy.rs` 的单一函数 `can(action, ctx)`，UI 的 `disabled` 绑定与运行时点击防护**共用同一裁决**（双保险，无竞态、无静默失败）。
> 下方表格即 `policy.rs` 末尾表驱动测试逐行断言的「文档副本」，改代码不同步改表（或反之）测试即挂。

### 2.1 按钮清单

| 按钮 | 粒度 | 说明 |
|---|---|---|
| 连接 | 每设备 | 建立 V4 握手 |
| 断开 | 每设备 | 主动断开 |
| 开始传输 | 每设备 | 新建会话并开始传输 |
| 中止 | 每会话 | 终止进行中的传输 |
| 重试 | 每会话 | 从 `failed` / `paused` 恢复 |
| 重新启用主算法 | 每设备 | 仅当设备级降级记忆生效时出现 |

### 2.2 连接 / 断开（依赖 Presence + Connection）

| Presence | Connection | 连接 | 断开 | 禁用提示 |
|---|---|---|---|---|
| unknown | 任意 | ✗ | ✗ | 「正在确认对方状态…」 |
| offline | 任意 | ✗ | ✗ | 「对方离线，无法连接」 |
| stale | 任意 | ✗ | ✗ | 「对方状态不稳定，正在重试确认…」 |
| online | disconnected | ✓ | ✗ | 断开：未连接 |
| online | connecting | ✗ | ✗ | 「正在连接…」 |
| online | connected | ✗ | ✓ | 连接：已连接 |
| online | disconnecting | ✗ | ✗ | 「正在断开…」 |
| online | lost | ✓ | ✗ | 断开：连接已丢失 |
| online | failed | ✓ | ✗ | 断开：未连接 |

> `lost` / `failed` 下「连接」必须可用——否则「连接」「断开」同时禁用会把用户彻底卡死（`user_is_never_stranded_after_connection_loss`）。

### 2.3 开始传输 / 中止 / 重试（依赖 Connection + Transfer）

| Connection | Transfer | 开始传输 | 中止 | 重试 | 禁用提示 |
|---|---|---|---|---|---|
| 非 connected | 任意 | ✗ | — | — | 「未连接，请先连接对方」 |
| connected | idle | ✓ | ✗ | ✗ | 中止：没有进行中的传输／重试：没有可重试的任务 |
| connected | preparing | ✗ | ✓ | ✗ | 开始：传输进行中 |
| connected | reconciling | ✗ | ✓ | ✗ | 开始：传输进行中 |
| connected | transferring | ✗ | ✓ | ✗ | 开始：传输进行中 |
| connected | paused | ✗ | ✓ | ✓ | 开始：传输已暂停，请重试或中止 |
| connected | degrading | ✗ | ✓ | ✗ | 开始：正在切换算法 |
| connected | verifying | ✗ | ✓ | ✗ | 开始：正在校验 |
| connected | completed | ✓ | ✗ | ✗ | 中止：传输已完成／重试：传输已成功 |
| connected | failed | ✓ | ✗ | ✓ | 中止：传输已结束 |
| connected | aborted | ✓ | ✗ | ✓ | 中止：传输已中止 |

**「重试」语义随来源态不同（由 `retry_events()` 保证合法迁移）：**

| 来源状态 | 重试做什么 | 派发事件 |
|---|---|---|
| `paused` | 重新对账（拉取权威位图）→ 从断点继续 | `Retry` |
| `failed` | 新建会话，从头开始；若失败源于降级则沿用 basic | `Retry` |
| `aborted` | **新建**会话（终态单调，非原地复活） | `ForceReset` → `Register` |

### 2.4 重新启用主算法（仅取决于设备级记忆）

| 条件 | 可用性 |
|---|---|
| 设备级降级记忆未生效 | 不渲染 |
| 设备级降级记忆生效（连续 3 次主算法失败） | ✓ 可用，点击后清除记忆并提示「下次传输将重新尝试主算法」 |

> 该按钮**只看 `prefer_basic` 记忆**，不看连接态 / 传输态 / 在线性——清除本机记忆无需任何网络交互，最自然的使用时机恰恰是「连接之前」（`reenable_advanced_works_while_disconnected`）。

---

## 三、降级触发条件与恢复策略

### 3.1 触发条件 D1–D6（取自 `core/src/transfer/degrade.rs`）

| # | 触发点 | 条件 | 原因码（`code()`） | 状态迁移 | 是否计入设备记忆 |
|---|---|---|---|---|---|
| D1 | 能力检测不通过 | `prepare` 响应无 `CAP_ADVANCED` | `PEER_NO_CAPABILITY` | `preparing → transferring(basic)` | **否**（稳定，对端升级即恢复） |
| D2 | 初始化失败 | Merkle 构建 / 密钥派生 / diff 端点 5xx / 内存不足 | `INIT_FAILED:<detail>` | `preparing → transferring(basic)` | 是 |
| D3 | 对账失败 | `diff` 连续 3 次失败 | `RECONCILE_FAILED` | `reconciling → degrading` | 是 |
| D4 | 传输中断且重试无效 | 心跳超时后对账 3 次全失败 | `RETRY_EXHAUSTED` | `paused → degrading` | 是 |
| D5 | 块连续失败 | 连续 3 个块重试耗尽 | `CHUNK_RETRY_EXHAUSTED` | `transferring → degrading` | 是 |
| D6 | 校验反复失败 | 校验失败 > 2 次 | `VERIFY_FAILED` | `verifying → degrading` | 是 |

阈值常量（`core/src/version.rs` 的 `retry` 模块，与文档 §2.4 一致）：
对账 `RECONCILE=3`、块连续 `CHUNK_FAIL_DEGRADE=3`、校验 `VERIFY=2`（触发阈值为 `VERIFY+1=3`）。

### 3.2 降级动作序列（§4.2，由 `SessionDriver::execute_degrade` 执行第 4–8 步）

```
1. 取消主算法所有在途块请求 / futures          （调用方，见 Applied.degraded）
2. 释放并发 Semaphore 许可（全局 + 每 peer）      （调用方）
3. 停止心跳 interval                              （调用方）
4. 按 4MB→16MB 对齐规则换算已确认进度 ── 必须在清空主算法队列【之前】取快照
5. 丢弃非对齐边界上的部分块（仅这些需重传）
6. 用 basic 重建块计划，状态机走 Degrade→DegradeComplete
7. 设 algorithm=basic，记录降级原因与时间戳
8. 发出 UI 事件，界面立即显示降级标识与原因
```

> 第 4 步的快照时序是实测抓出的坑：`progress_snapshot_is_taken_before_the_queue_is_rebuilt`
> 锁死——若先重建队列再取快照，UI 上「已用主算法完成 N 块」永远是 0，用户以为白传了。

### 3.3 恢复策略（§4.3）

| 策略 | 说明 | 代码落点 |
|---|---|---|
| 会话内不回切 | 一旦降级，本次会话保 basic 到底，避免主/基横跳丢进度 | `DegradeController` 一旦 `algorithm=Basic`，`observe` 直接返回 `AlreadyBasic`，`fire()` 是唯一写 `algorithm` 处 |
| 下次会话重测 | 新会话重新能力检测；通过用主算法，否则直接 basic | `SessionDriver::start` → `on_capabilities` |
| 设备级降级记忆 | 同一设备连续 3 次非 D1 失败 → `preferBasic=true`，后续会话直接 basic | `DegradeMemory`（阈值 `THRESHOLD=3`），`with_preferred_basic()` 构造 |
| 人工恢复 | 「重新启用主算法」按钮清除 `preferBasic` | `DegradeMemory::clear()` |
| 记忆不持久化到对端 | `preferBasic` 只存本机，不影响对端判断 | `DegradeMemory` 故意不实现 `Serialize/Deserialize/JsonSchema`（§4.3：记忆永不得发往对端） |

> **D1 vs D2–D6 的区分决定记忆**：D1（对端没能力）稳定，既不计数也不清零；
> D2/D3/D5/D6（有能力但跑不通）是环境性的，记入记忆避免反复失败。由 `DegradeReason::counts_toward_memory()` 单点保证。

### 3.4 降级的可见性（§4.4，UI 快照 `DegradeVisibility`）

每次降级产生一条事件，`DegradeVisibility` 一次性给出 UI 所需全部字段（做成结构体而非多个 getter，
「漏显示一项」会变成编译期字段缺失）：

```
┌────────────────────────────────────────────┐
│  当前算法：基础模式                          │  ← algorithm
│  降级原因：块连续失败 3 次（CHUNK_RETRY_    │  ← reason_code + reason_text
│            EXHAUSTED）                     │
│  已用主算法完成 12/40 块，将重传 7 块        │  ← progress_text()
│  [重新启用主算法]                            │  ← show_reenable_advanced（仅记忆生效时）
└────────────────────────────────────────────┘
```

`progress_text()` 文案：`"已用主算法完成 {completed}/{total} 块，将重传 {wasted} 块"`——
`wasted` 即「部分完成但要整块重传」的块数，UI 必须如实说出降级的代价，别让用户以为降级免费。

### 3.5 中止 / 断线不惩罚用户（S17）

`SessionOutcome` 对「用户中止 / 对端断开」判为 `Inconclusive`——既不计数也不清零。
否则用户连点三次取消就会永久失去主算法，且毫无提示。对应测试 `user_abort_and_peer_loss_are_inconclusive`。

---

## 四、代码落地对照

| 设计点 | 源码 |
|---|---|
| 三状态机（Presence / Connection / Transfer） | `core/src/state/{presence,connection,transfer}.rs` |
| 按钮裁决（唯一依据 `can()`） | `core/src/state/policy.rs` |
| 分块引擎（4MiB piece / 16MiB block / 弱强双校验 / 差异三分类 / piece→block 换算） | `core/src/transfer/chunk.rs` |
| 调度与退避（全局信号量 12 + 重试独立配额 4 + 握手/块两套全抖动退避） | `core/src/transfer/schedule.rs` |
| 降级控制器（D1–D6 判定 / 设备级记忆 / UI 可见性） | `core/src/transfer/degrade.rs` |
| 会话编排（决策与 IO 分离，驱动状态机串起全流程） | `core/src/transfer/session.rs` |
| 清理清单（§六 有序 8 步，删文件必在取消请求之后） | `core/src/transfer/cleanup.rs` |
| 模块分工文档 | `core/src/transfer/mod.rs` |

### 设计智慧留存

所有跨三代代码库的硬经验已沉淀进 `DESIGN-WISDOM-REGISTER.md`（E10 文档表格必须有测试守着、
S15 不把用户困在终态、S16 裁决结论必须能经状态机走通、S17 不惩罚用户正常操作、S18 迟到的信号不得污染已定局会话、S19 人工清除必须同时清零连续计数）。
