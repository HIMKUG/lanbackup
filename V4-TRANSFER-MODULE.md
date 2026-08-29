# V4 传输模块设计

> 状态：待评审 · 配套文档 `V4-ARCHITECTURE.md`
> 范围：文件传输模块的完整重构 —— 单一协议栈、两套算法、显式状态机、按钮可用性由状态推导

---

## 一、范围与定义

### 1.1 删除什么

| 删除项 | 现状 | 处置 |
|---|---|---|
| `/api/localsend/v2/*` 命名空间 | register / prepare-upload / upload / info / file-receipt / sync-dir / unpair | 整体删除 |
| `localsend` crate 的 `dto_v2` / `http::client::v2` / `http::server::v2` | 传输主路径 | 吸收 HTTP 管道后删除协议层（见 §1.3） |
| 自研 V2 降级路径 | `withDegradedResume` / `buildDegradedChunkPlan` / `DEGRADATION_STRATEGY` / `X-Scheduler-Version` | 整体删除，由本文的**算法级降级**取代 |
| `CAP_FALLBACK_V2` 能力位 | `V4-ARCHITECTURE.md` §2 已定义 | **撤销**，不再保留"退回另一个协议栈"的概念 |
| KDF v1 / CRYPTO v1 / device-id FNV-1a | 历史兼容分支 | 删除 |

### 1.2 保留什么：一套协议栈，两套算法

```
┌──────────────────────────────────────────┐
│  V4 协议栈（唯一）  /api/v4/*              │
├──────────────────────────────────────────┤
│  主算法   Advanced                        │  ← 默认路径
│    · 块级差异同步（弱校验快筛 + SHA-256）   │
│    · Merkle BEP-0052 证明校验              │
│    · 断点续传（权威块位图）                 │
│    · 并发：多接收端 × 每端多块              │
│    · piece = 4MB，leaf = 16KiB            │
├──────────────────────────────────────────┤
│  基础算法  Basic（内嵌兜底）                │  ← 同一协议栈内降级
│    · 16MB 固定分块，顺序传输               │
│    · 简单续传：记录已确认块序号             │
│    · 无 diff、无 Merkle、无并发            │
│    · 每块独立 SHA-256                     │
└──────────────────────────────────────────┘
```

**关键设计约束：块大小对齐。**
基础算法的 16MB 分块必须是主算法 4MB piece 的**整数倍**（16MB = 4 × 4MB）。这样降级时已完成的连续 piece 区间可以换算为已完成的 16MB 块区间，**只有落在非对齐边界上的部分需要重传**。若两者不对齐，降级就必须丢弃全部已传进度、从头再来 —— 那会让降级变成一场灾难。

### 1.3 localsend crate 的处置

删除的是它的**协议层**（v2 端点与 DTO），不是它的**HTTP 管道**。吸收进 `core` 的部分：

- `http/server/common/*` —— hyper 请求处理、JSON 收集、错误响应、文件落盘（保留）
- `util/*` —— base64 / filename / interface / time（保留）
- `model/discovery.rs` —— DeviceType / ProtocolType（保留）
- `http/server/v2.rs` / `http/client/v2.rs` / `http/dto_v2.rs` —— **删除**
- `http/server/v3.rs` / `http/client/v3.rs` —— 上游 v3，与本项目无关，**删除**
- `webrtc/` / `download` / `show` / mTLS —— **删除**

---

## 二、状态机总览

三张正交状态机 + 一个会话附加属性：

| 状态机 | 粒度 | 是否用户可控 | 作用 |
|---|---|---|---|
| **Presence 在线性** | 每设备 | 否（beacon 驱动） | 连接的前置门控 |
| **Connection 连接** | 每设备 | 是 | 传输的前置门控 |
| **Transfer 传输** | 每会话 | 是 | 传输过程 |
| **Algorithm 算法** | 每会话（附加） | 否（自动） | main / basic，供 UI 明示 |

### 2.1 Presence（在线性，每设备）

```
unknown ──收到 beacon──> online ──1.5s 无 beacon──> stale ──3s 无 beacon──> offline
              ↑                                                                │
              └──────────────────── 重新收到 beacon ───────────────────────────┘
```

| 参数 | 值 | 说明 |
|---|---|---|
| beacon 周期 | 500ms | UDP，32 字节定长，HMAC 截断 8B 认证 |
| online → stale | 1.5s | 连续 3 个周期未收到 |
| stale → offline | 3.0s | 连续 6 个周期未收到 |

`offline` 会**强制**把 Connection 推到 `lost`（见 C5）。

### 2.2 Connection（连接，每设备）

```
                    ┌──────────────────────────────────────┐
                    ↓                                      │
disconnected ──发起──> connecting ──握手成功──> connected ──断开──> disconnecting
     ↑                   │                        │                    │
     │              [超时/失败]             [beacon 中断]                 │
     │                   ↓                        ↓                     │
     └────────────── failed                    lost ────────────────────┘
                                                 │
                                        中止全部传输 + 清理
```

| # | 当前态 | 事件 | 守卫 | 目标态 | 副作用 |
|---|---|---|---|---|---|
| C1 | disconnected | 用户点「连接」 | presence == online | connecting | 发起 V4 握手，超时 5s |
| C2 | connecting | 握手成功 | — | connected | 启动心跳（周期 5s），记录 session_key |
| C3 | connecting | 超时或失败 | 重试 ≤3，退避 1s/2s/4s | connecting | 重试 |
| C4 | connecting | 重试耗尽 | — | failed | 提示「连接失败：<原因>」，2s 后回 disconnected |
| C5 | connected | presence → offline | — | lost | **中止该设备全部传输并清理**（见 §6） |
| C6 | connected | 心跳连续 3 次无响应（15s） | — | lost | 同 C5 |
| C7 | connected | 用户点「断开」 | — | disconnecting | 发送 disconnect 通知对端 |
| C8 | disconnecting | 通知完成或 1s 超时 | — | disconnected | 清理会话与心跳 |
| C9 | lost / failed | 用户点「连接」 | presence == online | connecting | 重新开始 |
| C10 | 任意 | 对端解配对（对账发现） | — | disconnected | 删除配对记录，提示「对方已解除配对」 |

**关键约束：`connected` 蕴含 `online`。** presence 一旦跌到 `offline`，连接必然转 `lost`，不存在"已连接但对方离线"的状态。这条直接消灭"离线却能连接"。

### 2.3 Transfer（传输，每会话）

```
                                    ┌──────────────────────────────────┐
                                    ↓                                  │
idle ──start──> preparing ──┬─[有 CAP_ADVANCED]─> reconciling ──> transferring ──> verifying ──> completed
                            │                                              │  ↑                    │
                            ├─[无 CAP_ADVANCED / 初始化失败]──────────────────┘  │                    │
                            │                                     [校验失败≤2]───┘                    │
                            └─[重试耗尽]──> failed                                                    │
                                                                                                     │
   transferring ──[心跳超时15s]──> paused ──[对账成功]──> transferring                                 │
                                     └──[对账失败>3]──> degrading ──> transferring(basic) ─────────────┘
   transferring ──[连续块失败>3]──> degrading ──> transferring(basic)
   verifying ──[校验失败>2]──> degrading ──> transferring(basic)

   任意非终态 ──[用户中止]──> aborted
   任意非终态 ──[连接断开]──> aborted（原因 CONNECTION_LOST）
   任意非终态 ──[不可恢复错误]──> failed
```

| # | 当前态 | 事件 | 守卫 | 目标态 | 副作用 |
|---|---|---|---|---|---|
| T1 | idle / completed / failed / aborted | 用户点「开始传输」 | connection == connected | preparing | 生成 session_id，发 `/api/v4/session/prepare` |
| T2 | preparing | prepare 成功，对端有 `CAP_ADVANCED` | — | reconciling | algorithm = main |
| T3 | preparing | prepare 成功，对端无 `CAP_ADVANCED` | — | transferring | algorithm = basic，降级原因 `PEER_NO_CAPABILITY` |
| T4 | preparing | 初始化失败（Merkle 构建 / 密钥派生 / 端点 5xx） | — | transferring | algorithm = basic，原因 `INIT_FAILED:<detail>` |
| T5 | preparing | prepare 失败 | 重试 ≤3，退避 1s/2s/4s | preparing | 重试 |
| T6 | preparing | 重试耗尽 | — | failed | 原因 `PREPARE_FAILED` |
| T7 | reconciling | 权威块位图拉取成功 | — | transferring | **用对端位图覆盖本地推测** |
| T8 | reconciling | 拉取失败 | 重试 ≤3 | reconciling | 退避重试 |
| T9 | reconciling | 重试耗尽 | — | degrading | 降级，原因 `RECONCILE_FAILED` |
| T10 | transferring | 心跳超时 15s | — | paused | 停发新块，保留已确认进度 |
| T11 | paused | 对账成功 | 重试 ≤3 | transferring | 从权威位图恢复 |
| T12 | paused | 对账失败 > 3 | — | degrading | 原因 `RETRY_EXHAUSTED` |
| T13 | transferring | 单块失败 | 该块重试 ≤3 | transferring | full jitter 退避（base 200ms，max 5s）后重发该块 |
| T14 | transferring | 连续块失败 > 3 | — | degrading | 原因 `CHUNK_RETRY_EXHAUSTED` |
| T15 | transferring | 所有块发完 | — | verifying | — |
| T16 | verifying | 校验通过 | — | completed | 写 receipt 终态，释放资源 |
| T17 | verifying | 校验失败 | 重试 ≤2 | transferring | 重传不一致块 |
| T18 | verifying | 校验失败 > 2 | — | degrading | 原因 `VERIFY_FAILED` |
| T19 | degrading | 清理完成 + 基础算法就绪 | — | transferring | algorithm = basic，按 16MB 重建块计划，**复用已对齐的进度** |
| T20 | degrading | 基础算法初始化失败 | — | failed | 原因 `BASIC_INIT_FAILED` |
| T21 | 任意非终态 | 用户点「中止」 | — | aborted | 清理（见 §6） |
| T22 | 任意非终态 | connection → lost / disconnected | — | aborted | 清理，原因 `CONNECTION_LOST` |
| T23 | 任意非终态 | 不可恢复错误 | — | failed | 清理 |
| T24 | transferring | 无进展超过 30 分钟 | — | failed | 原因 `STALLED` |

**终态单调**：`completed` / `failed` / `aborted` 不可回退到任何非终态。

### 2.4 阈值汇总

| 参数 | 值 | 适用 |
|---|---|---|
| 握手超时 | 5s | C1 |
| 握手重试 | 3 次，退避 1s/2s/4s | C3 |
| 心跳周期 | 5s | C2 |
| 心跳超时（→ paused） | 15s（连续 3 次无响应） | T10 |
| 心跳超时（→ lost） | 15s | C6 |
| 单块重试 | 3 次，full jitter base 200ms / max 5s | T13 |
| 连续块失败降级阈值 | 3 | T14 |
| 对账重试 | 3 次，退避 1s/2s/4s | T11 |
| 校验重试 | 2 次 | T17 |
| 会话无进展超时 | 30 分钟 | T24 |
| beacon 周期 / stale / offline | 500ms / 1.5s / 3.0s | Presence |

---

## 三、状态与按钮可用性对照表

### 3.1 按钮清单

| 按钮 | 粒度 | 说明 |
|---|---|---|
| 连接 | 每设备 | 建立 V4 握手 |
| 断开 | 每设备 | 主动断开 |
| 开始传输 | 每设备 | 新建会话并开始传输 |
| 中止 | 每会话 | 终止进行中的传输 |
| 重试 | 每会话 | 从 failed / paused 恢复 |
| 重新启用主算法 | 每设备 | 仅当设备级降级记忆生效时出现 |

### 3.2 连接 / 断开（依赖 Presence + Connection）

| Presence | Connection | 连接 | 断开 | 禁用时的提示 |
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

> **入口禁用而非禁用后报错**：`offline` 时「连接」按钮渲染为 `disabled`，鼠标悬停显示原因，点击不产生任何事件。

### 3.3 开始传输 / 中止 / 重试（依赖 Connection + Transfer）

| Connection | Transfer | 开始传输 | 中止 | 重试 | 禁用时的提示 |
|---|---|---|---|---|---|
| 非 connected | 任意 | ✗ | — | — | 「未连接，请先连接对方」 |
| connected | idle | ✓ | ✗ | ✗ | 中止：没有进行中的传输／重试：没有可重试的任务 |
| connected | preparing | ✗ | ✓ | ✗ | 开始：传输进行中／重试：传输进行中 |
| connected | reconciling | ✗ | ✓ | ✗ | 同上 |
| connected | transferring | ✗ | ✓ | ✗ | 同上 |
| connected | paused | ✗ | ✓ | ✓ | 开始：传输已暂停，请重试或中止 |
| connected | degrading | ✗ | ✓ | ✗ | 开始：正在切换算法／重试：正在切换算法 |
| connected | verifying | ✗ | ✓ | ✗ | 开始：正在校验／重试：正在校验 |
| connected | completed | ✓ | ✗ | ✗ | 中止：传输已完成／重试：传输已成功 |
| connected | failed | ✓ | ✗ | ✓ | 中止：传输已结束 |
| connected | aborted | ✓ | ✗ | ✓ | 中止：传输已中止 |

**「重试」在不同状态下语义不同：**

| 来源状态 | 重试做什么 |
|---|---|
| paused | 重新对账（拉取权威位图）→ 从断点继续 |
| failed | 新建会话，从头开始；若失败原因是降级相关则沿用 basic 算法 |

### 3.4 重新启用主算法

| 条件 | 可用性 |
|---|---|
| 设备级降级记忆未生效 | 不渲染 |
| 设备级降级记忆生效（连续 3 次主算法失败） | ✓ 可用，点击后清除记忆并提示「下次传输将重新尝试主算法」 |

---

## 四、降级触发条件与恢复策略

### 4.1 触发条件

| # | 触发点 | 条件 | 降级原因码 | 发生的状态迁移 |
|---|---|---|---|---|
| D1 | 能力检测不通过 | `/api/v4/session/prepare` 响应无 `CAP_ADVANCED` | `PEER_NO_CAPABILITY` | preparing → transferring(basic) |
| D2 | 初始化失败 | Merkle 构建失败 / 密钥派生失败 / diff 端点 5xx / 内存不足 | `INIT_FAILED:<detail>` | preparing → transferring(basic) |
| D3 | 对账失败 | `/api/v4/session/diff` 连续 3 次失败 | `RECONCILE_FAILED` | reconciling → degrading |
| D4 | 传输中断且重试无效 | 心跳超时后对账 3 次全失败 | `RETRY_EXHAUSTED` | paused → degrading |
| D5 | 块连续失败 | 连续 3 个块重试耗尽 | `CHUNK_RETRY_EXHAUSTED` | transferring → degrading |
| D6 | 校验反复失败 | verifying 失败 > 2 次 | `VERIFY_FAILED` | verifying → degrading |

### 4.2 降级动作序列

```
1. 停止主算法的所有在途块请求，取消 futures
2. 释放并发 Semaphore 许可（全局 + 每 peer）
3. 停止心跳 interval，记录已确认 piece 区间
4. 按 4MB→16MB 对齐规则换算已确认区间：
     已确认 16MB 块 = floor(连续已确认 piece 数 / 4)
5. 丢弃非对齐边界上的部分块（仅这些需要重传）
6. 用 basic 算法重建块计划，发 /api/v4/session/prepare?algo=basic
7. 更新 algorithm = basic，记录降级原因与时间戳
8. 发出 UI 事件，界面立即显示降级标识与原因
```

### 4.3 恢复策略

| 策略 | 说明 |
|---|---|
| **会话内不回切** | 一旦降级，本次会话保持 basic 到底。避免主/基反复横跳造成的抖动与进度丢失 |
| **下次会话重测** | 新建会话时重新做能力检测；通过则用主算法，不通过则直接 basic |
| **设备级降级记忆** | 同一设备连续 3 次触发 D2/D3/D5/D6（即非 D1 的"能力不足"，而是"能力有但跑不通"），在设备记录上标记 `preferBasic = true`，后续会话**直接**用 basic，跳过主算法尝试 |
| **人工恢复** | UI 提供「重新启用主算法」按钮，清除 `preferBasic`，下次会话重新尝试 |
| **记忆不持久化到对端** | `preferBasic` 只存在本机，不告知对端，不影响对端判断 |

> 区分两种降级原因很重要：
> **D1（对端没能力）** 是稳定的，不记入降级记忆——对端升级后自然恢复。
> **D2/D3/D5/D6（有能力但跑不通）** 是环境性的，记入记忆以避免反复失败。

### 4.4 降级的可见性

每次降级必须产生一条事件，UI 需展示：

```
┌────────────────────────────────────────────┐
│  当前算法：基础模式                          │
│  降级原因：块连续失败 3 次（CHUNK_RETRY_    │
│            EXHAUSTED）                     │
│  已用主算法完成 12/40 块，将重传 7 块        │
│  [重新启用主算法]                            │
└────────────────────────────────────────────┘
```

降级事件同时写入日志，含：时间戳、设备、原因码、已传进度、对端能力位图。

---

## 五、非法操作的处理

### 5.1 单一裁决函数

所有交互走同一个 `can()` 函数，它是**唯一依据**。UI 用它推导 `disabled`，运行时用它二次校验。

```ts
type Action = 'connect' | 'disconnect' | 'start' | 'abort' | 'retry' | 'restoreMain';

interface Verdict {
  allowed: boolean;
  reason?: string;   // 不允许时的可读提示
}

function can(action: Action, ctx: {
  presence: Presence;
  connection: Connection;
  transfer: Transfer;
  algorithm: Algorithm;
}): Verdict;
```

### 5.2 双保险

```
UI 层：   :disabled="!can('start', ctx).allowed"
          :title="can('start', ctx).reason ?? ''"

运行时：  async function onStart() {
            const v = can('start', ctx);
            if (!v.allowed) { toast.warn(v.reason); return; }   // 不静默失败
            ...
          }
```

即使 UI 绑定写漏、或状态在点击瞬间发生变化（竞态），运行时守卫仍会拦截并给出提示。**不存在静默失败**。

### 5.3 提示文案原则

- 说清**当前是什么状态**，而不是只说"不允许"
- 说清**要怎么做才能继续**
- 不暴露内部错误码给用户（`INIT_FAILED:merkle_oom` 记日志，UI 显示"传输初始化失败，已切换到基础模式"）

| 场景 | 文案 |
|---|---|
| 离线点连接 | 对方离线，无法连接 |
| 未连接点传输 | 未连接，请先连接对方 |
| 传输中再点开始 | 传输进行中 |
| 已完成后点重试 | 传输已成功，无需重试 |
| 降级中点击任何操作 | 正在切换传输算法，请稍候 |
| 连接断开导致中止 | 连接已断开，传输已中止 |

---

## 六、连接断开时的清理清单

`connection → lost` 或用户中止时，必须清理：

| 对象 | 清理动作 |
|---|---|
| 在途块请求 | 取消所有 futures，关闭上传流 |
| Semaphore 许可 | 归还全局 + 每 peer 许可，避免泄漏导致后续传输无法启动 |
| 心跳 interval | 停止并 drop |
| 内存状态 | 清除 `FileTransferState` / `PeerSession` / 权威块位图 |
| 临时分块文件 | 删除 `__chunked__/` 下的部分块 |
| 数据库会话记录 | 标记 `aborted` 并写入原因，**不删除**（便于排查） |
| 任务终态 | 未确认的任务一律标记 `cancelled`，不猜测成败 |
| UI | 清空进度条，显示中止原因 |

> 清理顺序固定：先停请求 → 再释放许可 → 再清内存 → 最后删文件。
> 反过来会在请求仍持有引用时删除文件，导致不可预期的 IO 错误。

---

## 七、与 V4-ARCHITECTURE.md 的差异

本文确认后，需同步修订架构文档：

| 位置 | 修订 |
|---|---|
| §2 能力位图 | 移除 `CAP_FALLBACK_V2`，新增 `CAP_ADVANCED`（主算法能力） |
| §3.4 降级路径 | 「协议级降级 → 纯 V2」整行删除，改为指向本文的算法级降级 |
| §4.4 降级矩阵 | 删除「协议级」行；能力级/分块级合并为本文 §4 的 D1–D6 |
| §5 路由表 | 删除所有 `来源 = v2/*` 的端点合并标记，改为纯 V4 端点 |
| §9 localsend 吸收 | 「需要搬入」清单移除 `http/server/v2.rs`、`http/client/v2.rs`、`http/dto_v2.rs` |
| §10 实施计划 | 阶段 2「吸收传输层」拆为「吸收 HTTP 管道」+「实现 V4 传输端点」两步 |

---

## 八、落地顺序

本模块依赖 `core` crate 存在，因此排在 V4 计划的阶段 2 之后：

| 顺序 | 依赖 | 内容 |
|---|---|---|
| 1 | 阶段 0 / 0.5 | 仓库可独立构建 + Android 绑定 spike 通过 |
| 2 | 阶段 1 | 契约即代码（schemars），路由表定稿 |
| 3 | 阶段 2 | 吸收 localsend 的 **HTTP 管道**（非协议层） |
| 4 | **本文** | 实现 V4 传输端点、两套算法、三张状态机、降级与恢复 |
| 5 | 阶段 4 | 双端状态一致性（对账、`reconciling`） |
| 6 | 阶段 5+ | 控制面合并、Android 绑定、清理 V2 残留 |

**不建议在当前的三份实现（TS / Rust / Java）上直接改** —— 那会产生第四份彼此不一致的实现，与 V4 的单一核心目标背道而驰。
