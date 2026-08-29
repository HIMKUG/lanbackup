# V4 架构设计

> 状态：待评审
> 目标：把 V1 / V2 / V3 三代设计的精华合并为单一的 V4 协议与单一实现

> ## ⚠️ 配套必读：`DESIGN-WISDOM-REGISTER.md`
>
> 现有代码（3 万行、三端）的注释里埋着大量**实测踩坑后总结的设计决策**。
> 该登记表逐条列出了这些智慧（带 `文件:行号` 可核对），并标注每一条在 V4 中的落地位置与状态。
>
> **本文件只描述架构方向；具体行为约束一律以登记表为准。**
> 每完成一个阶段，必须回到登记表更新状态 —— 任何一条从"待落地"直接消失（既未标记已落地、也未写明有意识变更的理由）都视为事故。

---

## 一、为什么要 V4

当前仓库里有 **五套并存的协议命名空间**，它们是不同时期叠加的产物，彼此没有统一版本号：

| 命名空间 | 来源 | 服务端实现 | 用途 |
|---|---|---|---|
| `/api/localsend/v2/*` | localsend 上游 | Rust（localsend crate）+ Java（手写） | 传输：register / prepare-upload / upload / info |
| `/api/backup/v1/*` | 自研 | Rust + Java | 清单与同步：manifest / chunk-status / cancel（`PROTOCOL_VERSION = '1.1'`） |
| `/api/v3/*` | 自研 | **仅 Rust** | 控制面：probe / handshake / sync-status / revoke |
| `v5` | 自研 | 部分 | 解配对与吊销，ECDSA 签名 + 吊销令牌 |
| `localsend-scheduler v1` | 自研扩展 | TS + Rust（死代码）+ Java | 块 diff / Merkle / 心跳 |

> **2026-08-29 修订：V2 整体移除，兜底改为「换算法」。**
>
> V2 存在的初衷不是兼容老设备，而是 **V3 在部分网络环境下跑不通，需要一条退路** —— 这个防御性意图是对的。
> 但退路不该是**另一套协议栈**：那意味着长期维护两份协议、两套 DTO、两套测试、三个 v3 混在语境里。
>
> V4 保留防御性意图，改变实现机制：**同一套 V4 协议栈内，主算法之下内嵌一层基础算法**。
> 因此 `/api/localsend/v2/*` 与自研的 V2 降级路径（`withDegradedResume` / `buildDegradedChunkPlan`）**一并删除**。
> 完整设计见 `V4-TRANSFER-MODULE.md`。

同时删除这三条**代码级历史兼容分支**：

| 历史遗留分支 | 说明 | V4 处置 |
|---|---|---|
| `KDF_VERSION = 1` | SHA-256 直推的旧密钥派生 | 删除 |
| `CRYPTO_VERSION` 枚举 | dispatch 层已删，枚举只剩内部转换 | 删除 |
| device-id v1 FNV-1a | 旧设备 ID 派生 | 删除 |

**三个问题：**

1. **命名冲突。** 上游 localsend 自己有一套 v3（`/api/localsend/v3/nonce`、`/api/localsend/v3/register`），与自研 `/api/v3/*` 同名不同物。这是"V1/V2/V3 哪个更好"这个问题的根源 —— 有三个 v3 混在同一语境里。
2. **三份实现，零共享测试向量。** 同一份协议在 TypeScript、Rust、Java 里各写一遍，没有任何交叉验证。漂移只是时间问题。
3. **第二套 HTTP 栈。** 传输走 localsend 的 hyper（53317），控制面是手写的 `std::net::TcpListener` + 手工 HTTP/1.1 解析（53318）。
4. **双端状态无一致性保证。** 见 §3 —— 这是实测中全部稳定性问题的共同根因。

V4 的目标不是再加一层，而是**收敛为一套命名空间、一份实现、一个版本号，并给双端状态建立单一事实源**。

---

## 二、V4 的定名与版本体系

### 命名空间

```
/api/v4/*
```

所有端点统一在此前缀下。与上游 `/api/localsend/v2|v3/*` 通过路径前缀天然区分，不再需要口头解释"哪个 v3"。

### 版本常量

现有三个版本常量合并为一个：

```rust
pub const PROTOCOL_VERSION: u32 = 4;
```

`KDF_VERSION`、`CRYPTO_VERSION` 不再独立演进 —— 它们只能跟随协议版本整体升级。

处于开发期、无存量设备，因此**代码级的历史兼容分支全部删除**：

- 删除 `derive_local_storage_key`（KDF v1 SHA-256 直推）
- 删除 `CryptoVersion` 枚举及其 dispatch 残留
- 删除 device-id 的 FNV-1a 旧派生
- 删除 `shared-core/src/transfer.ts` 中的 KDF v1 兼容路径

> **注意**：这里删的是"读旧数据"的兼容代码。
> "跑不通时退回去"的兜底能力依然存在，但已改为**同协议栈内的算法降级**（主算法 → 基础算法），见 §3.4 与 `V4-TRANSFER-MODULE.md`。

### 能力协商（替代版本号硬匹配）

V4 不再靠"版本号完全匹配才启用"来门控扩展能力，改为**能力位图**：

```rust
#[derive(Clone, Copy)]
pub struct Capabilities(u32);

pub const CAP_PAIRING_V4: u32   = 1 << 0;  // V4 配对握手
pub const CAP_ADVANCED: u32     = 1 << 1;  // ★ 主传输算法（块差异 + Merkle + 续传 + 并发）
pub const CAP_RECONCILE: u32    = 1 << 2;  // 双端状态对账（见 §三）
pub const CAP_ENCRYPT: u32      = 1 << 3;  // 传输层加密（默认开，可协商降级，见 §四）
pub const CAP_BEACON: u32       = 1 << 4;  // UDP presence beacon（支撑 0.5s TTL，见 §3.3-B）
```

`/api/v4/probe` 响应携带能力位图，双方按位与决定启用哪些能力。

> **2026-08-29 修订**：原 `CAP_FALLBACK_V2`（退回纯 V2 传输通道）已**撤销**。
> 兜底机制从"换协议栈"改为"**换算法**"：同一套 V4 协议栈内，主算法之下内嵌一层基础算法
> （16MB 分块 + 简单续传）。防御性意图保留，但不再维护两套协议。
> 详见 `V4-TRANSFER-MODULE.md`。

---

## 三、双端状态一致性模型（V4 的核心）

这一节是整份文档最重要的部分。前面 §一 §二 解决的是"代码混乱"，这一节解决的是"行为不可靠"。

### 3.1 根因：两端各自记账，没有权威方

实测中遇到的稳定性问题看起来是七个独立的 bug，实际上是同一个根因的不同表现：

| 实测问题 | 根因 |
|---|---|
| 一方解配对，另一方提示后自己仍配对 | 配对状态是**本机单方面记录**，没有"你还认我吗"的反向确认 |
| 对方离线却能连接 | **在线性**与**配对状态**两个维度被混为一谈，UI 拿配对状态当成了可连接性 |
| 一方认为任务在传输可重试，另一方认为已完成 | 任务终态**各自判定**，发送端的心跳超时推测覆盖不了接收端已确认完成的事实 |
| 断点续传不稳定 | 发送端的 `sentChunks` / `ackedChunks` 是**本地推测**，恢复时未向接收端拉取权威状态 |
| 双端状态机不匹配 | 三份实现（TS / Rust / Java）各跑各的，`phase` 变更**不需要对端确认** |
| 握不了手 | 缺幂等与可查询的握手状态 |
| 心跳不稳定 | `checkTimeouts()` **全仓库无人调用**，超时逻辑形同不存在 |

**一句话：两端各自维护一份状态，谁也不问谁，谁也不服谁。**

### 3.2 四条原则

**原则一：每个状态有且只有一个权威方。**

| 状态 | 权威方 | 理由 |
|---|---|---|
| 块到达状态（哪些块已收到且校验通过） | **接收端** | 数据在谁的磁盘上谁知道 |
| 任务终态（成功 / 失败 / 已取消） | **接收端** | 同上 |
| 会话阶段（phase） | **双方共同推进** | 必须一致才能继续 |
| 配对信任状态 | **各自维护 + 周期性双向对账** | 无第三方可仲裁 |
| 在线状态 | **各自探测，带 TTL** | 网络分区下无法达成全局一致 |

**原则二：对账优先于推测。**
任何恢复流程都必须先向权威方拉取状态，禁止用本地记录推测。发送端的 `sentChunks` 只能用于 UI 乐观显示，不能作为续传依据。

**原则三：阶段变更需对端确认。**
`phase` 不再是本地字段，而是双方共识。变更需对端 ack，未确认则停留在原阶段并重试。

**原则四：终态单调。**
已确认的终态不可回退。这一条直接消灭"complete 被心跳超时改成 paused"这类隐患。

### 3.3 四张状态机

#### A. 配对生命周期（解决"解配对不彻底"）

```
none ──发起──> pending ──对端确认──> active
                  │                    │
                  │                    ├──任一方发起解除──> revoking ──对端 ack──> revoked
                  │                    │                       │
                  └──超时──> revoked   │                       └──超时 + 吊销令牌──> revoked
                                       │
                                       └──对账失败（对端说不认 / 连续 N 次无响应）──> revoking
```

关键：**`active` 不是一次确认永久有效，需要周期性双向对账维持。**

**对账策略：事件驱动 + 定时兜底。**

- 有连接活动时（probe 成功、传输开始、握手）**立即**对账 —— 这是发现状态不一致最快的时机
- 无活动时低频轮询兜底：仅设备亮屏 / 前台时执行，默认 5 分钟一次
- 离线设备无法对账，用吊销令牌兜底（继承 v5 设计，30 天有效期）

对账问的不是"你在吗"，而是"**你还认我吗**"：

```
GET /api/v4/sync-status
--> { deviceId, youArePairedWithMe: true, myTrustVersion: 17 }
<-- { deviceId, youArePairedWithMe: false }     ← 对端已单方面解除
```

本机的有效信任状态 = **本机记录 ∩ 对端确认**。任一方说"不认"，本机立即进入 `revoking`。

离线对端无法对账，用吊销令牌兜底（继承 v5 设计，30 天有效期）。

#### B. 在线性（解决"离线却能连接"）

**TTL 定为 0.5 秒**，前后台一致 —— 在线性必须足够灵敏，否则"对方离线却能连接"这类反常识行为无法根治。

```
unknown ──beacon──> online (TTL 0.5s) ──1.5s 未刷新──> stale (3 个周期) ──> offline
                        ↑                                                    │
                        └────────────── 收到 beacon ─────────────────────────┘
```

关键：**配对状态 ≠ 可连接性**，两者必须分开建模与显示。

| 组合 | 允许的操作 |
|---|---|
| `paired AND online` | 发起新传输、重连会话、解配对 |
| `paired AND offline` | 仅查看历史、重连**已存在的**会话；**禁止发起新传输** |
| `NOT paired AND online` | 仅配对、probe |

`online` 不持久化（重启即 `unknown`），`paired` 持久化。UI 必须分别渲染这两个维度，不能只显示一个"已连接"。

##### 为什么 0.5s 不能用 HTTP 轮询

0.5 秒一次 HTTP GET 意味着每秒 2 次 TCP 建立 + TLS/加密 + HTTP 解析，双端每秒 4 次往返。这在局域网上带宽无所谓，但**每次都会唤醒移动端射频模块**，且 hyper 的连接开销远大于报文本身 —— 是杀鸡用牛刀。

V4 改用 **UDP presence beacon**。

##### beacon 报文格式（32 字节定长）

```
 0        8        16       20       24              32
├────────┼────────┼────────┼────────┼───────────────┤
│ deviceId 前 8B  │  ts(4B) │ seq(4B) │ HMAC 截断(8B) │
└────────┴────────┴────────┴────────┴───────────────┘
```

| 字段 | 长度 | 说明 |
|---|---|---|
| deviceId 前缀 | 8B | 设备标识前 8 字节，够做局域网内区分 |
| ts | 4B | Unix 秒（截断），防重放 |
| seq | 4B | 单调递增序号，防重放 + 检测丢包 |
| auth tag | 8B | `HMAC-SHA256(pairing_secret, deviceId‖ts‖seq)` 截断前 8 字节 |

##### 为什么是认证而不是加密

这是关键取舍：**presence beacon 需要的是 authenticity（防伪造），不是 confidentiality（防窃听）。**

- `deviceId` 本来就不是秘密 —— 加密一个公开标识符没有意义
- 真正要防的是"伪造某设备在线"，因此只需 HMAC 认证标签
- **HMAC-SHA256 截断 8 字节比 AES-256-GCM 快一个数量级**，且 64 bit 认证标签对防伪造绰绰有余（伪造成功率 1/2⁶⁴，且 0.5s 内即失效）
- 密钥直接用已建立的 `pairing_secret`，无需额外密钥交换

这样既满足"保证加密性"（认证性由 HMAC 保证），又满足 0.5s TTL 的性能要求。

##### 开销实测预期

| 项 | 数值 |
|---|---|
| 单 beacon | 32 字节 |
| 每设备每秒 | 64 B/s（2 次） |
| 10 台设备 | 640 B/s ≈ 5 kbps |

带宽可忽略。**真正的成本是移动端射频唤醒**（每秒 2 次），需要在 Android 上持 `WifiManager.MulticastLock`，这部分**必须实测电池影响**。周期做成配置项，默认 0.5s，若实测耗电不可接受再调整。

> **降级**：对端不支持 `CAP_BEACON` 时，退回 HTTP `GET /api/v4/probe` 轮询，周期放宽至 5 秒（避免高频 HTTP 开销）。

#### C. 会话（解决"断点续传不稳 + 状态机不匹配"）

```
idle ──start──> preparing ──┬─[对端有 CAP_ADVANCED]─> reconciling ──> transferring ──> verifying ──> completed
                            │                             │              │                │
                            ├─[无 CAP_ADVANCED]───────────────────────────┘                │
                            │                        [校验失败 ≤2]─────────────────────────┘
                            └─[重试耗尽]──> failed

   transferring ──[心跳超时 15s]──> paused ──[对账成功]──> transferring
                                       └──[对账失败 >3]──> degrading ──> transferring(basic)
   transferring ──[连续块失败 >3]──> degrading ──> transferring(basic)
   verifying    ──[校验失败 >2]──> degrading ──> transferring(basic)

   任意非终态 ──[用户中止]──> aborted
   任意非终态 ──[连接断开]──> aborted（清理中间状态）
   任意非终态 ──[不可恢复错误]──> failed
```

`reconciling` 是 V4 新增阶段，也是断点续传稳定性的关键：

> 从 `paused` 恢复时**不允许直接回到 `transferring`**。必须先进入 `reconciling`，向接收端 `GET /api/v4/session/diff` 拉取权威块位图，用对端的事实覆盖本地的推测，然后才继续传输。

`degrading` 是算法降级阶段：主算法跑不通时切到内嵌的基础算法（16MB 分块 + 简单续传），**不换协议栈**。

> **完整的迁移表、阈值、按钮可用性对照见 `V4-TRANSFER-MODULE.md`。** 本节只给出形状，避免两处维护同一张表而产生漂移。

#### D. 任务（解决"双端对任务认知不一致"）

```
queued ──> transferring ──> completed    ← 终态
                       ├──> failed       ← 终态
                       └──> cancelled    ← 终态
```

- 终态由**接收端**判定，通过 `POST /api/v4/session/receipt` 回传发送端
- 发送端心跳超时进入 `paused` 时，**不允许自行判定失败** —— 必须先查询对端任务终态
  （这正是"一方认为在传输可重试、另一方认为已完成"的直接原因）
- 终态单调，写入后不可回退
- 每个文件独立记录终态，UI 可查"这个文件到底成功没有"

### 3.4 降级路径：换算法，不换协议

> **2026-08-29 修订**：原「协议级降级 → 纯 V2 传输」已撤销。
> 完整的降级触发条件、动作序列与恢复策略见 **`V4-TRANSFER-MODULE.md` §4**，本节只讲定位。

三代设计里"留一条退路"的防御性意图是对的，但退路不该是**另一套协议栈** —— 那等于长期维护两份协议、两套 DTO、两套测试。V4 把它改成**同一协议栈内的算法降级**：

| | 主算法 Advanced | 基础算法 Basic |
|---|---|---|
| 分块 | 4MB piece，16KiB leaf | 16MB 固定分块 |
| 差异同步 | 弱校验快筛 + SHA-256 强校验 | 无 |
| 完整性 | Merkle BEP-0052 证明 | 每块独立 SHA-256 |
| 续传 | 权威块位图 | 已确认块序号 |
| 并发 | 多接收端 × 每端多块 | 顺序单块 |

**关键约束：16MB 必须是 4MB 的整数倍**，否则降级时已传进度无法换算，只能从头再来。

**降级必须可观测**：每次降级记录事件日志，携带触发原因，UI 需能显示"当前算法 + 降级原因 + 已传进度处置"。否则降级会变成 silently worse，出问题无从排查。

### 3.5 实测问题逐条对照

| 实测问题 | V4 解法 | 出处 |
|---|---|---|
| 断点续传不稳定 | 权威方改接收端；恢复前强制经 `reconciling` 拉取权威位图 | §3.2 / §3.3-C |
| 加密导致握手不稳 | 握手层去加密只做认证，加密收敛到统一的传输层，并可协商降级为明文 | §四 |
| 双端状态机不匹配 | 单一 Rust 实现 + phase 变更需对端 ack + 显式迁移表 | §3.2 / §7.2 |
| 协议握不了手 | 握手层去加密、只做认证；幂等 + 可查询状态 + 超时重试 | §四 / §六 |
| 心跳不稳定 | 会话自带 `tokio::time::interval` driver + 指数退避；心跳失败先进 `paused` 对账而非直接判失败 | §3.3-C / §7.2 |
| 连接码连接时协议不稳定 | 见 §十二 待确认项 | — |
| 一方解配对另一方仍配对 | 配对生命周期状态机 + `sync-status` 双向对账（事件驱动 + 定时兜底） | §3.3-A |
| 对方离线却能连接 | 在线性独立建模（TTL 0.5s + UDP beacon），`paired AND online` 门控 | §3.3-B |
| 任务状态双端分歧 | 任务终态由接收端权威判定并回传 | §3.3-D |
| 每个任务成功/失败/断联无记录 | 任务级 receipt + 事件日志 | §3.3-D |

---

## 四、协议分层与加密

### 4.1 问题：加密嵌在握手层里

V3 把加密做进了握手流程本身（连接码派生密钥 → HMAC 校验 → 派生会话密钥）。实测反馈是"什么特殊情况都出现过"。把加密与握手耦合在一起有三个后果：

1. **握手失败无法诊断。** HMAC 一旦不匹配，分不清是网络丢了包、双端状态不一致，还是密钥派生错了 —— 因为线上看到的是密文。
2. **双重加密。** 握手层加密 + 传输层加密嵌套两层，性能与复杂度翻倍，出问题时互相掩盖。
3. **没有退路。** 加密握手失败即整条链路不可用，连"先传完再说"这个选项都不存在。

### 4.2 V4 方案：握手只认证，传输统一加密

```
┌──────────────────────────────────────┐
│  应用层     manifest / sync / 任务     │
├──────────────────────────────────────┤
│  ★ 统一加密层   单一 AEAD 实例          │  ← 握手之后的全部流量在此统一加解密
│    AES-256-GCM，密钥由握手协商派生      │     数据 / 心跳 / 对账 / phase 同步
├──────────────────────────────────────┤
│  握手层     身份 + 能力 + 密钥协商       │  ← 明文，仅 ECDSA 签名做认证
│    /api/v4/handshake/*                │     失败可直接看报文定位
├──────────────────────────────────────┤
│  传输层     HTTP/1.1 over TCP (hyper)  │
└──────────────────────────────────────┘
```

**三条规则：**

**规则一：握手层不加密，只认证。**
probe / challenge / verify 全部明文传输，用 ECDSA P-256 签名保证 authenticity。连接码仍然只做 HKDF salt、**绝不上线**（继承 v3 设计）。

> 收益：握手失败时抓包即可定位，无需解密。"协议不稳定"里相当大的一类问题会因此变得可诊断。

**规则二：加密收敛到一层。**
握手成功后派生 `session_key`，此后**所有**流量走同一个 AEAD 实例，不存在第二层加密。

**规则三：加密可协商、可降级。**

```rust
pub const CAP_ENCRYPT: u32 = 1 << 6;  // 传输层加密（默认开启）
```

特殊网络环境下若加密导致不稳定，两端可协商降级为明文。局域网威胁模型下（防同网段普通用户，不防抓包者），明文是**可接受的最后退路** —— 这与 V2 兜底是同一条防御性思路：**先保证能用，再谈保密**。

> **取舍说明**：明文降级牺牲机密性，但**保留完整性校验**（HMAC 仍开启，防篡改）。是否允许降级由用户在设置中控制，默认关闭降级。

### 4.3 密钥派生

分层调整后，密钥树保持三层，但职责更清晰：

```
L1  storage_key   = PBKDF2-HMAC-SHA256(连接码, salt=SHA256(device_id), 600k, 32B)
                    加密本地存储的 pairing_secret（连接码 40bit 低熵 → 必须慢 KDF）

L2  pairing_secret = HKDF-SHA256(ECDH_shared, salt=H(连接码),
                                 info="lanbackup/v4/pairing/"||eph_pub||static_pub||双nonce)
                     长期存储。用于：握手签名、会话密钥派生、presence beacon 认证

L3  session_key    = HKDF-SHA256(session_shared, salt=pairing_secret,
                                 info="lanbackup/v4/session/"||session_id)
                     每会话一把，喂给统一加密层

L4  file_key       = HKDF-SHA256(session_key, info="lanbackup/v4/file/"||file_id)
                     每文件一把。nonce = chunk_index（文件内从 0 单调递增）
```

> **L4 为什么必须保留**：AES-GCM 的 nonce 复用是灾难性的（泄露明文异或与认证子密钥）。
> 每文件独立密钥 + nonce 用块序号，保证 nonce 在文件内绝不重复；断点续传时按块序号重建 nonce 即可，**不需要持久化 nonce 计数器** —— 这是三层设计真正的价值所在，不能简化掉。

### 4.4 完整降级矩阵

V4 有两级独立降级，互不干扰：

| 维度 | 级别 | 触发条件 | 退化到 | 出处 |
|---|---|---|---|---|
| **加密** | 明文级 | 加密传输连续失败，或两端协商不开 `CAP_ENCRYPT` | 明文传输 + HMAC 完整性校验 | §4.2 规则三 |
| **算法** | 基础级 | 对端无 `CAP_ADVANCED` / 初始化失败 / 重试耗尽 / 校验反复失败 | 16MB 分块 + 简单续传 | `V4-TRANSFER-MODULE.md` §4 |

> **2026-08-29 修订**：原「协议级 → 纯 V2 传输」整行删除。V4 只有一套协议栈。

---

## 五、目标架构

```
protocol/           契约事实源（schema 由 Rust 类型经 schemars 生成）
core/               ★ 第五个 workspace 包：lanbackup-core（Rust）
desktop/            Tauri 2，直接依赖 core
mobile/             Capacitor 6，经 JNI / uniFFI 调用同一份 core
shared-core/        瘦身：只留 logger / config / state / sync 编排 / scan
shared-ui/          不变
```

### core 模块划分

```
core/src/
├── lib.rs              uniFFI 导出 + Tauri 命令导出
├── version.rs          单一版本常量 + 能力位图
├── identity.rs         设备身份（删 FNV-1a）
├── crypto/
│   ├── kdf.rs          密钥树 L1–L4（storage → pairing → session → file）
│   ├── aead.rs         ★ 统一加密层：单一 AEAD 实例（见 §四）
│   └── sign.rs         ECDSA P-256 签名（握手层认证用，不加密）
├── pairing/            路径 A/B 握手（明文签名）+ 解配对 + 吊销 + 双向对账
├── presence/           UDP beacon 收发 + 在线性维护（TTL 0.5s，见 §3.3-B）
├── discovery/          组播 + /24 子网探测
├── sync/               三路增量 + manifest
├── transfer/
│   ├── server.rs       hyper 路由（吸收 localsend v2 server）
│   ├── client.rs       reqwest 客户端（吸收 localsend v2 client）
│   ├── dto.rs          ★ schemars 生成 JSON Schema
│   ├── session.rs      ★ 会话状态机（迁移自 scheduler.ts，补完迁移表）
│   ├── chunk.rs        ★ 弱/强双校验 + ChunkDiff
│   ├── merkle.rs       ★ BEP-0052，补 proof 生成与单 piece 校验
│   ├── reconcile.rs    ★ 对账：拉取对端权威块位图与任务终态
│   └── schedule.rs     ★ 并发控制（用 tokio Semaphore 补完空壳）
└── server/             单一路由表，单一端口 53317
```

★ 标记的部分来自 `shared-core/src/scheduler.ts`，是 V4 要继承并补完的精华，详见 §七。

### 关键决策

| # | 决策 | 理由 |
|---|---|---|
| 1 | 命名空间统一为 `/api/v4/` | 避开上游 v2/v3 命名冲突 |
| 2 | 三个版本常量合并为一个 | 三个版本号各自演进是无意义的复杂度 |
| 3 | 单一端口 53317 + 单一 hyper 路由表 | 消灭 53318 的手写 TCP/HTTP 解析器 |
| 4 | 契约即代码：schemars 从 Rust DTO 生成 schema | 手写 schema 与实现必然漂移，现有 9 份 schema 已与代码对不上 |
| 5 | Java 侧 3769 行手写 v2 服务端整体退役 | 同一协议的第二份实现，且是唯一没有契约测试的那份 |
| 6 | 情绪状态机留在前端，core 只发业务事件 | core 不应依赖 UI 概念，情绪引擎可独立演进 |
| 7 | **握手层不加密，只做 ECDSA 认证；加密收敛到统一传输层** | 加密嵌在握手里导致失败无法诊断、双重加密、没有退路（§4.1） |
| 8 | **每个状态指定唯一权威方，对账优先于推测** | 全部实测稳定性问题的共同根因（§3.2） |
| 9 | **在线性独立建模，TTL 0.5s，用 UDP beacon 而非 HTTP 轮询** | 根治"离线却能连接"；beacon 用 HMAC 认证而非加密，兼顾认证性与性能（§3.3-B） |

### 不可违背的既有约束

以下约束来自已有代码的实测经验，**V4 若在架构层面破坏它们，上层再怎么补都救不回来**。完整清单与出处见 `DESIGN-WISDOM-REGISTER.md`。

| # | 约束 | 破坏后果 |
|---|---|---|
| C1 | **设备形态与角色解耦**：任意设备可任任意角色，支持 A→B / B→A / A→A / B→B | 架构能力被砍（不能假设"电脑=发送端、手机=接收端"） |
| C2 | **扫描决策只在发送端做，接收端只被动接收** | 手机端算力被拖垮 |
| C3 | **增量判据用 mtime + size，不用内容哈希** | 手机端扫描从秒级变分钟级 |
| C4 | **接收端必须保留发送端 mtime** | 整条增量链路失效，每次全量重传 |
| C5 | **路径比较必须做 NFC 归一化，但存储/传输保留原样** | macOS↔Windows 备份**无限重传** |
| C6 | **所有网络调用走原生，绝不走 WebView fetch/XHR** | 无 CORS 头 → 被浏览器拦截 → "手机端从没同步成功" |
| C7 | **IO 全程流式、内存 O(1)，禁止整文件读入** | 大文件 OOM |
| C8 | **绝不持锁做慢 KDF（PBKDF2 600k）** | 接收路径解密全失败 + 并发 panic |
| C9 | **core → UI 的事件必须经单一派发线程，绝不在调用方线程 emit** | 跨线程消息死锁，整进程冻结而 WebView 照常动画 |
| C10 | **分块常量单一来源**（当前 4MB / 8MB / 16MB 四处并存） | 降级时进度无法换算，从头重传 |

> **关于 C10 的补充说明**：主算法 piece 与基础算法分块**必须成整数倍关系**，
> 否则降级时已传进度无法换算。当前代码里 4MB / 8MB / 16MB 三个值分属不同常量，
> V4 必须收敛为一个常量源并显式声明倍数关系。

---

## 六、V4 路由表

合并现有全部端点，单一命名空间：

### 发现与配对

| 方法 | 路径 | 来源 | 说明 |
|---|---|---|---|
| GET | `/api/v4/probe` | v3/probe + v2/info | 设备信息 + 静态公钥 + serverNonce + **能力位图** + **在线性 TTL** |
| POST | `/api/v4/handshake/challenge` | v3 | 重连（路径 B）：签发 JWT challenge。**幂等**，带 `request_id` |
| POST | `/api/v4/handshake/verify` | v3 | 首配（路径 A）/ 重连：验 HMAC。**幂等**，带 `request_id` |
| GET | `/api/v4/handshake/status` | **新增** | 按 `request_id` 查询握手结果。解决"握手发出去就失联，不知道成没成" |
| POST | `/api/v4/unpair-request` | v3 | 请求解配对 |
| POST | `/api/v4/unpair` | v2/unpair + v5 | 解配对通知（ECDSA 签名） |
| POST | `/api/v4/revoke-notify` | v3 | 吊销通知 |
| POST | `/api/v4/revoke-ack` | v3 | 吊销确认 |
| GET | `/api/v4/sync-status` | v3 | **双向信任对账**：不只问"你在吗"，而是问"你还认我吗" |

### 传输会话

| 方法 | 路径 | 来源 | 说明 |
|---|---|---|---|
| POST | `/api/v4/session/register` | v2/register | 会话注册 |
| POST | `/api/v4/session/prepare` | v2/prepare-upload | 上传准备，响应带 `X-Capabilities` |
| POST | `/api/v4/session/chunk` | v2/upload | 分块上传 |
| GET | `/api/v4/session/diff` | scheduler v1 `/file/{id}/diff` | 块差异探测。**权威块位图来源**，弱+强双校验 |
| GET | `/api/v4/session/verify` | scheduler v1 `/file/{id}/verify` | 整体校验 |
| GET | `/api/v4/session/phase` | **新增** | 查询会话当前 phase。phase 变更需对端 ack，此端点用于对账 |
| POST | `/api/v4/session/heartbeat` | scheduler v1 | 心跳，携带本端 phase 与权威块位图版本号 |
| POST | `/api/v4/session/abort` | scheduler v1 + v2/cancel | 中止会话 |
| POST | `/api/v4/session/receipt` | v2/file-receipt | 文件回执。**任务终态由接收端经此端点权威回传** |
| GET | `/api/v4/session/tasks` | **新增** | 查询会话内每个文件的终态。解决"双端对任务认知不一致" |

### 清单与同步

| 方法 | 路径 | 来源 | 说明 |
|---|---|---|---|
| GET | `/api/v4/manifest` | backup/v1 | 备份清单 |
| GET | `/api/v4/chunk-status` | backup/v1 | 块状态查询 |
| POST | `/api/v4/sync-dir` | v2/sync-dir | 目录映射同步 |
| POST | `/api/v4/move-to-delete` | backup/v1 | 移到待删 |
| POST | `/api/v4/disconnect` | backup/v1 | 断开连接 |

---

## 七、状态机的评估与迁移

`shared-core/src/scheduler.ts`（621 行）是三代设计中最有价值的部分，也是唯一**零调用**的部分。逐符号核查：

```
TransferScheduler            → 外部引用 0 处
MerkleTree                   → 外部引用 0 处
buildSchedulerManifest       → 外部引用 0 处
uploadChunkWithRetryUI       → 外部引用 0 处
withDegradedResume           → 外部引用 0 处
detectPeerSchedulerVersion   → 外部引用 0 处
DEGRADATION_STRATEGY         → 外部引用 0 处
weakChecksum                 → 外部引用 0 处
```

两端 `App.vue` 从 shared-core 导入的清单里不含任何 scheduler 符号。Rust 侧 `scheduler.rs`（1028 行）整体 `#[allow(dead_code)]`。**这是一台造好了但从未点火的引擎。** 好消息是它没有腐烂，设计完整。

### 7.1 保留的设计（V4 的核心竞争力）

| 设计 | 评价 |
|---|---|
| `X-Scheduler-Version` 头协商 + `withDegradedResume` 双路径 | 私有扩展的正确范式。多数实现直接硬切版本，这里留了退路 |
| `weakChecksum` 弱校验快筛 + SHA-256 强校验 | rsync 经典双校验；`ChunkDiff` 分 missing / matched / mismatched 三类 |
| Merkle 对齐 BEP-0052 | 选开放标准而非自创，奇数节点填充规则处理正确 |
| `TransferPhase` 用 `\| { error: string }` 代数变体 | 类型化错误态，优于可选字符串字段 |
| 四个不相交块集合（sent / acked / nacked / failed） | 断点续传记账的正确建模 |
| `jitteredBackoffMs` | full jitter 退避 |

### 7.2 需要在迁移时补完的部分

**问题 1：`TransferScheduler` 的并发控制是空壳。**

`globalChunksPermits` 和 `retryPermits` 只有 getter，没有 acquire / release。Rust 版有 `tokio::sync::Semaphore`，TS 版没有 —— "多接收端并发 + 全局并发控制"未实现。

> V4 做法：在 `core/transfer/schedule.rs` 用 `tokio::sync::Semaphore` 真正实现两级限流（全局块许可 + 每 peer 块许可 + 在途重试许可），并向 Tauri / JNI 暴露 acquire-release。

**问题 2：状态迁移没有约束。**

`setPeerState(ip, port, state)` 允许任意态跳任意态，没有迁移表。九态状态机配一个自由赋值的 setter，退化为字符串字段。`checkTimeouts()` 里 `complete → paused` 是合法但错误的迁移。

> V4 做法：改为显式迁移表，非法迁移返回 `Err` 而非静默赋值：
>
> ```rust
> const TRANSITIONS: &[(Phase, Phase)] = &[
>     (Phase::Idle,       Phase::Preparing),
>     (Phase::Preparing,  Phase::Diffing),
>     (Phase::Preparing,  Phase::Sending),   // 对端不支持 diff 时直发
>     (Phase::Diffing,    Phase::Sending),
>     (Phase::Sending,    Phase::Verifying),
>     (Phase::Sending,    Phase::Paused),    // 心跳超时
>     (Phase::Verifying,  Phase::Complete),
>     (Phase::Verifying,  Phase::Sending),   // 校验失败重传
>     (Phase::Paused,     Phase::Sending),   // 恢复
>     (Phase::Paused,     Phase::Aborted),
>     (Phase::*,          Phase::Aborted),   // 任意态可中止
>     (Phase::*,          Phase::Failed(..)),// 任意态可失败
> ];
> ```
>
> 关键点：`Complete` 不再是 `Paused` 的合法前驱。

**问题 3：`MerkleTree` 缺证明生成。**

只有构建与 root 计算，没有 `get_proof(piece_index)` / `verify_piece(piece, proof, root)`。没有证明生成就拿到 Merkle 的核心收益 —— 目前等价于"把 piece hash 再哈希一遍"，不如直接传 hash 列表。BEP-0052 的精髓是**单个 piece 可独立验证**，接收端无需持有完整 hash 列表。

> V4 做法：`core/transfer/merkle.rs` 补 `proof()` 与 `verify()`，并在契约里加一份 proof 测试向量，与 Rust 实现交叉校验。

**问题 4：心跳超时没有 driver。**

`checkTimeouts()` 需外部周期调用，目前无人调用。

> V4 做法：会话状态机持有 `tokio::time::interval`，会话创建即启动超时巡检，不再依赖外部驱动。

**问题 5：`buildSchedulerManifest` 需全量哈希。**

大文件 O(n) 全量计算 piece hash，增量场景代价高。

> V4 做法：piece hash 随写入增量计算并落盘缓存（key = 文件 inode + mtime + size），命中缓存则跳过哈希。

### 7.3 悬浮球情绪状态机

`desktop/public/emotion-ball/`（六个 JS 文件）+ `desktop/src-tauri/src/ball.rs` + `App.vue` 的 `BALL_FACE_FALLBACK` 是在用的，独立于传输状态机，V4 保留。

但当前耦合方式有问题：`App.vue` 直接把**业务状态**映射为**情绪 id**，业务与表现混在一起。

> V4 做法：core 只发业务事件，情绪映射留在前端。
>
> ```
> core  --(业务事件)-->  ball.rs  --(ball:emotion)-->  情绪引擎
>        TransferStarted      业务事件 → 情绪 id 的映射表放在前端
>        TransferProgress     可独立演进，core 不感知 UI 概念
>        TransferCompleted
>        TransferFailed
> ```
>
> 好处：情绪引擎可以加表情、改演出脚本，都不需要动 core；core 也可以被无 UI 的场景（CLI、测试）调用。

---

## 八、契约即代码

现状：`protocol/` 下 9 份手写 JSON Schema，10 个 conformance 测试。**手写 schema 与实现必然漂移**，且最大的自定义协议层（scheduler v1）完全没有被覆盖。

> V4 做法：
>
> 1. core 的所有 DTO 加 `#[derive(JsonSchema)]`（schemars）
> 2. `build.rs` 生成 schema 到 `protocol/schemas/`
> 3. CI 校验：重新生成并 diff，不一致即失败
> 4. golden file 必须来自真实 HTTP 响应抓包（现有约定保留）
> 5. `protocol/testvectors/` 补充 Merkle proof 向量，用于三端交叉校验

这样 schema 永远不可能与实现不一致 —— 因为它就是实现生成的。

---

## 九、localsend 的吸收

`D:/code/tools/docs/localsend-main/packages/core`：47 个文件 / 10688 行，基于 **hyper 1.x**（非 axum），reqwest 0.13。

只要它的**HTTP 管道**，不要它的**协议层**（V2 已整体移除，见 §一 修订）。

### 需要搬入 core 的

- `http/server/common/*` —— hyper 请求处理、JSON 收集、错误响应、文件落盘
- `util/` —— base64 / filename / interface / time
- `model/discovery.rs` —— DeviceType / ProtocolType
- `multicast/socket.rs` —— 组播 socket（供 presence 复用）

### 一刀砍掉的

- `http/server/v2.rs`、`http/client/v2.rs`、`http/dto_v2.rs` —— **V2 协议层，整体删除**
- `webrtc/` —— 未使用
- `http/server/v3.rs`、`http/client/v3.rs` —— 上游 v3，与本项目无关，且会造成命名混淆
- `download` / `show` / `prepare-download` —— 未使用
- mTLS / 证书相关（`rcgen` / `rustls` / `client_cert_verifier`）—— 纯 HTTP 场景不需要

### 依赖版本对齐

现靠 Cargo 多版本共存硬撑，吸收后统一：

| 依赖 | 项目 | localsend | V4 统一为 |
|---|---|---|---|
| rand | 0.8 | 0.10 | 0.10 |
| sha2 | 0.10 | 0.11 | 0.11 |
| base64 | 0.21 | 0.23 | 0.23 |
| if-addrs | 0.13 | 0.15 | 0.15 |

### 仓库自洽

- `git subtree` 把 localsend vendor 进 `third_party/`，`Cargo.toml` 改为指向仓库内
- `desktop/src-tauri/Cargo.lock` 从 `.gitignore` 放出（二进制 crate 必须提交 lockfile）

---

## 十、分阶段实施计划

| 阶段 | 任务 | 验收标准 |
|---|---|---|
| **0 奠基** | 0.1 `git subtree` vendor localsend，Cargo.toml 改指仓库内<br>0.2 `desktop/src-tauri/Cargo.lock` 加入 git<br>0.3 建 `core/` 空壳包并注册进 pnpm workspace | 全新目录 clone 后 `cargo build` 通过 |
| **0.5 风险验证** ⚠️ | 0.4 `cargo-ndk` + Gradle 接入，uniFFI 导出 toy 函数并在 Android 调通<br>0.5 验证 `ring` / `rustls` 在 Android 的交叉编译 | 手机上能收到 Rust 返回的字符串。**此步失败则整个方案需改道** |
| **1 契约先行** | 1.1 定 `/api/v4/` 完整路由表<br>1.2 core DTO 加 `#[derive(JsonSchema)]`，build.rs 生成 schema<br>1.3 CI 加"重新生成并 diff，不一致即失败" | `cargo test` 中 schema 与代码恒一致 |
| **2 吸收 HTTP 管道** | 2.1 搬 `http/server/common/*`、`util/`、`model/discovery.rs`、`multicast/socket.rs` 进 core<br>2.2 砍掉 V2 协议层 / webrtc / 上游 v3 / mTLS<br>2.3 统一依赖版本 | core 能启动一个空的 hyper 服务 |
| **2.5 实现 V4 传输** ★★★ | 2.4 实现 `/api/v4/session/*` 端点（V4 协议层，不再有 v2）<br>2.5 主算法：块差异 + Merkle + 续传 + 并发（**接通现有死代码**）<br>2.6 基础算法：16MB 分块 + 简单续传（内嵌兜底）<br>2.7 三张状态机 + `can()` 裁决函数 + 降级与恢复<br>2.8 desktop 的 `transfer/` 改为调 core | 桌面端收发功能不变；状态机与降级有单元测试；详见 `V4-TRANSFER-MODULE.md` |
| **3 状态机迁移** ★ | 3.1 `session.rs`：TransferPhase + 显式迁移表<br>3.2 `chunk.rs`：弱/强双校验 + ChunkDiff<br>3.3 `merkle.rs`：BEP-0052 + proof/verify（补完）<br>3.4 `schedule.rs`：Semaphore 并发控制（补完）<br>3.5 降级策略原样迁入，改为能力位图协商 | 单元测试覆盖全部合法/非法迁移；Merkle proof 向量通过 |
| **4 双端状态一致性** ★★ | 4.1 配对生命周期状态机（pending / active / revoking / revoked）+ `sync-status` 双向对账<br>4.2 在线性独立建模（TTL 0.5s），UI 用 `paired AND online` 门控，离线设备禁止发起新传输<br>4.3 **UDP presence beacon**（32B 定长，HMAC 截断 8B 认证）+ Android MulticastLock<br>4.4 会话新增 `reconciling` 阶段，从 `paused` 恢复前强制拉取权威块位图<br>4.5 任务终态由接收端权威判定，经 `session/receipt` 回传<br>4.6 握手幂等（`request_id` 去重）+ `handshake/status` 可查询<br>4.7 心跳自带 `tokio::time::interval` driver + 指数退避，失败先进 `paused` 对账而非判失败 | 双端断开重连后状态自动收敛；解配对双向生效；离线设备不可发起新传输；每个文件终态可查 |
| **4.5 加密分层** ★ | 4.8 握手层去加密，改 ECDSA 明文签名（probe / challenge / verify）<br>4.9 建立统一加密层：单一 AEAD 实例包裹握手后的全部流量<br>4.10 密钥树调整为 L1–L4（新增 `file_key`，nonce 用块序号）<br>4.11 `CAP_ENCRYPT` 协商 + 明文降级（保留 HMAC 完整性） | 握手失败可抓包直接定位；仓库内不存在两层加密嵌套 |
| **5 合并控制面** | 5.1 `pairing/` 的手写 TCP+HTTP 换成 hyper 路由并入 core<br>5.2 删除 53318<br>5.3 删 KDF v1 / CRYPTO v1 / device-id v1 兼容分支<br>5.4 单一版本常量 `PROTOCOL_VERSION = 4` | 全链路通，仓库里搜不到第二套 HTTP 实现 |
| **6 安卓绑定** | 6.1 uniFFI 导出 core 对外 API，生成 Kotlin 绑定<br>6.2 删 `LocalReceiverPlugin.java` 的 v2 服务端实现<br>6.3 补 v4 服务端能力（现在手机端完全没有，两端从此对称）<br>6.4 **补齐 `receiver.ts` 中 8 个 Java 从未实现的方法**（`v3Probe`/`v3PairClient`/`syncAllPeers`/`isPeerPaired`/`setDefensiveHidden`/`getDefensiveHidden`/`dumpNativeLogs`/事件 `java-log`+`pair-presence`）<br>6.5 **补 Android 前台服务 + 通知渠道 + `FOREGROUND_SERVICE`/`POST_NOTIFICATIONS`/`WAKE_LOCK` 权限 + manifest 存储权限**（当前全缺，后台长传与大目录读取都是坏的）<br>6.6 **删除 `AndroidSessionStore` / `SessionDatabase`**（零调用方孤儿，与 SAF 无关 —— 此前判断有误），仅保留其"热/温/冷 + 脏标记批量刷盘"的**设计模式**<br>6.7 SAF 相关能力保留在 Android 平台层（`takePersistableUriPermission` / DocumentFile 遍历 / 复制+删除代替 rename） | 手机端收发 + 双向配对可用；后台长传不被系统回收 |
| **7 瘦身清理** | 7.1 删 `shared-core` 的 crypto / scheduler / session-store / discovery / pairing 五份 TS<br>7.2 清 `mobile/src` 的 .ts/.js 双份文件<br>7.3 清 OTel 半截工程与 `probe!` 空宏<br>7.4 拆 `App.vue`（3280 行） | shared-core 里搜不到任何协议实现 |
| **8 CI 重建** | 8.1 `cargo test` + `clippy -D warnings` + `fmt --check`<br>8.2 `pnpm -r test`<br>8.3 Android 构建，去掉 `\|\| true`，补 Kotlin 单测<br>8.4 **双端状态一致性集成测试**（模拟断网 / 单方解配对 / 心跳超时） | CI 全绿，且**真的会变红**；一致性场景有回归保护 |

---

## 十一、风险

| 风险 | 影响 | 缓解 |
|---|---|---|
| **Android NDK + uniFFI 走不通** | 阶段 6 无法落地，方案退回"双实现" | 阶段 0.5 先做 spike，失败即改道（可退回 Capacitor 插件调 Rust 静态库的手写 JNI） |
| `ring` / `rustls` 交叉编译到 Android | 构建失败 | 同上，spike 中验证 |
| 状态机迁移期行为变化 | 断点续传出 bug | 迁移前先给现有 TransferPhase 补迁移表测试，锁定当前行为再重构 |
| **对账引入额外流量** | 移动端耗电、局域网广播增多 | 对账周期可配置；在线设备走事件驱动，离线设备才走定时轮询 |
| **0.5s TTL 的射频唤醒成本** | Android 端耗电显著（每秒 2 次唤醒） | 用 UDP beacon 而非 HTTP 轮询；周期做成配置项、默认 0.5s；**必须实测电池影响**再定最终值 |
| **握手改明文降低安全性** | 握手报文可被同网段窃听 | 握手报文不含密钥与连接码（连接码只做 HKDF salt，绝不上线）；明文降级默认关闭，需用户显式开启 |
| **`reconciling` 阶段拉长恢复耗时** | 大文件恢复变慢 | 位图用 roaring bitmap 压缩传输；小文件（<16MB）跳过 diff 直发 |
| 吸收 localsend 后依赖冲突 | 编译失败、二进制膨胀 | 阶段 2 逐步替换，每步 `cargo check` |
| 工作量集中在阶段 2-6 | 周期长 | 阶段 0 与 0.5 是任何路线都需要的地基，可先交付 |

---

## 十二、待确认项

### 已确认（2026-08-29）

| # | 问题 | 结论 | 落地位置 |
|---|---|---|---|
| 1 | 握手/连接码不稳定的症状 | 各种特殊情况都出现过 → **做充分的防御性设计**；必要时可舍弃加密，加密不放在握手层，改用统一的加密层 | §四 |
| 2 | 配对对账周期与耗电的取舍 | **事件驱动 + 定时兜底** | §3.3-A |
| 3 | 在线性 TTL 取值 | **0.5 秒**，前后台一致；若性能不足则研究轻量算法兼顾认证与性能 | §3.3-B（已给出 UDP beacon + HMAC 截断方案） |
| 4 | V2 兜底怎么处理 | **两者都删**，统一为 V4；兜底改为同协议栈内的**算法降级**（主算法 → 16MB 基础算法） | §一 / §3.4 / `V4-TRANSFER-MODULE.md` |
| 5 | 基础算法形态 | **16MB 分块 + 简单续传**（记录已确认块序号） | `V4-TRANSFER-MODULE.md` §1.2 |

### 仍待确认

| # | 问题 | 影响的设计点 |
|---|---|---|
| 6 | **过去 V2 兜底是被哪些网络环境触发的？**（跨 VLAN？AP 隔离？IPv6？组播被屏蔽？） | 这些环境现在要靠算法降级覆盖，需要知道失败模式才好设阈值 |
| 7 | **任务终态由接收端判定，发送端 UI 如何展示"对端说完成了但本机没收到回执"的中间态？** | §3.3-D 的 UI 状态设计 |
| 8 | **明文降级是否接受？** 握手改明文已定，但传输层明文降级要用户显式开启才生效 —— 这个开关是否要暴露在 UI 上，还是只作为内部故障转移？ | §4.2 规则三 |
| 9 | **UDP beacon 用组播还是单播？** 组播一条报文全网段可见（省流量），但部分路由器/AP 会屏蔽组播；单播要逐个已配对设备发（可靠但 N 倍流量） | §3.3-B 的 beacon 投递方式 |
| 10 | **降级阈值是否需要可配置？** 本文给的是固定值（单块重试 3 次、心跳 15s 等），是否要在设置里暴露给高级用户 | `V4-TRANSFER-MODULE.md` §2.4 |
| 5 | **任务终态由接收端判定，发送端 UI 如何展示"对端说完成了但本机没收到回执"的中间态？** | §3.3-D 的 UI 状态设计 |
| 6 | **明文降级是否接受？** 握手改明文已定，但传输层明文降级要用户显式开启才生效 —— 这个开关是否要暴露在 UI 上，还是只作为内部故障转移？ | §4.2 规则三 |
| 7 | **UDP beacon 用组播还是单播？** 组播一条报文全网段可见（省流量），但部分路由器/AP 会屏蔽组播；单播要逐个已配对设备发（可靠但 N 倍流量） | §3.3-B 的 beacon 投递方式 |

---

## 十三、不在 V4 范围内

- 悬浮球情绪引擎的表情与演出脚本（独立演进，只调整它与 core 的接口）
- `shared-ui` 液态玻璃组件库
- 桌面端 UI 交互 redesign（阶段 7.4 只做文件拆分，不改设计）
