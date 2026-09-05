# lanbackup V4 控制面协议契约

> 本目录是双端（Rust core / 手机端）唯一的协议事实源（Source of Truth）。
> 任何端点变更必须同步修改 `schemas/v4/*.schema.json` 与
> `schemas/v4/golden-manifest.json`（由 `core/src/bin/gen_schema.rs --golden` 生成，
> `schemaHash` 为真实 SHA-256），并由双端 conformance 测试断言。
>
> 协议版本：**4**（单一版本号，对齐 `core/src/version.rs::PROTOCOL_VERSION`）。
> 三代并存的教训是「命名空间与版本号各自演进」（`/api/localsend/v2/*`、
> `/api/backup/v1/*`、`/api/v3/*` + 三个独立 KDF/CRYPTO/device-id 版本号）；
> V4 收敛为**一个版本号（4）+ 一张能力位图（`Capabilities`）**。

## 传输层约定

- 控制面与数据面统一端口：**53317**（`core/src/version.rs::DEFAULT_PORT`），
  单一 hyper 路由表（`routes::ALL`）承载全部端点。
- Content-Type: `application/json`
- 无 TLS（局域网、威胁模型 = 防同网段普通用户，不防抓包者）
- 加密：P-256 ECDH + HKDF-SHA256 + AES-256-GCM（数据面，见 §密钥派生）

## 全局请求头（双端所有 v4 请求必须携带）

| Header | 值 | 说明 |
|--------|----|------|
| `X-Protocol-Version` | `4` | 版本协商（软降级用，非硬拒绝） |
| `X-Device-Id` | uuid | 发起方设备唯一标识 |
| `X-Request-Id` | uuid | 全链路追踪 ID，贯穿日志与错误响应 |

> 设计决策（承袭 V3，V4 不变）：
> - **放弃 `X-Timestamp ±容差` 校验**（避免双端时钟差导致握手失败的历史问题）。
>   时间戳仅用于日志/告警，不得用于拒绝请求。
> - **放弃 nonce 追踪**。防重放靠构造（幂等性）：每次握手 server_nonce/client_nonce
>   都是新的，派生的 pairing_secret 每次不同；重放旧 verify 派生出旧密钥 →
>   与当前会话不匹配 → 自然失败。
> - **verify 响应绝不返回任何密钥**。

## 端点清单（事实源 = `schemas/v4/golden-manifest.json`）

| 端点 | 认证 | 说明 |
|------|------|------|
| `GET /api/v4/probe` | 无 | 发现阶段设备信息 + 静态公钥 + 能力位图 + serverNonce |
| `POST /api/v4/handshake/challenge` | 无 | 重连（路径B）：签发 challenge_token + 临时公钥 |
| `POST /api/v4/handshake/verify` | — | 首次配对（路径A）/ 重连（路径B）：验 HMAC 后 approved |
| `GET /api/v4/handshake/status` | — | 握手状态查询（含失败结论） |
| `POST /api/v4/pair/unpair` | — | 解除配对 |
| `POST /api/v4/pair/revoke` | — | 吊销令牌同步 |
| `POST /api/v4/session/register` | — | 传输会话注册 |
| `POST /api/v4/session/prepare` | — | 上传准备（文件清单） |
| `POST /api/v4/session/chunk-diff` | — | 块级差异同步 |
| `GET /api/v4/session/{id}/phase` | — | 会话阶段/位图查询 |
| `POST /api/v4/session/heartbeat` | — | 心跳（续期 last_activity） |
| `POST /api/v4/session/abort` | — | 中止会话 |
| `GET /api/v4/sync/status` | — | 双端状态对账（纯读，绝不在其中改状态） |
| `POST /api/v4/sync/dir` | — | 目录同步计划 |
| `POST /api/v4/sync/move-to-delete` | — | 假删除（`delete/` 墓碑） |
| `POST /api/v4/sync/disconnect` | — | 断开（不动配对状态） |

**端点矛盾勘正（登记簿 E4）**：V3 契约曾同时存在「README 声称 3.0 / 无
pair/initiate 端点」与「golden manifest 列出 `GET /api/v3/pair/initiate`、
`GET /api/v3/pair/status`」的自相矛盾 —— 那是 V3 契约与 V3 golden 未同步的产物。
V4 以 `schemas/v4/golden-manifest.json` 的上述 16 个端点为**唯一事实源**：
**没有 pair/initiate、没有 pair/status 轮询端点**（异步轮询设计已取消），
配对生命周期由 `pair/unpair` + `pair/revoke` 承担。

## 两条握手路径

### 路径 A：首次配对（新设备，未在 paired_peers）

```
Client                                    Server
  │─── GET /api/v4/probe ────────────────>│  （无认证）
  │<── { deviceId, alias, staticPub, caps, serverNonce }
  │  生成 client 临时 P-256 密钥对
  │  shared = P-256(client_eph_priv, server_static_pub)
  │  pairing_secret = HKDF(shared, salt=H(code),
  │      info="lanbackup/v4/pairing/v1"||client_eph_pub||server_static_pub||serverNonce||clientNonce)
  │─── POST /api/v4/handshake/verify ────>│  { deviceId, clientEphPub, clientNonce,
  │                                        │    hmac = HMAC(pairing_secret, serverNonce||clientNonce) }
  │                                        │  服务端算同一 pairing_secret（用其自身连接码 + 收到的公钥/nonce）
  │                                        │  验 hmac 通过 → 状态机 Initiate→Pending→PeerConfirmed（同事务）
  │<── { status:"approved", deviceId, capabilities }
```

- **连接码验证是隐式的**：pairing_secret 的 salt=H(code)，双方用同一 code
  （主动方输入、被动方本地持有）才能算出同一 pairing_secret；客户端码错 →
  hmac 不匹配 → 拒绝。连接码**绝不上线**。
- **连接码规范化（登记簿 E8）**：双端必须先经
  `core::identity::normalize_connection_code` 的**严格版**规则（只保留
  `[A-Z0-9]` 并统一大写）规范化，再从规范化结果派生密钥 —— 任何一端漏掉
  这一步都会得到不同字节，HMAC 永远对不上。旧 TS 双实现（`identity.ts`
  只去 `[\s\-_]` vs `pairing.ts` 去所有 `[^A-Z0-9]`）的歧义在 V4 已消除。

### 路径 B：重连（已知设备，已在 paired_peers）

```
Client                                    Server
  │─── POST /api/v4/handshake/challenge ─>│  { deviceId }
  │<── { challengeToken(JWT), serverEphPub }
  │  shared = P-256(client_eph_priv, server_eph_pub)
  │  session_shared 同；pairing_secret 从本地持久化读取（长期存储）
  │─── POST /api/v4/handshake/verify ────>│  { challengeToken, clientEphPub, clientNonce,
  │                                        │    hmac = HMAC(pairing_secret, serverNonce||clientNonce) }
  │                                        │  用存储的 pairing_secret 验签 + 验 hmac
  │<── { status:"approved", deviceId, capabilities }
```

- 重连**不是**状态迁移：已 Active 的记录不得被再发一次 `PeerConfirmed`
  （状态机 `Active + PeerConfirmed` 是非法组合）。
- 断开（`sync/disconnect`）**不得**动配对状态 —— 否则切个 Wi-Fi 就要重新输连接码。

## JWT challenge_token 规格（路径B）

```
header.payload.signature
  header  = base64url({"alg":"HS256","typ":"JWT"})
  payload = base64url({
    "jti": "uuid-v4",           // JWT ID，日志关联/调试
    "deviceId": "<server>",
    "serverNonce": "<64 hex>",  // 32B 随机，参与 HMAC 与密钥派生
    "staticPub": "<server 静态公钥 SEC1>",
    "iat": <unix_sec>,
    "exp": <iat + 300>          // 仅卫生约束（日志/时钟漂移发现），绝不用于拒绝
  })
  signature = base64url(HMAC-SHA256(header.payload, pairing_secret))
```

## HMAC 构造（防重放靠构造）

```text
hmac = HMAC-SHA256(pairing_secret, serverNonce || clientNonce)
```

- 每次握手 server_nonce/client_nonce 都是新的 → 每次派生的 secret 不同 → 重放自然失败。
- 前提：verify 响应体**绝不包含任何密钥**，只返回 `{ status, deviceId, capabilities }`。

## 密钥派生（三层结构）

```text
L1 本地存储密钥  storage_key  = PBKDF2-HMAC-SHA256(连接码, salt=SHA256(device_id), 600k, 32B)
                                —— 连接码 40bit 低熵 → 慢 KDF（加密 pairing_secret / 本地文件）
L2 配对密钥      pairing_secret = HKDF-SHA256(ECDH_shared, salt=H(连接码),
                                info="lanbackup/v4/pairing/v1"||client_eph_pub||server_static_pub||双nonce)
                                —— 熵源 = ECDH 256bit；连接码仅绑定；长期存储
L3 会话传输密钥  transfer_key   = HKDF-SHA256(session_shared, salt=pairing_secret,
                                info="lanbackup/v4/transfer/"||file_id)
                                —— 每文件独立密钥（计数器 nonce 前提）
```

- P-256 点编码：SEC1 未压缩（0x04 || X || Y，65B），双端一致。
- 双端 conformance 测试向量见 `testvectors/`（RFC 5869 TC1 / PBKDF2 / P-256 交叉协商）。

## 统一错误格式

```json
{ "error": { "code": "RATE_LIMIT_EXCEEDED", "message": "...", "requestId": "..." } }
```

错误码：`INVALID_REQUEST` `INVALID_CODE` `HMAC_MISMATCH` `UNTRUSTED` `RATE_LIMIT_EXCEEDED`
`NOT_FOUND` `VERSION_UNSUPPORTED` `UNKNOWN_DEVICE` `TOKEN_EXPIRED` `ILLEGAL_STATE`

## 目录结构

```
protocol/
├── README.md                       ← 本文档（V4）
├── schemas/
│   └── v4/                         ← V4 唯一契约（45 份 schema + golden-manifest.json）
├── testvectors/
│   ├── hkdf_v3.json                ← RFC 5869 TC1（V4 沿用，HKDF 算法未变）
│   ├── pbkdf2_v3.json              ← PBKDF2-600k 基准（V4 沿用）
│   └── p256_ecdh_cross_check.json  ← P-256 交叉协商（V4 沿用）
```

## 遗留清理（登记簿 E4，2026-09-06 A4 已执行）

- `golden/` 目录（v2/v3 时代 golden 文件：manifest.json、prepare-upload/probe
  抓包等，曾被 V3 README 引用）—— **已删除**。
- `schemas/` 根下的 v2/v3/v5 旧 schema（common / probe.response /
  handshake.challenge / handshake.verify / manifest / prepare-upload.request /
  prepare-upload.response / chunk-status.response / v5-unpair）—— **已删除**。
- V4 契约仅存在于 `schemas/v4/`。`testvectors/` 虽带 v3 后缀，但 V4 沿用同一
  HKDF/PBKDF2/P-256 算法，保留。

## 校验方式（不引入额外运行时）

- Rust：`jsonschema` crate（dev-dependency，锁版本），`cargo test` 中校验
- Golden File：`core/src/bin/gen_schema.rs --golden` 生成，`schemaHash` 为
  真实 SHA-256（不再是 V3 时代的 `PENDING_FIRST_CAPTURE` 占位）
