# LocalSend v3 控制面协议契约（最终版，对齐方案.txt）

> 本目录是双端（Rust 桌面 / Java 手机）唯一的协议事实源（Source of Truth）。
> 任何端点变更必须同步修改此处 Schema 与 Golden File，并由双端 conformance 测试断言。
> 协议版本：**3.0**（硬升级，不再兼容 v2 配对/问候/探测端点）。

## 传输层约定

- 控制面：HTTP/1.1 over TCP，端口 **53318**（接收端口 + 1）
- 数据面：端口 **53317**，由 localsend crate 提供 v2 传输服务，**保持原样不迁移**（本契约不覆盖）
- Content-Type: `application/json`
- 无 TLS（局域网、威胁模型 = 防同网段普通用户，不防抓包者）
- 加密：P-256 ECDH + HKDF-SHA256 + AES-256-GCM（数据面，见 §密钥派生）

## 全局请求头（双端所有 v3 请求必须携带）

| Header | 值 | 说明 |
|--------|----|------|
| `X-Protocol-Version` | `3.0` | 版本协商（软降级用，非硬拒绝） |
| `X-Device-Id` | uuid | 发起方设备唯一标识 |
| `X-Request-Id` | uuid | 全链路追踪 ID，贯穿日志与错误响应 |

> 设计决策：
> - **放弃 `X-Timestamp ±容差` 校验**（避免双端时钟差导致握手失败的历史问题）。时间戳仅用于日志/告警，不得用于拒绝请求。
> - **放弃 nonce 追踪**。防重放靠构造（幂等性）：每次握手 server_nonce/client_nonce 都是新的，
>   派生的 pairing_secret 每次不同；重放旧 verify 派生出旧密钥 → 与当前会话不匹配 → 自然失败。
> - **verify 响应绝不返回任何密钥**（前提条件，方案.txt §3.4）。

## 端点清单

| 端点 | 认证 | 说明 |
|------|------|------|
| `GET /api/v3/probe` | 无 | 发现阶段设备信息 + 静态公钥 + serverNonce（替代 v2 `/info`） |
| `POST /api/v3/handshake/challenge` | 无 | 重连（路径B）：签发 challenge_token(JWT) + 临时公钥 |
| `POST /api/v3/handshake/verify` | — | 首次配对（路径A）/ 重连（路径B）：验 HMAC 后 approved |

**无独立 pair/initiate + pair/status 轮询端点**（方案.txt §三 取消异步轮询设计）。

## 两条握手路径（方案.txt §三）

### 路径 A：首次配对（新设备，未在 paired_peers）

```
Client                                    Server
  │─── GET /api/v3/probe ─────────────────>│  （无认证）
  │<── { deviceId, alias, staticPub, serverNonce, caps }
  │  生成 client 临时 P-256 密钥对
  │  shared = P-256(client_eph_priv, server_static_pub)
  │  pairing_secret = HKDF(shared, salt=H(code),
  │      info="localsend-v3/pairing/"||client_eph_pub||server_static_pub||serverNonce||clientNonce)
  │─── POST /api/v3/handshake/verify ─────>│  { deviceId, clientEphPub, clientNonce,
  │                                        │    hmac = HMAC(pairing_secret, serverNonce||clientNonce) }
  │                                        │  服务端算同一 pairing_secret（用其自身连接码 + 收到的公钥/nonce）
  │                                        │  验 hmac 通过 → 弹窗确认（被动方同意）→ 写入 paired_peers（同事务）
  │<── { status:"approved", deviceId, capabilities }
```

- **连接码验证是隐式的**：pairing_secret 的 salt=H(code)，双方用同一 code（主动方输入、被动方本地持有）
  才能算出同一 pairing_secret；客户端码错 → hmac 不匹配 → 拒绝。连接码**绝不上线**。

### 路径 B：重连（已知设备，已在 paired_peers）

```
Client                                    Server
  │─── POST /api/v3/handshake/challenge ──>│  { deviceId }
  │<── { challengeToken(JWT), serverEphPub }
  │   shared = P-256(client_eph_priv, server_eph_pub)
  │  session_shared 同；pairing_secret 从本地 SQLite 读取（长期存储）
  │─── POST /api/v3/handshake/verify ─────>│  { challengeToken, clientEphPub, clientNonce,
  │                                        │    hmac = HMAC(pairing_secret, serverNonce||clientNonce) }
  │                                        │  用存储的 pairing_secret 验签 + 验 hmac
  │<── { status:"approved", deviceId, capabilities }
```

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
    "exp": <iat + 300>          // 仅卫生约束（日志/时钟漂移发现），绝不用于拒绝（方案.txt §3.3）
  })
  signature = base64url(HMAC-SHA256(header.payload, pairing_secret))
```

## HMAC 构造（防重放靠构造，方案.txt §3.4）

```text
hmac = HMAC-SHA256(pairing_secret, serverNonce || clientNonce)
```

- 每次握手 server_nonce/client_nonce 都是新的 → 每次派生的 secret 不同 → 重放自然失败。
- 前提：verify 响应体**绝不包含任何密钥**，只返回 `{ status:"approved", deviceId, capabilities }`。

## 密钥派生（三层结构，方案.txt §2.1）

```text
L1 本地存储密钥  storage_key  = PBKDF2-HMAC-SHA256(连接码, salt=SHA256(device_id), 600k, 32B)
                                —— 连接码 40bit 低熵 → 慢 KDF（加密 pairing_secret 列 / 本地文件）
L2 配对密钥      pairing_secret = HKDF-SHA256(ECDH_shared, salt=H(连接码),
                                info="localsend-v3/pairing/"||client_eph_pub||server_static_pub||双nonce)
                                —— 熵源 = ECDH 256bit；连接码仅绑定；长期存储
L3 会话传输密钥  transfer_key   = HKDF-SHA256(session_shared, salt=pairing_secret,
                                info="localsend-v3/transfer/"||file_id)
                                —— 每文件独立密钥（计数器 nonce 前提）
```

- P-256 点编码：SEC1 未压缩（0x04 || X || Y，65B），Rust `p256` crate 与 Java `Key.getEncoded()` 一致。
- 双端 conformance 测试向量见 `testvectors/`（RFC 5869 TC1 / PBKDF2 / P-256 交叉协商）。

## 统一错误格式

```json
{ "error": { "code": "RATE_LIMIT_EXCEEDED", "message": "...", "requestId": "..." } }
```

错误码：`INVALID_REQUEST` `INVALID_CODE` `HMAC_MISMATCH` `UNTRUSTED` `RATE_LIMIT_EXCEEDED`
`NOT_FOUND` `VERSION_UNSUPPORTED` `UNKNOWN_DEVICE` `TOKEN_EXPIRED`

## 目录结构

```
protocol/
├── README.md                       ← 本文档
├── schemas/
│   ├── common.schema.json
│   ├── probe.response.schema.json
│   ├── handshake.challenge.schema.json
│   └── handshake.verify.schema.json
├── golden/                         ← 真实 HTTP 响应抓取（逐字节比对，防漂移）
│   ├── manifest.json               ← { schemaHash } 契约指纹
│   └── probe.response.golden.json
└── testvectors/
    ├── hkdf_v3.json                ← RFC 5869 TC1
    ├── pbkdf2_v3.json              ← PBKDF2-600k 基准（Rust 已产出）
    └── p256_ecdh_cross_check.json  ← P-256 交叉协商（P2 回填）
```

## 校验方式（不引入额外运行时）

- Rust：`jsonschema` crate（dev-dependency，锁版本），`cargo test` 中校验
- Java：`com.networknt:json-schema-validator`（testImplementation，锁版本），JUnit 中校验
- Golden File 必须来自**真实 HTTP 响应**（抓包），而非 Mock 序列化
