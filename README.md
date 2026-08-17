# 局域网备份工具

> 基于 LocalSend v2.2 协议二次开发的开源备份工具。  
> 只做一件事：**手机和电脑之间通过局域网互传文件做归档备份**。  
> 无账号、无云、无公网服务器。

---

## 快速上手

### 环境需求

| 工具 | 版本 | 用途 | 验证 |
|------|------|------|------|
| Node.js | ≥ 18 | 前端构建 | `node --version` |
| npm | ≥ 9 | 包管理 | `npm --version` |
| Rust | ≥ 1.70 | 桌面端编译 | `rustc --version` |
| MSVC Build Tools | 2022 + C++ 工具集 | Rust 链接器 | 见下方 |
| JDK | 21（**不要用 26**） | APK 构建 | `java -version` |
| Android SDK | 35 + build-tools 35.0.0 | APK 编译 | `$ANDROID_HOME/platforms/android-35` |

**JDK 21 获取方式**：本机路径 `C:\Users\VOS_User\AppData\Roaming\.minecraft\runtime\java-runtime-delta`（Minecraft 自带的 JDK 21）。构建时需设置 `JAVA_HOME` 指向该路径。

### 构建命令

```bash
# 1. 安装依赖（首次）
cd shared-core && npm install
cd ../mobile && npm install
cd ../desktop && npm install

# 2. shared-core 测试
cd shared-core
npm run build && npm run test    # 17 个单元测试

# 3. 手机端 APK
cd mobile
npm run build                    # Vite 构建前端
npx cap sync                     # 同步到 Android
cd android
JAVA_HOME="C:\Users\VOS_User\AppData\Roaming\.minecraft\runtime\java-runtime-delta" \
  ./gradlew assembleDebug --no-daemon
# 输出：mobile/android/app/build/outputs/apk/debug/app-debug.apk

# 4. 桌面端 EXE
cd desktop
npm run build                    # Vite 构建前端
cd src-tauri
cargo build --release            # 生成可执行文件
# 或打包：cargo tauri build
```

---

## 项目结构

```
6a7f5d5699c44b33268ede69/
├── shared-core/          ← 共享核心库（纯 TypeScript，手机/电脑共用）
│   ├── src/
│   │   ├── index.ts       统一导出
│   │   ├── identity.ts    连接码生成（FNV-1a + xorshift32，8 位字母数字）
│   │   ├── manifest.ts    文件清单全量构建与差异对比（只增不删）
│   │   ├── anchor.ts      锚点管理（按目录/文件 mtime 快速扫描）
│   │   ├── conflict.ts    冲突检测 + 重命名（`原名_MMDDhhmmss.扩展名`）
│   │   ├── scan.ts        扫描引擎（快速 = 锚点区间 / 深度 = 全量 Diff）
│   │   ├── state.ts       状态数据结构（BackupState/DeviceState + 版本迁移）
│   │   ├── transfer.ts    LocalSend v2.2 HTTP 传输客户端（TS 重写）
│   │   ├── discovery.ts   设备发现状态机（接口层，UDP 待平台实现）
│   │   ├── autopolicy.ts  自动备份策略决策（semi/auto/manual）
│   │   └── test/
│   │       └── selfcheck.ts  17 个单元测试（全部通过）
│   ├── package.json
│   └── tsconfig.json
│
├── mobile/              ← 手机端（Vue3 + Capacitor + Android）
│   ├── src/
│   │   ├── App.vue         主界面（备份目录/目标设备/三方向/进度/接收服务）
│   │   ├── main.ts         入口
│   │   ├── style.css       暗色主题
│   │   └── services/
│   │       ├── filesystem.ts  Android SAF 文件读写 + 目录遍历
│   │       ├── device.ts      设备身份 + 状态 JSON 管理
│   │       ├── backup.ts      备份编排（扫描 → 传输 → 状态更新）
│   │       └── receiver.ts    Capacitor 接收服务封装
│   ├── local-receiver/     ← 接收服务原生插件（Capacitor 插件包）
│   │   ├── package.json
│   │   └── android/
│   │       └── src/main/java/com/backup/mobile/
│   │           └── LocalReceiverPlugin.java  ServerSocket HTTP 接收端
│   ├── android/           Android 原生工程
│   └── capacitor.config.json
│
├── desktop/             ← 电脑端（Vue3 + Tauri + Rust）
│   ├── src/
│   │   ├── App.vue         主界面（集成 shared-core 扫描/锚点/清单 + 设备发现 UI）
│   │   └── main.ts / style.css
│   └── src-tauri/
│       ├── Cargo.toml      依赖：tauri 2 + localsend + rusqlite + tokio
│       ├── tauri.conf.json  CSP 允许 http://* 连接
│       ├── icons/           icon.ico + icon.png（桌面图标）
│       └── src/
│           ├── main.rs      入口
│           ├── lib.rs       应用入口 + 11 条 Tauri 命令注册
│           ├── identity.rs  MachineGuid → 连接码 + 数据库加密密钥
│           ├── db.rs        SQLite 存储（每配对设备一份状态）
│           ├── transfer.rs  ← 传输核心（基于 LocalSend core）
│           │   ├── start_receiver   启动 HTTP 接收服务器
│           │   ├── stop_receiver    停止接收服务器
│           │   ├── send_files       流式发送文件
│           │   ├── scan_directory   递归扫描目录
│           │   └── 冲突重命名（原名_MMDDhhmmss.扩展名）
│           └── discovery.rs  ← 设备发现（multicast UDP 广播）
│               ├── start_discovery   启动发现
│               ├── stop_discovery    停止发现
│               └── get_discovered_devices  获取设备列表
│
└── docs/
    ├── ARCHITECTURE.md  架构设计文档
    └── HANDOVER.md      开发交接文档
```

---

## 核心技术栈

| 端 | 界面 | 传输核心 | 身份 | 存储 |
|---|---|---|---|---|
| **手机端** | Vue3 + Capacitor | TypeScript 重写（协议兼容 LocalSend v2.2） | UUID → FNV-1a 哈希 → 8 位连接码 | JSON（每配对设备一份） |
| **电脑端** | Vue3 + Tauri | 复用 LocalSend 的 Rust crate（`packages/core`） | MachineGuid → 连接码 | SQLite（bundled） |

### 传输协议（LocalSend v2.2）

| 端点 | 用途 |
|------|------|
| `POST /api/localsend/v2/register` | 设备注册 / 发现 |
| `GET /api/localsend/v2/info` | 设备信息 |
| `POST /api/localsend/v2/prepare-upload` | 协商要上传的文件（返回 sessionId + token） |
| `POST /api/localsend/v2/upload?sessionId&fileId&token` | 上传文件内容（流式） |
| `POST /api/localsend/v2/cancel` | 取消传输 |

**关键**：两端使用纯 HTTP（无 mTLS）。桌面端接收时 `tls_config: None`，手机端 WebView 无法加载客户端证书。

---

## 三种备份方向

| 方向 | 发送端 | 接收端 | 状态 |
|------|--------|--------|------|
| **手机 → 电脑** | 手机端 `sendBackup()`（TS） | 桌面端 `start_receiver`（Rust） | ✅ 可用 |
| **电脑 → 手机** | 桌面端 `send_files`（Rust） | 手机端 `LocalReceiverPlugin`（Java） | ✅ 代码完成，需真机测试 |
| **双向同步** | 两边各推新增 | 两边各接收 | ✅ 按顺序执行 |

---

## 核心设计原则

### 1. 手机和电脑是"完全相同的设备"
两端共享同一套核心逻辑（shared-core 纯 TypeScript），只是外壳不同（Capacitor vs Tauri）。

### 2. 只增不删
备份策略永不删除目标端的文件，任一端删原文件不影响另一端。

### 3. 冲突永不覆盖
接收端目标存在同名文件且内容不同 → 自动重命名为 `原名_MMDDhhmmss.扩展名`，仍冲突则追加序号。

### 4. 扫描只在发送端做
发送端决定要传哪些文件（快速=锚点区间 / 深度=全量 Diff），接收端只负责收。

### 5. 设备身份：8 位连接码
- 字符集：`ABCDEFGHJKMNPQRSTUVWXYZ23456789`（去掉易混淆字符）
- 电脑端：基于 Windows MachineGuid（注册表）→ FNV-1a 哈希
- 手机端：基于 UUID → 相同算法
- 同一特征码始终生成同一连接码

---

## 桌面端 Tauri 命令速查（12 条）

| 命令 | 用途 | 关键参数 |
|------|------|---------|
| `get_self_code` | 本机连接码 | 无 |
| `get_device_state` | 查询配对设备状态 | `connectionCode` |
| `save_device_state` | 保存配对设备状态 | `connectionCode`, `deviceName`, `state` |
| `get_all_devices` | 所有已配对设备列表 | 无 |
| `start_receiver` | 启动接收服务器 | `receiveDir`, `port` |
| `stop_receiver` | 停止接收服务器 | 无 |
| `send_files` | 发送文件 | `targetIp`, `targetPort`, `files[]` |
| `scan_directory` | 递归扫描目录 | `dir` |
| `start_discovery` | 启动设备发现（multicast） | `serverPort` |
| `stop_discovery` | 停止设备发现 | 无 |
| `get_discovered_devices` | 获取发现的设备列表 | 无 |
| `export_logs` | 导出全链路日志 | `extraLines`（前端 TS 日志，可选） |

---

## 全链路 Debug 日志

两端所有关键链路（身份、扫描、清单、锚点、冲突、传输、发现、策略、数据库、命令出入口）都埋了日志，支持一键导出为文件，方便排查问题。

### 日志格式

```
[2026-08-15 14:23:45.123] [INFO] [transfer] register ← 200 (http://192.168.1.5:53317)
```

统一为 `[时间戳] [级别] [模块] 消息`，ERROR 会附带 Error Stack。

- **级别**：`DEBUG` / `INFO` / `WARN` / `ERROR`
- **模块**：`identity` / `manifest` / `anchor` / `conflict` / `scan` / `transfer` / `discovery` / `autopolicy`（shared-core）、`filesystem` / `device` / `backup` / `receiver` / `ui` / `global`（手机端）、`transfer` / `discovery` / `db` / `identity` / `cmd` / `logger` / `panic`（桌面端 Rust）
- **敏感脱敏**：连接码、指纹、会话 token 只保留前 2 + 后 2 字符（如 `AB****34`），日志文件可放心随工单分享；文件只记文件名/大小，绝不记录内容

### 存储与导出

- **内存环形缓冲**：两端各保留最近 1000 条，防止内存溢出（`shared-core/src/logger.ts`、`desktop/src-tauri/src/logger.rs`）
- **手机端导出**：App 底部「调试 → 导出日志」按钮。依次尝试：`文档/BackupLogs/debug_时间戳.log` → 已选择的 SAF 备份目录 `BackupLogs/` → 应用沙盒（需 adb），成功路径会弹窗提示
- **桌面端导出**：App 底部「调试 → 导出日志」按钮。Rust 缓冲 + 前端 shared-core 缓冲合并写入 `文档/BackupLogs/debug_时间戳.log`，命令 `export_logs`
- **日志文件名**：`debug_YYYYMMDD_HHmmss.log`
- **原生层**：`LocalReceiverPlugin.java` 用 logcat 输出，`adb logcat -s LocalReceiver` 可过滤查看
- **全局捕获**：前端 `window.onerror` / `unhandledrejection` → `global` 模块；Rust `std::panic::set_hook` → `panic` 模块

### 代码位置

- 日志核心（两端共用）：`shared-core/src/logger.ts`
- 桌面端日志：`desktop/src-tauri/src/logger.rs`（宏 `log_info!`/`log_debug!`/`log_warn!`/`log_error!`）
- 命令出入口：`desktop/src-tauri/src/lib.rs` → `mod commands` 包装层（12 条命令全部记录入口/出口与脱敏参数）

---

## 已知局限

| 问题 | 状态 | 说明 |
|------|------|------|
| 手机端接收需真机测试 | ⏳ 代码完成 | `LocalReceiverPlugin.java` 通过了 APK 编译，但未在真机运行 |
| 数据库加密（SQLCipher） | ⏳ 暂缓 | 默认用 `bundled`（无加密）。要启用：改 `features = ["bundled", "sqlcipher"]`，并设 `OPENSSL_DIR` 环境变量 |
| 手机端设备发现 | ⏳ 待实现 | 桌面端已经有 multicast 发现，手机端需原生 UDP 插件 |
| 手机端目录选择 | ⚠️ 已知问题 | `@capacitor/filesystem` 6.x 未提供目录选择器（`pickDirectory` 不存在），`pickBackupRoot()` 目前返回 null；需接入 SAF 目录选择插件（如 `@capawesome/capacitor-file-picker`）后该功能才可用 |
| Java 26 兼容性 | ⚠️ 已知问题 | AGP 8.5.0 + Gradle 8.7 不支持 Java 26。构建时需用 JDK 21（Minecraft 自带） |
| 环境变量 JAVA_HOME | ⚠️ 未设置 | 构建 APK 需显式设 `JAVA_HOME=C:\Users\VOS_User\AppData\Roaming\.minecraft\runtime\java-runtime-delta` |

---

## 文件关键路径

```
# 手机端连接码：    mobile/src/services/device.ts → getDeviceId() → generateConnectionCode()
# 电脑端连接码：    desktop/src-tauri/src/identity.rs → generate_code() → get_self_code()
# 传输协议：         shared-core/src/transfer.ts → TransferClient
# 桌面端传输：       desktop/src-tauri/src/transfer.rs → start_receiver() / send_files()
# 桌面端发现：       desktop/src-tauri/src/discovery.rs → start_discovery()
# 手机端接收：       mobile/local-receiver/.../LocalReceiverPlugin.java → ServerSocket
# 备份编排：         mobile/src/services/backup.ts → sendBackup()
# 桌面端扫描：       desktop/src-tauri/src/transfer.rs → scan_directory()
# 桌面端存储：       desktop/src-tauri/src/db.rs → Database（SQLite）
# 状态迁移：         shared-core/src/state.ts → migrateState()
# 冲突重命名：       shared-core/src/conflict.ts / desktop transfer.rs → resolve_target_path()
# 日志核心（共用）： shared-core/src/logger.ts → Logger（环形缓冲 + 脱敏 + export）
# 桌面端日志：       desktop/src-tauri/src/logger.rs → log_info! 等宏 + export_logs
# 命令出入口：       desktop/src-tauri/src/lib.rs → mod commands 包装层
```

---

## 外部依赖

### LocalSend（`packages/core`）
路径：`D:\code\tools\localsend-main\packages\core`  
作为 path 依赖引入，features: `["http", "multicast"]`。  
`http` 自动包含 `crypto`（mTLS 证书相关），本工具使用纯 HTTP 所以 `tls_config` 传 `None`。  
`multicast` 提供 UDP 设备发现。

### 其他核心依赖
- `tauri` v2 — 桌面端框架
- `rusqlite` 0.31 — SQLite 存储
- `tokio` 1.x — 异步运行时
- `localsend` — 传输 + 发现核心
- `@capacitor/filesystem` v6 — 手机端文件系统
- `vue` 3 — 前端框架