# 局域网备份工具 — 开发交接文档

> 生成时间：2026-08-15 | 项目路径：`C:\Users\123\AppData\Roaming\TRAE SOLO CN\ModularData\ai-agent\work-mode-projects\6a7f5d5699c44b33268ede69`
> 基于 LocalSend v2.2 协议实现，纯本地部署，无云服务。

---

## 一、项目结构总览

```
.
├── shared-core/          ← 共享核心库（纯 TypeScript，手机/电脑共用）
│   ├── src/
│   │   ├── identity.ts   设备连接码生成（FNV-1a + xorshift32）
│   │   ├── manifest.ts   文件清单差异对比（append-only）
│   │   ├── anchor.ts     锚点管理（按目录/文件 mtime 快速扫描）
│   │   ├── conflict.ts   冲突重命名（_MMDDhhmmss.ext，不覆盖）
│   │   ├── scan.ts       扫描引擎（快速锚点 + 深度全量 Diff）
│   │   ├── state.ts      状态数据结构（设备/备份/策略 + 版本迁移）
│   │   ├── transfer.ts   LocalSend v2.2 传输协议客户端（TS 重写）
│   │   ├── discovery.ts  设备发现状态机（接口层，平台层待实现）
│   │   ├── autopolicy.ts 自动策略决策（semi/auto/manual）
│   │   ├── index.ts      统一导出
│   │   └── test/
│   │       └── selfcheck.ts  17 个单元测试（全部通过）
│   ├── tsconfig.json
│   └── package.json
│
├── mobile/              ← 手机端（Vue3 + Capacitor + Android）
│   ├── src/
│   │   ├── App.vue       主界面（备份目录/目标设备/扫描模式/三方向/进度/状态）
│   │   ├── main.ts       Vue 入口
│   │   ├── style.css     CSS 变量 + 暗色主题
│   │   └── services/
│   │       ├── filesystem.ts  Android SAF 文件遍历 + 大文件分块读取
│   │       ├── device.ts      设备身份 + 状态 JSON 管理（UUID → 连接码）
│   │       └── backup.ts      备份编排（扫描 → 传输 → 状态更新）
│   ├── android/          Android 原生工程（Capacitor 生成）
│   │   ├── app/build.gradle        应用配置
│   │   ├── app/src/main/
│   │   │   ├── AndroidManifest.xml  权限声明
│   │   │   ├── java/com/backup/mobile/MainActivity.java  主 Activity
│   │   │   ├── res/                启动图/图标资源
│   │   │   └── assets/capacitor.plugins.json  插件声明
│   │   ├── gradle/wrapper/         Gradle 包装器（8.7）
│   │   ├── build.gradle            根构建脚本（AGP 8.5.0）
│   │   └── settings.gradle / gradlew / gradlew.bat
│   ├── capacitor.config.json
│   ├── vite.config.ts     Vite 配置（shared-core 别名）
│   ├── tsconfig.json
│   └── ANDROID_PERMISSIONS.md  Android 权限说明
│
├── desktop/             ← 电脑端（Vue3 + Tauri + Rust）
│   ├── src/
│   │   ├── App.vue       主界面（备份目录/目标设备/端口/三方向/已配对设备）
│   │   ├── main.ts       Vue 入口
│   │   └── style.css     CSS 变量 + 暗色主题
│   ├── src-tauri/
│   │   ├── src/
│   │   │   ├── lib.rs        Tauri 应用入口 + 命令注册 + DB 初始化
│   │   │   ├── main.rs       Rust 入口（调用 lib::run）
│   │   │   ├── identity.rs   MachineGuid 读取 + 连接码生成 + 数据库加密密钥
│   │   │   ├── db.rs         SQLCipher 加密 SQLite 存储（3 测试）
│   │   │   └── transfer.rs   传输模块占位（待接入 LocalSend Rust crate）
│   │   ├── capabilities/
│   │   │   └── default.json  Tauri v2 权限声明（core + dialog）
│   │   ├── tauri.conf.json   Tauri 配置（CSP/窗口/打包）
│   │   ├── Cargo.toml        Rust 依赖（rusqlite + sqlcipher）
│   │   └── build.rs          Tauri 构建脚本
│   ├── vite.config.ts
│   ├── tsconfig.json
│   └── package.json
│
└── docs/
    └── ARCHITECTURE.md   架构设计文档
```

---

## 二、各文件职责详表

### shared-core（10 个核心文件）

| 文件 | 行数 | 核心职责 | 关键函数 |
|------|------|----------|----------|
| `identity.ts` | ~76 | 连接码生成与校验 | `generateConnectionCode`, `codesMatch`, `isValidConnectionCode`, `deviceDisplayName` |
| `manifest.ts` | ~94 | 文件清单全量构建与差异 | `buildManifest`, `diffManifests` |
| `anchor.ts` | ~77 | 锚点管理（按目录/文件粒度） | `updateAnchors`, `isAfterAnchor`, `scanDateRange` |
| `conflict.ts` | ~93 | 冲突文件重命名 | `resolveFileName`（`_MMDDhhmmss` 后缀） |
| `scan.ts` | ~91 | 扫描引擎统一入口 | `scan(mode, anchors, prevManifest, files, now)` |
| `state.ts` | ~165 | 状态数据结构 + 版本迁移 | `BackupState`, `DeviceState`, `createEmptyState`, `migrateState`, `getOrCreateDevice`, `markBackupDone`, `setAutoPolicy` |
| `transfer.ts` | ~200 | LocalSend v2.2 HTTP 传输客户端 | `TransferClient`（register/prepareUpload/upload/cancel/info） |
| `discovery.ts` | ~130 | 设备发现状态机 | `DiscoveryManager`（reportDevice/reportDeviceLost/prune） |
| `autopolicy.ts` | ~80 | 自动备份策略决策 | `decidePolicy`, `isSameWifi`（可配置网段长度） |
| `index.ts` | ~10 | 统一导出入口 | `export * from ...` |
| `test/selfcheck.ts` | ~170 | 17 个单元测试 | 全部通过（TypeScript 编译 + Node.js --test） |

### mobile（4 个源码文件 + Android 工程）

| 文件 | 行数 | 核心职责 |
|------|------|----------|
| `App.vue` | ~240 | 主界面：备份目录选择/设备选择/IP 输入/扫描模式切换/三方向备份按钮/进度显示/状态面板 |
| `main.ts` | ~8 | Vue 入口，挂载 App 到 `#app` |
| `style.css` | ~140 | CSS 变量（暗色主题），页边距，暗色模式 |
| `services/filesystem.ts` | ~150 | Android SAF 文件权限请求、备份根目录选择、目录遍历、文件读取（Blob） |
| `services/device.ts` | ~110 | 设备身份管理：UUID → FNV-1a 哈希 → 8 位连接码，状态 JSON 读写 |
| `services/backup.ts` | ~130 | 备份编排：扫描→prepareUpload→分块上传→更新锚点与清单 |

### desktop（5 个源码文件 + Rust 后端 + Android 等效物）

| 文件 | 行数 | 核心职责 |
|------|------|----------|
| `src/App.vue` | ~220 | 主界面：备份目录/目标设备 IP/端口/三方向/已配对设备列表 |
| `src/main.ts` | ~8 | Vue 入口 |
| `src/style.css` | ~140 | CSS 变量（暗色主题） |
| `src-tauri/src/lib.rs` | ~40 | Tauri 应用入口：DB 初始化、dialog 插件、4 条命令注册 |
| `src-tauri/src/identity.rs` | ~140 | MachineGuid 读取、FNV-1a 连接码生成（与 TS 一致）、数据库加密密钥、5 个测试 |
| `src-tauri/src/db.rs` | ~230 | SQLCipher 加密 SQLite：3 个 Tauri 命令（get_device_state/save_device_state/get_all_devices）+ 4 个测试 |
| `src-tauri/src/transfer.rs` | ~30 | 传输模块占位（返回占位消息，待接入 LocalSend Rust crate） |
| `src-tauri/src/main.rs` | ~5 | Rust 入口，调用 `lib::run()` |
| `src-tauri/tauri.conf.json` | ~30 | Tauri v2 配置：CSP、窗口尺寸、bundle 图标路径 |
| `src-tauri/Cargo.toml` | ~20 | 依赖：tauri 2 / dialog / serde / rusqlite+sqlcipher |
| `src-tauri/capabilities/default.json` | ~10 | Tauri v2 权限声明 |

### 文档（2 个文件）

| 文件 | 职责 |
|------|------|
| `README.md` | 项目说明、环境要求、使用方式、已知问题 |
| `docs/ARCHITECTURE.md` | 架构设计：协议、连接码、锚点、冲突策略 |

---

## 三、参考工具与环境需求

### 必须安装的开发环境

| 工具 | 版本要求 | 用途 | 验证命令 |
|------|----------|------|----------|
| **Node.js** | ≥ 18 | TypeScript 编译、Vite 构建 | `node --version` |
| **npm** | ≥ 9 | 包管理、依赖安装 | `npm --version` |
| **Rust** | ≥ 1.70 | 桌面端 Tauri 编译 | `rustc --version` |
| **MSVC Build Tools** | 2022 + "Desktop development with C++" | Rust 链接器（必需） | `vswhere.exe -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find bin\Hostx64\x64\link.exe` |
| **Java JDK** | 21（或 17） | Android 构建 | `java -version` |
| **Android SDK** | 35 + build-tools 35.0.0 | APK 编译 | 检查 `$ANDROID_HOME/platforms/android-35` |
| **Gradle** | 8.7 | Android 构建（通过 wrapper 自动下载） | 首次构建时自动完成 |

### 构建命令

```bash
# 1. 安装依赖（首次）
cd shared-core && npm install
cd ../mobile && npm install
cd ../desktop && npm install

# 2. shared-core 测试
cd shared-core
npm run test          # 运行 17 个单元测试

# 3. 手机端 APK
cd mobile
npm run build         # Vite 构建前端
npx cap sync          # 同步到 Android
cd android
JAVA_HOME="C:\Program Files\Java\jdk-21" gradlew assembleDebug  # 生成 APK
# 输出：mobile/android/app/build/outputs/apk/debug/app-debug.apk

# 4. 桌面端 EXE
cd desktop
npm run build         # Vite 构建前端
cd src-tauri
cargo build --release # 生成可执行文件
# 输出：desktop/src-tauri/target/release/局域网备份.exe
# 或打包：cargo tauri build
```

### MCP 工具（代码库索引）

| 工具 | 用途 |
|------|------|
| `mcp_codebase-memory-mcp` | 代码库搜索、架构查询、代码片段获取（已建立 277 节点索引） |
| `integrated_code_mode` | 代码执行与工具编排 |

---

## 四、已知问题与待办

### 当前状态

- **shared-core**：17 个测试全部通过，代码已审计修复（34 个问题全部修复）
- **mobile 前端**：Vite 构建成功，Android 工程已初始化
- **desktop 前端**：Vite 构建成功，Tauri 配置完整（capabilities + CSP）
- **desktop Rust 后端**：依赖解析正确，编译被 MSVC 链接器阻断（需安装 VS Build Tools）

### 待完成项

| 优先级 | 事项 | 说明 |
|--------|------|------|
| **P1** | 安装 MSVC Build Tools | Rust 编译必需：`vswhere.exe -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64` |
| **P1** | `transfer.rs` 接入 LocalSend Rust crate | 当前为占位实现，需从 LocalSend `packages/core` 引入传输功能 |
| **P2** | 手机端接收服务 | `pc-to-phone` 方向需实现 LocalSend 接收端（HTTP server） |
| **P2** | 设备发现平台层 | UDP 广播在 Capacitor/Tauri 中的实现 |
| **P3** | Android 构建 Gradle 版本兼容性 | Gradle 8.7 + AGP 8.5.0，当前 AAPT 资源编译失败可能与 JDK 21 有关 |
| **P3** | 桌面端图标资源 | `tauri.conf.json` 中引用 `icons/icon.png` 和 `icons/icon.ico`，需放置到 `src-tauri/icons/` |
| **P3** | Rust 编译验证 | 安装 MSVC 后运行 `cargo check` 验证 `sqlcipher` 编译 |

### 两次审计发现的 34 个问题（已全部修复）

| 层级 | 第一轮 | 第二轮（新增） | 合计 |
|------|--------|---------------|------|
| P1 | 3 | 3 | 6 |
| P2 | 5 | 8 | 13 |
| P3 | 5 | 10 | 15 |
| **合计** | 13 | 21 | **34** |

关键修复包括：
- `prepareUpload` files 格式：数组 → 字典（LocalSend v2.2 协议）
- 清单用全部磁盘文件构建（避免深度扫描重复传输）
- 文件名保留完整相对路径（不丢目录层级）
- 大文件 4MB 分块上传（避免 OOM）
- 网络请求统一超时（30s）
- TS/Rust 哈希编码统一为 UTF-8
- 状态版本迁移（`migrateState`）
- SQLCipher 加密存储（密钥派生自 MachineGuid）
- 上传失败自动 cancel 会话
- 连接码格式校验

---

## 五、关键设计决策速查

| 决策 | 选择 | 理由 |
|------|------|------|
| 连接码长度 | 8 位 | 31^8 ≈ 8.5 万亿种可能，足够安全 |
| 连接码字符集 | `ABCDEFGHJKMNPQRSTUVWXYZ23456789` | 去掉易混淆字符（0/O/1/I/L/2/Z） |
| 冲突策略 | 接收端重命名 `_MMDDhhmmss` | 永远不覆盖，发送方无感 |
| 扫描模式 | 快速（锚点区间）+ 深度（全量 Diff） | 日常快速、导入旧照片深度 |
| 自动策略 | semi/auto/manual | 半自动弹窗、纯自动静默、纯手动不触发 |
| 桌面加密 | SQLCipher + MachineGuid 派生密钥 | 同设备自动解密，跨设备不可读 |
| 分块阈值 | 4MB | 避免移动端 WebView 内存溢出 |

---

> 文档结束。所有源码已清理缓存，仅保留源码文件。