# 局域网备份工具 - 架构设计

> 基于 LocalSend 二次开发的开源备份工具。只做一件事：手机和电脑之间通过局域网互传文件做归档备份。

## 一、技术栈

| 端 | 界面 | 传输核心 | 状态存储 |
|---|---|---|---|
| 手机端 | Vue3 + Capacitor | TypeScript 重写（协议兼容 LocalSend v2.2） | JSON（每配对设备一份） |
| 电脑端 | Vue3 + Tauri | 直接复用 LocalSend 的 Rust crate | SQLCipher 加密存储 |

## 二、目录结构

```
main/
├── shared-core/          # 共享核心（纯 TS，两端复用）
│   ├── identity.ts       # 连接码生成(8位字母数字) + 匹配
│   ├── discovery.ts      # 局域网广播发现 + 连接码校验
│   ├── scan.ts           # 快速模式(锚点区间) + 深度模式(全量清单Diff)
│   ├── anchor.ts         # 锚点管理(按配对设备/子目录/文件)
│   ├── manifest.ts       # 全量清单生成与Diff
│   ├── conflict.ts       # 冲突检测 + 重命名(接收端算力)
│   ├── state.ts          # 状态文件JSON读写(每配对设备一份)
│   └── transfer.ts       # HTTP传输协议(发送/接收)
├── mobile/               # 手机端 Vue3 + Capacitor
│   ├── src/              # Vue3 界面
│   └── capacitor/        # Capacitor 配置 + 原生插件
├── desktop/              # 电脑端 Vue3 + Tauri
│   ├── src/              # Vue3 界面
│   └── src-tauri/        # Tauri Rust 后端（复用 LocalSend crate）
└── docs/                 # 文档
```

## 三、核心设计原则

### 1. 手机和电脑是"完全相同的设备"
两端共享同一套核心逻辑（连接码、扫描、锚点、清单、冲突、状态），只是外壳不同。共享核心用纯 TypeScript 写，两端都能直接 import。

### 2. 传输协议复用 LocalSend v2.2
手机端用 TS 重写协议（HTTP + mTLS），电脑端直接复用 Rust crate。协议端点：
- `POST /api/localsend/v2/register` - 设备注册/发现
- `POST /api/localsend/v2/prepare-upload` - 准备上传（协商会话）
- `POST /api/localsend/v2/upload?sessionId&fileId&token` - 上传文件
- `POST /api/localsend/v2/cancel` - 取消
- `GET /api/localsend/v2/info` - 设备信息

### 3. 设备身份：证书指纹 + 8位连接码
- 首次配对：局域网发现后匹配 8 位连接码，匹配成功即信任
- 之后：用 mTLS 证书指纹识别设备身份

## 四、三大功能模块（主页平铺）

1. **手机 → 电脑备份**
2. **电脑 → 手机备份**
3. **双向同步备份**（两边各推新增，非镜像删除）

三者逻辑完全独立，互不干扰。

## 五、扫描引擎（核心差异点）

扫描决策逻辑只在**发送端**做，接收端只负责收。

### 快速模式（默认）
- 锚点只存在手机端本地（按配对设备分文件存）
- 记录上次备份成功的最新文件修改日期
- 本次只扫「上次锚点日期 → 当前日期」区间
- UI 展示：最后锚点日期 + 本次扫描区间

### 深度模式（手动触发）
- 全量遍历目录，生成「相对路径 + 大小 + mtime」清单
- 与上一次全量清单 Diff，找出真实新增/变更文件再传

## 六、自动策略（可配置）

- 默认：半自动（发现已配对电脑在线 + 同 Wi-Fi → 弹窗询问）
- 可切换：纯自动（静默传）/ 纯手动（点按钮才传）

## 七、冲突处理（唯一规则）

- 目标端存在同名文件且大小/mtime 不一致 → 绝不覆盖、绝不弹窗问
- 由**接收端**算力负责重命名
- 规则：`原文件名_MMDDhhmmss.扩展名`，例 `IMG_001_0815234500.jpg`

## 八、关键约束

1. 备份策略是**只增不删**：任一端删原文件，不影响另一端已备份内容
2. 状态文件：手机为每个配对设备存一份 JSON，含设备连接码、锚点日期、全量清单、自动策略
3. 电脑端状态用 SQLCipher 加密存储（密钥派生自本机 MachineGuid）
4. 无账号、无云、无公网服务器（信令用局域网广播）

## 九、Android SD 卡读取（重点）

Capacitor WebView 默认只能访问 App 私有目录，读不到外部 SD 卡/公共存储。需要：
- 用 `@capacitor/filesystem` 申请存储权限
- Android 10+ 需要 `READ_MEDIA_*` 权限，Android 13+ 需要 `READ_MEDIA_IMAGES/VIDEO/AUDIO`
- 用 Storage Access Framework（SAF）让用户选目录，拿到 URI 后通过 Capacitor 插件读写
