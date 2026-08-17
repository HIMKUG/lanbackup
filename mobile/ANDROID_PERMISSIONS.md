# Android 存储权限配置

> 重点：Capacitor WebView 默认只能访问 App 私有目录，读不到外部 SD 卡/公共存储。
> 运行 `npx cap sync android` 生成 Android 平台后，需在 `android/app/src/main/AndroidManifest.xml` 添加以下权限。

## 1. AndroidManifest.xml 权限声明

在 `<manifest>` 标签内添加：

```xml
<!-- Android 10-12：读取外部存储 -->
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" android:maxSdkVersion="32" />

<!-- Android 13+：细分媒体权限 -->
<uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
<uses-permission android:name="android.permission.READ_MEDIA_VIDEO" />
<uses-permission android:name="android.permission.READ_MEDIA_AUDIO" />

<!-- 网络（局域网发现/传输必需） -->
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
<uses-permission android:name="android.permission.CHANGE_WIFI_MULTICAST_STATE" />
```

## 2. 为什么需要 SAF（Storage Access Framework）

- Android 10+ 强制分区存储（Scoped Storage），App 无法直接访问公共目录的任意路径。
- 通过 `Filesystem.pickDirectory()` 让用户选择目录，系统返回一个**持久化 URI**。
- 该 URI 可跨 App 重启保留，App 通过它读写目录，无需 root。

## 3. 运行时权限请求

代码中已通过 `Filesystem.requestPermissions()` 请求存储权限（见 `src/services/filesystem.ts`）。

## 4. 网络权限（局域网发现）

- 局域网 UDP 广播/组播需要 `CHANGE_WIFI_MULTICAST_STATE`。
- 若使用 mDNS，还需在 `AndroidManifest.xml` 添加：
  ```xml
  <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
  ```

## 5. 生成 Android 平台

```bash
cd mobile
npm install
npm run build        # 构建 Vue3 前端
npx cap add android  # 首次生成 Android 平台
npx cap sync android # 同步
```

生成后手动编辑 `android/app/src/main/AndroidManifest.xml` 添加上述权限。
