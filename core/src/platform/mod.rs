//! 平台钩子（跨端契约的落地点）。
//!
//! V4 的协议/算法在 `lanbackup-core` 内单一实现，但**少数能力只有平台层拿得到**
//! （网卡、组播锁、原生日历/文件系统语义），必须抽象成 trait 由桌面 / Android 注入。
//!
//! # M22 —— Android 组播锁
//!
//! [`crate::presence::transport::MulticastGuard`] 的 trait 已在此定义，且
//! [`crate::presence::transport::PresenceSocket`] 已通过
//! [`crate::presence::transport::PresenceSocket::bind_with_guard`] + `Drop` 在
//! **收发全生命周期**内持锁。
//!
//! 桌面端用 [`crate::presence::transport::NoopMulticastGuard`]（无需锁）。
//! **Android 端需由 JNI 层实现一个真实 `MulticastGuard`**（调用
//! `WifiManager.createMulticastLock(...).acquire()/release()`），并在创建
//! `PresenceSocket` 时经 `bind_with_guard` 注入。
//!
//! 本模块下 [`android`]（`android-jni` feature 下可用）提供了基于 JNI 的真实
//! `MulticastGuard` 实现：Android 侧把 `WifiManager` 经 JNI 注入后，由运行时在
//! `bind_with_guard` 时 `acquire`、`Drop` 时 `release`，与桌面 `NoopMulticastGuard`
//! 共用同一条接线路径。
//!
//! [`android_bridge`]（同样在 `android-jni` 下）把上述实现暴露成 `com.backup.mobile.receiver`
//! 命名空间下的 JNI 符号，供 `local-receiver` Capacitor 插件直接 `System.loadLibrary` 后调用——
//! M22「Android 侧」的最后一环（Rust 侧契约）由此闭合；插件侧的 `native` 声明与 `.so` 打包
//! 仍属于 `mobile/` 集成工作。

#[cfg(feature = "android-jni")]
pub mod android;

#[cfg(feature = "android-jni")]
mod android_bridge;
