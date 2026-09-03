//! Android JNI 桥（M22 收尾）：把 [`AndroidMulticastGuard`] 的创建暴露给
//! `local-receiver` Capacitor 插件。
//!
//! 命名空间与 `mobile/local-receiver/android/build.gradle` 的
//! `namespace "com.backup.mobile.receiver"` 严格对齐——JNI 符号名即由它派生。
//! Kotlin 侧需在同一命名空间下声明 `external` 方法，本模块提供对应的 C 符号。
//!
//! # 生命周期
//!
//! 1. Android 侧在持有 `WifiManager` 的上下文中调用
//!    [`Java_com_backup_mobile_receiver_LanBackupCore_createMulticastGuard`]，
//!    拿到一个不透明句柄（`jlong`，实为装箱的 `AndroidMulticastGuard` 指针）。
//! 2. 该句柄交给后续 `PresenceSocket::bind_with_guard` 的 Android 调用方，
//!    由核心在绑定时 `acquire`、套接字销毁时 `release`。
//! 3. 进程退出前调用
//!    [`Java_com_backup_mobile_receiver_LanBackupCore_releaseMulticastGuard`]
//!    释放句柄。组播锁本身按设计在进程生命周期内常驻（见 `android.rs`）。
//!
//! # 风险
//!
//! 这些符号在核心作为 `cdylib` 编译进 `liblanbackup_core.so` 后，由 Android 侧
//! `System.loadLibrary("lanbackup_core")` 加载。本模块只定义符号，不依赖插件已存在——
//! 若 Kotlin 侧尚未声明对应的 `native` 方法，符号只是静静地躺在那里，不会造成破坏。

#![cfg(feature = "android-jni")]

use jni::objects::{JClass, JObject, JString};
use jni::sys::jlong;
use jni::JNIEnv;

use crate::platform::android::AndroidMulticastGuard;

/// 创建 Android 组播锁（M22）。
///
/// - `wifi`：`android.net.wifi.WifiManager` 实例（由 `Context.getSystemService` 取得）。
/// - `tag`：锁标签（建议 `"lanbackup-beacon"`），便于在 `dumpsys wifi` 中辨识。
///
/// 返回不透明句柄（实际为装箱的 `AndroidMulticastGuard` 指针）。**返回 0 表示失败**
/// （JNI 调用已失败，调用方按失败分支处理）。句柄必须交给
/// [`release_multicast_guard`](Java_com_backup_mobile_receiver_LanBackupCore_releaseMulticastGuard)。
#[no_mangle]
pub extern "system" fn Java_com_backup_mobile_receiver_LanBackupCore_createMulticastGuard(
    mut env: JNIEnv,
    _class: JClass,
    wifi: JObject,
    tag: JString,
) -> jlong {
    let Ok(tag) = env.get_string(&tag) else {
        return 0;
    };
    let Ok(tag) = tag.to_str() else {
        return 0;
    };
    match AndroidMulticastGuard::new(&mut env, &wifi, tag) {
        Ok(g) => Box::into_raw(Box::new(g)) as jlong,
        Err(_) => 0,
    }
}

/// 释放 [`create_multicast_guard`](Java_com_backup_mobile_receiver_LanBackupCore_createMulticastGuard)
/// 返回的句柄。句柄为 0 时视为空，直接返回。
///
/// 注意：组播锁按设计在进程生命周期内常驻，此处仅释放 Rust 侧句柄；
/// 真实锁由 Android 在进程退出时回收（见 `android.rs`）。
#[no_mangle]
pub extern "system" fn Java_com_backup_mobile_receiver_LanBackupCore_releaseMulticastGuard(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    // SAFETY: `handle` 必须来自 `createMulticastGuard` 且尚未释放。调用方（Kotlin 插件）
    // 负责保证这一契约——它在成功创建后持有着句柄，并在销毁路径上恰好释放一次。
    unsafe {
        drop(Box::from_raw(handle as *mut AndroidMulticastGuard));
    }
}
