package com.backup.mobile.receiver;

import android.net.wifi.WifiManager;
import android.util.Log;

/**
 * lanbackup-core 的 JNI 绑定（M22 组播锁）。
 *
 * 与 core/src/platform/android_bridge.rs 导出的符号一一对应：
 *   Java_com_backup_mobile_receiver_LanBackupCore_createMulticastGuard
 *   Java_com_backup_mobile_receiver_LanBackupCore_releaseMulticastGuard
 *
 * 库加载是"尽力而为"：核心 .so 尚未打进 APK 时（纯 Capacitor 阶段），
 * {@link #isAvailable()} 返回 false，调用方走 Java 内置降级路径，不崩溃。
 */
public final class LanBackupCore {

    private static final String TAG = "LanBackupCore";
    private static final String LIB_NAME = "lanbackup_core";

    private static volatile boolean attempted;
    private static volatile boolean loaded;

    private LanBackupCore() {
    }

    /**
     * 尝试加载核心动态库（幂等，仅尝试一次）。失败只记日志、不抛给调用方。
     *
     * @return true 表示 `createMulticastGuard`/`releaseMulticastGuard` 可用
     */
    public static boolean isAvailable() {
        if (attempted) {
            return loaded;
        }
        attempted = true;
        try {
            System.loadLibrary(LIB_NAME);
            loaded = true;
        } catch (UnsatisfiedLinkError e) {
            Log.w(TAG, "lib" + LIB_NAME + ".so 未打包，组播锁走 Java 内置实现");
        }
        return loaded;
    }

    /**
     * 创建组播锁守卫，把 {@link WifiManager} 交给 Rust 核心侧
     * （core 的 PresenceSocket 绑定时 acquire、销毁时 release）。
     *
     * @return 不透明句柄；0 表示创建失败（调用方走降级路径）。句柄必须交给
     *         {@link #releaseMulticastGuard(long)}，不可泄漏。
     */
    public static native long createMulticastGuard(WifiManager wifiManager, String tag);

    /**
     * 释放 {@link #createMulticastGuard} 返回的句柄。0 为合法空句柄（直接返回）。
     * 仅释放 Rust 侧句柄；真实 MulticastLock 由 Android 在进程退出时回收。
     */
    public static native void releaseMulticastGuard(long handle);
}
