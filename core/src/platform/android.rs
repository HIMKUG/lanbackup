//! Android 侧真实组播锁实现（M22）。
//!
//! 仅在 `android-jni` feature 下编译。由 Android JNI 桥调用：Android 侧把
//! `WifiManager` 经 JNI 传给 [`AndroidMulticastGuard::new`] 建立 `MulticastLock`，
//! 之后把它装进
//! [`crate::presence::transport::PresenceSocket::bind_with_guard`]，运行时会在
//! 绑定时 `acquire`、套接字销毁时 `release`，从而满足 M22「收发两条路径持锁」。
//!
//! 见 `crate::platform` 模块级文档了解契约。原生侧（Kotlin/Java）大致接线：
//!
//! ```kotlin
//! // 在持有 WifiManager 的上下文中（如 Activity / Service），把锁交给 Rust 核心
//! val wifi = getSystemService(Context.WIFI_SERVICE) as WifiManager
//! val guard = AndroidMulticastGuard.create(env, wifi, "lanbackup-beacon")
//! // 通过 JNI 把 guard 交给 Rust，由其调用 PresenceSocket::bind_with_guard(...)
//! ```
//!
//! 注意：全局引用跨 JNI 调用存活，但不在 `Drop` 中显式释放——组播锁在进程生命周期内
//! 常驻（单例语义），进程退出由 ART 回收，符合 Android 惯例。

use jni::objects::{GlobalRef, JObject, JValue};
use jni::sys::jobject;
use jni::JavaVM;
use crate::presence::transport::MulticastGuard;

/// 持有 `WifiManager.MulticastLock` 的全局引用（原始 `jobject`）。
pub struct AndroidMulticastGuard {
    vm: JavaVM,
    lock: jobject,
}

// JNI 句柄在 Android 上由系统在单线程 Looper 内使用；我们每次 acquire/release 都重新
// `attach_current_thread` 拿 env，句柄自身不被跨线程共享读写，故可安全标记为 Send + Sync。
// 同时 `MulticastGuard` 要求 `Send + Sync + Debug`，三者在此一并满足。
unsafe impl Send for AndroidMulticastGuard {}
unsafe impl Sync for AndroidMulticastGuard {}

impl std::fmt::Debug for AndroidMulticastGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidMulticastGuard")
            .field("has_lock", &(!self.lock.is_null()))
            .finish()
    }
}

impl AndroidMulticastGuard {
    /// 由 Android JNI 桥调用：给定当前线程的 `JNIEnv` 与 `WifiManager` 实例，
    /// 创建名为 `tag` 的组播锁并缓存为全局引用。
    pub fn new(
        env: &mut jni::JNIEnv,
        wifi_manager: &JObject,
        tag: &str,
    ) -> jni::errors::Result<Self> {
        let tag_j: JObject = env.new_string(tag)?.into();
        let lock = env
            .call_method(
                wifi_manager,
                "createMulticastLock",
                "(Ljava/lang/String;)Landroid/net/wifi/WifiManager$MulticastLock;",
                &[JValue::Object(&tag_j)],
            )?
            .l()?;
        // jni 0.21：`new_global_ref` 返回 `GlobalRef`；取其原始句柄常驻，
        // 并 `forget` 掉 `GlobalRef` 以免其 Drop 把全局引用一并释放（进程级单例，由 ART 回收）。
        let global: GlobalRef = env.new_global_ref(lock)?;
        let raw = global.as_raw();
        std::mem::forget(global);
        let vm = env.get_java_vm()?;
        Ok(Self { vm, lock: raw })
    }

    /// 把全局引用句柄还原为本次调用可用的 `JObject`。
    #[inline]
    fn as_object(&self) -> JObject<'_> {
        unsafe { JObject::from_raw(self.lock) }
    }
}

impl MulticastGuard for AndroidMulticastGuard {
    fn acquire(&self) -> Result<(), String> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|e| e.to_string())?;
        // acquire 失败（如权限不足）仅返回错误，由上层告警，不致命。
        env.call_method(self.as_object(), "acquire", "()V", &[])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn release(&self) {
        // release 失败无所谓（锁本来就该放了），静默吞掉。
        if let Ok(mut env) = self.vm.attach_current_thread() {
            let _ = env.call_method(self.as_object(), "release", "()V", &[]);
        }
    }
}
