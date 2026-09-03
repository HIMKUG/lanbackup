//! 移动端绑定门面（阶段 6）：稳定 C ABI + JSON 冷路径
//!
//! # 为什么是这一层，而不是直接上 uniffi
//!
//! 文档 §五 把 stage 6 写作「uniffi 绑定导出」。落地时 `uniffi` 不在
//! 可用的 registry 索引里（离线环境），但这不是把这一阶段跳过的理由 ——
//! 真正要解决的问题是**「协议与算法只此一份实现」**，而 uniffi 只是
//! 达成它的手段之一。
//!
//! 于是本模块提供一个**与绑定框架无关**的门面：
//!
//! ```text
//!   Kotlin / Swift / C++
//!            │
//!   ┌────────▼─────────┐
//!   │ JNI 或 uniffi    │  ← 各自生成，只做类型转换
//!   ├──────────────────┤
//!   │ 本模块：C ABI    │  ← **唯一需要手工维护的边界**
//!   ├──────────────────┤
//!   │ lanbackup-core   │  ← 协议与算法
//!   └─────────────────┘
//! ```
//!
//! 等 uniffi 可用时，它接在**本模块之上**而不是替换它 ——
//! 届时新增的只是「uniffi 类型 ↔ C ABI」的转换，core 一行不动。
//! 反过来若直接把 `#[derive(uniffi::Record)]` 撒进 DTO，
//! 就等于把绑定框架焊进了协议层，换框架要动协议层，正是三代并存的病根。
//!
//! # 两条路径的分工
//!
//! | 路径 | 适用 | 例子 | 代价 |
//! |---|---|---|---|
//! **定长签名** | 热路径、形状稳定 | beacon 签发/验签、常量 | 一次调用，零分配 |
//! | **JSON 冷路径**（[`lanbackup_invoke`]） | 形状易变、调用稀疏 | 路由表、同步决策、按钮裁决 | 一次 JSON 编解码 |
//!
//! beacon 每 500ms 就要签一次，为它付 JSON 的解析代价是不可接受的；
//! 而「这个按钮现在能不能点」一天也问不了几次，却会随着状态机演进而改形状，
//! 为它固定 C 结构体签名等于给每次演进都加一次双端同步发布。
//! 按这个标准分工，而不是一律 JSON 或一律定长。
//!
//! # 三条不可妥协的约定
//!
//! 1. **绝不 panic 跨越 FFI 边界。** Rust 的 unwind 穿过 `extern "C"` 是 UB。
//!    每个导出函数都由 [`guard!`] 包住，panic 被拦下并转成 [`ERR_PANIC`]。
//! 2. **跨边界分配的内存只能由本模块释放。** 混用两端的 allocator
//!    在 Android 上必崩，故提供 [`lanbackup_vec_free`]。
//! 3. **出参一律调用方提供缓冲区**，除非长度不定（那时才用 [`CVec`]）。
//!    这把「谁分配谁释放」的负担压到最低。

use std::cell::RefCell;
use std::ffi::{c_char, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use crate::dto::sync::Manifest;
use crate::presence::beacon::{sign_beacon, verify_beacon, BEACON_LEN, DEVICE_ID_PREFIX_LEN};
use crate::routes;
use crate::state::policy::{self, UiAction, UiContext, Verdict};
use crate::sync;
use crate::version::{API_PREFIX, DEFAULT_PORT, PROTOCOL_VERSION};

// ── 错误码（负数会与「成功」混淆，一律非负）────────────────────────────
pub const ERR_OK: i32 = 0;
/// 传入了空指针
pub const ERR_NULL_PTR: i32 = 1;
/// 缓冲区长度不足
pub const ERR_BUFFER_TOO_SMALL: i32 = 2;
/// 输入切片长度不符合该函数的固定要求
pub const ERR_BAD_LEN: i32 = 3;
/// 字符串不是合法 UTF-8
pub const ERR_UTF8: i32 = 4;
/// Rust 侧 panic，已被边界拦下（否则 unwind 穿 C ABI 是 UB）
pub const ERR_PANIC: i32 = 5;
/// JSON 冷路径的参数或内部序列化失败
pub const ERR_BAD_JSON: i32 = 6;
/// `lanbackup_invoke` 的 method 名不认识
pub const ERR_UNKNOWN_METHOD: i32 = 7;

/// 变长输出。
///
/// 由本模块分配，必须由 [`lanbackup_vec_free`] 释放。
/// `ptr` 在 `len == 0` 时可能为 dangling，释放前无需判空（`Vec::from_raw_parts`
/// 对空 Vec 有定义，只要 ptr 对齐且非 null —— 见 `from_bytes` 的保证）。
#[repr(C)]
pub struct CVec {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl CVec {
    fn from_bytes(bytes: Vec<u8>) -> Self {
        let mut b = std::mem::ManuallyDrop::new(bytes);
        let ptr = b.as_mut_ptr();
        let len = b.len();
        let cap = b.capacity();
        // 空 Vec 的 ptr 是 align-of-u8 的悬垂指针，跨 FFI 传出去后
        // 再传回来 from_raw_parts 是合法的（NonNull::dangling() 语义）。
        // 但为的是让 C 侧的 `if (v.ptr)` 判断不误报，这里显式对齐到 1。
        Self { ptr, len, cap }
    }

    fn null() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// 释放 [`CVec`]。重复释放同一个（非 null）CVec 是 UB，与 `free` 语义一致。
#[no_mangle]
pub extern "C" fn lanbackup_vec_free(v: CVec) {
    if v.ptr.is_null() {
        return;
    }
    drop(unsafe { Vec::from_raw_parts(v.ptr, v.len, v.cap) });
}

// ── 最后一次错误（线程局部）────────────────────────────────────────────

struct LastError {
    code: i32,
    msg: String,
}

thread_local! {
    static LAST: RefCell<LastError> = const {
        RefCell::new(LastError {
            code: ERR_OK,
            msg: String::new(),
        })
    };
}

fn set_error(code: i32, msg: impl Into<String>) -> i32 {
    LAST.with(|c| {
        let mut b = c.borrow_mut();
        b.code = code;
        b.msg = msg.into();
    });
    code
}

fn clear_error() {
    LAST.with(|c| {
        let mut b = c.borrow_mut();
        b.code = ERR_OK;
        b.msg.clear();
    });
}

/// 把整段逻辑包进 `catch_unwind`，panic 一律转成 [`ERR_PANIC`]。
macro_rules! guard {
    ($body:block) => {
        match catch_unwind(AssertUnwindSafe(|| $body)) {
            Ok(v) => v,
            Err(_) => set_error(ERR_PANIC, "Rust 侧 panic，已被 FFI 边界拦下"),
        }
    };
}

// ── 内部小工具（都是 unsafe：裸指针解引用集中在这几个函数里）────────────

// 这几个 helper 一律**自己** `set_error` 再返回错误码。
// 若只返回码、把写错误信息留给调用方，就会出现「返回了错误码，
// 但 last_error 还是 ERR_OK」这种自相矛盾的状态 —— 调用方问不出原因，
// 只能看到一个裸数字。错误码与错误信息必须同源、同时落库。

/// # Safety
/// `p` 必须指向一个以 NUL 结尾的合法 C 字符串，且在调用期间不被释放。
unsafe fn cstr_to_str<'a>(p: *const c_char) -> Result<&'a str, i32> {
    if p.is_null() {
        return Err(set_error(ERR_NULL_PTR, "字符串指针为空"));
    }
    CStr::from_ptr(p)
        .to_str()
        .map_err(|_| set_error(ERR_UTF8, "字符串不是合法 UTF-8"))
}

/// # Safety
/// `p` 为 null 时返回错误；否则 `[p, p+len)` 必须是调用方可写的合法内存。
unsafe fn out_slice<'a>(p: *mut u8, len: usize) -> Result<&'a mut [u8], i32> {
    if p.is_null() {
        return Err(set_error(ERR_NULL_PTR, "输出缓冲区指针为空"));
    }
    Ok(slice::from_raw_parts_mut(p, len))
}

/// # Safety
/// `p` 为 null 时返回空切片；否则 `[p, p+len)` 必须是可读的合法内存。
unsafe fn in_slice<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        return &[];
    }
    slice::from_raw_parts(p, len)
}

fn copy_out(dst: &mut [u8], src: &[u8]) -> i32 {
    if dst.len() < src.len() {
        return set_error(
            ERR_BUFFER_TOO_SMALL,
            format!("缓冲区需要 {} 字节，实得 {}", src.len(), dst.len()),
        );
    }
    dst[..src.len()].copy_from_slice(src);
    ERR_OK
}

// ============================================================
// 常量（无需分配、无需 JSON）
// ============================================================

/// 协议版本号
#[no_mangle]
pub extern "C" fn lanbackup_protocol_version() -> u32 {
    PROTOCOL_VERSION
}

/// 默认服务端口
#[no_mangle]
pub extern "C" fn lanbackup_default_port() -> u16 {
    DEFAULT_PORT
}

/// 路由总数。与 [`routes::ROUTE_COUNT`] 同源，用于双端启动自检。
#[no_mangle]
pub extern "C" fn lanbackup_route_count() -> usize {
    routes::ROUTE_COUNT
}

/// 最后一次错误的错误码
#[no_mangle]
pub extern "C" fn lanbackup_last_error_code() -> i32 {
    LAST.with(|c| c.borrow().code)
}

/// 最后一次错误信息的字节长度（不含结尾 NUL）
#[no_mangle]
pub extern "C" fn lanbackup_last_error_len() -> usize {
    LAST.with(|c| c.borrow().msg.len())
}

/// 把最后一次错误信息拷进调用方缓冲区。
///
/// # Safety
/// `out` 为 null 或 `out_len` 不足时返回 [`ERR_NULL_PTR`] / [`ERR_BUFFER_TOO_SMALL`]。
#[no_mangle]
pub unsafe extern "C" fn lanbackup_last_error_message(out: *mut u8, out_len: usize) -> i32 {
    guard!({
        let dst = match out_slice(out, out_len) {
            Ok(d) => d,
            Err(c) => return c,
        };
        // 先把消息克隆出来再写缓冲区：copy_out 在缓冲区不足时会 set_error，
        // 而 set_error 要 borrow_mut —— 若此刻还持着 borrow，就是重入 panic。
        // 错误信息通路自己先崩掉，是最坏的一种失败方式。
        let msg = LAST.with(|c| c.borrow().msg.clone());
        copy_out(dst, msg.as_bytes())
    })
}

// ============================================================
// 定长热路径：beacon
// ============================================================

/// 签出一个 presence beacon。
///
/// # Safety
/// - `secret` / `secret_len`：配对密钥（任意长度）
/// - `prefix` / `prefix_len`：设备 ID 前缀，必须恰好 [`DEVICE_ID_PREFIX_LEN`] 字节
/// - `out` / `out_len`：输出缓冲区，必须至少 [`BEACON_LEN`] 字节
#[no_mangle]
pub unsafe extern "C" fn lanbackup_beacon_sign(
    secret: *const u8,
    secret_len: usize,
    prefix: *const u8,
    prefix_len: usize,
    ts: u32,
    seq: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guard!({
        let secret = in_slice(secret, secret_len);
        let prefix = in_slice(prefix, prefix_len);
        let dst = match out_slice(out, out_len) {
            Ok(d) => d,
            Err(c) => return c,
        };
        if prefix.len() != DEVICE_ID_PREFIX_LEN {
            return set_error(
                ERR_BAD_LEN,
                format!(
                    "设备 ID 前缀必须 {} 字节，实得 {}",
                    DEVICE_ID_PREFIX_LEN,
                    prefix.len()
                ),
            );
        }
        if dst.len() < BEACON_LEN {
            return set_error(
                ERR_BUFFER_TOO_SMALL,
                format!("beacon 输出需要 {BEACON_LEN} 字节，实得 {}", dst.len()),
            );
        }
        let mut p = [0u8; DEVICE_ID_PREFIX_LEN];
        p.copy_from_slice(prefix);
        let packet = sign_beacon(secret, &p, ts, seq);
        dst[..BEACON_LEN].copy_from_slice(packet.as_bytes());
        ERR_OK
    })
}

/// 验证一个 presence beacon。
///
/// 验签失败**不是错误**：返回 [`ERR_OK`] 且 `out_ts` 写入 0 表示不通过。
/// 这是有意的 —— 收到伪造 beacon 是**常态**（同端口上还有别的协议流量），
/// 若把它报成错误码，上层日志会被噪声淹没，真正的故障反而看不见。
///
/// # Safety
/// - `packet` / `packet_len`：待验报文，必须恰好 [`BEACON_LEN`] 字节
/// - `out_prefix` / `out_prefix_len`：输出设备 ID 前缀，需 [`DEVICE_ID_PREFIX_LEN`] 字节
/// - `out_ts` / `out_seq`：输出时戳与序号；验签失败时写入 0
#[no_mangle]
pub unsafe extern "C" fn lanbackup_beacon_verify(
    secret: *const u8,
    secret_len: usize,
    packet: *const u8,
    packet_len: usize,
    out_prefix: *mut u8,
    out_prefix_len: usize,
    out_ts: *mut u32,
    out_seq: *mut u32,
) -> i32 {
    guard!({
        let secret = in_slice(secret, secret_len);
        let pkt = in_slice(packet, packet_len);
        let dst_prefix = match out_slice(out_prefix, out_prefix_len) {
            Ok(d) => d,
            Err(c) => return c,
        };
        if out_ts.is_null() || out_seq.is_null() {
            return set_error(ERR_NULL_PTR, "out_ts / out_seq 不得为空");
        }
        if dst_prefix.len() < DEVICE_ID_PREFIX_LEN {
            return set_error(
                ERR_BUFFER_TOO_SMALL,
                format!("前缀输出需要 {DEVICE_ID_PREFIX_LEN} 字节"),
            );
        }
        if pkt.len() != BEACON_LEN {
            return set_error(
                ERR_BAD_LEN,
                format!("beacon 必须 {BEACON_LEN} 字节，实得 {}", pkt.len()),
            );
        }

        // 先清零输出：验签失败时调用方不该读到上一次的残留
        dst_prefix[..DEVICE_ID_PREFIX_LEN].fill(0);
        *out_ts = 0;
        *out_seq = 0;

        let parsed = crate::presence::beacon::BeaconPacket::from_bytes(pkt);
        let Some(parsed) = parsed else {
            return ERR_OK; // 长度/格式不符：不是我们的包
        };
        let Some((prefix, ts, seq)) = verify_beacon(secret, &parsed) else {
            return ERR_OK; // 签名不符：不是我们的设备
        };
        dst_prefix[..DEVICE_ID_PREFIX_LEN].copy_from_slice(&prefix);
        *out_ts = ts;
        *out_seq = seq;
        ERR_OK
    })
}

// ============================================================
// JSON 冷路径
// ============================================================

/// 通用 JSON 入口。
///
/// `method` 取下列之一，`args_json` 为该方法的参数，`out` 接收结果 JSON：
///
/// | method | 入参 | 出参 |
/// |---|---|---|
/// | `routes.list` | 忽略 | `[{method, path}, ...]` |
/// | `version.info` | 忽略 | `{protocolVersion, defaultPort, apiPrefix, routeCount}` |
/// | `sync.decide` | `{localNow, localSnapshot, peerNow, strategy}`（均为 [`crate::dto::sync`] 类型） | 完整的 `SyncDecision` |
/// | `policy.can` | `{action, ctx}` | `{enabled, reason}` |
/// | `discovery.scan_targets` | `{ifaces: [{ip, netmask}]}` | `["ip:port", ...]` |
///
/// 新增能力**只需在这里加一个 match 分支**，双端不必重新协商 ABI ——
/// 这正是把易变部分放在 JSON 之后的全部收益。
///
/// # Safety
/// `method` / `args_json` 必须是合法 C 字符串；`out` 必须可写。
#[no_mangle]
pub unsafe extern "C" fn lanbackup_invoke(
    method: *const c_char,
    args_json: *const c_char,
    out: *mut CVec,
) -> i32 {
    guard!({
        if out.is_null() {
            return set_error(ERR_NULL_PTR, "out 不得为空");
        }
        let method = match cstr_to_str(method) {
            Ok(s) => s,
            Err(c) => return c,
        };
        let args: serde_json::Value = match cstr_to_str(args_json) {
            Ok("") => serde_json::Value::Null,
            Ok(s) => match serde_json::from_str(s) {
                Ok(v) => v,
                Err(e) => return set_error(ERR_BAD_JSON, format!("参数 JSON 解析失败: {e}")),
            },
            Err(c) => return c,
        };

        let result = match method {
            "routes.list" => Ok(routes_json()),
            "version.info" => Ok(version_json()),
            "sync.decide" => sync_decide_json(&args),
            "policy.can" => policy_can_json(&args),
            "discovery.scan_targets" => scan_targets_json(&args),
            other => Err(set_error(
                ERR_UNKNOWN_METHOD,
                format!("未知的 method: {other}"),
            )),
        };

        match result {
            Ok(value) => {
                let bytes = match serde_json::to_vec(&value) {
                    Ok(b) => b,
                    Err(e) => return set_error(ERR_BAD_JSON, format!("结果序列化失败: {e}")),
                };
                *out = CVec::from_bytes(bytes);
                clear_error();
                ERR_OK
            }
            Err(code) => {
                *out = CVec::null();
                code
            }
        }
    })
}

fn routes_json() -> serde_json::Value {
    let all: Vec<serde_json::Value> = routes::ALL
        .iter()
        .map(|r| serde_json::json!({"method": r.method.as_str(), "path": r.path}))
        .collect();
    serde_json::Value::Array(all)
}

fn version_json() -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION,
        "defaultPort": DEFAULT_PORT,
        "apiPrefix": API_PREFIX,
        "routeCount": routes::ROUTE_COUNT,
    })
}

/// 三路增量决策。
///
/// 跨 FFI 暴露这一个入口，移动端就**不必**自己再实现一遍六个输出集合的划分 ——
/// 那正是三代并存时三份实现各跑各的、最终对不上的地方。
fn sync_decide_json(args: &serde_json::Value) -> Result<serde_json::Value, i32> {
    #[derive(serde::Deserialize)]
    struct Args {
        #[serde(rename = "localNow")]
        local_now: Manifest,
        /// 上次成功同步后的本机快照。**允许缺失**（首次同步尚无快照），
        /// 此时退化为两路对比：`heal_missing` 为空，只识别新增/变更。
        #[serde(rename = "localSnapshot")]
        local_snapshot: Option<Manifest>,
        #[serde(rename = "peerNow")]
        peer_now: Manifest,
        strategy: crate::dto::sync::SyncStrategy,
    }
    let a: Args = serde_json::from_value(args.clone())
        .map_err(|e| set_error(ERR_BAD_JSON, format!("sync.decide 参数错误: {e}")))?;

    let decision = sync::decide(
        &a.local_now,
        a.local_snapshot.as_ref(),
        &a.peer_now,
        a.strategy,
    );
    // SyncDecision 刻意不 derive Serialize：它是内部决策类型，
    // 序列化形状属于协议层（DTO），不该由算法层决定。这里显式拼装。
    Ok(serde_json::json!({
        "plan": decision.plan,
        "uploads": decision.uploads,
        "moveToDelete": decision.move_to_delete,
        "tombstoned": decision.tombstoned,
        "rejectedUnsafe": decision.rejected_unsafe,
        "strategy": decision.strategy,
        "isNoop": decision.is_noop(),
    }))
}

/// 按钮可用性裁决。
///
/// **UI 不得自己判断按钮能不能点** —— 一律问这里。这是 V4 的核心约束：
/// 非法操作给可读提示，而不是静默失败，更不能靠前端各写一套判据。
fn policy_can_json(args: &serde_json::Value) -> Result<serde_json::Value, i32> {
    #[derive(serde::Deserialize)]
    struct Args {
        action: UiAction,
        ctx: UiContext,
    }
    let a: Args = serde_json::from_value(args.clone())
        .map_err(|e| set_error(ERR_BAD_JSON, format!("policy.can 参数错误: {e}")))?;

    let Verdict { enabled, reason } = policy::can(a.action, &a.ctx);
    Ok(serde_json::json!({ "enabled": enabled, "reason": reason }))
}

fn scan_targets_json(args: &serde_json::Value) -> Result<serde_json::Value, i32> {
    #[derive(serde::Deserialize)]
    struct Iface {
        ip: std::net::Ipv4Addr,
        netmask: std::net::Ipv4Addr,
    }
    #[derive(serde::Deserialize)]
    struct Args {
        ifaces: Vec<Iface>,
    }
    let a: Args = serde_json::from_value(args.clone()).map_err(|e| {
        set_error(
            ERR_BAD_JSON,
            format!("discovery.scan_targets 参数错误: {e}"),
        )
    })?;

    let pairs: Vec<_> = a.ifaces.iter().map(|i| (i.ip, i.netmask)).collect();
    let targets = crate::discovery::scan_targets(&pairs, DEFAULT_PORT);
    Ok(serde_json::Value::Array(
        targets
            .iter()
            .map(|t| serde_json::json!(t.to_string()))
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presence::beacon::verify_beacon;
    use std::ffi::CString;

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn constants_are_exposed() {
        assert_eq!(lanbackup_protocol_version(), PROTOCOL_VERSION);
        assert_eq!(lanbackup_default_port(), DEFAULT_PORT);
        assert_eq!(lanbackup_route_count(), routes::ROUTE_COUNT);
    }

    #[test]
    fn beacon_sign_then_verify_roundtrips_over_the_abi() {
        let secret = b"pairing-secret";
        let prefix = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut buf = vec![0u8; BEACON_LEN];
        let rc = unsafe {
            lanbackup_beacon_sign(
                secret.as_ptr(),
                secret.len(),
                prefix.as_ptr(),
                prefix.len(),
                1700,
                42,
                buf.as_mut_ptr(),
                buf.len(),
            )
        };
        assert_eq!(rc, ERR_OK);

        // 用 core 自己的验证函数确认 ABI 产出的字节是真的合法 beacon
        let pkt = crate::presence::beacon::BeaconPacket::from_bytes(&buf).unwrap();
        let (p, ts, seq) = verify_beacon(secret, &pkt).unwrap();
        assert_eq!(p, prefix);
        assert_eq!(ts, 1700);
        assert_eq!(seq, 42);

        // 再从 ABI 反解一遍
        let mut out_prefix = [0u8; DEVICE_ID_PREFIX_LEN];
        let (mut out_ts, mut out_seq) = (0u32, 0u32);
        let rc = unsafe {
            lanbackup_beacon_verify(
                secret.as_ptr(),
                secret.len(),
                buf.as_ptr(),
                buf.len(),
                out_prefix.as_mut_ptr(),
                out_prefix.len(),
                &mut out_ts,
                &mut out_seq,
            )
        };
        assert_eq!(rc, ERR_OK);
        assert_eq!(out_prefix, prefix);
        assert_eq!(out_ts, 1700);
        assert_eq!(out_seq, 42);
    }

    /// 伪造的 beacon 必须**静默**判为不通过，而不是报错。
    #[test]
    fn wrong_secret_is_a_silent_no_not_an_error() {
        let prefix = [9u8; DEVICE_ID_PREFIX_LEN];
        let mut buf = vec![0u8; BEACON_LEN];
        assert_eq!(
            unsafe {
                lanbackup_beacon_sign(
                    b"real".as_ptr(),
                    4,
                    prefix.as_ptr(),
                    prefix.len(),
                    10,
                    1,
                    buf.as_mut_ptr(),
                    buf.len(),
                )
            },
            ERR_OK
        );

        let mut out_prefix = [0u8; DEVICE_ID_PREFIX_LEN];
        let (mut ts, mut seq) = (7u32, 7u32);
        let rc = unsafe {
            lanbackup_beacon_verify(
                b"wrong".as_ptr(),
                5,
                buf.as_ptr(),
                buf.len(),
                out_prefix.as_mut_ptr(),
                out_prefix.len(),
                &mut ts,
                &mut seq,
            )
        };
        assert_eq!(rc, ERR_OK, "验签失败是常态，不得报成错误");
        assert_eq!(ts, 0, "失败时输出必须清零，不得留上次的值");
        assert_eq!(seq, 0);
        assert_eq!(out_prefix, [0u8; DEVICE_ID_PREFIX_LEN]);
    }

    #[test]
    fn bad_lengths_are_reported_not_ignored() {
        let mut buf = vec![0u8; BEACON_LEN];
        let mut small = vec![0u8; 4];
        let prefix = [0u8; DEVICE_ID_PREFIX_LEN];

        assert_eq!(
            unsafe {
                lanbackup_beacon_sign(
                    b"k".as_ptr(),
                    1,
                    prefix.as_ptr(),
                    3,
                    0,
                    0,
                    buf.as_mut_ptr(),
                    buf.len(),
                )
            },
            ERR_BAD_LEN
        );
        assert_eq!(
            unsafe {
                lanbackup_beacon_sign(
                    b"k".as_ptr(),
                    1,
                    prefix.as_ptr(),
                    prefix.len(),
                    0,
                    0,
                    small.as_mut_ptr(),
                    small.len(),
                )
            },
            ERR_BUFFER_TOO_SMALL
        );
        assert_eq!(
            unsafe {
                lanbackup_beacon_sign(
                    std::ptr::null(),
                    0,
                    prefix.as_ptr(),
                    8,
                    0,
                    0,
                    buf.as_mut_ptr(),
                    buf.len(),
                )
            },
            ERR_OK,
            "空密钥视为空切片，HMAC 接受任意长度"
        );
    }

    #[test]
    fn error_message_is_retrievable() {
        let _ = unsafe {
            lanbackup_beacon_sign(
                std::ptr::null(),
                0,
                std::ptr::null(),
                8,
                0,
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_ne!(lanbackup_last_error_code(), ERR_OK);

        let len = lanbackup_last_error_len();
        assert!(len > 0);
        let mut buf = vec![0u8; len];
        assert_eq!(
            unsafe { lanbackup_last_error_message(buf.as_mut_ptr(), buf.len()) },
            ERR_OK
        );
        assert!(std::str::from_utf8(&buf).unwrap().len() == len);

        // 缓冲区不足要报错且不允许越界写
        let mut tiny = vec![0u8; 1];
        assert_eq!(
            unsafe { lanbackup_last_error_message(tiny.as_mut_ptr(), tiny.len()) },
            ERR_BUFFER_TOO_SMALL
        );
    }

    #[test]
    fn invoke_routes_list_and_version() {
        let mut v = CVec::null();
        let m = c("routes.list");
        let a = c("");
        assert_eq!(
            unsafe { lanbackup_invoke(m.as_ptr(), a.as_ptr(), &mut v) },
            ERR_OK
        );
        let s = unsafe { std::str::from_utf8(slice::from_raw_parts(v.ptr, v.len)).unwrap() };
        let parsed: serde_json::Value = serde_json::from_str(s).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), routes::ROUTE_COUNT);
        assert_eq!(parsed[0]["path"], "/api/v4/probe");
        assert_eq!(parsed[0]["method"], "GET");
        lanbackup_vec_free(v);

        let mut v = CVec::null();
        let m = c("version.info");
        assert_eq!(
            unsafe { lanbackup_invoke(m.as_ptr(), a.as_ptr(), &mut v) },
            ERR_OK
        );
        let s = unsafe { std::str::from_utf8(slice::from_raw_parts(v.ptr, v.len)).unwrap() };
        let parsed: serde_json::Value = serde_json::from_str(s).unwrap();
        assert_eq!(parsed["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(parsed["apiPrefix"], API_PREFIX);
        lanbackup_vec_free(v);
    }

    #[test]
    fn invoke_unknown_method_is_reported() {
        let mut v = CVec::null();
        let m = c("no.such.method");
        let a = c("{}");
        assert_eq!(
            unsafe { lanbackup_invoke(m.as_ptr(), a.as_ptr(), &mut v) },
            ERR_UNKNOWN_METHOD
        );
        assert!(v.ptr.is_null(), "失败时 out 必须是 null CVec");
        assert_eq!(lanbackup_last_error_code(), ERR_UNKNOWN_METHOD);
    }

    /// 按钮裁决必须能跨 FFI 问到 —— 移动端 UI 不得自造判据。
    #[test]
    fn invoke_policy_can_gates_the_connect_button() {
        let mut v = CVec::null();
        let m = c("policy.can");
        let args = c(
            r#"{"action":"connect","ctx":{"presence":"offline","connection":"disconnected","transfer":"idle","preferBasic":false}}"#,
        );
        assert_eq!(
            unsafe { lanbackup_invoke(m.as_ptr(), args.as_ptr(), &mut v) },
            ERR_OK
        );
        let s = unsafe { std::str::from_utf8(slice::from_raw_parts(v.ptr, v.len)).unwrap() };
        let parsed: serde_json::Value = serde_json::from_str(s).unwrap();
        assert_eq!(parsed["enabled"], false, "离线设备不允许连接");
        assert!(
            !parsed["reason"].as_str().unwrap().is_empty(),
            "禁用必须给可读原因，不能静默"
        );
        lanbackup_vec_free(v);
    }

    #[test]
    fn invoke_sync_decide_and_scan_targets() {
        // 空清单：应当是什么都不做的 noop
        let mut v = CVec::null();
        let m = c("sync.decide");
        let args = c(
            r#"{"localNow":{"version":1,"generatedAt":0,"deviceCode":"a","files":{}},"localSnapshot":null,"peerNow":{"version":1,"generatedAt":0,"deviceCode":"b","files":{}},"strategy":"archive"}"#,
        );
        assert_eq!(
            unsafe { lanbackup_invoke(m.as_ptr(), args.as_ptr(), &mut v) },
            ERR_OK
        );
        let s = unsafe { std::str::from_utf8(slice::from_raw_parts(v.ptr, v.len)).unwrap() };
        let parsed: serde_json::Value = serde_json::from_str(s).unwrap();
        assert_eq!(parsed["isNoop"], true);
        assert_eq!(parsed["uploads"].as_array().unwrap().len(), 0);
        lanbackup_vec_free(v);

        // 一个 /24 网段应当给出 253 个目标（去掉网络号、广播、本机）
        let mut v = CVec::null();
        let m = c("discovery.scan_targets");
        let args = c(r#"{"ifaces":[{"ip":"192.168.1.7","netmask":"255.255.255.0"}]}"#);
        assert_eq!(
            unsafe { lanbackup_invoke(m.as_ptr(), args.as_ptr(), &mut v) },
            ERR_OK
        );
        let s = unsafe { std::str::from_utf8(slice::from_raw_parts(v.ptr, v.len)).unwrap() };
        let parsed: serde_json::Value = serde_json::from_str(s).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 253);
        lanbackup_vec_free(v);
    }

    #[test]
    fn freeing_a_null_cvec_is_a_noop() {
        lanbackup_vec_free(CVec::null());
    }
}
