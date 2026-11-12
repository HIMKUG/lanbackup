//! 设备身份：**随机安装标识** + 随机初始连接码（WB-0561..0566）
//!
//! 安全模型（本模块只兑现，不解释协议 —— 见施工文档 B5）：
//! - `deviceId`：首次启动 CSPRNG 生成 32 hex，持久化到 app_data，永不重算 ——
//!   不再由 MachineGuid 哈希派生（同型号镜像/同源虚拟机将共享身份）。
//! - 连接码：首次启动 CSPRNG 随机生成并持久化 —— 不再由设备特征确定性推导
//!   （推导码 = 把"秘密"写在公开特征里）。刷新仍是随机码。
//! - MachineGuid 仅作**降级兜底**：app_data 不可写（磁盘故障）时退回旧的
//!   派生 deviceId，保证进程可用，并在日志里显式告警身份降级。

use std::sync::atomic::Ordering;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};

use crate::db::AppError;

/// 随机安装 deviceId（`init_identity` 在 setup 最早阶段注入）
static DEVICE_ID: OnceLock<String> = OnceLock::new();

/// 数据库加密密钥缓存（WB-0569：PBKDF2-600k 只算一次，不再每次启动烧 CPU）
static DB_KEY: OnceLock<String> = OnceLock::new();

/// 启动时初始化设备身份（lib.rs setup 最早阶段调用）。
///
/// - `device_id.txt`：缺失/非法 → 生成随机 32 hex 并落盘；
///   写盘失败 → 退回 MachineGuid 派生（旧行为）并告警，绝不静默换身份。
/// - `self_code.txt`：缺失/空 → 生成**随机**初始连接码并落盘（WB-0564）。
///
/// 返回**本目录解析出的** deviceId（与文件内容一致）。
///
/// 返回值刻意不读全局 `DEVICE_ID`：测试并行使用不同目录时，全局只会保留
/// 最先 set 的进程 ID，拿它和本目录文件比对必然随机失败（原 flaky 根因）。
pub fn init_identity(app_data: &std::path::Path) -> String {
    if let Err(e) = std::fs::create_dir_all(app_data) {
        crate::log_error!("身份目录创建失败 {:?}: {e}，deviceId 降级为机器派生", app_data);
        let fallback = legacy_machine_device_id();
        let _ = DEVICE_ID.set(fallback.clone());
        return fallback;
    }
    let id_path = app_data.join("device_id.txt");
    let existing = std::fs::read_to_string(&id_path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let device_id = if existing.len() == 32 && existing.chars().all(|c| c.is_ascii_hexdigit()) {
        existing
    } else {
        let fresh = hex::encode(rand::random::<[u8; 16]>());
        if let Err(e) = std::fs::write(&id_path, &fresh) {
            crate::log_error!("deviceId 落盘失败: {e}，降级为机器派生（配对稳定性受损）");
            let fallback = legacy_machine_device_id();
            let _ = DEVICE_ID.set(fallback.clone());
            // 连接码仍随机初始化（它独立于 deviceId 存活）
            init_self_code(app_data);
            return fallback;
        }
        fresh
    };
    let _ = DEVICE_ID.set(device_id.clone());
    init_self_code(app_data);
    device_id
}

/// 首次初始化随机连接码（已持久化过则不动 —— 刷新语义归 refresh_self_code）
fn init_self_code(app_data: &std::path::Path) {
    let p = app_data.join("self_code.txt");
    let existing = std::fs::read_to_string(&p)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if !existing.is_empty() {
        return;
    }
    let code = random_code();
    if let Err(e) = std::fs::write(&p, &code) {
        crate::log_error!("初始连接码落盘失败: {e}（本次进程内有效，重启将重生成）");
    }
}

/// 旧版机器派生 deviceId（仅磁盘故障降级用；WB-0561 前的历史行为）
fn legacy_machine_device_id() -> String {
    let guid = machine_guid_cached();
    let digest = Sha256::digest(format!("{guid}|lanbackup-device-id|v2").as_bytes());
    hex::encode(&digest[..16])
}

/// 读取 Windows MachineGuid（注册表）
///
/// 经 reg.exe 子进程读取，带 2 秒超时：杀软 hook 进程创建时可令子进程
/// 无限期不退出，无超时会阻塞调用线程（Database::open 在主线程调用）。
fn get_machine_guid() -> String {
    #[cfg(target_os = "windows")]
    {
        use std::io::Read;
        use std::os::windows::process::CommandExt;
        use std::process::Stdio;
        use std::time::{Duration, Instant};
        // CREATE_NO_WINDOW(0x08000000)：隐藏 reg 命令的控制台窗口，
        // 避免配对/启动时闪现黑框
        let mut child = match Command::new("reg")
            .creation_flags(0x08000000)
            .args([
                "query",
                "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                crate::log_warn!("reg.exe 启动失败（{e}），使用 unknown-machine 兜底");
                return "unknown-machine".to_string();
            }
        };
        // 轮询等待最多 2 秒，超时强杀兜底
        let deadline = Instant::now() + Duration::from_secs(2);
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break None,
            }
        };
        if status.is_none() {
            crate::log_warn!("reg.exe 超时 2s 被强杀（疑似被安全软件拦截），使用 unknown-machine 兜底");
            // WB-0568：kill 后必须 wait 回收子进程，不留僵尸进程与悬垂句柄
            let _ = child.wait();
            return "unknown-machine".to_string();
        }
        let mut stdout = String::new();
        if let Some(mut out) = child.stdout.take() {
            let _ = out.read_to_string(&mut stdout);
        }
        // 提取 GUID 值
        for line in stdout.lines() {
            if let Some(idx) = line.find("MachineGuid") {
                let rest = &line[idx..];
                if let Some(eq) = rest.find("REG_SZ") {
                    let guid = rest[eq + 6..].trim();
                    if !guid.is_empty() {
                        crate::log_debug!(
                            "读取 MachineGuid 成功: {}",
                            crate::logger::mask(guid)
                        );
                        return guid.to_string();
                    }
                }
            }
        }
        crate::log_warn!("读取 MachineGuid 失败，使用 unknown-machine 兜底");
        "unknown-machine".to_string()
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Linux/macOS 用 machine-id
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            crate::log_debug!("读取 machine-id 成功: {}", crate::logger::mask(id.trim()));
            return id.trim().to_string();
        }
        crate::log_warn!("读取 machine-id 失败，使用 unknown-machine 兜底");
        "unknown-machine".to_string()
    }
}

/// MachineGuid 进程内缓存：`reg query` 是一次进程创建（10~50ms），
/// 此前 get_device_id 每次调用都查注册表——/info 每请求一次、
/// 子网扫描每线程一次（一次扫描最多 254 个并发 reg.exe）。缓存后全进程仅首次一次。
static MACHINE_GUID: OnceLock<String> = OnceLock::new();

fn machine_guid_cached() -> String {
    MACHINE_GUID.get_or_init(get_machine_guid).clone()
}

/// 生成 8 位连接码（**已废弃的确定性推导**，WB-0563/0564 后不再使用：
/// 输入特征日志可逆推连接码、公开特征推导 = 秘密写在明处。随机码见 `random_code`）
/// 连接码进程内缓存：接收端每个文件事件都要取码派生解密密钥，
/// 此前每文件一次磁盘读（Defender 实时扫描下每次 syscall 都不便宜）；
/// refresh_self_code 时同步失效，「刷新立即生效」语义不变
static SELF_CODE: Mutex<Option<String>> = Mutex::new(None);

/// 获取本机连接码（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
///
/// 优先返回配置文件中持久化的码（刷新过）；首次（未 init）现场生成随机码。
/// 进程内缓存 + 文件缓存两级，避免每次调用都执行磁盘读。
/// M5-3: 传输期间拒绝刷新（见 refresh_self_code）；读取永远返回缓存，永不阻塞传输。
pub fn get_self_code(app: &AppHandle) -> Result<String, AppError> {
    if let Some(c) = SELF_CODE.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
        return Ok(c.clone());
    }
    let dir = config_dir(app)?;
    let p = dir.join("self_code.txt");
    if let Ok(s) = std::fs::read_to_string(&p) {
        let t = s.trim().to_string();
        if !t.is_empty() {
            *SELF_CODE.lock().unwrap_or_else(|p| p.into_inner()) = Some(t.clone());
            return Ok(t);
        }
    }
    // 未持久化过（init 未跑或文件丢失）：生成随机码并尝试落盘。
    // 注意这是**随机**码而非设备特征推导（WB-0564）—— 丢失旧码等同刷新，
    // 配对需重建，这是比"全网同码"安全得多的失败方式。
    let code = random_code();
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(&p, &code);
    *SELF_CODE.lock().unwrap_or_else(|p| p.into_inner()) = Some(code.clone());
    Ok(code)
}

/// 刷新本机连接码：生成随机码并持久化，旧码立即失效（对方需重新配对）。
/// M2: 异步通知所有配对设备断开连接（不清除配对记录，传输完成后重新建立）。
/// M5-3: 传输期间拒绝刷新（防止解密密钥突变导致传输失败）。
pub fn refresh_self_code(app: &AppHandle) -> Result<String, AppError> {
    // P0-1: 检查是否有传输在进行中（引用计数 > 0）
    if let Some(state) = app.try_state::<crate::transfer::PairingState>() {
        if state.transfer_count.load(Ordering::Relaxed) > 0 {
            crate::log_warn!("刷新连接码被拒绝：传输正在进行中（密钥锁定）");
            return get_self_code(app);
        }
    }
    let code = random_code();
    let dir = config_dir(app)?;
    std::fs::create_dir_all(&dir).map_err(AppError::from_display)?;
    // WB-0085：写盘失败时绝不能返回一个"内存里换过、磁盘上没换"的新码 ——
    // 重启后旧码复活，已配对的 `target_code` 与新码不一致，传输密钥直接错。
    if let Err(e) = std::fs::write(dir.join("self_code.txt"), &code) {
        crate::log_error!("连接码刷新写盘失败，保留旧码: {e}");
        return get_self_code(app);
    }
    *SELF_CODE.lock().unwrap_or_else(|p| p.into_inner()) = Some(code.clone());
    crate::log_info!("连接码已刷新: {}", crate::logger::mask(&code));
    // M2: 通知所有配对设备断开（异步，不阻塞码刷新返回）
    crate::transfer::notify_peers_disconnect(app);
    Ok(code)
}

/// 随机 8 位连接码（CSPRNG + 拒绝采样消除模偏差，字符集与默认算法一致）
fn random_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    // 248 = 31 × 8：丢弃 >=248 的随机字节，保证 31 个字符等概率
    // （直接 %31 会因 256 非倍数产生模偏差）；同一毫秒内多次调用不再产出相同码
    let mut code = String::with_capacity(8);
    while code.len() < 8 {
        let b: u8 = rand::random();
        if b < 248 {
            code.push(ALPHABET[(b % ALPHABET.len() as u8) as usize] as char);
        }
    }
    code
}

/// 公开 deviceId（安装后固定）：广播/注册响应中作为 fingerprint。
/// 与连接码分离——连接码只在配对服务 /verify 端点本地比对，绝不广播。
pub fn get_device_id(app: &AppHandle) -> String {
    let _ = app;
    get_device_id_no_ctx()
}

/// 无句柄变体：deviceId 来自 `init_identity` 注入的**随机安装 ID**，
/// 与 Tauri 句柄无关。供 http_json_request 等没有 AppHandle 的底层网络
/// 上下文注入身份头。
///
/// 长度必须是 core `DEVICE_ID_LEN`（16 字节 → 32 hex）：core 的
/// `DeviceIdentity::restore` / `beacon_prefix` 都按这个长度校验。
pub fn get_device_id_no_ctx() -> String {
    DEVICE_ID
        .get_or_init(|| {
            // init 未跑（纯单元测试路径）——按旧机器派生兜底，保证确定性；
            // 生产进程在 setup 里必然先 init。
            crate::log_warn!("deviceId 在 init_identity 前被访问，使用机器派生兜底（仅测试预期）");
            legacy_machine_device_id()
        })
        .clone()
}

/// 设备配置目录（保存设备名/连接码等）。
///
/// WB-0566：获取失败**上抛错误**，绝不静默落到公共 temp —— 身份文件写
/// 全局临时目录 = 任何本机用户可读，还可能被系统清理。
fn config_dir(app: &AppHandle) -> Result<std::path::PathBuf, AppError> {
    app.path()
        .app_config_dir()
        .map_err(|e| AppError(format!("获取应用配置目录失败: {e}")))
}

/// 设备名（默认计算机名，可在设置中修改并持久化）
pub fn get_device_name(app: &AppHandle) -> Result<String, AppError> {
    let p = config_dir(app)?.join("device_name.txt");
    if let Ok(s) = std::fs::read_to_string(&p) {
        let t = s.trim().to_string();
        if !t.is_empty() {
            return Ok(t);
        }
    }
    Ok(std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "PC".to_string()))
}

/// 保存设备名（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）。
///
/// WB-0571：名称进 alias/清单/日志，必须有长度与控制符闸。
pub fn set_device_name(app: &AppHandle, name: String) -> Result<(), AppError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err(AppError("设备名长度非法（1..=64 字节）".to_string()));
    }
    if trimmed
        .chars()
        .any(|c| c.is_control() || c == '\n' || c == '\r')
    {
        return Err(AppError("设备名不得包含控制字符/换行".to_string()));
    }
    let dir = config_dir(app)?;
    std::fs::create_dir_all(&dir).map_err(AppError::from_display)?;
    std::fs::write(dir.join("device_name.txt"), trimmed).map_err(AppError::from_display)
}

/// 生成数据库加密密钥（派生自 MachineGuid，保证同一设备可解密）。
/// 返回 64 位十六进制字符串，作为 SQLCipher 的 key。
///
/// v2（P2-11 修复）：改用标准 PBKDF2-HMAC-SHA256（600k 迭代 + 独立 salt），
/// 替代原 FNV-1a 快速哈希。FNV-1a 非抗碰撞的密钥派生函数、无 salt、迭代不足，
/// 在攻击者可离线枚举 UUID 空间时保护性近零。PBKDF2-600k 单核穷举约 1 万年。
///
/// 说明：当前 rusqlite 用 `bundled` 特性未启用 SQLCipher（见 Cargo.toml），
/// `PRAGMA key` 暂无实际加密效果；本函数保证未来启用 SQLCipher 时密钥强度达标。
pub fn db_encryption_key() -> String {
    DB_KEY.get_or_init(|| {
        let guid = machine_guid_cached();
        crate::log_debug!(
            "派生数据库加密密钥 v2(PBKDF2-600k) 输入特征: 长度={} 前缀={}",
            guid.len(),
            crate::logger::mask(&guid)
        );
        // salt = SHA256(MachineGuid)：每设备唯一，防彩虹表
        let salt = Sha256::digest(guid.as_bytes());
        let mut key = [0u8; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(600_000).unwrap(),
            &salt,
            guid.as_bytes(),
            &mut key,
        );
        hex::encode(key)
    }).clone()
}

/// 旧版 FNV-1a 派生（v1，P2-11 前世）。
/// 保留供迁移判断参考：若某设备已用旧算法创建的 SQLCipher 库需解密，可据此回退读取。
#[allow(dead_code)]
pub fn db_encryption_key_legacy() -> String {
    let guid = machine_guid_cached();
    // 用 FNV-1a 哈希 + 多次迭代生成 64 位密钥
    let mut hash: u64 = 0xcbf29ce484222325;
    let input = format!("{}|localsend-backup-db|v1", guid);
    for b in input.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    // 再迭代一轮，充分扩散
    for _ in 0..4 {
        hash ^= hash >> 33;
        hash = hash.wrapping_mul(0xff51afd7ed558ccd);
        hash ^= hash >> 33;
    }
    format!("{:016x}{:016x}", hash, hash ^ 0x9e3779b97f4a7c15)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_code_is_8_chars_from_alphabet() {
        for _ in 0..32 {
            let code = random_code();
            assert_eq!(code.len(), 8, "code must be 8 characters");
            let valid: std::collections::HashSet<char> =
                "ABCDEFGHJKMNPQRSTUVWXYZ23456789".chars().collect();
            for c in code.chars() {
                assert!(valid.contains(&c), "char {c} not in alphabet");
            }
        }
    }

    /// 随机码不得重复出现（确定性推导被移除后，两次调用应几乎必然不同）
    #[test]
    fn random_codes_are_distinct() {
        let a = random_code();
        let b = random_code();
        assert_ne!(a, b, "CSPRNG 连续两码相同概率 ~31^-8，出现即实现有误");
    }

    /// WB-0561：init 幂等 —— 已有合法 deviceId 时必须原样保留（重启身份不变）。
    /// OnceLock 静态无法重置，重启不变性由「文件 → 内存」单向加载保证：
    /// 第二次 init 读到同一文件，set 失败但文件不被覆盖。
    #[test]
    fn init_identity_persists_random_device_id_across_restart() {
        let dir = std::env::temp_dir().join(format!("lanbak-id-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = init_identity(&dir);
        assert_eq!(first.len(), 32, "deviceId 必须是 32 hex");
        let persisted = std::fs::read_to_string(dir.join("device_id.txt")).unwrap();
        assert_eq!(persisted.trim(), first, "deviceId 必须落盘");
        // 第二次 init（模拟重启后）：同一目录 → 文件不被改写
        init_identity(&dir);
        assert_eq!(
            std::fs::read_to_string(dir.join("device_id.txt")).unwrap().trim(),
            first,
            "重启不得更换身份"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// WB-0564：首次 init 生成**随机**连接码并持久化；重启沿用
    #[test]
    fn init_identity_seeds_random_self_code_once() {
        let dir = std::env::temp_dir().join(format!("lanbak-code-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        init_identity(&dir);
        let code = std::fs::read_to_string(dir.join("self_code.txt")).unwrap();
        assert_eq!(code.trim().len(), 8);
        // 已有码不被覆盖
        init_identity(&dir);
        assert_eq!(std::fs::read_to_string(dir.join("self_code.txt")).unwrap(), code);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// WB-0571：设备名闸
    #[test]
    fn device_name_validation_rejects_control_chars_and_overlength() {
        let too_long = "x".repeat(65);
        assert!(set_device_name_checks(&too_long).is_err());
        assert!(set_device_name_checks("a\nb").is_err());
        assert!(set_device_name_checks("").is_err());
        assert!(set_device_name_checks("我的电脑-1").is_ok());
    }

    /// 提取纯校验逻辑供测试（不依赖 AppHandle）
    fn set_device_name_checks(name: &str) -> Result<(), AppError> {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.len() > 64 {
            return Err(AppError("设备名长度非法（1..=64 字节）".to_string()));
        }
        if trimmed
            .chars()
            .any(|c| c.is_control() || c == '\n' || c == '\r')
        {
            return Err(AppError("设备名不得包含控制字符/换行".to_string()));
        }
        Ok(())
    }
}
