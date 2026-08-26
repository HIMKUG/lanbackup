//! 设备身份：基于 Windows MachineGuid 生成永久连接码 + 公开设备标识

use std::sync::atomic::Ordering;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};

use crate::db::AppError;

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

/// 生成 8 位连接码（与 shared-core 的 identity.ts 算法一致）
fn generate_code(stable_id: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    const LEN: usize = 8;

    crate::log_debug!(
        "生成连接码 输入特征: 长度={} 前缀={}",
        stable_id.len(),
        crate::logger::mask(stable_id)
    );

    // FNV-1a 32-bit
    let mut hash: u32 = 0x811c9dc5;
    let input = format!("{}|localsend-backup|v1", stable_id);
    for b in input.bytes() {
        // u8 → u32 宽化，无截断风险
        hash ^= u32::from(b);
        hash = hash.wrapping_mul(0x01000193);
    }

    let mut seed = hash;
    let mut code = String::new();
    for _ in 0..LEN {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        // SAFETY: ALPHABET.len() = 31，远小于 u32::MAX，as u32 安全。
        // 取模结果 < 31，as usize 用于索引安全。
        let idx = (seed % ALPHABET.len() as u32) as usize;
        // SAFETY: ALPHABET 全是 ASCII 字符 (A-Z, 2-9)，u8 as char 安全。
        code.push(ALPHABET[idx] as char);
    }
    crate::log_info!(
        "连接码生成完成: {}（哈希种子={:08x}）",
        crate::logger::mask(&code),
        hash
    );
    code
}

/// 连接码进程内缓存：接收端每个文件事件都要取码派生解密密钥，
/// 此前每文件一次磁盘读（Defender 实时扫描下每次 syscall 都不便宜）；
/// refresh_self_code 时同步失效，「刷新立即生效」语义不变
static SELF_CODE: Mutex<Option<String>> = Mutex::new(None);

/// 获取本机连接码（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
///
/// 优先返回配置文件中持久化的码（刷新过）；否则按设备号计算并缓存到文件。
/// 进程内缓存 + 文件缓存两级，避免每次调用都执行注册表查询/磁盘读。
/// M5-3: 传输期间拒绝刷新（见 refresh_self_code）；读取永远返回缓存，永不阻塞传输。
pub fn get_self_code(app: &AppHandle) -> String {
    if let Some(c) = SELF_CODE.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
        return c.clone();
    }
    let dir = config_dir(app);
    let p = dir.join("self_code.txt");
    if let Ok(s) = std::fs::read_to_string(&p) {
        let t = s.trim().to_string();
        if !t.is_empty() {
            *SELF_CODE.lock().unwrap_or_else(|p| p.into_inner()) = Some(t.clone());
            return t;
        }
    }
    let code = generate_code(&machine_guid_cached());
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(&p, &code);
    *SELF_CODE.lock().unwrap_or_else(|p| p.into_inner()) = Some(code.clone());
    code
}

/// 刷新本机连接码：生成随机码并持久化，旧码立即失效（对方需重新配对）。
/// M2: 异步通知所有配对设备断开连接（不清除配对记录，传输完成后重新建立）。
/// M5-3: 传输期间拒绝刷新（防止解密密钥突变导致传输失败）。
pub fn refresh_self_code(app: &AppHandle) -> String {
    // P0-1: 检查是否有传输在进行中（引用计数 > 0）
    if let Some(state) = app.try_state::<crate::transfer::PairingState>() {
        if state.transfer_count.load(Ordering::Relaxed) > 0 {
            crate::log_warn!("刷新连接码被拒绝：传输正在进行中（密钥锁定）");
            return get_self_code(app);
        }
    }
    let code = random_code();
    let dir = config_dir(app);
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join("self_code.txt"), &code);
    *SELF_CODE.lock().unwrap_or_else(|p| p.into_inner()) = Some(code.clone());
    crate::log_info!("连接码已刷新: {}", crate::logger::mask(&code));
    // M2: 通知所有配对设备断开（异步，不阻塞码刷新返回）
    crate::transfer::notify_peers_disconnect(app);
    code
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

/// 本机公开指纹码（`v3-` + deviceId 前 8 位）。
/// 手机端在无配对 secret 时用 `SHA-256(targetCode)` 回退加密，
/// 其中 targetCode 即对端的指纹码（如 `v3-8eeea519`）。
/// 本函数用于接收端回退解密时用同一口径派生候选密钥，消除"密钥不匹配"全灭问题。
pub fn get_self_fingerprint_code(app: &AppHandle) -> String {
    let id = get_device_id(app);
    let prefix: String = id.chars().take(8).collect();
    format!("v3-{prefix}")
}

/// 无句柄变体：deviceId 仅由 MachineGuid 派生，与 Tauri 句柄无关。
/// 供 http_json_request 等没有 AppHandle 的底层网络上下文注入身份头。
pub fn get_device_id_no_ctx() -> String {
    let guid = machine_guid_cached();
    let mut h: u64 = 0xcbf29ce484222325;
    let input = format!("{guid}|lanbackup-device-id|v1");
    for b in input.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

/// 设备配置目录（保存设备名等）
fn config_dir(app: &AppHandle) -> std::path::PathBuf {
    app.path()
        .app_config_dir()
        .unwrap_or_else(|_| std::env::temp_dir())
}

/// 设备名（默认计算机名，可在设置中修改并持久化）
pub fn get_device_name(app: &AppHandle) -> String {
    let p = config_dir(app).join("device_name.txt");
    if let Ok(s) = std::fs::read_to_string(&p) {
        let t = s.trim().to_string();
        if !t.is_empty() {
            return t;
        }
    }
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "PC".to_string())
}

/// 保存设备名（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
pub fn set_device_name(app: &AppHandle, name: String) -> Result<(), AppError> {
    let dir = config_dir(app);
    std::fs::create_dir_all(&dir).map_err(AppError::from_display)?;
    std::fs::write(dir.join("device_name.txt"), name.trim()).map_err(AppError::from_display)
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
    fn same_input_produces_same_code() {
        let a = generate_code("machine-guid-abc");
        let b = generate_code("machine-guid-abc");
        assert_eq!(a, b, "same stable_id must produce same code");
    }

    #[test]
    fn different_input_produces_different_code() {
        let a = generate_code("device-a");
        let b = generate_code("device-b");
        assert_ne!(a, b, "different stable_ids must produce different codes");
    }

    #[test]
    fn code_is_8_chars_from_alphabet() {
        let code = generate_code("test-id");
        assert_eq!(code.len(), 8, "code must be 8 characters");
        let valid: std::collections::HashSet<char> =
            "ABCDEFGHJKMNPQRSTUVWXYZ23456789".chars().collect();
        for c in code.chars() {
            assert!(valid.contains(&c), "char {c} not in alphabet");
        }
    }

    #[test]
    fn unknown_machine_fallback_produces_valid_code() {
        let code = generate_code("unknown-machine");
        assert_eq!(code.len(), 8);
    }
}
