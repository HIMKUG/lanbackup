//! 设备身份：基于 Windows MachineGuid 生成永久连接码 + 公开设备标识

use std::process::Command;
use std::sync::{Mutex, OnceLock};
use tauri::{AppHandle, Manager};

use crate::db::AppError;

/// 读取 Windows MachineGuid（注册表）
fn get_machine_guid() -> String {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW(0x08000000)：隐藏 reg 命令的控制台窗口，
        // 避免配对/启动时闪现黑框
        let output = Command::new("reg")
            .creation_flags(0x08000000)
            .args([
                "query",
                "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output();
        if let Ok(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            // 提取 GUID 值
            for line in text.lines() {
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

/// 刷新本机连接码：生成随机码并持久化，旧码立即失效（对方需重新配对）
pub fn refresh_self_code(app: &AppHandle) -> String {
    let code = random_code();
    let dir = config_dir(app);
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join("self_code.txt"), &code);
    *SELF_CODE.lock().unwrap_or_else(|p| p.into_inner()) = Some(code.clone());
    crate::log_info!("连接码已刷新: {}", crate::logger::mask(&code));
    code
}

/// 随机 8 位连接码（LCG 伪随机，字符集与默认算法一致）
fn random_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    let mut seed = nanos ^ (pid << 32);
    let mut code = String::new();
    for _ in 0..8 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let idx = ((seed >> 33) % ALPHABET.len() as u128) as usize;
        code.push(ALPHABET[idx] as char);
    }
    code
}

/// 公开 deviceId（安装后固定）：广播/注册响应中作为 fingerprint。
/// 与连接码分离——连接码只在配对服务 /verify 端点本地比对，绝不广播。
pub fn get_device_id(_app: &AppHandle) -> String {
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
pub fn db_encryption_key() -> String {
    let guid = machine_guid_cached();
    crate::log_debug!(
        "派生数据库加密密钥 输入特征: 长度={} 前缀={}",
        guid.len(),
        crate::logger::mask(&guid)
    );
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
