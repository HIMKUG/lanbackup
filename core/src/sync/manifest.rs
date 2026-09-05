//! 清单归一化与路径安全（阶段 4）
//!
//! # 为什么归一化必须在**比较之前**
//!
//! 清单的 key 是相对路径，而平台层给出的写法五花八门：
//! Windows 给 `.\sub\file.txt`，Android SAF 给 `sub/file.txt`，
//! 目录条目可能带尾斜杠 `dir/`。不归一化，同一个文件在两端清单里就是
//! 两个不同的 key，三路对比的结论直接失效 —— 表现为「每次同步都判定全部新增，
//! 无限全量重传」（原 `manifest.ts:43-51`）。
//!
//! 归一化规则（幂等）：统一 `/` 分隔 → 丢弃空段与 `.` 段 → 无首尾斜杠。
//!
//! # 为什么**不**解析 `..`
//!
//! 解析 `..` 等于替攻击者把路径穿越算好。接收端拿到 `relPath` 会直接拼
//! `rootDir + relPath` 落盘，一个 `../../.ssh/authorized_keys` 就能写到备份根之外。
//! 因此这里**保留** `..` 段，再由 [`is_safe_rel_path`] 一票否决 ——
//! 让不安全的路径显式地"过不了闸"，而不是被悄悄改写成另一个路径。

use std::collections::HashMap;

use crate::dto::sync::{Manifest, ManifestEntry};

/// 假删除目录名。`moveToDelete` 把文件挪到这里，**不真删**。
pub const DELETE_DIR: &str = "delete";

/// 归一化一个相对路径。幂等：`normalize(normalize(p)) == normalize(p)`。
pub fn normalize_rel_path(raw: &str) -> String {
    let unified = raw.replace('\\', "/");
    unified
        .split('/')
        .filter(|seg| !seg.is_empty() && *seg != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// 路径是否可安全落盘。
///
/// 拒绝三类：
/// 1. 空路径 —— 拼出来就是备份根本身。
/// 2. 含 `..` 段 —— 路径穿越。
/// 3. 带盘符（`C:`）或归一化后仍以 `/` 开头 —— 绝对路径伪装成相对路径。
///
/// **必须在写盘前调用**，且必须在归一化之后调用（否则 `.\..\x` 混过检查）。
pub fn is_safe_rel_path(normalized: &str) -> bool {
    if normalized.is_empty() || normalized.starts_with('/') {
        return false;
    }
    normalized
        .split('/')
        .all(|seg| seg != ".." && !(seg.len() == 2 && seg.ends_with(':')))
}

/// 是否位于假删除目录之下。
///
/// **镜像模式的死循环就卡在这一步**：`moveToDelete` 之后文件仍在 `delete/` 里，
/// 若把它算作"对端多余文件"，下一轮又要求删除，用户就会看到确认框无限弹出
/// （原 `sync.ts:131-137`，实测问题 5）。
pub fn is_in_delete_dir(normalized: &str) -> bool {
    normalized == DELETE_DIR || normalized.starts_with(&format!("{DELETE_DIR}/"))
}

/// 一个相对路径对应的墓碑路径（`delete/<path>`）。
///
/// 对端把文件挪进 `delete/` 表示**用户有意删除**；自愈补全必须跳过它，
/// 否则备份工具会把用户刚删掉的东西复活，用户就永远删不掉东西了。
pub fn tombstone_path(normalized: &str) -> String {
    format!("{DELETE_DIR}/{normalized}")
}

/// 归一化整份清单的 key。
///
/// 同一归一化 key 出现多次时（例如平台同时给出 `a/b` 与 `./a/b`），
/// 保留 **mtime 更新** 的那条 —— 旧条目大概率是扫描过程中的陈旧快照。
pub fn normalize_manifest(m: &Manifest) -> Manifest {
    let mut files: HashMap<String, ManifestEntry> = HashMap::with_capacity(m.files.len());
    for (path, entry) in &m.files {
        let key = normalize_rel_path(path);
        if key.is_empty() {
            continue;
        }
        match files.get(&key) {
            Some(existing) if existing.mtime >= entry.mtime => {}
            _ => {
                files.insert(
                    key,
                    ManifestEntry {
                        size: entry.size,
                        mtime: entry.mtime,
                    },
                );
            }
        }
    }
    Manifest {
        version: m.version,
        generated_at: m.generated_at,
        device_id: m.device_id.clone(),
        files,
    }
}

/// 从平台扫描结果直接构建**已归一化**的清单。
///
/// `device_id` 必须是设备的公开指纹（M2：**绝不是连接码** —— 连接码进任何
/// 响应体都会被局域网嗅探者拿到明文加密密钥）。线格式仍序列化为 `deviceCode`，
/// 只是历史命名，值必须是 deviceId。
pub fn build_manifest<I>(device_id: &str, generated_at: i64, entries: I) -> Manifest
where
    I: IntoIterator<Item = (String, ManifestEntry)>,
{
    let raw = Manifest {
        version: 1,
        generated_at,
        device_id: device_id.to_string(),
        files: entries.into_iter().collect(),
    };
    normalize_manifest(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(size: u64, mtime: i64) -> ManifestEntry {
        ManifestEntry { size, mtime }
    }

    #[test]
    fn normalizes_windows_and_dot_prefixes() {
        assert_eq!(normalize_rel_path(r".\sub\file.txt"), "sub/file.txt");
        assert_eq!(normalize_rel_path("./sub/file.txt"), "sub/file.txt");
        assert_eq!(normalize_rel_path("sub//file.txt"), "sub/file.txt");
        assert_eq!(normalize_rel_path("dir/"), "dir");
        assert_eq!(normalize_rel_path("/abs/path"), "abs/path");
        assert_eq!(normalize_rel_path(r"a\b/c\d"), "a/b/c/d");
    }

    #[test]
    fn normalization_is_idempotent() {
        for raw in [r".\a\b\", "//a//b//", "./a/./b", "a/b"] {
            let once = normalize_rel_path(raw);
            assert_eq!(normalize_rel_path(&once), once, "对 {raw} 不幂等");
        }
    }

    #[test]
    fn traversal_is_rejected_not_resolved() {
        // 关键：`..` 必须被保留下来然后被拒，而不是被解析掉
        let n = normalize_rel_path("../../etc/passwd");
        assert_eq!(n, "../../etc/passwd");
        assert!(!is_safe_rel_path(&n));

        assert!(!is_safe_rel_path(&normalize_rel_path(r"a\..\..\b")));
        assert!(!is_safe_rel_path(&normalize_rel_path("C:/Windows/x")));
        assert!(!is_safe_rel_path(""));
        assert!(is_safe_rel_path("a/b/c.txt"));
        // 三个点不是穿越，是合法文件名
        assert!(is_safe_rel_path("a/.../b"));
        // 单个点段已在归一化时消失，不该被误判
        assert!(is_safe_rel_path(&normalize_rel_path("./a/./b")));
    }

    #[test]
    fn delete_dir_detection_covers_both_separators() {
        assert!(is_in_delete_dir(&normalize_rel_path("delete/x.txt")));
        assert!(is_in_delete_dir(&normalize_rel_path(r"delete\x.txt")));
        assert!(is_in_delete_dir("delete"));
        // 前缀相同但不是同一目录，不能误伤
        assert!(!is_in_delete_dir("deleted/x.txt"));
        assert!(!is_in_delete_dir("a/delete/x.txt"));
    }

    #[test]
    fn tombstone_path_is_recognized_as_delete_dir() {
        let t = tombstone_path("photos/a.jpg");
        assert_eq!(t, "delete/photos/a.jpg");
        assert!(is_in_delete_dir(&t));
    }

    #[test]
    fn duplicate_keys_collapse_keeping_newer_mtime() {
        let m = Manifest {
            files: HashMap::from([
                (r".\a\b.txt".to_string(), entry(10, 100)),
                ("a/b.txt".to_string(), entry(20, 500)),
            ]),
            ..Default::default()
        };
        let n = normalize_manifest(&m);
        assert_eq!(n.files.len(), 1, "归一化后必须合并成一个 key");
        let e = n.files.get("a/b.txt").unwrap();
        assert_eq!((e.size, e.mtime), (20, 500), "应保留 mtime 更新的那条");
    }

    #[test]
    fn build_manifest_normalizes_and_preserves_metadata() {
        let m = build_manifest("dev-1", 1700, [(r".\x\y.bin".to_string(), entry(7, 8))]);
        assert_eq!(m.device_id, "dev-1");
        assert_eq!(m.generated_at, 1700);
        assert_eq!(m.version, 1);
        assert!(m.files.contains_key("x/y.bin"));
    }

    /// M2：序列化产物里**只有** `deviceCode` 一处设备标识键，且值必须是传入的
    /// deviceId —— 连接码是加密密钥材料，一旦混进任何响应体就会被局域网嗅探者
    /// 拿到明文密钥。此测试锁住 wire schema：顶层键集合不允许悄悄长出第二个
    /// code 字段（平台层误把连接码塞进来时，这里会先于联调暴露问题）。
    #[test]
    fn serialized_manifest_has_no_extra_code_field() {
        let m = build_manifest("dev-9f3a", 1700, [("a.txt".to_string(), entry(1, 1))]);
        let v: serde_json::Value = serde_json::to_value(&m).unwrap();
        let obj = v.as_object().unwrap();
        let mut keys: Vec<&String> = obj.keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["deviceCode", "files", "generatedAt", "version"],
            "wire schema 长出新的顶层键：设备标识必须只有 deviceCode 一处"
        );
        assert_eq!(
            v["deviceCode"],
            serde_json::json!("dev-9f3a"),
            "deviceCode 值必须是设备公开指纹，绝不能是连接码"
        );
    }
}
