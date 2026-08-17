//! SQLite 加密存储
//!
//! 电脑端状态用 SQLite 存储，每配对设备一份记录。
//! 使用 rusqlite + bundled SQLite，数据存 App 数据目录。
//!
//! SAFETY: `conn` 用 `Mutex` 包裹，因为 `rusqlite::Connection` 是 `!Sync`，
//! 而 Tauri 的 `State` 要求 `Send + Sync`。Mutex 使其满足约束。
//! Tauri 命令是同步的（非 async），锁仅在单次数据库操作期间短暂持有，无死锁风险。

use rusqlite::{Connection, params};
use serde_json::Value;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

/// 应用错误类型。序列化为纯字符串，与前端 `invoke` 错误格式兼容。
#[derive(Debug)]
pub struct AppError(pub String);

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AppError {}

impl serde::Serialize for AppError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl AppError {
    /// 从任何实现了 Display 的错误创建 AppError
    pub(crate) fn from_display(e: impl std::fmt::Display) -> Self {
        AppError(e.to_string())
    }

    /// 从 Mutex 中毒错误创建可读的 AppError
    pub(crate) fn from_poison() -> Self {
        AppError("数据库内部错误，请重启应用".to_string())
    }
}

/// 数据库封装：持有文件路径与密钥，**每次操作打开独立连接**。
/// 多线程优化：`Mutex<Connection>` 会把所有数据库操作串行化（读写互斥）；
/// 每操作新连接 + WAL 模式下多线程完全并行（读不阻塞写），无共享锁竞争。
/// SQLite open 开销约 100µs，对本项目低频 DB 操作可忽略。
pub struct Database {
    path: PathBuf,
    key: String,
}

impl Database {
    /// 打开（或创建）数据库：验证可连接 + 建表 + 启用 WAL
    pub fn open(app: &AppHandle) -> Result<Self, AppError> {
        let dir: PathBuf = app
            .path()
            .app_data_dir()
            .map_err(AppError::from_display)?;
        std::fs::create_dir_all(&dir).map_err(AppError::from_display)?;
        let db_path = dir.join("backup.db");
        let key = crate::identity::db_encryption_key();
        // 打开一次验证 + 初始化 schema（后续每操作打开连接复用相同配置）
        {
            let conn = Connection::open(&db_path).map_err(AppError::from_display)?;
            // SQLCipher 加密：设置密钥。密钥派生自本机 MachineGuid，保证同一设备可解密。
            conn.pragma_update(None, "key", &key)
                .map_err(AppError::from_display)?;
            // WAL 模式：读写并行（读不阻塞写），配合多线程命令层减少锁竞争
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA busy_timeout=3000;
                 CREATE TABLE IF NOT EXISTS devices (
                    connection_code TEXT PRIMARY KEY,
                    device_name TEXT NOT NULL,
                    state_json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS transfer_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    direction TEXT NOT NULL,
                    peer TEXT NOT NULL,
                    file_count INTEGER NOT NULL,
                    bytes INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS paired_peers (
                    device_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    fingerprint TEXT NOT NULL,
                    at INTEGER NOT NULL
                );",
            )
            .map_err(AppError::from_display)?;
        }
        crate::log_info!("打开数据库成功: {}", db_path.display());
        Ok(Self { path: db_path, key })
    }

    /// 获取当前线程的连接（懒初始化；WAL 多连接并行读写）
    /// 打开一个独立连接（每次操作调用；WAL 多连接并行读写，无共享锁）
    fn conn(&self) -> Result<Connection, AppError> {
        let conn = Connection::open(&self.path).map_err(AppError::from_display)?;
        conn.pragma_update(None, "key", &self.key)
            .map_err(AppError::from_display)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=3000;")
            .map_err(AppError::from_display)?;
        Ok(conn)
    }

    /// 获取某配对设备的状态
    pub fn get_device(&self, code: &str) -> Result<Option<Value>, AppError> {
        crate::log_debug!("查询设备状态 code={}", crate::logger::mask(code));
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT state_json FROM devices WHERE connection_code = ?1")
            .map_err(AppError::from_display)?;
        let mut rows = stmt
            .query_map(params![code], |row| row.get::<_, String>(0))
            .map_err(AppError::from_display)?;
        if let Some(row) = rows.next() {
            let json = row.map_err(AppError::from_display)?;
            let val = serde_json::from_str(&json).map_err(AppError::from_display)?;
            crate::log_debug!("设备状态查询命中 code={}", crate::logger::mask(code));
            Ok(Some(val))
        } else {
            crate::log_debug!("设备状态查询未命中 code={}", crate::logger::mask(code));
            Ok(None)
        }
    }

    /// 获取所有配对设备的连接码列表
    pub fn get_all_codes(&self) -> Result<Vec<String>, AppError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT connection_code FROM devices ORDER BY updated_at DESC")
            .map_err(AppError::from_display)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(AppError::from_display)?;
        let mut codes = Vec::new();
        for row in rows {
            codes.push(row.map_err(AppError::from_display)?);
        }
        crate::log_debug!("查询配对设备列表 数量={}", codes.len());
        Ok(codes)
    }

    /// 保存某配对设备的状态
    pub fn save_device(&self, code: &str, name: &str, state: &Value) -> Result<(), AppError> {
        crate::log_debug!(
            "保存设备状态 code={} 名称={name} 状态keys={}",
            crate::logger::mask(code),
            state.as_object().map(|o| o.len()).unwrap_or(0)
        );
        let json = serde_json::to_string(state).map_err(AppError::from_display)?;
        // as_millis() 返回 u128，截断为 i64。292 万亿年后才溢出，实践中安全。
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(0))
            .unwrap_or(0);
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO devices (connection_code, device_name, state_json, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(connection_code) DO UPDATE SET
                device_name = ?2, state_json = ?3, updated_at = ?4",
            params![code, name, json, now],
        )
        .map_err(AppError::from_display)?;
        Ok(())
    }

    /// 记录一条传输历史（发送/接收），只保留最近 50 条
    pub fn add_transfer(
        &self,
        direction: &str,
        peer: &str,
        file_count: u64,
        bytes: u64,
        duration_ms: u64,
    ) -> Result<(), AppError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(0))
            .unwrap_or(0);
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO transfer_history (direction, peer, file_count, bytes, duration_ms, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                direction,
                peer,
                file_count as i64,
                bytes as i64,
                duration_ms as i64,
                now
            ],
        )
        .map_err(AppError::from_display)?;
        conn.execute(
            "DELETE FROM transfer_history WHERE id NOT IN
             (SELECT id FROM transfer_history ORDER BY id DESC LIMIT 200)",
            [],
        )
        .map_err(AppError::from_display)?;
        Ok(())
    }

    /// 读取最近 N 条传输历史（新→旧）
    pub fn get_transfers(&self, limit: usize) -> Result<Vec<Value>, AppError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, direction, peer, file_count, bytes, duration_ms, created_at
                 FROM transfer_history ORDER BY id DESC LIMIT ?1",
            )
            .map_err(AppError::from_display)?;
            let rows = stmt
                .query_map(params![limit as i64], |r| {
                    Ok(serde_json::json!({
                        "id": r.get::<_, i64>(0)?,
                        "direction": r.get::<_, String>(1)?,
                        "peer": r.get::<_, String>(2)?,
                        "fileCount": r.get::<_, i64>(3)?,
                        "bytes": r.get::<_, i64>(4)?,
                        "durationMs": r.get::<_, i64>(5)?,
                        "createdAt": r.get::<_, i64>(6)?,
                    }))
                })
            .map_err(AppError::from_display)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(AppError::from_display)?);
        }
        Ok(out)
    }

    /// 清空传输历史
    pub fn clear_transfers(&self) -> Result<(), AppError> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM transfer_history", [])
            .map_err(AppError::from_display)?;
        Ok(())
    }

    /// 删除单条传输历史
    pub fn delete_transfer(&self, id: i64) -> Result<(), AppError> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM transfer_history WHERE id = ?1", params![id])
            .map_err(AppError::from_display)?;
        Ok(())
    }

    /// 全量保存配对信任记录（清空后重建；SQLite 落盘，重启后配对关系不丢）
    pub fn save_paired_peers(
        &self,
        peers: &[(String, String, String, i64, String)],
    ) -> Result<(), AppError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(0))
            .unwrap_or(0);
        let conn = self.conn()?;
        conn.execute("DELETE FROM paired_peers", [])
            .map_err(AppError::from_display)?;
        for (device_id, name, ip, port, fingerprint) in peers {
            conn.execute(
                "INSERT INTO paired_peers (device_id, name, ip, port, fingerprint, at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![device_id, name, ip, port, fingerprint, now],
            )
            .map_err(AppError::from_display)?;
        }
        Ok(())
    }

    /// 读取全部配对信任记录
    pub fn load_paired_peers(&self) -> Result<Vec<Value>, AppError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT device_id, name, ip, port, fingerprint
                 FROM paired_peers ORDER BY at DESC",
            )
            .map_err(AppError::from_display)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(serde_json::json!({
                    "deviceId": r.get::<_, String>(0)?,
                    "name": r.get::<_, String>(1)?,
                    "ip": r.get::<_, String>(2)?,
                    "port": r.get::<_, i64>(3)?,
                    "fingerprint": r.get::<_, String>(4)?,
                }))
            })
            .map_err(AppError::from_display)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(AppError::from_display)?);
        }
        Ok(out)
    }
}

/// 获取配对设备状态（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
pub fn get_device_state(
    app: tauri::AppHandle,
    connection_code: String,
) -> Result<Option<Value>, AppError> {
    let state = app.state::<crate::AppState>();
    state.db.get_device(&connection_code)
}

/// 保存配对设备状态（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
pub fn save_device_state(
    app: tauri::AppHandle,
    connection_code: String,
    device_name: String,
    state: Value,
) -> Result<(), AppError> {
    let app_state = app.state::<crate::AppState>();
    app_state.db.save_device(&connection_code, &device_name, &state)
}

/// 获取所有配对设备连接码（纯逻辑，由 lib.rs 包装层注册为 Tauri 命令）
pub fn get_all_devices(app: tauri::AppHandle) -> Result<Vec<String>, AppError> {
    let state = app.state::<crate::AppState>();
    state.db.get_all_codes()
}

/// 全量保存配对信任记录到 SQLite（纯逻辑，供 transfer.rs 配对变更后落盘）
pub fn save_paired_peers(
    app: &tauri::AppHandle,
    peers: Vec<(String, String, String, i64, String)>,
) -> Result<(), AppError> {
    let state = app.state::<crate::AppState>();
    state.db.save_paired_peers(&peers)
}

/// 从 SQLite 读取配对信任记录（纯逻辑，启动时恢复）
pub fn load_paired_peers(app: &tauri::AppHandle) -> Result<Vec<Value>, AppError> {
    let state = app.state::<crate::AppState>();
    state.db.load_paired_peers()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn in_memory_db() -> Database {
        // 临时文件（每操作新连接，:memory: 会因连接独立而丢数据，故用真实文件）
        let path = std::env::temp_dir().join(format!(
            "backup_db_test_{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database {
            path,
            key: String::new(),
        };
        {
            let conn = db.conn().unwrap();
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS devices (
                    connection_code TEXT PRIMARY KEY,
                    device_name TEXT NOT NULL,
                    state_json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS transfer_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    direction TEXT NOT NULL,
                    peer TEXT NOT NULL,
                    file_count INTEGER NOT NULL,
                    bytes INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS paired_peers (
                    device_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    fingerprint TEXT NOT NULL,
                    at INTEGER NOT NULL
                );",
            )
            .unwrap();
        }
        db
    }

    #[test]
    fn save_and_get_device() {
        let db = in_memory_db();
        let state: Value = serde_json::json!({"connectionCode": "PAIR", "autoPolicy": "semi"});

        // 初始查询 → None
        let result = db.get_device("PAIRCODE").unwrap();
        assert!(result.is_none());

        // 保存后查询 → Some
        db.save_device("PAIRCODE", "Backup-PAIR", &state).unwrap();
        let result = db.get_device("PAIRCODE").unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap()["connectionCode"], "PAIR");
    }

    #[test]
    fn upsert_overwrites_existing() {
        let db = in_memory_db();
        let state1: Value = serde_json::json!({"version": 1});
        let state2: Value = serde_json::json!({"version": 2});

        db.save_device("DEV1", "Device1", &state1).unwrap();
        db.save_device("DEV1", "Device1-Updated", &state2).unwrap();

        let result = db.get_device("DEV1").unwrap().unwrap();
        assert_eq!(result["version"], 2);
    }

    #[test]
    fn concurrent_access_does_not_panic() {
        use std::sync::Arc;
        use std::thread;

        let db = Arc::new(in_memory_db());
        let state: Value = serde_json::json!({"key": "value"});

        let handles: Vec<_> = (0..4)
            .map(|i| {
                let db = Arc::clone(&db);
                let state = state.clone();
                thread::spawn(move || {
                    db.save_device(&format!("DEV{i}"), "name", &state).unwrap();
                    db.get_device(&format!("DEV{i}")).unwrap();
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }
}
