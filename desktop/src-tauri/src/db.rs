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

// base64：pairing_secret 列以 BLOB 加密字节存库，经 base64 随 JSON 返回给上层解密
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD, engine::general_purpose::URL_SAFE_NO_PAD};

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

/// schema 版本（方案.txt §4.2：用 PRAGMA user_version 管理，SQLite 不支持 ADD COLUMN IF NOT EXISTS）
/// v5（新架构）：paired_peers 加 status/peer_public_key/pairing_timestamp/last_heartbeat/pending_revoke_token；
/// local_identity 加 sig_priv/sig_pub（ECDSA P-256 签名身份锚）。
const SCHEMA_VERSION: u32 = 5;

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
                    manifest TEXT NOT NULL DEFAULT '{}',
                    at INTEGER NOT NULL
                );",
            )
            .map_err(AppError::from_display)?;
            // 老库迁移：CREATE TABLE IF NOT EXISTS 对已存在的表是 no-op。
            // 方案.txt §4：用 PRAGMA user_version 做 schema 版本管理（SQLite 不支持
            // ALTER ... ADD COLUMN IF NOT EXISTS）。旧记录 crypto_version 默认 1（SHA-256 派生），
            // 惰性迁移到 v2（读 v1/v2 都能读，写一律 v2）。
            let version: u32 = conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .map_err(AppError::from_display)?;
            if version < 2 {
                conn.execute_batch(
                    "ALTER TABLE paired_peers ADD COLUMN pairing_secret BLOB;
                     ALTER TABLE paired_peers ADD COLUMN crypto_version INTEGER NOT NULL DEFAULT 1;
                     ALTER TABLE paired_peers ADD COLUMN static_pub BLOB;",
                )
                .map_err(AppError::from_display)?;
            }
            if version < 3 {
                // 本机静态密钥表：空表即可，无记录 = 尚未生成（load 返回 NoRows → None）。
                // 不播种占位行——zeroblob 占位会让 load 误判为有效密钥。
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS local_identity (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        static_priv BLOB NOT NULL,
                        static_pub BLOB NOT NULL
                    );",
                )
                .map_err(AppError::from_display)?;
            }
            if version < 4 {
                // 3.3：配对设备历史 IP 列表（JSON 数组，DHCP 场景 IP 变化后仍可匹配重连）
                conn.execute_batch("ALTER TABLE paired_peers ADD COLUMN ips TEXT;")
                    .map_err(AppError::from_display)?;
            }
            if version < 5 {
                // 新架构（v5）：配对信任状态机字段 + ECDSA 签名身份锚
                // status: ACTIVE/REVOKE_PENDING/REVOKED；peer_public_key: 对方 ECDSA 公钥（SEC1）
                // pending_revoke_token: 离线解配对吊销令牌（JSON 文本，仅 REVOKE_PENDING 时非空）
                conn.execute_batch(
                    "ALTER TABLE paired_peers ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE';
                     ALTER TABLE paired_peers ADD COLUMN peer_public_key BLOB;
                     ALTER TABLE paired_peers ADD COLUMN pairing_timestamp INTEGER NOT NULL DEFAULT 0;
                     ALTER TABLE paired_peers ADD COLUMN last_heartbeat INTEGER NOT NULL DEFAULT 0;
                     ALTER TABLE paired_peers ADD COLUMN pending_revoke_token TEXT;
                     ALTER TABLE local_identity ADD COLUMN sig_priv BLOB;
                     ALTER TABLE local_identity ADD COLUMN sig_pub BLOB;",
                )
                .map_err(AppError::from_display)?;
            }
            // 更早版本（user_version=0 时代）缺 manifest 列：列已存在时报 duplicate column，忽略
            let _ = conn.execute_batch(
                "ALTER TABLE paired_peers ADD COLUMN manifest TEXT NOT NULL DEFAULT '{}';",
            );
            conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))
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

    /// 重置所有业务数据：清空设备、传输历史、配对、本机身份密钥。
    /// 用户主动「重置状态」用：保留数据库文件与 schema，仅删行。
    /// 调用方应在删行后重新生成并落库一套全新身份密钥（ECDH + ECDSA）。
    pub fn reset_all(&self) -> Result<(), AppError> {
        let conn = self.conn()?;
        conn.execute_batch(
            "DELETE FROM devices;
             DELETE FROM transfer_history;
             DELETE FROM paired_peers;
             DELETE FROM local_identity;",
        )
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

    /// 全量保存配对信任记录（清空后重建；SQLite 落盘，重启后配对关系不丢）。
    /// tuple: (device_id, name, ip, port, fingerprint, manifest_json, pairing_secret_enc, ips_json,
    ///         status, peer_public_key_sec1, pairing_timestamp, last_heartbeat, pending_revoke_token_json)
    /// pairing_secret_enc：L1 storage_key 加密后的 pairing_secret 字节（P5b，方案.txt §2.1）；
    /// None 表示该设备无 v3 pairing_secret（v2 遗留记录）。crypto_version 一律写 2（PBKDF2）。
    /// ips_json：历史 IP 的 JSON 数组（3.3 DHCP 兼容）；None = 旧格式调用方（仅当前 ip）。
    /// status/peer_public_key/pending_revoke_token：新架构信任状态机字段（v5）。
    pub fn save_paired_peers(
        &self,
        peers: &[(
            String,
            String,
            String,
            i64,
            String,
            String,
            Option<Vec<u8>>,
            Option<String>,
            String,
            Option<Vec<u8>>,
            i64,
            i64,
            Option<String>,
        )],
    ) -> Result<(), AppError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(0))
            .unwrap_or(0);
        let conn = self.conn()?;
        let tx = conn.unchecked_transaction().map_err(AppError::from_display)?;
        tx.execute("DELETE FROM paired_peers", [])
            .map_err(AppError::from_display)?;
        for (device_id, name, ip, port, fingerprint, manifest, secret_enc, ips, status, peer_pub, pair_ts, hb, revoke) in peers {
            tx.execute(
                "INSERT INTO paired_peers (device_id, name, ip, port, fingerprint, manifest, pairing_secret, crypto_version, ips, at, status, peer_public_key, pairing_timestamp, last_heartbeat, pending_revoke_token)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 2, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![device_id, name, ip, port, fingerprint, manifest, secret_enc, ips, now, status, peer_pub, pair_ts, hb, revoke],
            )
            .map_err(AppError::from_display)?;
        }
        tx.commit().map_err(AppError::from_display)?;
        Ok(())
    }

    /// 读取全部配对信任记录（含加密的 pairing_secret 与 crypto_version，供上层解密回填）
    pub fn load_paired_peers(&self) -> Result<Vec<Value>, AppError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT device_id, name, ip, port, fingerprint, manifest, pairing_secret, crypto_version, ips,
                        status, peer_public_key, pairing_timestamp, last_heartbeat, pending_revoke_token
                 FROM paired_peers ORDER BY at DESC",
            )
            .map_err(AppError::from_display)?;
        let rows = stmt
            .query_map([], |r| {
                // SELECT 列序（index）：0=device_id 1=name 2=ip 3=port 4=fingerprint
                // 5=manifest 6=pairing_secret 7=crypto_version 8=ips 9=status 10=peer_public_key
                // 11=pairing_timestamp 12=last_heartbeat 13=pending_revoke_token —— 改列序须同步此映射
                let manifest_str = r.get::<_, String>(5)?;
                let manifest: Value = serde_json::from_str(&manifest_str).unwrap_or(serde_json::Value::Object(Default::default()));
                // pairing_secret 列可能为 NULL（v2 遗留/旧库），读成 Option<Vec<u8>> 再转 base64
                let secret_b64: String = match r.get::<_, Option<Vec<u8>>>(6)? {
                    Some(b) => BASE64_STD.encode(b),
                    None => String::new(),
                };
                // ips 列可能为 NULL（v4 之前的记录）→ 空数组由调用方回退单 ip
                let ips: Value = match r.get::<_, Option<String>>(8)? {
                    Some(s) => serde_json::from_str(&s).unwrap_or(serde_json::json!([])),
                    None => serde_json::json!([]),
                };
                // v5：信任状态机字段（peer_public_key BLOB → base64url SEC1；pending_revoke_token 为 JSON 文本）
                let peer_pub_b64: String = match r.get::<_, Option<Vec<u8>>>(10)? {
                    Some(b) => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b),
                    None => String::new(),
                };
                let pending_revoke: Value = match r.get::<_, Option<String>>(13)? {
                    Some(s) => serde_json::from_str(&s).unwrap_or(serde_json::Value::Null),
                    None => serde_json::Value::Null,
                };
                Ok(serde_json::json!({
                    "deviceId": r.get::<_, String>(0)?,
                    "name": r.get::<_, String>(1)?,
                    "ip": r.get::<_, String>(2)?,
                    "port": r.get::<_, i64>(3)?,
                    "fingerprint": r.get::<_, String>(4)?,
                    "lastManifest": manifest,
                    "pairingSecretB64": secret_b64,
                    "cryptoVersion": r.get::<_, i64>(7)?,
                    "ips": ips,
                    "status": r.get::<_, String>(9)?,
                    "peerPublicKey": peer_pub_b64,
                    "pairingTimestamp": r.get::<_, i64>(11)?,
                    "lastHeartbeat": r.get::<_, i64>(12)?,
                    "pendingRevokeToken": pending_revoke,
                }))
            })
            .map_err(AppError::from_display)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(AppError::from_display)?);
        }
        Ok(out)
    }

    /// 保存本机静态 P-256 密钥对（local_identity 单行表）。
    /// 无条件 UPSERT：行不存在则插入，存在则覆盖（本机密钥一生只生成一次，
    /// 覆盖只发生在"首次生成"或"上次保存失败后的重试"，不存在覆盖有效数据的场景）。
    pub fn save_static_key(&self, priv_b64: &str, pub_b64: &str) -> Result<(), AppError> {
        // 空 key 守卫：ecdh_generate_keypair 失败时返回 ("","")，绝不能落库
        if priv_b64.is_empty() || pub_b64.is_empty() {
            return Err(AppError("拒绝保存空静态密钥".to_string()));
        }
        let priv_bytes = URL_SAFE_NO_PAD
            .decode(priv_b64)
            .map_err(|e| AppError(format!("static_priv base64 解码失败: {e}")))?;
        let pub_bytes = URL_SAFE_NO_PAD
            .decode(pub_b64)
            .map_err(|e| AppError(format!("static_pub base64 解码失败: {e}")))?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO local_identity (id, static_priv, static_pub) VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET static_priv = ?1, static_pub = ?2",
            params![priv_bytes, pub_bytes],
        )
        .map_err(AppError::from_display)?;
        Ok(())
    }

    /// 保存本机 ECDSA P-256 签名密钥对（local_identity 单行表 sig 列，v5 新架构）。
    /// 与 static_key（ECDH）分离：sig 密钥专用于消息签名/验签（配对信任锚、吊销令牌）。
    /// 冲突分支只更新 sig_priv/sig_pub——static_priv/static_pub 是 ECDH 身份密钥，
    /// 任何情况下都不得被本方法触碰（excluded.* 显式限定写入列）。
    pub fn save_sig_key(&self, priv_b64: &str, pub_b64: &str) -> Result<(), AppError> {
        if priv_b64.is_empty() || pub_b64.is_empty() {
            return Err(AppError("拒绝保存空签名密钥".to_string()));
        }
        let priv_bytes = URL_SAFE_NO_PAD
            .decode(priv_b64)
            .map_err(|e| AppError(format!("sig_priv base64 解码失败: {e}")))?;
        let pub_bytes = URL_SAFE_NO_PAD
            .decode(pub_b64)
            .map_err(|e| AppError(format!("sig_pub base64 解码失败: {e}")))?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO local_identity (id, static_priv, static_pub, sig_priv, sig_pub)
             VALUES (1, X'', X'', ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET
                sig_priv = excluded.sig_priv,
                sig_pub = excluded.sig_pub",
            params![priv_bytes, pub_bytes],
        )
        .map_err(AppError::from_display)?;
        Ok(())
    }

    /// 加载本机 ECDSA P-256 签名密钥对。返回 (priv_b64, pub_b64)；尚无记录时返回 None。
    pub fn load_sig_key(&self) -> Result<Option<(String, String)>, AppError> {
        let conn = self.conn()?;
        let row: Result<(Vec<u8>, Vec<u8>), _> = conn.query_row(
            "SELECT sig_priv, sig_pub FROM local_identity WHERE id = 1",
            [],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
        );
        match row {
            Ok((priv_bytes, pub_bytes)) => {
                if priv_bytes.is_empty() || pub_bytes.len() < 33 {
                    return Ok(None);
                }
                let priv_b64 = URL_SAFE_NO_PAD.encode(&priv_bytes);
                let pub_b64 = URL_SAFE_NO_PAD.encode(&pub_bytes);
                Ok(Some((priv_b64, pub_b64)))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::from_display(e)),
        }
    }

    /// 加载本机静态 P-256 密钥对（local_identity 单行表）。
    /// 返回 (priv_b64, pub_b64)；尚无记录时返回 None。
    pub fn load_static_key(&self) -> Result<Option<(String, String)>, AppError> {
        let conn = self.conn()?;
        let row: Result<(Vec<u8>, Vec<u8>), _> = conn.query_row(
            "SELECT static_priv, static_pub FROM local_identity WHERE id = 1",
            [],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
        );
        match row {
            Ok((priv_bytes, pub_bytes)) => {
                if priv_bytes.len() < 32 || pub_bytes.len() < 33 {
                    return Ok(None); // 长度异常的脏数据视为无记录
                }
                let priv_b64 = URL_SAFE_NO_PAD.encode(&priv_bytes);
                let pub_b64 = URL_SAFE_NO_PAD.encode(&pub_bytes);
                Ok(Some((priv_b64, pub_b64)))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::from_display(e)),
        }
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
/// tuple: (device_id, name, ip, port, fingerprint, manifest_json, pairing_secret_enc, ips_json,
///         status, peer_public_key_sec1, pairing_timestamp, last_heartbeat, pending_revoke_token_json)
pub fn save_paired_peers(
    app: &tauri::AppHandle,
    peers: Vec<(
        String,
        String,
        String,
        i64,
        String,
        String,
        Option<Vec<u8>>,
        Option<String>,
        String,
        Option<Vec<u8>>,
        i64,
        i64,
        Option<String>,
    )>,
) -> Result<(), AppError> {
    let state = app.state::<crate::AppState>();
    state.db.save_paired_peers(&peers)
}

/// 从 SQLite 读取配对信任记录（纯逻辑，启动时恢复）
pub fn load_paired_peers(app: &tauri::AppHandle) -> Result<Vec<Value>, AppError> {
    let state = app.state::<crate::AppState>();
    state.db.load_paired_peers()
}

/// 保存本机静态密钥到 SQLite（local_identity 单行表）
pub fn save_static_key(app: &tauri::AppHandle, priv_b64: &str, pub_b64: &str) -> Result<(), AppError> {
    let state = app.state::<crate::AppState>();
    state.db.save_static_key(priv_b64, pub_b64)
}

/// 保存本机 ECDSA 签名密钥到 SQLite（local_identity 单行表 sig 列，v5）
pub fn save_sig_key(app: &tauri::AppHandle, priv_b64: &str, pub_b64: &str) -> Result<(), AppError> {
    let state = app.state::<crate::AppState>();
    state.db.save_sig_key(priv_b64, pub_b64)
}

/// 从 SQLite 加载本机 ECDSA 签名密钥（启动时恢复）
pub fn load_sig_key(app: &tauri::AppHandle) -> Result<Option<(String, String)>, AppError> {
    let state = app.state::<crate::AppState>();
    state.db.load_sig_key()
}

/// 从 SQLite 加载本机静态密钥（启动时恢复）
pub fn load_static_key(app: &tauri::AppHandle) -> Result<Option<(String, String)>, AppError> {
    let state = app.state::<crate::AppState>();
    state.db.load_static_key()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn in_memory_db() -> Database {
        // 临时文件（每操作新连接，:memory: 会因连接独立而丢数据，故用真实文件）。
        // 路径追加自增序号：cargo test 多线程并行执行时，仅用进程 id 会让多个测试
        // 共享同一 SQLite 文件——互相 remove_file + SQLITE_BUSY 导致偶发 panic
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "backup_db_test_{}_{n}.db",
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
                    manifest TEXT NOT NULL DEFAULT '{}',
                    pairing_secret BLOB,
                    crypto_version INTEGER NOT NULL DEFAULT 1,
                    static_pub BLOB,
                    ips TEXT,
                    at INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    peer_public_key BLOB,
                    pairing_timestamp INTEGER NOT NULL DEFAULT 0,
                    last_heartbeat INTEGER NOT NULL DEFAULT 0,
                    pending_revoke_token TEXT
                );
                CREATE TABLE IF NOT EXISTS local_identity (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    static_priv BLOB NOT NULL,
                    static_pub BLOB NOT NULL,
                    sig_priv BLOB,
                    sig_pub BLOB
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
    fn static_key_roundtrip_and_empty_guard() {
        use base64::Engine as _;
        let db = in_memory_db();

        // 无记录 → None
        assert!(db.load_static_key().unwrap().is_none());

        // 首次保存 → 加载一致（B1 回归：此前 zeroblob 占位 + 条件 UPDATE 导致永不写入）
        let priv_b64 = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let pub_b64 = URL_SAFE_NO_PAD.encode([9u8; 33]);
        db.save_static_key(&priv_b64, &pub_b64).unwrap();
        let loaded = db.load_static_key().unwrap().unwrap();
        assert_eq!(loaded.0, priv_b64);
        assert_eq!(loaded.1, pub_b64);

        // 空 key 拒绝且不破坏已有数据
        assert!(db.save_static_key("", "").is_err());
        let again = db.load_static_key().unwrap().unwrap();
        assert_eq!(again.0, priv_b64);

        // 覆盖保存 → 读到新值
        let priv_b64b = URL_SAFE_NO_PAD.encode([8u8; 32]);
        db.save_static_key(&priv_b64b, &pub_b64).unwrap();
        assert_eq!(db.load_static_key().unwrap().unwrap().0, priv_b64b);
    }

    #[test]
    fn save_sig_key_never_touches_static_key() {
        use base64::Engine as _;
        let db = in_memory_db();

        // 先落 ECDH static key，再保存签名 key → static key 必须原样保留
        // （回归：save_sig_key 的 UPSERT 冲突分支曾可能触碰 static_priv/static_pub）
        let s_priv = URL_SAFE_NO_PAD.encode([1u8; 32]);
        let s_pub = URL_SAFE_NO_PAD.encode([2u8; 33]);
        db.save_static_key(&s_priv, &s_pub).unwrap();

        let sig_priv = URL_SAFE_NO_PAD.encode([3u8; 32]);
        let sig_pub = URL_SAFE_NO_PAD.encode([4u8; 33]);
        db.save_sig_key(&sig_priv, &sig_pub).unwrap();

        let loaded_static = db.load_static_key().unwrap().unwrap();
        assert_eq!(loaded_static.0, s_priv);
        assert_eq!(loaded_static.1, s_pub);
        let loaded_sig = db.load_sig_key().unwrap().unwrap();
        assert_eq!(loaded_sig.0, sig_priv);
        assert_eq!(loaded_sig.1, sig_pub);

        // 反向顺序（先 sig 后 static）→ 两者互不干扰
        let db2 = in_memory_db();
        db2.save_sig_key(&sig_priv, &sig_pub).unwrap();
        db2.save_static_key(&s_priv, &s_pub).unwrap();
        let loaded_sig2 = db2.load_sig_key().unwrap().unwrap();
        assert_eq!(loaded_sig2.0, sig_priv);
        assert_eq!(loaded_sig2.1, sig_pub);
        let loaded_static2 = db2.load_static_key().unwrap().unwrap();
        assert_eq!(loaded_static2.0, s_priv);
        assert_eq!(loaded_static2.1, s_pub);

        // 空 sig key 拒绝且不破坏已有数据
        assert!(db.save_sig_key("", "").is_err());
        assert!(db.load_sig_key().unwrap().is_some());
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

    #[test]
    fn paired_peers_secret_roundtrip() {
        // P5b：pairing_secret 加密 BLOB 存库 → 读取 base64 原样回（上层解密在 transfer.rs，
        // 此处验证列读写与 base64 往返正确）；3.3：ips JSON 数组同表往返
        let db = in_memory_db();
        let secret: Vec<u8> = (0u8..32).collect();
        let rows = vec![(
            "dev-1".to_string(),
            "Peer".to_string(),
            "192.168.1.5".to_string(),
            53317_i64,
            "fp-1".to_string(),
            "{}".to_string(),
            Some(secret.clone()),
            Some(r#"["192.168.1.5","192.168.1.23"]"#.to_string()),
            "ACTIVE".to_string(),
            None,
            0_i64,
            0_i64,
            None,
        )];
        db.save_paired_peers(&rows).unwrap();
        let loaded = db.load_paired_peers().unwrap();
        assert_eq!(loaded.len(), 1);
        let p = &loaded[0];
        assert_eq!(p["deviceId"], "dev-1");
        assert_eq!(p["ip"], "192.168.1.5");
        let b64 = p["pairingSecretB64"].as_str().expect("pairingSecretB64 缺失");
        let decoded = BASE64_STD.decode(b64).expect("base64 解码失败");
        assert_eq!(decoded, secret);
        assert_eq!(p["cryptoVersion"], 2);
        let ips = p["ips"].as_array().expect("ips 数组缺失");
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[1], "192.168.1.23");
    }

    #[test]
    fn paired_peers_secret_none_allowed() {
        // v2 遗留记录无 pairing_secret：None 可写入，读取时 pairingSecretB64 为空串；
        // ips None → 空数组（调用方回退单 ip）
        let db = in_memory_db();
        let rows = vec![(
            "dev-2".to_string(),
            "Legacy".to_string(),
            "192.168.1.9".to_string(),
            53317_i64,
            "fp-2".to_string(),
            "{}".to_string(),
            None,
            None,
            "ACTIVE".to_string(),
            None,
            0_i64,
            0_i64,
            None,
        )];
        db.save_paired_peers(&rows).unwrap();
        let loaded = db.load_paired_peers().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0]["pairingSecretB64"], "");
        assert_eq!(loaded[0]["ips"], serde_json::json!([]));
    }
}
