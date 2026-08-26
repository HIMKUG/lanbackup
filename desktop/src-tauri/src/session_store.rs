//! session_store.rs — Desktop 端会话状态持久化
//!
//! 使用 tauri-plugin-store 进行温状态持久化，内存 HashMap 作为热状态缓存。
//!
//! 三层状态分离：
//! - 热状态（内存）：RwLock<HashMap<SessionId, SessionState>>，实时更新
//! - 温状态（tauri-plugin-store）：实时持久化到 session_store.json
//! - 冷状态：本模块不处理冷状态（冷状态由 SQLite 处理）
//!
//! 设计原则：
//! - 所有写操作先写热状态，再异步持久化到 store
//! - 读取时优先热状态，未命中则从 store 加载
//! - 重启后自动从 store 恢复活跃会话

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

pub use crate::scheduler::{TransferProgress, PeerInfo};

// re-export scheduler types for use by other modules
// SchedulerFileManifest intentionally public for external type compatibility

// ============================================================
// 类型定义（与 shared-core/src/session-store.ts 对齐，camelCase JSON）
// ============================================================

/// 文件清单项（JSON 序列化用，与 scheduler FileManifest 字段对应但名称对齐 TypeScript）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    pub id: String,
    #[serde(rename = "fileName")]
    pub file_name: String,
    pub size: u64,
    pub sha256: String,
    #[serde(rename = "merkleRoot")]
    pub merkle_root: Option<String>,
    #[serde(rename = "pieceHashes")]
    pub piece_hashes: Vec<String>,
    #[serde(rename = "chunkSize")]
    pub chunk_size: Option<u64>,
}

/// 会话状态（持久化格式，allow(dead_code)：scheduler 差异同步引擎完全重构后接线）
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub id: String,
    pub files: Vec<FileManifest>,
    pub peers: Vec<PeerInfo>,
    #[serde(rename = "progress")]
    pub progress: HashMap<String, TransferProgress>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    pub status: SessionStatus,
}

/// 会话状态枚举（allow(dead_code)：scheduler 差异同步引擎完全重构后接线）
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    Active,
    Completed,
    Aborted,
    Failed,
}

/// 存储格式（对应 session_store.json 结构，allow(dead_code)：scheduler 差异同步引擎完全重构后接线）
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionStoreData {
    #[serde(rename = "sessions")]
    pub sessions: HashMap<String, SessionState>,
    #[serde(rename = "activeSessionId")]
    pub active_session_id: Option<String>,
}

// ============================================================
// DesktopSessionStore 实现
// ============================================================

/// Desktop 端会话存储（跨重启保持传输会话状态）
/// 故意标记 allow(dead_code)：DesktopSessionStore 已在 lib.rs setup 中注册，
/// 其公共 API（persist/create_session/update_session 等）在 send_files 重构后接线。
#[allow(dead_code)]
pub struct DesktopSessionStore {
    /// 热状态缓存
    hot: Arc<RwLock<HashMap<String, SessionState>>>,
    /// 活跃会话 ID
    active_id: Arc<RwLock<Option<String>>>,
    /// store 引用（用于持久化）
    store_path: std::path::PathBuf,
}

/// ISessionStore 接口实现（scheduler 差异同步引擎用，allow(dead_code)）
#[allow(dead_code)]
impl DesktopSessionStore {
    /// 创建新的 SessionStore
    pub fn new(app_data_dir: &std::path::Path) -> Result<Self, crate::AppError> {
        let store_path = app_data_dir.join("session_store.json");
        
        // 尝试从磁盘加载已有数据
        let (sessions, active_id) = if store_path.exists() {
            match std::fs::read_to_string(&store_path) {
                Ok(content) => {
                    match serde_json::from_str::<SessionStoreData>(&content) {
                        Ok(data) => (data.sessions, data.active_session_id),
                        Err(e) => {
                            eprintln!("[WARN] session_store.json 解析失败，使用空状态: {}", e);
                            (HashMap::new(), None)
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[WARN] session_store.json 读取失败，使用空状态: {}", e);
                    (HashMap::new(), None)
                }
            }
        } else {
            (HashMap::new(), None)
        };

        Ok(Self {
            hot: Arc::new(RwLock::new(sessions)),
            active_id: Arc::new(RwLock::new(active_id)),
            store_path,
        })
    }

    /// 持久化到磁盘（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub async fn persist(&self) -> Result<(), crate::AppError> {
        // 锁作用域最小化：仅克隆数据，序列化+磁盘写不持锁（避免阻塞读/写端）
        let data = {
            let hot = self.hot.read().await;
            let active_id = self.active_id.read().await;
            SessionStoreData {
                sessions: hot.clone(),
                active_session_id: active_id.clone(),
            }
        };

        let json = serde_json::to_string_pretty(&data)
            .map_err(|e| crate::AppError(format!("序列化会话状态失败: {}", e)))?;

        // 确保目录存在
        if let Some(parent) = self.store_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| crate::AppError(format!("创建目录失败: {}", e)))?;
        }

        // 异步非阻塞写：避免同步 std::fs::write 占住 tokio worker（P1-2）
        tokio::fs::write(&self.store_path, json)
            .await
            .map_err(|e| crate::AppError(format!("写入 session_store.json 失败: {}", e)))?;

        Ok(())
    }

    // ========================================================
    // ISessionStore 接口实现
    // ========================================================

    /// 创建新会话（allow(dead_code)：scheduler 差异同步引擎用）
    #[allow(dead_code)]
    pub async fn create_session(&self, session: SessionState) -> Result<(), crate::AppError> {
        let mut hot = self.hot.write().await;
        hot.insert(session.id.clone(), session);
        
        // 如果是活跃会话，设置 active_id
        drop(hot);
        self.persist().await
    }

    /// 更新会话（部分更新）
    pub async fn update_session(
        &self,
        session_id: &str,
        updates: PartialSessionUpdate,
    ) -> Result<(), crate::AppError> {
        let mut hot = self.hot.write().await;
        if let Some(session) = hot.get_mut(session_id) {
            if let Some(files) = updates.files {
                session.files = files;
            }
            if let Some(peers) = updates.peers {
                session.peers = peers;
            }
            if let Some(progress) = updates.progress {
                session.progress = progress;
            }
            if let Some(status) = updates.status {
                session.status = status;
            }
            session.updated_at = chrono_lite_now();
        }
        drop(hot);
        self.persist().await
    }

    /// 获取指定会话
    pub async fn get_session(&self, session_id: &str) -> Result<Option<SessionState>, crate::AppError> {
        let hot = self.hot.read().await;
        Ok(hot.get(session_id).cloned())
    }

    /// 列出所有会话
    pub async fn list_sessions(&self) -> Result<Vec<SessionState>, crate::AppError> {
        let hot = self.hot.read().await;
        Ok(hot.values().cloned().collect())
    }

    /// 删除会话
    pub async fn delete_session(&self, session_id: &str) -> Result<(), crate::AppError> {
        let mut hot = self.hot.write().await;
        hot.remove(session_id);
        
        let mut active_id = self.active_id.write().await;
        if active_id.as_deref() == Some(session_id) {
            *active_id = None;
        }
        
        drop(hot);
        drop(active_id);
        self.persist().await
    }

    /// 获取活跃会话
    pub async fn get_active_session(&self) -> Result<Option<SessionState>, crate::AppError> {
        let active_id = self.active_id.read().await;
        let session_id = match active_id.as_deref() {
            Some(id) => id,
            None => return Ok(None),
        };
        
        let hot = self.hot.read().await;
        Ok(hot.get(session_id).cloned())
    }

    /// 设置活跃会话
    pub async fn set_active_session(&self, session_id: Option<String>) -> Result<(), crate::AppError> {
        let mut active_id = self.active_id.write().await;
        *active_id = session_id;
        drop(active_id);
        self.persist().await
    }

    /// 批量更新进度
    pub async fn update_progress(
        &self,
        session_id: &str,
        progress: HashMap<String, TransferProgress>,
    ) -> Result<(), crate::AppError> {
        let mut hot = self.hot.write().await;
        if let Some(session) = hot.get_mut(session_id) {
            for (file_id, p) in progress {
                session.progress.insert(file_id, p);
            }
            session.updated_at = chrono_lite_now();
        }
        drop(hot);
        self.persist().await
    }

    /// 标记会话完成
    pub async fn complete_session(&self, session_id: &str) -> Result<(), crate::AppError> {
        self.update_session(
            session_id,
            PartialSessionUpdate {
                status: Some(SessionStatus::Completed),
                ..Default::default()
            },
        )
        .await
    }

    /// 标记会话失败
    pub async fn fail_session(&self, session_id: &str, _error: Option<String>) -> Result<(), crate::AppError> {
        self.update_session(
            session_id,
            PartialSessionUpdate {
                status: Some(SessionStatus::Failed),
                ..Default::default()
            },
        )
        .await
    }
}

/// 部分更新结构体（allow(dead_code)：scheduler 差异同步引擎完全重构后接线）
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct PartialSessionUpdate {
    pub files: Option<Vec<FileManifest>>,
    pub peers: Option<Vec<PeerInfo>>,
    pub progress: Option<HashMap<String, TransferProgress>>,
    pub status: Option<SessionStatus>,
}

/// 获取当前时间（ISO8601 格式化字符串，与 SessionState.updatedAt 语义一致）
/// 轻量时间戳（allow(dead_code)：scheduler 差异同步引擎完全重构后接线）
#[allow(dead_code)]
fn chrono_lite_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| {
            // 回退：即使 time crate 格式化失败，仍返回 Unix 秒（兼容旧行为）
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string()
        })
}

// ============================================================
// 测试辅助
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_get_session() {
        let temp_dir = std::env::temp_dir();
        let store = DesktopSessionStore::new(&temp_dir).unwrap();
        
        let session = SessionState {
            id: "test_sess".to_string(),
            files: vec![],
            peers: vec![],
            progress: HashMap::new(),
            created_at: "1234567890".to_string(),
            updated_at: "1234567890".to_string(),
            status: SessionStatus::Active,
        };
        
        store.create_session(session.clone()).await.unwrap();
        
        let retrieved = store.get_session("test_sess").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, "test_sess");
    }

    #[tokio::test]
    async fn test_active_session() {
        let temp_dir = std::env::temp_dir();
        let store = DesktopSessionStore::new(&temp_dir).unwrap();
        
        let session = SessionState {
            id: "active_sess".to_string(),
            files: vec![],
            peers: vec![],
            progress: HashMap::new(),
            created_at: "1234567890".to_string(),
            updated_at: "1234567890".to_string(),
            status: SessionStatus::Active,
        };
        
        store.create_session(session).await.unwrap();
        store.set_active_session(Some("active_sess".to_string())).await.unwrap();
        
        let active = store.get_active_session().await.unwrap();
        assert!(active.is_some());
        assert_eq!(active.unwrap().id, "active_sess");
    }
}
