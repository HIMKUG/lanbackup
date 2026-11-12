//! 配对记录的磁盘持久化（**纯 Rust，原子写 JSON**）。
//!
//! 与 `persist.rs`（传输会话持久化）同一手法：
//! - 内存 `PeerStore` 是唯一热表，所有读都走它；
//! - 每次写操作**同步写穿**到磁盘；
//! - 冷启动时从磁盘整组捞回内存。
//!
//! # 存储布局
//!
//! ```text
//! <persist_dir>/
//!   paired_peers.json   全量配对记录（每变更原子覆盖）
//! ```
//!
//! - 用「写临时文件 + sync_all + 原子 rename」保证半截写不污染旧值。
//!
//! # 持久化时机
//!
//! `PeerStore` 的所有写操作（`merge` / `put`）在修改内存后立即调用 persist。
//! 这覆盖了：新增配对、更新对端信息、吊销/解配对。
//! 没有单独的"保存"入口——写穿保证内存和磁盘永同步。
//!
//! # 持久化失败的处理哲学
//!
//! 持久化是**安全增强**，绝不能因为它失败而让正在进行的配对流程报错。
//! 因此所有写操作失败只 `log::warn!` 并继续。

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::dto::handshake::PairingState;
use crate::dto::Presence;
use crate::pairing::trust::TrustRecord;

use super::control::PeerRecord;

/// 单条配对记录的持久化格式（与 `PeerRecord` 字段对齐）。
#[derive(serde::Serialize, serde::Deserialize)]
struct PeerRecordJson {
    device_id: String,
    alias: String,
    public_key: Vec<u8>,
    pairing_secret: Vec<u8>,
    trust_state: PairingState,
    trust_version: u64,
    peer_trust_version: u64,
    presence: String,
    // last_peer_status 省略（对账结果不需要持久化，重启后对端重新上报即可）
}

impl PeerRecordJson {
    fn from(rec: &PeerRecord) -> Self {
        Self {
            device_id: rec.device_id.clone(),
            alias: rec.alias.clone(),
            public_key: rec.public_key.clone(),
            pairing_secret: rec.pairing_secret.clone(),
            trust_state: rec.trust.state,
            trust_version: rec.trust.trust_version,
            peer_trust_version: rec.trust.peer_trust_version,
            presence: serde_json::to_string(&rec.presence).unwrap_or_else(|_| "\"Unknown\"".to_string()),
        }
    }

    fn into_peer_record(self) -> PeerRecord {
        PeerRecord {
            device_id: self.device_id,
            alias: self.alias,
            public_key: self.public_key,
            pairing_secret: self.pairing_secret,
            trust: TrustRecord {
                state: self.trust_state,
                trust_version: self.trust_version,
                peer_trust_version: self.peer_trust_version,
            },
            presence: serde_json::from_str(&self.presence).unwrap_or(Presence::Unknown),
            last_peer_status: None,
        }
    }
}

/// 配对记录持久化后端（纯 Rust 原子写 JSON 实现）。
pub(crate) struct PairingPersister {
    path: PathBuf,
}

impl PairingPersister {
    /// 打开（或创建）持久化文件。
    pub(crate) fn open(dir: &Path) -> Result<Self, String> {
        // 确保父目录存在
        if let Some(parent) = dir.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("建持久化目录失败 {dir:?}: {e}"))?;
        }
        fs::create_dir_all(dir).map_err(|e| format!("建持久化目录失败 {dir:?}: {e}"))?;
        Ok(Self {
            path: dir.join("paired_peers.json"),
        })
    }

    /// 原子写全量配对记录：**进程内唯一**临时文件 + sync_all + rename（WB-0726）。
    /// 固定 `.json.tmp` 名在并发 persist 时会互踩 —— A 的 rename 可能捡到
    /// B 写了一半的临时文件，把半截 JSON 当成完整配对表。
    fn write_all(&self, records: &[PeerRecordJson]) {
        let data = match serde_json::to_vec(records) {
            Ok(d) => d,
            Err(e) => {
                log::warn!("序列化配对记录失败: {e}");
                return;
            }
        };
        static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let file_name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "paired_peers.json".to_string());
        let tmp = self.path.with_file_name(format!("{file_name}.{seq}.tmp"));
        let result = (|| -> std::io::Result<()> {
            let mut f = File::create(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
            fs::rename(&tmp, &self.path)?;
            Ok(())
        })();
        if let Err(e) = result {
            log::warn!("写配对记录失败: {e}");
            let _ = fs::remove_file(&tmp);
        }
    }

    /// 冷启动重载：从磁盘读出所有配对记录。
    ///
    /// WB-0727：损坏**隔离**而非当空表 —— 先把坏文件改名留档（吊销记录、
    /// pairing_secret 都在里面，直接覆盖等于帮攻击者/bug 销毁证据），
    /// 再从空配对启动并告警。重启后对端可通过 sync-status 对账收敛。
    pub(crate) fn load_all(&self) -> Vec<PeerRecord> {
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };
        match serde_json::from_slice::<Vec<PeerRecordJson>>(&bytes) {
            Ok(records) => records.into_iter().map(PeerRecordJson::into_peer_record).collect(),
            Err(e) => {
                static QUARANTINE_SEQ: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let seq = QUARANTINE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let file_name = self
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "paired_peers.json".to_string());
                let quarantine = self
                    .path
                    .with_file_name(format!("{file_name}.corrupt.{seq}"));
                match fs::rename(&self.path, &quarantine) {
                    Ok(()) => log::error!(
                        "配对记录损坏已隔离到 {:?}（原因: {e}）；从空配对启动，等待对账收敛",
                        quarantine
                    ),
                    Err(re) => log::error!(
                        "配对记录损坏且隔离失败（{re}，原因: {e}）；从空配对启动"
                    ),
                }
                Vec::new()
            }
        }
    }

    /// 写穿：从内存快照持久化全部记录。
    /// 由 `PeerStore` 的每次写操作在修改内存后调用。
    pub(crate) fn persist(&self, records: &[PeerRecord]) {
        let json_records: Vec<PeerRecordJson> = records.iter().map(PeerRecordJson::from).collect();
        self.write_all(&json_records);
    }
}
