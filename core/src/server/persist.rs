//! 传输会话的磁盘持久化（**纯 Rust，原子写 JSON**）。
//!
//! # 为什么不是 rusqlite
//!
//! `Cargo.toml` 里 `rusqlite = { ..., features = ["bundled"] }` 依赖已就位，
//! 但 `bundled` 会在**构建期用 C 编译器编译 SQLite 源码** —— 而本构建环境
//! （沙箱，cargo 1.96）**没有任何 C 工具链**（无 `cl` / `gcc` / `clang` / `cc`），
//! `rusqlite` 一编译就失败。因此这里用**纯 Rust 的原子写 JSON** 作为持久化后端。
//!
//! 接口与「rusqlite 后端」完全同构：
//! `new_session` / `set_file` / `set_piece` / `update_session` /
//! `set_receipt` / `remove_session` / `load_all`。
//! 后续环境具备 C 工具链时，**只需替换本模块的实现**，上层（handler、构造器、
//! 测试）零改动。
//!
//! # 为什么是「内存热表 + 磁盘镜像」而不是「纯 SQL 后端」
//!
//! 现有所有 handler 与测试都直接 `store.inner.lock()` 读改写内存 `HashMap`，
//! 且 `SessionStore` 的内存模型是整个协议推理的载体（确认位图、piece 自算哈希、
//! 终态单调性都落在 `SessionRecord` 上）。若把后端整体换成 SQL，
//! 这些调用点与全部测试都要重写，风险与改动面都不可接受。
//!
//! 因此采用**写穿（write-through）+ 冷启动重载**的增量方案：
//! - 内存 `HashMap` 仍是唯一热表，所有读都走它，零延迟；
//! - 每次状态变更**同步写穿**到磁盘（保证崩溃/重启后可恢复）；
//! - `SessionStore` 构造时若给了持久化目录，就从盘里把**未终态**的会话整组捞回内存。
//!
//! # 这解决的是哪个真实缺口
//!
//! 此前 `SessionRecord.confirmed` 位图只活在内存：进程一重启，
//! `register` 之前的会话全没了，对端再连上来时本端不记得收过哪些块
//! → 续传退化成全量重传。文档评审（高丢包环境完整性保障五层机制）把这一条
//! 列为**真实缺口**。落盘后，对端重连复用同一 `sessionId`，
//! `chunk-status` 能照常报出 `nextChunk`，从断点继续 —— 这才是真正的断点续传。
//!
//! # 存储布局（每个会话两个文件，互不干扰并发）
//!
//! ```text
//! <persist_dir>/
//!   meta/<session_id>.json    会话级元数据 + 文件清单 + 回执（小，随状态变更整体重写）
//!   pieces/<session_id>.jsonl 确认块追加日志（一行一条 {file_id, piece_index, sha}）
//! ```
//!
//! - `meta` 用「写临时文件 + 原子 rename」保证半截写不会污染旧值
//!   （这正是文档第五层「`*.part` 原子 rename」的同一手法）。
//! - `pieces` 用**追加**写，每块 O(1)，不随进度重排整个文件；
//!   崩溃残留的半截行在 `load_all` 重放时被跳过，不影响其余块。
//!
//! # 持久化失败的处理哲学
//!
//! 持久化是「续传可行性」的增强，**绝不能因为它失败而让正在进行的传输 500**。
//! 因此所有写操作失败只 `log::warn!` 并继续，绝不用 `expect` 把错误抛给请求路径。

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::dto::session::{Algorithm, DegradeReason, FileMeta, TaskReceipt};
use crate::state::transfer::TransferState;

use super::SessionRecord;

/// 单个会话的持久化元数据（不含确认块位图 —— 那部分在 `pieces/*.jsonl`）。
///
/// 与 `SessionRecord` 字段对齐但**不含 `confirmed` / `piece_sha`**，
/// 因为这两张表来自追加日志、在 `load_all` 时重放重建，没有「整文件改写」的必要。
#[derive(serde::Serialize, serde::Deserialize)]
struct MetaFile {
    device_id: String,
    phase: TransferState,
    algorithm: Algorithm,
    degrade_reason: Option<DegradeReason>,
    bitmap_version: u64,
    files: HashMap<String, FileMeta>,
    receipts: HashMap<String, TaskReceipt>,
}

/// `pieces/*.jsonl` 的一行。
#[derive(serde::Serialize, serde::Deserialize)]
struct PieceLine {
    file_id: String,
    piece_index: u64,
    sha: Option<String>,
}

/// 传输会话持久化后端（纯 Rust 原子写 JSON 实现）。
///
/// 见模块文档关于「为何不用 rusqlite」「存储布局」「失败哲学」的说明。
pub(crate) struct SessionPersister {
    meta_dir: PathBuf,
    pieces_dir: PathBuf,
}

impl SessionPersister {
    /// 打开（或创建）持久化目录。参数应是平台层给的 App 私有数据目录
    /// （App 私有目录支持同盘 rename；与 M20「SAF 无跨目录 rename」是两回事，
    /// 那里指的是把收到的备份文件搬进用户自选的 SAF 位置，与本站持久化库无关）。
    pub(crate) fn open(dir: &Path) -> Result<Self, String> {
        let meta_dir = dir.join("meta");
        let pieces_dir = dir.join("pieces");
        fs::create_dir_all(&meta_dir).map_err(|e| format!("建持久化目录失败 {meta_dir:?}: {e}"))?;
        fs::create_dir_all(&pieces_dir)
            .map_err(|e| format!("建持久化目录失败 {pieces_dir:?}: {e}"))?;
        Ok(Self { meta_dir, pieces_dir })
    }

    fn meta_path(&self, sid: &str) -> PathBuf {
        self.meta_dir.join(format!("{sid}.json"))
    }

    fn pieces_path(&self, sid: &str) -> PathBuf {
        self.pieces_dir.join(format!("{sid}.jsonl"))
    }

    /// 原子写 `meta/<sid>.json`：先写 `.tmp`，`sync_all` 后 rename 覆盖。
    fn write_meta(&self, sid: &str, meta: &MetaFile) {
        let data = match serde_json::to_vec(meta) {
            Ok(d) => d,
            Err(e) => {
                log::warn!("序列化会话元数据失败 {sid}: {e}");
                return;
            }
        };
        let tmp = self.meta_dir.join(format!("{sid}.json.tmp"));
        let result = (|| -> std::io::Result<()> {
            let mut f = File::create(&tmp)?;
            f.write_all(&data)?;
            // 落盘再 rename，否则崩溃可能留下一个没写完的新文件
            f.sync_all()?;
            fs::rename(&tmp, self.meta_path(sid))?;
            Ok(())
        })();
        if let Err(e) = result {
            log::warn!("写会话元数据失败 {sid}: {e}");
            let _ = fs::remove_file(&tmp);
        }
    }

    /// 读 `meta/<sid>.json`；缺失或损坏时返回占位（不应发生，仅为兜底）。
    fn read_meta(&self, sid: &str) -> MetaFile {
        match fs::read(self.meta_path(sid)) {
            Ok(bytes) => match serde_json::from_slice::<MetaFile>(&bytes) {
                Ok(m) => m,
                Err(e) => {
                    log::warn!("会话元数据损坏 {sid}: {e}（用占位重建）");
                    MetaFile::blank()
                }
            },
            Err(_) => MetaFile::blank(),
        }
    }

    /// 会话注册：建一份空 `meta`，并预建空 `pieces` 日志。
    pub(crate) fn new_session(
        &self,
        sid: &str,
        device_id: &str,
        phase: TransferState,
        algorithm: Algorithm,
        degrade_reason: Option<DegradeReason>,
        bitmap_version: u64,
    ) {
        let meta = MetaFile {
            device_id: device_id.to_string(),
            phase,
            algorithm,
            degrade_reason,
            bitmap_version,
            files: HashMap::new(),
            receipts: HashMap::new(),
        };
        self.write_meta(sid, &meta);
    }

    /// 登记一个待传文件（prepare 阶段）。
    pub(crate) fn set_file(&self, sid: &str, file_id: &str, meta: &FileMeta) {
        let mut m = self.read_meta(sid);
        m.files.insert(file_id.to_string(), meta.clone());
        self.write_meta(sid, &m);
    }

    /// 确认一块已落盘（chunk 阶段）。追加一行到 `pieces/*.jsonl`，O(1)。
    pub(crate) fn set_piece(&self, sid: &str, file_id: &str, piece_index: u64, sha: Option<&str>) {
        let line = PieceLine {
            file_id: file_id.to_string(),
            piece_index,
            sha: sha.map(|s| s.to_string()),
        };
        let data = match serde_json::to_vec(&line) {
            Ok(d) => d,
            Err(e) => {
                log::warn!("序列化确认块失败 {sid}: {e}");
                return;
            }
        };
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.pieces_path(sid))
        {
            Ok(mut f) => {
                if f.write_all(&data).is_err() || f.write_all(b"\n").is_err() {
                    log::warn!("追加确认块失败 {sid}/{file_id}#{piece_index}");
                }
            }
            Err(e) => log::warn!("打开确认块日志失败 {sid}: {e}"),
        }
    }

    /// 会话级状态变更（phase / bitmap_version / 降级原因）。
    pub(crate) fn update_session(
        &self,
        sid: &str,
        phase: TransferState,
        algorithm: Algorithm,
        degrade_reason: Option<DegradeReason>,
        bitmap_version: u64,
    ) {
        let mut m = self.read_meta(sid);
        m.phase = phase;
        m.algorithm = algorithm;
        m.degrade_reason = degrade_reason;
        m.bitmap_version = bitmap_version;
        self.write_meta(sid, &m);
    }

    /// 接收端回传的任务终态。
    pub(crate) fn set_receipt(&self, sid: &str, file_id: &str, receipt: &TaskReceipt) {
        let mut m = self.read_meta(sid);
        m.receipts.insert(file_id.to_string(), receipt.clone());
        self.write_meta(sid, &m);
    }

    /// 终态会话不再有续传价值：删掉它的两份文件，避免僵尸堆积。
    pub(crate) fn remove_session(&self, sid: &str) {
        let _ = fs::remove_file(self.meta_path(sid));
        let _ = fs::remove_file(self.pieces_path(sid));
    }

    /// 冷启动重载：读出所有**未终态**的会话，重建内存 `SessionRecord`。
    ///
    /// 终态会话（Completed/Failed/Aborted）直接丢弃并清理磁盘行 ——
    /// 它们没有续传意义，留着只会让持久化目录无限增长。
    pub(crate) fn load_all(&self) -> Result<HashMap<String, SessionRecord>, String> {
        let mut out: HashMap<String, SessionRecord> = HashMap::new();
        let entries = fs::read_dir(&self.meta_dir).map_err(|e| e.to_string())?;
        let mut terminal = Vec::new();

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            // 跳过崩溃残留的临时文件（`.json.tmp`）
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let meta: MetaFile = match serde_json::from_slice(&bytes) {
                Ok(m) => m,
                Err(e) => {
                    log::warn!("跳过损坏的会话元数据 {:?}: {e}", path);
                    continue;
                }
            };
            let sid = match path.file_stem() {
                Some(s) => s.to_string_lossy().to_string(),
                None => continue,
            };

            if meta.phase.is_terminal() {
                terminal.push(sid);
                continue;
            }

            let mut rec = SessionRecord {
                device_id: meta.device_id,
                phase: meta.phase,
                algorithm: meta.algorithm,
                degrade_reason: meta.degrade_reason,
                bitmap_version: meta.bitmap_version,
                files: meta.files,
                receipts: meta.receipts,
                ..Default::default()
            };

            // 重放确认块追加日志，重建 confirmed / piece_sha 位图
            if let Ok(f) = File::open(self.pieces_path(&sid)) {
                let reader = BufReader::new(f);
                for line in reader.lines() {
                    let line = match line {
                        Ok(l) => l,
                        Err(_) => continue,
                    };
                    if line.trim().is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<PieceLine>(&line) {
                        Ok(pl) => {
                            rec.confirmed
                                .entry(pl.file_id.clone())
                                .or_default()
                                .insert(pl.piece_index);
                            if let Some(s) = pl.sha {
                                rec.piece_sha
                                    .entry(pl.file_id)
                                    .or_default()
                                    .insert(pl.piece_index, s);
                            }
                        }
                        // 半截行（写入中崩溃）：跳过，不影响其余已确认的块
                        Err(_) => continue,
                    }
                }
            }

            out.insert(sid, rec);
        }

        // 清理终态会话的磁盘行
        for sid in &terminal {
            self.remove_session(sid);
        }

        Ok(out)
    }
}

impl MetaFile {
    fn blank() -> Self {
        Self {
            device_id: String::new(),
            phase: TransferState::Idle,
            algorithm: Algorithm::Advanced,
            degrade_reason: None,
            bitmap_version: 0,
            files: HashMap::new(),
            receipts: HashMap::new(),
        }
    }
}
