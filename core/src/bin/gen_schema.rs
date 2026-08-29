//! 从 Rust DTO 生成 JSON Schema 到 `protocol/schemas/v4/`
//!
//! 用法：
//! ```text
//! cargo run --bin gen-schema              # 生成 / 覆盖
//! cargo run --bin gen-schema -- --check   # 只校验，不一致则退出码 1（供 CI 使用）
//! ```
//!
//! # 为什么需要这个
//!
//! `protocol/schemas/` 下原有 9 份**手写** JSON Schema。手写契约与实现必然漂移，
//! 实际已经对不上：
//! - `README.md` 说协议 3.0，`probe.response.golden.json` 写 3.1
//! - `README.md` 说"无独立 pair/initiate + pair/status 端点"，
//!   `golden/manifest.json` 的 endpoints 又列了它们
//! - `golden/manifest.json` 的 `schemaHash` 仍是 `PENDING_FIRST_CAPTURE`，
//!   意味着契约指纹从未回填、golden 校验事实上未生效
//!
//! 改为从类型生成后，schema 就是实现本身，不可能漂移。

use schemars::schema::RootSchema;
use std::path::{Path, PathBuf};

use lanbackup_core::dto::*;

/// schema 输出目录（相对 core/）
const OUT_DIR: &str = "../protocol/schemas/v4";

/// `$id` 前缀
const ID_PREFIX: &str = "https://lanbackup/schemas/v4";

/// 生成一条 schema
fn emit(name: &str, schema: RootSchema) -> (String, String) {
    let mut schema = schema;
    let file_name = format!("{name}.schema.json");

    // 注入 $id，便于 golden 与实现互相引用
    if let Some(meta) = schema.schema.metadata.as_mut() {
        meta.id = Some(format!("{ID_PREFIX}/{file_name}"));
        meta.title = Some(format!("V4 {name}"));
    }

    let json = serde_json::to_string_pretty(&schema)
        .unwrap_or_else(|e| panic!("schema {name} 序列化失败: {e}"));
    (file_name, json)
}

/// 全部需要生成 schema 的类型。**新增 DTO 时必须登记在此**，
/// 否则 CI 的 --check 不会发现它。
fn all_schemas() -> Vec<(String, String)> {
    vec![
        // 公共
        emit("device-type", schemars::schema_for!(DeviceType)),
        emit("endpoint", schemars::schema_for!(Endpoint)),
        emit("presence", schemars::schema_for!(Presence)),
        emit("request-meta", schemars::schema_for!(RequestMeta)),
        // 发现与配对
        emit("probe.response", schemars::schema_for!(ProbeResponse)),
        emit(
            "handshake.challenge",
            schemars::schema_for!(handshake::ChallengeRequest),
        ),
        emit(
            "handshake.challenge.response",
            schemars::schema_for!(handshake::ChallengeResponse),
        ),
        emit(
            "handshake.verify",
            schemars::schema_for!(handshake::VerifyRequest),
        ),
        emit(
            "handshake.verify.response",
            schemars::schema_for!(handshake::VerifyResponse),
        ),
        emit(
            "handshake.status",
            schemars::schema_for!(handshake::HandshakeStatusResponse),
        ),
        emit("pairing-state", schemars::schema_for!(handshake::PairingState)),
        emit("unpair-request", schemars::schema_for!(handshake::UnpairRequest)),
        emit("unpair", schemars::schema_for!(handshake::UnpairNotification)),
        emit("revoke-notify", schemars::schema_for!(handshake::RevokeNotify)),
        emit("revoke-ack", schemars::schema_for!(handshake::RevokeAck)),
        emit(
            "sync-status",
            schemars::schema_for!(handshake::SyncStatusResponse),
        ),
        // 传输会话
        emit("transfer-phase", schemars::schema_for!(session::TransferPhase)),
        emit("algorithm", schemars::schema_for!(session::Algorithm)),
        emit(
            "degrade-reason",
            schemars::schema_for!(session::DegradeReason),
        ),
        emit("file-meta", schemars::schema_for!(session::FileMeta)),
        emit(
            "session.register",
            schemars::schema_for!(session::SessionRegisterRequest),
        ),
        emit(
            "session.register.response",
            schemars::schema_for!(session::SessionRegisterResponse),
        ),
        emit("session.prepare", schemars::schema_for!(session::PrepareRequest)),
        emit(
            "session.prepare.response",
            schemars::schema_for!(session::PrepareResponse),
        ),
        emit("chunk-diff", schemars::schema_for!(session::ChunkDiff)),
        emit(
            "diff-mismatch",
            schemars::schema_for!(session::DiffMismatch),
        ),
        emit(
            "session.verify.response",
            schemars::schema_for!(session::VerifyFileResponse),
        ),
        emit("session.phase", schemars::schema_for!(session::PhaseResponse)),
        emit(
            "session.heartbeat",
            schemars::schema_for!(session::HeartbeatRequest),
        ),
        emit(
            "session.heartbeat.response",
            schemars::schema_for!(session::HeartbeatResponse),
        ),
        emit("task-status", schemars::schema_for!(session::TaskStatus)),
        emit("task-receipt", schemars::schema_for!(session::TaskReceipt)),
        emit("session.receipt", schemars::schema_for!(session::ReceiptRequest)),
        emit("session.tasks", schemars::schema_for!(session::TaskListResponse)),
        emit("session.abort", schemars::schema_for!(session::AbortRequest)),
        // 清单与同步
        emit("sync-strategy", schemars::schema_for!(sync::SyncStrategy)),
        emit("manifest-entry", schemars::schema_for!(sync::ManifestEntry)),
        emit("manifest", schemars::schema_for!(sync::Manifest)),
        emit("sync-plan", schemars::schema_for!(sync::SyncPlan)),
        emit(
            "chunk-status.response",
            schemars::schema_for!(sync::ChunkStatusResponse),
        ),
        emit("sync-dir", schemars::schema_for!(sync::SyncDirRequest)),
        emit(
            "move-to-delete",
            schemars::schema_for!(sync::MoveToDeleteRequest),
        ),
        emit("disconnect", schemars::schema_for!(sync::DisconnectRequest)),
        // 错误
        emit("error", schemars::schema_for!(lanbackup_core::ErrorEnvelope)),
        emit("error-code", schemars::schema_for!(lanbackup_core::ErrorCode)),
    ]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let check = args.iter().any(|a| a == "--check");
    let golden = args.iter().any(|a| a == "--golden");
    let out = PathBuf::from(OUT_DIR);

    if !check && !golden {
        std::fs::create_dir_all(&out).expect("创建输出目录失败");
    }

    let mut drifted: Vec<String> = Vec::new();

    for (name, json) in all_schemas() {
        let path: PathBuf = Path::new(&out).join(&name);
        if check {
            let existing = std::fs::read_to_string(&path).unwrap_or_default();
            if existing.trim() != json.trim() {
                drifted.push(name);
            }
        } else if !golden {
            std::fs::write(&path, format!("{json}\n")).unwrap_or_else(|e| {
                panic!("写入 {name} 失败: {e}");
            });
        }
    }

    if check {
        if drifted.is_empty() {
            println!("schema 与实现一致（{} 项）", all_schemas().len());
        } else {
            eprintln!("以下 schema 与 Rust 类型不一致，请运行 `pnpm --filter lanbackup-core schema` 重新生成：");
            for name in &drifted {
                eprintln!("  - {name}");
            }
            std::process::exit(1);
        }
        return;
    }

    if golden {
        emit_golden(&out);
        return;
    }

    println!(
        "已生成 {} 份 schema 到 {}",
        all_schemas().len(),
        out.display()
    );
}

/// 计算全部 v4 schema 的 SHA-256 指纹，写入 `golden-manifest.json`。
///
/// 这是 V4 的「golden」：契约即代码，schema 由 `core/src/dto` 生成，
/// 指纹 = 所有 schema 文件（按文件名排序、canonical JSON）拼接后的 SHA-256。
/// 任何一个 DTO 改动导致 schema 变化，指纹必然改变，CI 比对即报警。
///
/// 旧版 `protocol/golden/manifest.json` 的 `schemaHash` 一直是
/// `PENDING_FIRST_CAPTURE`，意味着校验从未真正生效；此处将其落实。
fn emit_golden(out: &Path) {
    use sha2::{Digest, Sha256};

    let mut paths: Vec<PathBuf> = std::fs::read_dir(out)
        .expect("读取 schema 目录失败")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|x| x.to_str())
                .map(|x| x.ends_with(".schema.json"))
                .unwrap_or(false)
        })
        .collect();
    paths.sort();

    let mut hasher = Sha256::new();
    for p in &paths {
        let text = std::fs::read_to_string(p).expect("读取 schema 失败");
        // canonical：解析再序列化，消除空白/键序差异
        let v: serde_json::Value =
            serde_json::from_str(&text).expect("schema 不是合法 JSON");
        let canonical = serde_json::to_string(&v).expect("schema 规范化失败");
        hasher.update(canonical.as_bytes());
    }
    let hash = hex::encode(hasher.finalize());

    let manifest = serde_json::json!({
        "schemaHash": hash,
        "algorithm": "SHA-256",
        "description": "V4 契约指纹：全部 protocol/schemas/v4/*.schema.json（按文件名排序、canonical JSON）拼接后的 SHA-256。任一 DTO 变更导致 schema 变化，指纹必变，CI 比对即报警。由 `gen_schema --golden` 生成。",
        "schemaCount": paths.len(),
        "endpoints": [
            "GET /api/v4/probe",
            "POST /api/v4/handshake/challenge",
            "POST /api/v4/handshake/verify",
            "GET /api/v4/handshake/status",
            "POST /api/v4/pair/unpair",
            "POST /api/v4/pair/revoke",
            "POST /api/v4/session/register",
            "POST /api/v4/session/prepare",
            "POST /api/v4/session/chunk-diff",
            "GET /api/v4/session/{id}/phase",
            "POST /api/v4/session/heartbeat",
            "POST /api/v4/session/abort",
            "GET /api/v4/sync/status",
            "POST /api/v4/sync/dir",
            "POST /api/v4/sync/move-to-delete",
            "POST /api/v4/sync/disconnect"
        ]
    });

    let path = Path::new(out).join("golden-manifest.json");
    std::fs::write(&path, format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap()))
        .expect("写入 golden-manifest 失败");
    println!(
        "已生成 golden-manifest.json：{} 份 schema，SHA-256 = {}",
        paths.len(),
        hash
    );
}
