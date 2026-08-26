//! v3 协议 conformance 测试（方案.txt §3.8 / H.2）
//!
//! 用 jsonschema（仅 dev-dependency，锁版本 0.18）校验双端共享的 Schema 与 Golden File：
//! - L1 类型层：真实响应结构必须满足 Schema（字段名/类型/必填）
//! - Golden File：来自"真实 HTTP 响应"的样例必须持续满足 Schema（防字段漂移）
//! 双端（Rust cargo test / Java JUnit + networknt）各自跑同一套 Schema，防双端协议漂移。

use serde_json::Value;

const PROBE_RESPONSE_SCHEMA: &str = include_str!("../../../protocol/schemas/probe.response.schema.json");
const PROBE_RESPONSE_GOLDEN: &str = include_str!("../../../protocol/golden/probe.response.golden.json");
const VERIFY_RESPONSE_SCHEMA: &str = include_str!("../../../protocol/schemas/handshake.verify.schema.json");
const CHALLENGE_RESPONSE_SCHEMA: &str = include_str!("../../../protocol/schemas/handshake.challenge.schema.json");
const COMMON_SCHEMA: &str = include_str!("../../../protocol/schemas/common.schema.json");

fn compile(schema_val: &Value) -> jsonschema::JSONSchema {
    // 不显式指定 Draft：jsonschema 从 schema 的 $schema 关键字自动推断（probe 用 draft-07，其余 2020-12）
    jsonschema::JSONSchema::compile(schema_val).expect("Schema 编译失败")
}

/// 从自定义"request/response 双对象"结构的 schema 文件中提取 response 子 schema
fn response_sub_schema(schema_str: &str) -> Value {
    let v: Value = serde_json::from_str(schema_str).expect("schema JSON 解析失败");
    v.get("response").cloned().expect("schema 缺少 response 定义")
}

#[test]
fn probe_response_golden_conforms() {
    // Golden File（应来自真实 probe 响应）必须满足 probe.response.schema.json
    let schema: Value = serde_json::from_str(PROBE_RESPONSE_SCHEMA).unwrap();
    let validator = compile(&schema);
    let golden: Value = serde_json::from_str(PROBE_RESPONSE_GOLDEN).expect("golden 解析失败");
    let errors: Vec<String> = validator
        .validate(&golden)
        .err()
        .map(|it| it.map(|e| e.to_string()).collect())
        .unwrap_or_default();
    assert!(errors.is_empty(), "probe golden 不满足 schema: {errors:?}");
}

#[test]
fn probe_response_fields_required() {
    // 缺 staticPub/serverNonce 必须被 schema 拒绝（首次配对材料不可缺）
    let schema: Value = serde_json::from_str(PROBE_RESPONSE_SCHEMA).unwrap();
    let validator = compile(&schema);
    let bad: Value = serde_json::json!({
        "deviceId": "d3b0c6e2-4f1a-4c8e-9b2d-8a0f7e1c5a3b",
        "alias": "X",
        "deviceType": "mobile",
        "port": 53317,
        "protocolVersion": "3.0",
        "capabilities": { "maxChunkSize": 262144, "supportedEncryption": ["aes-256-gcm"], "supportsResume": true }
    });
    assert!(!validator.is_valid(&bad), "缺 staticPub/serverNonce 必须被拒");
}

#[test]
fn verify_response_conforms() {
    let response_schema = response_sub_schema(VERIFY_RESPONSE_SCHEMA);
    let validator = compile(&response_schema);
    let resp: Value = serde_json::json!({
        "status": "approved",
        "deviceId": "d3b0c6e2-4f1a-4c8e-9b2d-8a0f7e1c5a3b",
        "publicKey": "BG7vO0K0G9T2QhCeWfG6W4pDzNvRcXy0VnQhLk1aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wX3yZ4aB5cD6eF7gH8iJ9",
        "signature": "MEUCIQDTbYxqvJfKj8Zv6yM0c2fL7w2n0vQzHwX9pYx4s6u8qAMEUCIQDKd1gYxzJmTcUq3nXwVp2r6yS9tLmN0g8aZ4cE7fH5vL1k",
        "capabilities": { "maxChunkSize": 262144, "supportedEncryption": ["aes-256-gcm"], "supportsResume": true }
    });
    assert!(validator.is_valid(&resp), "verify 响应不满足 schema");
}

#[test]
fn verify_response_no_secrets() {
    // 方案.txt §3.4 前提：verify 响应绝不包含任何密钥字段（additionalProperties:false → 多余字段被拒）
    let response_schema = response_sub_schema(VERIFY_RESPONSE_SCHEMA);
    let validator = compile(&response_schema);
    let leak: Value = serde_json::json!({
        "status": "approved",
        "deviceId": "d3b0c6e2-4f1a-4c8e-9b2d-8a0f7e1c5a3b",
        "pairingSecret": "dGhpc2lzYXNlY3JldA",
        "capabilities": { "maxChunkSize": 262144, "supportedEncryption": ["aes-256-gcm"], "supportsResume": true }
    });
    assert!(!validator.is_valid(&leak), "verify 响应泄露密钥必须被拒");
}

#[test]
fn challenge_response_conforms() {
    let response_schema = response_sub_schema(CHALLENGE_RESPONSE_SCHEMA);
    let validator = compile(&response_schema);
    let resp: Value = serde_json::json!({
        "challengeToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxIn0.c2lnbmF0dXJl",
        "serverEphPub": "BL7vO0K0G9T2QhCeWfG6W4pDzNvRcXy0VnQhLk1aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wX3yZ4aB5cD6eF7gH8iJ9"
    });
    assert!(validator.is_valid(&resp), "challenge 响应不满足 schema");
}

#[test]
fn error_envelope_conforms() {
    // 统一错误格式必须满足 common.schema.json 的 $defs.error
    let common: Value = serde_json::from_str(COMMON_SCHEMA).unwrap();
    let error_def = common.get("$defs").and_then(|d| d.get("error")).cloned().expect("common 缺 $defs.error");
    let validator = compile(&error_def);
    let err: Value = serde_json::json!({
        "error": { "code": "RATE_LIMIT_EXCEEDED", "message": "Too many requests", "requestId": "req-123" }
    });
    assert!(validator.is_valid(&err), "错误信封不满足 schema");
}

// ═══════════════════════════════════════════════════════════════════
// 数据面 conformance（方案 A：P0）：manifest / prepare-upload / chunk-status
// 双端共享 protocol/schemas + protocol/golden，各自独立校验（Rust jsonschema / Java networknt）。
// ═══════════════════════════════════════════════════════════════════

const MANIFEST_SCHEMA: &str = include_str!("../../../protocol/schemas/manifest.schema.json");
const PREPARE_REQ_SCHEMA: &str = include_str!("../../../protocol/schemas/prepare-upload.request.schema.json");
const PREPARE_RESP_SCHEMA: &str = include_str!("../../../protocol/schemas/prepare-upload.response.schema.json");
const CHUNK_STATUS_SCHEMA: &str = include_str!("../../../protocol/schemas/chunk-status.response.schema.json");

/// 校验一组 (名称, JSON 内容) 均满足指定 schema
fn assert_all_valid(schema_str: &str, cases: &[(&str, &str)]) {
    let schema: Value = serde_json::from_str(schema_str).unwrap();
    let validator = compile(&schema);
    for (name, content) in cases {
        let instance: Value = serde_json::from_str(content).unwrap_or_else(|e| panic!("{name} 不是合法 JSON: {e}"));
        let errors: Vec<String> = validator
            .validate(&instance)
            .err()
            .map(|it| it.map(|e| e.to_string()).collect())
            .unwrap_or_default();
        assert!(errors.is_empty(), "{name} 不满足 schema: {errors:?}");
    }
}

#[test]
fn manifest_schema_conformance() {
    assert_all_valid(
        MANIFEST_SCHEMA,
        &[
            ("manifest.small.json", include_str!("../../../protocol/golden/manifest.small.json")),
            ("manifest.large.json", include_str!("../../../protocol/golden/manifest.large.json")),
            ("manifest.multiple.json", include_str!("../../../protocol/golden/manifest.multiple.json")),
        ],
    );
}

#[test]
fn prepare_upload_request_conformance() {
    assert_all_valid(
        PREPARE_REQ_SCHEMA,
        &[
            ("prepare-upload.request.json", include_str!("../../../protocol/golden/prepare-upload.request.json")),
        ],
    );
}

#[test]
fn prepare_upload_response_conformance() {
    assert_all_valid(
        PREPARE_RESP_SCHEMA,
        &[
            ("prepare-upload.response.json", include_str!("../../../protocol/golden/prepare-upload.response.json")),
        ],
    );
}

#[test]
fn chunk_status_response_conformance() {
    assert_all_valid(
        CHUNK_STATUS_SCHEMA,
        &[
            ("chunk-status.response.json", include_str!("../../../protocol/golden/chunk-status.response.json")),
        ],
    );
}
