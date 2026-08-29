//! 契约 conformance 测试
//!
//! 目的：确保 `protocol/schemas/v4/` 下由 `gen_schema` 生成的每一份
//! JSON Schema 都是**结构合法、可被标准 JSON Schema 校验器接受**的
//! Draft-07 文档。
//!
//! 这是 V4「契约即代码」的兜底闸门：
//! - `gen_schema --check`（CI）保证「提交的 schema == 类型生成的 schema」
//! - 本测试保证「生成的 schema 本身是合法契约，下游消费方不会炸」
//!
//! 历史上 `protocol/schemas/` 是手写契约，既与实现漂移、又从未被校验过
//! （`golden/manifest.json` 的 `schemaHash` 一直是 `PENDING_FIRST_CAPTURE`）。
//! 从类型生成 + 本测试 + `--check`，三道闸门彻底堵死漂移。

use std::fs;
use std::path::PathBuf;

/// 标准 Draft-07 meta-schema（JSON Schema 规范固定内容）。
/// 内嵌以避免任何网络依赖；用它校验每一份生成的 schema。
const DRAFT07_META: &str = r##"{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "http://json-schema.org/draft-07/schema#",
  "title": "Core schema meta-schema",
  "definitions": {
    "schemaArray": { "type": "array", "items": { "$ref": "#" } },
    "nonNegativeInteger": { "type": "integer", "minimum": 0 },
    "nonNegativeIntegerDefault0": {
      "allOf": [ { "$ref": "#/definitions/nonNegativeInteger" }, { "default": 0 } ]
    },
    "simpleTypes": {
      "enum": [ "array", "boolean", "integer", "null", "number", "object", "string" ]
    },
    "stringArray": { "type": "array", "items": { "type": "string" } }
  },
  "type": ["object", "boolean"],
  "properties": {
    "$id": { "type": "string", "format": "uri-reference" },
    "$schema": { "type": "string", "format": "uri" },
    "$ref": { "type": "string", "format": "uri-reference" },
    "$comment": { "type": "string" },
    "title": { "type": "string" },
    "description": { "type": "string" },
    "default": true,
    "readOnly": { "type": "boolean", "default": false },
    "writeOnly": { "type": "boolean", "default": false },
    "examples": { "type": "array", "items": true },
    "multipleOf": { "type": "number", "exclusiveMinimum": 0 },
    "maximum": { "type": "number" },
    "exclusiveMaximum": { "type": "number" },
    "minimum": { "type": "number" },
    "exclusiveMinimum": { "type": "number" },
    "maxLength": { "$ref": "#/definitions/nonNegativeInteger" },
    "minLength": { "$ref": "#/definitions/nonNegativeInteger" },
    "pattern": { "type": "string", "format": "regex" },
    "additionalItems": { "$ref": "#" },
    "items": { "$ref": "#" },
    "maxItems": { "$ref": "#/definitions/nonNegativeInteger" },
    "minItems": { "$ref": "#/definitions/nonNegativeInteger" },
    "uniqueItems": { "type": "boolean", "default": false },
    "contains": { "$ref": "#" },
    "maxProperties": { "$ref": "#/definitions/nonNegativeInteger" },
    "minProperties": { "$ref": "#/definitions/nonNegativeInteger" },
    "required": { "$ref": "#/definitions/stringArray" },
    "additionalProperties": { "$ref": "#" },
    "properties": { "type": "object", "additionalProperties": { "$ref": "#" }, "default": {} },
    "patternProperties": { "type": "object", "additionalProperties": { "$ref": "#" }, "default": {} },
    "dependencies": {
      "type": "object",
      "additionalProperties": {
        "anyOf": [ { "$ref": "#" }, { "$ref": "#/definitions/stringArray" } ]
      }
    },
    "propertyNames": { "$ref": "#" },
    "const": true,
    "enum": { "type": "array", "items": true, "minItems": 1, "uniqueItems": true },
    "type": {
      "anyOf": [
        { "$ref": "#/definitions/simpleTypes" },
        { "type": "array", "items": { "$ref": "#/definitions/simpleTypes" }, "minItems": 1, "uniqueItems": true }
      ]
    },
    "format": { "type": "string" },
    "contentMediaType": { "type": "string" },
    "contentEncoding": { "type": "string" },
    "if": { "$ref": "#" },
    "then": { "$ref": "#" },
    "else": { "$ref": "#" },
    "allOf": { "$ref": "#/definitions/schemaArray" },
    "anyOf": { "$ref": "#/definitions/schemaArray" },
    "oneOf": { "$ref": "#/definitions/schemaArray" },
    "not": { "$ref": "#" }
  },
  "default": true
}"##;

/// 定位 `protocol/schemas/v4/` 目录（相对 crate 根）
fn schema_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../protocol/schemas/v4")
}

#[test]
fn every_generated_schema_is_valid_draft07() {
    let meta: serde_json::Value =
        serde_json::from_str(DRAFT07_META).expect("内嵌的 draft-07 meta-schema 必须是合法 JSON");
    let validator = jsonschema::JSONSchema::compile(&meta)
        .expect("draft-07 meta-schema 必须能编译为校验器");

    let dir = schema_dir();
    assert!(dir.exists(), "schema 目录不存在: {}", dir.display());

    let mut files: Vec<_> = fs::read_dir(&dir)
        .expect("读取 schema 目录失败")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|x| x.to_str())
                .map(|x| x == "json")
                .unwrap_or(false)
                && p.file_name()
                    .and_then(|x| x.to_str())
                    .map(|x| x.ends_with(".schema.json"))
                    .unwrap_or(false)
        })
        .collect();
    files.sort();

    assert!(!files.is_empty(), "没有找到任何 *.schema.json，生成步骤可能未执行");

    let mut failures: Vec<String> = Vec::new();

    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let content = fs::read_to_string(path).expect("读取 schema 文件失败");
        let schema: serde_json::Value =
            match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(e) => {
                    failures.push(format!("  - {name}: JSON 解析失败: {e}"));
                    continue;
                }
            };

        // 必须声明 draft-07，与生成器一致
        let declared = schema
            .get("$schema")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if declared != "http://json-schema.org/draft-07/schema#" {
            failures.push(format!(
                "  - {name}: $schema 应为 draft-07，实际为 {declared:?}"
            ));
        }

        // 用 meta-schema 校验其结构合法性
        match validator.validate(&schema) {
            Ok(()) => {}
            Err(errors) => {
                let msg = errors
                    .take(3)
                    .map(|e| format!("      · {}", e))
                    .collect::<Vec<_>>()
                    .join("\n");
                failures.push(format!("  - {name}: 不是合法 JSON Schema:\n{msg}"));
            }
        };
    }

    assert!(
        failures.is_empty(),
        "以下 {} 份 schema 未通过 conformance 校验:\n{}",
        failures.len(),
        failures.join("\n")
    );

    eprintln!("conformance 通过：{} 份 schema 均为合法 Draft-07", files.len());
}
