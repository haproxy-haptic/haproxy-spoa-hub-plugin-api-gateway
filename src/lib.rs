//! API-gateway validation plugin for haproxy-spoa-hub.
//!
//! The initial scope is deliberately narrow: validate buffered JSON request
//! bodies against preconfigured JSON Schemas. The plugin never modifies the
//! request body. Schemas are compiled during `init()` / `validate()` so the
//! per-request path only parses bounded JSON and runs an in-memory validator.

#![allow(non_camel_case_types, non_local_definitions)]

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use haproxy_spoa_hub_plugin_api::{
    ConfigValue, Diagnostic, MetricRecorder, PluginContext, ProcessingResult, RString, RVec,
    SpoeMessage, SpoeValue, TxnVariable, define_plugin,
};
use serde_json::Value;

static METRICS: MetricRecorder = MetricRecorder::new();
static STATE: RwLock<Option<Arc<PluginState>>> = RwLock::new(None);

#[derive(Debug)]
struct ApiGatewayPlugin;

#[derive(Debug)]
struct PluginState {
    config: PluginConfig,
    schemas: HashMap<String, CompiledSchema>,
}

#[derive(Debug, Clone)]
struct PluginConfig {
    default_fail_open: bool,
    max_body_bytes: usize,
    schemas: HashMap<String, SchemaSource>,
}

#[derive(Debug, Clone)]
struct SchemaSource {
    schema_base64: String,
    content_types: Vec<String>,
}

#[derive(Debug)]
struct CompiledSchema {
    validator: jsonschema::Validator,
    content_types: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Allowed,
    InvalidJson,
    SchemaInvalid,
    SchemaNotFound,
    BodyTooLarge,
    UnsupportedMediaType,
    PluginError,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::InvalidJson => "invalid_json",
            Self::SchemaInvalid => "schema_invalid",
            Self::SchemaNotFound => "schema_not_found",
            Self::BodyTooLarge => "body_too_large",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::PluginError => "plugin_error",
        }
    }
}

struct Verdict {
    allowed: bool,
    outcome: Outcome,
    detail: String,
}

define_plugin!(ApiGatewayPlugin, {
    fn new() -> Self {
        ApiGatewayPlugin
    }

    fn init(
        &mut self,
        context: &PluginContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state = PluginState::from_context(context)?;
        let mut guard = STATE
            .write()
            .map_err(|_| "plugin state lock poisoned during init")?;
        *guard = Some(Arc::new(state));
        Ok(())
    }

    fn name(&self) -> &str {
        "api-gateway"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn process(
        &self,
        message: &SpoeMessage,
    ) -> Result<ProcessingResult, Box<dyn std::error::Error + Send + Sync>> {
        let state = STATE
            .read()
            .map_err(|_| "plugin state lock poisoned during process")?
            .as_ref()
            .cloned();
        let Some(state) = state else {
            METRICS.counter(
                "validation_requests_total",
                &[("outcome", "plugin_error")],
                1,
            );
            return Ok(build_result(&Verdict {
                allowed: false,
                outcome: Outcome::PluginError,
                detail: "plugin not initialized".to_string(),
            }));
        };

        let schema_id = message.get_string("schema_id").unwrap_or("").trim();
        if schema_id.is_empty() {
            METRICS.counter("validation_requests_total", &[("outcome", "allowed")], 1);
            return Ok(build_result(&Verdict {
                allowed: true,
                outcome: Outcome::Allowed,
                detail: "no schema id".to_string(),
            }));
        }

        let fail_open = message
            .get_string("fail_open")
            .and_then(parse_bool)
            .unwrap_or(state.config.default_fail_open);
        let max_body_bytes = message
            .get_string("max_body_bytes")
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(state.config.max_body_bytes);
        let content_type = message.get_string("content_type").unwrap_or("");

        let body = message_body(message);
        let verdict = validate_request(
            &state,
            schema_id,
            body,
            content_type,
            max_body_bytes,
            fail_open,
        );
        METRICS.counter(
            "validation_requests_total",
            &[("outcome", verdict.outcome.as_str())],
            1,
        );
        Ok(build_result(&verdict))
    }

    fn config_schema(&self) -> Option<&str> {
        Some(PluginConfig::config_schema())
    }

    fn validate(&self, context: &PluginContext) -> Vec<Diagnostic> {
        match PluginConfig::from_context(context) {
            Ok(config) => compile_schemas(&config)
                .err()
                .unwrap_or_default()
                .into_iter()
                .map(|msg| Diagnostic::error(0, 0, msg))
                .collect(),
            Err(err) => vec![Diagnostic::error(0, 0, err.to_string())],
        }
    }

    metrics_static = METRICS;
});

impl PluginState {
    fn from_context(
        context: &PluginContext,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config = PluginConfig::from_context(context)?;
        let schemas = compile_schemas(&config).map_err(|errors| errors.join("; "))?;
        Ok(Self { config, schemas })
    }
}

impl PluginConfig {
    fn from_context(
        context: &PluginContext,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let default_fail_open = context
            .get_config("default_fail_open")
            .and_then(ConfigValue::as_bool)
            .unwrap_or(false);
        let max_body_bytes = context
            .get_config("max_body_bytes")
            .and_then(ConfigValue::as_integer)
            .filter(|v| *v > 0)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(8 * 1024);

        let schemas = context
            .get_config("schemas")
            .and_then(ConfigValue::as_table)
            .map(parse_schemas_table)
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            default_fail_open,
            max_body_bytes,
            schemas,
        })
    }

    fn config_schema() -> &'static str {
        r#"{
  "type": "object",
  "properties": {
    "default_fail_open": {
      "type": "boolean",
      "description": "Default for routes that do not pass a fail_open SPOE arg; false fails closed."
    },
    "max_body_bytes": {
      "type": "integer",
      "minimum": 1,
      "maximum": 1048576,
      "description": "Default per-request validation body limit in bytes."
    },
    "schemas": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "required": ["schema_base64"],
        "properties": {
          "schema_base64": {
            "type": "string",
            "description": "Base64-encoded JSON Schema document."
          },
          "content_types": {
            "type": "array",
            "items": { "type": "string", "minLength": 1 },
            "description": "Optional request content-types documented for this schema."
          }
        },
        "additionalProperties": false
      }
    }
  },
  "additionalProperties": false
}"#
    }
}

fn parse_schemas_table(
    table: &haproxy_spoa_hub_plugin_api::RHashMap<RString, ConfigValue>,
) -> Result<HashMap<String, SchemaSource>, Box<dyn std::error::Error + Send + Sync>> {
    let mut schemas = HashMap::with_capacity(table.len());
    for haproxy_spoa_hub_plugin_api::Tuple2(name, value) in table {
        let entry = value
            .as_table()
            .ok_or_else(|| format!("schemas.{name} must be a table"))?;
        let schema_base64 = entry
            .get("schema_base64")
            .and_then(ConfigValue::as_str)
            .ok_or_else(|| format!("schemas.{name}.schema_base64 is required"))?
            .trim()
            .to_string();
        let content_types = entry
            .get("content_types")
            .and_then(ConfigValue::as_array)
            .into_iter()
            .flatten()
            .filter_map(ConfigValue::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase())
            .collect();
        schemas.insert(
            name.to_string(),
            SchemaSource {
                schema_base64,
                content_types,
            },
        );
    }
    Ok(schemas)
}

fn compile_schemas(config: &PluginConfig) -> Result<HashMap<String, CompiledSchema>, Vec<String>> {
    let mut compiled = HashMap::with_capacity(config.schemas.len());
    let mut errors = Vec::new();

    for (name, source) in &config.schemas {
        let decoded = match BASE64.decode(source.schema_base64.trim()) {
            Ok(v) => v,
            Err(err) => {
                errors.push(format!("schema '{name}' is not valid base64: {err}"));
                continue;
            }
        };
        let schema_json: Value = match serde_json::from_slice(&decoded) {
            Ok(v) => v,
            Err(err) => {
                errors.push(format!("schema '{name}' is not valid JSON: {err}"));
                continue;
            }
        };
        match jsonschema::validator_for(&schema_json) {
            Ok(validator) => {
                compiled.insert(
                    name.clone(),
                    CompiledSchema {
                        validator,
                        content_types: source.content_types.clone(),
                    },
                );
            }
            Err(err) => {
                errors.push(format!("schema '{name}' is not a valid JSON Schema: {err}"));
            }
        }
    }

    if errors.is_empty() {
        Ok(compiled)
    } else {
        Err(errors)
    }
}

fn validate_request(
    state: &PluginState,
    schema_id: &str,
    body: &[u8],
    content_type: &str,
    max_body_bytes: usize,
    fail_open: bool,
) -> Verdict {
    let Some(schema) = state.schemas.get(schema_id) else {
        return Verdict {
            allowed: fail_open,
            outcome: Outcome::SchemaNotFound,
            detail: format!("schema '{schema_id}' is not configured"),
        };
    };

    if !schema.content_types.is_empty()
        && !schema
            .content_types
            .iter()
            .any(|allowed| content_type_matches(content_type, allowed))
    {
        return Verdict {
            allowed: false,
            outcome: Outcome::UnsupportedMediaType,
            detail: format!(
                "content-type '{content_type}' is not accepted by schema '{schema_id}'"
            ),
        };
    }

    if body.len() > max_body_bytes {
        return Verdict {
            allowed: false,
            outcome: Outcome::BodyTooLarge,
            detail: format!(
                "request body is {} bytes; limit is {max_body_bytes}",
                body.len()
            ),
        };
    }

    let json: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(err) => {
            return Verdict {
                allowed: false,
                outcome: Outcome::InvalidJson,
                detail: format!("invalid JSON request body: {err}"),
            };
        }
    };

    if schema.validator.is_valid(&json) {
        Verdict {
            allowed: true,
            outcome: Outcome::Allowed,
            detail: "valid".to_string(),
        }
    } else {
        let detail = schema
            .validator
            .iter_errors(&json)
            .next()
            .map(|err| format!("{}: {err}", err.instance_path()))
            .unwrap_or_else(|| "schema validation failed".to_string());
        Verdict {
            allowed: false,
            outcome: Outcome::SchemaInvalid,
            detail,
        }
    }
}

fn content_type_matches(actual: &str, allowed: &str) -> bool {
    let actual = actual
        .split_once(';')
        .map_or(actual, |(media_type, _)| media_type)
        .trim()
        .to_ascii_lowercase();
    actual == allowed.trim().to_ascii_lowercase()
}

fn message_body(message: &SpoeMessage) -> &[u8] {
    message
        .get_binary("body")
        .or_else(|| message.get_string("body").map(str::as_bytes))
        .unwrap_or(&[])
}

fn parse_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn build_result(verdict: &Verdict) -> ProcessingResult {
    let mut vars = RVec::with_capacity(4);
    vars.push(TxnVariable::transaction(
        "allowed",
        SpoeValue::Bool(verdict.allowed),
    ));
    vars.push(TxnVariable::transaction(
        "outcome",
        SpoeValue::String(verdict.outcome.as_str().into()),
    ));
    vars.push(TxnVariable::transaction(
        "detail",
        SpoeValue::String(truncate_detail(&verdict.detail).into()),
    ));
    vars.push(TxnVariable::transaction(
        "schema_known",
        SpoeValue::Bool(verdict.outcome != Outcome::SchemaNotFound),
    ));
    ProcessingResult { variables: vars }
}

fn truncate_detail(s: &str) -> String {
    const MAX: usize = 240;
    if s.len() <= MAX {
        return s.to_string();
    }
    let mut end = MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use haproxy_spoa_hub_plugin_api::{RHashMap, SpoeValue, Tuple2};

    fn schema_b64(schema: &str) -> String {
        BASE64.encode(schema.as_bytes())
    }

    fn config_with_schema(schema: &str) -> PluginConfig {
        let mut schemas = HashMap::new();
        schemas.insert(
            "test".to_string(),
            SchemaSource {
                schema_base64: schema_b64(schema),
                content_types: vec!["application/json".to_string()],
            },
        );
        PluginConfig {
            default_fail_open: false,
            max_body_bytes: 1024,
            schemas,
        }
    }

    fn state_with_schema(schema: &str) -> PluginState {
        let config = config_with_schema(schema);
        let schemas = compile_schemas(&config).expect("schema compiles");
        PluginState { config, schemas }
    }

    fn ctx_with_schema(schema: &str) -> PluginContext {
        let mut schema_entry = RHashMap::new();
        schema_entry.insert(
            RString::from("schema_base64"),
            ConfigValue::String(schema_b64(schema).into()),
        );

        let mut schemas = RHashMap::new();
        schemas.insert(RString::from("test"), ConfigValue::Table(schema_entry));

        let mut config = RHashMap::new();
        config.insert(RString::from("schemas"), ConfigValue::Table(schemas));
        PluginContext {
            name: RString::from("api_gateway"),
            config,
        }
    }

    fn msg(schema_id: &str, body: &[u8]) -> SpoeMessage {
        let mut args = RHashMap::new();
        args.insert(
            RString::from("schema_id"),
            SpoeValue::String(schema_id.into()),
        );
        args.insert(
            RString::from("body"),
            SpoeValue::Binary(body.to_vec().into()),
        );
        SpoeMessage {
            name: RString::from("validate-request"),
            args,
            stream_id: 1,
            frame_id: 1,
        }
    }

    fn result_var<'a>(result: &'a ProcessingResult, name: &str) -> &'a SpoeValue {
        result
            .variables
            .iter()
            .find_map(|v| (v.name.as_str() == name).then_some(&v.value))
            .expect("variable exists")
    }

    #[test]
    fn compiles_valid_schema() {
        let config = config_with_schema(r#"{"type":"object"}"#);
        let compiled = compile_schemas(&config).expect("compile succeeds");
        assert!(compiled.contains_key("test"));
    }

    #[test]
    fn reports_invalid_schema_json() {
        let config = config_with_schema("{");
        let errors = compile_schemas(&config).expect_err("compile fails");
        assert!(errors[0].contains("not valid JSON"));
    }

    #[test]
    fn allows_valid_request() {
        let state = state_with_schema(
            r#"{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}"#,
        );
        let verdict = validate_request(
            &state,
            "test",
            br#"{"name":"alice"}"#,
            "application/json",
            1024,
            false,
        );
        assert!(verdict.allowed);
        assert_eq!(verdict.outcome, Outcome::Allowed);
    }

    #[test]
    fn denies_invalid_json() {
        let state = state_with_schema(r#"{"type":"object"}"#);
        let verdict = validate_request(&state, "test", b"{", "application/json", 1024, false);
        assert!(!verdict.allowed);
        assert_eq!(verdict.outcome, Outcome::InvalidJson);
    }

    #[test]
    fn denies_schema_mismatch() {
        let state = state_with_schema(
            r#"{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}"#,
        );
        let verdict = validate_request(
            &state,
            "test",
            br#"{"name":42}"#,
            "application/json",
            1024,
            false,
        );
        assert!(!verdict.allowed);
        assert_eq!(verdict.outcome, Outcome::SchemaInvalid);
        assert!(verdict.detail.contains("type"));
    }

    #[test]
    fn denies_oversized_body() {
        let state = state_with_schema(r#"{"type":"object"}"#);
        let verdict = validate_request(
            &state,
            "test",
            br#"{"name":"alice"}"#,
            "application/json",
            4,
            false,
        );
        assert!(!verdict.allowed);
        assert_eq!(verdict.outcome, Outcome::BodyTooLarge);
    }

    #[test]
    fn missing_schema_obeys_fail_open() {
        let state = state_with_schema(r#"{"type":"object"}"#);
        let closed = validate_request(&state, "missing", br#"{}"#, "application/json", 1024, false);
        assert!(!closed.allowed);
        assert_eq!(closed.outcome, Outcome::SchemaNotFound);

        let open = validate_request(&state, "missing", br#"{}"#, "application/json", 1024, true);
        assert!(open.allowed);
        assert_eq!(open.outcome, Outcome::SchemaNotFound);
    }

    #[test]
    fn process_returns_prefixed_variables_for_valid_request() {
        let ctx = ctx_with_schema(r#"{"type":"object"}"#);
        let mut plugin = ApiGatewayPlugin::__new();
        plugin.__init(&ctx).expect("init");
        let result = plugin
            .__process(&msg("test", br#"{"ok":true}"#))
            .expect("process");
        assert!(matches!(
            result_var(&result, "allowed"),
            SpoeValue::Bool(true)
        ));
        match result_var(&result, "outcome") {
            SpoeValue::String(value) => assert_eq!(value.as_str(), "allowed"),
            other => panic!("unexpected outcome value: {other:?}"),
        }
    }

    #[test]
    fn denies_unaccepted_content_type() {
        let state = state_with_schema(r#"{"type":"object"}"#);
        let verdict = validate_request(
            &state,
            "test",
            br#"{"name":"alice"}"#,
            "text/plain",
            1024,
            false,
        );
        assert!(!verdict.allowed);
        assert_eq!(verdict.outcome, Outcome::UnsupportedMediaType);
    }

    #[test]
    fn accepts_content_type_parameters_case_insensitively() {
        let state = state_with_schema(r#"{"type":"object"}"#);
        let verdict = validate_request(
            &state,
            "test",
            br#"{"name":"alice"}"#,
            "Application/JSON; charset=utf-8",
            1024,
            false,
        );
        assert!(verdict.allowed);
        assert_eq!(verdict.outcome, Outcome::Allowed);
    }

    #[test]
    fn validate_reports_bad_schema() {
        let ctx = ctx_with_schema("{");
        let plugin = ApiGatewayPlugin::__new();
        let diagnostics = plugin.__validate(&ctx);
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message.as_str().contains("not valid JSON"));
    }

    #[test]
    fn parse_schemas_table_accepts_content_types() {
        let mut entry = RHashMap::new();
        entry.insert(
            RString::from("schema_base64"),
            ConfigValue::String(schema_b64(r#"{"type":"object"}"#).into()),
        );
        entry.insert(
            RString::from("content_types"),
            ConfigValue::Array(vec![ConfigValue::String("Application/JSON".into())].into()),
        );
        let mut table = RHashMap::new();
        table.insert(RString::from("x"), ConfigValue::Table(entry));
        let parsed = parse_schemas_table(&table).expect("parse");
        assert_eq!(parsed["x"].content_types, vec!["application/json"]);
    }

    #[test]
    fn truncate_detail_keeps_utf8_boundary() {
        let input = "ä".repeat(300);
        let out = truncate_detail(&input);
        assert!(out.ends_with('…'));
        assert!(out.is_char_boundary(out.len()));
    }

    #[test]
    fn rstring_hashmap_lookup_from_str_works_in_tests() {
        let mut map = RHashMap::new();
        map.insert(RString::from("k"), ConfigValue::Bool(true));
        assert_eq!(map.get("k").and_then(ConfigValue::as_bool), Some(true));
    }

    #[test]
    fn tuple2_pattern_stays_available_for_iterators() {
        let mut map = RHashMap::new();
        map.insert(RString::from("k"), ConfigValue::Bool(true));
        let Tuple2(k, _) = map.iter().next().expect("entry");
        assert_eq!(k.as_str(), "k");
    }
}
