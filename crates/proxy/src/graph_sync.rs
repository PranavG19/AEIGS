use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::types::RecordedExchange;

pub struct ProxyGraphSync;

pub struct SyncResult {
    pub endpoints_added: usize,
    pub parameters_discovered: usize,
    pub operations: Vec<OperationLogEntry>,
}

/// Convert recorded proxy exchanges into knowledge graph operations.
///
/// Deduplicates by (path, method) — only the first occurrence produces a node.
/// Extracts parameters from URL query strings, JSON bodies, and form bodies.
/// Annotates endpoints with response metadata (status, server, technology hints).
pub fn sync_exchanges_to_graph(exchanges: &[RecordedExchange]) -> SyncResult {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut operations = Vec::new();
    let mut parameters_discovered: usize = 0;

    for exchange in exchanges {
        let path = extract_path(&exchange.request_url);
        let method = exchange.request_method.clone();
        let key = (path.clone(), method.clone());

        if !seen.insert(key) {
            continue;
        }

        let params = extract_parameters_from_exchange(exchange);
        parameters_discovered += params.len();

        let mut properties = vec![
            ("path".to_string(), path),
            ("method".to_string(), method),
            ("discovery_source".to_string(), "proxy".to_string()),
            (
                "status_code".to_string(),
                exchange.response_status.to_string(),
            ),
        ];

        if !params.is_empty() {
            let params_json = serde_json::to_string(&params).unwrap_or_default();
            properties.push(("parameters".to_string(), params_json));
        }

        append_response_metadata(&exchange.response_headers, &mut properties);

        operations.push(OperationLogEntry {
            sequence_number: operations.len() as u64 + 1,
            module: ModuleIdentifier::Proxy,
            operation: GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties,
            },
            timestamp_unix_ms: timestamp_ms(),
        });
    }

    SyncResult {
        endpoints_added: operations.len(),
        parameters_discovered,
        operations,
    }
}

/// Extract parameters from a recorded exchange's URL query string and request body.
///
/// Supports URL query parameters, top-level JSON object keys, and form-encoded bodies.
pub fn extract_parameters_from_exchange(exchange: &RecordedExchange) -> Vec<(String, String)> {
    let mut params = extract_query_params(&exchange.request_url);
    params.extend(extract_body_params(
        &exchange.request_headers,
        &exchange.request_body,
    ));
    params
}

fn extract_path(raw_url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(raw_url) {
        return parsed.path().to_string();
    }
    raw_url.split('?').next().unwrap_or(raw_url).to_string()
}

fn extract_query_params(raw_url: &str) -> Vec<(String, String)> {
    if let Ok(parsed) = url::Url::parse(raw_url) {
        return parsed
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    }
    let Some(query) = raw_url.split('?').nth(1) else {
        return Vec::new();
    };
    parse_form_encoded(query)
}

fn extract_body_params(headers: &[(String, String)], body: &[u8]) -> Vec<(String, String)> {
    if body.is_empty() {
        return Vec::new();
    }
    let content_type = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    if content_type.contains("application/json") {
        return extract_json_keys(body);
    }
    if content_type.contains("application/x-www-form-urlencoded")
        && let Ok(text) = std::str::from_utf8(body)
    {
        return parse_form_encoded(text);
    }
    Vec::new()
}

fn extract_json_keys(body: &[u8]) -> Vec<(String, String)> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let Some(obj) = value.as_object() else {
        return Vec::new();
    };
    obj.iter()
        .map(|(k, v)| (k.clone(), json_value_summary(v)))
        .collect()
}

fn json_value_summary(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Array(_) => "[array]".to_string(),
        serde_json::Value::Object(_) => "{object}".to_string(),
    }
}

fn parse_form_encoded(input: &str) -> Vec<(String, String)> {
    input
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

fn append_response_metadata(headers: &[(String, String)], properties: &mut Vec<(String, String)>) {
    for (name, value) in headers {
        match name.to_ascii_lowercase().as_str() {
            "server" => {
                properties.push(("server".to_string(), value.clone()));
            }
            "x-powered-by" => {
                properties.push(("technology".to_string(), value.clone()));
            }
            _ => {}
        }
    }
}

fn timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "graph_sync_test.rs"]
mod graph_sync_test;
