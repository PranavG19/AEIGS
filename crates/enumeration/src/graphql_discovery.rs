use std::collections::HashSet;

use crate::introspection::{EndpointParameter, IntrospectedEndpoint, ParameterLocation};

/// Common GraphQL query field names for brute-force probing.
pub const COMMON_QUERY_FIELDS: &[&str] = &[
    "users",
    "user",
    "me",
    "viewer",
    "node",
    "nodes",
    "search",
    "items",
    "products",
    "orders",
    "posts",
    "comments",
    "messages",
    "notifications",
    "settings",
    "profile",
    "account",
    "health",
    "status",
    "version",
    "ping",
];

/// Common GraphQL mutation field names for brute-force probing.
pub const COMMON_MUTATION_FIELDS: &[&str] = &[
    "createUser",
    "updateUser",
    "deleteUser",
    "login",
    "logout",
    "register",
    "resetPassword",
    "updateProfile",
    "createPost",
    "updatePost",
    "deletePost",
    "sendMessage",
    "updateSettings",
];

/// Common GraphQL argument (name, type) pairs.
pub const COMMON_ARGUMENTS: &[(&str, &str)] = &[
    ("id", "ID!"),
    ("input", "JSON"),
    ("limit", "Int"),
    ("offset", "Int"),
    ("first", "Int"),
    ("after", "String"),
    ("filter", "JSON"),
    ("query", "String"),
    ("email", "String!"),
    ("password", "String!"),
];

/// How a set of GraphQL fields was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMethod {
    /// Extracted field names from GraphQL error messages.
    ErrorBased,
    /// Brute-forced using common field name wordlist.
    CommonFieldBrute,
    /// Merged results from both methods.
    Combined,
}

/// Result of a GraphQL field discovery attempt.
#[derive(Debug, Clone)]
pub struct GraphQlDiscoveryResult {
    pub method: DiscoveryMethod,
    pub endpoints: Vec<IntrospectedEndpoint>,
    /// Confidence in the discovered fields (0.0-1.0), lower than introspection.
    pub confidence: f64,
}

/// Errors that can occur during GraphQL field discovery.
#[derive(Debug)]
pub enum DiscoveryError {
    /// Failed to parse error response.
    Parse(String),
    /// Neither discovery method found any fields.
    NoFieldsDiscovered,
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(msg) => write!(f, "parse error: {msg}"),
            Self::NoFieldsDiscovered => write!(f, "no fields discovered"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// Extract field names from a GraphQL error response JSON.
///
/// Recognizes patterns like:
/// - `"Did you mean \"fieldName\"?"`
/// - `"Cannot query field \"fieldName\" on type \"Query\""`
/// - `"Unknown field ... Did you mean \"alt1\" or \"alt2\"?"`
pub fn extract_fields_from_error(error_json: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(error_json) else {
        return Vec::new();
    };

    let mut fields = HashSet::new();
    collect_fields_from_value(&value, &mut fields);

    let mut result: Vec<String> = fields.into_iter().collect();
    result.sort();
    result
}

fn collect_fields_from_value(value: &serde_json::Value, fields: &mut HashSet<String>) {
    match value {
        serde_json::Value::String(s) => extract_quoted_field_names(s, fields),
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_fields_from_value(item, fields);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                collect_fields_from_value(v, fields);
            }
        }
        _ => {}
    }
}

fn extract_quoted_field_names(message: &str, fields: &mut HashSet<String>) {
    if message.contains("Cannot query field") {
        extract_cannot_query_field(message, fields);
    }

    if message.contains("Did you mean") || message.contains("did you mean") {
        extract_did_you_mean_suggestions(message, fields);
    }

    if message.contains("Unknown field") {
        extract_unknown_field(message, fields);
    }
}

fn extract_cannot_query_field(message: &str, fields: &mut HashSet<String>) {
    let prefix = "Cannot query field \"";
    if let Some(start) = message.find(prefix) {
        let after = &message[start + prefix.len()..];
        if let Some(end) = after.find('"') {
            let field_name = &after[..end];
            if is_valid_field_name(field_name) {
                fields.insert(field_name.to_string());
            }
        }
    }
}

fn extract_did_you_mean_suggestions(message: &str, fields: &mut HashSet<String>) {
    let search_start = message
        .find("Did you mean")
        .or_else(|| message.find("did you mean"))
        .unwrap_or(0);
    let tail = &message[search_start..];

    extract_all_double_quoted(tail, fields);
}

fn extract_unknown_field(message: &str, fields: &mut HashSet<String>) {
    let prefix = "Unknown field \"";
    if let Some(start) = message.find(prefix) {
        let after = &message[start + prefix.len()..];
        if let Some(end) = after.find('"') {
            let field_name = &after[..end];
            if is_valid_field_name(field_name) {
                fields.insert(field_name.to_string());
            }
        }
    }
}

fn extract_all_double_quoted(text: &str, fields: &mut HashSet<String>) {
    let mut remaining = text;
    while let Some(open) = remaining.find('"') {
        let after_open = &remaining[open + 1..];
        let Some(close) = after_open.find('"') else {
            break;
        };
        let candidate = &after_open[..close];
        if is_valid_field_name(candidate) {
            fields.insert(candidate.to_string());
        }
        remaining = &after_open[close + 1..];
    }
}

fn is_valid_field_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Generate minimal GraphQL queries to probe each field.
///
/// Returns one query per field (`{ fieldName }`) plus a batch query
/// using aliases (`{ f0: __typename f1: __typename ... }`).
pub fn build_probe_queries(fields: &[&str]) -> Vec<String> {
    if fields.is_empty() {
        return Vec::new();
    }

    let mut queries: Vec<String> = fields
        .iter()
        .map(|field| format!("{{ {field} }}"))
        .collect();

    let alias_parts: Vec<String> = fields
        .iter()
        .enumerate()
        .map(|(i, field)| format!("f{i}_{field}: __typename"))
        .collect();
    queries.push(format!("{{ {} }}", alias_parts.join(" ")));

    queries
}

/// Discover GraphQL fields from error response JSON strings.
///
/// Sets confidence to 0.6 (error-based is moderately reliable).
pub fn discover_from_error_responses(error_responses: &[&str]) -> GraphQlDiscoveryResult {
    let mut all_fields = HashSet::new();

    for response in error_responses {
        for field in extract_fields_from_error(response) {
            all_fields.insert(field);
        }
    }

    let endpoints = build_query_endpoints_from_fields(&all_fields);

    GraphQlDiscoveryResult {
        method: DiscoveryMethod::ErrorBased,
        endpoints,
        confidence: 0.6,
    }
}

fn build_query_endpoints_from_fields(fields: &HashSet<String>) -> Vec<IntrospectedEndpoint> {
    let mut sorted_fields: Vec<&String> = fields.iter().collect();
    sorted_fields.sort();

    sorted_fields
        .into_iter()
        .map(|field| IntrospectedEndpoint {
            path: "/graphql".to_string(),
            method: "POST".to_string(),
            parameters: Vec::new(),
            response_type: None,
            description: Some(format!("Query: {field}")),
            security_schemes: Vec::new(),
            request_content_types: Vec::new(),
            response_status_codes: Vec::new(),
        })
        .collect()
}

/// Generate discovery results for all common query and mutation fields.
///
/// Query fields get COMMON_ARGUMENTS as parameters. Mutation fields get
/// a single `input: JSON` parameter. Confidence is 0.3 (pure guessing).
pub fn discover_common_fields() -> GraphQlDiscoveryResult {
    let query_params: Vec<EndpointParameter> = COMMON_ARGUMENTS
        .iter()
        .map(|(name, param_type)| EndpointParameter {
            name: (*name).to_string(),
            location: ParameterLocation::Body,
            param_type: (*param_type).to_string(),
            required: param_type.ends_with('!'),
        })
        .collect();

    let mutation_params = vec![EndpointParameter {
        name: "input".to_string(),
        location: ParameterLocation::Body,
        param_type: "JSON".to_string(),
        required: false,
    }];

    let mut endpoints: Vec<IntrospectedEndpoint> = COMMON_QUERY_FIELDS
        .iter()
        .map(|field| IntrospectedEndpoint {
            path: "/graphql".to_string(),
            method: "POST".to_string(),
            parameters: query_params.clone(),
            response_type: None,
            description: Some(format!("Query: {field}")),
            security_schemes: Vec::new(),
            request_content_types: Vec::new(),
            response_status_codes: Vec::new(),
        })
        .collect();

    let mutation_endpoints: Vec<IntrospectedEndpoint> = COMMON_MUTATION_FIELDS
        .iter()
        .map(|field| IntrospectedEndpoint {
            path: "/graphql".to_string(),
            method: "POST".to_string(),
            parameters: mutation_params.clone(),
            response_type: None,
            description: Some(format!("Mutation: {field}")),
            security_schemes: Vec::new(),
            request_content_types: Vec::new(),
            response_status_codes: Vec::new(),
        })
        .collect();

    endpoints.extend(mutation_endpoints);

    GraphQlDiscoveryResult {
        method: DiscoveryMethod::CommonFieldBrute,
        endpoints,
        confidence: 0.3,
    }
}

/// Merge multiple discovery results, deduplicating by endpoint description.
///
/// Takes the highest confidence for any given field. Overall confidence
/// is the maximum of all input confidences.
pub fn merge_discovery_results(results: &[GraphQlDiscoveryResult]) -> GraphQlDiscoveryResult {
    if results.is_empty() {
        return GraphQlDiscoveryResult {
            method: DiscoveryMethod::Combined,
            endpoints: Vec::new(),
            confidence: 0.0,
        };
    }

    let mut seen_descriptions: HashSet<String> = HashSet::new();
    let mut merged_endpoints = Vec::new();
    let mut max_confidence: f64 = 0.0;

    for result in results {
        max_confidence = max_confidence.max(result.confidence);
        for endpoint in &result.endpoints {
            let key = endpoint.description.clone().unwrap_or_default();
            if seen_descriptions.insert(key) {
                merged_endpoints.push(endpoint.clone());
            }
        }
    }

    GraphQlDiscoveryResult {
        method: DiscoveryMethod::Combined,
        endpoints: merged_endpoints,
        confidence: max_confidence,
    }
}
