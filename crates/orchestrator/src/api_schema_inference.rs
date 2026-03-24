use std::collections::{HashMap, HashSet};
use std::fmt;

/// API schema inference engine — reverse-engineer API structure
/// from observed HTTP traffic when no documentation exists.
///
/// Most APIs lack public documentation. This engine watches traffic
/// (from the proxy module, crawled endpoints, or fuzzer responses)
/// and builds a structural model of the API:
///
/// 1. Path template inference (collapse /users/123 and /users/456 into /users/{id})
/// 2. Parameter type detection (is "123" an int? a UUID? a date?)
/// 3. Request/response schema extraction (JSON field names, types, nesting)
/// 4. Authentication pattern detection (which endpoints need auth?)
/// 5. Relationship mapping (GET /users/{id} → GET /users/{id}/orders)
///
/// The inferred schema feeds directly into the grammar fuzzer for
/// intelligent test case generation.

/// An observed HTTP request/response pair.
#[derive(Debug, Clone)]
pub struct ObservedRequest {
    pub method: String,
    pub path: String,
    pub query_params: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ObservedResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ObservedExchange {
    pub request: ObservedRequest,
    pub response: ObservedResponse,
}

/// Inferred type of a path segment or parameter value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InferredType {
    Integer,
    Uuid,
    Email,
    Date,
    DateTime,
    Float,
    Boolean,
    Slug,
    HexString,
    JwtToken,
    Base64,
    String,
}

impl fmt::Display for InferredType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer => write!(f, "integer"),
            Self::Uuid => write!(f, "uuid"),
            Self::Email => write!(f, "email"),
            Self::Date => write!(f, "date"),
            Self::DateTime => write!(f, "datetime"),
            Self::Float => write!(f, "float"),
            Self::Boolean => write!(f, "boolean"),
            Self::Slug => write!(f, "slug"),
            Self::HexString => write!(f, "hex"),
            Self::JwtToken => write!(f, "jwt"),
            Self::Base64 => write!(f, "base64"),
            Self::String => write!(f, "string"),
        }
    }
}

/// Infer the type of a string value.
pub fn infer_type(value: &str) -> InferredType {
    if value.is_empty() {
        return InferredType::String;
    }

    if value == "true" || value == "false" {
        return InferredType::Boolean;
    }

    if value.parse::<i64>().is_ok() {
        return InferredType::Integer;
    }

    if value.parse::<f64>().is_ok() {
        return InferredType::Float;
    }

    let uuid_re = value.len() == 36
        && value.chars().enumerate().all(|(i, c)| {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        });
    if uuid_re {
        return InferredType::Uuid;
    }

    if value.contains('@') && value.contains('.') && value.len() >= 5 {
        return InferredType::Email;
    }

    if value.len() == 10
        && value.chars().nth(4) == Some('-')
        && value.chars().nth(7) == Some('-')
        && value[..4].chars().all(|c| c.is_ascii_digit())
        && value[5..7].chars().all(|c| c.is_ascii_digit())
        && value[8..].chars().all(|c| c.is_ascii_digit())
    {
        return InferredType::Date;
    }

    if value.contains('T') && (value.ends_with('Z') || value.contains('+')) && value.len() >= 19 {
        return InferredType::DateTime;
    }

    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() == 3
        && parts
            .iter()
            .all(|p| p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        && parts[0].len() > 10
    {
        return InferredType::JwtToken;
    }

    if value.len() >= 16
        && value
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    {
        return InferredType::HexString;
    }

    if value.len() >= 8
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        && (value.ends_with('=') || value.len() % 4 == 0)
    {
        return InferredType::Base64;
    }

    if value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && value.contains('-')
        && value.len() >= 3
    {
        return InferredType::Slug;
    }

    InferredType::String
}

/// A path template inferred from observed paths.
#[derive(Debug, Clone)]
pub struct InferredPathTemplate {
    pub template: String,
    pub segments: Vec<PathSegment>,
    pub observed_count: usize,
    pub example_paths: Vec<String>,
}

impl fmt::Display for InferredPathTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}x)", self.template, self.observed_count)
    }
}

#[derive(Debug, Clone)]
pub enum PathSegment {
    Literal(String),
    Parameter { name: String, inferred_type: InferredType, observed_values: Vec<String> },
}

/// A JSON field extracted from request/response bodies.
#[derive(Debug, Clone)]
pub struct JsonField {
    pub name: String,
    pub inferred_type: InferredType,
    pub nullable: bool,
    pub observed_count: usize,
    pub example_values: Vec<String>,
    pub nested_fields: Vec<JsonField>,
    pub is_array: bool,
}

/// An inferred API endpoint with full schema.
#[derive(Debug, Clone)]
pub struct InferredEndpoint {
    pub method: String,
    pub path_template: InferredPathTemplate,
    pub query_params: Vec<InferredParam>,
    pub request_body_fields: Vec<JsonField>,
    pub response_body_fields: Vec<JsonField>,
    pub requires_auth: bool,
    pub auth_type: Option<AuthType>,
    pub response_codes: Vec<u16>,
    pub content_types: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct InferredParam {
    pub name: String,
    pub inferred_type: InferredType,
    pub required: bool,
    pub example_values: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthType {
    BearerToken,
    ApiKey,
    BasicAuth,
    Cookie,
    OAuth2,
    Custom,
}

impl fmt::Display for AuthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken => write!(f, "Bearer Token"),
            Self::ApiKey => write!(f, "API Key"),
            Self::BasicAuth => write!(f, "Basic Auth"),
            Self::Cookie => write!(f, "Cookie"),
            Self::OAuth2 => write!(f, "OAuth 2.0"),
            Self::Custom => write!(f, "Custom"),
        }
    }
}

/// Detect authentication type from request headers.
pub fn detect_auth_type(headers: &HashMap<String, String>) -> Option<AuthType> {
    let lower: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    if let Some(auth) = lower.get("authorization") {
        let auth_lower = auth.to_lowercase();
        if auth_lower.starts_with("bearer ") {
            return Some(AuthType::BearerToken);
        }
        if auth_lower.starts_with("basic ") {
            return Some(AuthType::BasicAuth);
        }
    }

    if lower.contains_key("x-api-key") || lower.contains_key("api-key") || lower.contains_key("apikey") {
        return Some(AuthType::ApiKey);
    }

    if lower.contains_key("cookie") {
        let cookie = lower.get("cookie").unwrap();
        if cookie.contains("session") || cookie.contains("token") || cookie.contains("auth") {
            return Some(AuthType::Cookie);
        }
    }

    None
}

/// Collapse observed paths into path templates by detecting
/// variable segments.
pub fn infer_path_templates(paths: &[String]) -> Vec<InferredPathTemplate> {
    let mut groups: HashMap<(usize, Vec<bool>), Vec<String>> = HashMap::new();

    for path in paths {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let pattern: Vec<bool> = segments
            .iter()
            .map(|s| is_likely_variable(s))
            .collect();
        groups
            .entry((segments.len(), pattern))
            .or_default()
            .push(path.clone());
    }

    let mut templates = Vec::new();

    for ((seg_count, pattern), example_paths) in &groups {
        if example_paths.is_empty() || *seg_count == 0 {
            continue;
        }

        let first_segments: Vec<&str> = example_paths[0]
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut template_parts = Vec::new();
        let mut segments = Vec::new();

        for (i, _seg) in first_segments.iter().enumerate() {
            if i < pattern.len() && pattern[i] {
                let values: Vec<String> = example_paths
                    .iter()
                    .filter_map(|p| {
                        let segs: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
                        segs.get(i).map(|s| s.to_string())
                    })
                    .collect();

                let inferred = if !values.is_empty() {
                    let types: HashSet<InferredType> = values.iter().map(|v| infer_type(v)).collect();
                    if types.len() == 1 {
                        *types.iter().next().unwrap()
                    } else if types.contains(&InferredType::Integer) {
                        InferredType::Integer
                    } else {
                        InferredType::String
                    }
                } else {
                    InferredType::String
                };

                let param_name = guess_param_name(i, &inferred, &first_segments);
                template_parts.push(format!("{{{}}}", param_name));
                segments.push(PathSegment::Parameter {
                    name: param_name,
                    inferred_type: inferred,
                    observed_values: values.into_iter().take(5).collect(),
                });
            } else {
                template_parts.push(first_segments[i].to_string());
                segments.push(PathSegment::Literal(first_segments[i].to_string()));
            }
        }

        templates.push(InferredPathTemplate {
            template: format!("/{}", template_parts.join("/")),
            segments,
            observed_count: example_paths.len(),
            example_paths: example_paths.iter().take(5).cloned().collect(),
        });
    }

    templates.sort_by(|a, b| b.observed_count.cmp(&a.observed_count));
    templates
}

fn is_likely_variable(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    if segment.parse::<i64>().is_ok() {
        return true;
    }
    let t = infer_type(segment);
    matches!(
        t,
        InferredType::Integer
            | InferredType::Uuid
            | InferredType::HexString
            | InferredType::Base64
    )
}

fn guess_param_name(index: usize, inferred: &InferredType, segments: &[&str]) -> String {
    if index > 0 {
        let prev = segments[index - 1];
        if prev.ends_with('s') && prev.len() > 2 {
            return format!("{}_id", &prev[..prev.len() - 1]);
        }
        return format!("{}_id", prev);
    }
    match inferred {
        InferredType::Integer => "id".into(),
        InferredType::Uuid => "uuid".into(),
        _ => format!("param_{}", index),
    }
}

/// Parse JSON string into a flat list of fields (top level only).
pub fn extract_json_fields(json_str: &str) -> Vec<JsonField> {
    let mut fields = Vec::new();

    let trimmed = json_str.trim();
    if !trimmed.starts_with('{') {
        return fields;
    }

    let content = &trimmed[1..trimmed.len().saturating_sub(1)];
    let pairs = split_json_pairs(content);

    for pair in pairs {
        if let Some((key, value)) = split_key_value(&pair) {
            let clean_key = key.trim().trim_matches('"').to_string();
            let clean_value = value.trim().to_string();

            let (inferred, nullable, is_array) = classify_json_value(&clean_value);

            let nested = if clean_value.starts_with('{') {
                extract_json_fields(&clean_value)
            } else {
                Vec::new()
            };

            fields.push(JsonField {
                name: clean_key,
                inferred_type: inferred,
                nullable,
                observed_count: 1,
                example_values: vec![clean_value],
                nested_fields: nested,
                is_array,
            });
        }
    }

    fields
}

fn split_json_pairs(content: &str) -> Vec<String> {
    let mut pairs = Vec::new();
    let mut current = String::new();
    let mut depth = 0;
    let mut in_string = false;
    let mut prev_char = '\0';

    for ch in content.chars() {
        if ch == '"' && prev_char != '\\' {
            in_string = !in_string;
        }
        if !in_string {
            match ch {
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                ',' if depth == 0 => {
                    let trimmed = current.trim().to_string();
                    if !trimmed.is_empty() {
                        pairs.push(trimmed);
                    }
                    current = String::new();
                    prev_char = ch;
                    continue;
                }
                _ => {}
            }
        }
        current.push(ch);
        prev_char = ch;
    }

    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        pairs.push(trimmed);
    }

    pairs
}

fn split_key_value(pair: &str) -> Option<(String, String)> {
    let mut depth = 0;
    let mut in_string = false;
    let mut prev_char = '\0';
    let mut colon_pos = None;
    let mut first_string_ended = false;

    for (i, ch) in pair.chars().enumerate() {
        if ch == '"' && prev_char != '\\' {
            in_string = !in_string;
            if !in_string && colon_pos.is_none() {
                first_string_ended = true;
            }
        }
        if !in_string {
            match ch {
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                ':' if depth == 0 && first_string_ended && colon_pos.is_none() => {
                    colon_pos = Some(i);
                }
                _ => {}
            }
        }
        prev_char = ch;
    }

    colon_pos.map(|pos| {
        let key = pair[..pos].trim().to_string();
        let value = pair[pos + 1..].trim().to_string();
        (key, value)
    })
}

fn classify_json_value(value: &str) -> (InferredType, bool, bool) {
    if value == "null" {
        return (InferredType::String, true, false);
    }
    if value == "true" || value == "false" {
        return (InferredType::Boolean, false, false);
    }
    if value.starts_with('[') {
        return (InferredType::String, false, true);
    }
    if value.starts_with('{') {
        return (InferredType::String, false, false);
    }
    if value.starts_with('"') && value.ends_with('"') {
        let inner = &value[1..value.len() - 1];
        return (infer_type(inner), false, false);
    }
    if value.parse::<i64>().is_ok() {
        return (InferredType::Integer, false, false);
    }
    if value.parse::<f64>().is_ok() {
        return (InferredType::Float, false, false);
    }
    (InferredType::String, false, false)
}

/// Relationship between two inferred endpoints.
#[derive(Debug, Clone)]
pub struct EndpointRelationship {
    pub parent: String,
    pub child: String,
    pub relationship_type: RelationType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationType {
    ParentChild,
    SiblingCrud,
    AuthGated,
    Redirect,
}

impl fmt::Display for RelationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParentChild => write!(f, "parent→child"),
            Self::SiblingCrud => write!(f, "CRUD siblings"),
            Self::AuthGated => write!(f, "auth-gated"),
            Self::Redirect => write!(f, "redirect"),
        }
    }
}

/// Detect relationships between inferred endpoints.
pub fn detect_relationships(endpoints: &[InferredEndpoint]) -> Vec<EndpointRelationship> {
    let mut relationships = Vec::new();

    for i in 0..endpoints.len() {
        for j in 0..endpoints.len() {
            if i == j {
                continue;
            }

            let parent = &endpoints[i].path_template.template;
            let child = &endpoints[j].path_template.template;

            if child.starts_with(parent) && child.len() > parent.len() {
                relationships.push(EndpointRelationship {
                    parent: format!("{} {}", endpoints[i].method, parent),
                    child: format!("{} {}", endpoints[j].method, child),
                    relationship_type: RelationType::ParentChild,
                });
            }

            if parent == child && endpoints[i].method != endpoints[j].method {
                let methods = vec![&endpoints[i].method, &endpoints[j].method];
                if (methods.contains(&&"GET".to_string()) && methods.contains(&&"POST".to_string()))
                    || (methods.contains(&&"GET".to_string()) && methods.contains(&&"PUT".to_string()))
                    || (methods.contains(&&"GET".to_string()) && methods.contains(&&"DELETE".to_string()))
                {
                    relationships.push(EndpointRelationship {
                        parent: format!("{} {}", endpoints[i].method, parent),
                        child: format!("{} {}", endpoints[j].method, child),
                        relationship_type: RelationType::SiblingCrud,
                    });
                }
            }
        }
    }

    relationships
}

/// Full inferred API schema.
#[derive(Debug, Clone)]
pub struct InferredApiSchema {
    pub endpoints: Vec<InferredEndpoint>,
    pub relationships: Vec<EndpointRelationship>,
    pub auth_types_detected: Vec<AuthType>,
    pub total_exchanges_analyzed: usize,
    pub summary: String,
}

/// Build an API schema from observed request/response exchanges.
pub fn infer_schema(exchanges: &[ObservedExchange]) -> InferredApiSchema {
    let mut endpoint_map: HashMap<(String, String), Vec<&ObservedExchange>> = HashMap::new();

    let paths: Vec<String> = exchanges
        .iter()
        .map(|e| e.request.path.clone())
        .collect();
    let templates = infer_path_templates(&paths);

    for exchange in exchanges {
        let template = find_matching_template(&exchange.request.path, &templates)
            .unwrap_or_else(|| exchange.request.path.clone());
        endpoint_map
            .entry((exchange.request.method.clone(), template))
            .or_default()
            .push(exchange);
    }

    let mut auth_types: HashSet<AuthType> = HashSet::new();
    let mut endpoints = Vec::new();

    for ((method, template_str), exs) in &endpoint_map {
        let template = templates
            .iter()
            .find(|t| t.template == *template_str)
            .cloned()
            .unwrap_or_else(|| InferredPathTemplate {
                template: template_str.clone(),
                segments: vec![PathSegment::Literal(template_str.clone())],
                observed_count: exs.len(),
                example_paths: vec![template_str.clone()],
            });

        let mut query_params_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut response_codes: HashSet<u16> = HashSet::new();
        let mut content_types: HashSet<String> = HashSet::new();
        let mut has_auth = false;
        let mut auth_type = None;
        let mut req_fields: Vec<JsonField> = Vec::new();
        let mut resp_fields: Vec<JsonField> = Vec::new();

        for ex in exs {
            for (k, v) in &ex.request.query_params {
                query_params_map.entry(k.clone()).or_default().push(v.clone());
            }
            response_codes.insert(ex.response.status_code);
            if let Some(ct) = &ex.response.content_type {
                content_types.insert(ct.clone());
            }

            let detected = detect_auth_type(&ex.request.headers);
            if let Some(at) = detected {
                has_auth = true;
                auth_type = Some(at);
                auth_types.insert(at);
            }

            if let Some(body) = &ex.request.body {
                let fields = extract_json_fields(body);
                if req_fields.is_empty() {
                    req_fields = fields;
                }
            }

            if let Some(body) = &ex.response.body {
                let fields = extract_json_fields(body);
                if resp_fields.is_empty() {
                    resp_fields = fields;
                }
            }
        }

        let query_params: Vec<InferredParam> = query_params_map
            .iter()
            .map(|(name, values)| {
                let types: HashSet<InferredType> = values.iter().map(|v| infer_type(v)).collect();
                let inferred = if types.len() == 1 {
                    *types.iter().next().unwrap()
                } else {
                    InferredType::String
                };
                InferredParam {
                    name: name.clone(),
                    inferred_type: inferred,
                    required: values.len() == exs.len(),
                    example_values: values.iter().take(3).cloned().collect(),
                }
            })
            .collect();

        let mut codes: Vec<u16> = response_codes.into_iter().collect();
        codes.sort();
        let cts: Vec<String> = content_types.into_iter().collect();

        endpoints.push(InferredEndpoint {
            method: method.clone(),
            path_template: template,
            query_params,
            request_body_fields: req_fields,
            response_body_fields: resp_fields,
            requires_auth: has_auth,
            auth_type,
            response_codes: codes,
            content_types: cts,
        });
    }

    let relationships = detect_relationships(&endpoints);
    let auth_list: Vec<AuthType> = auth_types.into_iter().collect();

    let summary = format!(
        "Inferred {} endpoints from {} exchanges. {} auth types detected. {} relationships found.",
        endpoints.len(),
        exchanges.len(),
        auth_list.len(),
        relationships.len()
    );

    InferredApiSchema {
        endpoints,
        relationships,
        auth_types_detected: auth_list,
        total_exchanges_analyzed: exchanges.len(),
        summary,
    }
}

fn find_matching_template(path: &str, templates: &[InferredPathTemplate]) -> Option<String> {
    let path_segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    for template in templates {
        if template.segments.len() != path_segments.len() {
            continue;
        }
        let matches = template
            .segments
            .iter()
            .zip(path_segments.iter())
            .all(|(seg, actual)| match seg {
                PathSegment::Literal(lit) => lit == actual,
                PathSegment::Parameter { .. } => true,
            });
        if matches {
            return Some(template.template.clone());
        }
    }

    None
}

#[cfg(test)]
#[path = "api_schema_inference_test.rs"]
mod tests;
