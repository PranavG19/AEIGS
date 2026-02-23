use std::fmt;
use std::time::Duration;

use aegis_protocol::target_validation::validate_target_is_localhost;
use url::Url;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

const AUTHENTICATED_IDOR_SEVERITY: f64 = 8.0;
const UNAUTHENTICATED_IDOR_SEVERITY: f64 = 9.0;

const BODY_SIMILARITY_THRESHOLD: f64 = 0.95;

const ID_PARAM_NAMES: &[&str] = &[
    "id",
    "user_id",
    "userid",
    "account_id",
    "accountid",
    "order_id",
    "orderid",
    "customer_id",
    "customerid",
    "profile_id",
    "profileid",
    "item_id",
    "itemid",
    "record_id",
    "recordid",
    "doc_id",
    "docid",
    "project_id",
    "projectid",
];

const UUID_REGEX_PATTERN: &str =
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdType {
    SequentialInteger,
    Uuid,
    EncodedId,
}

impl fmt::Display for IdType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::SequentialInteger => "sequential-integer",
            Self::Uuid => "uuid",
            Self::EncodedId => "encoded-id",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdLocation {
    PathSegment(usize),
    QueryParam,
}

impl fmt::Display for IdLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathSegment(pos) => write!(f, "path-segment({pos})"),
            Self::QueryParam => write!(f, "query-param"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IdParameter {
    pub name: String,
    pub value: String,
    pub id_type: IdType,
    pub location: IdLocation,
}

#[derive(Debug, Clone)]
pub struct IdorFinding {
    pub endpoint: String,
    pub original_id: String,
    pub tested_id: String,
    pub id_type: IdType,
    pub severity: f64,
    pub evidence: String,
}

pub struct IdorTester {
    client: reqwest::blocking::Client,
}

impl Default for IdorTester {
    fn default() -> Self {
        Self::new()
    }
}

impl IdorTester {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    pub fn with_client(client: reqwest::blocking::Client) -> Self {
        Self { client }
    }

    pub fn test_idor(
        &self,
        endpoint: &str,
        method: &str,
        auth_header: Option<&str>,
    ) -> Vec<IdorFinding> {
        if validate_target_is_localhost(endpoint).is_err() {
            return Vec::new();
        }

        let params = detect_id_parameters(endpoint, method);
        if params.is_empty() {
            return Vec::new();
        }

        let baseline = match self.send_request(endpoint, method, auth_header) {
            Some(resp) => resp,
            None => return Vec::new(),
        };

        if baseline.status != 200 {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for param in &params {
            let test_ids = generate_test_ids(&param.value, param.id_type);
            for test_id in &test_ids {
                if let Some(finding) =
                    self.test_single_id(endpoint, method, auth_header, param, test_id, &baseline)
                {
                    findings.push(finding);
                }
            }
        }
        findings
    }

    fn test_single_id(
        &self,
        endpoint: &str,
        method: &str,
        auth_header: Option<&str>,
        param: &IdParameter,
        test_id: &str,
        baseline: &HttpResponse,
    ) -> Option<IdorFinding> {
        let modified_url = replace_id_in_url(endpoint, param, test_id)?;
        let response = self.send_request(&modified_url, method, auth_header)?;

        if response.status != 200 {
            return None;
        }

        if bodies_are_similar(&baseline.body, &response.body) {
            return None;
        }

        let severity = if auth_header.is_some() {
            AUTHENTICATED_IDOR_SEVERITY
        } else {
            UNAUTHENTICATED_IDOR_SEVERITY
        };

        let evidence = format!(
            "Replacing {} '{}' with '{}' at {} returned HTTP 200 with different response body \
             (baseline {}B vs modified {}B)",
            param.id_type,
            param.value,
            test_id,
            param.location,
            baseline.body.len(),
            response.body.len(),
        );

        Some(IdorFinding {
            endpoint: endpoint.to_string(),
            original_id: param.value.clone(),
            tested_id: test_id.to_string(),
            id_type: param.id_type,
            severity,
            evidence,
        })
    }

    fn send_request(
        &self,
        url: &str,
        method: &str,
        auth_header: Option<&str>,
    ) -> Option<HttpResponse> {
        let mut builder = match method.to_uppercase().as_str() {
            "POST" => self.client.post(url),
            "PUT" => self.client.put(url),
            "DELETE" => self.client.delete(url),
            "PATCH" => self.client.patch(url),
            _ => self.client.get(url),
        };

        if let Some(auth) = auth_header {
            builder = builder.header("Authorization", auth);
        }

        let resp = builder.send().ok()?;
        let status = resp.status().as_u16();
        let body = resp.text().unwrap_or_default();
        Some(HttpResponse { status, body })
    }
}

struct HttpResponse {
    status: u16,
    body: String,
}

pub fn detect_id_parameters(endpoint: &str, _method: &str) -> Vec<IdParameter> {
    let mut params = Vec::new();

    let parsed = match Url::parse(endpoint) {
        Ok(u) => u,
        Err(_) => return params,
    };

    detect_path_ids(parsed.path(), &mut params);
    detect_query_ids(&parsed, &mut params);
    params
}

fn detect_path_ids(path: &str, params: &mut Vec<IdParameter>) {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    for (idx, segment) in segments.iter().enumerate() {
        if let Some(id_type) = classify_id_value(segment) {
            let name = infer_path_param_name(&segments, idx);
            params.push(IdParameter {
                name,
                value: (*segment).to_string(),
                id_type,
                location: IdLocation::PathSegment(idx),
            });
        }
    }
}

fn detect_query_ids(parsed: &Url, params: &mut Vec<IdParameter>) {
    for (key, value) in parsed.query_pairs() {
        let key_lower = key.to_lowercase();
        let is_known_id_name = ID_PARAM_NAMES.contains(&key_lower.as_str());
        let has_id_like_value = classify_id_value(&value).is_some();

        if is_known_id_name || (has_id_like_value && key_lower.contains("id")) {
            let id_type = classify_id_value(&value).unwrap_or(IdType::SequentialInteger);
            params.push(IdParameter {
                name: key.to_string(),
                value: value.to_string(),
                id_type,
                location: IdLocation::QueryParam,
            });
        }
    }
}

fn classify_id_value(value: &str) -> Option<IdType> {
    if value.is_empty() {
        return None;
    }

    if value.parse::<u64>().is_ok() {
        return Some(IdType::SequentialInteger);
    }

    if is_uuid(value) {
        return Some(IdType::Uuid);
    }

    if is_encoded_id(value) {
        return Some(IdType::EncodedId);
    }

    None
}

fn is_uuid(value: &str) -> bool {
    let re = regex::Regex::new(UUID_REGEX_PATTERN).expect("invalid UUID regex");
    re.is_match(value)
}

fn is_encoded_id(value: &str) -> bool {
    if value.len() < 4 {
        return false;
    }

    let has_base64_chars = value.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
    });

    if !has_base64_chars {
        return false;
    }

    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .is_ok()
        || base64::engine::general_purpose::URL_SAFE
            .decode(value)
            .is_ok()
}

fn infer_path_param_name(segments: &[&str], idx: usize) -> String {
    if idx > 0 {
        segments[idx - 1].to_string()
    } else {
        "id".to_string()
    }
}

pub fn generate_test_ids(original: &str, id_type: IdType) -> Vec<String> {
    match id_type {
        IdType::SequentialInteger => generate_sequential_ids(original),
        IdType::Uuid => Vec::new(),
        IdType::EncodedId => generate_encoded_ids(original),
    }
}

fn generate_sequential_ids(original: &str) -> Vec<String> {
    let mut ids = Vec::new();
    if let Ok(n) = original.parse::<i64>() {
        ids.push((n + 1).to_string());
        ids.push((n - 1).to_string());
        ids.push((n + 10).to_string());
        ids.push((n - 10).to_string());

        if n != 0 {
            ids.push("0".to_string());
        }
        if n != 1 {
            ids.push("1".to_string());
        }
        if n != 9999999 {
            ids.push("9999999".to_string());
        }
    }
    ids
}

fn generate_encoded_ids(original: &str) -> Vec<String> {
    use base64::Engine;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(original)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(original));

    let Ok(bytes) = decoded else {
        return Vec::new();
    };

    let Ok(decoded_str) = String::from_utf8(bytes) else {
        return Vec::new();
    };

    let mut ids = Vec::new();

    if let Ok(n) = decoded_str.parse::<i64>() {
        let engine = &base64::engine::general_purpose::STANDARD;
        ids.push(engine.encode((n + 1).to_string()));
        ids.push(engine.encode((n - 1).to_string()));
    } else {
        let engine = &base64::engine::general_purpose::STANDARD;
        let modified = format!("{decoded_str}_tampered");
        ids.push(engine.encode(&modified));
    }

    ids
}

fn replace_id_in_url(endpoint: &str, param: &IdParameter, new_id: &str) -> Option<String> {
    let mut parsed = Url::parse(endpoint).ok()?;

    match &param.location {
        IdLocation::PathSegment(idx) => {
            let segments: Vec<&str> = parsed.path().split('/').collect();
            let adjusted_idx = idx + 1;
            if adjusted_idx >= segments.len() {
                return None;
            }
            let new_path: Vec<String> = segments
                .iter()
                .enumerate()
                .map(|(i, seg)| {
                    if i == adjusted_idx {
                        new_id.to_string()
                    } else {
                        (*seg).to_string()
                    }
                })
                .collect();
            parsed.set_path(&new_path.join("/"));
        }
        IdLocation::QueryParam => {
            let pairs: Vec<(String, String)> = parsed
                .query_pairs()
                .map(|(k, v)| {
                    if k == param.name && v == param.value {
                        (k.to_string(), new_id.to_string())
                    } else {
                        (k.to_string(), v.to_string())
                    }
                })
                .collect();
            parsed.set_query(None);
            for (k, v) in &pairs {
                parsed.query_pairs_mut().append_pair(k, v);
            }
        }
    }

    Some(parsed.to_string())
}

fn bodies_are_similar(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }

    if a.is_empty() || b.is_empty() {
        return a.is_empty() && b.is_empty();
    }

    let max_len = a.len().max(b.len()) as f64;
    let min_len = a.len().min(b.len()) as f64;
    let length_ratio = min_len / max_len;

    length_ratio >= BODY_SIMILARITY_THRESHOLD && a.len().abs_diff(b.len()) < 50
}

#[cfg(test)]
#[path = "idor_tester_test.rs"]
mod idor_tester_test;
