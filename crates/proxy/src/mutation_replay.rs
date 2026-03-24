use std::collections::HashMap;

use crate::types::RecordedExchange;

/// Attack dimension for a mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttackDimension {
    ParameterPollution,
    VerbTampering,
    ContentTypeConfusion,
    PathNormalization,
    HeaderInjection,
    EncodingLadder,
}

impl AttackDimension {
    pub const ALL: &'static [AttackDimension] = &[
        AttackDimension::ParameterPollution,
        AttackDimension::VerbTampering,
        AttackDimension::ContentTypeConfusion,
        AttackDimension::PathNormalization,
        AttackDimension::HeaderInjection,
        AttackDimension::EncodingLadder,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            AttackDimension::ParameterPollution => "parameter-pollution",
            AttackDimension::VerbTampering => "verb-tampering",
            AttackDimension::ContentTypeConfusion => "content-type-confusion",
            AttackDimension::PathNormalization => "path-normalization",
            AttackDimension::HeaderInjection => "header-injection",
            AttackDimension::EncodingLadder => "encoding-ladder",
        }
    }
}

/// A single mutated request derived from a recorded exchange.
#[derive(Debug, Clone)]
pub struct MutatedRequest {
    pub dimension: AttackDimension,
    pub description: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Diff flags between a mutation response and the baseline.
#[derive(Debug, Clone, Default)]
pub struct ResponseDiff {
    pub status_code_changed: bool,
    pub body_length_delta_pct: f64,
    pub new_headers: Vec<String>,
    pub timing_ratio: f64,
    pub is_interesting: bool,
}

impl ResponseDiff {
    /// Compute diff between a mutation response and the baseline recorded exchange.
    pub fn compute(baseline: &RecordedExchange, mutation_status: u16, mutation_headers: &[(String, String)], mutation_body_len: usize, mutation_duration_ms: u64) -> Self {
        let status_code_changed = baseline.response_status != mutation_status;

        let baseline_len = baseline.response_body.len().max(1) as f64;
        let body_length_delta_pct =
            ((mutation_body_len as f64 - baseline_len) / baseline_len).abs() * 100.0;

        let baseline_header_names: std::collections::HashSet<String> = baseline
            .response_headers
            .iter()
            .map(|(k, _)| k.to_lowercase())
            .collect();
        let new_headers: Vec<String> = mutation_headers
            .iter()
            .filter(|(k, _)| !baseline_header_names.contains(&k.to_lowercase()))
            .map(|(k, _)| k.clone())
            .collect();

        let baseline_dur = baseline.duration_ms.max(1) as f64;
        let timing_ratio = mutation_duration_ms as f64 / baseline_dur;

        let is_interesting = status_code_changed
            || body_length_delta_pct > 10.0
            || !new_headers.is_empty()
            || timing_ratio > 2.0;

        Self {
            status_code_changed,
            body_length_delta_pct,
            new_headers,
            timing_ratio,
            is_interesting,
        }
    }
}

/// Result of replaying a single mutation.
#[derive(Debug, Clone)]
pub struct ReplayResult {
    pub mutation: MutatedRequest,
    pub response_status: Option<u16>,
    pub response_headers: Vec<(String, String)>,
    pub response_body_len: usize,
    pub duration_ms: u64,
    pub diff: ResponseDiff,
    pub error: Option<String>,
}

/// Full mutation matrix from a single recorded exchange.
#[derive(Debug)]
pub struct MutationMatrix {
    pub baseline: RecordedExchange,
    pub mutations: Vec<MutatedRequest>,
}

impl MutationMatrix {
    /// Generate mutation matrix for a recorded exchange.
    pub fn generate(exchange: &RecordedExchange) -> Self {
        let mut mutations = Vec::new();

        mutations.extend(generate_parameter_pollution(exchange));
        mutations.extend(generate_verb_tampering(exchange));
        mutations.extend(generate_content_type_confusion(exchange));
        mutations.extend(generate_path_normalization(exchange));
        mutations.extend(generate_header_injection(exchange));
        mutations.extend(generate_encoding_ladder(exchange));

        Self {
            baseline: exchange.clone(),
            mutations,
        }
    }

    /// Count mutations per dimension.
    pub fn counts_by_dimension(&self) -> HashMap<AttackDimension, usize> {
        let mut counts = HashMap::new();
        for m in &self.mutations {
            *counts.entry(m.dimension).or_insert(0) += 1;
        }
        counts
    }

    /// Number of distinct dimensions covered.
    pub fn dimension_count(&self) -> usize {
        self.counts_by_dimension().len()
    }
}

// ---------------------------------------------------------------------------
// Parameter pollution: duplicate query params with conflicting values
// ---------------------------------------------------------------------------

fn extract_query_params(url: &str) -> (String, Vec<(String, String)>) {
    if let Some(idx) = url.find('?') {
        let base = url[..idx].to_string();
        let query = &url[idx + 1..];
        let params: Vec<(String, String)> = query
            .split('&')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next()?.to_string();
                let val = parts.next().unwrap_or("").to_string();
                Some((key, val))
            })
            .collect();
        (base, params)
    } else {
        (url.to_string(), Vec::new())
    }
}

fn build_url_with_params(base: &str, params: &[(String, String)]) -> String {
    if params.is_empty() {
        return base.to_string();
    }
    let qs: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
    format!("{base}?{}", qs.join("&"))
}

fn generate_parameter_pollution(exchange: &RecordedExchange) -> Vec<MutatedRequest> {
    let mut out = Vec::new();
    let (base_url, params) = extract_query_params(&exchange.request_url);

    let conflicting_values = ["1", "0", "true", "null", "admin", "../etc/passwd", "<script>", "' OR 1=1--"];

    if params.is_empty() {
        // No existing params — inject synthetic ones
        let synthetic_params = ["id", "page", "debug", "admin", "redirect", "callback", "token"];
        for param in synthetic_params {
            for val in &conflicting_values[..3] {
                let new_url = if base_url.contains('?') {
                    format!("{base_url}&{param}={val}")
                } else {
                    format!("{base_url}?{param}={val}")
                };
                out.push(MutatedRequest {
                    dimension: AttackDimension::ParameterPollution,
                    description: format!("inject synthetic param {param}={val}"),
                    method: exchange.request_method.clone(),
                    url: new_url,
                    headers: exchange.request_headers.clone(),
                    body: exchange.request_body.clone(),
                });
            }
        }
    } else {
        // Duplicate each existing param with conflicting values
        for (key, _original) in &params {
            for conflict in &conflicting_values {
                let mut new_params = params.clone();
                new_params.push((key.clone(), conflict.to_string()));
                let new_url = build_url_with_params(&base_url, &new_params);
                out.push(MutatedRequest {
                    dimension: AttackDimension::ParameterPollution,
                    description: format!("duplicate param {key} with conflicting value {conflict}"),
                    method: exchange.request_method.clone(),
                    url: new_url,
                    headers: exchange.request_headers.clone(),
                    body: exchange.request_body.clone(),
                });
            }
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Verb tampering: cycle through HTTP methods
// ---------------------------------------------------------------------------

const VERBS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"];

fn generate_verb_tampering(exchange: &RecordedExchange) -> Vec<MutatedRequest> {
    let original = exchange.request_method.to_uppercase();
    VERBS
        .iter()
        .filter(|&&v| v != original)
        .map(|&verb| MutatedRequest {
            dimension: AttackDimension::VerbTampering,
            description: format!("{original}→{verb}"),
            method: verb.to_string(),
            url: exchange.request_url.clone(),
            headers: exchange.request_headers.clone(),
            body: exchange.request_body.clone(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Content-type confusion: transform payload across content types
// ---------------------------------------------------------------------------

fn body_as_json_string(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return Some("{}".to_string());
    }
    let s = std::str::from_utf8(body).ok()?;
    if serde_json::from_str::<serde_json::Value>(s).is_ok() {
        Some(s.to_string())
    } else {
        // Treat as form-urlencoded → JSON object
        let pairs: Vec<(String, String)> = s
            .split('&')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let k = parts.next()?.to_string();
                let v = parts.next().unwrap_or("").to_string();
                Some((k, v))
            })
            .collect();
        let map: serde_json::Map<String, serde_json::Value> = pairs
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        serde_json::to_string(&serde_json::Value::Object(map)).ok()
    }
}

fn json_to_xml(json_str: &str) -> String {
    let mut xml = String::from("<?xml version=\"1.0\"?><root>");
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str)
        && let Some(obj) = val.as_object()
    {
        for (k, v) in obj {
            let text = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            xml.push_str(&format!("<{k}>{text}</{k}>"));
        }
    }
    xml.push_str("</root>");
    xml
}

fn json_to_multipart(json_str: &str, boundary: &str) -> Vec<u8> {
    let mut body = Vec::new();
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str)
        && let Some(obj) = val.as_object()
    {
        for (k, v) in obj {
            let text = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{k}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(text.as_bytes());
            body.extend_from_slice(b"\r\n");
        }
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

fn set_content_type(headers: &[(String, String)], ct: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = headers
        .iter()
        .filter(|(k, _)| k.to_lowercase() != "content-type")
        .cloned()
        .collect();
    out.push(("Content-Type".to_string(), ct.to_string()));
    out
}

fn generate_content_type_confusion(exchange: &RecordedExchange) -> Vec<MutatedRequest> {
    let mut out = Vec::new();
    let json_str = body_as_json_string(&exchange.request_body)
        .unwrap_or_else(|| "{}".to_string());

    // → JSON
    out.push(MutatedRequest {
        dimension: AttackDimension::ContentTypeConfusion,
        description: "payload as application/json".to_string(),
        method: exchange.request_method.clone(),
        url: exchange.request_url.clone(),
        headers: set_content_type(&exchange.request_headers, "application/json"),
        body: json_str.as_bytes().to_vec(),
    });

    // → XML
    let xml_body = json_to_xml(&json_str);
    out.push(MutatedRequest {
        dimension: AttackDimension::ContentTypeConfusion,
        description: "payload as application/xml".to_string(),
        method: exchange.request_method.clone(),
        url: exchange.request_url.clone(),
        headers: set_content_type(&exchange.request_headers, "application/xml"),
        body: xml_body.into_bytes(),
    });

    // → text/xml variant
    out.push(MutatedRequest {
        dimension: AttackDimension::ContentTypeConfusion,
        description: "payload as text/xml".to_string(),
        method: exchange.request_method.clone(),
        url: exchange.request_url.clone(),
        headers: set_content_type(&exchange.request_headers, "text/xml"),
        body: json_to_xml(&json_str).into_bytes(),
    });

    // → multipart/form-data
    let boundary = "----AegisMutationBoundary";
    let mp_body = json_to_multipart(&json_str, boundary);
    out.push(MutatedRequest {
        dimension: AttackDimension::ContentTypeConfusion,
        description: "payload as multipart/form-data".to_string(),
        method: exchange.request_method.clone(),
        url: exchange.request_url.clone(),
        headers: set_content_type(
            &exchange.request_headers,
            &format!("multipart/form-data; boundary={boundary}"),
        ),
        body: mp_body,
    });

    // → x-www-form-urlencoded
    let form_body = json_to_form_urlencoded(&json_str);
    out.push(MutatedRequest {
        dimension: AttackDimension::ContentTypeConfusion,
        description: "payload as application/x-www-form-urlencoded".to_string(),
        method: exchange.request_method.clone(),
        url: exchange.request_url.clone(),
        headers: set_content_type(
            &exchange.request_headers,
            "application/x-www-form-urlencoded",
        ),
        body: form_body.into_bytes(),
    });

    out
}

fn json_to_form_urlencoded(json_str: &str) -> String {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str)
        && let Some(obj) = val.as_object()
    {
        let pairs: Vec<String> = obj
            .iter()
            .map(|(k, v)| {
                let text = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                format!("{k}={text}")
            })
            .collect();
        return pairs.join("&");
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Path normalization attacks
// ---------------------------------------------------------------------------

fn generate_path_normalization(exchange: &RecordedExchange) -> Vec<MutatedRequest> {
    let url = &exchange.request_url;
    let traversal_payloads = [
        ("..;/ traversal", insert_traversal(url, "..;/")),
        ("/./ self-reference", insert_traversal(url, "/./")),
        ("%2e%2e/ encoded traversal", insert_traversal(url, "%2e%2e/")),
        ("%2e%2e%2f double-encoded", insert_traversal(url, "%2e%2e%2f")),
        ("..%00/ null byte", insert_traversal(url, "..%00/")),
        ("..%5c/ backslash", insert_traversal(url, "..%5c/")),
        (".%2e/ mixed encoding", insert_traversal(url, ".%2e/")),
        ("path/./to normalization", normalize_slashes(url)),
        ("double slash //", double_slash(url)),
        ("trailing dot", add_trailing(url, ".")),
        ("trailing slash", add_trailing(url, "/")),
        ("trailing semicolon", add_trailing(url, ";")),
    ];

    traversal_payloads
        .into_iter()
        .map(|(desc, mutated_url)| MutatedRequest {
            dimension: AttackDimension::PathNormalization,
            description: desc.to_string(),
            method: exchange.request_method.clone(),
            url: mutated_url,
            headers: exchange.request_headers.clone(),
            body: exchange.request_body.clone(),
        })
        .collect()
}

fn insert_traversal(url: &str, payload: &str) -> String {
    // Insert traversal sequence after the host/path boundary
    if let Some(path_start) = url.find("//").and_then(|i| url[i + 2..].find('/').map(|j| i + 2 + j)) {
        let (prefix, suffix) = url.split_at(path_start + 1);
        format!("{prefix}{payload}{suffix}")
    } else if let Some(idx) = url.rfind('/') {
        let (prefix, suffix) = url.split_at(idx + 1);
        format!("{prefix}{payload}{suffix}")
    } else {
        format!("{url}/{payload}")
    }
}

fn normalize_slashes(url: &str) -> String {
    url.replace("//", "/").replacen(":/", "://", 1)
}

fn double_slash(url: &str) -> String {
    if let Some(idx) = url.rfind('/') {
        let (prefix, suffix) = url.split_at(idx);
        format!("{prefix}/{suffix}")
    } else {
        format!("{url}//")
    }
}

fn add_trailing(url: &str, suffix: &str) -> String {
    let (path, query) = if let Some(idx) = url.find('?') {
        (&url[..idx], Some(&url[idx..]))
    } else {
        (url, None)
    };
    match query {
        Some(q) => format!("{path}{suffix}{q}"),
        None => format!("{path}{suffix}"),
    }
}

// ---------------------------------------------------------------------------
// Header injection via CRLF
// ---------------------------------------------------------------------------

fn generate_header_injection(exchange: &RecordedExchange) -> Vec<MutatedRequest> {
    let crlf_payloads = [
        ("CRLF in X-Custom header", "X-Custom", "value\r\nInjected-Header: pwned"),
        ("CRLF in Referer", "Referer", "http://example.com\r\nX-Injected: true"),
        ("CRLF newline only", "X-Test", "value\nInjected: yes"),
        ("CRLF carriage return only", "X-Test", "value\rInjected: yes"),
        ("CRLF double inject", "X-Probe", "a\r\nSet-Cookie: evil=1\r\nX-End: b"),
        ("Host header override", "Host", "evil.com"),
        ("X-Forwarded-For spoofing", "X-Forwarded-For", "127.0.0.1"),
        ("X-Original-URL override", "X-Original-URL", "/admin"),
        ("X-Rewrite-URL override", "X-Rewrite-URL", "/admin"),
        ("X-Forwarded-Host injection", "X-Forwarded-Host", "evil.com"),
    ];

    crlf_payloads
        .into_iter()
        .map(|(desc, header_name, header_val)| {
            let mut headers = exchange.request_headers.clone();
            headers.push((header_name.to_string(), header_val.to_string()));
            MutatedRequest {
                dimension: AttackDimension::HeaderInjection,
                description: desc.to_string(),
                method: exchange.request_method.clone(),
                url: exchange.request_url.clone(),
                headers,
                body: exchange.request_body.clone(),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Encoding ladder: none → URL → double-URL → Unicode → hex
// ---------------------------------------------------------------------------

fn url_encode(input: &str) -> String {
    input
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
                String::from(b as char)
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn double_url_encode(input: &str) -> String {
    url_encode(&url_encode(input))
}

fn unicode_encode(input: &str) -> String {
    input.chars().map(|c| format!("\\u{:04x}", c as u32)).collect()
}

fn hex_encode(input: &str) -> String {
    input.bytes().map(|b| format!("%{b:02x}")).collect()
}

fn html_entity_encode(input: &str) -> String {
    input.chars().map(|c| format!("&#{};", c as u32)).collect()
}

type EncodingFn = fn(&str) -> String;

fn generate_encoding_ladder(exchange: &RecordedExchange) -> Vec<MutatedRequest> {
    let mut out = Vec::new();
    let (base_url, params) = extract_query_params(&exchange.request_url);

    let probe = if params.is_empty() {
        "<script>alert(1)</script>".to_string()
    } else {
        params
            .first()
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "test".to_string())
    };

    let encodings: Vec<(&str, String)> = vec![
        ("url-encoded", url_encode(&probe)),
        ("double-url-encoded", double_url_encode(&probe)),
        ("unicode-encoded", unicode_encode(&probe)),
        ("hex-encoded", hex_encode(&probe)),
        ("html-entity-encoded", html_entity_encode(&probe)),
    ];

    for (label, encoded_val) in &encodings {
        if params.is_empty() {
            let new_url = format!("{base_url}?probe={encoded_val}");
            out.push(MutatedRequest {
                dimension: AttackDimension::EncodingLadder,
                description: format!("encoding ladder: {label}"),
                method: exchange.request_method.clone(),
                url: new_url,
                headers: exchange.request_headers.clone(),
                body: exchange.request_body.clone(),
            });
        } else {
            for (i, (key, _)) in params.iter().enumerate() {
                let mut new_params = params.clone();
                new_params[i] = (key.clone(), encoded_val.clone());
                let new_url = build_url_with_params(&base_url, &new_params);
                out.push(MutatedRequest {
                    dimension: AttackDimension::EncodingLadder,
                    description: format!("encoding ladder: {label} on param {key}"),
                    method: exchange.request_method.clone(),
                    url: new_url,
                    headers: exchange.request_headers.clone(),
                    body: exchange.request_body.clone(),
                });
            }
        }
    }

    // Also encode the path segments
    let path_encoding_fns: &[(&str, EncodingFn)] = &[
        ("path url-encode", url_encode),
        ("path double-encode", double_url_encode),
        ("path unicode-encode", unicode_encode),
    ];

    let path_part = extract_path(&exchange.request_url);
    for (label, encoder) in path_encoding_fns {
        let encoded_path = encoder(&path_part);
        let new_url = exchange.request_url.replace(&path_part, &encoded_path);
        out.push(MutatedRequest {
            dimension: AttackDimension::EncodingLadder,
            description: format!("encoding ladder: {label}"),
            method: exchange.request_method.clone(),
            url: new_url,
            headers: exchange.request_headers.clone(),
            body: exchange.request_body.clone(),
        });
    }

    out
}

fn extract_path(url: &str) -> String {
    // Extract path component from URL
    if let Some(scheme_end) = url.find("://") {
        let after_scheme = &url[scheme_end + 3..];
        if let Some(path_start) = after_scheme.find('/') {
            let path_and_query = &after_scheme[path_start..];
            if let Some(q) = path_and_query.find('?') {
                return path_and_query[..q].to_string();
            }
            return path_and_query.to_string();
        }
        return "/".to_string();
    }
    // Relative URL
    if let Some(q) = url.find('?') {
        url[..q].to_string()
    } else {
        url.to_string()
    }
}

#[cfg(test)]
#[path = "mutation_replay_test.rs"]
mod mutation_replay_test;
