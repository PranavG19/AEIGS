use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use crate::executor::FuzzResponse;

/// Fingerprint of a response's behavioral signature.
///
/// Captures the "shape" of a response rather than its exact content,
/// enabling AFL-style coverage guidance for black-box web fuzzing.
/// Each distinct signature indicates a different server code path was exercised.
pub struct BehavioralSignature {
    /// Bucketed status class: 1xx=1, 2xx=2, 3xx=3, 4xx=4, 5xx=5
    pub status_bucket: u16,
    /// Hash of sorted, lowercased response header names
    pub header_set_hash: u64,
    /// Hash of body structure (HTML tag tree, JSON key tree, or text length bucket)
    pub body_structure_hash: u64,
    /// Latency bucket: 0=<10ms, 1=<100ms, 2=<500ms, 3=<1s, 4=>=1s
    pub timing_bucket: u8,
    /// Extracted error class if the response contains recognizable error patterns
    pub error_class: Option<String>,
    /// Bucketed content length: 0=empty, 1=<256, 2=<1K, 3=<4K, 4=<16K, 5=<64K, 6=>=64K
    pub content_length_bucket: u8,
}

impl BehavioralSignature {
    /// Produce a single u64 hash representing this entire signature.
    pub fn combined_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.status_bucket.hash(&mut hasher);
        self.header_set_hash.hash(&mut hasher);
        self.body_structure_hash.hash(&mut hasher);
        self.timing_bucket.hash(&mut hasher);
        self.error_class.hash(&mut hasher);
        self.content_length_bucket.hash(&mut hasher);
        hasher.finish()
    }
}

/// Outcome of recording a response with the coverage tracker.
pub enum CoverageResult {
    /// Previously unseen behavioral signature — new server behavior discovered.
    Novel(BehavioralSignature),
    /// Already observed this signature hash.
    Known(u64),
}

/// AFL-style behavioral coverage tracker for black-box web fuzzing.
///
/// Hashes response structure (status bucket + header set + body structure +
/// timing bucket + error class + content length bucket) into behavioral
/// signatures. Novel signatures indicate new server code paths, and the
/// triggering payloads receive a UCB1 priority boost.
pub struct CoverageTracker {
    seen_signatures: HashSet<u64>,
    signature_history: Vec<(u64, String)>,
}

impl CoverageTracker {
    pub fn new() -> Self {
        Self {
            seen_signatures: HashSet::new(),
            signature_history: Vec::new(),
        }
    }

    /// Record a fuzz response and determine if it represents novel behavior.
    pub fn record(&mut self, response: &FuzzResponse, payload: &str) -> CoverageResult {
        let sig = build_signature(response);
        let hash = sig.combined_hash();

        if self.seen_signatures.contains(&hash) {
            return CoverageResult::Known(hash);
        }

        self.seen_signatures.insert(hash);
        self.signature_history.push((hash, payload.to_string()));
        CoverageResult::Novel(sig)
    }

    /// Check whether a signature has already been observed.
    pub fn is_novel(&self, sig: &BehavioralSignature) -> bool {
        !self.seen_signatures.contains(&sig.combined_hash())
    }

    /// Number of distinct behavioral signatures observed so far.
    pub fn coverage_count(&self) -> usize {
        self.seen_signatures.len()
    }

    /// History of (signature_hash, triggering_payload) pairs in discovery order.
    pub fn history(&self) -> &[(u64, String)] {
        &self.signature_history
    }

    /// UCB1 priority boost for a coverage result.
    /// Novel signatures receive a significant boost; known signatures get zero.
    pub fn priority_boost(result: &CoverageResult) -> f64 {
        match result {
            CoverageResult::Novel(_) => 10.0,
            CoverageResult::Known(_) => 0.0,
        }
    }
}

impl Default for CoverageTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a BehavioralSignature from a raw FuzzResponse.
fn build_signature(response: &FuzzResponse) -> BehavioralSignature {
    BehavioralSignature {
        status_bucket: status_to_bucket(response.status_code),
        header_set_hash: hash_header_names(&response.headers),
        body_structure_hash: hash_body_structure(&response.body),
        timing_bucket: duration_to_bucket(response.response_time),
        error_class: extract_error_class(&response.body),
        content_length_bucket: size_to_bucket(response.body_size_bytes),
    }
}

/// Bucket a status code into its class (1xx=1 .. 5xx=5).
fn status_to_bucket(code: u16) -> u16 {
    match code {
        100..=199 => 1,
        200..=299 => 2,
        300..=399 => 3,
        400..=499 => 4,
        500..=599 => 5,
        _ => 0,
    }
}

/// Hash the set of lowercased header names (order-independent).
fn hash_header_names(headers: &[(String, String)]) -> u64 {
    let mut names: Vec<String> = headers.iter().map(|(k, _)| k.to_lowercase()).collect();
    names.sort();
    names.dedup();
    let mut hasher = DefaultHasher::new();
    for name in &names {
        name.hash(&mut hasher);
    }
    hasher.finish()
}

/// Hash body structure: JSON key tree, HTML tag tree, or text-length bucket.
fn hash_body_structure(body: &str) -> u64 {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return 0;
    }

    let structure = if looks_like_json(trimmed) {
        extract_json_key_tree(trimmed)
    } else if looks_like_html(trimmed) {
        extract_html_tag_tree(trimmed)
    } else {
        format!("text:{}", text_length_class(trimmed.len()))
    };

    let mut hasher = DefaultHasher::new();
    structure.hash(&mut hasher);
    hasher.finish()
}

/// Bucket response duration into latency classes.
pub fn duration_to_bucket(d: Duration) -> u8 {
    let ms = d.as_millis();
    if ms < 10 {
        0
    } else if ms < 100 {
        1
    } else if ms < 500 {
        2
    } else if ms < 1000 {
        3
    } else {
        4
    }
}

/// Bucket byte size into content-length classes.
fn size_to_bucket(bytes: usize) -> u8 {
    if bytes == 0 {
        0
    } else if bytes < 256 {
        1
    } else if bytes < 1024 {
        2
    } else if bytes < 4096 {
        3
    } else if bytes < 16384 {
        4
    } else if bytes < 65536 {
        5
    } else {
        6
    }
}

/// Extract a coarse error class from the response body.
fn extract_error_class(body: &str) -> Option<String> {
    let lower = body.to_lowercase();

    if lower.contains("sql") && (lower.contains("syntax") || lower.contains("error")) {
        return Some("sql_error".to_string());
    }
    if lower.contains("traceback") || lower.contains("stack trace") {
        return Some("stack_trace".to_string());
    }
    if lower.contains("not found") || lower.contains("404") {
        return Some("not_found".to_string());
    }
    if lower.contains("forbidden") || lower.contains("403") {
        return Some("forbidden".to_string());
    }
    if lower.contains("unauthorized") || lower.contains("401") {
        return Some("unauthorized".to_string());
    }
    if lower.contains("internal server error") || lower.contains("500") {
        return Some("server_error".to_string());
    }
    if lower.contains("timeout") || lower.contains("timed out") {
        return Some("timeout".to_string());
    }
    if lower.contains("rate limit") || lower.contains("too many requests") {
        return Some("rate_limit".to_string());
    }
    if lower.contains("invalid") && lower.contains("parameter") {
        return Some("invalid_parameter".to_string());
    }
    if lower.contains("exception") || lower.contains("error") {
        return Some("generic_error".to_string());
    }
    None
}

fn looks_like_json(s: &str) -> bool {
    (s.starts_with('{') && s.ends_with('}')) || (s.starts_with('[') && s.ends_with(']'))
}

fn looks_like_html(s: &str) -> bool {
    s.starts_with('<') && s.contains('>')
}

/// Extract a sorted tree of JSON keys as a structural fingerprint.
/// Traverses naively via serde_json::Value to capture nesting shape.
fn extract_json_key_tree(s: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(s) {
        Ok(val) => {
            let mut keys = Vec::new();
            collect_json_keys(&val, "", &mut keys);
            keys.sort();
            format!("json:{}", keys.join(","))
        }
        Err(_) => format!("json_malformed:{}", text_length_class(s.len())),
    }
}

fn collect_json_keys(val: &serde_json::Value, prefix: &str, out: &mut Vec<String>) {
    match val {
        serde_json::Value::Object(map) => {
            for key in map.keys() {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", prefix, key)
                };
                out.push(path.clone());
                collect_json_keys(&map[key], &path, out);
            }
        }
        serde_json::Value::Array(arr) => {
            out.push(format!("{}[]", prefix));
            if let Some(first) = arr.first() {
                collect_json_keys(first, &format!("{}[]", prefix), out);
            }
        }
        _ => {}
    }
}

/// Extract a sorted sequence of HTML tag names as a structural fingerprint.
fn extract_html_tag_tree(s: &str) -> String {
    let mut tags = Vec::new();
    let mut depth: usize = 0;
    let mut i = 0;
    let bytes = s.as_bytes();

    while i < bytes.len() {
        if bytes[i] == b'<' {
            let start = i + 1;
            let is_closing = start < bytes.len() && bytes[start] == b'/';
            let tag_start = if is_closing { start + 1 } else { start };

            let mut end = tag_start;
            while end < bytes.len() && bytes[end] != b'>' && bytes[end] != b' ' {
                end += 1;
            }

            if end > tag_start {
                let tag_name = String::from_utf8_lossy(&bytes[tag_start..end]).to_lowercase();
                if !tag_name.is_empty() && tag_name.chars().all(|c| c.is_ascii_alphanumeric()) {
                    if is_closing {
                        depth = depth.saturating_sub(1);
                    } else {
                        tags.push(format!("{}:{}", depth, tag_name));
                        depth += 1;
                    }
                }
            }
            while i < bytes.len() && bytes[i] != b'>' {
                i += 1;
            }
        }
        i += 1;
    }

    format!("html:{}", tags.join(","))
}

fn text_length_class(len: usize) -> &'static str {
    if len == 0 {
        "empty"
    } else if len < 64 {
        "tiny"
    } else if len < 256 {
        "small"
    } else if len < 1024 {
        "medium"
    } else if len < 4096 {
        "large"
    } else {
        "huge"
    }
}
