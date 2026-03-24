use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// A JavaScript source extracted from a page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsSource {
    pub url: Option<String>,
    pub content: String,
    pub source_type: JsSourceType,
    pub size_bytes: usize,
}

/// Type of JavaScript source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JsSourceType {
    Inline,
    External,
    EventHandler,
    DynamicImport,
}

/// Sensitive data found in JavaScript code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveJsData {
    pub data_type: SensitiveDataType,
    pub value: String,
    pub context: String,
    pub source_file: Option<String>,
    pub line_number: Option<u32>,
}

/// Type of sensitive data found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensitiveDataType {
    ApiKey,
    AwsAccessKey,
    AwsSecretKey,
    PrivateKey,
    JwtToken,
    Password,
    ConnectionString,
    InternalUrl,
    Email,
    BearerToken,
    GoogleApiKey,
    StripeKey,
    SlackToken,
    GitHubToken,
    GenericSecret,
}

/// A DOM XSS sink found in JavaScript code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomXssSink {
    pub sink_type: XssSinkType,
    pub code_snippet: String,
    pub source_file: Option<String>,
    pub taint_source: Option<String>,
}

/// Type of DOM XSS sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum XssSinkType {
    InnerHtml,
    OuterHtml,
    DocumentWrite,
    Eval,
    SetTimeout,
    SetInterval,
    Function,
    WindowOpen,
    LocationAssign,
    LocationHref,
    JQueryHtml,
    InsertAdjacentHtml,
}

/// Source map information for deobfuscation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMapInfo {
    pub source_map_url: String,
    pub original_sources: Vec<String>,
    pub mappings_present: bool,
}

/// Webpack chunk information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebpackChunk {
    pub chunk_id: String,
    pub url: String,
    pub modules: Vec<String>,
}

/// Service worker registration found on the page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceWorkerInfo {
    pub script_url: String,
    pub scope: String,
    pub cache_strategies: Vec<String>,
    pub intercepts_fetch: bool,
}

/// Full result of JavaScript analysis on a page.
#[derive(Debug, Clone, Default)]
pub struct JsAnalysisResult {
    pub sources: Vec<JsSource>,
    pub sensitive_data: Vec<SensitiveJsData>,
    pub xss_sinks: Vec<DomXssSink>,
    pub api_endpoints: Vec<String>,
    pub source_maps: Vec<SourceMapInfo>,
    pub webpack_chunks: Vec<WebpackChunk>,
    pub service_workers: Vec<ServiceWorkerInfo>,
    pub total_js_bytes: usize,
}

/// Extract all inline and external JavaScript references from HTML.
pub fn extract_js_sources(html: &str) -> Vec<JsSource> {
    let mut sources = Vec::new();

    let script_re =
        regex::Regex::new(r#"(?is)<script([^>]*)>(.*?)</script>"#).unwrap();
    let src_re = regex::Regex::new(r#"(?i)src\s*=\s*["']([^"']+)["']"#).unwrap();

    for cap in script_re.captures_iter(html) {
        let attrs = &cap[1];
        let body = &cap[2];

        if let Some(src_cap) = src_re.captures(attrs) {
            sources.push(JsSource {
                url: Some(src_cap[1].to_string()),
                content: String::new(),
                source_type: JsSourceType::External,
                size_bytes: 0,
            });
        }

        let trimmed = body.trim();
        if !trimmed.is_empty() {
            sources.push(JsSource {
                url: None,
                content: trimmed.to_string(),
                source_type: JsSourceType::Inline,
                size_bytes: trimmed.len(),
            });
        }
    }

    let handler_re = regex::Regex::new(
        r#"(?i)(?:onclick|onload|onerror|onsubmit|onchange|onfocus|onblur|onmouseover)\s*=\s*["']([^"']+)["']"#,
    ).unwrap();
    for cap in handler_re.captures_iter(html) {
        sources.push(JsSource {
            url: None,
            content: cap[1].to_string(),
            source_type: JsSourceType::EventHandler,
            size_bytes: cap[1].len(),
        });
    }

    let import_re =
        regex::Regex::new(r#"import\s*\(\s*["'`]([^"'`]+)["'`]\s*\)"#).unwrap();
    for cap in import_re.captures_iter(html) {
        sources.push(JsSource {
            url: Some(cap[1].to_string()),
            content: String::new(),
            source_type: JsSourceType::DynamicImport,
            size_bytes: 0,
        });
    }

    sources
}

/// Scan JavaScript source code for sensitive data like API keys, tokens, and credentials.
///
/// Uses regex patterns to detect common secret formats including AWS keys,
/// JWT tokens, API keys, connection strings, and other sensitive values
/// that should not be exposed in client-side code.
pub fn find_sensitive_data(js_content: &str, source_file: Option<&str>) -> Vec<SensitiveJsData> {
    let mut findings = Vec::new();

    let patterns: &[(&str, SensitiveDataType)] = &[
        (r"AKIA[0-9A-Z]{16}", SensitiveDataType::AwsAccessKey),
        (
            r#"(?:aws_secret|secret_key|secretAccessKey)\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']"#,
            SensitiveDataType::AwsSecretKey,
        ),
        (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", SensitiveDataType::JwtToken),
        (
            r#"(?:api_key|apikey|api-key|apiKey)\s*[:=]\s*["']([A-Za-z0-9_-]{20,})["']"#,
            SensitiveDataType::ApiKey,
        ),
        (
            r#"(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{4,})["']"#,
            SensitiveDataType::Password,
        ),
        (
            r#"(?:mongodb|postgres|mysql|redis)://[^\s"']+:[^\s"']+@[^\s"']+"#,
            SensitiveDataType::ConnectionString,
        ),
        (
            r#"(?:Bearer|bearer)\s+[A-Za-z0-9._-]{20,}"#,
            SensitiveDataType::BearerToken,
        ),
        (
            r"AIza[A-Za-z0-9_-]{35}",
            SensitiveDataType::GoogleApiKey,
        ),
        (
            r"(?:sk_live|pk_live|sk_test|pk_test)_[A-Za-z0-9]{20,}",
            SensitiveDataType::StripeKey,
        ),
        (
            r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}",
            SensitiveDataType::SlackToken,
        ),
        (
            r"gh[pousr]_[A-Za-z0-9_]{36,}",
            SensitiveDataType::GitHubToken,
        ),
        (
            r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
            SensitiveDataType::PrivateKey,
        ),
        (
            r#"(?:secret|token|key)\s*[:=]\s*["']([A-Za-z0-9_/+=]{16,})["']"#,
            SensitiveDataType::GenericSecret,
        ),
    ];

    for (pattern, data_type) in patterns {
        let re = regex::Regex::new(pattern).unwrap();
        for mat in re.find_iter(js_content) {
            let start = mat.start().saturating_sub(30);
            let end = (mat.end() + 30).min(js_content.len());
            let context = js_content[start..end].to_string();

            findings.push(SensitiveJsData {
                data_type: *data_type,
                value: mat.as_str().to_string(),
                context,
                source_file: source_file.map(|s| s.to_string()),
                line_number: Some(
                    js_content[..mat.start()]
                        .chars()
                        .filter(|c| *c == '\n')
                        .count() as u32
                        + 1,
                ),
            });
        }
    }

    findings
}

/// Find DOM XSS sinks in JavaScript code.
///
/// Identifies dangerous assignments to innerHTML, document.write(), eval(),
/// and other sinks that can lead to cross-site scripting vulnerabilities
/// when controlled by user input.
pub fn find_xss_sinks(js_content: &str, source_file: Option<&str>) -> Vec<DomXssSink> {
    let mut sinks = Vec::new();

    let patterns: &[(&str, XssSinkType, Option<&str>)] = &[
        (
            r"\.innerHTML\s*=",
            XssSinkType::InnerHtml,
            None,
        ),
        (
            r"\.outerHTML\s*=",
            XssSinkType::OuterHtml,
            None,
        ),
        (
            r"document\.write\s*\(",
            XssSinkType::DocumentWrite,
            None,
        ),
        (
            r"document\.writeln\s*\(",
            XssSinkType::DocumentWrite,
            None,
        ),
        (
            r"\beval\s*\(",
            XssSinkType::Eval,
            None,
        ),
        (
            r"setTimeout\s*\(\s*[^,]*(?:location|document|window)",
            XssSinkType::SetTimeout,
            Some("location/document/window"),
        ),
        (
            r"setInterval\s*\(\s*[^,]*(?:location|document|window)",
            XssSinkType::SetInterval,
            Some("location/document/window"),
        ),
        (
            r"new\s+Function\s*\(",
            XssSinkType::Function,
            None,
        ),
        (
            r"window\.open\s*\(",
            XssSinkType::WindowOpen,
            None,
        ),
        (
            r"location\s*=",
            XssSinkType::LocationAssign,
            None,
        ),
        (
            r"location\.href\s*=",
            XssSinkType::LocationHref,
            None,
        ),
        (
            r"\$\([^)]*\)\s*\.html\s*\(",
            XssSinkType::JQueryHtml,
            None,
        ),
        (
            r"\.insertAdjacentHTML\s*\(",
            XssSinkType::InsertAdjacentHtml,
            None,
        ),
    ];

    for (pattern, sink_type, taint) in patterns {
        let re = regex::Regex::new(pattern).unwrap();
        for mat in re.find_iter(js_content) {
            let start = mat.start().saturating_sub(40);
            let end = (mat.end() + 40).min(js_content.len());
            let snippet = js_content[start..end].to_string();

            sinks.push(DomXssSink {
                sink_type: *sink_type,
                code_snippet: snippet,
                source_file: source_file.map(|s| s.to_string()),
                taint_source: taint.map(|s| s.to_string()),
            });
        }
    }

    sinks
}

/// Extract API endpoint URLs referenced in JavaScript code.
pub fn extract_api_endpoints(js_content: &str) -> Vec<String> {
    let mut endpoints = HashSet::new();

    let url_patterns = [
        r#"["'`](/api/[^"'`\s]+)["'`]"#,
        r#"["'`](/v\d+/[^"'`\s]+)["'`]"#,
        r#"["'`](https?://[^"'`\s]+/api/[^"'`\s]+)["'`]"#,
        r#"["'`](/graphql)["'`]"#,
        r#"["'`](/rest/[^"'`\s]+)["'`]"#,
    ];

    for pattern in url_patterns {
        let re = regex::Regex::new(pattern).unwrap();
        for cap in re.captures_iter(js_content) {
            endpoints.insert(cap[1].to_string());
        }
    }

    let mut sorted: Vec<String> = endpoints.into_iter().collect();
    sorted.sort();
    sorted
}

/// Detect source map references in JavaScript content.
pub fn detect_source_maps(js_content: &str) -> Vec<SourceMapInfo> {
    let mut maps = Vec::new();

    let re = regex::Regex::new(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)").unwrap();
    for cap in re.captures_iter(js_content) {
        maps.push(SourceMapInfo {
            source_map_url: cap[1].to_string(),
            original_sources: Vec::new(),
            mappings_present: true,
        });
    }

    maps
}

/// Detect webpack chunk definitions and dynamic imports.
pub fn detect_webpack_chunks(js_content: &str) -> Vec<WebpackChunk> {
    let mut chunks = Vec::new();

    let chunk_re =
        regex::Regex::new(r#"(?:webpackChunkName|chunkFilename)\s*:\s*["']([^"']+)["']"#)
            .unwrap();
    for cap in chunk_re.captures_iter(js_content) {
        chunks.push(WebpackChunk {
            chunk_id: cap[1].to_string(),
            url: String::new(),
            modules: Vec::new(),
        });
    }

    let jsonp_re =
        regex::Regex::new(r#"(?:webpackJsonp|__webpack_require__)\s*\.\s*(?:push|e)\s*\(\s*\[?\s*["']?(\w+)["']?"#)
            .unwrap();
    for cap in jsonp_re.captures_iter(js_content) {
        let id = cap[1].to_string();
        if !chunks.iter().any(|c| c.chunk_id == id) {
            chunks.push(WebpackChunk {
                chunk_id: id,
                url: String::new(),
                modules: Vec::new(),
            });
        }
    }

    chunks
}

/// Detect service worker registrations in JavaScript.
pub fn detect_service_workers(js_content: &str) -> Vec<ServiceWorkerInfo> {
    let mut workers = Vec::new();

    let sw_re = regex::Regex::new(
        r#"navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*["'`]([^"'`]+)["'`]"#,
    )
    .unwrap();

    for cap in sw_re.captures_iter(js_content) {
        let script_url = cap[1].to_string();
        let scope = extract_sw_scope(js_content, &script_url);
        let intercepts = js_content.contains("FetchEvent")
            || js_content.contains("onfetch")
            || js_content.contains("addEventListener('fetch");

        workers.push(ServiceWorkerInfo {
            script_url,
            scope,
            cache_strategies: detect_cache_strategies(js_content),
            intercepts_fetch: intercepts,
        });
    }

    workers
}

fn extract_sw_scope(js_content: &str, _script_url: &str) -> String {
    let scope_re = regex::Regex::new(r#"scope\s*:\s*["'`]([^"'`]+)["'`]"#).unwrap();
    scope_re
        .captures(js_content)
        .map(|c| c[1].to_string())
        .unwrap_or_else(|| "/".to_string())
}

fn detect_cache_strategies(js_content: &str) -> Vec<String> {
    let mut strategies = Vec::new();
    let patterns = [
        ("cache-first", "CacheFirst"),
        ("network-first", "NetworkFirst"),
        ("stale-while-revalidate", "StaleWhileRevalidate"),
        ("network-only", "NetworkOnly"),
        ("cache-only", "CacheOnly"),
    ];
    for (pattern, name) in patterns {
        if js_content.to_lowercase().contains(pattern) {
            strategies.push(name.to_string());
        }
    }
    strategies
}

/// Perform full JavaScript analysis on collected sources.
///
/// Extracts sensitive data, XSS sinks, API endpoints, source maps,
/// webpack chunks, and service worker info from all provided JS sources.
pub fn analyze_javascript(sources: &[JsSource]) -> JsAnalysisResult {
    let mut result = JsAnalysisResult::default();
    let mut all_endpoints = HashSet::new();

    for source in sources {
        result.total_js_bytes += source.size_bytes;
        result.sources.push(source.clone());

        let content = &source.content;
        if content.is_empty() {
            continue;
        }

        let file_ref = source.url.as_deref();

        result
            .sensitive_data
            .extend(find_sensitive_data(content, file_ref));
        result.xss_sinks.extend(find_xss_sinks(content, file_ref));

        for ep in extract_api_endpoints(content) {
            if all_endpoints.insert(ep.clone()) {
                result.api_endpoints.push(ep);
            }
        }

        result
            .source_maps
            .extend(detect_source_maps(content));
        result
            .webpack_chunks
            .extend(detect_webpack_chunks(content));
        result
            .service_workers
            .extend(detect_service_workers(content));
    }

    result.api_endpoints.sort();
    result
}

#[cfg(test)]
#[path = "js_executor_test.rs"]
mod js_executor_test;
