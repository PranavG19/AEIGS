use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Configuration for the embedded JavaScript engine.
///
/// Controls execution limits and network intercept behavior. The engine
/// runs JS in-process without launching a browser, suitable for
/// high-throughput endpoint extraction during crawling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsEngineConfig {
    pub max_execution_time_ms: u64,
    pub max_memory_bytes: usize,
    pub enable_network_intercept: bool,
    pub enable_storage_simulation: bool,
    pub enable_console_capture: bool,
}

impl Default for JsEngineConfig {
    fn default() -> Self {
        Self {
            max_execution_time_ms: 5000,
            max_memory_bytes: 64 * 1024 * 1024,
            enable_network_intercept: true,
            enable_storage_simulation: true,
            enable_console_capture: true,
        }
    }
}

impl JsEngineConfig {
    pub fn with_max_execution_time_ms(mut self, ms: u64) -> Self {
        self.max_execution_time_ms = ms;
        self
    }

    pub fn with_max_memory_bytes(mut self, bytes: usize) -> Self {
        self.max_memory_bytes = bytes;
        self
    }

    pub fn with_network_intercept(mut self, enabled: bool) -> Self {
        self.enable_network_intercept = enabled;
        self
    }

    pub fn with_storage_simulation(mut self, enabled: bool) -> Self {
        self.enable_storage_simulation = enabled;
        self
    }

    pub fn with_console_capture(mut self, enabled: bool) -> Self {
        self.enable_console_capture = enabled;
        self
    }
}

/// HTTP method for an intercepted network request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Options,
    Head,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Options => "OPTIONS",
            Self::Head => "HEAD",
        };
        write!(f, "{label}")
    }
}

/// A network request intercepted from fetch() or XMLHttpRequest calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptedRequest {
    pub url: String,
    pub method: HttpMethod,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

/// Simulated DOM for stubbing document methods during JS execution.
///
/// Provides minimal getElementById, querySelector, and createElement
/// stubs that return element representations sufficient for endpoint
/// extraction without a full DOM implementation.
#[derive(Debug, Clone, Default)]
pub struct DomSimulation {
    elements: HashMap<String, SimulatedDomElement>,
}

/// Minimal DOM element representation for JS engine simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedDomElement {
    pub tag: String,
    pub id: Option<String>,
    pub attributes: HashMap<String, String>,
    pub inner_text: String,
}

impl DomSimulation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_element(&mut self, id: &str, element: SimulatedDomElement) {
        self.elements.insert(id.to_string(), element);
    }

    /// Stub for document.getElementById().
    pub fn get_element_by_id(&self, id: &str) -> Option<&SimulatedDomElement> {
        self.elements.get(id)
    }

    /// Stub for document.querySelector() — matches by tag or id selector.
    pub fn query_selector(&self, selector: &str) -> Option<&SimulatedDomElement> {
        if let Some(id) = selector.strip_prefix('#') {
            return self.elements.get(id);
        }
        self.elements.values().find(|el| el.tag == selector)
    }

    /// Stub for document.createElement().
    pub fn create_element(tag: &str) -> SimulatedDomElement {
        SimulatedDomElement {
            tag: tag.to_string(),
            id: None,
            attributes: HashMap::new(),
            inner_text: String::new(),
        }
    }

    pub fn element_count(&self) -> usize {
        self.elements.len()
    }
}

/// HashMap-backed simulation of localStorage/sessionStorage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageSimulation {
    local: HashMap<String, String>,
    session: HashMap<String, String>,
}

impl StorageSimulation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn local_set(&mut self, key: &str, value: &str) {
        self.local.insert(key.to_string(), value.to_string());
    }

    pub fn local_get(&self, key: &str) -> Option<&String> {
        self.local.get(key)
    }

    pub fn local_remove(&mut self, key: &str) {
        self.local.remove(key);
    }

    pub fn local_clear(&mut self) {
        self.local.clear();
    }

    pub fn session_set(&mut self, key: &str, value: &str) {
        self.session.insert(key.to_string(), value.to_string());
    }

    pub fn session_get(&self, key: &str) -> Option<&String> {
        self.session.get(key)
    }

    pub fn session_remove(&mut self, key: &str) {
        self.session.remove(key);
    }

    pub fn session_clear(&mut self) {
        self.session.clear();
    }

    pub fn local_entries(&self) -> &HashMap<String, String> {
        &self.local
    }

    pub fn session_entries(&self) -> &HashMap<String, String> {
        &self.session
    }

    pub fn all_entries(&self) -> HashMap<String, String> {
        let mut merged = self.local.clone();
        merged.extend(self.session.clone());
        merged
    }
}

/// Result of executing JavaScript in the embedded engine.
#[derive(Debug, Clone, Default)]
pub struct JsExecutionResult {
    pub extracted_urls: Vec<String>,
    pub intercepted_requests: Vec<InterceptedRequest>,
    pub storage_entries: HashMap<String, String>,
    pub console_output: Vec<String>,
    pub execution_time_ms: u64,
    pub errors: Vec<String>,
}

/// Parsed source map with mappings, source file references, and symbol names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMap {
    pub version: u32,
    pub file: Option<String>,
    pub source_root: Option<String>,
    pub sources: Vec<String>,
    pub names: Vec<String>,
    pub mappings: String,
}

/// Processor for parsing and applying source maps to deobfuscate JS.
pub struct SourceMapProcessor;

impl SourceMapProcessor {
    /// Parse a source map from raw JSON content.
    ///
    /// Extracts the version, sources, names, and mappings fields.
    /// Returns None if the JSON is malformed or missing required fields.
    pub fn parse(json_content: &str) -> Option<SourceMap> {
        let parsed: serde_json::Value = serde_json::from_str(json_content).ok()?;
        let version = parsed.get("version")?.as_u64()? as u32;
        let file = parsed
            .get("file")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let source_root = parsed
            .get("sourceRoot")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let sources = parsed
            .get("sources")?
            .as_array()?
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        let names = parsed
            .get("names")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let mappings = parsed.get("mappings")?.as_str()?.to_string();

        Some(SourceMap {
            version,
            file,
            source_root,
            sources,
            names,
            mappings,
        })
    }

    /// Count the number of mapping segments in a source map.
    pub fn segment_count(source_map: &SourceMap) -> usize {
        source_map
            .mappings
            .split([',', ';'])
            .filter(|s| !s.is_empty())
            .count()
    }

    /// Deobfuscate a function name using the source map's names array.
    pub fn deobfuscate_name(source_map: &SourceMap, index: usize) -> Option<&str> {
        source_map.names.get(index).map(|s| s.as_str())
    }
}

/// Embedded JavaScript engine for in-process script execution.
///
/// Provides endpoint extraction, network intercept, and storage simulation
/// without spawning a browser process. Uses regex-based static analysis
/// rather than actual JS interpretation for deterministic, fast results.
pub struct JsEngine {
    config: JsEngineConfig,
    dom: DomSimulation,
    storage: StorageSimulation,
    intercepted: Vec<InterceptedRequest>,
    console_output: Vec<String>,
}

impl JsEngine {
    pub fn new(config: JsEngineConfig) -> Self {
        Self {
            config,
            dom: DomSimulation::new(),
            storage: StorageSimulation::new(),
            intercepted: Vec::new(),
            console_output: Vec::new(),
        }
    }

    /// Access the DOM simulation for pre-populating elements.
    pub fn dom_mut(&mut self) -> &mut DomSimulation {
        &mut self.dom
    }

    /// Access the storage simulation for pre-populating values.
    pub fn storage_mut(&mut self) -> &mut StorageSimulation {
        &mut self.storage
    }

    /// Execute a JavaScript snippet and collect all intercepted data.
    ///
    /// Uses static analysis (regex extraction) to find fetch/XHR calls,
    /// URL constructions, localStorage operations, and console.log calls.
    /// Does not actually interpret JS — relies on pattern matching for
    /// high-speed deterministic extraction.
    pub fn execute(&mut self, script: &str) -> Result<JsExecutionResult, JsEngineError> {
        if script.is_empty() {
            return Err(JsEngineError::EmptyScript);
        }

        let start = std::time::Instant::now();

        let urls = self.extract_all_urls(script);
        let requests = self.extract_network_calls(script);
        self.extract_storage_ops(script);
        let console = self.extract_console_output(script);

        if self.config.enable_network_intercept {
            self.intercepted.extend(requests.clone());
        }
        if self.config.enable_console_capture {
            self.console_output.extend(console.clone());
        }

        let elapsed = start.elapsed().as_millis() as u64;

        Ok(JsExecutionResult {
            extracted_urls: urls,
            intercepted_requests: requests,
            storage_entries: self.storage.all_entries(),
            console_output: console,
            execution_time_ms: elapsed,
            errors: Vec::new(),
        })
    }

    /// Extract endpoint URLs from a script without collecting full intercept data.
    pub fn extract_endpoints(&self, script: &str) -> Vec<String> {
        self.extract_all_urls(script)
    }

    /// Access the current configuration.
    pub fn config(&self) -> &JsEngineConfig {
        &self.config
    }

    /// Get all intercepted requests accumulated across execute() calls.
    pub fn all_intercepted_requests(&self) -> &[InterceptedRequest] {
        &self.intercepted
    }

    fn extract_all_urls(&self, script: &str) -> Vec<String> {
        let mut urls = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let fetch_re = regex::Regex::new(r#"fetch\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap();
        for cap in fetch_re.captures_iter(script) {
            let url = cap[1].to_string();
            if seen.insert(url.clone()) {
                urls.push(url);
            }
        }

        let xhr_re = regex::Regex::new(
            r#"\.open\s*\(\s*["'](?:GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["'`]([^"'`]+)["'`]"#,
        )
        .unwrap();
        for cap in xhr_re.captures_iter(script) {
            let url = cap[1].to_string();
            if seen.insert(url.clone()) {
                urls.push(url);
            }
        }

        let axios_re = regex::Regex::new(
            r#"axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]"#,
        )
        .unwrap();
        for cap in axios_re.captures_iter(script) {
            let url = cap[1].to_string();
            if seen.insert(url.clone()) {
                urls.push(url);
            }
        }

        let string_url_re =
            regex::Regex::new(r#"["'`]((?:https?://|/api/|/v\d+/)[^"'`\s]+)["'`]"#).unwrap();
        for cap in string_url_re.captures_iter(script) {
            let url = cap[1].to_string();
            if seen.insert(url.clone()) {
                urls.push(url);
            }
        }

        let concat_re =
            regex::Regex::new(r#"["'`](/[a-zA-Z0-9_-]+)["'`]\s*\+\s*["'`](/[a-zA-Z0-9_/-]+)["'`]"#)
                .unwrap();
        for cap in concat_re.captures_iter(script) {
            let combined = format!("{}{}", &cap[1], &cap[2]);
            if seen.insert(combined.clone()) {
                urls.push(combined);
            }
        }

        urls
    }

    fn extract_network_calls(&self, script: &str) -> Vec<InterceptedRequest> {
        let mut requests = Vec::new();

        let fetch_re =
            regex::Regex::new(r#"fetch\s*\(\s*["'`]([^"'`]+)["'`](?:\s*,\s*\{([^}]*)\})?"#)
                .unwrap();
        let method_re = regex::Regex::new(r#"method\s*:\s*["'](\w+)["']"#).unwrap();
        let body_re =
            regex::Regex::new(r#"body\s*:\s*(?:JSON\.stringify\()?["'`]?([^"'`)}]+)"#).unwrap();
        for cap in fetch_re.captures_iter(script) {
            let url = cap[1].to_string();
            let method = cap
                .get(2)
                .and_then(|opts| method_re.captures(opts.as_str()).map(|m| m[1].to_string()))
                .unwrap_or_else(|| "GET".to_string());
            let body = cap
                .get(2)
                .and_then(|opts| body_re.captures(opts.as_str()).map(|m| m[1].to_string()));
            requests.push(InterceptedRequest {
                url,
                method: parse_http_method(&method),
                headers: HashMap::new(),
                body,
            });
        }

        let xhr_re =
            regex::Regex::new(r#"\.open\s*\(\s*["'](\w+)["']\s*,\s*["'`]([^"'`]+)["'`]"#).unwrap();
        for cap in xhr_re.captures_iter(script) {
            requests.push(InterceptedRequest {
                url: cap[2].to_string(),
                method: parse_http_method(&cap[1]),
                headers: HashMap::new(),
                body: None,
            });
        }

        requests
    }

    fn extract_storage_ops(&mut self, script: &str) {
        let set_re = regex::Regex::new(
            r#"localStorage\s*\.\s*setItem\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']\s*\)"#,
        )
        .unwrap();
        for cap in set_re.captures_iter(script) {
            self.storage.local_set(&cap[1], &cap[2]);
        }

        let session_set_re = regex::Regex::new(
            r#"sessionStorage\s*\.\s*setItem\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']\s*\)"#,
        )
        .unwrap();
        for cap in session_set_re.captures_iter(script) {
            self.storage.session_set(&cap[1], &cap[2]);
        }
    }

    fn extract_console_output(&self, script: &str) -> Vec<String> {
        let mut output = Vec::new();
        let log_re = regex::Regex::new(
            r#"console\s*\.\s*(?:log|warn|error|info)\s*\(\s*["'`]([^"'`]+)["'`]"#,
        )
        .unwrap();
        for cap in log_re.captures_iter(script) {
            output.push(cap[1].to_string());
        }
        output
    }
}

/// Parse a string HTTP method name into the enum variant.
fn parse_http_method(method: &str) -> HttpMethod {
    match method.to_uppercase().as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "PATCH" => HttpMethod::Patch,
        "OPTIONS" => HttpMethod::Options,
        "HEAD" => HttpMethod::Head,
        _ => HttpMethod::Get,
    }
}

/// Errors from the embedded JS engine.
#[derive(Debug)]
pub enum JsEngineError {
    EmptyScript,
    ExecutionTimeout(u64),
    MemoryExceeded(usize),
    ParseError(String),
}

impl fmt::Display for JsEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyScript => write!(f, "empty script"),
            Self::ExecutionTimeout(ms) => write!(f, "execution timed out after {ms}ms"),
            Self::MemoryExceeded(bytes) => {
                write!(f, "memory limit exceeded: {bytes} bytes")
            }
            Self::ParseError(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

impl std::error::Error for JsEngineError {}

#[cfg(test)]
#[path = "js_engine_test.rs"]
mod js_engine_test;
