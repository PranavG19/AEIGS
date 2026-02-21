use std::fmt;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

use aegis_protocol::request::ParameterLocation;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DiscoverySource {
    Link,
    Form,
    ScriptSrc,
    ApiCall,
    EventHandler,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub method: String,
    pub parameters: Vec<DiscoveredParameter>,
    pub source: DiscoverySource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredParameter {
    pub name: String,
    pub location: ParameterLocation,
    pub example_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredForm {
    pub action: String,
    pub method: String,
    pub inputs: Vec<FormInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormInput {
    pub name: String,
    pub input_type: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomEventHandler {
    pub element_selector: String,
    pub event_name: String,
    pub handler_snippet: String,
}

/// Configuration for a crawl session.
///
/// Controls depth limits, page count, URL scope, and timing behavior.
/// Use `with_*` builder methods to customize, or `Default` for sensible defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlConfig {
    pub max_depth: u32,
    pub max_pages: u32,
    pub scope_regex: Option<String>,
    pub timeout_secs: u64,
    pub wait_after_load_ms: u64,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_pages: 100,
            scope_regex: None,
            timeout_secs: 30,
            wait_after_load_ms: 1000,
        }
    }
}

impl CrawlConfig {
    pub fn with_max_depth(mut self, max_depth: u32) -> Self {
        self.max_depth = max_depth;
        self
    }

    pub fn with_max_pages(mut self, max_pages: u32) -> Self {
        self.max_pages = max_pages;
        self
    }

    pub fn with_scope_regex(mut self, pattern: &str) -> Self {
        self.scope_regex = Some(pattern.to_string());
        self
    }

    pub fn with_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    pub fn with_wait_after_load_ms(mut self, wait_ms: u64) -> Self {
        self.wait_after_load_ms = wait_ms;
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct CrawlResult {
    pub discovered_endpoints: Vec<DiscoveredEndpoint>,
    pub discovered_forms: Vec<DiscoveredForm>,
    pub event_handlers: Vec<DomEventHandler>,
    pub script_sources: Vec<String>,
    pub pages_visited: u32,
    pub errors: Vec<String>,
}

/// A URL normalized for deduplication: fragment stripped, host lowercased, default port removed.
#[derive(Debug, Clone)]
pub struct NormalizedUrl(String);

impl NormalizedUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for NormalizedUrl {
    fn from(raw: &str) -> Self {
        Self(normalize_url(raw))
    }
}

impl fmt::Display for NormalizedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq for NormalizedUrl {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for NormalizedUrl {}

impl Hash for NormalizedUrl {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

fn normalize_url(raw: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(raw) else {
        return raw.to_string();
    };

    parsed.set_fragment(None);

    if let Some(host) = parsed.host_str() {
        let lowered = host.to_ascii_lowercase();
        let _ = parsed.set_host(Some(&lowered));
    }

    if is_default_port_for_scheme(parsed.scheme(), parsed.port()) {
        let _ = parsed.set_port(None);
    }

    parsed.to_string()
}

fn is_default_port_for_scheme(scheme: &str, port: Option<u16>) -> bool {
    matches!((scheme, port), ("http", Some(80)) | ("https", Some(443)))
}

#[cfg(test)]
#[path = "types_test.rs"]
mod types_test;
