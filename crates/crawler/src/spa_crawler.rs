use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::types::{DiscoveredEndpoint, DiscoveredForm, DiscoverySource};

/// SPA framework detected on a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SpaFramework {
    React,
    Angular,
    Vue,
    Svelte,
    NextJs,
    Nuxt,
    Ember,
    Unknown,
}

impl SpaFramework {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::React => "React",
            Self::Angular => "Angular",
            Self::Vue => "Vue",
            Self::Svelte => "Svelte",
            Self::NextJs => "Next.js",
            Self::Nuxt => "Nuxt",
            Self::Ember => "Ember",
            Self::Unknown => "Unknown",
        }
    }
}

/// A DOM mutation observed during SPA interaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomMutation {
    pub mutation_type: DomMutationType,
    pub target_selector: String,
    pub added_nodes: u32,
    pub removed_nodes: u32,
    pub new_links: Vec<String>,
    pub new_forms: Vec<DiscoveredForm>,
}

/// Type of DOM mutation observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomMutationType {
    ChildList,
    Attributes,
    CharacterData,
}

/// Interactive element found on the page that can be clicked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractiveElement {
    pub selector: String,
    pub tag: String,
    pub text: String,
    pub element_type: InteractiveElementType,
}

/// Classification of interactive elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InteractiveElementType {
    Link,
    Button,
    Tab,
    NavItem,
    Dropdown,
    Modal,
    Accordion,
    Other,
}

/// API endpoint extracted from JavaScript source code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsApiEndpoint {
    pub url: String,
    pub method: String,
    pub source_file: Option<String>,
    pub call_type: JsCallType,
}

/// Type of API call found in JS source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JsCallType {
    Fetch,
    Axios,
    Xhr,
    SuperAgent,
    Got,
    Ky,
    Other,
}

/// Pagination pattern detected on a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PaginationPattern {
    InfiniteScroll,
    LoadMore,
    NumberedPages,
    CursorBased,
    #[default]
    None,
}

/// Configuration for SPA crawling behavior.
#[derive(Debug, Clone)]
pub struct SpaCrawlConfig {
    pub max_interactions: u32,
    pub max_scroll_attempts: u32,
    pub mutation_wait_ms: u64,
    pub click_delay_ms: u64,
    pub discover_api_endpoints: bool,
    pub follow_client_routes: bool,
}

impl Default for SpaCrawlConfig {
    fn default() -> Self {
        Self {
            max_interactions: 100,
            max_scroll_attempts: 10,
            mutation_wait_ms: 500,
            click_delay_ms: 200,
            discover_api_endpoints: true,
            follow_client_routes: true,
        }
    }
}

impl SpaCrawlConfig {
    pub fn with_max_interactions(mut self, max: u32) -> Self {
        self.max_interactions = max;
        self
    }

    pub fn with_max_scroll_attempts(mut self, max: u32) -> Self {
        self.max_scroll_attempts = max;
        self
    }

    pub fn with_mutation_wait_ms(mut self, ms: u64) -> Self {
        self.mutation_wait_ms = ms;
        self
    }

    pub fn with_click_delay_ms(mut self, ms: u64) -> Self {
        self.click_delay_ms = ms;
        self
    }
}

/// Result of crawling a single-page application.
#[derive(Debug, Clone, Default)]
pub struct SpaCrawlResult {
    pub detected_framework: Option<SpaFramework>,
    pub client_routes: Vec<String>,
    pub api_endpoints: Vec<JsApiEndpoint>,
    pub discovered_endpoints: Vec<DiscoveredEndpoint>,
    pub discovered_forms: Vec<DiscoveredForm>,
    pub mutations_observed: Vec<DomMutation>,
    pub interactive_elements: Vec<InteractiveElement>,
    pub pagination_pattern: PaginationPattern,
    pub pages_loaded: u32,
    pub interactions_performed: u32,
}

/// Detect which SPA framework is present based on DOM markers and global variables.
///
/// Checks for framework-specific root elements, global objects, and meta tags
/// that identify React, Angular, Vue, Svelte, Next.js, Nuxt, or Ember.
pub fn detect_spa_framework(html: &str) -> Option<SpaFramework> {
    let checks: &[(&[&str], SpaFramework)] = &[
        (&["__NEXT_DATA__", "_next/"], SpaFramework::NextJs),
        (&["__NUXT__", "_nuxt/"], SpaFramework::Nuxt),
        (
            &[
                "data-reactroot",
                "_reactRootContainer",
                "react-root",
                "__REACT_DEVTOOLS",
            ],
            SpaFramework::React,
        ),
        (
            &["ng-version", "ng-app", "ng-controller", "angular"],
            SpaFramework::Angular,
        ),
        (
            &["data-v-", "__vue__", "Vue.js", "data-vue-"],
            SpaFramework::Vue,
        ),
        (&["__svelte", "svelte-"], SpaFramework::Svelte),
        (&["data-ember-", "ember-application"], SpaFramework::Ember),
    ];

    for (markers, framework) in checks {
        if markers.iter().any(|m| html.contains(m)) {
            return Some(*framework);
        }
    }
    None
}

/// Extract client-side routes from HTML/JS by looking for route definitions.
///
/// Parses common routing patterns from React Router, Vue Router, Angular Router,
/// and hash-based routing to discover navigable paths in the SPA.
pub fn extract_client_routes(html: &str) -> Vec<String> {
    let mut routes = HashSet::new();

    let path_re = regex::Regex::new(r#"(?:path|route)\s*[:=]\s*["'](/[^"']*?)["']"#).unwrap();
    for cap in path_re.captures_iter(html) {
        routes.insert(cap[1].to_string());
    }

    let hash_re = regex::Regex::new(r#"#(/[a-zA-Z0-9/_-]+)"#).unwrap();
    for cap in hash_re.captures_iter(html) {
        routes.insert(cap[1].to_string());
    }

    let link_re = regex::Regex::new(r#"(?:to|href)\s*=\s*["'](/[a-zA-Z0-9/_-]+)["']"#).unwrap();
    for cap in link_re.captures_iter(html) {
        routes.insert(cap[1].to_string());
    }

    let mut sorted: Vec<String> = routes.into_iter().collect();
    sorted.sort();
    sorted
}

/// Extract API endpoint calls from JavaScript source code.
///
/// Finds fetch(), axios, XMLHttpRequest, and other HTTP client calls to
/// discover backend API endpoints that the SPA communicates with.
pub fn extract_api_endpoints_from_js(js_source: &str) -> Vec<JsApiEndpoint> {
    let mut endpoints = Vec::new();
    let mut seen = HashSet::new();

    let patterns: &[(&str, JsCallType, &str)] = &[
        (
            r#"fetch\s*\(\s*["'`]([^"'`]+)["'`]"#,
            JsCallType::Fetch,
            "GET",
        ),
        (
            r#"axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]"#,
            JsCallType::Axios,
            "",
        ),
        (
            r#"axios\s*\(\s*\{[^}]*url\s*:\s*["'`]([^"'`]+)["'`]"#,
            JsCallType::Axios,
            "GET",
        ),
        (
            r#"\.open\s*\(\s*["'](\w+)["']\s*,\s*["']([^"']+)["']"#,
            JsCallType::Xhr,
            "",
        ),
    ];

    for (pattern, call_type, default_method) in patterns {
        let re = regex::Regex::new(pattern).unwrap();
        for cap in re.captures_iter(js_source) {
            let (url, method) = match *call_type {
                JsCallType::Axios if default_method.is_empty() => {
                    (cap[2].to_string(), cap[1].to_uppercase())
                }
                JsCallType::Xhr => (cap[2].to_string(), cap[1].to_uppercase()),
                _ => (cap[1].to_string(), default_method.to_string()),
            };

            if seen.insert((url.clone(), method.clone())) {
                endpoints.push(JsApiEndpoint {
                    url,
                    method,
                    source_file: None,
                    call_type: *call_type,
                });
            }
        }
    }

    endpoints
}

/// Classify interactive elements found in HTML for automated clicking.
pub fn classify_interactive_elements(html: &str) -> Vec<InteractiveElement> {
    let mut elements = Vec::new();

    let button_re = regex::Regex::new(r#"(?is)<button([^>]*)>(.*?)</button>"#).unwrap();
    for cap in button_re.captures_iter(html) {
        let text = strip_html_tags(&cap[2]).trim().to_string();
        if !text.is_empty() {
            elements.push(InteractiveElement {
                selector: extract_selector_from_attrs(&cap[1], "button"),
                tag: "button".to_string(),
                text,
                element_type: InteractiveElementType::Button,
            });
        }
    }

    let anchor_re =
        regex::Regex::new(r#"(?is)<a\s([^>]*(?:role\s*=\s*["'](?:button|tab)["']|@click|v-on:click|onclick)[^>]*)>(.*?)</a>"#).unwrap();
    for cap in anchor_re.captures_iter(html) {
        let text = strip_html_tags(&cap[2]).trim().to_string();
        let attrs = &cap[1];
        let element_type = if attrs.contains("role=\"tab\"") || attrs.contains("role='tab'") {
            InteractiveElementType::Tab
        } else {
            InteractiveElementType::NavItem
        };
        if !text.is_empty() {
            elements.push(InteractiveElement {
                selector: extract_selector_from_attrs(attrs, "a"),
                tag: "a".to_string(),
                text,
                element_type,
            });
        }
    }

    elements
}

/// Detect pagination patterns from HTML structure.
pub fn detect_pagination(html: &str) -> PaginationPattern {
    let lower = html.to_lowercase();

    if lower.contains("infinite-scroll")
        || lower.contains("infinitescroll")
        || lower.contains("data-infinite")
    {
        return PaginationPattern::InfiniteScroll;
    }

    if lower.contains("load-more") || lower.contains("loadmore") || lower.contains("load more") {
        return PaginationPattern::LoadMore;
    }

    let page_re = regex::Regex::new(r#"[?&]page=\d+"#).unwrap();
    let cursor_re = regex::Regex::new(r#"[?&](?:cursor|after|before)="#).unwrap();

    if cursor_re.is_match(html) {
        return PaginationPattern::CursorBased;
    }

    if page_re.is_match(html) {
        return PaginationPattern::NumberedPages;
    }

    PaginationPattern::None
}

/// Crawl a single-page application by analyzing its HTML and JS sources.
///
/// Performs framework detection, route extraction, API endpoint discovery,
/// interactive element classification, and pagination detection all from
/// the provided HTML and JavaScript sources.
pub fn crawl_spa(
    html: &str,
    js_sources: &[&str],
    base_url: &str,
    _config: &SpaCrawlConfig,
) -> SpaCrawlResult {
    let detected_framework = detect_spa_framework(html);
    let client_routes = extract_client_routes(html);

    let mut api_endpoints = Vec::new();
    for js in js_sources {
        api_endpoints.extend(extract_api_endpoints_from_js(js));
    }
    api_endpoints.extend(extract_api_endpoints_from_js(html));

    let discovered_endpoints: Vec<DiscoveredEndpoint> = api_endpoints
        .iter()
        .map(|ep| DiscoveredEndpoint {
            url: resolve_url(base_url, &ep.url),
            method: ep.method.clone(),
            parameters: Vec::new(),
            source: DiscoverySource::ApiCall,
        })
        .collect();

    let interactive_elements = classify_interactive_elements(html);
    let pagination_pattern = detect_pagination(html);
    let discovered_forms = crate::headless_controller::extract_forms_from_html(html, base_url);

    SpaCrawlResult {
        detected_framework,
        client_routes,
        api_endpoints,
        discovered_endpoints,
        discovered_forms,
        mutations_observed: Vec::new(),
        interactive_elements,
        pagination_pattern,
        pages_loaded: 1,
        interactions_performed: 0,
    }
}

fn resolve_url(base: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    if path.starts_with('/')
        && let Ok(parsed) = url::Url::parse(base)
    {
        let port_str = parsed.port().map(|p| format!(":{}", p)).unwrap_or_default();
        return format!(
            "{}://{}{}{}",
            parsed.scheme(),
            parsed.host_str().unwrap_or("localhost"),
            port_str,
            path
        );
    }
    let base_trimmed = base.trim_end_matches('/');
    format!("{}/{}", base_trimmed, path.trim_start_matches('/'))
}

fn strip_html_tags(input: &str) -> String {
    let re = regex::Regex::new(r"<[^>]+>").unwrap();
    re.replace_all(input, "").to_string()
}

fn extract_selector_from_attrs(attrs: &str, tag: &str) -> String {
    let id_re = regex::Regex::new(r#"id\s*=\s*["']([^"']+)["']"#).unwrap();
    if let Some(cap) = id_re.captures(attrs) {
        return format!("#{}", &cap[1]);
    }

    let class_re = regex::Regex::new(r#"class\s*=\s*["']([^"']+)["']"#).unwrap();
    if let Some(cap) = class_re.captures(attrs) {
        let first_class = cap[1].split_whitespace().next().unwrap_or("");
        if !first_class.is_empty() {
            return format!("{}.{}", tag, first_class);
        }
    }

    tag.to_string()
}

#[cfg(test)]
#[path = "spa_crawler_test.rs"]
mod spa_crawler_test;
