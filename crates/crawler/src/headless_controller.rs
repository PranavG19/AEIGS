use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::error::CrawlError;
use crate::types::{DiscoveredEndpoint, DiscoveredForm, DiscoverySource, FormInput};

/// Browser fingerprint configuration sourced from evasion-engine identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserFingerprint {
    pub user_agent: String,
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub language: String,
    pub platform: String,
    pub timezone: String,
    pub webgl_vendor: Option<String>,
    pub webgl_renderer: Option<String>,
}

impl Default for BrowserFingerprint {
    fn default() -> Self {
        Self {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            viewport_width: 1920,
            viewport_height: 1080,
            language: "en-US".to_string(),
            platform: "Win32".to_string(),
            timezone: "America/New_York".to_string(),
            webgl_vendor: None,
            webgl_renderer: None,
        }
    }
}

/// Captured network request from XHR/fetch monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedNetworkRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub resource_type: NetworkResourceType,
}

/// Type of network resource intercepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkResourceType {
    Xhr,
    Fetch,
    Document,
    Script,
    Stylesheet,
    Image,
    Font,
    WebSocket,
    Other,
}

/// Extracted storage contents from a page.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageSnapshot {
    pub cookies: Vec<CookieEntry>,
    pub local_storage: HashMap<String, String>,
    pub session_storage: HashMap<String, String>,
}

/// A single cookie extracted from the browser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieEntry {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub expires: Option<u64>,
}

/// Result of a page navigation including DOM, network, and storage data.
#[derive(Debug, Clone, Default)]
pub struct PageCapture {
    pub url: String,
    pub dom_html: String,
    pub title: String,
    pub network_requests: Vec<CapturedNetworkRequest>,
    pub storage: StorageSnapshot,
    pub console_messages: Vec<String>,
    pub discovered_forms: Vec<DiscoveredForm>,
    pub discovered_endpoints: Vec<DiscoveredEndpoint>,
    pub screenshot_png: Option<Vec<u8>>,
}

/// Configuration for a headless browser instance.
#[derive(Debug, Clone)]
pub struct HeadlessConfig {
    pub fingerprint: BrowserFingerprint,
    pub headless: bool,
    pub navigation_timeout: Duration,
    pub wait_after_load: Duration,
    pub capture_network: bool,
    pub capture_screenshots: bool,
    pub max_concurrent_pages: usize,
}

impl Default for HeadlessConfig {
    fn default() -> Self {
        Self {
            fingerprint: BrowserFingerprint::default(),
            headless: true,
            navigation_timeout: Duration::from_secs(30),
            wait_after_load: Duration::from_millis(1000),
            capture_network: true,
            capture_screenshots: false,
            max_concurrent_pages: 4,
        }
    }
}

impl HeadlessConfig {
    pub fn with_fingerprint(mut self, fp: BrowserFingerprint) -> Self {
        self.fingerprint = fp;
        self
    }

    pub fn with_headless(mut self, headless: bool) -> Self {
        self.headless = headless;
        self
    }

    pub fn with_navigation_timeout(mut self, timeout: Duration) -> Self {
        self.navigation_timeout = timeout;
        self
    }

    pub fn with_wait_after_load(mut self, wait: Duration) -> Self {
        self.wait_after_load = wait;
        self
    }

    pub fn with_capture_network(mut self, capture: bool) -> Self {
        self.capture_network = capture;
        self
    }

    pub fn with_capture_screenshots(mut self, capture: bool) -> Self {
        self.capture_screenshots = capture;
        self
    }

    pub fn with_max_concurrent_pages(mut self, max: usize) -> Self {
        self.max_concurrent_pages = max;
        self
    }
}

/// Trait abstracting headless browser operations for testability.
///
/// Implementations wrap real browser automation (Chrome DevTools Protocol)
/// or provide mock behavior for unit tests. All navigation enforces
/// localhost-only targeting consistent with the crawler safety model.
#[allow(async_fn_in_trait)]
pub trait BrowserBackend: Send + Sync {
    async fn navigate(&self, url: &str) -> Result<PageCapture, CrawlError>;
    async fn execute_js(&self, script: &str) -> Result<String, CrawlError>;
    async fn click_element(&self, selector: &str) -> Result<(), CrawlError>;
    async fn fill_field(&self, selector: &str, value: &str) -> Result<(), CrawlError>;
    async fn submit_form(&self, selector: &str) -> Result<(), CrawlError>;
    async fn take_screenshot(&self) -> Result<Vec<u8>, CrawlError>;
    async fn get_storage(&self) -> Result<StorageSnapshot, CrawlError>;
    async fn close(&self) -> Result<(), CrawlError>;
}

/// Headless browser controller that manages browser instances and provides
/// high-level operations for crawling, form interaction, and evidence capture.
///
/// Wraps a `BrowserBackend` implementation and adds URL validation, network
/// request collection, and multi-page coordination. Each controller manages
/// a pool of browser pages up to `config.max_concurrent_pages`.
pub struct HeadlessController<B: BrowserBackend> {
    config: HeadlessConfig,
    backend: Arc<B>,
    captured_requests: Arc<Mutex<Vec<CapturedNetworkRequest>>>,
    page_count: Arc<Mutex<usize>>,
}

impl<B: BrowserBackend> HeadlessController<B> {
    pub fn new(config: HeadlessConfig, backend: B) -> Self {
        Self {
            config,
            backend: Arc::new(backend),
            captured_requests: Arc::new(Mutex::new(Vec::new())),
            page_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Navigate to a URL, wait for JS execution, and capture the full page state.
    ///
    /// Validates that the target is localhost before proceeding. Captures DOM,
    /// network requests, forms, and optionally takes a screenshot.
    pub async fn navigate_and_capture(&self, url: &str) -> Result<PageCapture, CrawlError> {
        if !is_allowed_target(url) {
            return Err(CrawlError::Scope(format!(
                "target must be localhost, got: {url}"
            )));
        }

        let capture = self.backend.navigate(url).await?;

        if self.config.capture_network {
            let mut requests = self.captured_requests.lock().await;
            requests.extend(capture.network_requests.clone());
        }

        Ok(capture)
    }

    /// Fill a form field and optionally submit.
    pub async fn fill_and_submit(
        &self,
        fields: &[(&str, &str)],
        submit_selector: Option<&str>,
    ) -> Result<(), CrawlError> {
        for (selector, value) in fields {
            self.backend.fill_field(selector, value).await?;
        }
        if let Some(submit) = submit_selector {
            self.backend.submit_form(submit).await?;
        }
        Ok(())
    }

    /// Click a button or interactive element by CSS selector.
    pub async fn click(&self, selector: &str) -> Result<(), CrawlError> {
        self.backend.click_element(selector).await
    }

    /// Execute arbitrary JavaScript and return the result.
    pub async fn execute_javascript(&self, script: &str) -> Result<String, CrawlError> {
        self.backend.execute_js(script).await
    }

    /// Take a screenshot for evidence collection.
    pub async fn screenshot(&self) -> Result<Vec<u8>, CrawlError> {
        self.backend.take_screenshot().await
    }

    /// Extract cookies, localStorage, and sessionStorage.
    pub async fn extract_storage(&self) -> Result<StorageSnapshot, CrawlError> {
        self.backend.get_storage().await
    }

    /// Get all captured network requests since the controller was created.
    pub async fn captured_network_requests(&self) -> Vec<CapturedNetworkRequest> {
        self.captured_requests.lock().await.clone()
    }

    /// Check whether another page can be opened within the concurrency limit.
    pub async fn can_open_page(&self) -> bool {
        let count = self.page_count.lock().await;
        *count < self.config.max_concurrent_pages
    }

    /// Register that a new page has been opened.
    pub async fn register_page_open(&self) {
        let mut count = self.page_count.lock().await;
        *count += 1;
    }

    /// Register that a page has been closed.
    pub async fn register_page_close(&self) {
        let mut count = self.page_count.lock().await;
        *count = count.saturating_sub(1);
    }

    /// Shut down all browser instances.
    pub async fn shutdown(&self) -> Result<(), CrawlError> {
        self.backend.close().await
    }

    /// Access the underlying configuration.
    pub fn config(&self) -> &HeadlessConfig {
        &self.config
    }
}

/// Validate that a URL targets localhost only.
fn is_allowed_target(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let lower = host.to_ascii_lowercase();
    matches!(lower.as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Extract forms from raw HTML for headless capture results.
pub fn extract_forms_from_html(html: &str, base_url: &str) -> Vec<DiscoveredForm> {
    let mut forms = Vec::new();
    let form_re = regex::Regex::new(r"(?is)<form([^>]*)>(.*?)</form>").unwrap();
    let action_re = regex::Regex::new(r#"(?i)action\s*=\s*["']([^"']*)["']"#).unwrap();
    let method_re = regex::Regex::new(r#"(?i)method\s*=\s*["']([^"']*)["']"#).unwrap();
    let input_re =
        regex::Regex::new(r#"(?i)<input([^>]*)>"#).unwrap();
    let name_re = regex::Regex::new(r#"(?i)name\s*=\s*["']([^"']*)["']"#).unwrap();
    let type_re = regex::Regex::new(r#"(?i)type\s*=\s*["']([^"']*)["']"#).unwrap();
    let value_re = regex::Regex::new(r#"(?i)value\s*=\s*["']([^"']*)["']"#).unwrap();

    for form_match in form_re.captures_iter(html) {
        let attrs = &form_match[1];
        let body = &form_match[2];

        let action = action_re
            .captures(attrs)
            .map(|c| c[1].to_string())
            .unwrap_or_else(|| base_url.to_string());

        let method = method_re
            .captures(attrs)
            .map(|c| c[1].to_uppercase())
            .unwrap_or_else(|| "GET".to_string());

        let mut inputs = Vec::new();
        for input_match in input_re.captures_iter(body) {
            let input_attrs = &input_match[1];
            let name = name_re
                .captures(input_attrs)
                .map(|c| c[1].to_string())
                .unwrap_or_default();
            let input_type = type_re
                .captures(input_attrs)
                .map(|c| c[1].to_string())
                .unwrap_or_else(|| "text".to_string());
            let value = value_re.captures(input_attrs).map(|c| c[1].to_string());

            if !name.is_empty() {
                inputs.push(FormInput {
                    name,
                    input_type,
                    value,
                });
            }
        }

        forms.push(DiscoveredForm {
            action,
            method,
            inputs,
        });
    }

    forms
}

/// Extract endpoint URLs from captured network requests.
pub fn network_requests_to_endpoints(
    requests: &[CapturedNetworkRequest],
) -> Vec<DiscoveredEndpoint> {
    requests
        .iter()
        .filter(|r| {
            matches!(
                r.resource_type,
                NetworkResourceType::Xhr | NetworkResourceType::Fetch
            )
        })
        .map(|r| DiscoveredEndpoint {
            url: r.url.clone(),
            method: r.method.clone(),
            parameters: Vec::new(),
            source: DiscoverySource::ApiCall,
        })
        .collect()
}

#[cfg(test)]
#[path = "headless_controller_test.rs"]
mod headless_controller_test;
