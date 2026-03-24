<!-- metadata: crate=aegis-crawler, purpose=BFS web crawler with optional headless Chrome browser backend for endpoint discovery, form extraction, API call interception, and DOM-based XSS verification, type=library, internal_deps=[aegis-protocol], external_deps=[url, regex, serde, chromiumoxide (feature=browser), tokio, futures] -->

# aegis-crawler

## Purpose

Performs BFS crawling of localhost web applications to discover endpoints, extract HTML forms, capture DOM event handlers, intercept XHR/fetch API calls, and optionally verify XSS payload execution in a real browser DOM. Enforces localhost-only scope with configurable URL regex filtering.

## Crate Type

Library

## Dependencies on Workspace Crates

- `aegis-protocol` — `ParameterLocation` (used in `DiscoveredParameter`)

## External Dependencies

- `url` — URL parsing, normalization, and form encoding
- `regex` — Scope regex compilation and matching
- `serde`, `serde_json` — `CrawlConfig` serialization, JS result deserialization
- `chromiumoxide` — Headless Chrome via CDP (feature-gated behind `browser` feature flag)
- `tokio` — async runtime, `time::timeout`, `spawn`
- `futures` — `StreamExt` for CDP event streams (browser feature only)

## Module Structure

| Module | Description |
|---|---|
| `types` | `CrawlConfig`, `CrawlResult`, `DiscoveredEndpoint`, `DiscoveredForm`, `FormInput`, `DomEventHandler`, `InterceptedApiCall`, `NormalizedUrl`, `DiscoverySource`, `ApiResourceType` |
| `error` | `CrawlError` — BrowserLaunch, Navigation, Timeout, Scope, Internal |
| `page_fetcher` | `PageContent` struct + `PageFetcher` trait (async, returns `PageContent`) |
| `crawler` | `Crawler` — BFS crawl engine; scope checking; endpoint/form/API call aggregation |
| `browser_fetcher` *(feature=browser)* | `BrowserFetcher` — `PageFetcher` backed by chromiumoxide; CDP Network interception for XHR/fetch; JS DOM extraction |
| `dom_verifier` *(feature=browser)* | `inject_xss_instrumentation`, `check_xss_markers`, `verify_xss_in_dom`, `DomVerificationResult`, `DomEvidence` |

## Public API Summary

### `types`

```rust
pub enum DiscoverySource { Link, Form, ScriptSrc, ApiCall, EventHandler }
pub enum ApiResourceType { Xhr, Fetch }

pub struct InterceptedApiCall { pub url: String, pub method: String,
                                 pub resource_type: ApiResourceType }

pub struct DiscoveredEndpoint { pub url: String, pub method: String,
                                 pub parameters: Vec<DiscoveredParameter>,
                                 pub source: DiscoverySource }

pub struct DiscoveredParameter { pub name: String, pub location: ParameterLocation,
                                  pub example_value: Option<String> }

pub struct DiscoveredForm { pub action: String, pub method: String,
                             pub inputs: Vec<FormInput> }

pub struct FormInput { pub name: String, pub input_type: String, pub value: Option<String> }

pub struct DomEventHandler { pub element_selector: String, pub event_name: String,
                              pub handler_snippet: String }

pub struct CrawlConfig {
    pub max_depth: u32,          // default: 3
    pub max_pages: u32,          // default: 100
    pub scope_regex: Option<String>,
    pub timeout_secs: u64,       // default: 30
    pub wait_after_load_ms: u64, // default: 1000 (time to wait after page load)
}
impl CrawlConfig {
    pub fn with_max_depth(self, max_depth: u32) -> Self
    pub fn with_max_pages(self, max_pages: u32) -> Self
    pub fn with_scope_regex(self, pattern: &str) -> Self
    pub fn with_timeout_secs(self, timeout_secs: u64) -> Self
    pub fn with_wait_after_load_ms(self, wait_ms: u64) -> Self
}

pub struct CrawlResult {
    pub discovered_endpoints: Vec<DiscoveredEndpoint>,
    pub discovered_forms: Vec<DiscoveredForm>,
    pub event_handlers: Vec<DomEventHandler>,
    pub script_sources: Vec<String>,
    pub pages_visited: u32,
    pub errors: Vec<String>,
}

/// URL normalized for dedup: fragment stripped, host lowercased, default port removed.
pub struct NormalizedUrl(String);
impl NormalizedUrl { pub fn as_str(&self) -> &str }
impl From<&str> for NormalizedUrl { ... }
// Implements PartialEq, Eq, Hash on the normalized string.
```

### `page_fetcher`

```rust
pub struct PageContent {
    pub final_url: String,
    pub links: Vec<String>,
    pub forms: Vec<DiscoveredForm>,
    pub event_handlers: Vec<DomEventHandler>,
    pub script_sources: Vec<String>,
    pub intercepted_api_calls: Vec<InterceptedApiCall>,
}

/// Abstracts page fetching. The browser implementation uses chromiumoxide.
/// Tests use mock implementations with pre-configured responses.
pub trait PageFetcher {
    fn fetch_page(&mut self, url: &str)
        -> impl Future<Output = Result<PageContent, CrawlError>> + Send;
}
```

### `crawler`

```rust
pub struct Crawler { /* private */ }

impl Crawler {
    pub fn new(config: CrawlConfig) -> Self
    /// Adds a URL to the BFS seed queue. Scope is NOT checked at seed time.
    pub fn add_seed(&mut self, url: &str)
    /// Returns true if the URL is localhost AND (if scope_regex set) path matches.
    pub fn is_in_scope(&self, url: &str) -> bool
    /// BFS crawl using the provided PageFetcher. Per-page errors are recorded, not propagated.
    /// Deduplicates endpoints by (url, method).
    pub async fn crawl<F: PageFetcher>(&mut self, fetcher: &mut F)
        -> Result<CrawlResult, CrawlError>
}
```

### `browser_fetcher` *(feature = "browser")*

```rust
/// PageFetcher backed by a headless Chrome instance via chromiumoxide/CDP.
/// Intercepts XHR/Fetch requests to localhost using the CDP Network domain.
pub struct BrowserFetcher {
    browser: Browser,
    config: CrawlConfig,
}
impl BrowserFetcher {
    pub fn new(browser: Browser, config: CrawlConfig) -> Self
}
// Implements PageFetcher: opens a new page per fetch, runs JS for links/forms/handlers/scripts.
```

### `dom_verifier` *(feature = "browser")*

```rust
pub enum DomEvidence {
    AlertFired,        // +0.3 confidence boost
    CookieAccess,      // +0.3
    NavigationAttempt, // +0.3
    DomMutation,       // +0.25
    FetchToExternal,   // +0.25
    NoExecution,       // -0.2
}

pub struct DomVerificationResult {
    pub payload: String, pub endpoint: String,
    pub dom_executed: bool, pub evidence: DomEvidence, pub confidence_boost: f64,
}

/// Injects window.__aegis_* marker overrides for alert, location, document.cookie, fetch.
pub async fn inject_xss_instrumentation(page: &chromiumoxide::Page) -> Result<(), CrawlError>

/// Reads __aegis_* markers + checks DOM for injected scripts/event handlers.
/// Priority: AlertFired > NavigationAttempt > CookieAccess > FetchToExternal > DomMutation > NoExecution.
pub async fn check_xss_markers(page: &chromiumoxide::Page) -> Result<DomEvidence, CrawlError>

/// Maps DomEvidence to confidence boost delta.
pub fn confidence_boost_for_evidence(evidence: &DomEvidence) -> f64

/// Builds URL with payload injected as q= query param (GET only; POST returns endpoint unchanged).
pub fn inject_payload_into_url(endpoint: &str, payload: &str, method: &str) -> String

/// Opens a new page, injects instrumentation + optional auth cookies, navigates to payload URL,
/// reads markers. Returns NoExecution on timeout rather than erroring.
pub async fn verify_xss_in_dom(browser: &Browser, endpoint: &str, method: &str,
    payload: &str, auth_cookies: Option<&[(String, String)]>, timeout_secs: u64)
    -> Result<DomVerificationResult, CrawlError>
```

### `error`

```rust
pub enum CrawlError {
    BrowserLaunch(String),
    Navigation(String),
    Timeout(String),
    Scope(String),
    Internal(String),
}
```

## Key Implementation Notes

- **Feature gate `browser`**: The `chromiumoxide`-dependent modules (`browser_fetcher`, `dom_verifier`) are compiled only when the `browser` feature is enabled. The default build (without headless Chrome) still provides the `Crawler` with `PageFetcher` trait and all type definitions, which can be used with a mock `PageFetcher` implementation (lib.rs:6-19).

- **`NormalizedUrl` removes fragment and default ports**: The normalization strips `#` fragments (deduplicate `page.html#section` with `page.html`), lowercases the host, and removes port 80 from `http://` and port 443 from `https://` URLs (types.rs:166-183). This prevents false duplicates in the visited set.

- **Scope enforcement in `is_in_scope` vs `add_seed`**: Seeds bypass scope checking — `add_seed` adds any URL to the queue. Scope is checked in `enqueue_links` for all discovered links (crawler.rs:106-115). This allows an out-of-scope seed to be crawled once, but discovered links from that page must be in-scope to be followed.

- **Per-page errors are recorded, not fatal**: The `crawl` loop pushes error strings to `result.errors` and continues to the next URL on any `PageFetcher::fetch_page` error (crawler.rs:95-98). This makes the crawler resilient to individual page failures.

- **CDP Network interception runs on a separate task**: `BrowserFetcher::fetch_page` spawns a `tokio::spawn` task that listens to `EventRequestWillBeSent` events. After navigation completes, `listener_handle.abort()` is called. If the task is still holding the `Arc<Mutex<Vec<InterceptedApiCall>>>`, `Arc::try_unwrap` will fail and fall back to `arc.lock().unwrap().clone()` (browser_fetcher.rs:116-119).

- **XSS instrumentation overrides browser APIs**: The `INSTRUMENTATION_JS` script overrides `window.alert`, `window.location` setter, `document.cookie` getter/setter, and `window.fetch`. These overrides set `window.__aegis_*` flags on invocation. The property descriptors are checked for `configurable: true` before overriding location to avoid exceptions on restricted origins (dom_verifier.rs:54-109).

- **DOM mutation check looks for injected scripts and event handler attributes**: `CHECK_DOM_MUTATION_JS` queries all `<script>` elements (excluding those containing `__aegis` — the instrumentation itself) and all elements with inline event handler attributes (`onclick`, `onerror`, `onload`, `onmouseover`, `onfocus`) (dom_verifier.rs:113-129).

- **Only 9 DOM event attributes are collected by the crawler**: `EXTRACT_EVENT_HANDLERS_JS` checks 9 attributes (`onclick`, `onsubmit`, `onchange`, `onload`, `onerror`, `onmouseover`, `onfocus`, `onblur`, `oninput`, `onkeyup`) (browser_fetcher.rs:158-169). This is a fixed set; new attribute types are not automatically discovered.

## Usage Context

Used by the orchestrator's crawl phase to populate the knowledge graph with discovered endpoints before fuzzing begins. When the `browser` feature is enabled (Tier 2 integration tests), `BrowserFetcher` replaces the plain HTTP page fetcher for SPA and JavaScript-heavy applications. `verify_xss_in_dom` is called from `phase_fuzz.rs` in the orchestrator's `dom_verify` pipeline step to confirm XSS findings with real browser execution before they are elevated to `EvidenceLevel::Confirmed`.
