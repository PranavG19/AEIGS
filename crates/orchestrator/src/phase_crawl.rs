use aegis_crawler::{CrawlConfig, CrawlError, CrawlResult, Crawler, PageContent, PageFetcher};
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

/// Converts crawl-discovered endpoints into knowledge graph operations.
///
/// Each `DiscoveredEndpoint` becomes an `AddNode` with `NodeType::Endpoint`
/// and properties for path, method, and discovery source.
pub fn crawl_result_to_operations(result: &CrawlResult, seq: &mut u64) -> Vec<OperationLogEntry> {
    result
        .discovered_endpoints
        .iter()
        .map(|ep| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::Enumeration,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: crawl_endpoint_properties(ep),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

fn crawl_endpoint_properties(
    endpoint: &aegis_crawler::DiscoveredEndpoint,
) -> Vec<(String, String)> {
    vec![
        ("path".to_string(), endpoint.url.clone()),
        ("method".to_string(), endpoint.method.clone()),
        (
            "discovery_source".to_string(),
            format!("{:?}", endpoint.source),
        ),
    ]
}

/// HTTP-based `PageFetcher` for basic link extraction without a headless browser.
pub(crate) struct HttpPageFetcher {
    client: reqwest::Client,
}

impl HttpPageFetcher {
    pub(crate) fn new(timeout_secs: u64) -> Result<Self, CrawlError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| CrawlError::Internal(format!("failed to build HTTP client: {e}")))?;
        Ok(Self { client })
    }
}

impl PageFetcher for HttpPageFetcher {
    async fn fetch_page(&mut self, url: &str) -> Result<PageContent, CrawlError> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| CrawlError::Navigation(format!("GET {url} failed: {e}")))?;
        let final_url = response.url().to_string();
        let body = response
            .text()
            .await
            .map_err(|e| CrawlError::Navigation(format!("failed to read body: {e}")))?;
        let links = extract_href_links(&body, url);
        Ok(PageContent {
            final_url,
            links,
            forms: Vec::new(),
            event_handlers: Vec::new(),
            script_sources: Vec::new(),
            intercepted_api_calls: Vec::new(),
        })
    }
}

/// Extracts `href` attribute values from `<a>` tags via simple string scanning.
pub(crate) fn extract_href_links(html: &str, base_url: &str) -> Vec<String> {
    let mut links = Vec::new();
    let needle = "href=\"";
    let mut pos = 0;
    while let Some(start) = html[pos..].find(needle) {
        let value_start = pos + start + needle.len();
        if let Some(end) = html[value_start..].find('"') {
            let href = &html[value_start..value_start + end];
            if let Some(resolved) = resolve_url(href, base_url) {
                links.push(resolved);
            }
        }
        pos = value_start;
    }
    links
}

/// Resolves a potentially relative URL against a base URL.
pub(crate) fn resolve_url(href: &str, base_url: &str) -> Option<String> {
    let absolute = if href.starts_with("http://") || href.starts_with("https://") {
        href.to_string()
    } else if href.starts_with('/') {
        let base = url::Url::parse(base_url).ok()?;
        base.join(href).ok()?.to_string()
    } else {
        return None;
    };
    let parsed = url::Url::parse(&absolute).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    if matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]") {
        Some(absolute)
    } else {
        None
    }
}

/// Runs the HTTP crawl phase, returning discovered endpoints.
pub(crate) async fn run_crawl(target: &str) -> CrawlResult {
    let config = CrawlConfig::default()
        .with_max_depth(3)
        .with_max_pages(50)
        .with_timeout_secs(10);
    let mut fetcher = match HttpPageFetcher::new(config.timeout_secs) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "crawl skipped: failed to create HTTP fetcher");
            return CrawlResult::default();
        }
    };
    let mut crawler = Crawler::new(config);
    crawler.add_seed(target);
    match crawler.crawl(&mut fetcher).await {
        Ok(result) => {
            tracing::info!(
                pages = result.pages_visited,
                endpoints = result.discovered_endpoints.len(),
                errors = result.errors.len(),
                "crawl completed"
            );
            result
        }
        Err(e) => {
            tracing::warn!(error = %e, "crawl failed, continuing with empty results");
            CrawlResult::default()
        }
    }
}
