use crate::error::CrawlError;
use crate::types::{DiscoveredForm, DomEventHandler, InterceptedApiCall};

/// Content extracted from a single page visit.
///
/// Contains all discoverable information from a rendered page: links, forms,
/// event handlers, script sources, and intercepted API calls. The `final_url`
/// reflects any redirects that occurred during navigation.
#[derive(Debug, Clone, Default)]
pub struct PageContent {
    pub final_url: String,
    pub links: Vec<String>,
    pub forms: Vec<DiscoveredForm>,
    pub event_handlers: Vec<DomEventHandler>,
    pub script_sources: Vec<String>,
    pub intercepted_api_calls: Vec<InterceptedApiCall>,
}

/// Abstracts page fetching for testability.
///
/// The real implementation wraps a headless browser (chromiumoxide).
/// Tests use a mock implementation for deterministic BFS testing.
pub trait PageFetcher {
    fn fetch_page(
        &mut self,
        url: &str,
    ) -> impl std::future::Future<Output = Result<PageContent, CrawlError>> + Send;
}

#[cfg(test)]
#[path = "page_fetcher_test.rs"]
mod page_fetcher_test;
