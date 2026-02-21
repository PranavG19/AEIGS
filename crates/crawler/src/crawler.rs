use std::collections::{HashSet, VecDeque};

use regex::Regex;

use crate::error::CrawlError;
use crate::types::{CrawlConfig, CrawlResult, NormalizedUrl};

/// Headless browser crawler for localhost-only target discovery.
///
/// Performs BFS crawling starting from seed URLs, extracting endpoints, forms,
/// event handlers, and script sources from visited pages. Enforces localhost-only
/// targeting to prevent accidental remote scanning.
pub struct Crawler {
    #[allow(dead_code)]
    pub(crate) config: CrawlConfig,
    #[allow(dead_code)]
    pub(crate) visited: HashSet<NormalizedUrl>,
    pub(crate) queue: VecDeque<(NormalizedUrl, u32)>,
    scope_regex: Option<Regex>,
}

impl Crawler {
    pub fn new(config: CrawlConfig) -> Self {
        let scope_regex = config
            .scope_regex
            .as_ref()
            .and_then(|pat| Regex::new(pat).ok());
        Self {
            config,
            visited: HashSet::new(),
            queue: VecDeque::new(),
            scope_regex,
        }
    }

    pub fn add_seed(&mut self, url: &str) {
        let normalized = NormalizedUrl::from(url);
        self.queue.push_back((normalized, 0));
    }

    /// Checks whether a URL is within the allowed crawl scope.
    ///
    /// A URL is in scope only if its host is localhost (localhost, 127.0.0.1, or [::1])
    /// and, when a scope regex is configured, the URL's path matches the pattern.
    pub fn is_in_scope(&self, url: &str) -> bool {
        if !is_localhost_url(url) {
            return false;
        }

        if let Some(ref regex) = self.scope_regex {
            let path = extract_path(url);
            return regex.is_match(path);
        }

        true
    }

    /// Crawl all seeded URLs via BFS, extracting discovered endpoints and forms.
    ///
    /// Currently a stub that returns an empty result. Browser-based crawling
    /// will be implemented when the headless browser dependency is added.
    pub async fn crawl(&mut self) -> Result<CrawlResult, CrawlError> {
        Ok(CrawlResult::default())
    }
}

fn is_localhost_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let lower = host.to_ascii_lowercase();
    matches!(lower.as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn extract_path(url: &str) -> &str {
    if url::Url::parse(url).is_err() {
        return url;
    }
    let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
    let after_scheme = &url[scheme_end..];
    after_scheme
        .find('/')
        .map(|i| &after_scheme[i..])
        .unwrap_or("/")
}

#[cfg(test)]
#[path = "crawler_test.rs"]
mod crawler_test;
