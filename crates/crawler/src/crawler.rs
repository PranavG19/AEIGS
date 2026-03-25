use std::collections::{HashSet, VecDeque};

use regex::Regex;

use crate::error::CrawlError;
use crate::page_fetcher::PageFetcher;
use crate::types::{
    CrawlConfig, CrawlResult, DiscoveredEndpoint, DiscoveredForm, DiscoveredParameter,
    DiscoverySource, InterceptedApiCall, NormalizedUrl,
};

/// Headless browser crawler for localhost-only target discovery.
///
/// Performs BFS crawling starting from seed URLs, extracting endpoints, forms,
/// event handlers, and script sources from visited pages. Enforces localhost-only
/// targeting to prevent accidental remote scanning.
pub struct Crawler {
    pub(crate) config: CrawlConfig,
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
    /// Visits pages breadth-first up to `config.max_depth` and `config.max_pages`.
    /// Errors on individual pages are recorded but do not abort the crawl.
    pub async fn crawl<F: PageFetcher>(
        &mut self,
        fetcher: &mut F,
    ) -> Result<CrawlResult, CrawlError> {
        let mut result = CrawlResult::default();
        let mut all_endpoints: Vec<DiscoveredEndpoint> = Vec::new();

        while let Some((url, depth)) = self.queue.pop_front() {
            if result.pages_visited >= self.config.max_pages {
                break;
            }
            if self.visited.contains(&url) {
                continue;
            }
            if depth > self.config.max_depth {
                continue;
            }

            self.visited.insert(url.clone());

            match fetcher.fetch_page(url.as_str()).await {
                Ok(content) => {
                    result.pages_visited += 1;
                    self.enqueue_links(&content.links, depth);
                    all_endpoints.extend(links_to_endpoints(&content.links));
                    all_endpoints.extend(forms_to_endpoints(&content.forms));
                    all_endpoints.extend(api_calls_to_endpoints(&content.intercepted_api_calls));
                    result.discovered_forms.extend(content.forms);
                    result.event_handlers.extend(content.event_handlers);
                    result.script_sources.extend(content.script_sources);
                }
                Err(err) => {
                    result.errors.push(err.to_string());
                }
            }
        }

        dedup_endpoints(&mut all_endpoints);
        result.discovered_endpoints = all_endpoints;
        Ok(result)
    }

    fn enqueue_links(&mut self, links: &[String], current_depth: u32) {
        for link in links {
            if self.is_in_scope(link) {
                let normalized = NormalizedUrl::from(link.as_str());
                if !self.visited.contains(&normalized) {
                    self.queue.push_back((normalized, current_depth + 1));
                }
            }
        }
    }
}

fn links_to_endpoints(links: &[String]) -> Vec<DiscoveredEndpoint> {
    links
        .iter()
        .map(|link| DiscoveredEndpoint {
            url: link.clone(),
            method: "GET".to_string(),
            parameters: Vec::new(),
            source: DiscoverySource::Link,
        })
        .collect()
}

fn forms_to_endpoints(forms: &[DiscoveredForm]) -> Vec<DiscoveredEndpoint> {
    forms
        .iter()
        .map(|form| DiscoveredEndpoint {
            url: form.action.clone(),
            method: form.method.clone(),
            parameters: form
                .inputs
                .iter()
                .map(|input| DiscoveredParameter {
                    name: input.name.clone(),
                    location: aegis_protocol::request::ParameterLocation::Body,
                    example_value: input.value.clone(),
                })
                .collect(),
            source: DiscoverySource::Form,
        })
        .collect()
}

pub(crate) fn api_calls_to_endpoints(api_calls: &[InterceptedApiCall]) -> Vec<DiscoveredEndpoint> {
    api_calls
        .iter()
        .map(|call| DiscoveredEndpoint {
            url: call.url.clone(),
            method: call.method.clone(),
            parameters: Vec::new(),
            source: DiscoverySource::ApiCall,
        })
        .collect()
}

fn dedup_endpoints(endpoints: &mut Vec<DiscoveredEndpoint>) {
    let mut seen = HashSet::new();
    endpoints.retain(|ep| seen.insert((ep.url.clone(), ep.method.clone())));
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
