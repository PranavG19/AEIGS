use std::collections::HashMap;

use super::*;
use crate::page_fetcher::{PageContent, PageFetcher};
use crate::types::{ApiResourceType, CrawlConfig, DomEventHandler, FormInput, InterceptedApiCall};

struct MockFetcher {
    pages: HashMap<String, PageContent>,
}

impl MockFetcher {
    fn new() -> Self {
        Self {
            pages: HashMap::new(),
        }
    }

    fn add_page(&mut self, url: &str, content: PageContent) {
        self.pages.insert(url.to_string(), content);
    }
}

impl PageFetcher for MockFetcher {
    async fn fetch_page(&mut self, url: &str) -> Result<PageContent, CrawlError> {
        self.pages
            .get(url)
            .cloned()
            .ok_or_else(|| CrawlError::Navigation(format!("404: {url}")))
    }
}

#[test]
fn crawler_new_creates_empty_state() {
    let crawler = Crawler::new(CrawlConfig::default());
    assert!(crawler.queue.is_empty());
    assert!(crawler.visited.is_empty());
}

#[test]
fn crawler_add_seed_enqueues_url() {
    let mut crawler = Crawler::new(CrawlConfig::default());
    crawler.add_seed("http://localhost:3000/");
    assert_eq!(crawler.queue.len(), 1);
    let (url, depth) = &crawler.queue[0];
    assert_eq!(url.as_str(), "http://localhost:3000/");
    assert_eq!(*depth, 0);
}

#[test]
fn crawler_add_multiple_seeds() {
    let mut crawler = Crawler::new(CrawlConfig::default());
    crawler.add_seed("http://localhost:3000/");
    crawler.add_seed("http://localhost:3000/api");
    crawler.add_seed("http://localhost:3000/admin");
    assert_eq!(crawler.queue.len(), 3);
}

#[test]
fn is_in_scope_allows_localhost() {
    let crawler = Crawler::new(CrawlConfig::default());
    assert!(crawler.is_in_scope("http://localhost:3000/api"));
}

#[test]
fn is_in_scope_allows_127_0_0_1() {
    let crawler = Crawler::new(CrawlConfig::default());
    assert!(crawler.is_in_scope("http://127.0.0.1:3000/api"));
}

#[test]
fn is_in_scope_rejects_remote() {
    let crawler = Crawler::new(CrawlConfig::default());
    assert!(!crawler.is_in_scope("http://example.com"));
}

#[test]
fn is_in_scope_respects_regex() {
    let config = CrawlConfig::default().with_scope_regex("^/api/.*");
    let crawler = Crawler::new(config);
    assert!(crawler.is_in_scope("http://localhost:3000/api/users"));
    assert!(!crawler.is_in_scope("http://localhost:3000/login"));
}

#[tokio::test]
async fn crawl_visits_seed_page() {
    let mut crawler = Crawler::new(CrawlConfig::default());
    crawler.add_seed("http://localhost:3000/");

    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/",
        PageContent {
            final_url: "http://localhost:3000/".to_string(),
            ..Default::default()
        },
    );

    let result = crawler.crawl(&mut fetcher).await.unwrap();
    assert_eq!(result.pages_visited, 1);
    assert!(result.errors.is_empty());
}

#[tokio::test]
async fn crawl_follows_links_bfs() {
    let mut crawler = Crawler::new(CrawlConfig::default());
    crawler.add_seed("http://localhost:3000/a");

    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/a",
        PageContent {
            final_url: "http://localhost:3000/a".to_string(),
            links: vec![
                "http://localhost:3000/b".to_string(),
                "http://localhost:3000/c".to_string(),
            ],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/b",
        PageContent {
            final_url: "http://localhost:3000/b".to_string(),
            links: vec!["http://localhost:3000/d".to_string()],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/c",
        PageContent {
            final_url: "http://localhost:3000/c".to_string(),
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/d",
        PageContent {
            final_url: "http://localhost:3000/d".to_string(),
            ..Default::default()
        },
    );

    let result = crawler.crawl(&mut fetcher).await.unwrap();
    assert_eq!(result.pages_visited, 4);
}

#[tokio::test]
async fn crawl_respects_max_depth() {
    let config = CrawlConfig::default().with_max_depth(1);
    let mut crawler = Crawler::new(config);
    crawler.add_seed("http://localhost:3000/a");

    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/a",
        PageContent {
            final_url: "http://localhost:3000/a".to_string(),
            links: vec!["http://localhost:3000/b".to_string()],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/b",
        PageContent {
            final_url: "http://localhost:3000/b".to_string(),
            links: vec!["http://localhost:3000/c".to_string()],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/c",
        PageContent {
            final_url: "http://localhost:3000/c".to_string(),
            ..Default::default()
        },
    );

    let result = crawler.crawl(&mut fetcher).await.unwrap();
    assert_eq!(result.pages_visited, 2);
    assert!(
        crawler
            .visited
            .contains(&NormalizedUrl::from("http://localhost:3000/a"))
    );
    assert!(
        crawler
            .visited
            .contains(&NormalizedUrl::from("http://localhost:3000/b"))
    );
}

#[tokio::test]
async fn crawl_respects_max_pages() {
    let config = CrawlConfig::default().with_max_pages(2);
    let mut crawler = Crawler::new(config);
    crawler.add_seed("http://localhost:3000/a");

    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/a",
        PageContent {
            final_url: "http://localhost:3000/a".to_string(),
            links: vec![
                "http://localhost:3000/b".to_string(),
                "http://localhost:3000/c".to_string(),
                "http://localhost:3000/d".to_string(),
            ],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/b",
        PageContent {
            final_url: "http://localhost:3000/b".to_string(),
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/c",
        PageContent {
            final_url: "http://localhost:3000/c".to_string(),
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/d",
        PageContent {
            final_url: "http://localhost:3000/d".to_string(),
            ..Default::default()
        },
    );

    let result = crawler.crawl(&mut fetcher).await.unwrap();
    assert_eq!(result.pages_visited, 2);
}

#[tokio::test]
async fn crawl_deduplicates_urls() {
    let mut crawler = Crawler::new(CrawlConfig::default());
    crawler.add_seed("http://localhost:3000/a");

    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/a",
        PageContent {
            final_url: "http://localhost:3000/a".to_string(),
            links: vec![
                "http://localhost:3000/b".to_string(),
                "http://localhost:3000/b".to_string(),
            ],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/b",
        PageContent {
            final_url: "http://localhost:3000/b".to_string(),
            ..Default::default()
        },
    );

    let result = crawler.crawl(&mut fetcher).await.unwrap();
    assert_eq!(result.pages_visited, 2);
}

#[tokio::test]
async fn crawl_skips_out_of_scope() {
    let mut crawler = Crawler::new(CrawlConfig::default());
    crawler.add_seed("http://localhost:3000/a");

    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/a",
        PageContent {
            final_url: "http://localhost:3000/a".to_string(),
            links: vec![
                "http://example.com/evil".to_string(),
                "http://localhost:3000/b".to_string(),
            ],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/b",
        PageContent {
            final_url: "http://localhost:3000/b".to_string(),
            ..Default::default()
        },
    );

    let result = crawler.crawl(&mut fetcher).await.unwrap();
    assert_eq!(result.pages_visited, 2);
    assert!(
        !crawler
            .visited
            .contains(&NormalizedUrl::from("http://example.com/evil"))
    );
}

#[tokio::test]
async fn crawl_collects_forms() {
    let mut crawler = Crawler::new(CrawlConfig::default());
    crawler.add_seed("http://localhost:3000/");

    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/",
        PageContent {
            final_url: "http://localhost:3000/".to_string(),
            forms: vec![DiscoveredForm {
                action: "http://localhost:3000/login".to_string(),
                method: "POST".to_string(),
                inputs: vec![
                    FormInput {
                        name: "username".to_string(),
                        input_type: "text".to_string(),
                        value: None,
                    },
                    FormInput {
                        name: "password".to_string(),
                        input_type: "password".to_string(),
                        value: None,
                    },
                ],
            }],
            ..Default::default()
        },
    );

    let result = crawler.crawl(&mut fetcher).await.unwrap();
    assert_eq!(result.discovered_forms.len(), 1);
    assert_eq!(
        result.discovered_forms[0].action,
        "http://localhost:3000/login"
    );
    assert_eq!(result.discovered_forms[0].method, "POST");
    assert_eq!(result.discovered_forms[0].inputs.len(), 2);

    let form_endpoint = result
        .discovered_endpoints
        .iter()
        .find(|ep| ep.source == DiscoverySource::Form);
    assert!(form_endpoint.is_some());
    let ep = form_endpoint.unwrap();
    assert_eq!(ep.method, "POST");
    assert_eq!(ep.parameters.len(), 2);
}

#[tokio::test]
async fn crawl_collects_script_sources() {
    let mut crawler = Crawler::new(CrawlConfig::default());
    crawler.add_seed("http://localhost:3000/");

    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/",
        PageContent {
            final_url: "http://localhost:3000/".to_string(),
            script_sources: vec![
                "http://localhost:3000/app.js".to_string(),
                "http://localhost:3000/vendor.js".to_string(),
            ],
            ..Default::default()
        },
    );

    let result = crawler.crawl(&mut fetcher).await.unwrap();
    assert_eq!(result.script_sources.len(), 2);
    assert!(
        result
            .script_sources
            .contains(&"http://localhost:3000/app.js".to_string())
    );
    assert!(
        result
            .script_sources
            .contains(&"http://localhost:3000/vendor.js".to_string())
    );
}

#[tokio::test]
async fn crawl_collects_event_handlers() {
    let mut crawler = Crawler::new(CrawlConfig::default());
    crawler.add_seed("http://localhost:3000/");

    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/",
        PageContent {
            final_url: "http://localhost:3000/".to_string(),
            event_handlers: vec![DomEventHandler {
                element_selector: "button#submit".to_string(),
                event_name: "onclick".to_string(),
                handler_snippet: "sendData()".to_string(),
            }],
            ..Default::default()
        },
    );

    let result = crawler.crawl(&mut fetcher).await.unwrap();
    assert_eq!(result.event_handlers.len(), 1);
    assert_eq!(result.event_handlers[0].event_name, "onclick");
    assert_eq!(result.event_handlers[0].element_selector, "button#submit");
}

#[tokio::test]
async fn crawl_records_errors_without_failing() {
    let mut crawler = Crawler::new(CrawlConfig::default());
    crawler.add_seed("http://localhost:3000/a");

    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/a",
        PageContent {
            final_url: "http://localhost:3000/a".to_string(),
            links: vec![
                "http://localhost:3000/missing".to_string(),
                "http://localhost:3000/b".to_string(),
            ],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/b",
        PageContent {
            final_url: "http://localhost:3000/b".to_string(),
            ..Default::default()
        },
    );

    let result = crawler.crawl(&mut fetcher).await.unwrap();
    assert_eq!(result.pages_visited, 2);
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].contains("404"));
}

#[tokio::test]
async fn crawl_deduplicates_endpoints() {
    let mut crawler = Crawler::new(CrawlConfig::default());
    crawler.add_seed("http://localhost:3000/a");

    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/a",
        PageContent {
            final_url: "http://localhost:3000/a".to_string(),
            links: vec![
                "http://localhost:3000/shared".to_string(),
                "http://localhost:3000/b".to_string(),
            ],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/b",
        PageContent {
            final_url: "http://localhost:3000/b".to_string(),
            links: vec!["http://localhost:3000/shared".to_string()],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/shared",
        PageContent {
            final_url: "http://localhost:3000/shared".to_string(),
            ..Default::default()
        },
    );

    let result = crawler.crawl(&mut fetcher).await.unwrap();
    let shared_count = result
        .discovered_endpoints
        .iter()
        .filter(|ep| ep.url == "http://localhost:3000/shared" && ep.method == "GET")
        .count();
    assert_eq!(shared_count, 1);
}

#[tokio::test]
async fn crawl_collects_intercepted_api_calls() {
    let mut crawler = Crawler::new(CrawlConfig::default());
    crawler.add_seed("http://localhost:3000/");

    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/",
        PageContent {
            final_url: "http://localhost:3000/".to_string(),
            intercepted_api_calls: vec![
                InterceptedApiCall {
                    url: "http://localhost:3000/api/users".to_string(),
                    method: "GET".to_string(),
                    resource_type: ApiResourceType::Xhr,
                },
                InterceptedApiCall {
                    url: "http://localhost:3000/api/data".to_string(),
                    method: "POST".to_string(),
                    resource_type: ApiResourceType::Fetch,
                },
            ],
            ..Default::default()
        },
    );

    let result = crawler.crawl(&mut fetcher).await.unwrap();
    let api_endpoints: Vec<_> = result
        .discovered_endpoints
        .iter()
        .filter(|ep| ep.source == DiscoverySource::ApiCall)
        .collect();
    assert_eq!(api_endpoints.len(), 2);
    assert!(
        api_endpoints
            .iter()
            .any(|ep| ep.url == "http://localhost:3000/api/users")
    );
    assert!(
        api_endpoints
            .iter()
            .any(|ep| ep.url == "http://localhost:3000/api/data")
    );
}

#[tokio::test]
async fn crawl_deduplicates_api_call_endpoints() {
    let mut crawler = Crawler::new(CrawlConfig::default());
    crawler.add_seed("http://localhost:3000/a");

    let api_call = InterceptedApiCall {
        url: "http://localhost:3000/api/shared".to_string(),
        method: "GET".to_string(),
        resource_type: ApiResourceType::Xhr,
    };

    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/a",
        PageContent {
            final_url: "http://localhost:3000/a".to_string(),
            links: vec!["http://localhost:3000/b".to_string()],
            intercepted_api_calls: vec![api_call.clone()],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/b",
        PageContent {
            final_url: "http://localhost:3000/b".to_string(),
            intercepted_api_calls: vec![api_call],
            ..Default::default()
        },
    );

    let result = crawler.crawl(&mut fetcher).await.unwrap();
    let api_count = result
        .discovered_endpoints
        .iter()
        .filter(|ep| {
            ep.url == "http://localhost:3000/api/shared"
                && ep.method == "GET"
                && ep.source == DiscoverySource::ApiCall
        })
        .count();
    assert_eq!(api_count, 1);
}

#[test]
fn api_calls_to_endpoints_preserves_method() {
    let calls = vec![
        InterceptedApiCall {
            url: "http://localhost:3000/api/create".to_string(),
            method: "POST".to_string(),
            resource_type: ApiResourceType::Fetch,
        },
        InterceptedApiCall {
            url: "http://localhost:3000/api/update".to_string(),
            method: "PUT".to_string(),
            resource_type: ApiResourceType::Xhr,
        },
        InterceptedApiCall {
            url: "http://localhost:3000/api/remove".to_string(),
            method: "DELETE".to_string(),
            resource_type: ApiResourceType::Fetch,
        },
    ];

    let endpoints = api_calls_to_endpoints(&calls);
    assert_eq!(endpoints.len(), 3);
    assert_eq!(endpoints[0].method, "POST");
    assert_eq!(endpoints[0].source, DiscoverySource::ApiCall);
    assert_eq!(endpoints[1].method, "PUT");
    assert_eq!(endpoints[1].source, DiscoverySource::ApiCall);
    assert_eq!(endpoints[2].method, "DELETE");
    assert_eq!(endpoints[2].source, DiscoverySource::ApiCall);
}

#[test]
fn api_calls_to_endpoints_empty_input() {
    let endpoints = api_calls_to_endpoints(&[]);
    assert!(endpoints.is_empty());
}
