use std::collections::HashMap;

use aegis_crawler::{
    ApiResourceType, CrawlConfig, CrawlError, Crawler, DiscoverySource, FormInput,
    InterceptedApiCall, PageContent, PageFetcher,
};

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

struct TimeoutFetcher;

impl PageFetcher for TimeoutFetcher {
    async fn fetch_page(&mut self, url: &str) -> Result<PageContent, CrawlError> {
        Err(CrawlError::Timeout(format!("simulated timeout for {url}")))
    }
}

#[tokio::test]
async fn crawler_timeout_does_not_hang() {
    let config = CrawlConfig::default().with_max_pages(5);
    let mut crawler = Crawler::new(config);
    crawler.add_seed("http://localhost:3000/");

    let mut fetcher = TimeoutFetcher;
    let result = crawler.crawl(&mut fetcher).await.unwrap();

    assert_eq!(result.pages_visited, 0);
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].contains("timeout"));
    assert!(result.discovered_endpoints.is_empty());
}

#[tokio::test]
async fn crawler_end_to_end_bfs_with_multiple_sources() {
    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/",
        PageContent {
            final_url: "http://localhost:3000/".to_string(),
            links: vec![
                "http://localhost:3000/about".to_string(),
                "http://localhost:3000/api/users".to_string(),
            ],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/about",
        PageContent {
            final_url: "http://localhost:3000/about".to_string(),
            forms: vec![aegis_crawler::DiscoveredForm {
                action: "http://localhost:3000/contact".to_string(),
                method: "POST".to_string(),
                inputs: vec![
                    FormInput {
                        name: "name".to_string(),
                        input_type: "text".to_string(),
                        value: None,
                    },
                    FormInput {
                        name: "message".to_string(),
                        input_type: "textarea".to_string(),
                        value: None,
                    },
                ],
            }],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/api/users",
        PageContent {
            final_url: "http://localhost:3000/api/users".to_string(),
            intercepted_api_calls: vec![
                InterceptedApiCall {
                    url: "http://localhost:3000/api/users/1".to_string(),
                    method: "GET".to_string(),
                    resource_type: ApiResourceType::Xhr,
                },
                InterceptedApiCall {
                    url: "http://localhost:3000/api/users".to_string(),
                    method: "POST".to_string(),
                    resource_type: ApiResourceType::Fetch,
                },
            ],
            ..Default::default()
        },
    );

    let config = CrawlConfig::default().with_max_depth(2).with_max_pages(10);
    let mut crawler = Crawler::new(config);
    crawler.add_seed("http://localhost:3000/");

    let result = crawler.crawl(&mut fetcher).await.unwrap();

    assert_eq!(result.pages_visited, 3);
    assert!(result.errors.is_empty());

    let link_endpoints: Vec<_> = result
        .discovered_endpoints
        .iter()
        .filter(|ep| ep.source == DiscoverySource::Link)
        .collect();
    assert!(
        link_endpoints
            .iter()
            .any(|ep| ep.url == "http://localhost:3000/about"),
        "expected /about as Link endpoint"
    );
    assert!(
        link_endpoints
            .iter()
            .any(|ep| ep.url == "http://localhost:3000/api/users"),
        "expected /api/users as Link endpoint"
    );

    let form_endpoints: Vec<_> = result
        .discovered_endpoints
        .iter()
        .filter(|ep| ep.source == DiscoverySource::Form)
        .collect();
    assert_eq!(form_endpoints.len(), 1);
    assert_eq!(form_endpoints[0].url, "http://localhost:3000/contact");
    assert_eq!(form_endpoints[0].method, "POST");
    assert_eq!(form_endpoints[0].parameters.len(), 2);

    let api_endpoints: Vec<_> = result
        .discovered_endpoints
        .iter()
        .filter(|ep| ep.source == DiscoverySource::ApiCall)
        .collect();
    assert_eq!(api_endpoints.len(), 2);
    assert!(
        api_endpoints
            .iter()
            .any(|ep| ep.url == "http://localhost:3000/api/users/1" && ep.method == "GET")
    );
    assert!(
        api_endpoints
            .iter()
            .any(|ep| ep.url == "http://localhost:3000/api/users" && ep.method == "POST")
    );

    assert_eq!(result.discovered_forms.len(), 1);
    assert_eq!(result.discovered_forms[0].inputs.len(), 2);
}

#[tokio::test]
async fn crawler_scope_regex_prevents_visiting_out_of_scope_pages() {
    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/",
        PageContent {
            final_url: "http://localhost:3000/".to_string(),
            links: vec![
                "http://localhost:3000/api/v1/data".to_string(),
                "http://localhost:3000/admin/panel".to_string(),
            ],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/api/v1/data",
        PageContent {
            final_url: "http://localhost:3000/api/v1/data".to_string(),
            links: vec!["http://localhost:3000/api/v1/users".to_string()],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/api/v1/users",
        PageContent {
            final_url: "http://localhost:3000/api/v1/users".to_string(),
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/admin/panel",
        PageContent {
            final_url: "http://localhost:3000/admin/panel".to_string(),
            links: vec!["http://localhost:3000/admin/settings".to_string()],
            ..Default::default()
        },
    );

    let config = CrawlConfig::default().with_scope_regex("^/api/.*");
    let mut crawler = Crawler::new(config);
    crawler.add_seed("http://localhost:3000/");

    let result = crawler.crawl(&mut fetcher).await.unwrap();

    let endpoint_urls: Vec<_> = result
        .discovered_endpoints
        .iter()
        .map(|ep| ep.url.as_str())
        .collect();
    assert!(
        endpoint_urls.iter().any(|u| u.contains("/api/v1/data")),
        "expected /api/v1/data to be discovered"
    );
    assert!(
        endpoint_urls.iter().any(|u| u.contains("/api/v1/users")),
        "expected /api/v1/users to be discovered (from visiting /api/v1/data)"
    );
    assert!(
        !endpoint_urls.iter().any(|u| u.contains("/admin/settings")),
        "/admin/settings should not appear because /admin/panel was never visited"
    );

    assert!(
        result.pages_visited <= 3,
        "should not have visited /admin/panel"
    );
}

#[tokio::test]
async fn crawler_error_resilience_with_mixed_pages() {
    let mut fetcher = MockFetcher::new();
    fetcher.add_page(
        "http://localhost:3000/",
        PageContent {
            final_url: "http://localhost:3000/".to_string(),
            links: vec![
                "http://localhost:3000/ok".to_string(),
                "http://localhost:3000/broken".to_string(),
                "http://localhost:3000/also-ok".to_string(),
            ],
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/ok",
        PageContent {
            final_url: "http://localhost:3000/ok".to_string(),
            ..Default::default()
        },
    );
    fetcher.add_page(
        "http://localhost:3000/also-ok",
        PageContent {
            final_url: "http://localhost:3000/also-ok".to_string(),
            ..Default::default()
        },
    );

    let mut crawler = Crawler::new(CrawlConfig::default());
    crawler.add_seed("http://localhost:3000/");

    let result = crawler.crawl(&mut fetcher).await.unwrap();

    assert_eq!(result.pages_visited, 3);
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].contains("404"));
    assert!(result.errors[0].contains("broken"));
}
