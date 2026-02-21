use super::*;
use crate::types::CrawlConfig;

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
async fn crawl_stub_returns_empty_result() {
    let mut crawler = Crawler::new(CrawlConfig::default());
    crawler.add_seed("http://localhost:3000/");
    let result = crawler.crawl().await.unwrap();
    assert!(result.discovered_endpoints.is_empty());
    assert!(result.discovered_forms.is_empty());
    assert!(result.event_handlers.is_empty());
    assert!(result.script_sources.is_empty());
    assert_eq!(result.pages_visited, 0);
    assert!(result.errors.is_empty());
}
