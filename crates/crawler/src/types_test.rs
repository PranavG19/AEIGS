use super::*;

#[test]
fn normalized_url_strips_fragment() {
    let url = NormalizedUrl::from("http://localhost:3000/path#frag");
    assert_eq!(url.as_str(), "http://localhost:3000/path");
}

#[test]
fn normalized_url_lowercases_host() {
    let url = NormalizedUrl::from("http://LOCALHOST:3000/Path");
    assert_eq!(url.as_str(), "http://localhost:3000/Path");
}

#[test]
fn normalized_url_removes_default_port() {
    let url = NormalizedUrl::from("http://localhost:80/path");
    assert_eq!(url.as_str(), "http://localhost/path");
}

#[test]
fn normalized_url_preserves_non_default_port() {
    let url = NormalizedUrl::from("http://localhost:3000/path");
    assert_eq!(url.as_str(), "http://localhost:3000/path");
}

#[test]
fn normalized_url_equality() {
    let a = NormalizedUrl::from("http://LOCALHOST:80/path#section");
    let b = NormalizedUrl::from("http://localhost/path");
    assert_eq!(a, b);
}

#[test]
fn crawl_config_default_values() {
    let config = CrawlConfig::default();
    assert_eq!(config.max_depth, 3);
    assert_eq!(config.max_pages, 100);
    assert!(config.scope_regex.is_none());
    assert_eq!(config.timeout_secs, 30);
    assert_eq!(config.wait_after_load_ms, 1000);
}

#[test]
fn crawl_config_builder() {
    let config = CrawlConfig::default()
        .with_max_depth(5)
        .with_max_pages(200)
        .with_scope_regex("^/api/.*")
        .with_timeout_secs(60)
        .with_wait_after_load_ms(2000);

    assert_eq!(config.max_depth, 5);
    assert_eq!(config.max_pages, 200);
    assert_eq!(config.scope_regex.as_deref(), Some("^/api/.*"));
    assert_eq!(config.timeout_secs, 60);
    assert_eq!(config.wait_after_load_ms, 2000);
}

#[test]
fn discovery_source_debug_format() {
    let source = DiscoverySource::Link;
    let debug_str = format!("{source:?}");
    assert_eq!(debug_str, "Link");
}
