use crate::util::*;

#[test]
fn timestamp_ms_returns_positive() {
    let ts = timestamp_ms();
    assert!(ts > 0, "timestamp should be positive, got {ts}");
}

#[test]
fn timestamp_ms_is_recent() {
    let ts = timestamp_ms();
    // Should be after 2024-01-01 (1704067200000 ms)
    assert!(ts > 1_704_067_200_000);
}

#[test]
fn extract_path_from_url_basic() {
    let path = extract_path_from_url("https://example.com/api/v1/users");
    assert_eq!(path, Some("/api/v1/users".to_string()));
}

#[test]
fn extract_path_from_url_with_query() {
    let path = extract_path_from_url("https://example.com/search?q=test");
    assert_eq!(path, Some("/search".to_string()));
}

#[test]
fn extract_path_from_url_root() {
    let path = extract_path_from_url("https://example.com/");
    assert_eq!(path, Some("/".to_string()));
}

#[test]
fn extract_path_from_url_invalid() {
    let path = extract_path_from_url("not-a-url");
    assert!(path.is_none());
}

#[test]
fn extract_path_from_url_with_fragment() {
    let path = extract_path_from_url("https://example.com/page#section");
    assert_eq!(path, Some("/page".to_string()));
}

#[test]
fn extract_path_from_url_with_port() {
    let path = extract_path_from_url("http://localhost:3000/api/health");
    assert_eq!(path, Some("/api/health".to_string()));
}
