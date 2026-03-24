use super::*;

fn make_af() -> AntiForensics {
    AntiForensics::with_seed(AntiForensicsConfig::default(), 42)
}

#[test]
fn detects_scanner_user_agents() {
    let af = make_af();
    assert!(af.is_scanner_ua("sqlmap/1.7"));
    assert!(af.is_scanner_ua("Mozilla/5.0 (Nikto/2.1.5)"));
    assert!(af.is_scanner_ua("Nmap Scripting Engine"));
    assert!(!af.is_scanner_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0"));
}

#[test]
fn detects_scanner_url_patterns() {
    let af = make_af();
    assert!(af.is_scanner_url_pattern(
        "https://target.com/wp-admin/admin-ajax.php?action=revslider_show_image"
    ));
    assert!(af.is_scanner_url_pattern("https://target.com/.env"));
    assert!(af.is_scanner_url_pattern("https://target.com/actuator/health"));
    assert!(!af.is_scanner_url_pattern("https://target.com/about"));
}

#[test]
fn clean_request_removes_scanner_headers() {
    let mut af = make_af();
    let headers = vec![
        ("Host".to_string(), "example.com".to_string()),
        ("X-Scanner".to_string(), "aegis".to_string()),
        ("X-Burp-Token".to_string(), "abc123".to_string()),
        ("Accept".to_string(), "*/*".to_string()),
    ];
    let result = af.clean_request("https://example.com/", "GET", &headers, &[]);
    let header_names: Vec<&str> = result.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert!(!header_names.contains(&"X-Scanner"));
    assert!(!header_names.contains(&"X-Burp-Token"));
    assert!(header_names.contains(&"Host"));
    assert!(result
        .signatures_removed
        .contains(&ScannerSignature::ScannerSpecificHeader));
}

#[test]
fn clean_request_replaces_scanner_ua() {
    let mut af = make_af();
    let headers = vec![("User-Agent".to_string(), "sqlmap/1.7.8".to_string())];
    let result = af.clean_request("https://example.com/", "GET", &headers, &[]);
    let ua = result
        .headers
        .iter()
        .find(|(n, _)| n == "User-Agent")
        .unwrap();
    assert!(!af.is_scanner_ua(&ua.1));
    assert!(result
        .signatures_removed
        .contains(&ScannerSignature::ToolSpecificUserAgent));
}

#[test]
fn clean_request_randomizes_parameters() {
    let mut af = make_af();
    let params: Vec<(String, String)> = (0..10)
        .map(|i| (format!("p{i}"), format!("v{i}")))
        .collect();
    let result = af.clean_request("https://example.com/", "GET", &[], &params);
    assert_eq!(result.parameters.len(), 10);
    let original_order: Vec<String> = params.iter().map(|(k, _)| k.clone()).collect();
    let cleaned_order: Vec<String> = result.parameters.iter().map(|(k, _)| k.clone()).collect();
    assert_ne!(original_order, cleaned_order);
}

#[test]
fn single_param_not_randomized() {
    let mut af = make_af();
    let params = vec![("key".to_string(), "value".to_string())];
    let result = af.clean_request("https://example.com/", "GET", &[], &params);
    assert_eq!(result.parameters.len(), 1);
    assert_eq!(result.parameters[0].0, "key");
}

#[test]
fn scanner_url_pattern_flagged() {
    let mut af = make_af();
    let result = af.clean_request("https://target.com/.env", "GET", &[], &[]);
    assert!(result
        .signatures_removed
        .contains(&ScannerSignature::KnownScannerUrlPattern));
}

#[test]
fn crawler_mimicry_uses_correct_ua() {
    let mut af = AntiForensics::with_seed(
        AntiForensicsConfig::default().with_crawler_mimicry(CrawlerMimicry::Googlebot),
        42,
    );
    let headers = vec![("User-Agent".to_string(), "nikto/2.1.5".to_string())];
    let result = af.clean_request("https://example.com/", "GET", &headers, &[]);
    let ua = result
        .headers
        .iter()
        .find(|(n, _)| n == "User-Agent")
        .unwrap();
    assert!(ua.1.contains("Googlebot"));
}

#[test]
fn sanitize_log_entry_redacts_sensitive() {
    let af = make_af();
    let entry = "Scanning password=secret123 at 192.168.1.100";
    let sanitized = af.sanitize_log_entry(entry);
    assert!(!sanitized.contains("secret123"));
    assert!(sanitized.contains("[REDACTED]"));
}

#[test]
fn sanitize_logs_disabled_returns_original() {
    let af = AntiForensics::with_seed(AntiForensicsConfig::default().with_sanitize_logs(false), 42);
    let entry = "password=secret";
    assert_eq!(af.sanitize_log_entry(entry), entry);
}

#[test]
fn browser_header_order_default() {
    let af = make_af();
    let order = af.browser_header_order();
    assert!(order.contains(&"Host"));
    assert!(order.contains(&"User-Agent"));
    assert!(order.contains(&"Accept"));
}

#[test]
fn browser_header_order_crawler_mimicry() {
    let af = AntiForensics::with_seed(
        AntiForensicsConfig::default().with_crawler_mimicry(CrawlerMimicry::Bingbot),
        42,
    );
    let order = af.browser_header_order();
    assert!(order.contains(&"Host"));
    assert!(order.contains(&"From"));
}

#[test]
fn crawler_mimicry_variants() {
    let crawlers = [
        CrawlerMimicry::Googlebot,
        CrawlerMimicry::Bingbot,
        CrawlerMimicry::Yandexbot,
        CrawlerMimicry::DuckDuckBot,
    ];
    for crawler in &crawlers {
        assert!(!crawler.user_agent().is_empty());
        assert!(!crawler.header_order().is_empty());
    }
}

#[test]
fn scanner_signature_display() {
    assert_eq!(
        format!("{}", ScannerSignature::ToolSpecificUserAgent),
        "tool-specific-user-agent"
    );
    assert_eq!(
        format!("{}", ScannerSignature::ScannerSpecificHeader),
        "scanner-specific-header"
    );
}

#[test]
fn headers_sorted_in_browser_order() {
    let mut af = make_af();
    let headers = vec![
        ("Accept".to_string(), "*/*".to_string()),
        ("Host".to_string(), "example.com".to_string()),
        ("User-Agent".to_string(), "Chrome/125".to_string()),
    ];
    let result = af.clean_request("https://example.com/", "GET", &headers, &[]);
    let names: Vec<&str> = result.headers.iter().map(|(n, _)| n.as_str()).collect();
    let host_pos = names.iter().position(|n| *n == "Host").unwrap();
    let ua_pos = names.iter().position(|n| *n == "User-Agent").unwrap();
    let accept_pos = names.iter().position(|n| *n == "Accept").unwrap();
    assert!(host_pos < ua_pos);
    assert!(ua_pos < accept_pos);
}

#[test]
fn clean_request_preserves_method() {
    let mut af = make_af();
    let result = af.clean_request("https://example.com/", "POST", &[], &[]);
    assert_eq!(result.method, "POST");
}

#[test]
fn non_scanner_ua_not_modified() {
    let mut af = make_af();
    let legitimate_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0 Safari/537.36";
    let headers = vec![("User-Agent".to_string(), legitimate_ua.to_string())];
    let result = af.clean_request("https://example.com/", "GET", &headers, &[]);
    let ua = result
        .headers
        .iter()
        .find(|(n, _)| n == "User-Agent")
        .unwrap();
    assert_eq!(ua.1, legitimate_ua);
}
