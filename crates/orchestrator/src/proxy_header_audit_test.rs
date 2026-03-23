use crate::proxy_header_audit::{
    ProxyHeaderIssueKind, analyze_proxy_headers, proxy_header_to_operations,
};

#[test]
fn no_headers_no_issues() {
    let issues = analyze_proxy_headers(&[], false, &[]);
    assert!(issues.is_empty());
}

#[test]
fn via_header_detected() {
    let via = vec!["1.1 varnish, 1.1 nginx".to_string()];
    let issues = analyze_proxy_headers(&via, false, &[]);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ProxyHeaderIssueKind::ViaProxyLeak)
    );
}

#[test]
fn age_header_detected() {
    let issues = analyze_proxy_headers(&[], true, &[]);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ProxyHeaderIssueKind::AgePresent)
    );
}

#[test]
fn x_cache_detected() {
    let extra = vec![("x-cache".to_string(), "HIT".to_string())];
    let issues = analyze_proxy_headers(&[], false, &extra);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ProxyHeaderIssueKind::XCacheHit)
    );
}

#[test]
fn x_forwarded_for_detected() {
    let extra = vec![(
        "x-forwarded-for".to_string(),
        "10.0.0.1, 192.168.1.1".to_string(),
    )];
    let issues = analyze_proxy_headers(&[], false, &extra);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ProxyHeaderIssueKind::XForwardedFor)
    );
}

#[test]
fn multiple_via_values() {
    let via = vec!["1.1 proxy1".to_string(), "1.0 proxy2".to_string()];
    let issues = analyze_proxy_headers(&via, false, &[]);
    assert_eq!(
        issues
            .iter()
            .filter(|i| i.kind == ProxyHeaderIssueKind::ViaProxyLeak)
            .count(),
        2
    );
}

#[test]
fn combined_headers() {
    let via = vec!["1.1 squid".to_string()];
    let extra = vec![("x-cache".to_string(), "MISS".to_string())];
    let issues = analyze_proxy_headers(&via, true, &extra);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ProxyHeaderIssueKind::ViaProxyLeak)
    );
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ProxyHeaderIssueKind::AgePresent)
    );
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ProxyHeaderIssueKind::XCacheHit)
    );
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = proxy_header_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_on_issues() {
    let via = vec!["1.1 proxy".to_string()];
    let issues = analyze_proxy_headers(&via, false, &[]);
    let mut seq = 5;
    let ops = proxy_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}
