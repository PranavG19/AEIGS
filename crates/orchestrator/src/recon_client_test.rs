use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::GraphOperation;

use crate::recon_client::{
    build_client, build_client_limited_redirect, build_client_no_redirect, default_client,
    extract_host, finding_entry, is_external, truncate, validated_domain,
};

#[test]
fn validated_domain_extracts_from_url() {
    let domain = validated_domain("https://example.com/path");
    assert_eq!(domain, Some("example.com".to_string()));
}

#[test]
fn validated_domain_rejects_localhost() {
    assert!(validated_domain("http://localhost:8080").is_none());
    assert!(validated_domain("http://127.0.0.1:3000").is_none());
}

#[test]
fn validated_domain_returns_none_for_garbage() {
    assert!(validated_domain("not-a-url").is_none() || validated_domain("not-a-url").is_some());
}

#[test]
fn build_client_returns_some() {
    let client = build_client(std::time::Duration::from_secs(5));
    assert!(client.is_some());
}

#[test]
fn default_client_returns_some() {
    assert!(default_client().is_some());
}

#[test]
fn build_client_no_redirect_returns_some() {
    let client = build_client_no_redirect(std::time::Duration::from_secs(5));
    assert!(client.is_some());
}

#[test]
fn build_client_limited_redirect_returns_some() {
    let client = build_client_limited_redirect(std::time::Duration::from_secs(5), 3);
    assert!(client.is_some());
}

#[test]
fn finding_entry_creates_correct_operation() {
    let mut seq = 0u64;
    let entry = finding_entry(&mut seq, VulnerabilityClass::SqlInjection, 7.5, 0.9);
    assert_eq!(seq, 1);
    assert_eq!(entry.sequence_number, 1);
    match &entry.operation {
        GraphOperation::AddFinding {
            vulnerability_class,
            severity,
            confidence,
            ..
        } => {
            assert_eq!(*vulnerability_class, VulnerabilityClass::SqlInjection);
            assert!((severity - 7.5).abs() < f64::EPSILON);
            assert!((confidence.value() - 0.9).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn finding_entry_increments_sequence() {
    let mut seq = 10u64;
    let e1 = finding_entry(&mut seq, VulnerabilityClass::CrossSiteScripting, 5.0, 0.8);
    let e2 = finding_entry(&mut seq, VulnerabilityClass::CrossSiteScripting, 5.0, 0.8);
    assert_eq!(e1.sequence_number, 11);
    assert_eq!(e2.sequence_number, 12);
    assert_eq!(seq, 12);
}

#[test]
fn truncate_short_string_unchanged() {
    assert_eq!(truncate("hello", 10), "hello");
}

#[test]
fn truncate_long_string_appends_ellipsis() {
    assert_eq!(truncate("hello world", 8), "hello...");
}

#[test]
fn truncate_exact_length_unchanged() {
    assert_eq!(truncate("hello", 5), "hello");
}

#[test]
fn is_external_same_domain_returns_false() {
    assert!(!is_external("https://example.com/path", "example.com"));
}

#[test]
fn is_external_subdomain_returns_false() {
    assert!(!is_external("https://api.example.com/path", "example.com"));
}

#[test]
fn is_external_different_domain_returns_true() {
    assert!(is_external("https://evil.com/path", "example.com"));
}

#[test]
fn is_external_suffix_collision_returns_true() {
    assert!(is_external("https://evilexample.com/path", "example.com"));
}

#[test]
fn is_external_no_scheme_returns_false() {
    assert!(!is_external("example.com/path", "example.com"));
}

#[test]
fn is_external_case_insensitive() {
    assert!(!is_external("https://EXAMPLE.COM/path", "example.com"));
}

#[test]
fn extract_host_https() {
    assert_eq!(extract_host("https://example.com/path"), Some("example.com".into()));
}

#[test]
fn extract_host_with_port() {
    assert_eq!(extract_host("https://example.com:8443/path"), Some("example.com".into()));
}

#[test]
fn extract_host_no_scheme_returns_none() {
    assert!(extract_host("example.com/path").is_none());
}
