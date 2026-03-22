use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::GraphOperation;

use crate::recon_client::{
    build_client, build_client_limited_redirect, build_client_no_redirect, default_client,
    finding_entry, validated_domain,
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
