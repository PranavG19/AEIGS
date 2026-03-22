use crate::tls_scanner::*;

#[test]
fn parse_hsts_max_age_standard() {
    assert_eq!(parse_hsts_max_age("max-age=31536000"), Some(31536000));
}

#[test]
fn parse_hsts_max_age_with_directives() {
    assert_eq!(
        parse_hsts_max_age("max-age=31536000; includeSubDomains; preload"),
        Some(31536000)
    );
}

#[test]
fn parse_hsts_max_age_short() {
    assert_eq!(parse_hsts_max_age("max-age=3600"), Some(3600));
}

#[test]
fn parse_hsts_max_age_zero() {
    assert_eq!(parse_hsts_max_age("max-age=0"), Some(0));
}

#[test]
fn parse_hsts_max_age_missing() {
    assert_eq!(parse_hsts_max_age("includeSubDomains; preload"), None);
}

#[test]
fn parse_hsts_max_age_invalid() {
    assert_eq!(parse_hsts_max_age("max-age=notanumber"), None);
}

#[test]
fn parse_hsts_max_age_case_insensitive() {
    assert_eq!(parse_hsts_max_age("Max-Age=86400"), Some(86400));
}

#[test]
fn tls_findings_to_operations_no_https() {
    let findings = vec![TlsFinding {
        issue: TlsIssue::NoHttps,
        detail: "test".to_string(),
    }];
    let mut seq = 0;
    let ops = tls_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            severity,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::WeakCryptography
            );
            assert!((severity - 7.0).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn tls_findings_to_operations_missing_hsts() {
    let findings = vec![TlsFinding {
        issue: TlsIssue::MissingHsts,
        detail: "test".to_string(),
    }];
    let mut seq = 0;
    let ops = tls_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::MissingSecurityHeader
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn tls_findings_to_operations_empty() {
    let mut seq = 3;
    let ops = tls_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 3);
}

#[test]
fn tls_findings_to_operations_multiple() {
    let findings = vec![
        TlsFinding {
            issue: TlsIssue::MissingHsts,
            detail: "test".to_string(),
        },
        TlsFinding {
            issue: TlsIssue::InsecureRedirect,
            detail: "test".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = tls_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn scan_tls_skips_localhost() {
    let findings = scan_tls("http://localhost:8080");
    assert!(findings.is_empty());
}

#[test]
fn scan_tls_skips_loopback() {
    let findings = scan_tls("http://127.0.0.1:3000");
    assert!(findings.is_empty());
}
