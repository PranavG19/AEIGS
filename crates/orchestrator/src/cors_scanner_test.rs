use crate::cors_scanner::*;

#[test]
fn cors_severity_reflected_is_highest() {
    assert!(cors_severity(&CorsIssue::ReflectedOrigin) > cors_severity(&CorsIssue::NullOrigin));
    assert!(cors_severity(&CorsIssue::NullOrigin) > cors_severity(&CorsIssue::ArbitrarySubdomain));
    assert!(
        cors_severity(&CorsIssue::ArbitrarySubdomain) > cors_severity(&CorsIssue::WildcardOrigin)
    );
}

#[test]
fn cors_issue_display() {
    assert_eq!(CorsIssue::WildcardOrigin.to_string(), "wildcard_origin");
    assert_eq!(CorsIssue::NullOrigin.to_string(), "null_origin");
    assert_eq!(CorsIssue::ReflectedOrigin.to_string(), "reflected_origin");
    assert_eq!(
        CorsIssue::ArbitrarySubdomain.to_string(),
        "arbitrary_subdomain"
    );
}

#[test]
fn cors_findings_to_operations_creates_findings() {
    let findings = vec![
        CorsFinding {
            issue: CorsIssue::WildcardOrigin,
            acao_value: "*".to_string(),
        },
        CorsFinding {
            issue: CorsIssue::ReflectedOrigin,
            acao_value: "https://evil.example.com".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = cors_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
    for op in &ops {
        match &op.operation {
            aegis_protocol::operation::GraphOperation::AddFinding {
                vulnerability_class,
                ..
            } => {
                assert_eq!(
                    *vulnerability_class,
                    aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
                );
            }
            _ => panic!("expected AddFinding"),
        }
    }
}

#[test]
fn cors_findings_to_operations_empty() {
    let mut seq = 3;
    let ops = cors_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 3);
}

#[test]
fn cors_findings_severity_matches_issue() {
    let findings = vec![CorsFinding {
        issue: CorsIssue::ReflectedOrigin,
        acao_value: "https://evil.com".to_string(),
    }];
    let mut seq = 0;
    let ops = cors_findings_to_operations(&findings, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 7.0);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn scan_cors_skips_localhost() {
    let findings = scan_cors("http://localhost:8080");
    assert!(findings.is_empty());
}

#[test]
fn scan_cors_skips_loopback() {
    let findings = scan_cors("http://127.0.0.1");
    assert!(findings.is_empty());
}

#[test]
fn scan_cors_skips_invalid() {
    let findings = scan_cors("not-a-url");
    assert!(findings.is_empty());
}
