use crate::info_disclosure::*;

#[test]
fn disclosure_headers_list() {
    assert!(DISCLOSURE_HEADERS.contains(&"server"));
    assert!(DISCLOSURE_HEADERS.contains(&"x-powered-by"));
    assert!(DISCLOSURE_HEADERS.contains(&"x-debug-token"));
}

#[test]
fn disclosure_severity_debug_highest() {
    assert!(disclosure_severity("x-debug-token") > disclosure_severity("x-powered-by"));
    assert!(disclosure_severity("x-powered-by") > disclosure_severity("server"));
}

#[test]
fn disclosure_severity_aspnet_versions() {
    assert_eq!(
        disclosure_severity("x-aspnet-version"),
        disclosure_severity("x-aspnetmvc-version")
    );
    assert!(disclosure_severity("x-aspnet-version") > disclosure_severity("server"));
}

#[test]
fn disclosure_findings_to_operations_creates_findings() {
    let findings = vec![
        DisclosedHeader {
            header: "server".to_string(),
            value: "Apache/2.4.51".to_string(),
        },
        DisclosedHeader {
            header: "x-powered-by".to_string(),
            value: "PHP/8.1".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = disclosure_findings_to_operations(&findings, &mut seq);
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
                    aegis_protocol::finding::VulnerabilityClass::InformationDisclosure
                );
            }
            _ => panic!("expected AddFinding"),
        }
    }
}

#[test]
fn disclosure_findings_severity_matches_header() {
    let findings = vec![DisclosedHeader {
        header: "x-debug-token".to_string(),
        value: "abc123".to_string(),
    }];
    let mut seq = 0;
    let ops = disclosure_findings_to_operations(&findings, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 5.0);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn disclosure_findings_to_operations_empty() {
    let mut seq = 5;
    let ops = disclosure_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn scan_info_disclosure_skips_localhost() {
    let findings = scan_info_disclosure("http://localhost:8080");
    assert!(findings.is_empty());
}

#[test]
fn scan_info_disclosure_skips_invalid() {
    let findings = scan_info_disclosure("not-a-url");
    assert!(findings.is_empty());
}
