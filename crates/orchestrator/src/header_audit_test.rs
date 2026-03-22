use crate::header_audit::*;

#[test]
fn header_findings_to_operations_creates_findings() {
    let findings = vec![
        MissingHeader {
            header: "content-security-policy".to_string(),
            severity: 6.0,
        },
        MissingHeader {
            header: "x-frame-options".to_string(),
            severity: 4.0,
        },
    ];
    let mut seq = 0;
    let ops = header_findings_to_operations(&findings, &mut seq);
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
                    aegis_protocol::finding::VulnerabilityClass::MissingSecurityHeader
                );
            }
            _ => panic!("expected AddFinding"),
        }
    }
}

#[test]
fn header_findings_to_operations_correct_severity() {
    let findings = vec![MissingHeader {
        header: "csp".to_string(),
        severity: 6.0,
    }];
    let mut seq = 0;
    let ops = header_findings_to_operations(&findings, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 6.0).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn header_findings_to_operations_empty() {
    let mut seq = 5;
    let ops = header_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn audit_security_headers_skips_localhost() {
    let findings = audit_security_headers("http://localhost:8080");
    assert!(findings.is_empty());
}

#[test]
fn audit_security_headers_skips_loopback() {
    let findings = audit_security_headers("http://127.0.0.1:3000");
    assert!(findings.is_empty());
}

#[test]
fn security_headers_list_has_five_entries() {
    assert_eq!(SECURITY_HEADERS.len(), 5);
}

#[test]
fn security_headers_all_lowercase() {
    for (name, _) in SECURITY_HEADERS {
        assert_eq!(*name, name.to_lowercase());
    }
}
