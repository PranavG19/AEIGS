use crate::redirect_scanner::*;

#[test]
fn is_external_redirect_https() {
    assert!(is_external_redirect("https://evil.example.com"));
    assert!(is_external_redirect("https://evil.example.com/path"));
}

#[test]
fn is_external_redirect_http() {
    assert!(is_external_redirect("http://evil.example.com"));
}

#[test]
fn is_external_redirect_protocol_relative() {
    assert!(is_external_redirect("//evil.example.com"));
}

#[test]
fn is_external_redirect_internal() {
    assert!(!is_external_redirect("/dashboard"));
    assert!(!is_external_redirect("https://safe.example.com"));
    assert!(!is_external_redirect("/"));
}

#[test]
fn is_external_redirect_empty() {
    assert!(!is_external_redirect(""));
}

#[test]
fn redirect_findings_to_operations_creates_findings() {
    let findings = vec![
        OpenRedirect {
            param: "url".to_string(),
            redirected_to: "https://evil.example.com".to_string(),
        },
        OpenRedirect {
            param: "next".to_string(),
            redirected_to: "https://evil.example.com/phish".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = redirect_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
    for op in &ops {
        match &op.operation {
            aegis_protocol::operation::GraphOperation::AddFinding {
                vulnerability_class,
                severity,
                ..
            } => {
                assert_eq!(
                    *vulnerability_class,
                    aegis_protocol::finding::VulnerabilityClass::OpenRedirect
                );
                assert_eq!(*severity, 5.0);
            }
            _ => panic!("expected AddFinding"),
        }
    }
}

#[test]
fn redirect_findings_to_operations_empty() {
    let mut seq = 3;
    let ops = redirect_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 3);
}

#[test]
fn scan_redirects_skips_localhost() {
    let findings = scan_redirects("http://localhost:8080");
    assert!(findings.is_empty());
}

#[test]
fn scan_redirects_skips_invalid() {
    let findings = scan_redirects("not-a-url");
    assert!(findings.is_empty());
}
