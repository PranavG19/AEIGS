use crate::subdomain_takeover::*;

#[test]
fn check_subdomain_takeover_empty_input() {
    let candidates = check_subdomain_takeover(&[]);
    assert!(candidates.is_empty());
}

#[test]
fn takeover_findings_to_operations_creates_findings() {
    let candidates = vec![TakeoverCandidate {
        subdomain: "blog.example.com".to_string(),
        cname: "example.github.io".to_string(),
        service: "github.io".to_string(),
    }];
    let mut seq = 0;
    let ops = takeover_findings_to_operations(&candidates, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            severity,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
            );
            assert_eq!(*severity, 8.0);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn takeover_findings_to_operations_empty() {
    let mut seq = 5;
    let ops = takeover_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn takeover_findings_to_operations_multiple() {
    let candidates = vec![
        TakeoverCandidate {
            subdomain: "blog.example.com".to_string(),
            cname: "example.github.io".to_string(),
            service: "github.io".to_string(),
        },
        TakeoverCandidate {
            subdomain: "app.example.com".to_string(),
            cname: "example.herokuapp.com".to_string(),
            service: "herokuapp.com".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = takeover_findings_to_operations(&candidates, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn resolve_cname_nonexistent_domain() {
    let result = resolve_cname("this-domain-does-not-exist-aegis-test.invalid");
    assert!(result.is_none());
}
