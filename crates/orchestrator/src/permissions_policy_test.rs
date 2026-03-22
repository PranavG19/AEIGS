use crate::permissions_policy::*;

#[test]
fn check_permissions_policy_skips_localhost() {
    let result = check_permissions_policy("http://localhost:8080");
    assert!(result.is_empty());
}

#[test]
fn check_permissions_policy_skips_loopback() {
    let result = check_permissions_policy("http://127.0.0.1");
    assert!(result.is_empty());
}

#[test]
fn analyze_policy_flags_wildcard() {
    let issues = analyze_policy("camera=*, microphone=()");
    let wildcards: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i.kind, PolicyIssueKind::WildcardAllowlist))
        .collect();
    assert_eq!(wildcards.len(), 1);
}

#[test]
fn analyze_policy_flags_unrestricted_sensitive_features() {
    let issues = analyze_policy("camera=(), microphone=()");
    let unrestricted: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i.kind, PolicyIssueKind::SensitiveFeatureUnrestricted))
        .collect();
    // 6 sensitive features not restricted (geolocation, payment, usb, bluetooth, serial, hid)
    assert_eq!(unrestricted.len(), 6);
}

#[test]
fn analyze_policy_all_restricted_no_issues() {
    let policy = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), serial=(), hid=()";
    let issues = analyze_policy(policy);
    assert!(issues.is_empty());
}

#[test]
fn policy_findings_to_operations_missing_header() {
    let issues = vec![PermissionsPolicyIssue {
        kind: PolicyIssueKind::MissingHeader,
        detail: "No header".to_string(),
    }];
    let mut seq = 0;
    let ops = policy_findings_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            severity,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::MissingSecurityHeader
            );
            assert!(*severity >= 3.0);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn policy_findings_to_operations_misconfig() {
    let issues = vec![PermissionsPolicyIssue {
        kind: PolicyIssueKind::WildcardAllowlist,
        detail: "wildcard".to_string(),
    }];
    let mut seq = 0;
    let ops = policy_findings_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    match &ops[0].operation {
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

#[test]
fn policy_findings_empty_returns_no_ops() {
    let mut seq = 0;
    let ops = policy_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}
