use crate::verb_tamper_audit::*;

#[test]
fn no_issues_when_all_denied() {
    let results = vec![
        ("HEAD".to_string(), 403u16),
        ("PATCH".to_string(), 403),
        ("PROPFIND".to_string(), 405),
    ];
    let issues = analyze_verb_tamper(403, &results);
    assert!(issues.is_empty());
}

#[test]
fn no_issues_when_all_match_baseline() {
    let results = vec![
        ("HEAD".to_string(), 200u16),
        ("PATCH".to_string(), 200),
    ];
    let issues = analyze_verb_tamper(200, &results);
    assert!(issues.is_empty());
}

#[test]
fn auth_bypass_detected() {
    let results = vec![
        ("HEAD".to_string(), 403u16),
        ("PATCH".to_string(), 200),
    ];
    let issues = analyze_verb_tamper(403, &results);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        &issues[0],
        VerbTamperIssue::AuthBypass {
            method,
            expected_status: 403,
            actual_status: 200
        } if method == "PATCH"
    ));
}

#[test]
fn auth_bypass_from_401() {
    let results = vec![("HEAD".to_string(), 200u16)];
    let issues = analyze_verb_tamper(401, &results);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], VerbTamperIssue::AuthBypass { .. }));
}

#[test]
fn unexpected_success_nonstandard_method() {
    let results = vec![
        ("PROPFIND".to_string(), 200u16),
        ("XMETHOD".to_string(), 200),
    ];
    let issues = analyze_verb_tamper(200, &results);
    assert_eq!(issues.len(), 2);
    assert!(issues
        .iter()
        .all(|i| matches!(i, VerbTamperIssue::UnexpectedSuccess { .. })));
}

#[test]
fn standard_methods_not_flagged_as_unexpected() {
    let results = vec![
        ("HEAD".to_string(), 200u16),
        ("PATCH".to_string(), 200),
    ];
    let issues = analyze_verb_tamper(200, &results);
    assert!(issues.is_empty());
}

#[test]
fn nonstandard_method_denied_not_flagged() {
    let results = vec![("PROPFIND".to_string(), 405u16)];
    let issues = analyze_verb_tamper(200, &results);
    assert!(issues.is_empty());
}

#[test]
fn multiple_bypass_methods() {
    let results = vec![
        ("HEAD".to_string(), 200u16),
        ("PATCH".to_string(), 200),
        ("PROPFIND".to_string(), 200),
    ];
    let issues = analyze_verb_tamper(403, &results);
    assert_eq!(issues.len(), 3);
}

#[test]
fn severity_bypass_higher_than_unexpected() {
    assert!(
        verb_tamper_severity(&VerbTamperIssue::AuthBypass {
            method: "X".to_string(),
            expected_status: 403,
            actual_status: 200
        }) > verb_tamper_severity(&VerbTamperIssue::UnexpectedSuccess {
            method: "X".to_string(),
            status: 200
        })
    );
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = verb_tamper_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_created_for_issues() {
    let issues = vec![VerbTamperIssue::AuthBypass {
        method: "PATCH".to_string(),
        expected_status: 403,
        actual_status: 200,
    }];
    let mut seq = 0;
    let ops = verb_tamper_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn display_auth_bypass() {
    let issue = VerbTamperIssue::AuthBypass {
        method: "PATCH".to_string(),
        expected_status: 403,
        actual_status: 200,
    };
    assert_eq!(
        issue.to_string(),
        "verb_tamper_auth_bypass:PATCH:403->200"
    );
}

#[test]
fn display_unexpected_success() {
    let issue = VerbTamperIssue::UnexpectedSuccess {
        method: "PROPFIND".to_string(),
        status: 200,
    };
    assert_eq!(
        issue.to_string(),
        "verb_tamper_unexpected_success:PROPFIND:200"
    );
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_verb_tampering("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback() {
    let issues = audit_verb_tampering("http://127.0.0.1");
    assert!(issues.is_empty());
}
