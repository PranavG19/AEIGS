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
    let results = vec![("HEAD".to_string(), 200u16), ("PATCH".to_string(), 200)];
    let issues = analyze_verb_tamper(200, &results);
    assert!(issues.is_empty());
}

#[test]
fn auth_bypass_detected() {
    let results = vec![("HEAD".to_string(), 403u16), ("PATCH".to_string(), 200)];
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
    assert!(
        issues
            .iter()
            .all(|i| matches!(i, VerbTamperIssue::UnexpectedSuccess { .. }))
    );
}

#[test]
fn standard_methods_not_flagged_as_unexpected() {
    let results = vec![("HEAD".to_string(), 200u16), ("PATCH".to_string(), 200)];
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
    assert_eq!(issue.to_string(), "verb_tamper_auth_bypass:PATCH:403->200");
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

// VerbTamperSecurityIssue tests

#[test]
fn trace_method_enabled_detected() {
    let issues = analyze_verb_tamper_security("TRACE", &[], 200);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        VerbTamperSecurityIssue::TraceMethodEnabled
    ));
}

#[test]
fn trace_method_case_insensitive() {
    let issues = analyze_verb_tamper_security("trace", &[], 200);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        VerbTamperSecurityIssue::TraceMethodEnabled
    ));
}

#[test]
fn trace_method_denied_no_issue() {
    let issues = analyze_verb_tamper_security("TRACE", &[], 405);
    assert!(issues.is_empty());
}

#[test]
fn connect_method_enabled_detected() {
    let issues = analyze_verb_tamper_security("CONNECT", &[], 200);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        VerbTamperSecurityIssue::ConnectMethodEnabled
    ));
}

#[test]
fn connect_method_case_insensitive() {
    let issues = analyze_verb_tamper_security("CoNnEcT", &[], 201);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        VerbTamperSecurityIssue::ConnectMethodEnabled
    ));
}

#[test]
fn patch_without_auth_detected() {
    let issues = analyze_verb_tamper_security("PATCH", &["GET", "POST"], 200);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        VerbTamperSecurityIssue::PatchWithoutAuth
    ));
}

#[test]
fn patch_with_auth_no_issue() {
    let issues = analyze_verb_tamper_security("PATCH", &["GET", "POST", "PATCH"], 200);
    assert!(issues.is_empty());
}

#[test]
fn patch_denied_no_issue() {
    let issues = analyze_verb_tamper_security("PATCH", &[], 403);
    assert!(issues.is_empty());
}

#[test]
fn delete_without_auth_detected() {
    let issues = analyze_verb_tamper_security("DELETE", &["GET", "POST"], 200);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        VerbTamperSecurityIssue::DeleteWithoutAuth
    ));
}

#[test]
fn delete_with_auth_no_issue() {
    let issues = analyze_verb_tamper_security("DELETE", &["GET", "DELETE"], 200);
    assert!(issues.is_empty());
}

#[test]
fn delete_case_insensitive() {
    let issues = analyze_verb_tamper_security("delete", &[], 204);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        VerbTamperSecurityIssue::DeleteWithoutAuth
    ));
}

#[test]
fn options_exposing_methods_detected() {
    let allowed = vec!["GET", "POST", "PUT", "DELETE"];
    let issues = analyze_verb_tamper_security("OPTIONS", &allowed, 200);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        &issues[0],
        VerbTamperSecurityIssue::OptionsExposingMethods { methods } if methods.len() == 4
    ));
}

#[test]
fn options_no_methods_no_issue() {
    let issues = analyze_verb_tamper_security("OPTIONS", &[], 200);
    assert!(issues.is_empty());
}

#[test]
fn options_denied_no_issue() {
    let issues = analyze_verb_tamper_security("OPTIONS", &["GET", "POST"], 405);
    assert!(issues.is_empty());
}

#[test]
fn head_method_bypass_detected() {
    let issues = analyze_verb_tamper_security("HEAD", &["GET", "POST"], 200);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        VerbTamperSecurityIssue::HeadMethodBypass
    ));
}

#[test]
fn head_method_allowed_no_issue() {
    let issues = analyze_verb_tamper_security("HEAD", &["GET", "HEAD"], 200);
    assert!(issues.is_empty());
}

#[test]
fn head_method_case_insensitive() {
    let issues = analyze_verb_tamper_security("head", &[], 200);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        VerbTamperSecurityIssue::HeadMethodBypass
    ));
}

#[test]
fn arbitrary_method_xmethod_detected() {
    let issues = analyze_verb_tamper_security("XMETHOD", &[], 200);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        &issues[0],
        VerbTamperSecurityIssue::ArbitraryMethodAccepted { method } if method == "XMETHOD"
    ));
}

#[test]
fn arbitrary_method_custom_detected() {
    let issues = analyze_verb_tamper_security("CUSTOM", &[], 200);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        &issues[0],
        VerbTamperSecurityIssue::ArbitraryMethodAccepted { method } if method == "CUSTOM"
    ));
}

#[test]
fn arbitrary_method_fuzz_detected() {
    let issues = analyze_verb_tamper_security("FUZZ", &[], 201);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        &issues[0],
        VerbTamperSecurityIssue::ArbitraryMethodAccepted { method } if method == "FUZZ"
    ));
}

#[test]
fn arbitrary_method_case_insensitive() {
    let issues = analyze_verb_tamper_security("xmethod", &[], 200);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        VerbTamperSecurityIssue::ArbitraryMethodAccepted { .. }
    ));
}

#[test]
fn arbitrary_method_denied_no_issue() {
    let issues = analyze_verb_tamper_security("XMETHOD", &[], 405);
    assert!(issues.is_empty());
}

#[test]
fn put_method_enabled_detected() {
    let issues = analyze_verb_tamper_security("PUT", &[], 200);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        VerbTamperSecurityIssue::PutMethodEnabled
    ));
}

#[test]
fn put_method_case_insensitive() {
    let issues = analyze_verb_tamper_security("put", &[], 201);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        VerbTamperSecurityIssue::PutMethodEnabled
    ));
}

#[test]
fn put_method_denied_no_issue() {
    let issues = analyze_verb_tamper_security("PUT", &[], 403);
    assert!(issues.is_empty());
}

#[test]
fn propfind_enabled_detected() {
    let issues = analyze_verb_tamper_security("PROPFIND", &[], 200);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        VerbTamperSecurityIssue::PropfindEnabled
    ));
}

#[test]
fn propfind_case_insensitive() {
    let issues = analyze_verb_tamper_security("propfind", &[], 207);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        VerbTamperSecurityIssue::PropfindEnabled
    ));
}

#[test]
fn propfind_denied_no_issue() {
    let issues = analyze_verb_tamper_security("PROPFIND", &[], 405);
    assert!(issues.is_empty());
}

#[test]
fn security_severity_delete_highest() {
    let delete_issue = VerbTamperSecurityIssue::DeleteWithoutAuth;
    let put_issue = VerbTamperSecurityIssue::PutMethodEnabled;
    assert!(
        verb_tamper_security_severity(&delete_issue) > verb_tamper_security_severity(&put_issue)
    );
}

#[test]
fn security_severity_options_lowest() {
    let options_issue = VerbTamperSecurityIssue::OptionsExposingMethods {
        methods: vec!["GET".to_string()],
    };
    let trace_issue = VerbTamperSecurityIssue::TraceMethodEnabled;
    assert!(
        verb_tamper_security_severity(&options_issue) < verb_tamper_security_severity(&trace_issue)
    );
}

#[test]
fn security_operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = verb_tamper_security_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn security_operations_created_for_issues() {
    let issues = vec![
        VerbTamperSecurityIssue::TraceMethodEnabled,
        VerbTamperSecurityIssue::PutMethodEnabled,
    ];
    let mut seq = 0;
    let ops = verb_tamper_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_operations_increment_sequence() {
    let issues = vec![VerbTamperSecurityIssue::PropfindEnabled];
    let mut seq = 42;
    let ops = verb_tamper_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 43);
}

#[test]
fn display_trace_method_enabled() {
    let issue = VerbTamperSecurityIssue::TraceMethodEnabled;
    assert_eq!(issue.to_string(), "verb_tamper_trace_enabled");
}

#[test]
fn display_connect_method_enabled() {
    let issue = VerbTamperSecurityIssue::ConnectMethodEnabled;
    assert_eq!(issue.to_string(), "verb_tamper_connect_enabled");
}

#[test]
fn display_patch_without_auth() {
    let issue = VerbTamperSecurityIssue::PatchWithoutAuth;
    assert_eq!(issue.to_string(), "verb_tamper_patch_no_auth");
}

#[test]
fn display_delete_without_auth() {
    let issue = VerbTamperSecurityIssue::DeleteWithoutAuth;
    assert_eq!(issue.to_string(), "verb_tamper_delete_no_auth");
}

#[test]
fn display_options_exposing_methods() {
    let issue = VerbTamperSecurityIssue::OptionsExposingMethods {
        methods: vec!["GET".to_string(), "POST".to_string(), "DELETE".to_string()],
    };
    assert_eq!(
        issue.to_string(),
        "verb_tamper_options_exposing:GET,POST,DELETE"
    );
}

#[test]
fn display_head_method_bypass() {
    let issue = VerbTamperSecurityIssue::HeadMethodBypass;
    assert_eq!(issue.to_string(), "verb_tamper_head_bypass");
}

#[test]
fn display_arbitrary_method_accepted() {
    let issue = VerbTamperSecurityIssue::ArbitraryMethodAccepted {
        method: "XMETHOD".to_string(),
    };
    assert_eq!(issue.to_string(), "verb_tamper_arbitrary_method:XMETHOD");
}

#[test]
fn display_method_override_via_header() {
    let issue = VerbTamperSecurityIssue::MethodOverrideViaHeader;
    assert_eq!(issue.to_string(), "verb_tamper_method_override_header");
}

#[test]
fn display_put_method_enabled() {
    let issue = VerbTamperSecurityIssue::PutMethodEnabled;
    assert_eq!(issue.to_string(), "verb_tamper_put_enabled");
}

#[test]
fn display_propfind_enabled() {
    let issue = VerbTamperSecurityIssue::PropfindEnabled;
    assert_eq!(issue.to_string(), "verb_tamper_propfind_enabled");
}

#[test]
fn multiple_issues_from_same_method() {
    let issues = analyze_verb_tamper_security("PROPFIND", &[], 200);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        VerbTamperSecurityIssue::PropfindEnabled
    ));
}

#[test]
fn get_method_no_security_issues() {
    let issues = analyze_verb_tamper_security("GET", &[], 200);
    assert!(issues.is_empty());
}

#[test]
fn post_method_no_security_issues() {
    let issues = analyze_verb_tamper_security("POST", &[], 200);
    assert!(issues.is_empty());
}

#[test]
fn status_299_considered_success() {
    let issues = analyze_verb_tamper_security("TRACE", &[], 299);
    assert_eq!(issues.len(), 1);
}

#[test]
fn status_300_not_success() {
    let issues = analyze_verb_tamper_security("TRACE", &[], 300);
    assert!(issues.is_empty());
}

#[test]
fn status_199_not_success() {
    let issues = analyze_verb_tamper_security("TRACE", &[], 199);
    assert!(issues.is_empty());
}
