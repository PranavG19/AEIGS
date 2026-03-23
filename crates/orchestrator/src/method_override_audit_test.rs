use crate::method_override_audit::*;

#[test]
fn same_status_no_issue() {
    let issues = analyze_method_override(200, 200, "header:X-HTTP-Method-Override", "DELETE");
    assert!(issues.is_empty());
}

#[test]
fn header_override_detected() {
    let issues = analyze_method_override(200, 405, "header:X-HTTP-Method-Override", "DELETE");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::HeaderOverrideAccepted { header, method }
            if header == "X-HTTP-Method-Override" && method == "DELETE"
    )));
}

#[test]
fn param_override_detected() {
    let issues = analyze_method_override(200, 405, "param:_method", "PUT");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::QueryParamOverrideAccepted { param, method }
            if param == "_method" && method == "PUT"
    )));
}

#[test]
fn response_alteration_detected_success_to_error() {
    let issues = analyze_method_override(200, 405, "header:X-Method-Override", "DELETE");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::MethodChangeAltersResponse { .. }
    )));
}

#[test]
fn response_alteration_detected_error_to_success() {
    let issues = analyze_method_override(404, 200, "header:X-HTTP-Method", "PUT");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::MethodChangeAltersResponse { .. }
    )));
}

#[test]
fn no_alteration_when_both_success() {
    let issues = analyze_method_override(200, 201, "header:X-HTTP-Method-Override", "PUT");
    assert!(!issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::MethodChangeAltersResponse { .. }
    )));
}

#[test]
fn no_alteration_when_both_error() {
    let issues = analyze_method_override(404, 405, "header:X-HTTP-Method-Override", "DELETE");
    assert!(!issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::MethodChangeAltersResponse { .. }
    )));
}

#[test]
fn severity_ordering() {
    assert!(
        method_override_severity(&MethodOverrideIssue::MethodChangeAltersResponse {
            override_type: "header".into(),
            method: "DELETE".into()
        }) > method_override_severity(&MethodOverrideIssue::HeaderOverrideAccepted {
            header: "X-HTTP-Method-Override".into(),
            method: "DELETE".into()
        })
    );
    assert!(
        method_override_severity(&MethodOverrideIssue::HeaderOverrideAccepted {
            header: "X-HTTP-Method".into(),
            method: "PUT".into()
        }) > method_override_severity(&MethodOverrideIssue::QueryParamOverrideAccepted {
            param: "_method".into(),
            method: "PUT".into()
        })
    );
}

#[test]
fn to_operations_produces_entries() {
    let issues = vec![
        MethodOverrideIssue::HeaderOverrideAccepted {
            header: "X-HTTP-Method-Override".into(),
            method: "DELETE".into(),
        },
    ];
    let mut seq = 30;
    let ops = method_override_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 31);
}

#[test]
fn display_header_override() {
    let issue = MethodOverrideIssue::HeaderOverrideAccepted {
        header: "X-HTTP-Method-Override".into(),
        method: "DELETE".into(),
    };
    assert_eq!(
        issue.to_string(),
        "method_override_header:X-HTTP-Method-Override=DELETE"
    );
}

#[test]
fn display_param_override() {
    let issue = MethodOverrideIssue::QueryParamOverrideAccepted {
        param: "_method".into(),
        method: "PUT".into(),
    };
    assert_eq!(issue.to_string(), "method_override_param:_method=PUT");
}

#[test]
fn display_method_change() {
    let issue = MethodOverrideIssue::MethodChangeAltersResponse {
        override_type: "header:X-HTTP-Method".into(),
        method: "PATCH".into(),
    };
    assert_eq!(
        issue.to_string(),
        "method_override_effect:header:X-HTTP-Method=PATCH"
    );
}
