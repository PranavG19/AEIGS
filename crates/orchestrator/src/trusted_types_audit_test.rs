use crate::trusted_types_audit::*;

#[test]
fn empty_csp_and_body_no_issues() {
    assert!(analyze_trusted_types("", "").is_empty());
}

#[test]
fn no_sinks_no_tt_no_issue() {
    let body = "<h1>Hello World</h1>";
    assert!(analyze_trusted_types("", body).is_empty());
}

#[test]
fn dangerous_sinks_without_tt_flagged() {
    let body = "element.innerHTML = userInput;";
    let issues = analyze_trusted_types("", body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, TrustedTypesIssue::MissingTrustedTypes)));
}

#[test]
fn dangerous_sinks_with_tt_not_flagged_missing() {
    let body = "element.innerHTML = userInput;";
    let csp = "require-trusted-types-for 'script'; trusted-types default";
    let issues = analyze_trusted_types(csp, body);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, TrustedTypesIssue::MissingTrustedTypes)));
}

#[test]
fn allow_duplicates_detected() {
    let csp = "trusted-types default 'allow-duplicates'";
    let issues = analyze_trusted_types(csp, "");
    assert!(issues
        .iter()
        .any(|i| matches!(i, TrustedTypesIssue::AllowDuplicates)));
}

#[test]
fn wildcard_policy_detected() {
    let csp = "trusted-types *";
    let issues = analyze_trusted_types(csp, "");
    assert!(issues
        .iter()
        .any(|i| matches!(i, TrustedTypesIssue::DefaultPolicyWildcard)));
}

#[test]
fn named_policy_no_wildcard() {
    let csp = "trusted-types myPolicy";
    let issues = analyze_trusted_types(csp, "");
    assert!(!issues
        .iter()
        .any(|i| matches!(i, TrustedTypesIssue::DefaultPolicyWildcard)));
}

#[test]
fn unsafe_eval_with_tt() {
    let csp =
        "trusted-types default; script-src 'self' 'unsafe-eval'";
    let issues = analyze_trusted_types(csp, "");
    assert!(issues
        .iter()
        .any(|i| matches!(i, TrustedTypesIssue::TrustedTypesWithUnsafeEval)));
}

#[test]
fn unsafe_eval_without_tt_not_flagged() {
    let csp = "script-src 'self' 'unsafe-eval'";
    let issues = analyze_trusted_types(csp, "");
    assert!(!issues
        .iter()
        .any(|i| matches!(i, TrustedTypesIssue::TrustedTypesWithUnsafeEval)));
}

#[test]
fn unsafe_sink_reported_once() {
    let body = "document.write(x); element.innerHTML = y;";
    let issues = analyze_trusted_types("", body);
    let sink_count = issues
        .iter()
        .filter(|i| matches!(i, TrustedTypesIssue::UnsafeSinkWithoutPolicy { .. }))
        .count();
    assert_eq!(sink_count, 1);
}

#[test]
fn document_write_sink_detected() {
    let body = "document.write('<script>alert(1)</script>');";
    let issues = analyze_trusted_types("", body);
    assert!(issues.iter().any(|i| matches!(
        i,
        TrustedTypesIssue::UnsafeSinkWithoutPolicy { sink } if sink == "document.write"
    )));
}

#[test]
fn eval_sink_detected() {
    let body = "eval(userInput);";
    let issues = analyze_trusted_types("", body);
    assert!(issues.iter().any(|i| matches!(
        i,
        TrustedTypesIssue::UnsafeSinkWithoutPolicy { sink } if sink == "eval("
    )));
}

#[test]
fn require_trusted_types_directive() {
    let csp = "default-src 'self'; require-trusted-types-for 'script'";
    let body = "element.innerHTML = x;";
    let issues = analyze_trusted_types(csp, body);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, TrustedTypesIssue::MissingTrustedTypes)));
}

#[test]
fn severity_ordering() {
    assert!(
        trusted_types_severity(&TrustedTypesIssue::DefaultPolicyWildcard)
            > trusted_types_severity(&TrustedTypesIssue::TrustedTypesWithUnsafeEval)
    );
    assert!(
        trusted_types_severity(&TrustedTypesIssue::TrustedTypesWithUnsafeEval)
            > trusted_types_severity(&TrustedTypesIssue::MissingTrustedTypes)
    );
}

#[test]
fn display_format() {
    let issue = TrustedTypesIssue::MissingTrustedTypes;
    assert_eq!(issue.to_string(), "missing_trusted_types");

    let issue = TrustedTypesIssue::UnsafeSinkWithoutPolicy {
        sink: ".innerHTML".into(),
    };
    assert_eq!(issue.to_string(), "unsafe_sink_no_tt:.innerHTML");
}

#[test]
fn to_operations_count() {
    let issues = vec![
        TrustedTypesIssue::MissingTrustedTypes,
        TrustedTypesIssue::UnsafeSinkWithoutPolicy {
            sink: "eval(".into(),
        },
    ];
    let mut seq = 0;
    let ops = trusted_types_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn multiple_directives_csp() {
    let csp = "default-src 'self'; trusted-types myPolicy; script-src 'self'";
    let body = "x.innerHTML = y;";
    let issues = analyze_trusted_types(csp, body);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, TrustedTypesIssue::MissingTrustedTypes)));
}
