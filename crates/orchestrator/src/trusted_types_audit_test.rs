use crate::trusted_types_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_trusted_types("", "");
    assert!(issues.is_empty());
}

#[test]
fn api_detected_trusted_types() {
    let body = "const policy = window.trustedTypes.createPolicy('test', {});";
    let issues = analyze_trusted_types("", body);
    assert!(issues.contains(&TrustedTypesIssue::ApiDetected));
}

#[test]
fn api_detected_trusted_html() {
    let body = "let html: TrustedHTML = policy.createHTML('<div>safe</div>');";
    let issues = analyze_trusted_types("", body);
    assert!(issues.contains(&TrustedTypesIssue::ApiDetected));
}

#[test]
fn api_detected_trusted_script() {
    let body = "const script: TrustedScript = policy.createScript('alert(1)');";
    let issues = analyze_trusted_types("", body);
    assert!(issues.contains(&TrustedTypesIssue::ApiDetected));
}

#[test]
fn api_detected_trusted_script_url() {
    let body = "const url: TrustedScriptURL = policy.createScriptURL('/script.js');";
    let issues = analyze_trusted_types("", body);
    assert!(issues.contains(&TrustedTypesIssue::ApiDetected));
}

#[test]
fn api_detected_create_policy() {
    let body = "trustedTypes.createPolicy('safe', { createHTML: (s) => s });";
    let issues = analyze_trusted_types("", body);
    assert!(issues.contains(&TrustedTypesIssue::ApiDetected));
}

#[test]
fn missing_enforcement_with_api() {
    let body = "const policy = trustedTypes.createPolicy('test', {});";
    let issues = analyze_trusted_types("", body);
    assert!(issues.contains(&TrustedTypesIssue::MissingEnforcement));
}

#[test]
fn no_missing_enforcement_when_present_in_csp() {
    let csp = "require-trusted-types-for 'script'";
    let body = "const policy = trustedTypes.createPolicy('test', {});";
    let issues = analyze_trusted_types(csp, body);
    assert!(!issues.contains(&TrustedTypesIssue::MissingEnforcement));
}

#[test]
fn no_missing_enforcement_when_present_in_body() {
    let body = r#"
        <meta http-equiv="Content-Security-Policy" content="require-trusted-types-for 'script'">
        const policy = trustedTypes.createPolicy('test', {});
    "#;
    let issues = analyze_trusted_types("", body);
    assert!(!issues.contains(&TrustedTypesIssue::MissingEnforcement));
}

#[test]
fn default_policy_bypass_single_quotes() {
    let body = "trustedTypes.createPolicy('default', { createHTML: (s) => s });";
    let issues = analyze_trusted_types("", body);
    assert!(issues.contains(&TrustedTypesIssue::DefaultPolicyBypass));
}

#[test]
fn default_policy_bypass_double_quotes() {
    let body = "trustedTypes.createPolicy(\"default\", { createHTML: (s) => s });";
    let issues = analyze_trusted_types("", body);
    assert!(issues.contains(&TrustedTypesIssue::DefaultPolicyBypass));
}

#[test]
fn named_policy_no_bypass() {
    let body = "trustedTypes.createPolicy('myPolicy', { createHTML: (s) => sanitize(s) });";
    let issues = analyze_trusted_types("", body);
    assert!(!issues.contains(&TrustedTypesIssue::DefaultPolicyBypass));
}

#[test]
fn unsafe_policy_return_input() {
    let body = "createPolicy('test', { createHTML: (input) => { return input; } });";
    let issues = analyze_trusted_types("", body);
    assert!(issues.contains(&TrustedTypesIssue::UnsafePolicyNoSanitization));
}

#[test]
fn unsafe_policy_return_value() {
    let body = "createPolicy('test', { createScript: (value) => { return value; } });";
    let issues = analyze_trusted_types("", body);
    assert!(issues.contains(&TrustedTypesIssue::UnsafePolicyNoSanitization));
}

#[test]
fn safe_policy_with_sanitization() {
    let body =
        "createPolicy('test', { createHTML: (input) => { return DOMPurify.sanitize(input); } });";
    let issues = analyze_trusted_types("", body);
    assert!(!issues.contains(&TrustedTypesIssue::UnsafePolicyNoSanitization));
}

#[test]
fn xss_sink_inner_html_without_api() {
    let body = "element.innerHTML = userInput;";
    let issues = analyze_trusted_types("", body);
    assert!(issues.contains(&TrustedTypesIssue::XssSinkWithoutTrustedTypes));
}

#[test]
fn xss_sink_eval_without_api() {
    let body = "eval(userInput);";
    let issues = analyze_trusted_types("", body);
    assert!(issues.contains(&TrustedTypesIssue::XssSinkWithoutTrustedTypes));
}

#[test]
fn xss_sink_document_write_without_api() {
    let body = "document.write('<script>' + userInput + '</script>');";
    let issues = analyze_trusted_types("", body);
    assert!(issues.contains(&TrustedTypesIssue::XssSinkWithoutTrustedTypes));
}

#[test]
fn xss_sink_with_api_not_flagged() {
    let body = "element.innerHTML = policy.createHTML(userInput);";
    let issues = analyze_trusted_types("", body);
    assert!(!issues.contains(&TrustedTypesIssue::XssSinkWithoutTrustedTypes));
}

#[test]
fn severity_ordering() {
    assert!(trusted_types_severity(&TrustedTypesIssue::DefaultPolicyBypass) > 7.5);
    assert!(trusted_types_severity(&TrustedTypesIssue::UnsafePolicyNoSanitization) > 7.0);
    assert!(trusted_types_severity(&TrustedTypesIssue::XssSinkWithoutTrustedTypes) > 6.5);
    assert!(trusted_types_severity(&TrustedTypesIssue::MissingEnforcement) > 6.0);
    assert!(trusted_types_severity(&TrustedTypesIssue::ApiDetected) < 3.0);
}

#[test]
fn display_format() {
    assert_eq!(TrustedTypesIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        TrustedTypesIssue::MissingEnforcement.to_string(),
        "missing_enforcement"
    );
    assert_eq!(
        TrustedTypesIssue::DefaultPolicyBypass.to_string(),
        "default_policy_bypass"
    );
    assert_eq!(
        TrustedTypesIssue::UnsafePolicyNoSanitization.to_string(),
        "unsafe_policy_no_sanitization"
    );
    assert_eq!(
        TrustedTypesIssue::XssSinkWithoutTrustedTypes.to_string(),
        "xss_sink_without_trusted_types"
    );
}

#[test]
fn to_operations_empty() {
    let issues = vec![];
    let mut seq = 0u64;
    let ops = trusted_types_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn to_operations_single_issue() {
    let issues = vec![TrustedTypesIssue::ApiDetected];
    let mut seq = 5u64;
    let ops = trusted_types_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}

#[test]
fn to_operations_multiple_issues() {
    let issues = vec![
        TrustedTypesIssue::ApiDetected,
        TrustedTypesIssue::MissingEnforcement,
        TrustedTypesIssue::DefaultPolicyBypass,
    ];
    let mut seq = 0u64;
    let ops = trusted_types_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn combined_issues_realistic_scenario() {
    let body = r#"
        const policy = trustedTypes.createPolicy('default', {
            createHTML: (input) => { return input; }
        });
        element.innerHTML = policy.createHTML(userContent);
    "#;
    let issues = analyze_trusted_types("", body);
    assert!(issues.contains(&TrustedTypesIssue::ApiDetected));
    assert!(issues.contains(&TrustedTypesIssue::MissingEnforcement));
    assert!(issues.contains(&TrustedTypesIssue::DefaultPolicyBypass));
    assert!(issues.contains(&TrustedTypesIssue::UnsafePolicyNoSanitization));
}

#[test]
fn no_false_positive_on_safe_code() {
    let csp = "require-trusted-types-for 'script'; trusted-types safePolicy";
    let body = r#"
        const policy = trustedTypes.createPolicy('safePolicy', {
            createHTML: (input) => DOMPurify.sanitize(input)
        });
        element.innerHTML = policy.createHTML(userContent);
    "#;
    let issues = analyze_trusted_types(csp, body);
    assert_eq!(issues.len(), 1);
    assert!(issues.contains(&TrustedTypesIssue::ApiDetected));
}
