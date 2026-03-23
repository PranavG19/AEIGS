use crate::structured_clone_audit::*;

#[test]
fn test_api_detected_structured_clone() {
    let body = "const clone = structuredClone(obj);";
    let issues = analyze_structured_clone(body);
    assert_eq!(issues, vec![StructuredCloneIssue::ApiDetected]);
}

#[test]
fn test_api_detected_post_message() {
    let body = "window.postMessage(data, '*');";
    let issues = analyze_structured_clone(body);
    assert_eq!(issues, vec![StructuredCloneIssue::ApiDetected]);
}

#[test]
fn test_api_detected_message_channel() {
    let body = "const channel = new MessageChannel();";
    let issues = analyze_structured_clone(body);
    assert_eq!(issues, vec![StructuredCloneIssue::ApiDetected]);
}

#[test]
fn test_prototype_pollution_proto() {
    let body = "const clone = structuredClone(obj); clone.__proto__ = malicious;";
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(issues.contains(&StructuredCloneIssue::PrototypePollution));
}

#[test]
fn test_prototype_pollution_constructor() {
    let body = "postMessage(data); data.constructor.prototype.polluted = true;";
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(issues.contains(&StructuredCloneIssue::PrototypePollution));
}

#[test]
fn test_prototype_pollution_object_assign() {
    let body = "MessageChannel(); Object.assign(target, source);";
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(issues.contains(&StructuredCloneIssue::PrototypePollution));
}

#[test]
fn test_sensitive_data_password() {
    let body = "structuredClone({username: user, password: pass});";
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(issues.contains(&StructuredCloneIssue::SensitiveDataClone));
}

#[test]
fn test_sensitive_data_token() {
    let body = "postMessage({token: authToken}, origin);";
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(issues.contains(&StructuredCloneIssue::SensitiveDataClone));
}

#[test]
fn test_sensitive_data_multiple() {
    let body = "MessageChannel(); const data = {secret: s, apiKey: k};";
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(issues.contains(&StructuredCloneIssue::SensitiveDataClone));
}

#[test]
fn test_cross_origin_leak() {
    let body = "postMessage(data, 'https://evil.com');";
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(issues.contains(&StructuredCloneIssue::CrossOriginLeak));
}

#[test]
fn test_cross_origin_leak_http() {
    let body = "structuredClone(obj); postMessage(obj, 'http://attacker.com');";
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(issues.contains(&StructuredCloneIssue::CrossOriginLeak));
}

#[test]
fn test_cross_origin_safe_with_origin_check() {
    let body = "postMessage(data, 'https://example.com'); if (event.origin === expected) {}";
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(!issues.contains(&StructuredCloneIssue::CrossOriginLeak));
}

#[test]
fn test_cross_origin_safe_with_same_origin() {
    let body = "postMessage(data, 'https://example.com'); window.parent.same-origin";
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(!issues.contains(&StructuredCloneIssue::CrossOriginLeak));
}

#[test]
fn test_large_object_dos() {
    let body = "while (true) { structuredClone(bigArray); }";
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(issues.contains(&StructuredCloneIssue::LargeObjectDos));
}

#[test]
fn test_large_object_dos_for_loop() {
    let body = "for (let i = 0; i < n; i++) { structuredClone(data); }";
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(issues.contains(&StructuredCloneIssue::LargeObjectDos));
}

#[test]
fn test_large_object_dos_map() {
    let body = "Array.from(items).map(x => structuredClone(x));";
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(issues.contains(&StructuredCloneIssue::LargeObjectDos));
}

#[test]
fn test_large_object_safe_with_limit() {
    let body = "if (size < limit) { structuredClone(obj); } while (processing) {}";
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(!issues.contains(&StructuredCloneIssue::LargeObjectDos));
}

#[test]
fn test_large_object_safe_with_slice() {
    let body = "structuredClone(arr.slice(0, 100)); for (let i = 0; i < n; i++) {}";
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(!issues.contains(&StructuredCloneIssue::LargeObjectDos));
}

#[test]
fn test_no_issues_clean_code() {
    let body = "const data = {name: 'test'}; console.log(data);";
    let issues = analyze_structured_clone(body);
    assert!(issues.is_empty());
}

#[test]
fn test_multiple_issues_combined() {
    let body = r#"
        while (true) {
            const clone = structuredClone({password: p, __proto__: evil});
            postMessage(clone, 'https://attacker.com');
        }
    "#;
    let issues = analyze_structured_clone(body);
    assert!(issues.contains(&StructuredCloneIssue::ApiDetected));
    assert!(issues.contains(&StructuredCloneIssue::PrototypePollution));
    assert!(issues.contains(&StructuredCloneIssue::SensitiveDataClone));
    assert!(issues.contains(&StructuredCloneIssue::CrossOriginLeak));
    assert!(issues.contains(&StructuredCloneIssue::LargeObjectDos));
    assert_eq!(issues.len(), 5);
}

#[test]
fn test_structured_clone_to_operations() {
    let issues = vec![
        StructuredCloneIssue::ApiDetected,
        StructuredCloneIssue::PrototypePollution,
    ];
    let mut seq = 0u64;
    let ops = structured_clone_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
}

#[test]
fn test_severity_values() {
    assert_eq!(
        structured_clone_severity(&StructuredCloneIssue::ApiDetected),
        2.0
    );
    assert_eq!(
        structured_clone_severity(&StructuredCloneIssue::PrototypePollution),
        7.5
    );
    assert_eq!(
        structured_clone_severity(&StructuredCloneIssue::SensitiveDataClone),
        7.0
    );
    assert_eq!(
        structured_clone_severity(&StructuredCloneIssue::CrossOriginLeak),
        6.5
    );
    assert_eq!(
        structured_clone_severity(&StructuredCloneIssue::LargeObjectDos),
        5.5
    );
}
