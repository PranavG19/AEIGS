use crate::sanitizer_api_audit::*;

#[test]
fn no_sanitizer_no_issues() {
    assert!(analyze_sanitizer_api("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_sanitizer_constructor() {
    let body = r#"<script>const s = new Sanitizer(); el.setHTML(input, {sanitizer: s});</script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(issues.contains(&SanitizerApiIssue::ApiDetected));
}

#[test]
fn detects_set_html_only() {
    let body = r#"<script>el.setHTML(userInput);</script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(issues.contains(&SanitizerApiIssue::ApiDetected));
}

#[test]
fn detects_sanitize_for() {
    let body = r#"<script>const result = Sanitizer.sanitizeFor("div", input);</script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(issues.contains(&SanitizerApiIssue::ApiDetected));
}

#[test]
fn detects_permissive_config_wildcard() {
    let body = r#"<script>
        const s = new Sanitizer({allowElements: ["*"]});
        el.setHTML(input, {sanitizer: s});
    </script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(issues.contains(&SanitizerApiIssue::PermissiveConfig));
}

#[test]
fn detects_permissive_config_spread() {
    let body = r#"<script>
        const s = new Sanitizer({allowAttributes: {...allAttrs}});
        el.setHTML(input, {sanitizer: s});
    </script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(issues.contains(&SanitizerApiIssue::PermissiveConfig));
}

#[test]
fn no_permissive_with_specific_elements() {
    let body = r#"<script>
        const s = new Sanitizer({allowElements: ["p", "b", "i"]});
        el.setHTML(input, {sanitizer: s});
    </script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(!issues.contains(&SanitizerApiIssue::PermissiveConfig));
}

#[test]
fn detects_script_allowed() {
    let body = r#"<script>
        const s = new Sanitizer({allowElements: ["script", "div"]});
    </script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(issues.contains(&SanitizerApiIssue::ScriptAllowed));
}

#[test]
fn detects_script_allowed_single_quotes() {
    let body = r#"<script>
        const s = new Sanitizer({allowElements: ['script']});
    </script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(issues.contains(&SanitizerApiIssue::ScriptAllowed));
}

#[test]
fn no_script_with_safe_elements() {
    let body = r#"<script>
        const s = new Sanitizer({allowElements: ["p", "div"]});
    </script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(!issues.contains(&SanitizerApiIssue::ScriptAllowed));
}

#[test]
fn detects_event_handler_onload() {
    let body = r#"<script>
        const s = new Sanitizer({allowAttributes: {"onload": ["img"]}});
    </script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(issues.contains(&SanitizerApiIssue::EventHandlerAllowed));
}

#[test]
fn detects_event_handler_onclick() {
    let body = r#"<script>
        const s = new Sanitizer({allowAttributes: {'onclick': ['*']}});
    </script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(issues.contains(&SanitizerApiIssue::EventHandlerAllowed));
}

#[test]
fn detects_event_handler_onerror() {
    let body = r#"<script>
        const s = new Sanitizer({allowAttributes: {"onerror": ["img"]}});
    </script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(issues.contains(&SanitizerApiIssue::EventHandlerAllowed));
}

#[test]
fn no_event_handler_with_safe_attrs() {
    let body = r#"<script>
        const s = new Sanitizer({allowAttributes: {"class": ["*"]}});
    </script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(!issues.contains(&SanitizerApiIssue::EventHandlerAllowed));
}

#[test]
fn detects_custom_element_risk() {
    let body = r#"<script>
        customElements.define("my-el", MyEl);
        el.setHTML(input);
    </script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(issues.contains(&SanitizerApiIssue::CustomElementRisk));
}

#[test]
fn no_custom_element_without_define() {
    let body = r#"<script>el.setHTML(input);</script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(!issues.contains(&SanitizerApiIssue::CustomElementRisk));
}

#[test]
fn detects_sanitization_bypassed() {
    let body = r#"<script>
        const s = new Sanitizer();
        el.innerHTML = userInput;
    </script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(issues.contains(&SanitizerApiIssue::SanitizationBypassed));
}

#[test]
fn no_bypass_when_using_set_html() {
    let body = r#"<script>
        const s = new Sanitizer();
        el.setHTML(userInput, {sanitizer: s});
    </script>"#;
    let issues = analyze_sanitizer_api(body);
    assert!(!issues.contains(&SanitizerApiIssue::SanitizationBypassed));
}

#[test]
fn severity_script_highest() {
    assert_eq!(sanitizer_api_severity(&SanitizerApiIssue::ScriptAllowed), 9.0);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(sanitizer_api_severity(&SanitizerApiIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![SanitizerApiIssue::ApiDetected, SanitizerApiIssue::ScriptAllowed];
    let mut seq = 0;
    let ops = sanitizer_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(SanitizerApiIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(SanitizerApiIssue::PermissiveConfig.to_string(), "permissive_config");
    assert_eq!(SanitizerApiIssue::ScriptAllowed.to_string(), "script_allowed");
    assert_eq!(SanitizerApiIssue::EventHandlerAllowed.to_string(), "event_handler_allowed");
    assert_eq!(SanitizerApiIssue::CustomElementRisk.to_string(), "custom_element_risk");
    assert_eq!(SanitizerApiIssue::SanitizationBypassed.to_string(), "sanitization_bypassed");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_sanitizer_api("").is_empty());
}
