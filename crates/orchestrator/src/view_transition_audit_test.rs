use crate::view_transition_audit::*;

#[test]
fn test_no_view_transition_api() {
    let body = "<html><body>Normal page</body></html>";
    let issues = analyze_view_transition(body);
    assert!(issues.is_empty());
}

#[test]
fn test_api_detected_start_view_transition() {
    let body = r#"
        <script>
            document.startViewTransition(() => {
                updateDOM();
            });
        </script>
    "#;
    let issues = analyze_view_transition(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], ViewTransitionIssue::ApiDetected);
}

#[test]
fn test_api_detected_view_transition_class() {
    let body = r#"
        <script>
            const transition = new ViewTransition();
        </script>
    "#;
    let issues = analyze_view_transition(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], ViewTransitionIssue::ApiDetected);
}

#[test]
fn test_api_detected_css_property() {
    let body = r#"
        <style>
            .card { view-transition-name: card-expand; }
        </style>
    "#;
    let issues = analyze_view_transition(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], ViewTransitionIssue::ApiDetected);
}

#[test]
fn test_dom_manipulation_inner_html() {
    let body = r#"
        <script>
            document.startViewTransition(() => {
                element.innerHTML = userContent;
            });
        </script>
    "#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::ApiDetected));
    assert!(issues.contains(&ViewTransitionIssue::DomManipulationInCallback));
}

#[test]
fn test_dom_manipulation_document_write() {
    let body = r#"
        <script>
            const vt = new ViewTransition();
            document.write(content);
        </script>
    "#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::ApiDetected));
    assert!(issues.contains(&ViewTransitionIssue::DomManipulationInCallback));
}

#[test]
fn test_sensitive_content_password() {
    let body = r#"
        <script>
            document.startViewTransition(() => {
                showPasswordField();
            });
        </script>
    "#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::ApiDetected));
    assert!(issues.contains(&ViewTransitionIssue::SensitiveContentExposure));
}

#[test]
fn test_sensitive_content_token() {
    let body = r#"
        <style>.auth { view-transition-name: auth; }</style>
        <script>const token = getAuthToken();</script>
    "#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::ApiDetected));
    assert!(issues.contains(&ViewTransitionIssue::SensitiveContentExposure));
}

#[test]
fn test_sensitive_content_secret() {
    let body = r#"
        <script>
            ViewTransition.prototype.start = function() {
                loadSecret();
            };
        </script>
    "#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::ApiDetected));
    assert!(issues.contains(&ViewTransitionIssue::SensitiveContentExposure));
}

#[test]
fn test_cross_document_without_origin_check() {
    let body = r#"
        <script>
            navigation.addEventListener('navigate', (e) => {
                document.startViewTransition(() => loadContent());
            });
        </script>
    "#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::ApiDetected));
    assert!(issues.contains(&ViewTransitionIssue::CrossDocumentWithoutOriginCheck));
}

#[test]
fn test_cross_document_with_origin_check() {
    let body = r#"
        <script>
            navigation.addEventListener('navigate', (e) => {
                if (e.destination.url.origin === location.origin) {
                    document.startViewTransition(() => loadContent());
                }
            });
        </script>
    "#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::ApiDetected));
    assert!(!issues.contains(&ViewTransitionIssue::CrossDocumentWithoutOriginCheck));
}

#[test]
fn test_transition_callback_override_update_callback_done() {
    let body = r#"
        <script>
            const vt = document.startViewTransition(update);
            vt.updateCallbackDone = Promise.resolve();
        </script>
    "#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::ApiDetected));
    assert!(issues.contains(&ViewTransitionIssue::TransitionCallbackOverride));
}

#[test]
fn test_transition_callback_override_ready() {
    let body = r#"
        <script>
            ViewTransition.ready = customPromise;
        </script>
    "#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::ApiDetected));
    assert!(issues.contains(&ViewTransitionIssue::TransitionCallbackOverride));
}

#[test]
fn test_transition_callback_override_finished() {
    let body = r#"
        <script>
            document.startViewTransition(() => {}).finished = interceptor();
        </script>
    "#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::ApiDetected));
    assert!(issues.contains(&ViewTransitionIssue::TransitionCallbackOverride));
}

#[test]
fn test_multiple_issues_combined() {
    let body = r#"
        <style>.card { view-transition-name: card; }</style>
        <script>
            navigation.addEventListener('navigate', () => {
                const vt = document.startViewTransition(() => {
                    element.innerHTML = getPasswordForm();
                });
                vt.finished = hijackedPromise;
            });
        </script>
    "#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::ApiDetected));
    assert!(issues.contains(&ViewTransitionIssue::DomManipulationInCallback));
    assert!(issues.contains(&ViewTransitionIssue::SensitiveContentExposure));
    assert!(issues.contains(&ViewTransitionIssue::CrossDocumentWithoutOriginCheck));
    assert!(issues.contains(&ViewTransitionIssue::TransitionCallbackOverride));
    assert_eq!(issues.len(), 5);
}

#[test]
fn test_to_operations() {
    let issues = vec![
        ViewTransitionIssue::ApiDetected,
        ViewTransitionIssue::DomManipulationInCallback,
    ];
    let mut seq = 0u64;
    let ops = view_transition_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn test_severity_api_detected() {
    let severity = view_transition_severity(&ViewTransitionIssue::ApiDetected);
    assert_eq!(severity, 2.0);
}

#[test]
fn test_severity_dom_manipulation() {
    let severity = view_transition_severity(&ViewTransitionIssue::DomManipulationInCallback);
    assert_eq!(severity, 7.0);
}

#[test]
fn test_severity_cross_document() {
    let severity = view_transition_severity(&ViewTransitionIssue::CrossDocumentWithoutOriginCheck);
    assert_eq!(severity, 8.0);
}

#[test]
fn test_display_formatting() {
    assert_eq!(ViewTransitionIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        ViewTransitionIssue::DomManipulationInCallback.to_string(),
        "dom_manipulation_in_callback"
    );
    assert_eq!(
        ViewTransitionIssue::SensitiveContentExposure.to_string(),
        "sensitive_content_exposure"
    );
    assert_eq!(
        ViewTransitionIssue::CrossDocumentWithoutOriginCheck.to_string(),
        "cross_document_without_origin_check"
    );
    assert_eq!(
        ViewTransitionIssue::TransitionCallbackOverride.to_string(),
        "transition_callback_override"
    );
}

#[test]
fn test_empty_body() {
    let body = "";
    let issues = analyze_view_transition(body);
    assert!(issues.is_empty());
}

#[test]
fn test_no_false_positive_without_api() {
    let body = r#"
        <script>
            element.innerHTML = content;
            const password = getPassword();
        </script>
    "#;
    let issues = analyze_view_transition(body);
    assert!(issues.is_empty());
}

#[test]
fn test_callback_override_without_assignment() {
    let body = r#"
        <script>
            document.startViewTransition(() => {
                console.log(vt.ready);
            });
        </script>
    "#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::ApiDetected));
    assert!(issues.contains(&ViewTransitionIssue::TransitionCallbackOverride));
}
