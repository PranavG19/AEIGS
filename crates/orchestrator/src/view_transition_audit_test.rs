use crate::view_transition_audit::*;

#[test]
fn no_view_transition_no_issues() {
    assert!(analyze_view_transition("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_start_view_transition() {
    let body = r#"<script>document.startViewTransition(() => updateDOM());</script>"#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::ApiDetected));
}

#[test]
fn detects_css_view_transition_name() {
    let body = r#"<style>.hero { view-transition-name: hero; }</style>"#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::ApiDetected));
}

#[test]
fn detects_view_transition_pseudo() {
    let body = r#"<style>::view-transition-old(hero) { animation: fade-out 0.3s; }</style>"#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::ApiDetected));
}

#[test]
fn detects_cross_document_transition() {
    let body = r#"<style>@view-transition { navigation: auto; }</style>"#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::CrossDocumentTransition));
}

#[test]
fn no_cross_document_without_navigation() {
    let body = r#"<style>.hero { view-transition-name: hero; }</style>"#;
    let issues = analyze_view_transition(body);
    assert!(!issues.contains(&ViewTransitionIssue::CrossDocumentTransition));
}

#[test]
fn detects_ui_spoofing() {
    let body = r#"<script>document.startViewTransition(() => {});</script>
        <style>.overlay { position: fixed; z-index: 9999; }</style>"#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::UiSpoofing));
}

#[test]
fn detects_ui_spoofing_opacity() {
    let body = r#"<style>
        .fake { view-transition-name: main; position: absolute; opacity: 0; }
    </style>"#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::UiSpoofing));
}

#[test]
fn no_spoofing_without_positioning() {
    let body = r#"<script>document.startViewTransition(() => {});</script>"#;
    let issues = analyze_view_transition(body);
    assert!(!issues.contains(&ViewTransitionIssue::UiSpoofing));
}

#[test]
fn detects_transition_hijacking() {
    let body = r#"<script>
        const t = document.startViewTransition(() => {});
        t.ready.then(() => { el.innerHTML = malicious; });
    </script>"#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::TransitionHijacking));
}

#[test]
fn detects_hijacking_with_remove() {
    let body = r#"<script>
        const t = document.startViewTransition(() => {});
        t.finished.then(() => { target.remove(); });
    </script>"#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::TransitionHijacking));
}

#[test]
fn no_hijacking_without_dom_mutation() {
    let body = r#"<script>
        const t = document.startViewTransition(() => {});
        t.ready.then(() => console.log("done"));
    </script>"#;
    let issues = analyze_view_transition(body);
    assert!(!issues.contains(&ViewTransitionIssue::TransitionHijacking));
}

#[test]
fn detects_timing_leak() {
    let body = r#"<script>
        const start = performance.now();
        const t = document.startViewTransition(() => {});
        t.finished.then(() => { const elapsed = performance.now() - start; });
    </script>"#;
    let issues = analyze_view_transition(body);
    assert!(issues.contains(&ViewTransitionIssue::TimingLeak));
}

#[test]
fn no_timing_without_perf() {
    let body = r#"<script>
        const t = document.startViewTransition(() => {});
        t.finished.then(() => console.log("done"));
    </script>"#;
    let issues = analyze_view_transition(body);
    assert!(!issues.contains(&ViewTransitionIssue::TimingLeak));
}

#[test]
fn severity_hijacking_highest() {
    assert_eq!(view_transition_severity(&ViewTransitionIssue::TransitionHijacking), 7.0);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(view_transition_severity(&ViewTransitionIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![ViewTransitionIssue::ApiDetected, ViewTransitionIssue::UiSpoofing];
    let mut seq = 0;
    let ops = view_transition_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(ViewTransitionIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(ViewTransitionIssue::CrossDocumentTransition.to_string(), "cross_document_transition");
    assert_eq!(ViewTransitionIssue::UiSpoofing.to_string(), "ui_spoofing");
    assert_eq!(ViewTransitionIssue::TransitionHijacking.to_string(), "transition_hijacking");
    assert_eq!(ViewTransitionIssue::TimingLeak.to_string(), "timing_leak");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_view_transition("").is_empty());
}
