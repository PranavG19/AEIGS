use crate::navigation_api_audit::*;

#[test]
fn no_navigation_api_no_issues() {
    assert!(analyze_navigation_api("<html></html>").is_empty());
}

#[test]
fn detects_navigate_intercept() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            e.intercept({handler() { return fetch(e.destination.url); }});
        });
    </script>"#;
    let issues = analyze_navigation_api(body);
    assert!(issues.contains(&NavigationApiIssue::NavigateIntercepted));
    assert!(issues.contains(&NavigationApiIssue::NavigateEventUsed));
}

#[test]
fn detects_navigate_event() {
    let body = r#"<script>
        const evt = new NavigateEvent("navigate", {});
    </script>"#;
    let issues = analyze_navigation_api(body);
    assert!(issues.contains(&NavigationApiIssue::NavigateEventUsed));
}

#[test]
fn detects_current_entry() {
    let body = r#"<script>const url = navigation.currentEntry.url;</script>"#;
    let issues = analyze_navigation_api(body);
    assert!(issues.contains(&NavigationApiIssue::CurrentEntryAccess));
}

#[test]
fn detects_entries_enumerated() {
    let body = r#"<script>
        const history = navigation.entries();
        history.forEach(e => console.log(e.url));
    </script>"#;
    let issues = analyze_navigation_api(body);
    assert!(issues.contains(&NavigationApiIssue::EntriesEnumerated));
}

#[test]
fn detects_transition_while() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            e.transitionWhile(fetchNewContent());
        });
    </script>"#;
    let issues = analyze_navigation_api(body);
    assert!(issues.contains(&NavigationApiIssue::TransitionWhileUsed));
}

#[test]
fn detects_back_forward() {
    let body = r#"<script>navigation.back();</script>"#;
    let issues = analyze_navigation_api(body);
    assert!(issues.contains(&NavigationApiIssue::BackForwardIntercept));
}

#[test]
fn detects_forward() {
    let body = r#"<script>navigation.forward();</script>"#;
    let issues = analyze_navigation_api(body);
    assert!(issues.contains(&NavigationApiIssue::BackForwardIntercept));
}

#[test]
fn severity_intercept_highest() {
    assert_eq!(navigation_api_severity(&NavigationApiIssue::NavigateIntercepted), 6.0);
}

#[test]
fn severity_current_entry_lowest() {
    assert_eq!(navigation_api_severity(&NavigationApiIssue::CurrentEntryAccess), 3.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        NavigationApiIssue::NavigateIntercepted,
        NavigationApiIssue::EntriesEnumerated,
    ];
    let mut seq = 0;
    let ops = navigation_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(NavigationApiIssue::NavigateIntercepted.to_string(), "navigate_intercepted");
    assert_eq!(NavigationApiIssue::NavigateEventUsed.to_string(), "navigate_event_used");
    assert_eq!(NavigationApiIssue::CurrentEntryAccess.to_string(), "current_entry_access");
    assert_eq!(NavigationApiIssue::EntriesEnumerated.to_string(), "entries_enumerated");
    assert_eq!(NavigationApiIssue::TransitionWhileUsed.to_string(), "transition_while_used");
    assert_eq!(NavigationApiIssue::BackForwardIntercept.to_string(), "back_forward_intercept");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_navigation_api("").is_empty());
}
