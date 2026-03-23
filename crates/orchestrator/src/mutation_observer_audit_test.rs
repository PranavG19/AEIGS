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
