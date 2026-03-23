use crate::selection_audit::*;

#[test]
fn no_selection_no_issues() {
    assert!(analyze_selection("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api() {
    let body = r#"<script>const sel = window.getSelection();</script>"#;
    let issues = analyze_selection(body);
    assert!(issues.contains(&SelectionIssue::ApiDetected));
}

#[test]
fn detects_exfiltration() {
    let body = r#"<script>
        const sel = window.getSelection();
        fetch("/track?text=" + sel.toString());
    </script>"#;
    let issues = analyze_selection(body);
    assert!(issues.contains(&SelectionIssue::SelectionExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const sel = window.getSelection();
        console.log(sel.toString());
    </script>"#;
    let issues = analyze_selection(body);
    assert!(!issues.contains(&SelectionIssue::SelectionExfiltration));
}

#[test]
fn detects_clipboard_hijack() {
    let body = r#"<script>
        window.getSelection();
        document.execCommand("copy");
    </script>"#;
    let issues = analyze_selection(body);
    assert!(issues.contains(&SelectionIssue::ClipboardHijack));
}

#[test]
fn detects_clipboard_write_text() {
    let body = r#"<script>
        const sel = window.getSelection();
        navigator.clipboard.writeText(sel.toString());
    </script>"#;
    let issues = analyze_selection(body);
    assert!(issues.contains(&SelectionIssue::ClipboardHijack));
}

#[test]
fn detects_hidden_text() {
    let body = r#"<div style="visibility:hidden">secret</div>
    <script>window.getSelection();</script>"#;
    let issues = analyze_selection(body);
    assert!(issues.contains(&SelectionIssue::HiddenTextSelection));
}

#[test]
fn detects_continuous_monitoring() {
    let body = r#"<script>
        document.addEventListener("selectionchange", () => {
            const sel = window.getSelection();
        });
    </script>"#;
    let issues = analyze_selection(body);
    assert!(issues.contains(&SelectionIssue::ContinuousMonitoring));
}

#[test]
fn detects_range_manipulation() {
    let body = r#"<script>
        const sel = window.getSelection();
        const range = document.createRange();
        sel.addRange(range);
    </script>"#;
    let issues = analyze_selection(body);
    assert!(issues.contains(&SelectionIssue::RangeManipulation));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        selection_severity(&SelectionIssue::SelectionExfiltration),
        6.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(selection_severity(&SelectionIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![SelectionIssue::ApiDetected, SelectionIssue::ClipboardHijack];
    let mut seq = 0;
    let ops = selection_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(SelectionIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        SelectionIssue::SelectionExfiltration.to_string(),
        "selection_exfiltration"
    );
    assert_eq!(
        SelectionIssue::ClipboardHijack.to_string(),
        "clipboard_hijack"
    );
    assert_eq!(
        SelectionIssue::HiddenTextSelection.to_string(),
        "hidden_text_selection"
    );
    assert_eq!(
        SelectionIssue::ContinuousMonitoring.to_string(),
        "continuous_monitoring"
    );
    assert_eq!(
        SelectionIssue::RangeManipulation.to_string(),
        "range_manipulation"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_selection("").is_empty());
}
