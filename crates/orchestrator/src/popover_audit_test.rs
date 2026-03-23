use crate::popover_audit::*;

#[test]
fn no_popover_no_issues() {
    assert!(analyze_popover("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_popover_attribute() {
    let body = r#"<div popover="auto">Content</div>"#;
    let issues = analyze_popover(body);
    assert!(issues.contains(&PopoverIssue::ApiDetected));
}

#[test]
fn detects_show_popover_api() {
    let body = r#"<script>el.showPopover();</script>"#;
    let issues = analyze_popover(body);
    assert!(issues.contains(&PopoverIssue::ApiDetected));
}

#[test]
fn detects_popovertarget() {
    let body = r#"<button popovertarget="info">Show Info</button>
        <div id="info" popover="auto">Info content</div>"#;
    let issues = analyze_popover(body);
    assert!(issues.contains(&PopoverIssue::ApiDetected));
}

#[test]
fn detects_content_spoofing() {
    let body = r#"<div popover="auto" style="position: fixed; z-index: 9999;">
        Fake login form
    </div>"#;
    let issues = analyze_popover(body);
    assert!(issues.contains(&PopoverIssue::ContentSpoofing));
}

#[test]
fn no_spoofing_without_positioning() {
    let body = r#"<div popover="auto">Simple tooltip</div>"#;
    let issues = analyze_popover(body);
    assert!(!issues.contains(&PopoverIssue::ContentSpoofing));
}

#[test]
fn detects_clickjacking_overlay() {
    let body = r#"<div popover="manual" style="pointer-events: none; opacity: 0;">
        Hidden overlay
    </div>
    <script>el.showPopover();</script>"#;
    let issues = analyze_popover(body);
    assert!(issues.contains(&PopoverIssue::ClickjackingOverlay));
}

#[test]
fn no_clickjacking_without_opacity() {
    let body = r#"<div popover="auto" style="pointer-events: none;">tooltip</div>"#;
    let issues = analyze_popover(body);
    assert!(!issues.contains(&PopoverIssue::ClickjackingOverlay));
}

#[test]
fn detects_auto_show_on_load() {
    let body = r#"<script>
        document.addEventListener("DOMContentLoaded", () => {
            document.getElementById("ad").showPopover();
        });
    </script>"#;
    let issues = analyze_popover(body);
    assert!(issues.contains(&PopoverIssue::AutoShowOnLoad));
}

#[test]
fn detects_auto_show_window_onload() {
    let body = r#"<script>
        window.onload = () => { popup.showPopover(); };
    </script>"#;
    let issues = analyze_popover(body);
    assert!(issues.contains(&PopoverIssue::AutoShowOnLoad));
}

#[test]
fn no_auto_show_without_load_event() {
    let body = r#"<script>button.onclick = () => popup.showPopover();</script>"#;
    let issues = analyze_popover(body);
    assert!(!issues.contains(&PopoverIssue::AutoShowOnLoad));
}

#[test]
fn detects_unsanitized_content() {
    let body = r#"<div popover="auto" id="tip"></div>
    <script>tip.innerHTML = userInput;</script>"#;
    let issues = analyze_popover(body);
    assert!(issues.contains(&PopoverIssue::UnsanitizedContent));
}

#[test]
fn no_unsanitized_with_sanitize() {
    let body = r#"<div popover="auto" id="tip"></div>
    <script>tip.innerHTML = sanitize(userInput);</script>"#;
    let issues = analyze_popover(body);
    assert!(!issues.contains(&PopoverIssue::UnsanitizedContent));
}

#[test]
fn detects_nested_popover() {
    let body = r#"<div popover="manual" id="p1">
        <button popovertarget="p2">Nest</button>
        <div popover="manual" id="p2">
            <div popover="manual" id="p3">Deep</div>
        </div>
    </div>"#;
    let issues = analyze_popover(body);
    assert!(issues.contains(&PopoverIssue::NestedPopover));
}

#[test]
fn no_nested_with_single_popover() {
    let body = r#"<div popover="manual" id="p1">Content</div>
        <button popovertarget="p1">Toggle</button>"#;
    let issues = analyze_popover(body);
    assert!(!issues.contains(&PopoverIssue::NestedPopover));
}

#[test]
fn severity_unsanitized_highest() {
    assert_eq!(popover_severity(&PopoverIssue::UnsanitizedContent), 7.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(popover_severity(&PopoverIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![PopoverIssue::ApiDetected, PopoverIssue::ContentSpoofing];
    let mut seq = 0;
    let ops = popover_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(PopoverIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(PopoverIssue::ContentSpoofing.to_string(), "content_spoofing");
    assert_eq!(PopoverIssue::ClickjackingOverlay.to_string(), "clickjacking_overlay");
    assert_eq!(PopoverIssue::AutoShowOnLoad.to_string(), "auto_show_on_load");
    assert_eq!(PopoverIssue::UnsanitizedContent.to_string(), "unsanitized_content");
    assert_eq!(PopoverIssue::NestedPopover.to_string(), "nested_popover");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_popover("").is_empty());
}
