use crate::dialog_element_audit::*;

#[test]
fn test_no_dialog_api() {
    let body = "<div>Normal content</div>";
    let issues = analyze_dialog_element(body);
    assert!(issues.is_empty());
}

#[test]
fn test_api_detected_dialog_tag() {
    let body = "<dialog>Content</dialog>";
    let issues = analyze_dialog_element(body);
    assert_eq!(issues, vec![DialogElementIssue::ApiDetected]);
}

#[test]
fn test_api_detected_show_modal() {
    let body = "dialog.showModal();";
    let issues = analyze_dialog_element(body);
    assert_eq!(issues, vec![DialogElementIssue::ApiDetected]);
}

#[test]
fn test_api_detected_show_popover() {
    let body = "element.showPopover();";
    let issues = analyze_dialog_element(body);
    assert_eq!(issues, vec![DialogElementIssue::ApiDetected]);
}

#[test]
fn test_api_detected_html_dialog_element() {
    let body = "const d = new HTMLDialogElement();";
    let issues = analyze_dialog_element(body);
    assert_eq!(issues, vec![DialogElementIssue::ApiDetected]);
}

#[test]
fn test_xss_in_dialog_inner_html() {
    let body = "<dialog>x</dialog><script>dialog.innerHTML = data;</script>";
    let issues = analyze_dialog_element(body);
    assert!(issues.contains(&DialogElementIssue::XssInDialog));
}

#[test]
fn test_xss_in_dialog_insert_adjacent_html() {
    let body = "<dialog>x</dialog><script>dialog.insertAdjacentHTML('beforeend', x);</script>";
    let issues = analyze_dialog_element(body);
    assert!(issues.contains(&DialogElementIssue::XssInDialog));
}

#[test]
fn test_xss_in_dialog_document_write() {
    let body = "<dialog>x</dialog><script>document.write(x);</script>";
    let issues = analyze_dialog_element(body);
    assert!(issues.contains(&DialogElementIssue::XssInDialog));
}

#[test]
fn test_no_xss_with_sanitization() {
    let body = "<dialog>x</dialog><script>dialog.innerHTML = DOMPurify.sanitize(data);</script>";
    let issues = analyze_dialog_element(body);
    assert!(!issues.contains(&DialogElementIssue::XssInDialog));
}

#[test]
fn test_clickjacking_via_modal() {
    let body = "<dialog>x</dialog><script>dialog.showModal();</script><style>.overlay{opacity:0.5;}</style>";
    let issues = analyze_dialog_element(body);
    assert!(issues.contains(&DialogElementIssue::ClickjackingViaModal));
}

#[test]
fn test_clickjacking_transparent() {
    let body = "<dialog>x</dialog><script>dialog.showModal();</script><style>.overlay{background:transparent;}</style>";
    let issues = analyze_dialog_element(body);
    assert!(issues.contains(&DialogElementIssue::ClickjackingViaModal));
}

#[test]
fn test_form_hijacking() {
    let body = "<dialog><form action=\"https://evil.com\">Submit</form></dialog>";
    let issues = analyze_dialog_element(body);
    assert!(issues.contains(&DialogElementIssue::FormHijacking));
}

#[test]
fn test_no_form_hijacking_with_method_dialog() {
    let body = "<dialog><form method=\"dialog\" action=\"https://example.com\">Submit</form></dialog>";
    let issues = analyze_dialog_element(body);
    assert!(!issues.contains(&DialogElementIssue::FormHijacking));
}

#[test]
fn test_focus_trap() {
    let body = "<dialog>x</dialog><script>dialog.showModal();input.focus();</script>";
    let issues = analyze_dialog_element(body);
    assert!(issues.contains(&DialogElementIssue::FocusTrap));
}

#[test]
fn test_no_focus_trap_with_close() {
    let body = "<dialog>x</dialog><script>dialog.showModal();input.focus();btn.addEventListener('click',()=>dialog.close());</script>";
    let issues = analyze_dialog_element(body);
    assert!(!issues.contains(&DialogElementIssue::FocusTrap));
}

#[test]
fn test_severity_values() {
    assert_eq!(dialog_element_severity(&DialogElementIssue::ApiDetected), 2.0);
    assert_eq!(dialog_element_severity(&DialogElementIssue::XssInDialog), 8.0);
    assert_eq!(dialog_element_severity(&DialogElementIssue::ClickjackingViaModal), 7.0);
    assert_eq!(dialog_element_severity(&DialogElementIssue::FormHijacking), 7.5);
    assert_eq!(dialog_element_severity(&DialogElementIssue::FocusTrap), 5.5);
}

#[test]
fn test_to_operations() {
    let issues = vec![DialogElementIssue::ApiDetected, DialogElementIssue::XssInDialog];
    let mut seq = 1;
    let ops = dialog_element_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 3);
}

#[test]
fn test_display_formatting() {
    assert_eq!(DialogElementIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(DialogElementIssue::XssInDialog.to_string(), "xss_in_dialog");
    assert_eq!(DialogElementIssue::ClickjackingViaModal.to_string(), "clickjacking_via_modal");
    assert_eq!(DialogElementIssue::FormHijacking.to_string(), "form_hijacking");
    assert_eq!(DialogElementIssue::FocusTrap.to_string(), "focus_trap");
}
