use crate::drag_drop_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_drag_drop("");
    assert!(issues.is_empty());
}

#[test]
fn no_drag_api_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_drag_drop(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_drop_event_data_access() {
    let body = "e.dataTransfer.getData('text/plain')";
    let issues = analyze_drag_drop(body);
    assert!(issues.contains(&DragDropIssue::DropEventDataAccess));
}

#[test]
fn detects_drop_event_items() {
    let body = "e.dataTransfer.items[0].getAsString(cb)";
    let issues = analyze_drag_drop(body);
    assert!(issues.contains(&DragDropIssue::DropEventDataAccess));
}

#[test]
fn detects_drag_start_data_set() {
    let body = "e.dataTransfer.setData('text/plain', secret)";
    let issues = analyze_drag_drop(body);
    assert!(issues.contains(&DragDropIssue::DragStartDataSet));
}

#[test]
fn detects_cross_origin_drag_data() {
    let body = "e.dataTransfer.setData('text/uri-list', url)";
    let issues = analyze_drag_drop(body);
    assert!(issues.contains(&DragDropIssue::CrossOriginDragData));
}

#[test]
fn detects_cross_origin_html() {
    let body = "e.dataTransfer.getData('text/html')";
    let issues = analyze_drag_drop(body);
    assert!(issues.contains(&DragDropIssue::CrossOriginDragData));
}

#[test]
fn detects_drag_data_exfiltration() {
    let body = r#"
        var data = e.dataTransfer.getData('text');
        fetch('/collect', {method:'POST', body: data});
    "#;
    let issues = analyze_drag_drop(body);
    assert!(issues.contains(&DragDropIssue::DragDataExfiltration));
}

#[test]
fn detects_hidden_drop_zone() {
    let body = r#"<div style="opacity:0" ondrop="steal(e)">Drop here</div>"#;
    let issues = analyze_drag_drop(body);
    assert!(issues.contains(&DragDropIssue::HiddenDropZone));
}

#[test]
fn detects_hidden_drop_zone_via_hidden() {
    let body = r#"<div class="hidden" ondrop="steal(e)">text</div>
        e.dataTransfer.getData('text')"#;
    let issues = analyze_drag_drop(body);
    assert!(issues.contains(&DragDropIssue::HiddenDropZone));
}

#[test]
fn detects_dragover_prevent_default() {
    let body = r#"
        el.addEventListener('dragover', function(e) { e.preventDefault(); });
        e.dataTransfer.getData('text');
    "#;
    let issues = analyze_drag_drop(body);
    assert!(issues.contains(&DragDropIssue::DragOverPreventDefault));
}

#[test]
fn detects_clipboard_via_drag() {
    let body = "e.dataTransfer; e.clipboardData.getData('text')";
    let issues = analyze_drag_drop(body);
    assert!(issues.contains(&DragDropIssue::ClipboardViaDrag));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        drag_drop_severity(&DragDropIssue::DragDataExfiltration),
        7.5
    );
}

#[test]
fn severity_dragover_lowest() {
    assert_eq!(
        drag_drop_severity(&DragDropIssue::DragOverPreventDefault),
        3.5
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        DragDropIssue::DropEventDataAccess,
        DragDropIssue::DragStartDataSet,
    ];
    let mut seq = 0;
    let ops = drag_drop_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        DragDropIssue::DropEventDataAccess.to_string(),
        "drop_event_data_access"
    );
    assert_eq!(
        DragDropIssue::DragDataExfiltration.to_string(),
        "drag_data_exfiltration"
    );
    assert_eq!(
        DragDropIssue::HiddenDropZone.to_string(),
        "hidden_drop_zone"
    );
    assert_eq!(
        DragDropIssue::ClipboardViaDrag.to_string(),
        "clipboard_via_drag"
    );
}
