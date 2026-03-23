use crate::clipboard_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_clipboard("");
    assert!(issues.is_empty());
}

#[test]
fn no_clipboard_no_issues() {
    let body = "var x = document.title;";
    let issues = analyze_clipboard(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_clipboard_read() {
    let body = "navigator.clipboard.readText().then(text => console.log(text));";
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::ClipboardReadAccess));
}

#[test]
fn detects_clipboard_read_blob() {
    let body = "navigator.clipboard.read().then(data => {});";
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::ClipboardReadAccess));
}

#[test]
fn detects_clipboard_write() {
    let body = "navigator.clipboard.writeText('hello');";
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::ClipboardWriteAccess));
}

#[test]
fn detects_clipboard_write_blob() {
    let body = "navigator.clipboard.write([item]);";
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::ClipboardWriteAccess));
}

#[test]
fn detects_paste_event_listener() {
    let body = r#"document.addEventListener("paste", function(e) { });"#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::PasteEventIntercepted));
}

#[test]
fn detects_paste_event_single_quote() {
    let body = "document.addEventListener('paste', handler);";
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::PasteEventIntercepted));
}

#[test]
fn detects_onpaste_handler() {
    let body = r#"<input onpaste="handlePaste(event)">"#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::PasteEventIntercepted));
}

#[test]
fn detects_copy_event_listener() {
    let body = r#"document.addEventListener("copy", function(e) { });"#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::CopyEventIntercepted));
}

#[test]
fn detects_oncopy_handler() {
    let body = r#"<div oncopy="modifyCopy(event)">text</div>"#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::CopyEventIntercepted));
}

#[test]
fn detects_exec_command_copy() {
    let body = r#"document.execCommand("copy");"#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::ExecCommandCopy));
}

#[test]
fn detects_exec_command_paste() {
    let body = r#"document.execCommand("paste");"#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::ExecCommandPaste));
}

#[test]
fn detects_exfiltration_pattern() {
    let body = r#"
        navigator.clipboard.readText().then(text => {
            fetch('/api/log', { method: 'POST', body: text });
        });
    "#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::ClipboardDataExfiltration));
}

#[test]
fn detects_exfiltration_with_clipboard_data() {
    let body = r#"
        document.addEventListener('paste', function(e) {
            var data = e.clipboardData.getData('text');
            var xhr = new XMLHttpRequest();
            xhr.send(data);
        });
    "#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::ClipboardDataExfiltration));
}

#[test]
fn no_exfiltration_without_send() {
    let body = "navigator.clipboard.readText().then(text => console.log(text));";
    let issues = analyze_clipboard(body);
    assert!(!issues.contains(&ClipboardIssue::ClipboardDataExfiltration));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        clipboard_severity(&ClipboardIssue::ClipboardDataExfiltration),
        8.0
    );
}

#[test]
fn severity_exec_copy_lowest() {
    assert_eq!(clipboard_severity(&ClipboardIssue::ExecCommandCopy), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ClipboardIssue::ClipboardReadAccess,
        ClipboardIssue::ClipboardDataExfiltration,
    ];
    let mut seq = 0;
    let ops = clipboard_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(ClipboardIssue::ClipboardReadAccess.to_string(), "clipboard_read");
    assert_eq!(ClipboardIssue::ClipboardWriteAccess.to_string(), "clipboard_write");
    assert_eq!(
        ClipboardIssue::PasteEventIntercepted.to_string(),
        "paste_intercepted"
    );
    assert_eq!(
        ClipboardIssue::CopyEventIntercepted.to_string(),
        "copy_intercepted"
    );
    assert_eq!(ClipboardIssue::ExecCommandCopy.to_string(), "exec_command_copy");
    assert_eq!(ClipboardIssue::ExecCommandPaste.to_string(), "exec_command_paste");
    assert_eq!(
        ClipboardIssue::ClipboardDataExfiltration.to_string(),
        "clipboard_exfiltration"
    );
}
