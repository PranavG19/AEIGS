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

#[test]
pub fn security_empty_body_no_issues() {
    let issues = analyze_drag_drop_security("");
    assert!(issues.is_empty());
}

#[test]
pub fn security_no_drag_keywords() {
    let body = "<html><body>No drag operations here</body></html>";
    let issues = analyze_drag_drop_security(body);
    assert!(issues.is_empty());
}

#[test]
pub fn detects_drag_data_exfiltration_with_fetch() {
    let body = r#"
        var data = e.dataTransfer.getData('text');
        fetch('/exfil', {method:'POST', body: data});
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragDataExfiltration));
}

#[test]
pub fn detects_drag_data_exfiltration_with_xhr() {
    let body = r#"
        var data = e.dataTransfer.items[0];
        var xhr = new XMLHttpRequest();
        xhr.send(data);
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragDataExfiltration));
}

#[test]
pub fn no_exfiltration_without_network() {
    let body = "var data = e.dataTransfer.getData('text'); console.log(data);";
    let issues = analyze_drag_drop_security(body);
    assert!(!issues.contains(&DragDropSecurityIssue::DragDataExfiltration));
}

#[test]
pub fn detects_drag_cross_origin() {
    let body = r#"
        e.dataTransfer.setData('text', secret);
        window.parent.postMessage(data, '*');
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragCrossOrigin));
}

#[test]
pub fn no_cross_origin_without_postmessage() {
    let body = "e.dataTransfer.setData('text', data);";
    let issues = analyze_drag_drop_security(body);
    assert!(!issues.contains(&DragDropSecurityIssue::DragCrossOrigin));
}

#[test]
pub fn detects_drag_hidden_content_btoa() {
    let body = r#"
        var encoded = btoa(secret);
        e.dataTransfer.setData('text', encoded);
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragHiddenContent));
}

#[test]
pub fn detects_drag_hidden_content_base64() {
    let body = r#"
        var encoded = base64Encode(data);
        e.dataTransfer.setData('text/plain', encoded);
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragHiddenContent));
}

#[test]
pub fn detects_drag_hidden_content_encodeuri() {
    let body = r#"
        e.dataTransfer.setData('text', encodeURIComponent(secret));
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragHiddenContent));
}

#[test]
pub fn no_hidden_content_without_encoding() {
    let body = "e.dataTransfer.setData('text', plaintext);";
    let issues = analyze_drag_drop_security(body);
    assert!(!issues.contains(&DragDropSecurityIssue::DragHiddenContent));
}

#[test]
pub fn detects_drop_zone_phishing_password() {
    let body = r#"
        <div ondrop="steal()">Drop your password here</div>
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DropZonePhishing));
}

#[test]
pub fn detects_drop_zone_phishing_credentials() {
    let body = r#"
        <div class="drop-zone" ondrop="capture">Drop your credentials here</div>
        e.dataTransfer.getData('text');
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DropZonePhishing));
}

#[test]
pub fn detects_drop_zone_phishing_login() {
    let body = r#"
        <div ondrop="capture()">Drop login information</div>
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DropZonePhishing));
}

#[test]
pub fn no_phishing_without_sensitive_terms() {
    let body = "<div ondrop='handler'>Drop files here</div>";
    let issues = analyze_drag_drop_security(body);
    assert!(!issues.contains(&DragDropSecurityIssue::DropZonePhishing));
}

#[test]
pub fn detects_drag_without_user_interaction() {
    let body = r#"
        var evt = new DragEvent('dragstart', {dataTransfer: dt});
        element.dispatchEvent(evt);
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragWithoutUserInteraction));
}

#[test]
pub fn no_synthetic_drag_without_dispatch() {
    let body = "var evt = new DragEvent('dragstart');";
    let issues = analyze_drag_drop_security(body);
    assert!(!issues.contains(&DragDropSecurityIssue::DragWithoutUserInteraction));
}

#[test]
pub fn detects_drag_file_access_files_property() {
    let body = r#"
        var files = e.dataTransfer.files;
        for (var i = 0; i < files.length; i++) { process(files[i]); }
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragFileAccess));
}

#[test]
pub fn detects_drag_file_access_filereader() {
    let body = r#"
        var file = e.dataTransfer.files[0];
        var reader = new FileReader();
        reader.readAsText(file);
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragFileAccess));
}

#[test]
pub fn no_file_access_without_files_api() {
    let body = "e.dataTransfer.getData('text/plain');";
    let issues = analyze_drag_drop_security(body);
    assert!(!issues.contains(&DragDropSecurityIssue::DragFileAccess));
}

#[test]
pub fn detects_drag_clipboard_overwrite() {
    let body = r#"
        e.dataTransfer.setData('text/plain', malicious);
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragClipboardOverwrite));
}

#[test]
pub fn no_clipboard_overwrite_without_text_plain() {
    let body = "e.dataTransfer.setData('application/json', data);";
    let issues = analyze_drag_drop_security(body);
    assert!(!issues.contains(&DragDropSecurityIssue::DragClipboardOverwrite));
}

#[test]
pub fn detects_drag_in_iframe_ondrop() {
    let body = r#"
        <iframe src="evil.com"></iframe>
        <div ondrop="handler">Drop here</div>
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragInIframe));
}

#[test]
pub fn detects_drag_in_iframe_ondragstart() {
    let body = r#"
        <iframe id="target"></iframe>
        <div ondragstart="start">Drag me</div>
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragInIframe));
}

#[test]
pub fn no_iframe_issue_without_drag() {
    let body = "<iframe src='page.html'></iframe>";
    let issues = analyze_drag_drop_security(body);
    assert!(!issues.contains(&DragDropSecurityIssue::DragInIframe));
}

#[test]
pub fn detects_drag_sensitive_data_password() {
    let body = r#"
        var password = e.dataTransfer.getData('text');
        validate(password);
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragSensitiveData));
}

#[test]
pub fn detects_drag_sensitive_data_credit() {
    let body = r#"
        var credit_card = e.dataTransfer.items[0];
        process(credit_card);
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragSensitiveData));
}

#[test]
pub fn detects_drag_sensitive_data_token() {
    let body = r#"
        var token = e.dataTransfer.getData('text/plain');
        authenticate(token);
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragSensitiveData));
}

#[test]
pub fn detects_drag_sensitive_data_apikey() {
    let body = r#"
        var apikey = e.dataTransfer.getData('text');
        callApi(apikey);
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragSensitiveData));
}

#[test]
pub fn no_sensitive_data_without_patterns() {
    let body = "var data = e.dataTransfer.getData('text'); console.log(data);";
    let issues = analyze_drag_drop_security(body);
    assert!(!issues.contains(&DragDropSecurityIssue::DragSensitiveData));
}

#[test]
pub fn detects_drag_event_spying_multiple_listeners() {
    let body = r#"
        element.addEventListener('dragstart', log);
        element.addEventListener('drop', log);
        e.dataTransfer.getData('text');
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragEventSpying));
}

#[test]
pub fn detects_drag_event_spying_on_attributes() {
    let body = r#"
        <div ondragstart="spy()" ondragend="spy()">text</div>
        e.dataTransfer.setData('text', data);
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragEventSpying));
}

#[test]
pub fn detects_drag_event_spying_mixed_styles() {
    let body = r#"
        <div ondragstart="log()">Drag</div>
        element.addEventListener('drop', track);
        e.dataTransfer.getData('text');
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragEventSpying));
}

#[test]
pub fn no_spying_with_single_listener() {
    let body = "element.addEventListener('drop', handler); e.dataTransfer.getData('text');";
    let issues = analyze_drag_drop_security(body);
    assert!(!issues.contains(&DragDropSecurityIssue::DragEventSpying));
}

#[test]
pub fn security_display_all_variants() {
    assert_eq!(
        DragDropSecurityIssue::DragDataExfiltration.to_string(),
        "drag_data_exfiltration"
    );
    assert_eq!(
        DragDropSecurityIssue::DragCrossOrigin.to_string(),
        "drag_cross_origin"
    );
    assert_eq!(
        DragDropSecurityIssue::DragHiddenContent.to_string(),
        "drag_hidden_content"
    );
    assert_eq!(
        DragDropSecurityIssue::DropZonePhishing.to_string(),
        "drop_zone_phishing"
    );
    assert_eq!(
        DragDropSecurityIssue::DragWithoutUserInteraction.to_string(),
        "drag_without_user_interaction"
    );
    assert_eq!(
        DragDropSecurityIssue::DragFileAccess.to_string(),
        "drag_file_access"
    );
    assert_eq!(
        DragDropSecurityIssue::DragClipboardOverwrite.to_string(),
        "drag_clipboard_overwrite"
    );
    assert_eq!(
        DragDropSecurityIssue::DragInIframe.to_string(),
        "drag_in_iframe"
    );
    assert_eq!(
        DragDropSecurityIssue::DragSensitiveData.to_string(),
        "drag_sensitive_data"
    );
    assert_eq!(
        DragDropSecurityIssue::DragEventSpying.to_string(),
        "drag_event_spying"
    );
}

#[test]
pub fn security_severity_highest() {
    assert_eq!(
        drag_drop_security_severity(&DragDropSecurityIssue::DragDataExfiltration),
        9.0
    );
}

#[test]
pub fn security_severity_lowest() {
    assert_eq!(
        drag_drop_security_severity(&DragDropSecurityIssue::DragClipboardOverwrite),
        3.0
    );
}

#[test]
pub fn security_severity_mid_range() {
    assert_eq!(
        drag_drop_security_severity(&DragDropSecurityIssue::DragCrossOrigin),
        7.0
    );
    assert_eq!(
        drag_drop_security_severity(&DragDropSecurityIssue::DragFileAccess),
        8.0
    );
}

#[test]
pub fn security_to_operations_creates_entries() {
    let issues = vec![
        DragDropSecurityIssue::DragDataExfiltration,
        DragDropSecurityIssue::DragFileAccess,
        DragDropSecurityIssue::DragSensitiveData,
    ];
    let mut seq = 0;
    let ops = drag_drop_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
pub fn security_to_operations_empty_list() {
    let issues: Vec<DragDropSecurityIssue> = vec![];
    let mut seq = 0;
    let ops = drag_drop_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
pub fn detects_multiple_security_issues() {
    let body = r#"
        var data = e.dataTransfer.getData('text');
        var password = data;
        fetch('/exfil', {method:'POST', body: password});
        window.parent.postMessage(data, '*');
    "#;
    let issues = analyze_drag_drop_security(body);
    assert!(issues.contains(&DragDropSecurityIssue::DragDataExfiltration));
    assert!(issues.contains(&DragDropSecurityIssue::DragSensitiveData));
    assert!(issues.contains(&DragDropSecurityIssue::DragCrossOrigin));
    assert!(issues.len() >= 3);
}
