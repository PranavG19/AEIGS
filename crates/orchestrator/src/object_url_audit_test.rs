use crate::object_url_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_object_urls("");
    assert!(issues.is_empty());
}

#[test]
fn detects_create_object_url() {
    let body = r#"var url = URL.createObjectURL(blob);"#;
    let issues = analyze_object_urls(body);
    assert!(issues.contains(&ObjectUrlIssue::CreateObjectUrl));
}

#[test]
fn detects_revoke_not_called() {
    let body = r#"var url = URL.createObjectURL(blob); document.body.src = url;"#;
    let issues = analyze_object_urls(body);
    assert!(issues.contains(&ObjectUrlIssue::RevokeNotCalled));
}

#[test]
fn revoke_present_no_issue() {
    let body = r#"
        var url = URL.createObjectURL(blob);
        URL.revokeObjectURL(url);
    "#;
    let issues = analyze_object_urls(body);
    assert!(issues.contains(&ObjectUrlIssue::CreateObjectUrl));
    assert!(!issues.contains(&ObjectUrlIssue::RevokeNotCalled));
}

#[test]
fn detects_blob_url_in_script() {
    let body = r#"<script src="blob:https://example.com/abc123"></script>"#;
    let issues = analyze_object_urls(body);
    assert!(issues.contains(&ObjectUrlIssue::BlobUrlInScript));
}

#[test]
fn detects_blob_url_single_quote_script() {
    let body = r#"<script src='blob:https://example.com/abc123'></script>"#;
    let issues = analyze_object_urls(body);
    assert!(issues.contains(&ObjectUrlIssue::BlobUrlInScript));
}

#[test]
fn detects_blob_url_unquoted_script() {
    let body = r#"<script src=blob:https://example.com/abc123></script>"#;
    let issues = analyze_object_urls(body);
    assert!(issues.contains(&ObjectUrlIssue::BlobUrlInScript));
}

#[test]
fn detects_blob_url_in_iframe() {
    let body = r#"<iframe src="blob:https://example.com/abc123"></iframe>"#;
    let issues = analyze_object_urls(body);
    assert!(issues.contains(&ObjectUrlIssue::BlobUrlInIframe));
}

#[test]
fn detects_blob_url_single_quote_iframe() {
    let body = r#"<iframe src='blob:https://example.com/abc123'></iframe>"#;
    let issues = analyze_object_urls(body);
    assert!(issues.contains(&ObjectUrlIssue::BlobUrlInIframe));
}

#[test]
fn detects_data_url_in_script() {
    let body = r#"<script src="data:text/javascript,alert(1)"></script>"#;
    let issues = analyze_object_urls(body);
    assert!(issues.contains(&ObjectUrlIssue::DataUrlInScript));
}

#[test]
fn detects_data_url_single_quote_script() {
    let body = r#"<script src='data:text/javascript,alert(1)'></script>"#;
    let issues = analyze_object_urls(body);
    assert!(issues.contains(&ObjectUrlIssue::DataUrlInScript));
}

#[test]
fn detects_data_url_in_iframe() {
    let body = r#"<iframe src="data:text/html,<h1>hi</h1>"></iframe>"#;
    let issues = analyze_object_urls(body);
    assert!(issues.contains(&ObjectUrlIssue::DataUrlInIframe));
}

#[test]
fn detects_data_url_single_quote_iframe() {
    let body = r#"<iframe src='data:text/html,<h1>hi</h1>'></iframe>"#;
    let issues = analyze_object_urls(body);
    assert!(issues.contains(&ObjectUrlIssue::DataUrlInIframe));
}

#[test]
fn no_false_positive_non_iframe_blob() {
    let body = r#"<div>blob:https://example.com/abc</div>"#;
    let issues = analyze_object_urls(body);
    assert!(!issues.contains(&ObjectUrlIssue::BlobUrlInIframe));
}

#[test]
fn no_false_positive_non_iframe_data() {
    let body = r#"<div>data:text/html,test</div>"#;
    let issues = analyze_object_urls(body);
    assert!(!issues.contains(&ObjectUrlIssue::DataUrlInIframe));
}

#[test]
fn severity_blob_script_high() {
    assert_eq!(object_url_severity(&ObjectUrlIssue::BlobUrlInScript), 7.0);
}

#[test]
fn severity_data_script_high() {
    assert_eq!(object_url_severity(&ObjectUrlIssue::DataUrlInScript), 7.0);
}

#[test]
fn severity_revoke_not_called_medium() {
    assert_eq!(object_url_severity(&ObjectUrlIssue::RevokeNotCalled), 4.0);
}

#[test]
fn severity_create_object_url_low() {
    assert_eq!(object_url_severity(&ObjectUrlIssue::CreateObjectUrl), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ObjectUrlIssue::BlobUrlInScript,
        ObjectUrlIssue::RevokeNotCalled,
    ];
    let mut seq = 0;
    let ops = object_url_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        ObjectUrlIssue::CreateObjectUrl.to_string(),
        "create_object_url"
    );
    assert_eq!(
        ObjectUrlIssue::BlobUrlInScript.to_string(),
        "blob_url_script"
    );
    assert_eq!(
        ObjectUrlIssue::BlobUrlInIframe.to_string(),
        "blob_url_iframe"
    );
    assert_eq!(
        ObjectUrlIssue::DataUrlInScript.to_string(),
        "data_url_script"
    );
    assert_eq!(
        ObjectUrlIssue::DataUrlInIframe.to_string(),
        "data_url_iframe"
    );
    assert_eq!(
        ObjectUrlIssue::RevokeNotCalled.to_string(),
        "revoke_not_called"
    );
}

#[test]
fn combined_issues_blob_and_data() {
    let body = r#"
        <script src="blob:https://example.com/abc"></script>
        <iframe src="data:text/html,test"></iframe>
    "#;
    let issues = analyze_object_urls(body);
    assert!(issues.contains(&ObjectUrlIssue::BlobUrlInScript));
    assert!(issues.contains(&ObjectUrlIssue::DataUrlInIframe));
}

#[test]
fn case_insensitive_iframe_detection() {
    let body = r#"<IFRAME SRC="blob:https://example.com/abc"></IFRAME>"#;
    let issues = analyze_object_urls(body);
    assert!(issues.contains(&ObjectUrlIssue::BlobUrlInIframe));
}
