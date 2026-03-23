use crate::jsonp_audit::{find_jsonp_endpoints, jsonp_to_operations, JsonpIssueKind};

#[test]
fn no_scripts_no_issues() {
    let issues = find_jsonp_endpoints("<html><body>Hello</body></html>");
    assert!(issues.is_empty());
}

#[test]
fn callback_param_detected() {
    let html = r#"<script src="https://api.example.com/data?callback=handleData"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, JsonpIssueKind::CallbackParam);
}

#[test]
fn jsonp_param_detected() {
    let html = r#"<script src="/api/feed?jsonp=cb123"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(issues
        .iter()
        .any(|i| i.kind == JsonpIssueKind::CallbackParam));
}

#[test]
fn cb_param_detected() {
    let html = r#"<script src="/api/v1?cb=myFunc"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(issues
        .iter()
        .any(|i| i.kind == JsonpIssueKind::CallbackParam));
}

#[test]
fn jsonp_endpoint_path() {
    let html = r#"<script src="/api/data.jsonp"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(issues
        .iter()
        .any(|i| i.kind == JsonpIssueKind::JsonpEndpoint));
}

#[test]
fn normal_script_not_flagged() {
    let html = r#"<script src="/js/app.js"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(issues.is_empty());
}

#[test]
fn inline_script_not_flagged() {
    let html = r#"<script>var callback = function() {};</script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(issues.is_empty());
}

#[test]
fn multiple_scripts_some_jsonp() {
    let html = concat!(
        r#"<script src="/js/app.js"></script>"#,
        r#"<script src="/api?callback=fn1"></script>"#,
        r#"<script src="/static/lib.js"></script>"#,
    );
    let issues = find_jsonp_endpoints(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn case_insensitive_param() {
    let html = r#"<script src="/api?CALLBACK=fn"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn no_duplicate_for_callback_in_jsonp_path() {
    let html = r#"<script src="/jsonp/data?callback=fn"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, JsonpIssueKind::CallbackParam);
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = jsonp_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_on_issues() {
    let html = r#"<script src="/api?callback=fn"></script>"#;
    let issues = find_jsonp_endpoints(html);
    let mut seq = 5;
    let ops = jsonp_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}
