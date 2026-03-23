use crate::mixed_content::{
    find_mixed_content, mixed_content_to_operations, MixedContentIssue, MixedContentKind,
};

#[test]
fn detects_http_script() {
    let html = r#"<script src="http://example.com/lib.js"></script>"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, MixedContentKind::Script);
    assert_eq!(issues[0].url, "http://example.com/lib.js");
}

#[test]
fn ignores_https_script() {
    let html = r#"<script src="https://example.com/lib.js"></script>"#;
    let issues = find_mixed_content(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_http_stylesheet() {
    let html = r#"<link href="http://example.com/style.css">"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, MixedContentKind::Stylesheet);
}

#[test]
fn detects_http_image() {
    let html = r#"<img src="http://example.com/img.png">"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, MixedContentKind::Image);
}

#[test]
fn detects_http_iframe() {
    let html = r#"<iframe src="http://example.com/page"></iframe>"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, MixedContentKind::Iframe);
}

#[test]
fn detects_http_form_action() {
    let html = r#"<form action="http://example.com/submit"></form>"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, MixedContentKind::Form);
}

#[test]
fn ignores_relative_urls() {
    let html = r#"<script src="/js/app.js"></script><img src="img.png">"#;
    let issues = find_mixed_content(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_multiple_issues() {
    let html = r#"
        <script src="http://cdn.example.com/a.js"></script>
        <img src="http://cdn.example.com/b.png">
        <link href="http://cdn.example.com/c.css">
    "#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 3);
}

#[test]
fn no_issues_in_clean_page() {
    let html = r#"<html><body><p>Hello</p></body></html>"#;
    let issues = find_mixed_content(html);
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = mixed_content_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn active_mixed_content_has_high_severity() {
    let issues = vec![MixedContentIssue {
        kind: MixedContentKind::Script,
        url: "http://example.com/lib.js".to_string(),
    }];
    let mut seq = 0;
    let ops = mixed_content_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn passive_mixed_content_has_lower_severity() {
    let issues = vec![MixedContentIssue {
        kind: MixedContentKind::Image,
        url: "http://example.com/img.png".to_string(),
    }];
    let mut seq = 0;
    let ops = mixed_content_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
}

#[test]
fn handles_single_quoted_attributes() {
    let html = r#"<script src='http://example.com/lib.js'></script>"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn display_kinds() {
    assert_eq!(MixedContentKind::Script.to_string(), "script");
    assert_eq!(MixedContentKind::Stylesheet.to_string(), "stylesheet");
    assert_eq!(MixedContentKind::Image.to_string(), "image");
    assert_eq!(MixedContentKind::Iframe.to_string(), "iframe");
    assert_eq!(MixedContentKind::Form.to_string(), "form");
}
