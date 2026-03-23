use crate::inline_handler_audit::{
    find_inline_handlers, inline_handler_to_operations, InlineHandlerIssue,
};

#[test]
fn detects_onclick_handler() {
    let html = r#"<div onclick="alert(1)">Click me</div>"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].tag, "div");
    assert_eq!(issues[0].handler, "onclick");
}

#[test]
fn detects_onerror_on_img() {
    let html = r#"<img src="x" onerror="alert(1)">"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].handler, "onerror");
}

#[test]
fn detects_onload_on_body() {
    let html = r#"<body onload="init()">"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].handler, "onload");
}

#[test]
fn detects_onsubmit_on_form() {
    let html = r#"<form onsubmit="return validate()">"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].handler, "onsubmit");
}

#[test]
fn no_issues_in_clean_html() {
    let html = r#"<html><body><p>Clean page</p></body></html>"#;
    let issues = find_inline_handlers(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_multiple_handlers() {
    let html = r#"
        <div onclick="doA()">A</div>
        <span onmouseover="doB()">B</span>
        <input onfocus="doC()">
    "#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 3);
}

#[test]
fn one_issue_per_tag_even_with_multiple_handlers() {
    let html = r#"<div onclick="a()" onmouseover="b()">text</div>"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = inline_handler_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = vec![InlineHandlerIssue {
        tag: "div".to_string(),
        handler: "onclick".to_string(),
    }];
    let mut seq = 0;
    let ops = inline_handler_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn case_insensitive_detection() {
    let html = r#"<DIV ONCLICK="alert(1)">text</DIV>"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
}
