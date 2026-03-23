use crate::dangerous_js_audit::{
    dangerous_js_to_operations, find_dangerous_js, DangerousJsIssue,
};

#[test]
fn detects_eval() {
    let html = r#"<script>eval(userInput)</script>"#;
    let issues = find_dangerous_js(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].pattern, "eval");
}

#[test]
fn detects_innerhtml() {
    let html = r#"<script>element.innerHTML = data;</script>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.iter().any(|i| i.pattern == "innerHTML"));
}

#[test]
fn detects_document_write() {
    let html = r#"<script>document.write('<p>' + name + '</p>')</script>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.iter().any(|i| i.pattern == "document.write"));
}

#[test]
fn detects_jquery_html() {
    let html = r#"<script>$('#div').html(response)</script>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.iter().any(|i| i.pattern == "jQuery.html"));
}

#[test]
fn detects_function_constructor() {
    let html = r#"<script>new Function(code)()</script>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.iter().any(|i| i.pattern == "Function_constructor"));
}

#[test]
fn skips_external_scripts() {
    let html = r#"<script src="https://cdn.example.com/app.js"></script>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.is_empty());
}

#[test]
fn no_issues_in_clean_script() {
    let html = r#"<script>console.log('hello');</script>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.is_empty());
}

#[test]
fn no_issues_without_scripts() {
    let html = r#"<html><body><p>Hello</p></body></html>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.is_empty());
}

#[test]
fn multiple_patterns_in_one_script() {
    let html = r#"<script>eval(x); element.innerHTML = y;</script>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.len() >= 2);
}

#[test]
fn deduplicates_same_pattern() {
    let html = r#"<script>eval(x); eval(y);</script>"#;
    let issues = find_dangerous_js(html);
    let eval_count = issues.iter().filter(|i| i.pattern == "eval").count();
    assert_eq!(eval_count, 1);
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = dangerous_js_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = vec![DangerousJsIssue {
        pattern: "eval".to_string(),
        severity: 6.0,
    }];
    let mut seq = 0;
    let ops = dangerous_js_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn case_insensitive() {
    let html = r#"<script>EVAL(userInput)</script>"#;
    let issues = find_dangerous_js(html);
    assert_eq!(issues.len(), 1);
}
