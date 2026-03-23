use crate::document_domain_audit::{
    document_domain_to_operations, find_document_domain,
};

#[test]
fn detects_document_domain_assignment() {
    let html = r#"<html><script>document.domain = "example.com";</script></html>"#;
    let issues = find_document_domain(html);
    assert_eq!(issues.len(), 1);
    assert!(issues[0].snippet.contains("document.domain"));
}

#[test]
fn ignores_external_scripts() {
    let html = r#"<html><script src="app.js">document.domain = "x";</script></html>"#;
    let issues = find_document_domain(html);
    assert!(issues.is_empty());
}

#[test]
fn case_insensitive_tag() {
    let html = r#"<SCRIPT>document.domain = "foo";</SCRIPT>"#;
    let issues = find_document_domain(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn no_script_tags() {
    let html = "<html><body>Hello</body></html>";
    let issues = find_document_domain(html);
    assert!(issues.is_empty());
}

#[test]
fn script_without_document_domain() {
    let html = r#"<script>var x = 1; console.log(x);</script>"#;
    let issues = find_document_domain(html);
    assert!(issues.is_empty());
}

#[test]
fn multiple_scripts_one_match() {
    let html = r#"<script>var a=1;</script><script>document.domain="x";</script>"#;
    let issues = find_document_domain(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn multiple_scripts_both_match() {
    let html = concat!(
        r#"<script>document.domain = "a.com";</script>"#,
        r#"<script>document.domain = "b.com";</script>"#,
    );
    let issues = find_document_domain(html);
    assert_eq!(issues.len(), 2);
}

#[test]
fn snippet_truncated_at_120_chars() {
    let long_line = format!(
        r#"<script>document.domain = "{}".slice(0,99);</script>"#,
        "a".repeat(200)
    );
    let issues = find_document_domain(&long_line);
    assert_eq!(issues.len(), 1);
    assert!(issues[0].snippet.len() <= 120);
    assert!(issues[0].snippet.ends_with("..."));
}

#[test]
fn unclosed_script_tag() {
    let html = r#"<script>document.domain = "x";"#;
    let issues = find_document_domain(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn empty_html() {
    let issues = find_document_domain("");
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = document_domain_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_on_issues() {
    let html = r#"<script>document.domain = "x";</script>"#;
    let issues = find_document_domain(html);
    let mut seq = 5;
    let ops = document_domain_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}
