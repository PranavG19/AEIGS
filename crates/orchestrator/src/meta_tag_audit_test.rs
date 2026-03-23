use crate::meta_tag_audit::{MetaIssue, analyze_meta_tags, meta_findings_to_operations};

#[test]
fn detects_generator_meta() {
    let html = r#"<meta name="generator" content="WordPress 6.4">"#;
    let issues = analyze_meta_tags(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::GeneratorDisclosure(v) if v == "WordPress 6.4"));
}

#[test]
fn detects_author_meta() {
    let html = r#"<meta name="author" content="John Dev">"#;
    let issues = analyze_meta_tags(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::GeneratorDisclosure(_)));
}

#[test]
fn detects_framework_meta() {
    let html = r#"<meta name="framework" content="Next.js 14">"#;
    let issues = analyze_meta_tags(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn skips_empty_generator_content() {
    let html = r#"<meta name="generator" content="">"#;
    let issues = analyze_meta_tags(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_noindex_robots() {
    let html = r#"<meta name="robots" content="noindex, nofollow">"#;
    let issues = analyze_meta_tags(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], MetaIssue::NoindexOnPublicPage);
}

#[test]
fn ignores_index_follow_robots() {
    let html = r#"<meta name="robots" content="index, follow">"#;
    let issues = analyze_meta_tags(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_set_cookie_http_equiv() {
    let html = r#"<meta http-equiv="set-cookie" content="session=abc">"#;
    let issues = analyze_meta_tags(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::SensitiveMetaTag(v) if v == "set-cookie"));
}

#[test]
fn ignores_content_type_http_equiv() {
    let html = r#"<meta http-equiv="content-type" content="text/html; charset=utf-8">"#;
    let issues = analyze_meta_tags(html);
    assert!(issues.is_empty());
}

#[test]
fn skips_description_meta() {
    let html = r#"<meta name="description" content="A great website">"#;
    let issues = analyze_meta_tags(html);
    assert!(issues.is_empty());
}

#[test]
fn no_issues_in_clean_html() {
    let html = r#"<html><head><meta charset="utf-8"></head><body></body></html>"#;
    let issues = analyze_meta_tags(html);
    assert!(issues.is_empty());
}

#[test]
fn multiple_issues() {
    let html = r#"
        <meta name="generator" content="Drupal 10">
        <meta http-equiv="set-cookie" content="id=123">
    "#;
    let issues = analyze_meta_tags(html);
    assert_eq!(issues.len(), 2);
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = meta_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = vec![MetaIssue::GeneratorDisclosure("WordPress".to_string())];
    let mut seq = 0;
    let ops = meta_findings_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn display_variants() {
    let disclosure = MetaIssue::GeneratorDisclosure("WP".to_string());
    assert_eq!(disclosure.to_string(), "generator_disclosure:WP");
    let sensitive = MetaIssue::SensitiveMetaTag("set-cookie".to_string());
    assert_eq!(sensitive.to_string(), "sensitive_meta:set-cookie");
    assert_eq!(
        MetaIssue::NoindexOnPublicPage.to_string(),
        "noindex_on_public"
    );
}
