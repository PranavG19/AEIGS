use crate::html_parser::{extract_attr, extract_attr_lower, TagIter};

#[test]
fn tag_iter_finds_script_tags() {
    let html = r#"<script src="a.js"></script><p>text</p><script src="b.js"></script>"#;
    let tags: Vec<_> = TagIter::new(html, "script").collect();
    assert_eq!(tags.len(), 2);
    assert!(tags[0].original.contains("a.js"));
    assert!(tags[1].original.contains("b.js"));
}

#[test]
fn tag_iter_case_insensitive() {
    let html = r#"<SCRIPT SRC="a.js"></SCRIPT>"#;
    let tags: Vec<_> = TagIter::new(html, "script").collect();
    assert_eq!(tags.len(), 1);
}

#[test]
fn tag_iter_empty_html() {
    let tags: Vec<_> = TagIter::new("", "script").collect();
    assert!(tags.is_empty());
}

#[test]
fn tag_iter_no_matching_tags() {
    let html = r#"<div><p>Hello</p></div>"#;
    let tags: Vec<_> = TagIter::new(html, "script").collect();
    assert!(tags.is_empty());
}

#[test]
fn tag_iter_meta_self_closing() {
    let html = r#"<meta name="gen" content="WP">"#;
    let tags: Vec<_> = TagIter::new(html, "meta").collect();
    assert_eq!(tags.len(), 1);
}

#[test]
fn extract_attr_double_quoted() {
    let tag = r#"<script src="https://cdn.example.com/lib.js">"#;
    let result = extract_attr(tag, &tag.to_ascii_lowercase(), "src");
    assert_eq!(result.as_deref(), Some("https://cdn.example.com/lib.js"));
}

#[test]
fn extract_attr_single_quoted() {
    let tag = r#"<script src='app.js'>"#;
    let result = extract_attr(tag, &tag.to_ascii_lowercase(), "src");
    assert_eq!(result.as_deref(), Some("app.js"));
}

#[test]
fn extract_attr_unquoted() {
    let tag = r#"<script src=app.js>"#;
    let result = extract_attr(tag, &tag.to_ascii_lowercase(), "src");
    assert_eq!(result.as_deref(), Some("app.js"));
}

#[test]
fn extract_attr_missing() {
    let tag = r#"<script type="text/javascript">"#;
    let result = extract_attr(tag, &tag.to_ascii_lowercase(), "src");
    assert!(result.is_none());
}

#[test]
fn extract_attr_preserves_case() {
    let tag = r#"<meta name="Generator" content="WordPress 6.4">"#;
    let result = extract_attr(tag, &tag.to_ascii_lowercase(), "content");
    assert_eq!(result.as_deref(), Some("WordPress 6.4"));
}

#[test]
fn extract_attr_lower_works() {
    let tag_lower = r#"<meta name="robots" content="noindex">"#;
    let result = extract_attr_lower(tag_lower, "content");
    assert_eq!(result.as_deref(), Some("noindex"));
}

#[test]
fn extract_attr_with_slash() {
    let tag = r#"<meta name="viewport" content="width=device-width"/>"#;
    let result = extract_attr(tag, &tag.to_ascii_lowercase(), "content");
    assert_eq!(result.as_deref(), Some("width=device-width"));
}
