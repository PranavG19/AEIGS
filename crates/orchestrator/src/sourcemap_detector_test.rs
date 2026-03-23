use crate::sourcemap_detector::{
    SourceMapLeak, find_sourcemap_references, sourcemap_to_operations,
};

#[test]
fn detects_js_file_with_map() {
    let html = r#"<script src="/js/app.js"></script>"#;
    let leaks = find_sourcemap_references(html, "https://example.com");
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].script_url, "/js/app.js");
    assert!(leaks[0].map_url.ends_with("/js/app.js.map"));
}

#[test]
fn skips_non_js_scripts() {
    let html = r#"<script src="/api/data"></script>"#;
    let leaks = find_sourcemap_references(html, "https://example.com");
    assert!(leaks.is_empty());
}

#[test]
fn detects_sourcemapping_url_comment() {
    let html = r#"<script>
        var x = 1;
        //# sourceMappingURL=app.js.map
    </script>"#;
    let leaks = find_sourcemap_references(html, "https://example.com");
    assert!(leaks.iter().any(|l| l.map_url.contains("app.js.map")));
}

#[test]
fn detects_legacy_sourcemapping_url() {
    let html = r#"<script>
        //@ sourceMappingURL=legacy.js.map
    </script>"#;
    let leaks = find_sourcemap_references(html, "https://example.com");
    assert!(leaks.iter().any(|l| l.map_url.contains("legacy.js.map")));
}

#[test]
fn skips_data_uri_sourcemaps() {
    let html = r#"<script>
        //# sourceMappingURL=data:application/json;base64,abc
    </script>"#;
    let leaks = find_sourcemap_references(html, "https://example.com");
    let comment_leaks: Vec<_> = leaks.iter().filter(|l| l.script_url.is_empty()).collect();
    assert!(comment_leaks.is_empty());
}

#[test]
fn resolves_absolute_url() {
    let html = r#"<script src="https://cdn.example.com/lib.js"></script>"#;
    let leaks = find_sourcemap_references(html, "https://example.com");
    assert_eq!(leaks[0].map_url, "https://cdn.example.com/lib.js.map");
}

#[test]
fn resolves_root_relative_url() {
    let html = r#"<script src="/assets/bundle.js"></script>"#;
    let leaks = find_sourcemap_references(html, "https://example.com/page");
    assert!(leaks[0].map_url.contains("example.com"));
    assert!(leaks[0].map_url.ends_with("/assets/bundle.js.map"));
}

#[test]
fn multiple_scripts() {
    let html = r#"
        <script src="/js/vendor.js"></script>
        <script src="/js/app.js"></script>
    "#;
    let leaks = find_sourcemap_references(html, "https://example.com");
    assert_eq!(leaks.len(), 2);
}

#[test]
fn no_leaks_in_scriptless_html() {
    let html = r#"<html><body><p>Hello</p></body></html>"#;
    let leaks = find_sourcemap_references(html, "https://example.com");
    assert!(leaks.is_empty());
}

#[test]
fn operations_empty_when_no_leaks() {
    let mut seq = 0;
    let ops = sourcemap_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_leaks() {
    let leaks = vec![SourceMapLeak {
        script_url: "/js/app.js".to_string(),
        map_url: "https://example.com/js/app.js.map".to_string(),
    }];
    let mut seq = 0;
    let ops = sourcemap_to_operations(&leaks, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn handles_single_quoted_src() {
    let html = r#"<script src='/js/app.js'></script>"#;
    let leaks = find_sourcemap_references(html, "https://example.com");
    assert_eq!(leaks.len(), 1);
}
