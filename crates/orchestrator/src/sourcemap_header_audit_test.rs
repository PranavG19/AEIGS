use crate::sourcemap_header_audit::*;

#[test]
fn no_header_no_body_no_issues() {
    let issues = analyze_sourcemap(None, "");
    assert!(issues.is_empty());
}

#[test]
fn no_header_plain_body_no_issues() {
    let issues = analyze_sourcemap(None, "var x = 42; console.log(x);");
    assert!(issues.is_empty());
}

#[test]
fn sourcemap_header_produces_header_exposed() {
    let issues = analyze_sourcemap(Some("/js/app.js.map"), "");
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], SourceMapIssue::HeaderExposed { url } if url == "/js/app.js.map"));
}

#[test]
fn x_sourcemap_header_produces_header_exposed() {
    let issues = analyze_sourcemap(Some("https://cdn.example.com/bundle.js.map"), "");
    assert_eq!(issues.len(), 1);
    assert!(
        matches!(&issues[0], SourceMapIssue::HeaderExposed { url } if url == "https://cdn.example.com/bundle.js.map")
    );
}

#[test]
fn header_value_trimmed() {
    let issues = analyze_sourcemap(Some("  /app.js.map  "), "");
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], SourceMapIssue::HeaderExposed { url } if url == "/app.js.map"));
}

#[test]
fn empty_header_value_no_issue() {
    let issues = analyze_sourcemap(Some(""), "");
    assert!(issues.is_empty());
}

#[test]
fn whitespace_only_header_no_issue() {
    let issues = analyze_sourcemap(Some("   "), "");
    assert!(issues.is_empty());
}

#[test]
fn inline_sourcemap_data_uri_js() {
    let body = "//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==";
    let issues = analyze_sourcemap(None, body);
    assert!(
        issues.iter().any(
            |i| matches!(i, SourceMapIssue::InlineSourceMap { file_type } if file_type == "js")
        )
    );
}

#[test]
fn inline_sourcemap_data_uri_css() {
    let body = "/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ== */";
    let issues = analyze_sourcemap(None, body);
    assert!(
        issues.iter().any(
            |i| matches!(i, SourceMapIssue::InlineSourceMap { file_type } if file_type == "css")
        )
    );
}

#[test]
fn source_mapping_url_comment_relative() {
    let body = "//# sourceMappingURL=app.js.map";
    let issues = analyze_sourcemap(None, body);
    assert!(issues.iter().any(
        |i| matches!(i, SourceMapIssue::SourceMappingUrlComment { url } if url == "app.js.map")
    ));
}

#[test]
fn source_mapping_url_comment_absolute() {
    let body = "//# sourceMappingURL=/static/bundle.js.map";
    let issues = analyze_sourcemap(None, body);
    assert!(issues.iter().any(
        |i| matches!(i, SourceMapIssue::SourceMappingUrlComment { url } if url == "/static/bundle.js.map")
    ));
}

#[test]
fn css_block_comment_sourcemap() {
    let body = "/*# sourceMappingURL=style.css.map */";
    let issues = analyze_sourcemap(None, body);
    assert!(issues.iter().any(
        |i| matches!(i, SourceMapIssue::SourceMappingUrlComment { url } if url == "style.css.map")
    ));
}

#[test]
fn third_party_sourcemap_http() {
    let body = "//# sourceMappingURL=http://evil.com/app.js.map";
    let issues = analyze_sourcemap(None, body);
    assert!(issues.iter().any(
        |i| matches!(i, SourceMapIssue::SourceMapToThirdParty { url } if url == "http://evil.com/app.js.map")
    ));
}

#[test]
fn third_party_sourcemap_https() {
    let body = "//# sourceMappingURL=https://cdn.external.com/vendor.js.map";
    let issues = analyze_sourcemap(None, body);
    assert!(issues.iter().any(
        |i| matches!(i, SourceMapIssue::SourceMapToThirdParty { url } if url == "https://cdn.external.com/vendor.js.map")
    ));
}

#[test]
fn relative_url_not_third_party() {
    let body = "//# sourceMappingURL=app.js.map";
    let issues = analyze_sourcemap(None, body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SourceMapIssue::SourceMapToThirdParty { .. }))
    );
}

#[test]
fn multiple_sourcemap_references() {
    let body = "//# sourceMappingURL=a.js.map\n//# sourceMappingURL=b.js.map";
    let issues = analyze_sourcemap(None, body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapIssue::MultipleSourceMaps { count } if *count == 2))
    );
}

#[test]
fn three_sourcemap_references() {
    let body =
        "//# sourceMappingURL=a.map\n//# sourceMappingURL=b.map\n/*# sourceMappingURL=c.map */";
    let issues = analyze_sourcemap(None, body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapIssue::MultipleSourceMaps { count } if *count == 3))
    );
}

#[test]
fn single_reference_no_multiple_issue() {
    let body = "//# sourceMappingURL=app.js.map";
    let issues = analyze_sourcemap(None, body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SourceMapIssue::MultipleSourceMaps { .. }))
    );
}

#[test]
fn external_map_file_accessible() {
    let body = "//# sourceMappingURL=vendor.js.map";
    let issues = analyze_sourcemap(None, body);
    assert!(issues.iter().any(
        |i| matches!(i, SourceMapIssue::ExternalSourceMapAccessible { url } if url == "vendor.js.map")
    ));
}

#[test]
fn non_map_extension_no_external_accessible() {
    let body = "//# sourceMappingURL=data:application/json;base64,abc";
    let issues = analyze_sourcemap(None, body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SourceMapIssue::ExternalSourceMapAccessible { .. }))
    );
}

#[test]
fn unprotected_js_map_path() {
    let body = r#"<script src="/js/bundle.js.map"></script>"#;
    let issues = analyze_sourcemap(None, body);
    assert!(issues.iter().any(
        |i| matches!(i, SourceMapIssue::UnprotectedSourceMapPath { path } if path == "/js/bundle.js.map")
    ));
}

#[test]
fn unprotected_assets_map_path() {
    let body = r#"href="/assets/style.css.map""#;
    let issues = analyze_sourcemap(None, body);
    assert!(issues.iter().any(
        |i| matches!(i, SourceMapIssue::UnprotectedSourceMapPath { path } if path == "/assets/style.css.map")
    ));
}

#[test]
fn unprotected_dist_map_path() {
    let body = r#""/dist/main.js.map""#;
    let issues = analyze_sourcemap(None, body);
    assert!(issues.iter().any(
        |i| matches!(i, SourceMapIssue::UnprotectedSourceMapPath { path } if path == "/dist/main.js.map")
    ));
}

#[test]
fn unprotected_build_map_path() {
    let body = r#"src='/build/app.js.map'"#;
    let issues = analyze_sourcemap(None, body);
    assert!(issues.iter().any(
        |i| matches!(i, SourceMapIssue::UnprotectedSourceMapPath { path } if path == "/build/app.js.map")
    ));
}

#[test]
fn no_unprotected_path_without_map_extension() {
    let body = r#"<script src="/js/bundle.js"></script>"#;
    let issues = analyze_sourcemap(None, body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SourceMapIssue::UnprotectedSourceMapPath { .. }))
    );
}

#[test]
fn display_header_exposed() {
    let issue = SourceMapIssue::HeaderExposed { url: String::new() };
    assert_eq!(issue.to_string(), "header_exposed");
}

#[test]
fn display_inline_source_map() {
    let issue = SourceMapIssue::InlineSourceMap {
        file_type: String::new(),
    };
    assert_eq!(issue.to_string(), "inline_source_map");
}

#[test]
fn display_source_mapping_url_comment() {
    let issue = SourceMapIssue::SourceMappingUrlComment { url: String::new() };
    assert_eq!(issue.to_string(), "source_mapping_url_comment");
}

#[test]
fn display_external_source_map_accessible() {
    let issue = SourceMapIssue::ExternalSourceMapAccessible { url: String::new() };
    assert_eq!(issue.to_string(), "external_source_map_accessible");
}

#[test]
fn display_multiple_source_maps() {
    let issue = SourceMapIssue::MultipleSourceMaps { count: 2 };
    assert_eq!(issue.to_string(), "multiple_source_maps");
}

#[test]
fn display_source_map_to_third_party() {
    let issue = SourceMapIssue::SourceMapToThirdParty { url: String::new() };
    assert_eq!(issue.to_string(), "source_map_to_third_party");
}

#[test]
fn display_unprotected_source_map_path() {
    let issue = SourceMapIssue::UnprotectedSourceMapPath {
        path: String::new(),
    };
    assert_eq!(issue.to_string(), "unprotected_source_map_path");
}

#[test]
fn severity_header_exposed() {
    let issue = SourceMapIssue::HeaderExposed { url: String::new() };
    assert_eq!(sourcemap_severity(&issue), 5.0);
}

#[test]
fn severity_inline_source_map() {
    let issue = SourceMapIssue::InlineSourceMap {
        file_type: String::new(),
    };
    assert_eq!(sourcemap_severity(&issue), 6.0);
}

#[test]
fn severity_source_mapping_url_comment() {
    let issue = SourceMapIssue::SourceMappingUrlComment { url: String::new() };
    assert_eq!(sourcemap_severity(&issue), 4.5);
}

#[test]
fn severity_external_source_map_accessible() {
    let issue = SourceMapIssue::ExternalSourceMapAccessible { url: String::new() };
    assert_eq!(sourcemap_severity(&issue), 5.5);
}

#[test]
fn severity_multiple_source_maps() {
    let issue = SourceMapIssue::MultipleSourceMaps { count: 3 };
    assert_eq!(sourcemap_severity(&issue), 3.0);
}

#[test]
fn severity_source_map_to_third_party() {
    let issue = SourceMapIssue::SourceMapToThirdParty { url: String::new() };
    assert_eq!(sourcemap_severity(&issue), 5.5);
}

#[test]
fn severity_unprotected_source_map_path() {
    let issue = SourceMapIssue::UnprotectedSourceMapPath {
        path: String::new(),
    };
    assert_eq!(sourcemap_severity(&issue), 4.0);
}

#[test]
fn to_operations_empty_issues() {
    let mut seq = 0;
    let ops = sourcemap_header_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn to_operations_single_issue() {
    let issues = vec![SourceMapIssue::HeaderExposed {
        url: "/app.js.map".to_string(),
    }];
    let mut seq = 0;
    let ops = sourcemap_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn to_operations_multiple_issues() {
    let issues = vec![
        SourceMapIssue::HeaderExposed {
            url: "/app.js.map".to_string(),
        },
        SourceMapIssue::InlineSourceMap {
            file_type: "js".to_string(),
        },
        SourceMapIssue::SourceMapToThirdParty {
            url: "https://evil.com/x.map".to_string(),
        },
    ];
    let mut seq = 5;
    let ops = sourcemap_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
}

#[test]
fn to_operations_seq_increments_from_nonzero() {
    let issues = vec![SourceMapIssue::MultipleSourceMaps { count: 2 }];
    let mut seq = 10;
    let ops = sourcemap_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 11);
}

#[test]
fn header_and_body_both_detected() {
    let body = "//# sourceMappingURL=app.js.map";
    let issues = analyze_sourcemap(Some("/static/app.js.map"), body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapIssue::HeaderExposed { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapIssue::SourceMappingUrlComment { .. }))
    );
}

#[test]
fn block_comment_without_closing_still_detected() {
    let body = "/*# sourceMappingURL=style.css.map";
    let issues = analyze_sourcemap(None, body);
    assert!(issues.iter().any(
        |i| matches!(i, SourceMapIssue::SourceMappingUrlComment { url } if url == "style.css.map")
    ));
}

#[test]
fn mixed_line_and_block_comments_counted() {
    let body = "//# sourceMappingURL=a.js.map\n/*# sourceMappingURL=b.css.map */";
    let issues = analyze_sourcemap(None, body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapIssue::MultipleSourceMaps { count } if *count == 2))
    );
}

#[test]
fn case_sensitive_no_uppercase_match() {
    let body = "//# SOURCEMAPPINGURL=app.js.map";
    let issues = analyze_sourcemap(None, body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SourceMapIssue::SourceMappingUrlComment { .. }))
    );
}
