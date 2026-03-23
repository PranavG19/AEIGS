use crate::sourcemap_detector::*;

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

// SourceMapDetectorIssue Display tests

#[test]
fn display_exposed_sourcemap() {
    let issue = SourceMapDetectorIssue::ExposedSourceMap {
        script_url: "/app.js".to_string(),
        map_url: "/app.js.map".to_string(),
    };
    assert_eq!(issue.to_string(), "exposed_sourcemap:/app.js:/app.js.map");
}

#[test]
fn display_third_party_sourcemap() {
    let issue = SourceMapDetectorIssue::ThirdPartySourceMap {
        script_url: "https://cdn.example.com/lib.js".to_string(),
        cdn: "Example CDN".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "third_party_sourcemap:https://cdn.example.com/lib.js:Example CDN"
    );
}

#[test]
fn display_inline_sourcemap() {
    let issue = SourceMapDetectorIssue::InlineSourceMap {
        script_url: "/inline.js".to_string(),
    };
    assert_eq!(issue.to_string(), "inline_sourcemap:/inline.js");
}

#[test]
fn display_multiple_sourcemaps() {
    let issue = SourceMapDetectorIssue::MultipleSourceMaps { count: 12 };
    assert_eq!(issue.to_string(), "multiple_sourcemaps:12");
}

#[test]
fn display_production_sourcemap() {
    let issue = SourceMapDetectorIssue::ProductionSourceMap {
        script_url: "/bundle.min.js".to_string(),
    };
    assert_eq!(issue.to_string(), "production_sourcemap:/bundle.min.js");
}

#[test]
fn display_sensitive_path_exposed() {
    let issue = SourceMapDetectorIssue::SensitivePathExposed {
        path: "/src/admin/secret.js".to_string(),
    };
    assert_eq!(issue.to_string(), "sensitive_path:/src/admin/secret.js");
}

#[test]
fn display_sourcemap_comment() {
    let issue = SourceMapDetectorIssue::SourceMapComment {
        comment_type: "sourceMappingURL".to_string(),
        url: "app.js.map".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "sourcemap_comment:sourceMappingURL:app.js.map"
    );
}

#[test]
fn display_unminified_source() {
    let issue = SourceMapDetectorIssue::UnminifiedSource {
        script_url: "/debug.js".to_string(),
    };
    assert_eq!(issue.to_string(), "unminified_source:/debug.js");
}

// sourcemap_issue_severity tests

#[test]
fn severity_sensitive_path_exposed() {
    let issue = SourceMapDetectorIssue::SensitivePathExposed {
        path: "/src/secret.js".to_string(),
    };
    assert_eq!(sourcemap_issue_severity(&issue), 7.0);
}

#[test]
fn severity_production_sourcemap() {
    let issue = SourceMapDetectorIssue::ProductionSourceMap {
        script_url: "/bundle.min.js".to_string(),
    };
    assert_eq!(sourcemap_issue_severity(&issue), 6.0);
}

#[test]
fn severity_multiple_sourcemaps() {
    let issue = SourceMapDetectorIssue::MultipleSourceMaps { count: 10 };
    assert_eq!(sourcemap_issue_severity(&issue), 5.5);
}

#[test]
fn severity_exposed_sourcemap() {
    let issue = SourceMapDetectorIssue::ExposedSourceMap {
        script_url: "/app.js".to_string(),
        map_url: "/app.js.map".to_string(),
    };
    assert_eq!(sourcemap_issue_severity(&issue), 5.0);
}

#[test]
fn severity_inline_sourcemap() {
    let issue = SourceMapDetectorIssue::InlineSourceMap {
        script_url: "/inline.js".to_string(),
    };
    assert_eq!(sourcemap_issue_severity(&issue), 4.5);
}

#[test]
fn severity_sourcemap_comment() {
    let issue = SourceMapDetectorIssue::SourceMapComment {
        comment_type: "sourceMappingURL".to_string(),
        url: "app.js.map".to_string(),
    };
    assert_eq!(sourcemap_issue_severity(&issue), 4.5);
}

#[test]
fn severity_third_party_sourcemap() {
    let issue = SourceMapDetectorIssue::ThirdPartySourceMap {
        script_url: "https://cdn.example.com/lib.js".to_string(),
        cdn: "Example CDN".to_string(),
    };
    assert_eq!(sourcemap_issue_severity(&issue), 4.0);
}

#[test]
fn severity_unminified_source() {
    let issue = SourceMapDetectorIssue::UnminifiedSource {
        script_url: "/debug.js".to_string(),
    };
    assert_eq!(sourcemap_issue_severity(&issue), 3.0);
}

// analyze_sourcemap_leaks tests

#[test]
fn exposed_sourcemap_basic() {
    let leaks = vec![SourceMapLeak {
        script_url: "/app.js".to_string(),
        map_url: "/app.js.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::ExposedSourceMap { .. }))
    );
}

#[test]
fn production_script_min_js() {
    let leaks = vec![SourceMapLeak {
        script_url: "/bundle.min.js".to_string(),
        map_url: "/bundle.min.js.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::ProductionSourceMap { .. }))
    );
}

#[test]
fn production_script_bundle_js() {
    let leaks = vec![SourceMapLeak {
        script_url: "/main.bundle.js".to_string(),
        map_url: "/main.bundle.js.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::ProductionSourceMap { .. }))
    );
}

#[test]
fn production_script_vendor() {
    let leaks = vec![SourceMapLeak {
        script_url: "/vendor.abc123.js".to_string(),
        map_url: "/vendor.abc123.js.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::ProductionSourceMap { .. }))
    );
}

#[test]
fn non_production_script_no_flag() {
    let leaks = vec![SourceMapLeak {
        script_url: "/debug.js".to_string(),
        map_url: "/debug.js.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::ProductionSourceMap { .. }))
    );
}

#[test]
fn sensitive_path_src() {
    let leaks = vec![SourceMapLeak {
        script_url: "/src/components/app.js".to_string(),
        map_url: "/src/components/app.js.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::SensitivePathExposed { .. }))
    );
}

#[test]
fn sensitive_path_admin() {
    let leaks = vec![SourceMapLeak {
        script_url: "/admin/panel.js".to_string(),
        map_url: "/admin/panel.js.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::SensitivePathExposed { .. }))
    );
}

#[test]
fn sensitive_path_config() {
    let leaks = vec![SourceMapLeak {
        script_url: "/config/settings.js".to_string(),
        map_url: "/config/settings.js.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::SensitivePathExposed { .. }))
    );
}

#[test]
fn sensitive_path_node_modules() {
    let leaks = vec![SourceMapLeak {
        script_url: "/node_modules/package/index.js".to_string(),
        map_url: "/node_modules/package/index.js.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::SensitivePathExposed { .. }))
    );
}

#[test]
fn sensitive_path_env() {
    let leaks = vec![SourceMapLeak {
        script_url: "/js/app.js".to_string(),
        map_url: "/.env.production.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::SensitivePathExposed { .. }))
    );
}

#[test]
fn no_sensitive_path() {
    let leaks = vec![SourceMapLeak {
        script_url: "/js/app.js".to_string(),
        map_url: "/js/app.js.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::SensitivePathExposed { .. }))
    );
}

#[test]
fn third_party_cdn_cloudflare() {
    let leaks = vec![SourceMapLeak {
        script_url: "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js".to_string(),
        map_url: "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js.map"
            .to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        SourceMapDetectorIssue::ThirdPartySourceMap { cdn, .. } if cdn == "Cloudflare CDN"
    )));
}

#[test]
fn third_party_cdn_jsdelivr() {
    let leaks = vec![SourceMapLeak {
        script_url: "https://cdn.jsdelivr.net/npm/vue@3.2.0/dist/vue.js".to_string(),
        map_url: "https://cdn.jsdelivr.net/npm/vue@3.2.0/dist/vue.js.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        SourceMapDetectorIssue::ThirdPartySourceMap { cdn, .. } if cdn == "jsDelivr"
    )));
}

#[test]
fn third_party_cdn_unpkg() {
    let leaks = vec![SourceMapLeak {
        script_url: "https://unpkg.com/react@17.0.2/umd/react.production.min.js".to_string(),
        map_url: "https://unpkg.com/react@17.0.2/umd/react.production.min.js.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        SourceMapDetectorIssue::ThirdPartySourceMap { cdn, .. } if cdn == "unpkg"
    )));
}

#[test]
fn first_party_no_cdn() {
    let leaks = vec![SourceMapLeak {
        script_url: "https://example.com/js/app.js".to_string(),
        map_url: "https://example.com/js/app.js.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::ThirdPartySourceMap { .. }))
    );
}

#[test]
fn unminified_source_detected() {
    let leaks = vec![SourceMapLeak {
        script_url: "/js/debug.js".to_string(),
        map_url: "/js/debug.js.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::UnminifiedSource { .. }))
    );
}

#[test]
fn minified_source_no_unminified_flag() {
    let leaks = vec![SourceMapLeak {
        script_url: "/js/app.min.js".to_string(),
        map_url: "/js/app.min.js.map".to_string(),
    }];
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::UnminifiedSource { .. }))
    );
}

#[test]
fn sourcemap_comment_hash() {
    let html = r#"<script>
        //# sourceMappingURL=app.js.map
    </script>"#;
    let issues = analyze_sourcemap_leaks(&[], html);
    assert!(issues.iter().any(|i| matches!(
        i,
        SourceMapDetectorIssue::SourceMapComment { comment_type, .. } if comment_type == "sourceMappingURL"
    )));
}

#[test]
fn sourcemap_comment_at_sign() {
    let html = r#"<script>
        //@ sourceMappingURL=legacy.js.map
    </script>"#;
    let issues = analyze_sourcemap_leaks(&[], html);
    assert!(issues.iter().any(|i| matches!(
        i,
        SourceMapDetectorIssue::SourceMapComment { comment_type, .. } if comment_type == "legacy_sourceMappingURL"
    )));
}

#[test]
fn inline_sourcemap_data_uri() {
    let html = r#"<script>
        //# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjoz...
    </script>"#;
    let issues = analyze_sourcemap_leaks(&[], html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::InlineSourceMap { .. }))
    );
}

#[test]
fn multiple_sourcemaps_over_5() {
    let leaks: Vec<_> = (0..6)
        .map(|i| SourceMapLeak {
            script_url: format!("/js/chunk{i}.js"),
            map_url: format!("/js/chunk{i}.js.map"),
        })
        .collect();
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        issues.iter().any(
            |i| matches!(i, SourceMapDetectorIssue::MultipleSourceMaps { count } if *count == 6)
        )
    );
}

#[test]
fn multiple_sourcemaps_5_no_flag() {
    let leaks: Vec<_> = (0..5)
        .map(|i| SourceMapLeak {
            script_url: format!("/js/chunk{i}.js"),
            map_url: format!("/js/chunk{i}.js.map"),
        })
        .collect();
    let issues = analyze_sourcemap_leaks(&leaks, "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::MultipleSourceMaps { .. }))
    );
}

#[test]
fn empty_leaks_no_issues() {
    let issues = analyze_sourcemap_leaks(&[], "");
    assert!(issues.is_empty());
}

#[test]
fn combined_all_issue_types() {
    let leaks = vec![
        SourceMapLeak {
            script_url: "https://cdnjs.cloudflare.com/lib.min.js".to_string(),
            map_url: "https://cdnjs.cloudflare.com/lib.min.js.map".to_string(),
        },
        SourceMapLeak {
            script_url: "/src/admin/secret.js".to_string(),
            map_url: "/src/admin/secret.js.map".to_string(),
        },
        SourceMapLeak {
            script_url: "/debug.js".to_string(),
            map_url: "/debug.js.map".to_string(),
        },
    ];
    let html = r#"<script>
        //# sourceMappingURL=inline.js.map
        //@ sourceMappingURL=legacy.js.map
        //# sourceMappingURL=data:application/json;base64,abc
    </script>"#;
    let issues = analyze_sourcemap_leaks(&leaks, html);

    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::ExposedSourceMap { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::ThirdPartySourceMap { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::SensitivePathExposed { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::UnminifiedSource { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::SourceMapComment { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SourceMapDetectorIssue::InlineSourceMap { .. }))
    );
}

// resolve_url tests

#[test]
fn resolve_url_absolute_http() {
    let result = resolve_url("https://example.com/page", "http://other.com/file.js");
    assert_eq!(result, "http://other.com/file.js");
}

#[test]
fn resolve_url_absolute_https() {
    let result = resolve_url("https://example.com/page", "https://cdn.example.com/lib.js");
    assert_eq!(result, "https://cdn.example.com/lib.js");
}

#[test]
fn resolve_url_protocol_relative() {
    let result = resolve_url("https://example.com/page", "//cdn.example.com/file.js");
    assert_eq!(result, "//cdn.example.com/file.js");
}

#[test]
fn resolve_url_root_relative() {
    let result = resolve_url("https://example.com/page/sub", "/assets/app.js");
    assert_eq!(result, "https://example.com/assets/app.js");
}

#[test]
fn resolve_url_relative() {
    let result = resolve_url("https://example.com/page", "app.js");
    assert_eq!(result, "https://example.com/page/app.js");
}

// sourcemap_issues_to_operations tests

#[test]
fn issues_to_operations_empty() {
    let mut seq = 0;
    let ops = sourcemap_issues_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn issues_to_operations_single() {
    let issues = vec![SourceMapDetectorIssue::ExposedSourceMap {
        script_url: "/app.js".to_string(),
        map_url: "/app.js.map".to_string(),
    }];
    let mut seq = 0;
    let ops = sourcemap_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn issues_to_operations_multiple_seq() {
    let issues = vec![
        SourceMapDetectorIssue::ExposedSourceMap {
            script_url: "/app.js".to_string(),
            map_url: "/app.js.map".to_string(),
        },
        SourceMapDetectorIssue::ProductionSourceMap {
            script_url: "/bundle.min.js".to_string(),
        },
        SourceMapDetectorIssue::SensitivePathExposed {
            path: "/src/admin.js".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = sourcemap_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}
