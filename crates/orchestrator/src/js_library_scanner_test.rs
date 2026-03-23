use crate::js_library_scanner::*;

// ===== EXISTING TESTS (13) =====

#[test]
fn detect_jquery_in_script_tag() {
    let html = r#"<html><head><script src="/js/jquery-3.2.1.min.js"></script></head></html>"#;
    let findings = detect_libraries(html);
    assert!(!findings.is_empty());
    let jq = findings.iter().find(|f| f.library == "jQuery").unwrap();
    assert_eq!(jq.version, Some("3.2.1".to_string()));
    assert!(jq.outdated);
}

#[test]
fn detect_jquery_safe_version() {
    let html = r#"<script src="https://cdn.example.com/jquery-3.7.1.min.js"></script>"#;
    let findings = detect_libraries(html);
    let jq = findings.iter().find(|f| f.library == "jQuery").unwrap();
    assert_eq!(jq.version, Some("3.7.1".to_string()));
    assert!(!jq.outdated);
}

#[test]
fn detect_angular_in_html() {
    let html = r#"<script src="/vendor/angular.min.js"></script>"#;
    let findings = detect_libraries(html);
    assert!(findings.iter().any(|f| f.library == "AngularJS"));
}

#[test]
fn detect_bootstrap() {
    let html = r#"<script src="/js/bootstrap-4.6.2/bootstrap.min.js"></script>"#;
    let findings = detect_libraries(html);
    let bs = findings.iter().find(|f| f.library == "Bootstrap").unwrap();
    assert_eq!(bs.version, Some("4.6.2".to_string()));
    assert!(bs.outdated);
}

#[test]
fn no_libraries_in_plain_html() {
    let html = r#"<html><body><p>Hello world</p></body></html>"#;
    let findings = detect_libraries(html);
    assert!(findings.is_empty());
}

#[test]
fn extract_version_from_path() {
    let version = extract_version(
        "https://cdn.example.com/jquery-3.6.0.min.js",
        r"jquery[/-](\d+\.\d+\.\d+)",
    );
    assert_eq!(version, Some("3.6.0".to_string()));
}

#[test]
fn extract_version_returns_none_for_no_match() {
    let version = extract_version("no version here", r"jquery[/-](\d+\.\d+\.\d+)");
    assert!(version.is_none());
}

#[test]
fn version_comparison_below() {
    assert!(is_version_below("3.2.1", "3.5.0"));
    assert!(is_version_below("1.7.0", "1.8.0"));
    assert!(is_version_below("4.17.20", "4.17.21"));
}

#[test]
fn version_comparison_equal_or_above() {
    assert!(!is_version_below("3.5.0", "3.5.0"));
    assert!(!is_version_below("3.6.0", "3.5.0"));
    assert!(!is_version_below("4.0.0", "3.5.0"));
}

#[test]
fn operations_empty_when_no_outdated() {
    let findings = vec![JsLibraryFinding {
        library: "jQuery".to_string(),
        version: Some("3.7.1".to_string()),
        min_safe_version: "3.5.0".to_string(),
        outdated: false,
    }];
    let mut seq = 0;
    let ops = js_library_findings_to_operations(&findings, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_for_outdated() {
    let findings = vec![JsLibraryFinding {
        library: "jQuery".to_string(),
        version: Some("3.2.1".to_string()),
        min_safe_version: "3.5.0".to_string(),
        outdated: true,
    }];
    let mut seq = 0;
    let ops = js_library_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn detect_vue_with_cdn_url() {
    let html = r#"<script src="https://cdn.jsdelivr.net/npm/vue@2.7.14/dist/vue.min.js"></script>"#;
    let findings = detect_libraries(html);
    let vue = findings.iter().find(|f| f.library == "Vue.js").unwrap();
    assert_eq!(vue.version, Some("2.7.14".to_string()));
    assert!(vue.outdated);
}

#[test]
fn detect_lodash() {
    let html = r#"<script src="/vendor/lodash-4.17.10.min.js"></script>"#;
    let findings = detect_libraries(html);
    let lodash = findings.iter().find(|f| f.library == "Lodash").unwrap();
    assert!(lodash.outdated);
}

// ===== NEW TESTS (47+) =====

// Display tests (8)
#[test]
fn display_outdated_library() {
    let issue = JsLibraryIssue::OutdatedLibrary {
        library: "jQuery".to_string(),
        version: "3.2.1".to_string(),
        min_safe: "3.5.0".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "jQuery 3.2.1 is outdated (min safe: 3.5.0)"
    );
}

#[test]
fn display_known_vulnerable() {
    let issue = JsLibraryIssue::KnownVulnerable {
        library: "jQuery".to_string(),
        cve_pattern: "CVE-2020-11022".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "jQuery has known vulnerability: CVE-2020-11022"
    );
}

#[test]
fn display_end_of_life() {
    let issue = JsLibraryIssue::EndOfLife {
        library: "AngularJS".to_string(),
    };
    assert_eq!(issue.to_string(), "AngularJS is end-of-life");
}

#[test]
fn display_unversioned_library() {
    let issue = JsLibraryIssue::UnversionedLibrary {
        library: "React".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "React detected without version information"
    );
}

#[test]
fn display_multiple_versions() {
    let issue = JsLibraryIssue::MultipleVersions {
        library: "jQuery".to_string(),
    };
    assert_eq!(issue.to_string(), "Multiple versions of jQuery detected");
}

#[test]
fn display_cdn_without_sri() {
    let issue = JsLibraryIssue::CdnWithoutSri {
        library: "unknown".to_string(),
        cdn_url: "cdnjs.cloudflare.com".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "unknown from CDN cdnjs.cloudflare.com without SRI"
    );
}

#[test]
fn display_debug_build() {
    let issue = JsLibraryIssue::DebugBuild {
        library: "React".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "React debug build detected in production"
    );
}

#[test]
fn display_deprecated_library() {
    let issue = JsLibraryIssue::DeprecatedLibrary {
        library: "AngularJS".to_string(),
        replacement: "Angular".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "AngularJS is deprecated, consider Angular"
    );
}

// Severity tests (8)
#[test]
fn severity_known_vulnerable() {
    let issue = JsLibraryIssue::KnownVulnerable {
        library: "jQuery".to_string(),
        cve_pattern: "CVE-2020-11022".to_string(),
    };
    assert_eq!(js_library_issue_severity(&issue), 8.0);
}

#[test]
fn severity_outdated_library() {
    let issue = JsLibraryIssue::OutdatedLibrary {
        library: "jQuery".to_string(),
        version: "3.2.1".to_string(),
        min_safe: "3.5.0".to_string(),
    };
    assert_eq!(js_library_issue_severity(&issue), 6.0);
}

#[test]
fn severity_end_of_life() {
    let issue = JsLibraryIssue::EndOfLife {
        library: "AngularJS".to_string(),
    };
    assert_eq!(js_library_issue_severity(&issue), 5.5);
}

#[test]
fn severity_deprecated_library() {
    let issue = JsLibraryIssue::DeprecatedLibrary {
        library: "AngularJS".to_string(),
        replacement: "Angular".to_string(),
    };
    assert_eq!(js_library_issue_severity(&issue), 5.0);
}

#[test]
fn severity_cdn_without_sri() {
    let issue = JsLibraryIssue::CdnWithoutSri {
        library: "unknown".to_string(),
        cdn_url: "cdnjs.cloudflare.com".to_string(),
    };
    assert_eq!(js_library_issue_severity(&issue), 4.5);
}

#[test]
fn severity_debug_build() {
    let issue = JsLibraryIssue::DebugBuild {
        library: "React".to_string(),
    };
    assert_eq!(js_library_issue_severity(&issue), 4.0);
}

#[test]
fn severity_unversioned_library() {
    let issue = JsLibraryIssue::UnversionedLibrary {
        library: "React".to_string(),
    };
    assert_eq!(js_library_issue_severity(&issue), 3.5);
}

#[test]
fn severity_multiple_versions() {
    let issue = JsLibraryIssue::MultipleVersions {
        library: "jQuery".to_string(),
    };
    assert_eq!(js_library_issue_severity(&issue), 3.0);
}

// analyze_js_libraries tests (31)
#[test]
fn analyze_outdated_library_flagged() {
    let findings = vec![JsLibraryFinding {
        library: "jQuery".to_string(),
        version: Some("3.2.1".to_string()),
        min_safe_version: "3.5.0".to_string(),
        outdated: true,
    }];
    let html = r#"<script src="/jquery-3.2.1.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::OutdatedLibrary { .. }))
    );
}

#[test]
fn analyze_non_outdated_no_outdated_issue() {
    let findings = vec![JsLibraryFinding {
        library: "jQuery".to_string(),
        version: Some("3.7.1".to_string()),
        min_safe_version: "3.5.0".to_string(),
        outdated: false,
    }];
    let html = r#"<script src="/jquery-3.7.1.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::OutdatedLibrary { .. }))
    );
}

#[test]
fn analyze_unversioned_library() {
    let findings = vec![JsLibraryFinding {
        library: "React".to_string(),
        version: None,
        min_safe_version: "18.0.0".to_string(),
        outdated: false,
    }];
    let html = r#"<script src="/react.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(issues.iter().any(
        |i| matches!(i, JsLibraryIssue::UnversionedLibrary { library } if library == "React")
    ));
}

#[test]
fn analyze_versioned_library_no_unversioned() {
    let findings = vec![JsLibraryFinding {
        library: "jQuery".to_string(),
        version: Some("3.7.1".to_string()),
        min_safe_version: "3.5.0".to_string(),
        outdated: false,
    }];
    let html = r#"<script src="/jquery-3.7.1.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::UnversionedLibrary { .. }))
    );
}

#[test]
fn analyze_eol_angularjs() {
    let findings = vec![JsLibraryFinding {
        library: "AngularJS".to_string(),
        version: Some("1.8.0".to_string()),
        min_safe_version: "1.8.0".to_string(),
        outdated: false,
    }];
    let html = r#"<script src="/angular.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::EndOfLife { library } if library == "AngularJS"))
    );
}

#[test]
fn analyze_eol_momentjs() {
    let findings = vec![JsLibraryFinding {
        library: "Moment.js".to_string(),
        version: Some("2.29.4".to_string()),
        min_safe_version: "2.29.4".to_string(),
        outdated: false,
    }];
    let html = r#"<script src="/moment.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::EndOfLife { library } if library == "Moment.js"))
    );
}

#[test]
fn analyze_non_eol_jquery() {
    let findings = vec![JsLibraryFinding {
        library: "jQuery".to_string(),
        version: Some("3.7.1".to_string()),
        min_safe_version: "3.5.0".to_string(),
        outdated: false,
    }];
    let html = r#"<script src="/jquery-3.7.1.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::EndOfLife { .. }))
    );
}

#[test]
fn analyze_deprecated_angularjs() {
    let findings = vec![JsLibraryFinding {
        library: "AngularJS".to_string(),
        version: Some("1.8.0".to_string()),
        min_safe_version: "1.8.0".to_string(),
        outdated: false,
    }];
    let html = r#"<script src="/angular.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(issues.iter().any(|i| matches!(i, JsLibraryIssue::DeprecatedLibrary { library, replacement } if library == "AngularJS" && replacement == "Angular")));
}

#[test]
fn analyze_deprecated_momentjs() {
    let findings = vec![JsLibraryFinding {
        library: "Moment.js".to_string(),
        version: Some("2.29.4".to_string()),
        min_safe_version: "2.29.4".to_string(),
        outdated: false,
    }];
    let html = r#"<script src="/moment.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(issues.iter().any(|i| matches!(i, JsLibraryIssue::DeprecatedLibrary { library, replacement } if library == "Moment.js" && replacement == "date-fns or Luxon")));
}

#[test]
fn analyze_non_deprecated_react() {
    let findings = vec![JsLibraryFinding {
        library: "React".to_string(),
        version: Some("18.2.0".to_string()),
        min_safe_version: "18.0.0".to_string(),
        outdated: false,
    }];
    let html = r#"<script src="/react-18.2.0.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::DeprecatedLibrary { .. }))
    );
}

#[test]
fn analyze_known_vulnerable_jquery_1x() {
    let findings = vec![JsLibraryFinding {
        library: "jQuery".to_string(),
        version: Some("1.12.4".to_string()),
        min_safe_version: "3.5.0".to_string(),
        outdated: true,
    }];
    let html = r#"<script src="/jquery-1.12.4.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(issues.iter().any(|i| matches!(i, JsLibraryIssue::KnownVulnerable { library, cve_pattern } if library == "jQuery" && cve_pattern == "CVE-2020-11022")));
}

#[test]
fn analyze_known_vulnerable_jquery_2x() {
    let findings = vec![JsLibraryFinding {
        library: "jQuery".to_string(),
        version: Some("2.2.4".to_string()),
        min_safe_version: "3.5.0".to_string(),
        outdated: true,
    }];
    let html = r#"<script src="/jquery-2.2.4.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(issues.iter().any(|i| matches!(i, JsLibraryIssue::KnownVulnerable { library, cve_pattern } if library == "jQuery" && cve_pattern == "CVE-2020-11023")));
}

#[test]
fn analyze_known_vulnerable_angularjs() {
    let findings = vec![JsLibraryFinding {
        library: "AngularJS".to_string(),
        version: Some("1.7.9".to_string()),
        min_safe_version: "1.8.0".to_string(),
        outdated: true,
    }];
    let html = r#"<script src="/angular-1.7.9.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(issues.iter().any(|i| matches!(i, JsLibraryIssue::KnownVulnerable { library, cve_pattern } if library == "AngularJS" && cve_pattern == "CVE-2022-25869")));
}

#[test]
fn analyze_known_vulnerable_lodash() {
    let findings = vec![JsLibraryFinding {
        library: "Lodash".to_string(),
        version: Some("4.17.1".to_string()),
        min_safe_version: "4.17.21".to_string(),
        outdated: true,
    }];
    let html = r#"<script src="/lodash-4.17.1.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(issues.iter().any(|i| matches!(i, JsLibraryIssue::KnownVulnerable { library, cve_pattern } if library == "Lodash" && cve_pattern == "CVE-2021-23337")));
}

#[test]
fn analyze_known_vulnerable_handlebars() {
    let findings = vec![JsLibraryFinding {
        library: "Handlebars".to_string(),
        version: Some("4.0.12".to_string()),
        min_safe_version: "4.7.7".to_string(),
        outdated: true,
    }];
    let html = r#"<script src="/handlebars-4.0.12.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(issues.iter().any(|i| matches!(i, JsLibraryIssue::KnownVulnerable { library, cve_pattern } if library == "Handlebars" && cve_pattern == "CVE-2021-23369")));
}

#[test]
fn analyze_safe_version_no_known_vuln() {
    let findings = vec![JsLibraryFinding {
        library: "jQuery".to_string(),
        version: Some("3.7.1".to_string()),
        min_safe_version: "3.5.0".to_string(),
        outdated: false,
    }];
    let html = r#"<script src="/jquery-3.7.1.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::KnownVulnerable { .. }))
    );
}

#[test]
fn analyze_debug_build_detected() {
    let findings = vec![JsLibraryFinding {
        library: "React".to_string(),
        version: Some("18.2.0".to_string()),
        min_safe_version: "18.0.0".to_string(),
        outdated: false,
    }];
    let html = r#"<script src="/react.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::DebugBuild { library } if library == "React"))
    );
}

#[test]
fn analyze_min_build_no_debug() {
    let findings = vec![JsLibraryFinding {
        library: "jQuery".to_string(),
        version: Some("3.7.1".to_string()),
        min_safe_version: "3.5.0".to_string(),
        outdated: false,
    }];
    let html = r#"<script src="/jquery.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::DebugBuild { .. }))
    );
}

#[test]
fn analyze_cdn_without_sri() {
    let findings = vec![];
    let html = r#"<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(issues.iter().any(|i| matches!(i, JsLibraryIssue::CdnWithoutSri { cdn_url, .. } if cdn_url == "cdnjs.cloudflare.com")));
}

#[test]
fn analyze_cdn_jsdelivr_without_sri() {
    let findings = vec![];
    let html = r#"<script src="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(issues.iter().any(|i| matches!(i, JsLibraryIssue::CdnWithoutSri { cdn_url, .. } if cdn_url == "cdn.jsdelivr.net")));
}

#[test]
fn analyze_cdn_unpkg_without_sri() {
    let findings = vec![];
    let html = r#"<script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(issues.iter().any(
        |i| matches!(i, JsLibraryIssue::CdnWithoutSri { cdn_url, .. } if cdn_url == "unpkg.com")
    ));
}

#[test]
fn analyze_cdn_with_sri_no_issue() {
    let findings = vec![];
    let html = r#"<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js" integrity="sha512-..."></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::CdnWithoutSri { .. }))
    );
}

#[test]
fn analyze_multiple_versions_same_lib() {
    let findings = vec![
        JsLibraryFinding {
            library: "jQuery".to_string(),
            version: Some("3.2.1".to_string()),
            min_safe_version: "3.5.0".to_string(),
            outdated: true,
        },
        JsLibraryFinding {
            library: "jQuery".to_string(),
            version: Some("3.7.1".to_string()),
            min_safe_version: "3.5.0".to_string(),
            outdated: false,
        },
    ];
    let html = r#"<script src="/jquery-3.2.1.min.js"></script><script src="/jquery-3.7.1.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(
        issues.iter().any(
            |i| matches!(i, JsLibraryIssue::MultipleVersions { library } if library == "jQuery")
        )
    );
}

#[test]
fn analyze_single_version_no_multiple() {
    let findings = vec![JsLibraryFinding {
        library: "jQuery".to_string(),
        version: Some("3.7.1".to_string()),
        min_safe_version: "3.5.0".to_string(),
        outdated: false,
    }];
    let html = r#"<script src="/jquery-3.7.1.min.js"></script>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::MultipleVersions { .. }))
    );
}

#[test]
fn analyze_combined_all_issues() {
    let findings = vec![
        JsLibraryFinding {
            library: "jQuery".to_string(),
            version: Some("1.12.4".to_string()),
            min_safe_version: "3.5.0".to_string(),
            outdated: true,
        },
        JsLibraryFinding {
            library: "AngularJS".to_string(),
            version: None,
            min_safe_version: "1.8.0".to_string(),
            outdated: false,
        },
        JsLibraryFinding {
            library: "jQuery".to_string(),
            version: Some("3.7.1".to_string()),
            min_safe_version: "3.5.0".to_string(),
            outdated: false,
        },
    ];
    let html = r#"
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
        <script src="/angularjs.js"></script>
        <script src="/jquery-3.7.1.min.js"></script>
    "#;
    let issues = analyze_js_libraries(&findings, html);

    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::OutdatedLibrary { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::KnownVulnerable { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::EndOfLife { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::DeprecatedLibrary { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::UnversionedLibrary { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::MultipleVersions { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::CdnWithoutSri { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsLibraryIssue::DebugBuild { .. }))
    );
}

#[test]
fn analyze_empty_findings_no_issues() {
    let findings = vec![];
    let html = r#"<html><body><p>No JavaScript libraries</p></body></html>"#;
    let issues = analyze_js_libraries(&findings, html);
    assert!(issues.is_empty());
}

// js_library_issues_to_operations tests (3)
#[test]
fn issues_to_operations_empty() {
    let issues = vec![];
    let mut seq = 0;
    let ops = js_library_issues_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn issues_to_operations_single() {
    let issues = vec![JsLibraryIssue::KnownVulnerable {
        library: "jQuery".to_string(),
        cve_pattern: "CVE-2020-11022".to_string(),
    }];
    let mut seq = 0;
    let ops = js_library_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn issues_to_operations_multiple() {
    let issues = vec![
        JsLibraryIssue::KnownVulnerable {
            library: "jQuery".to_string(),
            cve_pattern: "CVE-2020-11022".to_string(),
        },
        JsLibraryIssue::OutdatedLibrary {
            library: "Bootstrap".to_string(),
            version: "4.6.2".to_string(),
            min_safe: "5.2.0".to_string(),
        },
        JsLibraryIssue::EndOfLife {
            library: "AngularJS".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = js_library_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}
