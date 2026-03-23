use crate::sri_checker::*;
use crate::sri_checker::{SriIssue, find_missing_sri, sri_findings_to_operations};

// ── Existing tests (12) ─────────────────────────────────────────────

#[test]
fn detects_external_script_without_integrity() {
    let html = r#"<script src="https://cdn.example.com/lib.js"></script>"#;
    let issues = find_missing_sri(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].tag, "script");
    assert_eq!(issues[0].src, "https://cdn.example.com/lib.js");
}

#[test]
fn skips_script_with_integrity() {
    let html = r#"<script src="https://cdn.example.com/lib.js" integrity="sha384-abc123" crossorigin="anonymous"></script>"#;
    let issues = find_missing_sri(html);
    assert!(issues.is_empty());
}

#[test]
fn skips_local_script() {
    let html = r#"<script src="/js/app.js"></script>"#;
    let issues = find_missing_sri(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_protocol_relative_script() {
    let html = r#"<script src="//cdn.example.com/lib.js"></script>"#;
    let issues = find_missing_sri(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn detects_external_stylesheet_without_integrity() {
    let html = r#"<link rel="stylesheet" href="https://cdn.example.com/style.css">"#;
    let issues = find_missing_sri(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].tag, "link");
}

#[test]
fn skips_non_stylesheet_link() {
    let html = r#"<link rel="icon" href="https://cdn.example.com/favicon.ico">"#;
    let issues = find_missing_sri(html);
    assert!(issues.is_empty());
}

#[test]
fn skips_stylesheet_with_integrity() {
    let html = r#"<link rel="stylesheet" href="https://cdn.example.com/style.css" integrity="sha256-xyz">"#;
    let issues = find_missing_sri(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_multiple_issues() {
    let html = r#"
        <script src="https://cdn1.example.com/a.js"></script>
        <script src="https://cdn2.example.com/b.js"></script>
        <link rel="stylesheet" href="https://cdn3.example.com/c.css">
    "#;
    let issues = find_missing_sri(html);
    assert_eq!(issues.len(), 3);
}

#[test]
fn no_issues_in_plain_html() {
    let html = r#"<html><body><p>Hello</p></body></html>"#;
    let issues = find_missing_sri(html);
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = sri_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = vec![SriIssue {
        tag: "script".to_string(),
        src: "https://cdn.example.com/lib.js".to_string(),
    }];
    let mut seq = 0;
    let ops = sri_findings_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn handles_single_quoted_attributes() {
    let html = r#"<script src='https://cdn.example.com/lib.js'></script>"#;
    let issues = find_missing_sri(html);
    assert_eq!(issues.len(), 1);
}

// ── SriCheckIssue enum variant tests ────────────────────────────────

#[test]
fn analyze_detects_missing_sri_for_script() {
    let html = r#"<script src="https://cdn.example.com/lib.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::MissingSri { tag, .. } if tag == "script"))
    );
}

#[test]
fn analyze_detects_missing_sri_for_stylesheet() {
    let html = r#"<link rel="stylesheet" href="https://cdn.example.com/style.css">"#;
    let issues = analyze_sri(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::MissingSri { tag, .. } if tag == "link"))
    );
}

#[test]
fn analyze_detects_weak_sha256() {
    let html = r#"<script src="https://cdn.example.com/lib.js" integrity="sha256-abc123" crossorigin="anonymous"></script>"#;
    let issues = analyze_sri(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        SriCheckIssue::WeakHashAlgorithm { algorithm, .. } if algorithm == "sha256"
    )));
}

#[test]
fn analyze_no_weak_hash_for_sha384() {
    let html = r#"<script src="https://cdn.example.com/lib.js" integrity="sha384-abc123" crossorigin="anonymous"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::WeakHashAlgorithm { .. }))
    );
}

#[test]
fn analyze_no_weak_hash_for_sha512() {
    let html = r#"<script src="https://cdn.example.com/lib.js" integrity="sha512-abc123" crossorigin="anonymous"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::WeakHashAlgorithm { .. }))
    );
}

#[test]
fn analyze_detects_missing_crossorigin() {
    let html =
        r#"<script src="https://cdn.example.com/lib.js" integrity="sha384-abc123"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::MissingCrossorigin { .. }))
    );
}

#[test]
fn analyze_no_missing_crossorigin_when_present() {
    let html = r#"<script src="https://cdn.example.com/lib.js" integrity="sha384-abc123" crossorigin="anonymous"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::MissingCrossorigin { .. }))
    );
}

#[test]
fn analyze_detects_http_resource() {
    let html = r#"<script src="http://cdn.example.com/lib.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::HttpResource { .. }))
    );
}

#[test]
fn analyze_no_http_resource_for_https() {
    let html = r#"<script src="https://cdn.example.com/lib.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::HttpResource { .. }))
    );
}

#[test]
fn analyze_detects_protocol_relative() {
    let html = r#"<script src="//cdn.example.com/lib.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::ProtocolRelative { .. }))
    );
}

#[test]
fn analyze_no_protocol_relative_for_https() {
    let html = r#"<script src="https://cdn.example.com/lib.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::ProtocolRelative { .. }))
    );
}

#[test]
fn analyze_detects_dynamic_src_dollar_brace() {
    let html = r#"<script src="${API_URL}/bundle.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::DynamicSrc { .. }))
    );
}

#[test]
fn analyze_detects_dynamic_src_double_brace() {
    let html = r#"<script src="{{baseUrl}}/app.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::DynamicSrc { .. }))
    );
}

#[test]
fn analyze_detects_dynamic_src_encoded_brace() {
    let html = r#"<script src="https://cdn.example.com/%7Bpath%7B/lib.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::DynamicSrc { .. }))
    );
}

#[test]
fn analyze_detects_integrity_mismatch_bad_prefix() {
    let html = r#"<script src="https://cdn.example.com/lib.js" integrity="md5-abc123" crossorigin="anonymous"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::InlineIntegrityMismatch { .. }))
    );
}

#[test]
fn analyze_no_mismatch_for_valid_sha384() {
    let html = r#"<script src="https://cdn.example.com/lib.js" integrity="sha384-abc123" crossorigin="anonymous"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::InlineIntegrityMismatch { .. }))
    );
}

#[test]
fn analyze_detects_integrity_mismatch_empty_value() {
    let html = r#"<script src="https://cdn.example.com/lib.js" integrity="badvalue" crossorigin="anonymous"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::InlineIntegrityMismatch { .. }))
    );
}

// ── Known CDN detection ─────────────────────────────────────────────

#[test]
fn analyze_detects_cdnjs_cloudflare() {
    let html = r#"<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        SriCheckIssue::ThirdPartyCdn { cdn, .. } if cdn == "cdnjs.cloudflare.com"
    )));
}

#[test]
fn analyze_detects_jsdelivr() {
    let html = r#"<script src="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        SriCheckIssue::ThirdPartyCdn { cdn, .. } if cdn == "cdn.jsdelivr.net"
    )));
}

#[test]
fn analyze_detects_unpkg() {
    let html = r#"<script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        SriCheckIssue::ThirdPartyCdn { cdn, .. } if cdn == "unpkg.com"
    )));
}

#[test]
fn analyze_detects_googleapis() {
    let html = r#"<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        SriCheckIssue::ThirdPartyCdn { cdn, .. } if cdn == "ajax.googleapis.com"
    )));
}

#[test]
fn analyze_detects_bootstrapcdn() {
    let html = r#"<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">"#;
    let issues = analyze_sri(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        SriCheckIssue::ThirdPartyCdn { cdn, .. } if cdn == "stackpath.bootstrapcdn.com"
    )));
}

#[test]
fn analyze_detects_jquery_cdn() {
    let html = r#"<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        SriCheckIssue::ThirdPartyCdn { cdn, .. } if cdn == "code.jquery.com"
    )));
}

#[test]
fn analyze_no_cdn_for_unknown_domain() {
    let html = r#"<script src="https://myserver.example.com/lib.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::ThirdPartyCdn { .. }))
    );
}

// ── Excessive external resources ────────────────────────────────────

#[test]
fn analyze_detects_excessive_external_resources() {
    let html = (0..7)
        .map(|i| format!(r#"<script src="https://cdn{i}.example.com/lib.js"></script>"#))
        .collect::<Vec<_>>()
        .join("\n");
    let issues = analyze_sri(&html);
    assert!(issues.iter().any(|i| matches!(
        i,
        SriCheckIssue::ExcessiveExternalResources { count } if *count == 7
    )));
}

#[test]
fn analyze_no_excessive_for_five_or_fewer() {
    let html = (0..5)
        .map(|i| format!(r#"<script src="https://cdn{i}.example.com/lib.js"></script>"#))
        .collect::<Vec<_>>()
        .join("\n");
    let issues = analyze_sri(&html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::ExcessiveExternalResources { .. }))
    );
}

#[test]
fn analyze_excessive_threshold_is_six() {
    let html = (0..6)
        .map(|i| format!(r#"<script src="https://cdn{i}.example.com/lib.js"></script>"#))
        .collect::<Vec<_>>()
        .join("\n");
    let issues = analyze_sri(&html);
    assert!(issues.iter().any(|i| matches!(
        i,
        SriCheckIssue::ExcessiveExternalResources { count } if *count == 6
    )));
}

// ── Edge cases ──────────────────────────────────────────────────────

#[test]
fn analyze_empty_html() {
    let issues = analyze_sri("");
    assert!(issues.is_empty());
}

#[test]
fn analyze_no_external_resources() {
    let html = r#"<html><head><script src="/local.js"></script></head><body></body></html>"#;
    let issues = analyze_sri(html);
    assert!(issues.is_empty());
}

#[test]
fn analyze_all_with_integrity() {
    let html = r#"
        <script src="https://cdn.example.com/a.js" integrity="sha384-abc" crossorigin="anonymous"></script>
        <script src="https://cdn.example.com/b.js" integrity="sha512-def" crossorigin="anonymous"></script>
    "#;
    let issues = analyze_sri(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::MissingSri { .. }))
    );
}

#[test]
fn analyze_skips_non_stylesheet_links() {
    let html = r#"<link rel="icon" href="https://cdn.example.com/favicon.ico">"#;
    let issues = analyze_sri(html);
    assert!(issues.is_empty());
}

#[test]
fn analyze_http_stylesheet() {
    let html = r#"<link rel="stylesheet" href="http://cdn.example.com/style.css">"#;
    let issues = analyze_sri(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::HttpResource { tag, .. } if tag == "link"))
    );
}

#[test]
fn analyze_protocol_relative_stylesheet() {
    let html = r#"<link rel="stylesheet" href="//cdn.example.com/style.css">"#;
    let issues = analyze_sri(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::ProtocolRelative { tag, .. } if tag == "link"))
    );
}

#[test]
fn analyze_mixed_issues_on_single_tag() {
    let html = r#"<script src="http://cdn.example.com/lib.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::HttpResource { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::MissingSri { .. }))
    );
}

#[test]
fn analyze_cdn_with_protocol_relative() {
    let html = r#"<script src="//cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>"#;
    let issues = analyze_sri(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SriCheckIssue::ProtocolRelative { .. }))
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        SriCheckIssue::ThirdPartyCdn { cdn, .. } if cdn == "cdnjs.cloudflare.com"
    )));
}

// ── Severity tests ──────────────────────────────────────────────────

#[test]
fn severity_http_resource_highest() {
    let issue = SriCheckIssue::HttpResource {
        tag: "script".into(),
        src: "http://x.com/a.js".into(),
    };
    assert_eq!(sri_check_severity(&issue), 7.0);
}

#[test]
fn severity_mixed_content_high() {
    let issue = SriCheckIssue::MixedContent {
        src: "http://x.com/a.js".into(),
    };
    assert_eq!(sri_check_severity(&issue), 6.5);
}

#[test]
fn severity_integrity_mismatch() {
    let issue = SriCheckIssue::InlineIntegrityMismatch {
        tag: "script".into(),
        src: "https://x.com/a.js".into(),
    };
    assert_eq!(sri_check_severity(&issue), 6.0);
}

#[test]
fn severity_missing_sri() {
    let issue = SriCheckIssue::MissingSri {
        tag: "script".into(),
        src: "https://x.com/a.js".into(),
    };
    assert_eq!(sri_check_severity(&issue), 5.0);
}

#[test]
fn severity_third_party_cdn() {
    let issue = SriCheckIssue::ThirdPartyCdn {
        tag: "script".into(),
        src: "https://cdn.jsdelivr.net/a.js".into(),
        cdn: "cdn.jsdelivr.net".into(),
    };
    assert_eq!(sri_check_severity(&issue), 5.0);
}

#[test]
fn severity_weak_hash() {
    let issue = SriCheckIssue::WeakHashAlgorithm {
        tag: "script".into(),
        src: "https://x.com/a.js".into(),
        algorithm: "sha256".into(),
    };
    assert_eq!(sri_check_severity(&issue), 4.0);
}

#[test]
fn severity_excessive() {
    let issue = SriCheckIssue::ExcessiveExternalResources { count: 8 };
    assert_eq!(sri_check_severity(&issue), 4.5);
}

#[test]
fn severity_missing_crossorigin() {
    let issue = SriCheckIssue::MissingCrossorigin {
        tag: "script".into(),
        src: "https://x.com/a.js".into(),
    };
    assert_eq!(sri_check_severity(&issue), 3.5);
}

#[test]
fn severity_protocol_relative() {
    let issue = SriCheckIssue::ProtocolRelative {
        tag: "script".into(),
        src: "//x.com/a.js".into(),
    };
    assert_eq!(sri_check_severity(&issue), 3.5);
}

#[test]
fn severity_dynamic_src() {
    let issue = SriCheckIssue::DynamicSrc {
        tag: "script".into(),
    };
    assert_eq!(sri_check_severity(&issue), 3.0);
}

#[test]
fn severity_ordering_http_above_missing_sri() {
    let http = SriCheckIssue::HttpResource {
        tag: "script".into(),
        src: "http://x.com/a.js".into(),
    };
    let missing = SriCheckIssue::MissingSri {
        tag: "script".into(),
        src: "https://x.com/a.js".into(),
    };
    assert!(sri_check_severity(&http) > sri_check_severity(&missing));
}

#[test]
fn severity_ordering_missing_sri_above_weak_hash() {
    let missing = SriCheckIssue::MissingSri {
        tag: "script".into(),
        src: "https://x.com/a.js".into(),
    };
    let weak = SriCheckIssue::WeakHashAlgorithm {
        tag: "script".into(),
        src: "https://x.com/a.js".into(),
        algorithm: "sha256".into(),
    };
    assert!(sri_check_severity(&missing) > sri_check_severity(&weak));
}

// ── Display tests ───────────────────────────────────────────────────

#[test]
fn display_missing_sri() {
    let issue = SriCheckIssue::MissingSri {
        tag: "script".into(),
        src: "https://x.com/a.js".into(),
    };
    assert_eq!(issue.to_string(), "missing_sri:script:https://x.com/a.js");
}

#[test]
fn display_weak_hash() {
    let issue = SriCheckIssue::WeakHashAlgorithm {
        tag: "script".into(),
        src: "https://x.com/a.js".into(),
        algorithm: "sha256".into(),
    };
    assert_eq!(
        issue.to_string(),
        "weak_hash:script:https://x.com/a.js:sha256"
    );
}

#[test]
fn display_missing_crossorigin() {
    let issue = SriCheckIssue::MissingCrossorigin {
        tag: "link".into(),
        src: "https://x.com/s.css".into(),
    };
    assert_eq!(
        issue.to_string(),
        "missing_crossorigin:link:https://x.com/s.css"
    );
}

#[test]
fn display_http_resource() {
    let issue = SriCheckIssue::HttpResource {
        tag: "script".into(),
        src: "http://x.com/a.js".into(),
    };
    assert_eq!(issue.to_string(), "http_resource:script:http://x.com/a.js");
}

#[test]
fn display_mixed_content() {
    let issue = SriCheckIssue::MixedContent {
        src: "http://x.com/a.js".into(),
    };
    assert_eq!(issue.to_string(), "mixed_content:http://x.com/a.js");
}

#[test]
fn display_protocol_relative() {
    let issue = SriCheckIssue::ProtocolRelative {
        tag: "script".into(),
        src: "//x.com/a.js".into(),
    };
    assert_eq!(issue.to_string(), "protocol_relative:script://x.com/a.js");
}

#[test]
fn display_third_party_cdn() {
    let issue = SriCheckIssue::ThirdPartyCdn {
        tag: "script".into(),
        src: "https://cdn.jsdelivr.net/a.js".into(),
        cdn: "cdn.jsdelivr.net".into(),
    };
    assert_eq!(
        issue.to_string(),
        "third_party_cdn:script:https://cdn.jsdelivr.net/a.js:cdn.jsdelivr.net"
    );
}

#[test]
fn display_dynamic_src() {
    let issue = SriCheckIssue::DynamicSrc {
        tag: "script".into(),
    };
    assert_eq!(issue.to_string(), "dynamic_src:script");
}

#[test]
fn display_integrity_mismatch() {
    let issue = SriCheckIssue::InlineIntegrityMismatch {
        tag: "script".into(),
        src: "https://x.com/a.js".into(),
    };
    assert_eq!(
        issue.to_string(),
        "integrity_mismatch:script:https://x.com/a.js"
    );
}

#[test]
fn display_excessive_external() {
    let issue = SriCheckIssue::ExcessiveExternalResources { count: 12 };
    assert_eq!(issue.to_string(), "excessive_external:12");
}

// ── Operations tests ────────────────────────────────────────────────

#[test]
fn sri_check_operations_empty_for_no_issues() {
    let mut seq = 0;
    let ops = sri_check_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn sri_check_operations_one_per_issue() {
    let issues = vec![
        SriCheckIssue::MissingSri {
            tag: "script".into(),
            src: "https://x.com/a.js".into(),
        },
        SriCheckIssue::HttpResource {
            tag: "script".into(),
            src: "http://x.com/b.js".into(),
        },
    ];
    let mut seq = 0;
    let ops = sri_check_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn sri_check_operations_increments_seq() {
    let issues = vec![
        SriCheckIssue::DynamicSrc {
            tag: "script".into(),
        },
        SriCheckIssue::ProtocolRelative {
            tag: "link".into(),
            src: "//x.com/s.css".into(),
        },
        SriCheckIssue::WeakHashAlgorithm {
            tag: "script".into(),
            src: "https://x.com/a.js".into(),
            algorithm: "sha256".into(),
        },
    ];
    let mut seq = 10;
    let ops = sri_check_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
}

// ── Helper function tests ───────────────────────────────────────────

#[test]
fn is_external_resource_http() {
    assert!(is_external_resource("http://example.com/lib.js"));
}

#[test]
fn is_external_resource_https() {
    assert!(is_external_resource("https://example.com/lib.js"));
}

#[test]
fn is_external_resource_protocol_relative() {
    assert!(is_external_resource("//example.com/lib.js"));
}

#[test]
fn is_external_resource_relative_path() {
    assert!(!is_external_resource("/js/app.js"));
}

#[test]
fn is_external_resource_bare_filename() {
    assert!(!is_external_resource("app.js"));
}

#[test]
fn is_stylesheet_double_quote() {
    assert!(is_stylesheet(r#"<link rel="stylesheet" href="x.css">"#));
}

#[test]
fn is_stylesheet_single_quote() {
    assert!(is_stylesheet("<link rel='stylesheet' href='x.css'>"));
}

#[test]
fn is_stylesheet_icon_link() {
    assert!(!is_stylesheet(r#"<link rel="icon" href="x.ico">"#));
}
