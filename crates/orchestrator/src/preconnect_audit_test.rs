use crate::preconnect_audit::{
    PreconnectIssueKind, PreconnectSecurityIssue, analyze_preconnect_security, analyze_preconnects,
    preconnect_security_severity, preconnect_security_to_operations, preconnect_to_operations,
};

#[test]
fn detects_http_preconnect() {
    let html = r#"<link rel="preconnect" href="http://fonts.googleapis.com">"#;
    let issues = analyze_preconnects(html);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == PreconnectIssueKind::HttpOrigin)
    );
}

#[test]
fn detects_http_dns_prefetch() {
    let html = r#"<link rel="dns-prefetch" href="http://cdn.example.com">"#;
    let issues = analyze_preconnects(html);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == PreconnectIssueKind::HttpOrigin)
    );
}

#[test]
fn accepts_https_preconnect() {
    let html = r#"<link rel="preconnect" href="https://fonts.googleapis.com" crossorigin>"#;
    let issues = analyze_preconnects(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_missing_crossorigin() {
    let html = r#"<link rel="preconnect" href="https://cdn.example.com">"#;
    let issues = analyze_preconnects(html);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == PreconnectIssueKind::MissingCrossorigin)
    );
}

#[test]
fn crossorigin_present_no_issue() {
    let html = r#"<link rel="preconnect" href="https://cdn.example.com" crossorigin="anonymous">"#;
    let issues = analyze_preconnects(html);
    assert!(
        !issues
            .iter()
            .any(|i| i.kind == PreconnectIssueKind::MissingCrossorigin)
    );
}

#[test]
fn detects_excessive_preconnects() {
    let links: Vec<String> = (0..8)
        .map(|i| {
            format!(r#"<link rel="preconnect" href="https://cdn{i}.example.com" crossorigin>"#)
        })
        .collect();
    let html = links.join("\n");
    let issues = analyze_preconnects(&html);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == PreconnectIssueKind::ExcessivePreconnects)
    );
}

#[test]
fn six_preconnects_is_ok() {
    let links: Vec<String> = (0..6)
        .map(|i| {
            format!(r#"<link rel="preconnect" href="https://cdn{i}.example.com" crossorigin>"#)
        })
        .collect();
    let html = links.join("\n");
    let issues = analyze_preconnects(&html);
    assert!(
        !issues
            .iter()
            .any(|i| i.kind == PreconnectIssueKind::ExcessivePreconnects)
    );
}

#[test]
fn ignores_stylesheet_link() {
    let html = r#"<link rel="stylesheet" href="http://example.com/style.css">"#;
    let issues = analyze_preconnects(html);
    assert!(issues.is_empty());
}

#[test]
fn empty_href_skipped() {
    let html = r#"<link rel="preconnect" href="">"#;
    let issues = analyze_preconnects(html);
    assert!(issues.is_empty());
}

#[test]
fn no_link_tags() {
    let html = "<html><body><p>Hello</p></body></html>";
    let issues = analyze_preconnects(html);
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = preconnect_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let html = r#"<link rel="preconnect" href="http://cdn.example.com">"#;
    let issues = analyze_preconnects(html);
    let mut seq = 0;
    let ops = preconnect_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn display_variants() {
    assert!(!format!("{}", PreconnectIssueKind::HttpOrigin).is_empty());
    assert!(!format!("{}", PreconnectIssueKind::MissingCrossorigin).is_empty());
    assert!(!format!("{}", PreconnectIssueKind::ExcessivePreconnects).is_empty());
}

// ============================================================================
// NEW SECURITY ANALYSIS TESTS
// ============================================================================

#[test]
fn security_detects_http_preconnect() {
    let html = r#"<link rel="preconnect" href="http://cdn.example.com">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::HttpPreconnect { .. }))
    );
}

#[test]
fn security_accepts_https_preconnect() {
    let html = r#"<link rel="preconnect" href="https://cdn.example.com" crossorigin>"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::HttpPreconnect { .. }))
    );
}

#[test]
fn security_detects_third_party_preconnect() {
    let html = r#"<link rel="preconnect" href="https://cdn.somethirdparty.net" crossorigin>"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::ThirdPartyPreconnect { .. }))
    );
}

#[test]
fn security_allows_localhost_preconnect() {
    let html = r#"<link rel="preconnect" href="http://localhost:8080">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::ThirdPartyPreconnect { .. }))
    );
}

#[test]
fn security_detects_excessive_resource_hints() {
    let links: Vec<String> = (0..12)
        .map(|i| {
            format!(r#"<link rel="preconnect" href="https://cdn{i}.example.com" crossorigin>"#)
        })
        .collect();
    let html = links.join("\n");
    let issues = analyze_preconnect_security(&html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::ExcessiveResourceHints { .. }))
    );
}

#[test]
fn security_accepts_reasonable_resource_hints() {
    let links: Vec<String> = (0..5)
        .map(|i| {
            format!(r#"<link rel="preconnect" href="https://cdn{i}.example.com" crossorigin>"#)
        })
        .collect();
    let html = links.join("\n");
    let issues = analyze_preconnect_security(&html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::ExcessiveResourceHints { .. }))
    );
}

#[test]
fn security_detects_tracking_pixel_google_analytics() {
    let html = r#"<link rel="preconnect" href="https://www.google-analytics.com" crossorigin>"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::TrackingPixelPreconnect { .. }))
    );
}

#[test]
fn security_detects_tracking_pixel_facebook() {
    let html = r#"<link rel="dns-prefetch" href="https://connect.facebook.net">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::TrackingPixelPreconnect { .. }))
    );
}

#[test]
fn security_detects_tracking_pixel_doubleclick() {
    let html = r#"<link rel="preconnect" href="https://ad.doubleclick.net" crossorigin>"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::TrackingPixelPreconnect { .. }))
    );
}

#[test]
fn security_allows_non_tracking_domain() {
    let html = r#"<link rel="preconnect" href="https://fonts.googleapis.com" crossorigin>"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::TrackingPixelPreconnect { .. }))
    );
}

#[test]
fn security_detects_missing_crossorigin() {
    let html = r#"<link rel="preconnect" href="https://cdn.example.com">"#;
    let issues = analyze_preconnect_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        PreconnectSecurityIssue::MissingCrossoriginAttribute { .. }
    )));
}

#[test]
fn security_accepts_crossorigin_present() {
    let html = r#"<link rel="preconnect" href="https://cdn.example.com" crossorigin>"#;
    let issues = analyze_preconnect_security(html);
    assert!(!issues.iter().any(|i| matches!(
        i,
        PreconnectSecurityIssue::MissingCrossoriginAttribute { .. }
    )));
}

#[test]
fn security_detects_suspicious_tld_tk() {
    let html = r#"<link rel="preconnect" href="https://malicious.tk" crossorigin>"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::PreconnectToSuspiciousTld { .. }))
    );
}

#[test]
fn security_detects_suspicious_tld_ml() {
    let html = r#"<link rel="dns-prefetch" href="https://phishing.ml">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::PreconnectToSuspiciousTld { .. }))
    );
}

#[test]
fn security_detects_suspicious_tld_xyz() {
    let html = r#"<link rel="preconnect" href="https://suspicious.xyz">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::PreconnectToSuspiciousTld { .. }))
    );
}

#[test]
fn security_accepts_trusted_tld() {
    let html = r#"<link rel="preconnect" href="https://cdn.example.com" crossorigin>"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::PreconnectToSuspiciousTld { .. }))
    );
}

#[test]
fn security_detects_dns_prefetch_to_external() {
    let html = r#"<link rel="dns-prefetch" href="https://external.com">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::DnsPrefetchToExternal { .. }))
    );
}

#[test]
fn security_accepts_dns_prefetch_to_localhost() {
    let html = r#"<link rel="dns-prefetch" href="http://localhost:3000">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::DnsPrefetchToExternal { .. }))
    );
}

#[test]
fn security_detects_preload_script_without_integrity() {
    let html = r#"<link rel="preload" href="https://cdn.example.com/script.js" as="script">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::PreloadWithoutIntegrity { .. }))
    );
}

#[test]
fn security_detects_preload_style_without_integrity() {
    let html = r#"<link rel="preload" href="https://cdn.example.com/style.css" as="style">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::PreloadWithoutIntegrity { .. }))
    );
}

#[test]
fn security_accepts_preload_with_integrity() {
    let html = r#"<link rel="preload" href="https://cdn.example.com/script.js" as="script" integrity="sha384-xyz">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::PreloadWithoutIntegrity { .. }))
    );
}

#[test]
fn security_accepts_preload_non_script() {
    let html = r#"<link rel="preload" href="https://cdn.example.com/font.woff2" as="font">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::PreloadWithoutIntegrity { .. }))
    );
}

#[test]
fn security_detects_prerender_external_url() {
    let html = r#"<link rel="prerender" href="https://external.com/page">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::PrerenderExternalUrl { .. }))
    );
}

#[test]
fn security_detects_prerender_protocol_relative() {
    let html = r#"<link rel="prerender" href="//external.com/page">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::PrerenderExternalUrl { .. }))
    );
}

#[test]
fn security_accepts_prerender_relative_path() {
    let html = r#"<link rel="prerender" href="/next-page">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::PrerenderExternalUrl { .. }))
    );
}

#[test]
fn security_detects_duplicate_resource_hint() {
    let html = r#"
        <link rel="preconnect" href="https://cdn.example.com" crossorigin>
        <link rel="dns-prefetch" href="https://cdn.example.com">
    "#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::DuplicateResourceHint { .. }))
    );
}

#[test]
fn security_allows_unique_resource_hints() {
    let html = r#"
        <link rel="preconnect" href="https://cdn1.example.com" crossorigin>
        <link rel="preconnect" href="https://cdn2.example.com" crossorigin>
    "#;
    let issues = analyze_preconnect_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::DuplicateResourceHint { .. }))
    );
}

#[test]
fn security_empty_html() {
    let html = "";
    let issues = analyze_preconnect_security(html);
    assert!(issues.is_empty());
}

#[test]
fn security_no_link_tags() {
    let html = "<html><body><p>No links here</p></body></html>";
    let issues = analyze_preconnect_security(html);
    assert!(issues.is_empty());
}

#[test]
fn security_ignores_stylesheet_link() {
    let html = r#"<link rel="stylesheet" href="http://example.com/style.css">"#;
    let issues = analyze_preconnect_security(html);
    assert!(issues.is_empty());
}

#[test]
fn security_ignores_empty_href() {
    let html = r#"<link rel="preconnect" href="">"#;
    let issues = analyze_preconnect_security(html);
    assert!(issues.is_empty());
}

#[test]
fn security_multiple_issues_same_tag() {
    let html = r#"<link rel="preconnect" href="http://google-analytics.com">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::HttpPreconnect { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::TrackingPixelPreconnect { .. }))
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        PreconnectSecurityIssue::MissingCrossoriginAttribute { .. }
    )));
}

#[test]
fn security_display_http_preconnect() {
    let issue = PreconnectSecurityIssue::HttpPreconnect {
        href: "http://example.com".to_string(),
    };
    let display = format!("{}", issue);
    assert!(display.contains("HTTP"));
    assert!(display.contains("http://example.com"));
}

#[test]
fn security_display_third_party() {
    let issue = PreconnectSecurityIssue::ThirdPartyPreconnect {
        href: "https://third.party".to_string(),
    };
    let display = format!("{}", issue);
    assert!(display.contains("third-party"));
}

#[test]
fn security_display_excessive_hints() {
    let issue = PreconnectSecurityIssue::ExcessiveResourceHints { count: 15 };
    let display = format!("{}", issue);
    assert!(display.contains("15"));
}

#[test]
fn security_display_tracking_pixel() {
    let issue = PreconnectSecurityIssue::TrackingPixelPreconnect {
        href: "https://google-analytics.com".to_string(),
    };
    let display = format!("{}", issue);
    assert!(display.contains("tracking"));
}

#[test]
fn security_display_missing_crossorigin() {
    let issue = PreconnectSecurityIssue::MissingCrossoriginAttribute {
        href: "https://cdn.example.com".to_string(),
    };
    let display = format!("{}", issue);
    assert!(display.contains("crossorigin"));
}

#[test]
fn security_display_suspicious_tld() {
    let issue = PreconnectSecurityIssue::PreconnectToSuspiciousTld {
        href: "https://malicious.tk".to_string(),
        tld: ".tk".to_string(),
    };
    let display = format!("{}", issue);
    assert!(display.contains(".tk"));
}

#[test]
fn security_display_dns_prefetch() {
    let issue = PreconnectSecurityIssue::DnsPrefetchToExternal {
        href: "https://external.com".to_string(),
    };
    let display = format!("{}", issue);
    assert!(display.contains("dns-prefetch"));
}

#[test]
fn security_display_preload_integrity() {
    let issue = PreconnectSecurityIssue::PreloadWithoutIntegrity {
        href: "https://cdn.example.com/script.js".to_string(),
    };
    let display = format!("{}", issue);
    assert!(display.contains("integrity"));
}

#[test]
fn security_display_prerender() {
    let issue = PreconnectSecurityIssue::PrerenderExternalUrl {
        href: "https://external.com/page".to_string(),
    };
    let display = format!("{}", issue);
    assert!(display.contains("prerender"));
}

#[test]
fn security_display_duplicate() {
    let issue = PreconnectSecurityIssue::DuplicateResourceHint {
        href: "https://cdn.example.com".to_string(),
    };
    let display = format!("{}", issue);
    assert!(display.contains("duplicate"));
}

#[test]
fn security_severity_http_preconnect_highest() {
    let issue = PreconnectSecurityIssue::HttpPreconnect {
        href: "http://example.com".to_string(),
    };
    assert_eq!(preconnect_security_severity(&issue), 6.0);
}

#[test]
fn security_severity_preload_integrity() {
    let issue = PreconnectSecurityIssue::PreloadWithoutIntegrity {
        href: "https://cdn.example.com/script.js".to_string(),
    };
    assert_eq!(preconnect_security_severity(&issue), 5.5);
}

#[test]
fn security_severity_suspicious_tld() {
    let issue = PreconnectSecurityIssue::PreconnectToSuspiciousTld {
        href: "https://malicious.tk".to_string(),
        tld: ".tk".to_string(),
    };
    assert_eq!(preconnect_security_severity(&issue), 5.0);
}

#[test]
fn security_severity_tracking_pixel() {
    let issue = PreconnectSecurityIssue::TrackingPixelPreconnect {
        href: "https://google-analytics.com".to_string(),
    };
    assert_eq!(preconnect_security_severity(&issue), 4.0);
}

#[test]
fn security_severity_prerender() {
    let issue = PreconnectSecurityIssue::PrerenderExternalUrl {
        href: "https://external.com/page".to_string(),
    };
    assert_eq!(preconnect_security_severity(&issue), 3.5);
}

#[test]
fn security_severity_missing_crossorigin() {
    let issue = PreconnectSecurityIssue::MissingCrossoriginAttribute {
        href: "https://cdn.example.com".to_string(),
    };
    assert_eq!(preconnect_security_severity(&issue), 3.0);
}

#[test]
fn security_severity_third_party() {
    let issue = PreconnectSecurityIssue::ThirdPartyPreconnect {
        href: "https://third.party".to_string(),
    };
    assert_eq!(preconnect_security_severity(&issue), 2.5);
}

#[test]
fn security_severity_dns_prefetch() {
    let issue = PreconnectSecurityIssue::DnsPrefetchToExternal {
        href: "https://external.com".to_string(),
    };
    assert_eq!(preconnect_security_severity(&issue), 2.0);
}

#[test]
fn security_severity_excessive_hints() {
    let issue = PreconnectSecurityIssue::ExcessiveResourceHints { count: 15 };
    assert_eq!(preconnect_security_severity(&issue), 2.0);
}

#[test]
fn security_severity_duplicate_lowest() {
    let issue = PreconnectSecurityIssue::DuplicateResourceHint {
        href: "https://cdn.example.com".to_string(),
    };
    assert_eq!(preconnect_security_severity(&issue), 1.5);
}

#[test]
fn security_operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = preconnect_security_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn security_operations_produced_for_single_issue() {
    let html = r#"<link rel="preconnect" href="http://cdn.example.com">"#;
    let issues = analyze_preconnect_security(html);
    let mut seq = 100;
    let ops = preconnect_security_to_operations(&issues, &mut seq);
    assert!(!ops.is_empty());
    assert!(seq > 100);
}

#[test]
fn security_operations_produced_for_multiple_issues() {
    let html = r#"
        <link rel="preconnect" href="http://google-analytics.com">
        <link rel="preconnect" href="https://malicious.tk">
    "#;
    let issues = analyze_preconnect_security(html);
    let mut seq = 0;
    let ops = preconnect_security_to_operations(&issues, &mut seq);
    assert!(ops.len() >= 2);
}

#[test]
fn security_edge_case_protocol_relative_url() {
    let html = r#"<link rel="preconnect" href="//cdn.thirdparty.net">"#;
    let issues = analyze_preconnect_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        PreconnectSecurityIssue::MissingCrossoriginAttribute { .. }
    )));
}

#[test]
fn security_edge_case_uppercase_rel() {
    let html = r#"<link rel="PRECONNECT" href="http://example.com">"#;
    let issues = analyze_preconnect_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PreconnectSecurityIssue::HttpPreconnect { .. }))
    );
}

#[test]
fn security_edge_case_mixed_case_crossorigin() {
    let html = r#"<link rel="preconnect" href="https://cdn.example.com" CrossOrigin>"#;
    let issues = analyze_preconnect_security(html);
    assert!(!issues.iter().any(|i| matches!(
        i,
        PreconnectSecurityIssue::MissingCrossoriginAttribute { .. }
    )));
}

#[test]
fn security_comprehensive_tracking_domains() {
    let domains = vec![
        "google-analytics.com",
        "googletagmanager.com",
        "facebook.com",
        "doubleclick.net",
        "hotjar.com",
        "mixpanel.com",
    ];
    for domain in domains {
        let html = format!(
            r#"<link rel="preconnect" href="https://{}" crossorigin>"#,
            domain
        );
        let issues = analyze_preconnect_security(&html);
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, PreconnectSecurityIssue::TrackingPixelPreconnect { .. })),
            "Failed to detect tracking domain: {}",
            domain
        );
    }
}

#[test]
fn security_comprehensive_suspicious_tlds() {
    let tlds = vec![".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".xyz"];
    for tld in tlds {
        let html = format!(
            r#"<link rel="preconnect" href="https://malicious{}" crossorigin>"#,
            tld
        );
        let issues = analyze_preconnect_security(&html);
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, PreconnectSecurityIssue::PreconnectToSuspiciousTld { .. })),
            "Failed to detect suspicious TLD: {}",
            tld
        );
    }
}
