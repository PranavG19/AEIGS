use crate::link_header_audit::{
    LinkIssueKind, LinkSecurityIssue, analyze_link_headers, analyze_link_security,
    extract_link_url, extract_rel, link_header_to_operations, link_security_severity,
    link_security_to_operations,
};

#[test]
fn no_headers_no_issues() {
    let issues = analyze_link_headers(&[], Some("example.com"));
    assert!(issues.is_empty());
}

#[test]
fn same_domain_preload_ok() {
    let vals = vec![r#"<https://example.com/style.css>; rel="preload"; as="style""#.to_string()];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(issues.is_empty());
}

#[test]
fn external_preload_flagged() {
    let vals = vec![r#"<https://evil.com/track.js>; rel="preload"; as="script""#.to_string()];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == LinkIssueKind::ExternalPreload)
    );
}

#[test]
fn external_prefetch_flagged() {
    let vals = vec![r#"<https://cdn.other.com/data.json>; rel="prefetch""#.to_string()];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == LinkIssueKind::ExternalPreload)
    );
}

#[test]
fn dns_prefetch_external_flagged() {
    let vals = vec![r#"<https://tracker.io>; rel="dns-prefetch""#.to_string()];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == LinkIssueKind::DnsPrefetchExternal)
    );
}

#[test]
fn http_resource_flagged() {
    let vals = vec![r#"<http://example.com/style.css>; rel="stylesheet""#.to_string()];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(issues.iter().any(|i| i.kind == LinkIssueKind::HttpResource));
}

#[test]
fn subdomain_not_external() {
    let vals = vec![r#"<https://cdn.example.com/app.js>; rel="preload"; as="script""#.to_string()];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| i.kind == LinkIssueKind::ExternalPreload)
    );
}

#[test]
fn multiple_links_comma_separated() {
    let vals = vec![
        r#"<https://evil.com/a.js>; rel="preload", <https://example.com/b.css>; rel="stylesheet""#
            .to_string(),
    ];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert_eq!(
        issues
            .iter()
            .filter(|i| i.kind == LinkIssueKind::ExternalPreload)
            .count(),
        1
    );
}

#[test]
fn no_target_domain_skips_external() {
    let vals = vec![r#"<https://evil.com/a.js>; rel="preload""#.to_string()];
    let issues = analyze_link_headers(&vals, None);
    assert!(
        !issues
            .iter()
            .any(|i| i.kind == LinkIssueKind::ExternalPreload)
    );
}

#[test]
fn modulepreload_detected() {
    let vals = vec![r#"<https://attacker.com/mod.js>; rel="modulepreload""#.to_string()];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == LinkIssueKind::ExternalPreload)
    );
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = link_header_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_on_issues() {
    let vals = vec![r#"<http://example.com/x>; rel="stylesheet""#.to_string()];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    let mut seq = 5;
    let ops = link_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}

#[test]
fn empty_url_skipped() {
    let vals = vec![r#"<>; rel="preload""#.to_string()];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(issues.is_empty());
}

// LinkSecurityIssue tests

#[test]
fn cross_origin_preload_detected() {
    let vals = vec![r#"<https://external.com/script.js>; rel="preload"; as="script""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::CrossOriginPreload));
}

#[test]
fn cross_origin_preload_negative() {
    let vals = vec![r#"<https://example.com/script.js>; rel="preload"; as="script""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(!issues.contains(&LinkSecurityIssue::CrossOriginPreload));
}

#[test]
fn http_preload_detected() {
    let vals = vec![r#"<http://example.com/script.js>; rel="preload"; as="script""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::HttpPreload));
}

#[test]
fn http_preload_negative() {
    let vals = vec![r#"<https://example.com/script.js>; rel="preload"; as="script""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(!issues.contains(&LinkSecurityIssue::HttpPreload));
}

#[test]
fn untrusted_cdn_preload_detected() {
    let vals =
        vec![r#"<https://untrusted-cdn.com/lib.js>; rel="preload"; as="script""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::UntrustedCdnPreload));
}

#[test]
fn untrusted_cdn_preload_with_integrity_ok() {
    let vals = vec![
        r#"<https://untrusted-cdn.com/lib.js>; rel="preload"; as="script"; integrity="sha256-abc""#
            .to_string(),
    ];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(!issues.contains(&LinkSecurityIssue::UntrustedCdnPreload));
}

#[test]
fn trusted_cdn_without_integrity_ok() {
    let vals = vec![r#"<https://cdn.jsdelivr.net/lib.js>; rel="preload"; as="script""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(!issues.contains(&LinkSecurityIssue::UntrustedCdnPreload));
}

#[test]
fn excessive_preloads_detected() {
    let mut vals = Vec::new();
    for i in 1..=12 {
        vals.push(format!(
            r#"<https://example.com/file{}.css>; rel="preload"; as="style""#,
            i
        ));
    }
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::ExcessivePreloads));
}

#[test]
fn excessive_preloads_negative() {
    let mut vals = Vec::new();
    for i in 1..=5 {
        vals.push(format!(
            r#"<https://example.com/file{}.css>; rel="preload"; as="style""#,
            i
        ));
    }
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(!issues.contains(&LinkSecurityIssue::ExcessivePreloads));
}

#[test]
fn sensitive_resource_preload_auth_detected() {
    let vals =
        vec![r#"<https://example.com/auth/token.js>; rel="preload"; as="script""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::SensitiveResourcePreload));
}

#[test]
fn sensitive_resource_preload_admin_detected() {
    let vals = vec![r#"<https://example.com/admin/config.js>; rel="prefetch""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::SensitiveResourcePreload));
}

#[test]
fn sensitive_resource_preload_api_detected() {
    let vals = vec![r#"<https://example.com/api/users>; rel="preload""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::SensitiveResourcePreload));
}

#[test]
fn sensitive_resource_preload_negative() {
    let vals =
        vec![r#"<https://example.com/public/app.js>; rel="preload"; as="script""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(!issues.contains(&LinkSecurityIssue::SensitiveResourcePreload));
}

#[test]
fn module_preload_external_detected() {
    let vals = vec![r#"<https://external.com/module.js>; rel="modulepreload""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::ModulePreloadExternalOrigin));
}

#[test]
fn module_preload_external_negative() {
    let vals = vec![r#"<https://example.com/module.js>; rel="modulepreload""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(!issues.contains(&LinkSecurityIssue::ModulePreloadExternalOrigin));
}

#[test]
fn dns_prefetch_external_detected() {
    let vals = vec![r#"<https://tracker.example.org>; rel="dns-prefetch""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::DnsPrefetchExternal));
}

#[test]
fn dns_prefetch_external_negative() {
    let vals = vec![r#"<https://cdn.example.com>; rel="dns-prefetch""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(!issues.contains(&LinkSecurityIssue::DnsPrefetchExternal));
}

#[test]
fn preconnect_without_crossorigin_detected() {
    let vals = vec![r#"<https://cdn.example.com>; rel="preconnect""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::PreconnectWithoutCrossorigin));
}

#[test]
fn preconnect_with_crossorigin_ok() {
    let vals = vec![r#"<https://cdn.example.com>; rel="preconnect"; crossorigin"#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(!issues.contains(&LinkSecurityIssue::PreconnectWithoutCrossorigin));
}

#[test]
fn prerender_external_detected() {
    let vals = vec![r#"<https://attacker.com/landing>; rel="prerender""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::PrerenderExternalPage));
}

#[test]
fn prerender_external_negative() {
    let vals = vec![r#"<https://example.com/landing>; rel="prerender""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(!issues.contains(&LinkSecurityIssue::PrerenderExternalPage));
}

#[test]
fn missing_integrity_js_detected() {
    let vals = vec![r#"<https://example.com/app.js>; rel="preload"; as="script""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::MissingIntegrityAttribute));
}

#[test]
fn missing_integrity_css_detected() {
    let vals = vec![r#"<https://example.com/style.css>; rel="prefetch""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::MissingIntegrityAttribute));
}

#[test]
fn missing_integrity_with_integrity_ok() {
    let vals = vec![
        r#"<https://example.com/app.js>; rel="preload"; as="script"; integrity="sha384-xyz""#
            .to_string(),
    ];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(!issues.contains(&LinkSecurityIssue::MissingIntegrityAttribute));
}

#[test]
fn missing_integrity_non_script_ok() {
    let vals = vec![r#"<https://example.com/image.png>; rel="preload"; as="image""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(!issues.contains(&LinkSecurityIssue::MissingIntegrityAttribute));
}

#[test]
fn display_cross_origin_preload() {
    let issue = LinkSecurityIssue::CrossOriginPreload;
    assert_eq!(issue.to_string(), "Cross-origin preload detected");
}

#[test]
fn display_http_preload() {
    let issue = LinkSecurityIssue::HttpPreload;
    assert_eq!(issue.to_string(), "Insecure HTTP preload");
}

#[test]
fn display_untrusted_cdn() {
    let issue = LinkSecurityIssue::UntrustedCdnPreload;
    assert_eq!(issue.to_string(), "Untrusted CDN preload without integrity");
}

#[test]
fn display_excessive_preloads() {
    let issue = LinkSecurityIssue::ExcessivePreloads;
    assert_eq!(issue.to_string(), "Excessive preload/prefetch links");
}

#[test]
fn display_sensitive_resource() {
    let issue = LinkSecurityIssue::SensitiveResourcePreload;
    assert_eq!(issue.to_string(), "Sensitive resource preload detected");
}

#[test]
fn display_module_preload_external() {
    let issue = LinkSecurityIssue::ModulePreloadExternalOrigin;
    assert_eq!(issue.to_string(), "Module preload from external origin");
}

#[test]
fn display_dns_prefetch() {
    let issue = LinkSecurityIssue::DnsPrefetchExternal;
    assert_eq!(issue.to_string(), "DNS prefetch for external domain");
}

#[test]
fn display_preconnect_without_crossorigin() {
    let issue = LinkSecurityIssue::PreconnectWithoutCrossorigin;
    assert_eq!(
        issue.to_string(),
        "Preconnect missing crossorigin attribute"
    );
}

#[test]
fn display_prerender_external() {
    let issue = LinkSecurityIssue::PrerenderExternalPage;
    assert_eq!(issue.to_string(), "Prerender to external page");
}

#[test]
fn display_missing_integrity() {
    let issue = LinkSecurityIssue::MissingIntegrityAttribute;
    assert_eq!(
        issue.to_string(),
        "Missing integrity attribute on preloaded script/style"
    );
}

#[test]
fn severity_http_preload_highest() {
    assert_eq!(link_security_severity(&LinkSecurityIssue::HttpPreload), 6.0);
}

#[test]
fn severity_module_preload_external() {
    assert_eq!(
        link_security_severity(&LinkSecurityIssue::ModulePreloadExternalOrigin),
        5.5
    );
}

#[test]
fn severity_cross_origin_preload() {
    assert_eq!(
        link_security_severity(&LinkSecurityIssue::CrossOriginPreload),
        5.0
    );
}

#[test]
fn severity_untrusted_cdn() {
    assert_eq!(
        link_security_severity(&LinkSecurityIssue::UntrustedCdnPreload),
        5.0
    );
}

#[test]
fn severity_prerender_external() {
    assert_eq!(
        link_security_severity(&LinkSecurityIssue::PrerenderExternalPage),
        4.5
    );
}

#[test]
fn severity_sensitive_resource() {
    assert_eq!(
        link_security_severity(&LinkSecurityIssue::SensitiveResourcePreload),
        4.5
    );
}

#[test]
fn severity_missing_integrity() {
    assert_eq!(
        link_security_severity(&LinkSecurityIssue::MissingIntegrityAttribute),
        4.0
    );
}

#[test]
fn severity_preconnect_without_crossorigin() {
    assert_eq!(
        link_security_severity(&LinkSecurityIssue::PreconnectWithoutCrossorigin),
        3.5
    );
}

#[test]
fn severity_dns_prefetch() {
    assert_eq!(
        link_security_severity(&LinkSecurityIssue::DnsPrefetchExternal),
        3.0
    );
}

#[test]
fn severity_excessive_preloads_lowest() {
    assert_eq!(
        link_security_severity(&LinkSecurityIssue::ExcessivePreloads),
        2.5
    );
}

#[test]
fn operations_empty_on_no_security_issues() {
    let mut seq = 0;
    let ops = link_security_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_on_security_issues() {
    let issues = vec![LinkSecurityIssue::HttpPreload];
    let mut seq = 5;
    let ops = link_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}

#[test]
fn operations_uses_max_severity() {
    let issues = vec![
        LinkSecurityIssue::ExcessivePreloads,
        LinkSecurityIssue::HttpPreload,
        LinkSecurityIssue::DnsPrefetchExternal,
    ];
    let mut seq = 0;
    let ops = link_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
}

#[test]
fn no_issues_with_empty_values() {
    let issues = analyze_link_security(&[], Some("example.com"));
    assert!(issues.is_empty());
}

#[test]
fn no_issues_without_target_domain() {
    let vals = vec![r#"<https://external.com/script.js>; rel="preload"; as="script""#.to_string()];
    let issues = analyze_link_security(&vals, None);
    assert!(issues.is_empty() || !issues.contains(&LinkSecurityIssue::CrossOriginPreload));
}

#[test]
fn multiple_issues_same_link() {
    let vals =
        vec![r#"<http://untrusted-cdn.com/script.js>; rel="preload"; as="script""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::HttpPreload));
    assert!(issues.contains(&LinkSecurityIssue::UntrustedCdnPreload));
}

#[test]
fn comma_separated_links_processed() {
    let vals = vec![
        r#"<https://external.com/a.js>; rel="preload", <https://example.com/b.js>; rel="preload""#
            .to_string(),
    ];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::CrossOriginPreload));
}

#[test]
fn extract_url_works() {
    let entry = r#"<https://example.com/script.js>; rel="preload""#;
    let url = extract_link_url(entry);
    assert_eq!(url, Some("https://example.com/script.js".to_string()));
}

#[test]
fn extract_url_empty_returns_none() {
    let entry = r#"<>; rel="preload""#;
    let url = extract_link_url(entry);
    assert_eq!(url, None);
}

#[test]
fn extract_rel_works() {
    let entry = r#"<https://example.com/script.js>; rel="preload"; as="script""#;
    let rel = extract_rel(entry);
    assert_eq!(rel, Some("preload".to_string()));
}

#[test]
fn extract_rel_no_rel_returns_none() {
    let entry = r#"<https://example.com/script.js>; as="script""#;
    let rel = extract_rel(entry);
    assert_eq!(rel, None);
}

#[test]
fn prefetch_counted_for_excessive() {
    let mut vals = Vec::new();
    for i in 1..=11 {
        vals.push(format!(
            r#"<https://example.com/file{}.css>; rel="prefetch""#,
            i
        ));
    }
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::ExcessivePreloads));
}

#[test]
fn http_prefetch_also_flagged() {
    let vals = vec![r#"<http://example.com/data.json>; rel="prefetch""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::HttpPreload));
}

#[test]
fn http_modulepreload_flagged() {
    let vals = vec![r#"<http://example.com/module.js>; rel="modulepreload""#.to_string()];
    let issues = analyze_link_security(&vals, Some("example.com"));
    assert!(issues.contains(&LinkSecurityIssue::HttpPreload));
}
