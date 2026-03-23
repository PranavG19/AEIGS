use crate::meta_tag_audit::*;

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

// Tests for new security variants

#[test]
fn detects_csp_via_meta_tag() {
    let html = r#"<meta http-equiv="Content-Security-Policy" content="default-src 'self'">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::CspViaMetaTag(v) if v == "default-src 'self'"));
}

#[test]
fn detects_csp_case_insensitive() {
    let html = r#"<meta http-equiv="content-security-policy" content="script-src 'none'">"#;
    let issues = analyze_meta_tags_security(html);
    assert!(!issues.is_empty());
    assert!(matches!(&issues[0], MetaIssue::CspViaMetaTag(_)));
}

#[test]
fn detects_refresh_redirect_with_url() {
    let html = r#"<meta http-equiv="refresh" content="5;url=https://example.com">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(
        matches!(&issues[0], MetaIssue::RefreshRedirect { url, delay }
        if url == "https://example.com" && *delay == 5)
    );
}

#[test]
fn detects_refresh_redirect_uppercase_url() {
    let html = r#"<meta http-equiv="refresh" content="0;URL=/redirect">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(
        matches!(&issues[0], MetaIssue::RefreshRedirect { url, delay }
        if url == "/redirect" && *delay == 0)
    );
}

#[test]
fn skips_refresh_without_url() {
    let html = r#"<meta http-equiv="refresh" content="30">"#;
    let issues = analyze_meta_tags_security(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_referrer_policy_no_referrer_when_downgrade() {
    let html = r#"<meta name="referrer" content="no-referrer-when-downgrade">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::ReferrerPolicyInsecure(v)
        if v == "no-referrer-when-downgrade"));
}

#[test]
fn detects_referrer_policy_unsafe_url() {
    let html = r#"<meta name="referrer" content="unsafe-url">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::ReferrerPolicyInsecure(v) if v == "unsafe-url"));
}

#[test]
fn detects_referrer_policy_origin() {
    let html = r#"<meta name="referrer" content="origin">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::ReferrerPolicyInsecure(_)));
}

#[test]
fn skips_secure_referrer_policies() {
    let html = r#"<meta name="referrer" content="no-referrer">"#;
    let issues = analyze_meta_tags_security(html);
    assert!(issues.is_empty());
}

#[test]
fn skips_strict_origin_referrer_policy() {
    let html = r#"<meta name="referrer" content="strict-origin">"#;
    let issues = analyze_meta_tags_security(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_opengraph_email_leak() {
    let html = r#"<meta property="og:email" content="admin@internal.com">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::OpenGraphInfoLeak(v) if v.contains('@')));
}

#[test]
fn detects_opengraph_localhost_leak() {
    let html = r#"<meta property="og:url" content="http://localhost:8080/api">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::OpenGraphInfoLeak(_)));
}

#[test]
fn detects_opengraph_internal_ip_leak() {
    let html = r#"<meta property="og:image" content="http://192.168.1.100/img.png">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::OpenGraphInfoLeak(_)));
}

#[test]
fn detects_opengraph_private_ip_10_subnet() {
    let html = r#"<meta property="og:url" content="http://10.0.0.5/page">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn detects_opengraph_phone_number_leak() {
    let html = r#"<meta property="og:phone" content="5551234567890">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::OpenGraphInfoLeak(_)));
}

#[test]
fn skips_public_opengraph_content() {
    let html = r#"<meta property="og:title" content="Public Page Title">"#;
    let issues = analyze_meta_tags_security(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_viewport_user_scalable_no() {
    let html = r#"<meta name="viewport" content="width=device-width, user-scalable=no">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::ViewportManipulation(v)
        if v.contains("user-scalable=no")));
}

#[test]
fn detects_viewport_maximum_scale_1() {
    let html = r#"<meta name="viewport" content="width=device-width, maximum-scale=1">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::ViewportManipulation(_)));
}

#[test]
fn detects_viewport_both_issues() {
    let html =
        r#"<meta name="viewport" content="user-scalable=no, maximum-scale=1, initial-scale=1">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn skips_normal_viewport() {
    let html = r#"<meta name="viewport" content="width=device-width, initial-scale=1">"#;
    let issues = analyze_meta_tags_security(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_base_uri_in_meta() {
    let html = r#"<meta http-equiv="content-base" content="https://example.com/">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::BaseUriInMeta(_)));
}

#[test]
fn detects_base_variant() {
    let html = r#"<meta http-equiv="base-href" content="/app/">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn detects_dns_prefetch_control_on() {
    let html = r#"<meta http-equiv="x-dns-prefetch-control" content="on">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::DnsPrefetchControl(v) if v == "on"));
}

#[test]
fn skips_dns_prefetch_control_off() {
    let html = r#"<meta http-equiv="x-dns-prefetch-control" content="off">"#;
    let issues = analyze_meta_tags_security(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_xss_protection_disabled() {
    let html = r#"<meta http-equiv="X-XSS-Protection" content="0">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::HttpEquivXssProtection(v) if v == "0"));
}

#[test]
fn detects_xss_protection_0_with_mode() {
    let html = r#"<meta http-equiv="X-XSS-Protection" content="0; mode=block">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn skips_xss_protection_enabled() {
    let html = r#"<meta http-equiv="X-XSS-Protection" content="1; mode=block">"#;
    let issues = analyze_meta_tags_security(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_csp_with_report_uri() {
    let html = r#"<meta http-equiv="Content-Security-Policy" content="default-src 'self'; report-uri /csp-report">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 2);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MetaIssue::ContentSecurityPolicyReportUri(_)))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MetaIssue::CspViaMetaTag(_)))
    );
}

#[test]
fn detects_theme_color() {
    let html = r##"<meta name="theme-color" content="#4285f4">"##;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], MetaIssue::ThemeColorExposure(v) if v == "#4285f4"));
}

#[test]
fn detects_theme_color_rgb() {
    let html = r#"<meta name="theme-color" content="rgb(66, 133, 244)">"#;
    let issues = analyze_meta_tags_security(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn skips_empty_theme_color() {
    let html = r#"<meta name="theme-color" content="">"#;
    let issues = analyze_meta_tags_security(html);
    assert!(issues.is_empty());
}

#[test]
fn multiple_security_issues() {
    let html = r##"
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
        <meta http-equiv="refresh" content="3;url=/login">
        <meta name="referrer" content="unsafe-url">
        <meta name="viewport" content="user-scalable=no">
        <meta name="theme-color" content="#000000">
    "##;
    let issues = analyze_meta_tags_security(html);
    assert!(issues.len() >= 5);
}

#[test]
fn no_security_issues_in_clean_html() {
    let html = r#"
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="description" content="A secure website">
    "#;
    let issues = analyze_meta_tags_security(html);
    assert!(issues.is_empty());
}

#[test]
fn display_new_variants() {
    let csp = MetaIssue::CspViaMetaTag("default-src 'self'".to_string());
    assert_eq!(csp.to_string(), "csp_via_meta:default-src 'self'");

    let refresh = MetaIssue::RefreshRedirect {
        url: "https://example.com".to_string(),
        delay: 5,
    };
    assert_eq!(
        refresh.to_string(),
        "refresh_redirect:url=https://example.com,delay=5"
    );

    let referrer = MetaIssue::ReferrerPolicyInsecure("unsafe-url".to_string());
    assert_eq!(referrer.to_string(), "referrer_policy_insecure:unsafe-url");

    let og = MetaIssue::OpenGraphInfoLeak("admin@test.com".to_string());
    assert_eq!(og.to_string(), "opengraph_info_leak:admin@test.com");

    let viewport = MetaIssue::ViewportManipulation("user-scalable=no".to_string());
    assert_eq!(
        viewport.to_string(),
        "viewport_manipulation:user-scalable=no"
    );

    let base = MetaIssue::BaseUriInMeta("/base".to_string());
    assert_eq!(base.to_string(), "base_uri_in_meta:/base");

    let dns = MetaIssue::DnsPrefetchControl("on".to_string());
    assert_eq!(dns.to_string(), "dns_prefetch_control:on");

    let xss = MetaIssue::HttpEquivXssProtection("0".to_string());
    assert_eq!(xss.to_string(), "http_equiv_xss_protection:0");

    let csp_report = MetaIssue::ContentSecurityPolicyReportUri("report-uri /csp".to_string());
    assert_eq!(
        csp_report.to_string(),
        "csp_report_uri_in_meta:report-uri /csp"
    );

    let theme = MetaIssue::ThemeColorExposure("#4285f4".to_string());
    assert_eq!(theme.to_string(), "theme_color_exposure:#4285f4");
}
