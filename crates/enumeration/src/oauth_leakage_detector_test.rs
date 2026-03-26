use super::oauth_leakage_detector::*;

fn default_endpoint_info() -> OAuthEndpointInfo {
    OAuthEndpointInfo::default()
}

fn implicit_endpoint_info() -> OAuthEndpointInfo {
    OAuthEndpointInfo {
        flow_type: OAuthFlowType::Implicit,
        ..Default::default()
    }
}

fn empty_page_context() -> PageContext {
    PageContext::default()
}

#[test]
fn detect_implicit_flow_fires_on_implicit_type() {
    let detector = OAuthLeakageDetector::new(
        LeakageScanConfig::default(),
        implicit_endpoint_info(),
        empty_page_context(),
    );
    let finding = detector
        .detect_implicit_flow()
        .expect("should detect implicit flow");
    assert_eq!(finding.vector, LeakageVector::ImplicitFlow);
    assert!(finding.severity >= 7.0);
    assert_eq!(finding.flow_type, OAuthFlowType::Implicit);
    assert_eq!(finding.token_location, TokenLocation::Fragment);
    assert!(!finding.remediation.is_empty());
}

#[test]
fn detect_implicit_flow_returns_none_for_code_flow() {
    let detector = OAuthLeakageDetector::new(
        LeakageScanConfig::default(),
        default_endpoint_info(),
        empty_page_context(),
    );
    assert!(detector.detect_implicit_flow().is_none());
}

#[test]
fn check_token_in_url_finds_query_tokens() {
    let info = OAuthEndpointInfo {
        redirect_uris: vec![
            "https://app.example.com/callback?access_token=abc123".to_string(),
            "https://app.example.com/callback".to_string(),
        ],
        ..Default::default()
    };
    let detector =
        OAuthLeakageDetector::new(LeakageScanConfig::default(), info, empty_page_context());
    let findings = detector.check_token_in_url();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].vector, LeakageVector::UrlFragment);
    assert_eq!(findings[0].token_location, TokenLocation::Query);
    assert!(findings[0].severity >= 8.0);
}

#[test]
fn check_token_in_url_ignores_safe_uris() {
    let info = OAuthEndpointInfo {
        redirect_uris: vec![
            "https://app.example.com/callback".to_string(),
            "https://app.example.com/callback?state=xyz".to_string(),
        ],
        ..Default::default()
    };
    let detector =
        OAuthLeakageDetector::new(LeakageScanConfig::default(), info, empty_page_context());
    assert!(detector.check_token_in_url().is_empty());
}

#[test]
fn check_referer_leakage_detects_unsafe_policy() {
    let ctx = PageContext {
        response_headers: ResponseHeaders {
            referrer_policy: Some("unsafe-url".to_string()),
            ..Default::default()
        },
        external_resource_domains: vec![
            "analytics.evil.com".to_string(),
            "cdn.tracker.io".to_string(),
        ],
        ..Default::default()
    };
    let detector =
        OAuthLeakageDetector::new(LeakageScanConfig::default(), default_endpoint_info(), ctx);
    let findings = detector.check_referer_leakage();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].vector, LeakageVector::RefererExposure);
    assert!(findings[0].evidence.len() >= 2);
}

#[test]
fn check_referer_leakage_safe_policy_produces_no_findings() {
    let ctx = PageContext {
        response_headers: ResponseHeaders {
            referrer_policy: Some("no-referrer".to_string()),
            ..Default::default()
        },
        external_resource_domains: vec!["analytics.evil.com".to_string()],
        ..Default::default()
    };
    let detector =
        OAuthLeakageDetector::new(LeakageScanConfig::default(), default_endpoint_info(), ctx);
    assert!(detector.check_referer_leakage().is_empty());
}

#[test]
fn check_referer_disabled_by_config() {
    let config = LeakageScanConfig {
        check_referer: false,
        ..Default::default()
    };
    let ctx = PageContext {
        response_headers: ResponseHeaders {
            referrer_policy: Some("unsafe-url".to_string()),
            ..Default::default()
        },
        external_resource_domains: vec!["evil.com".to_string()],
        ..Default::default()
    };
    let detector = OAuthLeakageDetector::new(config, default_endpoint_info(), ctx);
    assert!(detector.check_referer_leakage().is_empty());
}

#[test]
fn check_cache_headers_public_cache() {
    let ctx = PageContext {
        response_headers: ResponseHeaders {
            cache_control: Some("public, max-age=3600".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let detector =
        OAuthLeakageDetector::new(LeakageScanConfig::default(), default_endpoint_info(), ctx);
    let findings = detector.check_cache_headers();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].vector, LeakageVector::CacheExposure);
    assert!(findings[0].severity >= 7.0);
}

#[test]
fn check_cache_headers_no_store_produces_no_findings() {
    let ctx = PageContext {
        response_headers: ResponseHeaders {
            cache_control: Some("no-store, no-cache, private".to_string()),
            pragma: Some("no-cache".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let detector =
        OAuthLeakageDetector::new(LeakageScanConfig::default(), default_endpoint_info(), ctx);
    assert!(detector.check_cache_headers().is_empty());
}

#[test]
fn check_postmessage_wildcard_origin() {
    let ctx = PageContext {
        postmessage_configs: vec![PostMessageConfig {
            target_origin: "*".to_string(),
            validates_origin: false,
            message_contains_token: true,
        }],
        ..Default::default()
    };
    let detector =
        OAuthLeakageDetector::new(LeakageScanConfig::default(), default_endpoint_info(), ctx);
    let findings = detector.check_postmessage_config();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].vector, LeakageVector::PostMessageLeak);
    assert!(findings[0].severity >= 9.0);
}

#[test]
fn check_postmessage_no_token_produces_no_findings() {
    let ctx = PageContext {
        postmessage_configs: vec![PostMessageConfig {
            target_origin: "*".to_string(),
            validates_origin: false,
            message_contains_token: false,
        }],
        ..Default::default()
    };
    let detector =
        OAuthLeakageDetector::new(LeakageScanConfig::default(), default_endpoint_info(), ctx);
    assert!(detector.check_postmessage_config().is_empty());
}

#[test]
fn analyze_redirect_chain_mixed_content() {
    let ctx = PageContext {
        redirect_chain: vec![
            RedirectHop {
                url: "https://auth.example.com/authorize".to_string(),
                status_code: 302,
                location_header: Some("http://app.example.com/callback".to_string()),
                is_https: true,
            },
            RedirectHop {
                url: "http://app.example.com/callback".to_string(),
                status_code: 200,
                location_header: None,
                is_https: false,
            },
        ],
        ..Default::default()
    };
    let detector =
        OAuthLeakageDetector::new(LeakageScanConfig::default(), default_endpoint_info(), ctx);
    let findings = detector.analyze_redirect_chain();
    assert!(
        findings
            .iter()
            .any(|f| f.vector == LeakageVector::MixedContent),
        "should detect HTTP downgrade"
    );
}

#[test]
fn analyze_redirect_chain_open_redirect() {
    let ctx = PageContext {
        redirect_chain: vec![
            RedirectHop {
                url: "https://auth.example.com/authorize".to_string(),
                status_code: 302,
                location_header: Some(
                    "https://app.example.com/redirect?next=https://evil.com".to_string(),
                ),
                is_https: true,
            },
            RedirectHop {
                url: "https://app.example.com/redirect?next=https://evil.com".to_string(),
                status_code: 302,
                location_header: Some("https://evil.com/steal".to_string()),
                is_https: true,
            },
        ],
        ..Default::default()
    };
    let detector =
        OAuthLeakageDetector::new(LeakageScanConfig::default(), default_endpoint_info(), ctx);
    let findings = detector.analyze_redirect_chain();
    assert!(
        findings
            .iter()
            .any(|f| f.vector == LeakageVector::OpenRedirectChain),
        "should detect open redirect hop"
    );
}

#[test]
fn scan_all_vectors_aggregates_across_checks() {
    let info = OAuthEndpointInfo {
        flow_type: OAuthFlowType::Implicit,
        redirect_uris: vec!["https://app.example.com/callback?access_token=tok".to_string()],
        ..Default::default()
    };
    let ctx = PageContext {
        response_headers: ResponseHeaders {
            cache_control: Some("public".to_string()),
            referrer_policy: Some("unsafe-url".to_string()),
            ..Default::default()
        },
        external_resource_domains: vec!["tracker.io".to_string()],
        third_party_scripts: vec!["https://cdn.analytics.com/track.js".to_string()],
        postmessage_configs: vec![PostMessageConfig {
            target_origin: "*".to_string(),
            validates_origin: false,
            message_contains_token: true,
        }],
        ..Default::default()
    };
    let detector = OAuthLeakageDetector::new(LeakageScanConfig::default(), info, ctx);
    let findings = detector.scan_all_vectors();
    assert!(
        findings.len() >= 5,
        "expected at least 5 findings from combined vectors, got {}",
        findings.len()
    );

    let vectors: Vec<LeakageVector> = findings.iter().map(|f| f.vector).collect();
    assert!(vectors.contains(&LeakageVector::ImplicitFlow));
    assert!(vectors.contains(&LeakageVector::CacheExposure));
    assert!(vectors.contains(&LeakageVector::PostMessageLeak));
}

#[test]
fn generate_findings_sorted_by_severity_descending() {
    let info = OAuthEndpointInfo {
        flow_type: OAuthFlowType::Implicit,
        redirect_uris: vec!["https://app.example.com/cb?access_token=x".to_string()],
        ..Default::default()
    };
    let ctx = PageContext {
        response_headers: ResponseHeaders {
            cache_control: Some("public".to_string()),
            ..Default::default()
        },
        postmessage_configs: vec![PostMessageConfig {
            target_origin: "*".to_string(),
            validates_origin: false,
            message_contains_token: true,
        }],
        ..Default::default()
    };
    let detector = OAuthLeakageDetector::new(LeakageScanConfig::default(), info, ctx);
    let report = detector.generate_findings();
    assert!(report.total_findings >= 3);
    assert_eq!(report.total_findings, report.findings.len());

    for window in report.findings.windows(2) {
        assert!(
            window[0].severity >= window[1].severity,
            "findings should be sorted descending: {} >= {}",
            window[0].severity,
            window[1].severity
        );
    }
    assert!(report.max_severity >= 7.0);
    assert!(!report.vector_counts.is_empty());
}

#[test]
fn severity_scoring_returns_expected_ranges() {
    assert!(base_severity_for_vector(LeakageVector::PostMessageLeak) >= 9.0);
    assert!(base_severity_for_vector(LeakageVector::UrlFragment) >= 8.0);
    assert!(base_severity_for_vector(LeakageVector::BrowserHistory) <= 5.0);
    assert!(base_severity_for_vector(LeakageVector::CacheExposure) >= 4.0);
    assert!(base_severity_for_vector(LeakageVector::ImplicitFlow) >= 7.0);
}

#[test]
fn leakage_vector_display_all_unique() {
    let vectors = [
        LeakageVector::UrlFragment,
        LeakageVector::RefererExposure,
        LeakageVector::BrowserHistory,
        LeakageVector::PostMessageLeak,
        LeakageVector::CacheExposure,
        LeakageVector::ImplicitFlow,
        LeakageVector::OpenRedirectChain,
        LeakageVector::MixedContent,
        LeakageVector::ThirdPartyScript,
    ];
    let mut displays = std::collections::HashSet::new();
    for v in &vectors {
        let d = format!("{v}");
        assert!(!d.is_empty());
        displays.insert(d);
    }
    assert_eq!(displays.len(), 9, "all 9 vector displays should be unique");
}

#[test]
fn oauth_flow_type_display_all_unique() {
    let flows = [
        OAuthFlowType::AuthorizationCode,
        OAuthFlowType::Implicit,
        OAuthFlowType::ClientCredentials,
        OAuthFlowType::DeviceCode,
        OAuthFlowType::Pkce,
    ];
    let mut displays = std::collections::HashSet::new();
    for f in &flows {
        let d = format!("{f}");
        assert!(!d.is_empty());
        displays.insert(d);
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn token_location_display_all_unique() {
    let locations = [
        TokenLocation::Fragment,
        TokenLocation::Query,
        TokenLocation::Header,
        TokenLocation::Body,
        TokenLocation::Cookie,
    ];
    let mut displays = std::collections::HashSet::new();
    for l in &locations {
        let d = format!("{l}");
        assert!(!d.is_empty());
        displays.insert(d);
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn empty_page_context_produces_minimal_findings() {
    let detector = OAuthLeakageDetector::new(
        LeakageScanConfig::default(),
        default_endpoint_info(),
        empty_page_context(),
    );
    let report = detector.generate_findings();
    assert_eq!(
        report.total_findings, 0,
        "default code flow with empty context should produce zero findings"
    );
}

#[test]
fn max_redirect_depth_limits_chain_analysis() {
    let mut chain = Vec::new();
    for i in 0..20 {
        chain.push(RedirectHop {
            url: format!("http://hop-{i}.example.com"),
            status_code: 302,
            location_header: Some(format!("http://hop-{}.example.com", i + 1)),
            is_https: false,
        });
    }
    let ctx = PageContext {
        redirect_chain: chain,
        ..Default::default()
    };
    let config = LeakageScanConfig {
        max_redirect_depth: 3,
        ..Default::default()
    };
    let detector = OAuthLeakageDetector::new(config, default_endpoint_info(), ctx);
    let findings = detector.analyze_redirect_chain();
    assert!(
        findings.len() <= 6,
        "should respect max_redirect_depth=3 (at most 3 mixed + 3 open redirect), got {}",
        findings.len()
    );
}
