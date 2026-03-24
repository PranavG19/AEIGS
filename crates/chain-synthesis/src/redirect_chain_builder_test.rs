use crate::redirect_chain_builder::{
    BypassEncoding, RedirectChain, RedirectChainBuilder, RedirectChainType, RedirectEndpoint,
};

fn sample_endpoint(url: &str, param: &str, domain: &str) -> RedirectEndpoint {
    RedirectEndpoint::new(url, param, domain)
}

fn builder_with_standard_endpoints() -> RedirectChainBuilder {
    let mut builder = RedirectChainBuilder::new("evil.com");
    builder.add_endpoint(sample_endpoint(
        "https://example.com/redirect",
        "url",
        "example.com",
    ));
    builder.add_endpoint(sample_endpoint("https://corp.io/goto", "target", "corp.io"));
    builder.add_endpoint(sample_endpoint(
        "https://shop.net/redir",
        "next",
        "shop.net",
    ));
    builder
}

// --- RedirectEndpoint tests ---

#[test]
fn endpoint_detects_oauth_callback() {
    let ep = sample_endpoint("https://app.com/oauth/callback", "code", "app.com");
    assert!(ep.is_oauth_callback);
}

#[test]
fn endpoint_detects_authorize_path() {
    let ep = sample_endpoint("https://app.com/authorize", "redirect_uri", "app.com");
    assert!(ep.is_oauth_callback);
}

#[test]
fn endpoint_not_oauth_for_plain_redirect() {
    let ep = sample_endpoint("https://app.com/redirect", "url", "app.com");
    assert!(!ep.is_oauth_callback);
}

#[test]
fn endpoint_detects_authenticated_login() {
    let ep = sample_endpoint("https://app.com/login/redirect", "next", "app.com");
    assert!(ep.is_authenticated);
}

#[test]
fn endpoint_detects_sso_path() {
    let ep = sample_endpoint("https://idp.com/sso/redirect", "return", "idp.com");
    assert!(ep.is_authenticated);
}

#[test]
fn endpoint_not_authenticated_for_plain() {
    let ep = sample_endpoint("https://cdn.com/redirect", "url", "cdn.com");
    assert!(!ep.is_authenticated);
}

// --- BypassEncoding tests ---

#[test]
fn bypass_url_encoding() {
    let result = BypassEncoding::UrlEncoding.apply("https://evil.com/path?q=1");
    assert!(result.contains("%3A"));
    assert!(result.contains("%2F"));
    assert!(!result.contains("://"));
}

#[test]
fn bypass_double_encoding() {
    let result = BypassEncoding::DoubleEncoding.apply("https://evil.com");
    assert!(result.contains("%25"));
}

#[test]
fn bypass_protocol_relative() {
    let result = BypassEncoding::ProtocolRelative.apply("https://evil.com/steal");
    assert_eq!(result, "//evil.com/steal");
}

#[test]
fn bypass_protocol_relative_http() {
    let result = BypassEncoding::ProtocolRelative.apply("http://evil.com/page");
    assert_eq!(result, "//evil.com/page");
}

#[test]
fn bypass_protocol_relative_no_scheme() {
    let result = BypassEncoding::ProtocolRelative.apply("evil.com/page");
    assert_eq!(result, "evil.com/page");
}

#[test]
fn bypass_unicode_normalization() {
    let result = BypassEncoding::UnicodeNormalization.apply("https://evilcorp.com");
    assert_ne!(result, "https://evilcorp.com");
    assert!(result.contains('\u{0435}')); // Cyrillic е
    assert!(result.contains('\u{043E}')); // Cyrillic о
}

#[test]
fn bypass_backslash_substitution() {
    let result = BypassEncoding::BackslashSubstitution.apply("https://evil.com/steal");
    assert!(result.contains("trusted.com\\@"));
    assert!(result.contains("evil.com/steal"));
}

#[test]
fn bypass_null_byte_injection() {
    let result = BypassEncoding::NullByteInjection.apply("https://evil.com/steal");
    assert!(result.contains("%00"));
    assert!(result.contains("trusted.com"));
}

#[test]
fn bypass_whitespace_injection() {
    let result = BypassEncoding::WhitespaceInjection.apply("https://evil.com/path");
    assert!(result.ends_with("%09"));
}

#[test]
fn bypass_all_returns_at_least_five() {
    assert!(BypassEncoding::all().len() >= 5);
}

// --- Chain building tests ---

#[test]
fn build_all_chains_generates_two_and_three_hop() {
    let builder = builder_with_standard_endpoints();
    let chains = builder.build_all_chains();

    let two_hop_count = chains.iter().filter(|c| c.hop_count() == 2).count();
    let three_hop_count = chains.iter().filter(|c| c.hop_count() == 3).count();

    // 3 endpoints → P(3,2) = 6 two-hop + P(3,3) = 6 three-hop = 12
    assert_eq!(two_hop_count, 6);
    assert_eq!(three_hop_count, 6);
    assert_eq!(chains.len(), 12);
}

#[test]
fn build_all_chains_empty_when_no_endpoints() {
    let builder = RedirectChainBuilder::new("evil.com");
    let chains = builder.build_all_chains();
    assert!(chains.is_empty());
}

#[test]
fn build_all_chains_empty_with_single_endpoint() {
    let mut builder = RedirectChainBuilder::new("evil.com");
    builder.add_endpoint(sample_endpoint("https://a.com/redir", "url", "a.com"));
    // Minimum chain is 2-hop, needs 2 distinct endpoints
    let chains = builder.build_all_chains();
    assert!(chains.is_empty());
}

#[test]
fn chain_url_construction_single_hop() {
    let chain = RedirectChain {
        hops: vec![sample_endpoint("https://a.com/redirect", "url", "a.com")],
        final_destination: "https://evil.com/collect".to_string(),
        chain_type: RedirectChainType::MultiHop,
        severity: 4.0,
        bypass_variants: Vec::new(),
    };
    let url = chain.build_url();
    assert!(url.starts_with("https://a.com/redirect?url="));
    assert!(url.contains("evil.com"));
}

#[test]
fn chain_url_construction_two_hop() {
    let chain = RedirectChain {
        hops: vec![
            sample_endpoint("https://a.com/redirect", "url", "a.com"),
            sample_endpoint("https://b.com/goto", "target", "b.com"),
        ],
        final_destination: "https://evil.com/collect".to_string(),
        chain_type: RedirectChainType::MultiHop,
        severity: 4.5,
        bypass_variants: Vec::new(),
    };
    let url = chain.build_url();
    assert!(url.starts_with("https://a.com/redirect?url="));
    // Second hop should be URL-encoded inside the first
    assert!(url.contains("b.com"));
}

#[test]
fn chain_url_empty_hops_returns_final_dest() {
    let chain = RedirectChain {
        hops: Vec::new(),
        final_destination: "https://evil.com/collect".to_string(),
        chain_type: RedirectChainType::MultiHop,
        severity: 0.0,
        bypass_variants: Vec::new(),
    };
    assert_eq!(chain.build_url(), "https://evil.com/collect");
}

// --- OAuth chain tests ---

#[test]
fn oauth_chains_require_oauth_endpoint() {
    let builder = builder_with_standard_endpoints();
    let chains = builder.build_oauth_chains("my-client-id", "openid profile");
    assert!(chains.is_empty());
}

#[test]
fn oauth_chains_generated_with_callback_endpoint() {
    let mut builder = RedirectChainBuilder::new("evil.com");
    builder.add_endpoint(sample_endpoint(
        "https://app.com/oauth/callback",
        "redirect_uri",
        "app.com",
    ));
    builder.add_endpoint(sample_endpoint(
        "https://cdn.com/redirect",
        "url",
        "cdn.com",
    ));

    let chains = builder.build_oauth_chains("client-123", "openid");
    assert!(!chains.is_empty());
    assert!(chains
        .iter()
        .all(|c| c.chain_type == RedirectChainType::OAuthTokenTheft));
    assert!(chains.iter().all(|c| c.severity >= 9.0));
}

#[test]
fn oauth_chain_contains_authorization_url() {
    let mut builder = RedirectChainBuilder::new("evil.com");
    builder.add_endpoint(sample_endpoint(
        "https://app.com/oauth/callback",
        "redirect_uri",
        "app.com",
    ));

    let chains = builder.build_oauth_chains("my-client", "openid");
    assert!(!chains.is_empty());

    let first = &chains[0];
    assert!(first.final_destination.contains("oauth/authorize"));
    assert!(first.final_destination.contains("client_id="));
    assert!(first.final_destination.contains("response_type=code"));
}

// --- CSP chain tests ---

#[test]
fn csp_chains_require_multiple_domains() {
    let mut builder = RedirectChainBuilder::new("evil.com");
    builder.add_endpoint(sample_endpoint("https://a.com/redir", "url", "a.com"));
    builder.add_endpoint(sample_endpoint("https://a.com/goto", "next", "a.com"));

    let chains = builder.build_csp_chains();
    assert!(chains.is_empty());
}

#[test]
fn csp_chains_generated_across_domains() {
    let builder = builder_with_standard_endpoints();
    let chains = builder.build_csp_chains();

    assert!(!chains.is_empty());
    assert!(chains
        .iter()
        .all(|c| c.chain_type == RedirectChainType::CspBypass));

    for chain in &chains {
        let domains: std::collections::HashSet<&str> =
            chain.hops.iter().map(|h| h.domain.as_str()).collect();
        assert!(
            domains.len() >= 2,
            "CSP chains must cross domain boundaries"
        );
    }
}

// --- SSRF chain tests ---

#[test]
fn ssrf_chains_target_internal_services() {
    let mut builder = RedirectChainBuilder::new("evil.com");
    builder.add_endpoint(sample_endpoint(
        "https://api.com/redirect",
        "url",
        "api.com",
    ));

    let internal = vec![
        "http://169.254.169.254/latest/meta-data".to_string(),
        "http://localhost:8080/admin".to_string(),
    ];
    let chains = builder.build_ssrf_chains(&internal);
    assert!(!chains.is_empty());
    assert!(chains
        .iter()
        .all(|c| c.chain_type == RedirectChainType::SsrfAmplification));

    let has_metadata = chains
        .iter()
        .any(|c| c.final_destination.contains("169.254.169.254"));
    assert!(has_metadata);
}

#[test]
fn ssrf_chains_empty_without_targets() {
    let mut builder = RedirectChainBuilder::new("evil.com");
    builder.add_endpoint(sample_endpoint(
        "https://api.com/redirect",
        "url",
        "api.com",
    ));
    let chains = builder.build_ssrf_chains(&[]);
    assert!(chains.is_empty());
}

// --- Phishing chain tests ---

#[test]
fn phishing_chains_generated() {
    let builder = builder_with_standard_endpoints();
    let chains = builder.build_phishing_chains();

    assert!(!chains.is_empty());
    assert!(chains
        .iter()
        .all(|c| c.chain_type == RedirectChainType::PhishingEscalation));
}

#[test]
fn phishing_chain_severity_scales_with_hops() {
    let builder = builder_with_standard_endpoints();
    let chains = builder.build_phishing_chains();

    let one_hop: Vec<&RedirectChain> = chains.iter().filter(|c| c.hop_count() == 1).collect();
    let two_hop: Vec<&RedirectChain> = chains.iter().filter(|c| c.hop_count() == 2).collect();

    if !one_hop.is_empty() && !two_hop.is_empty() {
        assert!(two_hop[0].severity > one_hop[0].severity);
    }
}

// --- Login chain tests ---

#[test]
fn login_chains_require_auth_endpoint() {
    let builder = builder_with_standard_endpoints();
    let chains = builder.build_login_chains();
    assert!(chains.is_empty());
}

#[test]
fn login_chains_generated_with_auth_endpoint() {
    let mut builder = RedirectChainBuilder::new("evil.com");
    builder.add_endpoint(sample_endpoint(
        "https://app.com/login/redirect",
        "next",
        "app.com",
    ));
    builder.add_endpoint(sample_endpoint(
        "https://cdn.com/redirect",
        "url",
        "cdn.com",
    ));

    let chains = builder.build_login_chains();
    assert!(!chains.is_empty());
    assert!(chains
        .iter()
        .all(|c| c.chain_type == RedirectChainType::LoginChain));
    assert!(chains.iter().all(|c| c.severity >= 8.0));
}

// --- Bypass variant generation tests ---

#[test]
fn bypass_variants_generated_for_each_hop() {
    let builder = builder_with_standard_endpoints();
    let chains = builder.build_all_chains();

    let two_hop_chain = chains.iter().find(|c| c.hop_count() == 2).unwrap();
    assert!(!two_hop_chain.bypass_variants.is_empty());

    let hop_indices: std::collections::HashSet<usize> = two_hop_chain
        .bypass_variants
        .iter()
        .map(|(idx, _, _)| *idx)
        .collect();
    assert!(hop_indices.contains(&0));
    assert!(hop_indices.contains(&1));
}

#[test]
fn bypass_variants_cover_all_techniques() {
    let builder = builder_with_standard_endpoints();
    let chains = builder.build_all_chains();

    let chain = chains.iter().find(|c| c.hop_count() == 2).unwrap();
    let hop0_encodings: std::collections::HashSet<String> = chain
        .bypass_variants
        .iter()
        .filter(|(idx, _, _)| *idx == 0)
        .map(|(_, enc, _)| enc.to_string())
        .collect();

    assert!(hop0_encodings.contains("url-encoding"));
    assert!(hop0_encodings.contains("double-encoding"));
    assert!(hop0_encodings.contains("protocol-relative"));
    assert!(hop0_encodings.contains("unicode-normalization"));
    assert!(hop0_encodings.contains("backslash-substitution"));
}

// --- Display impls ---

#[test]
fn chain_type_display() {
    assert_eq!(
        RedirectChainType::OAuthTokenTheft.to_string(),
        "oauth-token-theft"
    );
    assert_eq!(
        RedirectChainType::SsrfAmplification.to_string(),
        "ssrf-amplification"
    );
    assert_eq!(RedirectChainType::CspBypass.to_string(), "csp-bypass");
    assert_eq!(
        RedirectChainType::PhishingEscalation.to_string(),
        "phishing-escalation"
    );
    assert_eq!(RedirectChainType::LoginChain.to_string(), "login-chain");
    assert_eq!(RedirectChainType::MultiHop.to_string(), "multi-hop");
}

#[test]
fn bypass_encoding_display() {
    assert_eq!(BypassEncoding::UrlEncoding.to_string(), "url-encoding");
    assert_eq!(
        BypassEncoding::DoubleEncoding.to_string(),
        "double-encoding"
    );
    assert_eq!(
        BypassEncoding::NullByteInjection.to_string(),
        "null-byte-injection"
    );
    assert_eq!(
        BypassEncoding::WhitespaceInjection.to_string(),
        "whitespace-injection"
    );
}

// --- Severity scoring ---

#[test]
fn severity_capped_at_ten() {
    let mut builder = RedirectChainBuilder::new("evil.com").with_max_hops(5);
    for i in 0..5 {
        builder.add_endpoint(sample_endpoint(
            &format!("https://d{i}.com/oauth/callback"),
            "url",
            &format!("d{i}.com"),
        ));
    }

    let chains = builder.build_all_chains();
    for chain in &chains {
        assert!(
            chain.severity <= 10.0,
            "severity {} exceeds 10.0",
            chain.severity
        );
    }
}

// --- Builder configuration ---

#[test]
fn max_hops_limits_chain_depth() {
    let mut builder = RedirectChainBuilder::new("evil.com").with_max_hops(2);
    for i in 0..4 {
        builder.add_endpoint(sample_endpoint(
            &format!("https://d{i}.com/redir"),
            "url",
            &format!("d{i}.com"),
        ));
    }

    let chains = builder.build_all_chains();
    for chain in &chains {
        assert!(chain.hop_count() <= 2);
    }
}

#[test]
fn add_endpoints_bulk() {
    let mut builder = RedirectChainBuilder::new("evil.com");
    let endpoints = vec![
        sample_endpoint("https://a.com/redir", "url", "a.com"),
        sample_endpoint("https://b.com/redir", "url", "b.com"),
    ];
    builder.add_endpoints(endpoints);

    let chains = builder.build_all_chains();
    assert_eq!(chains.len(), 2); // P(2,2) = 2
}

#[test]
fn hop_count_matches_hops_len() {
    let chain = RedirectChain {
        hops: vec![
            sample_endpoint("https://a.com/r", "url", "a.com"),
            sample_endpoint("https://b.com/r", "url", "b.com"),
            sample_endpoint("https://c.com/r", "url", "c.com"),
        ],
        final_destination: "https://evil.com".to_string(),
        chain_type: RedirectChainType::MultiHop,
        severity: 5.0,
        bypass_variants: Vec::new(),
    };
    assert_eq!(chain.hop_count(), 3);
}
