use super::*;

#[test]
fn shannon_entropy_empty_string_returns_zero() {
    assert_eq!(shannon_entropy(""), 0.0);
}

#[test]
fn shannon_entropy_single_char_repeated_returns_zero() {
    assert_eq!(shannon_entropy("aaaaaaa"), 0.0);
}

#[test]
fn shannon_entropy_two_equal_chars_returns_one() {
    let e = shannon_entropy("ab");
    assert!((e - 1.0).abs() < 0.01, "expected ~1.0, got {}", e);
}

#[test]
fn shannon_entropy_high_for_diverse_token() {
    let token = "a3f2b1c4d5e6f7890123456789abcdef";
    let e = shannon_entropy(token);
    assert!(e > 3.0, "expected high entropy for hex token, got {}", e);
}

#[test]
fn identify_format_hex() {
    assert_eq!(identify_token_format("a3f2b1c4d5e6f789"), TokenFormat::Hex);
}

#[test]
fn identify_format_uuid() {
    assert_eq!(
        identify_token_format("550e8400-e29b-41d4-a716-446655440000"),
        TokenFormat::Uuid
    );
}

#[test]
fn identify_format_numeric() {
    assert_eq!(
        identify_token_format("12345678901234"),
        TokenFormat::Numeric
    );
}

#[test]
fn identify_format_jwt() {
    assert_eq!(
        identify_token_format("eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiam9obiJ9.signature123"),
        TokenFormat::Jwt
    );
}

#[test]
fn identify_format_base64() {
    assert_eq!(
        identify_token_format("dGhpcyBpcyBhIHRlc3Q="),
        TokenFormat::Base64
    );
}

#[test]
fn identify_format_opaque_for_short_string() {
    assert_eq!(identify_token_format("abc"), TokenFormat::Opaque);
}

#[test]
fn identify_format_empty_is_opaque() {
    assert_eq!(identify_token_format(""), TokenFormat::Opaque);
}

#[test]
fn analyze_token_strong_hex() {
    let token = "a3f2b1c4d5e6f7890abcdef012345678abcdef01";
    let analysis = analyze_token(token);
    assert_eq!(analysis.format, TokenFormat::Hex);
    assert!(analysis.entropy_bits_per_char > 3.0);
    assert_eq!(analysis.length, 40);
}

#[test]
fn analyze_token_weak_short() {
    let token = "abcdef123456";
    let analysis = analyze_token(token);
    assert_eq!(analysis.strength, TokenStrength::Weak);
}

#[test]
fn analyze_token_predictable_low_entropy() {
    let token = "aaaaabbbbb";
    let analysis = analyze_token(token);
    assert_eq!(analysis.strength, TokenStrength::Predictable);
}

#[test]
fn detect_sequential_pattern_arithmetic() {
    let tokens = vec!["token_100", "token_101", "token_102", "token_103"];
    let refs: Vec<&str> = tokens.iter().map(|s| s.as_ref()).collect();
    assert!(detect_sequential_pattern(&refs));
}

#[test]
fn detect_sequential_pattern_non_sequential() {
    let tokens = vec!["x9f2a1b4c3d5e6f7", "q8h3j2k5l4m6n7o8", "r1s9t2u3v4w5x6y7"];
    let refs: Vec<&str> = tokens.iter().map(|s| s.as_ref()).collect();
    assert!(!detect_sequential_pattern(&refs));
}

#[test]
fn detect_sequential_not_enough_tokens() {
    assert!(!detect_sequential_pattern(&["one", "two"]));
}

#[test]
fn analyze_token_set_empty() {
    let analysis = analyze_token_set(&[]);
    assert_eq!(analysis.sample_count, 0);
    assert_eq!(analysis.strength, TokenStrength::Predictable);
}

#[test]
fn analyze_token_set_sequential() {
    let tokens = vec!["csrf_000001", "csrf_000002", "csrf_000003", "csrf_000004"];
    let refs: Vec<&str> = tokens.iter().map(|s| s.as_ref()).collect();
    let analysis = analyze_token_set(&refs);
    assert!(analysis.has_sequential_pattern);
    assert_eq!(analysis.strength, TokenStrength::Predictable);
}

#[test]
fn analyze_token_set_common_prefix() {
    let tokens = vec![
        "PREFIX_abc123def456",
        "PREFIX_xyz789uvw012",
        "PREFIX_qrs345tuv678",
    ];
    let refs: Vec<&str> = tokens.iter().map(|s| s.as_ref()).collect();
    let analysis = analyze_token_set(&refs);
    assert!(analysis.common_prefix_len >= 7);
}

#[test]
fn token_strength_display() {
    assert_eq!(format!("{}", TokenStrength::Strong), "Strong");
    assert_eq!(format!("{}", TokenStrength::Weak), "Weak");
    assert_eq!(format!("{}", TokenStrength::Predictable), "Predictable");
}

#[test]
fn csrf_bypass_technique_display() {
    assert_eq!(
        format!("{}", CsrfBypassTechnique::TokenFixation),
        "Token Fixation"
    );
    assert_eq!(
        format!("{}", CsrfBypassTechnique::MethodOverride),
        "Method Override (GET bypass)"
    );
    assert_eq!(
        format!("{}", CsrfBypassTechnique::DoubleSubmitCookieOverwrite),
        "Double-Submit Cookie Overwrite"
    );
}

#[test]
fn samesite_policy_display() {
    assert_eq!(format!("{}", SameSitePolicy::Strict), "Strict");
    assert_eq!(format!("{}", SameSitePolicy::Lax), "Lax");
    assert_eq!(format!("{}", SameSitePolicy::None), "None");
    assert_eq!(
        format!("{}", SameSitePolicy::NotSet),
        "Not Set (defaults to Lax)"
    );
}

#[test]
fn token_format_display() {
    assert_eq!(format!("{}", TokenFormat::Hex), "Hex");
    assert_eq!(format!("{}", TokenFormat::Jwt), "JWT");
    assert_eq!(format!("{}", TokenFormat::Uuid), "UUID v4");
}

#[test]
fn generate_token_fixation_has_poc() {
    let config =
        CsrfTestConfig::new("https://target.com/transfer", "target.com").with_csrf_param("_token");
    let finding = generate_token_fixation_bypass(&config, "old_stale_token_value");
    assert_eq!(finding.technique, CsrfBypassTechnique::TokenFixation);
    assert!(finding.poc_html.is_some());
    let poc = finding.poc_html.unwrap();
    assert!(poc.contains("old_stale_token_value"));
    assert!(poc.contains("target.com/transfer"));
}

#[test]
fn generate_method_override_has_poc() {
    let config = CsrfTestConfig::new("https://target.com/api/action", "target.com")
        .with_parameter("amount", "1000");
    let finding = generate_method_override_bypass(&config);
    assert_eq!(finding.technique, CsrfBypassTechnique::MethodOverride);
    assert!(finding.poc_html.is_some());
    let poc = finding.poc_html.unwrap();
    assert!(poc.contains("amount=1000"));
}

#[test]
fn generate_content_type_bypass_has_poc() {
    let config = CsrfTestConfig::new("https://target.com/api/v1/transfer", "target.com");
    let finding = generate_content_type_bypass(&config);
    assert_eq!(finding.technique, CsrfBypassTechnique::ContentTypeBypass);
    assert!(finding.poc_html.is_some());
    assert!(finding.poc_html.unwrap().contains("text/plain"));
}

#[test]
fn generate_subdomain_bypass_has_poc() {
    let config = CsrfTestConfig::new("https://app.target.com/settings", "target.com")
        .with_csrf_param("csrf");
    let finding = generate_subdomain_bypass(&config, "evil.target.com");
    assert_eq!(finding.technique, CsrfBypassTechnique::SubdomainTokenReuse);
    assert!(finding.poc_html.is_some());
    let poc = finding.poc_html.unwrap();
    assert!(poc.contains("evil.target.com"));
}

#[test]
fn generate_referer_origin_bypass_returns_two_findings() {
    let config = CsrfTestConfig::new("https://bank.com/transfer", "bank.com");
    let findings = generate_referer_origin_bypass(&config);
    assert_eq!(findings.len(), 2);
    assert!(findings
        .iter()
        .all(|f| f.technique == CsrfBypassTechnique::RefererOriginBypass));
    assert!(findings[0]
        .poc_html
        .as_ref()
        .unwrap()
        .contains("no-referrer"));
    assert!(findings[1].poc_html.as_ref().unwrap().contains("data:"));
}

#[test]
fn generate_json_csrf_has_poc() {
    let config = CsrfTestConfig::new("https://api.target.com/action", "target.com");
    let finding = generate_json_csrf_bypass(&config, r#"{"action":"delete"}"#);
    assert_eq!(finding.technique, CsrfBypassTechnique::JsonFormConfusion);
    assert!(finding.poc_html.is_some());
    assert!(finding.poc_html.unwrap().contains("delete"));
}

#[test]
fn generate_flash_pdf_bypass_has_crossdomain() {
    let config = CsrfTestConfig::new("https://legacy.com/admin", "legacy.com");
    let finding = generate_flash_pdf_bypass(&config);
    assert_eq!(finding.technique, CsrfBypassTechnique::FlashPdfCrossdomain);
    assert!(finding.poc_html.is_some());
    let poc = finding.poc_html.unwrap();
    assert!(poc.contains("crossdomain.xml") || poc.contains("cross-domain-policy"));
}

#[test]
fn generate_samesite_none_highest_confidence() {
    let config = CsrfTestConfig::new("https://target.com/action", "target.com")
        .with_same_site(SameSitePolicy::None);
    let finding = generate_samesite_bypass(&config);
    assert_eq!(finding.technique, CsrfBypassTechnique::SameSiteBypass);
    assert!(finding.confidence >= 0.8);
}

#[test]
fn generate_samesite_lax_medium_confidence() {
    let config = CsrfTestConfig::new("https://target.com/action", "target.com")
        .with_same_site(SameSitePolicy::Lax);
    let finding = generate_samesite_bypass(&config);
    assert!(finding.confidence > 0.3 && finding.confidence < 0.8);
    assert!(finding.poc_html.unwrap().contains("top-level"));
}

#[test]
fn generate_samesite_strict_low_confidence() {
    let config = CsrfTestConfig::new("https://target.com/action", "target.com")
        .with_same_site(SameSitePolicy::Strict);
    let finding = generate_samesite_bypass(&config);
    assert!(finding.confidence < 0.5);
}

#[test]
fn generate_token_removal_excludes_csrf_param() {
    let config = CsrfTestConfig::new("https://target.com/submit", "target.com")
        .with_parameter("name", "Alice")
        .with_parameter("csrf_token", "some_value")
        .with_csrf_param("csrf_token");
    let finding = generate_token_removal_bypass(&config);
    assert_eq!(finding.technique, CsrfBypassTechnique::TokenRemoval);
    let poc = finding.poc_html.unwrap();
    assert!(poc.contains("Alice"));
    assert!(!poc.contains("some_value"));
}

#[test]
fn generate_double_submit_bypass_has_cookie() {
    let config =
        CsrfTestConfig::new("https://target.com/api", "target.com").with_csrf_param("_csrf");
    let finding = generate_double_submit_bypass(&config, "csrf_session");
    assert_eq!(
        finding.technique,
        CsrfBypassTechnique::DoubleSubmitCookieOverwrite
    );
    let poc = finding.poc_html.unwrap();
    assert!(poc.contains("csrf_session"));
    assert!(poc.contains("attacker_controlled_value"));
}

#[test]
fn generate_all_bypasses_returns_at_least_ten() {
    let config = CsrfTestConfig::new("https://target.com/action", "target.com")
        .with_csrf_param("token")
        .with_parameter("amount", "500");
    let findings = generate_all_bypasses(&config);
    assert!(
        findings.len() >= 10,
        "expected at least 10 bypass findings, got {}",
        findings.len()
    );

    let techniques: Vec<CsrfBypassTechnique> = findings.iter().map(|f| f.technique).collect();
    assert!(techniques.contains(&CsrfBypassTechnique::TokenRemoval));
    assert!(techniques.contains(&CsrfBypassTechnique::MethodOverride));
    assert!(techniques.contains(&CsrfBypassTechnique::ContentTypeBypass));
    assert!(techniques.contains(&CsrfBypassTechnique::RefererOriginBypass));
    assert!(techniques.contains(&CsrfBypassTechnique::JsonFormConfusion));
    assert!(techniques.contains(&CsrfBypassTechnique::FlashPdfCrossdomain));
    assert!(techniques.contains(&CsrfBypassTechnique::SameSiteBypass));
    assert!(techniques.contains(&CsrfBypassTechnique::TokenFixation));
    assert!(techniques.contains(&CsrfBypassTechnique::SubdomainTokenReuse));
    assert!(techniques.contains(&CsrfBypassTechnique::DoubleSubmitCookieOverwrite));
}

#[test]
fn all_findings_have_poc_html() {
    let config =
        CsrfTestConfig::new("https://target.com/action", "target.com").with_csrf_param("_token");
    let findings = generate_all_bypasses(&config);
    for finding in &findings {
        assert!(
            finding.poc_html.is_some(),
            "finding {:?} missing PoC HTML",
            finding.technique
        );
        assert!(
            !finding.poc_html.as_ref().unwrap().is_empty(),
            "finding {:?} has empty PoC HTML",
            finding.technique
        );
    }
}

#[test]
fn all_findings_have_remediation() {
    let config = CsrfTestConfig::new("https://target.com/action", "target.com");
    let findings = generate_all_bypasses(&config);
    for finding in &findings {
        assert!(
            !finding.remediation.is_empty(),
            "finding {:?} missing remediation",
            finding.technique
        );
    }
}

#[test]
fn config_builder_methods() {
    let config = CsrfTestConfig::new("https://example.com", "example.com")
        .with_method("PUT")
        .with_parameter("key", "val")
        .with_csrf_param("_csrf")
        .with_csrf_header("X-CSRF-Token")
        .with_cookie("session", "abc123")
        .with_same_site(SameSitePolicy::Strict);

    assert_eq!(config.method, "PUT");
    assert_eq!(config.parameters.get("key").unwrap(), "val");
    assert_eq!(config.csrf_param_name.as_deref(), Some("_csrf"));
    assert_eq!(config.csrf_header_name.as_deref(), Some("X-CSRF-Token"));
    assert_eq!(config.cookies.get("session").unwrap(), "abc123");
    assert_eq!(config.same_site_policy, SameSitePolicy::Strict);
}

#[test]
fn detect_timestamp_component_with_unix_epoch() {
    assert!(detect_timestamp_component("token_1700000000_suffix"));
}

#[test]
fn detect_timestamp_component_no_timestamp() {
    assert!(!detect_timestamp_component("abcdefghijklmnop"));
}

#[test]
fn html_escape_in_poc() {
    let config = CsrfTestConfig::new("https://target.com/a?b=1&c=2", "target.com")
        .with_parameter("<script>", "\"evil\"");
    let finding = generate_token_removal_bypass(&config);
    let poc = finding.poc_html.unwrap();
    assert!(!poc.contains("<script>") || poc.contains("&lt;script&gt;"));
    assert!(poc.contains("&amp;") || !poc.contains("&c="));
}

#[test]
fn confidence_values_in_valid_range() {
    let config =
        CsrfTestConfig::new("https://target.com/action", "target.com").with_csrf_param("_token");
    let findings = generate_all_bypasses(&config);
    for finding in &findings {
        assert!(
            finding.confidence >= 0.0 && finding.confidence <= 1.0,
            "confidence {} out of range for {:?}",
            finding.confidence,
            finding.technique
        );
    }
}
