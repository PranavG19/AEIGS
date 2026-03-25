use super::cors_credential_chain::*;

fn sample_finding_origin_reflection() -> CorsFinding {
    CorsFinding::new(
        "https://api.example.com/user/profile",
        "example.com",
        CorsMisconfigType::OriginReflection,
    )
    .with_exposed_data(vec![
        StolenDataType::SessionToken,
        StolenDataType::PersonalEmail,
        StolenDataType::FullName,
    ])
}

fn sample_finding_null_origin() -> CorsFinding {
    CorsFinding::new(
        "https://api.example.com/account/details",
        "example.com",
        CorsMisconfigType::NullOriginTrusted,
    )
    .with_exposed_data(vec![StolenDataType::UserProfile, StolenDataType::ApiKey])
}

fn sample_finding_regex() -> CorsFinding {
    CorsFinding::new(
        "https://api.example.com/data",
        "example.com",
        CorsMisconfigType::WeakRegexValidation,
    )
    .with_exposed_data(vec![StolenDataType::InternalApiResponse])
}

fn sample_finding_trusted_subdomains() -> CorsFinding {
    CorsFinding::new(
        "https://api.example.com/admin/users",
        "example.com",
        CorsMisconfigType::TrustedSubdomains,
    )
    .with_exposed_data(vec![
        StolenDataType::FinancialData,
        StolenDataType::CreditCardPartial,
    ])
    .with_trusted_origins(vec![
        "https://dev.example.com".to_string(),
        "https://staging.example.com".to_string(),
    ])
}

fn sample_finding_wildcard() -> CorsFinding {
    CorsFinding::new(
        "https://api.example.com/search",
        "example.com",
        CorsMisconfigType::WildcardWithCredentials,
    )
    .with_methods(vec![
        "GET".to_string(),
        "PUT".to_string(),
        "DELETE".to_string(),
    ])
    .with_exposed_data(vec![StolenDataType::CsrfToken])
}

fn basic_generator() -> CorsCredentialChainGenerator {
    CorsCredentialChainGenerator::new("evil.com")
}

// NOTE: We use `builder` as the variable name instead of `gen` because
// `gen` is a reserved keyword in Rust 2024 edition.

#[test]
fn test_cors_chain_type_display() {
    assert_eq!(
        CorsChainType::DirectOriginReflection.to_string(),
        "direct-origin-reflection"
    );
    assert_eq!(
        CorsChainType::SubdomainTakeover.to_string(),
        "subdomain-takeover"
    );
    assert_eq!(
        CorsChainType::XssCorsExploit.to_string(),
        "xss-cors-exploit"
    );
    assert_eq!(
        CorsChainType::OAuthTokenTheft.to_string(),
        "oauth-token-theft"
    );
    assert_eq!(
        CorsChainType::NullOriginExploit.to_string(),
        "null-origin-exploit"
    );
    assert_eq!(CorsChainType::RegexBypass.to_string(), "regex-bypass");
}

#[test]
fn test_cors_misconfig_type_display() {
    assert_eq!(
        CorsMisconfigType::OriginReflection.to_string(),
        "origin-reflection"
    );
    assert_eq!(
        CorsMisconfigType::WildcardWithCredentials.to_string(),
        "wildcard-with-credentials"
    );
    assert_eq!(
        CorsMisconfigType::NullOriginTrusted.to_string(),
        "null-origin-trusted"
    );
    assert_eq!(
        CorsMisconfigType::WeakRegexValidation.to_string(),
        "weak-regex-validation"
    );
    assert_eq!(
        CorsMisconfigType::TrustedSubdomains.to_string(),
        "trusted-subdomains"
    );
    assert_eq!(
        CorsMisconfigType::DangerousPreflightMethods.to_string(),
        "dangerous-preflight-methods"
    );
}

#[test]
fn test_stolen_data_type_display() {
    assert_eq!(StolenDataType::SessionToken.to_string(), "session-token");
    assert_eq!(
        StolenDataType::MedicalRecords.to_string(),
        "medical-records"
    );
    assert_eq!(
        StolenDataType::OAuthRefreshToken.to_string(),
        "oauth-refresh-token"
    );
}

#[test]
fn test_stolen_data_type_impact_scores() {
    assert_eq!(StolenDataType::MedicalRecords.impact_score(), 10.0);
    assert_eq!(StolenDataType::FinancialData.impact_score(), 9.5);
    assert_eq!(StolenDataType::SessionToken.impact_score(), 8.0);
    assert_eq!(StolenDataType::FullName.impact_score(), 4.0);
    assert!(StolenDataType::ApiKey.impact_score() > StolenDataType::UserProfile.impact_score());
}

#[test]
fn test_stolen_data_type_regulatory_impact() {
    let hipaa = StolenDataType::MedicalRecords.regulatory_impact();
    assert!(hipaa.contains(&"HIPAA"));
    assert!(hipaa.contains(&"GDPR"));

    let pci = StolenDataType::CreditCardPartial.regulatory_impact();
    assert!(pci.contains(&"PCI-DSS"));
}

#[test]
fn test_cors_finding_builder() {
    let finding = CorsFinding::new(
        "https://api.test.com/data",
        "test.com",
        CorsMisconfigType::OriginReflection,
    )
    .with_credentials(true)
    .with_methods(vec!["GET".to_string(), "POST".to_string()])
    .with_exposed_data(vec![StolenDataType::SessionToken])
    .with_trusted_origins(vec!["https://trusted.test.com".to_string()]);

    assert_eq!(finding.endpoint_url, "https://api.test.com/data");
    assert_eq!(finding.domain, "test.com");
    assert!(finding.allows_credentials);
    assert_eq!(finding.allowed_methods.len(), 2);
    assert_eq!(finding.exposed_data_types.len(), 1);
    assert_eq!(finding.trusted_origins.len(), 1);
}

#[test]
fn test_cors_finding_no_credentials() {
    let finding = CorsFinding::new(
        "https://api.test.com/public",
        "test.com",
        CorsMisconfigType::OriginReflection,
    )
    .with_credentials(false);

    assert!(!finding.allows_credentials);
}

#[test]
fn test_generator_construction() {
    let builder = CorsCredentialChainGenerator::new("attacker.com");
    assert_eq!(builder.finding_count(), 0);
    assert_eq!(builder.takeover_subdomain_count(), 0);
}

#[test]
fn test_generator_add_findings() {
    let mut builder = basic_generator();
    builder.add_finding(sample_finding_origin_reflection());
    assert_eq!(builder.finding_count(), 1);

    builder.add_findings(vec![sample_finding_null_origin(), sample_finding_regex()]);
    assert_eq!(builder.finding_count(), 3);
}

#[test]
fn test_direct_origin_reflection_chain() {
    let mut builder = basic_generator();
    let finding = sample_finding_origin_reflection();
    builder.add_finding(finding.clone());

    let chains = builder.generate_direct_chains(&finding);
    assert_eq!(chains.len(), 1);

    let chain = &chains[0];
    assert_eq!(chain.chain_type, CorsChainType::DirectOriginReflection);
    assert_eq!(
        chain.target_endpoint,
        "https://api.example.com/user/profile"
    );
    assert_eq!(chain.attacker_origin, "https://evil.com");
    assert_eq!(chain.steps.len(), 4);
    assert!(chain.severity > 0.0);
    assert!(!chain.poc_html.is_empty());
    assert!(chain.poc_html.contains("withCredentials"));
    assert!(chain.poc_html.contains("evil.com/exfil"));
}

#[test]
fn test_direct_chain_not_generated_for_wrong_misconfig() {
    let builder = basic_generator();
    let finding = sample_finding_null_origin();
    let chains = builder.generate_direct_chains(&finding);
    assert!(chains.is_empty());
}

#[test]
fn test_wildcard_generates_direct_chain() {
    let builder = basic_generator();
    let finding = sample_finding_wildcard();
    let chains = builder.generate_direct_chains(&finding);
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].chain_type, CorsChainType::DirectOriginReflection);
}

#[test]
fn test_null_origin_chain() {
    let builder = basic_generator();
    let finding = sample_finding_null_origin();
    let chains = builder.generate_null_origin_chains(&finding);

    assert_eq!(chains.len(), 1);
    let chain = &chains[0];
    assert_eq!(chain.chain_type, CorsChainType::NullOriginExploit);
    assert!(chain.poc_html.contains("sandbox"));
    assert!(chain.poc_html.contains("allow-scripts"));
    assert!(chain.poc_html.contains("postMessage"));
    assert_eq!(chain.steps.len(), 4);
}

#[test]
fn test_null_origin_not_generated_for_wrong_misconfig() {
    let builder = basic_generator();
    let finding = sample_finding_origin_reflection();
    let chains = builder.generate_null_origin_chains(&finding);
    assert!(chains.is_empty());
}

#[test]
fn test_regex_bypass_chains() {
    let builder = basic_generator();
    let finding = sample_finding_regex();
    let chains = builder.generate_regex_bypass_chains(&finding);

    assert!(chains.len() >= 4);
    for chain in &chains {
        assert_eq!(chain.chain_type, CorsChainType::RegexBypass);
        assert_eq!(chain.steps.len(), 4);
        assert!(chain.poc_html.contains("Regex Bypass"));
        assert!(
            chain.attacker_origin.contains("example.com")
                || chain.attacker_origin.contains("evil.com")
        );
    }
}

#[test]
fn test_regex_bypass_not_generated_for_wrong_misconfig() {
    let builder = basic_generator();
    let finding = sample_finding_origin_reflection();
    let chains = builder.generate_regex_bypass_chains(&finding);
    assert!(chains.is_empty());
}

#[test]
fn test_subdomain_takeover_chains() {
    let mut builder = basic_generator();
    builder.add_takeover_subdomain("dev.example.com");
    builder.add_takeover_subdomain("staging.example.com");

    let finding = sample_finding_trusted_subdomains();
    let chains = builder.generate_subdomain_takeover_chains(&finding);

    assert_eq!(chains.len(), 2);
    for chain in &chains {
        assert_eq!(chain.chain_type, CorsChainType::SubdomainTakeover);
        assert_eq!(chain.steps.len(), 4);
        assert!(!chain.prerequisites.is_empty());
        assert!(chain.poc_html.contains("Subdomain Takeover"));
    }
}

#[test]
fn test_subdomain_takeover_no_subdomains() {
    let builder = basic_generator();
    let finding = sample_finding_trusted_subdomains();
    let chains = builder.generate_subdomain_takeover_chains(&finding);
    assert!(chains.is_empty());
}

#[test]
fn test_xss_cors_chains() {
    let mut builder = basic_generator();
    builder.add_xss_endpoint(XssEndpoint {
        url: "https://blog.example.com/search".to_string(),
        domain: "blog.example.com".to_string(),
        param: "q".to_string(),
        is_stored: false,
    });

    let finding = sample_finding_origin_reflection();
    let chains = builder.generate_xss_cors_chains(&finding);

    assert_eq!(chains.len(), 1);
    let chain = &chains[0];
    assert_eq!(chain.chain_type, CorsChainType::XssCorsExploit);
    assert_eq!(chain.steps.len(), 3);
    assert!(chain.poc_html.contains("XSS"));
    assert!(chain.poc_html.contains("reflected"));
}

#[test]
fn test_xss_cors_stored_xss() {
    let mut builder = basic_generator();
    builder.add_xss_endpoint(XssEndpoint {
        url: "https://forum.example.com/post".to_string(),
        domain: "forum.example.com".to_string(),
        param: "body".to_string(),
        is_stored: true,
    });

    let finding = sample_finding_origin_reflection();
    let chains = builder.generate_xss_cors_chains(&finding);

    assert_eq!(chains.len(), 1);
    assert!(chains[0].poc_html.contains("stored"));
}

#[test]
fn test_xss_cors_no_xss_endpoints() {
    let builder = basic_generator();
    let finding = sample_finding_origin_reflection();
    let chains = builder.generate_xss_cors_chains(&finding);
    assert!(chains.is_empty());
}

#[test]
fn test_oauth_chains() {
    let mut builder = basic_generator();
    builder.add_oauth_endpoint(OAuthEndpoint {
        auth_url: "https://auth.example.com".to_string(),
        token_url: "https://auth.example.com/token".to_string(),
        domain: "example.com".to_string(),
        client_id: "app-client-123".to_string(),
        scopes: vec!["openid".to_string(), "profile".to_string()],
    });

    let finding = sample_finding_origin_reflection();
    let chains = builder.generate_oauth_chains(&finding);

    assert_eq!(chains.len(), 1);
    let chain = &chains[0];
    assert_eq!(chain.chain_type, CorsChainType::OAuthTokenTheft);
    assert_eq!(chain.steps.len(), 4);
    assert!(chain.poc_html.contains("OAuth"));
    assert!(chain.poc_html.contains("app-client-123"));
    assert!(chain.severity >= 9.0);
}

#[test]
fn test_oauth_no_endpoints() {
    let builder = basic_generator();
    let finding = sample_finding_origin_reflection();
    let chains = builder.generate_oauth_chains(&finding);
    assert!(chains.is_empty());
}

#[test]
fn test_generate_all_chains() {
    let mut builder = basic_generator();
    builder.add_finding(sample_finding_origin_reflection());
    builder.add_finding(sample_finding_null_origin());
    builder.add_finding(sample_finding_regex());
    builder.add_takeover_subdomain("dev.example.com");
    builder.add_xss_endpoint(XssEndpoint {
        url: "https://blog.example.com/search".to_string(),
        domain: "blog.example.com".to_string(),
        param: "q".to_string(),
        is_stored: false,
    });

    let chains = builder.generate_all_chains();
    assert!(chains.len() >= 5);

    let chain_types: Vec<CorsChainType> = chains.iter().map(|c| c.chain_type).collect();
    assert!(chain_types.contains(&CorsChainType::DirectOriginReflection));
    assert!(chain_types.contains(&CorsChainType::NullOriginExploit));
    assert!(chain_types.contains(&CorsChainType::RegexBypass));
}

#[test]
fn test_skips_non_credentialed_findings() {
    let mut builder = basic_generator();
    let finding = CorsFinding::new(
        "https://api.example.com/public",
        "example.com",
        CorsMisconfigType::OriginReflection,
    )
    .with_credentials(false);

    builder.add_finding(finding);
    let chains = builder.generate_all_chains();
    assert!(chains.is_empty());
}

#[test]
fn test_impact_scoring_high_value_data() {
    let finding = CorsFinding::new(
        "https://api.example.com/billing",
        "example.com",
        CorsMisconfigType::OriginReflection,
    )
    .with_exposed_data(vec![
        StolenDataType::CreditCardPartial,
        StolenDataType::FinancialData,
    ]);

    let impact = compute_impact(&finding);
    assert!(impact.overall_score >= 9.0);
    assert_eq!(impact.severity_label, "Critical");
    assert!(
        impact
            .regulatory_frameworks
            .contains(&"PCI-DSS".to_string())
    );
    assert!(impact.data_impact.contains_key("financial-data"));
    assert!(!impact.business_narrative.is_empty());
}

#[test]
fn test_impact_scoring_low_value_data() {
    let finding = CorsFinding::new(
        "https://api.example.com/profile",
        "example.com",
        CorsMisconfigType::OriginReflection,
    )
    .with_exposed_data(vec![StolenDataType::FullName]);

    let impact = compute_impact(&finding);
    assert!(impact.overall_score < 7.0);
}

#[test]
fn test_impact_scoring_no_data_types() {
    let finding = CorsFinding::new(
        "https://api.example.com/unknown",
        "example.com",
        CorsMisconfigType::OriginReflection,
    );

    let impact = compute_impact(&finding);
    assert!(impact.overall_score >= 5.0);
    assert!(impact.data_impact.is_empty());
}

#[test]
fn test_impact_method_multiplier() {
    let finding_get = CorsFinding::new(
        "https://api.example.com/data",
        "example.com",
        CorsMisconfigType::OriginReflection,
    )
    .with_methods(vec!["GET".to_string()]);

    let finding_put = CorsFinding::new(
        "https://api.example.com/data",
        "example.com",
        CorsMisconfigType::OriginReflection,
    )
    .with_methods(vec![
        "GET".to_string(),
        "PUT".to_string(),
        "DELETE".to_string(),
    ]);

    let impact_get = compute_impact(&finding_get);
    let impact_put = compute_impact(&finding_put);
    assert!(impact_put.overall_score > impact_get.overall_score);
}

#[test]
fn test_chain_severity_ordering() {
    let finding = sample_finding_origin_reflection();

    let direct = compute_chain_severity(CorsChainType::DirectOriginReflection, &finding);
    let null_origin = compute_chain_severity(CorsChainType::NullOriginExploit, &finding);
    let oauth = compute_chain_severity(CorsChainType::OAuthTokenTheft, &finding);

    assert!(oauth > direct);
    assert!(direct > null_origin);
}

#[test]
fn test_poc_html_contains_target_url() {
    let builder = basic_generator();
    let finding = sample_finding_origin_reflection();
    let chains = builder.generate_direct_chains(&finding);

    assert_eq!(chains.len(), 1);
    assert!(chains[0].poc_html.contains("api.example.com/user/profile"));
}

#[test]
fn test_poc_html_null_origin_contains_sandbox() {
    let builder = basic_generator();
    let finding = sample_finding_null_origin();
    let chains = builder.generate_null_origin_chains(&finding);

    assert_eq!(chains.len(), 1);
    let html = &chains[0].poc_html;
    assert!(html.contains("sandbox=\"allow-scripts allow-forms\""));
    assert!(html.contains("srcdoc="));
}

#[test]
fn test_chain_steps_are_sequential() {
    let builder = basic_generator();
    let finding = sample_finding_origin_reflection();
    let chains = builder.generate_direct_chains(&finding);

    let steps = &chains[0].steps;
    for (i, step) in steps.iter().enumerate() {
        assert_eq!(step.step_number, (i + 1) as u32);
        assert!(!step.description.is_empty());
        assert!(!step.technical_detail.is_empty());
        assert!(!step.expected_outcome.is_empty());
    }
}

#[test]
fn test_prerequisites_populated() {
    let builder = basic_generator();
    let finding = sample_finding_origin_reflection();
    let chains = builder.generate_direct_chains(&finding);

    assert!(!chains[0].prerequisites.is_empty());
    assert!(
        chains[0]
            .prerequisites
            .iter()
            .any(|p| p.contains("session"))
    );
}

#[test]
fn test_with_exfil_endpoint() {
    let mut builder = CorsCredentialChainGenerator::new("evil.com")
        .with_exfil_endpoint("https://evil.com/custom-collect");
    let finding = sample_finding_origin_reflection();
    builder.add_finding(finding.clone());

    let chains = builder.generate_direct_chains(&finding);
    assert!(chains[0].poc_html.contains("custom-collect"));
}

#[test]
fn test_multiple_chain_types_in_single_generate() {
    let mut builder = basic_generator();
    builder.add_finding(sample_finding_origin_reflection());
    builder.add_finding(sample_finding_null_origin());
    builder.add_finding(sample_finding_regex());
    builder.add_finding(sample_finding_trusted_subdomains());
    builder.add_finding(sample_finding_wildcard());

    builder.add_takeover_subdomain("staging.example.com");
    builder.add_xss_endpoint(XssEndpoint {
        url: "https://blog.example.com/comment".to_string(),
        domain: "blog.example.com".to_string(),
        param: "text".to_string(),
        is_stored: true,
    });
    builder.add_oauth_endpoint(OAuthEndpoint {
        auth_url: "https://auth.example.com".to_string(),
        token_url: "https://auth.example.com/token".to_string(),
        domain: "example.com".to_string(),
        client_id: "client-abc".to_string(),
        scopes: vec!["read".to_string()],
    });

    let chains = builder.generate_all_chains();

    let mut seen_types = std::collections::HashSet::new();
    for chain in &chains {
        seen_types.insert(chain.chain_type);
    }

    assert!(
        seen_types.len() >= 5,
        "Expected at least 5 chain types, got: {seen_types:?}"
    );
}

#[test]
fn test_business_narrative_includes_domain() {
    let finding = sample_finding_origin_reflection();
    let impact = compute_impact(&finding);
    assert!(impact.business_narrative.contains("example.com"));
}

#[test]
fn test_business_narrative_includes_data_types() {
    let finding = CorsFinding::new(
        "https://api.example.com/health",
        "example.com",
        CorsMisconfigType::OriginReflection,
    )
    .with_exposed_data(vec![StolenDataType::MedicalRecords]);

    let impact = compute_impact(&finding);
    assert!(impact.business_narrative.contains("medical-records"));
    assert!(impact.business_narrative.contains("critical"));
}
