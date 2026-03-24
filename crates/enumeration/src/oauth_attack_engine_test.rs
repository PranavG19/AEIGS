use super::oauth_attack_engine::*;
use std::collections::HashSet;

#[test]
fn all_nine_categories_covered() {
    let config = OAuthAttackConfig::default();
    let result = run_oauth_attack_engine(&config);
    assert!(
        result.categories_covered.len() >= 9,
        "expected >=9 categories, got {}",
        result.categories_covered.len()
    );

    let expected = [
        OAuthAttackCategory::RedirectUriManipulation,
        OAuthAttackCategory::StateParameterAttack,
        OAuthAttackCategory::PkceBypass,
        OAuthAttackCategory::TokenExchangeAbuse,
        OAuthAttackCategory::ScopeManipulation,
        OAuthAttackCategory::ClientAuthBypass,
        OAuthAttackCategory::IdTokenValidationGap,
        OAuthAttackCategory::TokenSubstitution,
        OAuthAttackCategory::DynamicClientRegistrationAbuse,
    ];
    for cat in &expected {
        assert!(
            result.categories_covered.contains(cat),
            "missing category: {cat}"
        );
    }
}

#[test]
fn total_test_count_matches_vec_length() {
    let config = OAuthAttackConfig::default();
    let result = run_oauth_attack_engine(&config);
    assert_eq!(result.total_test_count, result.test_cases.len());
}

#[test]
fn redirect_uri_produces_at_least_five_bypass_techniques() {
    let config = OAuthAttackConfig::default();
    let cases = generate_redirect_uri_bypasses(&config);
    let techniques: HashSet<String> = cases.iter().map(|c| c.technique.clone()).collect();
    assert!(
        techniques.len() >= 5,
        "expected >=5 redirect bypass techniques, got {}",
        techniques.len()
    );
}

#[test]
fn redirect_uri_produces_ten_techniques() {
    let config = OAuthAttackConfig::default();
    let cases = generate_redirect_uri_bypasses(&config);
    assert_eq!(cases.len(), 10);
    let techniques: HashSet<String> = cases.iter().map(|c| c.technique.clone()).collect();
    assert_eq!(techniques.len(), 10, "all 10 should be unique");
}

#[test]
fn redirect_bypasses_contain_attacker_domain() {
    let config = OAuthAttackConfig::default();
    let cases = generate_redirect_uri_bypasses(&config);
    for case in &cases {
        let has_attacker_ref = case
            .request
            .query_params
            .iter()
            .any(|(k, v)| k == "redirect_uri" && v.contains("attacker"));

        let is_case_mismatch = case.technique == "case-mismatch";
        let is_trailing_dot = case.technique == "trailing-dot-domain";

        assert!(
            has_attacker_ref || is_case_mismatch || is_trailing_dot,
            "technique '{}' should reference attacker domain or be a known exception",
            case.technique
        );
    }
}

#[test]
fn redirect_bypasses_all_target_authorization_endpoint() {
    let config = OAuthAttackConfig::default();
    let cases = generate_redirect_uri_bypasses(&config);
    for case in &cases {
        assert_eq!(case.request.endpoint, config.authorization_endpoint);
        assert_eq!(case.request.method, "GET");
    }
}

#[test]
fn state_parameter_missing_state_has_no_state_param() {
    let config = OAuthAttackConfig::default();
    let cases = generate_state_parameter_attacks(&config);
    let missing = cases
        .iter()
        .find(|c| c.technique == "missing-state")
        .expect("missing-state technique not found");
    assert!(
        !missing
            .request
            .query_params
            .iter()
            .any(|(k, _)| k == "state"),
        "missing-state should have no state param"
    );
}

#[test]
fn state_parameter_empty_state() {
    let config = OAuthAttackConfig::default();
    let cases = generate_state_parameter_attacks(&config);
    let empty = cases
        .iter()
        .find(|c| c.technique == "empty-state")
        .expect("empty-state technique not found");
    let state_val = empty
        .request
        .query_params
        .iter()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.as_str());
    assert_eq!(state_val, Some(""));
}

#[test]
fn state_attacks_produce_six_variants() {
    let config = OAuthAttackConfig::default();
    let cases = generate_state_parameter_attacks(&config);
    assert_eq!(cases.len(), 6);
    for case in &cases {
        assert_eq!(case.category, OAuthAttackCategory::StateParameterAttack);
    }
}

#[test]
fn pkce_bypass_produces_four_tests() {
    let config = OAuthAttackConfig::default();
    let cases = generate_pkce_bypass_attacks(&config);
    assert_eq!(cases.len(), 4);
    let techniques: Vec<&str> = cases.iter().map(|c| c.technique.as_str()).collect();
    assert!(techniques.contains(&"missing-verifier"));
    assert!(techniques.contains(&"wrong-verifier"));
    assert!(techniques.contains(&"s256-downgrade-to-plain"));
    assert!(techniques.contains(&"pkce-not-required"));
}

#[test]
fn pkce_s256_downgrade_uses_plain_method() {
    let config = OAuthAttackConfig::default();
    let cases = generate_pkce_bypass_attacks(&config);
    let downgrade = cases
        .iter()
        .find(|c| c.technique == "s256-downgrade-to-plain")
        .expect("s256-downgrade not found");
    let method_param = downgrade
        .request
        .query_params
        .iter()
        .find(|(k, _)| k == "code_challenge_method");
    assert_eq!(method_param.map(|(_, v)| v.as_str()), Some("plain"));
}

#[test]
fn token_exchange_produces_four_tests() {
    let config = OAuthAttackConfig::default();
    let cases = generate_token_exchange_attacks(&config);
    assert_eq!(cases.len(), 4);
    let techniques: Vec<&str> = cases.iter().map(|c| c.technique.as_str()).collect();
    assert!(techniques.contains(&"code-replay"));
    assert!(techniques.contains(&"wrong-endpoint-exchange"));
    assert!(techniques.contains(&"cross-client-code-use"));
    assert!(techniques.contains(&"redirect-uri-mismatch-at-token"));
}

#[test]
fn token_exchange_code_replay_targets_token_endpoint() {
    let config = OAuthAttackConfig::default();
    let cases = generate_token_exchange_attacks(&config);
    let replay = cases.iter().find(|c| c.technique == "code-replay").unwrap();
    assert_eq!(replay.request.endpoint, config.token_endpoint);
    assert_eq!(replay.request.method, "POST");
}

#[test]
fn scope_manipulation_includes_escalation_and_refresh() {
    let config = OAuthAttackConfig::default();
    let cases = generate_scope_manipulation_attacks(&config);
    assert!(cases.len() >= 2, "need at least escalation + refresh test");

    let has_refresh = cases
        .iter()
        .any(|c| c.technique == "scope-widening-on-refresh");
    assert!(has_refresh, "missing scope-widening-on-refresh test");

    let escalation_count = cases
        .iter()
        .filter(|c| c.technique.starts_with("scope-escalation"))
        .count();
    assert!(escalation_count >= 5, "need >=5 escalation variants");
}

#[test]
fn scope_widening_refresh_body_contains_admin() {
    let config = OAuthAttackConfig::default();
    let cases = generate_scope_manipulation_attacks(&config);
    let widening = cases
        .iter()
        .find(|c| c.technique == "scope-widening-on-refresh")
        .unwrap();
    let body = widening.request.body.as_ref().unwrap();
    assert!(
        body.contains("admin"),
        "refresh body should include admin scope"
    );
    assert!(body.contains("refresh_token"), "should be refresh grant");
}

#[test]
fn client_auth_bypass_produces_three_tests() {
    let config = OAuthAttackConfig::default();
    let cases = generate_client_auth_bypass_attacks(&config);
    assert_eq!(cases.len(), 3);
    let techniques: Vec<&str> = cases.iter().map(|c| c.technique.as_str()).collect();
    assert!(techniques.contains(&"missing-client-secret"));
    assert!(techniques.contains(&"wrong-client-secret"));
    assert!(techniques.contains(&"dual-auth-confusion"));
}

#[test]
fn client_auth_dual_confusion_has_basic_header() {
    let config = OAuthAttackConfig::default();
    let cases = generate_client_auth_bypass_attacks(&config);
    let dual = cases
        .iter()
        .find(|c| c.technique == "dual-auth-confusion")
        .unwrap();
    let has_basic = dual
        .request
        .headers
        .iter()
        .any(|(k, v)| k == "Authorization" && v.starts_with("Basic "));
    assert!(has_basic, "dual-auth-confusion should have Basic header");
}

#[test]
fn id_token_validation_produces_six_tests() {
    let config = OAuthAttackConfig::default();
    let cases = generate_id_token_validation_attacks(&config);
    assert_eq!(cases.len(), 6);
    let techniques: Vec<&str> = cases.iter().map(|c| c.technique.as_str()).collect();
    assert!(techniques.contains(&"wrong-issuer"));
    assert!(techniques.contains(&"wrong-audience"));
    assert!(techniques.contains(&"missing-nonce"));
    assert!(techniques.contains(&"expired-token"));
    assert!(techniques.contains(&"future-iat"));
    assert!(techniques.contains(&"alg-none-attack"));
}

#[test]
fn id_token_tests_use_bearer_authorization() {
    let config = OAuthAttackConfig::default();
    let cases = generate_id_token_validation_attacks(&config);
    for case in &cases {
        let has_bearer = case
            .request
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v.starts_with("Bearer "));
        assert!(
            has_bearer,
            "technique '{}' should have Bearer header",
            case.technique
        );
    }
}

#[test]
fn token_substitution_produces_three_tests() {
    let config = OAuthAttackConfig::default();
    let cases = generate_token_substitution_attacks(&config);
    assert_eq!(cases.len(), 3);
    let techniques: Vec<&str> = cases.iter().map(|c| c.technique.as_str()).collect();
    assert!(techniques.contains(&"access-token-as-id-token"));
    assert!(techniques.contains(&"implicit-token-in-code-flow"));
    assert!(techniques.contains(&"refresh-token-as-access-token"));
}

#[test]
fn dynamic_registration_produces_three_tests() {
    let config = OAuthAttackConfig::default();
    let cases = generate_dynamic_registration_attacks(&config);
    assert_eq!(cases.len(), 3);
    for case in &cases {
        assert_eq!(case.request.method, "POST");
        assert!(case.request.body.is_some());
    }
}

#[test]
fn dynamic_registration_malicious_redirect_body_is_valid_json() {
    let config = OAuthAttackConfig::default();
    let cases = generate_dynamic_registration_attacks(&config);
    let malicious = cases
        .iter()
        .find(|c| c.technique == "malicious-redirect-registration")
        .unwrap();
    let body = malicious.request.body.as_ref().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(body).expect("body should be valid JSON");
    assert!(parsed.get("redirect_uris").is_some());
    let uris = parsed["redirect_uris"].as_array().unwrap();
    assert!(uris[0].as_str().unwrap().contains("evil.attacker.com"));
}

#[test]
fn every_test_case_has_nonempty_descriptions() {
    let config = OAuthAttackConfig::default();
    let result = run_oauth_attack_engine(&config);
    for case in &result.test_cases {
        assert!(!case.technique.is_empty(), "technique should not be empty");
        assert!(
            !case.description.is_empty(),
            "description should not be empty for {}",
            case.technique
        );
        assert!(
            !case.expected_secure_behavior.is_empty(),
            "secure behavior should not be empty for {}",
            case.technique
        );
        assert!(
            !case.expected_vulnerable_behavior.is_empty(),
            "vulnerable behavior should not be empty for {}",
            case.technique
        );
    }
}

#[test]
fn every_test_case_has_valid_method() {
    let config = OAuthAttackConfig::default();
    let result = run_oauth_attack_engine(&config);
    let valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];
    for case in &result.test_cases {
        assert!(
            valid_methods.contains(&case.request.method.as_str()),
            "invalid method '{}' in technique '{}'",
            case.request.method,
            case.technique
        );
    }
}

#[test]
fn category_display_roundtrip() {
    let categories = [
        OAuthAttackCategory::RedirectUriManipulation,
        OAuthAttackCategory::StateParameterAttack,
        OAuthAttackCategory::PkceBypass,
        OAuthAttackCategory::TokenExchangeAbuse,
        OAuthAttackCategory::ScopeManipulation,
        OAuthAttackCategory::ClientAuthBypass,
        OAuthAttackCategory::IdTokenValidationGap,
        OAuthAttackCategory::TokenSubstitution,
        OAuthAttackCategory::DynamicClientRegistrationAbuse,
    ];
    for cat in &categories {
        let display = format!("{cat}");
        assert!(!display.is_empty());
        assert!(
            display.contains('-'),
            "display should use kebab-case: {display}"
        );
    }
}

#[test]
fn custom_config_propagates_endpoints() {
    let config = OAuthAttackConfig {
        authorization_endpoint: "/custom/auth".to_string(),
        token_endpoint: "/custom/token".to_string(),
        client_id: "custom-client".to_string(),
        registered_redirect_uri: "https://myapp.example.com/cb".to_string(),
        scopes: vec!["read".to_string()],
        issuer: "https://idp.custom.com".to_string(),
        userinfo_endpoint: Some("/custom/userinfo".to_string()),
        registration_endpoint: Some("/custom/register".to_string()),
        jwks_uri: Some("/custom/jwks".to_string()),
    };

    let redirect_cases = generate_redirect_uri_bypasses(&config);
    for case in &redirect_cases {
        assert_eq!(case.request.endpoint, "/custom/auth");
    }

    let token_cases = generate_token_exchange_attacks(&config);
    let replay = token_cases
        .iter()
        .find(|c| c.technique == "code-replay")
        .unwrap();
    assert_eq!(replay.request.endpoint, "/custom/token");

    let reg_cases = generate_dynamic_registration_attacks(&config);
    for case in &reg_cases {
        assert_eq!(case.request.endpoint, "/custom/register");
    }
}

#[test]
fn redirect_bypass_technique_display() {
    let techniques = [
        RedirectBypassTechnique::SubdomainPrefix,
        RedirectBypassTechnique::PathTraversal,
        RedirectBypassTechnique::FragmentInjection,
        RedirectBypassTechnique::ParameterPollution,
        RedirectBypassTechnique::OpenRedirectChain,
        RedirectBypassTechnique::UrlEncodingBypass,
        RedirectBypassTechnique::CaseMismatch,
        RedirectBypassTechnique::TrailingDotDomain,
        RedirectBypassTechnique::AtSignBypass,
        RedirectBypassTechnique::BackslashConfusion,
    ];
    let mut displays = HashSet::new();
    for t in &techniques {
        let d = format!("{t}");
        assert!(!d.is_empty());
        displays.insert(d);
    }
    assert_eq!(
        displays.len(),
        10,
        "all technique displays should be unique"
    );
}

#[test]
fn extract_domain_parses_correctly() {
    let config = OAuthAttackConfig::default();
    let cases = generate_redirect_uri_bypasses(&config);
    let subdomain_case = cases
        .iter()
        .find(|c| c.technique == "subdomain-prefix")
        .unwrap();
    let redirect = subdomain_case
        .request
        .query_params
        .iter()
        .find(|(k, _)| k == "redirect_uri")
        .map(|(_, v)| v.as_str())
        .unwrap();
    assert!(redirect.contains("legitimate.example.com"));
    assert!(redirect.contains("evil.attacker.com"));
}

#[test]
fn full_engine_generates_at_least_40_test_cases() {
    let config = OAuthAttackConfig::default();
    let result = run_oauth_attack_engine(&config);
    assert!(
        result.total_test_count >= 40,
        "expected >=40 total tests, got {}",
        result.total_test_count
    );
}

#[test]
fn no_duplicate_techniques_within_category() {
    let config = OAuthAttackConfig::default();
    let result = run_oauth_attack_engine(&config);

    let mut seen: HashSet<(String, String)> = HashSet::new();
    for case in &result.test_cases {
        let key = (format!("{}", case.category), case.technique.clone());
        assert!(
            seen.insert(key.clone()),
            "duplicate technique within category: {:?}",
            key
        );
    }
}
