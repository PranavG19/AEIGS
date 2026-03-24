use super::*;

fn make_test_jwt() -> String {
    let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
    let payload = URL_SAFE_NO_PAD.encode(
        b"{\"sub\":\"1234567890\",\"name\":\"Test User\",\"admin\":false,\"exp\":1700000000,\"iat\":1600000000}",
    );
    let sig = URL_SAFE_NO_PAD.encode(b"fake-signature-bytes-here");
    format!("{}.{}.{}", header, payload, sig)
}

fn make_hs256_jwt() -> String {
    let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    let payload =
        URL_SAFE_NO_PAD.encode(b"{\"sub\":\"user42\",\"role\":\"user\",\"exp\":1700000000}");
    let sig = URL_SAFE_NO_PAD.encode(b"hmac-signature");
    format!("{}.{}.{}", header, payload, sig)
}

#[test]
fn parse_valid_jwt() {
    let token = make_test_jwt();
    let parsed = parse_jwt(&token);
    assert!(parsed.is_some());
    let jwt = parsed.unwrap();
    assert!(jwt.header_json.contains("RS256"));
    assert!(jwt.payload_json.contains("Test User"));
}

#[test]
fn parse_invalid_jwt_two_parts() {
    assert!(parse_jwt("header.payload").is_none());
}

#[test]
fn parse_invalid_jwt_four_parts() {
    assert!(parse_jwt("a.b.c.d").is_none());
}

#[test]
fn parse_invalid_jwt_bad_base64() {
    assert!(parse_jwt("!!!.@@@.###").is_none());
}

#[test]
fn parse_invalid_jwt_non_json() {
    let non_json = URL_SAFE_NO_PAD.encode(b"not json");
    let token = format!("{}.{}.sig", non_json, non_json);
    assert!(parse_jwt(&token).is_none());
}

#[test]
fn forge_alg_none_generates_variants() {
    let token = make_test_jwt();
    let jwt = parse_jwt(&token).unwrap();
    let attacks = forge_alg_none(&jwt);

    assert!(
        attacks.len() >= 10,
        "Should generate multiple alg:none variants, got {}",
        attacks.len()
    );

    for attack in &attacks {
        assert_eq!(attack.attack_type, AuthAttackType::JwtAlgNone);
        assert_eq!(attack.original_alg, "RS256");
        assert!(attack.description.contains("alg:"));
    }

    let has_none = attacks.iter().any(|a| a.description.contains("alg:none"));
    let has_none_upper = attacks.iter().any(|a| a.description.contains("alg:NONE"));
    assert!(has_none, "Should include alg:none variant");
    assert!(has_none_upper, "Should include alg:NONE variant");
}

#[test]
fn forge_alg_none_tokens_are_parseable() {
    let token = make_test_jwt();
    let jwt = parse_jwt(&token).unwrap();
    let attacks = forge_alg_none(&jwt);

    for attack in &attacks {
        let parts: Vec<&str> = attack.raw.split('.').collect();
        assert!(
            parts.len() >= 2,
            "Tampered token should have at least 2 parts: {}",
            attack.raw
        );
    }
}

#[test]
fn forge_alg_confusion_from_rs256() {
    let token = make_test_jwt();
    let jwt = parse_jwt(&token).unwrap();
    let attacks = forge_alg_confusion(&jwt);

    assert!(
        !attacks.is_empty(),
        "Should generate confusion attacks for RS256"
    );

    let has_hs256 = attacks.iter().any(|a| a.description.contains("HS256"));
    assert!(has_hs256, "Should include RS256→HS256 confusion");

    for attack in &attacks {
        assert_eq!(attack.attack_type, AuthAttackType::JwtAlgConfusion);
        assert!(attack.raw.contains("SIGN_WITH_PUBLIC_KEY"));
    }
}

#[test]
fn forge_alg_confusion_from_hs256_no_results() {
    let token = make_hs256_jwt();
    let jwt = parse_jwt(&token).unwrap();
    let attacks = forge_alg_confusion(&jwt);

    assert!(
        attacks.is_empty(),
        "HS256 should not generate confusion attacks to itself"
    );
}

#[test]
fn forge_claim_tampering_escalates_privileges() {
    let token = make_test_jwt();
    let jwt = parse_jwt(&token).unwrap();
    let attacks = forge_claim_tampering(&jwt);

    assert!(
        attacks.len() >= 8,
        "Should generate multiple escalation payloads"
    );

    let has_admin = attacks.iter().any(|a| a.description.contains("admin=true"));
    let has_role = attacks.iter().any(|a| a.description.contains("role=admin"));
    assert!(has_admin, "Should include admin=true escalation");
    assert!(has_role, "Should include role=admin escalation");

    for attack in &attacks {
        assert_eq!(attack.attack_type, AuthAttackType::JwtClaimTampering);
        let parts: Vec<&str> = attack.raw.split('.').collect();
        assert_eq!(parts.len(), 3, "Tampered token should have 3 parts");
    }
}

#[test]
fn forge_exp_bypass_variants() {
    let token = make_test_jwt();
    let jwt = parse_jwt(&token).unwrap();
    let attacks = forge_exp_bypass(&jwt);

    assert!(
        attacks.len() >= 4,
        "Should generate removal + far future + zero + negative"
    );

    let has_removal = attacks.iter().any(|a| a.description.contains("remove"));
    let has_future = attacks.iter().any(|a| a.description.contains("future"));
    assert!(has_removal, "Should include exp removal");
    assert!(has_future, "Should include far future exp");

    for attack in &attacks {
        assert_eq!(attack.attack_type, AuthAttackType::JwtExpBypass);
    }
}

#[test]
fn forge_kid_injection_payloads() {
    let token = make_test_jwt();
    let jwt = parse_jwt(&token).unwrap();
    let attacks = forge_kid_injection(&jwt);

    assert!(
        attacks.len() >= 5,
        "Should generate multiple kid injection variants"
    );

    let has_traversal = attacks.iter().any(|a| a.description.contains("traversal"));
    let has_sqli = attacks
        .iter()
        .any(|a| a.description.contains("SQL injection"));
    let has_cmdi = attacks
        .iter()
        .any(|a| a.description.contains("command injection"));
    assert!(has_traversal, "Should include path traversal kid");
    assert!(has_sqli, "Should include SQL injection kid");
    assert!(has_cmdi, "Should include command injection kid");

    for attack in &attacks {
        assert_eq!(attack.attack_type, AuthAttackType::JwtKidInjection);
    }
}

#[test]
fn forge_jku_spoofing_payloads() {
    let token = make_test_jwt();
    let jwt = parse_jwt(&token).unwrap();
    let attacks = forge_jku_spoofing(&jwt);

    assert!(attacks.len() >= 3);

    let has_attacker = attacks
        .iter()
        .any(|a| a.raw.contains("SIGN_WITH_ATTACKER_KEY"));
    assert!(has_attacker, "JKU attacks need attacker-key signing");

    let has_ssrf = attacks.iter().any(|a| a.description.contains("SSRF"));
    assert!(has_ssrf, "Should include SSRF via jku");
}

#[test]
fn forge_null_signature_payloads() {
    let token = make_test_jwt();
    let jwt = parse_jwt(&token).unwrap();
    let attacks = forge_null_signature(&jwt);

    assert!(attacks.len() >= 3);

    let has_empty = attacks.iter().any(|a| a.description.contains("empty"));
    assert!(has_empty, "Should include empty signature variant");

    for attack in &attacks {
        assert_eq!(attack.attack_type, AuthAttackType::JwtNullSignature);
    }
}

#[test]
fn generate_all_jwt_attacks_comprehensive() {
    let token = make_test_jwt();
    let attacks = generate_all_jwt_attacks(&token);

    assert!(
        attacks.len() >= 40,
        "Full attack suite should generate 40+ payloads, got {}",
        attacks.len()
    );

    let attack_types: std::collections::HashSet<AuthAttackType> =
        attacks.iter().map(|a| a.attack_type).collect();
    assert!(attack_types.contains(&AuthAttackType::JwtAlgNone));
    assert!(attack_types.contains(&AuthAttackType::JwtAlgConfusion));
    assert!(attack_types.contains(&AuthAttackType::JwtClaimTampering));
    assert!(attack_types.contains(&AuthAttackType::JwtExpBypass));
    assert!(attack_types.contains(&AuthAttackType::JwtKidInjection));
    assert!(attack_types.contains(&AuthAttackType::JwtJkuSpoofing));
    assert!(attack_types.contains(&AuthAttackType::JwtNullSignature));
}

#[test]
fn generate_all_jwt_attacks_invalid_token() {
    let attacks = generate_all_jwt_attacks("not-a-jwt");
    assert!(attacks.is_empty());
}

#[test]
fn attack_count_matches() {
    let token = make_test_jwt();
    let count = attack_count(&token);
    let attacks = generate_all_jwt_attacks(&token);
    assert_eq!(count, attacks.len());
}

#[test]
fn measure_token_entropy_high() {
    let high_entropy = "a7f3b9c2e1d4f6a8b0c3d5e7f9a1b2c4d6e8f0a2b4c6d8e0f1a3b5c7d9e1f3";
    let entropy = measure_token_entropy(high_entropy);
    assert!(
        entropy > 3.0,
        "High entropy token should have entropy > 3.0, got {}",
        entropy
    );
}

#[test]
fn measure_token_entropy_low() {
    let low_entropy = "aaaaaaaaaaaaaaaa";
    let entropy = measure_token_entropy(low_entropy);
    assert!(
        entropy < 0.1,
        "Repeated char should have near-zero entropy, got {}",
        entropy
    );
}

#[test]
fn measure_token_entropy_empty() {
    assert_eq!(measure_token_entropy(""), 0.0);
}

#[test]
fn analyze_session_tokens_secure() {
    let tokens = vec![
        "a7f3b9c2e1d4f6a8b0c3d5e7f9a1b2c4",
        "d6e8f0a2b4c6d8e0f1a3b5c7d9e1f3a5",
        "c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1",
        "f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0",
        "b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5",
    ];
    let analysis = analyze_session_tokens(&tokens);
    assert_eq!(analysis.verdict, SessionVerdict::Secure);
    assert!(analysis.unique_ratio == 1.0);
    assert!(analysis.entropy_bits > 64.0);
}

#[test]
fn analyze_session_tokens_predictable_sequential() {
    let tokens = vec![
        "session_001",
        "session_002",
        "session_003",
        "session_004",
        "session_005",
    ];
    let analysis = analyze_session_tokens(&tokens);
    assert_eq!(analysis.verdict, SessionVerdict::Predictable);
    assert!(analysis.sequential_score > 0.5);
}

#[test]
fn analyze_session_tokens_weak_short() {
    let tokens = vec!["ab12", "cd34", "ef56", "gh78", "ij90"];
    let analysis = analyze_session_tokens(&tokens);
    assert!(
        analysis.verdict == SessionVerdict::Weak || analysis.verdict == SessionVerdict::Predictable,
        "Short tokens should be weak or predictable, got {}",
        analysis.verdict,
    );
}

#[test]
fn analyze_session_tokens_empty() {
    let analysis = analyze_session_tokens(&[]);
    assert_eq!(analysis.verdict, SessionVerdict::InsufficientData);
}

#[test]
fn analyze_session_tokens_duplicates() {
    let tokens = vec!["same_token", "same_token", "same_token", "same_token"];
    let analysis = analyze_session_tokens(&tokens);
    assert_eq!(analysis.verdict, SessionVerdict::Predictable);
    assert!(analysis.unique_ratio < 0.5);
}

#[test]
fn oauth_redirect_payloads_generated() {
    let payloads = generate_oauth_redirect_payloads("https://app.example.com/callback");

    assert!(
        payloads.len() >= 7,
        "Should generate multiple redirect manipulation payloads"
    );

    let has_at_sign = payloads
        .iter()
        .any(|p| p.redirect_uri.contains("@attacker.com"));
    let has_traversal = payloads.iter().any(|p| p.redirect_uri.contains(".."));
    let has_complete_override = payloads
        .iter()
        .any(|p| p.redirect_uri == "http://attacker.com");

    assert!(has_at_sign, "Should include @ URL confusion");
    assert!(has_traversal, "Should include path traversal");
    assert!(
        has_complete_override,
        "Should include complete redirect override"
    );

    for payload in &payloads {
        assert_eq!(
            payload.attack_type,
            AuthAttackType::OAuthRedirectManipulation
        );
        assert!(!payload.description.is_empty());
    }
}

#[test]
fn auth_attack_type_display() {
    assert_eq!(AuthAttackType::JwtAlgNone.to_string(), "jwt_alg_none");
    assert_eq!(
        AuthAttackType::JwtAlgConfusion.to_string(),
        "jwt_alg_confusion"
    );
    assert_eq!(
        AuthAttackType::JwtClaimTampering.to_string(),
        "jwt_claim_tampering"
    );
    assert_eq!(AuthAttackType::JwtExpBypass.to_string(), "jwt_exp_bypass");
    assert_eq!(
        AuthAttackType::JwtKidInjection.to_string(),
        "jwt_kid_injection"
    );
    assert_eq!(
        AuthAttackType::JwtJkuSpoofing.to_string(),
        "jwt_jku_spoofing"
    );
    assert_eq!(
        AuthAttackType::JwtNullSignature.to_string(),
        "jwt_null_signature"
    );
    assert_eq!(
        AuthAttackType::SessionFixation.to_string(),
        "session_fixation"
    );
    assert_eq!(
        AuthAttackType::SessionPrediction.to_string(),
        "session_prediction"
    );
    assert_eq!(
        AuthAttackType::SessionEntropy.to_string(),
        "session_entropy"
    );
    assert_eq!(
        AuthAttackType::OAuthRedirectManipulation.to_string(),
        "oauth_redirect_manipulation"
    );
    assert_eq!(
        AuthAttackType::OAuthStateMissing.to_string(),
        "oauth_state_missing"
    );
    assert_eq!(
        AuthAttackType::OAuthScopeEscalation.to_string(),
        "oauth_scope_escalation"
    );
    assert_eq!(
        AuthAttackType::OAuthCodeReuse.to_string(),
        "oauth_code_reuse"
    );
    assert_eq!(
        AuthAttackType::SamlSignatureWrapping.to_string(),
        "saml_signature_wrapping"
    );
    assert_eq!(
        AuthAttackType::SamlCommentInjection.to_string(),
        "saml_comment_injection"
    );
}

#[test]
fn session_verdict_display() {
    assert_eq!(SessionVerdict::Secure.to_string(), "SECURE");
    assert_eq!(SessionVerdict::Weak.to_string(), "WEAK");
    assert_eq!(SessionVerdict::Predictable.to_string(), "PREDICTABLE");
    assert_eq!(
        SessionVerdict::InsufficientData.to_string(),
        "INSUFFICIENT_DATA"
    );
}

#[test]
fn common_prefix_detected() {
    let tokens = vec!["prefix_abc123", "prefix_def456", "prefix_ghi789"];
    let analysis = analyze_session_tokens(&tokens);
    assert!(
        analysis.common_prefix_len >= 7,
        "Should detect 'prefix_' common prefix"
    );
}

#[test]
fn common_suffix_detected() {
    let tokens = vec!["abc_suffix", "def_suffix", "ghi_suffix"];
    let analysis = analyze_session_tokens(&tokens);
    assert!(
        analysis.common_suffix_len >= 7,
        "Should detect '_suffix' common suffix"
    );
}

#[test]
fn forge_claim_tampering_payload_decodable() {
    let token = make_test_jwt();
    let jwt = parse_jwt(&token).unwrap();
    let attacks = forge_claim_tampering(&jwt);

    for attack in &attacks {
        let parts: Vec<&str> = attack.raw.split('.').collect();
        assert_eq!(parts.len(), 3);

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("payload should be valid base64");
        let payload_str = String::from_utf8(payload_bytes).expect("payload should be valid UTF-8");
        let payload_val: serde_json::Value =
            serde_json::from_str(&payload_str).expect("payload should be valid JSON");

        assert!(
            payload_val.get("sub").is_some(),
            "Should preserve original sub claim"
        );
    }
}

#[test]
fn forge_exp_bypass_payload_decodable() {
    let token = make_test_jwt();
    let jwt = parse_jwt(&token).unwrap();
    let attacks = forge_exp_bypass(&jwt);

    let removed = &attacks[0];
    let parts: Vec<&str> = removed.raw.split('.').collect();
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("valid base64");
    let payload_str = String::from_utf8(payload_bytes).expect("valid UTF-8");
    let payload_val: serde_json::Value = serde_json::from_str(&payload_str).expect("valid JSON");
    assert!(
        payload_val.get("exp").is_none(),
        "exp claim should be removed"
    );

    let far_future = &attacks[1];
    let parts: Vec<&str> = far_future.raw.split('.').collect();
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("valid base64");
    let payload_str = String::from_utf8(payload_bytes).expect("valid UTF-8");
    let payload_val: serde_json::Value = serde_json::from_str(&payload_str).expect("valid JSON");
    assert!(
        payload_val.get("exp").is_some(),
        "far future should have exp claim"
    );
}
