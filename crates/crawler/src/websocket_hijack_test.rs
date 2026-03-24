use super::*;

#[test]
fn cswsh_poc_contains_target_url() {
    let config = WsHijackConfig::default().with_target("wss://target.local/ws");
    let vector = generate_cswsh_poc(&config);

    assert_eq!(vector.category, WsAttackCategory::CrossSiteHijack);
    assert_eq!(vector.severity, WsSeverity::Critical);

    if let WsAttackPayload::CswshPoc { ref html, .. } = vector.payload {
        assert!(html.contains("wss://target.local/ws"));
    } else {
        panic!("expected CswshPoc payload");
    }
}

#[test]
fn cswsh_poc_contains_attacker_origin() {
    let config = WsHijackConfig::default()
        .with_target("wss://victim.com/chat")
        .with_attacker_origin("https://evil.corp");
    let vector = generate_cswsh_poc(&config);

    if let WsAttackPayload::CswshPoc {
        ref html,
        ref attacker_origin,
    } = vector.payload
    {
        assert!(html.contains("evil.corp"));
        assert_eq!(attacker_origin, "https://evil.corp");
    } else {
        panic!("expected CswshPoc payload");
    }
}

#[test]
fn cswsh_poc_includes_cookie_when_provided() {
    let config = WsHijackConfig::default()
        .with_target("wss://target.local/ws")
        .with_session_cookie("abc123");
    let vector = generate_cswsh_poc(&config);

    if let WsAttackPayload::CswshPoc { ref html, .. } = vector.payload {
        assert!(html.contains("abc123"));
        assert!(html.contains("document.cookie"));
    } else {
        panic!("expected CswshPoc payload");
    }
}

#[test]
fn cswsh_poc_omits_cookie_when_absent() {
    let config = WsHijackConfig::default().with_target("wss://target.local/ws");
    let vector = generate_cswsh_poc(&config);

    if let WsAttackPayload::CswshPoc { ref html, .. } = vector.payload {
        assert!(!html.contains("document.cookie"));
    } else {
        panic!("expected CswshPoc payload");
    }
}

#[test]
fn auth_bypass_generates_minimum_vectors() {
    let config = WsHijackConfig::default().with_target("wss://app.local/ws");
    let vectors = generate_auth_bypass_vectors(&config);

    assert!(vectors.len() >= 3, "need at least 3 auth bypass vectors");
    for v in &vectors {
        assert_eq!(v.category, WsAttackCategory::AuthBypass);
    }
}

#[test]
fn auth_bypass_no_cookie_vector_present() {
    let config = WsHijackConfig::default().with_target("wss://app.local/ws");
    let vectors = generate_auth_bypass_vectors(&config);

    let no_cookie = vectors.iter().find(|v| v.name == "upgrade-no-cookies");
    assert!(no_cookie.is_some(), "missing no-cookies vector");

    if let WsAttackPayload::UpgradeRequest { with_cookies, .. } = &no_cookie.unwrap().payload {
        assert!(!with_cookies);
    } else {
        panic!("expected UpgradeRequest payload");
    }
}

#[test]
fn auth_bypass_adds_valid_cookie_baseline_when_configured() {
    let config = WsHijackConfig::default()
        .with_target("wss://app.local/ws")
        .with_session_cookie("real_session_value");
    let vectors = generate_auth_bypass_vectors(&config);

    let baseline = vectors
        .iter()
        .find(|v| v.name == "upgrade-with-valid-cookie");
    assert!(
        baseline.is_some(),
        "missing baseline vector when cookie provided"
    );
    assert_eq!(baseline.unwrap().severity, WsSeverity::Info);
}

#[test]
fn auth_bypass_skips_baseline_without_cookie() {
    let config = WsHijackConfig::default().with_target("wss://app.local/ws");
    let vectors = generate_auth_bypass_vectors(&config);

    let baseline = vectors
        .iter()
        .find(|v| v.name == "upgrade-with-valid-cookie");
    assert!(
        baseline.is_none(),
        "baseline should not appear without session cookie"
    );
}

#[test]
fn auth_bypass_expired_jwt_vector() {
    let config = WsHijackConfig::default().with_target("wss://app.local/ws");
    let vectors = generate_auth_bypass_vectors(&config);

    let jwt = vectors.iter().find(|v| v.name == "upgrade-expired-token");
    assert!(jwt.is_some(), "missing expired-token vector");

    if let WsAttackPayload::UpgradeRequest { headers, .. } = &jwt.unwrap().payload {
        let auth_header = headers.iter().find(|(k, _)| k == "Authorization");
        assert!(auth_header.is_some());
        assert!(auth_header.unwrap().1.starts_with("Bearer "));
    } else {
        panic!("expected UpgradeRequest payload");
    }
}

#[test]
fn message_injection_produces_at_least_five_formats() {
    let vectors = generate_message_injection_payloads();
    assert!(
        vectors.len() >= 5,
        "need at least 5 message injection payloads, got {}",
        vectors.len()
    );

    let formats: std::collections::HashSet<_> = vectors
        .iter()
        .filter_map(|v| {
            if let WsAttackPayload::Message { ref format, .. } = v.payload {
                Some(*format)
            } else {
                None
            }
        })
        .collect();
    assert!(
        formats.len() >= 5,
        "need at least 5 distinct formats, got {}",
        formats.len()
    );
}

#[test]
fn message_injection_all_have_correct_category() {
    let vectors = generate_message_injection_payloads();
    for v in &vectors {
        assert_eq!(v.category, WsAttackCategory::MessageInjection);
    }
}

#[test]
fn message_injection_json_payloads_are_valid_utf8() {
    let vectors = generate_message_injection_payloads();
    for v in &vectors {
        if let WsAttackPayload::Message {
            format: WsMessageFormat::JsonText,
            ref content,
        } = v.payload
        {
            let text = std::str::from_utf8(content);
            assert!(text.is_ok(), "JSON payload should be valid UTF-8");
        }
    }
}

#[test]
fn message_injection_includes_sqli_payload() {
    let vectors = generate_message_injection_payloads();
    let sqli = vectors.iter().find(|v| v.name == "json-sqli");
    assert!(sqli.is_some(), "missing SQL injection vector");
    assert_eq!(sqli.unwrap().severity, WsSeverity::Critical);
}

#[test]
fn message_injection_includes_xxe_payload() {
    let vectors = generate_message_injection_payloads();
    let xxe = vectors.iter().find(|v| v.name == "xml-xxe");
    assert!(xxe.is_some(), "missing XXE vector");

    if let WsAttackPayload::Message { content, .. } = &xxe.unwrap().payload {
        let text = std::str::from_utf8(content).unwrap();
        assert!(text.contains("<!ENTITY"));
    } else {
        panic!("expected Message payload");
    }
}

#[test]
fn message_injection_includes_graphql_subscription() {
    let vectors = generate_message_injection_payloads();
    let gql = vectors
        .iter()
        .find(|v| v.name == "graphql-subscription-injection");
    assert!(gql.is_some(), "missing GraphQL subscription vector");

    if let WsAttackPayload::Message { format, .. } = &gql.unwrap().payload {
        assert_eq!(*format, WsMessageFormat::GraphQlSubscription);
    } else {
        panic!("expected Message payload");
    }
}

#[test]
fn dos_generates_all_techniques() {
    let config = WsHijackConfig::default().with_target("wss://target.local/ws");
    let vectors = generate_dos_vectors(&config);

    let techniques: std::collections::HashSet<_> = vectors
        .iter()
        .filter_map(|v| {
            if let WsAttackPayload::DosConfig { technique, .. } = &v.payload {
                Some(*technique)
            } else {
                None
            }
        })
        .collect();

    assert!(techniques.contains(&DosTechnique::ConnectionFlood));
    assert!(techniques.contains(&DosTechnique::OversizedFrame));
    assert!(techniques.contains(&DosTechnique::PingFlood));
    assert!(techniques.contains(&DosTechnique::SlowRead));
    assert!(techniques.contains(&DosTechnique::FragmentFlood));
}

#[test]
fn dos_respects_config_limits() {
    let config = WsHijackConfig::default()
        .with_target("wss://target.local/ws")
        .with_max_connections(500)
        .with_max_frame_bytes(1024);
    let vectors = generate_dos_vectors(&config);

    let flood = vectors
        .iter()
        .find(|v| v.name == "connection-flood")
        .unwrap();
    if let WsAttackPayload::DosConfig { parameter, .. } = &flood.payload {
        assert_eq!(*parameter, 500);
    }

    let oversized = vectors
        .iter()
        .find(|v| v.name == "oversized-frame")
        .unwrap();
    if let WsAttackPayload::DosConfig { parameter, .. } = &oversized.payload {
        assert_eq!(*parameter, 1024);
    }
}

#[test]
fn downgrade_generates_wss_to_ws_for_tls_target() {
    let config = WsHijackConfig::default().with_target("wss://secure.local/ws");
    let vectors = generate_downgrade_vectors(&config);

    let downgrade = vectors.iter().find(|v| v.name == "wss-to-ws-downgrade");
    assert!(downgrade.is_some());

    if let WsAttackPayload::Downgrade { downgraded_url, .. } = &downgrade.unwrap().payload {
        assert!(downgraded_url.starts_with("ws://"));
        assert!(downgraded_url.contains("secure.local/ws"));
    } else {
        panic!("expected Downgrade payload");
    }
}

#[test]
fn downgrade_skips_wss_to_ws_for_plaintext_target() {
    let config = WsHijackConfig::default().with_target("ws://plain.local/ws");
    let vectors = generate_downgrade_vectors(&config);

    let downgrade = vectors.iter().find(|v| v.name == "wss-to-ws-downgrade");
    assert!(
        downgrade.is_none(),
        "should not generate wss→ws for already-plaintext target"
    );
}

#[test]
fn downgrade_includes_ws_to_http() {
    let config = WsHijackConfig::default().with_target("wss://app.local/socket");
    let vectors = generate_downgrade_vectors(&config);

    let http_down = vectors.iter().find(|v| v.name == "ws-to-http-downgrade");
    assert!(http_down.is_some());

    if let WsAttackPayload::Downgrade { downgraded_url, .. } = &http_down.unwrap().payload {
        assert!(downgraded_url.starts_with("https://"));
    } else {
        panic!("expected Downgrade payload");
    }
}

#[test]
fn smuggling_generates_three_vectors() {
    let config = WsHijackConfig::default().with_target("wss://app.local/ws");
    let vectors = generate_smuggling_vectors(&config);

    assert_eq!(vectors.len(), 3);
    for v in &vectors {
        assert_eq!(v.category, WsAttackCategory::ConnectionSmuggling);
    }
}

#[test]
fn smuggling_cl_te_contains_admin_path() {
    let config = WsHijackConfig::default().with_target("wss://app.local/ws");
    let vectors = generate_smuggling_vectors(&config);

    let clte = vectors
        .iter()
        .find(|v| v.name == "cl-te-websocket-smuggle")
        .unwrap();
    if let WsAttackPayload::Smuggle { raw_request } = &clte.payload {
        assert!(raw_request.contains("/admin"));
        assert!(raw_request.contains("Transfer-Encoding: chunked"));
    } else {
        panic!("expected Smuggle payload");
    }
}

#[test]
fn smuggling_h2c_contains_upgrade_header() {
    let config = WsHijackConfig::default().with_target("wss://app.local/ws");
    let vectors = generate_smuggling_vectors(&config);

    let h2c = vectors
        .iter()
        .find(|v| v.name == "h2c-smuggle-via-upgrade")
        .unwrap();
    if let WsAttackPayload::Smuggle { raw_request } = &h2c.payload {
        assert!(raw_request.contains("Upgrade: h2c"));
    } else {
        panic!("expected Smuggle payload");
    }
}

#[test]
fn token_leakage_detects_access_token() {
    let result = detect_token_leakage("wss://app.local/ws?access_token=secret123");
    assert!(result.is_some());

    let vector = result.unwrap();
    assert_eq!(vector.category, WsAttackCategory::TokenLeakage);
    assert_eq!(vector.severity, WsSeverity::High);

    if let WsAttackPayload::TokenLeak { leaked_params, .. } = &vector.payload {
        assert!(leaked_params.contains(&"access_token".to_string()));
    } else {
        panic!("expected TokenLeak payload");
    }
}

#[test]
fn token_leakage_detects_multiple_params() {
    let result = detect_token_leakage("wss://app.local/ws?token=abc&api_key=def&room=general");
    assert!(result.is_some());

    if let WsAttackPayload::TokenLeak { leaked_params, .. } = &result.unwrap().payload {
        assert!(leaked_params.len() >= 2);
        assert!(leaked_params.contains(&"token".to_string()));
        assert!(leaked_params.contains(&"api_key".to_string()));
    } else {
        panic!("expected TokenLeak payload");
    }
}

#[test]
fn token_leakage_returns_none_for_safe_url() {
    let result = detect_token_leakage("wss://app.local/ws?room=general&user=bob");
    assert!(result.is_none());
}

#[test]
fn token_leakage_case_insensitive() {
    let result = detect_token_leakage("wss://app.local/ws?API_KEY=xyz");
    assert!(result.is_some());
}

#[test]
fn token_leakage_handles_invalid_url() {
    let result = detect_token_leakage("not a valid url at all");
    assert!(result.is_none());
}

#[test]
fn full_analysis_covers_all_seven_categories() {
    let config = WsHijackConfig::default().with_target("wss://app.local/ws?token=leaked123");
    let result = analyze_websocket_endpoint(&config);

    assert_eq!(result.target_url, "wss://app.local/ws?token=leaked123");
    assert_eq!(result.summary.categories_tested.len(), 7);
    assert!(
        result.summary.total_vectors >= 20,
        "expected 20+ vectors, got {}",
        result.summary.total_vectors
    );
}

#[test]
fn full_analysis_counts_severities() {
    let config = WsHijackConfig::default().with_target("wss://app.local/ws?token=leaked");
    let result = analyze_websocket_endpoint(&config);

    assert!(result.summary.critical_count >= 2);
    assert!(result.summary.high_count >= 5);
}

#[test]
fn config_default_values() {
    let config = WsHijackConfig::default();
    assert_eq!(config.attacker_origin, "https://evil.attacker.com");
    assert_eq!(config.max_connections, 1000);
    assert_eq!(config.max_frame_bytes, 16 * 1024 * 1024);
    assert!(config.session_cookie.is_none());
    assert!(config.auth_token.is_none());
}

#[test]
fn config_builder_chain() {
    let config = WsHijackConfig::default()
        .with_target("wss://t.local/ws")
        .with_attacker_origin("https://my-evil.site")
        .with_session_cookie("sess_abc")
        .with_auth_token("tok_xyz")
        .with_max_connections(42)
        .with_max_frame_bytes(999);

    assert_eq!(config.target_url, "wss://t.local/ws");
    assert_eq!(config.attacker_origin, "https://my-evil.site");
    assert_eq!(config.session_cookie.as_deref(), Some("sess_abc"));
    assert_eq!(config.auth_token.as_deref(), Some("tok_xyz"));
    assert_eq!(config.max_connections, 42);
    assert_eq!(config.max_frame_bytes, 999);
}

#[test]
fn display_impls_are_non_empty() {
    assert!(!format!("{}", WsAttackCategory::CrossSiteHijack).is_empty());
    assert!(!format!("{}", WsAttackCategory::AuthBypass).is_empty());
    assert!(!format!("{}", WsAttackCategory::MessageInjection).is_empty());
    assert!(!format!("{}", WsAttackCategory::DenialOfService).is_empty());
    assert!(!format!("{}", WsAttackCategory::ProtocolDowngrade).is_empty());
    assert!(!format!("{}", WsAttackCategory::ConnectionSmuggling).is_empty());
    assert!(!format!("{}", WsAttackCategory::TokenLeakage).is_empty());
    assert!(!format!("{}", WsSeverity::Info).is_empty());
    assert!(!format!("{}", WsSeverity::Critical).is_empty());
    assert!(!format!("{}", WsMessageFormat::JsonText).is_empty());
    assert!(!format!("{}", WsMessageFormat::Binary).is_empty());
    assert!(!format!("{}", WsMessageFormat::GraphQlSubscription).is_empty());
    assert!(!format!("{}", DosTechnique::ConnectionFlood).is_empty());
    assert!(!format!("{}", DosTechnique::SlowRead).is_empty());
}

#[test]
fn severity_ordering() {
    assert!(WsSeverity::Info < WsSeverity::Low);
    assert!(WsSeverity::Low < WsSeverity::Medium);
    assert!(WsSeverity::Medium < WsSeverity::High);
    assert!(WsSeverity::High < WsSeverity::Critical);
}

#[test]
fn extract_host_from_wss_url() {
    assert_eq!(extract_host("wss://example.com/ws"), "example.com");
}

#[test]
fn extract_host_fallback_for_invalid_url() {
    assert_eq!(extract_host("not-a-url"), "localhost");
}

#[test]
fn extract_path_from_wss_url() {
    assert_eq!(extract_path("wss://example.com/api/ws"), "/api/ws");
}

#[test]
fn extract_path_fallback_for_invalid_url() {
    assert_eq!(extract_path("garbage"), "/");
}
