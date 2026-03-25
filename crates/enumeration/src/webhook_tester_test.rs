use crate::webhook_tester::*;

#[test]
fn ssrf_payloads_include_localhost_variants() {
    let payloads = generate_ssrf_payloads("webhook_url");
    let localhost: Vec<_> = payloads
        .iter()
        .filter(|p| p.technique == SsrfTechnique::LocalhostAccess)
        .collect();
    assert!(localhost.len() >= 8);
    assert!(localhost
        .iter()
        .any(|p| p.payload_url.contains("127.0.0.1")));
    assert!(localhost.iter().any(|p| p.payload_url.contains("::1")));
    assert!(localhost.iter().any(|p| p.payload_url.contains("0x7f")));
}

#[test]
fn ssrf_payloads_include_cloud_metadata() {
    let payloads = generate_ssrf_payloads("url");
    let metadata: Vec<_> = payloads
        .iter()
        .filter(|p| p.technique == SsrfTechnique::MetadataEndpoint)
        .collect();
    assert!(metadata.len() >= 4);
    assert!(metadata
        .iter()
        .any(|p| p.payload_url.contains("169.254.169.254")));
    assert!(metadata
        .iter()
        .any(|p| p.payload_url.contains("metadata.google.internal")));
}

#[test]
fn ssrf_payloads_include_internal_network() {
    let payloads = generate_ssrf_payloads("url");
    let internal: Vec<_> = payloads
        .iter()
        .filter(|p| p.technique == SsrfTechnique::InternalNetworkScan)
        .collect();
    assert!(internal.len() >= 3);
}

#[test]
fn ssrf_payloads_include_dns_rebinding() {
    let payloads = generate_ssrf_payloads("url");
    assert!(payloads
        .iter()
        .any(|p| p.technique == SsrfTechnique::DnsRebinding));
}

#[test]
fn ssrf_payloads_include_scheme_abuse() {
    let payloads = generate_ssrf_payloads("url");
    let scheme: Vec<_> = payloads
        .iter()
        .filter(|p| p.technique == SsrfTechnique::UrlSchemeAbuse)
        .collect();
    assert!(scheme.len() >= 3);
    assert!(scheme.iter().any(|p| p.payload_url.starts_with("file://")));
    assert!(scheme
        .iter()
        .any(|p| p.payload_url.starts_with("gopher://")));
}

#[test]
fn ssrf_payloads_include_redirect_chain() {
    let payloads = generate_ssrf_payloads("url");
    assert!(payloads
        .iter()
        .any(|p| p.technique == SsrfTechnique::RedirectChain));
}

#[test]
fn ssrf_payloads_all_critical_or_high() {
    let payloads = generate_ssrf_payloads("url");
    for p in &payloads {
        assert!(p.severity >= WebhookSeverity::High);
    }
}

#[test]
fn event_replay_tests_generated() {
    let tests = generate_event_replay_tests("evt_12345", "{\"type\": \"payment\"}");
    assert!(tests.len() >= 4);
    assert!(tests.iter().any(|t| t.replay_count == 1));
    assert!(tests.iter().any(|t| t.replay_count == 10));
    assert!(tests.iter().any(|t| t.event_id.contains("modified")));
}

#[test]
fn event_replay_content_dedup_test_has_hash_id() {
    let tests = generate_event_replay_tests("evt_abc", "{\"amount\": 100}");
    assert!(tests.iter().any(|t| t.event_id.starts_with("hash_")));
}

#[test]
fn evaluate_event_replay_accepted() {
    let test = &generate_event_replay_tests("evt_1", "body")[0];
    let result = evaluate_event_replay(test, true);
    assert!(result.accepted);
    assert_eq!(result.severity, WebhookSeverity::Critical);
}

#[test]
fn evaluate_event_replay_rejected() {
    let test = &generate_event_replay_tests("evt_1", "body")[0];
    let result = evaluate_event_replay(test, false);
    assert!(!result.accepted);
    assert_eq!(result.severity, WebhookSeverity::Info);
}

#[test]
fn signature_bypass_tests_generated() {
    let tests = generate_signature_bypass_tests("sha256=abcdef1234567890");
    assert!(tests.len() >= 7);
    assert!(tests
        .iter()
        .any(|t| t.technique == SignatureBypassTechnique::EmptySignature));
    assert!(tests
        .iter()
        .any(|t| t.technique == SignatureBypassTechnique::MissingHeader));
    assert!(tests
        .iter()
        .any(|t| t.technique == SignatureBypassTechnique::AlgorithmSwitch));
    assert!(tests
        .iter()
        .any(|t| t.technique == SignatureBypassTechnique::TimingAttack));
    assert!(tests
        .iter()
        .any(|t| t.technique == SignatureBypassTechnique::LengthExtension));
    assert!(tests
        .iter()
        .any(|t| t.technique == SignatureBypassTechnique::NonCanonicalEncoding));
    assert!(tests
        .iter()
        .any(|t| t.technique == SignatureBypassTechnique::ReplayWithTimestamp));
}

#[test]
fn signature_bypass_empty_has_empty_sig() {
    let tests = generate_signature_bypass_tests("sha256=abc123");
    let empty = tests
        .iter()
        .find(|t| t.technique == SignatureBypassTechnique::EmptySignature)
        .unwrap();
    assert!(empty.manipulated_signature.is_empty());
    assert_eq!(empty.severity, WebhookSeverity::Critical);
}

#[test]
fn signature_bypass_algo_switch_changes_prefix() {
    let tests = generate_signature_bypass_tests("sha256=abcdef1234567890");
    let algo = tests
        .iter()
        .find(|t| t.technique == SignatureBypassTechnique::AlgorithmSwitch)
        .unwrap();
    assert!(algo.manipulated_signature.starts_with("sha1="));
}

#[test]
fn signature_bypass_length_extension_appends() {
    let original = "sha256=abcdef1234567890";
    let tests = generate_signature_bypass_tests(original);
    let ext = tests
        .iter()
        .find(|t| t.technique == SignatureBypassTechnique::LengthExtension)
        .unwrap();
    assert!(ext.manipulated_signature.len() > original.len());
    assert!(ext.manipulated_signature.starts_with(original));
}

#[test]
fn signature_bypass_non_canonical_uppercases() {
    let tests = generate_signature_bypass_tests("sha256=abcdef");
    let nc = tests
        .iter()
        .find(|t| t.technique == SignatureBypassTechnique::NonCanonicalEncoding)
        .unwrap();
    assert_eq!(nc.manipulated_signature, "SHA256=ABCDEF");
}

#[test]
fn callback_manipulations_generated() {
    let manips = generate_callback_manipulations("https://myapp.com/webhooks/handle");
    assert!(manips.len() >= 5);
    assert!(manips
        .iter()
        .any(|m| m.technique == CallbackTechnique::UrlRedirect));
    assert!(manips
        .iter()
        .any(|m| m.technique == CallbackTechnique::HostOverride));
    assert!(manips
        .iter()
        .any(|m| m.technique == CallbackTechnique::PathTraversal));
    assert!(manips
        .iter()
        .any(|m| m.technique == CallbackTechnique::ProtocolDowngrade));
    assert!(manips
        .iter()
        .any(|m| m.technique == CallbackTechnique::ParameterInjection));
}

#[test]
fn callback_redirect_targets_attacker() {
    let manips = generate_callback_manipulations("https://myapp.com/hook");
    let redirect = manips
        .iter()
        .find(|m| m.technique == CallbackTechnique::UrlRedirect)
        .unwrap();
    assert!(redirect.manipulated_url.contains("attacker.com"));
    assert_eq!(redirect.severity, WebhookSeverity::Critical);
}

#[test]
fn callback_host_override_preserves_path() {
    let manips = generate_callback_manipulations("https://myapp.com/webhooks/handle");
    let host = manips
        .iter()
        .find(|m| m.technique == CallbackTechnique::HostOverride)
        .unwrap();
    assert!(host.manipulated_url.contains("attacker.com"));
    assert!(host.manipulated_url.contains("/webhooks/handle"));
}

#[test]
fn callback_protocol_downgrade() {
    let manips = generate_callback_manipulations("https://myapp.com/hook");
    let downgrade = manips
        .iter()
        .find(|m| m.technique == CallbackTechnique::ProtocolDowngrade)
        .unwrap();
    assert!(downgrade.manipulated_url.starts_with("http://"));
}

#[test]
fn callback_parameter_injection() {
    let manips = generate_callback_manipulations("https://myapp.com/hook");
    let param = manips
        .iter()
        .find(|m| m.technique == CallbackTechnique::ParameterInjection)
        .unwrap();
    assert!(param.manipulated_url.contains("?override=true"));
}

#[test]
fn payload_injections_generated() {
    let injections = generate_payload_injections("user_email");
    assert!(injections.len() >= 6);
    assert!(injections
        .iter()
        .any(|i| i.technique == PayloadInjectionTechnique::JsonFieldInjection));
    assert!(injections
        .iter()
        .any(|i| i.technique == PayloadInjectionTechnique::TypeConfusion));
    assert!(injections
        .iter()
        .any(|i| i.technique == PayloadInjectionTechnique::OversizedPayload));
    assert!(injections
        .iter()
        .any(|i| i.technique == PayloadInjectionTechnique::NestedObjectBomb));
    assert!(injections
        .iter()
        .any(|i| i.technique == PayloadInjectionTechnique::UnicodeBypass));
    assert!(injections
        .iter()
        .any(|i| i.technique == PayloadInjectionTechnique::HeaderInjectionViaPayload));
}

#[test]
fn payload_json_injection_escalates_privilege() {
    let injections = generate_payload_injections("name");
    let json_inj = injections
        .iter()
        .find(|i| i.technique == PayloadInjectionTechnique::JsonFieldInjection)
        .unwrap();
    assert!(json_inj.injected_value.contains("admin"));
    assert!(json_inj.injected_value.contains("true"));
}

#[test]
fn payload_type_confusion_nosql() {
    let injections = generate_payload_injections("field");
    let tc = injections
        .iter()
        .find(|i| i.technique == PayloadInjectionTechnique::TypeConfusion)
        .unwrap();
    assert!(tc.injected_value.contains("$gt"));
}

#[test]
fn payload_nested_bomb_has_depth() {
    let injections = generate_payload_injections("data");
    let nested = injections
        .iter()
        .find(|i| i.technique == PayloadInjectionTechnique::NestedObjectBomb)
        .unwrap();
    assert!(nested.injected_value.contains("deep"));
    assert!(nested.injected_value.matches('{').count() >= 50);
}

#[test]
fn payload_unicode_bypass_contains_zwsp() {
    let injections = generate_payload_injections("role");
    let unicode = injections
        .iter()
        .find(|i| i.technique == PayloadInjectionTechnique::UnicodeBypass)
        .unwrap();
    assert!(unicode.injected_value.contains('\u{200B}'));
}

#[test]
fn payload_header_injection_contains_crlf() {
    let injections = generate_payload_injections("comment");
    let header = injections
        .iter()
        .find(|i| i.technique == PayloadInjectionTechnique::HeaderInjectionViaPayload)
        .unwrap();
    assert!(header.injected_value.contains("\r\n"));
}

#[test]
fn full_analysis_all_categories() {
    let findings = run_webhook_security_analysis(
        "webhook_url",
        Some("https://myapp.com/hook"),
        Some("evt_123"),
        Some("{\"data\": \"test\"}"),
        Some("sha256=abc123"),
        Some("user_email"),
    );
    assert!(findings
        .iter()
        .any(|f| f.category == WebhookAttackCategory::SsrfViaWebhook));
    assert!(findings
        .iter()
        .any(|f| f.category == WebhookAttackCategory::EventReplay));
    assert!(findings
        .iter()
        .any(|f| f.category == WebhookAttackCategory::SignatureBypass));
    assert!(findings
        .iter()
        .any(|f| f.category == WebhookAttackCategory::CallbackManipulation));
    assert!(findings
        .iter()
        .any(|f| f.category == WebhookAttackCategory::PayloadInjection));
}

#[test]
fn full_analysis_minimal_input() {
    let findings = run_webhook_security_analysis("url", None, None, None, None, None);
    assert!(findings
        .iter()
        .any(|f| f.category == WebhookAttackCategory::SsrfViaWebhook));
    assert!(!findings
        .iter()
        .any(|f| f.category == WebhookAttackCategory::EventReplay));
    assert!(!findings
        .iter()
        .any(|f| f.category == WebhookAttackCategory::SignatureBypass));
}

#[test]
fn display_impls_produce_expected_strings() {
    assert_eq!(format!("{}", WebhookSeverity::Critical), "Critical");
    assert_eq!(
        format!("{}", SsrfTechnique::MetadataEndpoint),
        "Cloud Metadata Endpoint"
    );
    assert_eq!(
        format!("{}", SignatureBypassTechnique::EmptySignature),
        "Empty Signature"
    );
    assert_eq!(
        format!("{}", CallbackTechnique::UrlRedirect),
        "URL Redirect"
    );
    assert_eq!(
        format!("{}", PayloadInjectionTechnique::TypeConfusion),
        "Type Confusion"
    );
    assert_eq!(
        format!("{}", WebhookAttackCategory::SsrfViaWebhook),
        "SSRF via Webhook"
    );
    assert_eq!(
        format!("{}", SsrfTechnique::IpAddressObfuscation),
        "IP Address Obfuscation"
    );
}
