use crate::mobile_api_tester::*;
use std::collections::HashMap;

#[test]
fn cert_pinning_detected_with_hpkp_header() {
    let mut headers = HashMap::new();
    headers.insert(
        "public-key-pins".to_string(),
        "pin-sha256=\"base64==\"; max-age=5184000".to_string(),
    );
    let result = detect_cert_pinning("https://api.example.com/v1", &headers, false);
    assert!(result.pinning_detected);
    assert!(result.bypass_possible);
    assert!(!result.bypass_methods.is_empty());
    assert_eq!(result.severity, MobileApiSeverity::Low);
}

#[test]
fn cert_pinning_detected_with_proxy_failure() {
    let headers = HashMap::new();
    let result = detect_cert_pinning("https://api.example.com/v1", &headers, true);
    assert!(result.pinning_detected);
    assert_eq!(result.severity, MobileApiSeverity::Medium);
}

#[test]
fn no_cert_pinning_high_severity() {
    let headers = HashMap::new();
    let result = detect_cert_pinning("https://api.example.com/v1", &headers, false);
    assert!(!result.pinning_detected);
    assert!(result.bypass_methods.is_empty());
    assert_eq!(result.severity, MobileApiSeverity::High);
}

#[test]
fn cert_pinning_with_expect_ct_enforce() {
    let mut headers = HashMap::new();
    headers.insert(
        "expect-ct".to_string(),
        "max-age=86400, enforce".to_string(),
    );
    let result = detect_cert_pinning("https://api.example.com", &headers, true);
    assert!(result.pinning_detected);
    assert_eq!(result.severity, MobileApiSeverity::Medium);
}

#[test]
fn extract_api_key_from_authorization_header() {
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        "Bearer sk_live_abc123def456ghi789jkl012mno".to_string(),
    );
    let results = extract_api_keys_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].key_type, ApiKeyType::StripeKey);
    assert_eq!(results[0].source, ApiKeySource::HttpHeader);
    assert_eq!(results[0].severity, MobileApiSeverity::Critical);
}

#[test]
fn extract_api_key_from_custom_header() {
    let mut headers = HashMap::new();
    headers.insert(
        "X-Api-Key".to_string(),
        "AKIAIOSFODNN7EXAMPLE01".to_string(),
    );
    let results = extract_api_keys_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].key_type, ApiKeyType::AwsAccessKey);
    assert_eq!(results[0].severity, MobileApiSeverity::Critical);
}

#[test]
fn no_api_key_in_unrelated_header() {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    let results = extract_api_keys_from_headers(&headers);
    assert!(results.is_empty());
}

#[test]
fn extract_api_key_from_query_parameter() {
    let results =
        extract_api_keys_from_params("key=AIzaSyAbcDefGhiJklMnoPqrStUvWxYz12345678&format=json");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].source, ApiKeySource::QueryParameter);
    assert_eq!(results[0].key_type, ApiKeyType::GoogleMaps);
    assert_eq!(results[0].severity, MobileApiSeverity::High);
}

#[test]
fn no_api_key_in_unrelated_param() {
    let results = extract_api_keys_from_params("page=1&limit=10");
    assert!(results.is_empty());
}

#[test]
fn extract_hardcoded_aws_key_from_content() {
    let content = "some config = AKIAIOSFODNN7EXAMPLE01 and more stuff";
    let results = extract_api_keys_from_content(content);
    assert!(results
        .iter()
        .any(|r| r.key_type == ApiKeyType::AwsAccessKey));
}

#[test]
fn extract_hardcoded_stripe_key_from_content() {
    let content = r#"const key = "sk_live_abcdefghijklmnopqrstuvwx";"#;
    let results = extract_api_keys_from_content(content);
    assert!(results.iter().any(|r| r.key_type == ApiKeyType::StripeKey));
    assert!(results
        .iter()
        .all(|r| r.severity == MobileApiSeverity::Critical));
}

#[test]
fn extract_google_maps_key_from_content() {
    let content = "var mapsKey = 'AIzaSyBcDeFgHiJkLmNoPqRsTuVwXyZ_0123456789';";
    let results = extract_api_keys_from_content(content);
    assert!(results.iter().any(|r| r.key_type == ApiKeyType::GoogleMaps));
}

#[test]
fn no_api_key_in_clean_content() {
    let content = "Hello world, this is just a normal response body without secrets.";
    let results = extract_api_keys_from_content(content);
    assert!(results.is_empty());
}

#[test]
fn detect_protobuf_from_content_type() {
    let result = detect_binary_protocol(
        "https://api.example.com/rpc",
        "application/x-protobuf",
        &[0x08, 0x96, 0x01],
    );
    assert_eq!(result.protocol, DetectedBinaryProtocol::Protobuf);
    assert!(result.confidence >= 0.9);
    assert_eq!(result.severity, MobileApiSeverity::Medium);
}

#[test]
fn detect_msgpack_from_content_type() {
    let result = detect_binary_protocol(
        "https://api.example.com/data",
        "application/x-msgpack",
        &[0x82],
    );
    assert_eq!(result.protocol, DetectedBinaryProtocol::MessagePack);
    assert!(result.confidence >= 0.9);
}

#[test]
fn detect_cbor_from_content_type() {
    let result =
        detect_binary_protocol("https://api.example.com/data", "application/cbor", &[0xa2]);
    assert_eq!(result.protocol, DetectedBinaryProtocol::Cbor);
}

#[test]
fn no_binary_protocol_for_json() {
    let result = detect_binary_protocol(
        "https://api.example.com/data",
        "application/json",
        b"{\"hello\": \"world\"}",
    );
    assert_eq!(result.protocol, DetectedBinaryProtocol::None);
    assert_eq!(result.severity, MobileApiSeverity::Info);
}

#[test]
fn heuristic_protobuf_detection_from_bytes() {
    let result = detect_binary_protocol(
        "https://api.example.com/rpc",
        "application/octet-stream",
        &[0x0a, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f],
    );
    assert_eq!(result.protocol, DetectedBinaryProtocol::Protobuf);
    assert!(result.confidence > 0.0);
}

#[test]
fn heuristic_msgpack_detection_from_bytes() {
    let result = detect_binary_protocol(
        "https://api.example.com/data",
        "application/octet-stream",
        &[0x82, 0xa3, 0x66, 0x6f, 0x6f],
    );
    assert_eq!(result.protocol, DetectedBinaryProtocol::MessagePack);
}

#[test]
fn heuristic_custom_binary_detection() {
    let body: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
    let result = detect_binary_protocol(
        "https://api.example.com/stream",
        "application/octet-stream",
        &body,
    );
    assert!(result.protocol != DetectedBinaryProtocol::None);
}

#[test]
fn push_abuse_payloads_generated() {
    let payloads = generate_push_abuse_payloads("https://api.example.com/push", "abc123token");
    assert_eq!(payloads.len(), 5);
    assert!(payloads
        .iter()
        .any(|p| p.abuse_type == PushAbuseType::TokenLeakage));
    assert!(payloads
        .iter()
        .any(|p| p.abuse_type == PushAbuseType::UnauthorizedPush));
    assert!(payloads
        .iter()
        .any(|p| p.abuse_type == PushAbuseType::TopicEnumeration));
    assert!(payloads
        .iter()
        .any(|p| p.abuse_type == PushAbuseType::PayloadInjection));
    assert!(payloads
        .iter()
        .any(|p| p.abuse_type == PushAbuseType::RegistrationSpoof));
}

#[test]
fn push_abuse_payloads_contain_token() {
    let payloads = generate_push_abuse_payloads("https://api.example.com/push", "device_token_xyz");
    let token_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.proof_payload.contains("device_token_xyz"))
        .collect();
    assert!(token_payloads.len() >= 2);
}

#[test]
fn device_token_manipulations_generated() {
    let manips = generate_device_token_manipulations("abcdef0123456789abcdef");
    assert!(manips.len() >= 5);
    assert!(manips
        .iter()
        .any(|m| m.manipulation_type == DeviceTokenAttack::TokenReplay));
    assert!(manips
        .iter()
        .any(|m| m.manipulation_type == DeviceTokenAttack::TokenForge));
    assert!(manips
        .iter()
        .any(|m| m.manipulation_type == DeviceTokenAttack::TokenEnumeration));
    assert!(manips
        .iter()
        .any(|m| m.manipulation_type == DeviceTokenAttack::CrossUserTokenSwap));
    assert!(manips
        .iter()
        .any(|m| m.manipulation_type == DeviceTokenAttack::ExpiredTokenReuse));
}

#[test]
fn device_token_enumeration_increments_suffix() {
    let manips = generate_device_token_manipulations("abcdef0123456789");
    let enum_manip = manips
        .iter()
        .find(|m| m.manipulation_type == DeviceTokenAttack::TokenEnumeration)
        .unwrap();
    assert!(enum_manip.manipulated_token.contains(','));
    assert_eq!(enum_manip.severity, MobileApiSeverity::High);
}

#[test]
fn device_token_cross_user_swap_critical() {
    let manips = generate_device_token_manipulations("token123");
    let swap = manips
        .iter()
        .find(|m| m.manipulation_type == DeviceTokenAttack::CrossUserTokenSwap)
        .unwrap();
    assert_eq!(swap.severity, MobileApiSeverity::Critical);
    assert!(swap.manipulated_token.starts_with("victim_"));
}

#[test]
fn mask_key_hides_middle() {
    let mut headers = HashMap::new();
    headers.insert(
        "x-api-key".to_string(),
        "AKIAIOSFODNN7EXAMPLE01".to_string(),
    );
    let results = extract_api_keys_from_headers(&headers);
    assert_eq!(results.len(), 1);
    let masked = &results[0].matched_value;
    assert!(masked.contains("..."));
    assert!(!masked.contains("AKIAIOSFODNN7EXAMPLE01"));
}

#[test]
fn full_analysis_finds_multiple_categories() {
    let mut headers = HashMap::new();
    headers.insert(
        "x-api-key".to_string(),
        "AKIAIOSFODNN7EXAMPLE01".to_string(),
    );
    let findings = run_mobile_api_analysis(
        "https://api.example.com/v1",
        &headers,
        false,
        Some("key=AIzaSyBcDeFgHiJkLmNoPqRsTuVwXyZ_0123456789"),
        None,
        Some("application/x-protobuf"),
        Some(&[0x08, 0x96, 0x01]),
        Some("device_token_abc123"),
    );
    assert!(findings
        .iter()
        .any(|f| f.category == MobileApiAttackCategory::CertificatePinningBypass));
    assert!(findings
        .iter()
        .any(|f| f.category == MobileApiAttackCategory::ApiKeyExposure));
    assert!(findings
        .iter()
        .any(|f| f.category == MobileApiAttackCategory::BinaryProtocolAbuse));
    assert!(findings
        .iter()
        .any(|f| f.category == MobileApiAttackCategory::PushNotificationAbuse));
    assert!(findings
        .iter()
        .any(|f| f.category == MobileApiAttackCategory::DeviceTokenManipulation));
}

#[test]
fn full_analysis_minimal_input() {
    let headers = HashMap::new();
    let findings = run_mobile_api_analysis(
        "https://api.example.com/v1",
        &headers,
        false,
        None,
        None,
        None,
        None,
        None,
    );
    assert!(findings
        .iter()
        .any(|f| f.category == MobileApiAttackCategory::CertificatePinningBypass));
}

#[test]
fn display_impls_produce_expected_strings() {
    assert_eq!(format!("{}", MobileApiSeverity::Critical), "Critical");
    assert_eq!(
        format!("{}", CertPinningBypassMethod::FridaHook),
        "Frida Hook"
    );
    assert_eq!(format!("{}", ApiKeySource::HttpHeader), "HTTP Header");
    assert_eq!(format!("{}", ApiKeyType::AwsAccessKey), "AWS Access Key");
    assert_eq!(
        format!("{}", DetectedBinaryProtocol::Protobuf),
        "Protocol Buffers"
    );
    assert_eq!(format!("{}", PushAbuseType::TokenLeakage), "Token Leakage");
    assert_eq!(
        format!("{}", DeviceTokenAttack::TokenReplay),
        "Token Replay"
    );
    assert_eq!(
        format!("{}", MobileApiAttackCategory::ApiKeyExposure),
        "API Key Exposure"
    );
}

#[test]
fn extract_sendgrid_key_from_content() {
    let content = "api_key = SG.abcdefghijklmnopqrstuvwxyz1234567890";
    let results = extract_api_keys_from_content(content);
    assert!(results
        .iter()
        .any(|r| r.key_type == ApiKeyType::SendGridKey));
}

#[test]
fn detect_thrift_from_content_type() {
    let result = detect_binary_protocol(
        "https://api.example.com/thrift",
        "application/x-thrift",
        &[0x0c, 0x00, 0x01],
    );
    assert_eq!(result.protocol, DetectedBinaryProtocol::Thrift);
    assert!(result.confidence >= 0.9);
}

#[test]
fn detect_flatbuffers_from_content_type() {
    let result = detect_binary_protocol(
        "https://api.example.com/fb",
        "application/x-flatbuffers",
        &[0x04, 0x00, 0x00, 0x00],
    );
    assert_eq!(result.protocol, DetectedBinaryProtocol::Flatbuffers);
}

#[test]
fn empty_body_no_heuristic_detection() {
    let result = detect_binary_protocol(
        "https://api.example.com/empty",
        "application/octet-stream",
        &[],
    );
    assert_eq!(result.protocol, DetectedBinaryProtocol::None);
}

#[test]
fn short_device_token_skips_enumeration() {
    let manips = generate_device_token_manipulations("abc");
    assert!(!manips
        .iter()
        .any(|m| m.manipulation_type == DeviceTokenAttack::TokenEnumeration));
}
