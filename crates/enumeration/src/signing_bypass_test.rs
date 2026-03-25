use crate::signing_bypass::*;

#[test]
fn parse_signing_metadata_from_auth_header() {
    let metadata = parse_signing_metadata(
        "HMAC-SHA256 algorithm=hmac-sha256, timestamp=1700000000, nonce=abc123, headers=host content-type, signature=deadbeef",
        None,
        None,
    );
    assert_eq!(metadata.algorithm, "hmac-sha256");
    assert_eq!(metadata.timestamp, "1700000000");
    assert_eq!(metadata.nonce, Some("abc123".to_string()));
    assert_eq!(metadata.signed_headers, vec!["host", "content-type"]);
    assert_eq!(metadata.signature, "deadbeef");
}

#[test]
fn parse_signing_metadata_from_separate_headers() {
    let metadata = parse_signing_metadata(
        "SHA256 signature=abcdef",
        Some("abcdef"),
        Some("1700000000"),
    );
    assert_eq!(metadata.algorithm, "hmac-sha256");
    assert_eq!(metadata.timestamp, "1700000000");
    assert_eq!(metadata.signature, "abcdef");
}

#[test]
fn parse_signing_metadata_minimal() {
    let metadata = parse_signing_metadata("Bearer token123", None, None);
    assert_eq!(metadata.algorithm, "unknown");
    assert_eq!(metadata.signature, "token123");
}

#[test]
fn replay_attacks_generated() {
    let metadata = SigningMetadata {
        algorithm: "hmac-sha256".to_string(),
        timestamp: "1700000000".to_string(),
        nonce: Some("nonce123".to_string()),
        signed_headers: vec!["host".to_string()],
        signature: "sig123".to_string(),
    };
    let attacks = generate_replay_attacks(&metadata, "/api/v1/data");
    assert!(attacks.len() >= 8);
    assert!(attacks
        .iter()
        .any(|a| a.technique == ReplayTechnique::ExactReplay));
    assert!(attacks
        .iter()
        .any(|a| a.technique == ReplayTechnique::TimestampShift));
    assert!(attacks
        .iter()
        .any(|a| a.technique == ReplayTechnique::NonceReuse));
    assert!(attacks
        .iter()
        .any(|a| a.technique == ReplayTechnique::CrossEndpointReplay));
    assert!(attacks
        .iter()
        .any(|a| a.technique == ReplayTechnique::MethodSwitchReplay));
}

#[test]
fn replay_timestamp_shifts_have_multiple_offsets() {
    let metadata = SigningMetadata {
        algorithm: "hmac-sha256".to_string(),
        timestamp: "1700000000".to_string(),
        nonce: None,
        signed_headers: vec![],
        signature: "sig".to_string(),
    };
    let attacks = generate_replay_attacks(&metadata, "/api");
    let ts_shifts: Vec<_> = attacks
        .iter()
        .filter(|a| a.technique == ReplayTechnique::TimestampShift)
        .collect();
    assert!(ts_shifts.len() >= 5);
}

#[test]
fn replay_nonce_reuse_only_when_nonce_present() {
    let no_nonce = SigningMetadata {
        algorithm: "hmac-sha256".to_string(),
        timestamp: "1700000000".to_string(),
        nonce: None,
        signed_headers: vec![],
        signature: "sig".to_string(),
    };
    let attacks = generate_replay_attacks(&no_nonce, "/api");
    assert!(!attacks
        .iter()
        .any(|a| a.technique == ReplayTechnique::NonceReuse));
}

#[test]
fn algorithm_confusion_tests_generated() {
    let metadata = SigningMetadata {
        algorithm: "hmac-sha256".to_string(),
        timestamp: "1700000000".to_string(),
        nonce: None,
        signed_headers: vec![],
        signature: "abcdef1234567890".to_string(),
    };
    let tests = generate_algorithm_confusion_tests(&metadata);
    assert!(tests.len() >= 6);
    assert!(tests
        .iter()
        .any(|t| t.technique == AlgoConfusionTechnique::HmacToNone));
    assert!(tests
        .iter()
        .any(|t| t.technique == AlgoConfusionTechnique::RsaToHmac));
    assert!(tests
        .iter()
        .any(|t| t.technique == AlgoConfusionTechnique::Sha256ToSha1));
    assert!(tests
        .iter()
        .any(|t| t.technique == AlgoConfusionTechnique::Sha256ToMd5));
    assert!(tests
        .iter()
        .any(|t| t.technique == AlgoConfusionTechnique::CustomAlgorithm));
    assert!(tests
        .iter()
        .any(|t| t.technique == AlgoConfusionTechnique::AlgorithmHeaderStrip));
}

#[test]
fn hmac_to_none_has_empty_signature() {
    let metadata = SigningMetadata {
        algorithm: "hmac-sha256".to_string(),
        timestamp: String::new(),
        nonce: None,
        signed_headers: vec![],
        signature: "sig".to_string(),
    };
    let tests = generate_algorithm_confusion_tests(&metadata);
    let none_test = tests
        .iter()
        .find(|t| t.technique == AlgoConfusionTechnique::HmacToNone)
        .unwrap();
    assert_eq!(none_test.manipulated_algorithm, "none");
    assert!(none_test.signature_header.is_empty());
    assert_eq!(none_test.severity, SigningBypassSeverity::Critical);
}

#[test]
fn empty_signature_tests_generated() {
    let tests = generate_empty_signature_tests();
    assert!(tests.len() >= 6);
    assert!(tests
        .iter()
        .any(|t| t.technique == EmptySignatureTechnique::EmptyString));
    assert!(tests
        .iter()
        .any(|t| t.technique == EmptySignatureTechnique::NullByte));
    assert!(tests
        .iter()
        .any(|t| t.technique == EmptySignatureTechnique::WhitespaceOnly));
    assert!(tests
        .iter()
        .any(|t| t.technique == EmptySignatureTechnique::MissingHeader));
    assert!(tests
        .iter()
        .any(|t| t.technique == EmptySignatureTechnique::ZeroLength));
    assert!(tests
        .iter()
        .any(|t| t.technique == EmptySignatureTechnique::InvalidBase64));
}

#[test]
fn empty_string_signature_is_actually_empty() {
    let tests = generate_empty_signature_tests();
    let empty = tests
        .iter()
        .find(|t| t.technique == EmptySignatureTechnique::EmptyString)
        .unwrap();
    assert!(empty.signature_value.is_empty());
    assert_eq!(empty.severity, SigningBypassSeverity::Critical);
}

#[test]
fn null_byte_signature_contains_null() {
    let tests = generate_empty_signature_tests();
    let null = tests
        .iter()
        .find(|t| t.technique == EmptySignatureTechnique::NullByte)
        .unwrap();
    assert!(null.signature_value.contains('\0'));
}

#[test]
fn clock_skew_tests_generated() {
    let tests = generate_clock_skew_tests("1700000000");
    assert!(tests.len() >= 9);
    assert!(tests
        .iter()
        .any(|t| t.direction == ClockSkewDirection::Future));
    assert!(tests
        .iter()
        .any(|t| t.direction == ClockSkewDirection::Past));
}

#[test]
fn clock_skew_severity_increases_with_offset() {
    let tests = generate_clock_skew_tests("1700000000");
    let short = tests.iter().find(|t| t.offset_seconds == 30).unwrap();
    let long = tests.iter().find(|t| t.offset_seconds == 86400).unwrap();
    assert!(long.severity > short.severity);
}

#[test]
fn clock_skew_past_week_is_critical() {
    let tests = generate_clock_skew_tests("1700000000");
    let week = tests.iter().find(|t| t.offset_seconds == 604800).unwrap();
    assert_eq!(week.severity, SigningBypassSeverity::Critical);
    assert_eq!(week.direction, ClockSkewDirection::Past);
}

#[test]
fn partial_coverage_tests_generated() {
    let tests = generate_partial_coverage_tests(&["host".to_string(), "content-type".to_string()]);
    assert!(tests.len() >= 8);
    assert!(tests
        .iter()
        .any(|t| t.technique == PartialCoverageTechnique::UnsignedQueryParams));
    assert!(tests
        .iter()
        .any(|t| t.technique == PartialCoverageTechnique::UnsignedBody));
    assert!(tests
        .iter()
        .any(|t| t.technique == PartialCoverageTechnique::UnsignedMethod));
    assert!(tests
        .iter()
        .any(|t| t.technique == PartialCoverageTechnique::UnsignedPath));
    assert!(tests
        .iter()
        .any(|t| t.technique == PartialCoverageTechnique::HeaderOrderManipulation));
    assert!(tests
        .iter()
        .any(|t| t.technique == PartialCoverageTechnique::CasingManipulation));
}

#[test]
fn partial_coverage_detects_unsigned_headers() {
    let tests = generate_partial_coverage_tests(&["host".to_string()]);
    let unsigned: Vec<_> = tests
        .iter()
        .filter(|t| t.technique == PartialCoverageTechnique::UnsignedHeaders)
        .collect();
    assert!(unsigned.len() >= 3);
    assert!(unsigned
        .iter()
        .any(|t| t.unsigned_component == "content-type"));
    assert!(unsigned
        .iter()
        .any(|t| t.unsigned_component == "authorization"));
}

#[test]
fn partial_coverage_host_unsigned_is_critical() {
    let tests = generate_partial_coverage_tests(&[]);
    let host = tests
        .iter()
        .find(|t| {
            t.technique == PartialCoverageTechnique::UnsignedHeaders
                && t.unsigned_component == "host"
        })
        .unwrap();
    assert_eq!(host.severity, SigningBypassSeverity::Critical);
}

#[test]
fn partial_coverage_all_signed_has_fewer_unsigned_header_findings() {
    let all_headers: Vec<String> = vec![
        "host",
        "content-type",
        "content-length",
        "x-forwarded-for",
        "x-api-key",
        "authorization",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect();
    let tests = generate_partial_coverage_tests(&all_headers);
    let unsigned: Vec<_> = tests
        .iter()
        .filter(|t| t.technique == PartialCoverageTechnique::UnsignedHeaders)
        .collect();
    assert!(unsigned.is_empty());
}

#[test]
fn full_analysis_generates_all_categories() {
    let findings = run_signing_bypass_analysis(
        "HMAC-SHA256 algorithm=hmac-sha256, timestamp=1700000000, nonce=abc, headers=host, signature=deadbeef",
        None,
        None,
        "/api/v1/data",
    );
    assert!(findings
        .iter()
        .any(|f| f.category == SigningBypassCategory::ReplayAttack));
    assert!(findings
        .iter()
        .any(|f| f.category == SigningBypassCategory::AlgorithmConfusion));
    assert!(findings
        .iter()
        .any(|f| f.category == SigningBypassCategory::EmptySignature));
    assert!(findings
        .iter()
        .any(|f| f.category == SigningBypassCategory::ClockSkewExploitation));
    assert!(findings
        .iter()
        .any(|f| f.category == SigningBypassCategory::PartialCoverage));
}

#[test]
fn full_analysis_without_timestamp_skips_clock_skew() {
    let findings = run_signing_bypass_analysis("Bearer token123", None, None, "/api");
    assert!(!findings
        .iter()
        .any(|f| f.category == SigningBypassCategory::ClockSkewExploitation));
}

#[test]
fn full_analysis_has_substantial_finding_count() {
    let findings = run_signing_bypass_analysis(
        "HMAC-SHA256 algorithm=hmac-sha256, timestamp=1700000000, headers=host content-type, signature=abcdef",
        None,
        None,
        "/api/users",
    );
    assert!(findings.len() >= 25);
}

#[test]
fn display_impls_produce_expected_strings() {
    assert_eq!(format!("{}", SigningBypassSeverity::Critical), "Critical");
    assert_eq!(format!("{}", ReplayTechnique::ExactReplay), "Exact Replay");
    assert_eq!(
        format!("{}", AlgoConfusionTechnique::HmacToNone),
        "HMAC to None"
    );
    assert_eq!(
        format!("{}", EmptySignatureTechnique::NullByte),
        "Null Byte"
    );
    assert_eq!(format!("{}", ClockSkewDirection::Future), "Future");
    assert_eq!(
        format!("{}", PartialCoverageTechnique::UnsignedBody),
        "Unsigned Body"
    );
    assert_eq!(
        format!("{}", SigningBypassCategory::ReplayAttack),
        "Replay Attack"
    );
    assert_eq!(
        format!("{}", PartialCoverageTechnique::CasingManipulation),
        "Casing Manipulation"
    );
}
