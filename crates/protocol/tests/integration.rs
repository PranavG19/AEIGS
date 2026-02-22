use aegis_protocol::edge::{EDGE_WHITELIST, EdgeLabel, is_valid_edge};
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::ModuleIdentifier;
use aegis_protocol::scan_event::ScanEvent;
use aegis_protocol::scope_attestation::{
    AttestationError, ScopeDocument, load_attestation, sign_scope_document, verify_attestation,
};
use aegis_protocol::signed_config::{
    SignableConfig, SignedConfigError, load_signed_config, sign_config, verify_signed_config,
};
use aegis_protocol::target_validation::validate_target_is_localhost;

fn test_signing_key() -> ed25519_dalek::SigningKey {
    let secret: [u8; 32] = rand::random();
    ed25519_dalek::SigningKey::from_bytes(&secret)
}

fn future_scope_document(target: &str) -> ScopeDocument {
    ScopeDocument {
        target: target.to_string(),
        authorized_by: "security-team@example.com".to_string(),
        valid_until: "2099-12-31".to_string(),
        scope_id: "integration-test-scope-001".to_string(),
    }
}

fn sample_config() -> SignableConfig {
    SignableConfig {
        target: "http://localhost:8080".to_string(),
        stealth_level: "default".to_string(),
        max_iterations: 1,
        convergence_threshold: 2,
        no_llm: false,
        include_endpoints: None,
        exclude_endpoints: None,
    }
}

// ---------------------------------------------------------------------------
// 1. target_validation_accepts_localhost_variants
// ---------------------------------------------------------------------------
#[test]
fn target_validation_accepts_localhost_variants() {
    let accepted = [
        "127.0.0.1",
        "localhost",
        "http://127.0.0.1:3000/path",
        "http://localhost:8080/api",
        "http://[::1]:8080",
        "localhost:9090",
    ];
    for url in accepted {
        assert!(
            validate_target_is_localhost(url).is_ok(),
            "expected {url} to be accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. target_validation_rejects_non_localhost
// ---------------------------------------------------------------------------
#[test]
fn target_validation_rejects_non_localhost() {
    let rejected = [
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://example.com",
    ];
    for url in rejected {
        assert!(
            validate_target_is_localhost(url).is_err(),
            "expected {url} to be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. target_validation_rejects_ssrf_obfuscation
// ---------------------------------------------------------------------------
#[test]
fn target_validation_rejects_ssrf_obfuscation() {
    let obfuscated = [
        "http://2130706433:8080",
        "http://0x7f000001:8080",
        "http://0177.0.0.1:8080",
        "http://127.1:8080",
        "http://127.0.1:8080",
        "http://[::ffff:127.0.0.1]:8080",
        "http://[0:0:0:0:0:0:0:1]:8080",
    ];
    for url in obfuscated {
        assert!(
            validate_target_is_localhost(url).is_err(),
            "expected obfuscated form {url} to be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. scope_attestation_sign_verify_roundtrip
// ---------------------------------------------------------------------------
#[test]
fn scope_attestation_sign_verify_roundtrip() {
    let key = test_signing_key();
    let doc = future_scope_document("http://localhost:8080");
    let attestation = sign_scope_document(&doc, &key);

    let result = verify_attestation(&attestation, "http://localhost:8080");
    assert!(result.is_ok(), "roundtrip verification failed: {result:?}");
}

// ---------------------------------------------------------------------------
// 5. scope_attestation_reject_tampered_document
// ---------------------------------------------------------------------------
#[test]
fn scope_attestation_reject_tampered_document() {
    let key = test_signing_key();
    let doc = future_scope_document("http://localhost:8080");
    let mut attestation = sign_scope_document(&doc, &key);

    attestation.document.authorized_by = "attacker@evil.com".to_string();

    let result = verify_attestation(&attestation, "http://localhost:8080");
    assert!(matches!(result, Err(AttestationError::InvalidSignature)));
}

// ---------------------------------------------------------------------------
// 6. scope_attestation_reject_expired
// ---------------------------------------------------------------------------
#[test]
fn scope_attestation_reject_expired() {
    let key = test_signing_key();
    let mut doc = future_scope_document("http://localhost:8080");
    doc.valid_until = "2020-01-01".to_string();
    let attestation = sign_scope_document(&doc, &key);

    let result = verify_attestation(&attestation, "http://localhost:8080");
    assert!(matches!(result, Err(AttestationError::Expired(_))));
}

// ---------------------------------------------------------------------------
// 7. scope_attestation_reject_target_mismatch
// ---------------------------------------------------------------------------
#[test]
fn scope_attestation_reject_target_mismatch() {
    let key = test_signing_key();
    let doc = future_scope_document("http://localhost:8080");
    let attestation = sign_scope_document(&doc, &key);

    let result = verify_attestation(&attestation, "http://localhost:9999");
    assert!(matches!(
        result,
        Err(AttestationError::TargetMismatch { .. })
    ));
}

// ---------------------------------------------------------------------------
// 8. scope_attestation_file_roundtrip
// ---------------------------------------------------------------------------
#[test]
fn scope_attestation_file_roundtrip() {
    let key = test_signing_key();
    let doc = future_scope_document("http://localhost:8080");
    let attestation = sign_scope_document(&doc, &key);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attestation.json");
    let json = serde_json::to_string_pretty(&attestation).unwrap();
    std::fs::write(&path, json).unwrap();

    let loaded = load_attestation(&path).expect("should load attestation from file");
    assert_eq!(loaded.document.scope_id, doc.scope_id);
    assert_eq!(loaded.document.target, doc.target);
    assert_eq!(loaded.public_key_hex, attestation.public_key_hex);
    assert_eq!(loaded.signature_hex, attestation.signature_hex);

    let verify = verify_attestation(&loaded, "http://localhost:8080");
    assert!(
        verify.is_ok(),
        "loaded attestation should still verify: {verify:?}"
    );
}

// ---------------------------------------------------------------------------
// 9. signed_config_sign_verify_roundtrip
// ---------------------------------------------------------------------------
#[test]
fn signed_config_sign_verify_roundtrip() {
    let key = test_signing_key();
    let config = sample_config();
    let signed = sign_config(&config, &key);

    let result = verify_signed_config(&signed);
    assert!(result.is_ok(), "roundtrip verification failed: {result:?}");
}

// ---------------------------------------------------------------------------
// 10. signed_config_reject_tampered_config
// ---------------------------------------------------------------------------
#[test]
fn signed_config_reject_tampered_config() {
    let key = test_signing_key();
    let config = sample_config();
    let mut signed = sign_config(&config, &key);

    signed.config.target = "http://localhost:9999".to_string();

    let result = verify_signed_config(&signed);
    assert!(
        matches!(result, Err(SignedConfigError::HashMismatch { .. })),
        "expected HashMismatch, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// 11. signed_config_reject_invalid_signature
// ---------------------------------------------------------------------------
#[test]
fn signed_config_reject_invalid_signature() {
    let key = test_signing_key();
    let wrong_key = test_signing_key();
    let config = sample_config();
    let mut signed = sign_config(&config, &key);

    let wrong_pub_hex: String = wrong_key
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    signed.public_key_hex = wrong_pub_hex;

    let result = verify_signed_config(&signed);
    assert!(
        matches!(result, Err(SignedConfigError::InvalidSignature)),
        "expected InvalidSignature, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// 12. signed_config_file_roundtrip
// ---------------------------------------------------------------------------
#[test]
fn signed_config_file_roundtrip() {
    let key = test_signing_key();
    let config = sample_config();
    let signed = sign_config(&config, &key);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("signed_config.json");
    let json = serde_json::to_string_pretty(&signed).unwrap();
    std::fs::write(&path, json).unwrap();

    let loaded = load_signed_config(&path).expect("should load signed config from file");
    assert_eq!(loaded.config, config);
    assert_eq!(loaded.config_hash, signed.config_hash);
    assert_eq!(loaded.public_key_hex, signed.public_key_hex);
    assert_eq!(loaded.signature_hex, signed.signature_hex);

    let verify = verify_signed_config(&loaded);
    assert!(
        verify.is_ok(),
        "loaded signed config should still verify: {verify:?}"
    );
}

// ---------------------------------------------------------------------------
// 13. scan_event_serialization_all_variants
// ---------------------------------------------------------------------------
#[test]
fn scan_event_serialization_all_variants() {
    let variants: Vec<ScanEvent> = vec![
        ScanEvent::EndpointDiscovered {
            endpoint: "/api/users".to_string(),
            method: "GET".to_string(),
            source_module: ModuleIdentifier::Enumeration,
        },
        ScanEvent::HypothesisGenerated {
            vulnerability_class: VulnerabilityClass::SqlInjection,
            condition: "user input in query".to_string(),
            confidence: 0.85,
        },
        ScanEvent::PayloadTested {
            endpoint: "/api/login".to_string(),
            payload_hash: "abc123".to_string(),
            vulnerability_class: VulnerabilityClass::CrossSiteScripting,
            anomaly_score: 0.72,
        },
        ScanEvent::AnomalyDetected {
            endpoint: "/api/admin".to_string(),
            vulnerability_class: VulnerabilityClass::BrokenAuthorization,
            anomaly_type: "status_code_divergence".to_string(),
            score: 0.95,
        },
        ScanEvent::FindingConfirmed {
            finding_id: 42,
            vulnerability_class: VulnerabilityClass::CommandInjection,
            severity: 9.5,
            confidence: 0.92,
        },
        ScanEvent::PhaseCompleted {
            phase_name: "fuzzing".to_string(),
            operations_applied: 150,
            findings_count: 3,
            duration_ms: 12500,
        },
    ];

    for event in &variants {
        let json = serde_json::to_string(event).expect("ScanEvent must serialize");
        let roundtripped: ScanEvent =
            serde_json::from_str(&json).expect("ScanEvent must deserialize");
        let json2 = serde_json::to_string(&roundtripped).unwrap();
        assert_eq!(json, json2, "roundtrip JSON must be identical");
    }

    assert_eq!(variants.len(), 6, "all 6 ScanEvent variants must be tested");
}

// ---------------------------------------------------------------------------
// 14. edge_validation_all_28_valid_triples
// ---------------------------------------------------------------------------
#[test]
fn edge_validation_all_28_valid_triples() {
    assert_eq!(
        EDGE_WHITELIST.len(),
        28,
        "EDGE_WHITELIST should contain exactly 28 entries"
    );

    for &(source, label, target) in EDGE_WHITELIST {
        assert!(
            is_valid_edge(source, label, target),
            "expected ({source:?}, {label:?}, {target:?}) to be valid"
        );
    }
}

// ---------------------------------------------------------------------------
// 15. edge_validation_reject_invalid_triples
// ---------------------------------------------------------------------------
#[test]
fn edge_validation_reject_invalid_triples() {
    let invalid: [(NodeType, EdgeLabel, NodeType); 20] = [
        (NodeType::DataStore, EdgeLabel::Calls, NodeType::Function),
        (NodeType::Defense, EdgeLabel::Exposes, NodeType::DataStore),
        (NodeType::Defense, EdgeLabel::ProtectedBy, NodeType::Defense),
        (NodeType::Dependency, EdgeLabel::Writes, NodeType::DataStore),
        (NodeType::Config, EdgeLabel::Calls, NodeType::Function),
        (NodeType::Role, EdgeLabel::Reads, NodeType::DataStore),
        (NodeType::User, EdgeLabel::Writes, NodeType::DataStore),
        (NodeType::DataStore, EdgeLabel::Trusts, NodeType::Service),
        (NodeType::Defense, EdgeLabel::Calls, NodeType::Service),
        (
            NodeType::Dependency,
            EdgeLabel::DependsOn,
            NodeType::Dependency,
        ),
        (NodeType::Endpoint, EdgeLabel::Trusts, NodeType::Role),
        (
            NodeType::Function,
            EdgeLabel::Authenticates,
            NodeType::Endpoint,
        ),
        (
            NodeType::DataStore,
            EdgeLabel::DependsOn,
            NodeType::Dependency,
        ),
        (NodeType::Defense, EdgeLabel::Reads, NodeType::DataStore),
        (NodeType::Config, EdgeLabel::Writes, NodeType::DataStore),
        (NodeType::Role, EdgeLabel::Calls, NodeType::Function),
        (NodeType::User, EdgeLabel::Calls, NodeType::Function),
        (
            NodeType::Dependency,
            EdgeLabel::Exposes,
            NodeType::DataStore,
        ),
        (
            NodeType::Defense,
            EdgeLabel::Authenticates,
            NodeType::Endpoint,
        ),
        (NodeType::Config, EdgeLabel::Trusts, NodeType::Service),
    ];

    for (source, label, target) in invalid {
        assert!(
            !is_valid_edge(source, label, target),
            "expected ({source:?}, {label:?}, {target:?}) to be invalid"
        );
    }
}

// ---------------------------------------------------------------------------
// 16. vulnerability_class_display_all_16
// ---------------------------------------------------------------------------
#[test]
fn vulnerability_class_display_all_16() {
    let expected: [(VulnerabilityClass, &str); 16] = [
        (VulnerabilityClass::SqlInjection, "SQL Injection"),
        (
            VulnerabilityClass::CrossSiteScripting,
            "Cross-Site Scripting",
        ),
        (VulnerabilityClass::CommandInjection, "Command Injection"),
        (VulnerabilityClass::PathTraversal, "Path Traversal"),
        (
            VulnerabilityClass::ServerSideRequestForgery,
            "Server-Side Request Forgery",
        ),
        (
            VulnerabilityClass::InsecureDeserialization,
            "Insecure Deserialization",
        ),
        (
            VulnerabilityClass::BrokenAuthentication,
            "Broken Authentication",
        ),
        (
            VulnerabilityClass::BrokenAuthorization,
            "Broken Authorization",
        ),
        (
            VulnerabilityClass::SecurityMisconfiguration,
            "Security Misconfiguration",
        ),
        (
            VulnerabilityClass::SensitiveDataExposure,
            "Sensitive Data Exposure",
        ),
        (
            VulnerabilityClass::ServerSideTemplateInjection,
            "Server-Side Template Injection",
        ),
        (VulnerabilityClass::HeaderInjection, "Header Injection"),
        (VulnerabilityClass::OpenRedirect, "Open Redirect"),
        (VulnerabilityClass::CrlfInjection, "CRLF Injection"),
        (
            VulnerabilityClass::KnownVulnerableDependency,
            "Known Vulnerable Dependency",
        ),
        (
            VulnerabilityClass::InsufficientInputValidation,
            "Insufficient Input Validation",
        ),
    ];

    for (variant, display_str) in expected {
        assert_eq!(
            format!("{variant}"),
            display_str,
            "Display for {variant:?} should be \"{display_str}\""
        );
    }
}

// ---------------------------------------------------------------------------
// 17. finding_data_confidence_roundtrip
// ---------------------------------------------------------------------------
#[test]
fn finding_data_confidence_roundtrip() {
    let finding = FindingData::new(
        1,
        VulnerabilityClass::SqlInjection,
        9.0,
        0.9,
        ModuleIdentifier::Fuzzing,
        1700000000000,
    )
    .with_confidence(aegis_protocol::finding::Confidence::new(0.85).unwrap());

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: FindingData = serde_json::from_str(&json).unwrap();
    assert!(
        (deserialized.confidence.composite.value() - 0.85).abs() < f64::EPSILON,
        "confidence should survive serialization roundtrip"
    );
}

// ---------------------------------------------------------------------------
// 18. finding_data_missing_confidence_score_uses_confidence
// ---------------------------------------------------------------------------
#[test]
fn finding_data_missing_confidence_score_uses_confidence() {
    let json = r#"{
        "id": 1,
        "linked_node_ids": [],
        "vulnerability_class": "SqlInjection",
        "severity": 9.0,
        "confidence": 0.9,
        "certificate": [],
        "provenance_module": "Fuzzing",
        "timestamp_unix_ms": 1700000000000,
        "evidence_level": "Statistical"
    }"#;

    let deserialized: FindingData = serde_json::from_str(json).unwrap();
    assert!(
        (deserialized.confidence.composite.value() - 0.9).abs() < f64::EPSILON,
        "confidence should be read from the confidence field"
    );
    assert!(
        deserialized.stable_id.is_none(),
        "stable_id should default to None when absent from JSON"
    );
}
