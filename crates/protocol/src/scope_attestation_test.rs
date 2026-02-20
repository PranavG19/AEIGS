use crate::scope_attestation::*;

fn test_signing_key() -> ed25519_dalek::SigningKey {
    let secret: [u8; 32] = rand::random();
    ed25519_dalek::SigningKey::from_bytes(&secret)
}

fn valid_document() -> ScopeDocument {
    ScopeDocument {
        target: "http://localhost:8080".to_string(),
        authorized_by: "security-team@example.com".to_string(),
        valid_until: "2099-12-31".to_string(),
        scope_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
    }
}

#[test]
fn sign_and_verify_roundtrip() {
    let key = test_signing_key();
    let doc = valid_document();
    let attestation = sign_scope_document(&doc, &key);

    let result = verify_attestation(&attestation, "http://localhost:8080");
    assert!(result.is_ok(), "expected Ok, got: {result:?}");
}

#[test]
fn verify_fails_with_wrong_key() {
    let key = test_signing_key();
    let wrong_key = test_signing_key();
    let doc = valid_document();

    let mut attestation = sign_scope_document(&doc, &key);
    let wrong_pub_hex: String = wrong_key
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    attestation.public_key_hex = wrong_pub_hex;

    let result = verify_attestation(&attestation, "http://localhost:8080");
    assert!(matches!(result, Err(AttestationError::InvalidSignature)));
}

#[test]
fn verify_fails_with_tampered_document() {
    let key = test_signing_key();
    let doc = valid_document();
    let mut attestation = sign_scope_document(&doc, &key);

    attestation.document.target = "http://localhost:9999".to_string();

    let result = verify_attestation(&attestation, "http://localhost:9999");
    assert!(matches!(result, Err(AttestationError::InvalidSignature)));
}

#[test]
fn verify_fails_with_mismatched_target() {
    let key = test_signing_key();
    let doc = valid_document();
    let attestation = sign_scope_document(&doc, &key);

    let result = verify_attestation(&attestation, "http://localhost:9999");
    assert!(matches!(
        result,
        Err(AttestationError::TargetMismatch { .. })
    ));
}

#[test]
fn verify_fails_with_expired_date() {
    let key = test_signing_key();
    let mut doc = valid_document();
    doc.valid_until = "2020-01-01".to_string();
    let attestation = sign_scope_document(&doc, &key);

    let result = verify_attestation(&attestation, "http://localhost:8080");
    assert!(matches!(result, Err(AttestationError::Expired(_))));
}

#[test]
fn load_from_file_happy_path() {
    let key = test_signing_key();
    let doc = valid_document();
    let attestation = sign_scope_document(&doc, &key);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attestation.json");
    let json = serde_json::to_string_pretty(&attestation).unwrap();
    std::fs::write(&path, json).unwrap();

    let loaded = load_attestation(&path);
    assert!(loaded.is_ok(), "expected Ok, got: {loaded:?}");

    let loaded = loaded.unwrap();
    assert_eq!(loaded.document.scope_id, doc.scope_id);
    assert_eq!(loaded.public_key_hex, attestation.public_key_hex);
    assert_eq!(loaded.signature_hex, attestation.signature_hex);
}

#[test]
fn load_from_file_invalid_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.json");
    std::fs::write(&path, "not valid json{{{").unwrap();

    let result = load_attestation(&path);
    assert!(matches!(result, Err(AttestationError::InvalidFormat(_))));
}

#[test]
fn load_from_file_missing_file() {
    let path = std::path::Path::new("/tmp/nonexistent-attestation-file.json");
    let result = load_attestation(path);
    assert!(matches!(result, Err(AttestationError::InvalidFormat(_))));
}

#[test]
fn url_normalization_trailing_slash() {
    let key = test_signing_key();
    let doc = valid_document();
    let attestation = sign_scope_document(&doc, &key);

    let result = verify_attestation(&attestation, "http://localhost:8080/");
    assert!(
        result.is_ok(),
        "trailing slash should not cause mismatch: {result:?}"
    );
}

#[test]
fn url_normalization_case_insensitive_scheme_and_host() {
    let key = test_signing_key();
    let doc = valid_document();
    let attestation = sign_scope_document(&doc, &key);

    let result = verify_attestation(&attestation, "HTTP://LOCALHOST:8080");
    assert!(
        result.is_ok(),
        "scheme/host case should not cause mismatch: {result:?}"
    );
}

#[test]
fn attestation_error_display_invalid_signature() {
    let err = AttestationError::InvalidSignature;
    assert_eq!(format!("{err}"), "invalid Ed25519 signature");
}

#[test]
fn attestation_error_display_expired() {
    let err = AttestationError::Expired("2020-01-01".to_string());
    assert!(format!("{err}").contains("2020-01-01"));
}

#[test]
fn attestation_error_display_target_mismatch() {
    let err = AttestationError::TargetMismatch {
        expected: "http://localhost:8080".to_string(),
        actual: "http://localhost:9999".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("8080"));
    assert!(msg.contains("9999"));
}

#[test]
fn attestation_error_display_invalid_public_key() {
    let err = AttestationError::InvalidPublicKey("bad bytes".to_string());
    assert!(format!("{err}").contains("bad bytes"));
}

#[test]
fn attestation_error_display_invalid_format() {
    let err = AttestationError::InvalidFormat("missing field".to_string());
    assert!(format!("{err}").contains("missing field"));
}

#[test]
fn verify_fails_with_invalid_public_key_hex() {
    let attestation = SignedScopeAttestation {
        document: valid_document(),
        public_key_hex: "not-valid-hex".to_string(),
        signature_hex: "00".repeat(64),
    };
    let result = verify_attestation(&attestation, "http://localhost:8080");
    assert!(matches!(result, Err(AttestationError::InvalidPublicKey(_))));
}

#[test]
fn verify_fails_with_short_public_key() {
    let attestation = SignedScopeAttestation {
        document: valid_document(),
        public_key_hex: "abcd".to_string(),
        signature_hex: "00".repeat(64),
    };
    let result = verify_attestation(&attestation, "http://localhost:8080");
    assert!(matches!(result, Err(AttestationError::InvalidPublicKey(_))));
}

#[test]
fn verify_fails_with_invalid_date_format() {
    let key = test_signing_key();
    let mut doc = valid_document();
    doc.valid_until = "not-a-date".to_string();
    let attestation = sign_scope_document(&doc, &key);

    let result = verify_attestation(&attestation, "http://localhost:8080");
    assert!(matches!(result, Err(AttestationError::InvalidFormat(_))));
}
