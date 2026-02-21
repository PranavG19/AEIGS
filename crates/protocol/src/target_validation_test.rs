use crate::scope_attestation::{ScopeDocument, SignedScopeAttestation, sign_scope_document};
use crate::target_validation::*;

fn test_signing_key() -> ed25519_dalek::SigningKey {
    let secret: [u8; 32] = rand::random();
    ed25519_dalek::SigningKey::from_bytes(&secret)
}

fn remote_attestation(target: &str) -> SignedScopeAttestation {
    let key = test_signing_key();
    let doc = ScopeDocument {
        target: target.to_string(),
        authorized_by: "security-team@example.com".to_string(),
        valid_until: "2099-12-31".to_string(),
        scope_id: "test-scope-id".to_string(),
    };
    sign_scope_document(&doc, &key)
}

fn expired_attestation(target: &str) -> SignedScopeAttestation {
    let key = test_signing_key();
    let doc = ScopeDocument {
        target: target.to_string(),
        authorized_by: "security-team@example.com".to_string(),
        valid_until: "2020-01-01".to_string(),
        scope_id: "test-scope-id".to_string(),
    };
    sign_scope_document(&doc, &key)
}

#[test]
fn validate_target_localhost_no_attestation() {
    let result = validate_target("http://localhost:8080", None);
    assert!(result.is_ok());
}

#[test]
fn validate_target_localhost_with_attestation_still_ok() {
    let att = remote_attestation("http://localhost:8080");
    let result = validate_target("http://localhost:8080", Some(&att));
    assert!(result.is_ok());
}

#[test]
fn validate_target_localhost_127() {
    let result = validate_target("http://127.0.0.1:3000/api", None);
    assert!(result.is_ok());
}

#[test]
fn validate_target_remote_no_attestation_fails() {
    let result = validate_target("http://example.com:8080", None);
    assert!(
        matches!(
            result,
            Err(TargetValidationError::NonLocalhostTarget { .. })
        ),
        "expected NonLocalhostTarget, got: {result:?}"
    );
}

#[test]
fn validate_target_remote_with_valid_attestation() {
    let att = remote_attestation("http://example.com:8080");
    let result = validate_target("http://example.com:8080", Some(&att));
    assert!(
        result.is_ok(),
        "expected Ok with valid attestation, got: {result:?}"
    );
}

#[test]
fn validate_target_remote_with_expired_attestation() {
    let att = expired_attestation("http://example.com:8080");
    let result = validate_target("http://example.com:8080", Some(&att));
    assert!(
        matches!(result, Err(TargetValidationError::AttestationFailed { .. })),
        "expected AttestationFailed, got: {result:?}"
    );
}

#[test]
fn validate_target_remote_with_mismatched_attestation() {
    let att = remote_attestation("http://other-host.com:8080");
    let result = validate_target("http://example.com:8080", Some(&att));
    assert!(
        matches!(result, Err(TargetValidationError::AttestationFailed { .. })),
        "expected AttestationFailed for target mismatch, got: {result:?}"
    );
}

#[test]
fn validate_target_invalid_url_no_attestation() {
    let result = validate_target("", None);
    assert!(
        matches!(result, Err(TargetValidationError::InvalidUrl { .. })),
        "expected InvalidUrl, got: {result:?}"
    );
}

#[test]
fn validate_target_invalid_url_with_attestation() {
    let att = remote_attestation("http://example.com");
    let result = validate_target("", Some(&att));
    assert!(
        matches!(result, Err(TargetValidationError::AttestationFailed { .. })),
        "expected AttestationFailed (target mismatch on empty URL), got: {result:?}"
    );
}

#[test]
fn attestation_failed_display() {
    let err = TargetValidationError::AttestationFailed {
        reason: "expired on 2020-01-01".to_string(),
    };
    assert_eq!(
        format!("{err}"),
        "scope attestation failed: expired on 2020-01-01"
    );
}

#[test]
fn validate_target_remote_attestation_bad_signature() {
    let mut att = remote_attestation("http://example.com:8080");
    att.document.authorized_by = "tampered@evil.com".to_string();
    let result = validate_target("http://example.com:8080", Some(&att));
    assert!(
        matches!(result, Err(TargetValidationError::AttestationFailed { .. })),
        "expected AttestationFailed for tampered document, got: {result:?}"
    );
}

#[test]
fn validate_target_is_localhost_unchanged() {
    let ok = validate_target_is_localhost("http://localhost:8080");
    assert!(ok.is_ok());

    let err = validate_target_is_localhost("http://example.com");
    assert!(matches!(
        err,
        Err(TargetValidationError::NonLocalhostTarget { .. })
    ));
}
