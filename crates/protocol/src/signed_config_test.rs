use crate::signed_config::*;

fn test_signing_key() -> ed25519_dalek::SigningKey {
    let secret: [u8; 32] = rand::random();
    ed25519_dalek::SigningKey::from_bytes(&secret)
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

#[test]
fn sign_and_verify_roundtrip() {
    let key = test_signing_key();
    let config = sample_config();
    let signed = sign_config(&config, &key);

    let result = verify_signed_config(&signed);
    assert!(result.is_ok(), "expected Ok, got: {result:?}");
}

#[test]
fn hash_is_deterministic() {
    let config = sample_config();
    let hash1 = compute_config_hash(&config);
    let hash2 = compute_config_hash(&config);
    assert_eq!(hash1, hash2);
}

#[test]
fn tampered_config_fails_verification() {
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

#[test]
fn wrong_key_fails_verification() {
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

#[test]
fn load_from_file_roundtrip() {
    let key = test_signing_key();
    let config = sample_config();
    let signed = sign_config(&config, &key);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("signed_config.json");
    let json = serde_json::to_string_pretty(&signed).unwrap();
    std::fs::write(&path, json).unwrap();

    let loaded = load_signed_config(&path);
    assert!(loaded.is_ok(), "expected Ok, got: {loaded:?}");

    let loaded = loaded.unwrap();
    assert_eq!(loaded.config, config);
    assert_eq!(loaded.config_hash, signed.config_hash);
    assert_eq!(loaded.public_key_hex, signed.public_key_hex);
    assert_eq!(loaded.signature_hex, signed.signature_hex);

    let verify = verify_signed_config(&loaded);
    assert!(
        verify.is_ok(),
        "loaded config should still verify: {verify:?}"
    );
}

#[test]
fn load_from_file_invalid_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.json");
    std::fs::write(&path, "not valid json{{{").unwrap();

    let result = load_signed_config(&path);
    assert!(matches!(result, Err(SignedConfigError::InvalidFormat(_))));
}

#[test]
fn load_from_file_missing_file() {
    let path = std::path::Path::new("/tmp/nonexistent-signed-config.json");
    let result = load_signed_config(path);
    assert!(matches!(result, Err(SignedConfigError::InvalidFormat(_))));
}

#[test]
fn config_match_succeeds_for_identical_configs() {
    let config = sample_config();
    let result = verify_config_matches(&config, &config);
    assert!(result.is_ok());
}

#[test]
fn config_match_fails_on_target_mismatch() {
    let signed = sample_config();
    let mut actual = sample_config();
    actual.target = "http://localhost:9999".to_string();

    let result = verify_config_matches(&signed, &actual);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("target mismatch"));
}

#[test]
fn config_match_fails_on_stealth_level_mismatch() {
    let signed = sample_config();
    let mut actual = sample_config();
    actual.stealth_level = "paranoid".to_string();

    let result = verify_config_matches(&signed, &actual);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("stealth_level mismatch"));
}

#[test]
fn config_match_fails_on_max_iterations_mismatch() {
    let signed = sample_config();
    let mut actual = sample_config();
    actual.max_iterations = 99;

    let result = verify_config_matches(&signed, &actual);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("max_iterations mismatch"));
}

#[test]
fn config_match_fails_on_convergence_threshold_mismatch() {
    let signed = sample_config();
    let mut actual = sample_config();
    actual.convergence_threshold = 10;

    let result = verify_config_matches(&signed, &actual);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("convergence_threshold mismatch")
    );
}

#[test]
fn config_match_fails_on_no_llm_mismatch() {
    let signed = sample_config();
    let mut actual = sample_config();
    actual.no_llm = true;

    let result = verify_config_matches(&signed, &actual);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("no_llm mismatch"));
}

#[test]
fn config_match_fails_on_include_endpoints_mismatch() {
    let signed = sample_config();
    let mut actual = sample_config();
    actual.include_endpoints = Some(vec!["/api/v1".to_string()]);

    let result = verify_config_matches(&signed, &actual);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("include_endpoints mismatch"));
}

#[test]
fn config_match_fails_on_exclude_endpoints_mismatch() {
    let signed = sample_config();
    let mut actual = sample_config();
    actual.exclude_endpoints = Some(vec!["/health".to_string()]);

    let result = verify_config_matches(&signed, &actual);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("exclude_endpoints mismatch"));
}

#[test]
fn error_display_invalid_signature() {
    let err = SignedConfigError::InvalidSignature;
    assert_eq!(format!("{err}"), "invalid Ed25519 signature on config");
}

#[test]
fn error_display_hash_mismatch() {
    let err = SignedConfigError::HashMismatch {
        expected: "aaa".to_string(),
        actual: "bbb".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("aaa"));
    assert!(msg.contains("bbb"));
}

#[test]
fn error_display_invalid_public_key() {
    let err = SignedConfigError::InvalidPublicKey("bad bytes".to_string());
    assert!(format!("{err}").contains("bad bytes"));
}

#[test]
fn error_display_invalid_format() {
    let err = SignedConfigError::InvalidFormat("missing field".to_string());
    assert!(format!("{err}").contains("missing field"));
}

#[test]
fn hash_changes_when_config_changes() {
    let config1 = sample_config();
    let mut config2 = sample_config();
    config2.target = "http://localhost:9999".to_string();

    let hash1 = compute_config_hash(&config1);
    let hash2 = compute_config_hash(&config2);
    assert_ne!(hash1, hash2);
}

#[test]
fn signed_config_includes_correct_hash() {
    let key = test_signing_key();
    let config = sample_config();
    let signed = sign_config(&config, &key);

    let expected_hash = compute_config_hash(&config);
    assert_eq!(signed.config_hash, expected_hash);
}

#[test]
fn verify_fails_with_invalid_public_key_hex() {
    let signed = SignedConfig {
        config: sample_config(),
        config_hash: compute_config_hash(&sample_config()),
        public_key_hex: "not-valid-hex".to_string(),
        signature_hex: "00".repeat(64),
    };
    let result = verify_signed_config(&signed);
    assert!(matches!(
        result,
        Err(SignedConfigError::InvalidPublicKey(_))
    ));
}

#[test]
fn verify_fails_with_short_public_key() {
    let signed = SignedConfig {
        config: sample_config(),
        config_hash: compute_config_hash(&sample_config()),
        public_key_hex: "abcd".to_string(),
        signature_hex: "00".repeat(64),
    };
    let result = verify_signed_config(&signed);
    assert!(matches!(
        result,
        Err(SignedConfigError::InvalidPublicKey(_))
    ));
}

#[test]
fn config_with_endpoints_roundtrips() {
    let key = test_signing_key();
    let config = SignableConfig {
        target: "http://localhost:8080".to_string(),
        stealth_level: "aggressive".to_string(),
        max_iterations: 5,
        convergence_threshold: 3,
        no_llm: true,
        include_endpoints: Some(vec!["/api/v1".to_string(), "/api/v2".to_string()]),
        exclude_endpoints: Some(vec!["/health".to_string()]),
    };
    let signed = sign_config(&config, &key);
    let result = verify_signed_config(&signed);
    assert!(result.is_ok(), "expected Ok, got: {result:?}");
}
