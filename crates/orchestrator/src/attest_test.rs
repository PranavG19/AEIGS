use crate::attest::{
    AttestArgs, AttestError, DEFAULT_OUTPUT, compute_valid_until, generate_scope_id,
    load_or_generate_key, parse_attest_args, run_attest, write_attestation,
};
use aegis_protocol::scope_attestation::{
    SignedScopeAttestation, days_to_ymd, verify_attestation,
};
use std::path::PathBuf;

fn make_args(flags: &[(&str, &str)]) -> Vec<String> {
    flags
        .iter()
        .flat_map(|(k, v)| vec![format!("--{k}"), v.to_string()])
        .collect()
}

#[test]
fn generate_attestation_writes_valid_json() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("test.key");
    let output_path = dir.path().join("attestation.json");

    let args = AttestArgs {
        target: "http://localhost:3000".to_string(),
        authorized_by: "tester".to_string(),
        valid_days: 30,
        key_path: key_path.clone(),
        output_path: output_path.clone(),
    };

    run_attest(&args).unwrap();

    assert!(output_path.exists());
    let contents = std::fs::read_to_string(&output_path).unwrap();
    let attestation: SignedScopeAttestation = serde_json::from_str(&contents).unwrap();
    assert_eq!(attestation.document.target, "http://localhost:3000");
    assert_eq!(attestation.document.authorized_by, "tester");
    assert!(!attestation.public_key_hex.is_empty());
    assert!(!attestation.signature_hex.is_empty());
}

#[test]
fn generated_attestation_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("test.key");
    let output_path = dir.path().join("attestation.json");

    let args = AttestArgs {
        target: "http://localhost:8080".to_string(),
        authorized_by: "security-team".to_string(),
        valid_days: 90,
        key_path,
        output_path: output_path.clone(),
    };

    run_attest(&args).unwrap();

    let contents = std::fs::read_to_string(&output_path).unwrap();
    let attestation: SignedScopeAttestation = serde_json::from_str(&contents).unwrap();
    let result = verify_attestation(&attestation, "http://localhost:8080");
    assert!(result.is_ok(), "verification failed: {result:?}");
}

#[test]
fn key_generation_creates_file_when_missing() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("new.key");

    assert!(!key_path.exists());
    let key = load_or_generate_key(&key_path).unwrap();
    assert!(key_path.exists());

    let bytes = std::fs::read(&key_path).unwrap();
    assert_eq!(bytes.len(), 32);

    let reloaded = load_or_generate_key(&key_path).unwrap();
    assert_eq!(
        key.verifying_key().as_bytes(),
        reloaded.verifying_key().as_bytes()
    );
}

#[test]
fn key_loading_works_with_existing_key() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("existing.key");

    let secret: [u8; 32] = rand::random();
    std::fs::write(&key_path, secret).unwrap();

    let loaded = load_or_generate_key(&key_path).unwrap();
    let expected = ed25519_dalek::SigningKey::from_bytes(&secret);
    assert_eq!(
        loaded.verifying_key().as_bytes(),
        expected.verifying_key().as_bytes()
    );
}

#[test]
fn valid_days_calculation_produces_correct_date() {
    let date_str = compute_valid_until(0);
    assert_eq!(date_str.len(), 10);
    assert_eq!(&date_str[4..5], "-");
    assert_eq!(&date_str[7..8], "-");

    let today = compute_valid_until(0);
    let tomorrow = compute_valid_until(1);
    assert_ne!(
        today, tomorrow,
        "today and tomorrow should differ (unless midnight edge)"
    );

    let far_future = compute_valid_until(365);
    let year: i32 = far_future[..4].parse().unwrap();
    assert!(year >= 2026, "year should be at least 2026, got {year}");
}

#[test]
fn default_output_path_is_scope_attestation_json() {
    let args_vec = make_args(&[
        ("target", "http://localhost:3000"),
        ("authorized-by", "tester"),
        ("valid-days", "30"),
        ("key", "/tmp/test.key"),
    ]);
    let parsed = parse_attest_args(&args_vec).unwrap();
    assert_eq!(parsed.output_path, PathBuf::from(DEFAULT_OUTPUT));
}

#[test]
fn error_on_missing_required_target() {
    let args_vec = make_args(&[
        ("authorized-by", "tester"),
        ("valid-days", "30"),
        ("key", "/tmp/test.key"),
    ]);
    let result = parse_attest_args(&args_vec);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, AttestError::MissingArg(_)));
    assert!(format!("{err}").contains("target"));
}

#[test]
fn error_on_missing_required_authorized_by() {
    let args_vec = make_args(&[
        ("target", "http://localhost:3000"),
        ("valid-days", "30"),
        ("key", "/tmp/test.key"),
    ]);
    let result = parse_attest_args(&args_vec);
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("authorized-by"));
}

#[test]
fn error_on_missing_required_valid_days() {
    let args_vec = make_args(&[
        ("target", "http://localhost:3000"),
        ("authorized-by", "tester"),
        ("key", "/tmp/test.key"),
    ]);
    let result = parse_attest_args(&args_vec);
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("valid-days"));
}

#[test]
fn error_on_missing_required_key() {
    let args_vec = make_args(&[
        ("target", "http://localhost:3000"),
        ("authorized-by", "tester"),
        ("valid-days", "30"),
    ]);
    let result = parse_attest_args(&args_vec);
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("key"));
}

#[test]
fn error_on_invalid_valid_days() {
    let args_vec = make_args(&[
        ("target", "http://localhost:3000"),
        ("authorized-by", "tester"),
        ("valid-days", "not-a-number"),
        ("key", "/tmp/test.key"),
    ]);
    let result = parse_attest_args(&args_vec);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AttestError::InvalidDays(_)));
}

#[test]
fn error_on_zero_valid_days() {
    let args_vec = make_args(&[
        ("target", "http://localhost:3000"),
        ("authorized-by", "tester"),
        ("valid-days", "0"),
        ("key", "/tmp/test.key"),
    ]);
    let result = parse_attest_args(&args_vec);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AttestError::InvalidDays(_)));
}

#[test]
fn custom_output_path_is_respected() {
    let args_vec = make_args(&[
        ("target", "http://localhost:3000"),
        ("authorized-by", "tester"),
        ("valid-days", "30"),
        ("key", "/tmp/test.key"),
        ("output", "/tmp/custom.json"),
    ]);
    let parsed = parse_attest_args(&args_vec).unwrap();
    assert_eq!(parsed.output_path, PathBuf::from("/tmp/custom.json"));
}

#[test]
fn scope_id_is_32_hex_chars() {
    let id = generate_scope_id();
    assert_eq!(id.len(), 32);
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn scope_id_is_random() {
    let id1 = generate_scope_id();
    let id2 = generate_scope_id();
    assert_ne!(id1, id2, "two scope IDs should not be equal");
}

#[test]
fn days_to_ymd_epoch() {
    let (y, m, d) = days_to_ymd(0);
    assert_eq!((y, m, d), (1970, 1, 1));
}

#[test]
fn days_to_ymd_known_date() {
    // 2026-02-21 00:00 UTC = 1_771_632_000 seconds since epoch
    let days = 1_771_632_000u64 / 86400;
    let (y, m, d) = days_to_ymd(days);
    assert_eq!((y, m, d), (2026, 2, 21));
}

#[test]
fn key_format_error_on_wrong_size() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("bad.key");
    std::fs::write(&key_path, b"too short").unwrap();

    let result = load_or_generate_key(&key_path);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AttestError::KeyFormat(_)));
}

#[test]
fn attest_error_display_variants() {
    assert!(format!("{}", AttestError::MissingArg("foo".into())).contains("foo"));
    assert!(format!("{}", AttestError::InvalidDays("bar".into())).contains("bar"));
    assert!(format!("{}", AttestError::KeyIo("disk".into())).contains("disk"));
    assert!(format!("{}", AttestError::KeyFormat("bad".into())).contains("bad"));
    assert!(format!("{}", AttestError::OutputIo("fail".into())).contains("fail"));
}

#[test]
fn write_attestation_to_nonexistent_dir_fails() {
    let attestation = SignedScopeAttestation {
        document: aegis_protocol::scope_attestation::ScopeDocument {
            target: "http://localhost:3000".to_string(),
            authorized_by: "test".to_string(),
            valid_until: "2099-12-31".to_string(),
            scope_id: "abcd1234".to_string(),
        },
        public_key_hex: "00".repeat(32),
        signature_hex: "00".repeat(64),
    };
    let path = std::path::Path::new("/nonexistent/deep/dir/attestation.json");
    let result = write_attestation(&attestation, path);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AttestError::OutputIo(_)));
}
