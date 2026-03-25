use super::credential_harvest::*;

fn make_cred(
    cred_type: CredentialType,
    source: CredentialSource,
    value: CredentialValue,
    access: AccessLevel,
    scope: &str,
    confidence: f64,
    validated: bool,
) -> HarvestedCredential {
    let id = compute_credential_hash(cred_type, &value);
    HarvestedCredential {
        id,
        credential_type: cred_type,
        source,
        value,
        access_level: access,
        scope: scope.to_string(),
        confidence,
        location: "test-location".into(),
        validated,
        tags: Vec::new(),
    }
}

#[test]
fn test_harvester_new_has_default_patterns() {
    let h = CredentialHarvester::new();
    let patterns = default_credential_patterns();
    assert_eq!(h.get_credentials().len(), 0);
    assert!(
        patterns.len() >= 9,
        "should have at least 9 default patterns"
    );
}

#[test]
fn test_add_credential_and_retrieve() {
    let mut h = CredentialHarvester::new();
    let cred = make_cred(
        CredentialType::ApiKey,
        CredentialSource::JsFile,
        CredentialValue::Token("abc123".into()),
        AccessLevel::Standard,
        "api-service",
        0.8,
        false,
    );
    let result = h.add_credential(cred);
    assert_eq!(result, Ok(true));
    assert_eq!(h.get_credentials().len(), 1);
}

#[test]
fn test_deduplication_removes_identical() {
    let mut h = CredentialHarvester::new();
    let cred1 = make_cred(
        CredentialType::ApiKey,
        CredentialSource::JsFile,
        CredentialValue::Token("same-token".into()),
        AccessLevel::Standard,
        "svc",
        0.8,
        false,
    );
    let cred2 = make_cred(
        CredentialType::ApiKey,
        CredentialSource::ApiResponse,
        CredentialValue::Token("same-token".into()),
        AccessLevel::Standard,
        "svc",
        0.9,
        false,
    );
    assert_eq!(h.add_credential(cred1), Ok(true));
    assert_eq!(h.add_credential(cred2), Ok(false));
    assert_eq!(h.get_credentials().len(), 1);

    let removed = h.deduplicate();
    assert_eq!(removed, 0);
}

#[test]
fn test_scan_finds_aws_keys() {
    let mut h = CredentialHarvester::new();
    let text = "config: AKIAIOSFODNN7EXAMPLE and other stuff";
    let found = h.scan_text_for_credentials(text, CredentialSource::ConfigFile, "/app/.env");
    assert!(
        found
            .iter()
            .any(|c| c.credential_type == CredentialType::AwsAccessKey),
        "should find AWS access key in text"
    );
}

#[test]
fn test_scan_finds_jwt_tokens() {
    let mut h = CredentialHarvester::new();
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123_signature-here";
    let text = format!("Authorization: {jwt}");
    let found = h.scan_text_for_credentials(&text, CredentialSource::ApiResponse, "/api/token");
    assert!(
        found
            .iter()
            .any(|c| c.credential_type == CredentialType::JwtToken),
        "should find JWT token"
    );
}

#[test]
fn test_scan_finds_connection_strings() {
    let mut h = CredentialHarvester::new();
    let text = "DATABASE_URL=postgres://user:pass@db.host:5432/mydb\nREDIS=redis://localhost:6379";
    let found = h.scan_text_for_credentials(text, CredentialSource::ConfigFile, "/.env");
    let conn_types: Vec<_> = found
        .iter()
        .filter(|c| c.credential_type == CredentialType::DatabaseConnectionString)
        .collect();
    assert!(
        conn_types.len() >= 2,
        "should find postgres and redis connection strings"
    );
}

#[test]
fn test_scan_finds_private_key_header() {
    let mut h = CredentialHarvester::new();
    let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ...";
    let found = h.scan_text_for_credentials(text, CredentialSource::GitExposure, "/.git/key");
    assert!(
        found
            .iter()
            .any(|c| c.credential_type == CredentialType::PrivateKey),
        "should detect private key header"
    );
}

#[test]
fn test_scan_finds_password_patterns() {
    let mut h = CredentialHarvester::new();
    let text = r#"password=SuperS3cret123"#;
    let found = h.scan_text_for_credentials(text, CredentialSource::ConfigFile, "/.env");
    let pw_count = found
        .iter()
        .filter(|c| {
            c.credential_type == CredentialType::UsernamePassword
                || c.credential_type == CredentialType::GenericSecret
        })
        .count();
    assert!(
        pw_count >= 1,
        "should find password pattern, found {pw_count}"
    );
}

#[test]
fn test_scan_finds_bearer_tokens() {
    let mut h = CredentialHarvester::new();
    let text = "Authorization: Bearer eyToken123.abc-def_ghi";
    let found = h.scan_text_for_credentials(text, CredentialSource::ApiResponse, "/api/me");
    assert!(
        found
            .iter()
            .any(|c| c.credential_type == CredentialType::BearerToken),
        "should find Bearer token"
    );
}

#[test]
fn test_get_by_source_filters() {
    let mut h = CredentialHarvester::new();
    let c1 = make_cred(
        CredentialType::ApiKey,
        CredentialSource::JsFile,
        CredentialValue::Token("key-a".into()),
        AccessLevel::Standard,
        "",
        0.8,
        false,
    );
    let c2 = make_cred(
        CredentialType::BearerToken,
        CredentialSource::ApiResponse,
        CredentialValue::Token("tok-b".into()),
        AccessLevel::Standard,
        "",
        0.8,
        false,
    );
    h.add_credential(c1).unwrap();
    h.add_credential(c2).unwrap();

    let js = h.get_by_source(CredentialSource::JsFile);
    assert_eq!(js.len(), 1);
    assert_eq!(js[0].credential_type, CredentialType::ApiKey);

    let api = h.get_by_source(CredentialSource::ApiResponse);
    assert_eq!(api.len(), 1);
}

#[test]
fn test_get_by_type_filters() {
    let mut h = CredentialHarvester::new();
    let c1 = make_cred(
        CredentialType::JwtToken,
        CredentialSource::JsFile,
        CredentialValue::Token("jwt-1".into()),
        AccessLevel::Standard,
        "",
        0.9,
        false,
    );
    let c2 = make_cred(
        CredentialType::JwtToken,
        CredentialSource::ApiResponse,
        CredentialValue::Token("jwt-2".into()),
        AccessLevel::Standard,
        "",
        0.9,
        false,
    );
    let c3 = make_cred(
        CredentialType::ApiKey,
        CredentialSource::ConfigFile,
        CredentialValue::Token("api-k".into()),
        AccessLevel::Standard,
        "",
        0.8,
        false,
    );
    h.add_credential(c1).unwrap();
    h.add_credential(c2).unwrap();
    h.add_credential(c3).unwrap();

    let jwts = h.get_by_type(CredentialType::JwtToken);
    assert_eq!(jwts.len(), 2);
}

#[test]
fn test_get_by_access_level_minimum() {
    let mut h = CredentialHarvester::new();
    let c_standard = make_cred(
        CredentialType::SessionCookie,
        CredentialSource::SessionToken,
        CredentialValue::Cookie {
            name: "sid".into(),
            value: "abc".into(),
        },
        AccessLevel::Standard,
        "",
        0.8,
        false,
    );
    let c_admin = make_cred(
        CredentialType::SshKey,
        CredentialSource::GitExposure,
        CredentialValue::KeyPair {
            public_key: "pub".into(),
            private_key: "priv".into(),
        },
        AccessLevel::Admin,
        "",
        0.95,
        true,
    );
    let c_read = make_cred(
        CredentialType::ApiKey,
        CredentialSource::JsFile,
        CredentialValue::Token("ro-key".into()),
        AccessLevel::ReadOnly,
        "",
        0.5,
        false,
    );
    h.add_credential(c_standard).unwrap();
    h.add_credential(c_admin).unwrap();
    h.add_credential(c_read).unwrap();

    let elevated_plus = h.get_by_access_level(AccessLevel::Elevated);
    assert_eq!(elevated_plus.len(), 1);
    assert_eq!(elevated_plus[0].access_level, AccessLevel::Admin);

    let standard_plus = h.get_by_access_level(AccessLevel::Standard);
    assert_eq!(standard_plus.len(), 2);

    let all = h.get_by_access_level(AccessLevel::Unknown);
    assert_eq!(all.len(), 3);
}

#[test]
fn test_score_credential_root_validated() {
    let cred = make_cred(
        CredentialType::SshKey,
        CredentialSource::GitExposure,
        CredentialValue::KeyPair {
            public_key: "pub".into(),
            private_key: "priv".into(),
        },
        AccessLevel::Root,
        "prod-server",
        1.0,
        true,
    );
    let score = CredentialHarvester::score_credential(&cred);
    let expected = 10.0 * 1.0 * 1.5;
    assert!(
        (score - expected).abs() < f64::EPSILON,
        "root+validated score should be {expected}, got {score}"
    );
}

#[test]
fn test_score_credential_unknown_unvalidated() {
    let cred = make_cred(
        CredentialType::GenericSecret,
        CredentialSource::ErrorMessage,
        CredentialValue::Token("maybe".into()),
        AccessLevel::Unknown,
        "",
        0.3,
        false,
    );
    let score = CredentialHarvester::score_credential(&cred);
    let expected = 1.0 * 0.3;
    assert!(
        (score - expected).abs() < f64::EPSILON,
        "unknown+unvalidated score should be {expected}, got {score}"
    );
}

#[test]
fn test_classify_access_level() {
    assert_eq!(
        classify_access_level(CredentialType::SshKey, "web-server"),
        AccessLevel::Admin
    );
    assert_eq!(
        classify_access_level(CredentialType::AwsAccessKey, "s3-bucket"),
        AccessLevel::Elevated
    );
    assert_eq!(
        classify_access_level(CredentialType::SessionCookie, "user-portal"),
        AccessLevel::Standard
    );
    assert_eq!(
        classify_access_level(CredentialType::GenericSecret, "misc"),
        AccessLevel::Unknown
    );
    assert_eq!(
        classify_access_level(CredentialType::GenericSecret, "admin-panel"),
        AccessLevel::ReadOnly,
        "admin in scope should bump Unknown→ReadOnly"
    );
    assert_eq!(
        classify_access_level(CredentialType::AwsAccessKey, "root-account"),
        AccessLevel::Root,
        "root in scope should double-bump Elevated→Root"
    );
}

#[test]
fn test_summarize_counts() {
    let mut h = CredentialHarvester::new();
    let c1 = make_cred(
        CredentialType::ApiKey,
        CredentialSource::JsFile,
        CredentialValue::Token("key-1".into()),
        AccessLevel::Standard,
        "svc",
        0.8,
        false,
    );
    let c2 = make_cred(
        CredentialType::SshKey,
        CredentialSource::GitExposure,
        CredentialValue::KeyPair {
            public_key: "pub".into(),
            private_key: "priv".into(),
        },
        AccessLevel::Admin,
        "prod",
        0.95,
        true,
    );
    h.add_credential(c1).unwrap();
    h.add_credential(c2).unwrap();

    let summary = h.summarize();
    assert_eq!(summary.total_found, 2);
    assert_eq!(summary.unique_credentials, 2);
    assert_eq!(summary.duplicates_removed, 0);
    assert_eq!(summary.highest_access, AccessLevel::Admin);
    assert_eq!(summary.validated_count, 1);
    assert_eq!(summary.critical_findings.len(), 1);
}

#[test]
fn test_display_impls() {
    assert_eq!(format!("{}", CredentialSource::JsFile), "js-file");
    assert_eq!(
        format!("{}", CredentialSource::CloudMetadata),
        "cloud-metadata"
    );
    assert_eq!(
        format!("{}", CredentialType::AwsAccessKey),
        "aws-access-key"
    );
    assert_eq!(
        format!("{}", CredentialType::GenericSecret),
        "generic-secret"
    );
    assert_eq!(format!("{}", AccessLevel::Root), "root");
    assert_eq!(format!("{}", AccessLevel::ReadOnly), "read-only");

    let err = HarvestError::DuplicateCredential("abc".into());
    assert_eq!(format!("{err}"), "duplicate credential: abc");

    let err2 = HarvestError::InvalidCredential("bad".into());
    assert_eq!(format!("{err2}"), "invalid credential: bad");

    let err3 = HarvestError::PatternError("oops".into());
    assert_eq!(format!("{err3}"), "pattern error: oops");
}
