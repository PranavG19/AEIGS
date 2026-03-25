use super::email_intelligence::*;

#[test]
fn extract_domain_from_email() {
    assert_eq!(extract_domain("user@example.com"), "example.com");
    assert_eq!(extract_domain("USER@EXAMPLE.COM"), "example.com");
    assert_eq!(extract_domain("nope"), "");
}

#[test]
fn sha1_hex_known_value() {
    let hash = sha1_hex("test");
    assert_eq!(hash, "A94A8FE5CCB19BA61C4C0873D391E987982FBBD3");
}

#[test]
fn sha1_hex_empty_string() {
    let hash = sha1_hex("");
    assert_eq!(hash, "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
}

#[test]
fn md5_hex_known_value() {
    let hash = md5_hex("test");
    assert_eq!(hash, "098f6bcd4621d373cade4e832627b4f6");
}

#[test]
fn md5_hex_empty_string() {
    let hash = md5_hex("");
    assert_eq!(hash, "d41d8cd98f00b204e9800998ecf8427e");
}

#[test]
fn guess_name_dot_separated() {
    let (first, last) = guess_name_from_local("john.doe");
    assert_eq!(first.as_deref(), Some("john"));
    assert_eq!(last.as_deref(), Some("doe"));
}

#[test]
fn guess_name_underscore_separated() {
    let (first, last) = guess_name_from_local("jane_smith");
    assert_eq!(first.as_deref(), Some("jane"));
    assert_eq!(last.as_deref(), Some("smith"));
}

#[test]
fn guess_name_hyphen_separated() {
    let (first, last) = guess_name_from_local("mary-jones");
    assert_eq!(first.as_deref(), Some("mary"));
    assert_eq!(last.as_deref(), Some("jones"));
}

#[test]
fn guess_name_camel_case() {
    let (first, last) = guess_name_from_local("johnDoe");
    assert_eq!(first.as_deref(), Some("john"));
    assert_eq!(last.as_deref(), Some("Doe"));
}

#[test]
fn guess_name_no_separator() {
    let (first, last) = guess_name_from_local("jd");
    assert!(first.is_none());
    assert!(last.is_none());
}

#[test]
fn generate_permutations_for_valid_email() {
    let perms = generate_email_permutations("john.doe@example.com");
    assert!(!perms.is_empty());

    let emails: Vec<&str> = perms.iter().map(|p| p.email.as_str()).collect();
    assert!(emails.contains(&"doe.john@example.com"));
    assert!(emails.contains(&"johndoe@example.com"));
    assert!(emails.contains(&"john_doe@example.com"));
    assert!(emails.contains(&"john-doe@example.com"));
    assert!(emails.contains(&"j.doe@example.com"));
    assert!(emails.contains(&"john.d@example.com"));
}

#[test]
fn generate_permutations_excludes_original() {
    let perms = generate_email_permutations("john.doe@example.com");
    let emails: Vec<&str> = perms.iter().map(|p| p.email.as_str()).collect();
    assert!(!emails.contains(&"john.doe@example.com"));
}

#[test]
fn generate_permutations_invalid_email_returns_empty() {
    let perms = generate_email_permutations("not-an-email");
    assert!(perms.is_empty());
}

#[test]
fn email_permutation_has_format_label() {
    let perms = generate_email_permutations("alice.bob@test.com");
    for p in &perms {
        assert!(!p.format_label.is_empty());
    }
}

#[test]
fn email_validation_status_display() {
    assert_eq!(EmailValidationStatus::Valid.to_string(), "Valid");
    assert_eq!(EmailValidationStatus::Invalid.to_string(), "Invalid");
    assert_eq!(EmailValidationStatus::CatchAll.to_string(), "Catch-All");
    assert_eq!(EmailValidationStatus::Unknown.to_string(), "Unknown");
    assert!(EmailValidationStatus::SmtpError("timeout".into()).to_string().contains("timeout"));
}

#[test]
fn default_config_values() {
    let config = EmailIntelConfig::default();
    assert!(config.check_breaches);
    assert!(config.generate_permutations);
    assert!(config.check_disposable);
    assert!(config.check_gravatar);
    assert_eq!(config.timeout_secs, 10);
}

#[test]
fn engine_creation() {
    let engine = EmailIntelligenceEngine::new(EmailIntelConfig::default());
    assert!(!engine.disposable_domains.is_empty());
    assert!(!engine.free_providers.is_empty());
}

#[test]
fn disposable_detection_mailinator() {
    let engine = EmailIntelligenceEngine::new(EmailIntelConfig::default());
    assert!(engine.disposable_domains.contains("mailinator.com"));
    assert!(engine.disposable_domains.contains("guerrillamail.com"));
    assert!(engine.disposable_domains.contains("tempmail.com"));
}

#[test]
fn free_provider_detection() {
    let engine = EmailIntelligenceEngine::new(EmailIntelConfig::default());
    assert!(engine.free_providers.contains("gmail.com"));
    assert!(engine.free_providers.contains("yahoo.com"));
    assert!(engine.free_providers.contains("protonmail.com"));
}

#[test]
fn disposable_list_has_at_least_40_entries() {
    let domains = crate::email_intelligence::build_disposable_domains();
    assert!(domains.len() >= 40, "expected 40+ disposable domains, got {}", domains.len());
}

#[test]
fn free_provider_list_has_at_least_20_entries() {
    let providers = crate::email_intelligence::build_free_providers();
    assert!(providers.len() >= 20, "expected 20+ free providers, got {}", providers.len());
}

#[test]
fn email_intel_error_display() {
    assert!(EmailIntelError::InvalidEmail("bad".into()).to_string().contains("bad"));
    assert!(EmailIntelError::Network("timeout".into()).to_string().contains("timeout"));
    assert!(EmailIntelError::ApiError("401".into()).to_string().contains("401"));
}

#[test]
fn breach_info_serialization_roundtrip() {
    let info = BreachInfo {
        source: "TestBreach".into(),
        date: Some("2023-01-01".into()),
        data_types: vec!["Emails".into(), "Passwords".into()],
        is_verified: true,
        password_included: true,
    };
    let json = serde_json::to_string(&info).unwrap();
    let deserialized: BreachInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.source, "TestBreach");
    assert!(deserialized.password_included);
}

#[test]
fn pwned_password_result_serialization() {
    let result = PwnedPasswordResult {
        is_pwned: true,
        occurrence_count: 12345,
        sha1_prefix: "A94A8".into(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: PwnedPasswordResult = serde_json::from_str(&json).unwrap();
    assert!(deserialized.is_pwned);
    assert_eq!(deserialized.occurrence_count, 12345);
}

#[test]
fn email_intelligence_serialization() {
    let intel = EmailIntelligence {
        email: "user@example.com".into(),
        domain: "example.com".into(),
        validation_status: EmailValidationStatus::Unknown,
        mx_records: vec![MxRecord { hostname: "mx1.example.com".into(), priority: 10 }],
        is_disposable: false,
        is_free_provider: false,
        breaches: Vec::new(),
        pwned_password: None,
        permutations: Vec::new(),
        gravatar_exists: false,
    };
    let json = serde_json::to_string(&intel).unwrap();
    assert!(json.contains("example.com"));
}

#[tokio::test]
async fn investigate_with_unreachable_dns_still_returns() {
    let config = EmailIntelConfig {
        check_breaches: false,
        check_gravatar: false,
        timeout_secs: 1,
        ..EmailIntelConfig::default()
    };
    let engine = EmailIntelligenceEngine::new(config);
    let result = engine.investigate("test@nonexistent-domain-xyz.invalid").await;
    assert_eq!(result.email, "test@nonexistent-domain-xyz.invalid");
    assert_eq!(result.domain, "nonexistent-domain-xyz.invalid");
    assert!(!result.is_disposable);
}

#[test]
fn sha1_of_password_for_hibp() {
    let hash = sha1_hex("password");
    assert!(hash.starts_with("5BAA6"));
}

#[test]
fn permutation_uniqueness() {
    let perms = generate_email_permutations("alice.wonderland@test.org");
    let unique: std::collections::HashSet<_> = perms.iter().map(|p| &p.email).collect();
    assert_eq!(unique.len(), perms.len(), "duplicate permutations detected");
}
