use super::credential_intel::*;

#[test]
fn test_parse_credential_dump_email_password() {
    let lines = vec!["john@acme.com:password123", "jane@acme.com:letmein"];
    let entries = parse_credential_dump(&lines, Some("breach1"));
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].identifier, "john@acme.com");
    assert_eq!(entries[0].credential, "password123");
    assert_eq!(entries[0].format, DumpFormat::EmailPassword);
    assert_eq!(entries[0].source, Some("breach1".to_string()));
}

#[test]
fn test_parse_credential_dump_email_hash() {
    let lines = vec!["user@test.com:5f4dcc3b5aa765d61d8327deb882cf99"];
    let entries = parse_credential_dump(&lines, None);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].format, DumpFormat::EmailHash);
}

#[test]
fn test_parse_credential_dump_user_password() {
    let lines = vec!["admin:secretpass"];
    let entries = parse_credential_dump(&lines, None);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].format, DumpFormat::UserPassword);
    assert_eq!(entries[0].identifier, "admin");
}

#[test]
fn test_parse_credential_dump_combo_semicolon() {
    let lines = vec!["user@test.com;mypassword"];
    let entries = parse_credential_dump(&lines, None);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].format, DumpFormat::ComboList);
}

#[test]
fn test_parse_credential_dump_combo_pipe() {
    let lines = vec!["user@test.com|mypassword"];
    let entries = parse_credential_dump(&lines, None);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].format, DumpFormat::ComboList);
}

#[test]
fn test_parse_credential_dump_skip_empty_and_comments() {
    let lines = vec!["", "# this is a comment", "user@test.com:pass"];
    let entries = parse_credential_dump(&lines, None);
    assert_eq!(entries.len(), 1);
}

#[test]
fn test_parse_credential_dump_bcrypt_hash() {
    let lines = vec!["user@test.com:$2b$12$LJ3m4ys3Lg.Ry4JEOmMkKejWNdDGvaWE2PcuG6bfJSNNlm1lAHMha"];
    let entries = parse_credential_dump(&lines, None);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].format, DumpFormat::EmailHash);
}

#[test]
fn test_identify_hash_type_md5() {
    let ht = identify_hash_type("5f4dcc3b5aa765d61d8327deb882cf99");
    assert_eq!(ht, HashType::Md5);
}

#[test]
fn test_identify_hash_type_sha1() {
    let ht = identify_hash_type("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    assert_eq!(ht, HashType::Sha1);
}

#[test]
fn test_identify_hash_type_sha256() {
    let ht = identify_hash_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(ht, HashType::Sha256);
}

#[test]
fn test_identify_hash_type_bcrypt() {
    let ht = identify_hash_type("$2b$12$LJ3m4ys3Lg.Ry4JEOmMkKejWNdDGvaWE2PcuG6bfJSNNlm1lAHMha");
    assert_eq!(ht, HashType::Bcrypt);
}

#[test]
fn test_identify_hash_type_argon2() {
    let ht =
        identify_hash_type("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+daw");
    assert_eq!(ht, HashType::Argon2);
}

#[test]
fn test_identify_hash_type_unknown() {
    let ht = identify_hash_type("notahash");
    assert_eq!(ht, HashType::Unknown);
}

#[test]
fn test_analyze_password_patterns_basic() {
    let passwords = vec![
        "Password123",
        "Summer2024!",
        "qwerty",
        "admin",
        "p@ssw0rd",
        "letmein",
        "Password1",
        "Welcome1",
        "baseball99",
        "shadow",
    ];
    let analysis = analyze_password_patterns(&passwords);
    assert_eq!(analysis.total_analyzed, 10);
    assert!(analysis.avg_length > 0.0);
    assert!(analysis.has_uppercase_pct > 0.0);
    assert!(analysis.has_digit_pct > 0.0);
}

#[test]
fn test_analyze_password_patterns_empty() {
    let analysis = analyze_password_patterns(&[]);
    assert_eq!(analysis.total_analyzed, 0);
    assert!((analysis.avg_length - 0.0).abs() < f64::EPSILON);
}

#[test]
fn test_analyze_password_patterns_reuse() {
    let passwords = vec!["password", "password", "password", "unique1"];
    let analysis = analyze_password_patterns(&passwords);
    assert!(analysis.reuse_rate > 0.0);
}

#[test]
fn test_analyze_password_trailing_digits() {
    let passwords = vec!["admin123", "user456", "test789"];
    let analysis = analyze_password_patterns(&passwords);
    let trailing = analysis
        .common_patterns
        .iter()
        .find(|p| p.pattern == "trailing_digits");
    assert!(trailing.is_some());
    assert!((trailing.unwrap().frequency - 1.0).abs() < f64::EPSILON);
}

#[test]
fn test_analyze_password_year_pattern() {
    let passwords = vec!["Summer2024", "Winter2023", "pass"];
    let analysis = analyze_password_patterns(&passwords);
    let year = analysis
        .common_patterns
        .iter()
        .find(|p| p.pattern == "contains_year");
    assert!(year.is_some());
}

#[test]
fn test_analyze_password_lengths() {
    let passwords = vec!["ab", "abcdefghij", "abcde"];
    let analysis = analyze_password_patterns(&passwords);
    assert_eq!(analysis.min_length, 2);
    assert_eq!(analysis.max_length, 10);
}

#[test]
fn test_generate_stuffing_candidates_with_known() {
    let analysis = analyze_password_patterns(&["password", "password", "letmein"]);
    let candidates = generate_stuffing_candidates(
        &["john@acme.com", "jane@acme.com"],
        &["password", "password", "letmein"],
        &analysis,
    );
    assert_eq!(candidates.len(), 2);
    assert!(candidates[0].password_candidates.len() >= 5);
    assert!(candidates[0].confidence > 0.5);
    assert!(candidates[0].rationale.contains("known passwords"));
}

#[test]
fn test_generate_stuffing_candidates_no_known() {
    let analysis = analyze_password_patterns(&[]);
    let candidates = generate_stuffing_candidates(&["user@test.com"], &[], &analysis);
    assert_eq!(candidates.len(), 1);
    assert!(candidates[0].confidence < 0.5);
    assert!(candidates[0].rationale.contains("Generic"));
}

#[test]
fn test_generate_stuffing_includes_local_part() {
    let analysis = analyze_password_patterns(&[]);
    let candidates = generate_stuffing_candidates(&["john.doe@acme.com"], &[], &analysis);
    assert!(candidates[0]
        .password_candidates
        .iter()
        .any(|p| p.contains("john.doe")));
}

#[test]
fn test_scan_for_api_keys_aws() {
    let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE something";
    let keys = scan_for_api_keys(content, &["example.com"]);
    assert!(!keys.is_empty());
    assert_eq!(keys[0].key_type, ApiKeyType::AwsAccessKey);
}

#[test]
fn test_scan_for_api_keys_github_token() {
    let content = "token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
    let keys = scan_for_api_keys(content, &[]);
    assert!(!keys.is_empty());
    assert_eq!(keys[0].key_type, ApiKeyType::GitHubToken);
}

#[test]
fn test_scan_for_api_keys_stripe() {
    let content = "STRIPE_KEY=sk_live_1234567890abcdefghijklmn";
    let keys = scan_for_api_keys(content, &[]);
    assert!(!keys.is_empty());
    assert_eq!(keys[0].key_type, ApiKeyType::StripeKey);
}

#[test]
fn test_scan_for_api_keys_ssh_private() {
    let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ...";
    let keys = scan_for_api_keys(content, &[]);
    assert!(!keys.is_empty());
    assert_eq!(keys[0].key_type, ApiKeyType::SshPrivateKey);
}

#[test]
fn test_scan_for_api_keys_jwt() {
    let content = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let keys = scan_for_api_keys(content, &[]);
    assert!(keys.iter().any(|k| k.key_type == ApiKeyType::JwtSecret));
}

#[test]
fn test_scan_for_api_keys_domain_match() {
    let content = "key for acme.com: AKIAIOSFODNN7EXAMPLE1";
    let keys = scan_for_api_keys(content, &["acme.com"]);
    assert!(keys[0].domain_match);
    assert!(keys[0].confidence > 0.8);
}

#[test]
fn test_scan_for_api_keys_no_match() {
    let content = "nothing here, just regular text";
    let keys = scan_for_api_keys(content, &[]);
    assert!(keys.is_empty());
}

#[test]
fn test_classify_archived_token_jwt() {
    let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    assert_eq!(classify_archived_token(token), TokenType::Jwt);
}

#[test]
fn test_classify_archived_token_bearer() {
    assert_eq!(
        classify_archived_token("Bearer some-token-value"),
        TokenType::OAuthBearer
    );
}

#[test]
fn test_classify_archived_token_basic() {
    assert_eq!(
        classify_archived_token("Basic dXNlcjpwYXNz"),
        TokenType::BasicAuth
    );
}

#[test]
fn test_classify_archived_token_saml() {
    assert_eq!(
        classify_archived_token("SAML-assertion-data-here"),
        TokenType::SamlAssertion
    );
}

#[test]
fn test_classify_archived_token_api() {
    assert_eq!(
        classify_archived_token("abcdefghijklmnopqrstuvwxyz"),
        TokenType::ApiToken
    );
}

#[test]
fn test_parse_dark_web_paste_with_matches() {
    let content = "john@acme.com:password123\njane@acme.com:letmein\n";
    let finding = parse_dark_web_paste(
        content,
        &["acme.com"],
        DarkWebSource::PasteSite,
        Some("2024-01"),
    );
    assert!(finding.is_some());
    let f = finding.unwrap();
    assert!(f.domain_matches.contains(&"acme.com".to_string()));
    assert!(f.credential_count >= 2);
    assert_eq!(f.source_type, DarkWebSource::PasteSite);
}

#[test]
fn test_parse_dark_web_paste_no_match() {
    let content = "nothing relevant here at all";
    let finding = parse_dark_web_paste(content, &["acme.com"], DarkWebSource::ForumPost, None);
    assert!(finding.is_none());
}

#[test]
fn test_parse_dark_web_paste_long_content_preview() {
    let content = "a".repeat(500) + " user@acme.com:pass";
    let finding = parse_dark_web_paste(&content, &["acme.com"], DarkWebSource::PasteSite, None);
    assert!(finding.is_some());
    assert!(finding.unwrap().content_preview.len() <= 210);
}

#[test]
fn test_build_credential_intel_report() {
    let creds = vec![CredentialEntry {
        identifier: "user@test.com".to_string(),
        credential: "pass".to_string(),
        format: DumpFormat::EmailPassword,
        source: None,
    }];
    let api_keys = vec![DiscoveredApiKey {
        key_type: ApiKeyType::AwsAccessKey,
        key_value: "AKIAIOSFODNN7EXAMPLE".to_string(),
        source_url: String::new(),
        domain_match: true,
        is_active: None,
        confidence: 0.85,
    }];
    let report =
        build_credential_intel_report("test.com", creds, None, vec![], api_keys, vec![], vec![]);
    assert_eq!(report.total_credentials_found, 1);
    assert!(report.risk_score > 0.0);
    assert_eq!(report.target_domain, "test.com");
}

#[test]
fn test_build_credential_intel_report_empty() {
    let report =
        build_credential_intel_report("empty.com", vec![], None, vec![], vec![], vec![], vec![]);
    assert_eq!(report.total_credentials_found, 0);
    assert!((report.risk_score - 0.0).abs() < f64::EPSILON);
}

#[test]
fn test_dump_format_display() {
    assert_eq!(DumpFormat::EmailPassword.to_string(), "email:password");
    assert_eq!(DumpFormat::EmailHash.to_string(), "email:hash");
    assert_eq!(DumpFormat::ComboList.to_string(), "combo_list");
}

#[test]
fn test_hash_type_display() {
    assert_eq!(HashType::Bcrypt.to_string(), "bcrypt");
    assert_eq!(HashType::Sha256.to_string(), "SHA-256");
}

#[test]
fn test_api_key_type_display() {
    assert_eq!(ApiKeyType::AwsAccessKey.to_string(), "AWS Access Key");
    assert_eq!(ApiKeyType::GitHubToken.to_string(), "GitHub Token");
}

#[test]
fn test_token_type_display() {
    assert_eq!(TokenType::Jwt.to_string(), "JWT");
    assert_eq!(TokenType::OAuthBearer.to_string(), "OAuth Bearer");
}

#[test]
fn test_dark_web_source_display() {
    assert_eq!(DarkWebSource::PasteSite.to_string(), "Paste Site");
    assert_eq!(
        DarkWebSource::TelegramChannel.to_string(),
        "Telegram Channel"
    );
}
