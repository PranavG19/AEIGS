use super::breach_correlator::*;

#[test]
fn sha1_hash_known_value() {
    let hash = sha1_hash("password");
    assert_eq!(hash, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
}

#[test]
fn sha1_hash_empty_string() {
    let hash = sha1_hash("");
    assert_eq!(hash, "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
}

#[test]
fn extract_prefix_returns_first_five() {
    let hash = sha1_hash("password");
    let prefix = extract_prefix(&hash);
    assert_eq!(prefix, "5BAA6");
    assert_eq!(prefix.len(), 5);
}

#[test]
fn extract_suffix_returns_remainder() {
    let hash = sha1_hash("password");
    let suffix = extract_suffix(&hash);
    assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
}

#[test]
fn parse_hibp_range_response_valid() {
    let body = "0018A45C4D1DEF81644B54AB7F969B88D65:10\r\n\
                00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n\
                011053FD0102E94D6AE2F8B83D76FAF94F6:1\r\n";
    let matches = parse_hibp_range_response(body);
    assert_eq!(matches.len(), 3);
    assert_eq!(
        matches[0].hash_suffix,
        "0018A45C4D1DEF81644B54AB7F969B88D65"
    );
    assert_eq!(matches[0].occurrence_count, 10);
    assert_eq!(matches[2].occurrence_count, 1);
}

#[test]
fn parse_hibp_range_response_empty() {
    let matches = parse_hibp_range_response("");
    assert!(matches.is_empty());
}

#[test]
fn parse_hibp_range_response_malformed_lines() {
    let body = "badline\n\n:123\nABC:notanumber\nDEF:456\n";
    let matches = parse_hibp_range_response(body);
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[1].hash_suffix, "DEF");
    assert_eq!(matches[1].occurrence_count, 456);
}

#[test]
fn check_password_in_range_found() {
    let sha1 = sha1_hash("test123");
    let suffix = extract_suffix(&sha1).to_uppercase();
    let body = format!("{}:5234\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n", suffix);
    let result = check_password_in_range("test123", &body);
    assert!(result.found);
    assert_eq!(result.occurrence_count, 5234);
    assert_eq!(result.severity, BreachSeverity::High);
}

#[test]
fn check_password_in_range_not_found() {
    let body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n";
    let result = check_password_in_range("my_very_unique_password_xyz_123!", &body);
    assert!(!result.found);
    assert_eq!(result.occurrence_count, 0);
    assert_eq!(result.severity, BreachSeverity::Info);
}

#[test]
fn classify_password_severity_ranges() {
    assert_eq!(classify_password_severity(0), BreachSeverity::Info);
    assert_eq!(classify_password_severity(1), BreachSeverity::Low);
    assert_eq!(classify_password_severity(10), BreachSeverity::Low);
    assert_eq!(classify_password_severity(11), BreachSeverity::Medium);
    assert_eq!(classify_password_severity(100), BreachSeverity::Medium);
    assert_eq!(classify_password_severity(101), BreachSeverity::High);
    assert_eq!(classify_password_severity(10_000), BreachSeverity::High);
    assert_eq!(classify_password_severity(10_001), BreachSeverity::Critical);
}

#[test]
fn build_hibp_range_url_format() {
    let url = build_hibp_range_url("5BAA6");
    assert_eq!(url, "https://api.pwnedpasswords.com/range/5BAA6");
}

#[test]
fn build_hibp_breach_url_format() {
    let url = build_hibp_breach_url("test@example.com");
    assert!(url.contains("test@example.com"));
    assert!(url.contains("truncateResponse=false"));
}

#[test]
fn parse_breach_response_valid_json() {
    let json = r#"[
        {
            "Name": "Adobe",
            "BreachDate": "2013-10-04",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": true,
            "IsSensitive": false,
            "PwnCount": 152445165
        },
        {
            "Name": "LinkedIn",
            "BreachDate": "2012-05-05",
            "DataClasses": ["Email addresses", "Password hashes"],
            "IsVerified": true,
            "IsSensitive": false,
            "PwnCount": 164611595
        }
    ]"#;
    let records = parse_breach_response(json);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].breach_name, "Adobe");
    assert_eq!(records[0].exposure_type, ExposureType::PlaintextPassword);
    assert!(records[0].is_verified);
    assert_eq!(records[1].breach_name, "LinkedIn");
    assert_eq!(records[1].exposure_type, ExposureType::PasswordHash);
}

#[test]
fn parse_breach_response_empty_json() {
    let records = parse_breach_response("[]");
    assert!(records.is_empty());
}

#[test]
fn parse_breach_response_invalid_json() {
    let records = parse_breach_response("not json");
    assert!(records.is_empty());
}

#[test]
fn classify_exposure_type_variants() {
    assert_eq!(
        classify_exposure_type(&["Passwords".to_string(), "Email addresses".to_string()]),
        ExposureType::PlaintextPassword
    );
    assert_eq!(
        classify_exposure_type(&["Password hashes".to_string()]),
        ExposureType::PasswordHash
    );
    assert_eq!(
        classify_exposure_type(&["Email addresses".to_string()]),
        ExposureType::EmailOnly
    );
    assert_eq!(
        classify_exposure_type(&["IP addresses".to_string()]),
        ExposureType::DatabaseDump
    );
}

#[test]
fn correlate_email_breaches_multiple() {
    let json = r#"[
        {"Name":"Adobe","BreachDate":"2013-10-04","DataClasses":["Passwords","Email addresses"],"IsVerified":true,"IsSensitive":false,"PwnCount":152000000},
        {"Name":"LinkedIn","BreachDate":"2012-05-05","DataClasses":["Password hashes"],"IsVerified":true,"IsSensitive":false,"PwnCount":164000000},
        {"Name":"Dropbox","BreachDate":"2012-07-01","DataClasses":["Passwords"],"IsVerified":true,"IsSensitive":false,"PwnCount":68000000}
    ]"#;
    let corr = correlate_email_breaches("user@example.com", json);
    assert_eq!(corr.email, "user@example.com");
    assert_eq!(corr.domain, "example.com");
    assert_eq!(corr.total_exposures, 3);
    assert_eq!(corr.severity, BreachSeverity::Medium);
    assert!(corr.password_reuse_likelihood > 0.0);
    assert!(!corr.recommended_actions.is_empty());
}

#[test]
fn correlate_email_breaches_none() {
    let corr = correlate_email_breaches("clean@example.com", "[]");
    assert_eq!(corr.total_exposures, 0);
    assert_eq!(corr.severity, BreachSeverity::Info);
    assert!(corr.recommended_actions.is_empty());
}

#[test]
fn correlate_email_sensitive_breach() {
    let json = r#"[
        {"Name":"AshleyMadison","BreachDate":"2015-07-01","DataClasses":["Email addresses"],"IsVerified":true,"IsSensitive":true,"PwnCount":30000000}
    ]"#;
    let corr = correlate_email_breaches("user@example.com", json);
    assert!(corr.breaches[0].is_sensitive);
    assert!(corr
        .recommended_actions
        .iter()
        .any(|a| a.contains("phishing")));
}

#[test]
fn check_combo_entry_both_compromised() {
    let sha1 = sha1_hash("password123");
    let suffix = extract_suffix(&sha1).to_uppercase();
    let range_resp = format!("{}:9999\n", suffix);
    let breach_json = r#"[{"Name":"TestBreach","BreachDate":"2020-01-01","DataClasses":["Passwords"],"IsVerified":true,"IsSensitive":false,"PwnCount":100}]"#;

    let entry = ComboEntry {
        email: "victim@corp.com".to_string(),
        password_or_hash: "password123".to_string(),
        source: Some("darkweb_dump".to_string()),
    };

    let result = check_combo_entry(&entry, &range_resp, breach_json);
    assert!(result.password_compromised);
    assert_eq!(result.email_in_breaches, vec!["TestBreach".to_string()]);
    assert_eq!(result.severity, BreachSeverity::Critical);
}

#[test]
fn check_combo_entry_password_only() {
    let sha1 = sha1_hash("letmein");
    let suffix = extract_suffix(&sha1).to_uppercase();
    let range_resp = format!("{}:500\n", suffix);

    let entry = ComboEntry {
        email: "user@safe.com".to_string(),
        password_or_hash: "letmein".to_string(),
        source: None,
    };

    let result = check_combo_entry(&entry, &range_resp, "[]");
    assert!(result.password_compromised);
    assert!(result.email_in_breaches.is_empty());
    assert_eq!(result.severity, BreachSeverity::High);
}

#[test]
fn build_breach_timeline_aggregation() {
    let c1 = EmailBreachCorrelation {
        email: "a@test.com".to_string(),
        domain: "test.com".to_string(),
        breaches: vec![
            BreachRecord {
                breach_name: "B1".into(),
                breach_date: "2020-01-01".into(),
                exposure_type: ExposureType::EmailOnly,
                data_classes: vec![],
                is_verified: true,
                is_sensitive: false,
                pwn_count: 100,
            },
            BreachRecord {
                breach_name: "B2".into(),
                breach_date: "2021-06-15".into(),
                exposure_type: ExposureType::PasswordHash,
                data_classes: vec![],
                is_verified: true,
                is_sensitive: false,
                pwn_count: 200,
            },
        ],
        total_exposures: 2,
        severity: BreachSeverity::Low,
        password_reuse_likelihood: 0.1,
        recommended_actions: vec![],
    };
    let c2 = EmailBreachCorrelation {
        email: "b@test.com".to_string(),
        domain: "test.com".to_string(),
        breaches: vec![BreachRecord {
            breach_name: "B1".into(),
            breach_date: "2020-01-01".into(),
            exposure_type: ExposureType::EmailOnly,
            data_classes: vec![],
            is_verified: true,
            is_sensitive: false,
            pwn_count: 100,
        }],
        total_exposures: 1,
        severity: BreachSeverity::Low,
        password_reuse_likelihood: 0.0,
        recommended_actions: vec![],
    };

    let timeline = build_breach_timeline(&[c1, c2]);
    assert_eq!(timeline.len(), 2);
    let entry_2020 = timeline.iter().find(|(d, _)| d == "2020-01-01").unwrap();
    assert_eq!(entry_2020.1, 2);
}

#[test]
fn build_correlation_report_full() {
    let corr = EmailBreachCorrelation {
        email: "admin@corp.com".to_string(),
        domain: "corp.com".to_string(),
        breaches: vec![BreachRecord {
            breach_name: "MegaBreach".into(),
            breach_date: "2023-01-15".into(),
            exposure_type: ExposureType::PlaintextPassword,
            data_classes: vec!["Passwords".into()],
            is_verified: true,
            is_sensitive: false,
            pwn_count: 50_000_000,
        }],
        total_exposures: 1,
        severity: BreachSeverity::Low,
        password_reuse_likelihood: 0.1,
        recommended_actions: vec!["Reset password".into()],
    };

    let combo = ComboCheckResult {
        email: "admin@corp.com".to_string(),
        password_compromised: true,
        password_occurrences: 5000,
        email_in_breaches: vec!["MegaBreach".to_string()],
        severity: BreachSeverity::Critical,
    };

    let report = build_correlation_report("corp.com", vec![corr], vec![combo]);
    assert_eq!(report.target_domain, "corp.com");
    assert_eq!(report.total_emails_checked, 1);
    assert_eq!(report.total_compromised, 1);
    assert_eq!(report.overall_risk, BreachSeverity::Critical);
    assert!(!report.top_breaches.is_empty());
    assert_eq!(report.top_breaches[0].0, "MegaBreach");
}

#[test]
fn compute_overall_risk_picks_max() {
    let corr_low = EmailBreachCorrelation {
        email: "a@t.com".into(),
        domain: "t.com".into(),
        breaches: vec![],
        total_exposures: 1,
        severity: BreachSeverity::Low,
        password_reuse_likelihood: 0.0,
        recommended_actions: vec![],
    };
    let combo_high = ComboCheckResult {
        email: "a@t.com".into(),
        password_compromised: true,
        password_occurrences: 100,
        email_in_breaches: vec![],
        severity: BreachSeverity::High,
    };

    let risk = compute_overall_risk(&[corr_low], &[combo_high]);
    assert_eq!(risk, BreachSeverity::High);
}
