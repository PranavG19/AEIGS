use super::email_validator_v3::*;

#[test]
fn parse_smtp_response_250() {
    let resp = parse_smtp_response("250 2.1.5 OK");
    assert_eq!(resp.code, 250);
    assert_eq!(resp.enhanced_code, Some("2.1.5".to_string()));
    assert!(resp.is_positive);
    assert!(!resp.is_temporary);
}

#[test]
fn parse_smtp_response_550() {
    let resp = parse_smtp_response("550 5.1.1 User not found");
    assert_eq!(resp.code, 550);
    assert!(!resp.is_positive);
    assert!(!resp.is_temporary);
}

#[test]
fn parse_smtp_response_450_greylisting() {
    let resp = parse_smtp_response("450 4.7.1 Please try again later");
    assert_eq!(resp.code, 450);
    assert!(resp.is_temporary);
    assert!(!resp.is_positive);
}

#[test]
fn parse_smtp_response_no_code() {
    let resp = parse_smtp_response("unexpected garbage");
    assert_eq!(resp.code, 0);
}

#[test]
fn classify_smtp_valid() {
    assert_eq!(classify_smtp_response(250), EmailValidationStatus::Valid);
    assert_eq!(classify_smtp_response(251), EmailValidationStatus::Valid);
}

#[test]
fn classify_smtp_invalid() {
    assert_eq!(classify_smtp_response(550), EmailValidationStatus::Invalid);
    assert_eq!(classify_smtp_response(553), EmailValidationStatus::Invalid);
}

#[test]
fn classify_smtp_greylisted() {
    assert_eq!(
        classify_smtp_response(450),
        EmailValidationStatus::Greylisted
    );
    assert_eq!(
        classify_smtp_response(451),
        EmailValidationStatus::Greylisted
    );
}

#[test]
fn classify_smtp_refused() {
    assert_eq!(classify_smtp_response(421), EmailValidationStatus::Refused);
}

#[test]
fn classify_smtp_timeout() {
    assert_eq!(classify_smtp_response(0), EmailValidationStatus::Timeout);
}

#[test]
fn detect_catch_all_positive() {
    let responses: Vec<(String, u16)> = (0..5)
        .map(|i| (format!("random{}@test.com", i), 250))
        .collect();
    let result = detect_catch_all("test.com", &responses, vec!["mx.test.com".to_string()]);
    assert!(result.is_catch_all);
    assert_eq!(result.accepted_count, 5);
    assert_eq!(result.confidence, ValidationConfidence::High);
}

#[test]
fn detect_catch_all_negative() {
    let responses = vec![
        ("rand1@test.com".to_string(), 550u16),
        ("rand2@test.com".to_string(), 550),
        ("rand3@test.com".to_string(), 550),
    ];
    let result = detect_catch_all("test.com", &responses, vec![]);
    assert!(!result.is_catch_all);
    assert_eq!(result.rejected_count, 3);
}

#[test]
fn detect_catch_all_empty() {
    let result = detect_catch_all("test.com", &[], vec![]);
    assert!(!result.is_catch_all);
}

#[test]
fn analyze_timing_vulnerable() {
    let valid = vec![500, 520, 480, 510];
    let invalid = vec![100, 120, 110, 105];
    let profile = analyze_smtp_timing(&valid, &invalid, 490);
    assert!(profile.is_timing_vulnerable);
    assert!(profile.timing_delta_ms.unwrap() > 300);
}

#[test]
fn analyze_timing_not_vulnerable() {
    let valid = vec![200, 210, 205];
    let invalid = vec![195, 200, 198];
    let profile = analyze_smtp_timing(&valid, &invalid, 200);
    assert!(!profile.is_timing_vulnerable);
}

#[test]
fn analyze_timing_empty_samples() {
    let profile = analyze_smtp_timing(&[], &[], 100);
    assert!(!profile.is_timing_vulnerable);
    assert!(profile.valid_addr_avg_ms.is_none());
    assert!(profile.invalid_addr_avg_ms.is_none());
}

#[test]
fn detect_greylisting_positive() {
    let result = detect_greylisting(
        "test.com",
        450,
        "450 4.7.1 Try again later",
        Some(250),
        Some("250 OK"),
        300,
    );
    assert!(result.is_greylisting);
    assert_eq!(result.confidence, ValidationConfidence::High);
}

#[test]
fn detect_greylisting_false() {
    let result = detect_greylisting("test.com", 250, "250 OK", None, None, 0);
    assert!(!result.is_greylisting);
    assert_eq!(result.confidence, ValidationConfidence::Definitive);
}

#[test]
fn validate_email_normal_valid() {
    let result = validate_email("user@test.com", 250, "250 2.1.5 OK", None, None, None);
    assert_eq!(result.status, EmailValidationStatus::Valid);
    assert_eq!(result.confidence, ValidationConfidence::High);
    assert!(result
        .validation_methods
        .contains(&"SMTP RCPT TO".to_string()));
}

#[test]
fn validate_email_catch_all_domain() {
    let catch_all = CatchAllResult {
        domain: "test.com".to_string(),
        is_catch_all: true,
        test_addresses_tried: 5,
        accepted_count: 5,
        rejected_count: 0,
        confidence: ValidationConfidence::High,
        mx_records: vec![],
    };
    let result = validate_email("user@test.com", 250, "250 OK", Some(&catch_all), None, None);
    assert_eq!(result.status, EmailValidationStatus::CatchAll);
}

#[test]
fn validate_email_invalid() {
    let result = validate_email(
        "noone@test.com",
        550,
        "550 5.1.1 User not found",
        None,
        None,
        None,
    );
    assert_eq!(result.status, EmailValidationStatus::Invalid);
    assert_eq!(result.confidence, ValidationConfidence::Definitive);
}

#[test]
fn generate_catch_all_test_addresses_count() {
    let addrs = generate_catch_all_test_addresses("test.com", 5);
    assert_eq!(addrs.len(), 5);
    for addr in &addrs {
        assert!(addr.ends_with("@test.com"));
    }
    let unique: std::collections::HashSet<&String> = addrs.iter().collect();
    assert_eq!(unique.len(), 5);
}

#[test]
fn build_validation_report_counts() {
    let results = vec![
        EmailValidationResult {
            email: "a@t.com".into(),
            status: EmailValidationStatus::Valid,
            confidence: ValidationConfidence::High,
            smtp_response: None,
            catch_all: None,
            greylist: None,
            timing_profile: None,
            mx_server: None,
            validation_methods: vec![],
        },
        EmailValidationResult {
            email: "b@t.com".into(),
            status: EmailValidationStatus::Invalid,
            confidence: ValidationConfidence::Definitive,
            smtp_response: None,
            catch_all: None,
            greylist: None,
            timing_profile: None,
            mx_server: None,
            validation_methods: vec![],
        },
        EmailValidationResult {
            email: "c@t.com".into(),
            status: EmailValidationStatus::Valid,
            confidence: ValidationConfidence::High,
            smtp_response: None,
            catch_all: None,
            greylist: None,
            timing_profile: None,
            mx_server: None,
            validation_methods: vec![],
        },
    ];
    let report = build_validation_report("t.com", results, None, None);
    assert_eq!(report.total_checked, 3);
    assert_eq!(report.valid_count, 2);
    assert_eq!(report.invalid_count, 1);
    assert_eq!(report.status_distribution[&EmailValidationStatus::Valid], 2);
}

#[test]
fn email_validation_status_display() {
    assert_eq!(EmailValidationStatus::Valid.to_string(), "Valid");
    assert_eq!(EmailValidationStatus::CatchAll.to_string(), "Catch-All");
    assert_eq!(EmailValidationStatus::Greylisted.to_string(), "Greylisted");
}

#[test]
fn validation_confidence_ordering() {
    assert!(ValidationConfidence::Definitive > ValidationConfidence::High);
    assert!(ValidationConfidence::High > ValidationConfidence::Medium);
    assert!(ValidationConfidence::Medium > ValidationConfidence::Low);
}
