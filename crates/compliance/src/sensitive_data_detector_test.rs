use super::sensitive_data_detector::*;

#[test]
fn detects_ssn_pattern() {
    let body = r#"{"ssn": "123-45-6789"}"#;
    let findings = detect_sensitive_data(body);
    assert!(findings.iter().any(|f| f.kind == SensitiveDataKind::Ssn));
    let ssn = findings
        .iter()
        .find(|f| f.kind == SensitiveDataKind::Ssn)
        .unwrap();
    assert_eq!(ssn.matched_text, "123-45-6789");
    assert_eq!(ssn.category, SensitiveDataCategory::Pii);
}

#[test]
fn rejects_invalid_ssn_area_000() {
    let body = r#"{"ssn": "000-45-6789"}"#;
    let findings = detect_sensitive_data(body);
    assert!(findings.iter().all(|f| f.kind != SensitiveDataKind::Ssn));
}

#[test]
fn rejects_invalid_ssn_area_666() {
    let body = r#"{"ssn": "666-45-6789"}"#;
    let findings = detect_sensitive_data(body);
    assert!(findings.iter().all(|f| f.kind != SensitiveDataKind::Ssn));
}

#[test]
fn rejects_invalid_ssn_area_900_plus() {
    let body = r#"{"ssn": "900-45-6789"}"#;
    let findings = detect_sensitive_data(body);
    assert!(findings.iter().all(|f| f.kind != SensitiveDataKind::Ssn));
}

#[test]
fn luhn_valid_visa() {
    assert!(luhn_validate("4111111111111111"));
}

#[test]
fn luhn_valid_mastercard() {
    assert!(luhn_validate("5500000000000004"));
}

#[test]
fn luhn_invalid_number() {
    assert!(!luhn_validate("4111111111111112"));
}

#[test]
fn luhn_rejects_short_number() {
    assert!(!luhn_validate("123"));
}

#[test]
fn detects_credit_card_with_luhn() {
    let body = "Card on file: 4111111111111111 for user";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::CreditCard)
    );
}

#[test]
fn rejects_invalid_credit_card() {
    let body = "Card on file: 4111111111111112 for user";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .all(|f| f.kind != SensitiveDataKind::CreditCard)
    );
}

#[test]
fn credit_card_has_pci_dss_mapping() {
    let body = "Card: 4111111111111111 charged";
    let findings = detect_sensitive_data(body);
    let cc = findings
        .iter()
        .find(|f| f.kind == SensitiveDataKind::CreditCard)
        .unwrap();
    assert!(cc.regulatory.pci_dss.is_some());
    assert!(cc.regulatory.pci_dss.as_ref().unwrap().contains("3.4"));
}

#[test]
fn detects_phone_number() {
    let body = "Contact: (555) 123-4567 for support";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::PhoneNumber)
    );
}

#[test]
fn detects_email_address() {
    let body = "Send to john.doe@company.org immediately";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::EmailAddress)
    );
}

#[test]
fn filters_example_com_emails() {
    let body = "Send to user@example.com for info";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .all(|f| f.kind != SensitiveDataKind::EmailAddress)
    );
}

#[test]
fn detects_bank_account() {
    let body = "Account: 12345678901 balance $500";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::BankAccountNumber)
    );
}

#[test]
fn detects_routing_number() {
    let body = "Routing: 021000021 for wire";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::RoutingNumber)
    );
}

#[test]
fn rejects_invalid_routing_number() {
    let body = "Routing: 123456789 invalid";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .all(|f| f.kind != SensitiveDataKind::RoutingNumber)
    );
}

#[test]
fn detects_iban() {
    let body = "Transfer to GB29NWBK60161331926819 completed";
    let findings = detect_sensitive_data(body);
    assert!(findings.iter().any(|f| f.kind == SensitiveDataKind::Iban));
}

#[test]
fn rejects_invalid_iban_checksum() {
    let body = "Transfer to GB00NWBK60161331926819 completed";
    let findings = detect_sensitive_data(body);
    assert!(findings.iter().all(|f| f.kind != SensitiveDataKind::Iban));
}

#[test]
fn detects_icd10_code() {
    let body = "Diagnosis: J45.0 confirmed by specialist";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::Icd10Code)
    );
}

#[test]
fn icd10_has_hipaa_mapping() {
    let body = "Diagnosis: J45.0 confirmed";
    let findings = detect_sensitive_data(body);
    let f = findings
        .iter()
        .find(|f| f.kind == SensitiveDataKind::Icd10Code)
        .unwrap();
    assert!(f.regulatory.hipaa.is_some());
}

#[test]
fn detects_prescription() {
    let body = "Rx: Amoxicillin 500 mg twice daily";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::PrescriptionPattern)
    );
}

#[test]
fn detects_password_in_url() {
    let body = "https://app.internal/login?password=s3cretP@ss&user=admin";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::PasswordInUrl)
    );
}

#[test]
fn detects_token_in_error() {
    let body =
        "Error: authentication failed for token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::TokenInError)
    );
}

#[test]
fn detects_session_id_in_log() {
    let body = "session_id=abc123def456ghi789jkl012mno345pq active";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::SessionIdInLog)
    );
}

#[test]
fn detects_private_ip_10_range() {
    let body = "Server: 10.0.1.55 responding on port 8080";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::PrivateIpAddress)
    );
}

#[test]
fn detects_private_ip_192_168() {
    let body = "Gateway: 192.168.1.1 is unreachable";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::PrivateIpAddress)
    );
}

#[test]
fn detects_internal_hostname() {
    let body = "Connected to db-primary.internal on port 5432";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::Hostname)
    );
}

#[test]
fn detects_file_path_unix() {
    let body = "Config loaded from /etc/nginx/sites-enabled/app.conf";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::FilePath)
    );
}

#[test]
fn detects_file_path_windows() {
    let body = r"Error in C:\Users\admin\AppData\config.ini";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::FilePath)
    );
}

#[test]
fn detects_java_stack_trace() {
    let body = "at com.acme.UserService.handle(UserService.java:42)";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::StackTrace)
    );
}

#[test]
fn detects_python_stack_trace() {
    let body = r#"File "/app/server.py", line 128"#;
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::StackTrace)
    );
}

#[test]
fn detects_aws_access_key() {
    let body = "aws_access_key_id = AKIAIOSFODNN7PRODCTN";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::AwsAccessKey)
    );
}

#[test]
fn detects_aws_secret_key() {
    let body = "aws_secret_access_key=wJalrXUtnFEMIK7MDENG/bPxRfiCYPRODUCTKEYa";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::AwsSecretKey)
    );
}

#[test]
fn detects_generic_api_key() {
    let body = "api_key: sk_live_abcdefghijklmnopqrstuvwxyz1234";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::GenericApiKey)
    );
}

#[test]
fn detects_database_connection_string() {
    let body = "Connected to postgresql://admin:pass@db.internal:5432/production";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::DatabaseConnectionString)
    );
}

#[test]
fn detects_gps_coordinates() {
    let body = r#"{"latitude": 40.7128, "longitude": -74.0060}"#;
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::GpsCoordinates)
    );
}

#[test]
fn detects_street_address() {
    let body = "Ship to 742 Evergreen Terrace Drive";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::StreetAddress)
    );
}

#[test]
fn skips_test_document_entirely() {
    let body = "This is a test. SSN: 123-45-6789. This is a test.";
    let findings = detect_sensitive_data(body);
    assert!(findings.is_empty());
}

#[test]
fn false_positive_filter_skips_example_context() {
    let body = "A long response body with real data.\n\n\n\n\n\nThe example SSN is 123-45-6789 shown here.";
    let findings = detect_sensitive_data(body);
    assert!(findings.iter().all(|f| f.kind != SensitiveDataKind::Ssn));
}

#[test]
fn all_eight_categories_covered() {
    let categories = [
        SensitiveDataCategory::Pii,
        SensitiveDataCategory::Financial,
        SensitiveDataCategory::Medical,
        SensitiveDataCategory::Authentication,
        SensitiveDataCategory::InternalInfrastructure,
        SensitiveDataCategory::ApiKeyOrSecret,
        SensitiveDataCategory::Geolocation,
        SensitiveDataCategory::PersonalContact,
    ];
    assert_eq!(categories.len(), 8);
    for cat in &categories {
        let _ = format!("{}", cat);
    }
}

#[test]
fn regulatory_mapping_present_on_all_findings() {
    let body = concat!(
        "SSN: 123-45-6789 ",
        "Card: 4111111111111111 ",
        "Diagnosis: J45.0 ",
        "password=hunter2abc ",
        "Server: 10.0.1.55 ",
        "api_key: sk_live_abcdefghijklmnopqrstuvwxyz1234 ",
        "latitude: 40.71284444 ",
        "john.doe@company.org ",
    );
    let findings = detect_sensitive_data(body);
    for finding in &findings {
        let reg = &finding.regulatory;
        let has_any = reg.gdpr.is_some() || reg.pci_dss.is_some() || reg.hipaa.is_some();
        assert!(
            has_any,
            "Finding {:?} has no regulatory mapping",
            finding.kind
        );
    }
}

#[test]
fn display_implementations_complete() {
    let display_str = format!("{}", SensitiveDataKind::Ssn);
    assert_eq!(display_str, "Social Security Number");
    let cat_str = format!("{}", SensitiveDataCategory::Pii);
    assert_eq!(cat_str, "Personally Identifiable Information");
}

#[test]
fn iban_validation_rejects_too_short() {
    let body = "Transfer to GB29NWBK601 completed";
    let findings = detect_sensitive_data(body);
    assert!(findings.iter().all(|f| f.kind != SensitiveDataKind::Iban));
}

#[test]
fn detects_mongodb_connection_string() {
    let body = "mongodb+srv://user:pass@cluster0.abcde.mongodb.net/mydb";
    let findings = detect_sensitive_data(body);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == SensitiveDataKind::DatabaseConnectionString)
    );
}

#[test]
fn luhn_with_dashes() {
    assert!(luhn_validate("4111-1111-1111-1111"));
}

#[test]
fn luhn_with_spaces() {
    assert!(luhn_validate("4111 1111 1111 1111"));
}

#[test]
fn ssn_regulatory_has_gdpr_and_hipaa() {
    let body = "Record: 234-56-7890 stored";
    let findings = detect_sensitive_data(body);
    let ssn = findings
        .iter()
        .find(|f| f.kind == SensitiveDataKind::Ssn)
        .unwrap();
    assert!(ssn.regulatory.gdpr.is_some());
    assert!(ssn.regulatory.hipaa.is_some());
    assert!(ssn.regulatory.pci_dss.is_none());
}
