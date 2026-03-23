use crate::security_txt::*;

// ── Existing parse_security_txt tests ──────────────────────────────

#[test]
fn parse_security_txt_extracts_fields() {
    let body = "Contact: mailto:security@example.com\nExpires: 2025-12-31T23:59:59z\n";
    let fields = parse_security_txt(body);
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].0, "contact");
    assert_eq!(fields[0].1, "mailto:security@example.com");
    assert_eq!(fields[1].0, "expires");
}

#[test]
fn parse_security_txt_skips_comments_and_blanks() {
    let body = "# This is a comment\n\nContact: mailto:sec@example.com\n# Another comment\n";
    let fields = parse_security_txt(body);
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].0, "contact");
}

#[test]
fn parse_security_txt_handles_multiple_contacts() {
    let body = "\
Contact: mailto:security@example.com\n\
Contact: https://hackerone.com/example\n\
Preferred-Languages: en\n\
Canonical: https://example.com/.well-known/security.txt\n\
Policy: https://example.com/security-policy\n\
Hiring: https://example.com/jobs\n";
    let fields = parse_security_txt(body);
    assert_eq!(fields.len(), 6);
    let contacts: Vec<_> = fields.iter().filter(|(k, _)| k == "contact").collect();
    assert_eq!(contacts.len(), 2);
}

#[test]
fn parse_security_txt_skips_empty_values() {
    let body = "Contact:\nExpires: 2025-12-31T23:59:59z\n";
    let fields = parse_security_txt(body);
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].0, "expires");
}

#[test]
fn security_txt_to_operations_creates_config_node() {
    let info = SecurityTxtInfo {
        fields: vec![
            ("contact".to_string(), "mailto:sec@example.com".to_string()),
            ("expires".to_string(), "2025-12-31T23:59:59z".to_string()),
        ],
        path: ".well-known/security.txt".to_string(),
    };
    let mut seq = 0;
    let ops = security_txt_to_operations(&info, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode {
            node_type,
            properties,
        } => {
            assert_eq!(*node_type, aegis_protocol::node::NodeType::Config);
            let source = properties.iter().find(|(k, _)| k == "source").unwrap();
            assert_eq!(source.1, "security_txt");
            let path_prop = properties.iter().find(|(k, _)| k == "path").unwrap();
            assert_eq!(path_prop.1, ".well-known/security.txt");
            assert_eq!(properties.len(), 4); // 2 fields + source + path
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn fetch_security_txt_skips_localhost() {
    let result = fetch_security_txt("http://localhost:8080");
    assert!(result.is_none());
}

#[test]
fn fetch_security_txt_skips_loopback() {
    let result = fetch_security_txt("http://127.0.0.1");
    assert!(result.is_none());
}

#[test]
fn parse_security_txt_handles_colons_in_values() {
    let body = "Contact: https://example.com:8443/security\n";
    let fields = parse_security_txt(body);
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].1, "https://example.com:8443/security");
}

// ── SecurityTxtIssue Display tests ─────────────────────────────────

#[test]
fn display_missing_security_txt() {
    let issue = SecurityTxtIssue::MissingSecurityTxt;
    assert_eq!(issue.to_string(), "No security.txt file found");
}

#[test]
fn display_missing_contact() {
    let issue = SecurityTxtIssue::MissingContact;
    assert_eq!(
        issue.to_string(),
        "security.txt missing required Contact field"
    );
}

#[test]
fn display_missing_expires() {
    let issue = SecurityTxtIssue::MissingExpires;
    assert_eq!(
        issue.to_string(),
        "security.txt missing required Expires field"
    );
}

#[test]
fn display_expired_file() {
    let issue = SecurityTxtIssue::ExpiredFile {
        expires: "2024-01-01T00:00:00z".to_string(),
    };
    let s = issue.to_string();
    assert!(s.contains("in the past"));
    assert!(s.contains("2024-01-01T00:00:00z"));
}

#[test]
fn display_http_not_https() {
    let issue = SecurityTxtIssue::HttpNotHttps;
    assert_eq!(
        issue.to_string(),
        "security.txt served over HTTP instead of HTTPS"
    );
}

#[test]
fn display_wrong_path() {
    let issue = SecurityTxtIssue::WrongPath;
    let s = issue.to_string();
    assert!(s.contains("/security.txt"));
    assert!(s.contains("/.well-known/security.txt"));
}

#[test]
fn display_missing_canonical() {
    let issue = SecurityTxtIssue::MissingCanonical;
    assert!(issue.to_string().contains("Canonical"));
}

#[test]
fn display_missing_encryption() {
    let issue = SecurityTxtIssue::MissingEncryption;
    assert!(issue.to_string().contains("Encryption"));
}

#[test]
fn display_invalid_contact_format() {
    let issue = SecurityTxtIssue::InvalidContactFormat {
        contact: "tel:+1-555-0100".to_string(),
    };
    let s = issue.to_string();
    assert!(s.contains("mailto:"));
    assert!(s.contains("https:"));
    assert!(s.contains("tel:+1-555-0100"));
}

#[test]
fn display_duplicate_expires() {
    let issue = SecurityTxtIssue::DuplicateExpires;
    assert!(issue.to_string().contains("multiple Expires"));
}

// ── security_txt_severity tests ────────────────────────────────────

#[test]
fn severity_http_not_https_is_highest() {
    assert_eq!(security_txt_severity(&SecurityTxtIssue::HttpNotHttps), 7.0);
}

#[test]
fn severity_missing_contact() {
    assert_eq!(
        security_txt_severity(&SecurityTxtIssue::MissingContact),
        6.0
    );
}

#[test]
fn severity_missing_expires() {
    assert_eq!(
        security_txt_severity(&SecurityTxtIssue::MissingExpires),
        5.0
    );
}

#[test]
fn severity_expired_file() {
    let issue = SecurityTxtIssue::ExpiredFile {
        expires: "2020-01-01T00:00:00z".to_string(),
    };
    assert_eq!(security_txt_severity(&issue), 5.0);
}

#[test]
fn severity_invalid_contact_format() {
    let issue = SecurityTxtIssue::InvalidContactFormat {
        contact: "ftp://example.com".to_string(),
    };
    assert_eq!(security_txt_severity(&issue), 4.0);
}

#[test]
fn severity_duplicate_expires() {
    assert_eq!(
        security_txt_severity(&SecurityTxtIssue::DuplicateExpires),
        4.0
    );
}

#[test]
fn severity_wrong_path() {
    assert_eq!(security_txt_severity(&SecurityTxtIssue::WrongPath), 3.0);
}

#[test]
fn severity_missing_security_txt_is_low() {
    assert_eq!(
        security_txt_severity(&SecurityTxtIssue::MissingSecurityTxt),
        2.0
    );
}

#[test]
fn severity_missing_canonical_is_low() {
    assert_eq!(
        security_txt_severity(&SecurityTxtIssue::MissingCanonical),
        2.0
    );
}

#[test]
fn severity_missing_encryption_is_low() {
    assert_eq!(
        security_txt_severity(&SecurityTxtIssue::MissingEncryption),
        2.0
    );
}

// ── analyze_security_txt tests ─────────────────────────────────────

#[test]
fn analyze_perfect_file_https_wellknown() {
    let fields = vec![
        ("contact".to_string(), "mailto:sec@example.com".to_string()),
        ("expires".to_string(), "2027-12-31T23:59:59z".to_string()),
        (
            "canonical".to_string(),
            "https://example.com/.well-known/security.txt".to_string(),
        ),
        (
            "encryption".to_string(),
            "https://example.com/pgp-key.txt".to_string(),
        ),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(issues.is_empty(), "perfect file should produce no issues");
}

#[test]
fn analyze_missing_contact() {
    let fields = vec![("expires".to_string(), "2027-12-31T23:59:59z".to_string())];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(issues.contains(&SecurityTxtIssue::MissingContact));
}

#[test]
fn analyze_missing_expires() {
    let fields = vec![("contact".to_string(), "mailto:sec@example.com".to_string())];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(issues.contains(&SecurityTxtIssue::MissingExpires));
}

#[test]
fn analyze_expired_date() {
    let fields = vec![
        ("contact".to_string(), "mailto:sec@example.com".to_string()),
        ("expires".to_string(), "2024-06-15T00:00:00z".to_string()),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SecurityTxtIssue::ExpiredFile { .. }))
    );
}

#[test]
fn analyze_future_date_not_expired() {
    let fields = vec![
        ("contact".to_string(), "mailto:sec@example.com".to_string()),
        ("expires".to_string(), "2027-12-31T23:59:59z".to_string()),
        (
            "canonical".to_string(),
            "https://example.com/.well-known/security.txt".to_string(),
        ),
        (
            "encryption".to_string(),
            "https://example.com/pgp-key.txt".to_string(),
        ),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SecurityTxtIssue::ExpiredFile { .. })),
        "future date should not be flagged as expired"
    );
}

#[test]
fn analyze_http_not_https() {
    let fields = vec![
        ("contact".to_string(), "mailto:sec@example.com".to_string()),
        ("expires".to_string(), "2027-12-31T23:59:59z".to_string()),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", false);
    assert!(issues.contains(&SecurityTxtIssue::HttpNotHttps));
}

#[test]
fn analyze_https_no_http_issue() {
    let fields = vec![
        ("contact".to_string(), "mailto:sec@example.com".to_string()),
        ("expires".to_string(), "2027-12-31T23:59:59z".to_string()),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(!issues.contains(&SecurityTxtIssue::HttpNotHttps));
}

#[test]
fn analyze_wrong_path_security_txt() {
    let fields = vec![
        ("contact".to_string(), "mailto:sec@example.com".to_string()),
        ("expires".to_string(), "2027-12-31T23:59:59z".to_string()),
    ];
    let issues = analyze_security_txt(&fields, "security.txt", true);
    assert!(issues.contains(&SecurityTxtIssue::WrongPath));
}

#[test]
fn analyze_wellknown_path_no_wrong_path_issue() {
    let fields = vec![
        ("contact".to_string(), "mailto:sec@example.com".to_string()),
        ("expires".to_string(), "2027-12-31T23:59:59z".to_string()),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(!issues.contains(&SecurityTxtIssue::WrongPath));
}

#[test]
fn analyze_missing_canonical() {
    let fields = vec![
        ("contact".to_string(), "mailto:sec@example.com".to_string()),
        ("expires".to_string(), "2027-12-31T23:59:59z".to_string()),
        (
            "encryption".to_string(),
            "https://example.com/pgp-key.txt".to_string(),
        ),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(issues.contains(&SecurityTxtIssue::MissingCanonical));
}

#[test]
fn analyze_missing_encryption() {
    let fields = vec![
        ("contact".to_string(), "mailto:sec@example.com".to_string()),
        ("expires".to_string(), "2027-12-31T23:59:59z".to_string()),
        (
            "canonical".to_string(),
            "https://example.com/.well-known/security.txt".to_string(),
        ),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(issues.contains(&SecurityTxtIssue::MissingEncryption));
}

#[test]
fn analyze_invalid_contact_tel() {
    let fields = vec![
        ("contact".to_string(), "tel:+1-555-0100".to_string()),
        ("expires".to_string(), "2027-12-31T23:59:59z".to_string()),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(issues.iter().any(|i| matches!(
        i,
        SecurityTxtIssue::InvalidContactFormat { contact } if contact == "tel:+1-555-0100"
    )));
}

#[test]
fn analyze_invalid_contact_http() {
    let fields = vec![
        (
            "contact".to_string(),
            "http://example.com/security".to_string(),
        ),
        ("expires".to_string(), "2027-12-31T23:59:59z".to_string()),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SecurityTxtIssue::InvalidContactFormat { .. })),
        "http: (not https:) contact should be invalid"
    );
}

#[test]
fn analyze_valid_mailto_contact() {
    let fields = vec![
        ("contact".to_string(), "mailto:sec@example.com".to_string()),
        ("expires".to_string(), "2027-12-31T23:59:59z".to_string()),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SecurityTxtIssue::InvalidContactFormat { .. })),
        "mailto: contact should be valid"
    );
}

#[test]
fn analyze_valid_https_contact() {
    let fields = vec![
        (
            "contact".to_string(),
            "https://hackerone.com/example".to_string(),
        ),
        ("expires".to_string(), "2027-12-31T23:59:59z".to_string()),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SecurityTxtIssue::InvalidContactFormat { .. })),
        "https: contact should be valid"
    );
}

#[test]
fn analyze_duplicate_expires() {
    let fields = vec![
        ("contact".to_string(), "mailto:sec@example.com".to_string()),
        ("expires".to_string(), "2027-12-31T23:59:59z".to_string()),
        ("expires".to_string(), "2028-01-01T00:00:00z".to_string()),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(issues.contains(&SecurityTxtIssue::DuplicateExpires));
    // Duplicate expires means MissingExpires should NOT be present
    assert!(!issues.contains(&SecurityTxtIssue::MissingExpires));
}

#[test]
fn analyze_empty_fields_all_required_missing() {
    let fields: Vec<(String, String)> = vec![];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(issues.contains(&SecurityTxtIssue::MissingContact));
    assert!(issues.contains(&SecurityTxtIssue::MissingExpires));
    assert!(issues.contains(&SecurityTxtIssue::MissingCanonical));
    assert!(issues.contains(&SecurityTxtIssue::MissingEncryption));
}

#[test]
fn analyze_multiple_issues_combined() {
    let fields = vec![("contact".to_string(), "ftp://example.com".to_string())];
    let issues = analyze_security_txt(&fields, "security.txt", false);
    assert!(issues.contains(&SecurityTxtIssue::MissingExpires));
    assert!(issues.contains(&SecurityTxtIssue::HttpNotHttps));
    assert!(issues.contains(&SecurityTxtIssue::WrongPath));
    assert!(issues.contains(&SecurityTxtIssue::MissingCanonical));
    assert!(issues.contains(&SecurityTxtIssue::MissingEncryption));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SecurityTxtIssue::InvalidContactFormat { .. }))
    );
}

#[test]
fn analyze_multiple_contacts_one_invalid() {
    let fields = vec![
        ("contact".to_string(), "mailto:sec@example.com".to_string()),
        ("contact".to_string(), "ftp://bad.example.com".to_string()),
        ("expires".to_string(), "2027-12-31T23:59:59z".to_string()),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    // Should flag the bad one, not the good one
    let invalid: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, SecurityTxtIssue::InvalidContactFormat { .. }))
        .collect();
    assert_eq!(invalid.len(), 1);
    assert!(!issues.contains(&SecurityTxtIssue::MissingContact));
}

#[test]
fn analyze_expired_boundary_today() {
    // Date exactly matching "today" (2026-03-23) should NOT be expired
    // (serial comparison: equal means not less-than)
    let fields = vec![
        ("contact".to_string(), "mailto:sec@example.com".to_string()),
        ("expires".to_string(), "2026-03-23T00:00:00z".to_string()),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SecurityTxtIssue::ExpiredFile { .. })),
        "date equal to today should not be expired"
    );
}

#[test]
fn analyze_expired_yesterday() {
    let fields = vec![
        ("contact".to_string(), "mailto:sec@example.com".to_string()),
        ("expires".to_string(), "2026-03-22T23:59:59z".to_string()),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SecurityTxtIssue::ExpiredFile { .. }))
    );
}

#[test]
fn analyze_short_date_not_expired() {
    // Malformed short date should not trigger expired (not enough chars to parse)
    let fields = vec![
        ("contact".to_string(), "mailto:sec@example.com".to_string()),
        ("expires".to_string(), "2027".to_string()),
    ];
    let issues = analyze_security_txt(&fields, ".well-known/security.txt", true);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SecurityTxtIssue::ExpiredFile { .. })),
        "unparseable short date should not be flagged as expired"
    );
}

// ── security_txt_issues_to_operations tests ────────────────────────

#[test]
fn issues_to_operations_empty() {
    let mut seq = 5;
    let ops = security_txt_issues_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn issues_to_operations_one_per_issue() {
    let issues = vec![
        SecurityTxtIssue::MissingContact,
        SecurityTxtIssue::MissingExpires,
    ];
    let mut seq = 0;
    let ops = security_txt_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
}

#[test]
fn issues_to_operations_seq_increments() {
    let issues = vec![
        SecurityTxtIssue::HttpNotHttps,
        SecurityTxtIssue::WrongPath,
        SecurityTxtIssue::MissingCanonical,
    ];
    let mut seq = 10;
    let ops = security_txt_issues_to_operations(&issues, &mut seq);
    assert_eq!(seq, 13);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
    assert_eq!(ops[2].sequence_number, 13);
}

#[test]
fn issues_to_operations_uses_add_finding() {
    let issues = vec![SecurityTxtIssue::MissingSecurityTxt];
    let mut seq = 0;
    let ops = security_txt_issues_to_operations(&issues, &mut seq);
    assert!(matches!(
        &ops[0].operation,
        aegis_protocol::operation::GraphOperation::AddFinding { .. }
    ));
}

#[test]
fn issues_to_operations_uses_security_misconfiguration() {
    let issues = vec![SecurityTxtIssue::MissingContact];
    let mut seq = 0;
    let ops = security_txt_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn issues_to_operations_confidence_is_0_5() {
    let issues = vec![SecurityTxtIssue::HttpNotHttps];
    let mut seq = 0;
    let ops = security_txt_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { confidence, .. } => {
            assert!((confidence.value() - 0.5).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn issues_to_operations_severity_matches_issue() {
    let issues = vec![
        SecurityTxtIssue::HttpNotHttps,
        SecurityTxtIssue::MissingSecurityTxt,
    ];
    let mut seq = 0;
    let ops = security_txt_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 7.0).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
    match &ops[1].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 2.0).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn issues_to_operations_uses_passive_recon_module() {
    let issues = vec![SecurityTxtIssue::DuplicateExpires];
    let mut seq = 0;
    let ops = security_txt_issues_to_operations(&issues, &mut seq);
    assert_eq!(
        ops[0].module,
        aegis_protocol::operation::ModuleIdentifier::PassiveRecon
    );
}

// ── SecurityTxtIssue equality tests ────────────────────────────────

#[test]
fn issue_equality_unit_variants() {
    assert_eq!(
        SecurityTxtIssue::MissingContact,
        SecurityTxtIssue::MissingContact
    );
    assert_ne!(
        SecurityTxtIssue::MissingContact,
        SecurityTxtIssue::MissingExpires
    );
}

#[test]
fn issue_equality_struct_variants() {
    let a = SecurityTxtIssue::ExpiredFile {
        expires: "2024-01-01T00:00:00z".to_string(),
    };
    let b = SecurityTxtIssue::ExpiredFile {
        expires: "2024-01-01T00:00:00z".to_string(),
    };
    let c = SecurityTxtIssue::ExpiredFile {
        expires: "2023-06-01T00:00:00z".to_string(),
    };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn issue_debug_format() {
    let issue = SecurityTxtIssue::MissingSecurityTxt;
    let debug = format!("{issue:?}");
    assert!(debug.contains("MissingSecurityTxt"));
}

// ── parse_security_txt edge cases ──────────────────────────────────

#[test]
fn parse_security_txt_empty_body() {
    let fields = parse_security_txt("");
    assert!(fields.is_empty());
}

#[test]
fn parse_security_txt_only_comments() {
    let body = "# comment 1\n# comment 2\n# comment 3\n";
    let fields = parse_security_txt(body);
    assert!(fields.is_empty());
}

#[test]
fn parse_security_txt_whitespace_only() {
    let body = "   \n  \n\n  \n";
    let fields = parse_security_txt(body);
    assert!(fields.is_empty());
}

#[test]
fn parse_security_txt_case_normalizes_keys() {
    let body = "CONTACT: mailto:sec@example.com\nEXPIRES: 2027-12-31T23:59:59z\n";
    let fields = parse_security_txt(body);
    assert_eq!(fields[0].0, "contact");
    assert_eq!(fields[1].0, "expires");
}

#[test]
fn parse_security_txt_preserves_value_case() {
    let body = "Contact: mailto:Security@EXAMPLE.COM\n";
    let fields = parse_security_txt(body);
    assert_eq!(fields[0].1, "mailto:Security@EXAMPLE.COM");
}

#[test]
fn parse_security_txt_trims_whitespace() {
    let body = "  Contact  :   mailto:sec@example.com   \n";
    let fields = parse_security_txt(body);
    assert_eq!(fields[0].0, "contact");
    assert_eq!(fields[0].1, "mailto:sec@example.com");
}

#[test]
fn parse_security_txt_no_colon_line_skipped() {
    let body = "This line has no colon\nContact: mailto:sec@example.com\n";
    let fields = parse_security_txt(body);
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].0, "contact");
}

#[test]
fn parse_security_txt_all_rfc9116_fields() {
    let body = "\
Contact: mailto:sec@example.com\n\
Expires: 2027-12-31T23:59:59z\n\
Encryption: https://example.com/pgp.txt\n\
Acknowledgments: https://example.com/hall-of-fame\n\
Preferred-Languages: en, fr\n\
Canonical: https://example.com/.well-known/security.txt\n\
Policy: https://example.com/policy\n\
Hiring: https://example.com/jobs\n";
    let fields = parse_security_txt(body);
    assert_eq!(fields.len(), 8);
    let keys: Vec<_> = fields.iter().map(|(k, _)| k.as_str()).collect();
    assert!(keys.contains(&"acknowledgments"));
    assert!(keys.contains(&"preferred-languages"));
    assert!(keys.contains(&"policy"));
    assert!(keys.contains(&"hiring"));
}
