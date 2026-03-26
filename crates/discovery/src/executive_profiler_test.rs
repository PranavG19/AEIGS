use super::executive_profiler::*;

#[test]
fn parse_executive_role_ceo() {
    assert_eq!(parse_executive_role("CEO"), Some(ExecutiveRole::Ceo));
    assert_eq!(
        parse_executive_role("Chief Executive Officer"),
        Some(ExecutiveRole::Ceo)
    );
}

#[test]
fn parse_executive_role_cto() {
    assert_eq!(parse_executive_role("CTO"), Some(ExecutiveRole::Cto));
    assert_eq!(
        parse_executive_role("Chief Technology Officer"),
        Some(ExecutiveRole::Cto)
    );
}

#[test]
fn parse_executive_role_ciso() {
    assert_eq!(
        parse_executive_role("Chief Information Security Officer"),
        Some(ExecutiveRole::Ciso)
    );
    assert_eq!(parse_executive_role("CISO"), Some(ExecutiveRole::Ciso));
}

#[test]
fn parse_executive_role_vp_engineering() {
    assert_eq!(
        parse_executive_role("VP of Engineering"),
        Some(ExecutiveRole::VpEngineering)
    );
}

#[test]
fn parse_executive_role_founder() {
    assert_eq!(
        parse_executive_role("Co-Founder & CEO"),
        Some(ExecutiveRole::Founder)
    );
}

#[test]
fn parse_executive_role_board() {
    assert_eq!(
        parse_executive_role("Independent Board Director"),
        Some(ExecutiveRole::BoardMember)
    );
}

#[test]
fn parse_executive_role_unknown() {
    assert_eq!(parse_executive_role("Janitor"), None);
}

#[test]
fn email_format_first_dot_last() {
    let fmt = EmailFormat::FirstDotLast;
    assert_eq!(
        fmt.generate("John", "Doe", "acme.com"),
        Some("john.doe@acme.com".to_string())
    );
}

#[test]
fn email_format_first_initial_last() {
    let fmt = EmailFormat::FirstInitialLast;
    assert_eq!(
        fmt.generate("Jane", "Smith", "corp.io"),
        Some("jsmith@corp.io".to_string())
    );
}

#[test]
fn email_format_last_dot_first() {
    let fmt = EmailFormat::LastDotFirst;
    assert_eq!(
        fmt.generate("Bob", "Jones", "test.com"),
        Some("jones.bob@test.com".to_string())
    );
}

#[test]
fn email_format_unknown_returns_none() {
    let fmt = EmailFormat::Unknown;
    assert_eq!(fmt.generate("A", "B", "c.com"), None);
}

#[test]
fn infer_email_format_first_dot_last() {
    let samples = vec![
        ("John", "Smith", "john.smith@acme.com"),
        ("Jane", "Doe", "jane.doe@acme.com"),
        ("Bob", "Wilson", "bob.wilson@acme.com"),
    ];
    let result = infer_email_format(&samples, "acme.com");
    assert_eq!(result.detected_format, EmailFormat::FirstDotLast);
    assert!(result.confidence > 0.9);
}

#[test]
fn infer_email_format_first_initial_last() {
    let samples = vec![
        ("John", "Smith", "jsmith@corp.com"),
        ("Jane", "Doe", "jdoe@corp.com"),
    ];
    let result = infer_email_format(&samples, "corp.com");
    assert_eq!(result.detected_format, EmailFormat::FirstInitialLast);
}

#[test]
fn infer_email_format_empty_samples() {
    let result = infer_email_format(&[], "test.com");
    assert_eq!(result.detected_format, EmailFormat::Unknown);
    assert_eq!(result.confidence, 0.0);
}

#[test]
fn generate_executive_emails_multiple() {
    let emails =
        generate_executive_emails("Alice", "Wonder", "example.com", &EmailFormat::FirstDotLast);
    assert!(emails.contains(&"alice.wonder@example.com".to_string()));
    assert!(emails.len() >= 2);
}

#[test]
fn parse_conference_bio_extracts_execs() {
    let bio = "John Smith, Chief Technology Officer at Acme Corp, discussed cloud security. \
               Jane Doe - CEO of WidgetCo, presented on scaling.";
    let results = parse_conference_bio(bio);
    assert!(results.len() >= 1);
    let cto = results
        .iter()
        .find(|(_, role, _)| *role == ExecutiveRole::Cto);
    assert!(cto.is_some());
    assert_eq!(cto.unwrap().0, "John Smith");
}

#[test]
fn parse_sec_board_members_proxy() {
    let filing = "Our Board of Directors:\n\
                  Alice Johnson has served as Independent Director since 2019. \
                  She serves on the Audit Committee and Compensation Committee. \
                  She also serves on board of TechGiant Corp.\n\
                  Bob Martinez, Director of Strategic Initiatives. \
                  He serves on the Governance Committee.";
    let members = parse_sec_board_members(filing);
    assert!(members.len() >= 1);
    let alice = members.iter().find(|m| m.name.contains("Alice"));
    assert!(alice.is_some());
    let alice = alice.unwrap();
    assert!(!alice.committees.is_empty());
}

#[test]
fn extract_previous_companies_from_bio() {
    let bio = "She previously at Google Inc and formerly served at Microsoft Corp before joining.";
    let companies = extract_previous_companies(bio);
    assert!(!companies.is_empty());
    assert!(companies.iter().any(|c| c.contains("Google")));
}

#[test]
fn build_executive_profile_full() {
    let profile = build_executive_profile(
        "John Smith",
        ExecutiveRole::Cto,
        "Acme Corp",
        "acme.com",
        &EmailFormat::FirstDotLast,
        Some("John Smith previously at Google Inc. He has MBA from Stanford University."),
        vec![ConferenceAppearance {
            conference_name: "RSA 2024".to_string(),
            year: Some(2024),
            talk_title: Some("Zero Trust Architecture".to_string()),
            role_at_conference: "Speaker".to_string(),
            bio_text: None,
        }],
    );
    assert_eq!(profile.full_name, "John Smith");
    assert_eq!(profile.role, ExecutiveRole::Cto);
    assert!(profile
        .inferred_emails
        .contains(&"john.smith@acme.com".to_string()));
    assert_eq!(profile.conference_appearances.len(), 1);
    assert!(!profile.previous_companies.is_empty());
}

#[test]
fn build_executive_report_aggregates() {
    let exec = ExecutiveProfile {
        full_name: "Test Exec".to_string(),
        role: ExecutiveRole::Ceo,
        organization: "TestCo".to_string(),
        inferred_emails: vec!["test.exec@testco.com".to_string()],
        conference_appearances: vec![ConferenceAppearance {
            conference_name: "DefCon".to_string(),
            year: Some(2024),
            talk_title: None,
            role_at_conference: "Attendee".to_string(),
            bio_text: None,
        }],
        board_memberships: vec![],
        social_links: vec![],
        bio_snippets: vec![],
        education: vec![],
        previous_companies: vec![],
    };

    let board = BoardMember {
        name: "Board Person".to_string(),
        title: "Independent Director".to_string(),
        role: ExecutiveRole::BoardMember,
        committees: vec!["Audit Committee".to_string()],
        other_boards: vec![],
        compensation: Some(250_000),
        filing_source: SecFilingType::FormDef14A,
    };

    let email_fmt = EmailFormatInference {
        domain: "testco.com".to_string(),
        detected_format: EmailFormat::FirstDotLast,
        confidence: 0.95,
        sample_emails: vec![],
        generated_emails: vec![],
    };

    let report = build_executive_report(
        "TestCo",
        "testco.com",
        vec![exec],
        vec![board],
        email_fmt,
        3,
    );
    assert_eq!(report.total_profiles, 1);
    assert_eq!(report.conferences_found, 1);
    assert_eq!(report.sec_filings_analyzed, 3);
    assert_eq!(report.board_members.len(), 1);
}

#[test]
fn executive_role_display() {
    assert_eq!(ExecutiveRole::Ceo.to_string(), "CEO");
    assert_eq!(ExecutiveRole::VpEngineering.to_string(), "VP Engineering");
    assert_eq!(ExecutiveRole::BoardMember.to_string(), "Board Member");
}

#[test]
fn sec_filing_type_display() {
    assert_eq!(SecFilingType::Form10K.to_string(), "10-K");
    assert_eq!(SecFilingType::FormDef14A.to_string(), "DEF 14A");
    assert_eq!(SecFilingType::FormS1.to_string(), "S-1");
}

#[test]
fn email_format_display() {
    assert_eq!(EmailFormat::FirstDotLast.to_string(), "first.last");
    assert_eq!(EmailFormat::FirstInitialLast.to_string(), "flast");
    assert_eq!(EmailFormat::Unknown.to_string(), "unknown");
}
