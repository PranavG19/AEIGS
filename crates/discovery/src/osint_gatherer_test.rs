use super::osint_gatherer::*;

// ---------------------------------------------------------------------------
// infer_email_patterns
// ---------------------------------------------------------------------------

#[test]
fn test_infer_email_patterns_first_dot_last() {
    let emails = vec![
        "john.doe@acme.com",
        "jane.smith@acme.com",
        "bob.jones@acme.com",
    ];
    let patterns = infer_email_patterns(&emails, "acme.com");
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns[0].pattern, "first.last@domain");
    assert!((patterns[0].confidence - 1.0).abs() < f64::EPSILON);
    assert_eq!(patterns[0].examples.len(), 3);
    assert_eq!(patterns[0].description, "First name dot last name");
}

#[test]
fn test_infer_email_patterns_flast() {
    let emails = vec!["j.doe@acme.com", "j.smith@acme.com"];
    let patterns = infer_email_patterns(&emails, "acme.com");
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns[0].pattern, "flast@domain");
    assert_eq!(patterns[0].description, "First initial dot last name");
}

#[test]
fn test_infer_email_patterns_firstl() {
    let emails = vec!["john.d@acme.com", "jane.s@acme.com"];
    let patterns = infer_email_patterns(&emails, "acme.com");
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns[0].pattern, "firstl@domain");
    assert_eq!(patterns[0].description, "First name dot last initial");
}

#[test]
fn test_infer_email_patterns_first_only() {
    let emails = vec!["john@acme.com", "jane@acme.com", "bob@acme.com"];
    let patterns = infer_email_patterns(&emails, "acme.com");
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns[0].pattern, "first@domain");
    assert_eq!(patterns[0].description, "First name only");
}

#[test]
fn test_infer_email_patterns_underscore() {
    let emails = vec!["john_doe@acme.com", "jane_smith@acme.com"];
    let patterns = infer_email_patterns(&emails, "acme.com");
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns[0].pattern, "first_last@domain");
}

#[test]
fn test_infer_email_patterns_hyphen() {
    let emails = vec!["john-doe@acme.com", "jane-smith@acme.com"];
    let patterns = infer_email_patterns(&emails, "acme.com");
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns[0].pattern, "first-last@domain");
}

#[test]
fn test_infer_email_patterns_empty_input() {
    let patterns = infer_email_patterns(&[], "acme.com");
    assert!(patterns.is_empty());
}

#[test]
fn test_infer_email_patterns_no_matching_domain() {
    let emails = vec!["john.doe@other.com", "jane.smith@other.com"];
    let patterns = infer_email_patterns(&emails, "acme.com");
    assert!(patterns.is_empty());
}

#[test]
fn test_infer_email_patterns_mixed_formats_sorted_by_confidence() {
    let emails = vec![
        "john.doe@acme.com",
        "jane.smith@acme.com",
        "bob.jones@acme.com",
        "alice@acme.com",
    ];
    let patterns = infer_email_patterns(&emails, "acme.com");
    assert_eq!(patterns.len(), 2);
    assert!(
        patterns[0].confidence >= patterns[1].confidence,
        "patterns should be sorted descending by confidence"
    );
    assert_eq!(patterns[0].pattern, "first.last@domain");
    assert!((patterns[0].confidence - 0.75).abs() < f64::EPSILON);
}

#[test]
fn test_infer_email_patterns_case_insensitive_domain() {
    let emails = vec!["john.doe@ACME.COM", "jane.smith@Acme.Com"];
    let patterns = infer_email_patterns(&emails, "acme.com");
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns[0].examples.len(), 2);
}

// ---------------------------------------------------------------------------
// extract_tech_from_job_postings
// ---------------------------------------------------------------------------

#[test]
fn test_extract_tech_single_posting() {
    let postings = vec!["We need a python developer with experience in Django and PostgreSQL"];
    let items = extract_tech_from_job_postings(&postings);
    assert!(!items.is_empty());

    let tech_names: Vec<&str> = items.iter().map(|t| t.technology.as_str()).collect();
    assert!(tech_names.contains(&"Python"));
    assert!(tech_names.contains(&"Django"));
    assert!(tech_names.contains(&"PostgreSQL"));

    for item in &items {
        assert_eq!(item.source, OsintSource::JobPosting);
    }
}

#[test]
fn test_extract_tech_confidence_increases_with_multiple_postings() {
    let postings = vec![
        "Python developer needed",
        "Senior python engineer with AWS",
        "Backend python position with kubernetes",
    ];
    let items = extract_tech_from_job_postings(&postings);
    let python = items.iter().find(|t| t.technology == "Python").unwrap();
    assert!(
        python.confidence > 0.6,
        "confidence should increase above base 0.6 with repeated mentions"
    );
    assert!((python.confidence - 0.8).abs() < f64::EPSILON);
}

#[test]
fn test_extract_tech_empty_postings() {
    let items = extract_tech_from_job_postings(&[]);
    assert!(items.is_empty());
}

#[test]
fn test_extract_tech_no_matches() {
    let postings = vec!["We are hiring a project manager for our team"];
    let items = extract_tech_from_job_postings(&postings);
    assert!(items.is_empty());
}

#[test]
fn test_extract_tech_deduplicates_aliases() {
    let postings = vec!["Experience with nodejs and node.js required"];
    let items = extract_tech_from_job_postings(&postings);
    let node_items: Vec<&TechStackItem> =
        items.iter().filter(|t| t.technology == "Node.js").collect();
    assert_eq!(
        node_items.len(),
        1,
        "nodejs and node.js should map to a single Node.js entry"
    );
}

#[test]
fn test_extract_tech_categories() {
    let postings = vec![
        "Stack: React, TypeScript, PostgreSQL, AWS, Docker, Jenkins, Cloudflare, Datadog, Git, Okta",
    ];
    let items = extract_tech_from_job_postings(&postings);

    let find = |name: &str| items.iter().find(|t| t.technology == name);

    assert_eq!(
        find("React").unwrap().category,
        OsintTechCategory::Framework
    );
    assert_eq!(
        find("TypeScript").unwrap().category,
        OsintTechCategory::Language
    );
    assert_eq!(
        find("PostgreSQL").unwrap().category,
        OsintTechCategory::Database
    );
    assert_eq!(
        find("AWS").unwrap().category,
        OsintTechCategory::CloudProvider
    );
    assert_eq!(find("Docker").unwrap().category, OsintTechCategory::Other);
    assert_eq!(find("Jenkins").unwrap().category, OsintTechCategory::Ci);
    assert_eq!(find("Cloudflare").unwrap().category, OsintTechCategory::Cdn);
    assert_eq!(
        find("Datadog").unwrap().category,
        OsintTechCategory::Monitoring
    );
    assert_eq!(
        find("Git").unwrap().category,
        OsintTechCategory::VersionControl
    );
    assert_eq!(find("Okta").unwrap().category, OsintTechCategory::Security);
}

// ---------------------------------------------------------------------------
// correlate_breaches
// ---------------------------------------------------------------------------

#[test]
fn test_correlate_breaches_domain_match() {
    let entries: Vec<BreachEntry<'_>> = vec![(
        "acme.com leak",
        Some("2023-01-15"),
        Some(100_000),
        &["email", "password"],
    )];
    let records = correlate_breaches("acme.com", &entries);
    assert_eq!(records.len(), 1);
    assert!(records[0].email_domain_match);
    assert_eq!(records[0].source_name, "acme.com leak");
    assert_eq!(records[0].date.as_deref(), Some("2023-01-15"));
    assert_eq!(records[0].records_exposed, Some(100_000));
    assert!(records[0].data_types.contains(&BreachDataType::Email));
    assert!(records[0].data_types.contains(&BreachDataType::Password));
}

#[test]
fn test_correlate_breaches_no_domain_match() {
    let entries: Vec<BreachEntry<'_>> = vec![(
        "other-corp breach",
        Some("2022-06-01"),
        Some(50_000),
        &["email"],
    )];
    let records = correlate_breaches("acme.com", &entries);
    assert_eq!(records.len(), 1);
    assert!(!records[0].email_domain_match);
}

#[test]
fn test_correlate_breaches_data_type_parsing() {
    let entries: Vec<BreachEntry<'_>> = vec![(
        "acme leak",
        None,
        None,
        &[
            "email",
            "password_hash",
            "phone",
            "ssn",
            "credit_card",
            "ip_address",
            "name",
            "address",
            "custom_field",
        ],
    )];
    let records = correlate_breaches("acme.com", &entries);
    let types = &records[0].data_types;

    assert!(types.contains(&BreachDataType::Email));
    assert!(types.contains(&BreachDataType::PasswordHash));
    assert!(types.contains(&BreachDataType::Phone));
    assert!(types.contains(&BreachDataType::Ssn));
    assert!(types.contains(&BreachDataType::CreditCard));
    assert!(types.contains(&BreachDataType::IpAddress));
    assert!(types.contains(&BreachDataType::Name));
    assert!(types.contains(&BreachDataType::Address));
    assert!(types.contains(&BreachDataType::Other("custom_field".to_string())));
}

#[test]
fn test_correlate_breaches_empty() {
    let records = correlate_breaches("acme.com", &[]);
    assert!(records.is_empty());
}

#[test]
fn test_correlate_breaches_optional_fields_none() {
    let entries: Vec<BreachEntry<'_>> = vec![("some breach", None, None, &["email"])];
    let records = correlate_breaches("acme.com", &entries);
    assert_eq!(records.len(), 1);
    assert!(records[0].date.is_none());
    assert!(records[0].records_exposed.is_none());
}

// ---------------------------------------------------------------------------
// enumerate_repositories
// ---------------------------------------------------------------------------

#[test]
fn test_enumerate_repositories_basic() {
    let repos: Vec<RepoEntry<'_>> = vec![(
        "GitHub",
        "acme-org",
        "web-app",
        true,
        Some("TypeScript"),
        Some("2024-01-15"),
    )];
    let result = enumerate_repositories(&repos);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].platform, "GitHub");
    assert_eq!(result[0].org_name, "acme-org");
    assert_eq!(result[0].repo_name, "web-app");
    assert_eq!(result[0].url, "https://github/acme-org/web-app");
    assert!(result[0].is_public);
    assert_eq!(result[0].language.as_deref(), Some("TypeScript"));
    assert_eq!(result[0].last_updated.as_deref(), Some("2024-01-15"));
}

#[test]
fn test_enumerate_repositories_private_repo() {
    let repos: Vec<RepoEntry<'_>> = vec![(
        "GitLab",
        "acme-internal",
        "secrets-mgr",
        false,
        Some("Go"),
        None,
    )];
    let result = enumerate_repositories(&repos);
    assert_eq!(result.len(), 1);
    assert!(!result[0].is_public);
    assert!(result[0].last_updated.is_none());
}

#[test]
fn test_enumerate_repositories_multiple() {
    let repos: Vec<RepoEntry<'_>> = vec![
        ("GitHub", "acme", "frontend", true, Some("TypeScript"), None),
        ("GitHub", "acme", "backend", true, Some("Rust"), None),
        ("GitLab", "acme", "infra", false, None, None),
    ];
    let result = enumerate_repositories(&repos);
    assert_eq!(result.len(), 3);
}

#[test]
fn test_enumerate_repositories_empty() {
    let result = enumerate_repositories(&[]);
    assert!(result.is_empty());
}

// ---------------------------------------------------------------------------
// build_org_structure
// ---------------------------------------------------------------------------

fn make_employee(name: &str, role: Option<&str>, department: Option<&str>) -> EmployeeInfo {
    EmployeeInfo {
        name: name.to_string(),
        role: role.map(|r| r.to_string()),
        department: department.map(|d| d.to_string()),
        email_pattern: None,
        source: OsintSource::LinkedIn,
        confidence: 0.7,
    }
}

#[test]
fn test_build_org_structure_basic() {
    let employees = vec![
        make_employee("Alice Chen", Some("CTO"), Some("Engineering")),
        make_employee("Bob Rivera", Some("Senior Engineer"), Some("Engineering")),
        make_employee(
            "Claire Dubois",
            Some("Marketing Manager"),
            Some("Marketing"),
        ),
    ];
    let tech = vec![TechStackItem {
        technology: "Rust".to_string(),
        category: OsintTechCategory::Language,
        version: None,
        source: OsintSource::JobPosting,
        confidence: 0.8,
    }];

    let org = build_org_structure(&employees, &tech);
    assert_eq!(org.departments.len(), 2);
    assert_eq!(org.estimated_size, OrgSize::Startup(3));
    assert!(!org.leadership.is_empty());
    assert!(org.leadership.iter().any(|l| l.name == "Alice Chen"));
}

#[test]
fn test_build_org_structure_engineering_gets_tech() {
    let employees = vec![
        make_employee("Dev One", Some("Software Engineer"), Some("Engineering")),
        make_employee("Sales One", Some("Account Exec"), Some("Sales")),
    ];
    let tech = vec![TechStackItem {
        technology: "Python".to_string(),
        category: OsintTechCategory::Language,
        version: None,
        source: OsintSource::JobPosting,
        confidence: 0.7,
    }];

    let org = build_org_structure(&employees, &tech);
    let eng_dept = org.departments.iter().find(|d| d.name == "Engineering");
    let sales_dept = org.departments.iter().find(|d| d.name == "Sales");

    assert!(
        !eng_dept.unwrap().technologies.is_empty(),
        "engineering department should have technologies assigned"
    );
    assert!(
        sales_dept.unwrap().technologies.is_empty(),
        "sales department should not have technologies assigned"
    );
}

#[test]
fn test_build_org_structure_org_size_brackets() {
    let startup_emps: Vec<EmployeeInfo> = (0..5)
        .map(|i| make_employee(&format!("Emp {i}"), None, None))
        .collect();
    assert_eq!(
        build_org_structure(&startup_emps, &[]).estimated_size,
        OrgSize::Startup(5)
    );

    let small_emps: Vec<EmployeeInfo> = (0..30)
        .map(|i| make_employee(&format!("Emp {i}"), None, None))
        .collect();
    assert_eq!(
        build_org_structure(&small_emps, &[]).estimated_size,
        OrgSize::Small(30)
    );

    let medium_emps: Vec<EmployeeInfo> = (0..100)
        .map(|i| make_employee(&format!("Emp {i}"), None, None))
        .collect();
    assert_eq!(
        build_org_structure(&medium_emps, &[]).estimated_size,
        OrgSize::Medium(100)
    );
}

#[test]
fn test_build_org_structure_unknown_department() {
    let employees = vec![make_employee("Solo Dev", Some("Developer"), None)];
    let org = build_org_structure(&employees, &[]);
    assert!(org.departments.iter().any(|d| d.name == "Unknown"));
}

// ---------------------------------------------------------------------------
// calculate_osint_risk
// ---------------------------------------------------------------------------

fn make_empty_report() -> OsintReport {
    OsintReport {
        domain: "acme.com".to_string(),
        employees: Vec::new(),
        email_patterns: Vec::new(),
        tech_stack: Vec::new(),
        org_structure: None,
        breaches: Vec::new(),
        social_media: Vec::new(),
        repositories: Vec::new(),
        risk_score: 0.0,
    }
}

#[test]
fn test_calculate_osint_risk_empty_report() {
    let report = make_empty_report();
    let risk = calculate_osint_risk(&report);
    assert!(
        risk.abs() < f64::EPSILON,
        "empty report should have zero risk"
    );
}

#[test]
fn test_calculate_osint_risk_breaches_increase_score() {
    let mut report = make_empty_report();
    report.breaches = vec![BreachRecord {
        source_name: "acme leak".to_string(),
        date: Some("2023-01-01".to_string()),
        records_exposed: Some(1_000_000),
        data_types: vec![BreachDataType::Email, BreachDataType::Password],
        email_domain_match: true,
    }];
    let risk = calculate_osint_risk(&report);
    assert!(risk > 0.0, "breaches should increase risk score");
}

#[test]
fn test_calculate_osint_risk_sensitive_data_increases_breach_risk() {
    let mut report_passwords = make_empty_report();
    report_passwords.breaches = vec![BreachRecord {
        source_name: "acme leak".to_string(),
        date: None,
        records_exposed: None,
        data_types: vec![BreachDataType::Email, BreachDataType::Password],
        email_domain_match: true,
    }];

    let mut report_ssn = make_empty_report();
    report_ssn.breaches = vec![BreachRecord {
        source_name: "acme leak".to_string(),
        date: None,
        records_exposed: None,
        data_types: vec![
            BreachDataType::Email,
            BreachDataType::Password,
            BreachDataType::Ssn,
        ],
        email_domain_match: true,
    }];

    let risk_pw = calculate_osint_risk(&report_passwords);
    let risk_ssn = calculate_osint_risk(&report_ssn);
    assert!(
        risk_ssn > risk_pw,
        "SSN breach should score higher than password-only breach"
    );
}

#[test]
fn test_calculate_osint_risk_public_repos_increase_score() {
    let mut report = make_empty_report();
    report.repositories = (0..10)
        .map(|i| CodeRepository {
            platform: "GitHub".to_string(),
            org_name: "acme".to_string(),
            repo_name: format!("repo-{i}"),
            url: format!("https://github.com/acme/repo-{i}"),
            is_public: true,
            language: Some("Rust".to_string()),
            last_updated: None,
        })
        .collect();
    let risk = calculate_osint_risk(&report);
    assert!(risk > 0.0, "public repos should increase risk score");
}

#[test]
fn test_calculate_osint_risk_capped_at_one() {
    let mut report = make_empty_report();
    report.employees = (0..100)
        .map(|i| make_employee(&format!("Emp {i}"), None, None))
        .collect();
    report.email_patterns = vec![EmailPattern {
        pattern: "first.last@domain".to_string(),
        examples: vec!["a.b@acme.com".to_string()],
        confidence: 1.0,
        description: "test".to_string(),
    }];
    report.breaches = (0..10)
        .map(|i| BreachRecord {
            source_name: format!("acme breach {i}"),
            date: None,
            records_exposed: Some(1_000_000),
            data_types: vec![
                BreachDataType::Password,
                BreachDataType::Ssn,
                BreachDataType::CreditCard,
            ],
            email_domain_match: true,
        })
        .collect();
    report.repositories = (0..30)
        .map(|i| CodeRepository {
            platform: "GitHub".to_string(),
            org_name: "acme".to_string(),
            repo_name: format!("repo-{i}"),
            url: format!("https://github.com/acme/repo-{i}"),
            is_public: true,
            language: None,
            last_updated: None,
        })
        .collect();
    report.social_media = (0..20)
        .map(|i| SocialMediaPresence {
            platform: format!("platform-{i}"),
            url: format!("https://social.com/{i}"),
            username: None,
            verified: false,
            follower_count: None,
        })
        .collect();

    let risk = calculate_osint_risk(&report);
    assert!(risk <= 1.0, "risk score must not exceed 1.0, got {risk}");
}

// ---------------------------------------------------------------------------
// map_social_profiles
// ---------------------------------------------------------------------------

#[test]
fn test_map_social_profiles_basic() {
    let profiles: Vec<SocialEntry<'_>> = vec![(
        "Twitter",
        "https://twitter.com/acme",
        Some("acme"),
        true,
        Some(50_000),
    )];
    let result = map_social_profiles(&profiles);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].platform, "Twitter");
    assert_eq!(result[0].url, "https://twitter.com/acme");
    assert_eq!(result[0].username.as_deref(), Some("acme"));
    assert!(result[0].verified);
    assert_eq!(result[0].follower_count, Some(50_000));
}

#[test]
fn test_map_social_profiles_optional_fields() {
    let profiles: Vec<SocialEntry<'_>> = vec![(
        "LinkedIn",
        "https://linkedin.com/company/acme",
        None,
        false,
        None,
    )];
    let result = map_social_profiles(&profiles);
    assert_eq!(result.len(), 1);
    assert!(result[0].username.is_none());
    assert!(!result[0].verified);
    assert!(result[0].follower_count.is_none());
}

#[test]
fn test_map_social_profiles_empty() {
    let result = map_social_profiles(&[]);
    assert!(result.is_empty());
}

// ---------------------------------------------------------------------------
// gather_osint (full pipeline)
// ---------------------------------------------------------------------------

#[test]
fn test_gather_osint_full_pipeline() {
    let emails = vec!["john.doe@target.io", "jane.smith@target.io"];
    let postings = vec!["Looking for a rust and python developer with AWS experience"];
    let breach_data: Vec<BreachEntry<'_>> = vec![(
        "target.io dump",
        Some("2023-03-01"),
        Some(10_000),
        &["email", "password"],
    )];
    let repo_data: Vec<RepoEntry<'_>> = vec![(
        "GitHub",
        "target-io",
        "api-server",
        true,
        Some("Rust"),
        Some("2024-06-01"),
    )];
    let social: Vec<SocialEntry<'_>> = vec![(
        "Twitter",
        "https://twitter.com/targetio",
        Some("targetio"),
        true,
        Some(12_000),
    )];
    let employees: Vec<EmployeeEntry<'_>> = vec![
        ("John Doe", Some("CTO"), Some("Engineering"), "linkedin"),
        (
            "Jane Smith",
            Some("Engineer"),
            Some("Engineering"),
            "linkedin",
        ),
    ];

    let report = gather_osint(
        "target.io",
        &emails,
        &postings,
        &breach_data,
        &repo_data,
        &social,
        &employees,
    );

    assert_eq!(report.domain, "target.io");
    assert_eq!(report.employees.len(), 2);
    assert!(!report.email_patterns.is_empty());
    assert!(!report.tech_stack.is_empty());
    assert_eq!(report.breaches.len(), 1);
    assert_eq!(report.repositories.len(), 1);
    assert_eq!(report.social_media.len(), 1);
    assert!(report.org_structure.is_some());
    assert!(report.risk_score > 0.0);
}

#[test]
fn test_gather_osint_empty_inputs() {
    let report = gather_osint("empty.com", &[], &[], &[], &[], &[], &[]);
    assert_eq!(report.domain, "empty.com");
    assert!(report.employees.is_empty());
    assert!(report.email_patterns.is_empty());
    assert!(report.tech_stack.is_empty());
    assert!(report.breaches.is_empty());
    assert!(report.repositories.is_empty());
    assert!(report.social_media.is_empty());
    assert!(report.org_structure.is_none());
    assert!(report.risk_score.abs() < f64::EPSILON);
}

#[test]
fn test_gather_osint_employees_get_inferred_emails() {
    let emails = vec!["alice.wonder@corp.dev", "bob.builder@corp.dev"];
    let employees: Vec<EmployeeEntry<'_>> = vec![(
        "Charlie Brown",
        Some("Engineer"),
        Some("Engineering"),
        "linkedin",
    )];

    let report = gather_osint("corp.dev", &emails, &[], &[], &[], &[], &employees);

    assert_eq!(report.employees.len(), 1);
    assert_eq!(
        report.employees[0].email_pattern.as_deref(),
        Some("charlie.brown@corp.dev"),
        "employee email should be inferred from the dominant first.last pattern"
    );
}

#[test]
fn test_gather_osint_leadership_identified() {
    let employees: Vec<EmployeeEntry<'_>> = vec![
        ("Keiko Tanaka", Some("CEO"), Some("Executive"), "linkedin"),
        (
            "Dev McDevface",
            Some("Junior Developer"),
            Some("Engineering"),
            "linkedin",
        ),
    ];

    let report = gather_osint("example.com", &[], &[], &[], &[], &[], &employees);
    let org = report.org_structure.as_ref().unwrap();
    assert_eq!(org.leadership.len(), 1);
    assert_eq!(org.leadership[0].name, "Keiko Tanaka");
}

// ---------------------------------------------------------------------------
// OsintSource Display
// ---------------------------------------------------------------------------

#[test]
fn test_osint_source_display() {
    assert_eq!(OsintSource::LinkedIn.to_string(), "LinkedIn");
    assert_eq!(OsintSource::GitHub.to_string(), "GitHub");
    assert_eq!(OsintSource::GitLab.to_string(), "GitLab");
    assert_eq!(OsintSource::JobPosting.to_string(), "Job Posting");
    assert_eq!(OsintSource::BreachDatabase.to_string(), "Breach Database");
    assert_eq!(OsintSource::SocialMedia.to_string(), "Social Media");
    assert_eq!(OsintSource::PublicRecords.to_string(), "Public Records");
    assert_eq!(OsintSource::CodeRepository.to_string(), "Code Repository");
    assert_eq!(OsintSource::WebArchive.to_string(), "Web Archive");
    assert_eq!(OsintSource::Pastebin.to_string(), "Pastebin");
}

// ---------------------------------------------------------------------------
// OsintTechCategory Display
// ---------------------------------------------------------------------------

#[test]
fn test_osint_tech_category_display() {
    assert_eq!(OsintTechCategory::Language.to_string(), "Language");
    assert_eq!(OsintTechCategory::Framework.to_string(), "Framework");
    assert_eq!(OsintTechCategory::Database.to_string(), "Database");
    assert_eq!(
        OsintTechCategory::CloudProvider.to_string(),
        "Cloud Provider"
    );
    assert_eq!(OsintTechCategory::Cdn.to_string(), "CDN");
    assert_eq!(OsintTechCategory::Ci.to_string(), "CI/CD");
    assert_eq!(
        OsintTechCategory::VersionControl.to_string(),
        "Version Control"
    );
    assert_eq!(OsintTechCategory::Monitoring.to_string(), "Monitoring");
    assert_eq!(OsintTechCategory::Security.to_string(), "Security");
    assert_eq!(OsintTechCategory::Other.to_string(), "Other");
}
