use super::person_profiler::*;

#[test]
fn test_build_platform_checks_count() {
    let checks = build_platform_checks();
    assert!(
        checks.len() >= 400,
        "expected 400+ platform checks, got {}",
        checks.len()
    );
}

#[test]
fn test_build_platform_checks_has_major_platforms() {
    let checks = build_platform_checks();
    let platforms: Vec<_> = checks.iter().map(|c| c.platform.to_string()).collect();
    assert!(platforms.contains(&"GitHub".to_string()));
    assert!(platforms.contains(&"Twitter".to_string()));
    assert!(platforms.contains(&"LinkedIn".to_string()));
    assert!(platforms.contains(&"Reddit".to_string()));
    assert!(platforms.contains(&"Instagram".to_string()));
    assert!(platforms.contains(&"Discord".to_string()));
    assert!(platforms.contains(&"Telegram".to_string()));
}

#[test]
fn test_build_platform_checks_categories() {
    let checks = build_platform_checks();
    let has_social = checks
        .iter()
        .any(|c| c.category == PlatformCategory::SocialMedia);
    let has_dev = checks
        .iter()
        .any(|c| c.category == PlatformCategory::Developer);
    let has_pro = checks
        .iter()
        .any(|c| c.category == PlatformCategory::Professional);
    let has_msg = checks
        .iter()
        .any(|c| c.category == PlatformCategory::Messaging);
    assert!(has_social);
    assert!(has_dev);
    assert!(has_pro);
    assert!(has_msg);
}

#[test]
fn test_email_format_first_dot_last() {
    let email = EmailFormat::FirstDotLast.generate("John", "Doe", "acme.com");
    assert_eq!(email, "john.doe@acme.com");
}

#[test]
fn test_email_format_flast() {
    let email = EmailFormat::FLast.generate("John", "Doe", "acme.com");
    assert_eq!(email, "jdoe@acme.com");
}

#[test]
fn test_email_format_firstl() {
    let email = EmailFormat::FirstL.generate("John", "Doe", "acme.com");
    assert_eq!(email, "johnd@acme.com");
}

#[test]
fn test_email_format_first_only() {
    let email = EmailFormat::FirstOnly.generate("John", "Doe", "acme.com");
    assert_eq!(email, "john@acme.com");
}

#[test]
fn test_email_format_underscore() {
    let email = EmailFormat::FirstUnderscoreLast.generate("John", "Doe", "acme.com");
    assert_eq!(email, "john_doe@acme.com");
}

#[test]
fn test_email_format_hyphen() {
    let email = EmailFormat::FirstHyphenLast.generate("John", "Doe", "acme.com");
    assert_eq!(email, "john-doe@acme.com");
}

#[test]
fn test_email_format_last_dot_first() {
    let email = EmailFormat::LastDotFirst.generate("John", "Doe", "acme.com");
    assert_eq!(email, "doe.john@acme.com");
}

#[test]
fn test_email_format_lastfirst() {
    let email = EmailFormat::LastFirst.generate("John", "Doe", "acme.com");
    assert_eq!(email, "doejohn@acme.com");
}

#[test]
fn test_all_formats_count() {
    let formats = EmailFormat::all_formats();
    assert_eq!(formats.len(), 8);
}

#[test]
fn test_generate_email_permutations() {
    let perms = generate_email_permutations("Jane", "Smith", &["acme.com", "gmail.com"]);
    assert_eq!(perms.len(), 16);
    assert!(perms.contains(&"jane.smith@acme.com".to_string()));
    assert!(perms.contains(&"jsmith@gmail.com".to_string()));
    assert!(perms.contains(&"smith.jane@acme.com".to_string()));
}

#[test]
fn test_generate_email_permutations_single_domain() {
    let perms = generate_email_permutations("Alice", "Johnson", &["example.org"]);
    assert_eq!(perms.len(), 8);
    assert!(perms.contains(&"alice.johnson@example.org".to_string()));
    assert!(perms.contains(&"alice@example.org".to_string()));
}

#[test]
fn test_correlate_username() {
    let checks = vec![
        PlatformCheck {
            platform: Platform::GitHub,
            url_template: "https://github.com/{username}".to_string(),
            category: PlatformCategory::Developer,
        },
        PlatformCheck {
            platform: Platform::Twitter,
            url_template: "https://twitter.com/{username}".to_string(),
            category: PlatformCategory::SocialMedia,
        },
    ];
    let matches = correlate_username("johndoe", &checks);
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].url, "https://github.com/johndoe");
    assert_eq!(matches[1].url, "https://twitter.com/johndoe");
}

#[test]
fn test_correlate_username_confidence_tiers() {
    let checks = build_platform_checks();
    let matches = correlate_username("testuser", &checks);
    let github_match = matches
        .iter()
        .find(|m| m.platform == Platform::GitHub)
        .unwrap();
    let discord_match = matches
        .iter()
        .find(|m| m.platform == Platform::Discord)
        .unwrap();
    assert!(github_match.confidence > discord_match.confidence);
}

#[test]
fn test_infer_timezone_us_eastern() {
    let mut hours: Vec<u8> = Vec::new();
    for _ in 0..30 {
        hours.push(13);
    }
    for _ in 0..25 {
        hours.push(16);
    }
    for _ in 0..20 {
        hours.push(20);
    }
    for _ in 0..5 {
        hours.push(5);
    }
    for _ in 0..2 {
        hours.push(7);
    }
    let locations = infer_timezone_from_posts(&hours);
    assert!(!locations.is_empty());
    assert_eq!(locations[0].method, LocationMethod::TimezoneAnalysis);
    assert!(locations[0].confidence > 0.5);
}

#[test]
fn test_infer_timezone_empty() {
    let locations = infer_timezone_from_posts(&[]);
    assert!(locations.is_empty());
}

#[test]
fn test_infer_timezone_confidence_scales_with_data() {
    let few: Vec<u8> = (0..10).map(|i| i % 24).collect();
    let many: Vec<u8> = (0..100).map(|i| i % 24).collect();
    let loc_few = infer_timezone_from_posts(&few);
    let loc_many = infer_timezone_from_posts(&many);
    assert!(loc_many[0].confidence > loc_few[0].confidence);
}

#[test]
fn test_extract_tech_skills_basic() {
    let repos = vec![
        ("Rust", "aegis", 500),
        ("Rust", "scanner", 200),
        ("Python", "ml-tool", 300),
        ("JavaScript", "frontend", 50),
    ];
    let skills = extract_tech_skills(&repos);
    assert!(!skills.is_empty());
    let rust_skill = skills.iter().find(|s| s.technology == "rust").unwrap();
    assert_eq!(rust_skill.proficiency, ProficiencyLevel::Expert);
}

#[test]
fn test_extract_tech_skills_empty() {
    let skills = extract_tech_skills(&[]);
    assert!(skills.is_empty());
}

#[test]
fn test_extract_tech_skills_single_repo() {
    let repos = vec![("Go", "service", 10)];
    let skills = extract_tech_skills(&repos);
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].technology, "go");
}

#[test]
fn test_extract_tech_skills_sorted_by_confidence() {
    let repos = vec![
        ("Rust", "a", 1000),
        ("Rust", "b", 500),
        ("Python", "c", 100),
        ("Ruby", "d", 10),
    ];
    let skills = extract_tech_skills(&repos);
    for i in 1..skills.len() {
        assert!(skills[i - 1].confidence >= skills[i].confidence);
    }
}

#[test]
fn test_compute_footprint_score_maximum() {
    let score = compute_footprint_score(50, 10, 20, 100, true, true);
    assert!((score - 100.0).abs() < f64::EPSILON);
}

#[test]
fn test_compute_footprint_score_minimum() {
    let score = compute_footprint_score(0, 0, 0, 0, false, false);
    assert!((score - 0.0).abs() < f64::EPSILON);
}

#[test]
fn test_compute_footprint_score_partial() {
    let score = compute_footprint_score(10, 2, 5, 20, true, false);
    assert!(score > 0.0);
    assert!(score < 100.0);
}

#[test]
fn test_compute_footprint_score_breach_heavy() {
    let with_breaches = compute_footprint_score(5, 5, 2, 5, false, false);
    let without_breaches = compute_footprint_score(5, 0, 2, 5, false, false);
    assert!(with_breaches > without_breaches);
}

#[test]
fn test_generate_username_variants() {
    let variants = generate_username_variants("John", "Doe");
    assert!(variants.len() >= 15);
    assert!(variants.contains(&"johndoe".to_string()));
    assert!(variants.contains(&"john.doe".to_string()));
    assert!(variants.contains(&"john_doe".to_string()));
    assert!(variants.contains(&"doejohn".to_string()));
    assert!(variants.contains(&"jdoe".to_string()));
}

#[test]
fn test_generate_username_variants_no_duplicates() {
    let variants = generate_username_variants("Alice", "Bob");
    let mut sorted = variants.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(variants.len(), sorted.len());
}

#[test]
fn test_parse_hibp_breaches_valid() {
    let json = r#"[
        {
            "Name": "Adobe",
            "BreachDate": "2013-10-04",
            "DataClasses": ["Email addresses", "Password hints", "Passwords"],
            "IsVerified": true,
            "IsSensitive": false
        },
        {
            "Name": "LinkedIn",
            "BreachDate": "2012-05-05",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": true,
            "IsSensitive": false
        }
    ]"#;
    let breaches = parse_hibp_breaches(json);
    assert_eq!(breaches.len(), 2);
    assert_eq!(breaches[0].breach_name, "Adobe");
    assert_eq!(breaches[0].breach_date, Some("2013-10-04".to_string()));
    assert!(breaches[0].is_verified);
    assert!(!breaches[0].is_sensitive);
    assert_eq!(breaches[0].data_types.len(), 3);
    assert_eq!(breaches[1].breach_name, "LinkedIn");
}

#[test]
fn test_parse_hibp_breaches_invalid_json() {
    let breaches = parse_hibp_breaches("not json");
    assert!(breaches.is_empty());
}

#[test]
fn test_parse_hibp_breaches_empty_array() {
    let breaches = parse_hibp_breaches("[]");
    assert!(breaches.is_empty());
}

#[test]
fn test_parse_hibp_breaches_sensitive() {
    let json = r#"[{
        "Name": "AdultSite",
        "DataClasses": ["Email addresses"],
        "IsVerified": true,
        "IsSensitive": true
    }]"#;
    let breaches = parse_hibp_breaches(json);
    assert_eq!(breaches.len(), 1);
    assert!(breaches[0].is_sensitive);
    assert!(breaches[0].breach_date.is_none());
}

#[test]
fn test_classify_connections_mutual() {
    let interactions = vec![("twitter", "alice", 50, true, true)];
    let connections = classify_connections(&interactions);
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].relationship, ConnectionType::Mutual);
    assert_eq!(connections[0].target_username, "alice");
}

#[test]
fn test_classify_connections_following() {
    let interactions = vec![("github", "bob", 10, true, false)];
    let connections = classify_connections(&interactions);
    assert_eq!(connections[0].relationship, ConnectionType::Following);
}

#[test]
fn test_classify_connections_follower() {
    let interactions = vec![("instagram", "carol", 5, false, true)];
    let connections = classify_connections(&interactions);
    assert_eq!(connections[0].relationship, ConnectionType::Follower);
}

#[test]
fn test_classify_connections_collaborator() {
    let interactions = vec![("github", "dave", 20, false, false)];
    let connections = classify_connections(&interactions);
    assert_eq!(connections[0].relationship, ConnectionType::Collaborator);
}

#[test]
fn test_classify_connections_unknown() {
    let interactions = vec![("reddit", "eve", 3, false, false)];
    let connections = classify_connections(&interactions);
    assert_eq!(connections[0].relationship, ConnectionType::Unknown);
}

#[test]
fn test_build_employment_history() {
    let records = vec![
        (
            "Acme Corp",
            Some("Engineer"),
            Some("2020-01"),
            Some("2022-06"),
            "linkedin",
        ),
        ("StartupXYZ", Some("CTO"), Some("2022-07"), None, "github"),
    ];
    let history = build_employment_history(&records);
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].company, "Acme Corp");
    assert_eq!(history[0].title, Some("Engineer".to_string()));
    assert!(history[0].confidence > history[1].confidence);
}

#[test]
fn test_build_employment_history_unknown_source() {
    let records = vec![("BigCo", None, None, None, "unknown_source")];
    let history = build_employment_history(&records);
    assert_eq!(history.len(), 1);
    assert!((history[0].confidence - 0.50).abs() < f64::EPSILON);
}

#[test]
fn test_detect_username_patterns() {
    let usernames = vec![
        "john.doe",
        "jane_smith",
        "jd99",
        "alice-bob",
        "longusernamehere",
    ];
    let patterns = detect_username_patterns(&usernames);
    assert!(patterns.contains_key("dot_separated"));
    assert!(patterns.contains_key("underscore_separated"));
    assert!(patterns.contains_key("hyphen_separated"));
    assert!(patterns.contains_key("numeric_suffix"));
}

#[test]
fn test_detect_username_patterns_short_handles() {
    let usernames = vec!["abc", "xy", "test"];
    let patterns = detect_username_patterns(&usernames);
    assert!(patterns.contains_key("short_handle"));
    assert_eq!(patterns["short_handle"].len(), 3);
}

#[test]
fn test_build_person_profile_full() {
    let seed = PersonSeed {
        name: Some("John Doe".to_string()),
        email: Some("john@acme.com".to_string()),
        phone: Some("+1234567890".to_string()),
        username: Some("johndoe".to_string()),
        known_employers: vec!["Acme Corp".to_string()],
    };

    let platform_matches = vec![UsernameMatch {
        platform: Platform::GitHub,
        url: "https://github.com/johndoe".to_string(),
        confidence: 0.85,
        category: PlatformCategory::Developer,
    }];

    let breach_records = vec![PersonBreachRecord {
        breach_name: "TestBreach".to_string(),
        breach_date: Some("2023-01-01".to_string()),
        data_types: vec!["email".to_string()],
        is_verified: true,
        is_sensitive: false,
    }];

    let locations = vec![InferredLocation {
        location: "US/Eastern".to_string(),
        method: LocationMethod::TimezoneAnalysis,
        confidence: 0.80,
    }];

    let profile = build_person_profile(
        &seed,
        platform_matches,
        vec!["john.doe@acme.com".to_string()],
        breach_records,
        vec![],
        vec![],
        locations,
        vec![],
    );

    assert_eq!(profile.name, Some("John Doe".to_string()));
    assert_eq!(profile.emails.len(), 1);
    assert_eq!(profile.phones.len(), 1);
    assert_eq!(profile.platform_matches.len(), 1);
    assert_eq!(profile.breach_records.len(), 1);
    assert_eq!(profile.locations.len(), 1);
    assert!(profile.digital_footprint_score > 0.0);
    assert!(profile.data_points.contains_key("name"));
    assert!(profile.data_points.contains_key("primary_email"));
}

#[test]
fn test_build_person_profile_minimal() {
    let seed = PersonSeed::default();
    let profile = build_person_profile(
        &seed,
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
    );
    assert!(profile.name.is_none());
    assert!(profile.emails.is_empty());
    assert!((profile.digital_footprint_score - 0.0).abs() < f64::EPSILON);
}

#[test]
fn test_platform_display() {
    assert_eq!(Platform::GitHub.to_string(), "GitHub");
    assert_eq!(
        Platform::Custom("mysite.com".to_string()).to_string(),
        "mysite.com"
    );
}

#[test]
fn test_platform_category_display() {
    assert_eq!(PlatformCategory::Developer.to_string(), "Developer");
    assert_eq!(PlatformCategory::SocialMedia.to_string(), "Social Media");
}

#[test]
fn test_connection_type_display() {
    assert_eq!(ConnectionType::Mutual.to_string(), "Mutual");
    assert_eq!(ConnectionType::Collaborator.to_string(), "Collaborator");
}

#[test]
fn test_proficiency_level_ordering() {
    assert!(ProficiencyLevel::Expert > ProficiencyLevel::Beginner);
    assert!(ProficiencyLevel::Advanced > ProficiencyLevel::Intermediate);
}

#[test]
fn test_location_method_display() {
    assert_eq!(
        LocationMethod::TimezoneAnalysis.to_string(),
        "Timezone Analysis"
    );
    assert_eq!(
        LocationMethod::GeotagExtraction.to_string(),
        "Geotag Extraction"
    );
}

#[test]
fn test_email_format_labels() {
    assert_eq!(EmailFormat::FirstDotLast.label(), "first.last@domain");
    assert_eq!(EmailFormat::FLast.label(), "flast@domain");
    assert_eq!(EmailFormat::LastFirst.label(), "lastfirst@domain");
}

#[test]
fn test_correlate_username_url_substitution() {
    let checks = vec![PlatformCheck {
        platform: Platform::TikTok,
        url_template: "https://tiktok.com/@{username}".to_string(),
        category: PlatformCategory::SocialMedia,
    }];
    let matches = correlate_username("cooluser", &checks);
    assert_eq!(matches[0].url, "https://tiktok.com/@cooluser");
}
