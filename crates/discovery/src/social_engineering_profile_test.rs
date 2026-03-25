use super::social_engineering_profile::*;

#[test]
fn test_extract_interests_tech() {
    let posts = vec![
        "Just deployed my new Kubernetes cluster with Terraform!",
        "Learning Rust programming this weekend",
        "The new API design is really clean",
    ];
    let interests = extract_interests(&posts);
    assert!(interests
        .iter()
        .any(|i| i.category == InterestCategory::Technology));
}

#[test]
fn test_extract_interests_multiple() {
    let posts = vec![
        "Great football game last night!",
        "New Spotify playlist for my morning run",
        "Just finished a 10k marathon",
        "Cooking a new recipe tonight",
    ];
    let interests = extract_interests(&posts);
    assert!(interests.len() >= 2);
}

#[test]
fn test_extract_interests_sorted_by_strength() {
    let posts = vec![
        "coding session today",
        "new programming language",
        "deployed to cloud",
        "tech meetup tonight",
        "one football game",
    ];
    let interests = extract_interests(&posts);
    for i in 1..interests.len() {
        assert!(interests[i - 1].strength >= interests[i].strength);
    }
}

#[test]
fn test_extract_interests_empty() {
    let interests = extract_interests(&[]);
    assert!(interests.is_empty());
}

#[test]
fn test_extract_interests_no_match() {
    let posts = vec!["the weather is nice today", "good morning"];
    let interests = extract_interests(&posts);
    assert!(interests.is_empty());
}

#[test]
fn test_analyze_communication_style_formal() {
    let messages = vec![
        "Dear team, pursuant to our discussion, kindly review the enclosed document.",
        "Sincerely regards, I believe we should proceed with the proposal.",
    ];
    let style = analyze_communication_style(&messages);
    assert!(matches!(
        style.formality,
        FormalityLevel::VeryFormal | FormalityLevel::Formal
    ));
}

#[test]
fn test_analyze_communication_style_casual() {
    let messages = vec![
        "hey lol wanna grab lunch?",
        "haha omg that's so funny btw",
        "gonna be late tbh bruh",
    ];
    let style = analyze_communication_style(&messages);
    assert!(matches!(
        style.formality,
        FormalityLevel::VeryCasual | FormalityLevel::Casual
    ));
}

#[test]
fn test_analyze_communication_style_technical() {
    let messages = vec![
        "We need to deploy the Kubernetes cluster with proper VPC networking",
        "The API gateway uses OAuth with JWT tokens for authentication",
        "Set up the CI/CD pipeline with Docker containers and Terraform",
    ];
    let style = analyze_communication_style(&messages);
    assert!(matches!(
        style.technical_depth,
        TechnicalLevel::Expert | TechnicalLevel::Proficient
    ));
}

#[test]
fn test_analyze_communication_style_empty() {
    let style = analyze_communication_style(&[]);
    assert_eq!(style.formality, FormalityLevel::Neutral);
    assert!((style.avg_message_length - 0.0).abs() < f64::EPSILON);
}

#[test]
fn test_analyze_communication_avg_length() {
    let messages = vec!["short", "also short"];
    let style = analyze_communication_style(&messages);
    assert!(style.avg_message_length > 0.0);
    assert!(style.avg_message_length < 15.0);
}

#[test]
fn test_detect_emotional_triggers_job_change() {
    let posts = vec![(
        "Excited to announce I'm joining Google as a Senior Engineer!",
        Some("2024-03"),
    )];
    let triggers = detect_emotional_triggers(&posts);
    assert_eq!(triggers.len(), 1);
    assert_eq!(triggers[0].trigger_type, TriggerType::JobChange);
    assert_eq!(triggers[0].recency, Some("2024-03".to_string()));
}

#[test]
fn test_detect_emotional_triggers_layoff() {
    let posts = vec![(
        "Unfortunately I was laid off last week. Looking for opportunities in security.",
        None,
    )];
    let triggers = detect_emotional_triggers(&posts);
    assert_eq!(triggers.len(), 1);
    assert_eq!(triggers[0].trigger_type, TriggerType::Layoff);
    assert!(triggers[0].exploitability > 0.8);
}

#[test]
fn test_detect_emotional_triggers_multiple() {
    let posts = vec![
        (
            "Just moved to San Francisco! New apartment is great.",
            Some("2024-01"),
        ),
        ("Promoted to Staff Engineer!", Some("2024-02")),
        ("New baby arrived! Dad life begins.", Some("2024-03")),
    ];
    let triggers = detect_emotional_triggers(&posts);
    assert_eq!(triggers.len(), 3);
}

#[test]
fn test_detect_emotional_triggers_none() {
    let posts = vec![
        ("Beautiful sunset this evening", None),
        ("Coffee tastes great this morning", None),
    ];
    let triggers = detect_emotional_triggers(&posts);
    assert!(triggers.is_empty());
}

#[test]
fn test_generate_phishing_templates_with_company() {
    let interests = vec![ExtractedInterest {
        topic: "technology".to_string(),
        category: InterestCategory::Technology,
        evidence: vec![],
        strength: 0.9,
    }];
    let templates = generate_phishing_templates(
        "John Doe",
        &interests,
        &[],
        Some("Engineer"),
        Some("Acme Corp"),
    );
    assert!(!templates.is_empty());
    assert!(templates.iter().any(|t| t.body.contains("Acme Corp")));
    assert!(templates.iter().any(|t| t.body.contains("John Doe")));
}

#[test]
fn test_generate_phishing_templates_with_trigger() {
    let triggers = vec![EmotionalTrigger {
        trigger_type: TriggerType::JobChange,
        description: "New role at BigCo".to_string(),
        recency: Some("2024-03".to_string()),
        exploitability: 0.70,
    }];
    let templates = generate_phishing_templates("Jane", &[], &triggers, None, None);
    assert!(templates.iter().any(|t| t.pretext.contains("Recruiter")));
}

#[test]
fn test_generate_phishing_templates_developer_role() {
    let templates = generate_phishing_templates(
        "Dev User",
        &[],
        &[],
        Some("Software Engineer"),
        Some("TechCo"),
    );
    assert!(templates
        .iter()
        .any(|t| t.pretext.contains("Open Source") || t.pretext.contains("IT")));
}

#[test]
fn test_generate_phishing_urgency_varies() {
    let interests = vec![ExtractedInterest {
        topic: "gaming".to_string(),
        category: InterestCategory::Gaming,
        evidence: vec![],
        strength: 0.8,
    }];
    let templates = generate_phishing_templates("User", &interests, &[], None, Some("Corp"));
    let urgencies: Vec<_> = templates.iter().map(|t| t.urgency).collect();
    assert!(urgencies.contains(&UrgencyLevel::High) || urgencies.contains(&UrgencyLevel::Subtle));
}

#[test]
fn test_generate_pretext_scenarios_with_company() {
    let scenarios = generate_pretext_scenarios("John", Some("Engineer"), Some("Acme"), &[]);
    assert!(!scenarios.is_empty());
    assert!(scenarios.iter().any(|s| s.scenario_name.contains("Vendor")));
}

#[test]
fn test_generate_pretext_scenarios_manager() {
    let scenarios =
        generate_pretext_scenarios("Jane", Some("Engineering Manager"), Some("Corp"), &[]);
    assert!(scenarios
        .iter()
        .any(|s| s.scenario_name.contains("Executive")));
}

#[test]
fn test_generate_pretext_scenarios_with_interests() {
    let interests = vec![ExtractedInterest {
        topic: "technology".to_string(),
        category: InterestCategory::Technology,
        evidence: vec![],
        strength: 0.9,
    }];
    let scenarios = generate_pretext_scenarios("Dev", None, None, &interests);
    assert!(scenarios
        .iter()
        .any(|s| s.scenario_name.contains("technology")));
}

#[test]
fn test_generate_vishing_scripts_with_company() {
    let scripts = generate_vishing_scripts("John", Some("Engineer"), Some("Acme"));
    assert!(scripts.len() >= 2);
    assert!(scripts.iter().any(|s| s.scenario_name.contains("IT")));
    assert!(scripts.iter().any(|s| s.scenario_name.contains("Delivery")));
}

#[test]
fn test_generate_vishing_scripts_has_objection_handlers() {
    let scripts = generate_vishing_scripts("Jane", None, Some("Corp"));
    for script in &scripts {
        assert!(!script.objection_handlers.is_empty());
    }
}

#[test]
fn test_generate_vishing_scripts_has_branches() {
    let scripts = generate_vishing_scripts("User", None, Some("Test"));
    for script in &scripts {
        assert!(!script.script_branches.is_empty());
    }
}

#[test]
fn test_compute_susceptibility_high() {
    let score = compute_susceptibility_score(5, 3, 0.9, &FormalityLevel::VeryCasual, false);
    assert!(score > 70.0);
}

#[test]
fn test_compute_susceptibility_low() {
    let score = compute_susceptibility_score(0, 0, 0.1, &FormalityLevel::VeryFormal, true);
    assert!(score < 20.0);
}

#[test]
fn test_compute_susceptibility_training_reduces() {
    let with_training = compute_susceptibility_score(3, 2, 0.5, &FormalityLevel::Neutral, true);
    let without_training = compute_susceptibility_score(3, 2, 0.5, &FormalityLevel::Neutral, false);
    assert!(with_training < without_training);
}

#[test]
fn test_compute_susceptibility_clamped() {
    let score = compute_susceptibility_score(100, 100, 1.0, &FormalityLevel::VeryCasual, false);
    assert!(score <= 100.0);
    let score_low = compute_susceptibility_score(0, 0, 0.0, &FormalityLevel::VeryFormal, true);
    assert!(score_low >= 0.0);
}

#[test]
fn test_build_social_engineering_profile() {
    let style = CommunicationStyle {
        formality: FormalityLevel::Casual,
        technical_depth: TechnicalLevel::Proficient,
        avg_message_length: 50.0,
        emoji_usage: 0.3,
        response_time_pattern: None,
        preferred_channels: vec!["slack".to_string()],
        vocabulary_complexity: 0.6,
    };
    let profile = build_social_engineering_profile(
        "Test User",
        vec![],
        style,
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        0.5,
        false,
    );
    assert_eq!(profile.target_name, "Test User");
    assert!(profile.overall_susceptibility > 0.0);
}

#[test]
fn test_interest_category_display() {
    assert_eq!(InterestCategory::Technology.to_string(), "Technology");
    assert_eq!(InterestCategory::Gaming.to_string(), "Gaming");
}

#[test]
fn test_formality_level_display() {
    assert_eq!(FormalityLevel::VeryFormal.to_string(), "Very Formal");
    assert_eq!(FormalityLevel::VeryCasual.to_string(), "Very Casual");
}

#[test]
fn test_technical_level_display() {
    assert_eq!(TechnicalLevel::Expert.to_string(), "Expert");
    assert_eq!(TechnicalLevel::NonTechnical.to_string(), "Non-Technical");
}

#[test]
fn test_authority_relationship_display() {
    assert_eq!(
        AuthorityRelationship::DirectManager.to_string(),
        "Direct Manager"
    );
    assert_eq!(
        AuthorityRelationship::ExternalVendor.to_string(),
        "External Vendor"
    );
}

#[test]
fn test_trigger_type_display() {
    assert_eq!(TriggerType::Layoff.to_string(), "Layoff");
    assert_eq!(TriggerType::NewChild.to_string(), "New Child");
}

#[test]
fn test_urgency_level_display() {
    assert_eq!(UrgencyLevel::Critical.to_string(), "Critical");
    assert_eq!(UrgencyLevel::Subtle.to_string(), "Subtle");
}
