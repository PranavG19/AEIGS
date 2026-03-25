use super::workforce_topology::*;

#[test]
fn test_access_level_display_and_ordering() {
    assert_eq!(AccessLevel::External.to_string(), "External");
    assert_eq!(AccessLevel::Admin.to_string(), "Admin/Root");
    assert!(AccessLevel::External < AccessLevel::Executive);
    assert!(AccessLevel::Individual < AccessLevel::Manager);
}

#[test]
fn test_tech_sophistication_display_and_ordering() {
    assert_eq!(TechSophistication::Developer.to_string(), "Developer");
    assert_eq!(
        TechSophistication::SecurityEngineer.to_string(),
        "Security Engineer"
    );
    assert!(TechSophistication::NonTechnical < TechSophistication::Architect);
}

#[test]
fn test_social_eng_susceptibility_ordering() {
    assert!(SocialEngSusceptibility::Low < SocialEngSusceptibility::VeryHigh);
}

#[test]
fn test_workforce_data_source_display() {
    assert_eq!(WorkforceDataSource::JobPosting.to_string(), "Job Posting");
    assert_eq!(
        WorkforceDataSource::GitHubCommits.to_string(),
        "GitHub Commits"
    );
    assert_eq!(
        WorkforceDataSource::PatentFilings.to_string(),
        "Patent Filings"
    );
}

#[test]
fn test_workforce_relationship_display() {
    assert_eq!(WorkforceRelationship::ReportsTo.to_string(), "Reports To");
    assert_eq!(WorkforceRelationship::CoAuthor.to_string(), "Co-Author");
}

#[test]
fn test_default_config() {
    let config = WorkforceTopologyConfig::default();
    assert!(config.analyze_job_postings);
    assert!(config.analyze_git_patterns);
    assert!(config.analyze_conferences);
    assert!(config.analyze_patents);
    assert!((config.min_collaboration_confidence - 0.3).abs() < f64::EPSILON);
}

#[test]
fn test_config_builder() {
    let config = WorkforceTopologyConfig::default()
        .with_analyze_job_postings(false)
        .with_min_collaboration_confidence(0.5);
    assert!(!config.analyze_job_postings);
    assert!((config.min_collaboration_confidence - 0.5).abs() < f64::EPSILON);
}

#[test]
fn test_config_confidence_clamped() {
    let config = WorkforceTopologyConfig::default().with_min_collaboration_confidence(1.5);
    assert!((config.min_collaboration_confidence - 1.0).abs() < f64::EPSILON);
}

#[test]
fn test_ingest_job_postings() {
    let mut recon = WorkforceTopologyReconstructor::new(WorkforceTopologyConfig::default());
    let postings = vec![
        JobPostingData {
            title: "Senior Security Engineer".to_string(),
            department: Some("Security".to_string()),
            technologies: vec!["Python".to_string(), "Burp Suite".to_string()],
            seniority_signals: vec!["5+ years".to_string()],
            security_requirements: vec!["CISSP preferred".to_string()],
            clearance_required: false,
            remote_allowed: true,
            posted_date: Some("2024-01-15".to_string()),
            source_url: "https://careers.example.com/123".to_string(),
        },
        JobPostingData {
            title: "CTO".to_string(),
            department: None,
            technologies: vec![],
            seniority_signals: vec![],
            security_requirements: vec![],
            clearance_required: false,
            remote_allowed: false,
            posted_date: None,
            source_url: "https://careers.example.com/456".to_string(),
        },
    ];
    recon.ingest_job_postings(&postings);

    assert_eq!(recon.nodes().len(), 2);
    let security_node = recon
        .nodes()
        .iter()
        .find(|n| n.role.as_deref() == Some("Senior Security Engineer"))
        .unwrap();
    assert_eq!(
        security_node.tech_sophistication,
        TechSophistication::SecurityEngineer
    );
    assert_eq!(security_node.department.as_deref(), Some("Security"));

    let cto_node = recon
        .nodes()
        .iter()
        .find(|n| n.role.as_deref() == Some("CTO"))
        .unwrap();
    assert_eq!(cto_node.inferred_access, AccessLevel::Executive);
}

#[test]
fn test_job_postings_disabled() {
    let config = WorkforceTopologyConfig::default().with_analyze_job_postings(false);
    let mut recon = WorkforceTopologyReconstructor::new(config);
    recon.ingest_job_postings(&[JobPostingData {
        title: "Engineer".to_string(),
        department: None,
        technologies: vec![],
        seniority_signals: vec![],
        security_requirements: vec![],
        clearance_required: false,
        remote_allowed: false,
        posted_date: None,
        source_url: "https://example.com".to_string(),
    }]);
    assert!(recon.nodes().is_empty());
}

#[test]
fn test_ingest_git_patterns() {
    let mut recon = WorkforceTopologyReconstructor::new(WorkforceTopologyConfig::default());
    let patterns = vec![
        GitCommitPattern {
            username: "alice_dev".to_string(),
            email: Some("alice@example.com".to_string()),
            repositories: vec!["api-server".to_string(), "frontend".to_string()],
            commit_count: 350,
            active_hours: vec![9, 10, 11, 14, 15, 16],
            active_days: vec!["Mon".to_string(), "Tue".to_string(), "Wed".to_string()],
            languages: vec!["Rust".to_string(), "TypeScript".to_string()],
            first_commit_date: Some("2023-01-01".to_string()),
            last_commit_date: Some("2024-06-01".to_string()),
        },
        GitCommitPattern {
            username: "bob_ops".to_string(),
            email: None,
            repositories: vec!["api-server".to_string(), "infra".to_string()],
            commit_count: 600,
            active_hours: vec![8, 9, 10, 11],
            active_days: vec!["Mon".to_string(), "Fri".to_string()],
            languages: vec![
                "Go".to_string(),
                "Python".to_string(),
                "Bash".to_string(),
                "Terraform".to_string(),
            ],
            first_commit_date: Some("2022-06-01".to_string()),
            last_commit_date: Some("2024-06-15".to_string()),
        },
    ];
    recon.ingest_git_patterns(&patterns);

    assert_eq!(recon.nodes().len(), 2);
    let bob = recon.nodes().iter().find(|n| n.name == "bob_ops").unwrap();
    assert_eq!(bob.tech_sophistication, TechSophistication::SeniorEngineer);

    let collab_edges: Vec<_> = recon
        .edges()
        .iter()
        .filter(|e| e.relationship == WorkforceRelationship::CollaboratesWith)
        .collect();
    assert!(
        !collab_edges.is_empty(),
        "Should detect collaboration via shared repo"
    );
}

#[test]
fn test_ingest_conference_speakers() {
    let mut recon = WorkforceTopologyReconstructor::new(WorkforceTopologyConfig::default());
    let speakers = vec![ConferenceSpeaker {
        name: "Dr. Keiko Tanaka".to_string(),
        affiliation: Some("Security Research".to_string()),
        talk_title: "Breaking Modern TLS".to_string(),
        conference_name: "DEF CON".to_string(),
        topics: vec!["TLS".to_string(), "Cryptography".to_string()],
        year: 2024,
    }];
    recon.ingest_conference_speakers(&speakers);

    assert_eq!(recon.nodes().len(), 1);
    let keiko = &recon.nodes()[0];
    assert!(keiko.tech_sophistication >= TechSophistication::SeniorEngineer);
    assert!(keiko.technologies.contains(&"TLS".to_string()));
}

#[test]
fn test_ingest_patents() {
    let mut recon = WorkforceTopologyReconstructor::new(WorkforceTopologyConfig::default());
    let patents = vec![PatentRecord {
        inventors: vec![
            "Marco Rossi".to_string(),
            "Yuki Sato".to_string(),
            "Sarah Chen".to_string(),
        ],
        title: "Distributed Anomaly Detection System".to_string(),
        patent_number: Some("US12345678".to_string()),
        filing_date: Some("2023-06-15".to_string()),
        assignee: "TechCorp".to_string(),
        technology_area: "Machine Learning".to_string(),
    }];
    recon.ingest_patents(&patents);

    assert_eq!(recon.nodes().len(), 3);
    let coauthor_edges: Vec<_> = recon
        .edges()
        .iter()
        .filter(|e| e.relationship == WorkforceRelationship::CoAuthor)
        .collect();
    assert_eq!(coauthor_edges.len(), 3);
}

#[test]
fn test_full_analysis() {
    let mut recon = WorkforceTopologyReconstructor::new(WorkforceTopologyConfig::default());

    recon.ingest_job_postings(&[
        JobPostingData {
            title: "Director of Engineering".to_string(),
            department: Some("Engineering".to_string()),
            technologies: vec!["AWS".to_string(), "Kubernetes".to_string()],
            seniority_signals: vec!["10+ years".to_string()],
            security_requirements: vec![],
            clearance_required: false,
            remote_allowed: false,
            posted_date: None,
            source_url: "https://example.com/1".to_string(),
        },
        JobPostingData {
            title: "Junior Developer".to_string(),
            department: Some("Engineering".to_string()),
            technologies: vec!["React".to_string(), "TypeScript".to_string()],
            seniority_signals: vec![],
            security_requirements: vec![],
            clearance_required: false,
            remote_allowed: true,
            posted_date: None,
            source_url: "https://example.com/2".to_string(),
        },
    ]);

    let result = recon.analyze();
    assert_eq!(result.nodes.len(), 2);
    assert!(!result.edges.is_empty());
    assert!(!result.department_summary.is_empty());
    assert_eq!(*result.department_summary.get("Engineering").unwrap(), 2);
    assert!(!result.summary.is_empty());
}

#[test]
fn test_empty_analysis() {
    let mut recon = WorkforceTopologyReconstructor::new(WorkforceTopologyConfig::default());
    let result = recon.analyze();
    assert!(result.nodes.is_empty());
    assert!(result.edges.is_empty());
    assert!(result.high_value_targets.is_empty());
}

#[test]
fn test_tech_stack_aggregation() {
    let mut recon = WorkforceTopologyReconstructor::new(WorkforceTopologyConfig::default());
    recon.ingest_job_postings(&[JobPostingData {
        title: "Backend Engineer".to_string(),
        department: Some("Backend".to_string()),
        technologies: vec![
            "Rust".to_string(),
            "PostgreSQL".to_string(),
            "AWS".to_string(),
        ],
        seniority_signals: vec![],
        security_requirements: vec![],
        clearance_required: false,
        remote_allowed: false,
        posted_date: None,
        source_url: "https://example.com/3".to_string(),
    }]);
    let result = recon.analyze();
    assert!(!result.inferred_tech_stack.languages.is_empty());
}

#[test]
fn test_high_value_target_identification() {
    let mut recon = WorkforceTopologyReconstructor::new(WorkforceTopologyConfig::default());
    recon.ingest_job_postings(&[JobPostingData {
        title: "CEO".to_string(),
        department: Some("Executive".to_string()),
        technologies: vec![],
        seniority_signals: vec![],
        security_requirements: vec![],
        clearance_required: false,
        remote_allowed: false,
        posted_date: None,
        source_url: "https://example.com/ceo".to_string(),
    }]);
    let result = recon.analyze();
    assert!(
        !result.high_value_targets.is_empty(),
        "CEO should be high value"
    );
}

#[test]
fn test_department_inference_from_title() {
    let mut recon = WorkforceTopologyReconstructor::new(WorkforceTopologyConfig::default());
    recon.ingest_job_postings(&[JobPostingData {
        title: "DevOps Engineer".to_string(),
        department: None,
        technologies: vec![],
        seniority_signals: vec![],
        security_requirements: vec![],
        clearance_required: false,
        remote_allowed: false,
        posted_date: None,
        source_url: "https://example.com/devops".to_string(),
    }]);
    let node = &recon.nodes()[0];
    assert_eq!(node.department.as_deref(), Some("Infrastructure"));
    assert_eq!(node.inferred_access, AccessLevel::Admin);
}

#[test]
fn test_node_deduplication() {
    let mut recon = WorkforceTopologyReconstructor::new(WorkforceTopologyConfig::default());
    recon.ingest_conference_speakers(&[
        ConferenceSpeaker {
            name: "Jane Doe".to_string(),
            affiliation: Some("Research".to_string()),
            talk_title: "Talk 1".to_string(),
            conference_name: "Conf A".to_string(),
            topics: vec!["Topic1".to_string()],
            year: 2023,
        },
        ConferenceSpeaker {
            name: "Jane Doe".to_string(),
            affiliation: Some("Research".to_string()),
            talk_title: "Talk 2".to_string(),
            conference_name: "Conf B".to_string(),
            topics: vec!["Topic2".to_string()],
            year: 2024,
        },
    ]);
    assert_eq!(recon.nodes().len(), 1);
    assert!(recon.nodes()[0]
        .technologies
        .contains(&"Topic1".to_string()));
    assert!(recon.nodes()[0]
        .technologies
        .contains(&"Topic2".to_string()));
}

#[test]
fn test_reporting_relationships_inferred() {
    let mut recon = WorkforceTopologyReconstructor::new(WorkforceTopologyConfig::default());
    recon.ingest_job_postings(&[
        JobPostingData {
            title: "VP Engineering".to_string(),
            department: Some("Engineering".to_string()),
            technologies: vec![],
            seniority_signals: vec![],
            security_requirements: vec![],
            clearance_required: false,
            remote_allowed: false,
            posted_date: None,
            source_url: "https://example.com/vp".to_string(),
        },
        JobPostingData {
            title: "Software Engineer".to_string(),
            department: Some("Engineering".to_string()),
            technologies: vec!["Java".to_string()],
            seniority_signals: vec![],
            security_requirements: vec![],
            clearance_required: false,
            remote_allowed: true,
            posted_date: None,
            source_url: "https://example.com/swe".to_string(),
        },
    ]);
    let result = recon.analyze();

    let reports_to: Vec<_> = result
        .edges
        .iter()
        .filter(|e| e.relationship == WorkforceRelationship::ReportsTo)
        .collect();
    assert!(!reports_to.is_empty(), "Engineer should report to VP");
}
