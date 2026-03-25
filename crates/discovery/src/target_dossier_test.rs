use super::target_dossier::*;

#[test]
fn test_classify_risk_critical() {
    assert_eq!(classify_risk(95.0), RiskLevel::Critical);
    assert_eq!(classify_risk(80.0), RiskLevel::Critical);
}

#[test]
fn test_classify_risk_high() {
    assert_eq!(classify_risk(75.0), RiskLevel::High);
    assert_eq!(classify_risk(60.0), RiskLevel::High);
}

#[test]
fn test_classify_risk_medium() {
    assert_eq!(classify_risk(50.0), RiskLevel::Medium);
    assert_eq!(classify_risk(40.0), RiskLevel::Medium);
}

#[test]
fn test_classify_risk_low() {
    assert_eq!(classify_risk(30.0), RiskLevel::Low);
    assert_eq!(classify_risk(20.0), RiskLevel::Low);
}

#[test]
fn test_classify_risk_informational() {
    assert_eq!(classify_risk(10.0), RiskLevel::Informational);
    assert_eq!(classify_risk(0.0), RiskLevel::Informational);
}

#[test]
fn test_generate_key_findings_breaches() {
    let findings = generate_key_findings(0.0, 0.0, 0.0, 5, 0, 0, 0);
    assert!(findings
        .iter()
        .any(|f| f.category == FindingCategory::CredentialExposure));
    let breach_finding = findings
        .iter()
        .find(|f| f.title.contains("breach"))
        .unwrap();
    assert_eq!(breach_finding.risk_level, RiskLevel::Critical);
}

#[test]
fn test_generate_key_findings_api_keys() {
    let findings = generate_key_findings(0.0, 0.0, 0.0, 0, 3, 0, 0);
    assert!(findings
        .iter()
        .any(|f| f.category == FindingCategory::DataLeakage));
}

#[test]
fn test_generate_key_findings_infra() {
    let findings = generate_key_findings(0.0, 70.0, 0.0, 0, 0, 15, 0);
    assert!(findings
        .iter()
        .any(|f| f.category == FindingCategory::InfrastructureWeakness));
}

#[test]
fn test_generate_key_findings_social_eng() {
    let findings = generate_key_findings(0.0, 0.0, 65.0, 0, 0, 0, 0);
    assert!(findings
        .iter()
        .any(|f| f.category == FindingCategory::SocialEngineeringVector));
}

#[test]
fn test_generate_key_findings_stale_assets() {
    let findings = generate_key_findings(0.0, 0.0, 0.0, 0, 0, 0, 5);
    assert!(findings
        .iter()
        .any(|f| f.category == FindingCategory::StaleAsset));
}

#[test]
fn test_generate_key_findings_sorted_by_risk() {
    let findings = generate_key_findings(80.0, 70.0, 60.0, 5, 3, 20, 5);
    let ranks: Vec<u8> = findings
        .iter()
        .map(|f| match f.risk_level {
            RiskLevel::Critical => 0,
            RiskLevel::High => 1,
            RiskLevel::Medium => 2,
            RiskLevel::Low => 3,
            RiskLevel::Informational => 4,
        })
        .collect();
    for i in 1..ranks.len() {
        assert!(ranks[i] >= ranks[i - 1]);
    }
}

#[test]
fn test_generate_key_findings_empty() {
    let findings = generate_key_findings(0.0, 0.0, 0.0, 0, 0, 0, 0);
    assert!(findings.is_empty());
}

#[test]
fn test_build_attack_surface_web() {
    let techs1: Vec<&str> = vec!["React", "Node.js"];
    let techs2: Vec<&str> = vec!["Express"];
    let techs3: Vec<&str> = vec!["Django"];
    let web: Vec<(&str, &[&str])> = vec![
        ("https://app.example.com", techs1.as_slice()),
        ("https://api.example.com/v1", techs2.as_slice()),
        ("https://admin.example.com", techs3.as_slice()),
    ];
    let surface = build_attack_surface(&web, &[], &[], &[]);
    assert_eq!(surface.len(), 3);
    assert!(surface[0].risk_score >= surface[1].risk_score);
    let admin = surface
        .iter()
        .find(|e| e.entry_point.contains("admin"))
        .unwrap();
    assert_eq!(admin.entry_type, EntryPointType::AdminPanel);
}

#[test]
fn test_build_attack_surface_services() {
    let services = vec![("10.0.0.1", 3306_u16, "mysql"), ("10.0.0.2", 22, "ssh")];
    let surface = build_attack_surface(&[], &services, &[], &[]);
    assert_eq!(surface.len(), 2);
    let db = surface
        .iter()
        .find(|e| e.entry_type == EntryPointType::DatabaseServer)
        .unwrap();
    assert!(db.risk_score > 0.8);
}

#[test]
fn test_build_attack_surface_cloud() {
    let cloud = vec![("acme-backup", "S3")];
    let surface = build_attack_surface(&[], &[], &cloud, &[]);
    assert_eq!(surface.len(), 1);
    assert_eq!(surface[0].entry_type, EntryPointType::CloudStorage);
}

#[test]
fn test_build_attack_surface_third_party() {
    let third_party = vec![("Stripe", "Payment")];
    let surface = build_attack_surface(&[], &[], &[], &third_party);
    assert_eq!(surface.len(), 1);
    assert_eq!(surface[0].entry_type, EntryPointType::ThirdPartyIntegration);
}

#[test]
fn test_build_attack_surface_sorted_by_risk() {
    let web: Vec<(&str, &[&str])> = vec![
        ("https://api.example.com", &["Express"]),
        ("https://admin.example.com", &["Django"]),
        ("https://www.example.com", &["React"]),
    ];
    let surface = build_attack_surface(&web, &[], &[], &[]);
    for i in 1..surface.len() {
        assert!(surface[i - 1].risk_score >= surface[i].risk_score);
    }
}

#[test]
fn test_generate_attack_plan_basic() {
    let surface = vec![AttackSurfaceEntry {
        entry_point: "app.example.com".to_string(),
        entry_type: EntryPointType::WebApplication,
        risk_score: 0.70,
        technologies: vec!["nginx".to_string()],
        vulnerabilities: vec![],
        notes: vec![],
    }];
    let plan = generate_attack_plan(&surface, false, false);
    assert!(!plan.priority_targets.is_empty());
    assert!(!plan.recommended_tools.is_empty());
    assert!(!plan.estimated_timeline.is_empty());
}

#[test]
fn test_generate_attack_plan_with_credentials() {
    let surface = vec![];
    let plan = generate_attack_plan(&surface, true, false);
    assert!(plan
        .priority_targets
        .iter()
        .any(|t| t.target.contains("Credential")));
    assert!(plan.recommended_tools.contains(&"hydra".to_string()));
}

#[test]
fn test_generate_attack_plan_with_api_keys() {
    let surface = vec![];
    let plan = generate_attack_plan(&surface, false, true);
    assert!(plan
        .priority_targets
        .iter()
        .any(|t| t.target.contains("API key")));
}

#[test]
fn test_generate_attack_plan_priority_ordering() {
    let surface = vec![
        AttackSurfaceEntry {
            entry_point: "db.example.com:3306".to_string(),
            entry_type: EntryPointType::DatabaseServer,
            risk_score: 0.90,
            technologies: vec![],
            vulnerabilities: vec![],
            notes: vec![],
        },
        AttackSurfaceEntry {
            entry_point: "app.example.com".to_string(),
            entry_type: EntryPointType::WebApplication,
            risk_score: 0.50,
            technologies: vec![],
            vulnerabilities: vec![],
            notes: vec![],
        },
    ];
    let plan = generate_attack_plan(&surface, true, true);
    for (idx, target) in plan.priority_targets.iter().enumerate() {
        assert_eq!(target.priority, (idx as u8) + 1);
    }
}

#[test]
fn test_assess_opsec_strong() {
    let assessment = assess_opsec(true, true, true, true, true, 0.1, 0);
    assert!(matches!(
        assessment.awareness_level,
        AwarenessLevel::Excellent | AwarenessLevel::Good
    ));
    assert!(assessment.overall_opsec_score > 60.0);
    assert!(assessment.incident_response_readiness > 0.7);
}

#[test]
fn test_assess_opsec_weak() {
    let assessment = assess_opsec(false, false, false, false, false, 0.9, 5);
    assert!(matches!(
        assessment.awareness_level,
        AwarenessLevel::Poor | AwarenessLevel::Negligible
    ));
    assert!(assessment.overall_opsec_score < 30.0);
}

#[test]
fn test_assess_opsec_controls_count() {
    let assessment = assess_opsec(true, false, true, false, true, 0.5, 1);
    assert_eq!(assessment.security_controls.len(), 5);
    let present = assessment
        .security_controls
        .iter()
        .filter(|c| c.is_present)
        .count();
    assert_eq!(present, 3);
}

#[test]
fn test_assess_opsec_training_evidence() {
    let assessment = assess_opsec(true, true, true, true, true, 0.1, 0);
    assert!(!assessment.training_evidence.is_empty());
}

#[test]
fn test_assess_opsec_score_clamped() {
    let strong = assess_opsec(true, true, true, true, true, 0.0, 0);
    assert!(strong.overall_opsec_score <= 100.0);
    let weak = assess_opsec(false, false, false, false, false, 1.0, 10);
    assert!(weak.overall_opsec_score >= 0.0);
}

#[test]
fn test_render_dossier_json() {
    let dossier = make_test_dossier();
    let json = render_dossier_json(&dossier);
    assert!(json.contains("Test Target"));
    assert!(json.contains("executive_summary"));
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed.get("executive_summary").is_some());
}

#[test]
fn test_render_dossier_markdown() {
    let dossier = make_test_dossier();
    let md = render_dossier_markdown(&dossier);
    assert!(md.contains("# Target Dossier"));
    assert!(md.contains("## Executive Summary"));
    assert!(md.contains("Test Target"));
    assert!(md.contains("## Attack Surface Map"));
    assert!(md.contains("## Credential Intelligence"));
    assert!(md.contains("## Social Engineering Playbook"));
    assert!(md.contains("## Technical Attack Plan"));
    assert!(md.contains("## OPSEC Assessment"));
}

#[test]
fn test_render_dossier_markdown_table() {
    let dossier = make_test_dossier();
    let md = render_dossier_markdown(&dossier);
    assert!(md.contains("| Entry Point |"));
    assert!(md.contains("app.example.com"));
}

fn make_test_dossier() -> TargetDossier {
    TargetDossier {
        executive_summary: ExecutiveSummary {
            target_name: "Test Target".to_string(),
            target_type: TargetType::Organization,
            overall_risk: RiskLevel::High,
            risk_score: 72.0,
            key_findings: vec![KeyFinding {
                category: FindingCategory::CredentialExposure,
                title: "Breached credentials found".to_string(),
                description: "Multiple breaches detected".to_string(),
                risk_level: RiskLevel::High,
                confidence: 0.90,
                evidence: vec!["3 breaches".to_string()],
            }],
            recommended_actions: vec!["Rotate all credentials".to_string()],
            generated_at: "2024-03-25T00:00:00Z".to_string(),
        },
        attack_surface: vec![AttackSurfaceEntry {
            entry_point: "app.example.com".to_string(),
            entry_type: EntryPointType::WebApplication,
            risk_score: 0.70,
            technologies: vec!["nginx".to_string(), "React".to_string()],
            vulnerabilities: vec![],
            notes: vec![],
        }],
        credential_intel: CredentialSummary {
            total_breaches: 3,
            total_credentials: 150,
            api_keys_found: 2,
            reuse_probability: 0.45,
            most_recent_breach: Some("2024-01".to_string()),
            exposed_data_types: vec!["email".to_string(), "password".to_string()],
        },
        social_engineering: SocialEngineeringPlaybook {
            recommended_pretexts: vec![RecommendedPretext {
                name: "IT Support".to_string(),
                description: "Impersonate IT helpdesk".to_string(),
                target_audience: "All employees".to_string(),
                success_estimate: 0.65,
            }],
            optimal_timing: vec!["Monday morning".to_string()],
            susceptibility_score: 65.0,
            primary_attack_vector: "Phishing email".to_string(),
        },
        technical_plan: TechnicalAttackPlan {
            priority_targets: vec![PriorityTarget {
                target: "app.example.com".to_string(),
                attack_type: "Web scan".to_string(),
                priority: 1,
                rationale: "Highest risk".to_string(),
                expected_difficulty: Difficulty::Moderate,
            }],
            recommended_tools: vec!["nmap".to_string(), "burpsuite".to_string()],
            estimated_timeline: "1-2 weeks".to_string(),
            required_resources: vec!["Pentest workstation".to_string()],
        },
        opsec_assessment: OpsecAssessment {
            awareness_level: AwarenessLevel::Average,
            security_controls: vec![SecurityControl {
                control_name: "WAF".to_string(),
                is_present: true,
                effectiveness: 0.75,
                notes: None,
            }],
            training_evidence: vec!["WAF deployed".to_string()],
            incident_response_readiness: 0.50,
            overall_opsec_score: 55.0,
        },
    }
}

#[test]
fn test_risk_level_display() {
    assert_eq!(RiskLevel::Critical.to_string(), "Critical");
    assert_eq!(RiskLevel::Informational.to_string(), "Informational");
}

#[test]
fn test_target_type_display() {
    assert_eq!(TargetType::Person.to_string(), "Person");
    assert_eq!(TargetType::Both.to_string(), "Person & Organization");
}

#[test]
fn test_finding_category_display() {
    assert_eq!(
        FindingCategory::CredentialExposure.to_string(),
        "Credential Exposure"
    );
    assert_eq!(
        FindingCategory::SupplyChainRisk.to_string(),
        "Supply Chain Risk"
    );
}

#[test]
fn test_entry_point_type_display() {
    assert_eq!(
        EntryPointType::DatabaseServer.to_string(),
        "Database Server"
    );
    assert_eq!(EntryPointType::AdminPanel.to_string(), "Admin Panel");
}

#[test]
fn test_difficulty_display() {
    assert_eq!(Difficulty::Trivial.to_string(), "Trivial");
    assert_eq!(Difficulty::Expert.to_string(), "Expert");
}

#[test]
fn test_awareness_level_display() {
    assert_eq!(AwarenessLevel::Excellent.to_string(), "Excellent");
    assert_eq!(AwarenessLevel::Negligible.to_string(), "Negligible");
}
