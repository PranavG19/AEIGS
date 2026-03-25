use crate::threat_model::*;
use aegis_protocol::finding::VulnerabilityClass;

#[test]
fn test_compute_risk_rating_low() {
    assert_eq!(
        compute_risk_rating(ThreatLikelihood::Low, ThreatImpact::Low),
        RiskRating::Low
    );
    assert_eq!(
        compute_risk_rating(ThreatLikelihood::Low, ThreatImpact::Medium),
        RiskRating::Low
    );
}

#[test]
fn test_compute_risk_rating_medium() {
    assert_eq!(
        compute_risk_rating(ThreatLikelihood::Medium, ThreatImpact::Medium),
        RiskRating::Medium
    );
    assert_eq!(
        compute_risk_rating(ThreatLikelihood::Medium, ThreatImpact::High),
        RiskRating::Medium
    );
}

#[test]
fn test_compute_risk_rating_high() {
    assert_eq!(
        compute_risk_rating(ThreatLikelihood::High, ThreatImpact::High),
        RiskRating::High
    );
}

#[test]
fn test_compute_risk_rating_critical() {
    assert_eq!(
        compute_risk_rating(ThreatLikelihood::Critical, ThreatImpact::Critical),
        RiskRating::Critical
    );
    assert_eq!(
        compute_risk_rating(ThreatLikelihood::Critical, ThreatImpact::High),
        RiskRating::Critical
    );
}

fn sample_architecture() -> DiscoveredArchitecture {
    DiscoveredArchitecture {
        target_name: "TestApp".into(),
        trust_boundaries: vec![TrustBoundary {
            name: "DMZ to Internal".into(),
            from_zone: "DMZ".into(),
            to_zone: "Internal Network".into(),
            description: "Web server to application server boundary".into(),
        }],
        data_flows: vec![DataFlow {
            name: "User Auth Flow".into(),
            source: "Browser".into(),
            destination: "Auth Service".into(),
            data_classification: DataClassification::Confidential,
            protocol: "HTTPS".into(),
        }],
        entry_points: vec![
            EntryPoint {
                name: "/api/login".into(),
                entry_type: EntryPointType::ApiEndpoint,
                url_pattern: "POST /api/login".into(),
                authentication_required: false,
            },
            EntryPoint {
                name: "/api/users".into(),
                entry_type: EntryPointType::ApiEndpoint,
                url_pattern: "GET /api/users".into(),
                authentication_required: true,
            },
        ],
        discovered_vulnerabilities: vec![
            VulnerabilityClass::SqlInjection,
            VulnerabilityClass::BrokenAuthentication,
        ],
    }
}

#[test]
fn test_generate_threat_model_produces_threats() {
    let arch = sample_architecture();
    let model = generate_threat_model(&arch);

    assert_eq!(model.target_name, "TestApp");
    assert!(!model.threats.is_empty());
    assert_eq!(model.summary.total_threats, model.threats.len());
}

#[test]
fn test_all_stride_categories_covered_per_entry_point() {
    let arch = sample_architecture();
    let model = generate_threat_model(&arch);

    let categories_for_login: Vec<StrideCategory> = model
        .threats
        .iter()
        .filter(|t| t.target == "/api/login")
        .map(|t| t.category)
        .collect();

    assert!(categories_for_login.contains(&StrideCategory::Spoofing));
    assert!(categories_for_login.contains(&StrideCategory::Tampering));
    assert!(categories_for_login.contains(&StrideCategory::Repudiation));
    assert!(categories_for_login.contains(&StrideCategory::InformationDisclosure));
    assert!(categories_for_login.contains(&StrideCategory::DenialOfService));
    assert!(categories_for_login.contains(&StrideCategory::ElevationOfPrivilege));
}

#[test]
fn test_unauthenticated_endpoint_higher_spoofing_risk() {
    let arch = sample_architecture();
    let model = generate_threat_model(&arch);

    let login_spoof = model
        .threats
        .iter()
        .find(|t| t.target == "/api/login" && t.category == StrideCategory::Spoofing)
        .expect("login spoofing threat");

    assert_eq!(login_spoof.likelihood, ThreatLikelihood::High);
}

#[test]
fn test_discovered_sqli_raises_tampering_to_critical() {
    let arch = sample_architecture();
    let model = generate_threat_model(&arch);

    let login_tamper = model
        .threats
        .iter()
        .find(|t| t.target == "/api/login" && t.category == StrideCategory::Tampering)
        .expect("login tampering threat");

    assert_eq!(login_tamper.likelihood, ThreatLikelihood::Critical);
}

#[test]
fn test_data_flow_threats_generated() {
    let arch = sample_architecture();
    let model = generate_threat_model(&arch);

    let flow_threats: Vec<&StrideThreat> = model
        .threats
        .iter()
        .filter(|t| t.target == "User Auth Flow")
        .collect();

    assert!(flow_threats.len() >= 2);

    let has_tamper = flow_threats
        .iter()
        .any(|t| t.category == StrideCategory::Tampering);
    let has_info = flow_threats
        .iter()
        .any(|t| t.category == StrideCategory::InformationDisclosure);
    assert!(has_tamper);
    assert!(has_info);
}

#[test]
fn test_confidential_data_flow_high_impact() {
    let arch = sample_architecture();
    let model = generate_threat_model(&arch);

    let flow_info = model
        .threats
        .iter()
        .find(|t| {
            t.target == "User Auth Flow" && t.category == StrideCategory::InformationDisclosure
        })
        .expect("flow info disclosure threat");

    assert_eq!(flow_info.impact, ThreatImpact::High);
}

#[test]
fn test_trust_boundary_threats_generated() {
    let arch = sample_architecture();
    let model = generate_threat_model(&arch);

    let boundary_threats: Vec<&StrideThreat> = model
        .threats
        .iter()
        .filter(|t| t.target == "DMZ to Internal")
        .collect();

    assert!(boundary_threats.len() >= 2);
    let has_spoof = boundary_threats
        .iter()
        .any(|t| t.category == StrideCategory::Spoofing);
    let has_eop = boundary_threats
        .iter()
        .any(|t| t.category == StrideCategory::ElevationOfPrivilege);
    assert!(has_spoof);
    assert!(has_eop);
}

#[test]
fn test_summary_counts_match() {
    let arch = sample_architecture();
    let model = generate_threat_model(&arch);

    let sum = &model.summary;
    assert_eq!(
        sum.total_threats,
        sum.critical_threats + sum.high_threats + sum.medium_threats + sum.low_threats
    );

    let category_sum: usize = sum.threats_by_category.values().sum();
    assert_eq!(sum.total_threats, category_sum);
}

#[test]
fn test_format_threat_model_report_contains_sections() {
    let arch = sample_architecture();
    let model = generate_threat_model(&arch);
    let report = format_threat_model_report(&model);

    assert!(report.contains("# STRIDE Threat Model: TestApp"));
    assert!(report.contains("## Summary"));
    assert!(report.contains("## Trust Boundaries"));
    assert!(report.contains("## Data Flows"));
    assert!(report.contains("## Entry Points"));
    assert!(report.contains("## Threats"));
    assert!(report.contains("T001:"));
}

#[test]
fn test_vuln_to_stride_sqli() {
    let cats = vuln_to_stride_categories(VulnerabilityClass::SqlInjection);
    assert!(cats.contains(&StrideCategory::Tampering));
    assert!(cats.contains(&StrideCategory::InformationDisclosure));
}

#[test]
fn test_vuln_to_stride_broken_auth() {
    let cats = vuln_to_stride_categories(VulnerabilityClass::BrokenAuthentication);
    assert!(cats.contains(&StrideCategory::Spoofing));
    assert!(cats.contains(&StrideCategory::ElevationOfPrivilege));
}

#[test]
fn test_vuln_to_stride_xss() {
    let cats = vuln_to_stride_categories(VulnerabilityClass::CrossSiteScripting);
    assert!(cats.contains(&StrideCategory::Spoofing));
    assert!(cats.contains(&StrideCategory::Tampering));
    assert!(cats.contains(&StrideCategory::InformationDisclosure));
}

#[test]
fn test_empty_architecture() {
    let arch = DiscoveredArchitecture {
        target_name: "Empty".into(),
        ..Default::default()
    };
    let model = generate_threat_model(&arch);
    assert_eq!(model.threats.len(), 0);
    assert_eq!(model.summary.total_threats, 0);
}

#[test]
fn test_all_threats_have_mitigations() {
    let arch = sample_architecture();
    let model = generate_threat_model(&arch);

    for threat in &model.threats {
        assert!(
            !threat.mitigations.is_empty(),
            "threat {:?} on {} has no mitigations",
            threat.category,
            threat.target
        );
    }
}

#[test]
fn test_stride_category_display() {
    assert_eq!(StrideCategory::Spoofing.to_string(), "Spoofing");
    assert_eq!(
        StrideCategory::InformationDisclosure.to_string(),
        "Information Disclosure"
    );
    assert_eq!(
        StrideCategory::ElevationOfPrivilege.to_string(),
        "Elevation of Privilege"
    );
}

#[test]
fn test_data_classification_display() {
    assert_eq!(DataClassification::Restricted.to_string(), "Restricted");
    assert_eq!(DataClassification::Public.to_string(), "Public");
}

#[test]
fn test_entry_point_type_display() {
    assert_eq!(EntryPointType::ApiEndpoint.to_string(), "API Endpoint");
    assert_eq!(
        EntryPointType::GraphQlEndpoint.to_string(),
        "GraphQL Endpoint"
    );
}

#[test]
fn test_risk_rating_display() {
    assert_eq!(RiskRating::Critical.to_string(), "Critical");
    assert_eq!(RiskRating::Low.to_string(), "Low");
}
