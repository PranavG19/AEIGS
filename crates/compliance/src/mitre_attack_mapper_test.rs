use crate::mitre_attack_mapper::{
    generate_navigator_layer, map_finding, map_findings, technique_for, to_navigator_json,
};
use aegis_protocol::finding::VulnerabilityClass;

#[test]
fn map_sql_injection_returns_correct_technique() {
    let mapping = map_finding(VulnerabilityClass::SqlInjection, 9.8);
    assert_eq!(mapping.technique_id, "T1190");
    assert_eq!(mapping.technique_name, "Exploit Public-Facing Application");
    assert_eq!(mapping.tactic, "initial-access");
    assert_eq!(mapping.vulnerability_class, "SQL Injection");
    assert!((mapping.severity - 9.8).abs() < f64::EPSILON);
}

#[test]
fn map_all_34_vulnerability_classes() {
    let all_classes = [
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::ServerSideRequestForgery,
        VulnerabilityClass::InsecureDeserialization,
        VulnerabilityClass::BrokenAuthentication,
        VulnerabilityClass::BrokenAuthorization,
        VulnerabilityClass::SecurityMisconfiguration,
        VulnerabilityClass::SensitiveDataExposure,
        VulnerabilityClass::ServerSideTemplateInjection,
        VulnerabilityClass::HeaderInjection,
        VulnerabilityClass::OpenRedirect,
        VulnerabilityClass::CrlfInjection,
        VulnerabilityClass::KnownVulnerableDependency,
        VulnerabilityClass::InsufficientInputValidation,
        VulnerabilityClass::NoSqlInjection,
        VulnerabilityClass::XmlExternalEntity,
        VulnerabilityClass::CrossOriginMisconfiguration,
        VulnerabilityClass::MissingSecurityHeader,
        VulnerabilityClass::JwtVulnerability,
        VulnerabilityClass::HttpRequestSmuggling,
        VulnerabilityClass::RaceCondition,
        VulnerabilityClass::SubdomainTakeover,
        VulnerabilityClass::PrototypePollution,
        VulnerabilityClass::GraphQlAbuse,
        VulnerabilityClass::CloudMisconfiguration,
        VulnerabilityClass::Clickjacking,
        VulnerabilityClass::CachePoisoning,
        VulnerabilityClass::HostHeaderInjection,
        VulnerabilityClass::InsecureDirectObjectReference,
        VulnerabilityClass::InformationDisclosure,
        VulnerabilityClass::WeakCryptography,
        VulnerabilityClass::MassAssignment,
    ];

    assert_eq!(all_classes.len(), 34);

    for class in &all_classes {
        let mapping = map_finding(*class, 5.0);
        assert!(
            !mapping.technique_id.is_empty(),
            "empty technique_id for {class}"
        );
        assert!(
            !mapping.technique_name.is_empty(),
            "empty technique_name for {class}"
        );
        assert!(!mapping.tactic.is_empty(), "empty tactic for {class}");
        assert!(
            mapping.technique_id.starts_with('T'),
            "technique_id should start with 'T' for {class}, got {}",
            mapping.technique_id
        );
    }
}

#[test]
fn navigator_layer_contains_expected_structure() {
    let mappings = vec![
        map_finding(VulnerabilityClass::SqlInjection, 9.8),
        map_finding(VulnerabilityClass::CrossSiteScripting, 6.1),
    ];

    let layer = generate_navigator_layer(&mappings, "Test Scan");

    assert_eq!(layer.name, "Test Scan");
    assert_eq!(layer.domain, "enterprise-attack");
    assert_eq!(layer.versions.attack, "15.1");
    assert_eq!(layer.versions.navigator, "5.0.0");
    assert_eq!(layer.versions.layer, "4.5");
    assert_eq!(layer.techniques.len(), 2);
    assert_eq!(layer.gradient.colors.len(), 2);
    assert_eq!(layer.gradient.min_value, 0);
    assert_eq!(layer.gradient.max_value, 100);
}

#[test]
fn deduplication_keeps_highest_severity() {
    let findings = vec![
        (VulnerabilityClass::SqlInjection, 3.0),
        (VulnerabilityClass::NoSqlInjection, 7.5),
        (VulnerabilityClass::InsecureDeserialization, 9.8),
    ];

    let mappings = map_findings(&findings);

    let t1190 = mappings
        .iter()
        .find(|m| m.technique_id == "T1190")
        .expect("T1190 should be present");

    assert!(
        (t1190.severity - 9.8).abs() < f64::EPSILON,
        "should keep highest severity (9.8), got {}",
        t1190.severity
    );
}

#[test]
fn score_capping_at_100() {
    let mapping = map_finding(VulnerabilityClass::SqlInjection, 15.0);
    let layer = generate_navigator_layer(&[mapping], "Cap Test");

    assert_eq!(layer.techniques[0].score, 100);
}

#[test]
fn color_mapping_by_severity_thresholds() {
    let critical = map_finding(VulnerabilityClass::SqlInjection, 9.8);
    let high = map_finding(VulnerabilityClass::CrossSiteScripting, 5.5);
    let medium = map_finding(VulnerabilityClass::OpenRedirect, 3.0);
    let low = map_finding(VulnerabilityClass::MissingSecurityHeader, 1.0);

    let layer = generate_navigator_layer(&[critical, high, medium, low], "Color Test");

    assert_eq!(layer.techniques[0].color, "#ff4444", "severity 9.8 -> red");
    assert_eq!(
        layer.techniques[1].color, "#ff8c00",
        "severity 5.5 -> orange"
    );
    assert_eq!(layer.techniques[2].color, "#ffd700", "severity 3.0 -> gold");
    assert_eq!(
        layer.techniques[3].color, "#44ff44",
        "severity 1.0 -> green"
    );
}

#[test]
fn detection_recommendations_nonempty_for_all_classes() {
    let all_classes = [
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::ServerSideRequestForgery,
        VulnerabilityClass::InsecureDeserialization,
        VulnerabilityClass::BrokenAuthentication,
        VulnerabilityClass::BrokenAuthorization,
        VulnerabilityClass::SecurityMisconfiguration,
        VulnerabilityClass::SensitiveDataExposure,
        VulnerabilityClass::ServerSideTemplateInjection,
        VulnerabilityClass::HeaderInjection,
        VulnerabilityClass::OpenRedirect,
        VulnerabilityClass::CrlfInjection,
        VulnerabilityClass::KnownVulnerableDependency,
        VulnerabilityClass::InsufficientInputValidation,
        VulnerabilityClass::NoSqlInjection,
        VulnerabilityClass::XmlExternalEntity,
        VulnerabilityClass::CrossOriginMisconfiguration,
        VulnerabilityClass::MissingSecurityHeader,
        VulnerabilityClass::JwtVulnerability,
        VulnerabilityClass::HttpRequestSmuggling,
        VulnerabilityClass::RaceCondition,
        VulnerabilityClass::SubdomainTakeover,
        VulnerabilityClass::PrototypePollution,
        VulnerabilityClass::GraphQlAbuse,
        VulnerabilityClass::CloudMisconfiguration,
        VulnerabilityClass::Clickjacking,
        VulnerabilityClass::CachePoisoning,
        VulnerabilityClass::HostHeaderInjection,
        VulnerabilityClass::InsecureDirectObjectReference,
        VulnerabilityClass::InformationDisclosure,
        VulnerabilityClass::WeakCryptography,
        VulnerabilityClass::MassAssignment,
    ];

    for class in &all_classes {
        let mapping = map_finding(*class, 5.0);
        assert!(
            mapping.detection_recommendations.len() >= 2,
            "expected at least 2 detection recommendations for {class}, got {}",
            mapping.detection_recommendations.len()
        );
        for rec in &mapping.detection_recommendations {
            assert!(
                !rec.is_empty(),
                "empty detection recommendation for {class}"
            );
        }
    }
}

#[test]
fn procedure_descriptions_nonempty_for_all_classes() {
    let all_classes = [
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::ServerSideRequestForgery,
        VulnerabilityClass::InsecureDeserialization,
        VulnerabilityClass::BrokenAuthentication,
        VulnerabilityClass::BrokenAuthorization,
        VulnerabilityClass::SecurityMisconfiguration,
        VulnerabilityClass::SensitiveDataExposure,
        VulnerabilityClass::ServerSideTemplateInjection,
        VulnerabilityClass::HeaderInjection,
        VulnerabilityClass::OpenRedirect,
        VulnerabilityClass::CrlfInjection,
        VulnerabilityClass::KnownVulnerableDependency,
        VulnerabilityClass::InsufficientInputValidation,
        VulnerabilityClass::NoSqlInjection,
        VulnerabilityClass::XmlExternalEntity,
        VulnerabilityClass::CrossOriginMisconfiguration,
        VulnerabilityClass::MissingSecurityHeader,
        VulnerabilityClass::JwtVulnerability,
        VulnerabilityClass::HttpRequestSmuggling,
        VulnerabilityClass::RaceCondition,
        VulnerabilityClass::SubdomainTakeover,
        VulnerabilityClass::PrototypePollution,
        VulnerabilityClass::GraphQlAbuse,
        VulnerabilityClass::CloudMisconfiguration,
        VulnerabilityClass::Clickjacking,
        VulnerabilityClass::CachePoisoning,
        VulnerabilityClass::HostHeaderInjection,
        VulnerabilityClass::InsecureDirectObjectReference,
        VulnerabilityClass::InformationDisclosure,
        VulnerabilityClass::WeakCryptography,
        VulnerabilityClass::MassAssignment,
    ];

    for class in &all_classes {
        let mapping = map_finding(*class, 5.0);
        assert!(
            !mapping.procedure_description.is_empty(),
            "empty procedure_description for {class}"
        );
        assert!(
            mapping.procedure_description.len() > 50,
            "procedure_description too short for {class}: '{}'",
            mapping.procedure_description
        );
    }
}

#[test]
fn navigator_layer_domain_is_enterprise_attack() {
    let layer = generate_navigator_layer(&[], "Empty Layer");
    assert_eq!(layer.domain, "enterprise-attack");
}

#[test]
fn json_serialization_produces_valid_output() {
    let mappings = vec![
        map_finding(VulnerabilityClass::SqlInjection, 9.8),
        map_finding(VulnerabilityClass::CommandInjection, 7.2),
        map_finding(VulnerabilityClass::PathTraversal, 4.5),
    ];

    let layer = generate_navigator_layer(&mappings, "JSON Test");
    let json = to_navigator_json(&layer).expect("serialization should succeed");

    let parsed: serde_json::Value = serde_json::from_str(&json).expect("should be valid JSON");

    assert_eq!(parsed["name"], "JSON Test");
    assert_eq!(parsed["domain"], "enterprise-attack");
    assert!(parsed["techniques"].is_array());
    assert_eq!(parsed["techniques"].as_array().unwrap().len(), 3);
    assert_eq!(parsed["versions"]["attack"], "15.1");
    assert!(parsed["gradient"]["colors"].is_array());

    let first_technique = &parsed["techniques"][0];
    assert!(first_technique["techniqueID"].is_string());
    assert!(first_technique["score"].is_number());
    assert!(first_technique["enabled"].is_boolean());
    assert_eq!(first_technique["showSubtechniques"], false);
}

#[test]
fn technique_for_returns_correct_attack_technique() {
    let technique = technique_for(&VulnerabilityClass::SubdomainTakeover);
    assert_eq!(technique.id, "T1584");
    assert_eq!(technique.name, "Compromise Infrastructure");
    assert_eq!(technique.tactic, "resource-development");

    let technique = technique_for(&VulnerabilityClass::CachePoisoning);
    assert_eq!(technique.id, "T1557");
    assert_eq!(technique.name, "Adversary-in-the-Middle");
    assert_eq!(technique.tactic, "credential-access");
}

#[test]
fn map_findings_deduplicates_distinct_techniques() {
    let findings = vec![
        (VulnerabilityClass::SqlInjection, 8.0),
        (VulnerabilityClass::CommandInjection, 7.0),
        (VulnerabilityClass::CrossSiteScripting, 6.0),
    ];

    let mappings = map_findings(&findings);

    assert_eq!(mappings.len(), 3, "three distinct techniques should remain");

    let ids: Vec<&str> = mappings.iter().map(|m| m.technique_id.as_str()).collect();
    assert!(ids.contains(&"T1190"));
    assert!(ids.contains(&"T1059"));
    assert!(ids.contains(&"T1189"));
}

#[test]
fn navigator_technique_score_calculation() {
    let mapping = map_finding(VulnerabilityClass::SqlInjection, 7.5);
    let layer = generate_navigator_layer(&[mapping], "Score Test");

    assert_eq!(layer.techniques[0].score, 75);
}

#[test]
fn navigator_technique_enabled_and_subtechniques_flags() {
    let mapping = map_finding(VulnerabilityClass::CommandInjection, 5.0);
    let layer = generate_navigator_layer(&[mapping], "Flags Test");

    assert!(layer.techniques[0].enabled);
    assert!(!layer.techniques[0].show_subtechniques);
}

#[test]
fn navigator_technique_comment_contains_procedure_description() {
    let mapping = map_finding(VulnerabilityClass::ServerSideRequestForgery, 8.5);
    let layer = generate_navigator_layer(&[mapping], "Comment Test");

    assert!(
        layer.techniques[0].comment.contains("internal services"),
        "comment should contain procedure description"
    );
}
