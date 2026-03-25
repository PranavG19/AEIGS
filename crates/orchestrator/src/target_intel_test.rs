use super::target_intel::*;
use aegis_protocol::finding::{EvidenceLevel, VulnerabilityClass};

fn sample_intel() -> TargetIntel {
    let mut intel = TargetIntel::new("https://example.com", "scan-001");

    intel.add_tech(TechStackEntry {
        name: "nginx".to_string(),
        version: Some("1.24.0".to_string()),
        category: TechCategory::WebServer,
        confidence: 95,
    });
    intel.add_tech(TechStackEntry {
        name: "Express".to_string(),
        version: Some("4.18".to_string()),
        category: TechCategory::Framework,
        confidence: 90,
    });

    intel.add_endpoint(IntelEndpoint {
        url: "/api/users".to_string(),
        method: "GET".to_string(),
        parameters: vec!["id".to_string()],
        auth_required: true,
        response_codes: vec![200, 401],
        content_type: Some("application/json".to_string()),
        discovery_source: "crawler".to_string(),
    });
    intel.add_endpoint(IntelEndpoint {
        url: "/search".to_string(),
        method: "GET".to_string(),
        parameters: vec!["q".to_string()],
        auth_required: false,
        response_codes: vec![200],
        content_type: Some("text/html".to_string()),
        discovery_source: "crawler".to_string(),
    });

    intel.add_finding(IntelFinding {
        id: 1,
        vulnerability_class: VulnerabilityClass::SqlInjection,
        endpoint: "/api/users".to_string(),
        severity: 9.8,
        confidence: 0.92,
        evidence_level: EvidenceLevel::Confirmed,
        parameter: Some("id".to_string()),
        verified: true,
    });
    intel.add_finding(IntelFinding {
        id: 2,
        vulnerability_class: VulnerabilityClass::CrossSiteScripting,
        endpoint: "/search".to_string(),
        severity: 6.1,
        confidence: 0.85,
        evidence_level: EvidenceLevel::Controlled,
        parameter: Some("q".to_string()),
        verified: false,
    });

    intel.add_defense(IntelDefense {
        defense_type: DefenseType::Waf,
        vendor: Some("Cloudflare".to_string()),
        effectiveness: 0.7,
        bypassed: true,
        bypass_technique: Some("chunked encoding".to_string()),
    });

    intel.add_credential(IntelCredential {
        credential_type: CredentialType::ApiKey,
        location: "/js/config.js".to_string(),
        value_hint: "sk_live_...".to_string(),
        source: "js_extractor".to_string(),
    });

    intel
}

#[test]
fn create_target_intel() {
    let intel = TargetIntel::new("https://example.com", "scan-001");
    assert_eq!(intel.target_url, "https://example.com");
    assert!(intel.findings.is_empty());
}

#[test]
fn add_tech_deduplicates() {
    let mut intel = TargetIntel::new("https://example.com", "scan-001");
    let entry = TechStackEntry {
        name: "nginx".to_string(),
        version: Some("1.24".to_string()),
        category: TechCategory::WebServer,
        confidence: 90,
    };
    intel.add_tech(entry.clone());
    intel.add_tech(entry);
    assert_eq!(intel.tech_stack.len(), 1);
}

#[test]
fn add_endpoint_deduplicates() {
    let mut intel = TargetIntel::new("https://example.com", "scan-001");
    let ep = IntelEndpoint {
        url: "/api/test".to_string(),
        method: "POST".to_string(),
        parameters: vec![],
        auth_required: false,
        response_codes: vec![200],
        content_type: None,
        discovery_source: "manual".to_string(),
    };
    intel.add_endpoint(ep.clone());
    intel.add_endpoint(ep);
    assert_eq!(intel.endpoints.len(), 1);
}

#[test]
fn unique_vuln_classes() {
    let intel = sample_intel();
    let classes = intel.unique_vuln_classes();
    assert!(classes.contains(&VulnerabilityClass::SqlInjection));
    assert!(classes.contains(&VulnerabilityClass::CrossSiteScripting));
    assert_eq!(classes.len(), 2);
}

#[test]
fn findings_above_severity() {
    let intel = sample_intel();
    let critical = intel.findings_above_severity(9.0);
    assert_eq!(critical.len(), 1);
    assert_eq!(
        critical[0].vulnerability_class,
        VulnerabilityClass::SqlInjection
    );
}

#[test]
fn vulnerable_endpoints() {
    let intel = sample_intel();
    let eps = intel.vulnerable_endpoints();
    assert_eq!(eps.len(), 2);
    assert!(eps.contains(&"/api/users"));
    assert!(eps.contains(&"/search"));
}

#[test]
fn bypassed_defenses() {
    let intel = sample_intel();
    let bypassed = intel.bypassed_defenses();
    assert_eq!(bypassed.len(), 1);
    assert_eq!(bypassed[0].defense_type, DefenseType::Waf);
}

#[test]
fn has_waf() {
    let intel = sample_intel();
    assert!(intel.has_waf());

    let empty = TargetIntel::new("https://nowaf.com", "scan-002");
    assert!(!empty.has_waf());
}

#[test]
fn summarize_intel() {
    let intel = sample_intel();
    let summary = intel.summarize();

    assert_eq!(summary.total_endpoints, 2);
    assert_eq!(summary.total_findings, 2);
    assert_eq!(summary.critical_findings, 1);
    assert_eq!(summary.high_findings, 0);
    assert_eq!(summary.tech_stack_size, 2);
    assert_eq!(summary.defense_count, 1);
    assert_eq!(summary.credential_count, 1);
    assert!(summary.top_severity > 9.0);
    assert_eq!(
        summary.vuln_class_distribution.get("SQL Injection"),
        Some(&1)
    );
}

#[test]
fn merge_intels() {
    let mut intel1 = sample_intel();
    let mut intel2 = TargetIntel::new("https://example.com", "scan-002");
    intel2.last_updated_ms = 9999;

    intel2.add_finding(IntelFinding {
        id: 3,
        vulnerability_class: VulnerabilityClass::CommandInjection,
        endpoint: "/exec".to_string(),
        severity: 10.0,
        confidence: 0.99,
        evidence_level: EvidenceLevel::Confirmed,
        parameter: Some("cmd".to_string()),
        verified: true,
    });

    intel1.merge(&intel2);
    assert_eq!(intel1.findings.len(), 3);
    assert_eq!(intel1.last_updated_ms, 9999);
    let classes = intel1.unique_vuln_classes();
    assert!(classes.contains(&VulnerabilityClass::CommandInjection));
}

#[test]
fn json_round_trip() {
    let intel = sample_intel();
    let json = intel.to_json().unwrap();
    assert!(json.contains("SQL Injection") || json.contains("SqlInjection"));
    assert!(json.contains("example.com"));
}

#[test]
fn attack_path_storage() {
    let mut intel = TargetIntel::new("https://example.com", "scan-001");
    intel.add_attack_path(IntelAttackPath {
        name: "SSRF to DB".to_string(),
        steps: vec![
            AttackPathStep {
                description: "Exploit SSRF on /proxy".to_string(),
                vulnerability_class: Some(VulnerabilityClass::ServerSideRequestForgery),
                endpoint: Some("/proxy".to_string()),
                requires_auth: false,
            },
            AttackPathStep {
                description: "Access internal DB".to_string(),
                vulnerability_class: None,
                endpoint: None,
                requires_auth: false,
            },
        ],
        total_severity: 9.5,
        likelihood: 0.7,
    });

    assert_eq!(intel.attack_paths.len(), 1);
    assert_eq!(intel.attack_paths[0].steps.len(), 2);
}
