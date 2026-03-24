use aegis_protocol::finding::VulnerabilityClass;

use crate::narrative_gen::{
    AttackChainNode, AttackChainPath, BaselineFindings, FindingEvidence, NarrativeInput,
    NarrativeReport, ReportSection, ReportTemplate, generate_narrative_report,
};
use crate::sarif_emitter::{SarifDefenseContext, SarifFinding, SarifLevel};

fn make_finding(
    rule_id: &str,
    vc: VulnerabilityClass,
    composite: f64,
    severity: f64,
    confidence: f64,
) -> SarifFinding {
    SarifFinding {
        rule_id: rule_id.to_string(),
        rule_description: format!("{vc} detected"),
        level: if composite >= 70.0 {
            SarifLevel::Error
        } else if composite >= 40.0 {
            SarifLevel::Warning
        } else {
            SarifLevel::Note
        },
        message: format!("{vc} found in application"),
        uri: Some("https://example.com/app".to_string()),
        logical_location_name: None,
        logical_location_kind: None,
        severity,
        confidence,
        composite_score: composite,
        vulnerability_class: Some(vc),
        related_locations: vec![],
        defense_context: None,
        evidence_level: None,
        cve_id: None,
        mitigation_rank: None,
        suppression_kind: None,
        suppression_message: None,
        endpoint: Some("/api/users".to_string()),
        http_method: Some("POST".to_string()),
        parameter_name: Some("id".to_string()),
    }
}

fn make_finding_with_defense(
    rule_id: &str,
    vc: VulnerabilityClass,
    composite: f64,
) -> SarifFinding {
    let mut f = make_finding(rule_id, vc, composite, 8.0, 0.9);
    f.defense_context = Some(SarifDefenseContext {
        waf_vendor: Some("Cloudflare".to_string()),
        exploitable_despite_waf: true,
        evasion_technique: Some("encoding".to_string()),
        defenses_detected: vec!["WAF".to_string(), "Rate Limiter".to_string()],
        evasion_success_rate: Some(0.75),
        stealth_mode_used: true,
    });
    f
}

fn default_input(findings: &[SarifFinding]) -> NarrativeInput<'_> {
    NarrativeInput {
        findings,
        attack_chains: &[],
        baseline: None,
        evidence: &[],
        target_url: "https://example.com",
        scan_date: "2025-01-15",
    }
}

#[test]
fn full_report_generates_all_eight_sections() {
    let findings = vec![make_finding(
        "SQLI-001",
        VulnerabilityClass::SqlInjection,
        85.0,
        9.0,
        0.95,
    )];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    assert_eq!(report.sections.len(), 8);
}

#[test]
fn executive_summary_contains_target_and_date() {
    let findings = vec![make_finding(
        "XSS-001",
        VulnerabilityClass::CrossSiteScripting,
        55.0,
        7.0,
        0.8,
    )];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let exec = &report.sections[0];
    assert_eq!(exec.title, "Executive Summary");
    assert!(exec.body.contains("https://example.com"));
    assert!(exec.body.contains("2025-01-15"));
    assert!(exec.body.contains("1 findings"));
}

#[test]
fn executive_summary_critical_urgency() {
    let findings = vec![
        make_finding(
            "SQLI-001",
            VulnerabilityClass::SqlInjection,
            85.0,
            9.0,
            0.95,
        ),
        make_finding(
            "XSS-001",
            VulnerabilityClass::CrossSiteScripting,
            30.0,
            5.0,
            0.6,
        ),
    ];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let exec = &report.sections[0];
    assert!(exec.body.contains("critical"));
    assert!(exec.body.contains("immediate remediation"));
}

#[test]
fn executive_summary_no_critical_findings() {
    let findings = vec![make_finding(
        "INFO-001",
        VulnerabilityClass::InformationDisclosure,
        15.0,
        3.0,
        0.5,
    )];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let exec = &report.sections[0];
    assert!(exec.body.contains("sound security posture"));
}

#[test]
fn executive_summary_defense_context() {
    let findings = vec![make_finding_with_defense(
        "SQLI-001",
        VulnerabilityClass::SqlInjection,
        80.0,
    )];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let exec = &report.sections[0];
    assert!(exec.body.contains("WAF"));
}

#[test]
fn finding_narrative_has_description_impact_repro_remediation() {
    let findings = vec![make_finding(
        "SQLI-001",
        VulnerabilityClass::SqlInjection,
        85.0,
        9.0,
        0.95,
    )];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[1];
    assert_eq!(section.title, "Detailed Findings");
    assert!(section.body.contains("**Description:**"));
    assert!(section.body.contains("**Impact:**"));
    assert!(section.body.contains("**Reproduction Steps:**"));
    assert!(section.body.contains("**Remediation:**"));
}

#[test]
fn finding_narrative_includes_endpoint_and_parameter() {
    let findings = vec![make_finding(
        "SQLI-001",
        VulnerabilityClass::SqlInjection,
        85.0,
        9.0,
        0.95,
    )];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[1];
    assert!(section.body.contains("POST /api/users"));
    assert!(section.body.contains("`id`"));
}

#[test]
fn finding_narrative_respects_max_findings_limit() {
    let findings = vec![
        make_finding(
            "SQLI-001",
            VulnerabilityClass::SqlInjection,
            85.0,
            9.0,
            0.95,
        ),
        make_finding(
            "XSS-001",
            VulnerabilityClass::CrossSiteScripting,
            55.0,
            7.0,
            0.8,
        ),
        make_finding(
            "CMD-001",
            VulnerabilityClass::CommandInjection,
            45.0,
            6.0,
            0.7,
        ),
    ];
    let mut template = ReportTemplate::default();
    template.max_findings_in_detail = Some(1);
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &template);
    let section = &report.sections[1];
    assert!(section.body.contains("SQLI-001"));
    assert!(!section.body.contains("CMD-001"));
}

#[test]
fn risk_scoring_narrative_explains_scale() {
    let findings = vec![make_finding(
        "SQLI-001",
        VulnerabilityClass::SqlInjection,
        85.0,
        9.0,
        0.95,
    )];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[2];
    assert_eq!(section.title, "Risk Scoring Analysis");
    assert!(section.body.contains("0\u{2013}100"));
    assert!(section.body.contains("critical"));
    assert!(section.body.contains("SQLI-001"));
}

#[test]
fn risk_scoring_shows_average() {
    let findings = vec![
        make_finding("A", VulnerabilityClass::SqlInjection, 80.0, 9.0, 0.9),
        make_finding("B", VulnerabilityClass::CrossSiteScripting, 40.0, 5.0, 0.7),
    ];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[2];
    assert!(section.body.contains("60.0"));
}

#[test]
fn attack_chain_empty() {
    let findings = vec![make_finding(
        "A",
        VulnerabilityClass::SqlInjection,
        80.0,
        9.0,
        0.9,
    )];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[3];
    assert_eq!(section.title, "Attack Chain Analysis");
    assert!(section.body.contains("No multi-step attack chains"));
}

#[test]
fn attack_chain_narrative_from_path() {
    let findings = vec![make_finding(
        "A",
        VulnerabilityClass::SqlInjection,
        80.0,
        9.0,
        0.9,
    )];
    let chains = vec![AttackChainPath {
        nodes: vec![
            AttackChainNode {
                label: "entry".to_string(),
                vulnerability_class: Some(VulnerabilityClass::CrossSiteScripting),
                endpoint: Some("/login".to_string()),
            },
            AttackChainNode {
                label: "pivot".to_string(),
                vulnerability_class: Some(VulnerabilityClass::InsecureDirectObjectReference),
                endpoint: Some("/api/users".to_string()),
            },
        ],
        total_difficulty: 3.5,
    }];
    let input = NarrativeInput {
        findings: &findings,
        attack_chains: &chains,
        baseline: None,
        evidence: &[],
        target_url: "https://example.com",
        scan_date: "2025-01-15",
    };
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[3];
    assert!(section.body.contains("Chain 1"));
    assert!(section.body.contains("Cross-Site Scripting"));
    assert!(section.body.contains("/login"));
    assert!(section.body.contains("Insecure Direct Object Reference"));
    assert!(section.body.contains("/api/users"));
}

#[test]
fn trend_analysis_no_baseline() {
    let findings = vec![make_finding(
        "A",
        VulnerabilityClass::SqlInjection,
        80.0,
        9.0,
        0.9,
    )];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[4];
    assert_eq!(section.title, "Trend Analysis");
    assert!(section.body.contains("No baseline"));
}

#[test]
fn trend_analysis_with_baseline_increase() {
    let findings = vec![
        make_finding("A", VulnerabilityClass::SqlInjection, 80.0, 9.0, 0.9),
        make_finding("B", VulnerabilityClass::CrossSiteScripting, 50.0, 6.0, 0.8),
    ];
    let baseline = BaselineFindings {
        total_count: 1,
        critical_count: 1,
        high_count: 0,
        resolved_rule_ids: vec!["OLD-001".to_string()],
        new_rule_ids: vec!["B".to_string()],
    };
    let input = NarrativeInput {
        findings: &findings,
        attack_chains: &[],
        baseline: Some(&baseline),
        evidence: &[],
        target_url: "https://example.com",
        scan_date: "2025-01-15",
    };
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[4];
    assert!(section.body.contains("increase of 1"));
    assert!(section.body.contains("OLD-001"));
    assert!(section.body.contains("Newly identified"));
}

#[test]
fn trend_analysis_with_baseline_decrease() {
    let findings = vec![make_finding(
        "A",
        VulnerabilityClass::SqlInjection,
        80.0,
        9.0,
        0.9,
    )];
    let baseline = BaselineFindings {
        total_count: 3,
        critical_count: 2,
        high_count: 1,
        resolved_rule_ids: vec![],
        new_rule_ids: vec![],
    };
    let input = NarrativeInput {
        findings: &findings,
        attack_chains: &[],
        baseline: Some(&baseline),
        evidence: &[],
        target_url: "https://example.com",
        scan_date: "2025-01-15",
    };
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[4];
    assert!(section.body.contains("decrease of 2"));
}

#[test]
fn remediation_priority_ordered_by_score() {
    let findings = vec![
        make_finding(
            "LOW-001",
            VulnerabilityClass::InformationDisclosure,
            10.0,
            2.0,
            0.5,
        ),
        make_finding(
            "HIGH-001",
            VulnerabilityClass::SqlInjection,
            85.0,
            9.0,
            0.95,
        ),
        make_finding("MED-001", VulnerabilityClass::OpenRedirect, 35.0, 5.0, 0.7),
    ];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[5];
    assert_eq!(section.title, "Remediation Priority");
    let high_pos = section.body.find("HIGH-001").unwrap();
    let med_pos = section.body.find("MED-001").unwrap();
    let low_pos = section.body.find("LOW-001").unwrap();
    assert!(high_pos < med_pos);
    assert!(med_pos < low_pos);
}

#[test]
fn compliance_mapping_owasp_groups() {
    let findings = vec![
        make_finding(
            "SQLI-001",
            VulnerabilityClass::SqlInjection,
            85.0,
            9.0,
            0.95,
        ),
        make_finding(
            "XSS-001",
            VulnerabilityClass::CrossSiteScripting,
            55.0,
            7.0,
            0.8,
        ),
    ];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[6];
    assert_eq!(section.title, "Compliance Mapping");
    assert!(section.body.contains("A03:2021 Injection"));
    assert!(section.body.contains("PCI-DSS"));
}

#[test]
fn compliance_mapping_multiple_categories() {
    let findings = vec![
        make_finding(
            "SQLI-001",
            VulnerabilityClass::SqlInjection,
            85.0,
            9.0,
            0.95,
        ),
        make_finding(
            "AUTH-001",
            VulnerabilityClass::BrokenAuthentication,
            60.0,
            7.0,
            0.85,
        ),
    ];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[6];
    assert!(section.body.contains("A03:2021"));
    assert!(section.body.contains("A07:2021"));
}

#[test]
fn technical_appendix_empty() {
    let findings = vec![make_finding(
        "A",
        VulnerabilityClass::SqlInjection,
        80.0,
        9.0,
        0.9,
    )];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[7];
    assert_eq!(section.title, "Technical Appendix");
    assert!(section.body.contains("No raw request/response evidence"));
}

#[test]
fn technical_appendix_with_evidence() {
    let findings = vec![make_finding(
        "A",
        VulnerabilityClass::SqlInjection,
        80.0,
        9.0,
        0.9,
    )];
    let evidence = vec![FindingEvidence {
        rule_id: "SQLI-001".to_string(),
        request_method: "POST".to_string(),
        request_url: "https://example.com/api/users".to_string(),
        request_headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        request_body: Some("{\"id\": \"1 OR 1=1\"}".to_string()),
        response_status: 200,
        response_headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        response_body_snippet: Some("{\"users\": [...]}".to_string()),
    }];
    let input = NarrativeInput {
        findings: &findings,
        attack_chains: &[],
        baseline: None,
        evidence: &evidence,
        target_url: "https://example.com",
        scan_date: "2025-01-15",
    };
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[7];
    assert!(section.body.contains("SQLI-001"));
    assert!(section.body.contains("POST https://example.com/api/users"));
    assert!(section.body.contains("1 OR 1=1"));
    assert!(section.body.contains("200"));
}

#[test]
fn template_executive_only_three_sections() {
    let findings = vec![make_finding(
        "A",
        VulnerabilityClass::SqlInjection,
        80.0,
        9.0,
        0.9,
    )];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::executive_only());
    assert_eq!(report.sections.len(), 3);
    let titles: Vec<&str> = report.sections.iter().map(|s| s.title.as_str()).collect();
    assert!(titles.contains(&"Executive Summary"));
    assert!(titles.contains(&"Risk Scoring Analysis"));
    assert!(titles.contains(&"Remediation Priority"));
}

#[test]
fn template_technical_only_excludes_executive() {
    let findings = vec![make_finding(
        "A",
        VulnerabilityClass::SqlInjection,
        80.0,
        9.0,
        0.9,
    )];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::technical_only());
    let titles: Vec<&str> = report.sections.iter().map(|s| s.title.as_str()).collect();
    assert!(!titles.contains(&"Executive Summary"));
    assert!(titles.contains(&"Detailed Findings"));
    assert!(titles.contains(&"Technical Appendix"));
}

#[test]
fn custom_header_and_footer() {
    let findings = vec![make_finding(
        "A",
        VulnerabilityClass::SqlInjection,
        80.0,
        9.0,
        0.9,
    )];
    let input = default_input(&findings);
    let mut template = ReportTemplate::default();
    template.custom_header = Some("CONFIDENTIAL REPORT".to_string());
    template.custom_footer = Some("End of Report".to_string());
    let report = generate_narrative_report(&input, &template);
    assert_eq!(report.sections.first().unwrap().title, "Header");
    assert!(
        report
            .sections
            .first()
            .unwrap()
            .body
            .contains("CONFIDENTIAL")
    );
    assert_eq!(report.sections.last().unwrap().title, "Footer");
    assert!(
        report
            .sections
            .last()
            .unwrap()
            .body
            .contains("End of Report")
    );
}

#[test]
fn empty_findings_produces_report() {
    let findings: Vec<SarifFinding> = vec![];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    assert_eq!(report.sections.len(), 8);
    let exec = &report.sections[0];
    assert!(exec.body.contains("0 findings"));
}

#[test]
fn attack_chain_single_node() {
    let findings = vec![make_finding(
        "A",
        VulnerabilityClass::SqlInjection,
        80.0,
        9.0,
        0.9,
    )];
    let chains = vec![AttackChainPath {
        nodes: vec![AttackChainNode {
            label: "entry".to_string(),
            vulnerability_class: Some(VulnerabilityClass::SqlInjection),
            endpoint: Some("/api/data".to_string()),
        }],
        total_difficulty: 1.0,
    }];
    let input = NarrativeInput {
        findings: &findings,
        attack_chains: &chains,
        baseline: None,
        evidence: &[],
        target_url: "https://example.com",
        scan_date: "2025-01-15",
    };
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[3];
    assert!(section.body.contains("exploit"));
    assert!(section.body.contains("SQL Injection"));
    assert!(section.body.contains("/api/data"));
}

#[test]
fn attack_chain_three_nodes() {
    let findings = vec![make_finding(
        "A",
        VulnerabilityClass::SqlInjection,
        80.0,
        9.0,
        0.9,
    )];
    let chains = vec![AttackChainPath {
        nodes: vec![
            AttackChainNode {
                label: "step1".to_string(),
                vulnerability_class: Some(VulnerabilityClass::CrossSiteScripting),
                endpoint: Some("/login".to_string()),
            },
            AttackChainNode {
                label: "step2".to_string(),
                vulnerability_class: Some(VulnerabilityClass::BrokenAuthentication),
                endpoint: Some("/session".to_string()),
            },
            AttackChainNode {
                label: "step3".to_string(),
                vulnerability_class: Some(VulnerabilityClass::SqlInjection),
                endpoint: Some("/api/admin".to_string()),
            },
        ],
        total_difficulty: 7.2,
    }];
    let input = NarrativeInput {
        findings: &findings,
        attack_chains: &chains,
        baseline: None,
        evidence: &[],
        target_url: "https://example.com",
        scan_date: "2025-01-15",
    };
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[3];
    assert!(section.body.contains("/login"));
    assert!(section.body.contains("/session"));
    assert!(section.body.contains("/api/admin"));
    assert!(section.body.contains("7.2"));
}

#[test]
fn remediation_includes_cwe_based_advice() {
    let findings = vec![make_finding(
        "CMD-001",
        VulnerabilityClass::CommandInjection,
        75.0,
        8.0,
        0.9,
    )];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[5];
    assert!(section.body.contains("shell invocation") || section.body.contains("language-native"));
}

#[test]
fn multiple_findings_different_classes() {
    let findings = vec![
        make_finding(
            "SQLI-001",
            VulnerabilityClass::SqlInjection,
            85.0,
            9.0,
            0.95,
        ),
        make_finding(
            "XSS-001",
            VulnerabilityClass::CrossSiteScripting,
            60.0,
            7.0,
            0.85,
        ),
        make_finding(
            "SSRF-001",
            VulnerabilityClass::ServerSideRequestForgery,
            70.0,
            8.0,
            0.9,
        ),
        make_finding(
            "IDOR-001",
            VulnerabilityClass::InsecureDirectObjectReference,
            50.0,
            6.0,
            0.8,
        ),
        make_finding(
            "INFO-001",
            VulnerabilityClass::InformationDisclosure,
            15.0,
            3.0,
            0.5,
        ),
    ];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());

    let exec = &report.sections[0];
    assert!(exec.body.contains("5 findings"));

    let detailed = &report.sections[1];
    assert!(detailed.body.contains("SQL Injection"));
    assert!(detailed.body.contains("Cross-Site Scripting"));
    assert!(detailed.body.contains("Server-Side Request Forgery"));

    let compliance = &report.sections[6];
    assert!(compliance.body.contains("A03:2021"));
    assert!(compliance.body.contains("A10:2021"));
    assert!(compliance.body.contains("A01:2021"));
}

#[test]
fn trend_analysis_no_change() {
    let findings = vec![make_finding(
        "A",
        VulnerabilityClass::SqlInjection,
        80.0,
        9.0,
        0.9,
    )];
    let baseline = BaselineFindings {
        total_count: 1,
        critical_count: 1,
        high_count: 0,
        resolved_rule_ids: vec![],
        new_rule_ids: vec![],
    };
    let input = NarrativeInput {
        findings: &findings,
        attack_chains: &[],
        baseline: Some(&baseline),
        evidence: &[],
        target_url: "https://example.com",
        scan_date: "2025-01-15",
    };
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[4];
    assert!(section.body.contains("no change"));
}

#[test]
fn finding_narrative_without_parameter() {
    let mut finding = make_finding("A", VulnerabilityClass::SqlInjection, 80.0, 9.0, 0.9);
    finding.parameter_name = None;
    let findings = vec![finding];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[1];
    assert!(section.body.contains("POST /api/users"));
    assert!(!section.body.contains("via the"));
}

#[test]
fn finding_narrative_without_endpoint() {
    let mut finding = make_finding("A", VulnerabilityClass::SqlInjection, 80.0, 9.0, 0.9);
    finding.endpoint = None;
    finding.http_method = None;
    let findings = vec![finding];
    let input = default_input(&findings);
    let report = generate_narrative_report(&input, &ReportTemplate::default());
    let section = &report.sections[1];
    assert!(section.body.contains("SQL Injection"));
}

#[test]
fn report_section_struct_accessible() {
    let section = ReportSection {
        title: "Test".to_string(),
        body: "Body content".to_string(),
    };
    assert_eq!(section.title, "Test");
    assert_eq!(section.body, "Body content");
}

#[test]
fn narrative_report_struct_accessible() {
    let report = NarrativeReport {
        sections: vec![ReportSection {
            title: "A".to_string(),
            body: "B".to_string(),
        }],
    };
    assert_eq!(report.sections.len(), 1);
}
