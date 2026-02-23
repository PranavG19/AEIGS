use crate::report_generator::{
    FindingInput, ReportInput, generate_executive_summary, generate_finding_narrative,
    generate_full_report, generate_remediation_roadmap,
};

fn sample_finding(vuln_class: &str, endpoint: &str, score: f64) -> FindingInput {
    FindingInput {
        vulnerability_class: vuln_class.to_string(),
        endpoint: endpoint.to_string(),
        parameter: Some("id".to_string()),
        evidence: "Anomalous response observed".to_string(),
        cvss_score: score,
        cvss_vector: format!("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
        owasp_category: Some("A03:2021 Injection".to_string()),
        poc_command: Some("curl http://localhost/api?id=1'OR'1'='1".to_string()),
    }
}

fn sample_input() -> ReportInput {
    ReportInput {
        target_url: "http://localhost:3000".to_string(),
        scan_duration_secs: 3661,
        total_findings: 4,
        critical_count: 1,
        high_count: 1,
        medium_count: 1,
        low_count: 1,
        tech_stack: vec!["Express.js".to_string(), "Node.js".to_string()],
        defenses_detected: vec!["ModSecurity WAF".to_string()],
        findings: vec![
            sample_finding("SQL Injection", "/api/users", 9.8),
            sample_finding("Broken Authentication", "/login", 8.1),
            sample_finding("Security Misconfiguration", "/admin", 5.3),
            sample_finding("Open Redirect", "/redirect", 3.1),
        ],
    }
}

#[test]
fn executive_summary_contains_all_counts() {
    let input = sample_input();
    let summary = generate_executive_summary(&input);
    assert!(summary.contains("1 critical"));
    assert!(summary.contains("1 high"));
    assert!(summary.contains("1 medium"));
    assert!(summary.contains("1 low"));
    assert!(summary.contains("4 vulnerabilities"));
}

#[test]
fn executive_summary_contains_target_url() {
    let input = sample_input();
    let summary = generate_executive_summary(&input);
    assert!(summary.contains("http://localhost:3000"));
}

#[test]
fn executive_summary_contains_duration() {
    let input = sample_input();
    let summary = generate_executive_summary(&input);
    assert!(summary.contains("1h 1m 1s"));
}

#[test]
fn executive_summary_risk_rating_critical() {
    let input = sample_input();
    let summary = generate_executive_summary(&input);
    assert!(summary.contains("Risk Rating: Critical"));
}

#[test]
fn executive_summary_risk_rating_high() {
    let mut input = sample_input();
    input.critical_count = 0;
    let summary = generate_executive_summary(&input);
    assert!(summary.contains("Risk Rating: High"));
}

#[test]
fn executive_summary_risk_rating_medium() {
    let mut input = sample_input();
    input.critical_count = 0;
    input.high_count = 0;
    let summary = generate_executive_summary(&input);
    assert!(summary.contains("Risk Rating: Medium"));
}

#[test]
fn executive_summary_risk_rating_low() {
    let mut input = sample_input();
    input.critical_count = 0;
    input.high_count = 0;
    input.medium_count = 0;
    let summary = generate_executive_summary(&input);
    assert!(summary.contains("Risk Rating: Low"));
}

#[test]
fn executive_summary_risk_rating_informational() {
    let mut input = sample_input();
    input.critical_count = 0;
    input.high_count = 0;
    input.medium_count = 0;
    input.low_count = 0;
    let summary = generate_executive_summary(&input);
    assert!(summary.contains("Risk Rating: Informational"));
}

#[test]
fn executive_summary_key_findings_sorted_by_severity() {
    let input = sample_input();
    let summary = generate_executive_summary(&input);
    let sql_pos = summary.find("SQL Injection").unwrap();
    let auth_pos = summary.find("Broken Authentication").unwrap();
    assert!(sql_pos < auth_pos);
}

#[test]
fn finding_narrative_title_format() {
    let finding = sample_finding("SQL Injection", "/api/users", 9.8);
    let narrative = generate_finding_narrative(&finding);
    assert_eq!(narrative.title, "SQL Injection in /api/users");
}

#[test]
fn finding_narrative_description_mentions_endpoint() {
    let finding = sample_finding("SQL Injection", "/api/users", 9.8);
    let narrative = generate_finding_narrative(&finding);
    assert!(narrative.description.contains("/api/users"));
}

#[test]
fn finding_narrative_description_mentions_parameter() {
    let finding = sample_finding("SQL Injection", "/api/users", 9.8);
    let narrative = generate_finding_narrative(&finding);
    assert!(narrative.description.contains("`id`"));
}

#[test]
fn finding_narrative_impact_contains_severity() {
    let finding = sample_finding("SQL Injection", "/api/users", 9.8);
    let narrative = generate_finding_narrative(&finding);
    assert!(narrative.impact.contains("critical"));
}

#[test]
fn finding_narrative_poc_from_command() {
    let finding = sample_finding("SQL Injection", "/api/users", 9.8);
    let narrative = generate_finding_narrative(&finding);
    assert!(narrative.proof_of_concept.contains("curl"));
}

#[test]
fn finding_narrative_poc_without_command() {
    let mut finding = sample_finding("SQL Injection", "/api/users", 9.8);
    finding.poc_command = None;
    let narrative = generate_finding_narrative(&finding);
    assert!(narrative.proof_of_concept.contains("automated testing"));
    assert!(narrative.proof_of_concept.contains(&finding.evidence));
}

#[test]
fn finding_narrative_remediation_nonempty() {
    let finding = sample_finding("SQL Injection", "/api/users", 9.8);
    let narrative = generate_finding_narrative(&finding);
    assert!(!narrative.remediation.is_empty());
    assert!(narrative.remediation.contains("parameterized"));
}

#[test]
fn finding_narrative_references_contain_cwe() {
    let finding = sample_finding("SQL Injection", "/api/users", 9.8);
    let narrative = generate_finding_narrative(&finding);
    assert!(
        narrative
            .references
            .iter()
            .any(|r| r.contains("cwe.mitre.org"))
    );
    assert!(narrative.references.iter().any(|r| r.contains("89")));
}

#[test]
fn finding_narrative_references_contain_owasp() {
    let finding = sample_finding("SQL Injection", "/api/users", 9.8);
    let narrative = generate_finding_narrative(&finding);
    assert!(narrative.references.iter().any(|r| r.contains("owasp.org")));
}

#[test]
fn finding_narrative_preserves_cvss() {
    let finding = sample_finding("SQL Injection", "/api/users", 9.8);
    let narrative = generate_finding_narrative(&finding);
    assert!((narrative.cvss_score - 9.8).abs() < f64::EPSILON);
    assert!(narrative.cvss_vector.starts_with("CVSS:3.1"));
}

#[test]
fn finding_narrative_preserves_owasp_category() {
    let finding = sample_finding("SQL Injection", "/api/users", 9.8);
    let narrative = generate_finding_narrative(&finding);
    assert_eq!(
        narrative.owasp_category,
        Some("A03:2021 Injection".to_string())
    );
}

#[test]
fn finding_narrative_unknown_class_produces_generic() {
    let mut finding = sample_finding("Custom Vuln", "/api/test", 5.0);
    finding.parameter = None;
    let narrative = generate_finding_narrative(&finding);
    assert!(narrative.title.contains("Custom Vuln"));
    assert!(narrative.description.contains("Custom Vuln"));
    assert!(!narrative.remediation.is_empty());
}

#[test]
fn roadmap_groups_by_severity() {
    let findings = vec![
        sample_finding("SQL Injection", "/api/users", 9.8),
        sample_finding("Security Misconfiguration", "/admin", 5.3),
        sample_finding("Open Redirect", "/redirect", 3.1),
    ];
    let roadmap = generate_remediation_roadmap(&findings);
    assert!(roadmap.contains("Immediate"));
    assert!(roadmap.contains("Short-Term"));
    assert!(roadmap.contains("Long-Term"));
}

#[test]
fn roadmap_critical_before_medium() {
    let findings = vec![
        sample_finding("Security Misconfiguration", "/admin", 5.3),
        sample_finding("SQL Injection", "/api/users", 9.8),
    ];
    let roadmap = generate_remediation_roadmap(&findings);
    let immediate_pos = roadmap.find("Immediate").unwrap();
    let short_term_pos = roadmap.find("Short-Term").unwrap();
    assert!(immediate_pos < short_term_pos);
}

#[test]
fn roadmap_contains_cwe_ids() {
    let findings = vec![sample_finding("SQL Injection", "/api/users", 9.8)];
    let roadmap = generate_remediation_roadmap(&findings);
    assert!(roadmap.contains("CWE-89"));
}

#[test]
fn roadmap_empty_findings_has_heading_only() {
    let roadmap = generate_remediation_roadmap(&[]);
    assert!(roadmap.contains("Remediation Roadmap"));
    assert!(!roadmap.contains("Immediate"));
    assert!(!roadmap.contains("Short-Term"));
    assert!(!roadmap.contains("Long-Term"));
}

#[test]
fn full_report_all_sections_populated() {
    let input = sample_input();
    let report = generate_full_report(&input);
    assert!(!report.executive_summary.is_empty());
    assert!(!report.methodology.is_empty());
    assert_eq!(report.findings.len(), 4);
    assert!(!report.remediation_roadmap.is_empty());
    assert!(!report.compliance_summary.is_empty());
}

#[test]
fn full_report_methodology_mentions_tech_stack() {
    let input = sample_input();
    let report = generate_full_report(&input);
    assert!(report.methodology.contains("Express.js"));
    assert!(report.methodology.contains("Node.js"));
}

#[test]
fn full_report_methodology_mentions_defenses() {
    let input = sample_input();
    let report = generate_full_report(&input);
    assert!(report.methodology.contains("ModSecurity WAF"));
}

#[test]
fn full_report_compliance_summary_lists_owasp() {
    let input = sample_input();
    let report = generate_full_report(&input);
    assert!(report.compliance_summary.contains("A03:2021 Injection"));
}

#[test]
fn full_report_compliance_summary_risk_rating() {
    let input = sample_input();
    let report = generate_full_report(&input);
    assert!(report.compliance_summary.contains("Critical"));
}

#[test]
fn empty_findings_report() {
    let input = ReportInput {
        target_url: "http://localhost:3000".to_string(),
        scan_duration_secs: 60,
        total_findings: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        tech_stack: vec![],
        defenses_detected: vec![],
        findings: vec![],
    };
    let report = generate_full_report(&input);
    assert!(report.executive_summary.contains("0 vulnerabilities"));
    assert!(report.executive_summary.contains("Informational"));
    assert!(report.findings.is_empty());
    assert!(report.methodology.contains("not explicitly identified"));
    assert!(
        report
            .methodology
            .contains("No active defenses were detected")
    );
    assert!(report.compliance_summary.contains("No OWASP Top 10"));
}

#[test]
fn duration_formatting_seconds_only() {
    let input = ReportInput {
        target_url: "http://localhost".to_string(),
        scan_duration_secs: 45,
        total_findings: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        tech_stack: vec![],
        defenses_detected: vec![],
        findings: vec![],
    };
    let summary = generate_executive_summary(&input);
    assert!(summary.contains("45s"));
}

#[test]
fn duration_formatting_minutes() {
    let input = ReportInput {
        target_url: "http://localhost".to_string(),
        scan_duration_secs: 125,
        total_findings: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        tech_stack: vec![],
        defenses_detected: vec![],
        findings: vec![],
    };
    let summary = generate_executive_summary(&input);
    assert!(summary.contains("2m 5s"));
}

#[test]
fn all_severity_levels_in_roadmap() {
    let findings = vec![
        sample_finding("SQL Injection", "/a", 9.5),
        sample_finding("Broken Authentication", "/b", 7.5),
        sample_finding("Security Misconfiguration", "/c", 5.0),
        sample_finding("Open Redirect", "/d", 2.0),
    ];
    let roadmap = generate_remediation_roadmap(&findings);
    assert!(roadmap.contains("Immediate"));
    assert!(roadmap.contains("Short-Term"));
    assert!(roadmap.contains("Long-Term"));
}

#[test]
fn narrative_for_xss() {
    let finding = sample_finding("Cross-Site Scripting", "/search", 6.1);
    let narrative = generate_finding_narrative(&finding);
    assert!(narrative.description.contains("XSS"));
    assert!(narrative.remediation.contains("Content-Security-Policy"));
    assert!(narrative.references.iter().any(|r| r.contains("79")));
}

#[test]
fn narrative_for_command_injection() {
    let finding = sample_finding("Command Injection", "/exec", 9.8);
    let narrative = generate_finding_narrative(&finding);
    assert!(narrative.description.contains("shell"));
    assert!(narrative.remediation.contains("allowlist"));
}

#[test]
fn narrative_for_ssrf() {
    let finding = sample_finding("Server-Side Request Forgery", "/fetch", 8.6);
    let narrative = generate_finding_narrative(&finding);
    assert!(narrative.description.contains("SSRF"));
    assert!(narrative.remediation.contains("169.254.169.254"));
}

#[test]
fn narrative_for_ssti() {
    let finding = sample_finding("Server-Side Template Injection", "/render", 9.8);
    let narrative = generate_finding_narrative(&finding);
    assert!(narrative.description.contains("SSTI"));
    assert!(narrative.remediation.contains("template"));
}

#[test]
fn narrative_for_path_traversal() {
    let finding = sample_finding("Path Traversal", "/files", 7.5);
    let narrative = generate_finding_narrative(&finding);
    assert!(narrative.description.contains("files outside"));
    assert!(narrative.remediation.contains("Canonicalize"));
}

#[test]
fn narrative_for_known_vulnerable_dependency() {
    let finding = sample_finding("Known Vulnerable Dependency", "/", 5.3);
    let narrative = generate_finding_narrative(&finding);
    assert!(narrative.description.contains("third-party"));
    assert!(narrative.remediation.contains("Update"));
}

#[test]
fn serde_roundtrip_pentest_report() {
    let input = sample_input();
    let report = generate_full_report(&input);
    let json = serde_json::to_string(&report).unwrap();
    let deserialized: crate::report_generator::PentestReport = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.findings.len(), report.findings.len());
    assert_eq!(deserialized.executive_summary, report.executive_summary);
}

#[test]
fn serde_roundtrip_report_input() {
    let input = sample_input();
    let json = serde_json::to_string(&input).unwrap();
    let deserialized: ReportInput = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.target_url, input.target_url);
    assert_eq!(deserialized.findings.len(), input.findings.len());
}

#[test]
fn roadmap_numbering_is_sequential() {
    let findings = vec![
        sample_finding("SQL Injection", "/a", 9.8),
        sample_finding("Command Injection", "/b", 9.8),
        sample_finding("Security Misconfiguration", "/c", 5.0),
    ];
    let roadmap = generate_remediation_roadmap(&findings);
    assert!(roadmap.contains("1. Fix"));
    assert!(roadmap.contains("2. Fix"));
    assert!(roadmap.contains("3. Fix"));
}

#[test]
fn executive_summary_recommendations_match_counts() {
    let input = sample_input();
    let summary = generate_executive_summary(&input);
    assert!(summary.contains("Immediate"));
    assert!(summary.contains("Short-Term"));
    assert!(summary.contains("Medium-Term"));
    assert!(summary.contains("Long-Term"));
}

#[test]
fn no_recommendations_for_zero_findings() {
    let input = ReportInput {
        target_url: "http://localhost".to_string(),
        scan_duration_secs: 10,
        total_findings: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        tech_stack: vec![],
        defenses_detected: vec![],
        findings: vec![],
    };
    let summary = generate_executive_summary(&input);
    assert!(summary.contains("No specific remediation"));
}

#[test]
fn compliance_summary_deduplicates_owasp() {
    let input = ReportInput {
        target_url: "http://localhost".to_string(),
        scan_duration_secs: 10,
        total_findings: 2,
        critical_count: 2,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        tech_stack: vec![],
        defenses_detected: vec![],
        findings: vec![
            sample_finding("SQL Injection", "/a", 9.8),
            sample_finding("SQL Injection", "/b", 9.5),
        ],
    };
    let report = generate_full_report(&input);
    let count = report
        .compliance_summary
        .matches("A03:2021 Injection")
        .count();
    assert_eq!(count, 1);
}
