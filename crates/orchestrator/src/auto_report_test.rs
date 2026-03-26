use super::auto_report::*;
use std::collections::HashMap;

fn sample_input() -> ReportInput {
    ReportInput {
        target_url: "http://target.local/api/auth".to_string(),
        objective: "domain admin".to_string(),
        objective_achieved: true,
        objective_progress_pct: 100.0,
        final_access_level: "Domain Admin".to_string(),
        timeline: vec![
            TimelineAction {
                timestamp_ms: 1000,
                phase: "Reconnaissance".to_string(),
                action: "Port scan".to_string(),
                target: Some("target.local".to_string()),
                result: "15 endpoints discovered".to_string(),
                evidence_ref: None,
            },
            TimelineAction {
                timestamp_ms: 5000,
                phase: "Initial Access".to_string(),
                action: "SQL injection on /api/auth".to_string(),
                target: Some("/api/auth".to_string()),
                result: "Admin password hash extracted".to_string(),
                evidence_ref: Some("evidence-001".to_string()),
            },
            TimelineAction {
                timestamp_ms: 8000,
                phase: "Execution".to_string(),
                action: "Authenticate as admin".to_string(),
                target: Some("/api/admin".to_string()),
                result: "Admin panel accessed".to_string(),
                evidence_ref: Some("evidence-002".to_string()),
            },
        ],
        evidence_chain: vec![
            EvidenceLink {
                step_number: 1,
                description: "SQL injection discovered on /api/auth".to_string(),
                http_evidence: Some(HttpEvidence {
                    request_method: "POST".to_string(),
                    request_url: "http://target.local/api/auth".to_string(),
                    request_headers: HashMap::new(),
                    request_body: Some("username=admin' OR 1=1--".to_string()),
                    response_status: 200,
                    response_headers: HashMap::new(),
                    response_body_snippet: "Welcome admin".to_string(),
                }),
                finding_id: Some("finding-001".to_string()),
                critical: true,
            },
            EvidenceLink {
                step_number: 2,
                description: "Admin credentials extracted".to_string(),
                http_evidence: None,
                finding_id: Some("finding-002".to_string()),
                critical: true,
            },
        ],
        exposed_data: vec![ExposedData {
            data_type: "User credentials".to_string(),
            description: "Database table with hashed passwords".to_string(),
            record_count: Some(1500),
            sensitivity: DataSensitivity::Pii,
        }],
        credentials_obtained: vec![
            ReportCredential {
                username: "admin".to_string(),
                credential_type: "password_hash".to_string(),
                source: "SQL injection extraction".to_string(),
                access_level: "admin".to_string(),
            },
            ReportCredential {
                username: "svc_account".to_string(),
                credential_type: "password".to_string(),
                source: "Config file on admin panel".to_string(),
                access_level: "domain admin".to_string(),
            },
        ],
        hosts_compromised: vec![
            "target.local".to_string(),
            "10.0.0.5".to_string(),
            "10.0.0.10".to_string(),
        ],
        vulnerabilities_exploited: vec![
            ExploitedVuln {
                vulnerability_class: "SQL Injection".to_string(),
                endpoint: "/api/auth".to_string(),
                severity: 9.8,
                cwe_id: Some("CWE-89".to_string()),
                technique: "UNION-based extraction".to_string(),
            },
            ExploitedVuln {
                vulnerability_class: "SSRF".to_string(),
                endpoint: "/api/admin/proxy".to_string(),
                severity: 8.5,
                cwe_id: Some("CWE-918".to_string()),
                technique: "Internal service enumeration".to_string(),
            },
        ],
    }
}

#[test]
fn generate_auto_report_produces_all_sections() {
    let input = sample_input();
    let report = generate_auto_report(&input);

    assert!(!report.executive_narrative.is_empty());
    assert_eq!(report.timeline.len(), 3);
    assert_eq!(report.evidence_chain.len(), 2);
    assert!(!report.remediations.is_empty());
    assert_eq!(report.metadata.target_url, "http://target.local/api/auth");
    assert!(report.metadata.objective_achieved);
}

#[test]
fn executive_narrative_contains_key_details() {
    let input = sample_input();
    let report = generate_auto_report(&input);

    assert!(report.executive_narrative.contains("target.local"));
    assert!(report.executive_narrative.contains("SQL Injection"));
    assert!(report.executive_narrative.contains("SSRF"));
    assert!(report.executive_narrative.contains("admin"));
    assert!(report.executive_narrative.contains("fully achieved"));
}

#[test]
fn executive_narrative_not_achieved() {
    let mut input = sample_input();
    input.objective_achieved = false;
    input.objective_progress_pct = 65.0;

    let report = generate_auto_report(&input);
    assert!(report.executive_narrative.contains("not fully achieved"));
    assert!(report.executive_narrative.contains("65%"));
}

#[test]
fn impact_assessment_critical_when_objective_achieved() {
    let input = sample_input();
    let report = generate_auto_report(&input);

    assert_eq!(report.impact_assessment.overall_risk, "Critical");
    assert_eq!(report.impact_assessment.credential_count, 2);
    assert_eq!(report.impact_assessment.hosts_compromised, 3);
    assert!(report
        .impact_assessment
        .data_exposure_summary
        .contains("PII"));
}

#[test]
fn impact_assessment_low_risk() {
    let input = ReportInput {
        target_url: "http://test.local".to_string(),
        objective: "scan".to_string(),
        objective_achieved: false,
        objective_progress_pct: 10.0,
        final_access_level: "anonymous".to_string(),
        timeline: vec![],
        evidence_chain: vec![],
        exposed_data: vec![],
        credentials_obtained: vec![],
        hosts_compromised: vec![],
        vulnerabilities_exploited: vec![ExploitedVuln {
            vulnerability_class: "Info Disclosure".to_string(),
            endpoint: "/debug".to_string(),
            severity: 3.0,
            cwe_id: None,
            technique: "Direct access".to_string(),
        }],
    };

    let report = generate_auto_report(&input);
    assert_eq!(report.impact_assessment.overall_risk, "Low");
}

#[test]
fn remediations_sorted_by_severity() {
    let input = sample_input();
    let report = generate_auto_report(&input);

    assert!(report.remediations.len() >= 2);
    assert_eq!(report.remediations[0].priority, 1);
    assert!(report.remediations[0].title.contains("SQL Injection"));
    assert_eq!(report.remediations[1].priority, 2);
}

#[test]
fn remediations_include_credential_rotation() {
    let input = sample_input();
    let report = generate_auto_report(&input);

    let has_cred_rotation = report
        .remediations
        .iter()
        .any(|r| r.title.contains("credential rotation"));
    assert!(has_cred_rotation);
}

#[test]
fn remediations_include_network_segmentation() {
    let input = sample_input();
    let report = generate_auto_report(&input);

    let has_segmentation = report
        .remediations
        .iter()
        .any(|r| r.title.contains("network segmentation"));
    assert!(has_segmentation);
}

#[test]
fn format_timeline_produces_numbered_steps() {
    let actions = vec![
        TimelineAction {
            timestamp_ms: 1000,
            phase: "Recon".to_string(),
            action: "Port scan".to_string(),
            target: Some("target.local".to_string()),
            result: "15 ports open".to_string(),
            evidence_ref: None,
        },
        TimelineAction {
            timestamp_ms: 2000,
            phase: "Exploit".to_string(),
            action: "SQLi".to_string(),
            target: Some("/api/auth".to_string()),
            result: "Success".to_string(),
            evidence_ref: None,
        },
    ];

    let formatted = format_timeline(&actions);
    assert!(formatted.contains("1. [Recon]"));
    assert!(formatted.contains("2. [Exploit]"));
    assert!(formatted.contains("→ target.local"));
}

#[test]
fn format_evidence_chain_marks_critical() {
    let chain = vec![
        EvidenceLink {
            step_number: 1,
            description: "SQLi found".to_string(),
            http_evidence: Some(HttpEvidence {
                request_method: "POST".to_string(),
                request_url: "http://target.local/api".to_string(),
                request_headers: HashMap::new(),
                request_body: None,
                response_status: 200,
                response_headers: HashMap::new(),
                response_body_snippet: "OK".to_string(),
            }),
            finding_id: None,
            critical: true,
        },
        EvidenceLink {
            step_number: 2,
            description: "Info gathered".to_string(),
            http_evidence: None,
            finding_id: None,
            critical: false,
        },
    ];

    let formatted = format_evidence_chain(&chain);
    assert!(formatted.contains("[CRITICAL]"));
    assert!(formatted.contains("Step 1:"));
    assert!(formatted.contains("Step 2:"));
    assert!(formatted.contains("POST http://target.local/api → 200"));
}

#[test]
fn metadata_reflects_input() {
    let input = sample_input();
    let report = generate_auto_report(&input);

    assert_eq!(report.metadata.total_actions, 3);
    assert_eq!(report.metadata.total_evidence_steps, 2);
    assert!(report.metadata.total_remediations >= 2);
    assert_eq!(report.metadata.objective_progress_pct, 100.0);
}

#[test]
fn empty_input_produces_valid_report() {
    let input = ReportInput {
        target_url: "http://empty.local".to_string(),
        objective: "test".to_string(),
        objective_achieved: false,
        objective_progress_pct: 0.0,
        final_access_level: "none".to_string(),
        timeline: vec![],
        evidence_chain: vec![],
        exposed_data: vec![],
        credentials_obtained: vec![],
        hosts_compromised: vec![],
        vulnerabilities_exploited: vec![],
    };

    let report = generate_auto_report(&input);
    assert!(!report.executive_narrative.is_empty());
    assert!(report.remediations.is_empty());
    assert_eq!(report.metadata.total_actions, 0);
}

#[test]
fn narrative_includes_host_and_data_info() {
    let input = sample_input();
    let report = generate_auto_report(&input);

    assert!(report.executive_narrative.contains("3 host(s)"));
    assert!(report.executive_narrative.contains("User credentials"));
}
