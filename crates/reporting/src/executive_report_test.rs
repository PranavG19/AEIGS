#[cfg(test)]
mod tests {
    use crate::executive_report::{
        ComplianceFramework, EffortEstimate, ExecutiveReportInput, FindingSummary,
        PreviousScanData, generate_executive_report, render_html, render_json, render_markdown,
    };

    fn sqli_finding() -> FindingSummary {
        FindingSummary {
            id: "AEGIS-001".to_string(),
            title: "SQL Injection in login".to_string(),
            vulnerability_class: "SqlInjection".to_string(),
            composite_score: 85.0,
            endpoint: "/api/login".to_string(),
            business_impact: "Full database compromise".to_string(),
            remediation: "Use parameterized queries".to_string(),
            effort_estimate: EffortEstimate::Days(3),
        }
    }

    fn xss_finding() -> FindingSummary {
        FindingSummary {
            id: "AEGIS-002".to_string(),
            title: "Reflected XSS in search".to_string(),
            vulnerability_class: "CrossSiteScripting".to_string(),
            composite_score: 55.0,
            endpoint: "/search".to_string(),
            business_impact: "Session hijacking".to_string(),
            remediation: "Apply output encoding".to_string(),
            effort_estimate: EffortEstimate::Days(2),
        }
    }

    fn misconfig_finding() -> FindingSummary {
        FindingSummary {
            id: "AEGIS-003".to_string(),
            title: "Missing security headers".to_string(),
            vulnerability_class: "MissingSecurityHeader".to_string(),
            composite_score: 25.0,
            endpoint: "/".to_string(),
            business_impact: "Reduced defense-in-depth".to_string(),
            remediation: "Add CSP and HSTS headers".to_string(),
            effort_estimate: EffortEstimate::Hours(4),
        }
    }

    fn low_finding() -> FindingSummary {
        FindingSummary {
            id: "AEGIS-004".to_string(),
            title: "Open redirect".to_string(),
            vulnerability_class: "OpenRedirect".to_string(),
            composite_score: 12.0,
            endpoint: "/callback".to_string(),
            business_impact: "Phishing vector".to_string(),
            remediation: "Validate redirect targets".to_string(),
            effort_estimate: EffortEstimate::Hours(2),
        }
    }

    fn sample_input() -> ExecutiveReportInput {
        ExecutiveReportInput {
            findings: vec![
                sqli_finding(),
                xss_finding(),
                misconfig_finding(),
                low_finding(),
            ],
            target_url: "http://localhost:8080".to_string(),
            scan_duration_secs: 45.3,
            total_endpoints: 50,
            tested_endpoints: 42,
            previous_scan: None,
            compliance_frameworks: vec![
                ComplianceFramework::OwaspTop10,
                ComplianceFramework::PciDss,
            ],
        }
    }

    #[test]
    fn generate_report_with_multiple_findings() {
        let input = sample_input();
        let report = generate_executive_report(&input);

        assert!(report.risk_dashboard.overall_score <= 100);
        assert_eq!(report.risk_dashboard.critical_count, 1);
        assert_eq!(report.risk_dashboard.high_count, 1);
        assert_eq!(report.risk_dashboard.medium_count, 1);
        assert_eq!(report.risk_dashboard.low_count, 1);
        assert!(report.top_findings.len() <= 5);
        assert_eq!(report.top_findings.len(), 4);
        assert_eq!(report.top_findings[0].id, "AEGIS-001");
        assert_eq!(report.top_findings[0].severity, "Critical");
        assert_eq!(report.attack_surface.total_endpoints, 50);
        assert_eq!(report.attack_surface.tested_endpoints, 42);
        assert_eq!(report.remediation_roadmap.len(), 4);
        assert_eq!(report.remediation_roadmap[0].priority, 1);
        assert_eq!(report.remediation_roadmap[0].finding_id, "AEGIS-001");
        assert!(!report.compliance_status.is_empty());
    }

    #[test]
    fn generate_report_empty_findings_produces_valid_report() {
        let input = ExecutiveReportInput {
            findings: Vec::new(),
            target_url: "http://localhost:3000".to_string(),
            scan_duration_secs: 10.0,
            total_endpoints: 20,
            tested_endpoints: 20,
            previous_scan: None,
            compliance_frameworks: vec![ComplianceFramework::OwaspTop10],
        };
        let report = generate_executive_report(&input);

        assert_eq!(report.risk_dashboard.overall_score, 100);
        assert_eq!(report.risk_dashboard.posture_rating, "Excellent");
        assert_eq!(report.risk_dashboard.critical_count, 0);
        assert!(report.top_findings.is_empty());
        assert_eq!(report.attack_surface.coverage_percent, 100.0);
        assert_eq!(report.attack_surface.untested_count, 0);
        assert!(report.remediation_roadmap.is_empty());
        assert!(report.trend_analysis.is_none());
        assert_eq!(report.compliance_status[0].status, "Compliant");
    }

    #[test]
    fn trend_analysis_with_previous_scan() {
        let mut input = sample_input();
        input.previous_scan = Some(PreviousScanData {
            total_findings: 8,
            critical_count: 3,
            high_count: 2,
            risk_score: 35.0,
            scan_date: "2025-01-15".to_string(),
        });
        let report = generate_executive_report(&input);

        let trend = report.trend_analysis.as_ref().unwrap();
        assert_eq!(trend.previous_scan_date, "2025-01-15");
        assert_eq!(trend.previous_finding_count, 8);
        assert_eq!(trend.current_finding_count, 4);
        assert_eq!(trend.delta_findings, -4);
        assert!(trend.current_risk_score > 0.0);
    }

    #[test]
    fn trend_analysis_none_without_previous_scan() {
        let input = sample_input();
        let report = generate_executive_report(&input);
        assert!(report.trend_analysis.is_none());
    }

    #[test]
    fn json_rendering_produces_valid_json() {
        let input = sample_input();
        let report = generate_executive_report(&input);
        let json_str = render_json(&report);

        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.get("risk_dashboard").is_some());
        assert!(parsed.get("top_findings").is_some());
        assert!(parsed.get("attack_surface").is_some());
        assert!(parsed.get("remediation_roadmap").is_some());
        assert!(parsed.get("compliance_status").is_some());

        let dash = &parsed["risk_dashboard"];
        assert!(dash["overall_score"].as_u64().is_some());
        assert!(dash["posture_rating"].as_str().is_some());

        let findings = parsed["top_findings"].as_array().unwrap();
        assert_eq!(findings[0]["id"].as_str().unwrap(), "AEGIS-001");
    }

    #[test]
    fn html_rendering_contains_key_elements() {
        let input = sample_input();
        let report = generate_executive_report(&input);
        let html = render_html(&report);

        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("<title>AEGIS Executive Security Report</title>"));
        assert!(html.contains("Risk Dashboard"));
        assert!(html.contains("Top Critical Findings"));
        assert!(html.contains("Attack Surface"));
        assert!(html.contains("Trend Analysis"));
        assert!(html.contains("Remediation Roadmap"));
        assert!(html.contains("Compliance Status"));
        assert!(html.contains("AEGIS-001"));
        assert!(html.contains("SQL Injection in login"));
        assert!(html.contains("class=\"critical\""));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn markdown_rendering_contains_sections() {
        let input = sample_input();
        let report = generate_executive_report(&input);
        let md = render_markdown(&report);

        assert!(md.starts_with("# AEGIS Executive Security Report"));
        assert!(md.contains("## Risk Dashboard"));
        assert!(md.contains("## Top Critical Findings"));
        assert!(md.contains("## Attack Surface"));
        assert!(md.contains("## Trend Analysis"));
        assert!(md.contains("## Remediation Roadmap"));
        assert!(md.contains("## Compliance Status"));
        assert!(md.contains("AEGIS-001"));
        assert!(md.contains("| Overall Score |"));
        assert!(md.contains("No previous scan data available."));
    }

    #[test]
    fn top_findings_capped_at_five() {
        let mut findings = Vec::new();
        for i in 0..10 {
            let mut f = sqli_finding();
            f.id = format!("AEGIS-{:03}", i);
            f.composite_score = 90.0 - (i as f64 * 3.0);
            findings.push(f);
        }
        let input = ExecutiveReportInput {
            findings,
            target_url: "http://localhost".to_string(),
            scan_duration_secs: 30.0,
            total_endpoints: 100,
            tested_endpoints: 80,
            previous_scan: None,
            compliance_frameworks: Vec::new(),
        };
        let report = generate_executive_report(&input);

        assert_eq!(report.top_findings.len(), 5);
        assert_eq!(report.top_findings[0].id, "AEGIS-000");
        assert!(report.top_findings[0].composite_score >= report.top_findings[4].composite_score);
        assert_eq!(report.remediation_roadmap.len(), 10);
    }

    #[test]
    fn attack_surface_zero_endpoints() {
        let input = ExecutiveReportInput {
            findings: Vec::new(),
            target_url: "http://localhost".to_string(),
            scan_duration_secs: 1.0,
            total_endpoints: 0,
            tested_endpoints: 0,
            previous_scan: None,
            compliance_frameworks: Vec::new(),
        };
        let report = generate_executive_report(&input);
        assert_eq!(report.attack_surface.coverage_percent, 0.0);
        assert_eq!(report.attack_surface.untested_count, 0);
    }

    #[test]
    fn compliance_maps_multiple_frameworks() {
        let input = ExecutiveReportInput {
            findings: vec![sqli_finding(), xss_finding(), misconfig_finding()],
            target_url: "http://localhost".to_string(),
            scan_duration_secs: 20.0,
            total_endpoints: 30,
            tested_endpoints: 25,
            previous_scan: None,
            compliance_frameworks: vec![
                ComplianceFramework::OwaspTop10,
                ComplianceFramework::PciDss,
                ComplianceFramework::Nist80053,
            ],
        };
        let report = generate_executive_report(&input);

        assert_eq!(report.compliance_status.len(), 3);
        let owasp = &report.compliance_status[0];
        assert_eq!(owasp.framework, "OWASP Top 10 2021");
        assert!(owasp.violation_count > 0);
        assert!(!owasp.violated_categories.is_empty());

        let pci = &report.compliance_status[1];
        assert_eq!(pci.framework, "PCI-DSS 4.0");
        assert!(pci.violation_count > 0);

        let nist = &report.compliance_status[2];
        assert_eq!(nist.framework, "NIST 800-53");
        assert!(nist.violation_count > 0);
    }

    #[test]
    fn effort_estimate_serializes_correctly() {
        let input = ExecutiveReportInput {
            findings: vec![
                FindingSummary {
                    effort_estimate: EffortEstimate::Hours(4),
                    ..sqli_finding()
                },
                FindingSummary {
                    id: "AEGIS-010".to_string(),
                    effort_estimate: EffortEstimate::Weeks(2),
                    ..xss_finding()
                },
            ],
            target_url: "http://localhost".to_string(),
            scan_duration_secs: 5.0,
            total_endpoints: 10,
            tested_endpoints: 10,
            previous_scan: None,
            compliance_frameworks: Vec::new(),
        };
        let report = generate_executive_report(&input);
        let json_str = render_json(&report);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let roadmap = parsed["remediation_roadmap"].as_array().unwrap();
        assert!(json_str.contains("Hours"));
        assert!(json_str.contains("Weeks"));
        assert_eq!(roadmap.len(), 2);
    }

    #[test]
    fn trend_direction_improving() {
        let mut input = sample_input();
        input.previous_scan = Some(PreviousScanData {
            total_findings: 10,
            critical_count: 5,
            high_count: 3,
            risk_score: 20.0,
            scan_date: "2024-12-01".to_string(),
        });
        let report = generate_executive_report(&input);
        let trend = report.trend_analysis.unwrap();
        assert_eq!(trend.trend_direction, "Improving");
    }

    #[test]
    fn trend_direction_degrading() {
        let mut input = sample_input();
        input.previous_scan = Some(PreviousScanData {
            total_findings: 2,
            critical_count: 0,
            high_count: 0,
            risk_score: 90.0,
            scan_date: "2024-12-01".to_string(),
        });
        let report = generate_executive_report(&input);
        let trend = report.trend_analysis.unwrap();
        assert_eq!(trend.trend_direction, "Degrading");
    }

    #[test]
    fn markdown_with_trend_data() {
        let mut input = sample_input();
        input.previous_scan = Some(PreviousScanData {
            total_findings: 6,
            critical_count: 2,
            high_count: 2,
            risk_score: 40.0,
            scan_date: "2025-02-01".to_string(),
        });
        let report = generate_executive_report(&input);
        let md = render_markdown(&report);

        assert!(md.contains("2025-02-01"));
        assert!(md.contains("Trend:"));
        assert!(!md.contains("No previous scan data available."));
    }
}
