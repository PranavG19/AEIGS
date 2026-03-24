use crate::compliance_report::{
    ComplianceFinding, ComplianceStatus, generate_cis_report, generate_compliance_report,
    generate_nist_report, generate_owasp_report, generate_pci_dss_report,
};

fn sqli_finding() -> ComplianceFinding {
    ComplianceFinding {
        id: "F-001".into(),
        vulnerability_class: "SQL Injection".into(),
        endpoint: "/api/users".into(),
        severity: "High".into(),
        composite_score: 0.92,
    }
}

fn xss_finding() -> ComplianceFinding {
    ComplianceFinding {
        id: "F-002".into(),
        vulnerability_class: "Cross-Site Scripting".into(),
        endpoint: "/search".into(),
        severity: "Medium".into(),
        composite_score: 0.78,
    }
}

fn auth_finding() -> ComplianceFinding {
    ComplianceFinding {
        id: "F-003".into(),
        vulnerability_class: "Broken Authentication".into(),
        endpoint: "/login".into(),
        severity: "Critical".into(),
        composite_score: 0.95,
    }
}

fn misconfig_finding() -> ComplianceFinding {
    ComplianceFinding {
        id: "F-004".into(),
        vulnerability_class: "Security Misconfiguration".into(),
        endpoint: "/api/debug".into(),
        severity: "Medium".into(),
        composite_score: 0.65,
    }
}

fn dep_finding() -> ComplianceFinding {
    ComplianceFinding {
        id: "F-005".into(),
        vulnerability_class: "Known Vulnerable Dependency".into(),
        endpoint: "lodash@4.17.15".into(),
        severity: "High".into(),
        composite_score: 0.88,
    }
}

fn ssrf_finding() -> ComplianceFinding {
    ComplianceFinding {
        id: "F-006".into(),
        vulnerability_class: "Server-Side Request Forgery".into(),
        endpoint: "/api/fetch-url".into(),
        severity: "High".into(),
        composite_score: 0.90,
    }
}

fn mixed_findings() -> Vec<ComplianceFinding> {
    vec![
        sqli_finding(),
        xss_finding(),
        auth_finding(),
        misconfig_finding(),
        dep_finding(),
        ssrf_finding(),
    ]
}

#[test]
fn full_compliance_report_with_mixed_findings() {
    let findings = mixed_findings();
    let report = generate_compliance_report(&findings);

    assert_eq!(report.owasp_top10.framework_name, "OWASP Top 10");
    assert_eq!(report.pci_dss.framework_name, "PCI-DSS");
    assert_eq!(report.nist_800_53.framework_name, "NIST 800-53");
    assert_eq!(report.cis_controls.framework_name, "CIS Controls");

    assert!(report.owasp_top10.fail_count > 0);
    assert!(report.owasp_top10.pass_count > 0);

    assert!(report.pci_dss.fail_count > 0);
    assert!(report.nist_800_53.fail_count > 0);
    assert!(report.cis_controls.fail_count > 0);

    let total_owasp = report.owasp_top10.pass_count
        + report.owasp_top10.fail_count
        + report.owasp_top10.partial_count
        + report.owasp_top10.not_tested_count;
    assert_eq!(total_owasp, 10);

    assert!(report.owasp_top10.coverage_percentage > 0.0);
    assert!(report.owasp_top10.coverage_percentage <= 100.0);

    assert!(!report.gap_analysis.is_empty());
}

#[test]
fn owasp_mapping_correctness() {
    let findings = mixed_findings();
    let owasp = generate_owasp_report(&findings);
    assert_eq!(owasp.requirements.len(), 10);

    let a03 = owasp
        .requirements
        .iter()
        .find(|r| r.requirement_id == "A03")
        .expect("A03 Injection must exist");
    assert_eq!(a03.status, ComplianceStatus::Fail);
    assert!(a03.findings.contains(&"F-001".to_string()));
    assert!(a03.findings.contains(&"F-002".to_string()));

    let a07 = owasp
        .requirements
        .iter()
        .find(|r| r.requirement_id == "A07")
        .expect("A07 Auth Failures must exist");
    assert_eq!(a07.status, ComplianceStatus::Fail);
    assert!(a07.findings.contains(&"F-003".to_string()));

    let a05 = owasp
        .requirements
        .iter()
        .find(|r| r.requirement_id == "A05")
        .expect("A05 Security Misconfig must exist");
    assert_eq!(a05.status, ComplianceStatus::Fail);

    let a10 = owasp
        .requirements
        .iter()
        .find(|r| r.requirement_id == "A10")
        .expect("A10 SSRF must exist");
    assert_eq!(a10.status, ComplianceStatus::Fail);
    assert!(a10.findings.contains(&"F-006".to_string()));

    let a06 = owasp
        .requirements
        .iter()
        .find(|r| r.requirement_id == "A06")
        .expect("A06 must exist");
    assert_eq!(a06.status, ComplianceStatus::Fail);
    assert!(a06.findings.contains(&"F-005".to_string()));

    let a09 = owasp
        .requirements
        .iter()
        .find(|r| r.requirement_id == "A09")
        .expect("A09 must exist");
    assert_eq!(a09.status, ComplianceStatus::NotTested);
    assert!(a09.findings.is_empty());
}

#[test]
fn pci_dss_mapping() {
    let findings = mixed_findings();
    let pci = generate_pci_dss_report(&findings);

    let r62 = pci
        .requirements
        .iter()
        .find(|r| r.requirement_id == "6.2")
        .expect("PCI-DSS 6.2 must exist");
    assert_eq!(r62.status, ComplianceStatus::Fail);
    assert!(
        r62.findings.contains(&"F-001".to_string()),
        "SQL Injection should map to 6.2"
    );

    let r64 = pci
        .requirements
        .iter()
        .find(|r| r.requirement_id == "6.4")
        .expect("PCI-DSS 6.4 must exist");
    assert_eq!(r64.status, ComplianceStatus::Fail);

    let r83 = pci
        .requirements
        .iter()
        .find(|r| r.requirement_id == "8.3")
        .expect("PCI-DSS 8.3 must exist");
    assert_eq!(r83.status, ComplianceStatus::Fail);
    assert!(
        r83.findings.contains(&"F-003".to_string()),
        "Broken Auth should map to 8.3"
    );

    let r113 = pci
        .requirements
        .iter()
        .find(|r| r.requirement_id == "11.3")
        .expect("PCI-DSS 11.3 must exist");
    assert_eq!(r113.status, ComplianceStatus::Fail);
    assert!(
        r113.findings.contains(&"F-005".to_string()),
        "Known Vuln Dep should map to 11.3"
    );
}

#[test]
fn nist_mapping() {
    let findings = mixed_findings();
    let nist = generate_nist_report(&findings);
    assert_eq!(nist.requirements.len(), 8);

    let si = nist
        .requirements
        .iter()
        .find(|r| r.requirement_id == "SI")
        .expect("SI must exist");
    assert_eq!(si.status, ComplianceStatus::Fail);
    assert!(
        si.findings.contains(&"F-001".to_string()),
        "SQLi should map to SI"
    );

    let ia = nist
        .requirements
        .iter()
        .find(|r| r.requirement_id == "IA")
        .expect("IA must exist");
    assert_eq!(ia.status, ComplianceStatus::Fail);
    assert!(ia.findings.contains(&"F-003".to_string()));

    let cm = nist
        .requirements
        .iter()
        .find(|r| r.requirement_id == "CM")
        .expect("CM must exist");
    assert_eq!(cm.status, ComplianceStatus::Fail);

    let sc = nist
        .requirements
        .iter()
        .find(|r| r.requirement_id == "SC")
        .expect("SC must exist");
    assert_eq!(sc.status, ComplianceStatus::Fail);

    let ir = nist
        .requirements
        .iter()
        .find(|r| r.requirement_id == "IR")
        .expect("IR must exist");
    assert_eq!(ir.status, ComplianceStatus::NotTested);
}

#[test]
fn gap_analysis_identifies_untested_requirements() {
    let findings = vec![sqli_finding()];
    let report = generate_compliance_report(&findings);
    let gaps = &report.gap_analysis;

    assert!(!gaps.is_empty(), "single finding should leave gaps");

    let owasp_gaps: Vec<_> = gaps
        .iter()
        .filter(|g| g.framework.starts_with("OWASP"))
        .collect();
    assert!(
        !owasp_gaps.is_empty(),
        "OWASP should have untested categories with only SQLi"
    );

    let a09_gap = owasp_gaps.iter().find(|g| g.requirement_id == "A09");
    assert!(
        a09_gap.is_some(),
        "A09 Logging & Monitoring should be a gap (no vuln classes map to it)"
    );

    for gap in gaps {
        assert!(!gap.recommendation.is_empty());
        assert!(!gap.title.is_empty());
    }
}

#[test]
fn empty_findings_all_not_tested() {
    let report = generate_compliance_report(&[]);

    assert_eq!(report.owasp_top10.pass_count, 0);
    assert_eq!(report.owasp_top10.fail_count, 0);
    assert_eq!(report.owasp_top10.partial_count, 0);
    assert_eq!(report.owasp_top10.not_tested_count, 10);
    assert_eq!(report.owasp_top10.coverage_percentage, 0.0);

    assert_eq!(
        report.pci_dss.not_tested_count,
        report.pci_dss.requirements.len()
    );
    assert_eq!(
        report.nist_800_53.not_tested_count,
        report.nist_800_53.requirements.len()
    );
    assert_eq!(
        report.cis_controls.not_tested_count,
        report.cis_controls.requirements.len()
    );

    for req in &report.owasp_top10.requirements {
        assert_eq!(req.status, ComplianceStatus::NotTested);
        assert!(req.findings.is_empty());
    }

    assert_eq!(report.gap_analysis.len(), 10 + 6 + 8 + 7);
}

#[test]
fn cis_controls_mapping() {
    let findings = mixed_findings();
    let cis = generate_cis_report(&findings);
    assert_eq!(cis.requirements.len(), 7);

    let ig2_16 = cis
        .requirements
        .iter()
        .find(|r| r.requirement_id == "IG2-16")
        .expect("IG2-16 must exist");
    assert_eq!(ig2_16.status, ComplianceStatus::Fail);
    assert!(
        ig2_16.findings.contains(&"F-001".to_string()),
        "SQLi maps to IG2-16"
    );

    let ig1_5 = cis
        .requirements
        .iter()
        .find(|r| r.requirement_id == "IG1-5")
        .expect("IG1-5 must exist");
    assert_eq!(ig1_5.status, ComplianceStatus::Fail);

    let ig2_7 = cis
        .requirements
        .iter()
        .find(|r| r.requirement_id == "IG2-7")
        .expect("IG2-7 must exist");
    assert_eq!(ig2_7.status, ComplianceStatus::Fail);
    assert!(ig2_7.findings.contains(&"F-005".to_string()));
}

#[test]
fn framework_report_serializes_to_json() {
    let findings = vec![sqli_finding()];
    let report = generate_compliance_report(&findings);
    let json = serde_json::to_string(&report).expect("should serialize");
    assert!(json.contains("OWASP Top 10"));
    assert!(json.contains("PCI-DSS"));
    assert!(json.contains("NIST 800-53"));
    assert!(json.contains("CIS Controls"));
    assert!(json.contains("NotTested"));
}

#[test]
fn coverage_percentage_calculation() {
    let findings = mixed_findings();
    let owasp = generate_owasp_report(&findings);
    let tested = owasp.pass_count + owasp.fail_count + owasp.partial_count;
    let expected = (tested as f64 / 10.0) * 100.0;
    assert!(
        (owasp.coverage_percentage - expected).abs() < f64::EPSILON,
        "coverage should be {}%, got {}%",
        expected,
        owasp.coverage_percentage,
    );
}

#[test]
fn single_finding_marks_pass_for_unrelated_requirements() {
    let findings = vec![ssrf_finding()];
    let owasp = generate_owasp_report(&findings);

    let a10 = owasp
        .requirements
        .iter()
        .find(|r| r.requirement_id == "A10")
        .unwrap();
    assert_eq!(a10.status, ComplianceStatus::Fail);

    let a03 = owasp
        .requirements
        .iter()
        .find(|r| r.requirement_id == "A03")
        .unwrap();
    assert_eq!(
        a03.status,
        ComplianceStatus::Pass,
        "A03 should pass: has mapped classes but none found in findings"
    );
}
