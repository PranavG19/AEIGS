use crate::shodan_lookup::*;

// ===== Existing Tests (11 tests) =====

#[test]
fn parse_internetdb_full_response() {
    let body = r#"{
        "cpes": ["cpe:/a:apache:http_server:2.4.51"],
        "hostnames": ["example.com"],
        "ip": "93.184.216.34",
        "ports": [80, 443],
        "tags": ["cloud"],
        "vulns": ["CVE-2021-44228", "CVE-2022-22965"]
    }"#;
    let result = parse_internetdb_response(body, "93.184.216.34").unwrap();
    assert_eq!(result.ip, "93.184.216.34");
    assert_eq!(result.ports, vec![80, 443]);
    assert_eq!(result.hostnames, vec!["example.com"]);
    assert_eq!(result.vulns.len(), 2);
    assert!(result.vulns.contains(&"CVE-2021-44228".to_string()));
    assert_eq!(result.cpes.len(), 1);
    assert_eq!(result.tags, vec!["cloud"]);
}

#[test]
fn parse_internetdb_empty_arrays() {
    let body = r#"{
        "cpes": [],
        "hostnames": [],
        "ip": "1.2.3.4",
        "ports": [],
        "tags": [],
        "vulns": []
    }"#;
    let result = parse_internetdb_response(body, "1.2.3.4").unwrap();
    assert!(result.ports.is_empty());
    assert!(result.vulns.is_empty());
    assert!(result.hostnames.is_empty());
}

#[test]
fn parse_internetdb_missing_fields() {
    let body = r#"{"ip": "1.2.3.4", "ports": [22]}"#;
    let result = parse_internetdb_response(body, "1.2.3.4").unwrap();
    assert_eq!(result.ports, vec![22]);
    assert!(result.vulns.is_empty());
    assert!(result.hostnames.is_empty());
    assert!(result.cpes.is_empty());
    assert!(result.tags.is_empty());
}

#[test]
fn parse_internetdb_invalid_json() {
    let result = parse_internetdb_response("not json", "1.2.3.4");
    assert!(result.is_none());
}

#[test]
fn parse_internetdb_not_object() {
    let result = parse_internetdb_response("[1,2,3]", "1.2.3.4");
    assert!(result.is_none());
}

#[test]
fn shodan_to_operations_ports_and_vulns() {
    let result = ShodanResult {
        ip: "93.184.216.34".to_string(),
        ports: vec![80, 443],
        hostnames: vec!["example.com".to_string()],
        vulns: vec!["CVE-2021-44228".to_string()],
        cpes: vec![],
        tags: vec![],
    };
    let mut seq = 0;
    let ops = shodan_to_operations(&result, &mut seq);
    // 2 ports (AddNode each) + 1 vuln (AddFinding) = 3
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);

    // First two should be AddNode for ports
    for op in &ops[..2] {
        match &op.operation {
            aegis_protocol::operation::GraphOperation::AddNode {
                node_type,
                properties,
            } => {
                assert_eq!(*node_type, aegis_protocol::node::NodeType::Service);
                let source = properties.iter().find(|(k, _)| k == "source").unwrap();
                assert_eq!(source.1, "shodan-internetdb");
            }
            _ => panic!("expected AddNode"),
        }
    }

    // Third should be AddFinding for vuln
    match &ops[2].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 7.0).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn shodan_to_operations_empty() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let mut seq = 5;
    let ops = shodan_to_operations(&result, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn shodan_to_operations_ports_only() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![22, 80, 443],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let mut seq = 0;
    let ops = shodan_to_operations(&result, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn shodan_lookup_skips_localhost() {
    let result = shodan_lookup("http://localhost:8080");
    assert!(result.is_none());
}

#[test]
fn shodan_lookup_skips_loopback() {
    let result = shodan_lookup("http://127.0.0.1:3000");
    assert!(result.is_none());
}

#[test]
fn resolve_ip_skips_loopback() {
    let result = resolve_ip("localhost");
    assert!(result.is_none());
}

// ===== New Tests: ShodanIssue Display (8 tests) =====

#[test]
fn shodan_issue_display_high_risk_port() {
    let issue = ShodanIssue::HighRiskPort { port: 3389 };
    assert_eq!(issue.to_string(), "high_risk_port:3389");
}

#[test]
fn shodan_issue_display_known_cve() {
    let issue = ShodanIssue::KnownCve {
        cve_id: "CVE-2021-44228".to_string(),
    };
    assert_eq!(issue.to_string(), "known_cve:CVE-2021-44228");
}

#[test]
fn shodan_issue_display_multiple_cves() {
    let issue = ShodanIssue::MultipleCves { count: 15 };
    assert_eq!(issue.to_string(), "multiple_cves:15");
}

#[test]
fn shodan_issue_display_outdated_cpe() {
    let issue = ShodanIssue::OutdatedCpe {
        cpe: "cpe:/a:apache:http_server:2.4".to_string(),
        technology: "http server".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "outdated_cpe:http server:cpe:/a:apache:http_server:2.4"
    );
}

#[test]
fn shodan_issue_display_cloud_hosted() {
    let issue = ShodanIssue::CloudHosted {
        provider: "AWS".to_string(),
    };
    assert_eq!(issue.to_string(), "cloud_hosted:AWS");
}

#[test]
fn shodan_issue_display_honeypot() {
    let issue = ShodanIssue::HoneypotIndicator {
        tag: "honeypot".to_string(),
    };
    assert_eq!(issue.to_string(), "honeypot:honeypot");
}

#[test]
fn shodan_issue_display_exposive_service() {
    let issue = ShodanIssue::ExposiveService {
        port: 3306,
        service: "MySQL".to_string(),
    };
    assert_eq!(issue.to_string(), "exposed_service:MySQL:3306");
}

#[test]
fn shodan_issue_display_high_port_count() {
    let issue = ShodanIssue::HighPortCount { count: 50 };
    assert_eq!(issue.to_string(), "high_port_count:50");
}

// ===== New Tests: shodan_issue_severity (8 tests) =====

#[test]
fn severity_known_cve() {
    let issue = ShodanIssue::KnownCve {
        cve_id: "CVE-2021-44228".to_string(),
    };
    assert_eq!(shodan_issue_severity(&issue), 8.0);
}

#[test]
fn severity_multiple_cves_over_10() {
    let issue = ShodanIssue::MultipleCves { count: 15 };
    assert_eq!(shodan_issue_severity(&issue), 9.0);
}

#[test]
fn severity_multiple_cves_10_or_less() {
    let issue = ShodanIssue::MultipleCves { count: 5 };
    assert_eq!(shodan_issue_severity(&issue), 7.5);
}

#[test]
fn severity_exposive_service() {
    let issue = ShodanIssue::ExposiveService {
        port: 3306,
        service: "MySQL".to_string(),
    };
    assert_eq!(shodan_issue_severity(&issue), 7.0);
}

#[test]
fn severity_high_risk_port() {
    let issue = ShodanIssue::HighRiskPort { port: 3389 };
    assert_eq!(shodan_issue_severity(&issue), 6.0);
}

#[test]
fn severity_outdated_cpe() {
    let issue = ShodanIssue::OutdatedCpe {
        cpe: "cpe:/a:apache:http_server:2.4".to_string(),
        technology: "http server".to_string(),
    };
    assert_eq!(shodan_issue_severity(&issue), 6.5);
}

#[test]
fn severity_high_port_count() {
    let issue = ShodanIssue::HighPortCount { count: 50 };
    assert_eq!(shodan_issue_severity(&issue), 5.5);
}

#[test]
fn severity_honeypot() {
    let issue = ShodanIssue::HoneypotIndicator {
        tag: "honeypot".to_string(),
    };
    assert_eq!(shodan_issue_severity(&issue), 5.0);
}

#[test]
fn severity_cloud_hosted() {
    let issue = ShodanIssue::CloudHosted {
        provider: "AWS".to_string(),
    };
    assert_eq!(shodan_issue_severity(&issue), 2.0);
}

// ===== New Tests: analyze_shodan_result (33+ tests) =====

#[test]
fn analyze_high_risk_port_21_detected() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![21],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::HighRiskPort { port: 21 }))
    );
}

#[test]
fn analyze_high_risk_port_3389_detected() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![3389],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::HighRiskPort { port: 3389 }))
    );
}

#[test]
fn analyze_multiple_high_risk_ports() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![21, 23, 3389],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    let high_risk_count = issues
        .iter()
        .filter(|i| matches!(i, ShodanIssue::HighRiskPort { .. }))
        .count();
    assert_eq!(high_risk_count, 3);
}

#[test]
fn analyze_no_high_risk_ports_for_safe_ports() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![80, 443],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::HighRiskPort { .. }))
    );
}

#[test]
fn analyze_known_cve_single() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![],
        hostnames: vec![],
        vulns: vec!["CVE-2021-44228".to_string()],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::KnownCve { cve_id } if cve_id == "CVE-2021-44228"))
    );
}

#[test]
fn analyze_known_cve_multiple_triggers_count() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![],
        hostnames: vec![],
        vulns: vec![
            "CVE-2021-44228".to_string(),
            "CVE-2022-22965".to_string(),
            "CVE-2020-1234".to_string(),
            "CVE-2019-5678".to_string(),
        ],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::MultipleCves { count: 4 }))
    );
}

#[test]
fn analyze_known_cve_three_no_multiple() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![],
        hostnames: vec![],
        vulns: vec![
            "CVE-2021-44228".to_string(),
            "CVE-2022-22965".to_string(),
            "CVE-2020-1234".to_string(),
        ],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::MultipleCves { .. }))
    );
    // Should have exactly 3 KnownCve issues
    let cve_count = issues
        .iter()
        .filter(|i| matches!(i, ShodanIssue::KnownCve { .. }))
        .count();
    assert_eq!(cve_count, 3);
}

#[test]
fn analyze_exposed_service_mysql_3306() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![3306],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(issues.iter().any(|i| matches!(
        i,
        ShodanIssue::ExposiveService { port: 3306, service } if service == "MySQL"
    )));
}

#[test]
fn analyze_exposed_service_redis_6379() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![6379],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(issues.iter().any(|i| matches!(
        i,
        ShodanIssue::ExposiveService { port: 6379, service } if service == "Redis"
    )));
}

#[test]
fn analyze_exposed_service_mongodb_27017() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![27017],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(issues.iter().any(|i| matches!(
        i,
        ShodanIssue::ExposiveService { port: 27017, service } if service == "MongoDB"
    )));
}

#[test]
fn analyze_multiple_exposed_services() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![3306, 6379, 27017],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    let exposed_count = issues
        .iter()
        .filter(|i| matches!(i, ShodanIssue::ExposiveService { .. }))
        .count();
    assert_eq!(exposed_count, 3);
}

#[test]
fn analyze_high_port_count_over_20() {
    let mut ports = Vec::new();
    for i in 0..25 {
        ports.push(8000 + i);
    }
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports,
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::HighPortCount { count: 25 }))
    );
}

#[test]
fn analyze_port_count_20_no_issue() {
    let mut ports = Vec::new();
    for i in 0..20 {
        ports.push(8000 + i);
    }
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports,
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::HighPortCount { .. }))
    );
}

#[test]
fn analyze_outdated_cpe_standard_format() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec!["cpe:/a:apache:http_server:2.4".to_string()],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(issues.iter().any(|i| matches!(
        i,
        ShodanIssue::OutdatedCpe { technology, .. } if technology == "http server"
    )));
}

#[test]
fn analyze_outdated_cpe_23_format() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec!["cpe:2.3:a:microsoft:iis:10.0".to_string()],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(issues.iter().any(|i| matches!(
        i,
        ShodanIssue::OutdatedCpe { technology, .. } if technology == "iis"
    )));
}

#[test]
fn analyze_cpe_invalid_no_issue() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec!["invalid-cpe".to_string()],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::OutdatedCpe { .. }))
    );
}

#[test]
fn analyze_cloud_hosted_aws() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![],
        hostnames: vec!["ec2-52-123-45-67.compute-1.amazonaws.com".to_string()],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(issues.iter().any(|i| matches!(
        i,
        ShodanIssue::CloudHosted { provider } if provider == "AWS"
    )));
}

#[test]
fn analyze_cloud_hosted_azure() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![],
        hostnames: vec!["myapp.azurewebsites.net".to_string()],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(issues.iter().any(|i| matches!(
        i,
        ShodanIssue::CloudHosted { provider } if provider == "Azure"
    )));
}

#[test]
fn analyze_cloud_hosted_not_detected() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![],
        hostnames: vec!["example.com".to_string()],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::CloudHosted { .. }))
    );
}

#[test]
fn analyze_honeypot_tag() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec!["honeypot".to_string()],
    };
    let issues = analyze_shodan_result(&result);
    assert!(issues.iter().any(|i| matches!(
        i,
        ShodanIssue::HoneypotIndicator { tag } if tag == "honeypot"
    )));
}

#[test]
fn analyze_self_signed_tag() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec!["self-signed".to_string()],
    };
    let issues = analyze_shodan_result(&result);
    assert!(issues.iter().any(|i| matches!(
        i,
        ShodanIssue::HoneypotIndicator { tag } if tag == "self-signed"
    )));
}

#[test]
fn analyze_normal_tag_no_issue() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec!["cloud".to_string()],
    };
    let issues = analyze_shodan_result(&result);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::HoneypotIndicator { .. }))
    );
}

#[test]
fn analyze_empty_result_no_issues() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let issues = analyze_shodan_result(&result);
    assert!(issues.is_empty());
}

#[test]
fn analyze_combined_all_issue_types() {
    let mut ports = vec![21, 3306, 6379];
    for i in 0..22 {
        ports.push(8000 + i);
    }
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports,
        hostnames: vec!["ec2-52-123-45-67.compute-1.amazonaws.com".to_string()],
        vulns: vec![
            "CVE-2021-44228".to_string(),
            "CVE-2022-22965".to_string(),
            "CVE-2020-1234".to_string(),
            "CVE-2019-5678".to_string(),
        ],
        cpes: vec!["cpe:/a:apache:http_server:2.4".to_string()],
        tags: vec!["honeypot".to_string()],
    };
    let issues = analyze_shodan_result(&result);

    // Should have: 1 HighRiskPort (21), 2 ExposiveService (3306, 6379), 1 HighPortCount,
    // 4 KnownCve, 1 MultipleCves, 1 OutdatedCpe, 1 HoneypotIndicator, 1 CloudHosted
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::HighRiskPort { port: 21 }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::ExposiveService { port: 3306, .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::ExposiveService { port: 6379, .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::HighPortCount { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::MultipleCves { count: 4 }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::OutdatedCpe { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::HoneypotIndicator { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ShodanIssue::CloudHosted { .. }))
    );
}

// ===== New Tests: shodan_issues_to_operations (3 tests) =====

#[test]
fn issues_to_operations_empty() {
    let issues = vec![];
    let mut seq = 10;
    let ops = shodan_issues_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 10);
}

#[test]
fn issues_to_operations_single_issue() {
    let issues = vec![ShodanIssue::HighRiskPort { port: 3389 }];
    let mut seq = 0;
    let ops = shodan_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);

    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            severity,
            confidence,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::InformationDisclosure
            );
            assert_eq!(*severity, 6.0);
            assert!((confidence.value() - 0.5).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn issues_to_operations_multiple_issues_seq_increments() {
    let issues = vec![
        ShodanIssue::KnownCve {
            cve_id: "CVE-2021-44228".to_string(),
        },
        ShodanIssue::ExposiveService {
            port: 3306,
            service: "MySQL".to_string(),
        },
        ShodanIssue::CloudHosted {
            provider: "AWS".to_string(),
        },
    ];
    let mut seq = 5;
    let ops = shodan_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);

    // Verify sequence numbers
    assert_eq!(ops[0].sequence_number, 6);
    assert_eq!(ops[1].sequence_number, 7);
    assert_eq!(ops[2].sequence_number, 8);

    // Verify severities
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 8.0);
        }
        _ => panic!("expected AddFinding"),
    }
    match &ops[1].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 7.0);
        }
        _ => panic!("expected AddFinding"),
    }
    match &ops[2].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 2.0);
        }
        _ => panic!("expected AddFinding"),
    }
}
