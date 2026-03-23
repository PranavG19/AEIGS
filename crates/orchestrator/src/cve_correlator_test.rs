use super::*;
use aegis_protocol::operation::GraphOperation;

#[test]
fn parse_nvd_response_extracts_cves() {
    let json = r#"{
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [
                        {"lang": "en", "value": "XSS in nginx proxy"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 7.5}
                        }]
                    }
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-5678",
                    "descriptions": [
                        {"lang": "en", "value": "Buffer overflow"}
                    ],
                    "metrics": {}
                }
            }
        ]
    }"#;
    let matches = cve_correlator::parse_nvd_response(json, "nginx");
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].cve_id, "CVE-2024-1234");
    assert_eq!(matches[0].description, "XSS in nginx proxy");
    assert_eq!(matches[0].cvss_score, Some(7.5));
    assert_eq!(matches[0].technology, "nginx");
    assert_eq!(matches[1].cve_id, "CVE-2024-5678");
    assert!(matches[1].cvss_score.is_none());
}

#[test]
fn parse_nvd_response_empty_vulnerabilities() {
    let json = r#"{"vulnerabilities": []}"#;
    let matches = cve_correlator::parse_nvd_response(json, "nginx");
    assert!(matches.is_empty());
}

#[test]
fn parse_nvd_response_invalid_json() {
    let matches = cve_correlator::parse_nvd_response("not json", "nginx");
    assert!(matches.is_empty());
}

#[test]
fn parse_nvd_response_cvss_v2_fallback() {
    let json = r#"{
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2020-9999",
                "descriptions": [{"lang": "en", "value": "old vuln"}],
                "metrics": {
                    "cvssMetricV2": [{
                        "cvssData": {"baseScore": 6.0}
                    }]
                }
            }
        }]
    }"#;
    let matches = cve_correlator::parse_nvd_response(json, "php");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].cvss_score, Some(6.0));
}

#[test]
fn parse_nvd_response_skips_entries_without_id() {
    let json = r#"{
        "vulnerabilities": [{
            "cve": {
                "descriptions": [{"lang": "en", "value": "no id"}],
                "metrics": {}
            }
        }]
    }"#;
    let matches = cve_correlator::parse_nvd_response(json, "nginx");
    assert!(matches.is_empty());
}

#[test]
fn cve_matches_to_operations_creates_findings() {
    let matches = vec![
        cve_correlator::NvdCveMatch {
            cve_id: "CVE-2024-1234".to_string(),
            description: "XSS".to_string(),
            cvss_score: Some(7.5),
            technology: "nginx".to_string(),
        },
        cve_correlator::NvdCveMatch {
            cve_id: "CVE-2024-5678".to_string(),
            description: "RCE".to_string(),
            cvss_score: None,
            technology: "nginx".to_string(),
        },
    ];
    let mut seq = 0u64;
    let ops = cve_correlator::cve_matches_to_operations(&matches, &mut seq);

    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);

    match &ops[0].operation {
        GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 7.5).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }

    match &ops[1].operation {
        GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 5.0).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn cve_matches_to_operations_empty() {
    let matches: Vec<cve_correlator::NvdCveMatch> = Vec::new();
    let mut seq = 0u64;
    let ops = cve_correlator::cve_matches_to_operations(&matches, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn correlate_cves_empty_tech_returns_empty() {
    let techs: Vec<String> = Vec::new();
    let matches = cve_correlator::correlate_cves(&techs);
    assert!(matches.is_empty());
}

#[test]
fn parse_nvd_response_prefers_english_description() {
    let json = r#"{
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-0001",
                "descriptions": [
                    {"lang": "es", "value": "Vulnerabilidad en..."},
                    {"lang": "en", "value": "Vulnerability in..."}
                ],
                "metrics": {}
            }
        }]
    }"#;
    let matches = cve_correlator::parse_nvd_response(json, "test");
    assert_eq!(matches[0].description, "Vulnerability in...");
}

#[test]
fn parse_nvd_response_missing_cve_field() {
    let json = r#"{"vulnerabilities": [{"cve": null}]}"#;
    let matches = cve_correlator::parse_nvd_response(json, "test");
    assert!(matches.is_empty());
}

#[test]
fn cve_matches_to_operations_uses_known_vuln_dep_class() {
    let matches = vec![cve_correlator::NvdCveMatch {
        cve_id: "CVE-2024-0001".to_string(),
        description: "test".to_string(),
        cvss_score: Some(9.8),
        technology: "openssl".to_string(),
    }];
    let mut seq = 0;
    let ops = cve_correlator::cve_matches_to_operations(&matches, &mut seq);
    match &ops[0].operation {
        GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::KnownVulnerableDependency
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn parse_nvd_response_v31_takes_precedence_over_v2() {
    let json = r#"{
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-0001",
                "descriptions": [{"lang": "en", "value": "test"}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 9.0}}],
                    "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]
                }
            }
        }]
    }"#;
    let matches = cve_correlator::parse_nvd_response(json, "test");
    assert_eq!(matches[0].cvss_score, Some(9.0));
}

// --- analyze_cve_matches tests ---

fn make_match(
    cve_id: &str,
    desc: &str,
    score: Option<f64>,
    tech: &str,
) -> cve_correlator::NvdCveMatch {
    cve_correlator::NvdCveMatch {
        cve_id: cve_id.to_string(),
        description: desc.to_string(),
        cvss_score: score,
        technology: tech.to_string(),
    }
}

#[test]
fn analyze_empty_matches() {
    let issues = cve_correlator::analyze_cve_matches(&[]);
    assert!(issues.is_empty());
}

#[test]
fn analyze_known_cve_with_score() {
    let matches = vec![make_match(
        "CVE-2024-0001",
        "buffer overflow",
        Some(7.5),
        "nginx",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let known = issues
        .iter()
        .find(|i| matches!(i, cve_correlator::CveIssue::KnownCve { .. }));
    assert!(known.is_some());
    if let cve_correlator::CveIssue::KnownCve {
        cve_id,
        technology,
        cvss_score,
    } = known.unwrap()
    {
        assert_eq!(cve_id, "CVE-2024-0001");
        assert_eq!(technology, "nginx");
        assert!((cvss_score - 7.5).abs() < 1e-9);
    }
}

#[test]
fn analyze_no_score_available() {
    let matches = vec![make_match("CVE-2024-0002", "unknown severity", None, "php")];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let no_score = issues
        .iter()
        .find(|i| matches!(i, cve_correlator::CveIssue::NoScoreAvailable { .. }));
    assert!(no_score.is_some());
    if let cve_correlator::CveIssue::NoScoreAvailable { cve_id, technology } = no_score.unwrap() {
        assert_eq!(cve_id, "CVE-2024-0002");
        assert_eq!(technology, "php");
    }
}

#[test]
fn analyze_critical_cve_threshold_at_nine() {
    let matches = vec![make_match(
        "CVE-2024-0003",
        "critical vuln",
        Some(9.0),
        "openssl",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let critical = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::CriticalCve { .. }))
        .count();
    assert_eq!(critical, 1);
}

#[test]
fn analyze_critical_cve_threshold_below_nine() {
    let matches = vec![make_match(
        "CVE-2024-0004",
        "high vuln",
        Some(8.9),
        "openssl",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let critical = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::CriticalCve { .. }))
        .count();
    assert_eq!(critical, 0);
}

#[test]
fn analyze_critical_cve_above_nine() {
    let matches = vec![make_match(
        "CVE-2024-0005",
        "severe vuln",
        Some(9.8),
        "nginx",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let critical: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::CriticalCve { .. }))
        .collect();
    assert_eq!(critical.len(), 1);
    if let cve_correlator::CveIssue::CriticalCve { cvss_score, .. } = critical[0] {
        assert!((cvss_score - 9.8).abs() < 1e-9);
    }
}

#[test]
fn analyze_rce_detection_lowercase() {
    let matches = vec![make_match(
        "CVE-2024-0006",
        "remote code execution in component",
        Some(9.5),
        "nginx",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let rce = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::RemoteCodeExecution { .. }))
        .count();
    assert_eq!(rce, 1);
}

#[test]
fn analyze_rce_detection_uppercase() {
    let matches = vec![make_match(
        "CVE-2024-0007",
        "An RCE vulnerability was found",
        Some(9.0),
        "php",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let rce = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::RemoteCodeExecution { .. }))
        .count();
    assert_eq!(rce, 1);
}

#[test]
fn analyze_rce_detection_mixed_case() {
    let matches = vec![make_match(
        "CVE-2024-0008",
        "Remote Code Execution found",
        Some(9.2),
        "java",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let rce = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::RemoteCodeExecution { .. }))
        .count();
    assert_eq!(rce, 1);
}

#[test]
fn analyze_auth_bypass_detection() {
    let matches = vec![make_match(
        "CVE-2024-0009",
        "authentication bypass in login",
        Some(8.0),
        "nginx",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let auth = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::AuthBypass { .. }))
        .count();
    assert_eq!(auth, 1);
}

#[test]
fn analyze_auth_bypass_short_form() {
    let matches = vec![make_match(
        "CVE-2024-0010",
        "auth bypass via token replay",
        Some(7.5),
        "java",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let auth = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::AuthBypass { .. }))
        .count();
    assert_eq!(auth, 1);
}

#[test]
fn analyze_exploit_detection_keyword() {
    let matches = vec![make_match(
        "CVE-2024-0011",
        "exploit available in the wild",
        Some(7.0),
        "php",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let exploit = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::ExploitAvailable { .. }))
        .count();
    assert_eq!(exploit, 1);
}

#[test]
fn analyze_exploit_detection_poc() {
    let matches = vec![make_match(
        "CVE-2024-0012",
        "PoC demonstrates the issue",
        Some(6.5),
        "nginx",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let exploit = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::ExploitAvailable { .. }))
        .count();
    assert_eq!(exploit, 1);
}

#[test]
fn analyze_exploit_detection_proof_of_concept() {
    let matches = vec![make_match(
        "CVE-2024-0013",
        "proof of concept was published",
        Some(6.0),
        "nginx",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let exploit = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::ExploitAvailable { .. }))
        .count();
    assert_eq!(exploit, 1);
}

#[test]
fn analyze_no_exploit_on_unrelated_description() {
    let matches = vec![make_match(
        "CVE-2024-0014",
        "buffer overflow in parser",
        Some(6.0),
        "nginx",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let exploit = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::ExploitAvailable { .. }))
        .count();
    assert_eq!(exploit, 0);
}

#[test]
fn analyze_high_cve_count_above_threshold() {
    let matches: Vec<_> = (0..6)
        .map(|i| make_match(&format!("CVE-2024-{i:04}"), "vuln", Some(5.0), "nginx"))
        .collect();
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let high_count: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::HighCveCount { .. }))
        .collect();
    assert_eq!(high_count.len(), 1);
    if let cve_correlator::CveIssue::HighCveCount { technology, count } = high_count[0] {
        assert_eq!(technology, "nginx");
        assert_eq!(*count, 6);
    }
}

#[test]
fn analyze_high_cve_count_at_threshold() {
    let matches: Vec<_> = (0..5)
        .map(|i| make_match(&format!("CVE-2024-{i:04}"), "vuln", Some(5.0), "nginx"))
        .collect();
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let high_count = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::HighCveCount { .. }))
        .count();
    assert_eq!(high_count, 0);
}

#[test]
fn analyze_high_cve_count_per_technology() {
    let mut matches: Vec<_> = (0..6)
        .map(|i| make_match(&format!("CVE-2024-{i:04}"), "vuln", Some(5.0), "nginx"))
        .collect();
    matches
        .extend((0..3).map(|i| make_match(&format!("CVE-2024-1{i:03}"), "vuln", Some(4.0), "php")));
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let high_count: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::HighCveCount { .. }))
        .collect();
    assert_eq!(high_count.len(), 1);
    if let cve_correlator::CveIssue::HighCveCount { technology, .. } = high_count[0] {
        assert_eq!(technology, "nginx");
    }
}

#[test]
fn analyze_outdated_technology_recent_cve() {
    let current_year = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (1970 + secs / 31_557_600) as u16
    };
    let cve_id = format!("CVE-{current_year}-0001");
    let matches = vec![make_match(&cve_id, "vuln", Some(5.0), "nginx")];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let outdated = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::OutdatedTechnology { .. }))
        .count();
    assert_eq!(outdated, 1);
}

#[test]
fn analyze_outdated_technology_previous_year() {
    let current_year = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (1970 + secs / 31_557_600) as u16
    };
    let prev_year = current_year - 1;
    let cve_id = format!("CVE-{prev_year}-0001");
    let matches = vec![make_match(&cve_id, "vuln", Some(5.0), "php")];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let outdated = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::OutdatedTechnology { .. }))
        .count();
    assert_eq!(outdated, 1);
}

#[test]
fn analyze_not_outdated_old_cve() {
    let matches = vec![make_match("CVE-2015-0001", "old vuln", Some(5.0), "nginx")];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let outdated = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::OutdatedTechnology { .. }))
        .count();
    assert_eq!(outdated, 0);
}

#[test]
fn analyze_multiple_issues_single_cve() {
    let matches = vec![make_match(
        "CVE-2025-0001",
        "Remote Code Execution with exploit available",
        Some(9.8),
        "openssl",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let known = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::KnownCve { .. }))
        .count();
    let critical = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::CriticalCve { .. }))
        .count();
    let rce = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::RemoteCodeExecution { .. }))
        .count();
    let exploit = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::ExploitAvailable { .. }))
        .count();
    assert_eq!(known, 1);
    assert_eq!(critical, 1);
    assert_eq!(rce, 1);
    assert_eq!(exploit, 1);
}

#[test]
fn analyze_all_same_tech() {
    let matches: Vec<_> = (0..3)
        .map(|i| make_match(&format!("CVE-2024-{i:04}"), "vuln", Some(5.0), "nginx"))
        .collect();
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let known = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::KnownCve { .. }))
        .count();
    assert_eq!(known, 3);
}

#[test]
fn analyze_mixed_techs() {
    let matches = vec![
        make_match("CVE-2024-0001", "vuln", Some(5.0), "nginx"),
        make_match("CVE-2024-0002", "vuln", Some(6.0), "php"),
        make_match("CVE-2024-0003", "vuln", Some(7.0), "java"),
    ];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let known = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::KnownCve { .. }))
        .count();
    assert_eq!(known, 3);
}

#[test]
fn analyze_case_insensitive_rce_in_description() {
    let matches = vec![make_match(
        "CVE-2024-0001",
        "rce vulnerability found",
        Some(8.0),
        "nginx",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let rce = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::RemoteCodeExecution { .. }))
        .count();
    assert_eq!(rce, 1);
}

#[test]
fn analyze_case_insensitive_auth_bypass() {
    let matches = vec![make_match(
        "CVE-2024-0001",
        "Authentication Bypass in API",
        Some(8.0),
        "nginx",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let auth = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::AuthBypass { .. }))
        .count();
    assert_eq!(auth, 1);
}

#[test]
fn analyze_case_insensitive_exploit() {
    let matches = vec![make_match(
        "CVE-2024-0001",
        "An EXPLOIT exists for this",
        Some(7.0),
        "nginx",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let exploit = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::ExploitAvailable { .. }))
        .count();
    assert_eq!(exploit, 1);
}

// --- Display tests ---

#[test]
fn display_known_cve() {
    let issue = cve_correlator::CveIssue::KnownCve {
        cve_id: "CVE-2024-0001".to_string(),
        technology: "nginx".to_string(),
        cvss_score: 7.5,
    };
    assert_eq!(format!("{issue}"), "known_cve:CVE-2024-0001:nginx:7.5");
}

#[test]
fn display_critical_cve() {
    let issue = cve_correlator::CveIssue::CriticalCve {
        cve_id: "CVE-2024-0002".to_string(),
        technology: "openssl".to_string(),
        cvss_score: 9.8,
    };
    assert_eq!(format!("{issue}"), "critical_cve:CVE-2024-0002:openssl:9.8");
}

#[test]
fn display_exploit_available() {
    let issue = cve_correlator::CveIssue::ExploitAvailable {
        cve_id: "CVE-2024-0003".to_string(),
        technology: "php".to_string(),
    };
    assert_eq!(format!("{issue}"), "exploit_available:CVE-2024-0003:php");
}

#[test]
fn display_remote_code_execution() {
    let issue = cve_correlator::CveIssue::RemoteCodeExecution {
        cve_id: "CVE-2024-0004".to_string(),
        technology: "java".to_string(),
    };
    assert_eq!(
        format!("{issue}"),
        "remote_code_execution:CVE-2024-0004:java"
    );
}

#[test]
fn display_auth_bypass() {
    let issue = cve_correlator::CveIssue::AuthBypass {
        cve_id: "CVE-2024-0005".to_string(),
        technology: "nginx".to_string(),
    };
    assert_eq!(format!("{issue}"), "auth_bypass:CVE-2024-0005:nginx");
}

#[test]
fn display_outdated_technology() {
    let issue = cve_correlator::CveIssue::OutdatedTechnology {
        technology: "nginx".to_string(),
        latest_cve_year: 2025,
    };
    assert_eq!(format!("{issue}"), "outdated_technology:nginx:2025");
}

#[test]
fn display_high_cve_count() {
    let issue = cve_correlator::CveIssue::HighCveCount {
        technology: "php".to_string(),
        count: 12,
    };
    assert_eq!(format!("{issue}"), "high_cve_count:php:12");
}

#[test]
fn display_no_score_available() {
    let issue = cve_correlator::CveIssue::NoScoreAvailable {
        cve_id: "CVE-2024-0006".to_string(),
        technology: "nginx".to_string(),
    };
    assert_eq!(format!("{issue}"), "no_score_available:CVE-2024-0006:nginx");
}

// --- Severity tests ---

#[test]
fn severity_critical_cve_uses_cvss_score() {
    let issue = cve_correlator::CveIssue::CriticalCve {
        cve_id: "CVE-2024-0001".to_string(),
        technology: "nginx".to_string(),
        cvss_score: 9.8,
    };
    assert!((cve_correlator::cve_issue_severity(&issue) - 9.8).abs() < 1e-9);
}

#[test]
fn severity_known_cve_uses_cvss_score() {
    let issue = cve_correlator::CveIssue::KnownCve {
        cve_id: "CVE-2024-0001".to_string(),
        technology: "nginx".to_string(),
        cvss_score: 6.5,
    };
    assert!((cve_correlator::cve_issue_severity(&issue) - 6.5).abs() < 1e-9);
}

#[test]
fn severity_rce_is_9_5() {
    let issue = cve_correlator::CveIssue::RemoteCodeExecution {
        cve_id: "CVE-2024-0001".to_string(),
        technology: "nginx".to_string(),
    };
    assert!((cve_correlator::cve_issue_severity(&issue) - 9.5).abs() < 1e-9);
}

#[test]
fn severity_auth_bypass_is_8_5() {
    let issue = cve_correlator::CveIssue::AuthBypass {
        cve_id: "CVE-2024-0001".to_string(),
        technology: "nginx".to_string(),
    };
    assert!((cve_correlator::cve_issue_severity(&issue) - 8.5).abs() < 1e-9);
}

#[test]
fn severity_exploit_available_is_8() {
    let issue = cve_correlator::CveIssue::ExploitAvailable {
        cve_id: "CVE-2024-0001".to_string(),
        technology: "nginx".to_string(),
    };
    assert!((cve_correlator::cve_issue_severity(&issue) - 8.0).abs() < 1e-9);
}

#[test]
fn severity_high_cve_count_is_7() {
    let issue = cve_correlator::CveIssue::HighCveCount {
        technology: "nginx".to_string(),
        count: 10,
    };
    assert!((cve_correlator::cve_issue_severity(&issue) - 7.0).abs() < 1e-9);
}

#[test]
fn severity_outdated_technology_is_6() {
    let issue = cve_correlator::CveIssue::OutdatedTechnology {
        technology: "nginx".to_string(),
        latest_cve_year: 2025,
    };
    assert!((cve_correlator::cve_issue_severity(&issue) - 6.0).abs() < 1e-9);
}

#[test]
fn severity_no_score_available_is_5() {
    let issue = cve_correlator::CveIssue::NoScoreAvailable {
        cve_id: "CVE-2024-0001".to_string(),
        technology: "nginx".to_string(),
    };
    assert!((cve_correlator::cve_issue_severity(&issue) - 5.0).abs() < 1e-9);
}

#[test]
fn severity_ordering_critical_above_known() {
    let critical = cve_correlator::CveIssue::CriticalCve {
        cve_id: "CVE-2024-0001".to_string(),
        technology: "nginx".to_string(),
        cvss_score: 9.5,
    };
    let known = cve_correlator::CveIssue::KnownCve {
        cve_id: "CVE-2024-0002".to_string(),
        technology: "nginx".to_string(),
        cvss_score: 6.0,
    };
    assert!(
        cve_correlator::cve_issue_severity(&critical) > cve_correlator::cve_issue_severity(&known)
    );
}

#[test]
fn severity_ordering_rce_above_exploit() {
    let rce = cve_correlator::CveIssue::RemoteCodeExecution {
        cve_id: "CVE-2024-0001".to_string(),
        technology: "nginx".to_string(),
    };
    let exploit = cve_correlator::CveIssue::ExploitAvailable {
        cve_id: "CVE-2024-0002".to_string(),
        technology: "nginx".to_string(),
    };
    assert!(
        cve_correlator::cve_issue_severity(&rce) > cve_correlator::cve_issue_severity(&exploit)
    );
}

// --- cve_issues_to_operations tests ---

#[test]
fn issues_to_operations_one_per_issue() {
    let issues = vec![
        cve_correlator::CveIssue::KnownCve {
            cve_id: "CVE-2024-0001".to_string(),
            technology: "nginx".to_string(),
            cvss_score: 7.5,
        },
        cve_correlator::CveIssue::CriticalCve {
            cve_id: "CVE-2024-0002".to_string(),
            technology: "openssl".to_string(),
            cvss_score: 9.8,
        },
        cve_correlator::CveIssue::NoScoreAvailable {
            cve_id: "CVE-2024-0003".to_string(),
            technology: "php".to_string(),
        },
    ];
    let mut seq = 0u64;
    let ops = cve_correlator::cve_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn issues_to_operations_empty() {
    let issues: Vec<cve_correlator::CveIssue> = Vec::new();
    let mut seq = 0u64;
    let ops = cve_correlator::cve_issues_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn issues_to_operations_seq_increments() {
    let issues = vec![
        cve_correlator::CveIssue::KnownCve {
            cve_id: "CVE-2024-0001".to_string(),
            technology: "nginx".to_string(),
            cvss_score: 5.0,
        },
        cve_correlator::CveIssue::RemoteCodeExecution {
            cve_id: "CVE-2024-0002".to_string(),
            technology: "php".to_string(),
        },
    ];
    let mut seq = 10u64;
    let ops = cve_correlator::cve_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
    assert_eq!(seq, 12);
}

#[test]
fn issues_to_operations_uses_known_vuln_dep_class() {
    let issues = vec![cve_correlator::CveIssue::RemoteCodeExecution {
        cve_id: "CVE-2024-0001".to_string(),
        technology: "nginx".to_string(),
    }];
    let mut seq = 0u64;
    let ops = cve_correlator::cve_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::KnownVulnerableDependency
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn issues_to_operations_uses_confidence_0_5() {
    let issues = vec![cve_correlator::CveIssue::KnownCve {
        cve_id: "CVE-2024-0001".to_string(),
        technology: "nginx".to_string(),
        cvss_score: 7.0,
    }];
    let mut seq = 0u64;
    let ops = cve_correlator::cve_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        GraphOperation::AddFinding { confidence, .. } => {
            assert!((confidence.value() - 0.5).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn issues_to_operations_severity_matches_issue() {
    let issues = vec![
        cve_correlator::CveIssue::RemoteCodeExecution {
            cve_id: "CVE-2024-0001".to_string(),
            technology: "nginx".to_string(),
        },
        cve_correlator::CveIssue::NoScoreAvailable {
            cve_id: "CVE-2024-0002".to_string(),
            technology: "php".to_string(),
        },
    ];
    let mut seq = 0u64;
    let ops = cve_correlator::cve_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 9.5).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
    match &ops[1].operation {
        GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 5.0).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn analyze_no_false_auth_bypass() {
    let matches = vec![make_match(
        "CVE-2024-0001",
        "buffer overflow in auth module",
        Some(7.0),
        "nginx",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let auth = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::AuthBypass { .. }))
        .count();
    assert_eq!(auth, 0);
}

#[test]
fn analyze_no_false_rce() {
    let matches = vec![make_match(
        "CVE-2024-0001",
        "denial of service via crafted request",
        Some(7.0),
        "nginx",
    )];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let rce = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::RemoteCodeExecution { .. }))
        .count();
    assert_eq!(rce, 0);
}

#[test]
fn analyze_outdated_technology_captures_latest_year() {
    let current_year = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (1970 + secs / 31_557_600) as u16
    };
    let matches = vec![
        make_match("CVE-2015-0001", "old vuln", Some(5.0), "nginx"),
        make_match(
            &format!("CVE-{current_year}-0002"),
            "new vuln",
            Some(6.0),
            "nginx",
        ),
    ];
    let issues = cve_correlator::analyze_cve_matches(&matches);
    let outdated: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, cve_correlator::CveIssue::OutdatedTechnology { .. }))
        .collect();
    assert_eq!(outdated.len(), 1);
    if let cve_correlator::CveIssue::OutdatedTechnology {
        latest_cve_year, ..
    } = outdated[0]
    {
        assert_eq!(*latest_cve_year, current_year);
    }
}
