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
