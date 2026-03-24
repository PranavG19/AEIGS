use std::collections::HashMap;

use super::threat_intel_feed::*;

fn sample_nvd_json() -> &'static str {
    r#"{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2023-44487",
        "descriptions": [
          {"lang": "en", "value": "HTTP/2 Rapid Reset Attack allows denial of service"}
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "cvssData": {
                "baseScore": 7.5,
                "baseSeverity": "HIGH"
              }
            }
          ]
        },
        "configurations": [
          {
            "nodes": [
              {
                "cpeMatch": [
                  {
                    "vulnerable": true,
                    "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "1.0.0",
                    "versionEndExcluding": "1.25.3"
                  }
                ]
              }
            ]
          }
        ]
      }
    },
    {
      "cve": {
        "id": "CVE-2024-1234",
        "descriptions": [
          {"lang": "en", "value": "Buffer overflow in example_lib"}
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "cvssData": {
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL"
              }
            }
          ]
        },
        "configurations": [
          {
            "nodes": [
              {
                "cpeMatch": [
                  {
                    "vulnerable": true,
                    "criteria": "cpe:2.3:a:example:example_lib:*:*:*:*:*:*:*:*",
                    "versionEndIncluding": "2.0.0"
                  },
                  {
                    "vulnerable": false,
                    "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
                  }
                ]
              }
            ]
          }
        ]
      }
    }
  ]
}"#
}

fn sample_exploitdb_csv() -> &'static str {
    "id,description,platform,type,cve_list,verified\n\
     51234,Nginx Rapid Reset DoS,linux,dos,CVE-2023-44487,true\n\
     51235,Example Lib BOF,multiple,remote,CVE-2024-1234;CVE-2024-0001,false\n\
     51236,Standalone Exploit,windows,local,,true\n"
}

fn sample_cisa_kev_json() -> &'static str {
    r#"{
  "vulnerabilities": [
    {
      "cveID": "CVE-2023-44487",
      "vendorProject": "IETF",
      "product": "nginx",
      "vulnerabilityName": "HTTP/2 Rapid Reset Attack",
      "dateAdded": "2023-10-10",
      "dueDate": "2023-10-31",
      "requiredAction": "Apply mitigations per vendor instructions"
    },
    {
      "cveID": "CVE-2021-44228",
      "vendorProject": "Apache",
      "product": "log4j",
      "vulnerabilityName": "Apache Log4j Remote Code Execution",
      "dateAdded": "2021-12-10",
      "dueDate": "2021-12-24",
      "requiredAction": "Apply updates per vendor instructions"
    }
  ]
}"#
}

// ──────────────────────────────────────────────────────
//  SemVer parsing
// ──────────────────────────────────────────────────────

#[test]
fn semver_parse_full() {
    let v = SemVer::parse("1.25.3").unwrap();
    assert_eq!(
        v,
        SemVer {
            major: 1,
            minor: 25,
            patch: 3
        }
    );
}

#[test]
fn semver_parse_two_parts() {
    let v = SemVer::parse("2.0").unwrap();
    assert_eq!(
        v,
        SemVer {
            major: 2,
            minor: 0,
            patch: 0
        }
    );
}

#[test]
fn semver_parse_single_part() {
    let v = SemVer::parse("5").unwrap();
    assert_eq!(
        v,
        SemVer {
            major: 5,
            minor: 0,
            patch: 0
        }
    );
}

#[test]
fn semver_parse_v_prefix() {
    let v = SemVer::parse("v1.2.3").unwrap();
    assert_eq!(
        v,
        SemVer {
            major: 1,
            minor: 2,
            patch: 3
        }
    );
}

#[test]
fn semver_parse_prerelease_suffix() {
    let v = SemVer::parse("1.2.3-rc1").unwrap();
    assert_eq!(
        v,
        SemVer {
            major: 1,
            minor: 2,
            patch: 3
        }
    );
}

#[test]
fn semver_parse_invalid_returns_none() {
    assert!(SemVer::parse("").is_none());
    assert!(SemVer::parse("abc").is_none());
    assert!(SemVer::parse("1.2.3.4").is_none());
}

#[test]
fn semver_ordering() {
    let v1 = SemVer::parse("1.2.3").unwrap();
    let v2 = SemVer::parse("1.2.4").unwrap();
    let v3 = SemVer::parse("1.3.0").unwrap();
    let v4 = SemVer::parse("2.0.0").unwrap();
    assert!(v1 < v2);
    assert!(v2 < v3);
    assert!(v3 < v4);
    assert_eq!(v1, SemVer::parse("1.2.3").unwrap());
}

// ──────────────────────────────────────────────────────
//  NVD JSON parsing
// ──────────────────────────────────────────────────────

#[test]
fn nvd_ingest_parses_two_cves() {
    let mut feed = ThreatIntelFeed::new();
    let count = feed.ingest_nvd_json(sample_nvd_json()).unwrap();
    // 1 CPE from first CVE + 1 vulnerable CPE from second CVE (the non-vulnerable one is skipped)
    assert_eq!(count, 2);
    assert_eq!(feed.cve_records().len(), 2);
}

#[test]
fn nvd_ingest_extracts_correct_fields() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_nvd_json(sample_nvd_json()).unwrap();
    let cve = &feed.cve_records()[0];
    assert_eq!(cve.cve_id, "CVE-2023-44487");
    assert_eq!(cve.affected_product, "nginx");
    assert_eq!(cve.affected_vendor, "nginx");
    assert_eq!(cve.severity, CveSeverity::High);
    assert!((cve.cvss_score - 7.5).abs() < f64::EPSILON);
    assert_eq!(
        cve.version_start,
        Some(SemVer {
            major: 1,
            minor: 0,
            patch: 0
        })
    );
    assert_eq!(
        cve.version_end_excluding,
        Some(SemVer {
            major: 1,
            minor: 25,
            patch: 3
        })
    );
}

#[test]
fn nvd_ingest_skips_non_vulnerable_cpe() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_nvd_json(sample_nvd_json()).unwrap();
    // The linux_kernel CPE with vulnerable=false should not produce a record
    let linux_cves: Vec<_> = feed
        .cve_records()
        .iter()
        .filter(|c| c.affected_product == "linux_kernel")
        .collect();
    assert!(linux_cves.is_empty());
}

#[test]
fn nvd_ingest_invalid_json_returns_error() {
    let mut feed = ThreatIntelFeed::new();
    let result = feed.ingest_nvd_json("not json at all");
    assert!(result.is_err());
}

// ──────────────────────────────────────────────────────
//  Exploit-DB CSV parsing
// ──────────────────────────────────────────────────────

#[test]
fn exploitdb_ingest_parses_three_entries() {
    let mut feed = ThreatIntelFeed::new();
    let count = feed.ingest_exploitdb_csv(sample_exploitdb_csv()).unwrap();
    assert_eq!(count, 3);
    assert_eq!(feed.exploit_records().len(), 3);
}

#[test]
fn exploitdb_ingest_extracts_fields() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_exploitdb_csv(sample_exploitdb_csv()).unwrap();
    let e = &feed.exploit_records()[0];
    assert_eq!(e.edb_id, "51234");
    assert_eq!(e.platform, "linux");
    assert!(e.verified);
    assert_eq!(e.associated_cves, vec!["CVE-2023-44487"]);
}

#[test]
fn exploitdb_multiple_cves_split_correctly() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_exploitdb_csv(sample_exploitdb_csv()).unwrap();
    let e = &feed.exploit_records()[1];
    assert_eq!(e.associated_cves, vec!["CVE-2024-1234", "CVE-2024-0001"]);
    assert!(!e.verified);
}

#[test]
fn exploitdb_empty_cve_list_yields_empty_vec() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_exploitdb_csv(sample_exploitdb_csv()).unwrap();
    let e = &feed.exploit_records()[2];
    assert!(e.associated_cves.is_empty());
}

#[test]
fn exploitdb_malformed_csv_returns_error() {
    let mut feed = ThreatIntelFeed::new();
    let result = feed.ingest_exploitdb_csv("id,desc,platform,type,cves,verified\n1,test");
    assert!(result.is_err());
}

// ──────────────────────────────────────────────────────
//  CISA KEV parsing
// ──────────────────────────────────────────────────────

#[test]
fn cisa_kev_ingest_parses_entries() {
    let mut feed = ThreatIntelFeed::new();
    let count = feed.ingest_cisa_kev_json(sample_cisa_kev_json()).unwrap();
    assert_eq!(count, 2);
}

#[test]
fn cisa_kev_extracts_fields() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_cisa_kev_json(sample_cisa_kev_json()).unwrap();
    let entry = &feed.kev_entries()[0];
    assert_eq!(entry.cve_id, "CVE-2023-44487");
    assert_eq!(entry.vendor, "IETF");
    assert_eq!(entry.product, "nginx");
    assert_eq!(entry.date_added, "2023-10-10");
}

#[test]
fn cisa_kev_date_filter_after() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_cisa_kev_json(sample_cisa_kev_json()).unwrap();
    let recent = feed.kev_entries_after("2023-01-01");
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].cve_id, "CVE-2023-44487");
}

#[test]
fn cisa_kev_date_filter_none() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_cisa_kev_json(sample_cisa_kev_json()).unwrap();
    let future = feed.kev_entries_after("2025-01-01");
    assert!(future.is_empty());
}

#[test]
fn cisa_kev_invalid_json_returns_error() {
    let mut feed = ThreatIntelFeed::new();
    let result = feed.ingest_cisa_kev_json("{invalid}");
    assert!(result.is_err());
}

// ──────────────────────────────────────────────────────
//  Version-aware CVE matching
// ──────────────────────────────────────────────────────

#[test]
fn version_match_within_range() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_nvd_json(sample_nvd_json()).unwrap();
    let mut stack = HashMap::new();
    stack.insert("nginx".to_string(), "1.24.0".to_string());
    let matches = feed.correlate(&stack);
    let nvd_matches: Vec<_> = matches
        .iter()
        .filter(|m| m.source == ThreatIntelSource::Nvd)
        .collect();
    assert_eq!(nvd_matches.len(), 1);
    assert_eq!(nvd_matches[0].reference_id, "CVE-2023-44487");
}

#[test]
fn version_match_at_boundary_excluded() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_nvd_json(sample_nvd_json()).unwrap();
    let mut stack = HashMap::new();
    // 1.25.3 is the versionEndExcluding — should NOT match
    stack.insert("nginx".to_string(), "1.25.3".to_string());
    let matches = feed.correlate(&stack);
    let nvd_matches: Vec<_> = matches
        .iter()
        .filter(|m| m.source == ThreatIntelSource::Nvd)
        .collect();
    assert!(nvd_matches.is_empty());
}

#[test]
fn version_below_start_not_matched() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_nvd_json(sample_nvd_json()).unwrap();
    let mut stack = HashMap::new();
    stack.insert("nginx".to_string(), "0.9.9".to_string());
    let matches = feed.correlate(&stack);
    let nvd_matches: Vec<_> = matches
        .iter()
        .filter(|m| m.source == ThreatIntelSource::Nvd)
        .collect();
    assert!(nvd_matches.is_empty());
}

#[test]
fn version_end_including_boundary_matches() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_nvd_json(sample_nvd_json()).unwrap();
    let mut stack = HashMap::new();
    // CVE-2024-1234 has versionEndIncluding=2.0.0
    stack.insert("example_lib".to_string(), "2.0.0".to_string());
    let matches = feed.correlate(&stack);
    let cve_match: Vec<_> = matches
        .iter()
        .filter(|m| m.reference_id == "CVE-2024-1234")
        .collect();
    assert_eq!(cve_match.len(), 1);
}

#[test]
fn version_above_end_including_not_matched() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_nvd_json(sample_nvd_json()).unwrap();
    let mut stack = HashMap::new();
    stack.insert("example_lib".to_string(), "2.0.1".to_string());
    let matches = feed.correlate(&stack);
    let cve_match: Vec<_> = matches
        .iter()
        .filter(|m| m.reference_id == "CVE-2024-1234")
        .collect();
    assert!(cve_match.is_empty());
}

#[test]
fn unrecognized_product_yields_no_matches() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_nvd_json(sample_nvd_json()).unwrap();
    let mut stack = HashMap::new();
    stack.insert("unknown_product".to_string(), "1.0.0".to_string());
    let matches = feed.correlate(&stack);
    assert!(matches.is_empty());
}

// ──────────────────────────────────────────────────────
//  Cross-feed correlation
// ──────────────────────────────────────────────────────

#[test]
fn exploitdb_cross_references_matched_cves() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_nvd_json(sample_nvd_json()).unwrap();
    feed.ingest_exploitdb_csv(sample_exploitdb_csv()).unwrap();
    let mut stack = HashMap::new();
    stack.insert("nginx".to_string(), "1.24.0".to_string());
    let matches = feed.correlate(&stack);
    let edb_matches: Vec<_> = matches
        .iter()
        .filter(|m| m.source == ThreatIntelSource::ExploitDb)
        .collect();
    assert_eq!(edb_matches.len(), 1);
    assert_eq!(edb_matches[0].reference_id, "51234");
}

#[test]
fn cisa_kev_correlates_with_tech_stack() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_cisa_kev_json(sample_cisa_kev_json()).unwrap();
    let mut stack = HashMap::new();
    stack.insert("nginx".to_string(), "1.24.0".to_string());
    let matches = feed.correlate(&stack);
    let kev_matches: Vec<_> = matches
        .iter()
        .filter(|m| m.source == ThreatIntelSource::CisaKev)
        .collect();
    assert_eq!(kev_matches.len(), 1);
    assert_eq!(kev_matches[0].severity, CveSeverity::Critical);
}

// ──────────────────────────────────────────────────────
//  Nuclei template matching
// ──────────────────────────────────────────────────────

#[test]
fn nuclei_template_matches_product() {
    let mut feed = ThreatIntelFeed::new();
    feed.add_nuclei_templates(vec![NucleiTemplateMatch {
        template_id: "nginx-misconfig-01".to_string(),
        template_name: "Nginx Misconfiguration Alias Traversal".to_string(),
        severity: CveSeverity::Medium,
        matched_product: "nginx".to_string(),
    }]);
    let mut stack = HashMap::new();
    stack.insert("nginx".to_string(), "1.24.0".to_string());
    let matches = feed.correlate(&stack);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].source, ThreatIntelSource::NucleiTemplate);
}

// ──────────────────────────────────────────────────────
//  C2 indicator checks
// ──────────────────────────────────────────────────────

#[test]
fn c2_indicator_ip_match() {
    let mut feed = ThreatIntelFeed::new();
    feed.add_c2_indicators(vec![MalwareC2Indicator {
        indicator: "192.168.1.100".to_string(),
        indicator_type: IndicatorType::IpAddress,
        malware_family: "Cobalt Strike".to_string(),
        confidence: 0.95,
        last_seen: "2024-01-15".to_string(),
    }]);
    let hits = feed.check_c2_indicators(&["192.168.1.100", "10.0.0.1"]);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].malware_family, "Cobalt Strike");
}

#[test]
fn c2_indicator_no_match() {
    let mut feed = ThreatIntelFeed::new();
    feed.add_c2_indicators(vec![MalwareC2Indicator {
        indicator: "evil.example.com".to_string(),
        indicator_type: IndicatorType::Domain,
        malware_family: "Emotet".to_string(),
        confidence: 0.87,
        last_seen: "2024-02-20".to_string(),
    }]);
    let hits = feed.check_c2_indicators(&["safe.example.com"]);
    assert!(hits.is_empty());
}

// ──────────────────────────────────────────────────────
//  Abuse IP checks
// ──────────────────────────────────────────────────────

#[test]
fn abuse_ip_match() {
    let mut feed = ThreatIntelFeed::new();
    feed.add_abuse_ips(vec![AbuseIpEntry {
        ip_address: "45.33.32.156".to_string(),
        abuse_confidence_score: 92,
        country_code: "US".to_string(),
        total_reports: 340,
        last_reported: "2024-03-01".to_string(),
    }]);
    let hits = feed.check_abuse_ips(&["45.33.32.156"]);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].abuse_confidence_score, 92);
}

#[test]
fn abuse_ip_no_match() {
    let mut feed = ThreatIntelFeed::new();
    feed.add_abuse_ips(vec![AbuseIpEntry {
        ip_address: "1.2.3.4".to_string(),
        abuse_confidence_score: 50,
        country_code: "CN".to_string(),
        total_reports: 10,
        last_reported: "2024-01-01".to_string(),
    }]);
    let hits = feed.check_abuse_ips(&["5.6.7.8"]);
    assert!(hits.is_empty());
}

// ──────────────────────────────────────────────────────
//  Emerging threats
// ──────────────────────────────────────────────────────

#[test]
fn emerging_threat_correlates() {
    let mut feed = ThreatIntelFeed::new();
    feed.add_emerging_threats(vec![EmergingThreat {
        cve_id: "CVE-2024-9999".to_string(),
        epss_score: 0.92,
        published_date: "2024-03-15".to_string(),
        affected_product: "nginx".to_string(),
        severity: CveSeverity::Critical,
    }]);
    let mut stack = HashMap::new();
    stack.insert("nginx".to_string(), "1.24.0".to_string());
    let matches = feed.correlate(&stack);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].source, ThreatIntelSource::EmergingThreat);
    assert!(matches[0].description.contains("0.9200"));
}

// ──────────────────────────────────────────────────────
//  Aggregate / utility
// ──────────────────────────────────────────────────────

#[test]
fn total_indicators_counts_all_feeds() {
    let mut feed = ThreatIntelFeed::new();
    feed.ingest_nvd_json(sample_nvd_json()).unwrap();
    feed.ingest_exploitdb_csv(sample_exploitdb_csv()).unwrap();
    feed.ingest_cisa_kev_json(sample_cisa_kev_json()).unwrap();
    feed.add_c2_indicators(vec![MalwareC2Indicator {
        indicator: "x".to_string(),
        indicator_type: IndicatorType::Domain,
        malware_family: "test".to_string(),
        confidence: 0.5,
        last_seen: "2024-01-01".to_string(),
    }]);
    // 2 CVE + 3 exploit + 2 KEV + 1 C2 = 8
    assert_eq!(feed.total_indicators(), 8);
}

#[test]
fn default_feed_is_empty() {
    let feed = ThreatIntelFeed::default();
    assert_eq!(feed.total_indicators(), 0);
    assert!(feed.cve_records().is_empty());
    assert!(feed.exploit_records().is_empty());
    assert!(feed.kev_entries().is_empty());
}

#[test]
fn display_impls_produce_readable_text() {
    assert_eq!(format!("{}", CveSeverity::Critical), "CRITICAL");
    assert_eq!(format!("{}", ThreatIntelSource::Nvd), "NVD");
    assert_eq!(format!("{}", ThreatIntelSource::CisaKev), "CISA KEV");

    let err = ThreatIntelError::ParseError {
        source: "test".to_string(),
        detail: "bad data".to_string(),
    };
    assert!(format!("{err}").contains("bad data"));
}

#[test]
fn csv_parser_handles_quoted_fields() {
    let line = r#"1,"description with, comma",linux,remote,CVE-1234,true"#;
    let mut feed = ThreatIntelFeed::new();
    let csv = format!("id,desc,platform,type,cves,verified\n{line}\n");
    let count = feed.ingest_exploitdb_csv(&csv).unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        feed.exploit_records()[0].description,
        "description with, comma"
    );
}
