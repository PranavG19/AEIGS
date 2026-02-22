use super::*;

fn make_osv_vuln(
    id: &str,
    aliases: Vec<&str>,
    summary: &str,
    severity_score: Option<&str>,
    affected: Vec<OsvAffected>,
) -> OsvVulnerability {
    OsvVulnerability {
        id: id.to_string(),
        aliases: if aliases.is_empty() {
            None
        } else {
            Some(aliases.into_iter().map(String::from).collect())
        },
        summary: Some(summary.to_string()),
        severity: severity_score.map(|s| {
            vec![OsvSeverity {
                severity_type: "CVSS_V3".to_string(),
                score: s.to_string(),
            }]
        }),
        affected: Some(affected),
    }
}

fn make_affected(package: &str, ecosystem: &str, events: Vec<OsvEvent>) -> OsvAffected {
    OsvAffected {
        package: Some(OsvPackage {
            name: package.to_string(),
            ecosystem: ecosystem.to_string(),
        }),
        ranges: Some(vec![OsvRange {
            range_type: "SEMVER".to_string(),
            events,
        }]),
    }
}

fn event_introduced(v: &str) -> OsvEvent {
    OsvEvent {
        introduced: Some(v.to_string()),
        fixed: None,
        last_affected: None,
    }
}

fn event_fixed(v: &str) -> OsvEvent {
    OsvEvent {
        introduced: None,
        fixed: Some(v.to_string()),
        last_affected: None,
    }
}

fn event_last_affected(v: &str) -> OsvEvent {
    OsvEvent {
        introduced: None,
        fixed: None,
        last_affected: Some(v.to_string()),
    }
}

#[test]
fn parse_args_with_all_flags() {
    let args: Vec<String> = vec![
        "--source-dir",
        "/tmp/project",
        "--db-path",
        "/tmp/vuln.db",
        "--full-refresh",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    let parsed = parse_update_db_args(&args).unwrap();
    assert_eq!(parsed.source_dir, PathBuf::from("/tmp/project"));
    assert_eq!(parsed.db_path, PathBuf::from("/tmp/vuln.db"));
    assert!(parsed.full_refresh);
}

#[test]
fn parse_args_defaults_db_path() {
    let args: Vec<String> = vec!["--source-dir", "/tmp/project"]
        .into_iter()
        .map(String::from)
        .collect();
    let parsed = parse_update_db_args(&args).unwrap();
    assert!(parsed.db_path.ends_with("vuln.db"));
    assert!(!parsed.full_refresh);
}

#[test]
fn parse_args_missing_source_dir_errors() {
    let args: Vec<String> = vec!["--db-path", "/tmp/vuln.db"]
        .into_iter()
        .map(String::from)
        .collect();
    let result = parse_update_db_args(&args);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("source-dir"));
}

#[test]
fn convert_osv_single_range() {
    let vuln = make_osv_vuln(
        "GHSA-1234",
        vec!["CVE-2024-0001"],
        "test vuln",
        Some("7.5"),
        vec![make_affected(
            "tokio",
            "crates.io",
            vec![event_introduced("1.0.0"), event_fixed("1.5.0")],
        )],
    );
    let records = convert_osv_to_records(&vuln, "cargo");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].cve_id, "CVE-2024-0001");
    assert_eq!(records[0].package_name, "tokio");
    assert_eq!(records[0].ecosystem, "cargo");
    assert_eq!(records[0].vulnerable_version_start, "1.0.0");
    assert_eq!(records[0].vulnerable_version_end, "1.5.0");
    assert!((records[0].severity - 7.5).abs() < 1e-9);
}

#[test]
fn convert_osv_multi_range_produces_multiple_records() {
    let vuln = make_osv_vuln(
        "GHSA-5678",
        vec!["CVE-2024-0002"],
        "multi-range",
        None,
        vec![make_affected(
            "tokio",
            "crates.io",
            vec![
                event_introduced("1.7.0"),
                event_fixed("1.18.4"),
                event_introduced("1.19.0"),
                event_fixed("1.20.3"),
            ],
        )],
    );
    let records = convert_osv_to_records(&vuln, "cargo");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].vulnerable_version_start, "1.7.0");
    assert_eq!(records[0].vulnerable_version_end, "1.18.4");
    assert_eq!(records[1].vulnerable_version_start, "1.19.0");
    assert_eq!(records[1].vulnerable_version_end, "1.20.3");
}

#[test]
fn convert_osv_no_fixed_uses_sentinel() {
    let vuln = make_osv_vuln(
        "GHSA-9999",
        vec![],
        "unfixed",
        None,
        vec![make_affected(
            "serde",
            "crates.io",
            vec![event_introduced("1.0.0")],
        )],
    );
    let records = convert_osv_to_records(&vuln, "cargo");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].vulnerable_version_start, "1.0.0");
    assert_eq!(records[0].vulnerable_version_end, SENTINEL_VERSION);
}

#[test]
fn convert_osv_last_affected_used_as_end() {
    let vuln = make_osv_vuln(
        "GHSA-AAAA",
        vec!["CVE-2024-0003"],
        "last-affected",
        None,
        vec![make_affected(
            "express",
            "npm",
            vec![event_introduced("4.0.0"), event_last_affected("4.17.21")],
        )],
    );
    let records = convert_osv_to_records(&vuln, "npm");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].vulnerable_version_end, "4.17.21");
}

#[test]
fn extract_cve_id_prefers_cve_alias() {
    let vuln = make_osv_vuln(
        "GHSA-1234",
        vec!["GHSA-1234", "CVE-2024-9999"],
        "",
        None,
        vec![],
    );
    assert_eq!(extract_cve_id(&vuln), "CVE-2024-9999");
}

#[test]
fn extract_cve_id_falls_back_to_osv_id() {
    let vuln = make_osv_vuln("GHSA-5678", vec![], "", None, vec![]);
    assert_eq!(extract_cve_id(&vuln), "GHSA-5678");
}

#[test]
fn extract_severity_defaults_to_5() {
    assert!((extract_severity(&None) - DEFAULT_SEVERITY).abs() < 1e-9);
    assert!((extract_severity(&Some(vec![])) - DEFAULT_SEVERITY).abs() < 1e-9);
}

#[test]
fn extract_severity_parses_numeric_score() {
    let entries = Some(vec![OsvSeverity {
        severity_type: "CVSS_V3".to_string(),
        score: "9.8".to_string(),
    }]);
    assert!((extract_severity(&entries) - 9.8).abs() < 1e-9);
}

#[test]
fn extract_version_ranges_pairs_introduced_fixed() {
    let events = vec![
        event_introduced("1.0.0"),
        event_fixed("1.5.0"),
        event_introduced("2.0.0"),
        event_fixed("2.3.0"),
    ];
    let ranges = extract_version_ranges(&events);
    assert_eq!(ranges.len(), 2);
    assert_eq!(ranges[0], ("1.0.0".to_string(), "1.5.0".to_string()));
    assert_eq!(ranges[1], ("2.0.0".to_string(), "2.3.0".to_string()));
}

#[test]
fn default_db_path_is_under_home() {
    let path = default_db_path();
    assert!(path.to_string_lossy().contains(".aegis"));
    assert!(path.to_string_lossy().ends_with("vuln.db"));
}

#[test]
fn update_db_error_display() {
    let err = UpdateDbError::MissingArg("target".to_string());
    assert!(err.to_string().contains("target"));
    let err = UpdateDbError::NoPackagesFound;
    assert!(err.to_string().contains("no packages found"));
}

#[test]
fn convert_osv_no_affected_returns_empty() {
    let vuln = OsvVulnerability {
        id: "GHSA-0000".to_string(),
        aliases: None,
        summary: None,
        severity: None,
        affected: None,
    };
    assert!(convert_osv_to_records(&vuln, "cargo").is_empty());
}

#[test]
fn convert_osv_empty_package_name_skipped() {
    let vuln = make_osv_vuln(
        "GHSA-BBBB",
        vec![],
        "",
        None,
        vec![OsvAffected {
            package: Some(OsvPackage {
                name: String::new(),
                ecosystem: "crates.io".to_string(),
            }),
            ranges: Some(vec![OsvRange {
                range_type: "SEMVER".to_string(),
                events: vec![event_introduced("1.0.0"), event_fixed("2.0.0")],
            }]),
        }],
    );
    assert!(convert_osv_to_records(&vuln, "cargo").is_empty());
}
