use super::*;

use aegis_protocol::finding::{EvidenceLevel, VulnerabilityClass};

fn sqli_finding(endpoint: &str, param: &str, confidence: f64) -> ScanFinding {
    make_scan_finding(
        endpoint,
        param,
        VulnerabilityClass::SqlInjection,
        confidence,
        EvidenceLevel::Confirmed,
    )
}

fn xss_finding(endpoint: &str, param: &str, confidence: f64) -> ScanFinding {
    make_scan_finding(
        endpoint,
        param,
        VulnerabilityClass::CrossSiteScripting,
        confidence,
        EvidenceLevel::Controlled,
    )
}

fn path_traversal_finding(endpoint: &str, param: &str, confidence: f64) -> ScanFinding {
    make_scan_finding(
        endpoint,
        param,
        VulnerabilityClass::PathTraversal,
        confidence,
        EvidenceLevel::Statistical,
    )
}

fn sample_baseline() -> RegressionBaseline {
    let findings = vec![
        sqli_finding("/api/search", "q", 0.9),
        xss_finding("/api/comments", "body", 0.8),
        path_traversal_finding("/api/files", "path", 0.7),
    ];
    RegressionBaseline::from_findings("test-fixture", &findings, "0.1.0")
}

// --- Baseline creation tests ---

#[test]
fn baseline_from_findings_preserves_count() {
    let baseline = sample_baseline();
    assert_eq!(baseline.findings.len(), 3);
}

#[test]
fn baseline_from_findings_records_fixture_name() {
    let baseline = sample_baseline();
    assert_eq!(baseline.fixture_name, "test-fixture");
}

#[test]
fn baseline_from_findings_records_version() {
    let baseline = sample_baseline();
    assert_eq!(baseline.aegis_version, "0.1.0");
}

#[test]
fn baseline_from_findings_sets_timestamp() {
    let baseline = sample_baseline();
    assert!(baseline.created_at_unix_ms > 0);
}

#[test]
fn baseline_finding_has_correct_vulnerability_class() {
    let baseline = sample_baseline();
    let classes: Vec<VulnerabilityClass> = baseline
        .findings
        .iter()
        .map(|f| f.vulnerability_class)
        .collect();
    assert!(classes.contains(&VulnerabilityClass::SqlInjection));
    assert!(classes.contains(&VulnerabilityClass::CrossSiteScripting));
    assert!(classes.contains(&VulnerabilityClass::PathTraversal));
}

#[test]
fn baseline_finding_stores_endpoint_and_parameter() {
    let baseline = sample_baseline();
    let sqli = baseline
        .findings
        .iter()
        .find(|f| f.vulnerability_class == VulnerabilityClass::SqlInjection)
        .unwrap();
    assert_eq!(sqli.endpoint, "/api/search");
    assert_eq!(sqli.parameter, "q");
}

#[test]
fn baseline_finding_stores_confidence() {
    let baseline = sample_baseline();
    let sqli = baseline
        .findings
        .iter()
        .find(|f| f.vulnerability_class == VulnerabilityClass::SqlInjection)
        .unwrap();
    assert!((sqli.confidence - 0.9).abs() < 1e-6);
}

// --- Save/load round-trip tests ---

#[test]
fn baseline_save_and_load_roundtrip() {
    let baseline = sample_baseline();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("baseline.json");

    baseline.save(&path).unwrap();
    let loaded = RegressionBaseline::load(&path).unwrap();

    assert_eq!(loaded.fixture_name, baseline.fixture_name);
    assert_eq!(loaded.aegis_version, baseline.aegis_version);
    assert_eq!(loaded.findings.len(), baseline.findings.len());
    assert_eq!(loaded.created_at_unix_ms, baseline.created_at_unix_ms);
}

#[test]
fn baseline_save_creates_parent_dirs() {
    let baseline = sample_baseline();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("deep").join("baseline.json");

    baseline.save(&path).unwrap();
    assert!(path.exists());
}

#[test]
fn baseline_load_nonexistent_returns_error() {
    let result = RegressionBaseline::load(Path::new("/nonexistent/baseline.json"));
    assert!(result.is_err());
}

#[test]
fn baseline_load_invalid_json_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.json");
    std::fs::write(&path, "not json at all").unwrap();

    let result = RegressionBaseline::load(&path);
    assert!(result.is_err());
}

// --- Regression comparison tests ---

#[test]
fn identical_scan_produces_no_regressions() {
    let baseline = sample_baseline();
    let current = vec![
        sqli_finding("/api/search", "q", 0.9),
        xss_finding("/api/comments", "body", 0.8),
        path_traversal_finding("/api/files", "path", 0.7),
    ];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);

    assert!(!report.has_regressions());
    assert!(!report.has_new_findings());
    assert!(!report.has_drift());
    assert_eq!(report.unchanged, 3);
}

#[test]
fn missing_finding_is_a_regression() {
    let baseline = sample_baseline();
    let current = vec![
        sqli_finding("/api/search", "q", 0.9),
        xss_finding("/api/comments", "body", 0.8),
    ];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);

    assert!(report.has_regressions());
    assert_eq!(report.missing.len(), 1);
    assert_eq!(
        report.missing[0].vulnerability_class,
        VulnerabilityClass::PathTraversal
    );
}

#[test]
fn all_findings_missing_produces_full_regression() {
    let baseline = sample_baseline();
    let current: Vec<ScanFinding> = vec![];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);

    assert!(report.has_regressions());
    assert_eq!(report.missing.len(), 3);
    assert_eq!(report.unchanged, 0);
}

#[test]
fn new_finding_flagged_correctly() {
    let baseline = sample_baseline();
    let current = vec![
        sqli_finding("/api/search", "q", 0.9),
        xss_finding("/api/comments", "body", 0.8),
        path_traversal_finding("/api/files", "path", 0.7),
        make_scan_finding(
            "/api/admin",
            "cmd",
            VulnerabilityClass::CommandInjection,
            0.85,
            EvidenceLevel::Confirmed,
        ),
    ];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);

    assert!(!report.has_regressions());
    assert!(report.has_new_findings());
    assert_eq!(report.new.len(), 1);
    assert_eq!(
        report.new[0].vulnerability_class,
        VulnerabilityClass::CommandInjection
    );
}

#[test]
fn confidence_drift_detected_above_threshold() {
    let baseline = sample_baseline();
    let current = vec![
        sqli_finding("/api/search", "q", 0.9),
        xss_finding("/api/comments", "body", 0.5),
        path_traversal_finding("/api/files", "path", 0.7),
    ];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);

    assert!(report.has_drift());
    assert_eq!(report.drifted.len(), 1);
    assert_eq!(
        report.drifted[0].vulnerability_class,
        VulnerabilityClass::CrossSiteScripting
    );
    assert!((report.drifted[0].delta - (-0.3)).abs() < 1e-6);
}

#[test]
fn confidence_drift_within_threshold_counts_as_unchanged() {
    let baseline = sample_baseline();
    let current = vec![
        sqli_finding("/api/search", "q", 0.89),
        xss_finding("/api/comments", "body", 0.79),
        path_traversal_finding("/api/files", "path", 0.71),
    ];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);

    assert!(!report.has_drift());
    assert_eq!(report.unchanged, 3);
}

#[test]
fn custom_drift_threshold_is_respected() {
    let baseline = sample_baseline();
    let current = vec![
        sqli_finding("/api/search", "q", 0.86),
        xss_finding("/api/comments", "body", 0.8),
        path_traversal_finding("/api/files", "path", 0.7),
    ];

    let runner = RegressionRunner::new(DriftThreshold { absolute: 0.03 });
    let report = runner.compare(&baseline, &current);

    assert!(report.has_drift());
    assert_eq!(report.drifted.len(), 1);
}

#[test]
fn positive_confidence_drift_detected() {
    let baseline = sample_baseline();
    let current = vec![
        sqli_finding("/api/search", "q", 0.9),
        xss_finding("/api/comments", "body", 0.95),
        path_traversal_finding("/api/files", "path", 0.7),
    ];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);

    assert!(report.has_drift());
    assert_eq!(report.drifted.len(), 1);
    assert!(report.drifted[0].delta > 0.0);
}

#[test]
fn report_counts_are_correct() {
    let baseline = sample_baseline();
    let current = vec![
        sqli_finding("/api/search", "q", 0.9),
        make_scan_finding(
            "/api/admin",
            "cmd",
            VulnerabilityClass::CommandInjection,
            0.85,
            EvidenceLevel::Confirmed,
        ),
    ];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);

    assert_eq!(report.baseline_count, 3);
    assert_eq!(report.current_count, 2);
    assert_eq!(report.missing.len(), 2);
    assert_eq!(report.new.len(), 1);
    assert_eq!(report.unchanged, 1);
}

// --- Report formatting tests ---

#[test]
fn format_report_includes_fixture_name() {
    let baseline = sample_baseline();
    let current = vec![
        sqli_finding("/api/search", "q", 0.9),
        xss_finding("/api/comments", "body", 0.8),
        path_traversal_finding("/api/files", "path", 0.7),
    ];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);
    let formatted = report.format();

    assert!(formatted.contains("test-fixture"));
}

#[test]
fn format_report_shows_regressions() {
    let baseline = sample_baseline();
    let current = vec![sqli_finding("/api/search", "q", 0.9)];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);
    let formatted = report.format();

    assert!(formatted.contains("REGRESSIONS"));
    assert!(formatted.contains("Cross-Site Scripting"));
    assert!(formatted.contains("Path Traversal"));
}

#[test]
fn format_report_shows_new_findings() {
    let baseline = sample_baseline();
    let mut current = vec![
        sqli_finding("/api/search", "q", 0.9),
        xss_finding("/api/comments", "body", 0.8),
        path_traversal_finding("/api/files", "path", 0.7),
    ];
    current.push(make_scan_finding(
        "/api/admin",
        "cmd",
        VulnerabilityClass::CommandInjection,
        0.85,
        EvidenceLevel::Confirmed,
    ));

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);
    let formatted = report.format();

    assert!(formatted.contains("NEW findings"));
    assert!(formatted.contains("Command Injection"));
}

#[test]
fn format_report_shows_drift() {
    let baseline = sample_baseline();
    let current = vec![
        sqli_finding("/api/search", "q", 0.5),
        xss_finding("/api/comments", "body", 0.8),
        path_traversal_finding("/api/files", "path", 0.7),
    ];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);
    let formatted = report.format();

    assert!(formatted.contains("CONFIDENCE DRIFT"));
    assert!(formatted.contains("SQL Injection"));
}

// --- Empty baseline tests ---

#[test]
fn empty_baseline_with_findings_reports_all_new() {
    let baseline = RegressionBaseline {
        fixture_name: "empty".to_string(),
        created_at_unix_ms: 0,
        aegis_version: "0.1.0".to_string(),
        findings: vec![],
    };
    let current = vec![sqli_finding("/api/search", "q", 0.9)];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);

    assert!(!report.has_regressions());
    assert!(report.has_new_findings());
    assert_eq!(report.new.len(), 1);
}

#[test]
fn empty_baseline_and_empty_scan_is_clean() {
    let baseline = RegressionBaseline {
        fixture_name: "empty".to_string(),
        created_at_unix_ms: 0,
        aegis_version: "0.1.0".to_string(),
        findings: vec![],
    };
    let current: Vec<ScanFinding> = vec![];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);

    assert!(!report.has_regressions());
    assert!(!report.has_new_findings());
    assert!(!report.has_drift());
    assert_eq!(report.unchanged, 0);
}

// --- Edge cases ---

#[test]
fn different_parameter_same_endpoint_class_is_distinct() {
    let findings_a = vec![sqli_finding("/api/search", "q", 0.9)];
    let baseline = RegressionBaseline::from_findings("test", &findings_a, "0.1.0");

    let current = vec![sqli_finding("/api/search", "name", 0.9)];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);

    assert!(report.has_regressions());
    assert!(report.has_new_findings());
    assert_eq!(report.missing.len(), 1);
    assert_eq!(report.new.len(), 1);
}

#[test]
fn same_class_different_endpoint_is_distinct() {
    let findings_a = vec![sqli_finding("/api/search", "q", 0.9)];
    let baseline = RegressionBaseline::from_findings("test", &findings_a, "0.1.0");

    let current = vec![sqli_finding("/api/users", "q", 0.9)];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);

    assert!(report.has_regressions());
    assert!(report.has_new_findings());
}

#[test]
fn regression_error_display_formats_correctly() {
    let io_err = RegressionError::Io("disk full".to_string());
    assert_eq!(format!("{io_err}"), "I/O error: disk full");

    let parse_err = RegressionError::Parse("unexpected token".to_string());
    assert_eq!(format!("{parse_err}"), "parse error: unexpected token");

    let ser_err = RegressionError::Serialize("cycle detected".to_string());
    assert_eq!(format!("{ser_err}"), "serialization error: cycle detected");
}

#[test]
fn drift_threshold_default_is_point_one() {
    let threshold = DriftThreshold::default();
    assert!((threshold.absolute - 0.1).abs() < 1e-9);
}

#[test]
fn missing_finding_records_baseline_confidence() {
    let baseline = sample_baseline();
    let current: Vec<ScanFinding> = vec![];

    let runner = RegressionRunner::with_default_threshold();
    let report = runner.compare(&baseline, &current);

    let sqli_missing = report
        .missing
        .iter()
        .find(|m| m.vulnerability_class == VulnerabilityClass::SqlInjection)
        .unwrap();
    assert!((sqli_missing.baseline_confidence - 0.9).abs() < 1e-6);
}

#[test]
fn baseline_roundtrip_preserves_finding_ids() {
    let baseline = sample_baseline();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rt.json");

    baseline.save(&path).unwrap();
    let loaded = RegressionBaseline::load(&path).unwrap();

    for (orig, loaded) in baseline.findings.iter().zip(loaded.findings.iter()) {
        assert_eq!(orig.finding_id, loaded.finding_id);
        assert_eq!(orig.vulnerability_class, loaded.vulnerability_class);
        assert!((orig.confidence - loaded.confidence).abs() < 1e-9);
    }
}
