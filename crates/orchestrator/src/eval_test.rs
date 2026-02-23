use std::collections::HashSet;

use super::*;
use crate::benchmark::{ComparisonResult, GroundTruthFileEntry, compare_findings};

#[test]
fn parse_eval_args_express() {
    let args = vec!["--fixture".to_string(), "express".to_string()];
    let parsed = parse_eval_args(&args).unwrap();
    assert_eq!(parsed.fixture, "express");
    assert!(!parsed.no_cleanup);
    assert!(!parsed.verbose);
}

#[test]
fn parse_eval_args_missing_fixture() {
    let args: Vec<String> = vec![];
    let result = parse_eval_args(&args);
    assert!(result.is_err());
}

#[test]
fn parse_eval_args_unknown_fixture_ok_at_parse_time() {
    let args = vec!["--fixture".to_string(), "unknown".to_string()];
    let parsed = parse_eval_args(&args).unwrap();
    assert_eq!(parsed.fixture, "unknown");
}

#[test]
fn parse_eval_args_with_flags() {
    let args = vec![
        "--fixture".to_string(),
        "flask".to_string(),
        "--no-cleanup".to_string(),
        "--verbose".to_string(),
    ];
    let parsed = parse_eval_args(&args).unwrap();
    assert_eq!(parsed.fixture, "flask");
    assert!(parsed.no_cleanup);
    assert!(parsed.verbose);
}

#[test]
fn find_fixture_express() {
    let config = find_fixture("express").unwrap();
    assert_eq!(config.port, 3000);
    assert_eq!(config.compose_file, "docker-compose.yml");
}

#[test]
fn find_fixture_flask() {
    let config = find_fixture("flask").unwrap();
    assert_eq!(config.port, 5001);
}

#[test]
fn find_fixture_graphql() {
    let config = find_fixture("graphql").unwrap();
    assert_eq!(config.port, 4000);
}

#[test]
fn find_fixture_unknown() {
    assert!(find_fixture("unknown").is_none());
}

#[test]
fn compare_findings_perfect() {
    let gt = vec![
        make_gt_entry("/a", "SqlInjection"),
        make_gt_entry("/b", "CrossSiteScripting"),
    ];
    let mut findings = HashSet::new();
    findings.insert(("/a".to_string(), "SqlInjection".to_string()));
    findings.insert(("/b".to_string(), "CrossSiteScripting".to_string()));

    let result = compare_findings(&gt, &findings);

    assert_eq!(result.true_positives, 2);
    assert_eq!(result.false_positives, 0);
    assert_eq!(result.false_negatives, 0);
    assert!((result.precision - 1.0).abs() < 1e-9);
    assert!((result.recall - 1.0).abs() < 1e-9);
    assert!((result.f1 - 1.0).abs() < 1e-9);
}

#[test]
fn compare_findings_with_misses() {
    let gt = vec![
        make_gt_entry("/a", "SqlInjection"),
        make_gt_entry("/b", "CrossSiteScripting"),
        make_gt_entry("/c", "CommandInjection"),
    ];
    let mut findings = HashSet::new();
    findings.insert(("/a".to_string(), "SqlInjection".to_string()));

    let result = compare_findings(&gt, &findings);

    assert_eq!(result.true_positives, 1);
    assert_eq!(result.false_positives, 0);
    assert_eq!(result.false_negatives, 2);
    assert!((result.precision - 1.0).abs() < 1e-9);
    assert!(result.recall < 1.0);
}

#[test]
fn compare_findings_with_extras() {
    let gt = vec![make_gt_entry("/a", "SqlInjection")];
    let mut findings = HashSet::new();
    findings.insert(("/a".to_string(), "SqlInjection".to_string()));
    findings.insert(("/z".to_string(), "PathTraversal".to_string()));

    let result = compare_findings(&gt, &findings);

    assert_eq!(result.true_positives, 1);
    assert_eq!(result.false_positives, 1);
    assert_eq!(result.false_negatives, 0);
    assert!(result.precision < 1.0);
    assert!((result.recall - 1.0).abs() < 1e-9);
}

#[test]
fn compare_findings_empty_both() {
    let gt: Vec<GroundTruthFileEntry> = vec![];
    let findings: HashSet<(String, String)> = HashSet::new();

    let result = compare_findings(&gt, &findings);

    assert_eq!(result.true_positives, 0);
    assert_eq!(result.false_positives, 0);
    assert_eq!(result.false_negatives, 0);
}

#[test]
fn format_eval_result_shows_metrics() {
    let result = make_eval_result(0.8, 0.6, 0.685);
    let output = format_eval_result(&result);

    assert!(output.contains("Precision:"));
    assert!(output.contains("Recall:"));
    assert!(output.contains("F1:"));
}

#[test]
fn format_eval_result_shows_per_class() {
    let result = EvalResult {
        fixture: "express".to_string(),
        comparison: ComparisonResult {
            true_positives: 1,
            false_positives: 0,
            false_negatives: 1,
            precision: 1.0,
            recall: 0.5,
            f1: 0.666,
            matched: vec![],
            missed: vec![],
            extra: vec![],
        },
        scan_duration_ms: 100,
        per_class: vec![
            ClassResult {
                vulnerability_class: "SqlInjection".to_string(),
                detected: true,
            },
            ClassResult {
                vulnerability_class: "CrossSiteScripting".to_string(),
                detected: false,
            },
        ],
    };
    let output = format_eval_result(&result);

    assert!(output.contains("SqlInjection"));
    assert!(output.contains("CrossSiteScripting"));
    assert!(output.contains("[+]"));
    assert!(output.contains("[-]"));
}

#[test]
fn resolve_paths_returns_valid_directories() {
    let fixture = find_fixture("express").unwrap();
    let (compose_dir, gt_path) = resolve_paths(fixture);
    assert!(compose_dir.ends_with("compose"));
    assert!(gt_path.ends_with("express-vuln-app/ground-truth.json"));
}

fn make_gt_entry(endpoint: &str, vuln_class: &str) -> GroundTruthFileEntry {
    GroundTruthFileEntry {
        endpoint: endpoint.to_string(),
        method: "GET".to_string(),
        parameter: None,
        vulnerability_class: vuln_class.to_string(),
        operation: None,
        note: None,
    }
}

fn make_eval_result(precision: f64, recall: f64, f1: f64) -> EvalResult {
    EvalResult {
        fixture: "test".to_string(),
        comparison: ComparisonResult {
            true_positives: 4,
            false_positives: 1,
            false_negatives: 2,
            precision,
            recall,
            f1,
            matched: vec![],
            missed: vec![],
            extra: vec![],
        },
        scan_duration_ms: 500,
        per_class: vec![],
    }
}
