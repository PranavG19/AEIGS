use super::*;

use aegis_protocol::finding::{EvidenceLevel, FindingData, VulnerabilityClass};
use aegis_protocol::operation::ModuleIdentifier;

fn make_finding(id: u64, class: VulnerabilityClass) -> FindingData {
    FindingData::new(
        id,
        class,
        7.0,
        0.8,
        ModuleIdentifier::Fuzzing,
        1700000000000,
    )
    .with_evidence_level(EvidenceLevel::Confirmed)
}

fn dvwa_ground_truth() -> GroundTruth {
    GroundTruth {
        entries: vec![
            GroundTruthEntry {
                endpoint: "/api/search?q=".to_string(),
                vulnerability_class: VulnerabilityClass::SqlInjection,
            },
            GroundTruthEntry {
                endpoint: "/api/comments".to_string(),
                vulnerability_class: VulnerabilityClass::CrossSiteScripting,
            },
            GroundTruthEntry {
                endpoint: "/api/files?path=".to_string(),
                vulnerability_class: VulnerabilityClass::PathTraversal,
            },
        ],
    }
}

#[test]
fn evaluate_perfect_detection() {
    let gt = dvwa_ground_truth();
    let findings = vec![
        make_finding(0, VulnerabilityClass::SqlInjection),
        make_finding(1, VulnerabilityClass::CrossSiteScripting),
        make_finding(2, VulnerabilityClass::PathTraversal),
    ];

    let result = evaluate_findings("dvwa-lite", &findings, &gt);

    assert_eq!(result.true_positives, 3);
    assert_eq!(result.false_positives, 0);
    assert_eq!(result.false_negatives, 0);
    assert!((result.precision - 1.0).abs() < 1e-9);
    assert!((result.recall - 1.0).abs() < 1e-9);
    assert!((result.f1_score - 1.0).abs() < 1e-9);
}

#[test]
fn evaluate_with_false_positives() {
    let gt = dvwa_ground_truth();
    let findings = vec![
        make_finding(0, VulnerabilityClass::SqlInjection),
        make_finding(1, VulnerabilityClass::CrossSiteScripting),
        make_finding(2, VulnerabilityClass::PathTraversal),
        make_finding(3, VulnerabilityClass::CommandInjection),
        make_finding(4, VulnerabilityClass::HeaderInjection),
    ];

    let result = evaluate_findings("dvwa-lite", &findings, &gt);

    assert_eq!(result.true_positives, 3);
    assert_eq!(result.false_positives, 2);
    assert_eq!(result.false_negatives, 0);
    // precision = 3 / (3 + 2) = 0.6
    assert!((result.precision - 0.6).abs() < 1e-9);
    assert!((result.recall - 1.0).abs() < 1e-9);
}

#[test]
fn evaluate_with_false_negatives() {
    let gt = dvwa_ground_truth();
    let findings = vec![make_finding(0, VulnerabilityClass::SqlInjection)];

    let result = evaluate_findings("dvwa-lite", &findings, &gt);

    assert_eq!(result.true_positives, 1);
    assert_eq!(result.false_positives, 0);
    assert_eq!(result.false_negatives, 2);
    assert!((result.precision - 1.0).abs() < 1e-9);
    // recall = 1 / (1 + 2) = 1/3
    assert!((result.recall - 1.0 / 3.0).abs() < 1e-9);
}

#[test]
fn evaluate_mixed_results() {
    let gt = dvwa_ground_truth();
    let findings = vec![
        make_finding(0, VulnerabilityClass::SqlInjection),
        make_finding(1, VulnerabilityClass::CommandInjection),
    ];

    let result = evaluate_findings("dvwa-lite", &findings, &gt);

    assert_eq!(result.true_positives, 1);
    assert_eq!(result.false_positives, 1);
    assert_eq!(result.false_negatives, 2);
    // precision = 1 / 2 = 0.5, recall = 1 / 3
    assert!((result.precision - 0.5).abs() < 1e-9);
    assert!((result.recall - 1.0 / 3.0).abs() < 1e-9);
    // f1 = 2 * 0.5 * (1/3) / (0.5 + 1/3) = (1/3) / (5/6) = 2/5 = 0.4
    assert!((result.f1_score - 0.4).abs() < 1e-9);
}

#[test]
fn evaluate_empty_findings_against_ground_truth() {
    let gt = dvwa_ground_truth();
    let findings: Vec<FindingData> = vec![];

    let result = evaluate_findings("dvwa-lite", &findings, &gt);

    assert_eq!(result.true_positives, 0);
    assert_eq!(result.false_positives, 0);
    assert_eq!(result.false_negatives, 3);
    // precision = 1.0 (vacuous: 0 / 0)
    assert!((result.precision - 1.0).abs() < 1e-9);
    // recall = 0 / 3 = 0.0
    assert!((result.recall - 0.0).abs() < 1e-9);
}

#[test]
fn evaluate_empty_findings_and_empty_ground_truth() {
    let gt = GroundTruth { entries: vec![] };
    let findings: Vec<FindingData> = vec![];

    let result = evaluate_findings("empty", &findings, &gt);

    assert_eq!(result.true_positives, 0);
    assert_eq!(result.false_positives, 0);
    assert_eq!(result.false_negatives, 0);
    assert!((result.precision - 1.0).abs() < 1e-9);
    assert!((result.recall - 1.0).abs() < 1e-9);
    // f1 = 2 * 1.0 * 1.0 / (1.0 + 1.0) = 1.0
    assert!((result.f1_score - 1.0).abs() < 1e-9);
}

#[test]
fn evaluate_findings_only_against_empty_ground_truth() {
    let gt = GroundTruth { entries: vec![] };
    let findings = vec![
        make_finding(0, VulnerabilityClass::SqlInjection),
        make_finding(1, VulnerabilityClass::CrossSiteScripting),
    ];

    let result = evaluate_findings("all-fp", &findings, &gt);

    assert_eq!(result.true_positives, 0);
    assert_eq!(result.false_positives, 2);
    assert_eq!(result.false_negatives, 0);
    // precision = 0 / 2 = 0.0
    assert!((result.precision - 0.0).abs() < 1e-9);
    // recall = 1.0 (vacuous: 0 / 0)
    assert!((result.recall - 1.0).abs() < 1e-9);
}

#[test]
fn evaluate_per_class_metrics_tracks_tp_fp_fn() {
    let gt = dvwa_ground_truth();
    let findings = vec![
        make_finding(0, VulnerabilityClass::SqlInjection),
        make_finding(1, VulnerabilityClass::CommandInjection),
    ];

    let result = evaluate_findings("dvwa-lite", &findings, &gt);

    let sql = result
        .findings_by_class
        .get(&VulnerabilityClass::SqlInjection)
        .unwrap();
    assert_eq!(sql.true_positives, 1);
    assert_eq!(sql.false_positives, 0);

    let cmd = result
        .findings_by_class
        .get(&VulnerabilityClass::CommandInjection)
        .unwrap();
    assert_eq!(cmd.true_positives, 0);
    assert_eq!(cmd.false_positives, 1);

    let xss = result
        .findings_by_class
        .get(&VulnerabilityClass::CrossSiteScripting)
        .unwrap();
    assert_eq!(xss.false_negatives, 1);
    assert_eq!(xss.true_positives, 0);

    let pt = result
        .findings_by_class
        .get(&VulnerabilityClass::PathTraversal)
        .unwrap();
    assert_eq!(pt.false_negatives, 1);
    assert_eq!(pt.true_positives, 0);
}

#[test]
fn aggregate_results_combines_multiple_fixtures() {
    let r1 = BenchmarkResult {
        fixture_name: "fixture-a".to_string(),
        true_positives: 3,
        false_positives: 1,
        false_negatives: 0,
        precision: 0.75,
        recall: 1.0,
        f1_score: 6.0 / 7.0,
        findings_by_class: HashMap::from([(
            VulnerabilityClass::SqlInjection,
            ClassMetrics {
                true_positives: 1,
                false_positives: 0,
                false_negatives: 0,
            },
        )]),
    };
    let r2 = BenchmarkResult {
        fixture_name: "fixture-b".to_string(),
        true_positives: 1,
        false_positives: 0,
        false_negatives: 2,
        precision: 1.0,
        recall: 1.0 / 3.0,
        f1_score: 0.5,
        findings_by_class: HashMap::from([(
            VulnerabilityClass::SqlInjection,
            ClassMetrics {
                true_positives: 1,
                false_positives: 0,
                false_negatives: 1,
            },
        )]),
    };

    let summary = aggregate_results(&[r1, r2]);

    assert_eq!(summary.total_tp, 4);
    assert_eq!(summary.total_fp, 1);
    assert_eq!(summary.total_fn, 2);
    // precision = 4 / 5 = 0.8
    assert!((summary.overall_precision - 0.8).abs() < 1e-9);
    // recall = 4 / 6 = 2/3
    assert!((summary.overall_recall - 2.0 / 3.0).abs() < 1e-9);

    let sql = summary
        .per_class_metrics
        .get(&VulnerabilityClass::SqlInjection)
        .unwrap();
    assert_eq!(sql.true_positives, 2);
    assert_eq!(sql.false_negatives, 1);
}

#[test]
fn aggregate_results_empty_input() {
    let summary = aggregate_results(&[]);

    assert_eq!(summary.total_tp, 0);
    assert_eq!(summary.total_fp, 0);
    assert_eq!(summary.total_fn, 0);
    assert!((summary.overall_precision - 1.0).abs() < 1e-9);
    assert!((summary.overall_recall - 1.0).abs() < 1e-9);
    assert!((summary.overall_f1 - 1.0).abs() < 1e-9);
    assert!(summary.per_class_metrics.is_empty());
}

#[test]
fn aggregate_all_zeros_gives_zero_f1() {
    let r = BenchmarkResult {
        fixture_name: "zero".to_string(),
        true_positives: 0,
        false_positives: 0,
        false_negatives: 0,
        precision: 1.0,
        recall: 1.0,
        f1_score: 1.0,
        findings_by_class: HashMap::new(),
    };

    let summary = aggregate_results(&[r]);

    // 0 TP, 0 FP, 0 FN → vacuous precision=1, recall=1, f1=1
    assert!((summary.overall_f1 - 1.0).abs() < 1e-9);
}

#[test]
fn build_fixtures_returns_expected_count() {
    let fixtures = build_fixtures();
    assert_eq!(fixtures.len(), 3);
}

#[test]
fn build_fixtures_dvwa_lite_has_three_ground_truth_entries() {
    let fixtures = build_fixtures();
    let dvwa = fixtures.iter().find(|f| f.name == "dvwa-lite").unwrap();
    assert_eq!(dvwa.ground_truth.entries.len(), 3);

    let classes: Vec<VulnerabilityClass> = dvwa
        .ground_truth
        .entries
        .iter()
        .map(|e| e.vulnerability_class)
        .collect();
    assert!(classes.contains(&VulnerabilityClass::SqlInjection));
    assert!(classes.contains(&VulnerabilityClass::CrossSiteScripting));
    assert!(classes.contains(&VulnerabilityClass::PathTraversal));
}

#[test]
fn build_fixtures_broken_auth_has_three_ground_truth_entries() {
    let fixtures = build_fixtures();
    let broken = fixtures
        .iter()
        .find(|f| f.name == "broken-auth-api")
        .unwrap();
    assert_eq!(broken.ground_truth.entries.len(), 3);
}

#[test]
fn build_fixtures_graphql_exposed_has_two_ground_truth_entries() {
    let fixtures = build_fixtures();
    let gql = fixtures
        .iter()
        .find(|f| f.name == "graphql-exposed")
        .unwrap();
    assert_eq!(gql.ground_truth.entries.len(), 2);
}

#[test]
fn precision_recall_f1_all_tp_no_fp_no_fn() {
    let (p, r, f1) = compute_prf(5, 0, 0);
    assert!((p - 1.0).abs() < 1e-9);
    assert!((r - 1.0).abs() < 1e-9);
    assert!((f1 - 1.0).abs() < 1e-9);
}

#[test]
fn precision_recall_f1_zero_tp_with_fp_and_fn() {
    let (p, r, f1) = compute_prf(0, 3, 2);
    assert!((p - 0.0).abs() < 1e-9);
    assert!((r - 0.0).abs() < 1e-9);
    assert!((f1 - 0.0).abs() < 1e-9);
}

#[test]
fn f1_score_calculation_correctness() {
    // TP=3, FP=1, FN=1 → precision=3/4=0.75, recall=3/4=0.75, f1=0.75
    let (p, r, f1) = compute_prf(3, 1, 1);
    assert!((p - 0.75).abs() < 1e-9);
    assert!((r - 0.75).abs() < 1e-9);
    assert!((f1 - 0.75).abs() < 1e-9);
}

#[test]
fn benchmark_f1_is_zero_when_all_findings_miss() {
    let gt = dvwa_ground_truth();
    let findings = vec![
        make_finding(0, VulnerabilityClass::CommandInjection),
        make_finding(1, VulnerabilityClass::HeaderInjection),
    ];

    let result = evaluate_findings("all-miss", &findings, &gt);

    assert_eq!(result.true_positives, 0);
    assert_eq!(result.false_positives, 2);
    assert_eq!(result.false_negatives, 3);
    assert!((result.precision - 0.0).abs() < 1e-9);
    assert!((result.recall - 0.0).abs() < 1e-9);
    assert!((result.f1_score - 0.0).abs() < 1e-9);
}

#[test]
fn benchmark_perfect_score_all_classes_have_full_tp() {
    let gt = dvwa_ground_truth();
    let findings = vec![
        make_finding(0, VulnerabilityClass::SqlInjection),
        make_finding(1, VulnerabilityClass::CrossSiteScripting),
        make_finding(2, VulnerabilityClass::PathTraversal),
    ];

    let result = evaluate_findings("perfect", &findings, &gt);

    assert!((result.f1_score - 1.0).abs() < 1e-9);
    for class in &[
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::PathTraversal,
    ] {
        let m = result.findings_by_class.get(class).unwrap();
        assert_eq!(m.true_positives, 1, "{class:?} should have 1 TP");
        assert_eq!(m.false_positives, 0, "{class:?} should have 0 FP");
        assert_eq!(m.false_negatives, 0, "{class:?} should have 0 FN");
    }
}

#[test]
fn benchmark_per_class_metrics_covers_all_present_classes() {
    let gt = dvwa_ground_truth();
    let findings = vec![
        make_finding(0, VulnerabilityClass::SqlInjection),
        make_finding(1, VulnerabilityClass::SqlInjection),
        make_finding(2, VulnerabilityClass::PathTraversal),
    ];

    let result = evaluate_findings("multi-sql", &findings, &gt);

    let sql = result
        .findings_by_class
        .get(&VulnerabilityClass::SqlInjection)
        .unwrap();
    assert_eq!(sql.true_positives, 1);
    assert_eq!(sql.false_positives, 1);

    let pt = result
        .findings_by_class
        .get(&VulnerabilityClass::PathTraversal)
        .unwrap();
    assert_eq!(pt.true_positives, 1);
    assert_eq!(pt.false_positives, 0);

    let xss = result
        .findings_by_class
        .get(&VulnerabilityClass::CrossSiteScripting)
        .unwrap();
    assert_eq!(xss.true_positives, 0);
    assert_eq!(xss.false_negatives, 1);

    assert_eq!(result.true_positives, 2);
    assert_eq!(result.false_positives, 1);
    assert_eq!(result.false_negatives, 1);
}

#[test]
fn ground_truth_comparison_case_insensitive_endpoint() {
    let gt = GroundTruth {
        entries: vec![GroundTruthEntry {
            endpoint: "/API/Users".to_string(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
        }],
    };
    let findings = vec![make_finding(0, VulnerabilityClass::SqlInjection)];

    let result = evaluate_findings("case-test", &findings, &gt);

    assert_eq!(result.true_positives, 1);
    assert_eq!(result.false_positives, 0);
    assert_eq!(result.false_negatives, 0);
}

#[test]
fn ground_truth_comparison_trailing_slash() {
    let gt = GroundTruth {
        entries: vec![
            GroundTruthEntry {
                endpoint: "/api/users/".to_string(),
                vulnerability_class: VulnerabilityClass::SqlInjection,
            },
            GroundTruthEntry {
                endpoint: "/api/search".to_string(),
                vulnerability_class: VulnerabilityClass::CrossSiteScripting,
            },
        ],
    };
    let findings = vec![
        make_finding(0, VulnerabilityClass::SqlInjection),
        make_finding(1, VulnerabilityClass::CrossSiteScripting),
    ];

    let result = evaluate_findings("trailing-slash", &findings, &gt);

    assert_eq!(result.true_positives, 2);
    assert_eq!(result.false_positives, 0);
    assert_eq!(result.false_negatives, 0);
}

#[test]
fn ground_truth_comparison_with_query_params() {
    let gt = GroundTruth {
        entries: vec![GroundTruthEntry {
            endpoint: "/api/search?q=test&page=1".to_string(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
        }],
    };
    let findings = vec![make_finding(0, VulnerabilityClass::SqlInjection)];

    let result = evaluate_findings("query-params", &findings, &gt);

    assert_eq!(result.true_positives, 1);
    assert_eq!(result.false_positives, 0);
    assert_eq!(result.false_negatives, 0);
}
