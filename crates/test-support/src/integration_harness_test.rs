use super::*;
use crate::ground_truth_v2::{AnnotationBuilder, GroundTruthManifest, GroundTruthSeverity};

fn simple_router() -> Router {
    use axum::routing::get;
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/api/search",
            get(|axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>| async move {
                let q = params.get("q").cloned().unwrap_or_default();
                if q.contains('\'') {
                    format!("SQL error: {q}")
                } else {
                    format!("Results for: {q}")
                }
            }),
        )
        .route(
            "/api/render",
            get(|axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>| async move {
                let name = params.get("name").cloned().unwrap_or_default();
                axum::response::Html(format!("<h1>{name}</h1>"))
            }),
        )
}

fn simple_ground_truth() -> GroundTruthManifest {
    let mut m = GroundTruthManifest::new("simple-test");
    m.add(
        AnnotationBuilder::new("/api/search", VulnerabilityClass::SqlInjection)
            .severity(GroundTruthSeverity::Critical)
            .cwe("CWE-89")
            .description("SQL injection")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/api/render", VulnerabilityClass::CrossSiteScripting)
            .severity(GroundTruthSeverity::High)
            .cwe("CWE-79")
            .description("Reflected XSS")
            .build(),
    );
    m
}

/// A mock scanner that finds all expected vulnerabilities (perfect scanner).
fn perfect_scanner() -> ScannerFn {
    Box::new(|_url: String| {
        vec![
            (
                "/api/search".to_string(),
                VulnerabilityClass::SqlInjection,
            ),
            (
                "/api/render".to_string(),
                VulnerabilityClass::CrossSiteScripting,
            ),
        ]
    })
}

/// A mock scanner that finds nothing.
fn empty_scanner() -> ScannerFn {
    Box::new(|_url: String| vec![])
}

/// A scanner that produces false positives.
fn noisy_scanner() -> ScannerFn {
    Box::new(|_url: String| {
        vec![
            (
                "/api/search".to_string(),
                VulnerabilityClass::SqlInjection,
            ),
            (
                "/api/render".to_string(),
                VulnerabilityClass::CrossSiteScripting,
            ),
            // False positive
            (
                "/api/health".to_string(),
                VulnerabilityClass::SecurityMisconfiguration,
            ),
        ]
    })
}

/// A scanner that finds only half.
fn partial_scanner() -> ScannerFn {
    Box::new(|_url: String| {
        vec![(
            "/api/search".to_string(),
            VulnerabilityClass::SqlInjection,
        )]
    })
}

#[tokio::test]
async fn perfect_scanner_gets_full_marks() {
    let harness = IntegrationHarness::new(simple_router(), simple_ground_truth());
    let result = harness.run_sync(perfect_scanner()).await;

    assert!((result.evaluation.precision - 1.0).abs() < 0.001);
    assert!((result.evaluation.recall - 1.0).abs() < 0.001);
    assert!((result.evaluation.f1 - 1.0).abs() < 0.001);
    assert_eq!(result.total_findings, 2);
    assert_eq!(result.total_expected, 2);
    assert!(result.precision_meets(0.99));
    assert!(result.recall_meets(0.99));
    assert!(result.f1_meets(0.99));
}

#[tokio::test]
async fn empty_scanner_gets_zero_recall() {
    let harness = IntegrationHarness::new(simple_router(), simple_ground_truth());
    let result = harness.run_sync(empty_scanner()).await;

    assert!((result.evaluation.recall - 0.0).abs() < 0.001);
    assert_eq!(result.total_findings, 0);
    assert!(!result.recall_meets(0.01));
}

#[tokio::test]
async fn noisy_scanner_has_reduced_precision() {
    let harness = IntegrationHarness::new(simple_router(), simple_ground_truth());
    let result = harness.run_sync(noisy_scanner()).await;

    // 2 TP + 1 FP → precision = 2/3
    assert!((result.evaluation.precision - 2.0 / 3.0).abs() < 0.001);
    assert!((result.evaluation.recall - 1.0).abs() < 0.001);
    assert_eq!(result.evaluation.false_positives.len(), 1);
}

#[tokio::test]
async fn partial_scanner_has_reduced_recall() {
    let harness = IntegrationHarness::new(simple_router(), simple_ground_truth());
    let result = harness.run_sync(partial_scanner()).await;

    assert!((result.evaluation.precision - 1.0).abs() < 0.001);
    assert!((result.evaluation.recall - 0.5).abs() < 0.001);
    assert_eq!(result.evaluation.false_negatives.len(), 1);
}

#[tokio::test]
async fn server_url_is_valid() {
    let harness = IntegrationHarness::new(simple_router(), simple_ground_truth());
    let result = harness.run_sync(empty_scanner()).await;

    assert!(result.server_url.starts_with("http://127.0.0.1:"));
}

#[tokio::test]
async fn timings_are_recorded() {
    let harness = IntegrationHarness::new(simple_router(), simple_ground_truth());
    let result = harness.run_sync(perfect_scanner()).await;

    assert!(result.timings.get(HarnessPhase::ServerStart) > Duration::ZERO);
    assert!(result.timings.get(HarnessPhase::Total) > Duration::ZERO);
    // Evaluation can be near-zero but should be recorded
    assert!(result.timings.timings.contains_key(&HarnessPhase::Evaluation));
}

#[tokio::test]
async fn summary_contains_key_metrics() {
    let harness = IntegrationHarness::new(simple_router(), simple_ground_truth());
    let result = harness.run_sync(noisy_scanner()).await;

    let summary = result.summary();
    assert!(summary.contains("Precision:"));
    assert!(summary.contains("Recall:"));
    assert!(summary.contains("F1 Score:"));
    assert!(summary.contains("True Positives:"));
    assert!(summary.contains("False Positives:"));
    assert!(summary.contains("Unexpected findings:"));
}

#[tokio::test]
async fn to_benchmark_report_has_phase_measurements() {
    let harness = IntegrationHarness::new(simple_router(), simple_ground_truth());
    let result = harness.run_sync(perfect_scanner()).await;

    let report = result.to_benchmark_report();
    assert!(report.count() >= 3); // At least ServerStart, Scan, Evaluation
    let integration_items = report.by_tag("integration");
    assert!(!integration_items.is_empty());
}

#[tokio::test]
async fn async_scanner_works() {
    let harness = IntegrationHarness::new(simple_router(), simple_ground_truth());

    let async_scanner: AsyncScannerFn = Box::new(|_url| {
        Box::pin(async {
            vec![
                (
                    "/api/search".to_string(),
                    VulnerabilityClass::SqlInjection,
                ),
                (
                    "/api/render".to_string(),
                    VulnerabilityClass::CrossSiteScripting,
                ),
            ]
        })
    });

    let result = harness.run_async(async_scanner).await;
    assert!((result.evaluation.f1 - 1.0).abs() < 0.001);
}

#[tokio::test]
async fn harness_from_vulnerable_api_builds() {
    let harness = harness_from_vulnerable_api();
    let gt = harness.ground_truth();
    assert!(gt.count() >= 30);
    assert_eq!(gt.fixture_name, "vulnerable-api");
}

#[tokio::test]
async fn ground_truth_accessor_returns_manifest() {
    let harness = IntegrationHarness::new(simple_router(), simple_ground_truth());
    assert_eq!(harness.ground_truth().fixture_name, "simple-test");
    assert_eq!(harness.ground_truth().count(), 2);
}

#[test]
fn phase_timings_get_returns_zero_for_unrecorded() {
    let timings = PhaseTimings::new();
    assert_eq!(timings.get(HarnessPhase::Scan), Duration::ZERO);
}
