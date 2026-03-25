use aegis_protocol::finding::VulnerabilityClass;
use axum::Router;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::benchmark_suite::{BenchmarkMeasurement, BenchmarkReport};
use crate::fixture_server::TestServer;
use crate::ground_truth_v2::{GroundTruthEvaluation, GroundTruthManifest};

/// Phase of the integration test pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarnessPhase {
    ServerStart,
    Scan,
    Evaluation,
    Total,
}

/// Timing information for each phase of the harness run.
#[derive(Debug, Clone)]
pub struct PhaseTimings {
    pub timings: HashMap<HarnessPhase, Duration>,
}

impl PhaseTimings {
    fn new() -> Self {
        Self {
            timings: HashMap::new(),
        }
    }

    fn record(&mut self, phase: HarnessPhase, duration: Duration) {
        self.timings.insert(phase, duration);
    }

    /// Returns duration for a phase, or zero if not recorded.
    pub fn get(&self, phase: HarnessPhase) -> Duration {
        self.timings.get(&phase).copied().unwrap_or(Duration::ZERO)
    }
}

/// Result of a full integration test run.
#[derive(Debug, Clone)]
pub struct HarnessResult {
    /// The evaluation comparing findings to ground truth.
    pub evaluation: GroundTruthEvaluation,
    /// Timing breakdown per phase.
    pub timings: PhaseTimings,
    /// The base URL of the test server used.
    pub server_url: String,
    /// Total number of findings produced by the scanner.
    pub total_findings: usize,
    /// Total number of ground truth annotations.
    pub total_expected: usize,
}

impl HarnessResult {
    /// Returns true if precision meets or exceeds threshold.
    pub fn precision_meets(&self, threshold: f64) -> bool {
        self.evaluation.precision >= threshold
    }

    /// Returns true if recall meets or exceeds threshold.
    pub fn recall_meets(&self, threshold: f64) -> bool {
        self.evaluation.recall >= threshold
    }

    /// Returns true if F1 meets or exceeds threshold.
    pub fn f1_meets(&self, threshold: f64) -> bool {
        self.evaluation.f1 >= threshold
    }

    /// Produces a human-readable summary of the run.
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push("Integration Test Results".to_string());
        lines.push("=".repeat(60));
        lines.push(format!("Server URL:       {}", self.server_url));
        lines.push(format!("Total Expected:   {}", self.total_expected));
        lines.push(format!("Total Findings:   {}", self.total_findings));
        lines.push(format!(
            "True Positives:   {}",
            self.evaluation.true_positives.len()
        ));
        lines.push(format!(
            "False Positives:  {}",
            self.evaluation.false_positives.len()
        ));
        lines.push(format!(
            "False Negatives:  {}",
            self.evaluation.false_negatives.len()
        ));
        lines.push("-".repeat(60));
        lines.push(format!("Precision:        {:.2}%", self.evaluation.precision * 100.0));
        lines.push(format!("Recall:           {:.2}%", self.evaluation.recall * 100.0));
        lines.push(format!("F1 Score:         {:.2}%", self.evaluation.f1 * 100.0));
        lines.push("-".repeat(60));
        lines.push(format!(
            "Server Start:     {:?}",
            self.timings.get(HarnessPhase::ServerStart)
        ));
        lines.push(format!(
            "Scan Duration:    {:?}",
            self.timings.get(HarnessPhase::Scan)
        ));
        lines.push(format!(
            "Evaluation:       {:?}",
            self.timings.get(HarnessPhase::Evaluation)
        ));
        lines.push(format!(
            "Total:            {:?}",
            self.timings.get(HarnessPhase::Total)
        ));
        lines.push("=".repeat(60));

        if !self.evaluation.false_negatives.is_empty() {
            lines.push("Missed findings:".to_string());
            for (ep, cls) in &self.evaluation.false_negatives {
                lines.push(format!("  - {} @ {}", cls, ep));
            }
        }

        if !self.evaluation.false_positives.is_empty() {
            lines.push("Unexpected findings:".to_string());
            for (ep, cls) in &self.evaluation.false_positives {
                lines.push(format!("  - {} @ {}", cls, ep));
            }
        }

        lines.join("\n")
    }

    /// Converts timing data into benchmark measurements for the report.
    pub fn to_benchmark_report(&self) -> BenchmarkReport {
        let mut report = BenchmarkReport::new();

        for (phase, duration) in &self.timings.timings {
            let name = format!("integration/{:?}", phase);
            report.add(BenchmarkMeasurement {
                name,
                duration: *duration,
                iterations: 1,
                ops_per_sec: if duration.as_secs_f64() > 0.0 {
                    1.0 / duration.as_secs_f64()
                } else {
                    f64::INFINITY
                },
                avg_per_op: *duration,
                memory_bytes: None,
                tags: vec!["integration".to_string()],
            });
        }

        report
    }
}

/// Scanner function signature used by the harness.
///
/// Receives the base URL of the running test server and returns a list
/// of `(endpoint, vulnerability_class)` tuples representing findings.
pub type ScannerFn =
    Box<dyn FnOnce(String) -> Vec<(String, VulnerabilityClass)> + Send>;

/// Async scanner function signature.
pub type AsyncScannerFn = Box<
    dyn FnOnce(String) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Vec<(String, VulnerabilityClass)>> + Send>,
    > + Send,
>;

/// Integration test harness that orchestrates end-to-end scan testing.
///
/// Workflow: start vulnerable server → run scanner → compare against ground
/// truth → report precision/recall/F1.
pub struct IntegrationHarness {
    router: Router,
    ground_truth: GroundTruthManifest,
}

impl IntegrationHarness {
    /// Creates a new harness with the given router and ground truth.
    pub fn new(router: Router, ground_truth: GroundTruthManifest) -> Self {
        Self {
            router,
            ground_truth,
        }
    }

    /// Runs the integration test with a synchronous scanner function.
    ///
    /// Starts the test server, invokes the scanner, evaluates results.
    pub async fn run_sync(self, scanner: ScannerFn) -> HarnessResult {
        let total_start = Instant::now();
        let mut timings = PhaseTimings::new();

        // Phase 1: Start server
        let server_start = Instant::now();
        let server = TestServer::new(self.router).await;
        let url = server.url();
        timings.record(HarnessPhase::ServerStart, server_start.elapsed());

        // Phase 2: Run scanner
        let scan_start = Instant::now();
        let findings = scanner(url.clone());
        timings.record(HarnessPhase::Scan, scan_start.elapsed());

        // Phase 3: Evaluate
        let eval_start = Instant::now();
        let evaluation = self.ground_truth.evaluate(&findings);
        timings.record(HarnessPhase::Evaluation, eval_start.elapsed());

        timings.record(HarnessPhase::Total, total_start.elapsed());

        let total_expected = self
            .ground_truth
            .annotations
            .iter()
            .filter(|a| a.expected_detected)
            .count();

        // Server drops here (auto-abort)
        drop(server);

        HarnessResult {
            evaluation,
            timings,
            server_url: url,
            total_findings: findings.len(),
            total_expected,
        }
    }

    /// Runs the integration test with an async scanner function.
    pub async fn run_async(self, scanner: AsyncScannerFn) -> HarnessResult {
        let total_start = Instant::now();
        let mut timings = PhaseTimings::new();

        // Phase 1: Start server
        let server_start = Instant::now();
        let server = TestServer::new(self.router).await;
        let url = server.url();
        timings.record(HarnessPhase::ServerStart, server_start.elapsed());

        // Phase 2: Run scanner
        let scan_start = Instant::now();
        let findings = scanner(url.clone()).await;
        timings.record(HarnessPhase::Scan, scan_start.elapsed());

        // Phase 3: Evaluate
        let eval_start = Instant::now();
        let evaluation = self.ground_truth.evaluate(&findings);
        timings.record(HarnessPhase::Evaluation, eval_start.elapsed());

        timings.record(HarnessPhase::Total, total_start.elapsed());

        let total_expected = self
            .ground_truth
            .annotations
            .iter()
            .filter(|a| a.expected_detected)
            .count();

        drop(server);

        HarnessResult {
            evaluation,
            timings,
            server_url: url,
            total_findings: findings.len(),
            total_expected,
        }
    }

    /// Returns a reference to the ground truth manifest.
    pub fn ground_truth(&self) -> &GroundTruthManifest {
        &self.ground_truth
    }
}

/// Convenience function: build a harness from VulnerableApi + its annotations.
pub fn harness_from_vulnerable_api() -> IntegrationHarness {
    use crate::ground_truth_v2::{AnnotationBuilder, GroundTruthSeverity};
    use crate::vulnerable_api::VulnerableApi;

    let api = VulnerableApi::build();
    let mut manifest = GroundTruthManifest::new("vulnerable-api");

    for ann in api.annotations() {
        manifest.add(
            AnnotationBuilder::new(&ann.endpoint, ann.vulnerability_class.clone())
                .severity(match ann.severity {
                    crate::vulnerable_api::Severity::Critical => GroundTruthSeverity::Critical,
                    crate::vulnerable_api::Severity::High => GroundTruthSeverity::High,
                    crate::vulnerable_api::Severity::Medium => GroundTruthSeverity::Medium,
                    crate::vulnerable_api::Severity::Low => GroundTruthSeverity::Low,
                    crate::vulnerable_api::Severity::Info => GroundTruthSeverity::Info,
                })
                .cwe(&ann.cwe_id)
                .description(&ann.description)
                .build(),
        );
    }

    IntegrationHarness::new(api.into_router(), manifest)
}

#[cfg(test)]
#[path = "integration_harness_test.rs"]
mod tests;
