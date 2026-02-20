use std::collections::HashMap;

use aegis_protocol::finding::{FindingData, VulnerabilityClass};

/// A single expected vulnerability at a specific endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroundTruthEntry {
    pub endpoint: String,
    pub vulnerability_class: VulnerabilityClass,
}

/// The complete set of expected vulnerabilities for a benchmark fixture.
#[derive(Debug, Clone)]
pub struct GroundTruth {
    pub entries: Vec<GroundTruthEntry>,
}

/// A self-contained test fixture describing a simulated target with known vulnerabilities.
#[derive(Debug, Clone)]
pub struct BenchmarkFixture {
    pub name: String,
    pub description: String,
    pub ground_truth: GroundTruth,
}

/// Per-class breakdown of true/false positive counts within a benchmark evaluation.
#[derive(Debug, Clone, Default)]
pub struct ClassMetrics {
    pub true_positives: u64,
    pub false_positives: u64,
    pub false_negatives: u64,
}

/// Evaluation result for a single benchmark fixture.
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub fixture_name: String,
    pub true_positives: u64,
    pub false_positives: u64,
    pub false_negatives: u64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub findings_by_class: HashMap<VulnerabilityClass, ClassMetrics>,
}

/// Aggregate metrics across multiple benchmark fixtures.
#[derive(Debug, Clone)]
pub struct BenchmarkSummary {
    pub total_tp: u64,
    pub total_fp: u64,
    pub total_fn: u64,
    pub overall_precision: f64,
    pub overall_recall: f64,
    pub overall_f1: f64,
    pub per_class_metrics: HashMap<VulnerabilityClass, ClassMetrics>,
}

/// Compares detected findings against ground truth for a single fixture.
///
/// Matching is done by vulnerability class. Within a fixture each ground truth
/// entry has a distinct class, so a finding matches if its `vulnerability_class`
/// equals a ground truth entry's class. Each ground truth entry and each finding
/// can participate in at most one match.
pub fn evaluate_findings(
    fixture_name: &str,
    findings: &[FindingData],
    ground_truth: &GroundTruth,
) -> BenchmarkResult {
    let mut matched_gt: Vec<bool> = vec![false; ground_truth.entries.len()];
    let mut matched_finding: Vec<bool> = vec![false; findings.len()];

    for (fi, finding) in findings.iter().enumerate() {
        for (gi, gt_entry) in ground_truth.entries.iter().enumerate() {
            if !matched_gt[gi]
                && !matched_finding[fi]
                && finding.vulnerability_class == gt_entry.vulnerability_class
            {
                matched_gt[gi] = true;
                matched_finding[fi] = true;
            }
        }
    }

    let true_positives = matched_finding.iter().filter(|&&m| m).count() as u64;
    let false_positives = matched_finding.iter().filter(|&&m| !m).count() as u64;
    let false_negatives = matched_gt.iter().filter(|&&m| !m).count() as u64;

    let findings_by_class =
        build_class_metrics(findings, ground_truth, &matched_finding, &matched_gt);
    let (precision, recall, f1_score) =
        compute_prf(true_positives, false_positives, false_negatives);

    BenchmarkResult {
        fixture_name: fixture_name.to_string(),
        true_positives,
        false_positives,
        false_negatives,
        precision,
        recall,
        f1_score,
        findings_by_class,
    }
}

fn build_class_metrics(
    findings: &[FindingData],
    ground_truth: &GroundTruth,
    matched_finding: &[bool],
    matched_gt: &[bool],
) -> HashMap<VulnerabilityClass, ClassMetrics> {
    let mut by_class: HashMap<VulnerabilityClass, ClassMetrics> = HashMap::new();

    for (fi, finding) in findings.iter().enumerate() {
        let entry = by_class.entry(finding.vulnerability_class).or_default();
        if matched_finding[fi] {
            entry.true_positives += 1;
        } else {
            entry.false_positives += 1;
        }
    }

    for (gi, gt_entry) in ground_truth.entries.iter().enumerate() {
        if !matched_gt[gi] {
            by_class
                .entry(gt_entry.vulnerability_class)
                .or_default()
                .false_negatives += 1;
        }
    }

    by_class
}

fn compute_prf(tp: u64, fp: u64, r#fn: u64) -> (f64, f64, f64) {
    let precision = if tp + fp == 0 {
        1.0
    } else {
        tp as f64 / (tp + fp) as f64
    };
    let recall = if tp + r#fn == 0 {
        1.0
    } else {
        tp as f64 / (tp + r#fn) as f64
    };
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };
    (precision, recall, f1)
}

/// Creates the standard set of benchmark fixtures with known vulnerability ground truth.
pub fn build_fixtures() -> Vec<BenchmarkFixture> {
    vec![
        build_dvwa_lite(),
        build_broken_auth_api(),
        build_graphql_exposed(),
    ]
}

fn build_dvwa_lite() -> BenchmarkFixture {
    BenchmarkFixture {
        name: "dvwa-lite".to_string(),
        description: "Minimal DVWA-style app with SQL injection, XSS, and path traversal"
            .to_string(),
        ground_truth: GroundTruth {
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
        },
    }
}

fn build_broken_auth_api() -> BenchmarkFixture {
    BenchmarkFixture {
        name: "broken-auth-api".to_string(),
        description: "API with broken authentication, IDOR, and sensitive data exposure"
            .to_string(),
        ground_truth: GroundTruth {
            entries: vec![
                GroundTruthEntry {
                    endpoint: "/api/login".to_string(),
                    vulnerability_class: VulnerabilityClass::BrokenAuthentication,
                },
                GroundTruthEntry {
                    endpoint: "/api/users/{id}".to_string(),
                    vulnerability_class: VulnerabilityClass::BrokenAuthorization,
                },
                GroundTruthEntry {
                    endpoint: "/api/config".to_string(),
                    vulnerability_class: VulnerabilityClass::SensitiveDataExposure,
                },
            ],
        },
    }
}

fn build_graphql_exposed() -> BenchmarkFixture {
    BenchmarkFixture {
        name: "graphql-exposed".to_string(),
        description: "GraphQL API with injection via variables and introspection enabled"
            .to_string(),
        ground_truth: GroundTruth {
            entries: vec![
                GroundTruthEntry {
                    endpoint: "/graphql".to_string(),
                    vulnerability_class: VulnerabilityClass::SqlInjection,
                },
                GroundTruthEntry {
                    endpoint: "/graphql".to_string(),
                    vulnerability_class: VulnerabilityClass::SecurityMisconfiguration,
                },
            ],
        },
    }
}

/// Aggregates results from multiple benchmark fixture evaluations into a single summary.
pub fn aggregate_results(results: &[BenchmarkResult]) -> BenchmarkSummary {
    let total_tp: u64 = results.iter().map(|r| r.true_positives).sum();
    let total_fp: u64 = results.iter().map(|r| r.false_positives).sum();
    let total_fn: u64 = results.iter().map(|r| r.false_negatives).sum();

    let (overall_precision, overall_recall, overall_f1) = compute_prf(total_tp, total_fp, total_fn);

    let mut per_class_metrics: HashMap<VulnerabilityClass, ClassMetrics> = HashMap::new();
    for result in results {
        for (&class, metrics) in &result.findings_by_class {
            let entry = per_class_metrics.entry(class).or_default();
            entry.true_positives += metrics.true_positives;
            entry.false_positives += metrics.false_positives;
            entry.false_negatives += metrics.false_negatives;
        }
    }

    BenchmarkSummary {
        total_tp,
        total_fp,
        total_fn,
        overall_precision,
        overall_recall,
        overall_f1,
        per_class_metrics,
    }
}

#[cfg(test)]
#[path = "benchmark_test.rs"]
mod benchmark_test;
