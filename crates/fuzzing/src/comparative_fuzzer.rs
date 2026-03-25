use std::collections::HashMap;
use std::time::Duration;

use crate::executor::FuzzResponse;

/// Type of discrepancy detected between compared responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscrepancyType {
    StatusCodeMismatch,
    BodyLengthDivergence,
    ValidationInconsistency,
    ErrorHandlingDifference,
    AuthDiscrepancy,
    HeaderDivergence,
    TimingDivergence,
    ContentStructureDifference,
}

/// Severity of a detected discrepancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiscrepancySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// A single discrepancy found when comparing responses.
#[derive(Debug, Clone)]
pub struct Discrepancy {
    pub discrepancy_type: DiscrepancyType,
    pub severity: DiscrepancySeverity,
    pub description: String,
    pub payload: String,
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub detail_a: String,
    pub detail_b: String,
}

/// A pair of endpoints to compare.
#[derive(Debug, Clone)]
pub struct ComparisonTarget {
    pub label_a: String,
    pub endpoint_a: String,
    pub label_b: String,
    pub endpoint_b: String,
}

/// Result of comparing a single input across two endpoints.
#[derive(Debug, Clone)]
pub struct ComparisonResult {
    pub payload: String,
    pub response_a: ResponseSummary,
    pub response_b: ResponseSummary,
    pub discrepancies: Vec<Discrepancy>,
    pub similarity_score: f64,
}

/// Lightweight summary of a response for comparison purposes.
#[derive(Debug, Clone)]
pub struct ResponseSummary {
    pub status_code: u16,
    pub body_length: usize,
    pub response_time_ms: u64,
    pub header_count: usize,
    pub content_type: Option<String>,
    pub has_error_body: bool,
}

impl ResponseSummary {
    pub fn from_response(response: &FuzzResponse) -> Self {
        let content_type = response
            .headers
            .iter()
            .find(|(n, _)| n.to_lowercase() == "content-type")
            .map(|(_, v)| v.clone());
        let lower_body = response.body.to_lowercase();
        let has_error_body = lower_body.contains("error")
            || lower_body.contains("exception")
            || lower_body.contains("traceback")
            || lower_body.contains("stack trace");

        Self {
            status_code: response.status_code,
            body_length: response.body_size_bytes,
            response_time_ms: response.response_time.as_millis() as u64,
            header_count: response.headers.len(),
            content_type,
            has_error_body,
        }
    }
}

/// Comparative fuzzer that detects security regressions and inconsistencies
/// by sending the same input to different endpoints/versions and comparing responses.
///
/// Use cases:
/// - Compare v1/v2 API for security regression
/// - Compare dev/staging/prod for config differences
/// - Detect inconsistent validation across endpoints
pub struct ComparativeFuzzer {
    targets: Vec<ComparisonTarget>,
    results: Vec<ComparisonResult>,
    body_length_tolerance: f64,
    timing_tolerance_ms: u64,
}

impl ComparativeFuzzer {
    pub fn new() -> Self {
        Self {
            targets: Vec::new(),
            results: Vec::new(),
            body_length_tolerance: 0.1,
            timing_tolerance_ms: 500,
        }
    }

    pub fn with_body_length_tolerance(mut self, tolerance: f64) -> Self {
        self.body_length_tolerance = tolerance;
        self
    }

    pub fn with_timing_tolerance_ms(mut self, tolerance_ms: u64) -> Self {
        self.timing_tolerance_ms = tolerance_ms;
        self
    }

    /// Add a comparison target pair.
    pub fn add_target(&mut self, target: ComparisonTarget) {
        self.targets.push(target);
    }

    /// Compare two responses for the same payload and record discrepancies.
    pub fn compare(
        &mut self,
        payload: &str,
        endpoint_a: &str,
        response_a: &FuzzResponse,
        endpoint_b: &str,
        response_b: &FuzzResponse,
    ) -> ComparisonResult {
        let summary_a = ResponseSummary::from_response(response_a);
        let summary_b = ResponseSummary::from_response(response_b);

        let mut discrepancies = Vec::new();

        check_status_code(
            payload,
            endpoint_a,
            endpoint_b,
            &summary_a,
            &summary_b,
            &mut discrepancies,
        );
        check_body_length(
            payload,
            endpoint_a,
            endpoint_b,
            &summary_a,
            &summary_b,
            self.body_length_tolerance,
            &mut discrepancies,
        );
        check_validation(
            payload,
            endpoint_a,
            endpoint_b,
            response_a,
            response_b,
            &summary_a,
            &summary_b,
            &mut discrepancies,
        );
        check_error_handling(
            payload,
            endpoint_a,
            endpoint_b,
            &summary_a,
            &summary_b,
            &mut discrepancies,
        );
        check_auth_discrepancy(
            payload,
            endpoint_a,
            endpoint_b,
            response_a,
            response_b,
            &mut discrepancies,
        );
        check_headers(
            payload,
            endpoint_a,
            endpoint_b,
            response_a,
            response_b,
            &mut discrepancies,
        );
        check_timing(
            payload,
            endpoint_a,
            endpoint_b,
            &summary_a,
            &summary_b,
            self.timing_tolerance_ms,
            &mut discrepancies,
        );
        check_content_structure(
            payload,
            endpoint_a,
            endpoint_b,
            response_a,
            response_b,
            &mut discrepancies,
        );

        let similarity = compute_similarity(&summary_a, &summary_b);

        let result = ComparisonResult {
            payload: payload.to_string(),
            response_a: summary_a,
            response_b: summary_b,
            discrepancies,
            similarity_score: similarity,
        };

        self.results.push(result.clone());
        result
    }

    pub fn targets(&self) -> &[ComparisonTarget] {
        &self.targets
    }

    pub fn results(&self) -> &[ComparisonResult] {
        &self.results
    }

    /// Return all high+ severity discrepancies across all comparisons.
    pub fn critical_findings(&self) -> Vec<&Discrepancy> {
        self.results
            .iter()
            .flat_map(|r| r.discrepancies.iter())
            .filter(|d| d.severity >= DiscrepancySeverity::High)
            .collect()
    }

    /// Summary of discrepancy types and their counts.
    pub fn discrepancy_summary(&self) -> HashMap<DiscrepancyType, usize> {
        let mut counts = HashMap::new();
        for result in &self.results {
            for d in &result.discrepancies {
                *counts.entry(d.discrepancy_type).or_insert(0) += 1;
            }
        }
        counts
    }
}

impl Default for ComparativeFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

fn check_status_code(
    payload: &str,
    endpoint_a: &str,
    endpoint_b: &str,
    a: &ResponseSummary,
    b: &ResponseSummary,
    out: &mut Vec<Discrepancy>,
) {
    if a.status_code != b.status_code {
        let severity = classify_status_severity(a.status_code, b.status_code);
        out.push(Discrepancy {
            discrepancy_type: DiscrepancyType::StatusCodeMismatch,
            severity,
            description: format!(
                "Status code mismatch: {} returned {}, {} returned {}",
                endpoint_a, a.status_code, endpoint_b, b.status_code
            ),
            payload: payload.to_string(),
            endpoint_a: endpoint_a.to_string(),
            endpoint_b: endpoint_b.to_string(),
            detail_a: a.status_code.to_string(),
            detail_b: b.status_code.to_string(),
        });
    }
}

fn check_body_length(
    payload: &str,
    endpoint_a: &str,
    endpoint_b: &str,
    a: &ResponseSummary,
    b: &ResponseSummary,
    tolerance: f64,
    out: &mut Vec<Discrepancy>,
) {
    let max_len = a.body_length.max(b.body_length);
    if max_len == 0 {
        return;
    }
    let diff = (a.body_length as f64 - b.body_length as f64).abs();
    let ratio = diff / max_len as f64;

    if ratio > tolerance {
        out.push(Discrepancy {
            discrepancy_type: DiscrepancyType::BodyLengthDivergence,
            severity: if ratio > 0.5 {
                DiscrepancySeverity::Medium
            } else {
                DiscrepancySeverity::Low
            },
            description: format!(
                "Body length divergence: {} bytes vs {} bytes ({:.0}% difference)",
                a.body_length,
                b.body_length,
                ratio * 100.0
            ),
            payload: payload.to_string(),
            endpoint_a: endpoint_a.to_string(),
            endpoint_b: endpoint_b.to_string(),
            detail_a: a.body_length.to_string(),
            detail_b: b.body_length.to_string(),
        });
    }
}

fn check_validation(
    payload: &str,
    endpoint_a: &str,
    endpoint_b: &str,
    response_a: &FuzzResponse,
    response_b: &FuzzResponse,
    a: &ResponseSummary,
    b: &ResponseSummary,
    out: &mut Vec<Discrepancy>,
) {
    let a_accepted = a.status_code >= 200 && a.status_code < 300;
    let b_accepted = b.status_code >= 200 && b.status_code < 300;
    let a_rejected = a.status_code == 400 || a.status_code == 422;
    let b_rejected = b.status_code == 400 || b.status_code == 422;

    if (a_accepted && b_rejected) || (a_rejected && b_accepted) {
        let accepting = if a_accepted { endpoint_a } else { endpoint_b };
        let rejecting = if a_accepted { endpoint_b } else { endpoint_a };

        out.push(Discrepancy {
            discrepancy_type: DiscrepancyType::ValidationInconsistency,
            severity: DiscrepancySeverity::High,
            description: format!(
                "Validation inconsistency: {} accepts input that {} rejects",
                accepting, rejecting
            ),
            payload: payload.to_string(),
            endpoint_a: endpoint_a.to_string(),
            endpoint_b: endpoint_b.to_string(),
            detail_a: format!(
                "status={}, body_len={}",
                a.status_code,
                response_a.body.len()
            ),
            detail_b: format!(
                "status={}, body_len={}",
                b.status_code,
                response_b.body.len()
            ),
        });
    }
}

fn check_error_handling(
    payload: &str,
    endpoint_a: &str,
    endpoint_b: &str,
    a: &ResponseSummary,
    b: &ResponseSummary,
    out: &mut Vec<Discrepancy>,
) {
    if a.has_error_body != b.has_error_body {
        let leaking = if a.has_error_body {
            endpoint_a
        } else {
            endpoint_b
        };
        out.push(Discrepancy {
            discrepancy_type: DiscrepancyType::ErrorHandlingDifference,
            severity: DiscrepancySeverity::Medium,
            description: format!(
                "Error handling difference: {} leaks error details while the other does not",
                leaking
            ),
            payload: payload.to_string(),
            endpoint_a: endpoint_a.to_string(),
            endpoint_b: endpoint_b.to_string(),
            detail_a: format!("has_error_body={}", a.has_error_body),
            detail_b: format!("has_error_body={}", b.has_error_body),
        });
    }
}

fn check_auth_discrepancy(
    payload: &str,
    endpoint_a: &str,
    endpoint_b: &str,
    response_a: &FuzzResponse,
    response_b: &FuzzResponse,
    out: &mut Vec<Discrepancy>,
) {
    let a_auth = response_a.status_code == 401 || response_a.status_code == 403;
    let b_auth = response_b.status_code == 401 || response_b.status_code == 403;
    let a_ok = response_a.status_code >= 200 && response_a.status_code < 300;
    let b_ok = response_b.status_code >= 200 && response_b.status_code < 300;

    if (a_auth && b_ok) || (a_ok && b_auth) {
        let bypassed = if a_ok && b_auth {
            endpoint_a
        } else {
            endpoint_b
        };
        out.push(Discrepancy {
            discrepancy_type: DiscrepancyType::AuthDiscrepancy,
            severity: DiscrepancySeverity::Critical,
            description: format!(
                "Auth discrepancy: {} bypasses authentication that {} enforces",
                bypassed,
                if bypassed == endpoint_a {
                    endpoint_b
                } else {
                    endpoint_a
                }
            ),
            payload: payload.to_string(),
            endpoint_a: endpoint_a.to_string(),
            endpoint_b: endpoint_b.to_string(),
            detail_a: response_a.status_code.to_string(),
            detail_b: response_b.status_code.to_string(),
        });
    }
}

fn check_headers(
    payload: &str,
    endpoint_a: &str,
    endpoint_b: &str,
    response_a: &FuzzResponse,
    response_b: &FuzzResponse,
    out: &mut Vec<Discrepancy>,
) {
    let security_headers = [
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "content-security-policy",
        "x-xss-protection",
    ];

    let headers_a: Vec<String> = response_a
        .headers
        .iter()
        .map(|(n, _)| n.to_lowercase())
        .collect();
    let headers_b: Vec<String> = response_b
        .headers
        .iter()
        .map(|(n, _)| n.to_lowercase())
        .collect();

    for header in &security_headers {
        let in_a = headers_a.contains(&header.to_string());
        let in_b = headers_b.contains(&header.to_string());
        if in_a != in_b {
            let missing_from = if in_a { endpoint_b } else { endpoint_a };
            out.push(Discrepancy {
                discrepancy_type: DiscrepancyType::HeaderDivergence,
                severity: DiscrepancySeverity::Medium,
                description: format!("Security header '{}' missing from {}", header, missing_from),
                payload: payload.to_string(),
                endpoint_a: endpoint_a.to_string(),
                endpoint_b: endpoint_b.to_string(),
                detail_a: format!("present={}", in_a),
                detail_b: format!("present={}", in_b),
            });
        }
    }
}

fn check_timing(
    payload: &str,
    endpoint_a: &str,
    endpoint_b: &str,
    a: &ResponseSummary,
    b: &ResponseSummary,
    tolerance_ms: u64,
    out: &mut Vec<Discrepancy>,
) {
    let diff = (a.response_time_ms as i64 - b.response_time_ms as i64).unsigned_abs();
    if diff > tolerance_ms {
        out.push(Discrepancy {
            discrepancy_type: DiscrepancyType::TimingDivergence,
            severity: if diff > 5000 {
                DiscrepancySeverity::High
            } else {
                DiscrepancySeverity::Low
            },
            description: format!(
                "Timing divergence: {}ms vs {}ms ({}ms difference)",
                a.response_time_ms, b.response_time_ms, diff
            ),
            payload: payload.to_string(),
            endpoint_a: endpoint_a.to_string(),
            endpoint_b: endpoint_b.to_string(),
            detail_a: format!("{}ms", a.response_time_ms),
            detail_b: format!("{}ms", b.response_time_ms),
        });
    }
}

fn check_content_structure(
    payload: &str,
    endpoint_a: &str,
    endpoint_b: &str,
    response_a: &FuzzResponse,
    response_b: &FuzzResponse,
    out: &mut Vec<Discrepancy>,
) {
    let a_json = serde_json::from_str::<serde_json::Value>(&response_a.body).ok();
    let b_json = serde_json::from_str::<serde_json::Value>(&response_b.body).ok();

    match (a_json, b_json) {
        (Some(a_val), Some(b_val)) => {
            let keys_a = extract_keys(&a_val);
            let keys_b = extract_keys(&b_val);
            if keys_a != keys_b {
                out.push(Discrepancy {
                    discrepancy_type: DiscrepancyType::ContentStructureDifference,
                    severity: DiscrepancySeverity::Low,
                    description: format!(
                        "JSON key structure differs: {} has keys [{}], {} has keys [{}]",
                        endpoint_a,
                        keys_a.join(", "),
                        endpoint_b,
                        keys_b.join(", ")
                    ),
                    payload: payload.to_string(),
                    endpoint_a: endpoint_a.to_string(),
                    endpoint_b: endpoint_b.to_string(),
                    detail_a: keys_a.join(", "),
                    detail_b: keys_b.join(", "),
                });
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            out.push(Discrepancy {
                discrepancy_type: DiscrepancyType::ContentStructureDifference,
                severity: DiscrepancySeverity::Medium,
                description: "One response is JSON, the other is not".to_string(),
                payload: payload.to_string(),
                endpoint_a: endpoint_a.to_string(),
                endpoint_b: endpoint_b.to_string(),
                detail_a: if response_a.body.starts_with('{') {
                    "JSON".to_string()
                } else {
                    "non-JSON".to_string()
                },
                detail_b: if response_b.body.starts_with('{') {
                    "JSON".to_string()
                } else {
                    "non-JSON".to_string()
                },
            });
        }
        _ => {}
    }
}

fn extract_keys(value: &serde_json::Value) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(obj) = value.as_object() {
        for key in obj.keys() {
            keys.push(key.clone());
        }
    }
    keys.sort();
    keys
}

fn classify_status_severity(a: u16, b: u16) -> DiscrepancySeverity {
    let a_class = a / 100;
    let b_class = b / 100;
    if a_class == b_class {
        return DiscrepancySeverity::Low;
    }
    if (a_class == 2 && b_class == 4) || (a_class == 4 && b_class == 2) {
        return DiscrepancySeverity::High;
    }
    if (a_class == 2 && b_class == 5) || (a_class == 5 && b_class == 2) {
        return DiscrepancySeverity::High;
    }
    DiscrepancySeverity::Medium
}

fn compute_similarity(a: &ResponseSummary, b: &ResponseSummary) -> f64 {
    let mut score: f64 = 0.0;
    let mut dimensions: f64 = 0.0;

    dimensions += 1.0;
    if a.status_code == b.status_code {
        score += 1.0;
    } else if a.status_code / 100 == b.status_code / 100 {
        score += 0.5;
    }

    dimensions += 1.0;
    let max_len = a.body_length.max(b.body_length) as f64;
    if max_len > 0.0 {
        let len_sim = 1.0 - (a.body_length as f64 - b.body_length as f64).abs() / max_len;
        score += len_sim;
    } else {
        score += 1.0;
    }

    dimensions += 1.0;
    let max_time = a.response_time_ms.max(b.response_time_ms) as f64;
    if max_time > 0.0 {
        let time_sim =
            1.0 - (a.response_time_ms as f64 - b.response_time_ms as f64).abs() / max_time;
        score += time_sim;
    } else {
        score += 1.0;
    }

    dimensions += 1.0;
    if a.content_type == b.content_type {
        score += 1.0;
    }

    score / dimensions
}
