use std::time::Duration;

use crate::comparative_fuzzer::{
    ComparativeFuzzer, ComparisonTarget, DiscrepancySeverity, DiscrepancyType,
};
use crate::executor::FuzzResponse;

fn make_response(
    status: u16,
    body: &str,
    time_ms: u64,
    headers: Vec<(&str, &str)>,
) -> FuzzResponse {
    FuzzResponse {
        request_id: 1,
        status_code: status,
        body: body.to_string(),
        headers: headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        response_time: Duration::from_millis(time_ms),
        body_size_bytes: body.len(),
    }
}

fn json_headers() -> Vec<(&'static str, &'static str)> {
    vec![("content-type", "application/json")]
}

#[test]
fn identical_responses_no_discrepancies() {
    let mut fuzzer = ComparativeFuzzer::new();
    let resp = make_response(200, "{\"ok\": true}", 50, json_headers());
    let result = fuzzer.compare("payload", "/v1/api", &resp, "/v2/api", &resp);
    assert!(result.discrepancies.is_empty());
    assert!(result.similarity_score > 0.9);
}

#[test]
fn status_code_mismatch_detected() {
    let mut fuzzer = ComparativeFuzzer::new();
    let resp_a = make_response(200, "ok", 50, json_headers());
    let resp_b = make_response(500, "error", 50, json_headers());
    let result = fuzzer.compare("payload", "/v1/api", &resp_a, "/v2/api", &resp_b);
    let status_discs: Vec<_> = result
        .discrepancies
        .iter()
        .filter(|d| d.discrepancy_type == DiscrepancyType::StatusCodeMismatch)
        .collect();
    assert!(!status_discs.is_empty());
    assert!(status_discs[0].severity >= DiscrepancySeverity::High);
}

#[test]
fn body_length_divergence_detected() {
    let mut fuzzer = ComparativeFuzzer::new().with_body_length_tolerance(0.1);
    let resp_a = make_response(200, "short", 50, json_headers());
    let resp_b = make_response(200, &"x".repeat(1000), 50, json_headers());
    let result = fuzzer.compare("payload", "/v1/api", &resp_a, "/v2/api", &resp_b);
    let length_discs: Vec<_> = result
        .discrepancies
        .iter()
        .filter(|d| d.discrepancy_type == DiscrepancyType::BodyLengthDivergence)
        .collect();
    assert!(!length_discs.is_empty());
}

#[test]
fn validation_inconsistency_detected() {
    let mut fuzzer = ComparativeFuzzer::new();
    let resp_a = make_response(200, "{\"result\": \"ok\"}", 50, json_headers());
    let resp_b = make_response(400, "{\"error\": \"invalid input\"}", 50, json_headers());
    let result = fuzzer.compare("' OR '1'='1", "/v1/api", &resp_a, "/v2/api", &resp_b);
    let validation_discs: Vec<_> = result
        .discrepancies
        .iter()
        .filter(|d| d.discrepancy_type == DiscrepancyType::ValidationInconsistency)
        .collect();
    assert!(!validation_discs.is_empty());
    assert!(validation_discs[0].severity >= DiscrepancySeverity::High);
}

#[test]
fn error_handling_difference_detected() {
    let mut fuzzer = ComparativeFuzzer::new();
    let resp_a = make_response(
        500,
        "Stack trace: NullPointerException at...",
        50,
        json_headers(),
    );
    let resp_b = make_response(
        500,
        "Something went wrong. Please try again.",
        50,
        json_headers(),
    );
    let result = fuzzer.compare("crash", "/v1/api", &resp_a, "/v2/api", &resp_b);
    let error_discs: Vec<_> = result
        .discrepancies
        .iter()
        .filter(|d| d.discrepancy_type == DiscrepancyType::ErrorHandlingDifference)
        .collect();
    assert!(!error_discs.is_empty());
}

#[test]
fn auth_discrepancy_detected() {
    let mut fuzzer = ComparativeFuzzer::new();
    let resp_a = make_response(200, "{\"data\": \"secret\"}", 50, json_headers());
    let resp_b = make_response(403, "Forbidden", 50, json_headers());
    let result = fuzzer.compare("no_token", "/v1/api", &resp_a, "/v2/api", &resp_b);
    let auth_discs: Vec<_> = result
        .discrepancies
        .iter()
        .filter(|d| d.discrepancy_type == DiscrepancyType::AuthDiscrepancy)
        .collect();
    assert!(!auth_discs.is_empty());
    assert_eq!(auth_discs[0].severity, DiscrepancySeverity::Critical);
}

#[test]
fn header_divergence_detected() {
    let mut fuzzer = ComparativeFuzzer::new();
    let resp_a = make_response(
        200,
        "ok",
        50,
        vec![
            ("content-type", "application/json"),
            ("strict-transport-security", "max-age=31536000"),
            ("x-content-type-options", "nosniff"),
        ],
    );
    let resp_b = make_response(200, "ok", 50, vec![("content-type", "application/json")]);
    let result = fuzzer.compare("test", "/v1/api", &resp_a, "/v2/api", &resp_b);
    let header_discs: Vec<_> = result
        .discrepancies
        .iter()
        .filter(|d| d.discrepancy_type == DiscrepancyType::HeaderDivergence)
        .collect();
    assert!(!header_discs.is_empty());
}

#[test]
fn timing_divergence_detected() {
    let mut fuzzer = ComparativeFuzzer::new().with_timing_tolerance_ms(100);
    let resp_a = make_response(200, "ok", 50, json_headers());
    let resp_b = make_response(200, "ok", 5000, json_headers());
    let result = fuzzer.compare("timing_test", "/v1/api", &resp_a, "/v2/api", &resp_b);
    let timing_discs: Vec<_> = result
        .discrepancies
        .iter()
        .filter(|d| d.discrepancy_type == DiscrepancyType::TimingDivergence)
        .collect();
    assert!(!timing_discs.is_empty());
}

#[test]
fn content_structure_difference_detected() {
    let mut fuzzer = ComparativeFuzzer::new();
    let resp_a = make_response(
        200,
        "{\"name\": \"alice\", \"age\": 30}",
        50,
        json_headers(),
    );
    let resp_b = make_response(
        200,
        "{\"name\": \"alice\", \"age\": 30, \"secret\": \"admin_key\"}",
        50,
        json_headers(),
    );
    let result = fuzzer.compare("probe", "/v1/api", &resp_a, "/v2/api", &resp_b);
    let struct_discs: Vec<_> = result
        .discrepancies
        .iter()
        .filter(|d| d.discrepancy_type == DiscrepancyType::ContentStructureDifference)
        .collect();
    assert!(!struct_discs.is_empty());
}

#[test]
fn critical_findings_filters_high_severity() {
    let mut fuzzer = ComparativeFuzzer::new();
    let resp_a = make_response(200, "data", 50, json_headers());
    let resp_b = make_response(403, "forbidden", 50, json_headers());
    fuzzer.compare("test", "/v1", &resp_a, "/v2", &resp_b);
    let critical = fuzzer.critical_findings();
    assert!(!critical.is_empty());
    for f in &critical {
        assert!(f.severity >= DiscrepancySeverity::High);
    }
}

#[test]
fn discrepancy_summary_counts() {
    let mut fuzzer = ComparativeFuzzer::new();
    let resp_a = make_response(200, "ok", 50, json_headers());
    let resp_b = make_response(500, "error body", 50, json_headers());
    fuzzer.compare("p1", "/v1", &resp_a, "/v2", &resp_b);
    fuzzer.compare("p2", "/v1", &resp_a, "/v2", &resp_b);
    let summary = fuzzer.discrepancy_summary();
    assert!(summary.contains_key(&DiscrepancyType::StatusCodeMismatch));
}

#[test]
fn add_target() {
    let mut fuzzer = ComparativeFuzzer::new();
    fuzzer.add_target(ComparisonTarget {
        label_a: "v1".to_string(),
        endpoint_a: "http://localhost:3000/v1".to_string(),
        label_b: "v2".to_string(),
        endpoint_b: "http://localhost:3000/v2".to_string(),
    });
    assert_eq!(fuzzer.targets().len(), 1);
}

#[test]
fn results_accumulate() {
    let mut fuzzer = ComparativeFuzzer::new();
    let resp = make_response(200, "ok", 50, json_headers());
    fuzzer.compare("p1", "/v1", &resp, "/v2", &resp);
    fuzzer.compare("p2", "/v1", &resp, "/v2", &resp);
    fuzzer.compare("p3", "/v1", &resp, "/v2", &resp);
    assert_eq!(fuzzer.results().len(), 3);
}

#[test]
fn similarity_score_high_for_identical() {
    let mut fuzzer = ComparativeFuzzer::new();
    let resp = make_response(200, "{\"ok\": true}", 50, json_headers());
    let result = fuzzer.compare("payload", "/v1", &resp, "/v2", &resp);
    assert!(result.similarity_score > 0.95);
}

#[test]
fn similarity_score_low_for_different() {
    let mut fuzzer = ComparativeFuzzer::new();
    let resp_a = make_response(200, "{\"ok\": true}", 50, json_headers());
    let resp_b = make_response(500, "error", 5000, vec![("content-type", "text/html")]);
    let result = fuzzer.compare("payload", "/v1", &resp_a, "/v2", &resp_b);
    assert!(result.similarity_score < 0.5);
}

#[test]
fn default_trait_works() {
    let fuzzer = ComparativeFuzzer::default();
    assert!(fuzzer.results().is_empty());
    assert!(fuzzer.targets().is_empty());
}

#[test]
fn severity_ordering() {
    assert!(DiscrepancySeverity::Critical > DiscrepancySeverity::High);
    assert!(DiscrepancySeverity::High > DiscrepancySeverity::Medium);
    assert!(DiscrepancySeverity::Medium > DiscrepancySeverity::Low);
}

#[test]
fn response_summary_detects_error_body() {
    use crate::comparative_fuzzer::ResponseSummary;
    let resp = make_response(500, "Fatal exception occurred", 50, json_headers());
    let summary = ResponseSummary::from_response(&resp);
    assert!(summary.has_error_body);
    assert_eq!(summary.status_code, 500);
}
