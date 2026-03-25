use std::time::Duration;

use crate::coverage_guided_fuzzer::{CoverageGuidedFuzzer, CrashType, PowerSchedule};
use crate::executor::FuzzResponse;

fn make_response(status: u16, body: &str, time_ms: u64) -> FuzzResponse {
    FuzzResponse {
        request_id: 1,
        status_code: status,
        body: body.to_string(),
        headers: vec![("content-type".to_string(), "text/html".to_string())],
        response_time: Duration::from_millis(time_ms),
        body_size_bytes: body.len(),
    }
}

#[test]
fn novel_payload_added_to_corpus() {
    let mut fuzzer = CoverageGuidedFuzzer::new();
    let resp = make_response(200, "ok", 10);
    let novel = fuzzer.record_execution("test1", &resp);
    assert!(novel);
    assert_eq!(fuzzer.corpus_size(), 1);
    assert_eq!(fuzzer.coverage_count(), 1);
}

#[test]
fn duplicate_response_not_added() {
    let mut fuzzer = CoverageGuidedFuzzer::new();
    let resp = make_response(200, "ok", 10);
    fuzzer.record_execution("test1", &resp);
    let novel = fuzzer.record_execution("test2", &resp);
    assert!(!novel);
    assert_eq!(fuzzer.corpus_size(), 1);
}

#[test]
fn different_status_codes_are_novel() {
    let mut fuzzer = CoverageGuidedFuzzer::new();
    let r200 = make_response(200, "ok", 10);
    let r404 = make_response(404, "not found", 10);
    let r500 = make_response(500, "error", 10);

    assert!(fuzzer.record_execution("p1", &r200));
    assert!(fuzzer.record_execution("p2", &r404));
    assert!(fuzzer.record_execution("p3", &r500));
    assert_eq!(fuzzer.corpus_size(), 3);
}

#[test]
fn crash_detection_server_error() {
    let mut fuzzer = CoverageGuidedFuzzer::new();
    let resp = make_response(500, "internal server error", 10);
    fuzzer.record_execution("crash_payload", &resp);
    assert_eq!(fuzzer.crashes().len(), 1);
    assert_eq!(fuzzer.crashes()[0].crash_type, CrashType::ServerError);
    assert_eq!(fuzzer.crashes()[0].payload, "crash_payload");
}

#[test]
fn crash_detection_timeout() {
    let mut fuzzer = CoverageGuidedFuzzer::new();
    let resp = make_response(200, "slow", 15_000);
    fuzzer.record_execution("slow_payload", &resp);
    assert_eq!(fuzzer.crashes().len(), 1);
    assert_eq!(fuzzer.crashes()[0].crash_type, CrashType::Timeout);
}

#[test]
fn crash_detection_empty_response() {
    let mut fuzzer = CoverageGuidedFuzzer::new();
    let resp = make_response(200, "", 10);
    fuzzer.record_execution("empty_payload", &resp);
    assert_eq!(fuzzer.crashes().len(), 1);
    assert_eq!(fuzzer.crashes()[0].crash_type, CrashType::EmptyResponse);
}

#[test]
fn crash_deduplication() {
    let mut fuzzer = CoverageGuidedFuzzer::new();
    let resp = make_response(500, "error", 10);
    fuzzer.record_execution("same", &resp);
    fuzzer.record_execution("same", &resp);
    assert_eq!(fuzzer.crashes().len(), 1);
}

#[test]
fn select_input_returns_none_when_empty() {
    let fuzzer = CoverageGuidedFuzzer::new();
    assert!(fuzzer.select_input().is_none());
}

#[test]
fn select_input_returns_entry_when_corpus_nonempty() {
    let mut fuzzer = CoverageGuidedFuzzer::new();
    let resp = make_response(200, "ok", 10);
    fuzzer.record_execution("seed", &resp);
    let entry = fuzzer.select_input().unwrap();
    assert_eq!(entry.payload, "seed");
}

#[test]
fn power_schedule_path_favored() {
    let mut fuzzer = CoverageGuidedFuzzer::new().with_power_schedule(PowerSchedule::PathFavored);
    let r1 = make_response(200, "ok", 10);
    let r2 = make_response(404, "not found", 10);
    fuzzer.record_execution("p1", &r1);
    fuzzer.record_execution("p2", &r2);
    fuzzer.record_novel_child(0);
    fuzzer.record_novel_child(0);
    fuzzer.record_novel_child(0);
    assert!(fuzzer.corpus()[0].novel_children > fuzzer.corpus()[1].novel_children);
}

#[test]
fn power_schedule_exponential_backoff() {
    let mut fuzzer =
        CoverageGuidedFuzzer::new().with_power_schedule(PowerSchedule::ExponentialBackoff);
    let resp = make_response(200, "ok", 10);
    fuzzer.record_execution("p1", &resp);
    let initial_energy = fuzzer.corpus()[0].energy;
    for _ in 0..10 {
        fuzzer.record_mutation(0);
    }
    assert!(fuzzer.corpus()[0].energy < initial_energy);
}

#[test]
fn executions_since_novel_tracks_correctly() {
    let mut fuzzer = CoverageGuidedFuzzer::new();
    let r1 = make_response(200, "ok", 10);
    fuzzer.record_execution("p1", &r1);
    assert_eq!(fuzzer.executions_since_novel(), 0);
    fuzzer.record_execution("p2", &r1);
    assert_eq!(fuzzer.executions_since_novel(), 1);
    fuzzer.record_execution("p3", &r1);
    assert_eq!(fuzzer.executions_since_novel(), 2);
}

#[test]
fn max_corpus_size_eviction() {
    let mut fuzzer = CoverageGuidedFuzzer::new().with_max_corpus_size(3);
    for i in 0..5 {
        let body = format!("response_{}", i);
        let resp = make_response(200 + i as u16, &body, 10);
        fuzzer.record_execution(&format!("p{}", i), &resp);
    }
    assert!(fuzzer.corpus_size() <= 3);
}

#[test]
fn minimize_input_finds_shorter_payload() {
    let fuzzer = CoverageGuidedFuzzer::new();
    let minimized = fuzzer.minimize_input("AAAA<script>alert(1)</script>BBBB", 42, |candidate| {
        if candidate.contains("<script>") {
            Some(FuzzResponse {
                request_id: 1,
                status_code: 500,
                body: "error".to_string(),
                headers: vec![],
                response_time: Duration::from_millis(10),
                body_size_bytes: 5,
            })
        } else {
            Some(FuzzResponse {
                request_id: 1,
                status_code: 200,
                body: "ok".to_string(),
                headers: vec![],
                response_time: Duration::from_millis(10),
                body_size_bytes: 2,
            })
        }
    });
    assert!(minimized.len() <= "AAAA<script>alert(1)</script>BBBB".len());
}

#[test]
fn total_executions_counted() {
    let mut fuzzer = CoverageGuidedFuzzer::new();
    let resp = make_response(200, "ok", 10);
    for _ in 0..5 {
        fuzzer.record_execution("p", &resp);
    }
    assert_eq!(fuzzer.total_executions(), 5);
}

#[test]
fn different_body_structures_are_novel() {
    let mut fuzzer = CoverageGuidedFuzzer::new();
    let json_resp = make_response(200, "{\"key\": \"value\"}", 10);
    let html_resp = make_response(200, "<html><body>hello</body></html>", 10);
    assert!(fuzzer.record_execution("p1", &json_resp));
    assert!(fuzzer.record_execution("p2", &html_resp));
    assert_eq!(fuzzer.corpus_size(), 2);
}

#[test]
fn uniform_power_schedule_works() {
    let mut fuzzer = CoverageGuidedFuzzer::new().with_power_schedule(PowerSchedule::Uniform);
    let r1 = make_response(200, "ok", 10);
    let r2 = make_response(404, "nope", 10);
    fuzzer.record_execution("p1", &r1);
    fuzzer.record_execution("p2", &r2);
    assert!(fuzzer.select_input().is_some());
}

#[test]
fn recency_biased_schedule_works() {
    let mut fuzzer = CoverageGuidedFuzzer::new().with_power_schedule(PowerSchedule::RecencyBiased);
    let r1 = make_response(200, "ok", 10);
    let r2 = make_response(404, "nope", 10);
    fuzzer.record_execution("p1", &r1);
    fuzzer.record_execution("p2", &r2);
    assert!(fuzzer.select_input().is_some());
}

#[test]
fn default_trait_works() {
    let fuzzer = CoverageGuidedFuzzer::default();
    assert_eq!(fuzzer.total_executions(), 0);
    assert_eq!(fuzzer.corpus_size(), 0);
}
