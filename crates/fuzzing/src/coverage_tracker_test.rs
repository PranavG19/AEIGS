use std::time::Duration;

use crate::coverage_tracker::{CoverageResult, CoverageTracker, duration_to_bucket};
use crate::executor::FuzzResponse;

fn make_response(
    status_code: u16,
    body: &str,
    headers: Vec<(&str, &str)>,
    response_time_ms: u64,
) -> FuzzResponse {
    FuzzResponse {
        request_id: 1,
        status_code,
        body: body.to_string(),
        headers: headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        response_time: Duration::from_millis(response_time_ms),
        body_size_bytes: body.len(),
    }
}

// ─── Timing bucket tests ───

#[test]
fn timing_bucket_under_10ms() {
    assert_eq!(duration_to_bucket(Duration::from_millis(5)), 0);
}

#[test]
fn timing_bucket_under_100ms() {
    assert_eq!(duration_to_bucket(Duration::from_millis(50)), 1);
}

#[test]
fn timing_bucket_under_500ms() {
    assert_eq!(duration_to_bucket(Duration::from_millis(250)), 2);
}

#[test]
fn timing_bucket_under_1s() {
    assert_eq!(duration_to_bucket(Duration::from_millis(800)), 3);
}

#[test]
fn timing_bucket_over_1s() {
    assert_eq!(duration_to_bucket(Duration::from_millis(2000)), 4);
}

#[test]
fn timing_bucket_boundary_10ms() {
    assert_eq!(duration_to_bucket(Duration::from_millis(10)), 1);
}

// ─── Status bucket tests ───

#[test]
fn status_bucket_2xx() {
    let resp = make_response(200, "", vec![], 1);
    let mut tracker = CoverageTracker::new();
    if let CoverageResult::Novel(sig) = tracker.record(&resp, "p") {
        assert_eq!(sig.status_bucket, 2);
    } else {
        panic!("expected Novel");
    }
}

#[test]
fn status_bucket_4xx() {
    let resp = make_response(403, "Forbidden", vec![], 1);
    let mut tracker = CoverageTracker::new();
    if let CoverageResult::Novel(sig) = tracker.record(&resp, "p") {
        assert_eq!(sig.status_bucket, 4);
    } else {
        panic!("expected Novel");
    }
}

#[test]
fn status_bucket_5xx() {
    let resp = make_response(500, "error", vec![], 1);
    let mut tracker = CoverageTracker::new();
    if let CoverageResult::Novel(sig) = tracker.record(&resp, "p") {
        assert_eq!(sig.status_bucket, 5);
    } else {
        panic!("expected Novel");
    }
}

// ─── Body structure hashing ───

#[test]
fn json_body_structure() {
    let json_a = r#"{"name":"alice","age":30}"#;
    let json_b = r#"{"name":"bob","age":25}"#;
    let resp_a = make_response(200, json_a, vec![], 1);
    let resp_b = make_response(200, json_b, vec![], 1);
    let mut tracker = CoverageTracker::new();
    let res_a = tracker.record(&resp_a, "a");
    let res_b = tracker.record(&resp_b, "b");
    assert!(matches!(res_a, CoverageResult::Novel(_)));
    assert!(
        matches!(res_b, CoverageResult::Known(_)),
        "same JSON structure should produce same signature"
    );
}

#[test]
fn different_json_structures_are_distinct() {
    let json_a = r#"{"name":"alice"}"#;
    let json_b = r#"{"name":"bob","email":"b@b.com"}"#;
    let resp_a = make_response(200, json_a, vec![], 1);
    let resp_b = make_response(200, json_b, vec![], 1);
    let mut tracker = CoverageTracker::new();
    let res_a = tracker.record(&resp_a, "a");
    let res_b = tracker.record(&resp_b, "b");
    assert!(matches!(res_a, CoverageResult::Novel(_)));
    assert!(matches!(res_b, CoverageResult::Novel(_)));
}

#[test]
fn html_body_structure() {
    let html_a = "<html><body><h1>Hello</h1></body></html>";
    let html_b = "<html><body><h1>World</h1></body></html>";
    let resp_a = make_response(200, html_a, vec![], 1);
    let resp_b = make_response(200, html_b, vec![], 1);
    let mut tracker = CoverageTracker::new();
    let res_a = tracker.record(&resp_a, "a");
    let res_b = tracker.record(&resp_b, "b");
    assert!(matches!(res_a, CoverageResult::Novel(_)));
    assert!(
        matches!(res_b, CoverageResult::Known(_)),
        "same HTML structure should produce same signature"
    );
}

#[test]
fn different_html_structures_are_distinct() {
    let html_a = "<html><body><h1>Hello</h1></body></html>";
    let html_b = "<html><body><div><p>Hello</p></div></body></html>";
    let resp_a = make_response(200, html_a, vec![], 1);
    let resp_b = make_response(200, html_b, vec![], 1);
    let mut tracker = CoverageTracker::new();
    let res_a = tracker.record(&resp_a, "a");
    let res_b = tracker.record(&resp_b, "b");
    assert!(matches!(res_a, CoverageResult::Novel(_)));
    assert!(matches!(res_b, CoverageResult::Novel(_)));
}

#[test]
fn plain_text_body_structure() {
    let text_a = "short";
    let text_b = "also short";
    let resp_a = make_response(200, text_a, vec![], 1);
    let resp_b = make_response(200, text_b, vec![], 1);
    let mut tracker = CoverageTracker::new();
    let res_a = tracker.record(&resp_a, "a");
    let res_b = tracker.record(&resp_b, "b");
    assert!(matches!(res_a, CoverageResult::Novel(_)));
    assert!(
        matches!(res_b, CoverageResult::Known(_)),
        "same text size class should match"
    );
}

// ─── Error class extraction ───

#[test]
fn error_class_sql() {
    let resp = make_response(500, "SQL syntax error near 'DROP'", vec![], 1);
    let mut tracker = CoverageTracker::new();
    if let CoverageResult::Novel(sig) = tracker.record(&resp, "p") {
        assert_eq!(sig.error_class.as_deref(), Some("sql_error"));
    } else {
        panic!("expected Novel");
    }
}

#[test]
fn error_class_stack_trace() {
    let resp = make_response(
        500,
        "Traceback (most recent call last):\n  File ...",
        vec![],
        1,
    );
    let mut tracker = CoverageTracker::new();
    if let CoverageResult::Novel(sig) = tracker.record(&resp, "p") {
        assert_eq!(sig.error_class.as_deref(), Some("stack_trace"));
    } else {
        panic!("expected Novel");
    }
}

#[test]
fn error_class_none_for_clean_response() {
    let resp = make_response(200, r#"{"status":"ok"}"#, vec![], 1);
    let mut tracker = CoverageTracker::new();
    if let CoverageResult::Novel(sig) = tracker.record(&resp, "p") {
        assert!(sig.error_class.is_none());
    } else {
        panic!("expected Novel");
    }
}

#[test]
fn error_class_rate_limit() {
    let resp = make_response(429, "Rate limit exceeded. Too many requests.", vec![], 1);
    let mut tracker = CoverageTracker::new();
    if let CoverageResult::Novel(sig) = tracker.record(&resp, "p") {
        assert_eq!(sig.error_class.as_deref(), Some("rate_limit"));
    } else {
        panic!("expected Novel");
    }
}

// ─── Header set hashing ───

#[test]
fn same_headers_different_values_produce_same_hash() {
    let resp_a = make_response(200, "ok", vec![("Content-Type", "text/html")], 1);
    let resp_b = make_response(200, "ok", vec![("Content-Type", "application/json")], 1);
    let mut tracker = CoverageTracker::new();
    let res_a = tracker.record(&resp_a, "a");
    let res_b = tracker.record(&resp_b, "b");
    assert!(matches!(res_a, CoverageResult::Novel(_)));
    assert!(matches!(res_b, CoverageResult::Known(_)));
}

#[test]
fn different_header_sets_are_distinct() {
    let resp_a = make_response(200, "ok", vec![("Content-Type", "text/html")], 1);
    let resp_b = make_response(
        200,
        "ok",
        vec![("Content-Type", "text/html"), ("X-Custom", "val")],
        1,
    );
    let mut tracker = CoverageTracker::new();
    let res_a = tracker.record(&resp_a, "a");
    let res_b = tracker.record(&resp_b, "b");
    assert!(matches!(res_a, CoverageResult::Novel(_)));
    assert!(matches!(res_b, CoverageResult::Novel(_)));
}

// ─── Content length bucketing ───

#[test]
fn content_length_empty_bucket() {
    let resp = make_response(200, "", vec![], 1);
    let mut tracker = CoverageTracker::new();
    if let CoverageResult::Novel(sig) = tracker.record(&resp, "p") {
        assert_eq!(sig.content_length_bucket, 0);
    } else {
        panic!("expected Novel");
    }
}

#[test]
fn content_length_small_bucket() {
    let body = "a".repeat(100);
    let resp = make_response(200, &body, vec![], 1);
    let mut tracker = CoverageTracker::new();
    if let CoverageResult::Novel(sig) = tracker.record(&resp, "p") {
        assert_eq!(sig.content_length_bucket, 1);
    } else {
        panic!("expected Novel");
    }
}

// ─── CoverageTracker behavior ───

#[test]
fn novel_then_known() {
    let resp = make_response(200, "hello", vec![], 1);
    let mut tracker = CoverageTracker::new();
    assert!(matches!(
        tracker.record(&resp, "first"),
        CoverageResult::Novel(_)
    ));
    assert!(matches!(
        tracker.record(&resp, "second"),
        CoverageResult::Known(_)
    ));
}

#[test]
fn coverage_count_increments() {
    let mut tracker = CoverageTracker::new();
    assert_eq!(tracker.coverage_count(), 0);

    let r1 = make_response(200, "ok", vec![], 1);
    tracker.record(&r1, "p1");
    assert_eq!(tracker.coverage_count(), 1);

    let r2 = make_response(404, "not found", vec![], 1);
    tracker.record(&r2, "p2");
    assert_eq!(tracker.coverage_count(), 2);

    tracker.record(&r1, "p3");
    assert_eq!(
        tracker.coverage_count(),
        2,
        "duplicate should not increment"
    );
}

#[test]
fn is_novel_check() {
    let mut tracker = CoverageTracker::new();
    let resp = make_response(200, "ok", vec![], 1);
    if let CoverageResult::Novel(sig) = tracker.record(&resp, "p") {
        assert!(
            !tracker.is_novel(&sig),
            "after recording, the same sig should not be novel"
        );
    }
}

#[test]
fn priority_boost_novel_is_positive() {
    let resp = make_response(200, "ok", vec![], 1);
    let mut tracker = CoverageTracker::new();
    let result = tracker.record(&resp, "p");
    assert!(CoverageTracker::priority_boost(&result) > 0.0);
}

#[test]
fn priority_boost_known_is_zero() {
    let resp = make_response(200, "ok", vec![], 1);
    let mut tracker = CoverageTracker::new();
    tracker.record(&resp, "p");
    let result = tracker.record(&resp, "p");
    assert_eq!(CoverageTracker::priority_boost(&result), 0.0);
}

#[test]
fn history_tracks_discoveries() {
    let mut tracker = CoverageTracker::new();
    let r1 = make_response(200, "a", vec![], 1);
    let r2 = make_response(500, "b", vec![], 1);
    tracker.record(&r1, "payload_one");
    tracker.record(&r2, "payload_two");
    tracker.record(&r1, "payload_dup");

    let hist = tracker.history();
    assert_eq!(hist.len(), 2);
    assert_eq!(hist[0].1, "payload_one");
    assert_eq!(hist[1].1, "payload_two");
}

#[test]
fn default_trait() {
    let tracker = CoverageTracker::default();
    assert_eq!(tracker.coverage_count(), 0);
}

// ─── 8-path mock server simulation ───

#[test]
fn eight_distinct_code_paths() {
    let mut tracker = CoverageTracker::new();

    let paths: Vec<FuzzResponse> = vec![
        make_response(
            200,
            r#"{"status":"ok"}"#,
            vec![("Content-Type", "application/json")],
            5,
        ),
        make_response(
            200,
            "<html><body><h1>Welcome</h1></body></html>",
            vec![("Content-Type", "text/html")],
            5,
        ),
        make_response(
            404,
            r#"{"error":"not found"}"#,
            vec![("Content-Type", "application/json")],
            5,
        ),
        make_response(
            500,
            "Internal Server Error\nTraceback (most recent call last):\n  File ...",
            vec![],
            50,
        ),
        make_response(403, "Forbidden", vec![("X-WAF", "blocked")], 5),
        make_response(
            200,
            r#"{"users":[{"id":1,"name":"alice"}]}"#,
            vec![("Content-Type", "application/json")],
            200,
        ),
        make_response(302, "", vec![("Location", "/login")], 5),
        make_response(
            429,
            "Rate limit exceeded. Too many requests.",
            vec![("Retry-After", "60")],
            5,
        ),
    ];

    for (i, resp) in paths.iter().enumerate() {
        let result = tracker.record(resp, &format!("payload_{}", i));
        assert!(
            matches!(result, CoverageResult::Novel(_)),
            "path {} should be novel",
            i
        );
    }

    assert_eq!(tracker.coverage_count(), 8);
}

// ─── Nested JSON structure ───

#[test]
fn nested_json_captures_key_tree() {
    let json_a = r#"{"user":{"name":"alice","address":{"city":"ny"}}}"#;
    let json_b = r#"{"user":{"name":"bob","address":{"city":"la"}}}"#;
    let json_c = r#"{"user":{"name":"carol"}}"#;

    let mut tracker = CoverageTracker::new();
    let resp_a = make_response(200, json_a, vec![], 1);
    let resp_b = make_response(200, json_b, vec![], 1);
    let resp_c = make_response(200, json_c, vec![], 1);

    assert!(matches!(
        tracker.record(&resp_a, "a"),
        CoverageResult::Novel(_)
    ));
    assert!(
        matches!(tracker.record(&resp_b, "b"), CoverageResult::Known(_)),
        "same nested structure should match"
    );
    assert!(
        matches!(tracker.record(&resp_c, "c"), CoverageResult::Novel(_)),
        "different nested structure should be novel"
    );
}

// ─── JSON array structure ───

#[test]
fn json_array_structure() {
    let arr = r#"[{"id":1},{"id":2}]"#;
    let resp = make_response(200, arr, vec![], 1);
    let mut tracker = CoverageTracker::new();
    assert!(matches!(
        tracker.record(&resp, "p"),
        CoverageResult::Novel(_)
    ));
}

// ─── Empty body ───

#[test]
fn empty_body_produces_consistent_hash() {
    let resp_a = make_response(204, "", vec![], 1);
    let resp_b = make_response(204, "", vec![], 1);
    let mut tracker = CoverageTracker::new();
    assert!(matches!(
        tracker.record(&resp_a, "a"),
        CoverageResult::Novel(_)
    ));
    assert!(matches!(
        tracker.record(&resp_b, "b"),
        CoverageResult::Known(_)
    ));
}
