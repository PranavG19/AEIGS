use std::time::Duration;

use crate::anomaly_detector::{AnomalyDetector, AnomalyType, ExploitPotential};
use crate::executor::FuzzResponse;

fn make_baseline_response(status: u16, body: &str, time_ms: u64) -> FuzzResponse {
    FuzzResponse {
        request_id: 1,
        status_code: status,
        body: body.to_string(),
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-request-id".to_string(), "abc123".to_string()),
        ],
        response_time: Duration::from_millis(time_ms),
        body_size_bytes: body.len(),
    }
}

fn seed_baseline(detector: &mut AnomalyDetector, endpoint: &str, count: usize) {
    for i in 0..count {
        let body = format!("{{\"result\": \"ok\", \"id\": {}}}", i);
        let resp = make_baseline_response(200, &body, 50 + (i as u64 % 20));
        detector.learn_baseline(endpoint, &resp);
    }
}

#[test]
fn no_baseline_returns_none() {
    let detector = AnomalyDetector::new();
    let resp = make_baseline_response(200, "ok", 50);
    assert!(detector.analyze("/api/test", &resp, "payload").is_none());
}

#[test]
fn insufficient_baseline_returns_none() {
    let mut detector = AnomalyDetector::new();
    for _ in 0..3 {
        let resp = make_baseline_response(200, "ok", 50);
        detector.learn_baseline("/api/test", &resp);
    }
    let resp = make_baseline_response(200, "ok", 50);
    assert!(detector.analyze("/api/test", &resp, "payload").is_none());
}

#[test]
fn normal_response_has_low_anomaly_score() {
    let mut detector = AnomalyDetector::new();
    seed_baseline(&mut detector, "/api/test", 20);
    let resp = make_baseline_response(200, "{\"result\": \"ok\", \"id\": 99}", 55);
    let score = detector.analyze("/api/test", &resp, "normal").unwrap();
    assert!(score.total < 0.3);
}

#[test]
fn unusual_status_code_detected() {
    let mut detector = AnomalyDetector::new();
    seed_baseline(&mut detector, "/api/test", 20);
    let resp = make_baseline_response(500, "Internal Server Error", 50);
    let score = detector
        .analyze("/api/test", &resp, "crash_payload")
        .unwrap();
    assert!(score.status_component > 0.5);
    let status_anomalies: Vec<_> = score
        .anomalies
        .iter()
        .filter(|a| a.anomaly_type == AnomalyType::UnusualStatusCode)
        .collect();
    assert!(!status_anomalies.is_empty());
}

#[test]
fn body_length_deviation_detected() {
    let mut detector = AnomalyDetector::new();
    seed_baseline(&mut detector, "/api/test", 20);
    let long_body = "A".repeat(50000);
    let resp = make_baseline_response(200, &long_body, 50);
    let score = detector
        .analyze("/api/test", &resp, "long_payload")
        .unwrap();
    assert!(score.length_component > 0.0);
    let length_anomalies: Vec<_> = score
        .anomalies
        .iter()
        .filter(|a| a.anomaly_type == AnomalyType::BodyLengthDeviation)
        .collect();
    assert!(!length_anomalies.is_empty());
}

#[test]
fn empty_body_detected() {
    let mut detector = AnomalyDetector::new();
    seed_baseline(&mut detector, "/api/test", 20);
    let resp = FuzzResponse {
        request_id: 1,
        status_code: 200,
        body: String::new(),
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-request-id".to_string(), "abc123".to_string()),
        ],
        response_time: Duration::from_millis(50),
        body_size_bytes: 0,
    };
    let score = detector.analyze("/api/test", &resp, "empty").unwrap();
    let empty_anomalies: Vec<_> = score
        .anomalies
        .iter()
        .filter(|a| a.anomaly_type == AnomalyType::EmptyBody)
        .collect();
    assert!(!empty_anomalies.is_empty());
}

#[test]
fn timing_spike_detected() {
    let mut detector = AnomalyDetector::new();
    seed_baseline(&mut detector, "/api/test", 20);
    let resp = make_baseline_response(200, "{\"result\": \"ok\"}", 10_000);
    let score = detector
        .analyze("/api/test", &resp, "sleep_payload")
        .unwrap();
    assert!(score.timing_component > 0.0);
    let timing_anomalies: Vec<_> = score
        .anomalies
        .iter()
        .filter(|a| a.anomaly_type == AnomalyType::TimingSpike)
        .collect();
    assert!(!timing_anomalies.is_empty());
}

#[test]
fn new_header_detected() {
    let mut detector = AnomalyDetector::new();
    seed_baseline(&mut detector, "/api/test", 20);
    let resp = FuzzResponse {
        request_id: 1,
        status_code: 200,
        body: "{\"result\": \"ok\"}".to_string(),
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-request-id".to_string(), "abc123".to_string()),
            (
                "x-debug-info".to_string(),
                "internal_error_trace".to_string(),
            ),
        ],
        response_time: Duration::from_millis(50),
        body_size_bytes: 16,
    };
    let score = detector
        .analyze("/api/test", &resp, "debug_payload")
        .unwrap();
    let header_anomalies: Vec<_> = score
        .anomalies
        .iter()
        .filter(|a| a.anomaly_type == AnomalyType::NewHeader)
        .collect();
    assert!(!header_anomalies.is_empty());
}

#[test]
fn missing_header_detected() {
    let mut detector = AnomalyDetector::new();
    seed_baseline(&mut detector, "/api/test", 20);
    let resp = FuzzResponse {
        request_id: 1,
        status_code: 200,
        body: "{\"result\": \"ok\"}".to_string(),
        headers: vec![],
        response_time: Duration::from_millis(50),
        body_size_bytes: 16,
    };
    let score = detector.analyze("/api/test", &resp, "stripped").unwrap();
    let missing_anomalies: Vec<_> = score
        .anomalies
        .iter()
        .filter(|a| a.anomaly_type == AnomalyType::MissingHeader)
        .collect();
    assert!(!missing_anomalies.is_empty());
}

#[test]
fn content_type_change_detected() {
    let mut detector = AnomalyDetector::new();
    seed_baseline(&mut detector, "/api/test", 20);
    let resp = FuzzResponse {
        request_id: 1,
        status_code: 200,
        body: "<html>error</html>".to_string(),
        headers: vec![
            ("content-type".to_string(), "text/html".to_string()),
            ("x-request-id".to_string(), "abc123".to_string()),
        ],
        response_time: Duration::from_millis(50),
        body_size_bytes: 18,
    };
    let score = detector.analyze("/api/test", &resp, "type_change").unwrap();
    let ct_anomalies: Vec<_> = score
        .anomalies
        .iter()
        .filter(|a| a.anomaly_type == AnomalyType::ContentTypeChange)
        .collect();
    assert!(!ct_anomalies.is_empty());
}

#[test]
fn error_leakage_detected_sql() {
    let mut detector = AnomalyDetector::new();
    seed_baseline(&mut detector, "/api/test", 20);
    let resp = make_baseline_response(
        500,
        "Error: mysql_query() failed: You have an error in your SQL syntax",
        50,
    );
    let score = detector.analyze("/api/test", &resp, "sqli_probe").unwrap();
    let error_anomalies: Vec<_> = score
        .anomalies
        .iter()
        .filter(|a| a.anomaly_type == AnomalyType::ErrorLeakage)
        .collect();
    assert!(!error_anomalies.is_empty());
    assert!(error_anomalies[0].exploit_potential >= ExploitPotential::Confirmed);
}

#[test]
fn error_leakage_detected_stack_trace() {
    let mut detector = AnomalyDetector::new();
    seed_baseline(&mut detector, "/api/test", 20);
    let resp = make_baseline_response(
        500,
        "Unhandled exception: NullPointerException\nStack Trace:\n at com.example.App.main",
        50,
    );
    let score = detector.analyze("/api/test", &resp, "stack_probe").unwrap();
    let error_anomalies: Vec<_> = score
        .anomalies
        .iter()
        .filter(|a| a.anomaly_type == AnomalyType::ErrorLeakage)
        .collect();
    assert!(!error_anomalies.is_empty());
}

#[test]
fn multi_dimensional_score_combines_signals() {
    let mut detector = AnomalyDetector::new();
    seed_baseline(&mut detector, "/api/test", 20);
    let resp = FuzzResponse {
        request_id: 1,
        status_code: 500,
        body: "Fatal error: SQL syntax error near 'DROP TABLE'".to_string(),
        headers: vec![
            ("content-type".to_string(), "text/plain".to_string()),
            ("x-debug-info".to_string(), "enabled".to_string()),
        ],
        response_time: Duration::from_millis(8_000),
        body_size_bytes: 47,
    };
    let score = detector
        .analyze("/api/test", &resp, "multi_signal")
        .unwrap();
    assert!(score.total > 0.3);
    assert!(score.anomalies.len() >= 2);
}

#[test]
fn exploit_potential_ordering() {
    assert!(ExploitPotential::Confirmed > ExploitPotential::LikelyExploitable);
    assert!(ExploitPotential::LikelyExploitable > ExploitPotential::Suspicious);
    assert!(ExploitPotential::Suspicious > ExploitPotential::Noise);
}

#[test]
fn multiple_endpoints_tracked_independently() {
    let mut detector = AnomalyDetector::new();
    seed_baseline(&mut detector, "/api/users", 10);
    seed_baseline(&mut detector, "/api/items", 10);
    assert_eq!(detector.endpoint_count(), 2);
    assert!(detector.baseline_for("/api/users").is_some());
    assert!(detector.baseline_for("/api/items").is_some());
    assert!(detector.baseline_for("/api/unknown").is_none());
}

#[test]
fn z_score_threshold_configurable() {
    let mut detector = AnomalyDetector::new().with_z_score_threshold(1.0);
    seed_baseline(&mut detector, "/api/test", 20);
    let resp = make_baseline_response(200, "{\"result\": \"ok\"}", 200);
    let score = detector
        .analyze("/api/test", &resp, "slightly_slow")
        .unwrap();
    assert!(score.timing_component >= 0.0);
}

#[test]
fn custom_weights() {
    let mut detector = AnomalyDetector::new().with_weights(0.5, 0.2, 0.1, 0.1, 0.1);
    seed_baseline(&mut detector, "/api/test", 20);
    let resp = make_baseline_response(500, "error", 50);
    let score = detector.analyze("/api/test", &resp, "weighted").unwrap();
    assert!(score.total > 0.0);
}

#[test]
fn default_trait_works() {
    let detector = AnomalyDetector::default();
    assert_eq!(detector.endpoint_count(), 0);
}

#[test]
fn baseline_sample_count_tracks() {
    let mut detector = AnomalyDetector::new();
    for i in 0..10 {
        let body = format!("response_{}", i);
        let resp = make_baseline_response(200, &body, 50);
        detector.learn_baseline("/api/test", &resp);
    }
    let baseline = detector.baseline_for("/api/test").unwrap();
    assert_eq!(baseline.sample_count, 10);
    assert!(baseline.is_ready());
}
