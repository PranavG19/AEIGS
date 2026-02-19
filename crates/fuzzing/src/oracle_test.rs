#[cfg(test)]
mod tests {
    use crate::executor::FuzzResponse;
    use crate::oracle::{AnomalyType, BaselineProfile, FuzzOracle};
    use std::time::Duration;

    fn baseline() -> BaselineProfile {
        BaselineProfile {
            endpoint: "/api/users".to_string(),
            method: "GET".to_string(),
            expected_status_codes: vec![200, 404],
            mean_response_time_ms: 50.0,
            p99_response_time_ms: 100.0,
            mean_body_size: 500.0,
            body_size_std_dev: 50.0,
        }
    }

    fn response(status: u16, body: &str, time_ms: u64, size: usize) -> FuzzResponse {
        FuzzResponse {
            request_id: 1,
            status_code: status,
            body: body.to_string(),
            headers: Vec::new(),
            response_time: Duration::from_millis(time_ms),
            body_size_bytes: size,
        }
    }

    #[test]
    fn no_anomaly_for_normal_response() {
        let mut oracle = FuzzOracle::new(0.5);
        oracle.add_baseline(baseline());

        let resp = response(200, "ok", 50, 500);
        let anomalies = oracle.analyze_response(&resp, "test", "/api/users", "GET");
        assert!(anomalies.is_empty());
    }

    #[test]
    fn status_code_anomaly_detected() {
        let mut oracle = FuzzOracle::new(0.5);
        oracle.add_baseline(baseline());

        let resp = response(500, "Internal Server Error", 50, 500);
        let anomalies = oracle.analyze_response(&resp, "test", "/api/users", "GET");

        let status_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| a.anomaly_type == AnomalyType::StatusCodeAnomaly)
            .collect();
        assert!(!status_anomalies.is_empty());
    }

    #[test]
    fn timing_anomaly_detected() {
        let mut oracle = FuzzOracle::new(0.5);
        oracle.add_baseline(baseline());

        let resp = response(200, "ok", 500, 500);
        let anomalies = oracle.analyze_response(&resp, "test", "/api/users", "GET");

        let timing = anomalies
            .iter()
            .find(|a| a.anomaly_type == AnomalyType::TimingAnomaly);
        assert!(timing.is_some());
    }

    #[test]
    fn size_anomaly_detected() {
        let mut oracle = FuzzOracle::new(0.3);
        oracle.add_baseline(baseline());

        let resp = response(200, "ok", 50, 5000);
        let anomalies = oracle.analyze_response(&resp, "test", "/api/users", "GET");

        let size = anomalies
            .iter()
            .find(|a| a.anomaly_type == AnomalyType::SizeAnomaly);
        assert!(size.is_some());
    }

    #[test]
    fn content_anomaly_for_sql_error() {
        let oracle = FuzzOracle::new(0.5);
        let resp = response(500, "You have an error in your SQL syntax near...", 50, 100);
        let anomalies = oracle.analyze_response(&resp, "' OR 1=1", "/test", "POST");

        let content = anomalies
            .iter()
            .find(|a| a.anomaly_type == AnomalyType::ContentAnomaly);
        assert!(content.is_some());
    }

    #[test]
    fn content_anomaly_for_stack_trace() {
        let mut oracle = FuzzOracle::new(0.5);
        oracle.add_baseline(baseline());
        let body = "Error: Traceback (most recent call last):\n  File app.py, line 42";
        let resp = response(500, body, 50, 100);
        let anomalies = oracle.analyze_response(&resp, "test", "/api", "GET");

        assert!(
            anomalies
                .iter()
                .any(|a| a.anomaly_type == AnomalyType::ContentAnomaly)
        );
    }

    #[test]
    fn reflection_detected() {
        let oracle = FuzzOracle::new(0.5);
        let payload = "<script>alert(1)</script>";
        let body = format!("Result: {payload}");
        let resp = response(200, &body, 50, 100);
        let anomalies = oracle.analyze_response(&resp, payload, "/search", "GET");

        let reflection = anomalies
            .iter()
            .find(|a| a.anomaly_type == AnomalyType::ReflectionDetected);
        assert!(reflection.is_some());
    }

    #[test]
    fn short_payload_reflection_not_flagged() {
        let oracle = FuzzOracle::new(0.5);
        let resp = response(200, "abc", 50, 100);
        let anomalies = oracle.analyze_response(&resp, "ab", "/test", "GET");

        let reflection = anomalies
            .iter()
            .find(|a| a.anomaly_type == AnomalyType::ReflectionDetected);
        assert!(reflection.is_none());
    }

    #[test]
    fn baseline_from_responses() {
        let responses = vec![
            response(200, "ok", 50, 500),
            response(200, "ok", 60, 520),
            response(404, "not found", 45, 100),
        ];

        let profile = BaselineProfile::from_responses("/api", "GET", &responses);
        assert_eq!(profile.endpoint, "/api");
        assert_eq!(profile.expected_status_codes, vec![200, 404]);
        assert!(profile.mean_response_time_ms > 0.0);
        assert!(profile.p99_response_time_ms >= profile.mean_response_time_ms);
    }

    #[test]
    fn baseline_from_empty_responses() {
        let profile = BaselineProfile::from_responses("/api", "GET", &[]);
        assert_eq!(profile.mean_response_time_ms, 0.0);
        assert!(profile.expected_status_codes.is_empty());
    }

    #[test]
    fn anomaly_threshold_filters_low_scores() {
        let mut oracle = FuzzOracle::new(0.95);
        oracle.add_baseline(baseline());

        let resp = response(500, "error", 50, 500);
        let anomalies = oracle.analyze_response(&resp, "test", "/api/users", "GET");

        assert!(
            anomalies.is_empty(),
            "high threshold should filter out anomalies with score < 0.95"
        );
    }

    #[test]
    fn oracle_default_threshold() {
        let oracle = FuzzOracle::default();
        assert_eq!(oracle.anomaly_threshold(), 0.5);
    }

    #[test]
    fn baseline_count() {
        let mut oracle = FuzzOracle::new(0.5);
        assert_eq!(oracle.baseline_count(), 0);

        oracle.add_baseline(baseline());
        assert_eq!(oracle.baseline_count(), 1);
    }

    #[test]
    fn anomaly_type_display() {
        assert_eq!(AnomalyType::StatusCodeAnomaly.to_string(), "status-code");
        assert_eq!(AnomalyType::TimingAnomaly.to_string(), "timing");
        assert_eq!(AnomalyType::SizeAnomaly.to_string(), "size");
        assert_eq!(AnomalyType::ContentAnomaly.to_string(), "content");
        assert_eq!(AnomalyType::ReflectionDetected.to_string(), "reflection");
    }

    #[test]
    fn counterfactual_returns_treatment_only_anomaly() {
        let mut oracle = FuzzOracle::new(0.5);
        oracle.add_baseline(baseline());

        let treatment = response(500, "error", 50, 500);
        let control = response(200, "ok", 50, 500);
        let anomalies = oracle.analyze_response_with_control(
            &treatment,
            &control,
            "' OR 1=1",
            "/api/users",
            "GET",
        );

        assert!(
            anomalies
                .iter()
                .any(|a| a.anomaly_type == AnomalyType::StatusCodeAnomaly),
            "treatment-only status anomaly should be returned"
        );
    }

    #[test]
    fn counterfactual_filters_shared_anomaly() {
        let mut oracle = FuzzOracle::new(0.5);
        oracle.add_baseline(baseline());

        let treatment = response(500, "error", 50, 500);
        let control = response(500, "error", 50, 500);
        let anomalies = oracle.analyze_response_with_control(
            &treatment,
            &control,
            "' OR 1=1",
            "/api/users",
            "GET",
        );

        assert!(
            !anomalies
                .iter()
                .any(|a| a.anomaly_type == AnomalyType::StatusCodeAnomaly),
            "shared status anomaly should be filtered out"
        );
    }

    #[test]
    fn counterfactual_excludes_control_only_anomalies() {
        let mut oracle = FuzzOracle::new(0.5);
        oracle.add_baseline(baseline());

        let treatment = response(200, "ok", 50, 500);
        let control = response(500, "error", 50, 500);
        let anomalies =
            oracle.analyze_response_with_control(&treatment, &control, "test", "/api/users", "GET");

        assert!(
            anomalies.is_empty(),
            "control-only anomalies should not appear in results"
        );
    }

    #[test]
    fn counterfactual_works_without_baseline() {
        let oracle = FuzzOracle::new(0.5);

        let treatment = response(500, "You have an error in your SQL syntax near...", 50, 100);
        let control = response(200, "ok", 50, 100);
        let anomalies = oracle.analyze_response_with_control(
            &treatment,
            &control,
            "' OR 1=1",
            "/api/users",
            "GET",
        );

        assert!(
            anomalies
                .iter()
                .any(|a| a.anomaly_type == AnomalyType::ContentAnomaly),
            "content anomaly should be detected even without baseline"
        );
    }

    #[test]
    fn counterfactual_preserves_reflection_despite_control() {
        let mut oracle = FuzzOracle::new(0.5);
        oracle.add_baseline(baseline());

        let payload = "<script>alert(1)</script>";
        let treatment = response(200, &format!("Result: {payload}"), 50, 500);
        let control = response(200, "Result: benign", 50, 500);
        let anomalies = oracle.analyze_response_with_control(
            &treatment,
            &control,
            payload,
            "/api/users",
            "GET",
        );

        assert!(
            anomalies
                .iter()
                .any(|a| a.anomaly_type == AnomalyType::ReflectionDetected),
            "reflection should never be filtered by control comparison"
        );
    }

    #[test]
    fn no_size_anomaly_when_std_dev_is_zero() {
        let mut profile = baseline();
        profile.body_size_std_dev = 0.0;

        let mut oracle = FuzzOracle::new(0.3);
        oracle.add_baseline(profile);

        let resp = response(200, "ok", 50, 99999);
        let anomalies = oracle.analyze_response(&resp, "test", "/api/users", "GET");

        assert!(
            !anomalies
                .iter()
                .any(|a| a.anomaly_type == AnomalyType::SizeAnomaly)
        );
    }

    #[test]
    fn variance_deterministic_endpoint_constant_responses() {
        use crate::oracle::measure_endpoint_variance;

        let responses = vec![
            response(200, "ok", 50, 100),
            response(200, "ok", 52, 100),
            response(200, "ok", 48, 100),
        ];

        let report = measure_endpoint_variance(&responses);
        assert!(report.is_deterministic);
        assert!(report.body_similarity > 0.95);
        assert_eq!(report.response_codes, vec![200, 200, 200]);
    }

    #[test]
    fn variance_nondeterministic_endpoint_varying_responses() {
        use crate::oracle::measure_endpoint_variance;

        let responses = vec![
            response(200, "short", 50, 100),
            response(500, "very long error dump with lots of text", 52, 5000),
            response(200, "short", 48, 100),
        ];

        let report = measure_endpoint_variance(&responses);
        assert!(!report.is_deterministic);
    }

    #[test]
    fn variance_single_response_is_deterministic() {
        use crate::oracle::measure_endpoint_variance;

        let responses = vec![response(200, "ok", 50, 100)];
        let report = measure_endpoint_variance(&responses);
        assert!(report.is_deterministic);
        assert!((report.body_similarity - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn variance_empty_responses_is_deterministic() {
        use crate::oracle::measure_endpoint_variance;

        let report = measure_endpoint_variance(&[]);
        assert!(report.is_deterministic);
        assert!(report.response_codes.is_empty());
    }
}
