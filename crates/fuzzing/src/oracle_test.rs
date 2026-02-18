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

        assert!(anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::ContentAnomaly));
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
    fn no_size_anomaly_when_std_dev_is_zero() {
        let mut profile = baseline();
        profile.body_size_std_dev = 0.0;

        let mut oracle = FuzzOracle::new(0.3);
        oracle.add_baseline(profile);

        let resp = response(200, "ok", 50, 99999);
        let anomalies = oracle.analyze_response(&resp, "test", "/api/users", "GET");

        assert!(!anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::SizeAnomaly));
    }
}
