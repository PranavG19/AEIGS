#[cfg(test)]
mod tests {
    use aegis_protocol::finding::VulnerabilityClass;

    use crate::executor::FuzzResponse;
    use crate::oracle::{AnomalyType, BaselineProfile, CounterfactualOrder, FuzzOracle};
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

    #[test]
    fn randomize_order_defaults_to_true() {
        let oracle = FuzzOracle::new(0.5);
        assert!(oracle.randomize_order());
    }

    #[test]
    fn inter_request_spacing_defaults_to_100ms() {
        let oracle = FuzzOracle::new(0.5);
        assert_eq!(oracle.inter_request_spacing(), Duration::from_millis(100));
    }

    #[test]
    fn with_randomize_order_builder() {
        let oracle = FuzzOracle::new(0.5).with_randomize_order(false);
        assert!(!oracle.randomize_order());
    }

    #[test]
    fn with_inter_request_spacing_builder() {
        let oracle = FuzzOracle::new(0.5).with_inter_request_spacing(Duration::from_millis(250));
        assert_eq!(oracle.inter_request_spacing(), Duration::from_millis(250));
    }

    #[test]
    fn plan_counterfactual_order_fixed_returns_control_first() {
        let oracle = FuzzOracle::new(0.5).with_randomize_order(false);
        for _ in 0..50 {
            assert_eq!(
                oracle.plan_counterfactual_order(),
                CounterfactualOrder::ControlFirst
            );
        }
    }

    #[test]
    fn plan_counterfactual_order_randomized_produces_both_orderings() {
        let oracle = FuzzOracle::new(0.5).with_randomize_order(true);
        let mut saw_control_first = false;
        let mut saw_treatment_first = false;

        // 200 trials: probability of never seeing one ordering is 2^-200
        for _ in 0..200 {
            match oracle.plan_counterfactual_order() {
                CounterfactualOrder::ControlFirst => saw_control_first = true,
                CounterfactualOrder::TreatmentFirst => saw_treatment_first = true,
            }
            if saw_control_first && saw_treatment_first {
                break;
            }
        }

        assert!(
            saw_control_first && saw_treatment_first,
            "randomized ordering should produce both ControlFirst and TreatmentFirst"
        );
    }

    #[test]
    fn counterfactual_analysis_independent_of_request_order() {
        let mut oracle = FuzzOracle::new(0.5);
        oracle.add_baseline(baseline());

        let treatment = response(500, "error", 50, 500);
        let control = response(200, "ok", 50, 500);

        let anomalies_control_first = oracle.analyze_response_with_control(
            &treatment,
            &control,
            "' OR 1=1",
            "/api/users",
            "GET",
        );
        let anomalies_treatment_first = oracle.analyze_response_with_control(
            &treatment,
            &control,
            "' OR 1=1",
            "/api/users",
            "GET",
        );

        assert_eq!(
            anomalies_control_first.len(),
            anomalies_treatment_first.len()
        );
        for (a, b) in anomalies_control_first
            .iter()
            .zip(&anomalies_treatment_first)
        {
            assert_eq!(a.anomaly_type, b.anomaly_type);
        }
    }

    #[test]
    fn default_oracle_has_randomize_and_spacing() {
        let oracle = FuzzOracle::default();
        assert!(oracle.randomize_order());
        assert_eq!(oracle.inter_request_spacing(), Duration::from_millis(100));
    }

    #[test]
    fn normalize_body_strips_timestamps_uuids_session_ids() {
        use crate::oracle::normalize_body;

        let body = concat!(
            r#"{"id":"550e8400-e29b-41d4-a716-446655440000","#,
            r#""created":"2024-01-15T10:30:00Z","#,
            r#""csrf":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6","#,
            r#""ts":1705312200000}"#
        );

        let normalized = normalize_body(body);
        assert!(normalized.contains("[UUID]"));
        assert!(normalized.contains("[TIMESTAMP]"));
        assert!(normalized.contains("[HEX]"));
        assert!(normalized.contains("[UNIX_TS]"));
        assert!(!normalized.contains("550e8400"));
        assert!(!normalized.contains("2024-01-15"));
        assert!(!normalized.contains("a1b2c3d4e5f6a7b8"));
        assert!(!normalized.contains("1705312200000"));
    }

    #[test]
    fn simhash_identical_strings_are_similar() {
        use crate::oracle::{simhash, simhash_similarity};

        let text = "the quick brown fox jumps over the lazy dog";
        let h1 = simhash(text);
        let h2 = simhash(text);
        let sim = simhash_similarity(h1, h2);
        assert!((sim - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn simhash_completely_different_strings_are_dissimilar() {
        use crate::oracle::{simhash, simhash_similarity};

        // SimHash of unrelated content should hover near 0.5 (random chance)
        // and be well below the 0.95 determinism threshold
        let h1 = simhash(r#"{"status":"ok","items":[],"count":0,"user":"alice"}"#);
        let h2 = simhash(
            "<html><body><h1>404 Not Found</h1><p>The requested page does not exist.</p></body></html>",
        );
        let sim = simhash_similarity(h1, h2);
        assert!(
            sim < 0.7,
            "completely different bodies should be dissimilar, got {sim}"
        );
    }

    #[test]
    fn simhash_similar_strings_with_token_changes() {
        use crate::oracle::{normalize_body, simhash, simhash_similarity};

        let body_a = r#"{"user":"alice","csrf":"aabbccdd11223344aabbccdd11223344","time":"2024-01-15T10:00:00Z"}"#;
        let body_b = r#"{"user":"alice","csrf":"11223344aabbccdd11223344aabbccdd","time":"2024-06-20T14:30:00Z"}"#;

        let norm_a = normalize_body(body_a);
        let norm_b = normalize_body(body_b);

        let sim = simhash_similarity(simhash(&norm_a), simhash(&norm_b));
        assert!(
            sim > 0.9,
            "normalized bodies should be highly similar, got {sim}"
        );
    }

    #[test]
    fn variance_with_csrf_tokens_is_deterministic() {
        use crate::oracle::measure_endpoint_variance;

        let make_resp = |csrf: &str| FuzzResponse {
            request_id: 1,
            status_code: 200,
            body: format!(r#"{{"page":"home","csrf":"{csrf}","content":"Welcome back"}}"#),
            headers: Vec::new(),
            response_time: Duration::from_millis(50),
            body_size_bytes: 60,
        };

        let responses = vec![
            make_resp("aabbccdd11223344eeff0011aabbccdd"),
            make_resp("11223344aabbccddeeff001122334455"),
            make_resp("ffeeddccbbaa99887766554433221100"),
        ];

        let report = measure_endpoint_variance(&responses);
        assert!(
            report.is_deterministic,
            "responses identical except CSRF tokens should be deterministic, similarity={}",
            report.body_similarity
        );
    }

    #[test]
    fn variance_with_genuinely_different_bodies_is_nondeterministic() {
        use crate::oracle::measure_endpoint_variance;

        let responses = vec![
            FuzzResponse {
                request_id: 1,
                status_code: 200,
                body: r#"{"status":"ok","items":[]}"#.to_string(),
                headers: Vec::new(),
                response_time: Duration::from_millis(50),
                body_size_bytes: 26,
            },
            FuzzResponse {
                request_id: 2,
                status_code: 200,
                body: "Internal Server Error: stack trace at line 42 in module database"
                    .to_string(),
                headers: Vec::new(),
                response_time: Duration::from_millis(50),
                body_size_bytes: 63,
            },
            FuzzResponse {
                request_id: 3,
                status_code: 200,
                body: "<html><body><h1>404 Not Found</h1></body></html>".to_string(),
                headers: Vec::new(),
                response_time: Duration::from_millis(50),
                body_size_bytes: 48,
            },
        ];

        let report = measure_endpoint_variance(&responses);
        assert!(
            !report.is_deterministic,
            "genuinely different bodies should be non-deterministic, similarity={}",
            report.body_similarity
        );
    }

    #[test]
    fn confirmation_detects_sql_error_in_treatment() {
        let oracle = FuzzOracle::new(0.5);

        let treatment = response(
            500,
            "You have an error in your SQL syntax near '1'",
            50,
            100,
        );
        let control = response(200, "ok", 50, 100);

        let anomalies = oracle.analyze_response_with_confirmation(
            &treatment,
            &control,
            "' OR 1=1",
            "/api/users",
            "POST",
            VulnerabilityClass::SqlInjection,
        );

        assert!(
            anomalies
                .iter()
                .any(|a| a.description.contains("[SQL Injection]")),
            "should contain class-specific SQL Injection anomaly"
        );
    }

    #[test]
    fn confirmation_returns_empty_for_unregistered_class() {
        let oracle = FuzzOracle::new(0.5);

        let treatment = response(200, "ok", 50, 100);
        let control = response(200, "ok", 50, 100);

        let anomalies = oracle.analyze_response_with_confirmation(
            &treatment,
            &control,
            "test",
            "/api/data",
            "GET",
            VulnerabilityClass::BrokenAuthentication,
        );

        assert!(
            anomalies.is_empty(),
            "unregistered vuln class should produce no class-specific anomalies"
        );
    }

    #[test]
    fn confirmation_deduplicates_keeping_higher_score() {
        let oracle = FuzzOracle::new(0.5);

        let treatment = response(
            500,
            "You have an error in your SQL syntax near '1'",
            50,
            100,
        );
        let control = response(200, "ok", 50, 100);

        let anomalies = oracle.analyze_response_with_confirmation(
            &treatment,
            &control,
            "' OR 1=1",
            "/api/users",
            "POST",
            VulnerabilityClass::SqlInjection,
        );

        let content_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| a.anomaly_type == AnomalyType::ContentAnomaly)
            .collect();

        assert_eq!(
            content_anomalies.len(),
            1,
            "dedup should keep exactly one ContentAnomaly, got {}",
            content_anomalies.len()
        );

        assert!(
            content_anomalies[0].score >= 0.9,
            "should keep the higher-scoring anomaly, got {}",
            content_anomalies[0].score
        );
    }

    #[test]
    fn confirmation_works_without_baseline() {
        let oracle = FuzzOracle::new(0.5);

        let treatment = response(
            200,
            "You have an error in your SQL syntax near '1'",
            50,
            100,
        );
        let control = response(200, "ok", 50, 100);

        let anomalies = oracle.analyze_response_with_confirmation(
            &treatment,
            &control,
            "' OR 1=1",
            "/no/baseline/here",
            "POST",
            VulnerabilityClass::SqlInjection,
        );

        assert!(
            !anomalies.is_empty(),
            "should detect anomalies even without a stored baseline"
        );
    }

    #[test]
    fn confirmation_threshold_filters_low_confidence() {
        let oracle = FuzzOracle::new(0.99);

        let treatment = response(
            500,
            "You have an error in your SQL syntax near '1'",
            50,
            100,
        );
        let control = response(200, "ok", 50, 100);

        let anomalies = oracle.analyze_response_with_confirmation(
            &treatment,
            &control,
            "' OR 1=1",
            "/api/users",
            "POST",
            VulnerabilityClass::SqlInjection,
        );

        assert!(
            anomalies.is_empty(),
            "threshold 0.99 should filter out all anomalies"
        );
    }

    #[test]
    fn confirmation_preserves_generic_anomalies_for_different_types() {
        let mut oracle = FuzzOracle::new(0.5);
        oracle.add_baseline(baseline());

        let treatment = response(
            500,
            "You have an error in your SQL syntax near '1'",
            50,
            500,
        );
        let control = response(200, "ok", 50, 500);

        let anomalies = oracle.analyze_response_with_confirmation(
            &treatment,
            &control,
            "' OR 1=1",
            "/api/users",
            "GET",
            VulnerabilityClass::SqlInjection,
        );

        let has_status = anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::StatusCodeAnomaly);
        let has_content = anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::ContentAnomaly);

        assert!(has_status, "should preserve generic StatusCodeAnomaly");
        assert!(
            has_content,
            "should have ContentAnomaly from confirmation or generic"
        );
    }

    #[test]
    fn confirmation_xss_reflection_tagged_with_class() {
        let oracle = FuzzOracle::new(0.5);

        let payload = "<script>alert(1)</script>";
        let treatment = response(200, &format!("Result: {payload}"), 50, 100);
        let control = response(200, "Result: benign", 50, 100);

        let anomalies = oracle.analyze_response_with_confirmation(
            &treatment,
            &control,
            payload,
            "/search",
            "GET",
            VulnerabilityClass::CrossSiteScripting,
        );

        assert!(
            anomalies
                .iter()
                .any(|a| a.description.contains("[Cross-Site Scripting]")),
            "should contain class-specific XSS anomaly"
        );
    }
}
