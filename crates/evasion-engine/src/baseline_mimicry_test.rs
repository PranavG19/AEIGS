use super::baseline_mimicry::*;

fn make_samples(count: usize) -> Vec<TrafficSample> {
    let mut samples = Vec::with_capacity(count);
    for i in 0..count {
        let methods = ["GET", "POST", "GET", "GET", "PUT"];
        let paths = [
            "/api/users",
            "/api/products",
            "/api/orders",
            "/static/main.js",
            "/api/users/123",
        ];
        samples.push(TrafficSample {
            protocol: if i % 5 == 0 {
                ObservedProtocol::Http
            } else {
                ObservedProtocol::Https
            },
            payload_size_bytes: 200 + (i as u32 * 17) % 800,
            inter_arrival_ms: 50 + (i as u64 * 13) % 500,
            uri_path: paths[i % paths.len()].to_string(),
            method: methods[i % methods.len()].to_string(),
            timestamp_ms: 1000 + i as u64 * 100,
        });
    }
    samples
}

#[test]
fn learner_rejects_insufficient_samples() {
    let config = LearnerConfig::default().with_min_samples(100);
    let mut learner = BaselineLearner::new("target-1", config);
    for s in make_samples(10) {
        learner.ingest_sample(s);
    }
    let result = learner.build_profile();
    assert!(result.is_err());
    match result.unwrap_err() {
        LearnerError::InsufficientSamples {
            collected,
            required,
        } => {
            assert_eq!(collected, 10);
            assert_eq!(required, 100);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn learner_builds_profile_with_sufficient_samples() {
    let config = LearnerConfig::default().with_min_samples(20);
    let mut learner = BaselineLearner::new("target-2", config);
    for s in make_samples(100) {
        learner.ingest_sample(s);
    }
    assert!(learner.has_sufficient_samples());
    let profile = learner.build_profile().unwrap();
    assert_eq!(profile.target_id, "target-2");
    assert_eq!(profile.total_samples, 100);
    assert!(!profile.protocol_distribution.is_empty());
    assert!(profile.cadence_stats.mean > 0.0);
    assert!(profile.payload_size_stats.mean > 0.0);
    assert!(!profile.uri_patterns.is_empty());
    assert!(!profile.method_distribution.is_empty());
}

#[test]
fn learner_respects_learning_window() {
    let config = LearnerConfig::default()
        .with_learning_window_ms(500)
        .with_min_samples(5);
    let mut learner = BaselineLearner::new("target-3", config);

    let accepted = learner.ingest_sample(TrafficSample {
        protocol: ObservedProtocol::Https,
        payload_size_bytes: 100,
        inter_arrival_ms: 50,
        uri_path: "/api/test".to_string(),
        method: "GET".to_string(),
        timestamp_ms: 1000,
    });
    assert!(accepted);

    let rejected = learner.ingest_sample(TrafficSample {
        protocol: ObservedProtocol::Https,
        payload_size_bytes: 100,
        inter_arrival_ms: 50,
        uri_path: "/api/test".to_string(),
        method: "GET".to_string(),
        timestamp_ms: 2000,
    });
    assert!(!rejected);
}

#[test]
fn protocol_distribution_sums_to_one() {
    let config = LearnerConfig::default().with_min_samples(10);
    let mut learner = BaselineLearner::new("target-4", config);
    for s in make_samples(50) {
        learner.ingest_sample(s);
    }
    let profile = learner.build_profile().unwrap();
    let sum: f64 = profile.protocol_distribution.values().sum();
    assert!((sum - 1.0).abs() < 0.001);
}

#[test]
fn method_distribution_sums_to_one() {
    let config = LearnerConfig::default().with_min_samples(10);
    let mut learner = BaselineLearner::new("target-5", config);
    for s in make_samples(50) {
        learner.ingest_sample(s);
    }
    let profile = learner.build_profile().unwrap();
    let sum: f64 = profile.method_distribution.values().sum();
    assert!((sum - 1.0).abs() < 0.001);
}

#[test]
fn conformance_score_rewards_matching_traffic() {
    let config = LearnerConfig::default().with_min_samples(10);
    let mut learner = BaselineLearner::new("target-6", config);
    for s in make_samples(100) {
        learner.ingest_sample(s);
    }
    let profile = learner.build_profile().unwrap();

    let good_score = profile.conformance_score(400, 200, "/api/users", "GET");
    let bad_score = profile.conformance_score(50000, 99999, "/totally/unknown/path", "DELETE");
    assert!(
        good_score > bad_score,
        "matching traffic ({good_score}) should score higher than anomalous ({bad_score})"
    );
}

#[test]
fn mimicry_engine_generates_conformant_delays() {
    let config = LearnerConfig::default().with_min_samples(10);
    let mut learner = BaselineLearner::new("target-7", config);
    for s in make_samples(100) {
        learner.ingest_sample(s);
    }
    let profile = learner.build_profile().unwrap();
    let min = profile.cadence_stats.min as u64;
    let max = profile.cadence_stats.max as u64;

    let mut engine = MimicryEngine::with_seed(profile, 0.3, 42);
    for _ in 0..50 {
        let delay = engine.conformant_delay_ms();
        assert!(
            delay >= min && delay <= max,
            "delay {delay} outside learned range [{min}, {max}]"
        );
    }
}

#[test]
fn mimicry_engine_generates_conformant_payload_sizes() {
    let config = LearnerConfig::default().with_min_samples(10);
    let mut learner = BaselineLearner::new("target-8", config);
    for s in make_samples(100) {
        learner.ingest_sample(s);
    }
    let profile = learner.build_profile().unwrap();
    let min = profile.payload_size_stats.min as u32;
    let max = profile.payload_size_stats.max as u32;

    let mut engine = MimicryEngine::with_seed(profile, 0.3, 42);
    for _ in 0..50 {
        let size = engine.conformant_payload_size();
        assert!(
            size >= min && size <= max,
            "payload size {size} outside learned range [{min}, {max}]"
        );
    }
}

#[test]
fn mimicry_engine_shape_request_returns_valid_data() {
    let config = LearnerConfig::default().with_min_samples(10);
    let mut learner = BaselineLearner::new("target-9", config);
    for s in make_samples(100) {
        learner.ingest_sample(s);
    }
    let profile = learner.build_profile().unwrap();
    let mut engine = MimicryEngine::with_seed(profile, 0.3, 42);

    for _ in 0..20 {
        let shaped = engine.shape_request();
        assert!(!shaped.method.is_empty());
        assert!(shaped.delay_ms > 0 || shaped.payload_size > 0);
    }
    assert_eq!(engine.requests_shaped(), 20);
}

#[test]
fn profile_serialization_roundtrip() {
    let config = LearnerConfig::default().with_min_samples(10);
    let mut learner = BaselineLearner::new("target-10", config);
    for s in make_samples(50) {
        learner.ingest_sample(s);
    }
    let profile = learner.build_profile().unwrap();
    let json = save_profile(&profile).unwrap();
    let restored = load_profile(&json).unwrap();
    assert_eq!(restored.target_id, profile.target_id);
    assert_eq!(restored.total_samples, profile.total_samples);
    assert!((restored.cadence_stats.mean - profile.cadence_stats.mean).abs() < 0.001);
}

#[test]
fn uri_prefix_extraction_handles_edge_cases() {
    let config = LearnerConfig::default().with_min_samples(5);
    let mut learner = BaselineLearner::new("target-11", config);

    let paths = ["/", "/single", "/two/segments", "/three/seg/deep"];
    for (i, path) in paths.iter().enumerate() {
        learner.ingest_sample(TrafficSample {
            protocol: ObservedProtocol::Https,
            payload_size_bytes: 100,
            inter_arrival_ms: 50,
            uri_path: path.to_string(),
            method: "GET".to_string(),
            timestamp_ms: 1000 + i as u64 * 10,
        });
    }
    // Just enough to not error
    for s in make_samples(5) {
        learner.ingest_sample(s);
    }

    let profile = learner.build_profile().unwrap();
    let prefixes: Vec<&str> = profile
        .uri_patterns
        .iter()
        .map(|p| p.prefix.as_str())
        .collect();
    assert!(prefixes.contains(&"/"));
    assert!(prefixes.contains(&"/single"));
}

#[test]
fn mimicry_engine_meets_threshold_check() {
    let config = LearnerConfig::default().with_min_samples(10);
    let mut learner = BaselineLearner::new("target-12", config);
    for s in make_samples(50) {
        learner.ingest_sample(s);
    }
    let profile = learner.build_profile().unwrap();
    let engine = MimicryEngine::with_seed(profile, 0.5, 42);

    assert!(engine.meets_threshold(0.8));
    assert!(engine.meets_threshold(0.5));
    assert!(!engine.meets_threshold(0.3));
    assert!(!engine.meets_threshold(0.0));
}

#[test]
fn distribution_stats_percentiles_are_ordered() {
    let config = LearnerConfig::default().with_min_samples(10);
    let mut learner = BaselineLearner::new("target-13", config);
    for s in make_samples(200) {
        learner.ingest_sample(s);
    }
    let profile = learner.build_profile().unwrap();
    let stats = &profile.payload_size_stats;
    assert!(stats.min <= stats.p25);
    assert!(stats.p25 <= stats.p50);
    assert!(stats.p50 <= stats.p75);
    assert!(stats.p75 <= stats.p95);
    assert!(stats.p95 <= stats.max);
}
