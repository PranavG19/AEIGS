use super::*;

fn make_snapshots(count: usize, base_ts: u64, interval_ms: u64) -> Vec<RequestSnapshot> {
    (0..count)
        .map(|i| RequestSnapshot {
            timestamp_ms: base_ts + i as u64 * interval_ms,
            method: if i % 5 == 0 {
                "POST".to_string()
            } else {
                "GET".to_string()
            },
            uri: format!("/api/resource/{}", i % 20),
            payload_size: 100 + (i % 10) * 50,
        })
        .collect()
}

#[test]
fn test_observe_builds_profile() {
    let mut normalizer = TrafficNormalizer::new();
    let snapshots = make_snapshots(50, 1000, 200);

    for snap in &snapshots {
        normalizer.observe(snap);
    }

    let profile = normalizer.build_profile();
    assert_eq!(profile.observation_count(), 50);
    assert!(profile.inter_arrival.is_fitted());
    assert!(profile.inter_arrival.observation_count() > 0);
    assert!(profile.payload_sizes.total_observations() > 0);
    assert!(profile.uri_entropy.observation_count() > 0);
    assert!(profile.method_distribution.total() > 0);

    let freqs = profile.method_distribution.frequencies();
    assert!(freqs.contains_key("GET"));
    assert!(freqs.contains_key("POST"));
    assert!(freqs["GET"] > freqs["POST"]);
}

#[test]
fn test_enforce_conformance_adjusts_timing() {
    let mut normalizer = TrafficNormalizer::new();
    let snapshots = make_snapshots(100, 1000, 500);

    for snap in &snapshots {
        normalizer.observe(snap);
    }

    let mut too_fast: u64 = 10;
    let mut payload: usize = 200;
    normalizer.enforce_conformance(&mut too_fast, &mut payload);
    assert!(too_fast > 10);

    let mut too_slow: u64 = 999_999;
    let mut payload2: usize = 200;
    normalizer.enforce_conformance(&mut too_slow, &mut payload2);
    assert!(too_slow < 999_999);
}

#[test]
fn test_enforce_conformance_caps_payload() {
    let mut normalizer = TrafficNormalizer::new();
    for i in 0..100 {
        normalizer.observe(&RequestSnapshot {
            timestamp_ms: 1000 + i * 100,
            method: "GET".to_string(),
            uri: "/small".to_string(),
            payload_size: 64,
        });
    }

    let mut delay = 100u64;
    let mut oversized_payload = 50_000usize;
    normalizer.enforce_conformance(&mut delay, &mut oversized_payload);
    assert!(oversized_payload < 50_000);
}

#[test]
fn test_enforce_conformance_noop_with_few_observations() {
    let normalizer = TrafficNormalizer::new();
    let mut delay = 42u64;
    let mut size = 999usize;
    normalizer.enforce_conformance(&mut delay, &mut size);
    assert_eq!(delay, 42);
    assert_eq!(size, 999);
}

#[test]
fn test_baseline_serialization_roundtrip() {
    let mut normalizer = TrafficNormalizer::new();
    let snapshots = make_snapshots(30, 5000, 300);
    for snap in &snapshots {
        normalizer.observe(snap);
    }

    let profile = normalizer.build_profile();
    let json = serde_json::to_string(&profile).unwrap();
    let restored: BaselineProfile = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.observation_count(), profile.observation_count());
    assert_eq!(
        restored.inter_arrival.observation_count(),
        profile.inter_arrival.observation_count()
    );
    assert_eq!(
        restored.payload_sizes.total_observations(),
        profile.payload_sizes.total_observations()
    );
    assert_eq!(
        restored.uri_entropy.observation_count(),
        profile.uri_entropy.observation_count()
    );
    let orig_freqs = profile.method_distribution.frequencies();
    let rest_freqs = restored.method_distribution.frequencies();
    assert_eq!(orig_freqs.len(), rest_freqs.len());
}

#[test]
fn test_drift_detection() {
    let mut normalizer = TrafficNormalizer::new();
    let baseline_snaps = make_snapshots(100, 1000, 200);
    for snap in &baseline_snaps {
        normalizer.observe(snap);
    }

    let identical_profile = normalizer.build_profile();
    let self_drift = normalizer.detect_drift(&identical_profile);
    assert!(
        self_drift < 0.05,
        "self-drift should be near zero, got {self_drift}"
    );

    let mut divergent = TrafficNormalizer::new();
    for i in 0..100 {
        divergent.observe(&RequestSnapshot {
            timestamp_ms: 1000 + i * 5000,
            method: "DELETE".to_string(),
            uri: format!("/x/{}/y/{}/z/{}", i * 7, i * 13, i * 31),
            payload_size: 10_000 + i as usize * 500,
        });
    }
    let divergent_profile = divergent.build_profile();
    let high_drift = normalizer.detect_drift(&divergent_profile);
    assert!(
        high_drift > self_drift,
        "divergent drift {high_drift} should exceed self drift {self_drift}"
    );
    assert!(
        high_drift > 0.1,
        "divergent profile should show meaningful drift, got {high_drift}"
    );
}

#[test]
fn test_drift_empty_profiles() {
    let normalizer = TrafficNormalizer::new();
    let empty_profile = BaselineProfile::new();
    let drift = normalizer.detect_drift(&empty_profile);
    assert!(drift >= 0.0 && drift <= 1.0);
}

#[test]
fn test_pareto_fit() {
    let mut dist = InterArrivalDistribution::new();
    let observations = [
        150.0, 200.0, 180.0, 250.0, 300.0, 500.0, 160.0, 220.0, 400.0, 175.0,
    ];
    for &obs in &observations {
        dist.record(obs);
    }

    dist.fit();
    assert!(dist.is_fitted());
    assert_eq!(dist.observation_count(), 10);

    assert!(dist.xm() > 0.0);
    assert_eq!(dist.xm(), 150.0);

    assert!(dist.alpha() > 0.0);

    let survival_at_xm = dist.survival_probability(dist.xm());
    assert!((survival_at_xm - 1.0).abs() < f64::EPSILON);

    let survival_high = dist.survival_probability(dist.xm() * 100.0);
    assert!(survival_high < survival_at_xm);
    assert!(survival_high >= 0.0);

    if dist.alpha() > 1.0 {
        let ev = dist.expected_value().unwrap();
        assert!(ev > dist.xm());
    }
}

#[test]
fn test_pareto_fit_uniform_observations() {
    let mut dist = InterArrivalDistribution::new();
    for _ in 0..20 {
        dist.record(100.0);
    }
    dist.fit();
    assert!(dist.is_fitted());
    assert_eq!(dist.xm(), 100.0);
    assert_eq!(dist.alpha(), 1.0);
}

#[test]
fn test_pareto_ignores_non_positive() {
    let mut dist = InterArrivalDistribution::new();
    dist.record(0.0);
    dist.record(-5.0);
    dist.record(100.0);
    assert_eq!(dist.observation_count(), 1);
}

#[test]
fn test_payload_histogram_percentile() {
    let mut hist = PayloadSizeHistogram::new(100, 10);
    for size in (0..1000).step_by(10) {
        hist.record(size);
    }

    let p50 = hist.percentile_bucket(0.50);
    let p90 = hist.percentile_bucket(0.90);
    assert!(p90 >= p50);
}

#[test]
fn test_uri_entropy_distribution() {
    let mut dist = UriEntropyDistribution::new();
    dist.record("/api/users");
    dist.record("/api/users/123");
    dist.record("/");

    assert_eq!(dist.observation_count(), 3);
    assert!(dist.mean_entropy() > 0.0);
    assert!(dist.std_dev() >= 0.0);
}

#[test]
fn test_shannon_entropy_uniform() {
    let entropy = UriEntropyDistribution::shannon_entropy("abcdefghijklmnopqrstuvwxyz");
    assert!(entropy > 4.0);
}

#[test]
fn test_shannon_entropy_single_char() {
    let entropy = UriEntropyDistribution::shannon_entropy("aaaaaaa");
    assert!((entropy - 0.0).abs() < f64::EPSILON);
}

#[test]
fn test_shannon_entropy_empty() {
    assert_eq!(UriEntropyDistribution::shannon_entropy(""), 0.0);
}

#[test]
fn test_http_method_distribution() {
    let mut dist = HttpMethodDistribution::new();
    for _ in 0..80 {
        dist.record("GET");
    }
    for _ in 0..20 {
        dist.record("POST");
    }
    let freqs = dist.frequencies();
    assert!((freqs["GET"] - 0.8).abs() < f64::EPSILON);
    assert!((freqs["POST"] - 0.2).abs() < f64::EPSILON);
    assert_eq!(dist.total(), 100);
}

#[test]
fn test_http_method_js_divergence_identical() {
    let mut a = HttpMethodDistribution::new();
    let mut b = HttpMethodDistribution::new();
    for _ in 0..50 {
        a.record("GET");
        b.record("GET");
    }
    let div = a.js_divergence(&b);
    assert!(
        div < 0.001,
        "identical distributions should have ~0 divergence, got {div}"
    );
}

#[test]
fn test_http_method_js_divergence_different() {
    let mut a = HttpMethodDistribution::new();
    let mut b = HttpMethodDistribution::new();
    for _ in 0..100 {
        a.record("GET");
        b.record("DELETE");
    }
    let div = a.js_divergence(&b);
    assert!(
        div > 0.1,
        "completely different distributions should have high divergence, got {div}"
    );
}

#[test]
fn test_ks_statistic_identical() {
    let mut h1 = PayloadSizeHistogram::new(100, 10);
    let mut h2 = PayloadSizeHistogram::new(100, 10);
    for s in [50, 150, 250, 350, 450] {
        h1.record(s);
        h2.record(s);
    }
    let ks = h1.ks_statistic(&h2);
    assert!(ks < 0.001, "identical histograms KS should be ~0, got {ks}");
}

#[test]
fn test_request_snapshot_serialization() {
    let snap = RequestSnapshot {
        timestamp_ms: 1234567890,
        method: "PUT".to_string(),
        uri: "/api/update".to_string(),
        payload_size: 2048,
    };
    let json = serde_json::to_string(&snap).unwrap();
    let restored: RequestSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.timestamp_ms, snap.timestamp_ms);
    assert_eq!(restored.method, snap.method);
    assert_eq!(restored.uri, snap.uri);
    assert_eq!(restored.payload_size, snap.payload_size);
}
