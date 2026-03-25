use super::*;

#[test]
fn build_race_batch_correct_count() {
    let config = RaceConfig {
        burst_size: 15,
        endpoint: "/api/redeem".to_string(),
        method: "POST".to_string(),
        ..RaceConfig::default()
    };

    let batch = build_race_batch(&config);
    assert_eq!(batch.len(), 15);
    for (i, req) in batch.iter().enumerate() {
        assert_eq!(req.index, i as u32);
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/redeem");
    }
}

#[test]
fn build_race_batch_carries_headers() {
    let config = RaceConfig {
        burst_size: 3,
        headers: vec![
            ("Cookie".to_string(), "session=abc123".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        ..RaceConfig::default()
    };

    let batch = build_race_batch(&config);
    for req in &batch {
        assert_eq!(req.headers.len(), 2);
        assert!(req.headers.iter().any(|(k, _)| k == "Cookie"));
    }
}

#[test]
fn build_race_batch_carries_body() {
    let config = RaceConfig {
        burst_size: 2,
        body: Some(b"{\"code\":\"DISCOUNT50\"}".to_vec()),
        ..RaceConfig::default()
    };

    let batch = build_race_batch(&config);
    for req in &batch {
        assert!(req.body.is_some());
        let body = req.body.as_ref().unwrap();
        assert!(String::from_utf8_lossy(body).contains("DISCOUNT50"));
    }
}

#[test]
fn serialize_http11_basic() {
    let request = RaceRequest {
        index: 0,
        method: "POST".to_string(),
        path: "/api/redeem".to_string(),
        headers: vec![("Cookie".to_string(), "sid=abc".to_string())],
        body: Some(b"code=FREE".to_vec()),
    };

    let raw = serialize_http11(&request, "target.local");
    let text = String::from_utf8_lossy(&raw.bytes);

    assert!(text.starts_with("POST /api/redeem HTTP/1.1\r\n"));
    assert!(text.contains("Host: target.local\r\n"));
    assert!(text.contains("Cookie: sid=abc\r\n"));
    assert!(text.contains("Content-Length: 9\r\n"));
    assert!(text.ends_with("code=FREE"));
}

#[test]
fn serialize_http11_no_body() {
    let request = RaceRequest {
        index: 0,
        method: "GET".to_string(),
        path: "/api/balance".to_string(),
        headers: Vec::new(),
        body: None,
    };

    let raw = serialize_http11(&request, "target.local");
    let text = String::from_utf8_lossy(&raw.bytes);

    assert!(text.starts_with("GET /api/balance HTTP/1.1\r\n"));
    assert!(text.contains("Host: target.local\r\n"));
    assert!(text.ends_with("\r\n"));
    assert!(!text.contains("Content-Length"));
}

#[test]
fn serialize_boundary_offset_at_end() {
    let request = RaceRequest {
        index: 0,
        method: "GET".to_string(),
        path: "/".to_string(),
        headers: Vec::new(),
        body: None,
    };

    let raw = serialize_http11(&request, "x.com");
    assert_eq!(raw.boundary_offset, raw.bytes.len() - 1);
}

#[test]
fn single_packet_small_requests() {
    let requests: Vec<RawHttpRequest> = (0..5)
        .map(|i| {
            let req = RaceRequest {
                index: i,
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: Vec::new(),
                body: None,
            };
            serialize_http11(&req, "x.com")
        })
        .collect();

    let packet = build_single_packet(&requests);
    assert!(packet.is_some(), "5 tiny requests should fit in one packet");

    let data = packet.unwrap();
    let text = String::from_utf8_lossy(&data);
    let count = text.matches("HTTP/1.1").count();
    assert_eq!(count, 5, "should contain 5 HTTP requests");
}

#[test]
fn single_packet_too_large() {
    let big_body = vec![b'A'; 500];
    let requests: Vec<RawHttpRequest> = (0..5)
        .map(|i| {
            let req = RaceRequest {
                index: i,
                method: "POST".to_string(),
                path: "/".to_string(),
                headers: Vec::new(),
                body: Some(big_body.clone()),
            };
            serialize_http11(&req, "x.com")
        })
        .collect();

    let packet = build_single_packet(&requests);
    assert!(
        packet.is_none(),
        "5 requests with 500-byte bodies should exceed MSS"
    );
}

#[test]
fn recommend_strategy_small_requests() {
    let strategy = recommend_strategy(100, 5);
    assert_eq!(strategy, DeliveryStrategy::SinglePacket);
}

#[test]
fn recommend_strategy_medium_requests() {
    let strategy = recommend_strategy(200, 10);
    assert_eq!(strategy, DeliveryStrategy::LastByte);
}

#[test]
fn recommend_strategy_large_burst() {
    let strategy = recommend_strategy(200, 50);
    assert_eq!(strategy, DeliveryStrategy::ParallelBurst);
}

#[test]
fn detect_anomalies_multiple_successes() {
    let results = RaceBurstResult {
        burst_index: 0,
        strategy: DeliveryStrategy::ParallelBurst,
        request_count: 10,
        success_count: 5,
        response_statuses: vec![200, 200, 200, 200, 200, 409, 409, 409, 409, 409],
        timing_spread_us: 1000,
        anomalies: Vec::new(),
    };

    let anomalies = detect_anomalies(&results, 1);
    assert!(!anomalies.is_empty());
    assert!(anomalies.iter().any(|a| matches!(
        a,
        RaceAnomaly::MultipleSuccesses {
            expected_max: 1,
            actual: 5
        }
    )));
}

#[test]
fn detect_anomalies_response_divergence() {
    let results = RaceBurstResult {
        burst_index: 0,
        strategy: DeliveryStrategy::SinglePacket,
        request_count: 5,
        success_count: 1,
        response_statuses: vec![200, 429, 429, 429, 429],
        timing_spread_us: 500,
        anomalies: Vec::new(),
    };

    let anomalies = detect_anomalies(&results, 1);
    assert!(
        anomalies
            .iter()
            .any(|a| matches!(a, RaceAnomaly::ResponseDivergence { .. }))
    );
}

#[test]
fn detect_anomalies_no_issues() {
    let results = RaceBurstResult {
        burst_index: 0,
        strategy: DeliveryStrategy::ParallelBurst,
        request_count: 10,
        success_count: 1,
        response_statuses: vec![200, 409, 409, 409, 409, 409, 409, 409, 409, 409],
        timing_spread_us: 1000,
        anomalies: Vec::new(),
    };

    let anomalies = detect_anomalies(&results, 1);
    assert!(
        anomalies
            .iter()
            .all(|a| !matches!(a, RaceAnomaly::MultipleSuccesses { .. }))
    );
}

#[test]
fn race_severity_values() {
    assert!(race_severity(RaceTarget::BalanceTransfer) > 9.0);
    assert!(race_severity(RaceTarget::CouponRedemption) >= 8.0);
    assert!(race_severity(RaceTarget::TokenReuse) >= 8.0);
    assert!(race_severity(RaceTarget::VoteManipulation) < 6.0);
}

#[test]
fn exploitability_no_rate_limit_fast_server() {
    let score = estimate_exploitability(RaceTarget::BalanceTransfer, false, 30);
    assert!(
        score > 0.8,
        "fast server + no rate limit = high exploitability, got {score}"
    );
}

#[test]
fn exploitability_with_rate_limit() {
    let without = estimate_exploitability(RaceTarget::CouponRedemption, false, 100);
    let with = estimate_exploitability(RaceTarget::CouponRedemption, true, 100);
    assert!(with < without, "rate limit should reduce exploitability");
}

#[test]
fn exploitability_slow_server() {
    let fast = estimate_exploitability(RaceTarget::InventoryCheck, false, 30);
    let slow = estimate_exploitability(RaceTarget::InventoryCheck, false, 500);
    assert!(slow < fast, "slow server = lower exploitability");
}

#[test]
fn exploitability_clamped_to_01() {
    let score = estimate_exploitability(RaceTarget::BalanceTransfer, false, 10);
    assert!(score >= 0.0 && score <= 1.0);

    let score2 = estimate_exploitability(RaceTarget::SequencePrediction, true, 1000);
    assert!(score2 >= 0.0 && score2 <= 1.0);
}

#[test]
fn race_target_display() {
    assert_eq!(
        format!("{}", RaceTarget::CouponRedemption),
        "coupon_redemption"
    );
    assert_eq!(
        format!("{}", RaceTarget::BalanceTransfer),
        "balance_transfer"
    );
    assert_eq!(
        format!("{}", RaceTarget::RateLimitBypass),
        "rate_limit_bypass"
    );
}

#[test]
fn delivery_strategy_display() {
    assert_eq!(
        format!("{}", DeliveryStrategy::SinglePacket),
        "single_packet"
    );
    assert_eq!(format!("{}", DeliveryStrategy::LastByte), "last_byte");
    assert_eq!(
        format!("{}", DeliveryStrategy::ParallelBurst),
        "parallel_burst"
    );
    assert_eq!(format!("{}", DeliveryStrategy::Pipelined), "pipelined");
}

#[test]
fn anomaly_display() {
    let a = RaceAnomaly::MultipleSuccesses {
        expected_max: 1,
        actual: 5,
    };
    assert!(format!("{a}").contains("expected max 1"));

    let b = RaceAnomaly::StateInconsistency {
        description: "negative balance".to_string(),
    };
    assert!(format!("{b}").contains("negative balance"));

    let c = RaceAnomaly::ResponseDivergence {
        status_a: 200,
        status_b: 409,
    };
    assert!(format!("{c}").contains("200"));

    let d = RaceAnomaly::LockContention {
        fast_ms: 5,
        slow_ms: 500,
    };
    assert!(format!("{d}").contains("500ms"));
}

#[test]
fn default_config_sensible_values() {
    let config = RaceConfig::default();
    assert_eq!(config.burst_size, 10);
    assert_eq!(config.warmup_rounds, 2);
    assert_eq!(config.max_retries, 3);
    assert_eq!(config.strategy, DeliveryStrategy::ParallelBurst);
}
