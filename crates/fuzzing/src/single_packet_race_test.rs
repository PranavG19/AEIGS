use super::single_packet_race::*;
use std::collections::HashMap;

#[test]
fn default_config_sane_values() {
    let config = RaceConfig::default();
    assert_eq!(config.num_requests, 20);
    assert_eq!(config.strategy, RaceStrategy::DoubleSpend);
    assert_eq!(config.warmup_requests, 5);
    assert!(config.vary_last_byte);
}

#[test]
fn generates_correct_number_of_requests() {
    let engine = SinglePacketRaceEngine::new(RaceConfig {
        num_requests: 10,
        target_endpoints: vec!["http://localhost:8080/transfer".to_string()],
        ..RaceConfig::default()
    });
    let requests = engine.generate_requests();
    assert_eq!(requests.len(), 10);
}

#[test]
fn double_spend_requests_have_post_method() {
    let engine = SinglePacketRaceEngine::new(RaceConfig {
        num_requests: 5,
        strategy: RaceStrategy::DoubleSpend,
        target_endpoints: vec!["http://localhost:8080/api/transfer".to_string()],
        ..RaceConfig::default()
    });
    let requests = engine.generate_requests();
    for req in &requests {
        assert_eq!(req.method, HttpMethod::Post);
        assert!(req.body.is_some());
    }
}

#[test]
fn privilege_escalation_uses_put() {
    let engine = SinglePacketRaceEngine::new(RaceConfig {
        num_requests: 3,
        strategy: RaceStrategy::PrivilegeEscalation,
        target_endpoints: vec!["http://localhost:8080/api/roles".to_string()],
        ..RaceConfig::default()
    });
    let requests = engine.generate_requests();
    for req in &requests {
        assert_eq!(req.method, HttpMethod::Put);
        assert!(req.body.as_ref().unwrap().contains("admin"));
    }
}

#[test]
fn coupon_reuse_sends_identical_bodies() {
    let engine = SinglePacketRaceEngine::new(RaceConfig {
        num_requests: 5,
        strategy: RaceStrategy::CouponReuse,
        target_endpoints: vec!["http://localhost:8080/apply-coupon".to_string()],
        ..RaceConfig::default()
    });
    let requests = engine.generate_requests();
    let bodies: Vec<_> = requests.iter().map(|r| r.body.clone().unwrap()).collect();
    assert!(
        bodies.windows(2).all(|w| w[0] == w[1]),
        "coupon reuse should send identical request bodies"
    );
}

#[test]
fn build_frame_batch_produces_h2_frames() {
    let engine = SinglePacketRaceEngine::new(RaceConfig {
        num_requests: 3,
        target_endpoints: vec!["http://localhost:8080/api/action".to_string()],
        ..RaceConfig::default()
    });
    let requests = engine.generate_requests();
    let batch = engine.build_frame_batch(&requests[..3]);

    assert_eq!(batch.request_count, 3);
    assert_eq!(batch.stream_ids.len(), 3);
    assert!(
        batch.total_bytes > 0,
        "frame batch should have non-zero size"
    );
    assert_eq!(batch.stream_ids[0], 1);
    assert_eq!(batch.stream_ids[1], 3);
    assert_eq!(batch.stream_ids[2], 5);
}

#[test]
fn h2_stream_ids_are_odd_and_sequential() {
    let engine = SinglePacketRaceEngine::default();
    let requests = engine.generate_requests();
    let batch = engine.build_frame_batch(&requests);

    for (i, id) in batch.stream_ids.iter().enumerate() {
        let expected = (i as u32 * 2) + 1;
        assert_eq!(*id, expected, "stream ID should be odd and sequential");
    }
}

#[test]
fn gate_release_frame_non_empty_with_vary() {
    let engine = SinglePacketRaceEngine::new(RaceConfig {
        num_requests: 5,
        vary_last_byte: true,
        target_endpoints: vec!["http://localhost:8080/api/action".to_string()],
        ..RaceConfig::default()
    });
    let requests = engine.generate_requests();
    let gate = engine.build_gate_release(&requests);
    assert!(
        !gate.is_empty(),
        "gate release should contain last-byte frames"
    );
}

#[test]
fn gate_release_empty_without_vary() {
    let engine = SinglePacketRaceEngine::new(RaceConfig {
        num_requests: 5,
        vary_last_byte: false,
        target_endpoints: vec!["http://localhost:8080/api/action".to_string()],
        ..RaceConfig::default()
    });
    let requests = engine.generate_requests();
    let gate = engine.build_gate_release(&requests);
    assert!(
        gate.is_empty(),
        "gate release should be empty when vary_last_byte=false"
    );
}

#[test]
fn analyze_responses_detects_race_confirmed() {
    let engine = SinglePacketRaceEngine::new(RaceConfig {
        num_requests: 5,
        strategy: RaceStrategy::DoubleSpend,
        detector: SuccessDetector {
            expected_success_status: vec![200],
            max_expected_successes: 1,
            ..SuccessDetector::default()
        },
        ..RaceConfig::default()
    });

    let responses: Vec<_> = (0..5)
        .map(|i| RaceResponse {
            request_id: format!("req-{}", i),
            status_code: 200,
            headers: HashMap::new(),
            body: r#"{"status":"success","amount":100}"#.to_string(),
            elapsed_ms: 50 + i,
            h2_stream_id: (i as u32 * 2) + 1,
        })
        .collect();

    let result = engine.analyze_responses(&responses);
    assert_eq!(result.outcome, RaceOutcome::Confirmed);
    assert_eq!(result.successful_count, 5);
    assert_eq!(result.severity, RaceSeverity::Critical);
}

#[test]
fn analyze_responses_detects_mitigated() {
    let engine = SinglePacketRaceEngine::new(RaceConfig {
        num_requests: 5,
        strategy: RaceStrategy::CouponReuse,
        detector: SuccessDetector {
            expected_success_status: vec![200],
            max_expected_successes: 1,
            ..SuccessDetector::default()
        },
        ..RaceConfig::default()
    });

    let mut responses: Vec<_> = vec![RaceResponse {
        request_id: "req-0".to_string(),
        status_code: 200,
        headers: HashMap::new(),
        body: r#"{"status":"success"}"#.to_string(),
        elapsed_ms: 50,
        h2_stream_id: 1,
    }];
    for i in 1..5 {
        responses.push(RaceResponse {
            request_id: format!("req-{}", i),
            status_code: 409,
            headers: HashMap::new(),
            body: r#"{"error":"coupon already used"}"#.to_string(),
            elapsed_ms: 51 + i,
            h2_stream_id: (i as u32 * 2) + 1,
        });
    }

    let result = engine.analyze_responses(&responses);
    assert_eq!(result.outcome, RaceOutcome::Mitigated);
}

#[test]
fn analyze_empty_responses_is_error() {
    let engine = SinglePacketRaceEngine::default();
    let result = engine.analyze_responses(&[]);
    assert_eq!(result.outcome, RaceOutcome::Error);
}

#[test]
fn warmup_requests_are_get() {
    let engine = SinglePacketRaceEngine::new(RaceConfig {
        warmup_requests: 3,
        target_endpoints: vec!["http://localhost:8080/".to_string()],
        ..RaceConfig::default()
    });
    let warmups = engine.generate_warmup_requests();
    assert_eq!(warmups.len(), 3);
    for req in &warmups {
        assert_eq!(req.method, HttpMethod::Get);
        assert!(req.body.is_none());
    }
}

#[test]
fn connection_timeout_converts_correctly() {
    let engine = SinglePacketRaceEngine::new(RaceConfig {
        connection_timeout_ms: 3000,
        ..RaceConfig::default()
    });
    assert_eq!(
        engine.connection_timeout(),
        std::time::Duration::from_millis(3000)
    );
}

#[test]
fn race_strategy_display_all_variants() {
    for strategy in RaceStrategy::all() {
        let display = format!("{}", strategy);
        assert!(
            !display.is_empty(),
            "display should be non-empty for {:?}",
            strategy
        );
    }
}

#[test]
fn race_outcome_display() {
    assert_eq!(format!("{}", RaceOutcome::Confirmed), "CONFIRMED");
    assert_eq!(format!("{}", RaceOutcome::Partial), "PARTIAL");
    assert_eq!(format!("{}", RaceOutcome::Mitigated), "MITIGATED");
    assert_eq!(format!("{}", RaceOutcome::Error), "ERROR");
}

#[test]
fn severity_ordering() {
    assert!(RaceSeverity::Critical > RaceSeverity::High);
    assert!(RaceSeverity::High > RaceSeverity::Medium);
    assert!(RaceSeverity::Medium > RaceSeverity::Low);
    assert!(RaceSeverity::Low > RaceSeverity::Info);
}

#[test]
fn h2_connection_preface_valid() {
    assert!(H2_CONNECTION_PREFACE.starts_with(b"PRI"));
    assert!(H2_CONNECTION_PREFACE.ends_with(b"\r\n\r\n"));
}

#[test]
fn evidence_contains_status_distribution() {
    let engine = SinglePacketRaceEngine::default();
    let responses = vec![
        RaceResponse {
            request_id: "r1".to_string(),
            status_code: 200,
            headers: HashMap::new(),
            body: "ok".to_string(),
            elapsed_ms: 10,
            h2_stream_id: 1,
        },
        RaceResponse {
            request_id: "r2".to_string(),
            status_code: 429,
            headers: HashMap::new(),
            body: "rate limited".to_string(),
            elapsed_ms: 11,
            h2_stream_id: 3,
        },
    ];
    let result = engine.analyze_responses(&responses);
    assert!(
        result.evidence.contains("Status distribution"),
        "evidence should include status distribution"
    );
}

#[test]
fn limit_bypass_strategy_generates_requests() {
    let engine = SinglePacketRaceEngine::new(RaceConfig {
        num_requests: 8,
        strategy: RaceStrategy::LimitBypass,
        target_endpoints: vec!["http://localhost:8080/rewards".to_string()],
        ..RaceConfig::default()
    });
    let requests = engine.generate_requests();
    assert_eq!(requests.len(), 8);
    for req in &requests {
        assert_eq!(req.method, HttpMethod::Post);
    }
}

#[test]
fn session_overlap_generates_unique_sessions() {
    let engine = SinglePacketRaceEngine::new(RaceConfig {
        num_requests: 5,
        strategy: RaceStrategy::SessionOverlap,
        target_endpoints: vec!["http://localhost:8080/login".to_string()],
        ..RaceConfig::default()
    });
    let requests = engine.generate_requests();
    let bodies: Vec<_> = requests.iter().map(|r| r.body.clone().unwrap()).collect();
    let unique_count = bodies
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert_eq!(
        unique_count, 5,
        "session overlap should have unique session IDs"
    );
}

#[test]
fn toctou_requests_have_unique_ids() {
    let engine = SinglePacketRaceEngine::new(RaceConfig {
        num_requests: 4,
        strategy: RaceStrategy::Toctou,
        target_endpoints: vec!["http://localhost:8080/withdraw".to_string()],
        ..RaceConfig::default()
    });
    let requests = engine.generate_requests();
    let ids: Vec<_> = requests.iter().map(|r| &r.id).collect();
    let unique = ids.iter().collect::<std::collections::HashSet<_>>().len();
    assert_eq!(unique, 4, "each TOCTOU request should have unique id");
}

#[test]
fn partial_outcome_for_some_failures() {
    let engine = SinglePacketRaceEngine::new(RaceConfig {
        num_requests: 5,
        detector: SuccessDetector {
            expected_success_status: vec![200],
            max_expected_successes: 3,
            failure_body_contains: vec![],
            ..SuccessDetector::default()
        },
        ..RaceConfig::default()
    });

    let responses = vec![
        RaceResponse {
            request_id: "r0".to_string(),
            status_code: 200,
            headers: HashMap::new(),
            body: "ok".to_string(),
            elapsed_ms: 10,
            h2_stream_id: 1,
        },
        RaceResponse {
            request_id: "r1".to_string(),
            status_code: 500,
            headers: HashMap::new(),
            body: "internal".to_string(),
            elapsed_ms: 10,
            h2_stream_id: 3,
        },
    ];

    let result = engine.analyze_responses(&responses);
    assert!(
        result.successful_count <= result.config.detector.max_expected_successes,
        "partial should not exceed max expected"
    );
}
