use super::race_window_detector::*;

#[test]
fn config_default_values() {
    let config = RaceWindowConfig::default();
    assert_eq!(config.max_concurrent, 50);
    assert_eq!(config.initial_requests, 10);
    assert_eq!(config.timeout_ms, 5000);
    assert!(config.adaptive);
}

#[test]
fn config_builder_sets_max_concurrent() {
    let config = RaceWindowConfig::default().with_max_concurrent(100);
    assert_eq!(config.max_concurrent, 100);
}

#[test]
fn config_builder_sets_initial_requests() {
    let config = RaceWindowConfig::default().with_initial_requests(5);
    assert_eq!(config.initial_requests, 5);
}

#[test]
fn config_builder_sets_timeout_ms() {
    let config = RaceWindowConfig::default().with_timeout_ms(10000);
    assert_eq!(config.timeout_ms, 10000);
}

#[test]
fn config_builder_sets_adaptive() {
    let config = RaceWindowConfig::default().with_adaptive(false);
    assert!(!config.adaptive);
}

#[test]
fn identify_race_prone_filters_non_state_changing() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let endpoints = vec![
        EndpointInfo {
            url: "http://127.0.0.1:3000/api/transfer".into(),
            method: "POST".into(),
            has_state_change: true,
            operation_type: OperationType::Transfer,
        },
        EndpointInfo {
            url: "http://127.0.0.1:3000/api/users".into(),
            method: "GET".into(),
            has_state_change: false,
            operation_type: OperationType::AccountCreate,
        },
    ];
    let candidates = detector.identify_race_prone(&endpoints);
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        candidates[0].endpoint.url,
        "http://127.0.0.1:3000/api/transfer"
    );
}

#[test]
fn identify_race_prone_rejects_get_method() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let endpoints = vec![EndpointInfo {
        url: "http://127.0.0.1:3000/api/transfer".into(),
        method: "GET".into(),
        has_state_change: true,
        operation_type: OperationType::Transfer,
    }];
    let candidates = detector.identify_race_prone(&endpoints);
    assert!(candidates.is_empty());
}

#[test]
fn identify_race_prone_rejects_no_state_change() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let endpoints = vec![EndpointInfo {
        url: "http://127.0.0.1:3000/api/transfer".into(),
        method: "POST".into(),
        has_state_change: false,
        operation_type: OperationType::Transfer,
    }];
    let candidates = detector.identify_race_prone(&endpoints);
    assert!(candidates.is_empty());
}

#[test]
fn identify_race_prone_accepts_all_state_changing_methods() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    for method in &["POST", "PUT", "DELETE", "PATCH"] {
        let endpoints = vec![EndpointInfo {
            url: "http://127.0.0.1:3000/api/transfer".into(),
            method: method.to_string(),
            has_state_change: true,
            operation_type: OperationType::Transfer,
        }];
        let candidates = detector.identify_race_prone(&endpoints);
        assert_eq!(
            candidates.len(),
            1,
            "expected candidate for method {method}"
        );
    }
}

#[test]
fn identify_race_prone_confidence_transfer_highest() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let endpoints = vec![
        EndpointInfo {
            url: "http://127.0.0.1:3000/transfer".into(),
            method: "POST".into(),
            has_state_change: true,
            operation_type: OperationType::Transfer,
        },
        EndpointInfo {
            url: "http://127.0.0.1:3000/vote".into(),
            method: "POST".into(),
            has_state_change: true,
            operation_type: OperationType::Vote,
        },
    ];
    let candidates = detector.identify_race_prone(&endpoints);
    assert_eq!(candidates.len(), 2);
    assert!(candidates[0].confidence > candidates[1].confidence);
}

#[test]
fn identify_race_prone_all_operation_types_above_threshold() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    for op in OperationType::all() {
        let endpoints = vec![EndpointInfo {
            url: "http://127.0.0.1:3000/test".into(),
            method: "POST".into(),
            has_state_change: true,
            operation_type: *op,
        }];
        let candidates = detector.identify_race_prone(&endpoints);
        assert_eq!(
            candidates.len(),
            1,
            "operation type {:?} should produce a candidate",
            op
        );
    }
}

#[test]
fn measure_window_returns_positive_gap() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let measurement = detector.measure_window("http://127.0.0.1:3000/transfer", "POST");
    assert!(measurement.window_ns > 0);
    assert_eq!(
        measurement.window_ns,
        measurement.write_time_ns - measurement.read_time_ns
    );
}

#[test]
fn measure_window_write_after_read() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let m = detector.measure_window("http://127.0.0.1:3000/transfer", "POST");
    assert!(m.write_time_ns > m.read_time_ns);
}

#[test]
fn generate_attack_correct_concurrency() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let candidate = RaceCandidate {
        endpoint: EndpointInfo {
            url: "http://127.0.0.1:3000/transfer".into(),
            method: "POST".into(),
            has_state_change: true,
            operation_type: OperationType::Transfer,
        },
        estimated_window_ms: 5.0,
        confidence: 0.95,
    };
    let attack = detector.generate_attack(&candidate, 20);
    assert_eq!(attack.concurrent_requests, 20);
    assert_eq!(attack.timing_offset_ns.len(), 20);
}

#[test]
fn generate_attack_timing_offsets_ascending() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let candidate = RaceCandidate {
        endpoint: EndpointInfo {
            url: "http://127.0.0.1:3000/transfer".into(),
            method: "POST".into(),
            has_state_change: true,
            operation_type: OperationType::Transfer,
        },
        estimated_window_ms: 10.0,
        confidence: 0.9,
    };
    let attack = detector.generate_attack(&candidate, 5);
    for window in attack.timing_offset_ns.windows(2) {
        assert!(window[1] >= window[0]);
    }
}

#[test]
fn generate_attack_first_offset_is_zero() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let candidate = RaceCandidate {
        endpoint: EndpointInfo {
            url: "http://127.0.0.1:3000/transfer".into(),
            method: "POST".into(),
            has_state_change: true,
            operation_type: OperationType::Transfer,
        },
        estimated_window_ms: 5.0,
        confidence: 0.9,
    };
    let attack = detector.generate_attack(&candidate, 10);
    assert_eq!(attack.timing_offset_ns[0], 0);
}

#[test]
fn generate_attack_payload_contains_operation() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let candidate = RaceCandidate {
        endpoint: EndpointInfo {
            url: "http://127.0.0.1:3000/purchase".into(),
            method: "POST".into(),
            has_state_change: true,
            operation_type: OperationType::Purchase,
        },
        estimated_window_ms: 5.0,
        confidence: 0.9,
    };
    let attack = detector.generate_attack(&candidate, 5);
    assert!(attack.payload.contains("purchase"));
}

#[test]
fn generate_attack_single_request_zero_offset() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let candidate = RaceCandidate {
        endpoint: EndpointInfo {
            url: "http://127.0.0.1:3000/transfer".into(),
            method: "POST".into(),
            has_state_change: true,
            operation_type: OperationType::Transfer,
        },
        estimated_window_ms: 5.0,
        confidence: 0.9,
    };
    let attack = detector.generate_attack(&candidate, 1);
    assert_eq!(attack.timing_offset_ns, vec![0]);
}

#[test]
fn verify_exploit_detects_duplicates() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let attack = RaceAttack {
        target_url: "http://127.0.0.1:3000/transfer".into(),
        method: "POST".into(),
        concurrent_requests: 5,
        timing_offset_ns: vec![0; 5],
        payload: "{}".into(),
    };
    let responses = vec![
        RaceResponse {
            request_index: 0,
            status: 200,
            body: "{\"ok\":true}".into(),
            response_time_ns: 1000,
        },
        RaceResponse {
            request_index: 1,
            status: 200,
            body: "{\"ok\":true}".into(),
            response_time_ns: 1100,
        },
        RaceResponse {
            request_index: 2,
            status: 200,
            body: "{\"ok\":true}".into(),
            response_time_ns: 1200,
        },
        RaceResponse {
            request_index: 3,
            status: 409,
            body: "{\"error\":\"conflict\"}".into(),
            response_time_ns: 1300,
        },
        RaceResponse {
            request_index: 4,
            status: 409,
            body: "{\"error\":\"conflict\"}".into(),
            response_time_ns: 1400,
        },
    ];
    let verification = detector.verify_exploit(&attack, &responses);
    assert!(verification.exploited);
    assert_eq!(verification.duplicate_effects, 3);
}

#[test]
fn verify_exploit_no_duplicates_single_success() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let attack = RaceAttack {
        target_url: "http://127.0.0.1:3000/transfer".into(),
        method: "POST".into(),
        concurrent_requests: 3,
        timing_offset_ns: vec![0; 3],
        payload: "{}".into(),
    };
    let responses = vec![
        RaceResponse {
            request_index: 0,
            status: 200,
            body: "{\"ok\":true}".into(),
            response_time_ns: 1000,
        },
        RaceResponse {
            request_index: 1,
            status: 409,
            body: "{\"error\":\"conflict\"}".into(),
            response_time_ns: 1100,
        },
        RaceResponse {
            request_index: 2,
            status: 409,
            body: "{\"error\":\"conflict\"}".into(),
            response_time_ns: 1200,
        },
    ];
    let verification = detector.verify_exploit(&attack, &responses);
    assert!(!verification.exploited);
    assert_eq!(verification.duplicate_effects, 0);
}

#[test]
fn verify_exploit_no_duplicates_all_fail() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let attack = RaceAttack {
        target_url: "http://127.0.0.1:3000/transfer".into(),
        method: "POST".into(),
        concurrent_requests: 3,
        timing_offset_ns: vec![0; 3],
        payload: "{}".into(),
    };
    let responses = vec![
        RaceResponse {
            request_index: 0,
            status: 500,
            body: "error".into(),
            response_time_ns: 1000,
        },
        RaceResponse {
            request_index: 1,
            status: 500,
            body: "error".into(),
            response_time_ns: 1100,
        },
        RaceResponse {
            request_index: 2,
            status: 500,
            body: "error".into(),
            response_time_ns: 1200,
        },
    ];
    let verification = detector.verify_exploit(&attack, &responses);
    assert!(!verification.exploited);
}

#[test]
fn verify_exploit_evidence_contains_url() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let attack = RaceAttack {
        target_url: "http://127.0.0.1:3000/transfer".into(),
        method: "POST".into(),
        concurrent_requests: 2,
        timing_offset_ns: vec![0; 2],
        payload: "{}".into(),
    };
    let responses = vec![
        RaceResponse {
            request_index: 0,
            status: 200,
            body: "{\"ok\":true}".into(),
            response_time_ns: 1000,
        },
        RaceResponse {
            request_index: 1,
            status: 200,
            body: "{\"ok\":true}".into(),
            response_time_ns: 1100,
        },
    ];
    let verification = detector.verify_exploit(&attack, &responses);
    assert!(verification.evidence.contains("transfer"));
}

#[test]
fn adaptive_concurrency_increases_until_success() {
    let config = RaceWindowConfig::default()
        .with_initial_requests(5)
        .with_max_concurrent(50);
    let detector = RaceWindowDetector::new(config);
    let candidate = RaceCandidate {
        endpoint: EndpointInfo {
            url: "http://127.0.0.1:3000/transfer".into(),
            method: "POST".into(),
            has_state_change: true,
            operation_type: OperationType::Transfer,
        },
        estimated_window_ms: 5.0,
        confidence: 0.95,
    };
    let result = detector.adaptive_concurrency(&candidate);
    assert!(result.optimal_concurrency >= 5);
    assert!(!result.attempts.is_empty());
}

#[test]
fn adaptive_concurrency_attempts_are_ascending() {
    let config = RaceWindowConfig::default()
        .with_initial_requests(2)
        .with_max_concurrent(50);
    let detector = RaceWindowDetector::new(config);
    let candidate = RaceCandidate {
        endpoint: EndpointInfo {
            url: "http://127.0.0.1:3000/transfer".into(),
            method: "POST".into(),
            has_state_change: true,
            operation_type: OperationType::Transfer,
        },
        estimated_window_ms: 5.0,
        confidence: 0.95,
    };
    let result = detector.adaptive_concurrency(&candidate);
    for window in result.attempts.windows(2) {
        assert!(window[1].0 > window[0].0);
    }
}

#[test]
fn adaptive_concurrency_stops_on_success() {
    let config = RaceWindowConfig::default()
        .with_initial_requests(15)
        .with_max_concurrent(100);
    let detector = RaceWindowDetector::new(config);
    let candidate = RaceCandidate {
        endpoint: EndpointInfo {
            url: "http://127.0.0.1:3000/transfer".into(),
            method: "POST".into(),
            has_state_change: true,
            operation_type: OperationType::Transfer,
        },
        estimated_window_ms: 5.0,
        confidence: 0.95,
    };
    let result = detector.adaptive_concurrency(&candidate);
    let last = result.attempts.last().unwrap();
    assert!(last.1, "last attempt should be successful");
}

#[test]
fn operation_type_display() {
    assert_eq!(OperationType::Transfer.to_string(), "transfer");
    assert_eq!(OperationType::Purchase.to_string(), "purchase");
    assert_eq!(OperationType::Vote.to_string(), "vote");
    assert_eq!(OperationType::AccountCreate.to_string(), "account_create");
    assert_eq!(OperationType::PasswordChange.to_string(), "password_change");
    assert_eq!(OperationType::TokenGenerate.to_string(), "token_generate");
    assert_eq!(OperationType::BalanceModify.to_string(), "balance_modify");
}

#[test]
fn operation_type_all_returns_seven() {
    assert_eq!(OperationType::all().len(), 7);
}

#[test]
fn infer_operation_type_transfer() {
    assert_eq!(
        infer_operation_type("http://localhost/api/transfer"),
        Some(OperationType::Transfer)
    );
}

#[test]
fn infer_operation_type_purchase() {
    assert_eq!(
        infer_operation_type("http://localhost/purchase"),
        Some(OperationType::Purchase)
    );
}

#[test]
fn infer_operation_type_vote() {
    assert_eq!(
        infer_operation_type("http://localhost/api/vote"),
        Some(OperationType::Vote)
    );
}

#[test]
fn infer_operation_type_unknown_path() {
    assert_eq!(infer_operation_type("http://localhost/api/health"), None);
}

#[test]
fn infer_operation_type_case_insensitive() {
    assert_eq!(
        infer_operation_type("http://localhost/api/Transfer"),
        Some(OperationType::Transfer)
    );
}

#[test]
fn identify_race_prone_empty_input() {
    let detector = RaceWindowDetector::new(RaceWindowConfig::default());
    let candidates = detector.identify_race_prone(&[]);
    assert!(candidates.is_empty());
}
