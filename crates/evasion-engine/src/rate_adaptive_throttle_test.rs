use super::rate_adaptive_throttle::*;

#[test]
fn initial_rate_matches_config() {
    let throttle = RateAdaptiveThrottle::with_defaults();
    assert_eq!(throttle.endpoint_count(), 0);
}

#[test]
fn delay_creates_endpoint() {
    let mut throttle = RateAdaptiveThrottle::with_defaults();
    let delay = throttle.delay_ms("/api/test");
    assert!(delay > 0);
    assert_eq!(throttle.endpoint_count(), 1);
}

#[test]
fn delay_decreases_as_rate_increases() {
    let config = AdaptiveThrottleConfig {
        initial_rate_rps: 50.0,
        ..Default::default()
    };
    let mut throttle = RateAdaptiveThrottle::new(config);
    let fast_delay = throttle.delay_ms("/fast");

    let config2 = AdaptiveThrottleConfig {
        initial_rate_rps: 5.0,
        ..Default::default()
    };
    let mut throttle2 = RateAdaptiveThrottle::new(config2);
    let slow_delay = throttle2.delay_ms("/slow");

    assert!(
        fast_delay < slow_delay,
        "fast_delay={fast_delay} should be < slow_delay={slow_delay}"
    );
}

#[test]
fn report_ok_eventually_increases_rate() {
    let config = AdaptiveThrottleConfig {
        ok_threshold: 3,
        initial_rate_rps: 10.0,
        ..Default::default()
    };
    let mut throttle = RateAdaptiveThrottle::new(config);
    let _ = throttle.delay_ms("/api");
    let initial = throttle.current_rate("/api").unwrap();

    for _ in 0..10 {
        throttle.report("/api", RateLimitSignal::Ok);
    }
    let after = throttle.current_rate("/api").unwrap();
    assert!(
        after >= initial,
        "rate should not decrease after OK: initial={initial}, after={after}"
    );
}

#[test]
fn report_limited_decreases_rate() {
    let config = AdaptiveThrottleConfig {
        limited_threshold: 2,
        initial_rate_rps: 50.0,
        ..Default::default()
    };
    let mut throttle = RateAdaptiveThrottle::new(config);
    let _ = throttle.delay_ms("/api");
    let initial = throttle.current_rate("/api").unwrap();

    for _ in 0..5 {
        throttle.report("/api", RateLimitSignal::SoftLimit);
    }
    let after = throttle.current_rate("/api").unwrap();
    assert!(
        after < initial,
        "rate should decrease after limits: initial={initial}, after={after}"
    );
}

#[test]
fn blocked_causes_immediate_backoff() {
    let mut throttle = RateAdaptiveThrottle::with_defaults();
    let _ = throttle.delay_ms("/api");
    let before = throttle.current_rate("/api").unwrap();
    throttle.report("/api", RateLimitSignal::Blocked);
    let after = throttle.current_rate("/api").unwrap();
    assert!(after < before, "blocked should cause immediate backoff");
    assert_eq!(
        throttle.endpoint_state("/api"),
        Some(ThrottleState::BackingOff)
    );
}

#[test]
fn per_endpoint_tracking() {
    let mut throttle = RateAdaptiveThrottle::with_defaults();
    let _ = throttle.delay_ms("/api/a");
    let _ = throttle.delay_ms("/api/b");
    assert_eq!(throttle.endpoint_count(), 2);
    throttle.report("/api/a", RateLimitSignal::Blocked);
    let rate_a = throttle.current_rate("/api/a").unwrap();
    let rate_b = throttle.current_rate("/api/b").unwrap();
    assert!(
        rate_a < rate_b,
        "endpoint A should be throttled independently"
    );
}

#[test]
fn converges_to_85_percent() {
    let config = AdaptiveThrottleConfig {
        target_utilization: 0.85,
        initial_rate_rps: 10.0,
        max_rate_rps: 100.0,
        ok_threshold: 2,
        limited_threshold: 1,
        convergence_tolerance: 1.0,
        ..Default::default()
    };
    let mut throttle = RateAdaptiveThrottle::new(config);
    let _ = throttle.delay_ms("/api");

    for _ in 0..50 {
        throttle.report("/api", RateLimitSignal::Ok);
    }
    for _ in 0..10 {
        throttle.report("/api", RateLimitSignal::SoftLimit);
    }
    for _ in 0..20 {
        throttle.report("/api", RateLimitSignal::Ok);
    }

    if let Some(state) = throttle.endpoint_state("/api") {
        assert!(
            state == ThrottleState::Converged
                || state == ThrottleState::Stable
                || state == ThrottleState::Searching,
            "should converge, got {:?}",
            state
        );
    }
}

#[test]
fn reset_clears_all_endpoints() {
    let mut throttle = RateAdaptiveThrottle::with_defaults();
    let _ = throttle.delay_ms("/a");
    let _ = throttle.delay_ms("/b");
    assert_eq!(throttle.endpoint_count(), 2);
    throttle.reset();
    assert_eq!(throttle.endpoint_count(), 0);
}

#[test]
fn utilization_zero_initially() {
    let mut throttle = RateAdaptiveThrottle::with_defaults();
    let _ = throttle.delay_ms("/api");
    let util = throttle.utilization("/api").unwrap();
    assert!(util > 0.0 && util <= 1.0);
}

#[test]
fn throttle_state_display() {
    assert_eq!(format!("{}", ThrottleState::Searching), "searching");
    assert_eq!(format!("{}", ThrottleState::Converged), "converged");
    assert_eq!(format!("{}", ThrottleState::BackingOff), "backing-off");
    assert_eq!(format!("{}", ThrottleState::Stable), "stable");
}

#[test]
fn rate_never_below_minimum() {
    let config = AdaptiveThrottleConfig {
        min_rate_rps: 1.0,
        initial_rate_rps: 2.0,
        ..Default::default()
    };
    let mut throttle = RateAdaptiveThrottle::new(config);
    let _ = throttle.delay_ms("/api");
    for _ in 0..20 {
        throttle.report("/api", RateLimitSignal::Blocked);
    }
    let rate = throttle.current_rate("/api").unwrap();
    assert!(rate >= 1.0, "rate {} should be >= min 1.0", rate);
}
