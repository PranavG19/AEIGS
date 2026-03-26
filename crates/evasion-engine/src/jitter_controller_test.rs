use super::jitter_controller::*;

#[test]
fn default_controller_produces_delays() {
    let mut ctrl = JitterController::with_defaults();
    let delay = ctrl.next_delay_ms();
    assert!(delay > 0);
}

#[test]
fn delays_respect_minimum() {
    let config = JitterConfig {
        min_delay_ms: 100,
        session_bias_ms: 0,
        ..Default::default()
    };
    let mut ctrl = JitterController::with_seed(config, 42);
    for _ in 0..100 {
        let delay = ctrl.next_delay_ms();
        assert!(delay >= 100, "delay {} should be >= 100", delay);
    }
}

#[test]
fn delays_respect_maximum() {
    let config = JitterConfig {
        max_delay_ms: 5000,
        ..Default::default()
    };
    let mut ctrl = JitterController::with_seed(config, 42);
    for _ in 0..100 {
        let delay = ctrl.next_delay_ms();
        assert!(delay <= 5000, "delay {} should be <= 5000", delay);
    }
}

#[test]
fn session_bias_added_to_delays() {
    let config_no_bias = JitterConfig {
        session_bias_ms: 0,
        ..Default::default()
    };
    let config_bias = JitterConfig {
        session_bias_ms: 500,
        ..Default::default()
    };
    let mut ctrl1 = JitterController::with_seed(config_no_bias, 42);
    let mut ctrl2 = JitterController::with_seed(config_bias, 42);
    let d1 = ctrl1.next_delay_ms();
    let d2 = ctrl2.next_delay_ms();
    assert!(d2 >= d1, "biased delay {} should be >= unbiased {}", d2, d1);
}

#[test]
fn same_seed_produces_same_sequence() {
    let config = JitterConfig::default();
    let mut ctrl1 = JitterController::with_seed(config.clone(), 123);
    let mut ctrl2 = JitterController::with_seed(config, 123);
    for _ in 0..20 {
        assert_eq!(ctrl1.next_delay_ms(), ctrl2.next_delay_ms());
    }
}

#[test]
fn different_seeds_produce_different_sequences() {
    let config = JitterConfig::default();
    let mut ctrl1 = JitterController::with_seed(config.clone(), 1);
    let mut ctrl2 = JitterController::with_seed(config, 2);
    let mut all_same = true;
    for _ in 0..10 {
        if ctrl1.next_delay_ms() != ctrl2.next_delay_ms() {
            all_same = false;
            break;
        }
    }
    assert!(!all_same, "different seeds should produce different delays");
}

#[test]
fn burst_dampening_activates_on_fast_requests() {
    let config = JitterConfig {
        min_delay_ms: 100,
        max_delay_ms: 100_000,
        burst_window_size: 5,
        burst_threshold: 0.6,
        burst_dampen_factor: 3.0,
        pareto_alpha: 100.0,
        session_bias_ms: 0,
    };
    let mut ctrl = JitterController::new(config);
    for _ in 0..5 {
        ctrl.next_delay_ms();
    }
    let post_fill = ctrl.next_delay_ms();
    assert!(post_fill > 0);
}

#[test]
fn total_requests_tracks_count() {
    let mut ctrl = JitterController::with_defaults();
    assert_eq!(ctrl.total_requests(), 0);
    ctrl.next_delay_ms();
    assert_eq!(ctrl.total_requests(), 1);
    ctrl.next_delay_ms();
    assert_eq!(ctrl.total_requests(), 2);
}

#[test]
fn reset_clears_state() {
    let mut ctrl = JitterController::with_defaults();
    ctrl.next_delay_ms();
    ctrl.next_delay_ms();
    assert_eq!(ctrl.total_requests(), 2);
    ctrl.reset();
    assert_eq!(ctrl.total_requests(), 0);
}

#[test]
fn timing_profile_reflects_state() {
    let mut ctrl = JitterController::with_defaults();
    for _ in 0..10 {
        ctrl.next_delay_ms();
    }
    let profile = ctrl.timing_profile();
    assert_eq!(profile.total_requests, 10);
    assert!(profile.mean_delay_ms > 0.0);
    assert!(profile.min_observed_ms <= profile.max_observed_ms);
    assert!((profile.pareto_alpha - 2.0).abs() < f64::EPSILON);
}

#[test]
fn pareto_distribution_produces_heavy_tail() {
    let config = JitterConfig {
        pareto_alpha: 1.5,
        min_delay_ms: 100,
        max_delay_ms: 60_000,
        session_bias_ms: 0,
        ..Default::default()
    };
    let mut ctrl = JitterController::with_seed(config, 42);
    let mut delays: Vec<u64> = (0..200).map(|_| ctrl.next_delay_ms()).collect();
    delays.sort();
    let median = delays[100];
    let p90 = delays[180];
    assert!(
        p90 > median * 2,
        "Pareto should have heavy tail: median={median}, p90={p90}"
    );
}

#[test]
fn high_alpha_produces_tighter_distribution() {
    let config_low = JitterConfig {
        pareto_alpha: 1.2,
        min_delay_ms: 100,
        max_delay_ms: 100_000,
        session_bias_ms: 0,
        ..Default::default()
    };
    let config_high = JitterConfig {
        pareto_alpha: 5.0,
        min_delay_ms: 100,
        max_delay_ms: 100_000,
        session_bias_ms: 0,
        ..Default::default()
    };
    let mut ctrl_low = JitterController::with_seed(config_low, 42);
    let mut ctrl_high = JitterController::with_seed(config_high, 42);
    let delays_low: Vec<u64> = (0..100).map(|_| ctrl_low.next_delay_ms()).collect();
    let delays_high: Vec<u64> = (0..100).map(|_| ctrl_high.next_delay_ms()).collect();
    let variance_low: f64 = {
        let mean = delays_low.iter().sum::<u64>() as f64 / delays_low.len() as f64;
        delays_low
            .iter()
            .map(|&d| (d as f64 - mean).powi(2))
            .sum::<f64>()
            / delays_low.len() as f64
    };
    let variance_high: f64 = {
        let mean = delays_high.iter().sum::<u64>() as f64 / delays_high.len() as f64;
        delays_high
            .iter()
            .map(|&d| (d as f64 - mean).powi(2))
            .sum::<f64>()
            / delays_high.len() as f64
    };
    assert!(
        variance_high < variance_low,
        "higher alpha should produce lower variance: low={variance_low}, high={variance_high}"
    );
}
