use super::accel_detector::*;

#[test]
fn clean_environment_returns_clean() {
    let detector = AccelDetector::with_defaults();
    let env = TimingEnvironment {
        rdtsc_deltas: vec![1000, 1100, 950, 1050, 1000],
        wall_clock_deltas_ns: vec![1000, 1100, 950, 1050, 1000],
        sleep_requested_ms: vec![100, 100],
        sleep_actual_ms: vec![101, 99],
        cpu_frequency_mhz: None,
        tsc_invariant: false,
    };
    let result = detector.analyze(&env);
    assert_eq!(result.verdict, AccelVerdict::Clean);
}

#[test]
fn high_rdtsc_delta_detected() {
    let detector = AccelDetector::with_defaults();
    let env = TimingEnvironment {
        rdtsc_deltas: vec![
            1_000_000, 2_000_000, 1_500_000, 3_000_000, 900_000, 1_000_000, 2_000_000, 1_500_000,
            3_000_000, 900_000,
        ],
        wall_clock_deltas_ns: vec![1000; 10],
        sleep_requested_ms: vec![],
        sleep_actual_ms: vec![],
        cpu_frequency_mhz: None,
        tsc_invariant: false,
    };
    let result = detector.analyze(&env);
    assert!(result.anomaly_count > 0);
    assert_ne!(result.verdict, AccelVerdict::Clean);
}

#[test]
fn sleep_acceleration_detected() {
    let detector = AccelDetector::new(AccelDetectorConfig {
        max_sleep_error_pct: 10.0,
        confidence_threshold: 0.3,
        ..Default::default()
    });
    let env = TimingEnvironment {
        rdtsc_deltas: vec![1_000_000; 10],
        wall_clock_deltas_ns: vec![100; 10],
        sleep_requested_ms: vec![1000, 1000, 1000],
        sleep_actual_ms: vec![100, 100, 100],
        cpu_frequency_mhz: None,
        tsc_invariant: false,
    };
    let result = detector.analyze(&env);
    assert!(result.sleep_accuracy_pct < 50.0);
    assert_ne!(result.verdict, AccelVerdict::Clean);
}

#[test]
fn wall_clock_drift_detected() {
    let detector = AccelDetector::new(AccelDetectorConfig {
        max_drift_pct: 5.0,
        confidence_threshold: 0.3,
        ..Default::default()
    });
    let env = TimingEnvironment {
        rdtsc_deltas: vec![2000; 10],
        wall_clock_deltas_ns: vec![1000; 10],
        sleep_requested_ms: vec![100],
        sleep_actual_ms: vec![100],
        cpu_frequency_mhz: None,
        tsc_invariant: false,
    };
    let result = detector.analyze(&env);
    assert!(result.wall_clock_drift_pct.abs() > 5.0);
}

#[test]
fn empty_environment_is_clean() {
    let detector = AccelDetector::with_defaults();
    let env = TimingEnvironment::default();
    let result = detector.analyze(&env);
    assert_eq!(result.verdict, AccelVerdict::Clean);
    assert_eq!(result.anomaly_count, 0);
}

#[test]
fn rdtsc_mean_delta_calculated() {
    let detector = AccelDetector::with_defaults();
    let env = TimingEnvironment {
        rdtsc_deltas: vec![100, 200, 300],
        wall_clock_deltas_ns: vec![100, 200, 300],
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert!((result.rdtsc_mean_delta - 200.0).abs() < 0.001);
}

#[test]
fn sleep_accuracy_100_when_no_sleep_data() {
    let detector = AccelDetector::with_defaults();
    let env = TimingEnvironment {
        rdtsc_deltas: vec![1000],
        wall_clock_deltas_ns: vec![1000],
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert!((result.sleep_accuracy_pct - 100.0).abs() < 0.001);
}

#[test]
fn verdict_display_formatting() {
    assert_eq!(format!("{}", AccelVerdict::Clean), "clean");
    assert_eq!(format!("{}", AccelVerdict::Suspicious), "suspicious");
    assert_eq!(format!("{}", AccelVerdict::Accelerated), "accelerated");
    assert_eq!(format!("{}", AccelVerdict::Decelerated), "decelerated");
    assert_eq!(format!("{}", AccelVerdict::ClockSkewed), "clock-skewed");
}

#[test]
fn rdtsc_measurement_asm_contains_key_instructions() {
    let asm = AccelDetector::rdtsc_measurement_asm();
    assert!(asm.contains("rdtsc"));
    assert!(asm.contains("cpuid"));
    assert!(asm.contains("mfence"));
}

#[test]
fn cpu_frequency_mismatch_flagged() {
    let detector = AccelDetector::new(AccelDetectorConfig {
        expected_cpu_mhz: Some(3000),
        confidence_threshold: 0.3,
        ..Default::default()
    });
    let env = TimingEnvironment {
        rdtsc_deltas: vec![1_000_000; 5],
        wall_clock_deltas_ns: vec![100; 5],
        cpu_frequency_mhz: Some(600),
        tsc_invariant: false,
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert!(result.anomaly_count > 0);
}

#[test]
fn confidence_bounded_0_to_1() {
    let detector = AccelDetector::with_defaults();
    let env = TimingEnvironment {
        rdtsc_deltas: vec![10_000_000; 20],
        wall_clock_deltas_ns: vec![1; 20],
        sleep_requested_ms: vec![1000],
        sleep_actual_ms: vec![1],
        cpu_frequency_mhz: None,
        tsc_invariant: false,
    };
    let result = detector.analyze(&env);
    assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
}

#[test]
fn samples_match_input_count() {
    let detector = AccelDetector::with_defaults();
    let env = TimingEnvironment {
        rdtsc_deltas: vec![1000, 2000, 3000],
        wall_clock_deltas_ns: vec![1000, 2000, 3000],
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert_eq!(result.samples.len(), 3);
}
