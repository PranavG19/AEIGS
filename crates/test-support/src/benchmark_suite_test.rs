use super::*;
use std::time::Duration;

#[test]
fn run_benchmark_produces_valid_measurement() {
    let config = BenchmarkConfig::default()
        .with_min_iterations(10)
        .with_max_duration(Duration::from_millis(100))
        .with_warmup(2);

    let m = run_benchmark("test-bench", &config, &["unit", "fast"], |_i| {
        let _sum: u64 = (0..1000).sum();
    });

    assert_eq!(m.name, "test-bench");
    assert!(m.iterations >= 10);
    assert!(m.ops_per_sec > 0.0);
    assert!(m.avg_per_op > Duration::ZERO);
    assert_eq!(m.tags, vec!["unit", "fast"]);
}

#[test]
fn run_benchmark_fixed_exact_iterations() {
    let m = run_benchmark_fixed("fixed-bench", 50, 5, &["fixed"], |_i| {
        let _sum: u64 = (0..100).sum();
    });

    assert_eq!(m.iterations, 50);
    assert!(m.ops_per_sec > 0.0);
}

#[test]
fn measure_block_returns_result_and_measurement() {
    let (result, m) = measure_block("compute", || {
        let sum: u64 = (0..10_000).sum();
        sum
    });

    assert_eq!(result, 49_995_000);
    assert_eq!(m.name, "compute");
    assert_eq!(m.iterations, 1);
    assert!(m.duration > Duration::ZERO);
    assert!(m.tags.contains(&"block".to_string()));
}

#[test]
fn benchmark_report_add_and_count() {
    let mut report = BenchmarkReport::new();
    assert_eq!(report.count(), 0);

    let m = run_benchmark_fixed("test1", 10, 0, &["a"], |_| {});
    report.add(m);
    assert_eq!(report.count(), 1);

    let m2 = run_benchmark_fixed("test2", 10, 0, &["b"], |_| {});
    report.add(m2);
    assert_eq!(report.count(), 2);
}

#[test]
fn benchmark_report_by_tag() {
    let mut report = BenchmarkReport::new();
    report.add(run_benchmark_fixed("fast", 10, 0, &["speed"], |_| {}));
    report.add(run_benchmark_fixed("slow", 10, 0, &["memory"], |_| {}));
    report.add(run_benchmark_fixed(
        "both",
        10,
        0,
        &["speed", "memory"],
        |_| {},
    ));

    let speed = report.by_tag("speed");
    assert_eq!(speed.len(), 2);

    let memory = report.by_tag("memory");
    assert_eq!(memory.len(), 2);
}

#[test]
fn benchmark_report_by_name() {
    let mut report = BenchmarkReport::new();
    report.add(run_benchmark_fixed("alpha", 10, 0, &[], |_| {}));
    report.add(run_benchmark_fixed("beta", 10, 0, &[], |_| {}));

    assert!(report.by_name("alpha").is_some());
    assert!(report.by_name("gamma").is_none());
}

#[test]
fn benchmark_report_summary_contains_headers() {
    let mut report = BenchmarkReport::new();
    report.add(run_benchmark_fixed("bench1", 100, 0, &[], |_| {}));

    let summary = report.summary();
    assert!(summary.contains("Benchmark Report"));
    assert!(summary.contains("Name"));
    assert!(summary.contains("Iters"));
    assert!(summary.contains("Ops/sec"));
    assert!(summary.contains("bench1"));
}

#[test]
fn benchmark_report_json_roundtrip() {
    let mut report = BenchmarkReport::new();
    report.add(run_benchmark_fixed("bench-rt", 50, 0, &["test"], |_| {}));

    let json = report.to_json().unwrap();
    let parsed = BenchmarkReport::from_json(&json).unwrap();

    assert_eq!(parsed.count(), 1);
    assert_eq!(parsed.measurements[0].name, "bench-rt");
    assert_eq!(parsed.measurements[0].iterations, 50);
}

#[test]
fn benchmark_report_has_environment_info() {
    let report = BenchmarkReport::new();
    assert!(report.environment.contains_key("os"));
    assert!(report.environment.contains_key("arch"));
    assert!(report.timestamp_unix_secs > 0);
}

#[test]
fn regressions_detects_slowdown() {
    let mut baseline = BenchmarkReport::new();
    baseline.add(BenchmarkMeasurement {
        name: "hot-path".to_string(),
        duration: Duration::from_secs(1),
        iterations: 1000,
        ops_per_sec: 1000.0,
        avg_per_op: Duration::from_millis(1),
        memory_bytes: None,
        tags: vec![],
    });

    let mut current = BenchmarkReport::new();
    current.add(BenchmarkMeasurement {
        name: "hot-path".to_string(),
        duration: Duration::from_secs(1),
        iterations: 700,
        ops_per_sec: 700.0, // 30% regression
        avg_per_op: Duration::from_nanos(1_428_571),
        memory_bytes: None,
        tags: vec![],
    });

    let regressions = current.regressions(&baseline, 10.0);
    assert_eq!(regressions.len(), 1);
    assert_eq!(regressions[0].name, "hot-path");
    assert!(regressions[0].change_pct < -20.0);
}

#[test]
fn regressions_ignores_improvements() {
    let mut baseline = BenchmarkReport::new();
    baseline.add(BenchmarkMeasurement {
        name: "improved".to_string(),
        duration: Duration::from_secs(1),
        iterations: 1000,
        ops_per_sec: 1000.0,
        avg_per_op: Duration::from_millis(1),
        memory_bytes: None,
        tags: vec![],
    });

    let mut current = BenchmarkReport::new();
    current.add(BenchmarkMeasurement {
        name: "improved".to_string(),
        duration: Duration::from_secs(1),
        iterations: 1500,
        ops_per_sec: 1500.0, // 50% faster
        avg_per_op: Duration::from_nanos(666_666),
        memory_bytes: None,
        tags: vec![],
    });

    let regressions = current.regressions(&baseline, 10.0);
    assert!(regressions.is_empty());
}

#[test]
fn regressions_skips_missing_baseline() {
    let baseline = BenchmarkReport::new();
    let mut current = BenchmarkReport::new();
    current.add(run_benchmark_fixed("new-bench", 10, 0, &[], |_| {}));

    let regressions = current.regressions(&baseline, 10.0);
    assert!(regressions.is_empty());
}

#[test]
fn benchmark_config_defaults_are_sensible() {
    let config = BenchmarkConfig::default();
    assert_eq!(config.min_iterations, 10);
    assert_eq!(config.max_duration, Duration::from_secs(5));
    assert_eq!(config.warmup_iterations, 3);
}

#[test]
fn measurement_memory_bytes_optional() {
    let m = run_benchmark_fixed("no-mem", 10, 0, &[], |_| {});
    assert!(m.memory_bytes.is_none());
}

#[test]
fn ops_per_sec_is_positive_for_nonzero_work() {
    let m = run_benchmark_fixed("positive", 100, 0, &[], |_i| {
        std::hint::black_box(42);
    });
    assert!(m.ops_per_sec > 0.0);
    assert!(m.ops_per_sec.is_finite());
}
