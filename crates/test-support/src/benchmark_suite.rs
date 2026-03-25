use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A single benchmark measurement capturing timing and throughput.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMeasurement {
    /// Name of the benchmark.
    pub name: String,
    /// Duration of the benchmark run.
    pub duration: Duration,
    /// Number of iterations completed.
    pub iterations: u64,
    /// Throughput: operations per second.
    pub ops_per_sec: f64,
    /// Average time per operation.
    pub avg_per_op: Duration,
    /// Optional memory usage in bytes (peak RSS approximation).
    pub memory_bytes: Option<u64>,
    /// Arbitrary string tags for filtering.
    pub tags: Vec<String>,
}

/// Configuration for a benchmark run.
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Minimum number of iterations.
    pub min_iterations: u64,
    /// Maximum duration for the benchmark.
    pub max_duration: Duration,
    /// Number of warmup iterations before measurement.
    pub warmup_iterations: u64,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            min_iterations: 10,
            max_duration: Duration::from_secs(5),
            warmup_iterations: 3,
        }
    }
}

impl BenchmarkConfig {
    pub fn with_min_iterations(mut self, n: u64) -> Self {
        self.min_iterations = n;
        self
    }

    pub fn with_max_duration(mut self, d: Duration) -> Self {
        self.max_duration = d;
        self
    }

    pub fn with_warmup(mut self, n: u64) -> Self {
        self.warmup_iterations = n;
        self
    }
}

/// Runs a single benchmark, calling `f` repeatedly and measuring timing.
///
/// Returns a `BenchmarkMeasurement` with stats. The closure receives the
/// iteration index.
pub fn run_benchmark<F>(
    name: &str,
    config: &BenchmarkConfig,
    tags: &[&str],
    mut f: F,
) -> BenchmarkMeasurement
where
    F: FnMut(u64),
{
    // Warmup
    for i in 0..config.warmup_iterations {
        f(i);
    }

    let start = Instant::now();
    let mut iterations: u64 = 0;

    loop {
        f(iterations);
        iterations += 1;

        let elapsed = start.elapsed();
        if iterations >= config.min_iterations && elapsed >= config.max_duration {
            break;
        }
        // Safety cap to prevent infinite loops in fast benchmarks
        if iterations >= config.min_iterations * 1000 {
            break;
        }
    }

    let total_duration = start.elapsed();
    let ops_per_sec = if total_duration.as_secs_f64() > 0.0 {
        iterations as f64 / total_duration.as_secs_f64()
    } else {
        f64::INFINITY
    };
    let avg_per_op = total_duration / iterations as u32;

    BenchmarkMeasurement {
        name: name.to_string(),
        duration: total_duration,
        iterations,
        ops_per_sec,
        avg_per_op,
        memory_bytes: None,
        tags: tags.iter().map(|t| t.to_string()).collect(),
    }
}

/// Runs a single benchmark with explicit iteration count (no time-based loop).
pub fn run_benchmark_fixed<F>(
    name: &str,
    iterations: u64,
    warmup: u64,
    tags: &[&str],
    mut f: F,
) -> BenchmarkMeasurement
where
    F: FnMut(u64),
{
    for i in 0..warmup {
        f(i);
    }

    let start = Instant::now();
    for i in 0..iterations {
        f(i);
    }
    let total_duration = start.elapsed();

    let ops_per_sec = if total_duration.as_secs_f64() > 0.0 {
        iterations as f64 / total_duration.as_secs_f64()
    } else {
        f64::INFINITY
    };
    let avg_per_op = if iterations > 0 {
        total_duration / iterations as u32
    } else {
        Duration::ZERO
    };

    BenchmarkMeasurement {
        name: name.to_string(),
        duration: total_duration,
        iterations,
        ops_per_sec,
        avg_per_op,
        memory_bytes: None,
        tags: tags.iter().map(|t| t.to_string()).collect(),
    }
}

/// A complete benchmark report aggregating multiple measurements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// Timestamp when the report was generated (Unix seconds).
    pub timestamp_unix_secs: u64,
    /// All measurements in the report.
    pub measurements: Vec<BenchmarkMeasurement>,
    /// Environment metadata.
    pub environment: HashMap<String, String>,
}

impl BenchmarkReport {
    /// Creates a new empty report.
    pub fn new() -> Self {
        let mut env = HashMap::new();
        env.insert("os".to_string(), std::env::consts::OS.to_string());
        env.insert("arch".to_string(), std::env::consts::ARCH.to_string());

        Self {
            timestamp_unix_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            measurements: Vec::new(),
            environment: env,
        }
    }

    /// Adds a measurement to the report.
    pub fn add(&mut self, measurement: BenchmarkMeasurement) {
        self.measurements.push(measurement);
    }

    /// Returns all measurements matching a tag.
    pub fn by_tag(&self, tag: &str) -> Vec<&BenchmarkMeasurement> {
        self.measurements
            .iter()
            .filter(|m| m.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Returns the measurement with the given name.
    pub fn by_name(&self, name: &str) -> Option<&BenchmarkMeasurement> {
        self.measurements.iter().find(|m| m.name == name)
    }

    /// Returns a summary string suitable for console output.
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push("Benchmark Report".to_string());
        lines.push("=".repeat(72));
        lines.push(format!(
            "{:<40} {:>10} {:>10} {:>10}",
            "Name", "Iters", "Total", "Ops/sec"
        ));
        lines.push("-".repeat(72));

        for m in &self.measurements {
            lines.push(format!(
                "{:<40} {:>10} {:>10.2?} {:>10.0}",
                m.name, m.iterations, m.duration, m.ops_per_sec
            ));
        }
        lines.push("-".repeat(72));
        lines.join("\n")
    }

    /// Serializes the report to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserializes a report from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Returns the total number of measurements.
    pub fn count(&self) -> usize {
        self.measurements.len()
    }

    /// Compares this report against a baseline, returning regressions.
    ///
    /// A regression is any benchmark where ops/sec dropped by more than
    /// `threshold_pct` percent compared to baseline.
    pub fn regressions(
        &self,
        baseline: &BenchmarkReport,
        threshold_pct: f64,
    ) -> Vec<BenchmarkRegression> {
        let mut regressions = Vec::new();

        for current in &self.measurements {
            if let Some(base) = baseline.by_name(&current.name) {
                if base.ops_per_sec > 0.0 {
                    let change_pct =
                        ((current.ops_per_sec - base.ops_per_sec) / base.ops_per_sec) * 100.0;
                    if change_pct < -threshold_pct {
                        regressions.push(BenchmarkRegression {
                            name: current.name.clone(),
                            baseline_ops_per_sec: base.ops_per_sec,
                            current_ops_per_sec: current.ops_per_sec,
                            change_pct,
                        });
                    }
                }
            }
        }

        regressions
    }
}

impl Default for BenchmarkReport {
    fn default() -> Self {
        Self::new()
    }
}

/// A detected performance regression between baseline and current.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkRegression {
    pub name: String,
    pub baseline_ops_per_sec: f64,
    pub current_ops_per_sec: f64,
    /// Negative means regression (slower).
    pub change_pct: f64,
}

/// Convenience macro-like helper to measure a block of code.
pub fn measure_block<F, T>(name: &str, f: F) -> (T, BenchmarkMeasurement)
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();

    let measurement = BenchmarkMeasurement {
        name: name.to_string(),
        duration,
        iterations: 1,
        ops_per_sec: if duration.as_secs_f64() > 0.0 {
            1.0 / duration.as_secs_f64()
        } else {
            f64::INFINITY
        },
        avg_per_op: duration,
        memory_bytes: None,
        tags: vec!["block".to_string()],
    };

    (result, measurement)
}

#[cfg(test)]
#[path = "benchmark_suite_test.rs"]
mod tests;
