use serde::{Deserialize, Serialize};

/// Hardware-level timing analysis for detecting VM/sandbox acceleration.
///
/// Measures discrepancies between RDTSC (CPU timestamp counter), wall-clock time,
/// and OS-reported time to detect time dilation, VM clock skew, and hardware
/// breakpoint overhead.

/// Acceleration detection verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccelVerdict {
    Clean,
    Suspicious,
    Accelerated,
    Decelerated,
    ClockSkewed,
}

impl std::fmt::Display for AccelVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "clean"),
            Self::Suspicious => write!(f, "suspicious"),
            Self::Accelerated => write!(f, "accelerated"),
            Self::Decelerated => write!(f, "decelerated"),
            Self::ClockSkewed => write!(f, "clock-skewed"),
        }
    }
}

/// Type of timing anomaly detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimingAnomalyType {
    RdtscDeltaHigh,
    RdtscDeltaLow,
    WallClockDrift,
    SleepAcceleration,
    SleepDeceleration,
    CpuFrequencyMismatch,
    TscInvariantViolation,
}

/// Individual timing measurement sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingSample {
    pub rdtsc_delta: u64,
    pub wall_clock_ns: u64,
    pub expected_ns: u64,
    pub anomaly: Option<TimingAnomalyType>,
}

/// Aggregated result from the acceleration detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccelDetectionResult {
    pub verdict: AccelVerdict,
    pub confidence: f64,
    pub samples: Vec<TimingSample>,
    pub anomaly_count: u32,
    pub rdtsc_mean_delta: f64,
    pub wall_clock_drift_pct: f64,
    pub sleep_accuracy_pct: f64,
}

/// Configuration for the acceleration detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccelDetectorConfig {
    /// Maximum expected RDTSC delta in nanoseconds for a single CPUID instruction.
    pub rdtsc_threshold_ns: u64,
    /// Maximum acceptable wall-clock drift percentage.
    pub max_drift_pct: f64,
    /// Maximum acceptable sleep acceleration/deceleration percentage.
    pub max_sleep_error_pct: f64,
    /// Number of samples to collect per measurement run.
    pub sample_count: u32,
    /// Confidence threshold above which we report an anomaly.
    pub confidence_threshold: f64,
    /// Expected CPU frequency in MHz for TSC rate validation.
    pub expected_cpu_mhz: Option<u64>,
}

impl Default for AccelDetectorConfig {
    fn default() -> Self {
        Self {
            rdtsc_threshold_ns: 500_000,
            max_drift_pct: 5.0,
            max_sleep_error_pct: 20.0,
            sample_count: 10,
            confidence_threshold: 0.7,
            expected_cpu_mhz: None,
        }
    }
}

/// Simulated timing environment for testing without real hardware access.
#[derive(Debug, Clone, Default)]
pub struct TimingEnvironment {
    pub rdtsc_deltas: Vec<u64>,
    pub wall_clock_deltas_ns: Vec<u64>,
    pub sleep_requested_ms: Vec<u64>,
    pub sleep_actual_ms: Vec<u64>,
    pub cpu_frequency_mhz: Option<u64>,
    pub tsc_invariant: bool,
}

/// Acceleration detection engine.
pub struct AccelDetector {
    config: AccelDetectorConfig,
}

impl AccelDetector {
    pub fn new(config: AccelDetectorConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(AccelDetectorConfig::default())
    }

    /// Analyze a timing environment for acceleration/deceleration artifacts.
    pub fn analyze(&self, env: &TimingEnvironment) -> AccelDetectionResult {
        let mut samples = Vec::new();
        let mut anomaly_count = 0u32;

        for (i, &delta) in env.rdtsc_deltas.iter().enumerate() {
            let wall_ns = env.wall_clock_deltas_ns.get(i).copied().unwrap_or(delta);
            let expected_ns = self.config.rdtsc_threshold_ns / 2;

            let anomaly = if delta > self.config.rdtsc_threshold_ns {
                anomaly_count += 1;
                Some(TimingAnomalyType::RdtscDeltaHigh)
            } else if delta < 10 {
                anomaly_count += 1;
                Some(TimingAnomalyType::RdtscDeltaLow)
            } else {
                None
            };

            samples.push(TimingSample {
                rdtsc_delta: delta,
                wall_clock_ns: wall_ns,
                expected_ns,
                anomaly,
            });
        }

        let wall_clock_drift_pct = self.compute_wall_clock_drift(env);
        if wall_clock_drift_pct.abs() > self.config.max_drift_pct {
            anomaly_count += 1;
        }

        let sleep_accuracy_pct = self.compute_sleep_accuracy(env);
        if (100.0 - sleep_accuracy_pct).abs() > self.config.max_sleep_error_pct {
            anomaly_count += 1;
        }

        if let (Some(expected), Some(actual)) =
            (self.config.expected_cpu_mhz, env.cpu_frequency_mhz)
        {
            let freq_diff_pct = ((actual as f64 - expected as f64) / expected as f64 * 100.0).abs();
            if freq_diff_pct > 10.0 {
                anomaly_count += 1;
            }
        }

        if env.tsc_invariant {
            let has_tsc_violations = env.rdtsc_deltas.windows(2).any(|w| {
                (w[1] as i64 - w[0] as i64).unsigned_abs() > self.config.rdtsc_threshold_ns * 10
            });
            if has_tsc_violations {
                anomaly_count += 1;
            }
        }

        let rdtsc_mean_delta = if env.rdtsc_deltas.is_empty() {
            0.0
        } else {
            env.rdtsc_deltas.iter().sum::<u64>() as f64 / env.rdtsc_deltas.len() as f64
        };

        let total_checks = env.rdtsc_deltas.len().max(1) as f64 + 2.0;
        let confidence = (anomaly_count as f64 / total_checks).min(1.0);

        let verdict = if confidence >= self.config.confidence_threshold {
            if sleep_accuracy_pct > 100.0 + self.config.max_sleep_error_pct {
                AccelVerdict::Decelerated
            } else if sleep_accuracy_pct < 100.0 - self.config.max_sleep_error_pct {
                AccelVerdict::Accelerated
            } else if wall_clock_drift_pct.abs() > self.config.max_drift_pct {
                AccelVerdict::ClockSkewed
            } else {
                AccelVerdict::Suspicious
            }
        } else if anomaly_count > 0 {
            AccelVerdict::Suspicious
        } else {
            AccelVerdict::Clean
        };

        AccelDetectionResult {
            verdict,
            confidence,
            samples,
            anomaly_count,
            rdtsc_mean_delta,
            wall_clock_drift_pct,
            sleep_accuracy_pct,
        }
    }

    /// Generate RDTSC measurement shellcode for embedding.
    pub fn rdtsc_measurement_asm() -> String {
        let mut asm = String::new();
        asm.push_str("; RDTSC-based timing measurement\n");
        asm.push_str("mfence\n");
        asm.push_str("rdtsc\n");
        asm.push_str("shl rdx, 32\n");
        asm.push_str("or rax, rdx\n");
        asm.push_str("mov r8, rax          ; first timestamp\n");
        asm.push_str("cpuid                ; serialize\n");
        asm.push_str("rdtsc\n");
        asm.push_str("shl rdx, 32\n");
        asm.push_str("or rax, rdx\n");
        asm.push_str("sub rax, r8          ; delta\n");
        asm
    }

    fn compute_wall_clock_drift(&self, env: &TimingEnvironment) -> f64 {
        if env.rdtsc_deltas.is_empty() || env.wall_clock_deltas_ns.is_empty() {
            return 0.0;
        }

        let min_len = env.rdtsc_deltas.len().min(env.wall_clock_deltas_ns.len());
        let rdtsc_total: u64 = env.rdtsc_deltas[..min_len].iter().sum();
        let wall_total: u64 = env.wall_clock_deltas_ns[..min_len].iter().sum();

        if wall_total == 0 {
            return 0.0;
        }

        ((rdtsc_total as f64 - wall_total as f64) / wall_total as f64) * 100.0
    }

    fn compute_sleep_accuracy(&self, env: &TimingEnvironment) -> f64 {
        if env.sleep_requested_ms.is_empty() || env.sleep_actual_ms.is_empty() {
            return 100.0;
        }

        let min_len = env.sleep_requested_ms.len().min(env.sleep_actual_ms.len());
        let req_total: u64 = env.sleep_requested_ms[..min_len].iter().sum();
        let act_total: u64 = env.sleep_actual_ms[..min_len].iter().sum();

        if req_total == 0 {
            return 100.0;
        }

        (act_total as f64 / req_total as f64) * 100.0
    }
}
