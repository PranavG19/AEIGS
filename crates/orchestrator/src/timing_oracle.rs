use std::fmt;
use std::time::Duration;

use aegis_protocol::finding::VulnerabilityClass;

/// Blind vulnerability classes detectable through response timing differentials.
///
/// Each variant maps to a specific delay-inducing payload pattern: SQL SLEEP,
/// shell sleep, DNS resolution delays, file system traversal latency, or
/// template evaluation cost. The oracle sends treatment (delay-inducing) and
/// control (benign) requests, then applies a Welch's t-test to determine if
/// the timing difference is statistically significant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlindVulnType {
    /// SQL injection via time-based payloads (SLEEP, WAITFOR, pg_sleep, BENCHMARK)
    BlindSqli,
    /// Command injection via sleep/timeout commands
    BlindCmdi,
    /// SSRF via DNS resolution timing against controlled domains
    BlindSsrf,
    /// SSTI via computationally expensive template expressions
    BlindSsti,
    /// LDAP injection via slow query patterns
    BlindLdap,
    /// XXE via external entity resolution timing
    BlindXxe,
    /// XPath injection via time-consuming predicates
    BlindXpath,
    /// NoSQL injection via JavaScript sleep in MongoDB $where
    BlindNosql,
}

impl BlindVulnType {
    pub fn to_vulnerability_class(self) -> VulnerabilityClass {
        match self {
            Self::BlindSqli => VulnerabilityClass::SqlInjection,
            Self::BlindCmdi => VulnerabilityClass::CommandInjection,
            Self::BlindSsrf => VulnerabilityClass::ServerSideRequestForgery,
            Self::BlindSsti => VulnerabilityClass::ServerSideTemplateInjection,
            Self::BlindLdap => VulnerabilityClass::InsufficientInputValidation,
            Self::BlindXxe => VulnerabilityClass::XmlExternalEntity,
            Self::BlindXpath => VulnerabilityClass::InsufficientInputValidation,
            Self::BlindNosql => VulnerabilityClass::NoSqlInjection,
        }
    }

    pub fn default_delay_seconds(self) -> f64 {
        match self {
            Self::BlindSqli => 5.0,
            Self::BlindCmdi => 5.0,
            Self::BlindSsrf => 3.0,
            Self::BlindSsti => 2.0,
            Self::BlindLdap => 3.0,
            Self::BlindXxe => 3.0,
            Self::BlindXpath => 3.0,
            Self::BlindNosql => 5.0,
        }
    }
}

impl fmt::Display for BlindVulnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlindSqli => write!(f, "blind_sqli"),
            Self::BlindCmdi => write!(f, "blind_cmdi"),
            Self::BlindSsrf => write!(f, "blind_ssrf"),
            Self::BlindSsti => write!(f, "blind_ssti"),
            Self::BlindLdap => write!(f, "blind_ldap"),
            Self::BlindXxe => write!(f, "blind_xxe"),
            Self::BlindXpath => write!(f, "blind_xpath"),
            Self::BlindNosql => write!(f, "blind_nosql"),
        }
    }
}

/// Configuration for a timing oracle probe sequence.
#[derive(Debug, Clone)]
pub struct TimingOracleConfig {
    pub vuln_type: BlindVulnType,
    pub endpoint: String,
    pub method: String,
    pub parameter: String,
    pub baseline_value: String,
    pub sample_count: u32,
    pub delay_seconds: f64,
    pub significance_level: f64,
    pub jitter_tolerance_ms: u64,
    pub warmup_requests: u32,
    pub timeout: Duration,
    pub headers: Vec<(String, String)>,
}

impl Default for TimingOracleConfig {
    fn default() -> Self {
        Self {
            vuln_type: BlindVulnType::BlindSqli,
            endpoint: String::new(),
            method: "GET".to_string(),
            parameter: String::new(),
            baseline_value: "1".to_string(),
            sample_count: 10,
            delay_seconds: 5.0,
            significance_level: 0.01,
            jitter_tolerance_ms: 200,
            warmup_requests: 3,
            timeout: Duration::from_secs(30),
            headers: Vec::new(),
        }
    }
}

/// Time-based payloads for each blind vulnerability type.
///
/// Each function returns (treatment_payload, control_payload) pairs.
/// The treatment induces a server-side delay; the control is syntactically
/// similar but causes no delay. The differential isolates the vulnerability
/// from baseline network jitter.
pub fn generate_timing_payloads(
    vuln_type: BlindVulnType,
    delay_seconds: f64,
) -> Vec<TimingPayloadPair> {
    let delay_int = delay_seconds as u64;
    let delay_ms = (delay_seconds * 1000.0) as u64;

    match vuln_type {
        BlindVulnType::BlindSqli => vec![
            TimingPayloadPair {
                treatment: format!("1' AND SLEEP({delay_int})-- -"),
                control: "1' AND 1=1-- -".to_string(),
                label: "MySQL SLEEP".to_string(),
            },
            TimingPayloadPair {
                treatment: format!("1'; WAITFOR DELAY '0:0:{delay_int}'-- "),
                control: "1'; SELECT 1-- ".to_string(),
                label: "MSSQL WAITFOR".to_string(),
            },
            TimingPayloadPair {
                treatment: format!("1'; SELECT pg_sleep({delay_int})-- "),
                control: "1'; SELECT 1-- ".to_string(),
                label: "PostgreSQL pg_sleep".to_string(),
            },
            TimingPayloadPair {
                treatment: format!("1' AND BENCHMARK({},SHA1('test'))-- -", delay_ms * 50000),
                control: "1' AND BENCHMARK(1,SHA1('test'))-- -".to_string(),
                label: "MySQL BENCHMARK".to_string(),
            },
            TimingPayloadPair {
                treatment: format!("1' || dbms_pipe.receive_message('a',{delay_int})-- "),
                control: "1' || 1-- ".to_string(),
                label: "Oracle DBMS_PIPE".to_string(),
            },
            TimingPayloadPair {
                treatment: format!("1 AND (SELECT {delay_int} FROM (SELECT(SLEEP({delay_int})))a)"),
                control: "1 AND (SELECT 1 FROM (SELECT(1))a)".to_string(),
                label: "MySQL subquery SLEEP".to_string(),
            },
        ],
        BlindVulnType::BlindCmdi => vec![
            TimingPayloadPair {
                treatment: format!("; sleep {delay_int}"),
                control: "; echo test".to_string(),
                label: "Unix sleep".to_string(),
            },
            TimingPayloadPair {
                treatment: format!("| sleep {delay_int}"),
                control: "| echo test".to_string(),
                label: "Unix pipe sleep".to_string(),
            },
            TimingPayloadPair {
                treatment: format!("$(sleep {delay_int})"),
                control: "$(echo test)".to_string(),
                label: "Unix subshell sleep".to_string(),
            },
            TimingPayloadPair {
                treatment: format!("`sleep {delay_int}`"),
                control: "`echo test`".to_string(),
                label: "Unix backtick sleep".to_string(),
            },
            TimingPayloadPair {
                treatment: format!("& timeout /t {delay_int}"),
                control: "& echo test".to_string(),
                label: "Windows timeout".to_string(),
            },
            TimingPayloadPair {
                treatment: format!("& ping -n {delay_int} 127.0.0.1", delay_int = delay_int + 1),
                control: "& echo test".to_string(),
                label: "Windows ping delay".to_string(),
            },
        ],
        BlindVulnType::BlindSsrf => vec![
            TimingPayloadPair {
                treatment: "http://nonexistent-subdomain-timing-probe.invalid/test".to_string(),
                control: "http://127.0.0.1/test".to_string(),
                label: "DNS resolution delay".to_string(),
            },
            TimingPayloadPair {
                treatment: "http://240.0.0.1:1234/test".to_string(),
                control: "http://127.0.0.1/test".to_string(),
                label: "Non-routable IP timeout".to_string(),
            },
            TimingPayloadPair {
                treatment: "http://[::ffff:240.0.0.1]:1234/test".to_string(),
                control: "http://127.0.0.1/test".to_string(),
                label: "IPv6-mapped non-routable".to_string(),
            },
        ],
        BlindVulnType::BlindSsti => vec![
            TimingPayloadPair {
                treatment: format!("{{{{#each (range 0 {}000000)}}}}x{{{{/each}}}}", delay_int),
                control: "{{test}}".to_string(),
                label: "Handlebars loop".to_string(),
            },
            TimingPayloadPair {
                treatment: format!(
                    "{{% for i in range({}) %}}x{{% endfor %}}",
                    delay_ms * 100000
                ),
                control: "{{ 1+1 }}".to_string(),
                label: "Jinja2 heavy loop".to_string(),
            },
            TimingPayloadPair {
                treatment: format!(
                    "#set($x=0)#foreach($i in [1..{}])#set($x=$x+1)#end$x",
                    delay_ms * 100000
                ),
                control: "#set($x=1)$x".to_string(),
                label: "Velocity loop".to_string(),
            },
        ],
        BlindVulnType::BlindLdap => vec![TimingPayloadPair {
            treatment: "*)(&(objectClass=*)(|(cn=a*)(cn=b*)(cn=c*)(cn=d*)))".to_string(),
            control: "*)(objectClass=*)".to_string(),
            label: "LDAP wildcard expansion".to_string(),
        }],
        BlindVulnType::BlindXxe => vec![
            TimingPayloadPair {
                treatment: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \
                     \"http://nonexistent-xxe-timing-probe.invalid/\">]>\
                     <foo>&xxe;</foo>"
                    .to_string(),
                control: "<?xml version=\"1.0\"?><foo>bar</foo>".to_string(),
                label: "XXE external entity DNS".to_string(),
            },
            TimingPayloadPair {
                treatment: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \
                     \"http://240.0.0.1:1234/\">]><foo>&xxe;</foo>"
                    .to_string(),
                control: "<?xml version=\"1.0\"?><foo>bar</foo>".to_string(),
                label: "XXE non-routable IP".to_string(),
            },
        ],
        BlindVulnType::BlindXpath => vec![TimingPayloadPair {
            treatment: format!("1 or string-length(name(/*[1]))>{delay_int} or 1=1"),
            control: "1 or 1=1".to_string(),
            label: "XPath string-length probe".to_string(),
        }],
        BlindVulnType::BlindNosql => vec![
            TimingPayloadPair {
                treatment: format!("{{\"$where\": \"sleep({delay_ms})\"}}"),
                control: "{\"$where\": \"1==1\"}".to_string(),
                label: "MongoDB $where sleep".to_string(),
            },
            TimingPayloadPair {
                treatment: format!(
                    "{{\"$where\": \"function(){{ var start=new Date(); \
                     while(new Date()-start<{delay_ms}){{}} return true; }}\"}}"
                ),
                control: "{\"$where\": \"function(){ return true; }\"}".to_string(),
                label: "MongoDB JS busy-wait".to_string(),
            },
        ],
    }
}

/// A treatment/control payload pair for timing differential analysis.
#[derive(Debug, Clone)]
pub struct TimingPayloadPair {
    pub treatment: String,
    pub control: String,
    pub label: String,
}

/// Raw timing measurement from a single request.
#[derive(Debug, Clone, Copy)]
pub struct TimingSample {
    pub response_time_ms: f64,
    pub status_code: u16,
    pub is_treatment: bool,
}

/// Statistical summary of a timing sample group.
#[derive(Debug, Clone)]
pub struct TimingDistribution {
    pub mean_ms: f64,
    pub std_dev_ms: f64,
    pub median_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub sample_count: u32,
    pub samples: Vec<f64>,
}

impl TimingDistribution {
    pub fn from_samples(raw: &[f64]) -> Self {
        if raw.is_empty() {
            return Self {
                mean_ms: 0.0,
                std_dev_ms: 0.0,
                median_ms: 0.0,
                min_ms: 0.0,
                max_ms: 0.0,
                sample_count: 0,
                samples: Vec::new(),
            };
        }

        let n = raw.len() as f64;
        let mean = raw.iter().sum::<f64>() / n;

        let variance = raw.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0).max(1.0);
        let std_dev = variance.sqrt();

        let mut sorted = raw.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = if sorted.len().is_multiple_of(2) {
            (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0
        } else {
            sorted[sorted.len() / 2]
        };

        Self {
            mean_ms: mean,
            std_dev_ms: std_dev,
            median_ms: median,
            min_ms: sorted[0],
            max_ms: sorted[sorted.len() - 1],
            sample_count: raw.len() as u32,
            samples: sorted,
        }
    }
}

/// Result of Welch's t-test comparing treatment vs control timing distributions.
#[derive(Debug, Clone)]
pub struct WelchTTestResult {
    pub t_statistic: f64,
    pub degrees_of_freedom: f64,
    pub p_value: f64,
    pub mean_difference_ms: f64,
    pub is_significant: bool,
    pub significance_level: f64,
}

/// Perform Welch's t-test (unequal variances t-test) on two sample groups.
///
/// Welch's t-test is preferred over Student's t-test because treatment and
/// control groups may have different variances (delay-injected requests often
/// show higher variance due to server-side scheduling effects).
pub fn welch_t_test(
    treatment: &TimingDistribution,
    control: &TimingDistribution,
    significance_level: f64,
) -> WelchTTestResult {
    let n1 = treatment.sample_count as f64;
    let n2 = control.sample_count as f64;

    if n1 < 2.0 || n2 < 2.0 {
        return WelchTTestResult {
            t_statistic: 0.0,
            degrees_of_freedom: 0.0,
            p_value: 1.0,
            mean_difference_ms: treatment.mean_ms - control.mean_ms,
            is_significant: false,
            significance_level,
        };
    }

    let s1_sq = treatment.std_dev_ms.powi(2);
    let s2_sq = control.std_dev_ms.powi(2);

    let se1 = s1_sq / n1;
    let se2 = s2_sq / n2;
    let se_sum = se1 + se2;

    if se_sum < 1e-12 {
        let mean_diff = treatment.mean_ms - control.mean_ms;
        return WelchTTestResult {
            t_statistic: if mean_diff.abs() < 1e-12 {
                0.0
            } else {
                f64::INFINITY * mean_diff.signum()
            },
            degrees_of_freedom: n1 + n2 - 2.0,
            p_value: if mean_diff.abs() < 1e-12 { 1.0 } else { 0.0 },
            mean_difference_ms: mean_diff,
            is_significant: mean_diff.abs() > 1e-12,
            significance_level,
        };
    }

    let t_stat = (treatment.mean_ms - control.mean_ms) / se_sum.sqrt();

    let df_numerator = se_sum.powi(2);
    let df_denominator = (se1.powi(2) / (n1 - 1.0)) + (se2.powi(2) / (n2 - 1.0));
    let df = if df_denominator < 1e-12 {
        n1 + n2 - 2.0
    } else {
        df_numerator / df_denominator
    };

    let p_value = t_distribution_p_value(t_stat.abs(), df);

    WelchTTestResult {
        t_statistic: t_stat,
        degrees_of_freedom: df,
        p_value,
        mean_difference_ms: treatment.mean_ms - control.mean_ms,
        is_significant: p_value < significance_level,
        significance_level,
    }
}

/// Approximate p-value for a two-tailed t-distribution using the
/// regularized incomplete beta function approximation.
///
/// For high df (>30), we use the normal approximation. For lower df,
/// we use a series expansion of the beta function. Accuracy is within
/// 0.001 for the significance levels we care about (0.01, 0.05).
fn t_distribution_p_value(t_abs: f64, df: f64) -> f64 {
    if df <= 0.0 || t_abs.is_nan() || df.is_nan() {
        return 1.0;
    }

    if t_abs.is_infinite() {
        return 0.0;
    }

    let x = df / (df + t_abs * t_abs);
    let p_one_tail = 0.5 * regularized_incomplete_beta(df / 2.0, 0.5, x);
    (2.0 * p_one_tail).clamp(0.0, 1.0)
}

/// Regularized incomplete beta function I_x(a, b) via continued fraction.
///
/// Uses Lentz's algorithm for the continued fraction representation.
/// Converges rapidly for the parameter ranges we encounter in t-tests
/// (a = df/2, b = 0.5, x near 0 or 1).
fn regularized_incomplete_beta(a: f64, b: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }

    let ln_beta = ln_gamma(a) + ln_gamma(b) - ln_gamma(a + b);
    let front = (x.ln() * a + (1.0 - x).ln() * b - ln_beta).exp() / a;

    let mut f: f64;
    let mut c = 1.0_f64;
    let mut d: f64;

    let max_iter = 200;
    let epsilon = 1e-10;
    let tiny = 1e-30;

    d = 1.0 - (a + 1.0) * (a + b) / (a + 2.0) * x;
    if d.abs() < tiny {
        d = tiny;
    }
    d = 1.0 / d;
    f = d;

    for m in 1..=max_iter {
        let m_f64 = m as f64;

        let numerator_even =
            m_f64 * (b - m_f64) * x / ((a + 2.0 * m_f64 - 1.0) * (a + 2.0 * m_f64));
        d = 1.0 + numerator_even / d;
        if d.abs() < tiny {
            d = tiny;
        }
        c = 1.0 + numerator_even / c;
        if c.abs() < tiny {
            c = tiny;
        }
        d = 1.0 / d;
        f *= c * d;

        let numerator_odd =
            -((a + m_f64) * (a + b + m_f64) * x) / ((a + 2.0 * m_f64) * (a + 2.0 * m_f64 + 1.0));
        d = 1.0 + numerator_odd / d;
        if d.abs() < tiny {
            d = tiny;
        }
        c = 1.0 + numerator_odd / c;
        if c.abs() < tiny {
            c = tiny;
        }
        d = 1.0 / d;
        let delta = c * d;
        f *= delta;

        if (delta - 1.0).abs() < epsilon {
            break;
        }
    }

    front * f
}

/// Lanczos approximation to ln(Gamma(x)).
fn ln_gamma(x: f64) -> f64 {
    let coefficients: [f64; 7] = [
        1.000000000190015,
        76.18009172947146,
        -86.50532032941677,
        24.01409824083091,
        -1.231739572450155,
        0.1208650973866179e-2,
        -0.5395239384953e-5,
    ];

    let tmp = x + 5.5;
    let tmp = tmp - (x + 0.5) * tmp.ln();
    let mut ser = coefficients[0];
    for (j, &coeff) in coefficients[1..].iter().enumerate() {
        ser += coeff / (x + j as f64 + 1.0);
    }
    -tmp + (2.5066282746310005_f64 * ser / x).ln()
}

/// Full result of a timing oracle analysis for one payload pair.
#[derive(Debug, Clone)]
pub struct TimingOracleResult {
    pub vuln_type: BlindVulnType,
    pub payload_label: String,
    pub treatment_payload: String,
    pub control_payload: String,
    pub treatment_dist: TimingDistribution,
    pub control_dist: TimingDistribution,
    pub t_test: WelchTTestResult,
    pub verdict: TimingVerdict,
    pub confidence: f64,
    pub expected_delay_ms: f64,
    pub observed_delay_ms: f64,
}

/// Classification of the timing oracle probe result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingVerdict {
    /// Statistically significant timing difference matching expected delay
    Confirmed,
    /// Significant difference but magnitude doesn't match expected delay
    Suspicious,
    /// Timing difference present but below significance threshold
    Inconclusive,
    /// No meaningful timing difference detected
    NotVulnerable,
}

impl fmt::Display for TimingVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Confirmed => write!(f, "CONFIRMED"),
            Self::Suspicious => write!(f, "SUSPICIOUS"),
            Self::Inconclusive => write!(f, "INCONCLUSIVE"),
            Self::NotVulnerable => write!(f, "NOT_VULNERABLE"),
        }
    }
}

/// Analyze timing samples and produce a verdict.
///
/// The analysis pipeline:
/// 1. Separate samples into treatment/control groups
/// 2. Compute distributions for each group
/// 3. Run Welch's t-test for statistical significance
/// 4. Compare observed delay magnitude against expected delay
/// 5. Classify: Confirmed, Suspicious, Inconclusive, or NotVulnerable
pub fn analyze_timing_oracle(
    samples: &[TimingSample],
    config: &TimingOracleConfig,
    payload: &TimingPayloadPair,
) -> TimingOracleResult {
    let treatment_times: Vec<f64> = samples
        .iter()
        .filter(|s| s.is_treatment)
        .map(|s| s.response_time_ms)
        .collect();

    let control_times: Vec<f64> = samples
        .iter()
        .filter(|s| !s.is_treatment)
        .map(|s| s.response_time_ms)
        .collect();

    let treatment_dist = TimingDistribution::from_samples(&treatment_times);
    let control_dist = TimingDistribution::from_samples(&control_times);

    let t_test = welch_t_test(&treatment_dist, &control_dist, config.significance_level);

    let expected_delay_ms = config.delay_seconds * 1000.0;
    let observed_delay_ms = treatment_dist.mean_ms - control_dist.mean_ms;

    let delay_ratio = if expected_delay_ms > 0.0 {
        observed_delay_ms / expected_delay_ms
    } else {
        0.0
    };

    let verdict = classify_verdict(
        &t_test,
        delay_ratio,
        observed_delay_ms,
        config.jitter_tolerance_ms as f64,
    );

    let confidence = compute_confidence(&t_test, delay_ratio, &treatment_dist, &control_dist);

    TimingOracleResult {
        vuln_type: config.vuln_type,
        payload_label: payload.label.clone(),
        treatment_payload: payload.treatment.clone(),
        control_payload: payload.control.clone(),
        treatment_dist,
        control_dist,
        t_test,
        verdict,
        confidence,
        expected_delay_ms,
        observed_delay_ms,
    }
}

/// Classify the verdict based on statistical significance and delay magnitude.
fn classify_verdict(
    t_test: &WelchTTestResult,
    delay_ratio: f64,
    observed_delay_ms: f64,
    jitter_tolerance_ms: f64,
) -> TimingVerdict {
    if !t_test.is_significant {
        if observed_delay_ms > jitter_tolerance_ms {
            return TimingVerdict::Inconclusive;
        }
        return TimingVerdict::NotVulnerable;
    }

    if delay_ratio > 0.5 && delay_ratio < 2.0 {
        TimingVerdict::Confirmed
    } else if observed_delay_ms > jitter_tolerance_ms {
        TimingVerdict::Suspicious
    } else {
        TimingVerdict::NotVulnerable
    }
}

/// Compute a confidence score [0.0, 1.0] combining statistical strength,
/// delay magnitude match, and distribution quality.
fn compute_confidence(
    t_test: &WelchTTestResult,
    delay_ratio: f64,
    treatment: &TimingDistribution,
    control: &TimingDistribution,
) -> f64 {
    let statistical_strength = if t_test.p_value <= 0.0 {
        1.0
    } else {
        (1.0 - t_test.p_value).clamp(0.0, 1.0)
    };

    let magnitude_match = if (0.8..=1.3).contains(&delay_ratio) {
        1.0
    } else if (0.5..=2.0).contains(&delay_ratio) {
        0.7
    } else if delay_ratio > 0.0 {
        0.3
    } else {
        0.0
    };

    let treatment_cv = if treatment.mean_ms > 0.0 {
        treatment.std_dev_ms / treatment.mean_ms
    } else {
        1.0
    };
    let control_cv = if control.mean_ms > 0.0 {
        control.std_dev_ms / control.mean_ms
    } else {
        1.0
    };
    let consistency = (1.0 - (treatment_cv + control_cv) / 2.0).clamp(0.0, 1.0);

    (0.4 * statistical_strength + 0.4 * magnitude_match + 0.2 * consistency).clamp(0.0, 1.0)
}

/// Remove statistical outliers using the IQR method.
///
/// Samples beyond Q1 - 1.5*IQR or Q3 + 1.5*IQR are removed.
/// Essential for timing analysis where occasional network spikes
/// can corrupt the distribution.
pub fn remove_outliers(samples: &[f64]) -> Vec<f64> {
    if samples.len() < 4 {
        return samples.to_vec();
    }

    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let q1_idx = sorted.len() / 4;
    let q3_idx = 3 * sorted.len() / 4;
    let q1 = sorted[q1_idx];
    let q3 = sorted[q3_idx];
    let iqr = q3 - q1;

    let lower = q1 - 1.5 * iqr;
    let upper = q3 + 1.5 * iqr;

    sorted
        .into_iter()
        .filter(|&x| x >= lower && x <= upper)
        .collect()
}

/// Compute Cohen's d effect size for the timing difference.
///
/// Effect size tells us the practical significance beyond statistical
/// significance. A large sample can make tiny differences "significant"
/// statistically; Cohen's d measures how meaningful the difference is.
/// - Small: d = 0.2
/// - Medium: d = 0.5
/// - Large: d = 0.8
pub fn cohens_d(treatment: &TimingDistribution, control: &TimingDistribution) -> f64 {
    let n1 = treatment.sample_count as f64;
    let n2 = control.sample_count as f64;

    if n1 < 2.0 || n2 < 2.0 {
        return 0.0;
    }

    let pooled_var = ((n1 - 1.0) * treatment.std_dev_ms.powi(2)
        + (n2 - 1.0) * control.std_dev_ms.powi(2))
        / (n1 + n2 - 2.0);
    let pooled_sd = pooled_var.sqrt();

    if pooled_sd < 1e-12 {
        return if (treatment.mean_ms - control.mean_ms).abs() < 1e-12 {
            0.0
        } else {
            f64::INFINITY
        };
    }

    (treatment.mean_ms - control.mean_ms) / pooled_sd
}

/// Determine optimal sample count based on observed variance.
///
/// Uses the formula: n = (z_alpha/2 + z_beta)^2 * (s1^2 + s2^2) / delta^2
/// where delta is the minimum detectable difference (expected delay).
/// z_alpha/2 for 0.01 = 2.576, z_beta for 0.8 power = 0.842.
pub fn optimal_sample_count(
    pilot_treatment: &TimingDistribution,
    pilot_control: &TimingDistribution,
    expected_delay_ms: f64,
) -> u32 {
    if expected_delay_ms < 1.0 {
        return 30;
    }

    let z_alpha: f64 = 2.576;
    let z_beta: f64 = 0.842;
    let z_sum_sq = (z_alpha + z_beta).powi(2);

    let var_sum = pilot_treatment.std_dev_ms.powi(2) + pilot_control.std_dev_ms.powi(2);
    let delta_sq = expected_delay_ms.powi(2);

    let n = (z_sum_sq * var_sum / delta_sq).ceil() as u32;
    n.clamp(5, 100)
}

/// Adaptive delay probing: verify a finding by testing with multiple delay values.
///
/// If the endpoint is truly vulnerable, a 3-second delay should produce ~3s
/// of additional response time, and a 7-second delay should produce ~7s.
/// Linear correlation between injected delay and observed delay confirms
/// the vulnerability with high confidence.
pub fn generate_confirmation_delays(base_delay: f64) -> Vec<f64> {
    vec![
        base_delay * 0.5,
        base_delay,
        base_delay * 1.5,
        base_delay * 2.0,
    ]
}

/// Compute the Pearson correlation coefficient between injected delays
/// and observed response time increases.
///
/// r close to 1.0 confirms a causal relationship between the injected
/// delay and the response time — the gold standard for blind injection
/// confirmation.
pub fn delay_correlation(injected_delays: &[f64], observed_delays: &[f64]) -> f64 {
    let n = injected_delays.len().min(observed_delays.len());
    if n < 2 {
        return 0.0;
    }

    let x = &injected_delays[..n];
    let y = &observed_delays[..n];

    let mean_x: f64 = x.iter().sum::<f64>() / n as f64;
    let mean_y: f64 = y.iter().sum::<f64>() / n as f64;

    let mut cov = 0.0;
    let mut var_x = 0.0;
    let mut var_y = 0.0;

    for i in 0..n {
        let dx = x[i] - mean_x;
        let dy = y[i] - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }

    let denominator = (var_x * var_y).sqrt();
    if denominator < 1e-12 {
        return 0.0;
    }

    (cov / denominator).clamp(-1.0, 1.0)
}

/// Generate a human-readable summary of the timing oracle result.
pub fn format_finding(result: &TimingOracleResult) -> String {
    format!(
        "[{}] {} via {} — {} (p={:.4}, d={:.1}ms, conf={:.2})",
        result.verdict,
        result.vuln_type,
        result.payload_label,
        if result.verdict == TimingVerdict::Confirmed {
            "VULNERABLE"
        } else if result.verdict == TimingVerdict::Suspicious {
            "NEEDS INVESTIGATION"
        } else {
            "CLEAN"
        },
        result.t_test.p_value,
        result.observed_delay_ms,
        result.confidence,
    )
}

#[cfg(test)]
#[path = "timing_oracle_test.rs"]
mod timing_oracle_test;
