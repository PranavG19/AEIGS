use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// Observed WAF response to a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProbeOutcome {
    Blocked,
    Allowed,
    RateLimited,
    Error,
}

/// A probe sent to the WAF with its observed outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafProbe {
    pub payload: String,
    pub outcome: ProbeOutcome,
    pub encoding: Option<String>,
    pub status_code: u16,
}

/// A reverse-engineered WAF rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReversedRule {
    pub trigger_tokens: Vec<String>,
    pub blocked_chars: Vec<char>,
    pub allowed_substitutions: Vec<(String, String)>,
    pub bypass_encodings: Vec<String>,
    pub combination_bypasses: Vec<(String, String)>,
    pub confidence: f64,
    pub rule_pattern: String,
}

/// Result of binary search for trigger token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerSearchResult {
    pub token: String,
    pub minimal_trigger: String,
    pub search_steps: usize,
}

/// Result of character substitution probing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubstitutionResult {
    pub original: char,
    pub substitutions: Vec<(char, bool)>,
    pub effective_bypasses: Vec<char>,
}

/// Result of encoding discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingDiscoveryResult {
    pub payload: String,
    pub encoding: String,
    pub bypasses_waf: bool,
}

/// Result of combination testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinationTestResult {
    pub payload_a: String,
    pub payload_b: String,
    pub a_blocked: bool,
    pub b_blocked: bool,
    pub combined_blocked: bool,
    pub bypass_found: bool,
}

/// WAF Rule Reverse Engineer: given observed block/allow patterns,
/// reverse-engineers WAF rules through systematic probing.
pub struct WafRuleReverser {
    probes: Vec<WafProbe>,
    trigger_cache: HashMap<String, TriggerSearchResult>,
    substitution_cache: HashMap<char, SubstitutionResult>,
}

impl WafRuleReverser {
    pub fn new() -> Self {
        Self {
            probes: Vec::new(),
            trigger_cache: HashMap::new(),
            substitution_cache: HashMap::new(),
        }
    }

    /// Record an observed probe result.
    pub fn record_probe(&mut self, probe: WafProbe) {
        self.probes.push(probe);
    }

    /// Record multiple probes at once.
    pub fn record_probes(&mut self, probes: Vec<WafProbe>) {
        self.probes.extend(probes);
    }

    /// Binary search for the minimum trigger token within a blocked payload.
    /// Takes a payload known to be blocked and narrows down the trigger.
    pub fn binary_search_trigger(&mut self, blocked_payload: &str) -> TriggerSearchResult {
        if let Some(cached) = self.trigger_cache.get(blocked_payload) {
            return cached.clone();
        }

        let chars: Vec<char> = blocked_payload.chars().collect();
        let len = chars.len();

        if len <= 1 {
            let result = TriggerSearchResult {
                token: blocked_payload.to_string(),
                minimal_trigger: blocked_payload.to_string(),
                search_steps: 0,
            };
            self.trigger_cache
                .insert(blocked_payload.to_string(), result.clone());
            return result;
        }

        let mut steps = 0;
        let mut best_trigger = blocked_payload.to_string();
        let mut start = 0;
        let mut end = len;

        while end - start > 1 {
            steps += 1;
            let mid = (start + end) / 2;
            let left: String = chars[start..mid].iter().collect();
            let right: String = chars[mid..end].iter().collect();

            let left_blocked = self.is_likely_blocked(&left);
            let right_blocked = self.is_likely_blocked(&right);

            if left_blocked && left.len() < best_trigger.len() {
                best_trigger = left;
                end = mid;
            } else if right_blocked && right.len() < best_trigger.len() {
                best_trigger = right;
                start = mid;
            } else {
                break;
            }
        }

        let result = TriggerSearchResult {
            token: blocked_payload.to_string(),
            minimal_trigger: best_trigger,
            search_steps: steps,
        };
        self.trigger_cache
            .insert(blocked_payload.to_string(), result.clone());
        result
    }

    /// Probe character substitutions to find what's blocked.
    pub fn probe_char_substitutions(&mut self, blocked_char: char) -> SubstitutionResult {
        if let Some(cached) = self.substitution_cache.get(&blocked_char) {
            return cached.clone();
        }

        let substitution_candidates = get_substitution_candidates(blocked_char);
        let mut substitutions = Vec::new();
        let mut effective = Vec::new();

        for candidate in &substitution_candidates {
            let bypasses = !self.is_char_blocked(*candidate);
            substitutions.push((*candidate, bypasses));
            if bypasses {
                effective.push(*candidate);
            }
        }

        let result = SubstitutionResult {
            original: blocked_char,
            substitutions,
            effective_bypasses: effective,
        };
        self.substitution_cache.insert(blocked_char, result.clone());
        result
    }

    /// Discover which encodings bypass the WAF for a blocked payload.
    pub fn discover_bypass_encodings(&self, payload: &str) -> Vec<EncodingDiscoveryResult> {
        #[allow(clippy::type_complexity)]
        let encoding_fns: Vec<(&str, fn(&str) -> String)> = vec![
            ("url", url_encode_simple as fn(&str) -> String),
            ("double-url", double_url_encode as fn(&str) -> String),
            ("unicode", unicode_escape as fn(&str) -> String),
            ("html-entity", html_entity as fn(&str) -> String),
            ("hex", hex_escape as fn(&str) -> String),
            ("octal", octal_escape as fn(&str) -> String),
            ("overlong-utf8", overlong_utf8 as fn(&str) -> String),
            ("base64", simple_base64 as fn(&str) -> String),
        ];

        encoding_fns
            .into_iter()
            .map(|(name, encode_fn)| {
                let encoded = encode_fn(payload);
                let bypasses = !self.is_payload_in_blocked_set(&encoded);
                EncodingDiscoveryResult {
                    payload: encoded,
                    encoding: name.to_string(),
                    bypasses_waf: bypasses,
                }
            })
            .collect()
    }

    /// Test combinations of payloads: A blocked, B blocked, A+B might be allowed.
    pub fn test_combinations(&self, payloads: &[String]) -> Vec<CombinationTestResult> {
        let mut results = Vec::new();

        for i in 0..payloads.len() {
            for j in (i + 1)..payloads.len() {
                let a = &payloads[i];
                let b = &payloads[j];
                let a_blocked = self.is_payload_in_blocked_set(a);
                let b_blocked = self.is_payload_in_blocked_set(b);

                let combined = format!("{}{}", a, b);
                let combined_blocked = self.is_payload_in_blocked_set(&combined);

                let interleaved = interleave_strings(a, b);
                let interleaved_blocked = self.is_payload_in_blocked_set(&interleaved);

                let bypass_found =
                    (a_blocked || b_blocked) && (!combined_blocked || !interleaved_blocked);

                results.push(CombinationTestResult {
                    payload_a: a.clone(),
                    payload_b: b.clone(),
                    a_blocked,
                    b_blocked,
                    combined_blocked: combined_blocked && interleaved_blocked,
                    bypass_found,
                });
            }
        }

        results
    }

    /// Analyze all recorded probes and reverse-engineer rules.
    pub fn analyze(&mut self) -> Vec<ReversedRule> {
        let blocked: Vec<String> = self
            .probes
            .iter()
            .filter(|p| p.outcome == ProbeOutcome::Blocked)
            .map(|p| p.payload.clone())
            .collect();

        let allowed: Vec<String> = self
            .probes
            .iter()
            .filter(|p| p.outcome == ProbeOutcome::Allowed)
            .map(|p| p.payload.clone())
            .collect();

        if blocked.is_empty() {
            return Vec::new();
        }

        let mut trigger_tokens: Vec<String> = Vec::new();
        let blocked_clone = blocked.clone();
        for payload in &blocked_clone {
            let result = self.binary_search_trigger(payload);
            trigger_tokens.push(result.minimal_trigger);
        }
        trigger_tokens.sort();
        trigger_tokens.dedup();

        let blocked_chars = extract_blocked_chars(&blocked, &allowed);

        let mut allowed_substitutions = Vec::new();
        for &ch in &blocked_chars {
            let subs = self.probe_char_substitutions(ch);
            for bypass_char in &subs.effective_bypasses {
                allowed_substitutions.push((ch.to_string(), bypass_char.to_string()));
            }
        }

        let mut bypass_encodings = Vec::new();
        if let Some(first_blocked) = blocked.first() {
            let enc_results = self.discover_bypass_encodings(first_blocked);
            for r in enc_results {
                if r.bypasses_waf {
                    bypass_encodings.push(r.encoding);
                }
            }
        }

        let combination_results = self.test_combinations(&blocked);
        let mut combination_bypasses = Vec::new();
        for cr in &combination_results {
            if cr.bypass_found {
                combination_bypasses.push((cr.payload_a.clone(), cr.payload_b.clone()));
            }
        }

        let pattern = infer_rule_pattern(&trigger_tokens);
        let confidence = compute_confidence(blocked.len(), allowed.len(), &trigger_tokens);

        vec![ReversedRule {
            trigger_tokens,
            blocked_chars,
            allowed_substitutions,
            bypass_encodings,
            combination_bypasses,
            confidence,
            rule_pattern: pattern,
        }]
    }

    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }

    pub fn blocked_count(&self) -> usize {
        self.probes
            .iter()
            .filter(|p| p.outcome == ProbeOutcome::Blocked)
            .count()
    }

    pub fn allowed_count(&self) -> usize {
        self.probes
            .iter()
            .filter(|p| p.outcome == ProbeOutcome::Allowed)
            .count()
    }

    fn is_likely_blocked(&self, fragment: &str) -> bool {
        let fragment_lower = fragment.to_lowercase();
        self.probes.iter().any(|p| {
            p.outcome == ProbeOutcome::Blocked && p.payload.to_lowercase().contains(&fragment_lower)
        })
    }

    fn is_payload_in_blocked_set(&self, payload: &str) -> bool {
        let payload_lower = payload.to_lowercase();
        self.probes.iter().any(|p| {
            p.outcome == ProbeOutcome::Blocked && p.payload.to_lowercase() == payload_lower
        })
    }

    fn is_char_blocked(&self, ch: char) -> bool {
        let ch_str = ch.to_string();
        self.probes
            .iter()
            .any(|p| p.outcome == ProbeOutcome::Blocked && p.payload.contains(&ch_str))
    }
}

impl Default for WafRuleReverser {
    fn default() -> Self {
        Self::new()
    }
}

fn get_substitution_candidates(ch: char) -> Vec<char> {
    match ch {
        '<' => vec!['\u{FF1C}', '\u{FE64}', '\u{2039}', '\u{00AB}'],
        '>' => vec!['\u{FF1E}', '\u{FE65}', '\u{203A}', '\u{00BB}'],
        '\'' => vec!['\u{2018}', '\u{2019}', '\u{FF07}', '\u{0060}'],
        '"' => vec!['\u{201C}', '\u{201D}', '\u{FF02}', '\u{00AB}'],
        '(' => vec!['\u{FF08}', '\u{FE59}', '\u{207D}'],
        ')' => vec!['\u{FF09}', '\u{FE5A}', '\u{207E}'],
        '/' => vec!['\u{FF0F}', '\u{2215}', '\u{2044}'],
        '\\' => vec!['\u{FF3C}', '\u{FE68}', '\u{2216}'],
        '=' => vec!['\u{FF1D}', '\u{FE66}', '\u{2261}'],
        ';' => vec!['\u{FF1B}', '\u{FE54}', '\u{037E}'],
        ' ' => vec![
            '\u{00A0}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{3000}',
        ],
        _ => vec![],
    }
}

fn extract_blocked_chars(blocked: &[String], allowed: &[String]) -> Vec<char> {
    let mut blocked_char_set: HashSet<char> = HashSet::new();
    for payload in blocked {
        for ch in payload.chars() {
            blocked_char_set.insert(ch);
        }
    }

    let mut allowed_char_set: HashSet<char> = HashSet::new();
    for payload in allowed {
        for ch in payload.chars() {
            allowed_char_set.insert(ch);
        }
    }

    let special_chars: HashSet<char> = [
        '<', '>', '\'', '"', '(', ')', '/', '\\', '=', ';', '&', '|', '`', '{', '}',
    ]
    .iter()
    .copied()
    .collect();

    blocked_char_set
        .iter()
        .filter(|ch| special_chars.contains(ch))
        .filter(|ch| !allowed_char_set.contains(ch))
        .copied()
        .collect()
}

fn infer_rule_pattern(triggers: &[String]) -> String {
    if triggers.is_empty() {
        return "unknown".to_string();
    }

    let common_sqli = [
        "select", "union", "insert", "drop", "delete", "update", "exec",
    ];
    let common_xss = [
        "script", "alert", "onerror", "onload", "img", "svg", "iframe",
    ];
    let common_cmdi = ["|", ";", "&&", "||", "`", "$("];
    let common_path = ["../", "..\\", "%2e%2e", "/etc/passwd"];

    let lower_triggers: Vec<String> = triggers.iter().map(|t| t.to_lowercase()).collect();

    if lower_triggers
        .iter()
        .any(|t| common_sqli.iter().any(|s| t.contains(s)))
    {
        return "sqli-keyword-filter".to_string();
    }
    if lower_triggers
        .iter()
        .any(|t| common_xss.iter().any(|s| t.contains(s)))
    {
        return "xss-tag-filter".to_string();
    }
    if lower_triggers
        .iter()
        .any(|t| common_cmdi.iter().any(|s| t.contains(s)))
    {
        return "command-injection-filter".to_string();
    }
    if lower_triggers
        .iter()
        .any(|t| common_path.iter().any(|s| t.contains(s)))
    {
        return "path-traversal-filter".to_string();
    }

    "generic-pattern-filter".to_string()
}

fn compute_confidence(blocked: usize, allowed: usize, triggers: &[String]) -> f64 {
    let sample_score = ((blocked + allowed) as f64 / 20.0).min(1.0);
    let trigger_score = if triggers.is_empty() {
        0.0
    } else {
        (triggers.len() as f64 / 5.0).min(1.0)
    };
    let diversity_score = if allowed > 0 && blocked > 0 { 0.8 } else { 0.4 };
    (sample_score * 0.4 + trigger_score * 0.3 + diversity_score * 0.3).min(1.0)
}

fn interleave_strings(a: &str, b: &str) -> String {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let mut result = String::new();
    let max_len = a_chars.len().max(b_chars.len());
    for i in 0..max_len {
        if i < a_chars.len() {
            result.push(a_chars[i]);
        }
        if i < b_chars.len() {
            result.push(b_chars[i]);
        }
    }
    result
}

fn url_encode_simple(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => (b as char).to_string(),
            _ => format!("%{:02X}", b),
        })
        .collect()
}

fn double_url_encode(s: &str) -> String {
    url_encode_simple(&url_encode_simple(s))
}

fn unicode_escape(s: &str) -> String {
    s.chars().map(|c| format!("\\u{:04x}", c as u32)).collect()
}

fn html_entity(s: &str) -> String {
    s.chars().map(|c| format!("&#{};", c as u32)).collect()
}

fn hex_escape(s: &str) -> String {
    s.bytes().map(|b| format!("\\x{:02x}", b)).collect()
}

fn octal_escape(s: &str) -> String {
    s.bytes().map(|b| format!("\\{:03o}", b)).collect()
}

fn overlong_utf8(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b < 0x80 {
                format!("%{:02X}%{:02X}", 0xC0 | (b >> 6), 0x80 | (b & 0x3F))
            } else {
                format!("%{:02X}", b)
            }
        })
        .collect()
}

fn simple_base64(s: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = s.as_bytes();
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        let mut buf = [0u8; 3];
        for (i, &b) in chunk.iter().enumerate() {
            buf[i] = b;
        }
        let n = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        result.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((n >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(n & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}
