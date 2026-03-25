use std::collections::HashMap;
use std::fmt;

/// Differential response analysis engine for WAF rule inference.
///
/// The core insight: by sending the same payload through different
/// encodings, paths, and transformations, we can observe which
/// mutations get blocked and which pass. The pattern of blocks/passes
/// reveals the WAF's detection rules, enabling targeted bypass
/// construction.
///
/// The workflow:
/// 1. Send a baseline benign request → record response fingerprint
/// 2. Send the attack payload (gets blocked) → record block fingerprint
/// 3. Send mutations of the payload → classify each as blocked/passed
/// 4. Analyze the block/pass pattern → infer what the WAF is matching
/// 5. Generate targeted bypasses based on inferred rules
///
/// How a WAF responded to a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WafDecision {
    Allowed,
    Blocked,
    RateLimited,
    Challenged,
    Unknown,
}

impl fmt::Display for WafDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed => write!(f, "ALLOWED"),
            Self::Blocked => write!(f, "BLOCKED"),
            Self::RateLimited => write!(f, "RATE_LIMITED"),
            Self::Challenged => write!(f, "CHALLENGED"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Fingerprint of an HTTP response for differential comparison.
#[derive(Debug, Clone)]
pub struct ResponseFingerprint {
    pub status_code: u16,
    pub body_length: usize,
    pub body_hash: u64,
    pub content_type: Option<String>,
    pub server_header: Option<String>,
    pub has_waf_headers: bool,
    pub response_time_ms: f64,
    pub header_count: usize,
    pub body_snippet: String,
}

impl ResponseFingerprint {
    pub fn from_response(
        status_code: u16,
        headers: &[(String, String)],
        body: &str,
        response_time_ms: f64,
    ) -> Self {
        let content_type = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone());

        let server_header = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("server"))
            .map(|(_, v)| v.clone());

        let waf_header_names = [
            "x-waf-",
            "x-cdn-",
            "cf-ray",
            "x-sucuri",
            "x-akamai",
            "x-powered-by-plesk",
            "x-firewall",
        ];
        let has_waf_headers = headers.iter().any(|(k, _)| {
            let lower = k.to_lowercase();
            waf_header_names.iter().any(|w| lower.contains(w))
        });

        let snippet_len = body.len().min(200);
        let body_snippet = body[..snippet_len].to_string();

        Self {
            status_code,
            body_length: body.len(),
            body_hash: simple_hash(body),
            content_type,
            server_header,
            has_waf_headers,
            response_time_ms,
            header_count: headers.len(),
            body_snippet,
        }
    }
}

/// A probe sent to the target with its result.
#[derive(Debug, Clone)]
pub struct DifferentialProbe {
    pub payload: String,
    pub mutation: MutationType,
    pub fingerprint: ResponseFingerprint,
    pub decision: WafDecision,
}

/// Type of mutation applied to the base payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MutationType {
    Baseline,
    Original,
    UrlEncoded,
    DoubleUrlEncoded,
    UnicodeNormalized,
    HtmlEntityEncoded,
    CaseToggled,
    CommentInserted,
    WhitespaceVariant,
    NullByteInserted,
    NewlineVariant,
    TabVariant,
    CharsetOverride,
    ChunkedTransferEncoding,
    ContentTypeSwitch,
    ParameterPollution,
    JsonWrapped,
    XmlWrapped,
    PathNormalized,
    FragmentAppended,
    Custom(String),
}

impl fmt::Display for MutationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Baseline => write!(f, "baseline"),
            Self::Original => write!(f, "original"),
            Self::UrlEncoded => write!(f, "url_encoded"),
            Self::DoubleUrlEncoded => write!(f, "double_url_encoded"),
            Self::UnicodeNormalized => write!(f, "unicode_normalized"),
            Self::HtmlEntityEncoded => write!(f, "html_entity_encoded"),
            Self::CaseToggled => write!(f, "case_toggled"),
            Self::CommentInserted => write!(f, "comment_inserted"),
            Self::WhitespaceVariant => write!(f, "whitespace_variant"),
            Self::NullByteInserted => write!(f, "null_byte_inserted"),
            Self::NewlineVariant => write!(f, "newline_variant"),
            Self::TabVariant => write!(f, "tab_variant"),
            Self::CharsetOverride => write!(f, "charset_override"),
            Self::ChunkedTransferEncoding => write!(f, "chunked_transfer_encoding"),
            Self::ContentTypeSwitch => write!(f, "content_type_switch"),
            Self::ParameterPollution => write!(f, "parameter_pollution"),
            Self::JsonWrapped => write!(f, "json_wrapped"),
            Self::XmlWrapped => write!(f, "xml_wrapped"),
            Self::PathNormalized => write!(f, "path_normalized"),
            Self::FragmentAppended => write!(f, "fragment_appended"),
            Self::Custom(name) => write!(f, "custom:{}", name),
        }
    }
}

/// Generate mutation variants of a payload for differential testing.
pub fn generate_mutations(payload: &str) -> Vec<(MutationType, String)> {
    vec![
        (MutationType::Original, payload.to_string()),
        (MutationType::UrlEncoded, url_encode(payload)),
        (
            MutationType::DoubleUrlEncoded,
            url_encode(&url_encode(payload)),
        ),
        (MutationType::UnicodeNormalized, unicode_normalize(payload)),
        (MutationType::HtmlEntityEncoded, html_entity_encode(payload)),
        (MutationType::CaseToggled, toggle_case(payload)),
        (MutationType::CommentInserted, insert_comments(payload)),
        (MutationType::WhitespaceVariant, whitespace_variant(payload)),
        (MutationType::NullByteInserted, insert_null_bytes(payload)),
        (MutationType::NewlineVariant, newline_variant(payload)),
        (MutationType::TabVariant, tab_variant(payload)),
        (MutationType::JsonWrapped, json_wrap(payload)),
        (MutationType::XmlWrapped, xml_wrap(payload)),
        (
            MutationType::FragmentAppended,
            format!("{}#fragment", payload),
        ),
    ]
}

/// Classify the WAF decision based on response fingerprint comparison
/// against the baseline (benign request) and block (known blocked request)
/// fingerprints.
pub fn classify_decision(
    probe: &ResponseFingerprint,
    baseline: &ResponseFingerprint,
    block_pattern: &ResponseFingerprint,
) -> WafDecision {
    if probe.status_code == 429 {
        return WafDecision::RateLimited;
    }

    if probe.status_code == 503 && probe.body_snippet.to_lowercase().contains("challenge") {
        return WafDecision::Challenged;
    }

    let block_sim = fingerprint_similarity(probe, block_pattern);
    let baseline_sim = fingerprint_similarity(probe, baseline);

    if block_sim > 0.8 {
        return WafDecision::Blocked;
    }

    if baseline_sim > 0.7 {
        return WafDecision::Allowed;
    }

    if probe.status_code == block_pattern.status_code && probe.status_code != baseline.status_code {
        return WafDecision::Blocked;
    }

    if probe.status_code == baseline.status_code {
        return WafDecision::Allowed;
    }

    WafDecision::Unknown
}

/// Compute similarity score between two response fingerprints [0.0, 1.0].
pub fn fingerprint_similarity(a: &ResponseFingerprint, b: &ResponseFingerprint) -> f64 {
    let mut score = 0.0;
    let mut weight = 0.0;

    weight += 3.0;
    if a.status_code == b.status_code {
        score += 3.0;
    }

    weight += 2.0;
    if a.body_hash == b.body_hash {
        score += 2.0;
    } else {
        let len_ratio = if a.body_length > 0 && b.body_length > 0 {
            let min = a.body_length.min(b.body_length) as f64;
            let max = a.body_length.max(b.body_length) as f64;
            min / max
        } else if a.body_length == 0 && b.body_length == 0 {
            1.0
        } else {
            0.0
        };
        score += 2.0 * len_ratio;
    }

    weight += 1.0;
    if a.content_type == b.content_type {
        score += 1.0;
    }

    weight += 1.0;
    if a.header_count == b.header_count {
        score += 1.0;
    } else {
        let diff = (a.header_count as i32 - b.header_count as i32).unsigned_abs();
        if diff <= 2 {
            score += 0.5;
        }
    }

    if weight > 0.0 { score / weight } else { 0.0 }
}

/// An inferred WAF rule based on the pattern of blocks and passes.
#[derive(Debug, Clone)]
pub struct InferredRule {
    pub pattern: String,
    pub rule_type: InferredRuleType,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub suggested_bypasses: Vec<String>,
}

/// What kind of detection rule the WAF is using.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InferredRuleType {
    StringMatch,
    RegexPattern,
    KeywordList,
    LengthBased,
    ContentTypeRestriction,
    EncodingAware,
}

impl fmt::Display for InferredRuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StringMatch => write!(f, "string_match"),
            Self::RegexPattern => write!(f, "regex_pattern"),
            Self::KeywordList => write!(f, "keyword_list"),
            Self::LengthBased => write!(f, "length_based"),
            Self::ContentTypeRestriction => write!(f, "content_type_restriction"),
            Self::EncodingAware => write!(f, "encoding_aware"),
        }
    }
}

/// Analyze a set of differential probes to infer WAF rules.
pub fn infer_waf_rules(probes: &[DifferentialProbe]) -> Vec<InferredRule> {
    let mut rules = Vec::new();

    let allowed: Vec<&DifferentialProbe> = probes
        .iter()
        .filter(|p| p.decision == WafDecision::Allowed)
        .collect();

    let blocked: Vec<&DifferentialProbe> = probes
        .iter()
        .filter(|p| p.decision == WafDecision::Blocked)
        .collect();

    if blocked.is_empty() || allowed.is_empty() {
        return rules;
    }

    if is_case_sensitive(&allowed, &blocked) {
        rules.push(InferredRule {
            pattern: "case-sensitive keyword matching".to_string(),
            rule_type: InferredRuleType::StringMatch,
            confidence: 0.8,
            evidence: vec![
                "case-toggled variant was allowed".to_string(),
                "original was blocked".to_string(),
            ],
            suggested_bypasses: vec![
                "use mixed case: SeLeCt instead of SELECT".to_string(),
                "alternate capitalization patterns".to_string(),
            ],
        });
    }

    if encoding_bypasses_work(&allowed) {
        rules.push(InferredRule {
            pattern: "encoding-unaware detection".to_string(),
            rule_type: InferredRuleType::StringMatch,
            confidence: 0.85,
            evidence: vec![
                "URL-encoded variant was allowed".to_string(),
                "WAF does not decode before matching".to_string(),
            ],
            suggested_bypasses: vec![
                "URL encode critical characters".to_string(),
                "double URL encode".to_string(),
                "Unicode normalization".to_string(),
            ],
        });
    }

    if comment_insertion_bypasses(&allowed) {
        rules.push(InferredRule {
            pattern: "token-based matching without comment stripping".to_string(),
            rule_type: InferredRuleType::RegexPattern,
            confidence: 0.75,
            evidence: vec![
                "comment-inserted variant was allowed".to_string(),
                "WAF matches continuous token strings".to_string(),
            ],
            suggested_bypasses: vec![
                "insert SQL comments: SEL/**/ECT".to_string(),
                "insert HTML comments in XSS payloads".to_string(),
            ],
        });
    }

    if whitespace_variants_work(&allowed) {
        rules.push(InferredRule {
            pattern: "strict whitespace matching".to_string(),
            rule_type: InferredRuleType::RegexPattern,
            confidence: 0.7,
            evidence: vec![
                "whitespace variant was allowed".to_string(),
                "WAF expects specific whitespace patterns".to_string(),
            ],
            suggested_bypasses: vec![
                "use tab instead of space".to_string(),
                "use newline as whitespace".to_string(),
                "use multiple spaces".to_string(),
            ],
        });
    }

    if json_wrapping_works(&allowed) {
        rules.push(InferredRule {
            pattern: "content-type blind — no JSON body inspection".to_string(),
            rule_type: InferredRuleType::ContentTypeRestriction,
            confidence: 0.8,
            evidence: vec![
                "JSON-wrapped payload was allowed".to_string(),
                "WAF only inspects URL parameters, not JSON bodies".to_string(),
            ],
            suggested_bypasses: vec![
                "send payload in JSON body instead of URL parameter".to_string(),
                "switch Content-Type to application/json".to_string(),
            ],
        });
    }

    rules
}

/// Generate a summary of the differential analysis.
pub fn generate_analysis_summary(probes: &[DifferentialProbe]) -> AnalysisSummary {
    let mut mutation_results: HashMap<String, WafDecision> = HashMap::new();

    for probe in probes {
        mutation_results.insert(probe.mutation.to_string(), probe.decision);
    }

    let allowed_count = probes
        .iter()
        .filter(|p| p.decision == WafDecision::Allowed)
        .count();
    let blocked_count = probes
        .iter()
        .filter(|p| p.decision == WafDecision::Blocked)
        .count();

    let rules = infer_waf_rules(probes);

    let bypass_mutations: Vec<String> = probes
        .iter()
        .filter(|p| p.decision == WafDecision::Allowed && p.mutation != MutationType::Baseline)
        .map(|p| p.mutation.to_string())
        .collect();

    let waf_strictness = if blocked_count == 0 {
        0.0
    } else if allowed_count == 0 {
        1.0
    } else {
        blocked_count as f64 / (allowed_count + blocked_count) as f64
    };

    AnalysisSummary {
        total_probes: probes.len(),
        allowed_count,
        blocked_count,
        rate_limited_count: probes
            .iter()
            .filter(|p| p.decision == WafDecision::RateLimited)
            .count(),
        inferred_rules: rules,
        bypass_mutations,
        waf_strictness,
        mutation_results,
    }
}

/// Summary of the differential response analysis.
#[derive(Debug, Clone)]
pub struct AnalysisSummary {
    pub total_probes: usize,
    pub allowed_count: usize,
    pub blocked_count: usize,
    pub rate_limited_count: usize,
    pub inferred_rules: Vec<InferredRule>,
    pub bypass_mutations: Vec<String>,
    pub waf_strictness: f64,
    pub mutation_results: HashMap<String, WafDecision>,
}

fn is_case_sensitive(allowed: &[&DifferentialProbe], _blocked: &[&DifferentialProbe]) -> bool {
    allowed
        .iter()
        .any(|p| p.mutation == MutationType::CaseToggled)
}

fn encoding_bypasses_work(allowed: &[&DifferentialProbe]) -> bool {
    allowed.iter().any(|p| {
        p.mutation == MutationType::UrlEncoded
            || p.mutation == MutationType::DoubleUrlEncoded
            || p.mutation == MutationType::UnicodeNormalized
    })
}

fn comment_insertion_bypasses(allowed: &[&DifferentialProbe]) -> bool {
    allowed
        .iter()
        .any(|p| p.mutation == MutationType::CommentInserted)
}

fn whitespace_variants_work(allowed: &[&DifferentialProbe]) -> bool {
    allowed.iter().any(|p| {
        p.mutation == MutationType::WhitespaceVariant
            || p.mutation == MutationType::TabVariant
            || p.mutation == MutationType::NewlineVariant
    })
}

fn json_wrapping_works(allowed: &[&DifferentialProbe]) -> bool {
    allowed
        .iter()
        .any(|p| p.mutation == MutationType::JsonWrapped)
}

fn url_encode(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

fn unicode_normalize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '<' => '\u{FF1C}',
            '>' => '\u{FF1E}',
            '\'' => '\u{2019}',
            '"' => '\u{201D}',
            '(' => '\u{FF08}',
            ')' => '\u{FF09}',
            _ => c,
        })
        .collect()
}

fn html_entity_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '<' => "&#60;".to_string(),
            '>' => "&#62;".to_string(),
            '\'' => "&#39;".to_string(),
            '"' => "&#34;".to_string(),
            '&' => "&#38;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

fn toggle_case(s: &str) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_uppercase().next().unwrap_or(c)
            } else {
                c.to_lowercase().next().unwrap_or(c)
            }
        })
        .collect()
}

fn insert_comments(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        result.push(*c);
        if i % 3 == 1 && i < chars.len() - 1 {
            result.push_str("/**/");
        }
    }
    result
}

fn whitespace_variant(s: &str) -> String {
    s.replace(' ', "\t")
}

fn insert_null_bytes(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for (i, c) in s.chars().enumerate() {
        result.push(c);
        if i % 4 == 2 {
            result.push_str("%00");
        }
    }
    result
}

fn newline_variant(s: &str) -> String {
    s.replace(' ', "\n")
}

fn tab_variant(s: &str) -> String {
    s.replace(' ', "\t")
}

fn json_wrap(s: &str) -> String {
    format!("{{\"value\":\"{}\"}}", s.replace('"', "\\\""))
}

fn xml_wrap(s: &str) -> String {
    format!("<value>{}</value>", s)
}

fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 5381;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}

#[cfg(test)]
#[path = "differential_response_test.rs"]
mod differential_response_test;
