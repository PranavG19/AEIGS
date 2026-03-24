use std::collections::HashMap;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum TokenEntropyIssue {
    WeakSessionToken,
    PredictableCsrfToken,
    ShortApiKey,
    NumericOnlyToken,
    SequentialToken,
    TimestampBasedToken,
    Base64WeakSecret,
    HardcodedToken,
}

impl std::fmt::Display for TokenEntropyIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WeakSessionToken => write!(f, "weak_session_token"),
            Self::PredictableCsrfToken => write!(f, "predictable_csrf_token"),
            Self::ShortApiKey => write!(f, "short_api_key"),
            Self::NumericOnlyToken => write!(f, "numeric_only_token"),
            Self::SequentialToken => write!(f, "sequential_token"),
            Self::TimestampBasedToken => write!(f, "timestamp_based_token"),
            Self::Base64WeakSecret => write!(f, "base64_weak_secret"),
            Self::HardcodedToken => write!(f, "hardcoded_token"),
        }
    }
}

const TOKEN_KEYS: &[&str] = &[
    "token=",
    "session_id=",
    "api_key=",
    "csrf_token=",
    "secret=",
];

const JS_ASSIGN_PATTERNS: &[&str] = &[
    "const token",
    "var token",
    "let token",
    "const api_key",
    "var api_key",
    "let api_key",
    "const apikey",
    "var apikey",
    "let apikey",
    "const secret",
    "var secret",
    "let secret",
    "const session_token",
    "var session_token",
    "let session_token",
];

pub fn scan_token_entropy(target: &str) -> Vec<TokenEntropyIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_token_entropy(&body)
}

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<u8, usize> = HashMap::new();
    for b in s.as_bytes() {
        *freq.entry(*b).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    freq.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

pub fn extract_tokens(body: &str) -> Vec<(String, String)> {
    let lower = body.to_ascii_lowercase();
    let mut tokens = Vec::new();
    for key in TOKEN_KEYS {
        let name = key.trim_end_matches('=');
        let mut pos = 0;
        while let Some(idx) = lower[pos..].find(key) {
            let abs = pos + idx + key.len();
            let rest = &body[abs..];
            let rest = rest.trim_start_matches(['"', '\'', ' ']);
            let end = rest
                .find(['"', '\'', '&', ' ', ';', ',', '\n', '\r', '}', ')'])
                .unwrap_or(rest.len());
            let value = rest[..end].trim();
            if !value.is_empty() {
                tokens.push((name.to_string(), value.to_string()));
            }
            pos = abs;
        }
    }
    tokens
}

fn is_sequential(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }
    let bytes = s.as_bytes();
    let ascending = bytes.windows(2).all(|w| w[1] == w[0] + 1);
    let descending = bytes.windows(2).all(|w| w[0] == w[1] + 1);
    if ascending || descending {
        return true;
    }
    if s.chars().all(|c| c.is_ascii_digit())
        && let Ok(n) = s.parse::<u64>()
    {
        let digits = s.len() as u32;
        let base = 10u64.pow(digits - 1);
        if n > 0 && n % base == 0 {
            return false;
        }
        let s_str = n.to_string();
        let s_bytes = s_str.as_bytes();
        let num_ascending = s_bytes.windows(2).all(|w| w[1] == w[0] + 1);
        let num_descending = s_bytes.windows(2).all(|w| w[0] == w[1] + 1);
        if num_ascending || num_descending {
            return true;
        }
    }
    false
}

fn is_timestamp_based(s: &str) -> bool {
    if s.chars().all(|c| c.is_ascii_digit())
        && let Ok(n) = s.parse::<u64>()
    {
        let unix_epoch_2020 = 1_577_836_800;
        let unix_epoch_2030 = 1_893_456_000;
        if n >= unix_epoch_2020 && n <= unix_epoch_2030 {
            return true;
        }
        let ms_2020 = unix_epoch_2020 * 1000;
        let ms_2030 = unix_epoch_2030 * 1000;
        if n >= ms_2020 && n <= ms_2030 {
            return true;
        }
    }
    false
}

fn is_base64_weak(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }
    let b64_chars = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    if !b64_chars {
        return false;
    }
    let cleaned = s.trim_end_matches('=');
    if cleaned.len() < 4 {
        return false;
    }
    use std::collections::HashSet;
    let unique: HashSet<char> = cleaned.chars().collect();
    unique.len() <= 4 || shannon_entropy(cleaned) < 2.5
}

fn is_predictable_csrf(name: &str, value: &str) -> bool {
    if !name.contains("csrf") {
        return false;
    }
    if value.len() < 16 {
        return true;
    }
    if is_sequential(value) || value.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    shannon_entropy(value) < 3.0
}

pub fn analyze_token_entropy(body: &str) -> Vec<TokenEntropyIssue> {
    let mut issues = Vec::new();
    let tokens = extract_tokens(body);

    for (name, value) in &tokens {
        if value.len() < 16 && !name.contains("csrf") {
            issues.push(TokenEntropyIssue::WeakSessionToken);
        }

        if value.chars().all(|c| c.is_ascii_digit()) && value.len() >= 2 {
            issues.push(TokenEntropyIssue::NumericOnlyToken);
        }

        if is_sequential(value) {
            issues.push(TokenEntropyIssue::SequentialToken);
        }

        if is_timestamp_based(value) {
            issues.push(TokenEntropyIssue::TimestampBasedToken);
        }

        if is_base64_weak(value) {
            issues.push(TokenEntropyIssue::Base64WeakSecret);
        }

        if is_predictable_csrf(name, value) {
            issues.push(TokenEntropyIssue::PredictableCsrfToken);
        }

        if name.contains("api_key") && value.len() < 20 {
            issues.push(TokenEntropyIssue::ShortApiKey);
        }
    }

    let lower = body.to_ascii_lowercase();
    for pattern in JS_ASSIGN_PATTERNS {
        if lower.contains(pattern) {
            issues.push(TokenEntropyIssue::HardcodedToken);
            break;
        }
    }

    issues
}

pub fn token_entropy_severity(issue: &TokenEntropyIssue) -> f64 {
    match issue {
        TokenEntropyIssue::HardcodedToken => 8.0,
        TokenEntropyIssue::WeakSessionToken => 7.5,
        TokenEntropyIssue::PredictableCsrfToken => 7.0,
        TokenEntropyIssue::NumericOnlyToken => 7.0,
        TokenEntropyIssue::SequentialToken => 6.5,
        TokenEntropyIssue::ShortApiKey => 6.5,
        TokenEntropyIssue::TimestampBasedToken => 6.0,
        TokenEntropyIssue::Base64WeakSecret => 5.5,
    }
}

pub fn token_entropy_to_operations(
    issues: &[TokenEntropyIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::BrokenAuthentication,
                token_entropy_severity(issue),
                0.7,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum TokenSecurityIssue {
    TokenExfiltration,
    TokenInUrl,
    TokenNoExpiry,
    TokenCrossOriginLeak,
    TokenReplayVulnerable,
    WeakTokenGeneration,
    TokenInLocalStorage,
    TokenInComment,
    JwtWeakAlgorithm,
    TokenPaddingOracle,
}

impl std::fmt::Display for TokenSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TokenExfiltration => write!(f, "token_exfiltration"),
            Self::TokenInUrl => write!(f, "token_in_url"),
            Self::TokenNoExpiry => write!(f, "token_no_expiry"),
            Self::TokenCrossOriginLeak => write!(f, "token_cross_origin_leak"),
            Self::TokenReplayVulnerable => write!(f, "token_replay_vulnerable"),
            Self::WeakTokenGeneration => write!(f, "weak_token_generation"),
            Self::TokenInLocalStorage => write!(f, "token_in_local_storage"),
            Self::TokenInComment => write!(f, "token_in_comment"),
            Self::JwtWeakAlgorithm => write!(f, "jwt_weak_algorithm"),
            Self::TokenPaddingOracle => write!(f, "token_padding_oracle"),
        }
    }
}

pub fn analyze_token_security(body: &str) -> Vec<TokenSecurityIssue> {
    let lower = body.to_ascii_lowercase();
    let has_token_keyword = lower.contains("token")
        || lower.contains("session_id")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("csrf")
        || lower.contains("secret")
        || lower.contains("jwt");

    if !has_token_keyword {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if has_token_keyword
        && (lower.contains("fetch(")
            || lower.contains("xmlhttprequest")
            || lower.contains("sendbeacon"))
    {
        issues.push(TokenSecurityIssue::TokenExfiltration);
    }

    if (lower.contains("token=") || lower.contains("api_key=") || lower.contains("secret="))
        && (lower.contains("href=") || lower.contains("src=") || lower.contains("action="))
    {
        issues.push(TokenSecurityIssue::TokenInUrl);
    }

    if has_token_keyword
        && !lower.contains("expires")
        && !lower.contains("max-age")
        && !lower.contains("max_age")
        && !lower.contains("ttl")
        && !lower.contains("expiry")
    {
        issues.push(TokenSecurityIssue::TokenNoExpiry);
    }

    if has_token_keyword
        && (lower.contains("postmessage") || lower.contains("access-control-allow-origin: *"))
    {
        issues.push(TokenSecurityIssue::TokenCrossOriginLeak);
    }

    if has_token_keyword
        && !lower.contains("nonce")
        && !lower.contains("timestamp")
        && !lower.contains("request_id")
    {
        issues.push(TokenSecurityIssue::TokenReplayVulnerable);
    }

    if lower.contains("math.random()") && has_token_keyword {
        issues.push(TokenSecurityIssue::WeakTokenGeneration);
    }

    if lower.contains("localstorage.setitem")
        && (lower.contains("token") || lower.contains("secret") || lower.contains("api_key"))
    {
        issues.push(TokenSecurityIssue::TokenInLocalStorage);
    }

    if lower.contains("<!--") {
        let mut pos = 0;
        while let Some(start) = lower[pos..].find("<!--") {
            let abs_start = pos + start;
            if let Some(end) = lower[abs_start..].find("-->") {
                let comment = &lower[abs_start..abs_start + end + 3];
                if comment.contains("token")
                    || comment.contains("secret")
                    || comment.contains("api_key")
                    || comment.contains("session")
                {
                    issues.push(TokenSecurityIssue::TokenInComment);
                    break;
                }
                pos = abs_start + end + 3;
            } else {
                break;
            }
        }
    }

    if lower.contains("\"alg\":\"none\"")
        || lower.contains("\"alg\": \"none\"")
        || lower.contains("'alg':'none'")
        || lower.contains("\"alg\":\"hs256\"")
        || lower.contains("\"alg\": \"hs256\"")
        || lower.contains("'alg':'hs256'")
    {
        issues.push(TokenSecurityIssue::JwtWeakAlgorithm);
    }

    if has_token_keyword {
        let tokens = extract_tokens(body);
        for (_, value) in &tokens {
            if value.len() >= 16 && value.len() % 8 == 0 && is_block_cipher_padding(value) {
                issues.push(TokenSecurityIssue::TokenPaddingOracle);
                break;
            }
        }
    }

    issues
}

fn is_block_cipher_padding(value: &str) -> bool {
    if value.len() < 16 {
        return false;
    }
    let last_chars: Vec<char> = value.chars().rev().take(4).collect();
    last_chars.windows(2).all(|w| w[0] == w[1])
}

pub fn token_security_severity(issue: &TokenSecurityIssue) -> f64 {
    match issue {
        TokenSecurityIssue::TokenExfiltration => 8.5,
        TokenSecurityIssue::JwtWeakAlgorithm => 8.0,
        TokenSecurityIssue::WeakTokenGeneration => 8.0,
        TokenSecurityIssue::TokenInUrl => 7.5,
        TokenSecurityIssue::TokenCrossOriginLeak => 7.0,
        TokenSecurityIssue::TokenReplayVulnerable => 7.0,
        TokenSecurityIssue::TokenInLocalStorage => 6.5,
        TokenSecurityIssue::TokenInComment => 6.5,
        TokenSecurityIssue::TokenNoExpiry => 6.0,
        TokenSecurityIssue::TokenPaddingOracle => 5.5,
    }
}

pub fn token_security_to_operations(
    issues: &[TokenSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::BrokenAuthentication,
                token_security_severity(issue),
                0.5,
            )
        })
        .collect()
}

#[cfg(test)]
#[path = "token_entropy_scanner_test.rs"]
mod token_entropy_scanner_test;
