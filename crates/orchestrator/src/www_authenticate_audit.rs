use std::fmt;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WwwAuthIssue {
    BasicOverHttp,
    BasicOverHttps,
    DigestWithoutQop,
    DigestWeakAlgorithm { algorithm: String },
    RealmInfoLeak { realm: String },
    RealmPathLeak { realm: String },
    NtlmAuth,
    NegotiateAuth,
    MultipleSchemes { count: usize },
    CustomScheme { scheme: String },
    MissingRealmQuotes { scheme: String },
}

impl fmt::Display for WwwAuthIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BasicOverHttp => write!(f, "basic_over_http"),
            Self::BasicOverHttps => write!(f, "basic_over_https"),
            Self::DigestWithoutQop => write!(f, "digest_without_qop"),
            Self::DigestWeakAlgorithm { algorithm } => {
                write!(f, "digest_weak_algorithm: {algorithm}")
            }
            Self::RealmInfoLeak { realm } => write!(f, "realm_info_leak: {realm}"),
            Self::RealmPathLeak { realm } => write!(f, "realm_path_leak: {realm}"),
            Self::NtlmAuth => write!(f, "ntlm_auth"),
            Self::NegotiateAuth => write!(f, "negotiate_auth"),
            Self::MultipleSchemes { count } => write!(f, "multiple_schemes: {count}"),
            Self::CustomScheme { scheme } => write!(f, "custom_scheme: {scheme}"),
            Self::MissingRealmQuotes { scheme } => {
                write!(f, "missing_realm_quotes: {scheme}")
            }
        }
    }
}

pub fn www_auth_severity(issue: &WwwAuthIssue) -> f64 {
    match issue {
        WwwAuthIssue::BasicOverHttp => 7.0,
        WwwAuthIssue::BasicOverHttps => 3.5,
        WwwAuthIssue::DigestWithoutQop => 5.0,
        WwwAuthIssue::DigestWeakAlgorithm { .. } => 4.5,
        WwwAuthIssue::RealmInfoLeak { .. } => 3.0,
        WwwAuthIssue::RealmPathLeak { .. } => 4.0,
        WwwAuthIssue::NtlmAuth => 5.5,
        WwwAuthIssue::NegotiateAuth => 3.0,
        WwwAuthIssue::MultipleSchemes { .. } => 2.0,
        WwwAuthIssue::CustomScheme { .. } => 2.5,
        WwwAuthIssue::MissingRealmQuotes { .. } => 1.5,
    }
}

const KNOWN_SCHEMES: &[&str] = &[
    "basic",
    "digest",
    "bearer",
    "ntlm",
    "negotiate",
    "hoba",
    "mutual",
    "vapid",
    "scram-sha-1",
    "scram-sha-256",
    "aws4-hmac-sha256",
    "dpop",
];

const INFO_LEAK_KEYWORDS: &[&str] = &["admin", "internal", "staging", "debug", "test", "dev "];

pub fn audit_www_authenticate(target: &str) -> Vec<WwwAuthIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let values: Vec<String> = resp
        .headers()
        .get_all("www-authenticate")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();

    let is_https = target.starts_with("https://");
    analyze_www_authenticate(&values, is_https)
}

pub fn analyze_www_authenticate(values: &[String], is_https: bool) -> Vec<WwwAuthIssue> {
    let mut issues = Vec::new();

    for val in values {
        let lower = val.to_ascii_lowercase();
        let scheme = lower.split_whitespace().next().unwrap_or("");
        let scheme_trimmed = scheme.trim_end_matches(',');

        if scheme_trimmed == "basic" {
            if is_https {
                issues.push(WwwAuthIssue::BasicOverHttps);
            } else {
                issues.push(WwwAuthIssue::BasicOverHttp);
            }
        }

        if scheme_trimmed == "digest" {
            if !lower.contains("qop=") {
                issues.push(WwwAuthIssue::DigestWithoutQop);
            }
            if let Some(algo) = extract_digest_algorithm(val) {
                let algo_lower = algo.to_ascii_lowercase();
                if algo_lower == "md5" || algo_lower == "md5-sess" {
                    issues.push(WwwAuthIssue::DigestWeakAlgorithm { algorithm: algo });
                }
            }
        }

        if scheme_trimmed == "ntlm" {
            issues.push(WwwAuthIssue::NtlmAuth);
        }

        if scheme_trimmed == "negotiate" {
            issues.push(WwwAuthIssue::NegotiateAuth);
        }

        if !KNOWN_SCHEMES.contains(&scheme_trimmed) && !scheme_trimmed.is_empty() {
            issues.push(WwwAuthIssue::CustomScheme {
                scheme: scheme_trimmed.to_string(),
            });
        }

        if let Some(realm) = extract_realm(val) {
            let realm_lower = realm.to_ascii_lowercase();
            if INFO_LEAK_KEYWORDS.iter().any(|kw| realm_lower.contains(kw)) {
                issues.push(WwwAuthIssue::RealmInfoLeak {
                    realm: realm.clone(),
                });
            }
            if realm.contains('/') || realm.contains('\\') || realm.contains("C:") {
                issues.push(WwwAuthIssue::RealmPathLeak { realm });
            }
        }

        if has_unquoted_realm(&lower, val) {
            issues.push(WwwAuthIssue::MissingRealmQuotes {
                scheme: scheme_trimmed.to_string(),
            });
        }

        let scheme_count = count_schemes(val);
        if scheme_count > 1 {
            issues.push(WwwAuthIssue::MultipleSchemes {
                count: scheme_count,
            });
        }
    }

    issues
}

pub fn extract_realm(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let pos = lower.find("realm=")?;
    let after = &value[pos + 6..];
    if let Some(quoted) = after.strip_prefix('"') {
        let end = quoted.find('"').unwrap_or(quoted.len());
        Some(quoted[..end].to_string())
    } else {
        let end = after.find([',', ' ', ';']).unwrap_or(after.len());
        Some(after[..end].to_string())
    }
}

fn extract_digest_algorithm(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let pos = lower.find("algorithm=")?;
    let after = &value[pos + 10..];
    let after = after.trim_start_matches('"');
    let end = after.find([',', ' ', ';', '"']).unwrap_or(after.len());
    let algo = after[..end].trim().to_string();
    if algo.is_empty() { None } else { Some(algo) }
}

fn has_unquoted_realm(lower: &str, _original: &str) -> bool {
    let Some(pos) = lower.find("realm=") else {
        return false;
    };
    let after = &lower[pos + 6..];
    !after.starts_with('"')
}

fn count_schemes(value: &str) -> usize {
    let mut count = 0usize;
    let lower = value.to_ascii_lowercase();
    for known in KNOWN_SCHEMES {
        if lower.contains(known) {
            count += 1;
        }
    }
    let tokens: Vec<&str> = value.split_whitespace().collect();
    for token in &tokens {
        let t = token.trim_end_matches(',').to_ascii_lowercase();
        if !KNOWN_SCHEMES.contains(&t.as_str())
            && !t.is_empty()
            && !t.contains('=')
            && !t.contains('"')
            && t.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && !t.contains('/')
        {
            count += 1;
        }
    }
    count
}

pub fn www_auth_to_operations(issues: &[WwwAuthIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                www_auth_severity(issue),
                0.5,
            )
        })
        .collect()
}

/// Backward-compatible wrapper. Delegates to `www_auth_to_operations`.
pub fn www_authenticate_to_operations(
    issues: &[WwwAuthIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    www_auth_to_operations(issues, seq)
}
