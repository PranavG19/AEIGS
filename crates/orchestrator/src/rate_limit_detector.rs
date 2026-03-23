use std::fmt;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::recon_client;
use crate::util::timestamp_ms;

const RATE_LIMIT_HEADERS: &[&str] = &[
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "x-rate-limit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "retry-after",
];

#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub headers: Vec<(String, String)>,
}

pub fn detect_rate_limits(target: &str) -> Option<RateLimitInfo> {
    recon_client::validated_domain(target)?;
    let client = recon_client::default_client()?;

    let resp = client.get(target).send().ok()?;
    let mut found_headers = Vec::new();

    for name in RATE_LIMIT_HEADERS {
        if let Some(val) = resp.headers().get(*name).and_then(|v| v.to_str().ok()) {
            found_headers.push((name.to_string(), val.to_string()));
        }
    }

    if found_headers.is_empty() {
        None
    } else {
        Some(RateLimitInfo {
            headers: found_headers,
        })
    }
}

pub fn rate_limit_to_operations(info: &RateLimitInfo, seq: &mut u64) -> Vec<OperationLogEntry> {
    *seq += 1;
    let props: Vec<(String, String)> = info
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .chain(std::iter::once((
            "source".to_string(),
            "rate_limit_detect".to_string(),
        )))
        .collect();

    vec![OperationLogEntry {
        sequence_number: *seq,
        module: ModuleIdentifier::PassiveRecon,
        operation: GraphOperation::AddNode {
            node_type: NodeType::Defense,
            properties: props,
        },
        timestamp_unix_ms: timestamp_ms(),
    }]
}

#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitIssue {
    NoRateLimiting,
    HighLimit { limit: u64 },
    NoResetHeader,
    InconsistentHeaders { headers: Vec<String> },
    RetryAfterMissing,
    LowBurstAllowance { remaining: u64, limit: u64 },
    NoLimitOnAuth,
    RateLimitBypassable { method: String },
}

impl fmt::Display for RateLimitIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRateLimiting => write!(f, "no_rate_limiting"),
            Self::HighLimit { limit } => write!(f, "high_limit:{limit}"),
            Self::NoResetHeader => write!(f, "no_reset_header"),
            Self::InconsistentHeaders { headers } => {
                write!(f, "inconsistent_headers:{}", headers.join(","))
            }
            Self::RetryAfterMissing => write!(f, "retry_after_missing"),
            Self::LowBurstAllowance { remaining, limit } => {
                write!(f, "low_burst_allowance:{remaining}/{limit}")
            }
            Self::NoLimitOnAuth => write!(f, "no_limit_on_auth"),
            Self::RateLimitBypassable { method } => {
                write!(f, "rate_limit_bypassable:{method}")
            }
        }
    }
}

pub fn rate_limit_severity(issue: &RateLimitIssue) -> f64 {
    match issue {
        RateLimitIssue::NoRateLimiting => 6.0,
        RateLimitIssue::NoLimitOnAuth => 7.0,
        RateLimitIssue::RateLimitBypassable { .. } => 6.5,
        RateLimitIssue::RetryAfterMissing => 4.0,
        RateLimitIssue::HighLimit { .. } => 5.0,
        RateLimitIssue::LowBurstAllowance { .. } => 3.5,
        RateLimitIssue::InconsistentHeaders { .. } => 3.0,
        RateLimitIssue::NoResetHeader => 2.5,
    }
}

pub fn analyze_rate_limit_headers(headers: &[(&str, &str)]) -> Vec<RateLimitIssue> {
    let mut issues = Vec::new();

    let lower: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
        .collect();

    let has_any_limit = lower.iter().any(|(k, _)| {
        k.contains("ratelimit-limit") || k.contains("rate-limit-limit") || k == "retry-after"
    });

    if !has_any_limit {
        issues.push(RateLimitIssue::NoRateLimiting);
        return issues;
    }

    let limit_value = lower
        .iter()
        .find(|(k, _)| k.contains("ratelimit-limit") || k.contains("rate-limit-limit"))
        .and_then(|(_, v)| v.parse::<u64>().ok());

    if let Some(limit) = limit_value
        && limit > 10_000
    {
        issues.push(RateLimitIssue::HighLimit { limit });
    }

    let has_limit_header = lower
        .iter()
        .any(|(k, _)| k.contains("ratelimit-limit") || k.contains("rate-limit-limit"));
    let has_reset_header = lower
        .iter()
        .any(|(k, _)| k.contains("ratelimit-reset") || k.contains("rate-limit-reset"));

    if has_limit_header && !has_reset_header {
        issues.push(RateLimitIssue::NoResetHeader);
    }

    let has_x_ratelimit = lower.iter().any(|(k, _)| k.starts_with("x-ratelimit-"));
    let has_standard_ratelimit = lower
        .iter()
        .any(|(k, _)| k.starts_with("ratelimit-") && !k.starts_with("x-"));
    let has_x_rate_limit = lower.iter().any(|(k, _)| k.starts_with("x-rate-limit-"));

    let style_count = [has_x_ratelimit, has_standard_ratelimit, has_x_rate_limit]
        .iter()
        .filter(|&&v| v)
        .count();
    if style_count > 1 {
        let mut styles = Vec::new();
        if has_x_ratelimit {
            styles.push("x-ratelimit-*".to_string());
        }
        if has_standard_ratelimit {
            styles.push("ratelimit-*".to_string());
        }
        if has_x_rate_limit {
            styles.push("x-rate-limit-*".to_string());
        }
        issues.push(RateLimitIssue::InconsistentHeaders { headers: styles });
    }

    if let Some(limit) = limit_value {
        let remaining = lower
            .iter()
            .find(|(k, _)| k.contains("ratelimit-remaining") || k.contains("rate-limit-remaining"))
            .and_then(|(_, v)| v.parse::<u64>().ok());

        if let Some(rem) = remaining
            && limit > 0
            && (rem as f64 / limit as f64) < 0.05
        {
            issues.push(RateLimitIssue::LowBurstAllowance {
                remaining: rem,
                limit,
            });
        }
    }

    issues
}

pub fn rate_limit_issues_to_operations(
    issues: &[RateLimitIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                rate_limit_severity(issue),
                0.5,
            )
        })
        .collect()
}
