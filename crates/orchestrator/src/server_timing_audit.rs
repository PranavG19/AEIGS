use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const SENSITIVE_METRIC_PATTERNS: &[(&str, f64)] = &[
    ("db", 4.0),
    ("database", 4.0),
    ("mysql", 4.5),
    ("postgres", 4.5),
    ("redis", 4.0),
    ("mongo", 4.0),
    ("cache", 3.0),
    ("memcache", 3.5),
    ("queue", 3.0),
    ("auth", 3.5),
    ("internal", 4.0),
    ("backend", 3.5),
    ("upstream", 3.0),
    ("cdn", 2.0),
];

#[derive(Debug, Clone)]
pub struct ServerTimingLeak {
    pub metric_name: String,
    pub severity: f64,
}

pub fn audit_server_timing(target: &str) -> Vec<ServerTimingLeak> {
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
        .get_all("server-timing")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();

    analyze_server_timing(&values)
}

pub(crate) fn analyze_server_timing(values: &[String]) -> Vec<ServerTimingLeak> {
    let mut leaks = Vec::new();
    let mut seen = Vec::new();

    for value in values {
        for metric in value.split(',') {
            let name = metric.split(';').next().unwrap_or("").trim();
            let lower = name.to_ascii_lowercase();

            for (pattern, severity) in SENSITIVE_METRIC_PATTERNS {
                if lower.contains(pattern) && !seen.contains(&lower) {
                    seen.push(lower.clone());
                    leaks.push(ServerTimingLeak {
                        metric_name: name.to_string(),
                        severity: *severity,
                    });
                    break;
                }
            }
        }
    }

    leaks
}

pub fn server_timing_to_operations(
    leaks: &[ServerTimingLeak],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if leaks.is_empty() {
        return Vec::new();
    }

    let max_severity = leaks.iter().map(|l| l.severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::InformationDisclosure,
        max_severity,
        0.8,
    )]
}
