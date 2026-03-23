use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum DnsPrefetchControlIssue {
    PrefetchEnabled,
    InvalidValue { value: String },
    MissingHeader,
    PrefetchWithSensitiveMeta,
    PrefetchWithExternalResources { count: usize },
    ConflictingHeaders { values: Vec<String> },
}

impl std::fmt::Display for DnsPrefetchControlIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrefetchEnabled => write!(f, "prefetch_enabled"),
            Self::InvalidValue { value } => write!(f, "invalid_value:{value}"),
            Self::MissingHeader => write!(f, "missing_header"),
            Self::PrefetchWithSensitiveMeta => write!(f, "prefetch_with_sensitive_meta"),
            Self::PrefetchWithExternalResources { count } => {
                write!(f, "prefetch_with_external_resources:{count}")
            }
            Self::ConflictingHeaders { values } => {
                write!(f, "conflicting_headers:{}", values.join(","))
            }
        }
    }
}

pub fn dns_prefetch_severity(issue: &DnsPrefetchControlIssue) -> f64 {
    match issue {
        DnsPrefetchControlIssue::PrefetchEnabled => 2.5,
        DnsPrefetchControlIssue::InvalidValue { .. } => 1.5,
        DnsPrefetchControlIssue::MissingHeader => 1.0,
        DnsPrefetchControlIssue::PrefetchWithSensitiveMeta => 4.5,
        DnsPrefetchControlIssue::PrefetchWithExternalResources { .. } => 3.5,
        DnsPrefetchControlIssue::ConflictingHeaders { .. } => 2.0,
    }
}

pub fn audit_dns_prefetch_control(target: &str) -> Vec<DnsPrefetchControlIssue> {
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

    let all_values: Vec<String> = resp
        .headers()
        .get_all("x-dns-prefetch-control")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .collect();

    let primary = all_values.first().map(|s| s.as_str());
    let body = resp.text().unwrap_or_default();

    let mut issues = analyze_dns_prefetch(primary, &body);
    if let Some(conflict) = detect_conflicting_dns_prefetch(&all_values) {
        issues.push(conflict);
    }
    issues
}

pub fn analyze_dns_prefetch(
    header_value: Option<&str>,
    body: &str,
) -> Vec<DnsPrefetchControlIssue> {
    let Some(raw) = header_value else {
        return vec![DnsPrefetchControlIssue::MissingHeader];
    };

    let lower = raw.trim().to_ascii_lowercase();
    let mut issues = Vec::new();

    if lower == "on" {
        issues.push(DnsPrefetchControlIssue::PrefetchEnabled);

        if has_sensitive_meta(body) {
            issues.push(DnsPrefetchControlIssue::PrefetchWithSensitiveMeta);
        }

        let external_count = count_external_prefetch_resources(body);
        if external_count > 0 {
            issues.push(DnsPrefetchControlIssue::PrefetchWithExternalResources {
                count: external_count,
            });
        }
    } else if lower != "off" {
        issues.push(DnsPrefetchControlIssue::InvalidValue {
            value: raw.to_string(),
        });
    }

    issues
}

pub fn detect_conflicting_dns_prefetch(values: &[String]) -> Option<DnsPrefetchControlIssue> {
    if values.len() < 2 {
        return None;
    }
    let normalized: Vec<String> = values
        .iter()
        .map(|v| v.trim().to_ascii_lowercase())
        .collect();
    let first = &normalized[0];
    let has_conflict = normalized.iter().skip(1).any(|v| v != first);
    if has_conflict {
        Some(DnsPrefetchControlIssue::ConflictingHeaders {
            values: values.to_vec(),
        })
    } else {
        None
    }
}

fn has_sensitive_meta(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    let sensitive_patterns = [
        "name=\"csrf-token\"",
        "name=\"csrf_token\"",
        "name=\"api-key\"",
        "name=\"api_key\"",
        "name=\"secret\"",
        "name=\"access-token\"",
        "name=\"access_token\"",
    ];
    sensitive_patterns.iter().any(|pat| lower.contains(pat))
}

fn count_external_prefetch_resources(body: &str) -> usize {
    let lower = body.to_ascii_lowercase();
    let mut count = 0;
    for line in lower.lines() {
        if !line.contains("<link") {
            continue;
        }
        let is_prefetch = line.contains("rel=\"dns-prefetch\"")
            || line.contains("rel='dns-prefetch'")
            || line.contains("rel=\"preconnect\"")
            || line.contains("rel='preconnect'");
        if is_prefetch {
            count += 1;
        }
    }
    count
}

pub fn dns_prefetch_to_operations(
    issues: &[DnsPrefetchControlIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues
        .iter()
        .map(dns_prefetch_severity)
        .fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        max_severity,
        0.5,
    )]
}
