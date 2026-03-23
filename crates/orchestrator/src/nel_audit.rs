use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone)]
pub struct NelIssue {
    pub kind: NelIssueKind,
    pub detail: String,
    pub severity: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NelIssueKind {
    NelPresent,
    ExternalReportEndpoint,
    HttpReportEndpoint,
    HighSampleRate,
    ReportToPresent,
}

pub fn audit_nel(target: &str) -> Vec<NelIssue> {
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

    let nel_value = resp
        .headers()
        .get("nel")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let report_to_values: Vec<String> = resp
        .headers()
        .get_all("report-to")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();

    let target_domain = recon_client::validated_domain(target);
    analyze_nel(nel_value.as_deref(), &report_to_values, target_domain.as_deref())
}

pub(crate) fn analyze_nel(
    nel: Option<&str>,
    report_to: &[String],
    target_domain: Option<&str>,
) -> Vec<NelIssue> {
    let mut issues = Vec::new();

    if let Some(nel_val) = nel {
        issues.push(NelIssue {
            kind: NelIssueKind::NelPresent,
            detail: "NEL header exposes network error telemetry to report collector".into(),
            severity: 3.0,
        });

        if let Some(rate) = extract_json_f64(nel_val, "success_fraction")
            && rate > 0.5
        {
            issues.push(NelIssue {
                kind: NelIssueKind::HighSampleRate,
                detail: format!("success_fraction={rate} — high sample rate increases data leak"),
                severity: 3.5,
            });
        }
    }

    for val in report_to {
        issues.extend(check_report_to(val, target_domain));
    }

    issues
}

fn check_report_to(value: &str, target_domain: Option<&str>) -> Vec<NelIssue> {
    let mut issues = Vec::new();
    let lower = value.to_ascii_lowercase();

    if !issues.iter().any(|i: &NelIssue| i.kind == NelIssueKind::ReportToPresent)
        && lower.contains("\"endpoints\"")
    {
        issues.push(NelIssue {
            kind: NelIssueKind::ReportToPresent,
            detail: "Report-To header configured — browser sends error reports to collector".into(),
            severity: 2.5,
        });
    }

    for url in extract_urls(&lower) {
        if url.starts_with("http://") {
            issues.push(NelIssue {
                kind: NelIssueKind::HttpReportEndpoint,
                detail: format!("Report endpoint uses HTTP (not HTTPS): {}", truncate(&url, 80)),
                severity: 5.0,
            });
        }

        if let Some(domain) = target_domain
            && let Some(host) = extract_host(&url)
            && !host.ends_with(domain)
            && host != domain
        {
            issues.push(NelIssue {
                kind: NelIssueKind::ExternalReportEndpoint,
                detail: format!(
                    "Reports sent to external domain: {}",
                    truncate(&host, 60)
                ),
                severity: 4.0,
            });
        }
    }

    issues
}

fn extract_urls(json_like: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut search_from = 0;
    while let Some(pos) = json_like[search_from..].find("http") {
        let abs = search_from + pos;
        let end = json_like[abs..]
            .find(['"', '\'', ' ', ',', '}'])
            .map(|e| abs + e)
            .unwrap_or(json_like.len());
        let url = &json_like[abs..end];
        if url.starts_with("http://") || url.starts_with("https://") {
            urls.push(url.to_string());
        }
        search_from = end;
    }
    urls
}

fn extract_host(url: &str) -> Option<String> {
    let without_scheme = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let host = without_scheme.split('/').next()?;
    let host = host.split(':').next()?;
    if host.is_empty() {
        return None;
    }
    Some(host.to_string())
}

fn extract_json_f64(json_like: &str, key: &str) -> Option<f64> {
    let lower = json_like.to_ascii_lowercase();
    let pat = format!("\"{key}\"");
    let pos = lower.find(&pat)?;
    let after_key = &json_like[pos + pat.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    let end = after_colon
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
        .unwrap_or(after_colon.len());
    after_colon[..end].parse().ok()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max.saturating_sub(3)])
    } else {
        s.to_string()
    }
}

pub fn nel_to_operations(
    issues: &[NelIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues
        .iter()
        .map(|i| i.severity)
        .fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::InformationDisclosure,
        max_severity,
        0.85,
    )]
}
