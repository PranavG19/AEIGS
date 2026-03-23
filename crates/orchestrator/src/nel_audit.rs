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
    analyze_nel(
        nel_value.as_deref(),
        &report_to_values,
        target_domain.as_deref(),
    )
}

pub fn analyze_nel(
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

    if !issues
        .iter()
        .any(|i: &NelIssue| i.kind == NelIssueKind::ReportToPresent)
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
                detail: format!(
                    "Report endpoint uses HTTP (not HTTPS): {}",
                    recon_client::truncate(&url, 80)
                ),
                severity: 5.0,
            });
        }

        if let Some(domain) = target_domain
            && let Some(host) = recon_client::extract_host(&url)
            && !host.ends_with(domain)
            && host != domain
        {
            issues.push(NelIssue {
                kind: NelIssueKind::ExternalReportEndpoint,
                detail: format!(
                    "Reports sent to external domain: {}",
                    recon_client::truncate(&host, 60)
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

pub fn nel_to_operations(issues: &[NelIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues.iter().map(|i| i.severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::InformationDisclosure,
        max_severity,
        0.85,
    )]
}

#[derive(Debug, Clone, PartialEq)]
pub enum NelCheckIssue {
    NelConfigured,
    ExternalEndpoint { host: String },
    HttpEndpoint { url: String },
    HighSuccessFraction { rate: String },
    HighFailureFraction { rate: String },
    LongMaxAge { seconds: u64 },
    MissingReportTo,
    ExcessiveReportGroups { count: usize },
    ThirdPartyCollector { collector: String },
    IncludeSubdomains,
    NoMaxAge,
    ReportToWithoutNel,
}

impl std::fmt::Display for NelCheckIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NelConfigured => {
                write!(f, "NEL header configured — exposes network error telemetry")
            }
            Self::ExternalEndpoint { host } => write!(
                f,
                "Reports sent to external domain: {}",
                recon_client::truncate(host, 60)
            ),
            Self::HttpEndpoint { url } => write!(
                f,
                "Report endpoint uses HTTP (not HTTPS): {}",
                recon_client::truncate(url, 80)
            ),
            Self::HighSuccessFraction { rate } => write!(
                f,
                "success_fraction={rate} — high sample rate increases data leak"
            ),
            Self::HighFailureFraction { rate } => write!(
                f,
                "failure_fraction={rate} — high sample rate increases data leak"
            ),
            Self::LongMaxAge { seconds } => write!(
                f,
                "max_age={seconds}s exceeds 30 days — long retention of error data"
            ),
            Self::MissingReportTo => write!(
                f,
                "NEL configured but no Report-To header — reports will fail"
            ),
            Self::ExcessiveReportGroups { count } => write!(
                f,
                "{count} Report-To groups configured — unnecessary complexity"
            ),
            Self::ThirdPartyCollector { collector } => write!(
                f,
                "Reports sent to third-party collector: {}",
                recon_client::truncate(collector, 60)
            ),
            Self::IncludeSubdomains => write!(
                f,
                "include_subdomains enabled — error reporting applies to all subdomains"
            ),
            Self::NoMaxAge => write!(f, "max_age=0 — NEL policy immediately expires"),
            Self::ReportToWithoutNel => {
                write!(f, "Report-To configured without NEL — header has no effect")
            }
        }
    }
}

pub fn nel_check_severity(issue: &NelCheckIssue) -> f64 {
    match issue {
        NelCheckIssue::HttpEndpoint { .. } => 6.0,
        NelCheckIssue::ThirdPartyCollector { .. } => 5.0,
        NelCheckIssue::ExternalEndpoint { .. } => 4.5,
        NelCheckIssue::HighSuccessFraction { .. } => 4.0,
        NelCheckIssue::HighFailureFraction { .. } => 3.5,
        NelCheckIssue::IncludeSubdomains => 3.5,
        NelCheckIssue::LongMaxAge { .. } => 3.0,
        NelCheckIssue::NelConfigured => 3.0,
        NelCheckIssue::ExcessiveReportGroups { .. } => 2.5,
        NelCheckIssue::MissingReportTo => 2.5,
        NelCheckIssue::ReportToWithoutNel => 2.0,
        NelCheckIssue::NoMaxAge => 2.0,
    }
}

pub fn analyze_nel_headers(
    headers: &[(&str, &str)],
    target_domain: Option<&str>,
) -> Vec<NelCheckIssue> {
    let mut issues = Vec::new();

    let nel = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("nel"))
        .map(|(_, v)| *v);
    let report_to_values: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("report-to"))
        .map(|(_, v)| *v)
        .collect();

    if let Some(nel_val) = nel {
        issues.push(NelCheckIssue::NelConfigured);
        let lower = nel_val.to_ascii_lowercase();

        if let Some(rate) = extract_json_f64(nel_val, "success_fraction")
            && rate > 0.5
        {
            issues.push(NelCheckIssue::HighSuccessFraction {
                rate: format!("{rate}"),
            });
        }
        if let Some(rate) = extract_json_f64(nel_val, "failure_fraction")
            && rate > 0.5
        {
            issues.push(NelCheckIssue::HighFailureFraction {
                rate: format!("{rate}"),
            });
        }
        if let Some(age) = extract_json_f64(nel_val, "max_age") {
            let secs = age as u64;
            if secs > 2_592_000 {
                // 30 days
                issues.push(NelCheckIssue::LongMaxAge { seconds: secs });
            }
            if secs == 0 {
                issues.push(NelCheckIssue::NoMaxAge);
            }
        }
        if lower.contains("\"include_subdomains\"") && lower.contains("true") {
            issues.push(NelCheckIssue::IncludeSubdomains);
        }
        if report_to_values.is_empty() {
            issues.push(NelCheckIssue::MissingReportTo);
        }
    } else if !report_to_values.is_empty() {
        issues.push(NelCheckIssue::ReportToWithoutNel);
    }

    if report_to_values.len() > 3 {
        issues.push(NelCheckIssue::ExcessiveReportGroups {
            count: report_to_values.len(),
        });
    }

    let known_collectors = [
        "sentry.io",
        "report-uri.com",
        "uriports.com",
        "nel.cloudflare.com",
    ];
    for val in &report_to_values {
        let lower = val.to_ascii_lowercase();
        for url in extract_urls(&lower) {
            if url.starts_with("http://") {
                issues.push(NelCheckIssue::HttpEndpoint { url: url.clone() });
            }
            if let Some(host) = recon_client::extract_host(&url) {
                if known_collectors.iter().any(|c| host.contains(c)) {
                    issues.push(NelCheckIssue::ThirdPartyCollector {
                        collector: host.clone(),
                    });
                }
                if let Some(domain) = target_domain
                    && !host.ends_with(domain)
                    && host != domain
                {
                    issues.push(NelCheckIssue::ExternalEndpoint { host });
                }
            }
        }
    }

    issues
}

pub fn nel_check_to_operations(issues: &[NelCheckIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                nel_check_severity(issue),
                0.5,
            )
        })
        .collect()
}
