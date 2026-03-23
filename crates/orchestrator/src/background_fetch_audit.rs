use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum BackgroundFetchIssue {
    ApiDetected,
    DataExfiltration,
    LargeDownload,
    TrackingViaBgFetch,
    ResourceAbuse,
}

impl std::fmt::Display for BackgroundFetchIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::LargeDownload => write!(f, "large_download"),
            Self::TrackingViaBgFetch => write!(f, "tracking_via_bg_fetch"),
            Self::ResourceAbuse => write!(f, "resource_abuse"),
        }
    }
}

fn has_background_fetch_api(body: &str) -> bool {
    body.contains("backgroundFetch")
        || body.contains("BackgroundFetchManager")
        || body.contains("BackgroundFetchRegistration")
}

pub fn audit_background_fetch(target: &str) -> Vec<BackgroundFetchIssue> {
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
    analyze_background_fetch(&body)
}

pub fn analyze_background_fetch(body: &str) -> Vec<BackgroundFetchIssue> {
    let mut issues = Vec::new();

    if !has_background_fetch_api(body) {
        return issues;
    }

    issues.push(BackgroundFetchIssue::ApiDetected);

    if body.contains("fetch(")
        && (body.contains("userData")
            || body.contains("localStorage")
            || body.contains("sessionStorage")
            || body.contains("cookie")
            || body.contains("indexedDB"))
    {
        issues.push(BackgroundFetchIssue::DataExfiltration);
    }

    if (body.contains("downloadTotal") || body.contains("GB") || body.contains("gigabyte"))
        && !body.contains("confirm")
        && !body.contains("prompt")
    {
        issues.push(BackgroundFetchIssue::LargeDownload);
    }

    if (body.contains("backgroundfetchsuccess")
        || body.contains("backgroundfetchfail")
        || body.contains("backgroundfetchclick"))
        && (body.contains("analytics") || body.contains("track") || body.contains("beacon"))
    {
        issues.push(BackgroundFetchIssue::TrackingViaBgFetch);
    }

    if (body.contains("while") || body.contains("setInterval") || body.contains("for(") || body.contains("for ("))
        && body.contains("fetch(")
        && !body.contains("limit")
        && !body.contains("abort")
    {
        issues.push(BackgroundFetchIssue::ResourceAbuse);
    }

    issues
}

pub fn background_fetch_severity(issue: &BackgroundFetchIssue) -> f64 {
    match issue {
        BackgroundFetchIssue::ApiDetected => 2.0,
        BackgroundFetchIssue::DataExfiltration => 7.5,
        BackgroundFetchIssue::LargeDownload => 6.0,
        BackgroundFetchIssue::TrackingViaBgFetch => 6.5,
        BackgroundFetchIssue::ResourceAbuse => 5.5,
    }
}

pub fn background_fetch_to_operations(
    issues: &[BackgroundFetchIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                background_fetch_severity(issue),
                0.5,
            )
        })
        .collect()
}
