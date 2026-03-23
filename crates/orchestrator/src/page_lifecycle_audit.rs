use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;
use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum PageLifecycleIssue {
    ApiDetected,
    DataLeakOnFreeze,
    StateRestorationRisk,
    BackForwardCacheAbuse,
    UnloadDataLoss,
}

impl std::fmt::Display for PageLifecycleIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataLeakOnFreeze => write!(f, "data_leak_on_freeze"),
            Self::StateRestorationRisk => write!(f, "state_restoration_risk"),
            Self::BackForwardCacheAbuse => write!(f, "back_forward_cache_abuse"),
            Self::UnloadDataLoss => write!(f, "unload_data_loss"),
        }
    }
}

pub fn page_lifecycle_severity(issue: &PageLifecycleIssue) -> f64 {
    match issue {
        PageLifecycleIssue::ApiDetected => 2.0,
        PageLifecycleIssue::DataLeakOnFreeze => 7.0,
        PageLifecycleIssue::StateRestorationRisk => 6.5,
        PageLifecycleIssue::BackForwardCacheAbuse => 6.0,
        PageLifecycleIssue::UnloadDataLoss => 5.5,
    }
}

pub fn audit_page_lifecycle(target: &str) -> Vec<PageLifecycleIssue> {
    if recon_client::validated_domain(target).is_none() { return Vec::new(); }
    let Some(client) = recon_client::default_client() else { return Vec::new(); };
    let body = match client.get(target).send() { Ok(r) => r.text().unwrap_or_default(), Err(_) => return Vec::new() };
    analyze_page_lifecycle(&body)
}

pub fn analyze_page_lifecycle(body: &str) -> Vec<PageLifecycleIssue> {
    let mut issues = Vec::new();

    if body.contains("freeze") || body.contains("resume") || body.contains("visibilitychange")
        || body.contains("document.wasDiscarded") || body.contains("pagehide") || body.contains("pageshow")
    {
        issues.push(PageLifecycleIssue::ApiDetected);
    }

    if (body.contains("freeze") || body.contains("pagehide") || body.contains("visibilitychange"))
        && (body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest"))
    {
        issues.push(PageLifecycleIssue::DataLeakOnFreeze);
    }

    if (body.contains("pageshow") || body.contains("resume") || body.contains("wasDiscarded"))
        && (body.contains("sessionStorage") || body.contains("localStorage") || body.contains("indexedDB"))
        && !(body.contains("validate") || body.contains("verify") || body.contains("check"))
    {
        issues.push(PageLifecycleIssue::StateRestorationRisk);
    }

    if body.contains("pageshow")
        && (body.contains("persisted") || body.contains("performance.navigation"))
        && (body.contains("cache") || body.contains("restore"))
    {
        issues.push(PageLifecycleIssue::BackForwardCacheAbuse);
    }

    if (body.contains("beforeunload") || body.contains("unload") || body.contains("pagehide"))
        && (body.contains("unsaved") || body.contains("dirty") || body.contains("modified") || body.contains("pending"))
        && !(body.contains("save") || body.contains("persist") || body.contains("flush"))
    {
        issues.push(PageLifecycleIssue::UnloadDataLoss);
    }

    issues
}

pub fn page_lifecycle_to_operations(
    issues: &[PageLifecycleIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                page_lifecycle_severity(issue),
                0.5,
            )
        })
        .collect()
}
