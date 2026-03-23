use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum NavigationApiIssue {
    NavigateIntercepted,
    NavigateEventUsed,
    CurrentEntryAccess,
    EntriesEnumerated,
    TransitionWhileUsed,
    BackForwardIntercept,
}

impl std::fmt::Display for NavigationApiIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NavigateIntercepted => write!(f, "navigate_intercepted"),
            Self::NavigateEventUsed => write!(f, "navigate_event_used"),
            Self::CurrentEntryAccess => write!(f, "current_entry_access"),
            Self::EntriesEnumerated => write!(f, "entries_enumerated"),
            Self::TransitionWhileUsed => write!(f, "transition_while_used"),
            Self::BackForwardIntercept => write!(f, "back_forward_intercept"),
        }
    }
}

pub fn audit_navigation_api(target: &str) -> Vec<NavigationApiIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_navigation_api(&body)
}

pub fn analyze_navigation_api(body: &str) -> Vec<NavigationApiIssue> {
    if !body.contains("navigation.") && !body.contains("NavigateEvent") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("navigation.addEventListener") && body.contains("\"navigate\"") {
        issues.push(NavigationApiIssue::NavigateIntercepted);
    }

    if body.contains("NavigateEvent") || body.contains("intercept(") {
        issues.push(NavigationApiIssue::NavigateEventUsed);
    }

    if body.contains("navigation.currentEntry") {
        issues.push(NavigationApiIssue::CurrentEntryAccess);
    }

    if body.contains("navigation.entries()") {
        issues.push(NavigationApiIssue::EntriesEnumerated);
    }

    if body.contains("transitionWhile") {
        issues.push(NavigationApiIssue::TransitionWhileUsed);
    }

    if body.contains("navigation.back") || body.contains("navigation.forward") {
        issues.push(NavigationApiIssue::BackForwardIntercept);
    }

    issues
}

pub fn navigation_api_severity(issue: &NavigationApiIssue) -> f64 {
    match issue {
        NavigationApiIssue::NavigateIntercepted => 6.0,
        NavigationApiIssue::TransitionWhileUsed => 5.5,
        NavigationApiIssue::NavigateEventUsed => 5.0,
        NavigationApiIssue::EntriesEnumerated => 4.5,
        NavigationApiIssue::BackForwardIntercept => 4.0,
        NavigationApiIssue::CurrentEntryAccess => 3.5,
    }
}

pub fn navigation_api_to_operations(
    issues: &[NavigationApiIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                navigation_api_severity(issue),
                0.6,
            )
        })
        .collect()
}
