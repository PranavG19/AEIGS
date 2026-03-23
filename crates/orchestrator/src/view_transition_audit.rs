use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ViewTransitionIssue {
    ApiDetected,
    CrossDocumentTransition,
    UiSpoofing,
    TransitionHijacking,
    TimingLeak,
}

impl std::fmt::Display for ViewTransitionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::CrossDocumentTransition => write!(f, "cross_document_transition"),
            Self::UiSpoofing => write!(f, "ui_spoofing"),
            Self::TransitionHijacking => write!(f, "transition_hijacking"),
            Self::TimingLeak => write!(f, "timing_leak"),
        }
    }
}

pub fn audit_view_transition(target: &str) -> Vec<ViewTransitionIssue> {
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
    analyze_view_transition(&body)
}

pub fn analyze_view_transition(body: &str) -> Vec<ViewTransitionIssue> {
    let has_api = body.contains("startViewTransition")
        || body.contains("ViewTransition");
    let has_css = body.contains("view-transition-name")
        || body.contains("::view-transition")
        || body.contains("@view-transition");

    if !has_api && !has_css {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(ViewTransitionIssue::ApiDetected);

    if body.contains("@view-transition") && body.contains("navigation") {
        issues.push(ViewTransitionIssue::CrossDocumentTransition);
    }

    if (has_api || has_css)
        && (body.contains("position: fixed") || body.contains("position: absolute"))
        && (body.contains("z-index") || body.contains("opacity"))
    {
        issues.push(ViewTransitionIssue::UiSpoofing);
    }

    if has_api
        && (body.contains(".ready") || body.contains(".finished") || body.contains(".updateCallbackDone"))
        && (body.contains("innerHTML") || body.contains("replaceWith") || body.contains("remove("))
    {
        issues.push(ViewTransitionIssue::TransitionHijacking);
    }

    if has_api
        && body.contains(".finished")
        && (body.contains("performance.now") || body.contains("Date.now"))
    {
        issues.push(ViewTransitionIssue::TimingLeak);
    }

    issues
}

pub fn view_transition_severity(issue: &ViewTransitionIssue) -> f64 {
    match issue {
        ViewTransitionIssue::TransitionHijacking => 7.0,
        ViewTransitionIssue::UiSpoofing => 6.5,
        ViewTransitionIssue::CrossDocumentTransition => 5.0,
        ViewTransitionIssue::TimingLeak => 4.0,
        ViewTransitionIssue::ApiDetected => 2.0,
    }
}

pub fn view_transition_to_operations(
    issues: &[ViewTransitionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                view_transition_severity(issue),
                0.5,
            )
        })
        .collect()
}
