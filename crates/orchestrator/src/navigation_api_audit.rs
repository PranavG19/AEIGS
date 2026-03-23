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

#[derive(Debug, Clone, PartialEq)]
pub enum NavigationSecurityIssue {
    NavigationHijacking,
    HistoryEnumeration,
    StateExfiltration,
    CrossOriginNavigation,
    BackButtonDisabling,
    UrlSpoofing,
    FormInterception,
    PersistentNavTracking,
    NavigationTiming,
    UnauthorizedRedirect,
}

impl std::fmt::Display for NavigationSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NavigationHijacking => write!(f, "navigation_hijacking"),
            Self::HistoryEnumeration => write!(f, "history_enumeration"),
            Self::StateExfiltration => write!(f, "state_exfiltration"),
            Self::CrossOriginNavigation => write!(f, "cross_origin_navigation"),
            Self::BackButtonDisabling => write!(f, "back_button_disabling"),
            Self::UrlSpoofing => write!(f, "url_spoofing"),
            Self::FormInterception => write!(f, "form_interception"),
            Self::PersistentNavTracking => write!(f, "persistent_nav_tracking"),
            Self::NavigationTiming => write!(f, "navigation_timing"),
            Self::UnauthorizedRedirect => write!(f, "unauthorized_redirect"),
        }
    }
}

pub fn analyze_navigation_security(body: &str) -> Vec<NavigationSecurityIssue> {
    if !body.contains("navigation.") && !body.contains("NavigateEvent") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("navigation.addEventListener")
        && body.contains("intercept(")
        && (body.contains("window.location") || body.contains("redirect"))
    {
        issues.push(NavigationSecurityIssue::NavigationHijacking);
    }

    if body.contains("navigation.entries()")
        && (body.contains(".url") || body.contains(".key") || body.contains("forEach"))
    {
        issues.push(NavigationSecurityIssue::HistoryEnumeration);
    }

    if body.contains("navigation.")
        && (body.contains("fetch(")
            || body.contains("XMLHttpRequest")
            || body.contains("sendBeacon"))
        && (body.contains(".state") || body.contains(".url") || body.contains("currentEntry"))
    {
        issues.push(NavigationSecurityIssue::StateExfiltration);
    }

    if body.contains("navigation.addEventListener")
        && body.contains("intercept(")
        && (body.contains(".origin")
            || body.contains("cross-origin")
            || body.contains("crossOrigin"))
    {
        issues.push(NavigationSecurityIssue::CrossOriginNavigation);
    }

    if body.contains("navigation.addEventListener")
        && (body.contains("preventDefault") || body.contains("intercept("))
        && (body.contains("\"back\"") || body.contains("history.back"))
    {
        issues.push(NavigationSecurityIssue::BackButtonDisabling);
    }

    if body.contains("navigation.navigate")
        && (body.contains("pushState")
            || body.contains("replaceState")
            || body.contains("history."))
        && body.contains("location.href")
    {
        issues.push(NavigationSecurityIssue::UrlSpoofing);
    }

    if (body.contains("NavigateEvent") || body.contains("navigation.addEventListener"))
        && body.contains("intercept(")
        && (body.contains("formData") || body.contains(".form") || body.contains("\"submit\""))
    {
        issues.push(NavigationSecurityIssue::FormInterception);
    }

    if body.contains("navigation.")
        && body.contains("localStorage")
        && (body.contains("setItem") || body.contains("getItem"))
    {
        issues.push(NavigationSecurityIssue::PersistentNavTracking);
    }

    if body.contains("navigation.")
        && (body.contains("performance.now")
            || body.contains("performance.timing")
            || body.contains("Date.now"))
    {
        issues.push(NavigationSecurityIssue::NavigationTiming);
    }

    if body.contains("navigation.navigate(")
        && !body.contains("user")
        && !body.contains("click")
        && (body.contains("setTimeout") || body.contains("setInterval") || body.contains("onload"))
    {
        issues.push(NavigationSecurityIssue::UnauthorizedRedirect);
    }

    issues
}

pub fn navigation_security_severity(issue: &NavigationSecurityIssue) -> f64 {
    match issue {
        NavigationSecurityIssue::NavigationHijacking => 8.5,
        NavigationSecurityIssue::StateExfiltration => 8.0,
        NavigationSecurityIssue::FormInterception => 7.5,
        NavigationSecurityIssue::CrossOriginNavigation => 7.0,
        NavigationSecurityIssue::UrlSpoofing => 6.5,
        NavigationSecurityIssue::BackButtonDisabling => 6.0,
        NavigationSecurityIssue::UnauthorizedRedirect => 5.5,
        NavigationSecurityIssue::HistoryEnumeration => 5.0,
        NavigationSecurityIssue::PersistentNavTracking => 4.5,
        NavigationSecurityIssue::NavigationTiming => 4.0,
    }
}

pub fn navigation_security_to_operations(
    issues: &[NavigationSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                navigation_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
