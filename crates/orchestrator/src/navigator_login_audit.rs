use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum NavigatorLoginIssue {
    ApiDetected,
    LoginStatusLeak,
    PhishingRisk,
    SessionFixation,
    TrackingViaLogin,
}

impl std::fmt::Display for NavigatorLoginIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::LoginStatusLeak => write!(f, "login_status_leak"),
            Self::PhishingRisk => write!(f, "phishing_risk"),
            Self::SessionFixation => write!(f, "session_fixation"),
            Self::TrackingViaLogin => write!(f, "tracking_via_login"),
        }
    }
}

pub fn audit_navigator_login(target: &str) -> Vec<NavigatorLoginIssue> {
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
    analyze_navigator_login(&body)
}

pub fn analyze_navigator_login(body: &str) -> Vec<NavigatorLoginIssue> {
    let mut issues = Vec::new();

    let has_api = body.contains("navigator.login")
        || body.contains("NavigatorLogin")
        || body.contains("setLoggedIn")
        || body.contains("setLoggedOut")
        || body.contains("isLoggedIn");

    if !has_api {
        return issues;
    }

    issues.push(NavigatorLoginIssue::ApiDetected);

    // LoginStatusLeak: login status exposed cross-origin
    if body.contains("postMessage")
        || body.contains("iframe")
        || body.contains("cross-origin")
        || body.contains("SharedWorker")
    {
        issues.push(NavigatorLoginIssue::LoginStatusLeak);
    }

    // PhishingRisk: fake login status for phishing
    if body.contains("setLoggedIn")
        && (body.contains("modal")
            || body.contains("dialog")
            || body.contains("prompt")
            || body.contains("overlay"))
    {
        issues.push(NavigatorLoginIssue::PhishingRisk);
    }

    // SessionFixation: login state manipulation without validation
    if (body.contains("setLoggedIn") || body.contains("setLoggedOut"))
        && !(body.contains("verify")
            || body.contains("validate")
            || body.contains("token")
            || body.contains("csrf"))
    {
        issues.push(NavigatorLoginIssue::SessionFixation);
    }

    // TrackingViaLogin: login status used for tracking
    if body.contains("isLoggedIn")
        && (body.contains("analytics")
            || body.contains("track")
            || body.contains("beacon")
            || body.contains("pixel"))
    {
        issues.push(NavigatorLoginIssue::TrackingViaLogin);
    }

    issues
}

pub fn navigator_login_severity(issue: &NavigatorLoginIssue) -> f64 {
    match issue {
        NavigatorLoginIssue::ApiDetected => 2.0,
        NavigatorLoginIssue::LoginStatusLeak => 7.0,
        NavigatorLoginIssue::PhishingRisk => 7.5,
        NavigatorLoginIssue::SessionFixation => 6.5,
        NavigatorLoginIssue::TrackingViaLogin => 6.0,
    }
}

pub fn navigator_login_to_operations(
    issues: &[NavigatorLoginIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                navigator_login_severity(issue),
                0.5,
            )
        })
        .collect()
}
