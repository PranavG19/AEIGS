use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum HostHeaderIssue {
    ReflectedInBody,
    ReflectedInLocation,
    XForwardedHostAccepted,
}

impl std::fmt::Display for HostHeaderIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReflectedInBody => write!(f, "host_reflected_in_body"),
            Self::ReflectedInLocation => write!(f, "host_reflected_in_location"),
            Self::XForwardedHostAccepted => write!(f, "x_forwarded_host_accepted"),
        }
    }
}

pub(crate) const CANARY_HOST: &str = "evil-canary.example.com";

pub fn audit_host_header(target: &str) -> Vec<HostHeaderIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client_no_redirect() else {
        return Vec::new();
    };

    let mut issues = Vec::new();

    // Test 1: Inject Host header with canary
    if let Ok(resp) = client.get(target).header("Host", CANARY_HOST).send() {
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if location.contains(CANARY_HOST) {
            issues.push(HostHeaderIssue::ReflectedInLocation);
        }
        if let Ok(body) = resp.text()
            && body.contains(CANARY_HOST)
        {
            issues.push(HostHeaderIssue::ReflectedInBody);
        }
    }

    // Test 2: X-Forwarded-Host injection
    if let Ok(resp) = client
        .get(target)
        .header("X-Forwarded-Host", CANARY_HOST)
        .send()
    {
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let body = resp.text().unwrap_or_default();
        let loc_match = location.as_deref().unwrap_or("").contains(CANARY_HOST);
        if loc_match || body.contains(CANARY_HOST) {
            issues.push(HostHeaderIssue::XForwardedHostAccepted);
        }
    }

    issues
}

#[cfg(test)]
pub(crate) fn analyze_host_header_response(
    location: Option<&str>,
    body: &str,
    x_forwarded_location: Option<&str>,
    x_forwarded_body: &str,
) -> Vec<HostHeaderIssue> {
    let mut issues = Vec::new();

    if let Some(loc) = location
        && loc.contains(CANARY_HOST)
    {
        issues.push(HostHeaderIssue::ReflectedInLocation);
    }
    if body.contains(CANARY_HOST) {
        issues.push(HostHeaderIssue::ReflectedInBody);
    }
    if let Some(loc) = x_forwarded_location
        && loc.contains(CANARY_HOST)
    {
        issues.push(HostHeaderIssue::XForwardedHostAccepted);
    }
    if x_forwarded_body.contains(CANARY_HOST)
        && !issues.contains(&HostHeaderIssue::XForwardedHostAccepted)
    {
        issues.push(HostHeaderIssue::XForwardedHostAccepted);
    }

    issues
}

pub(crate) fn host_header_severity(issue: &HostHeaderIssue) -> f64 {
    match issue {
        HostHeaderIssue::ReflectedInLocation => 7.0,
        HostHeaderIssue::ReflectedInBody => 5.0,
        HostHeaderIssue::XForwardedHostAccepted => 6.5,
    }
}

pub fn host_header_to_operations(
    issues: &[HostHeaderIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                host_header_severity(issue),
                0.8,
            )
        })
        .collect()
}
