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

pub const CANARY_HOST: &str = "evil-canary.example.com";

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

pub fn analyze_host_header_response(
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

pub fn host_header_severity(issue: &HostHeaderIssue) -> f64 {
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

#[derive(Debug, Clone, PartialEq)]
pub enum HostInjectionIssue {
    HostReflectedInBody { canary: String },
    HostReflectedInLocation { canary: String },
    XForwardedHostReflected { canary: String },
    XForwardedForAccepted,
    AbsoluteUrlAccepted,
    PortInjection { port: String },
    DuplicateHostHeader,
    HostHeaderCachePoisoning,
    PasswordResetPoisoning,
    WebCachePoisoning { header: String },
    SsrfViaHost { canary: String },
}

impl std::fmt::Display for HostInjectionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HostReflectedInBody { .. } => write!(f, "host_reflected_in_body"),
            Self::HostReflectedInLocation { .. } => write!(f, "host_reflected_in_location"),
            Self::XForwardedHostReflected { .. } => write!(f, "x_forwarded_host_reflected"),
            Self::XForwardedForAccepted => write!(f, "x_forwarded_for_accepted"),
            Self::AbsoluteUrlAccepted => write!(f, "absolute_url_accepted"),
            Self::PortInjection { .. } => write!(f, "port_injection"),
            Self::DuplicateHostHeader => write!(f, "duplicate_host_header"),
            Self::HostHeaderCachePoisoning => write!(f, "host_header_cache_poisoning"),
            Self::PasswordResetPoisoning => write!(f, "password_reset_poisoning"),
            Self::WebCachePoisoning { .. } => write!(f, "web_cache_poisoning"),
            Self::SsrfViaHost { .. } => write!(f, "ssrf_via_host"),
        }
    }
}

pub fn host_injection_severity(issue: &HostInjectionIssue) -> f64 {
    match issue {
        HostInjectionIssue::PasswordResetPoisoning => 9.0,
        HostInjectionIssue::SsrfViaHost { .. } => 8.5,
        HostInjectionIssue::HostHeaderCachePoisoning => 8.0,
        HostInjectionIssue::WebCachePoisoning { .. } => 7.5,
        HostInjectionIssue::HostReflectedInLocation { .. } => 7.0,
        HostInjectionIssue::XForwardedHostReflected { .. } => 6.5,
        HostInjectionIssue::AbsoluteUrlAccepted => 6.0,
        HostInjectionIssue::DuplicateHostHeader => 5.5,
        HostInjectionIssue::HostReflectedInBody { .. } => 5.0,
        HostInjectionIssue::PortInjection { .. } => 4.5,
        HostInjectionIssue::XForwardedForAccepted => 4.0,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn analyze_host_injection(
    host_response_status: u16,
    host_response_location: Option<&str>,
    host_response_body: &str,
    xfh_response_location: Option<&str>,
    xfh_response_body: &str,
    xff_accepted: bool,
    absolute_url_status: Option<u16>,
    port_response_location: Option<&str>,
    canary: &str,
) -> Vec<HostInjectionIssue> {
    let mut issues = Vec::new();

    if let Some(loc) = host_response_location
        && loc.contains(canary)
    {
        issues.push(HostInjectionIssue::HostReflectedInLocation {
            canary: canary.to_string(),
        });
    }

    if host_response_body.contains(canary) {
        issues.push(HostInjectionIssue::HostReflectedInBody {
            canary: canary.to_string(),
        });
    }

    if let Some(loc) = xfh_response_location
        && loc.contains(canary)
    {
        issues.push(HostInjectionIssue::XForwardedHostReflected {
            canary: canary.to_string(),
        });
    }
    if xfh_response_body.contains(canary)
        && !issues
            .iter()
            .any(|i| matches!(i, HostInjectionIssue::XForwardedHostReflected { .. }))
    {
        issues.push(HostInjectionIssue::XForwardedHostReflected {
            canary: canary.to_string(),
        });
    }

    if xff_accepted {
        issues.push(HostInjectionIssue::XForwardedForAccepted);
    }

    if let Some(status) = absolute_url_status
        && (200..400).contains(&status)
    {
        issues.push(HostInjectionIssue::AbsoluteUrlAccepted);
    }

    if let Some(loc) = port_response_location
        && (loc.contains(":1337") || loc.contains(canary))
    {
        issues.push(HostInjectionIssue::PortInjection {
            port: "1337".to_string(),
        });
    }

    // Cache poisoning: if body reflects canary AND response was cacheable (200)
    if host_response_status == 200 && host_response_body.contains(canary) {
        issues.push(HostInjectionIssue::HostHeaderCachePoisoning);
    }

    // Password reset: if location reflects canary (redirect to attacker)
    if let Some(loc) = host_response_location
        && loc.contains(canary)
        && (300..400).contains(&host_response_status)
    {
        issues.push(HostInjectionIssue::PasswordResetPoisoning);
    }

    issues
}

pub fn host_injection_to_operations(
    issues: &[HostInjectionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                host_injection_severity(issue),
                0.5,
            )
        })
        .collect()
}
