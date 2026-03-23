use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum UrlPatternIssue {
    ApiDetected,
    RedosRisk,
    RoutingBypass,
    OpenRedirect,
    PatternInjection,
}

impl std::fmt::Display for UrlPatternIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::RedosRisk => write!(f, "redos_risk"),
            Self::RoutingBypass => write!(f, "routing_bypass"),
            Self::OpenRedirect => write!(f, "open_redirect"),
            Self::PatternInjection => write!(f, "pattern_injection"),
        }
    }
}

pub fn audit_url_pattern(target: &str) -> Vec<UrlPatternIssue> {
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
    analyze_url_pattern(&body)
}

pub fn analyze_url_pattern(body: &str) -> Vec<UrlPatternIssue> {
    let mut issues = Vec::new();

    if body.contains("URLPattern") || body.contains("urlPattern") || body.contains("new URLPattern")
    {
        issues.push(UrlPatternIssue::ApiDetected);

        if (body.contains("*") || body.contains("+") || body.contains("{") || body.contains("}"))
            && (body.contains("pathname") || body.contains("search") || body.contains("hash"))
        {
            issues.push(UrlPatternIssue::RedosRisk);
        }

        if (body.contains("test(") || body.contains("exec("))
            && (body.contains("auth")
                || body.contains("admin")
                || body.contains("private")
                || body.contains("secure"))
        {
            issues.push(UrlPatternIssue::RoutingBypass);
        }

        if (body.contains("location")
            || body.contains("redirect")
            || body.contains("window.location"))
            && (body.contains("protocol") || body.contains("hostname") || body.contains("origin"))
        {
            issues.push(UrlPatternIssue::OpenRedirect);
        }

        if (body.contains("URLPattern(") || body.contains("new URLPattern"))
            && (body.contains("input")
                || body.contains("param")
                || body.contains("query")
                || body.contains("user")
                || body.contains("request"))
        {
            issues.push(UrlPatternIssue::PatternInjection);
        }
    }

    issues
}

pub fn url_pattern_severity(issue: &UrlPatternIssue) -> f64 {
    match issue {
        UrlPatternIssue::ApiDetected => 2.0,
        UrlPatternIssue::RedosRisk => 7.5,
        UrlPatternIssue::RoutingBypass => 7.0,
        UrlPatternIssue::OpenRedirect => 6.5,
        UrlPatternIssue::PatternInjection => 6.0,
    }
}

pub fn url_pattern_to_operations(
    issues: &[UrlPatternIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                url_pattern_severity(issue),
                0.5,
            )
        })
        .collect()
}
