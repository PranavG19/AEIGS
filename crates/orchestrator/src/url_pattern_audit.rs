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

#[derive(Debug, Clone, PartialEq)]
pub enum UrlPatternSecurityIssue {
    WildcardUrlPattern,
    UrlPatternRedoS,
    PathParameterInjection,
    UrlPatternBypass,
    MissingPathNormalization,
    UrlPatternCrossOrigin,
    SensitivePathExposed,
    UrlPatternOverlap,
    UrlPatternWithoutAuth,
    UrlPatternWildcardSubdomain,
}

impl std::fmt::Display for UrlPatternSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WildcardUrlPattern => write!(f, "wildcard_url_pattern"),
            Self::UrlPatternRedoS => write!(f, "url_pattern_redos"),
            Self::PathParameterInjection => write!(f, "path_parameter_injection"),
            Self::UrlPatternBypass => write!(f, "url_pattern_bypass"),
            Self::MissingPathNormalization => write!(f, "missing_path_normalization"),
            Self::UrlPatternCrossOrigin => write!(f, "url_pattern_cross_origin"),
            Self::SensitivePathExposed => write!(f, "sensitive_path_exposed"),
            Self::UrlPatternOverlap => write!(f, "url_pattern_overlap"),
            Self::UrlPatternWithoutAuth => write!(f, "url_pattern_without_auth"),
            Self::UrlPatternWildcardSubdomain => write!(f, "url_pattern_wildcard_subdomain"),
        }
    }
}

pub fn analyze_url_pattern_security(body: &str) -> Vec<UrlPatternSecurityIssue> {
    let mut issues = Vec::new();

    if !body.contains("URLPattern") && !body.contains("urlPattern") {
        return issues;
    }

    // WildcardUrlPattern - overly permissive patterns
    if (body.contains("pathname: '*'") || body.contains("pathname:'*'"))
        || (body.contains("search: '*'") || body.contains("search:'*'"))
        || (body.contains("hash: '*'") || body.contains("hash:'*'"))
    {
        issues.push(UrlPatternSecurityIssue::WildcardUrlPattern);
    }

    // UrlPatternRedoS - catastrophic backtracking patterns
    if (body.contains("(.*)*") || body.contains("(.+)+") || body.contains("(a*)*"))
        && (body.contains("URLPattern") || body.contains("pathname") || body.contains("search"))
    {
        issues.push(UrlPatternSecurityIssue::UrlPatternRedoS);
    }

    // PathParameterInjection - unvalidated path parameters
    if (body.contains(":id") || body.contains(":userId") || body.contains(":path"))
        && !body.contains("validate")
        && !body.contains("sanitize")
        && (body.contains("URLPattern") || body.contains("pathname"))
    {
        issues.push(UrlPatternSecurityIssue::PathParameterInjection);
    }

    // UrlPatternBypass - encoding-based bypasses
    if (body.contains("%2e%2e") || body.contains("..%2f") || body.contains("%00"))
        && (body.contains("test(") || body.contains("exec(") || body.contains("match("))
        && (body.contains("URLPattern") || body.contains("pattern"))
    {
        issues.push(UrlPatternSecurityIssue::UrlPatternBypass);
    }

    // MissingPathNormalization - patterns without normalization
    if (body.contains("/../") || body.contains("/./") || body.contains("//"))
        && (body.contains("URLPattern") || body.contains("pathname"))
        && !body.contains("normalize")
        && !body.contains("resolve")
    {
        issues.push(UrlPatternSecurityIssue::MissingPathNormalization);
    }

    // UrlPatternCrossOrigin - patterns matching external origins
    if (body.contains("protocol: '*'") || body.contains("protocol:'*'"))
        || (body.contains("hostname: '*'") || body.contains("hostname:'*'"))
        || (body.contains("origin: '*'") || body.contains("origin:'*'"))
    {
        issues.push(UrlPatternSecurityIssue::UrlPatternCrossOrigin);
    }

    // SensitivePathExposed - internal API structure revealed
    if (body.contains("/internal/") || body.contains("/api/v1/") || body.contains("/admin/"))
        && (body.contains("URLPattern") || body.contains("pathname"))
        && (body.contains("debug") || body.contains("config") || body.contains("secret"))
    {
        issues.push(UrlPatternSecurityIssue::SensitivePathExposed);
    }

    // UrlPatternOverlap - conflicting patterns
    if body.matches("URLPattern").count() > 1
        && (body.contains("/:id")
            || body.contains("/*")
            || body.contains("/:path*")
            || body.contains("/:slug"))
    {
        issues.push(UrlPatternSecurityIssue::UrlPatternOverlap);
    }

    // UrlPatternWithoutAuth - admin patterns without auth checks
    if (body.contains("/admin") || body.contains("/privileged") || body.contains("/private"))
        && (body.contains("URLPattern") || body.contains("pathname"))
        && !body.contains("authenticate")
        && !body.contains("authorize")
        && !body.contains("checkAuth")
        && !body.contains("requireAuth")
    {
        issues.push(UrlPatternSecurityIssue::UrlPatternWithoutAuth);
    }

    // UrlPatternWildcardSubdomain - wildcard subdomain matching
    if (body.contains("hostname: '*.") || body.contains("hostname:'*."))
        || (body.contains("subdomain: '*'") || body.contains("subdomain:'*'"))
    {
        issues.push(UrlPatternSecurityIssue::UrlPatternWildcardSubdomain);
    }

    issues
}

pub fn url_pattern_security_severity(issue: &UrlPatternSecurityIssue) -> f64 {
    match issue {
        UrlPatternSecurityIssue::WildcardUrlPattern => 6.5,
        UrlPatternSecurityIssue::UrlPatternRedoS => 8.5,
        UrlPatternSecurityIssue::PathParameterInjection => 7.5,
        UrlPatternSecurityIssue::UrlPatternBypass => 8.0,
        UrlPatternSecurityIssue::MissingPathNormalization => 7.0,
        UrlPatternSecurityIssue::UrlPatternCrossOrigin => 7.5,
        UrlPatternSecurityIssue::SensitivePathExposed => 6.0,
        UrlPatternSecurityIssue::UrlPatternOverlap => 5.5,
        UrlPatternSecurityIssue::UrlPatternWithoutAuth => 9.0,
        UrlPatternSecurityIssue::UrlPatternWildcardSubdomain => 6.5,
    }
}

pub fn url_pattern_security_to_operations(
    issues: &[UrlPatternSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                url_pattern_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
