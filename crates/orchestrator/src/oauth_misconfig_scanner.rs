use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum OAuthMisconfigIssue {
    ImplicitFlowUsed,
    MissingStateParameter,
    InsecureRedirectUri,
    WildcardRedirectUri,
    OpenRedirectInAuth,
    TokenInQueryString,
    MissingPkce,
    InsecureTokenStorage,
}

impl std::fmt::Display for OAuthMisconfigIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ImplicitFlowUsed => write!(f, "implicit_flow_used"),
            Self::MissingStateParameter => write!(f, "missing_state_parameter"),
            Self::InsecureRedirectUri => write!(f, "insecure_redirect_uri"),
            Self::WildcardRedirectUri => write!(f, "wildcard_redirect_uri"),
            Self::OpenRedirectInAuth => write!(f, "open_redirect_in_auth"),
            Self::TokenInQueryString => write!(f, "token_in_query_string"),
            Self::MissingPkce => write!(f, "missing_pkce"),
            Self::InsecureTokenStorage => write!(f, "insecure_token_storage"),
        }
    }
}

pub fn scan_oauth_misconfig(target: &str) -> Vec<OAuthMisconfigIssue> {
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
    analyze_oauth_misconfig(&body)
}

pub fn analyze_oauth_misconfig(body: &str) -> Vec<OAuthMisconfigIssue> {
    let lower = body.to_ascii_lowercase();
    let mut issues = Vec::new();

    if lower.contains("response_type=token") || lower.contains("response_type=id_token") {
        issues.push(OAuthMisconfigIssue::ImplicitFlowUsed);
    }

    if has_oauth_authorize_url(&lower) && !lower.contains("state=") {
        issues.push(OAuthMisconfigIssue::MissingStateParameter);
    }

    if lower.contains("redirect_uri=http://") || lower.contains("redirect_uri=http%3a%2f%2f") {
        issues.push(OAuthMisconfigIssue::InsecureRedirectUri);
    }

    if lower.contains("redirect_uri") && (lower.contains("*") || lower.contains("%2a")) {
        issues.push(OAuthMisconfigIssue::WildcardRedirectUri);
    }

    if has_oauth_authorize_url(&lower)
        && (lower.contains("redirect") && lower.contains("url="))
        && (lower.contains("javascript:") || lower.contains("data:") || lower.contains("//"))
    {
        issues.push(OAuthMisconfigIssue::OpenRedirectInAuth);
    }

    if lower.contains("access_token=") {
        issues.push(OAuthMisconfigIssue::TokenInQueryString);
    }

    if has_oauth_authorize_url(&lower)
        && lower.contains("response_type=code")
        && !lower.contains("code_challenge")
    {
        issues.push(OAuthMisconfigIssue::MissingPkce);
    }

    if has_insecure_token_storage(&lower) {
        issues.push(OAuthMisconfigIssue::InsecureTokenStorage);
    }

    issues
}

fn has_oauth_authorize_url(lower: &str) -> bool {
    lower.contains("authorize?")
        || lower.contains("oauth/authorize")
        || lower.contains("/auth?")
        || lower.contains("oauth2/auth")
}

fn has_insecure_token_storage(lower: &str) -> bool {
    let has_storage =
        lower.contains("localstorage.setitem") || lower.contains("sessionstorage.setitem");
    let has_token_keyword = lower.contains("token")
        || lower.contains("access_token")
        || lower.contains("id_token")
        || lower.contains("jwt");
    has_storage && has_token_keyword
}

pub fn oauth_misconfig_severity(issue: &OAuthMisconfigIssue) -> f64 {
    match issue {
        OAuthMisconfigIssue::OpenRedirectInAuth => 8.0,
        OAuthMisconfigIssue::ImplicitFlowUsed => 7.5,
        OAuthMisconfigIssue::TokenInQueryString => 7.5,
        OAuthMisconfigIssue::MissingStateParameter => 7.0,
        OAuthMisconfigIssue::WildcardRedirectUri => 7.0,
        OAuthMisconfigIssue::InsecureRedirectUri => 6.5,
        OAuthMisconfigIssue::InsecureTokenStorage => 6.5,
        OAuthMisconfigIssue::MissingPkce => 6.0,
    }
}

pub fn oauth_misconfig_to_operations(
    issues: &[OAuthMisconfigIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                oauth_misconfig_severity(issue),
                0.7,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum OAuthSecurityIssue {
    OAuthEndpointExposed,
    ClientSecretExposed,
    JwksEndpointExposed,
    TokenEndpointCors,
    RefreshTokenInClient,
    IdTokenUnvalidated,
    NonceReuse,
    ScopeOverprivileged,
    ImplicitConsentScreen,
    DiscoveryEndpointExposed,
}

impl std::fmt::Display for OAuthSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OAuthEndpointExposed => write!(f, "oauth_endpoint_exposed"),
            Self::ClientSecretExposed => write!(f, "client_secret_exposed"),
            Self::JwksEndpointExposed => write!(f, "jwks_endpoint_exposed"),
            Self::TokenEndpointCors => write!(f, "token_endpoint_cors"),
            Self::RefreshTokenInClient => write!(f, "refresh_token_in_client"),
            Self::IdTokenUnvalidated => write!(f, "id_token_unvalidated"),
            Self::NonceReuse => write!(f, "nonce_reuse"),
            Self::ScopeOverprivileged => write!(f, "scope_overprivileged"),
            Self::ImplicitConsentScreen => write!(f, "implicit_consent_screen"),
            Self::DiscoveryEndpointExposed => write!(f, "discovery_endpoint_exposed"),
        }
    }
}

pub fn analyze_oauth_security(body: &str) -> Vec<OAuthSecurityIssue> {
    let lower = body.to_ascii_lowercase();
    let mut issues = Vec::new();

    if lower.contains("client_id=") || lower.contains("oauth/authorize") {
        issues.push(OAuthSecurityIssue::OAuthEndpointExposed);
    }

    if lower.contains("client_secret") {
        issues.push(OAuthSecurityIssue::ClientSecretExposed);
    }

    if lower.contains(".well-known/jwks") || lower.contains("jwks_uri") {
        issues.push(OAuthSecurityIssue::JwksEndpointExposed);
    }

    if (lower.contains("/token") || lower.contains("/oauth/token"))
        && lower.contains("access-control-allow-origin")
    {
        issues.push(OAuthSecurityIssue::TokenEndpointCors);
    }

    if lower.contains("refresh_token")
        && (lower.contains("<script") || lower.contains("function ") || lower.contains("=> {"))
    {
        issues.push(OAuthSecurityIssue::RefreshTokenInClient);
    }

    if lower.contains("id_token") && !lower.contains("verify") && !lower.contains("validate") {
        issues.push(OAuthSecurityIssue::IdTokenUnvalidated);
    }

    if lower.contains("nonce=") && has_hardcoded_nonce(&lower) {
        issues.push(OAuthSecurityIssue::NonceReuse);
    }

    if has_overprivileged_scope(&lower) {
        issues.push(OAuthSecurityIssue::ScopeOverprivileged);
    }

    if lower.contains("prompt=none") || lower.contains("consent=auto") {
        issues.push(OAuthSecurityIssue::ImplicitConsentScreen);
    }

    if lower.contains(".well-known/openid-configuration") {
        issues.push(OAuthSecurityIssue::DiscoveryEndpointExposed);
    }

    issues
}

fn has_hardcoded_nonce(lower: &str) -> bool {
    if let Some(idx) = lower.find("nonce=") {
        let rest = &lower[idx + 6..];
        let end = rest
            .find(['&', '"', '\'', ' ', '<', '>'])
            .unwrap_or(rest.len());
        let value = &rest[..end];
        !value.is_empty() && !value.contains("random") && !value.contains("generate")
    } else {
        false
    }
}

fn has_overprivileged_scope(lower: &str) -> bool {
    if let Some(idx) = lower.find("scope=") {
        let rest = &lower[idx + 6..];
        let end = rest.find(['&', '"', '\'', '<', '>']).unwrap_or(rest.len());
        let scope_value = &rest[..end];
        let scope_count = scope_value
            .split([' ', '+', '%'])
            .filter(|s| !s.is_empty())
            .count();
        scope_count >= 5
    } else {
        false
    }
}

pub fn oauth_security_severity(issue: &OAuthSecurityIssue) -> f64 {
    match issue {
        OAuthSecurityIssue::ClientSecretExposed => 9.0,
        OAuthSecurityIssue::RefreshTokenInClient => 7.5,
        OAuthSecurityIssue::IdTokenUnvalidated => 7.0,
        OAuthSecurityIssue::TokenEndpointCors => 6.5,
        OAuthSecurityIssue::NonceReuse => 6.5,
        OAuthSecurityIssue::ImplicitConsentScreen => 6.5,
        OAuthSecurityIssue::ScopeOverprivileged => 6.0,
        OAuthSecurityIssue::JwksEndpointExposed => 5.5,
        OAuthSecurityIssue::OAuthEndpointExposed => 5.0,
        OAuthSecurityIssue::DiscoveryEndpointExposed => 4.5,
    }
}

pub fn oauth_security_to_operations(
    issues: &[OAuthSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::BrokenAuthentication,
                oauth_security_severity(issue),
                0.6,
            )
        })
        .collect()
}

#[cfg(test)]
#[path = "oauth_misconfig_scanner_test.rs"]
mod oauth_misconfig_scanner_test;
