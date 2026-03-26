use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Maximum depth when tracing redirect chains for open-redirect-based token leakage.
const MAX_REDIRECT_CHAIN_DEPTH: usize = 10;

/// Severity floor for implicit flow findings regardless of other factors.
const IMPLICIT_FLOW_SEVERITY_FLOOR: f64 = 7.0;

/// Weight applied to each third-party script domain found loading alongside token handling.
const THIRD_PARTY_SCRIPT_WEIGHT: f64 = 0.8;

// ─── Enums ──────────────────────────────────────────────────────────────────

/// The mechanism through which an OAuth token leaks to an unintended party.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LeakageVector {
    UrlFragment,
    RefererExposure,
    BrowserHistory,
    PostMessageLeak,
    CacheExposure,
    ImplicitFlow,
    OpenRedirectChain,
    MixedContent,
    ThirdPartyScript,
}

impl fmt::Display for LeakageVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::UrlFragment => "url-fragment-leakage",
            Self::RefererExposure => "referer-header-exposure",
            Self::BrowserHistory => "browser-history-exposure",
            Self::PostMessageLeak => "postmessage-wrong-origin",
            Self::CacheExposure => "cache-control-exposure",
            Self::ImplicitFlow => "implicit-flow-detected",
            Self::OpenRedirectChain => "open-redirect-chain",
            Self::MixedContent => "mixed-content-token-leak",
            Self::ThirdPartyScript => "third-party-script-exfil",
        };
        write!(f, "{label}")
    }
}

/// OAuth 2.x grant flow type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OAuthFlowType {
    AuthorizationCode,
    Implicit,
    ClientCredentials,
    DeviceCode,
    Pkce,
}

impl fmt::Display for OAuthFlowType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::AuthorizationCode => "authorization_code",
            Self::Implicit => "implicit",
            Self::ClientCredentials => "client_credentials",
            Self::DeviceCode => "device_code",
            Self::Pkce => "authorization_code+pkce",
        };
        write!(f, "{label}")
    }
}

/// Where in the HTTP exchange a token was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenLocation {
    Fragment,
    Query,
    Header,
    Body,
    Cookie,
}

impl fmt::Display for TokenLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Fragment => "url-fragment",
            Self::Query => "url-query",
            Self::Header => "http-header",
            Self::Body => "response-body",
            Self::Cookie => "cookie",
        };
        write!(f, "{label}")
    }
}

// ─── Core Structs ───────────────────────────────────────────────────────────

/// A single token leakage finding with remediation guidance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakageFinding {
    pub vector: LeakageVector,
    pub severity: f64,
    pub flow_type: OAuthFlowType,
    pub token_location: TokenLocation,
    pub description: String,
    pub remediation: String,
    pub evidence: Vec<String>,
}

/// Metadata describing an OAuth endpoint's configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthEndpointInfo {
    pub authorization_url: String,
    pub token_url: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub flow_type: OAuthFlowType,
}

impl Default for OAuthEndpointInfo {
    fn default() -> Self {
        Self {
            authorization_url: "/oauth/authorize".to_string(),
            token_url: "/oauth/token".to_string(),
            redirect_uris: vec!["https://app.example.com/callback".to_string()],
            scopes: vec!["openid".to_string(), "profile".to_string()],
            flow_type: OAuthFlowType::AuthorizationCode,
        }
    }
}

/// Toggles controlling which leakage vectors to scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakageScanConfig {
    pub check_referer: bool,
    pub check_cache: bool,
    pub check_postmessage: bool,
    pub check_third_party: bool,
    pub max_redirect_depth: usize,
}

impl Default for LeakageScanConfig {
    fn default() -> Self {
        Self {
            check_referer: true,
            check_cache: true,
            check_postmessage: true,
            check_third_party: true,
            max_redirect_depth: MAX_REDIRECT_CHAIN_DEPTH,
        }
    }
}

/// Observed HTTP response headers relevant to token caching behavior.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseHeaders {
    pub cache_control: Option<String>,
    pub pragma: Option<String>,
    pub referrer_policy: Option<String>,
    pub content_security_policy: Option<String>,
    pub strict_transport_security: Option<String>,
}

/// A single hop in a redirect chain with its response metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectHop {
    pub url: String,
    pub status_code: u16,
    pub location_header: Option<String>,
    pub is_https: bool,
}

/// Configuration of a postMessage listener observed on a page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMessageConfig {
    pub target_origin: String,
    pub validates_origin: bool,
    pub message_contains_token: bool,
}

/// Snapshot of the page context surrounding an OAuth callback.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PageContext {
    pub response_headers: ResponseHeaders,
    pub redirect_chain: Vec<RedirectHop>,
    pub postmessage_configs: Vec<PostMessageConfig>,
    pub third_party_scripts: Vec<String>,
    pub is_https: bool,
    pub external_resource_domains: Vec<String>,
}

// ─── Detector ───────────────────────────────────────────────────────────────

/// Detects token leakage vectors on OAuth endpoints.
///
/// Operates as a pure analysis engine over supplied metadata —
/// it does not make network requests itself. The caller populates
/// `OAuthEndpointInfo` and `PageContext`, then invokes `scan_all_vectors`
/// or individual `check_*` methods.
#[derive(Debug, Clone)]
pub struct OAuthLeakageDetector {
    pub config: LeakageScanConfig,
    pub endpoint_info: OAuthEndpointInfo,
    pub page_context: PageContext,
}

impl OAuthLeakageDetector {
    pub fn new(
        config: LeakageScanConfig,
        endpoint_info: OAuthEndpointInfo,
        page_context: PageContext,
    ) -> Self {
        Self {
            config,
            endpoint_info,
            page_context,
        }
    }

    /// Returns true when the endpoint is configured for the OAuth 2.0 implicit flow
    /// (response_type=token), which places access tokens directly in the URL fragment.
    pub fn detect_implicit_flow(&self) -> Option<LeakageFinding> {
        if self.endpoint_info.flow_type != OAuthFlowType::Implicit {
            return None;
        }
        Some(LeakageFinding {
            vector: LeakageVector::ImplicitFlow,
            severity: IMPLICIT_FLOW_SEVERITY_FLOOR,
            flow_type: OAuthFlowType::Implicit,
            token_location: TokenLocation::Fragment,
            description: "Implicit flow returns access_token in URL fragment \
                          — deprecated by OAuth 2.1 due to token exposure risk"
                .to_string(),
            remediation: "Migrate to authorization code flow with PKCE \
                          (RFC 7636) for public clients"
                .to_string(),
            evidence: vec![
                format!(
                    "authorization_url: {}",
                    self.endpoint_info.authorization_url
                ),
                "response_type=token detected".to_string(),
            ],
        })
    }

    /// Checks whether access_token or code appears in a URL query string
    /// rather than in the fragment or POST body.
    pub fn check_token_in_url(&self) -> Vec<LeakageFinding> {
        let mut findings = Vec::new();
        for uri in &self.endpoint_info.redirect_uris {
            if contains_token_in_query(uri) {
                findings.push(LeakageFinding {
                    vector: LeakageVector::UrlFragment,
                    severity: 8.5,
                    flow_type: self.endpoint_info.flow_type,
                    token_location: TokenLocation::Query,
                    description: format!(
                        "Token material present in query string of redirect URI: {uri}"
                    ),
                    remediation: "Deliver tokens via POST body or fragment only — \
                                  never in query parameters (logged by proxies, servers, CDNs)"
                        .to_string(),
                    evidence: vec![format!("redirect_uri: {uri}")],
                });
            }
        }
        findings
    }

    /// Determines whether the Referer / Referrer-Policy headers would leak
    /// tokens to third-party resources loaded on the callback page.
    pub fn check_referer_leakage(&self) -> Vec<LeakageFinding> {
        if !self.config.check_referer {
            return Vec::new();
        }
        let policy = self
            .page_context
            .response_headers
            .referrer_policy
            .as_deref()
            .unwrap_or("no-referrer-policy-set");

        let leaks_referer = matches!(
            policy,
            "no-referrer-policy-set" | "unsafe-url" | "no-referrer-when-downgrade"
        );
        if !leaks_referer {
            return Vec::new();
        }
        let mut findings = Vec::new();
        let external_count = self.page_context.external_resource_domains.len();
        if external_count > 0 {
            findings.push(LeakageFinding {
                vector: LeakageVector::RefererExposure,
                severity: severity_for_referer(external_count),
                flow_type: self.endpoint_info.flow_type,
                token_location: TokenLocation::Fragment,
                description: format!(
                    "Referrer-Policy '{policy}' leaks callback URL \
                     (including fragment) to {external_count} external domain(s)"
                ),
                remediation: "Set Referrer-Policy: no-referrer on the callback page \
                              and avoid loading external resources before stripping tokens"
                    .to_string(),
                evidence: self.page_context.external_resource_domains.clone(),
            });
        }
        findings
    }

    /// Inspects Cache-Control and Pragma headers on responses that carry tokens.
    pub fn check_cache_headers(&self) -> Vec<LeakageFinding> {
        if !self.config.check_cache {
            return Vec::new();
        }
        let headers = &self.page_context.response_headers;
        if headers.cache_control.is_none() && headers.pragma.is_none() {
            return Vec::new();
        }
        let cc = headers.cache_control.as_deref().unwrap_or("");
        let pragma = headers.pragma.as_deref().unwrap_or("");

        let is_public = cc.contains("public");
        let missing_no_store = !cc.contains("no-store");
        let missing_pragma_no_cache = !pragma.contains("no-cache");

        if !is_public && !missing_no_store {
            return Vec::new();
        }
        let mut evidence = Vec::new();
        let severity;
        if is_public {
            evidence.push(format!("Cache-Control: {cc}"));
            severity = 7.5;
        } else if missing_no_store && missing_pragma_no_cache {
            evidence.push("Cache-Control missing no-store directive".to_string());
            evidence.push("Pragma missing no-cache directive".to_string());
            severity = 5.0;
        } else {
            severity = 3.5;
            evidence.push(format!("Cache-Control: {cc}"));
        }
        vec![LeakageFinding {
            vector: LeakageVector::CacheExposure,
            severity,
            flow_type: self.endpoint_info.flow_type,
            token_location: TokenLocation::Header,
            description: "Token-bearing response may be stored in shared/proxy caches".to_string(),
            remediation: "Set Cache-Control: no-store, no-cache, private and Pragma: no-cache \
                          on all token-bearing responses"
                .to_string(),
            evidence,
        }]
    }

    /// Analyzes postMessage listeners on the callback page for missing
    /// origin validation or wildcard target origins.
    pub fn check_postmessage_config(&self) -> Vec<LeakageFinding> {
        if !self.config.check_postmessage {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for pm in &self.page_context.postmessage_configs {
            if !pm.message_contains_token {
                continue;
            }
            let is_wildcard = pm.target_origin == "*";
            let missing_validation = !pm.validates_origin;
            if is_wildcard || missing_validation {
                let severity = if is_wildcard { 9.0 } else { 7.0 };
                findings.push(LeakageFinding {
                    vector: LeakageVector::PostMessageLeak,
                    severity,
                    flow_type: self.endpoint_info.flow_type,
                    token_location: TokenLocation::Body,
                    description: format!(
                        "postMessage sends token to origin '{}' \
                         (validates_origin={})",
                        pm.target_origin, pm.validates_origin
                    ),
                    remediation: "Restrict postMessage targetOrigin to the exact parent \
                                  origin and validate event.origin in the receiver"
                        .to_string(),
                    evidence: vec![
                        format!("target_origin: {}", pm.target_origin),
                        format!("validates_origin: {}", pm.validates_origin),
                    ],
                });
            }
        }
        findings
    }

    /// Walks the redirect chain looking for HTTPS→HTTP downgrades
    /// and open-redirect hops that could expose tokens to intermediaries.
    pub fn analyze_redirect_chain(&self) -> Vec<LeakageFinding> {
        let chain = &self.page_context.redirect_chain;
        let max_depth = self.config.max_redirect_depth.min(MAX_REDIRECT_CHAIN_DEPTH);
        let mut findings = Vec::new();

        for (idx, hop) in chain.iter().enumerate() {
            if idx >= max_depth {
                break;
            }
            if !hop.is_https {
                findings.push(build_mixed_content_finding(&self.endpoint_info, hop, idx));
            }
            if idx > 0 && is_open_redirect_hop(hop) {
                findings.push(build_open_redirect_finding(&self.endpoint_info, hop, idx));
            }
        }
        findings
    }

    /// Detects third-party JavaScript loaded on the callback page that
    /// could read the URL fragment containing tokens.
    fn check_third_party_scripts(&self) -> Vec<LeakageFinding> {
        if !self.config.check_third_party {
            return Vec::new();
        }
        if self.page_context.third_party_scripts.is_empty() {
            return Vec::new();
        }
        let domains: Vec<String> = self
            .page_context
            .third_party_scripts
            .iter()
            .filter_map(|s| extract_script_domain(s))
            .collect();

        if domains.is_empty() {
            return Vec::new();
        }
        let severity = (THIRD_PARTY_SCRIPT_WEIGHT * domains.len() as f64 + 4.0).min(9.5);
        vec![LeakageFinding {
            vector: LeakageVector::ThirdPartyScript,
            severity,
            flow_type: self.endpoint_info.flow_type,
            token_location: TokenLocation::Fragment,
            description: format!(
                "{} third-party script domain(s) can read window.location.hash on callback page",
                domains.len()
            ),
            remediation: "Remove third-party scripts from callback/redirect pages \
                          or strip the fragment before any external code executes"
                .to_string(),
            evidence: domains,
        }]
    }

    /// Checks for browser-history exposure when tokens ride in the URL
    /// rather than ephemeral channels.
    fn check_browser_history(&self) -> Vec<LeakageFinding> {
        let exposed = self.endpoint_info.flow_type == OAuthFlowType::Implicit
            || self
                .endpoint_info
                .redirect_uris
                .iter()
                .any(|u| contains_token_in_query(u));
        if !exposed {
            return Vec::new();
        }
        vec![LeakageFinding {
            vector: LeakageVector::BrowserHistory,
            severity: 4.5,
            flow_type: self.endpoint_info.flow_type,
            token_location: if self.endpoint_info.flow_type == OAuthFlowType::Implicit {
                TokenLocation::Fragment
            } else {
                TokenLocation::Query
            },
            description: "Token-bearing URL persists in browser history / autocomplete \
                          — accessible to later users of the same device"
                .to_string(),
            remediation: "Replace token in URL with a short-lived authorization code \
                          exchanged server-side; use replaceState to strip fragments immediately"
                .to_string(),
            evidence: vec![format!("flow_type: {}", self.endpoint_info.flow_type)],
        }]
    }

    /// Runs every enabled check and returns the union of all findings.
    pub fn scan_all_vectors(&self) -> Vec<LeakageFinding> {
        let mut findings = Vec::new();
        if let Some(f) = self.detect_implicit_flow() {
            findings.push(f);
        }
        findings.extend(self.check_token_in_url());
        findings.extend(self.check_referer_leakage());
        findings.extend(self.check_cache_headers());
        findings.extend(self.check_postmessage_config());
        findings.extend(self.analyze_redirect_chain());
        findings.extend(self.check_third_party_scripts());
        findings.extend(self.check_browser_history());
        findings
    }

    /// Produces a severity-sorted, deduplicated report from a raw finding set.
    pub fn generate_findings(&self) -> LeakageReport {
        let mut findings = self.scan_all_vectors();
        findings.sort_by(|a, b| {
            b.severity
                .partial_cmp(&a.severity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let vector_counts = count_vectors(&findings);
        let max_severity = findings.first().map(|f| f.severity).unwrap_or(0.0);
        let total = findings.len();

        LeakageReport {
            findings,
            vector_counts,
            max_severity,
            total_findings: total,
        }
    }
}

// ─── Report ─────────────────────────────────────────────────────────────────

/// Aggregated leakage scan results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakageReport {
    pub findings: Vec<LeakageFinding>,
    pub vector_counts: HashMap<String, usize>,
    pub max_severity: f64,
    pub total_findings: usize,
}

// ─── Severity Helpers ───────────────────────────────────────────────────────

/// Base severity per vector type (CVSS-adjacent 0-10 scale).
pub fn base_severity_for_vector(vector: LeakageVector) -> f64 {
    match vector {
        LeakageVector::PostMessageLeak => 9.0,
        LeakageVector::UrlFragment => 8.5,
        LeakageVector::OpenRedirectChain => 8.0,
        LeakageVector::MixedContent => 7.5,
        LeakageVector::ImplicitFlow => 7.0,
        LeakageVector::RefererExposure => 6.5,
        LeakageVector::ThirdPartyScript => 6.0,
        LeakageVector::CacheExposure => 5.0,
        LeakageVector::BrowserHistory => 4.5,
    }
}

fn severity_for_referer(external_domain_count: usize) -> f64 {
    let base = base_severity_for_vector(LeakageVector::RefererExposure);
    (base + 0.5 * external_domain_count as f64).min(9.5)
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn contains_token_in_query(uri: &str) -> bool {
    let query = match uri.find('?') {
        Some(idx) => &uri[idx + 1..],
        None => return false,
    };
    let fragment_end = query.find('#').unwrap_or(query.len());
    let query_only = &query[..fragment_end];
    query_only.split('&').any(|pair| {
        let key = pair.split('=').next().unwrap_or("");
        matches!(
            key,
            "access_token" | "token" | "code" | "id_token" | "refresh_token"
        )
    })
}

fn is_open_redirect_hop(hop: &RedirectHop) -> bool {
    if let Some(loc) = &hop.location_header {
        let trimmed = loc.trim();
        let starts_external = trimmed.starts_with("http://") || trimmed.starts_with("https://");
        let has_param_redirect = trimmed.contains("redirect=")
            || trimmed.contains("next=")
            || trimmed.contains("url=")
            || trimmed.contains("return_to=");
        starts_external || has_param_redirect
    } else {
        false
    }
}

fn build_mixed_content_finding(
    info: &OAuthEndpointInfo,
    hop: &RedirectHop,
    hop_index: usize,
) -> LeakageFinding {
    LeakageFinding {
        vector: LeakageVector::MixedContent,
        severity: 7.5,
        flow_type: info.flow_type,
        token_location: TokenLocation::Header,
        description: format!(
            "Redirect hop #{} downgrades to HTTP ({}) — \
             token may transit in cleartext",
            hop_index, hop.url
        ),
        remediation: "Enforce HTTPS across the entire redirect chain; \
                      set HSTS with includeSubDomains"
            .to_string(),
        evidence: vec![
            format!("hop_index: {hop_index}"),
            format!("url: {}", hop.url),
            format!("status: {}", hop.status_code),
        ],
    }
}

fn build_open_redirect_finding(
    info: &OAuthEndpointInfo,
    hop: &RedirectHop,
    hop_index: usize,
) -> LeakageFinding {
    LeakageFinding {
        vector: LeakageVector::OpenRedirectChain,
        severity: 8.0,
        flow_type: info.flow_type,
        token_location: TokenLocation::Header,
        description: format!(
            "Redirect hop #{} appears to be an open redirect ({}) — \
             token in Referer or query leaked to arbitrary destination",
            hop_index, hop.url
        ),
        remediation: "Validate all redirect destinations server-side against \
                      an allowlist; do not pass tokens through redirects"
            .to_string(),
        evidence: vec![
            format!("hop_index: {hop_index}"),
            format!("url: {}", hop.url),
            format!(
                "location: {}",
                hop.location_header.as_deref().unwrap_or("(none)")
            ),
        ],
    }
}

fn extract_script_domain(src: &str) -> Option<String> {
    let trimmed = src.trim();
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .or_else(|| trimmed.strip_prefix("//"))?;
    let domain = without_scheme.split('/').next()?;
    if domain.is_empty() {
        return None;
    }
    Some(domain.to_string())
}

fn count_vectors(findings: &[LeakageFinding]) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    for f in findings {
        *map.entry(f.vector.to_string()).or_insert(0) += 1;
    }
    map
}
