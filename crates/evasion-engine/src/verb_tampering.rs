use std::fmt;

use serde::{Deserialize, Serialize};

/// Category of HTTP verb tampering technique used to probe method-handling weaknesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerbTamperingTechnique {
    /// Switch between standard methods (GET↔POST↔PUT↔DELETE↔PATCH).
    StandardMethodSwitch,
    /// Use X-HTTP-Method-Override and similar headers to override the actual HTTP method.
    MethodOverrideHeader,
    /// Smuggle method via query parameter (`?_method=DELETE`).
    MethodOverrideParam,
    /// TRACE/TRACK methods for Cross-Site Tracing (XST) attacks.
    CrossSiteTracing,
    /// CONNECT method abuse for proxy tunneling.
    ConnectProxyAbuse,
    /// WebDAV methods (PROPFIND, MKCOL, COPY, MOVE, LOCK) on non-WebDAV endpoints.
    WebDavMethodProbe,
    /// HEAD request returns body content (response leakage).
    HeadResponseLeakage,
    /// Auth bypass via method change (admin restricted to POST, try GET/PUT/PATCH).
    MethodAuthBypass,
    /// Case sensitivity probes (get, Get, gEt vs canonical GET).
    CaseSensitivityProbe,
    /// Arbitrary/invented methods to test error handling (FOO, HACK, TEST).
    ArbitraryMethodProbe,
}

impl VerbTamperingTechnique {
    /// All supported verb tampering techniques.
    pub fn all() -> &'static [VerbTamperingTechnique] {
        &[
            Self::StandardMethodSwitch,
            Self::MethodOverrideHeader,
            Self::MethodOverrideParam,
            Self::CrossSiteTracing,
            Self::ConnectProxyAbuse,
            Self::WebDavMethodProbe,
            Self::HeadResponseLeakage,
            Self::MethodAuthBypass,
            Self::CaseSensitivityProbe,
            Self::ArbitraryMethodProbe,
        ]
    }

    /// Risk level from 0.0 (informational) to 1.0 (critical).
    pub fn risk_score(&self) -> f64 {
        match self {
            Self::StandardMethodSwitch => 0.5,
            Self::MethodOverrideHeader => 0.7,
            Self::MethodOverrideParam => 0.7,
            Self::CrossSiteTracing => 0.8,
            Self::ConnectProxyAbuse => 0.9,
            Self::WebDavMethodProbe => 0.6,
            Self::HeadResponseLeakage => 0.4,
            Self::MethodAuthBypass => 0.9,
            Self::CaseSensitivityProbe => 0.3,
            Self::ArbitraryMethodProbe => 0.3,
        }
    }
}

impl fmt::Display for VerbTamperingTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::StandardMethodSwitch => "Standard Method Switch",
            Self::MethodOverrideHeader => "Method Override Header",
            Self::MethodOverrideParam => "Method Override Parameter",
            Self::CrossSiteTracing => "Cross-Site Tracing (XST)",
            Self::ConnectProxyAbuse => "CONNECT Proxy Abuse",
            Self::WebDavMethodProbe => "WebDAV Method Probe",
            Self::HeadResponseLeakage => "HEAD Response Leakage",
            Self::MethodAuthBypass => "Method-Based Auth Bypass",
            Self::CaseSensitivityProbe => "Method Case Sensitivity",
            Self::ArbitraryMethodProbe => "Arbitrary Method Probe",
        };
        write!(f, "{label}")
    }
}

/// Standard HTTP methods used in verb switching attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Options,
    Head,
    Trace,
    Track,
    Connect,
}

impl HttpMethod {
    /// Canonical uppercase wire representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Options => "OPTIONS",
            Self::Head => "HEAD",
            Self::Trace => "TRACE",
            Self::Track => "TRACK",
            Self::Connect => "CONNECT",
        }
    }

    /// The seven standard methods commonly seen in REST APIs.
    pub fn standard_rest() -> &'static [HttpMethod] {
        &[
            Self::Get,
            Self::Post,
            Self::Put,
            Self::Delete,
            Self::Patch,
            Self::Options,
            Self::Head,
        ]
    }

    /// Methods that should typically be disabled in production.
    pub fn dangerous() -> &'static [HttpMethod] {
        &[Self::Trace, Self::Track, Self::Connect]
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Header name used to smuggle a different HTTP method past middleware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MethodOverrideHeader {
    XHttpMethodOverride,
    XMethodOverride,
    XHttpMethod,
    OverrideMethod,
}

impl MethodOverrideHeader {
    /// Wire name as sent in the HTTP request.
    pub fn header_name(&self) -> &'static str {
        match self {
            Self::XHttpMethodOverride => "X-HTTP-Method-Override",
            Self::XMethodOverride => "X-Method-Override",
            Self::XHttpMethod => "X-HTTP-Method",
            Self::OverrideMethod => "Override-Method",
        }
    }

    /// All known method override headers.
    pub fn all() -> &'static [MethodOverrideHeader] {
        &[
            Self::XHttpMethodOverride,
            Self::XMethodOverride,
            Self::XHttpMethod,
            Self::OverrideMethod,
        ]
    }
}

impl fmt::Display for MethodOverrideHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.header_name())
    }
}

/// Query/body parameter names used for method override smuggling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MethodOverrideParam {
    Underscore,
    HttpMethod,
    Method,
}

impl MethodOverrideParam {
    /// Parameter name as sent in query string or form body.
    pub fn param_name(&self) -> &'static str {
        match self {
            Self::Underscore => "_method",
            Self::HttpMethod => "http_method",
            Self::Method => "method",
        }
    }

    /// All known method override parameter names.
    pub fn all() -> &'static [MethodOverrideParam] {
        &[Self::Underscore, Self::HttpMethod, Self::Method]
    }
}

impl fmt::Display for MethodOverrideParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.param_name())
    }
}

/// WebDAV-specific methods used to probe for unintended WebDAV exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WebDavMethod {
    Propfind,
    Proppatch,
    Mkcol,
    Copy,
    Move,
    Lock,
    Unlock,
}

impl WebDavMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Propfind => "PROPFIND",
            Self::Proppatch => "PROPPATCH",
            Self::Mkcol => "MKCOL",
            Self::Copy => "COPY",
            Self::Move => "MOVE",
            Self::Lock => "LOCK",
            Self::Unlock => "UNLOCK",
        }
    }

    pub fn all() -> &'static [WebDavMethod] {
        &[
            Self::Propfind,
            Self::Proppatch,
            Self::Mkcol,
            Self::Copy,
            Self::Move,
            Self::Lock,
            Self::Unlock,
        ]
    }
}

impl fmt::Display for WebDavMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Single verb tampering probe to be executed against a target endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerbTamperingProbe {
    pub technique: VerbTamperingTechnique,
    pub method: String,
    pub override_headers: Vec<(String, String)>,
    pub override_params: Vec<(String, String)>,
    pub description: String,
}

/// Outcome of a verb tampering probe execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TamperingOutcome {
    /// Method was accepted and returned a success status.
    Accepted { status_code: u16 },
    /// Server rejected the method with an expected error.
    Rejected { status_code: u16 },
    /// Response indicates the override header was honored.
    OverrideHonored {
        effective_method: String,
        status_code: u16,
    },
    /// HEAD response contained body content (leakage).
    HeadBodyLeakage { body_length: usize },
    /// TRACE/TRACK echoed the request back (XST vulnerable).
    TraceEchoed { echoed_headers: bool },
    /// Method-based auth bypass succeeded (restricted endpoint accessible).
    AuthBypassed {
        original_method: String,
        bypass_method: String,
        status_code: u16,
    },
    /// Server error indicating poor method handling.
    ServerError { status_code: u16 },
}

impl TamperingOutcome {
    /// Whether this outcome represents a confirmed vulnerability.
    pub fn is_vulnerable(&self) -> bool {
        matches!(
            self,
            Self::OverrideHonored { .. }
                | Self::HeadBodyLeakage { .. }
                | Self::TraceEchoed {
                    echoed_headers: true
                }
                | Self::AuthBypassed { .. }
        )
    }

    /// Whether this outcome indicates a potential finding worth investigating.
    pub fn is_interesting(&self) -> bool {
        match self {
            Self::Accepted { status_code } => *status_code < 400,
            Self::ServerError { .. } => true,
            other => other.is_vulnerable(),
        }
    }
}

impl fmt::Display for TamperingOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted { status_code } => write!(f, "Method accepted (HTTP {status_code})"),
            Self::Rejected { status_code } => write!(f, "Method rejected (HTTP {status_code})"),
            Self::OverrideHonored {
                effective_method,
                status_code,
            } => {
                write!(
                    f,
                    "Override honored as {effective_method} (HTTP {status_code})"
                )
            }
            Self::HeadBodyLeakage { body_length } => {
                write!(f, "HEAD returned {body_length} bytes of body content")
            }
            Self::TraceEchoed { echoed_headers } => {
                if *echoed_headers {
                    write!(f, "TRACE echoed request headers (XST vulnerable)")
                } else {
                    write!(f, "TRACE responded but did not echo headers")
                }
            }
            Self::AuthBypassed {
                original_method,
                bypass_method,
                status_code,
            } => {
                write!(
                    f,
                    "Auth bypass: {original_method}→{bypass_method} returned HTTP {status_code}"
                )
            }
            Self::ServerError { status_code } => {
                write!(f, "Server error on method probe (HTTP {status_code})")
            }
        }
    }
}

/// Result of analyzing a complete set of verb tampering probes against an endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerbTamperingResult {
    pub endpoint: String,
    pub original_method: String,
    pub findings: Vec<VerbTamperingFinding>,
}

impl VerbTamperingResult {
    /// Findings that represent confirmed vulnerabilities.
    pub fn vulnerabilities(&self) -> Vec<&VerbTamperingFinding> {
        self.findings
            .iter()
            .filter(|f| f.outcome.is_vulnerable())
            .collect()
    }

    /// Highest risk score across all findings, 0.0 if no findings.
    pub fn max_risk(&self) -> f64 {
        self.findings
            .iter()
            .map(|f| f.technique.risk_score())
            .fold(0.0_f64, f64::max)
    }
}

/// Single finding from a verb tampering probe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerbTamperingFinding {
    pub technique: VerbTamperingTechnique,
    pub probe: VerbTamperingProbe,
    pub outcome: TamperingOutcome,
}

/// Generates the full suite of verb tampering probes for a given endpoint.
#[derive(Debug)]
pub struct VerbTamperingEngine {
    case_variants: Vec<String>,
    arbitrary_methods: Vec<String>,
}

impl Default for VerbTamperingEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl VerbTamperingEngine {
    pub fn new() -> Self {
        Self {
            case_variants: vec![
                "get".into(),
                "Get".into(),
                "gEt".into(),
                "GEt".into(),
                "post".into(),
                "Post".into(),
                "pOsT".into(),
                "delete".into(),
                "Delete".into(),
                "put".into(),
                "Put".into(),
                "patch".into(),
                "Patch".into(),
            ],
            arbitrary_methods: vec![
                "FOO".into(),
                "HACK".into(),
                "TEST".into(),
                "BANANA".into(),
                "JEFF".into(),
            ],
        }
    }

    /// Generate all verb tampering probes for the given endpoint method pair.
    pub fn generate_probes(
        &self,
        endpoint: &str,
        original_method: &str,
    ) -> Vec<VerbTamperingProbe> {
        let mut probes = Vec::new();
        probes.extend(self.standard_method_switch_probes(endpoint, original_method));
        probes.extend(self.method_override_header_probes(endpoint, original_method));
        probes.extend(self.method_override_param_probes(endpoint, original_method));
        probes.extend(self.cross_site_tracing_probes(endpoint));
        probes.extend(self.connect_abuse_probes(endpoint));
        probes.extend(self.webdav_probes(endpoint));
        probes.extend(self.head_leakage_probes(endpoint));
        probes.extend(self.case_sensitivity_probes(endpoint));
        probes.extend(self.arbitrary_method_probes(endpoint));
        probes.extend(self.auth_bypass_probes(endpoint, original_method));
        probes
    }

    /// Standard method switching: try every REST method except the original.
    pub fn standard_method_switch_probes(
        &self,
        _endpoint: &str,
        original_method: &str,
    ) -> Vec<VerbTamperingProbe> {
        let original_upper = original_method.to_uppercase();
        HttpMethod::standard_rest()
            .iter()
            .filter(|m| m.as_str() != original_upper)
            .map(|m| VerbTamperingProbe {
                technique: VerbTamperingTechnique::StandardMethodSwitch,
                method: m.as_str().to_string(),
                override_headers: Vec::new(),
                override_params: Vec::new(),
                description: format!(
                    "Switch from {original_upper} to {} to test method handling",
                    m.as_str()
                ),
            })
            .collect()
    }

    /// Method override via headers: send POST with X-HTTP-Method-Override: DELETE etc.
    pub fn method_override_header_probes(
        &self,
        _endpoint: &str,
        original_method: &str,
    ) -> Vec<VerbTamperingProbe> {
        let target_methods = ["GET", "PUT", "DELETE", "PATCH"];
        let mut probes = Vec::new();
        for header in MethodOverrideHeader::all() {
            for target in &target_methods {
                if *target == original_method.to_uppercase() {
                    continue;
                }
                probes.push(VerbTamperingProbe {
                    technique: VerbTamperingTechnique::MethodOverrideHeader,
                    method: "POST".to_string(),
                    override_headers: vec![(
                        header.header_name().to_string(),
                        (*target).to_string(),
                    )],
                    override_params: Vec::new(),
                    description: format!(
                        "POST with {}: {} to override method",
                        header.header_name(),
                        target,
                    ),
                });
            }
        }
        probes
    }

    /// Method override via query/body parameters: ?_method=DELETE etc.
    pub fn method_override_param_probes(
        &self,
        _endpoint: &str,
        original_method: &str,
    ) -> Vec<VerbTamperingProbe> {
        let target_methods = ["GET", "PUT", "DELETE", "PATCH"];
        let mut probes = Vec::new();
        for param in MethodOverrideParam::all() {
            for target in &target_methods {
                if *target == original_method.to_uppercase() {
                    continue;
                }
                probes.push(VerbTamperingProbe {
                    technique: VerbTamperingTechnique::MethodOverrideParam,
                    method: "POST".to_string(),
                    override_headers: Vec::new(),
                    override_params: vec![(param.param_name().to_string(), (*target).to_string())],
                    description: format!(
                        "POST with {}={} query parameter to override method",
                        param.param_name(),
                        target,
                    ),
                });
            }
        }
        probes
    }

    /// TRACE and TRACK method probes for Cross-Site Tracing.
    pub fn cross_site_tracing_probes(&self, _endpoint: &str) -> Vec<VerbTamperingProbe> {
        vec![
            VerbTamperingProbe {
                technique: VerbTamperingTechnique::CrossSiteTracing,
                method: "TRACE".to_string(),
                override_headers: Vec::new(),
                override_params: Vec::new(),
                description: "TRACE method to test for XST (request echo)".to_string(),
            },
            VerbTamperingProbe {
                technique: VerbTamperingTechnique::CrossSiteTracing,
                method: "TRACK".to_string(),
                override_headers: Vec::new(),
                override_params: Vec::new(),
                description: "TRACK method (IIS variant) to test for XST".to_string(),
            },
        ]
    }

    /// CONNECT method abuse for proxy tunneling.
    pub fn connect_abuse_probes(&self, _endpoint: &str) -> Vec<VerbTamperingProbe> {
        vec![VerbTamperingProbe {
            technique: VerbTamperingTechnique::ConnectProxyAbuse,
            method: "CONNECT".to_string(),
            override_headers: Vec::new(),
            override_params: Vec::new(),
            description: "CONNECT method to probe for proxy tunneling support".to_string(),
        }]
    }

    /// WebDAV method probes on non-WebDAV endpoints.
    pub fn webdav_probes(&self, _endpoint: &str) -> Vec<VerbTamperingProbe> {
        WebDavMethod::all()
            .iter()
            .map(|m| VerbTamperingProbe {
                technique: VerbTamperingTechnique::WebDavMethodProbe,
                method: m.as_str().to_string(),
                override_headers: Vec::new(),
                override_params: Vec::new(),
                description: format!("{} method probe for unintended WebDAV exposure", m.as_str()),
            })
            .collect()
    }

    /// HEAD request to detect response body leakage.
    pub fn head_leakage_probes(&self, _endpoint: &str) -> Vec<VerbTamperingProbe> {
        vec![VerbTamperingProbe {
            technique: VerbTamperingTechnique::HeadResponseLeakage,
            method: "HEAD".to_string(),
            override_headers: Vec::new(),
            override_params: Vec::new(),
            description: "HEAD request to check for body content leakage".to_string(),
        }]
    }

    /// Case sensitivity probes: lowercase, mixed-case method names.
    pub fn case_sensitivity_probes(&self, _endpoint: &str) -> Vec<VerbTamperingProbe> {
        self.case_variants
            .iter()
            .map(|variant| VerbTamperingProbe {
                technique: VerbTamperingTechnique::CaseSensitivityProbe,
                method: variant.clone(),
                override_headers: Vec::new(),
                override_params: Vec::new(),
                description: format!("Case variant '{variant}' to test method name normalization"),
            })
            .collect()
    }

    /// Arbitrary/invented method probes for error handling analysis.
    pub fn arbitrary_method_probes(&self, _endpoint: &str) -> Vec<VerbTamperingProbe> {
        self.arbitrary_methods
            .iter()
            .map(|method| VerbTamperingProbe {
                technique: VerbTamperingTechnique::ArbitraryMethodProbe,
                method: method.clone(),
                override_headers: Vec::new(),
                override_params: Vec::new(),
                description: format!("Arbitrary method '{method}' to test unknown method handling"),
            })
            .collect()
    }

    /// Auth bypass probes: if endpoint expects POST, try GET/PUT/PATCH/DELETE.
    pub fn auth_bypass_probes(
        &self,
        _endpoint: &str,
        original_method: &str,
    ) -> Vec<VerbTamperingProbe> {
        let original_upper = original_method.to_uppercase();
        let bypass_methods = ["GET", "POST", "PUT", "PATCH", "DELETE"];
        bypass_methods
            .iter()
            .filter(|m| **m != original_upper)
            .map(|m| VerbTamperingProbe {
                technique: VerbTamperingTechnique::MethodAuthBypass,
                method: m.to_string(),
                override_headers: Vec::new(),
                override_params: Vec::new(),
                description: format!(
                    "Auth bypass: switch from {original_upper} to {m} on restricted endpoint"
                ),
            })
            .collect()
    }
}

/// Classify a raw HTTP response into a `TamperingOutcome` for a given probe.
pub fn classify_response(
    probe: &VerbTamperingProbe,
    status_code: u16,
    body: &str,
    response_headers: &[(String, String)],
) -> TamperingOutcome {
    match probe.technique {
        VerbTamperingTechnique::CrossSiteTracing => {
            let echoed = body.contains("TRACE") || body.contains("TRACK");
            let echoed_headers =
                response_headers.iter().any(|(_, v)| v.contains("TRACE")) || echoed;
            if status_code == 200 && echoed_headers {
                TamperingOutcome::TraceEchoed {
                    echoed_headers: true,
                }
            } else if status_code == 200 {
                TamperingOutcome::TraceEchoed {
                    echoed_headers: false,
                }
            } else {
                TamperingOutcome::Rejected { status_code }
            }
        }
        VerbTamperingTechnique::HeadResponseLeakage => {
            if !body.is_empty() {
                TamperingOutcome::HeadBodyLeakage {
                    body_length: body.len(),
                }
            } else if status_code < 400 {
                TamperingOutcome::Accepted { status_code }
            } else {
                TamperingOutcome::Rejected { status_code }
            }
        }
        VerbTamperingTechnique::MethodOverrideHeader
        | VerbTamperingTechnique::MethodOverrideParam => {
            let intended_method = probe
                .override_headers
                .first()
                .map(|(_, v)| v.as_str())
                .or_else(|| probe.override_params.first().map(|(_, v)| v.as_str()))
                .unwrap_or("UNKNOWN");
            if status_code < 400 {
                TamperingOutcome::OverrideHonored {
                    effective_method: intended_method.to_string(),
                    status_code,
                }
            } else {
                TamperingOutcome::Rejected { status_code }
            }
        }
        VerbTamperingTechnique::MethodAuthBypass => {
            if status_code < 400 {
                let bypass_method = probe.method.clone();
                let original = probe
                    .description
                    .split("from ")
                    .nth(1)
                    .and_then(|s| s.split(" to").next())
                    .unwrap_or("UNKNOWN")
                    .to_string();
                TamperingOutcome::AuthBypassed {
                    original_method: original,
                    bypass_method,
                    status_code,
                }
            } else {
                TamperingOutcome::Rejected { status_code }
            }
        }
        _ => {
            if (500..600).contains(&status_code) {
                TamperingOutcome::ServerError { status_code }
            } else if status_code < 400 {
                TamperingOutcome::Accepted { status_code }
            } else {
                TamperingOutcome::Rejected { status_code }
            }
        }
    }
}

/// Build a `VerbTamperingResult` from a set of probes and their corresponding outcomes.
pub fn build_result(
    endpoint: &str,
    original_method: &str,
    probe_outcomes: Vec<(VerbTamperingProbe, TamperingOutcome)>,
) -> VerbTamperingResult {
    let findings = probe_outcomes
        .into_iter()
        .map(|(probe, outcome)| VerbTamperingFinding {
            technique: probe.technique,
            probe,
            outcome,
        })
        .collect();
    VerbTamperingResult {
        endpoint: endpoint.to_string(),
        original_method: original_method.to_string(),
        findings,
    }
}
