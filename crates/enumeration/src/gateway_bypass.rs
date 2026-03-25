use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Severity for gateway bypass findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GatewayBypassSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for GatewayBypassSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayBypassSeverity::Info => write!(f, "Info"),
            GatewayBypassSeverity::Low => write!(f, "Low"),
            GatewayBypassSeverity::Medium => write!(f, "Medium"),
            GatewayBypassSeverity::High => write!(f, "High"),
            GatewayBypassSeverity::Critical => write!(f, "Critical"),
        }
    }
}

/// Direct backend access probe result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectBackendAccessResult {
    pub technique: DirectAccessTechnique,
    pub host_header: String,
    pub target_url: String,
    pub gateway_status: Option<u16>,
    pub direct_status: Option<u16>,
    pub bypassed: bool,
    pub severity: GatewayBypassSeverity,
    pub description: String,
}

/// Techniques for direct backend access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectAccessTechnique {
    HostHeaderOverride,
    XForwardedHost,
    XOriginalUrl,
    XRewriteUrl,
    InternalIpAccess,
    AlternatePort,
}

impl fmt::Display for DirectAccessTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DirectAccessTechnique::HostHeaderOverride => write!(f, "Host Header Override"),
            DirectAccessTechnique::XForwardedHost => write!(f, "X-Forwarded-Host"),
            DirectAccessTechnique::XOriginalUrl => write!(f, "X-Original-URL"),
            DirectAccessTechnique::XRewriteUrl => write!(f, "X-Rewrite-URL"),
            DirectAccessTechnique::InternalIpAccess => write!(f, "Internal IP Access"),
            DirectAccessTechnique::AlternatePort => write!(f, "Alternate Port"),
        }
    }
}

/// Path normalization differential finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathNormalizationResult {
    pub original_path: String,
    pub manipulated_path: String,
    pub technique: PathNormTechnique,
    pub gateway_blocked: bool,
    pub backend_allowed: bool,
    pub bypassed: bool,
    pub severity: GatewayBypassSeverity,
    pub description: String,
}

/// Path normalization confusion techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathNormTechnique {
    DotSegmentTraversal,
    DoubleUrlEncoding,
    UnicodeNormalization,
    BackslashSubstitution,
    NullByteInjection,
    SemicolonPathParam,
    TabNewlineInsertion,
    CaseSwitching,
    TrailingDotSegment,
    DoubleSlash,
}

impl fmt::Display for PathNormTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathNormTechnique::DotSegmentTraversal => write!(f, "Dot Segment Traversal"),
            PathNormTechnique::DoubleUrlEncoding => write!(f, "Double URL Encoding"),
            PathNormTechnique::UnicodeNormalization => write!(f, "Unicode Normalization"),
            PathNormTechnique::BackslashSubstitution => write!(f, "Backslash Substitution"),
            PathNormTechnique::NullByteInjection => write!(f, "Null Byte Injection"),
            PathNormTechnique::SemicolonPathParam => write!(f, "Semicolon Path Parameter"),
            PathNormTechnique::TabNewlineInsertion => write!(f, "Tab/Newline Insertion"),
            PathNormTechnique::CaseSwitching => write!(f, "Case Switching"),
            PathNormTechnique::TrailingDotSegment => write!(f, "Trailing Dot Segment"),
            PathNormTechnique::DoubleSlash => write!(f, "Double Slash"),
        }
    }
}

/// Rate limit bypass probe result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitBypassResult {
    pub technique: RateLimitBypassTechnique,
    pub header_payload: HashMap<String, String>,
    pub bypassed: bool,
    pub severity: GatewayBypassSeverity,
    pub description: String,
}

/// Rate limit bypass techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RateLimitBypassTechnique {
    XForwardedForRotation,
    XRealIpSpoof,
    XClientIp,
    TrueClientIp,
    XClusterClientIp,
    ForwardedHeader,
    OriginIpRotation,
    HttpMethodSwitch,
}

impl fmt::Display for RateLimitBypassTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RateLimitBypassTechnique::XForwardedForRotation => {
                write!(f, "X-Forwarded-For Rotation")
            }
            RateLimitBypassTechnique::XRealIpSpoof => write!(f, "X-Real-IP Spoof"),
            RateLimitBypassTechnique::XClientIp => write!(f, "X-Client-IP"),
            RateLimitBypassTechnique::TrueClientIp => write!(f, "True-Client-IP"),
            RateLimitBypassTechnique::XClusterClientIp => write!(f, "X-Cluster-Client-IP"),
            RateLimitBypassTechnique::ForwardedHeader => write!(f, "Forwarded Header"),
            RateLimitBypassTechnique::OriginIpRotation => write!(f, "Origin IP Rotation"),
            RateLimitBypassTechnique::HttpMethodSwitch => write!(f, "HTTP Method Switch"),
        }
    }
}

/// Auth forwarding issue finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthForwardingResult {
    pub issue_type: AuthForwardingIssue,
    pub header_name: String,
    pub severity: GatewayBypassSeverity,
    pub description: String,
    pub proof_headers: HashMap<String, String>,
}

/// Auth forwarding issue categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthForwardingIssue {
    TokenPassthrough,
    InternalHeaderInjection,
    AuthBypassViaHop,
    SessionFixationViaGateway,
    CredentialLeakInProxy,
}

impl fmt::Display for AuthForwardingIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthForwardingIssue::TokenPassthrough => write!(f, "Token Passthrough"),
            AuthForwardingIssue::InternalHeaderInjection => {
                write!(f, "Internal Header Injection")
            }
            AuthForwardingIssue::AuthBypassViaHop => write!(f, "Auth Bypass via Hop"),
            AuthForwardingIssue::SessionFixationViaGateway => {
                write!(f, "Session Fixation via Gateway")
            }
            AuthForwardingIssue::CredentialLeakInProxy => {
                write!(f, "Credential Leak in Proxy")
            }
        }
    }
}

/// Top-level gateway bypass finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayBypassFinding {
    pub category: GatewayBypassCategory,
    pub severity: GatewayBypassSeverity,
    pub title: String,
    pub detail: String,
}

/// Gateway bypass attack category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayBypassCategory {
    DirectBackendAccess,
    PathNormalizationDiff,
    RateLimitBypass,
    AuthForwardingIssue,
}

impl fmt::Display for GatewayBypassCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayBypassCategory::DirectBackendAccess => write!(f, "Direct Backend Access"),
            GatewayBypassCategory::PathNormalizationDiff => {
                write!(f, "Path Normalization Differential")
            }
            GatewayBypassCategory::RateLimitBypass => write!(f, "Rate Limit Bypass"),
            GatewayBypassCategory::AuthForwardingIssue => write!(f, "Auth Forwarding Issue"),
        }
    }
}

/// Generate direct backend access probes using Host header manipulation.
pub fn generate_direct_access_probes(
    target_url: &str,
    backend_hosts: &[&str],
) -> Vec<DirectBackendAccessResult> {
    let mut results = Vec::new();

    for &backend in backend_hosts {
        results.push(DirectBackendAccessResult {
            technique: DirectAccessTechnique::HostHeaderOverride,
            host_header: backend.to_string(),
            target_url: target_url.to_string(),
            gateway_status: None,
            direct_status: None,
            bypassed: false,
            severity: GatewayBypassSeverity::High,
            description: format!(
                "Override Host header to '{}' to reach backend directly, bypassing gateway routing",
                backend
            ),
        });

        results.push(DirectBackendAccessResult {
            technique: DirectAccessTechnique::XForwardedHost,
            host_header: backend.to_string(),
            target_url: target_url.to_string(),
            gateway_status: None,
            direct_status: None,
            bypassed: false,
            severity: GatewayBypassSeverity::High,
            description: format!(
                "Set X-Forwarded-Host to '{}' to confuse gateway routing logic",
                backend
            ),
        });

        results.push(DirectBackendAccessResult {
            technique: DirectAccessTechnique::XOriginalUrl,
            host_header: backend.to_string(),
            target_url: target_url.to_string(),
            gateway_status: None,
            direct_status: None,
            bypassed: false,
            severity: GatewayBypassSeverity::High,
            description: format!(
                "Set X-Original-URL header to reach '{}' past gateway URL rewriting",
                backend
            ),
        });

        results.push(DirectBackendAccessResult {
            technique: DirectAccessTechnique::XRewriteUrl,
            host_header: backend.to_string(),
            target_url: target_url.to_string(),
            gateway_status: None,
            direct_status: None,
            bypassed: false,
            severity: GatewayBypassSeverity::High,
            description: format!(
                "Set X-Rewrite-URL header to override path routing to '{}'",
                backend
            ),
        });
    }

    let internal_ips = ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1"];
    for ip in &internal_ips {
        results.push(DirectBackendAccessResult {
            technique: DirectAccessTechnique::InternalIpAccess,
            host_header: ip.to_string(),
            target_url: target_url.to_string(),
            gateway_status: None,
            direct_status: None,
            bypassed: false,
            severity: GatewayBypassSeverity::Critical,
            description: format!(
                "Access backend directly via internal IP {} to bypass gateway completely",
                ip
            ),
        });
    }

    let alternate_ports = [8080, 8443, 3000, 4443, 9090];
    for port in &alternate_ports {
        results.push(DirectBackendAccessResult {
            technique: DirectAccessTechnique::AlternatePort,
            host_header: format!(
                "{}:{}",
                target_url
                    .split("://")
                    .nth(1)
                    .unwrap_or(target_url)
                    .split('/')
                    .next()
                    .unwrap_or(""),
                port
            ),
            target_url: target_url.to_string(),
            gateway_status: None,
            direct_status: None,
            bypassed: false,
            severity: GatewayBypassSeverity::Medium,
            description: format!(
                "Connect to alternate port {} which may expose backend without gateway protection",
                port
            ),
        });
    }

    results
}

/// Evaluate a direct access probe given observed response codes.
pub fn evaluate_direct_access(
    probe: &DirectBackendAccessResult,
    gateway_status: u16,
    direct_status: u16,
) -> DirectBackendAccessResult {
    let bypassed =
        (gateway_status == 403 || gateway_status == 401) && (200..=299).contains(&direct_status);

    let severity = if bypassed {
        GatewayBypassSeverity::Critical
    } else {
        probe.severity
    };

    let description = if bypassed {
        format!(
            "Gateway returned {} but direct access via {} returned {}; backend reachable without gateway protection",
            gateway_status, probe.technique, direct_status
        )
    } else {
        format!(
            "Gateway: {}, Direct: {} via {} — no bypass confirmed",
            gateway_status, direct_status, probe.technique
        )
    };

    DirectBackendAccessResult {
        technique: probe.technique,
        host_header: probe.host_header.clone(),
        target_url: probe.target_url.clone(),
        gateway_status: Some(gateway_status),
        direct_status: Some(direct_status),
        bypassed,
        severity,
        description,
    }
}

/// Generate path normalization differential payloads.
pub fn generate_path_norm_payloads(restricted_path: &str) -> Vec<PathNormalizationResult> {
    let mut results = Vec::new();

    let techniques: Vec<(PathNormTechnique, String)> = vec![
        (
            PathNormTechnique::DotSegmentTraversal,
            format!("/allowed/../{}", restricted_path.trim_start_matches('/')),
        ),
        (
            PathNormTechnique::DoubleUrlEncoding,
            restricted_path.replace('/', "%252f"),
        ),
        (
            PathNormTechnique::UnicodeNormalization,
            restricted_path.replace('/', "\u{2215}"),
        ),
        (
            PathNormTechnique::BackslashSubstitution,
            restricted_path.replace('/', "\\"),
        ),
        (
            PathNormTechnique::NullByteInjection,
            format!("{}%00.html", restricted_path),
        ),
        (
            PathNormTechnique::SemicolonPathParam,
            format!("{};bypass=true", restricted_path),
        ),
        (
            PathNormTechnique::TabNewlineInsertion,
            format!("{}%09", restricted_path),
        ),
        (
            PathNormTechnique::CaseSwitching,
            alternate_case(restricted_path),
        ),
        (
            PathNormTechnique::TrailingDotSegment,
            format!("{}/..", restricted_path),
        ),
        (
            PathNormTechnique::DoubleSlash,
            restricted_path.replace('/', "//"),
        ),
    ];

    for (technique, manipulated) in techniques {
        results.push(PathNormalizationResult {
            original_path: restricted_path.to_string(),
            manipulated_path: manipulated,
            technique,
            gateway_blocked: false,
            backend_allowed: false,
            bypassed: false,
            severity: GatewayBypassSeverity::High,
            description: format!(
                "{} applied to '{}' to exploit normalization difference between gateway and backend",
                technique, restricted_path
            ),
        });
    }

    results
}

/// Evaluate a path normalization probe given observed behavior.
pub fn evaluate_path_norm(
    probe: &PathNormalizationResult,
    gateway_blocked: bool,
    backend_allowed: bool,
) -> PathNormalizationResult {
    let bypassed = gateway_blocked && backend_allowed;
    let severity = if bypassed {
        GatewayBypassSeverity::Critical
    } else {
        GatewayBypassSeverity::Info
    };

    let description = if bypassed {
        format!(
            "Gateway blocked '{}' but backend accepted '{}' via {}; normalization differential exploited",
            probe.original_path, probe.manipulated_path, probe.technique
        )
    } else {
        format!(
            "No normalization bypass: gateway_blocked={}, backend_allowed={} for {}",
            gateway_blocked, backend_allowed, probe.technique
        )
    };

    PathNormalizationResult {
        original_path: probe.original_path.clone(),
        manipulated_path: probe.manipulated_path.clone(),
        technique: probe.technique,
        gateway_blocked,
        backend_allowed,
        bypassed,
        severity,
        description,
    }
}

/// Generate rate limit bypass probes using IP spoofing headers.
pub fn generate_rate_limit_bypass_probes() -> Vec<RateLimitBypassResult> {
    let mut results = Vec::new();

    let ip_pool: Vec<String> = (1..=5).map(|i| format!("10.0.{}.{}", i, i + 100)).collect();

    for (idx, ip) in ip_pool.iter().enumerate() {
        let technique = match idx % 6 {
            0 => RateLimitBypassTechnique::XForwardedForRotation,
            1 => RateLimitBypassTechnique::XRealIpSpoof,
            2 => RateLimitBypassTechnique::XClientIp,
            3 => RateLimitBypassTechnique::TrueClientIp,
            4 => RateLimitBypassTechnique::XClusterClientIp,
            _ => RateLimitBypassTechnique::ForwardedHeader,
        };

        let header_name = match technique {
            RateLimitBypassTechnique::XForwardedForRotation => "X-Forwarded-For",
            RateLimitBypassTechnique::XRealIpSpoof => "X-Real-IP",
            RateLimitBypassTechnique::XClientIp => "X-Client-IP",
            RateLimitBypassTechnique::TrueClientIp => "True-Client-IP",
            RateLimitBypassTechnique::XClusterClientIp => "X-Cluster-Client-IP",
            RateLimitBypassTechnique::ForwardedHeader => "Forwarded",
            _ => "X-Forwarded-For",
        };

        let header_value = if technique == RateLimitBypassTechnique::ForwardedHeader {
            format!("for={}", ip)
        } else {
            ip.clone()
        };

        let mut payload = HashMap::new();
        payload.insert(header_name.to_string(), header_value);

        results.push(RateLimitBypassResult {
            technique,
            header_payload: payload,
            bypassed: false,
            severity: GatewayBypassSeverity::High,
            description: format!(
                "Spoof client IP via {} header to reset rate limit counter at gateway",
                header_name
            ),
        });
    }

    let mut method_payload = HashMap::new();
    method_payload.insert("Method".to_string(), "POST→GET".to_string());
    results.push(RateLimitBypassResult {
        technique: RateLimitBypassTechnique::HttpMethodSwitch,
        header_payload: method_payload,
        bypassed: false,
        severity: GatewayBypassSeverity::Medium,
        description: "Switch HTTP method to bypass method-specific rate limits at gateway"
            .to_string(),
    });

    let mut origin_payload = HashMap::new();
    origin_payload.insert(
        "X-Forwarded-For".to_string(),
        "1.2.3.4, 5.6.7.8".to_string(),
    );
    origin_payload.insert("X-Real-IP".to_string(), "9.10.11.12".to_string());
    results.push(RateLimitBypassResult {
        technique: RateLimitBypassTechnique::OriginIpRotation,
        header_payload: origin_payload,
        bypassed: false,
        severity: GatewayBypassSeverity::High,
        description: "Send conflicting IP headers to confuse gateway IP extraction logic"
            .to_string(),
    });

    results
}

/// Evaluate a rate limit bypass probe given observed behavior.
pub fn evaluate_rate_limit_bypass(
    probe: &RateLimitBypassResult,
    requests_before_limit: u32,
    requests_with_bypass: u32,
) -> RateLimitBypassResult {
    let bypassed = requests_with_bypass > requests_before_limit;
    let severity = if bypassed {
        GatewayBypassSeverity::Critical
    } else {
        probe.severity
    };

    let description = if bypassed {
        format!(
            "Rate limit bypassed via {}: {} requests allowed vs {} baseline",
            probe.technique, requests_with_bypass, requests_before_limit
        )
    } else {
        format!(
            "Rate limit held: {} requests with bypass vs {} baseline via {}",
            requests_with_bypass, requests_before_limit, probe.technique
        )
    };

    RateLimitBypassResult {
        technique: probe.technique,
        header_payload: probe.header_payload.clone(),
        bypassed,
        severity,
        description,
    }
}

/// Generate auth forwarding issue probes.
pub fn generate_auth_forwarding_probes(auth_header_value: &str) -> Vec<AuthForwardingResult> {
    let mut results = Vec::new();

    let mut passthrough_headers = HashMap::new();
    passthrough_headers.insert("Authorization".to_string(), auth_header_value.to_string());
    passthrough_headers.insert("X-Forwarded-Host".to_string(), "attacker.com".to_string());
    results.push(AuthForwardingResult {
        issue_type: AuthForwardingIssue::TokenPassthrough,
        header_name: "Authorization".to_string(),
        severity: GatewayBypassSeverity::High,
        description: "Gateway forwards raw Authorization header to backend without stripping or re-signing; token exposed to all downstream services".to_string(),
        proof_headers: passthrough_headers,
    });

    let internal_headers = vec![
        ("X-User-Id", "1337"),
        ("X-User-Role", "admin"),
        ("X-Authenticated-User", "admin@internal"),
        ("X-Original-User", "root"),
    ];

    for (header, value) in &internal_headers {
        let mut proof = HashMap::new();
        proof.insert(header.to_string(), value.to_string());
        results.push(AuthForwardingResult {
            issue_type: AuthForwardingIssue::InternalHeaderInjection,
            header_name: header.to_string(),
            severity: GatewayBypassSeverity::Critical,
            description: format!(
                "Gateway trusts client-supplied '{}' header; injecting '{}={}' may bypass backend auth",
                header, header, value
            ),
            proof_headers: proof,
        });
    }

    let mut hop_headers = HashMap::new();
    hop_headers.insert("Authorization".to_string(), String::new());
    hop_headers.insert("X-Gateway-Auth".to_string(), "internal-token".to_string());
    results.push(AuthForwardingResult {
        issue_type: AuthForwardingIssue::AuthBypassViaHop,
        header_name: "X-Gateway-Auth".to_string(),
        severity: GatewayBypassSeverity::Critical,
        description: "Strip client Authorization and inject gateway internal auth token to test if backend trusts gateway-level auth alone".to_string(),
        proof_headers: hop_headers,
    });

    let mut fixation_headers = HashMap::new();
    fixation_headers.insert(
        "Cookie".to_string(),
        "session=attacker_controlled_session".to_string(),
    );
    fixation_headers.insert("X-Forwarded-For".to_string(), "127.0.0.1".to_string());
    results.push(AuthForwardingResult {
        issue_type: AuthForwardingIssue::SessionFixationViaGateway,
        header_name: "Cookie".to_string(),
        severity: GatewayBypassSeverity::High,
        description: "Gateway preserves attacker-supplied session cookie and forwards to backend; enables session fixation through gateway proxy".to_string(),
        proof_headers: fixation_headers,
    });

    let mut leak_headers = HashMap::new();
    leak_headers.insert("Authorization".to_string(), auth_header_value.to_string());
    leak_headers.insert("Via".to_string(), "1.1 gateway-proxy".to_string());
    results.push(AuthForwardingResult {
        issue_type: AuthForwardingIssue::CredentialLeakInProxy,
        header_name: "Authorization".to_string(),
        severity: GatewayBypassSeverity::High,
        description: "Gateway logs or exposes credentials in Via/X-Forwarded headers during multi-hop proxy chains".to_string(),
        proof_headers: leak_headers,
    });

    results
}

fn alternate_case(path: &str) -> String {
    path.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_uppercase().to_string()
            } else {
                c.to_lowercase().to_string()
            }
        })
        .collect()
}

/// Run the full gateway bypass analysis.
pub fn run_gateway_bypass_analysis(
    target_url: &str,
    backend_hosts: &[&str],
    restricted_paths: &[&str],
    auth_header: Option<&str>,
) -> Vec<GatewayBypassFinding> {
    let mut findings = Vec::new();

    let access_probes = generate_direct_access_probes(target_url, backend_hosts);
    for probe in &access_probes {
        findings.push(GatewayBypassFinding {
            category: GatewayBypassCategory::DirectBackendAccess,
            severity: probe.severity,
            title: format!("{} via {}", probe.technique, probe.host_header),
            detail: probe.description.clone(),
        });
    }

    for path in restricted_paths {
        let norm_probes = generate_path_norm_payloads(path);
        for probe in &norm_probes {
            findings.push(GatewayBypassFinding {
                category: GatewayBypassCategory::PathNormalizationDiff,
                severity: probe.severity,
                title: format!("{} on '{}'", probe.technique, path),
                detail: probe.description.clone(),
            });
        }
    }

    let rate_probes = generate_rate_limit_bypass_probes();
    for probe in &rate_probes {
        findings.push(GatewayBypassFinding {
            category: GatewayBypassCategory::RateLimitBypass,
            severity: probe.severity,
            title: format!("Rate limit bypass via {}", probe.technique),
            detail: probe.description.clone(),
        });
    }

    if let Some(auth) = auth_header {
        let auth_probes = generate_auth_forwarding_probes(auth);
        for probe in &auth_probes {
            findings.push(GatewayBypassFinding {
                category: GatewayBypassCategory::AuthForwardingIssue,
                severity: probe.severity,
                title: format!("{} via {}", probe.issue_type, probe.header_name),
                detail: probe.description.clone(),
            });
        }
    }

    findings
}
