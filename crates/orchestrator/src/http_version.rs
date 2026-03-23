use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::recon_client;
use crate::util::timestamp_ms;

#[derive(Debug, Clone)]
pub struct HttpVersionInfo {
    pub version: String,
    pub supports_h2: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HttpVersionIssue {
    Http10 { version: String },
    Http11Only,
    NoHsts,
    InsecureDowngrade,
    MissingSecurityHeaders { headers: Vec<String> },
    ServerVersionExposed { server: String },
    DeprecatedProtocol { protocol: String },
    ConnectionKeepAlive,
}

impl std::fmt::Display for HttpVersionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpVersionIssue::Http10 { .. } => write!(f, "http10_detected"),
            HttpVersionIssue::Http11Only => write!(f, "http11_only"),
            HttpVersionIssue::NoHsts => write!(f, "no_hsts"),
            HttpVersionIssue::InsecureDowngrade => write!(f, "insecure_downgrade"),
            HttpVersionIssue::MissingSecurityHeaders { .. } => {
                write!(f, "missing_security_headers")
            }
            HttpVersionIssue::ServerVersionExposed { .. } => {
                write!(f, "server_version_exposed")
            }
            HttpVersionIssue::DeprecatedProtocol { .. } => write!(f, "deprecated_protocol"),
            HttpVersionIssue::ConnectionKeepAlive => write!(f, "connection_keep_alive"),
        }
    }
}

pub fn http_version_severity(issue: &HttpVersionIssue) -> f64 {
    match issue {
        HttpVersionIssue::InsecureDowngrade => 7.0,
        HttpVersionIssue::ServerVersionExposed { .. } => 5.0,
        HttpVersionIssue::NoHsts => 5.0,
        HttpVersionIssue::Http10 { .. } => 4.0,
        HttpVersionIssue::DeprecatedProtocol { .. } => 4.0,
        HttpVersionIssue::MissingSecurityHeaders { .. } => 3.5,
        HttpVersionIssue::Http11Only => 2.0,
        HttpVersionIssue::ConnectionKeepAlive => 2.0,
    }
}

const SECURITY_HEADERS: &[&str] = &[
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "content-security-policy",
    "referrer-policy",
];

pub fn analyze_http_version(
    version: &str,
    supports_h2: bool,
    headers: &[(&str, &str)],
) -> Vec<HttpVersionIssue> {
    let mut issues = Vec::new();

    let find_header = |name: &str| -> Option<&str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    };

    if version.contains("1.0") || version.eq_ignore_ascii_case("http/1.0") {
        issues.push(HttpVersionIssue::Http10 {
            version: version.to_string(),
        });
    } else if !supports_h2 {
        issues.push(HttpVersionIssue::Http11Only);
    }

    if find_header("strict-transport-security").is_none() {
        issues.push(HttpVersionIssue::NoHsts);
    }

    if let Some(server) = find_header("server") {
        let has_version = server.chars().any(|c| c.is_ascii_digit()) && server.contains('/');
        if has_version {
            issues.push(HttpVersionIssue::ServerVersionExposed {
                server: server.to_string(),
            });
        }
    }

    let has_connection_keep_alive = find_header("connection")
        .map(|v| v.eq_ignore_ascii_case("keep-alive"))
        .unwrap_or(false);
    if has_connection_keep_alive && find_header("keep-alive").is_none() {
        issues.push(HttpVersionIssue::ConnectionKeepAlive);
    }

    let missing: Vec<String> = SECURITY_HEADERS
        .iter()
        .filter(|h| find_header(h).is_none())
        .map(|h| h.to_string())
        .collect();
    if !missing.is_empty() {
        issues.push(HttpVersionIssue::MissingSecurityHeaders { headers: missing });
    }

    issues
}

pub fn http_version_to_operations(
    issues: &[HttpVersionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                http_version_severity(issue),
                0.5,
            )
        })
        .collect()
}

pub fn detect_http_version(target: &str) -> Option<HttpVersionInfo> {
    recon_client::validated_domain(target)?;
    let client = recon_client::default_client()?;

    let resp = client.get(target).send().ok()?;
    let version = format!("{:?}", resp.version());
    let supports_h2 = resp.version() == reqwest::Version::HTTP_2;

    Some(HttpVersionInfo {
        version,
        supports_h2,
    })
}

pub fn version_to_operations(info: &HttpVersionInfo, seq: &mut u64) -> Vec<OperationLogEntry> {
    *seq += 1;
    vec![OperationLogEntry {
        sequence_number: *seq,
        module: ModuleIdentifier::PassiveRecon,
        operation: GraphOperation::AddNode {
            node_type: NodeType::Service,
            properties: vec![
                ("http_version".to_string(), info.version.clone()),
                ("supports_h2".to_string(), info.supports_h2.to_string()),
                ("source".to_string(), "http_version_detect".to_string()),
            ],
        },
        timestamp_unix_ms: timestamp_ms(),
    }]
}
