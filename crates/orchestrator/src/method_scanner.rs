use std::fmt;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum MethodIssue {
    TraceEnabled,
    ConnectEnabled,
    PutEnabled,
    DeleteEnabled,
    PatchEnabled,
    WebdavPropfind,
    WebdavMkcol,
    WebdavCopy,
    WebdavMove,
    ExcessiveMethods { count: usize },
    OptionsExposed,
    WildcardAllow,
}

impl fmt::Display for MethodIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TraceEnabled => write!(f, "trace_enabled"),
            Self::ConnectEnabled => write!(f, "connect_enabled"),
            Self::PutEnabled => write!(f, "put_enabled"),
            Self::DeleteEnabled => write!(f, "delete_enabled"),
            Self::PatchEnabled => write!(f, "patch_enabled"),
            Self::WebdavPropfind => write!(f, "webdav_propfind"),
            Self::WebdavMkcol => write!(f, "webdav_mkcol"),
            Self::WebdavCopy => write!(f, "webdav_copy"),
            Self::WebdavMove => write!(f, "webdav_move"),
            Self::ExcessiveMethods { count } => write!(f, "excessive_methods_{count}"),
            Self::OptionsExposed => write!(f, "options_exposed"),
            Self::WildcardAllow => write!(f, "wildcard_allow"),
        }
    }
}

pub fn method_severity(issue: &MethodIssue) -> f64 {
    match issue {
        MethodIssue::TraceEnabled => 5.0,
        MethodIssue::ConnectEnabled => 4.0,
        MethodIssue::PutEnabled => 4.5,
        MethodIssue::DeleteEnabled => 4.5,
        MethodIssue::PatchEnabled => 3.0,
        MethodIssue::WebdavPropfind => 4.0,
        MethodIssue::WebdavMkcol => 4.0,
        MethodIssue::WebdavCopy => 4.0,
        MethodIssue::WebdavMove => 4.0,
        MethodIssue::ExcessiveMethods { .. } => 3.0,
        MethodIssue::OptionsExposed => 1.5,
        MethodIssue::WildcardAllow => 5.5,
    }
}

pub fn analyze_methods(allow_header: &str) -> Vec<MethodIssue> {
    let methods: Vec<String> = allow_header
        .split(',')
        .map(|m| m.trim().to_uppercase())
        .filter(|m| !m.is_empty())
        .collect();

    if methods.is_empty() {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if methods.iter().any(|m| m == "*") {
        issues.push(MethodIssue::WildcardAllow);
    }
    if methods.iter().any(|m| m == "TRACE") {
        issues.push(MethodIssue::TraceEnabled);
    }
    if methods.iter().any(|m| m == "CONNECT") {
        issues.push(MethodIssue::ConnectEnabled);
    }
    if methods.iter().any(|m| m == "PUT") {
        issues.push(MethodIssue::PutEnabled);
    }
    if methods.iter().any(|m| m == "DELETE") {
        issues.push(MethodIssue::DeleteEnabled);
    }
    if methods.iter().any(|m| m == "PATCH") {
        issues.push(MethodIssue::PatchEnabled);
    }
    if methods.iter().any(|m| m == "PROPFIND") {
        issues.push(MethodIssue::WebdavPropfind);
    }
    if methods.iter().any(|m| m == "MKCOL") {
        issues.push(MethodIssue::WebdavMkcol);
    }
    if methods.iter().any(|m| m == "COPY") {
        issues.push(MethodIssue::WebdavCopy);
    }
    if methods.iter().any(|m| m == "MOVE") {
        issues.push(MethodIssue::WebdavMove);
    }
    if methods.iter().any(|m| m == "OPTIONS") {
        issues.push(MethodIssue::OptionsExposed);
    }
    if methods.len() > 7 {
        issues.push(MethodIssue::ExcessiveMethods {
            count: methods.len(),
        });
    }

    issues
}

#[derive(Debug, Clone)]
pub struct MethodResult {
    pub allowed_methods: Vec<String>,
    pub dangerous_methods: Vec<String>,
}

pub fn parse_allow_header(header: &str) -> MethodResult {
    let allowed: Vec<String> = header
        .split(',')
        .map(|m| m.trim().to_uppercase())
        .filter(|m| !m.is_empty())
        .collect();
    let dangerous: Vec<String> = allowed
        .iter()
        .filter(|m| {
            matches!(
                m.as_str(),
                "PUT"
                    | "DELETE"
                    | "TRACE"
                    | "CONNECT"
                    | "PATCH"
                    | "PROPFIND"
                    | "MKCOL"
                    | "COPY"
                    | "MOVE"
            )
        })
        .cloned()
        .collect();
    MethodResult {
        allowed_methods: allowed,
        dangerous_methods: dangerous,
    }
}

pub fn scan_methods(target: &str) -> Option<Vec<MethodIssue>> {
    recon_client::validated_domain(target)?;
    let client = recon_client::default_client()?;

    let resp = client
        .request(reqwest::Method::OPTIONS, target)
        .send()
        .ok()?;

    let allow_header = resp.headers().get("allow").and_then(|v| v.to_str().ok())?;

    let issues = analyze_methods(allow_header);
    if issues.is_empty() {
        return None;
    }
    Some(issues)
}

pub fn method_findings_to_operations(
    issues: &[MethodIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                method_severity(issue),
                0.5,
            )
        })
        .collect()
}
