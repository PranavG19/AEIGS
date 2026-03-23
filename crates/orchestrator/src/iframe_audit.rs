use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum IframeIssue {
    MissingSandbox,
    OverlyPermissiveSandbox,
    HttpSource,
}

impl std::fmt::Display for IframeIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IframeIssue::MissingSandbox => write!(f, "missing_sandbox"),
            IframeIssue::OverlyPermissiveSandbox => write!(f, "overly_permissive_sandbox"),
            IframeIssue::HttpSource => write!(f, "http_source"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IframeFinding {
    pub issue: IframeIssue,
    pub src: String,
}

const DANGEROUS_SANDBOX_FLAGS: &[&str] = &[
    "allow-scripts",
    "allow-same-origin",
    "allow-top-navigation",
    "allow-popups",
];

pub fn audit_iframes(target: &str) -> Vec<IframeFinding> {
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
    analyze_iframes(&body)
}

pub(crate) fn analyze_iframes(html: &str) -> Vec<IframeFinding> {
    let mut findings = Vec::new();

    for tag in TagIter::new(html, "iframe") {
        let src = html_parser::extract_attr(tag.original, &tag.lower, "src").unwrap_or_default();

        if !tag.lower.contains("sandbox") {
            findings.push(IframeFinding {
                issue: IframeIssue::MissingSandbox,
                src: src.clone(),
            });
        } else if let Some(sandbox_val) = html_parser::extract_attr_lower(&tag.lower, "sandbox") {
            let dangerous_count = DANGEROUS_SANDBOX_FLAGS
                .iter()
                .filter(|flag| sandbox_val.contains(**flag))
                .count();
            if dangerous_count >= 3 {
                findings.push(IframeFinding {
                    issue: IframeIssue::OverlyPermissiveSandbox,
                    src: src.clone(),
                });
            }
        }

        if src.starts_with("http://") {
            findings.push(IframeFinding {
                issue: IframeIssue::HttpSource,
                src,
            });
        }
    }

    findings
}

pub fn iframe_findings_to_operations(
    findings: &[IframeFinding],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    findings
        .iter()
        .map(|f| {
            let severity = match f.issue {
                IframeIssue::MissingSandbox => 4.5,
                IframeIssue::OverlyPermissiveSandbox => 3.5,
                IframeIssue::HttpSource => 5.0,
            };
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                severity,
                0.85,
            )
        })
        .collect()
}
