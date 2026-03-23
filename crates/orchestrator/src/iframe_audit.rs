use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

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
    let lower = html.to_ascii_lowercase();
    let mut search_from = 0;

    while let Some(start) = lower[search_from..].find("<iframe") {
        let abs_start = search_from + start;
        let Some(end) = lower[abs_start..].find('>') else {
            break;
        };
        let tag = &html[abs_start..abs_start + end + 1];
        let tag_lower = &lower[abs_start..abs_start + end + 1];
        search_from = abs_start + end + 1;

        let src = extract_src(tag, tag_lower).unwrap_or_default();

        if !tag_lower.contains("sandbox") {
            findings.push(IframeFinding {
                issue: IframeIssue::MissingSandbox,
                src: src.clone(),
            });
        } else if let Some(sandbox_val) = extract_sandbox_value(tag_lower) {
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

fn extract_src(tag: &str, tag_lower: &str) -> Option<String> {
    let pos = tag_lower.find("src=")?;
    let rest = &tag[pos + 4..];
    let trimmed = rest.trim_start();
    if let Some(stripped) = trimmed.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else if let Some(stripped) = trimmed.strip_prefix('\'') {
        let end = stripped.find('\'')?;
        Some(stripped[..end].to_string())
    } else {
        let end = trimmed
            .find(|c: char| c.is_whitespace() || c == '>')
            .unwrap_or(trimmed.len());
        Some(trimmed[..end].to_string())
    }
}

fn extract_sandbox_value(tag_lower: &str) -> Option<String> {
    let pos = tag_lower.find("sandbox=")?;
    let rest = &tag_lower[pos + 8..];
    let trimmed = rest.trim_start();
    if let Some(stripped) = trimmed.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else if let Some(stripped) = trimmed.strip_prefix('\'') {
        let end = stripped.find('\'')?;
        Some(stripped[..end].to_string())
    } else {
        let end = trimmed
            .find(|c: char| c.is_whitespace() || c == '>')
            .unwrap_or(trimmed.len());
        Some(trimmed[..end].to_string())
    }
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
