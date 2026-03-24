use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum IframeIssue {
    MissingSandbox { src: String },
    OverlyPermissiveSandbox { src: String, flags: String },
    AllowScriptsAndSameOrigin { src: String },
    HttpSource { src: String },
    ExternalSource { src: String },
    MissingTitle { src: String },
    DataUriSource,
    JavascriptUriSource,
    BlobSource { src: String },
    SrcdocWithScript,
    LazyLoadCrossOrigin { src: String },
    MissingReferrerPolicy { src: String },
}

impl std::fmt::Display for IframeIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IframeIssue::MissingSandbox { .. } => write!(f, "missing_sandbox"),
            IframeIssue::OverlyPermissiveSandbox { .. } => {
                write!(f, "overly_permissive_sandbox")
            }
            IframeIssue::AllowScriptsAndSameOrigin { .. } => {
                write!(f, "allow_scripts_and_same_origin")
            }
            IframeIssue::HttpSource { .. } => write!(f, "http_source"),
            IframeIssue::ExternalSource { .. } => write!(f, "external_source"),
            IframeIssue::MissingTitle { .. } => write!(f, "missing_title"),
            IframeIssue::DataUriSource => write!(f, "data_uri_source"),
            IframeIssue::JavascriptUriSource => write!(f, "javascript_uri_source"),
            IframeIssue::BlobSource { .. } => write!(f, "blob_source"),
            IframeIssue::SrcdocWithScript => write!(f, "srcdoc_with_script"),
            IframeIssue::LazyLoadCrossOrigin { .. } => write!(f, "lazy_load_cross_origin"),
            IframeIssue::MissingReferrerPolicy { .. } => write!(f, "missing_referrer_policy"),
        }
    }
}

pub fn iframe_severity(issue: &IframeIssue) -> f64 {
    match issue {
        IframeIssue::MissingSandbox { .. } => 4.5,
        IframeIssue::OverlyPermissiveSandbox { .. } => 3.5,
        IframeIssue::AllowScriptsAndSameOrigin { .. } => 6.0,
        IframeIssue::HttpSource { .. } => 5.0,
        IframeIssue::ExternalSource { .. } => 2.0,
        IframeIssue::MissingTitle { .. } => 1.0,
        IframeIssue::DataUriSource => 7.0,
        IframeIssue::JavascriptUriSource => 8.0,
        IframeIssue::BlobSource { .. } => 4.0,
        IframeIssue::SrcdocWithScript => 7.5,
        IframeIssue::LazyLoadCrossOrigin { .. } => 2.5,
        IframeIssue::MissingReferrerPolicy { .. } => 2.0,
    }
}

const DANGEROUS_SANDBOX_FLAGS: &[&str] = &[
    "allow-scripts",
    "allow-same-origin",
    "allow-top-navigation",
    "allow-popups",
];

fn is_external_src(src: &str) -> bool {
    src.starts_with("http://") || src.starts_with("https://")
}

pub fn audit_iframes(target: &str) -> Vec<IframeIssue> {
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

pub fn analyze_iframes(html: &str) -> Vec<IframeIssue> {
    let mut findings = Vec::new();

    for tag in TagIter::new(html, "iframe") {
        let src = html_parser::extract_attr(tag.original, &tag.lower, "src").unwrap_or_default();
        let src_lower = src.to_ascii_lowercase();

        if src_lower.starts_with("data:") {
            findings.push(IframeIssue::DataUriSource);
        }

        if src_lower.starts_with("javascript:") {
            findings.push(IframeIssue::JavascriptUriSource);
        }

        if src_lower.starts_with("blob:") {
            findings.push(IframeIssue::BlobSource { src: src.clone() });
        }

        if src.starts_with("http://") {
            findings.push(IframeIssue::HttpSource { src: src.clone() });
        }

        let external = is_external_src(&src);

        if external {
            findings.push(IframeIssue::ExternalSource { src: src.clone() });
        }

        let sandbox_val = html_parser::extract_attr_lower(&tag.lower, "sandbox");
        let has_sandbox = tag.lower.contains("sandbox");

        if !has_sandbox {
            findings.push(IframeIssue::MissingSandbox { src: src.clone() });
        } else if let Some(ref val) = sandbox_val {
            let has_scripts = val.contains("allow-scripts");
            let has_same_origin = val.contains("allow-same-origin");
            if has_scripts && has_same_origin {
                findings.push(IframeIssue::AllowScriptsAndSameOrigin { src: src.clone() });
            } else {
                let dangerous_count = DANGEROUS_SANDBOX_FLAGS
                    .iter()
                    .filter(|flag| val.contains(**flag))
                    .count();
                if dangerous_count >= 3 {
                    findings.push(IframeIssue::OverlyPermissiveSandbox {
                        src: src.clone(),
                        flags: val.clone(),
                    });
                }
            }
        }

        if let Some(srcdoc_val) = html_parser::extract_attr_lower(&tag.lower, "srcdoc") {
            let has_script = srcdoc_val.contains("<script") || srcdoc_val.contains("&lt;script");
            if has_script || srcdoc_val.contains("onerror=") || srcdoc_val.contains("onload=") {
                findings.push(IframeIssue::SrcdocWithScript);
            }
        }

        if external {
            if html_parser::extract_attr_lower(&tag.lower, "title").is_none() {
                findings.push(IframeIssue::MissingTitle { src: src.clone() });
            }

            if html_parser::extract_attr_lower(&tag.lower, "referrerpolicy").is_none() {
                findings.push(IframeIssue::MissingReferrerPolicy { src: src.clone() });
            }

            if let Some(loading) = html_parser::extract_attr_lower(&tag.lower, "loading")
                && loading == "lazy"
            {
                findings.push(IframeIssue::LazyLoadCrossOrigin { src: src.clone() });
            }
        }
    }

    findings
}

pub fn iframe_findings_to_operations(
    findings: &[IframeIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    findings
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                iframe_severity(issue),
                0.5,
            )
        })
        .collect()
}
