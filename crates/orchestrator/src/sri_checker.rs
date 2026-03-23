use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

#[derive(Debug, Clone)]
pub struct SriIssue {
    pub tag: String,
    pub src: String,
}

pub fn check_sri(target: &str) -> Vec<SriIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let body = match resp.text() {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };

    find_missing_sri(&body)
}

pub(crate) fn find_missing_sri(html: &str) -> Vec<SriIssue> {
    let mut issues = Vec::new();

    for (tag_name, attr) in &[("script", "src"), ("link", "href")] {
        for tag in TagIter::new(html, tag_name) {
            let Some(src_val) = html_parser::extract_attr(tag.original, &tag.lower, attr) else {
                continue;
            };
            if !is_external_resource(&src_val) {
                continue;
            }
            if *tag_name == "link" && !is_stylesheet(&tag.lower) {
                continue;
            }
            if tag.lower.contains("integrity") {
                continue;
            }
            issues.push(SriIssue {
                tag: tag_name.to_string(),
                src: src_val,
            });
        }
    }

    issues
}

fn is_external_resource(src: &str) -> bool {
    src.starts_with("http://") || src.starts_with("https://") || src.starts_with("//")
}

fn is_stylesheet(tag_lower: &str) -> bool {
    tag_lower.contains("rel=\"stylesheet\"") || tag_lower.contains("rel='stylesheet'")
}

pub fn sri_findings_to_operations(issues: &[SriIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let severity = if issues.len() > 3 { 4.5 } else { 3.5 };

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        severity,
        0.9,
    )]
}
