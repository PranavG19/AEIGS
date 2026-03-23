use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

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
    let lower = html.to_ascii_lowercase();

    for (tag_name, attr) in &[("script", "src"), ("link", "href")] {
        let pattern = format!("<{tag_name}");
        let mut search_from = 0;

        while let Some(start) = lower[search_from..].find(&pattern) {
            let abs_start = search_from + start;
            let Some(end) = lower[abs_start..].find('>') else {
                break;
            };
            let tag = &html[abs_start..abs_start + end + 1];
            let tag_lower = &lower[abs_start..abs_start + end + 1];
            search_from = abs_start + end + 1;

            let Some(src_val) = extract_attr(tag, tag_lower, attr) else {
                continue;
            };
            if !is_external_resource(&src_val) {
                continue;
            }
            if *tag_name == "link" && !is_stylesheet(tag_lower) {
                continue;
            }
            if tag_lower.contains("integrity") {
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

fn extract_attr(tag: &str, tag_lower: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{attr_name}=");
    let pos = tag_lower.find(&pattern)?;
    let rest = &tag[pos + pattern.len()..];
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
