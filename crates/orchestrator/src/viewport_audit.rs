use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ViewportIssue {
    ZoomDisabled,
    MaximumScaleOne,
    MinimalInitialScale,
    ViewportMissing,
    FixedWidthViewport,
    ShrinkToFitDisabled,
}

impl std::fmt::Display for ViewportIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZoomDisabled => write!(f, "zoom_disabled"),
            Self::MaximumScaleOne => write!(f, "maximum_scale_one"),
            Self::MinimalInitialScale => write!(f, "minimal_initial_scale"),
            Self::ViewportMissing => write!(f, "viewport_missing"),
            Self::FixedWidthViewport => write!(f, "fixed_width_viewport"),
            Self::ShrinkToFitDisabled => write!(f, "shrink_to_fit_disabled"),
        }
    }
}

pub fn audit_viewport(target: &str) -> Vec<ViewportIssue> {
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
    analyze_viewport(&body)
}

pub fn analyze_viewport(body: &str) -> Vec<ViewportIssue> {
    let lower = body.to_ascii_lowercase();
    if !lower.contains("<meta") {
        return vec![ViewportIssue::ViewportMissing];
    }

    let viewport_content = extract_viewport_content(&lower);
    let Some(content) = viewport_content else {
        return vec![ViewportIssue::ViewportMissing];
    };

    let mut issues = Vec::new();

    if content.contains("user-scalable=no") || content.contains("user-scalable=0") {
        issues.push(ViewportIssue::ZoomDisabled);
    }

    if let Some(max) = extract_value(&content, "maximum-scale")
        && let Ok(v) = max.parse::<f64>()
        && v <= 1.0
    {
        issues.push(ViewportIssue::MaximumScaleOne);
    }

    if let Some(init) = extract_value(&content, "initial-scale")
        && let Ok(v) = init.parse::<f64>()
        && v < 0.5
    {
        issues.push(ViewportIssue::MinimalInitialScale);
    }

    if let Some(width) = extract_value(&content, "width")
        && width != "device-width"
        && width.parse::<u32>().is_ok()
    {
        issues.push(ViewportIssue::FixedWidthViewport);
    }

    if content.contains("shrink-to-fit=no") {
        issues.push(ViewportIssue::ShrinkToFitDisabled);
    }

    issues
}

fn extract_viewport_content(lower: &str) -> Option<String> {
    let mut pos = 0;
    while let Some(idx) = lower[pos..].find("<meta") {
        let abs = pos + idx;
        let end = lower[abs..].find('>')?;
        let tag = &lower[abs..abs + end + 1];
        if tag.contains("viewport") && let Some(ci) = tag.find("content=") {
            let rest = &tag[ci + 8..];
            let rest = rest.trim_start_matches(['"', '\'']);
            let end_q = rest
                .find(['"', '\'', '>'])
                .unwrap_or(rest.len());
            return Some(rest[..end_q].to_string());
        }
        pos = abs + 5;
    }
    None
}

fn extract_value<'a>(content: &'a str, key: &str) -> Option<&'a str> {
    let idx = content.find(key)?;
    let rest = &content[idx + key.len()..];
    let rest = rest.trim_start_matches([' ', '=']);
    let end = rest.find([',', ';', ' ']).unwrap_or(rest.len());
    let val = rest[..end].trim();
    if val.is_empty() {
        None
    } else {
        Some(val)
    }
}

pub fn viewport_severity(issue: &ViewportIssue) -> f64 {
    match issue {
        ViewportIssue::ZoomDisabled => 5.5,
        ViewportIssue::MaximumScaleOne => 5.0,
        ViewportIssue::FixedWidthViewport => 4.5,
        ViewportIssue::MinimalInitialScale => 4.0,
        ViewportIssue::ShrinkToFitDisabled => 3.5,
        ViewportIssue::ViewportMissing => 3.0,
    }
}

pub fn viewport_to_operations(
    issues: &[ViewportIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                viewport_severity(issue),
                0.7,
            )
        })
        .collect()
}
