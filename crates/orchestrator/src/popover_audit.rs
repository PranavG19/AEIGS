use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum PopoverIssue {
    ApiDetected,
    ContentSpoofing,
    ClickjackingOverlay,
    AutoShowOnLoad,
    UnsanitizedContent,
    NestedPopover,
}

impl std::fmt::Display for PopoverIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::ContentSpoofing => write!(f, "content_spoofing"),
            Self::ClickjackingOverlay => write!(f, "clickjacking_overlay"),
            Self::AutoShowOnLoad => write!(f, "auto_show_on_load"),
            Self::UnsanitizedContent => write!(f, "unsanitized_content"),
            Self::NestedPopover => write!(f, "nested_popover"),
        }
    }
}

pub fn audit_popover(target: &str) -> Vec<PopoverIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_popover(&body)
}

pub fn analyze_popover(body: &str) -> Vec<PopoverIssue> {
    let has_attr = body.contains("popover=") || body.contains("popover ");
    let has_api = body.contains("showPopover(")
        || body.contains("hidePopover(")
        || body.contains("togglePopover(");
    let has_target = body.contains("popovertarget");

    if !has_attr && !has_api && !has_target {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(PopoverIssue::ApiDetected);

    if (has_attr || has_api)
        && (body.contains("position: fixed") || body.contains("position: absolute"))
        && (body.contains("z-index") || body.contains("inset: 0"))
    {
        issues.push(PopoverIssue::ContentSpoofing);
    }

    if (has_attr || has_api)
        && body.contains("pointer-events")
        && (body.contains("opacity: 0")
            || body.contains("opacity:0")
            || body.contains("visibility: hidden"))
    {
        issues.push(PopoverIssue::ClickjackingOverlay);
    }

    if has_api
        && (body.contains("DOMContentLoaded")
            || body.contains("window.onload")
            || body.contains("addEventListener(\"load\""))
        && body.contains("showPopover(")
    {
        issues.push(PopoverIssue::AutoShowOnLoad);
    }

    if (has_attr || has_api)
        && body.contains("innerHTML")
        && !body.contains("sanitize")
        && !body.contains("textContent")
        && !body.contains("escapeHtml")
    {
        issues.push(PopoverIssue::UnsanitizedContent);
    }

    if has_attr && body.contains("popover=\"manual\"") && body.contains("popovertarget") {
        let popover_count = body.matches("popover=").count();
        if popover_count > 2 {
            issues.push(PopoverIssue::NestedPopover);
        }
    }

    issues
}

pub fn popover_severity(issue: &PopoverIssue) -> f64 {
    match issue {
        PopoverIssue::UnsanitizedContent => 7.5,
        PopoverIssue::ClickjackingOverlay => 7.0,
        PopoverIssue::ContentSpoofing => 6.5,
        PopoverIssue::AutoShowOnLoad => 5.0,
        PopoverIssue::NestedPopover => 4.0,
        PopoverIssue::ApiDetected => 2.0,
    }
}

pub fn popover_to_operations(issues: &[PopoverIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                popover_severity(issue),
                0.5,
            )
        })
        .collect()
}
