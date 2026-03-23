use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum PointerLockIssue {
    ApiDetected,
    ClickjackingRisk,
    UiSpoofing,
    InputHijacking,
    EscapeBypass,
}

impl std::fmt::Display for PointerLockIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::ClickjackingRisk => write!(f, "clickjacking_risk"),
            Self::UiSpoofing => write!(f, "ui_spoofing"),
            Self::InputHijacking => write!(f, "input_hijacking"),
            Self::EscapeBypass => write!(f, "escape_bypass"),
        }
    }
}

pub fn audit_pointer_lock(target: &str) -> Vec<PointerLockIssue> {
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
    analyze_pointer_lock(&body)
}

pub fn analyze_pointer_lock(body: &str) -> Vec<PointerLockIssue> {
    let has_request = body.contains("requestPointerLock");
    let has_element = body.contains("pointerLockElement");
    let has_exit = body.contains("exitPointerLock");

    if !has_request && !has_element && !has_exit {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(PointerLockIssue::ApiDetected);

    if has_request
        && (body.contains("fullscreen") || body.contains("requestFullscreen"))
        && (body.contains("innerHTML") || body.contains("document.write") || body.contains("location"))
    {
        issues.push(PointerLockIssue::ClickjackingRisk);
    }

    if has_request
        && body.contains("cursor")
        && (body.contains("none") || body.contains("custom"))
        && (body.contains("position: fixed") || body.contains("position: absolute"))
    {
        issues.push(PointerLockIssue::UiSpoofing);
    }

    if has_element
        && (body.contains("mousemove") || body.contains("onmousemove"))
        && !has_exit
    {
        issues.push(PointerLockIssue::InputHijacking);
    }

    if has_request
        && body.contains("unadjustedMovement")
        && !body.contains("pointerlockerror")
    {
        issues.push(PointerLockIssue::EscapeBypass);
    }

    issues
}

pub fn pointer_lock_severity(issue: &PointerLockIssue) -> f64 {
    match issue {
        PointerLockIssue::ClickjackingRisk => 7.0,
        PointerLockIssue::UiSpoofing => 6.5,
        PointerLockIssue::InputHijacking => 6.0,
        PointerLockIssue::EscapeBypass => 5.5,
        PointerLockIssue::ApiDetected => 2.0,
    }
}

pub fn pointer_lock_to_operations(
    issues: &[PointerLockIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                pointer_lock_severity(issue),
                0.5,
            )
        })
        .collect()
}
