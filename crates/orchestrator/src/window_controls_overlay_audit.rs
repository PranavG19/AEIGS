use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WindowControlsOverlayIssue {
    ApiDetected,
    UiSpoofing,
    ClickjackingRisk,
    GeometryTracking,
    DynamicTitlebar,
}

impl std::fmt::Display for WindowControlsOverlayIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::UiSpoofing => write!(f, "ui_spoofing"),
            Self::ClickjackingRisk => write!(f, "clickjacking_risk"),
            Self::GeometryTracking => write!(f, "geometry_tracking"),
            Self::DynamicTitlebar => write!(f, "dynamic_titlebar"),
        }
    }
}

pub fn audit_window_controls_overlay(target: &str) -> Vec<WindowControlsOverlayIssue> {
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
    analyze_window_controls_overlay(&body)
}

pub fn analyze_window_controls_overlay(body: &str) -> Vec<WindowControlsOverlayIssue> {
    let has_manifest = body.contains("window-controls-overlay");
    let has_api =
        body.contains("windowControlsOverlay") || body.contains("titlebarAreaRect");

    if !has_manifest && !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WindowControlsOverlayIssue::ApiDetected);

    if has_manifest
        && (body.contains("position: absolute") || body.contains("position: fixed"))
        && (body.contains("top: 0") || body.contains("top:0") || body.contains("env(titlebar-area"))
    {
        issues.push(WindowControlsOverlayIssue::UiSpoofing);
    }

    if has_api
        && (body.contains("pointer-events") || body.contains("z-index"))
        && (body.contains("titlebar") || body.contains("app-region"))
    {
        issues.push(WindowControlsOverlayIssue::ClickjackingRisk);
    }

    if has_api && body.contains("geometrychange") {
        issues.push(WindowControlsOverlayIssue::GeometryTracking);
    }

    if has_api
        && body.contains("titlebarAreaRect")
        && (body.contains("setInterval") || body.contains("requestAnimationFrame"))
    {
        issues.push(WindowControlsOverlayIssue::DynamicTitlebar);
    }

    issues
}

pub fn window_controls_overlay_severity(issue: &WindowControlsOverlayIssue) -> f64 {
    match issue {
        WindowControlsOverlayIssue::UiSpoofing => 7.5,
        WindowControlsOverlayIssue::ClickjackingRisk => 7.0,
        WindowControlsOverlayIssue::DynamicTitlebar => 5.5,
        WindowControlsOverlayIssue::GeometryTracking => 4.0,
        WindowControlsOverlayIssue::ApiDetected => 2.5,
    }
}

pub fn window_controls_overlay_to_operations(
    issues: &[WindowControlsOverlayIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                window_controls_overlay_severity(issue),
                0.55,
            )
        })
        .collect()
}
