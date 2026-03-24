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
        if tag.contains("viewport")
            && let Some(ci) = tag.find("content=")
        {
            let rest = &tag[ci + 8..];
            let rest = rest.trim_start_matches(['"', '\'']);
            let end_q = rest.find(['"', '\'', '>']).unwrap_or(rest.len());
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
    if val.is_empty() { None } else { Some(val) }
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

pub fn viewport_to_operations(issues: &[ViewportIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
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

#[derive(Debug, Clone, PartialEq)]
pub enum ViewportSecurityIssue {
    ViewportExfiltration,
    ViewportFingerprinting,
    ViewportPhishingRisk,
    ViewportTrackingPersistence,
    ViewportCrossOrigin,
    ViewportKeyloggerRisk,
    ViewportClickjacking,
    ViewportScreenCapture,
    ViewportOrientationTracking,
    ViewportResizeSpying,
}

impl std::fmt::Display for ViewportSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ViewportExfiltration => write!(f, "viewport_exfiltration"),
            Self::ViewportFingerprinting => write!(f, "viewport_fingerprinting"),
            Self::ViewportPhishingRisk => write!(f, "viewport_phishing_risk"),
            Self::ViewportTrackingPersistence => write!(f, "viewport_tracking_persistence"),
            Self::ViewportCrossOrigin => write!(f, "viewport_cross_origin"),
            Self::ViewportKeyloggerRisk => write!(f, "viewport_keylogger_risk"),
            Self::ViewportClickjacking => write!(f, "viewport_clickjacking"),
            Self::ViewportScreenCapture => write!(f, "viewport_screen_capture"),
            Self::ViewportOrientationTracking => write!(f, "viewport_orientation_tracking"),
            Self::ViewportResizeSpying => write!(f, "viewport_resize_spying"),
        }
    }
}

pub fn analyze_viewport_security(body: &str) -> Vec<ViewportSecurityIssue> {
    let lower = body.to_ascii_lowercase();
    if !lower.contains("viewport")
        && !lower.contains("innerwidth")
        && !lower.contains("innerheight")
        && !lower.contains("screen.width")
    {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if (lower.contains("viewport") || lower.contains("innerwidth") || lower.contains("innerheight"))
        && (lower.contains("fetch(")
            || lower.contains("xmlhttprequest")
            || lower.contains("sendbeacon"))
    {
        issues.push(ViewportSecurityIssue::ViewportExfiltration);
    }

    if (lower.contains("viewport")
        || lower.contains("innerwidth")
        || lower.contains("innerheight")
        || lower.contains("screen.width")
        || lower.contains("screen.height"))
        && (lower.contains("useragent") || lower.contains("navigator"))
    {
        issues.push(ViewportSecurityIssue::ViewportFingerprinting);
    }

    if (lower.contains("viewport") || lower.contains("innerwidth") || lower.contains("innerheight"))
        && (lower.contains("position:") || lower.contains("z-index") || lower.contains("overlay"))
    {
        issues.push(ViewportSecurityIssue::ViewportPhishingRisk);
    }

    if (lower.contains("viewport") || lower.contains("innerwidth") || lower.contains("innerheight"))
        && (lower.contains("localstorage") || lower.contains("sessionstorage"))
    {
        issues.push(ViewportSecurityIssue::ViewportTrackingPersistence);
    }

    if (lower.contains("viewport") || lower.contains("innerwidth") || lower.contains("innerheight"))
        && lower.contains("postmessage")
    {
        issues.push(ViewportSecurityIssue::ViewportCrossOrigin);
    }

    if (lower.contains("viewport") || lower.contains("innerwidth") || lower.contains("innerheight"))
        && (lower.contains("keydown") || lower.contains("keypress") || lower.contains("keyup"))
    {
        issues.push(ViewportSecurityIssue::ViewportKeyloggerRisk);
    }

    if (lower.contains("viewport") || lower.contains("innerwidth") || lower.contains("innerheight"))
        && (lower.contains("iframe")
            || lower.contains("opacity")
            || lower.contains("pointer-events"))
    {
        issues.push(ViewportSecurityIssue::ViewportClickjacking);
    }

    if (lower.contains("viewport") || lower.contains("screen.width"))
        && (lower.contains("getdisplaymedia") || lower.contains("capturestream"))
    {
        issues.push(ViewportSecurityIssue::ViewportScreenCapture);
    }

    if lower.contains("screen.orientation") && lower.contains("addeventlistener") {
        issues.push(ViewportSecurityIssue::ViewportOrientationTracking);
    }

    if (lower.contains("viewport") || lower.contains("innerwidth") || lower.contains("innerheight"))
        && lower.contains("resizeobserver")
    {
        issues.push(ViewportSecurityIssue::ViewportResizeSpying);
    }

    issues
}

pub fn viewport_security_severity(issue: &ViewportSecurityIssue) -> f64 {
    match issue {
        ViewportSecurityIssue::ViewportExfiltration => 7.5,
        ViewportSecurityIssue::ViewportKeyloggerRisk => 7.0,
        ViewportSecurityIssue::ViewportClickjacking => 6.5,
        ViewportSecurityIssue::ViewportScreenCapture => 6.5,
        ViewportSecurityIssue::ViewportFingerprinting => 6.0,
        ViewportSecurityIssue::ViewportPhishingRisk => 6.0,
        ViewportSecurityIssue::ViewportCrossOrigin => 5.5,
        ViewportSecurityIssue::ViewportTrackingPersistence => 5.0,
        ViewportSecurityIssue::ViewportOrientationTracking => 4.5,
        ViewportSecurityIssue::ViewportResizeSpying => 4.0,
    }
}

pub fn viewport_security_to_operations(
    issues: &[ViewportSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                viewport_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
