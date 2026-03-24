use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum PresentationIssue {
    ApiDetected,
    DataExfiltration,
    CrossOriginUrl,
    NoAvailabilityCheck,
    MessageChannel,
    AutoReconnect,
}

impl std::fmt::Display for PresentationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::CrossOriginUrl => write!(f, "cross_origin_url"),
            Self::NoAvailabilityCheck => write!(f, "no_availability_check"),
            Self::MessageChannel => write!(f, "message_channel"),
            Self::AutoReconnect => write!(f, "auto_reconnect"),
        }
    }
}

pub fn audit_presentation(target: &str) -> Vec<PresentationIssue> {
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
    analyze_presentation(&body)
}

pub fn analyze_presentation(body: &str) -> Vec<PresentationIssue> {
    if !body.contains("PresentationRequest") && !body.contains("PresentationConnection") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(PresentationIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(PresentationIssue::DataExfiltration);
    }

    if body.contains("http://") && body.contains("PresentationRequest(") {
        issues.push(PresentationIssue::CrossOriginUrl);
    }

    if body.contains("PresentationRequest") && !body.contains("getAvailability") {
        issues.push(PresentationIssue::NoAvailabilityCheck);
    }

    if body.contains(".send(") && body.contains("onmessage") {
        issues.push(PresentationIssue::MessageChannel);
    }

    if body.contains("reconnect") || body.contains("connectionavailable") {
        issues.push(PresentationIssue::AutoReconnect);
    }

    issues
}

pub fn presentation_severity(issue: &PresentationIssue) -> f64 {
    match issue {
        PresentationIssue::DataExfiltration => 6.5,
        PresentationIssue::CrossOriginUrl => 6.0,
        PresentationIssue::MessageChannel => 5.5,
        PresentationIssue::AutoReconnect => 5.0,
        PresentationIssue::NoAvailabilityCheck => 4.0,
        PresentationIssue::ApiDetected => 3.0,
    }
}

pub fn presentation_to_operations(
    issues: &[PresentationIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                presentation_severity(issue),
                0.6,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum PresentationSecurityIssue {
    PresentationDataExfiltration,
    PresentationCrossOrigin,
    PresentationSessionHijack,
    PresentationWithoutConsent,
    PresentationScreenCapture,
    PresentationPersistence,
    PresentationInBackground,
    PresentationChannelAbuse,
    PresentationDeviceEnumeration,
    PresentationContentInjection,
}

impl std::fmt::Display for PresentationSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PresentationDataExfiltration => write!(f, "presentation_data_exfiltration"),
            Self::PresentationCrossOrigin => write!(f, "presentation_cross_origin"),
            Self::PresentationSessionHijack => write!(f, "presentation_session_hijack"),
            Self::PresentationWithoutConsent => write!(f, "presentation_without_consent"),
            Self::PresentationScreenCapture => write!(f, "presentation_screen_capture"),
            Self::PresentationPersistence => write!(f, "presentation_persistence"),
            Self::PresentationInBackground => write!(f, "presentation_in_background"),
            Self::PresentationChannelAbuse => write!(f, "presentation_channel_abuse"),
            Self::PresentationDeviceEnumeration => write!(f, "presentation_device_enumeration"),
            Self::PresentationContentInjection => write!(f, "presentation_content_injection"),
        }
    }
}

pub fn analyze_presentation_security(body: &str) -> Vec<PresentationSecurityIssue> {
    if !body.contains("PresentationRequest") && !body.contains("PresentationConnection") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if (body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest"))
        && (body.contains("connection.send") || body.contains("conn.send"))
    {
        issues.push(PresentationSecurityIssue::PresentationDataExfiltration);
    }

    if body.contains("postMessage") && body.contains("PresentationConnection") {
        issues.push(PresentationSecurityIssue::PresentationCrossOrigin);
    }

    if body.contains("connection.id") && body.contains("localStorage") {
        issues.push(PresentationSecurityIssue::PresentationSessionHijack);
    }

    if body.contains("PresentationRequest")
        && (body.contains(".start()") || body.contains(".start("))
        && !body.contains("user activation")
        && !body.contains("click")
        && !body.contains("addEventListener")
    {
        issues.push(PresentationSecurityIssue::PresentationWithoutConsent);
    }

    if body.contains("getDisplayMedia") && body.contains("PresentationRequest") {
        issues.push(PresentationSecurityIssue::PresentationScreenCapture);
    }

    if (body.contains("sessionStorage") || body.contains("indexedDB"))
        && (body.contains("connection.id") || body.contains("presentation.id"))
    {
        issues.push(PresentationSecurityIssue::PresentationPersistence);
    }

    if body.contains("visibilityState")
        && body.contains("hidden")
        && body.contains("PresentationConnection")
    {
        issues.push(PresentationSecurityIssue::PresentationInBackground);
    }

    if body.contains("MessageChannel") && body.contains("PresentationConnection") {
        issues.push(PresentationSecurityIssue::PresentationChannelAbuse);
    }

    if body.contains("getAvailability") && body.contains("monitor") {
        issues.push(PresentationSecurityIssue::PresentationDeviceEnumeration);
    }

    if (body.contains("connection.send") || body.contains("conn.send"))
        && ((body.contains("send(\"<script") || body.contains("send('<script"))
            || (body.contains("send(payload") && body.contains("\"<script"))
            || (body.contains("send(payload") && body.contains("'<script")))
    {
        issues.push(PresentationSecurityIssue::PresentationContentInjection);
    }

    issues
}

pub fn presentation_security_severity(issue: &PresentationSecurityIssue) -> f64 {
    match issue {
        PresentationSecurityIssue::PresentationContentInjection => 9.0,
        PresentationSecurityIssue::PresentationSessionHijack => 8.5,
        PresentationSecurityIssue::PresentationDataExfiltration => 8.0,
        PresentationSecurityIssue::PresentationScreenCapture => 7.5,
        PresentationSecurityIssue::PresentationCrossOrigin => 7.0,
        PresentationSecurityIssue::PresentationChannelAbuse => 6.5,
        PresentationSecurityIssue::PresentationPersistence => 6.0,
        PresentationSecurityIssue::PresentationInBackground => 5.5,
        PresentationSecurityIssue::PresentationWithoutConsent => 5.0,
        PresentationSecurityIssue::PresentationDeviceEnumeration => 3.0,
    }
}

pub fn presentation_security_to_operations(
    issues: &[PresentationSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                presentation_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
