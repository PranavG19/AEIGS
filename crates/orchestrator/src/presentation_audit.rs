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
