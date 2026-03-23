use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebMidiIssue {
    ApiDetected,
    SysexAccess,
    DeviceFingerprinting,
    DataExfiltration,
    NoUserActivation,
}

impl std::fmt::Display for WebMidiIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::SysexAccess => write!(f, "sysex_access"),
            Self::DeviceFingerprinting => write!(f, "device_fingerprinting"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
        }
    }
}

pub fn audit_web_midi(target: &str) -> Vec<WebMidiIssue> {
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
    analyze_web_midi(&body)
}

pub fn analyze_web_midi(body: &str) -> Vec<WebMidiIssue> {
    let has_api = body.contains("requestMIDIAccess")
        || body.contains("MIDIAccess")
        || body.contains("MIDIInput")
        || body.contains("MIDIOutput");

    if !has_api {
        return Vec::new();
    }

    let mut issues = vec![WebMidiIssue::ApiDetected];

    if has_api && body.contains("sysex") && body.contains("true") {
        issues.push(WebMidiIssue::SysexAccess);
    }

    let has_device_enum = (body.contains("inputs") || body.contains("outputs"))
        && (body.contains("forEach")
            || body.contains("entries")
            || body.contains("values")
            || body.contains("size"));
    if has_api && has_device_enum {
        issues.push(WebMidiIssue::DeviceFingerprinting);
    }

    let has_midi_event = body.contains("onmidimessage") || body.contains("midimessage");
    let has_network =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_api && has_midi_event && has_network {
        issues.push(WebMidiIssue::DataExfiltration);
    }

    let has_user_gesture = body.contains("click")
        || body.contains("keydown")
        || body.contains("pointerdown")
        || body.contains("touchstart");
    if has_api && !has_user_gesture {
        issues.push(WebMidiIssue::NoUserActivation);
    }

    issues
}

pub fn web_midi_severity(issue: &WebMidiIssue) -> f64 {
    match issue {
        WebMidiIssue::ApiDetected => 2.0,
        WebMidiIssue::SysexAccess => 8.0,
        WebMidiIssue::DeviceFingerprinting => 7.0,
        WebMidiIssue::DataExfiltration => 7.5,
        WebMidiIssue::NoUserActivation => 5.5,
    }
}

pub fn web_midi_to_operations(issues: &[WebMidiIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                web_midi_severity(issue),
                0.5,
            )
        })
        .collect()
}
