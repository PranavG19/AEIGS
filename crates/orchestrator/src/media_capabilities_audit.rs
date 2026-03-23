use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum MediaCapabilitiesIssue {
    ApiDetected,
    CodecFingerprinting,
    HardwareFingerprinting,
    PerformanceProbing,
    DataExfiltration,
}

impl std::fmt::Display for MediaCapabilitiesIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::CodecFingerprinting => write!(f, "codec_fingerprinting"),
            Self::HardwareFingerprinting => write!(f, "hardware_fingerprinting"),
            Self::PerformanceProbing => write!(f, "performance_probing"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
        }
    }
}

pub fn audit_media_capabilities(target: &str) -> Vec<MediaCapabilitiesIssue> {
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
    analyze_media_capabilities(&body)
}

pub fn analyze_media_capabilities(body: &str) -> Vec<MediaCapabilitiesIssue> {
    let has_api = body.contains("mediaCapabilities")
        || body.contains("decodingInfo")
        || body.contains("encodingInfo");

    if !has_api {
        return Vec::new();
    }

    let mut issues = vec![MediaCapabilitiesIssue::ApiDetected];

    let has_codec_terms = body.contains("codec")
        || body.contains("codecs")
        || body.contains("MediaDecodingConfiguration");
    let has_context_terms = body.contains("navigator.") || body.contains("screen.");
    let codec_count = body.matches("codec").count() + body.matches("codecs").count();
    if has_codec_terms && (has_context_terms || codec_count > 1) {
        issues.push(MediaCapabilitiesIssue::CodecFingerprinting);
    }

    let has_hardware_terms = body.contains("powerEfficient")
        || body.contains("hardwareAcceleration")
        || body.contains("gpu");
    if has_hardware_terms {
        issues.push(MediaCapabilitiesIssue::HardwareFingerprinting);
    }

    let has_perf_support =
        body.contains("smooth") || body.contains("supported") || body.contains("performance");
    let has_perf_measure =
        body.contains("measure") || body.contains("timing") || body.contains("benchmark");
    if has_perf_support && has_perf_measure {
        issues.push(MediaCapabilitiesIssue::PerformanceProbing);
    }

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(MediaCapabilitiesIssue::DataExfiltration);
    }

    issues
}

pub fn media_capabilities_severity(issue: &MediaCapabilitiesIssue) -> f64 {
    match issue {
        MediaCapabilitiesIssue::ApiDetected => 2.0,
        MediaCapabilitiesIssue::CodecFingerprinting => 7.0,
        MediaCapabilitiesIssue::HardwareFingerprinting => 7.5,
        MediaCapabilitiesIssue::PerformanceProbing => 6.0,
        MediaCapabilitiesIssue::DataExfiltration => 6.5,
    }
}

pub fn media_capabilities_to_operations(
    issues: &[MediaCapabilitiesIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                media_capabilities_severity(issue),
                0.5,
            )
        })
        .collect()
}
