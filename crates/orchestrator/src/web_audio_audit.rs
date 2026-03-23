use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebAudioIssue {
    ApiDetected,
    AudioFingerprinting,
    CryptoMining,
    DataExfiltration,
    ResourceExhaustion,
}

impl std::fmt::Display for WebAudioIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::AudioFingerprinting => write!(f, "audio_fingerprinting"),
            Self::CryptoMining => write!(f, "crypto_mining"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::ResourceExhaustion => write!(f, "resource_exhaustion"),
        }
    }
}

pub fn audit_web_audio(target: &str) -> Vec<WebAudioIssue> {
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
    analyze_web_audio(&body)
}

pub fn analyze_web_audio(body: &str) -> Vec<WebAudioIssue> {
    let has_api = body.contains("AudioContext")
        || body.contains("OfflineAudioContext")
        || body.contains("AudioWorklet")
        || body.contains("audioWorklet");

    if !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebAudioIssue::ApiDetected);

    if (body.contains("createOscillator")
        || body.contains("createDynamicsCompressor")
        || body.contains("createAnalyser"))
        && (body.contains("getFloatFrequencyData")
            || body.contains("getByteFrequencyData")
            || body.contains("getChannelData")
            || body.contains("toDataURL"))
    {
        issues.push(WebAudioIssue::AudioFingerprinting);
    }

    if (body.contains("AudioWorklet") || body.contains("audioWorklet"))
        && (body.contains("addModule") || body.contains("AudioWorkletProcessor"))
        && (body.contains("SharedArrayBuffer") || body.contains("Atomics") || body.contains("while"))
    {
        issues.push(WebAudioIssue::CryptoMining);
    }

    if (body.contains("MediaStreamDestination") || body.contains("createMediaStreamDestination"))
        && (body.contains("fetch(") || body.contains("WebSocket") || body.contains("sendBeacon"))
    {
        issues.push(WebAudioIssue::DataExfiltration);
    }

    if (body.contains("createScriptProcessor") || body.contains("onaudioprocess"))
        && !body.contains("disconnect")
        && !body.contains("close(")
    {
        issues.push(WebAudioIssue::ResourceExhaustion);
    }

    issues
}

pub fn web_audio_severity(issue: &WebAudioIssue) -> f64 {
    match issue {
        WebAudioIssue::CryptoMining => 7.5,
        WebAudioIssue::AudioFingerprinting => 7.0,
        WebAudioIssue::DataExfiltration => 6.5,
        WebAudioIssue::ResourceExhaustion => 6.0,
        WebAudioIssue::ApiDetected => 2.0,
    }
}

pub fn web_audio_to_operations(
    issues: &[WebAudioIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                web_audio_severity(issue),
                0.5,
            )
        })
        .collect()
}
