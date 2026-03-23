use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum AudioWorkletIssue {
    ApiDetected,
    CryptoMining,
    SideChannelTiming,
    ResourceExhaustion,
    DataExfiltration,
}

impl std::fmt::Display for AudioWorkletIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::CryptoMining => write!(f, "crypto_mining"),
            Self::SideChannelTiming => write!(f, "side_channel_timing"),
            Self::ResourceExhaustion => write!(f, "resource_exhaustion"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
        }
    }
}

pub fn audit_audio_worklet(target: &str) -> Vec<AudioWorkletIssue> {
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
    analyze_audio_worklet(&body)
}

pub fn analyze_audio_worklet(body: &str) -> Vec<AudioWorkletIssue> {
    let has_api = body.contains("audioWorklet")
        || body.contains("AudioWorkletNode")
        || body.contains("AudioWorkletProcessor");

    if !has_api {
        return Vec::new();
    }

    let mut issues = vec![AudioWorkletIssue::ApiDetected];

    let has_crypto_indicators = body.contains("crypto")
        || body.contains("hash")
        || body.contains("nonce")
        || body.contains("mining")
        || body.contains("sha256");
    if has_crypto_indicators {
        issues.push(AudioWorkletIssue::CryptoMining);
    }

    let has_timing_functions = body.contains("performance.now") || body.contains("currentTime");
    let has_timing_operations =
        body.contains("measure") || body.contains("timing") || body.contains("duration");
    if has_timing_functions && has_timing_operations {
        issues.push(AudioWorkletIssue::SideChannelTiming);
    }

    let has_loop =
        body.contains("while(true)") || body.contains("for(;;)") || body.contains("setInterval");
    let has_control =
        body.contains("cancel") || body.contains("close") || body.contains("terminate");
    if has_loop && !has_control {
        issues.push(AudioWorkletIssue::ResourceExhaustion);
    }

    let has_message = body.contains("port.postMessage") || body.contains("MessagePort");
    let has_network =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_message && has_network {
        issues.push(AudioWorkletIssue::DataExfiltration);
    }

    issues
}

pub fn audio_worklet_severity(issue: &AudioWorkletIssue) -> f64 {
    match issue {
        AudioWorkletIssue::ApiDetected => 2.0,
        AudioWorkletIssue::CryptoMining => 8.0,
        AudioWorkletIssue::SideChannelTiming => 7.0,
        AudioWorkletIssue::ResourceExhaustion => 6.5,
        AudioWorkletIssue::DataExfiltration => 7.5,
    }
}

pub fn audio_worklet_to_operations(
    issues: &[AudioWorkletIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                audio_worklet_severity(issue),
                0.5,
            )
        })
        .collect()
}
