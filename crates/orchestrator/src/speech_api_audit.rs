use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum SpeechApiIssue {
    SpeechRecognitionUsage,
    ContinuousListening,
    SpeechDataExfiltration,
    SpeechSynthesisFingerprint,
    SpeechGrammarList,
    InterimResultsCapture,
}

impl std::fmt::Display for SpeechApiIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpeechRecognitionUsage => write!(f, "speech_recognition_usage"),
            Self::ContinuousListening => write!(f, "continuous_listening"),
            Self::SpeechDataExfiltration => write!(f, "speech_data_exfiltration"),
            Self::SpeechSynthesisFingerprint => write!(f, "speech_synthesis_fingerprint"),
            Self::SpeechGrammarList => write!(f, "speech_grammar_list"),
            Self::InterimResultsCapture => write!(f, "interim_results_capture"),
        }
    }
}

pub fn audit_speech_api(target: &str) -> Vec<SpeechApiIssue> {
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
    analyze_speech_api(&body)
}

pub fn analyze_speech_api(body: &str) -> Vec<SpeechApiIssue> {
    if !has_speech_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("SpeechRecognition") || body.contains("webkitSpeechRecognition") {
        issues.push(SpeechApiIssue::SpeechRecognitionUsage);
    }

    if body.contains("continuous")
        && body.contains("true")
        && (body.contains("SpeechRecognition") || body.contains("webkitSpeechRecognition"))
    {
        issues.push(SpeechApiIssue::ContinuousListening);
    }

    let has_speech = body.contains("SpeechRecognition") || body.contains("webkitSpeechRecognition");
    let sends = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains(".send(")
        || body.contains("sendBeacon");
    if has_speech && sends {
        issues.push(SpeechApiIssue::SpeechDataExfiltration);
    }

    if body.contains("speechSynthesis.getVoices")
        || body.contains("speechSynthesis.onvoiceschanged")
    {
        issues.push(SpeechApiIssue::SpeechSynthesisFingerprint);
    }

    if body.contains("SpeechGrammarList") || body.contains("webkitSpeechGrammarList") {
        issues.push(SpeechApiIssue::SpeechGrammarList);
    }

    if body.contains("interimResults")
        && (body.contains("SpeechRecognition") || body.contains("webkitSpeechRecognition"))
    {
        issues.push(SpeechApiIssue::InterimResultsCapture);
    }

    issues
}

fn has_speech_indicators(body: &str) -> bool {
    body.contains("SpeechRecognition")
        || body.contains("webkitSpeechRecognition")
        || body.contains("speechSynthesis")
        || body.contains("SpeechGrammarList")
        || body.contains("webkitSpeechGrammarList")
}

pub fn speech_api_severity(issue: &SpeechApiIssue) -> f64 {
    match issue {
        SpeechApiIssue::SpeechDataExfiltration => 8.0,
        SpeechApiIssue::ContinuousListening => 7.5,
        SpeechApiIssue::InterimResultsCapture => 7.0,
        SpeechApiIssue::SpeechRecognitionUsage => 6.0,
        SpeechApiIssue::SpeechGrammarList => 5.5,
        SpeechApiIssue::SpeechSynthesisFingerprint => 5.0,
    }
}

pub fn speech_api_to_operations(
    issues: &[SpeechApiIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                speech_api_severity(issue),
                0.7,
            )
        })
        .collect()
}
