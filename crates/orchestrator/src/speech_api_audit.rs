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

#[derive(Debug, Clone, PartialEq)]
pub enum SpeechApiSecurityIssue {
    SpeechRecognitionEavesdropping,
    SpeechDataExfiltration,
    SpeechWithoutPermission,
    SpeechInBackground,
    SpeechCrossOrigin,
    SpeechSynthesisPhishing,
    SpeechPersistence,
    ContinuousSpeechRecognition,
    SpeechWithGeolocation,
    SpeechInIframe,
}

impl std::fmt::Display for SpeechApiSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpeechRecognitionEavesdropping => write!(f, "speech_recognition_eavesdropping"),
            Self::SpeechDataExfiltration => write!(f, "speech_data_exfiltration"),
            Self::SpeechWithoutPermission => write!(f, "speech_without_permission"),
            Self::SpeechInBackground => write!(f, "speech_in_background"),
            Self::SpeechCrossOrigin => write!(f, "speech_cross_origin"),
            Self::SpeechSynthesisPhishing => write!(f, "speech_synthesis_phishing"),
            Self::SpeechPersistence => write!(f, "speech_persistence"),
            Self::ContinuousSpeechRecognition => write!(f, "continuous_speech_recognition"),
            Self::SpeechWithGeolocation => write!(f, "speech_with_geolocation"),
            Self::SpeechInIframe => write!(f, "speech_in_iframe"),
        }
    }
}

pub fn analyze_speech_api_security(body: &str) -> Vec<SpeechApiSecurityIssue> {
    if !has_speech_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // SpeechRecognitionEavesdropping: continuous speech recognition without indication
    let has_indicator = body.to_ascii_lowercase().contains("indicator")
        || body.to_ascii_lowercase().contains("recording")
        || body.to_ascii_lowercase().contains("listening-icon");
    if (body.contains("SpeechRecognition") || body.contains("webkitSpeechRecognition"))
        && body.contains("continuous")
        && body.contains("true")
        && !has_indicator
    {
        issues.push(SpeechApiSecurityIssue::SpeechRecognitionEavesdropping);
    }

    // SpeechDataExfiltration: sending recognized speech to external endpoint
    let has_speech = body.contains("SpeechRecognition") || body.contains("webkitSpeechRecognition");
    let has_result_handler = body.contains("onresult") || body.contains("addEventListener");
    let sends_data = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains(".send(")
        || body.contains("sendBeacon")
        || body.contains("postMessage");
    if has_speech && has_result_handler && sends_data {
        issues.push(SpeechApiSecurityIssue::SpeechDataExfiltration);
    }

    // SpeechWithoutPermission: using speech API without microphone permission check
    if (body.contains("SpeechRecognition") || body.contains("webkitSpeechRecognition"))
        && body.contains("start(")
        && !body.contains("navigator.permissions")
        && !body.contains("getUserMedia")
        && !body.contains("checkPermission")
    {
        issues.push(SpeechApiSecurityIssue::SpeechWithoutPermission);
    }

    // SpeechInBackground: speech recognition when page is hidden
    if (body.contains("SpeechRecognition") || body.contains("webkitSpeechRecognition"))
        && (body.contains("document.hidden") || body.contains("visibilityState"))
        && !body.contains("stop()")
        && body.contains("start(")
    {
        issues.push(SpeechApiSecurityIssue::SpeechInBackground);
    }

    // SpeechCrossOrigin: speech data shared cross-origin
    if (body.contains("SpeechRecognition") || body.contains("webkitSpeechRecognition"))
        && (body.contains("postMessage")
            || body.contains("parent.")
            || body.contains("window.opener")
            || body.contains("crossOrigin"))
    {
        issues.push(SpeechApiSecurityIssue::SpeechCrossOrigin);
    }

    // SpeechSynthesisPhishing: using TTS for social engineering/phishing
    if body.contains("speechSynthesis.speak")
        && (body.contains("alert") || body.contains("confirm") || body.contains("password"))
    {
        issues.push(SpeechApiSecurityIssue::SpeechSynthesisPhishing);
    }

    // SpeechPersistence: storing speech recognition results
    if (body.contains("SpeechRecognition") || body.contains("webkitSpeechRecognition"))
        && body.contains("onresult")
        && (body.contains("localStorage")
            || body.contains("sessionStorage")
            || body.contains("indexedDB")
            || body.contains("setItem"))
    {
        issues.push(SpeechApiSecurityIssue::SpeechPersistence);
    }

    // ContinuousSpeechRecognition: always-on speech monitoring
    if (body.contains("SpeechRecognition") || body.contains("webkitSpeechRecognition"))
        && body.contains("continuous")
        && body.contains("true")
        && body.contains("onerror")
        && body.contains("start()")
    {
        issues.push(SpeechApiSecurityIssue::ContinuousSpeechRecognition);
    }

    // SpeechWithGeolocation: combining speech with location data
    if (body.contains("SpeechRecognition") || body.contains("webkitSpeechRecognition"))
        && (body.contains("navigator.geolocation")
            || body.contains("getCurrentPosition")
            || body.contains("watchPosition"))
    {
        issues.push(SpeechApiSecurityIssue::SpeechWithGeolocation);
    }

    // SpeechInIframe: speech recognition from iframe context
    if (body.contains("SpeechRecognition") || body.contains("webkitSpeechRecognition"))
        && (body.contains("<iframe") || body.contains("contentWindow") || body.contains("frames["))
    {
        issues.push(SpeechApiSecurityIssue::SpeechInIframe);
    }

    issues
}

pub fn speech_api_security_severity(issue: &SpeechApiSecurityIssue) -> f64 {
    match issue {
        SpeechApiSecurityIssue::SpeechRecognitionEavesdropping => 9.0,
        SpeechApiSecurityIssue::SpeechDataExfiltration => 8.5,
        SpeechApiSecurityIssue::SpeechPersistence => 8.0,
        SpeechApiSecurityIssue::ContinuousSpeechRecognition => 7.5,
        SpeechApiSecurityIssue::SpeechWithGeolocation => 7.5,
        SpeechApiSecurityIssue::SpeechCrossOrigin => 7.0,
        SpeechApiSecurityIssue::SpeechWithoutPermission => 6.5,
        SpeechApiSecurityIssue::SpeechInBackground => 6.5,
        SpeechApiSecurityIssue::SpeechSynthesisPhishing => 6.0,
        SpeechApiSecurityIssue::SpeechInIframe => 5.5,
    }
}

pub fn speech_api_security_to_operations(
    issues: &[SpeechApiSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                speech_api_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
