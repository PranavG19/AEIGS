use crate::defense_profile::BotDetectionProfile;
use regex::Regex;
use std::sync::LazyLock;

/// Response from a single bot-detection probe request.
/// Captures whether browser headers were sent and whether the request was rapid,
/// along with the response status and body for challenge detection.
#[derive(Debug, Clone)]
pub struct BotProbeResult {
    pub headers_sent: bool,
    pub response_status: u16,
    pub response_body_snippet: String,
    pub rapid_request: bool,
}

/// How the target detects bots: JavaScript challenges, CAPTCHAs, header analysis,
/// behavioral rate patterns, or unknown. Serialized into `BotDetectionProfile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionMethod {
    JavaScriptChallenge,
    Captcha,
    HeaderAnalysis,
    Behavioral,
    Unknown,
}

impl std::fmt::Display for DetectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::JavaScriptChallenge => "javascript_challenge",
            Self::Captcha => "captcha",
            Self::HeaderAnalysis => "header_analysis",
            Self::Behavioral => "behavioral",
            Self::Unknown => "unknown",
        };
        write!(f, "{label}")
    }
}

static CHALLENGE_SCRIPT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)<script[^>]*>.*?(challenge|verify|check|proof[\-_]?of[\-_]?work|turnstile|__cf).*?</script>").unwrap()
});

static CAPTCHA_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(recaptcha|hcaptcha|cf-turnstile|g-recaptcha|h-captcha|captcha[\-_]?container)",
    )
    .unwrap()
});

pub fn detect_challenge_type(body: &str) -> DetectionMethod {
    if CAPTCHA_RE.is_match(body) {
        return DetectionMethod::Captcha;
    }
    if CHALLENGE_SCRIPT_RE.is_match(body) {
        return DetectionMethod::JavaScriptChallenge;
    }
    DetectionMethod::Unknown
}

pub fn is_challenge_response(status: u16, body: &str) -> bool {
    let challenge_status = matches!(status, 403 | 429 | 503);
    if !challenge_status {
        return false;
    }
    has_challenge_patterns(body)
}

fn has_challenge_patterns(body: &str) -> bool {
    CHALLENGE_SCRIPT_RE.is_match(body) || CAPTCHA_RE.is_match(body)
}

pub fn analyze_bot_detection(
    no_headers_result: &BotProbeResult,
    with_headers_result: &BotProbeResult,
    rapid_results: &[BotProbeResult],
) -> Option<BotDetectionProfile> {
    let no_headers_blocked = is_challenge_response(
        no_headers_result.response_status,
        &no_headers_result.response_body_snippet,
    );
    let with_headers_blocked = is_challenge_response(
        with_headers_result.response_status,
        &with_headers_result.response_body_snippet,
    );

    if no_headers_blocked && !with_headers_blocked {
        return Some(build_profile(
            DetectionMethod::HeaderAnalysis,
            Some(no_headers_result.response_status),
        ));
    }

    if no_headers_blocked && with_headers_blocked {
        let method = detect_challenge_type(&with_headers_result.response_body_snippet);
        return Some(build_profile(
            method,
            Some(with_headers_result.response_status),
        ));
    }

    if let Some(behavioral) = detect_behavioral(rapid_results) {
        return Some(behavioral);
    }

    None
}

fn detect_behavioral(rapid_results: &[BotProbeResult]) -> Option<BotDetectionProfile> {
    for result in rapid_results {
        if is_challenge_response(result.response_status, &result.response_body_snippet) {
            return Some(build_profile(
                DetectionMethod::Behavioral,
                Some(result.response_status),
            ));
        }
    }
    None
}

fn build_profile(method: DetectionMethod, challenge_code: Option<u16>) -> BotDetectionProfile {
    BotDetectionProfile {
        detected: true,
        detection_method: method.to_string(),
        challenge_response_code: challenge_code,
    }
}

#[cfg(test)]
#[path = "bot_detection_probe_test.rs"]
mod bot_detection_probe_test;
