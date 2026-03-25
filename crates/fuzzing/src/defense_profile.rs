use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};

/// Classification of a detected defense mechanism on the target.
/// Returned by `DefenseProfile::defense_types()` for downstream strategy selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DefenseType {
    Waf,
    RateLimiter,
    BotDetection,
    TlsTermination,
    None,
}

/// Identified WAF vendor based on response header and body fingerprinting.
/// `Unknown` is the default when no vendor-specific signatures match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WafVendor {
    ModSecurity,
    Cloudflare,
    AwsWaf,
    Imperva,
    Akamai,
    Unknown,
}

/// Observed rate-limiting behavior: threshold RPS, burst allowance, and recovery window.
/// Built by `rate_limit_detector::build_rate_limit_profile()` from probe results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitProfile {
    pub requests_per_second: Option<f64>,
    pub burst_allowance: Option<u32>,
    pub limit_response_code: u16,
    pub limit_window_seconds: Option<u32>,
}

/// Fingerprinted WAF configuration: vendor, paranoia level, and which vulnerability
/// classes are blocked. Built by `waf_fingerprinter::build_waf_profile()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafProfile {
    pub vendor: WafVendor,
    pub paranoia_level: Option<u8>,
    pub blocked_response_code: u16,
    pub blocked_categories: Vec<VulnerabilityClass>,
}

/// Result of bot-detection probing: whether detection is present, the method used
/// (JS challenge, CAPTCHA, header analysis, behavioral), and the challenge status code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotDetectionProfile {
    pub detected: bool,
    pub detection_method: String,
    pub challenge_response_code: Option<u16>,
}

/// Aggregated defense fingerprint for a target: WAF, rate limiting, and bot detection.
/// Constructed via builder methods (`with_waf`, `with_rate_limit`, `with_bot_detection`)
/// starting from `DefenseProfile::empty(timestamp_ms)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseProfile {
    pub waf: Option<WafProfile>,
    pub rate_limit: Option<RateLimitProfile>,
    pub bot_detection: Option<BotDetectionProfile>,
    pub fingerprint_timestamp_ms: u64,
}

impl DefenseProfile {
    pub fn empty(timestamp_ms: u64) -> Self {
        Self {
            waf: None,
            rate_limit: None,
            bot_detection: None,
            fingerprint_timestamp_ms: timestamp_ms,
        }
    }

    pub fn with_waf(mut self, waf: WafProfile) -> Self {
        self.waf = Some(waf);
        self
    }

    pub fn with_rate_limit(mut self, rate_limit: RateLimitProfile) -> Self {
        self.rate_limit = Some(rate_limit);
        self
    }

    pub fn with_bot_detection(mut self, bot_detection: BotDetectionProfile) -> Self {
        self.bot_detection = Some(bot_detection);
        self
    }

    pub fn defense_types(&self) -> Vec<DefenseType> {
        let mut types = Vec::new();
        if self.waf.is_some() {
            types.push(DefenseType::Waf);
        }
        if self.rate_limit.is_some() {
            types.push(DefenseType::RateLimiter);
        }
        if self.bot_detection.is_some() {
            types.push(DefenseType::BotDetection);
        }
        if types.is_empty() {
            types.push(DefenseType::None);
        }
        types
    }
}
