use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Honeypot scoring and classification engine (v2).
///
/// Analyzes HTTP response characteristics to determine if the target
/// is a honeypot (Glastopf, Snare, Cowrie, etc.). Scores responses
/// on response time, error patterns, and known honeypot signatures.
/// Recommends abort when score exceeds 0.7.

/// Known honeypot products.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HoneypotProduct {
    Glastopf,
    Snare,
    Cowrie,
    Dionaea,
    Conpot,
    HoneyD,
    KippoKippo,
    ElasticHoney,
    Heralding,
    Unknown,
}

impl std::fmt::Display for HoneypotProduct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Glastopf => write!(f, "Glastopf"),
            Self::Snare => write!(f, "Snare/Tanner"),
            Self::Cowrie => write!(f, "Cowrie"),
            Self::Dionaea => write!(f, "Dionaea"),
            Self::Conpot => write!(f, "Conpot"),
            Self::HoneyD => write!(f, "HoneyD"),
            Self::KippoKippo => write!(f, "Kippo"),
            Self::ElasticHoney => write!(f, "ElasticHoney"),
            Self::Heralding => write!(f, "Heralding"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Response characteristic that contributes to honeypot scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HoneypotSignal {
    FastResponseTime,
    TooEasyVuln,
    KnownSignature,
    AnomalousHeaders,
    InconsistentBehavior,
    AllPortsOpen,
    GenericBanner,
    DefaultContent,
}

/// Individual scoring signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringSignal {
    pub signal_type: HoneypotSignal,
    pub weight: f64,
    pub evidence: String,
    pub matched_product: Option<HoneypotProduct>,
}

/// Action recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HoneypotAction {
    Proceed,
    Caution,
    Abort,
}

/// Aggregated honeypot scoring result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotScore {
    pub score: f64,
    pub action: HoneypotAction,
    pub signals: Vec<ScoringSignal>,
    pub suspected_product: Option<HoneypotProduct>,
    pub signal_breakdown: HashMap<HoneypotSignal, f64>,
}

/// HTTP response characteristics for analysis.
#[derive(Debug, Clone)]
pub struct ResponseProfile {
    pub response_time_ms: u64,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub body_length: usize,
    pub server_header: Option<String>,
    pub content_type: Option<String>,
    pub open_ports: Vec<u16>,
    pub banner: Option<String>,
}

/// Configuration for honeypot scoring.
#[derive(Debug, Clone)]
pub struct HoneypotScorerConfig {
    pub abort_threshold: f64,
    pub caution_threshold: f64,
    pub fast_response_threshold_ms: u64,
    pub too_easy_vuln_patterns: Vec<String>,
}

impl Default for HoneypotScorerConfig {
    fn default() -> Self {
        Self {
            abort_threshold: 0.7,
            caution_threshold: 0.4,
            fast_response_threshold_ms: 5,
            too_easy_vuln_patterns: vec![
                "root:x:0:0".to_string(),
                "/etc/passwd".to_string(),
                "admin:admin".to_string(),
                "SELECT * FROM users".to_string(),
            ],
        }
    }
}

/// Glastopf response signatures.
const GLASTOPF_SIGS: &[&str] = &[
    "glastopf",
    "blog/wp-content",
    "Unknown column '1' in 'order clause'",
    "BusyBox",
];

/// Snare/Tanner response signatures.
const SNARE_SIGS: &[&str] = &["snare", "tanner", "mushorg", "Server: nginx/snare"];

/// Cowrie SSH honeypot signatures.
const COWRIE_SIGS: &[&str] = &[
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
    "cowrie",
    "shell got killed",
];

/// Dionaea signatures.
const DIONAEA_SIGS: &[&str] = &["dionaea", "Microsoft-IIS/6.0"];

/// Conpot ICS/SCADA honeypot signatures.
const CONPOT_SIGS: &[&str] = &["conpot", "Siemens, SIMATIC"];

/// ElasticHoney signatures.
const ELASTICHONEY_SIGS: &[&str] = &["elastichoney", "\"cluster_name\" : \"elasticsearch\""];

/// Honeypot scoring engine.
pub struct HoneypotScorer {
    config: HoneypotScorerConfig,
}

impl HoneypotScorer {
    pub fn new(config: HoneypotScorerConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(HoneypotScorerConfig::default())
    }

    /// Score a response for honeypot indicators.
    pub fn score(&self, profile: &ResponseProfile) -> HoneypotScore {
        let mut signals = Vec::new();
        let mut signal_breakdown: HashMap<HoneypotSignal, f64> = HashMap::new();

        if profile.response_time_ms <= self.config.fast_response_threshold_ms {
            let weight = 0.2;
            signals.push(ScoringSignal {
                signal_type: HoneypotSignal::FastResponseTime,
                weight,
                evidence: format!(
                    "Response in {}ms (threshold: {}ms)",
                    profile.response_time_ms, self.config.fast_response_threshold_ms
                ),
                matched_product: None,
            });
            signal_breakdown.insert(HoneypotSignal::FastResponseTime, weight);
        }

        self.check_too_easy_vulns(profile, &mut signals, &mut signal_breakdown);
        self.check_known_signatures(profile, &mut signals, &mut signal_breakdown);
        self.check_anomalous_headers(profile, &mut signals, &mut signal_breakdown);
        self.check_all_ports_open(profile, &mut signals, &mut signal_breakdown);
        self.check_generic_banner(profile, &mut signals, &mut signal_breakdown);
        self.check_default_content(profile, &mut signals, &mut signal_breakdown);

        let score: f64 = signals.iter().map(|s| s.weight).sum::<f64>().min(1.0);

        let suspected_product = signals.iter().filter_map(|s| s.matched_product).next();

        let action = if score >= self.config.abort_threshold {
            HoneypotAction::Abort
        } else if score >= self.config.caution_threshold {
            HoneypotAction::Caution
        } else {
            HoneypotAction::Proceed
        };

        HoneypotScore {
            score,
            action,
            signals,
            suspected_product,
            signal_breakdown,
        }
    }

    /// Quick check: should we abort based on this response?
    pub fn should_abort(&self, profile: &ResponseProfile) -> bool {
        self.score(profile).score >= self.config.abort_threshold
    }

    fn check_too_easy_vulns(
        &self,
        profile: &ResponseProfile,
        signals: &mut Vec<ScoringSignal>,
        breakdown: &mut HashMap<HoneypotSignal, f64>,
    ) {
        let body_lower = profile.body.to_lowercase();
        for pattern in &self.config.too_easy_vuln_patterns {
            if body_lower.contains(&pattern.to_lowercase()) {
                let weight = 0.25;
                signals.push(ScoringSignal {
                    signal_type: HoneypotSignal::TooEasyVuln,
                    weight,
                    evidence: format!("Response contains too-easy vuln pattern: '{pattern}'"),
                    matched_product: None,
                });
                let existing = breakdown
                    .get(&HoneypotSignal::TooEasyVuln)
                    .copied()
                    .unwrap_or(0.0);
                breakdown.insert(HoneypotSignal::TooEasyVuln, (existing + weight).min(0.4));
                break;
            }
        }
    }

    fn check_known_signatures(
        &self,
        profile: &ResponseProfile,
        signals: &mut Vec<ScoringSignal>,
        breakdown: &mut HashMap<HoneypotSignal, f64>,
    ) {
        let combined = format!(
            "{} {} {}",
            profile.body,
            profile.server_header.as_deref().unwrap_or(""),
            profile.banner.as_deref().unwrap_or(""),
        )
        .to_lowercase();

        let signature_sets: &[(&[&str], HoneypotProduct)] = &[
            (GLASTOPF_SIGS, HoneypotProduct::Glastopf),
            (SNARE_SIGS, HoneypotProduct::Snare),
            (COWRIE_SIGS, HoneypotProduct::Cowrie),
            (DIONAEA_SIGS, HoneypotProduct::Dionaea),
            (CONPOT_SIGS, HoneypotProduct::Conpot),
            (ELASTICHONEY_SIGS, HoneypotProduct::ElasticHoney),
        ];

        for (sigs, product) in signature_sets {
            for sig in *sigs {
                if combined.contains(&sig.to_lowercase()) {
                    let weight = 0.4;
                    signals.push(ScoringSignal {
                        signal_type: HoneypotSignal::KnownSignature,
                        weight,
                        evidence: format!("Known {product} signature: '{sig}'"),
                        matched_product: Some(*product),
                    });
                    let existing = breakdown
                        .get(&HoneypotSignal::KnownSignature)
                        .copied()
                        .unwrap_or(0.0);
                    breakdown.insert(HoneypotSignal::KnownSignature, (existing + weight).min(0.5));
                    return;
                }
            }
        }
    }

    fn check_anomalous_headers(
        &self,
        profile: &ResponseProfile,
        signals: &mut Vec<ScoringSignal>,
        breakdown: &mut HashMap<HoneypotSignal, f64>,
    ) {
        if let Some(ref server) = profile.server_header {
            let server_lower = server.to_lowercase();
            if server_lower.contains("honeypot") || server_lower.contains("decoy") {
                let weight = 0.3;
                signals.push(ScoringSignal {
                    signal_type: HoneypotSignal::AnomalousHeaders,
                    weight,
                    evidence: format!("Server header contains honeypot indicator: {server}"),
                    matched_product: None,
                });
                breakdown.insert(HoneypotSignal::AnomalousHeaders, weight);
            }
        }
    }

    fn check_all_ports_open(
        &self,
        profile: &ResponseProfile,
        signals: &mut Vec<ScoringSignal>,
        breakdown: &mut HashMap<HoneypotSignal, f64>,
    ) {
        if profile.open_ports.len() > 20 {
            let weight = 0.25;
            signals.push(ScoringSignal {
                signal_type: HoneypotSignal::AllPortsOpen,
                weight,
                evidence: format!(
                    "{} ports open (suspiciously many)",
                    profile.open_ports.len()
                ),
                matched_product: None,
            });
            breakdown.insert(HoneypotSignal::AllPortsOpen, weight);
        }
    }

    fn check_generic_banner(
        &self,
        profile: &ResponseProfile,
        signals: &mut Vec<ScoringSignal>,
        breakdown: &mut HashMap<HoneypotSignal, f64>,
    ) {
        if let Some(ref banner) = profile.banner {
            let generic_banners = [
                "Welcome to Ubuntu",
                "Welcome to Debian",
                "Microsoft Windows [Version",
                "login:",
            ];
            let banner_lower = banner.to_lowercase();
            for gb in &generic_banners {
                if banner_lower.contains(&gb.to_lowercase()) {
                    let weight = 0.1;
                    signals.push(ScoringSignal {
                        signal_type: HoneypotSignal::GenericBanner,
                        weight,
                        evidence: format!("Generic banner: '{banner}'"),
                        matched_product: None,
                    });
                    breakdown.insert(HoneypotSignal::GenericBanner, weight);
                    break;
                }
            }
        }
    }

    fn check_default_content(
        &self,
        profile: &ResponseProfile,
        signals: &mut Vec<ScoringSignal>,
        breakdown: &mut HashMap<HoneypotSignal, f64>,
    ) {
        let default_pages = [
            "it works!",
            "welcome to nginx",
            "apache2 default page",
            "iis windows server",
            "test page for the",
        ];
        let body_lower = profile.body.to_lowercase();
        for page in &default_pages {
            if body_lower.contains(page) {
                let weight = 0.15;
                signals.push(ScoringSignal {
                    signal_type: HoneypotSignal::DefaultContent,
                    weight,
                    evidence: format!("Default page content: '{page}'"),
                    matched_product: None,
                });
                breakdown.insert(HoneypotSignal::DefaultContent, weight);
                break;
            }
        }
    }
}
