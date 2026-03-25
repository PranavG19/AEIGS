use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Known WAF vendors with fingerprinting signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WafVendor {
    Cloudflare,
    Akamai,
    AwsWaf,
    ModSecurity,
    Imperva,
    F5BigIp,
    Barracuda,
    Sucuri,
    Wordfence,
    AzureFrontDoor,
    Fastly,
    StackPath,
    DenyAll,
    FortiWeb,
    Radware,
    SonicWall,
    Citrix,
    Palo,
    Reblaze,
    SafeDog,
    Comodo,
    WallArm,
    Unknown,
}

impl std::fmt::Display for WafVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cloudflare => write!(f, "Cloudflare"),
            Self::Akamai => write!(f, "Akamai"),
            Self::AwsWaf => write!(f, "AWS WAF"),
            Self::ModSecurity => write!(f, "ModSecurity"),
            Self::Imperva => write!(f, "Imperva/Incapsula"),
            Self::F5BigIp => write!(f, "F5 BIG-IP"),
            Self::Barracuda => write!(f, "Barracuda"),
            Self::Sucuri => write!(f, "Sucuri"),
            Self::Wordfence => write!(f, "Wordfence"),
            Self::AzureFrontDoor => write!(f, "Azure Front Door"),
            Self::Fastly => write!(f, "Fastly"),
            Self::StackPath => write!(f, "StackPath"),
            Self::DenyAll => write!(f, "DenyAll"),
            Self::FortiWeb => write!(f, "FortiWeb"),
            Self::Radware => write!(f, "Radware AppWall"),
            Self::SonicWall => write!(f, "SonicWall"),
            Self::Citrix => write!(f, "Citrix NetScaler"),
            Self::Palo => write!(f, "Palo Alto"),
            Self::Reblaze => write!(f, "Reblaze"),
            Self::SafeDog => write!(f, "SafeDog"),
            Self::Comodo => write!(f, "Comodo WAF"),
            Self::WallArm => write!(f, "Wallarm"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Bypass strategy recommended for a specific WAF vendor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassStrategy {
    pub vendor: WafVendor,
    pub preferred_encodings: Vec<String>,
    pub header_mutations: Vec<(String, String)>,
    pub timing_advice_ms: (u64, u64),
    pub notes: String,
}

/// A single fingerprint signature for matching WAF responses.
#[derive(Debug, Clone)]
struct FingerprintSignature {
    vendor: WafVendor,
    header_name: String,
    header_pattern: SignaturePattern,
    confidence: f64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum SignaturePattern {
    Exists,
    Contains(String),
    Prefix(String),
    Exact(String),
}

/// Result of WAF fingerprinting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafFingerprintResult {
    pub detected_vendors: Vec<(WafVendor, f64)>,
    pub primary_vendor: WafVendor,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub bypass_strategies: Vec<BypassStrategy>,
}

/// Simulated HTTP response headers for fingerprinting.
#[derive(Debug, Clone)]
pub struct ResponseFingerprint {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body_snippet: String,
}

/// WAF Vendor Fingerprinter V2: identifies 20+ WAF vendors from response
/// patterns and selects per-vendor bypass strategies.
pub struct WafFingerprinterV2 {
    signatures: Vec<FingerprintSignature>,
    body_signatures: Vec<(WafVendor, String, f64)>,
    status_hints: Vec<(WafVendor, u16, f64)>,
    bypass_db: HashMap<WafVendor, BypassStrategy>,
}

impl WafFingerprinterV2 {
    pub fn new() -> Self {
        Self {
            signatures: build_header_signatures(),
            body_signatures: build_body_signatures(),
            status_hints: build_status_hints(),
            bypass_db: build_bypass_database(),
        }
    }

    /// Fingerprint a WAF from a single HTTP response.
    pub fn fingerprint(&self, response: &ResponseFingerprint) -> WafFingerprintResult {
        let mut scores: HashMap<WafVendor, (f64, Vec<String>)> = HashMap::new();

        let lower_headers: HashMap<String, String> = response
            .headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        for sig in &self.signatures {
            let header_key = sig.header_name.to_lowercase();
            if let Some(val) = lower_headers.get(&header_key) {
                let matched = match &sig.header_pattern {
                    SignaturePattern::Exists => true,
                    SignaturePattern::Contains(s) => val.to_lowercase().contains(&s.to_lowercase()),
                    SignaturePattern::Prefix(s) => {
                        val.to_lowercase().starts_with(&s.to_lowercase())
                    }
                    SignaturePattern::Exact(s) => val.to_lowercase() == s.to_lowercase(),
                };
                if matched {
                    let entry = scores
                        .entry(sig.vendor)
                        .or_insert_with(|| (0.0, Vec::new()));
                    entry.0 += sig.confidence;
                    entry.1.push(format!(
                        "Header '{}' matched for {}",
                        sig.header_name, sig.vendor
                    ));
                }
            }
        }

        let body_lower = response.body_snippet.to_lowercase();
        for (vendor, pattern, conf) in &self.body_signatures {
            if body_lower.contains(&pattern.to_lowercase()) {
                let entry = scores.entry(*vendor).or_insert_with(|| (0.0, Vec::new()));
                entry.0 += conf;
                entry
                    .1
                    .push(format!("Body pattern '{}' matched for {}", pattern, vendor));
            }
        }

        for (vendor, code, conf) in &self.status_hints {
            if response.status_code == *code {
                let entry = scores.entry(*vendor).or_insert_with(|| (0.0, Vec::new()));
                entry.0 += conf;
                entry.1.push(format!("Status {} hint for {}", code, vendor));
            }
        }

        let mut detected: Vec<(WafVendor, f64)> = scores
            .iter()
            .map(|(v, (s, _))| (*v, s.clamp(0.0, 1.0)))
            .filter(|(_, s)| *s > 0.1)
            .collect();
        detected.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let (primary, confidence) = detected
            .first()
            .copied()
            .unwrap_or((WafVendor::Unknown, 0.0));

        let evidence: Vec<String> = scores.values().flat_map(|(_, ev)| ev.clone()).collect();

        let mut bypass_strategies = Vec::new();
        for (vendor, _) in &detected {
            if let Some(strat) = self.bypass_db.get(vendor) {
                bypass_strategies.push(strat.clone());
            }
        }

        WafFingerprintResult {
            detected_vendors: detected,
            primary_vendor: primary,
            confidence,
            evidence,
            bypass_strategies,
        }
    }

    /// Fingerprint from multiple responses for higher confidence.
    pub fn fingerprint_multi(&self, responses: &[ResponseFingerprint]) -> WafFingerprintResult {
        let mut combined_scores: HashMap<WafVendor, (f64, Vec<String>)> = HashMap::new();

        for resp in responses {
            let result = self.fingerprint(resp);
            for (vendor, score) in &result.detected_vendors {
                let entry = combined_scores
                    .entry(*vendor)
                    .or_insert_with(|| (0.0, Vec::new()));
                entry.0 += score;
            }
            for ev in result.evidence {
                let vendor = result.primary_vendor;
                let entry = combined_scores
                    .entry(vendor)
                    .or_insert_with(|| (0.0, Vec::new()));
                entry.1.push(ev);
            }
        }

        let count = responses.len().max(1) as f64;
        let mut detected: Vec<(WafVendor, f64)> = combined_scores
            .iter()
            .map(|(v, (s, _))| (*v, (s / count).min(1.0)))
            .filter(|(_, s)| *s > 0.1)
            .collect();
        detected.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let (primary, confidence) = detected
            .first()
            .copied()
            .unwrap_or((WafVendor::Unknown, 0.0));

        let evidence: Vec<String> = combined_scores
            .values()
            .flat_map(|(_, ev)| ev.clone())
            .collect();

        let mut bypass_strategies = Vec::new();
        for (vendor, _) in &detected {
            if let Some(strat) = self.bypass_db.get(vendor) {
                bypass_strategies.push(strat.clone());
            }
        }

        WafFingerprintResult {
            detected_vendors: detected,
            primary_vendor: primary,
            confidence,
            evidence,
            bypass_strategies,
        }
    }

    pub fn vendor_count(&self) -> usize {
        let mut vendors: std::collections::HashSet<WafVendor> = std::collections::HashSet::new();
        for sig in &self.signatures {
            vendors.insert(sig.vendor);
        }
        for (v, _, _) in &self.body_signatures {
            vendors.insert(*v);
        }
        vendors.len()
    }

    pub fn get_bypass_strategy(&self, vendor: WafVendor) -> Option<&BypassStrategy> {
        self.bypass_db.get(&vendor)
    }
}

impl Default for WafFingerprinterV2 {
    fn default() -> Self {
        Self::new()
    }
}

fn build_header_signatures() -> Vec<FingerprintSignature> {
    vec![
        FingerprintSignature {
            vendor: WafVendor::Cloudflare,
            header_name: "cf-ray".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.9,
        },
        FingerprintSignature {
            vendor: WafVendor::Cloudflare,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("cloudflare".to_string()),
            confidence: 0.85,
        },
        FingerprintSignature {
            vendor: WafVendor::Cloudflare,
            header_name: "cf-cache-status".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.5,
        },
        FingerprintSignature {
            vendor: WafVendor::Akamai,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("AkamaiGHost".to_string()),
            confidence: 0.9,
        },
        FingerprintSignature {
            vendor: WafVendor::Akamai,
            header_name: "x-akamai-transformed".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.85,
        },
        FingerprintSignature {
            vendor: WafVendor::Akamai,
            header_name: "akamai-grn".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.8,
        },
        FingerprintSignature {
            vendor: WafVendor::AwsWaf,
            header_name: "x-amzn-requestid".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.7,
        },
        FingerprintSignature {
            vendor: WafVendor::AwsWaf,
            header_name: "x-amz-apigw-id".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.75,
        },
        FingerprintSignature {
            vendor: WafVendor::AwsWaf,
            header_name: "x-amzn-waf-action".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.95,
        },
        FingerprintSignature {
            vendor: WafVendor::ModSecurity,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("mod_security".to_string()),
            confidence: 0.9,
        },
        FingerprintSignature {
            vendor: WafVendor::ModSecurity,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("NOYB".to_string()),
            confidence: 0.6,
        },
        FingerprintSignature {
            vendor: WafVendor::Imperva,
            header_name: "x-iinfo".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.9,
        },
        FingerprintSignature {
            vendor: WafVendor::Imperva,
            header_name: "x-cdn".to_string(),
            header_pattern: SignaturePattern::Contains("Incapsula".to_string()),
            confidence: 0.85,
        },
        FingerprintSignature {
            vendor: WafVendor::F5BigIp,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("BIG-IP".to_string()),
            confidence: 0.9,
        },
        FingerprintSignature {
            vendor: WafVendor::F5BigIp,
            header_name: "x-wa-info".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.7,
        },
        FingerprintSignature {
            vendor: WafVendor::Barracuda,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("Barracuda".to_string()),
            confidence: 0.9,
        },
        FingerprintSignature {
            vendor: WafVendor::Barracuda,
            header_name: "barra_counter_session".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.85,
        },
        FingerprintSignature {
            vendor: WafVendor::Sucuri,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("Sucuri".to_string()),
            confidence: 0.9,
        },
        FingerprintSignature {
            vendor: WafVendor::Sucuri,
            header_name: "x-sucuri-id".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.95,
        },
        FingerprintSignature {
            vendor: WafVendor::Wordfence,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("Wordfence".to_string()),
            confidence: 0.85,
        },
        FingerprintSignature {
            vendor: WafVendor::AzureFrontDoor,
            header_name: "x-azure-ref".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.85,
        },
        FingerprintSignature {
            vendor: WafVendor::AzureFrontDoor,
            header_name: "x-fd-healthprobe".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.7,
        },
        FingerprintSignature {
            vendor: WafVendor::Fastly,
            header_name: "x-served-by".to_string(),
            header_pattern: SignaturePattern::Contains("cache-".to_string()),
            confidence: 0.7,
        },
        FingerprintSignature {
            vendor: WafVendor::Fastly,
            header_name: "x-fastly-request-id".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.9,
        },
        FingerprintSignature {
            vendor: WafVendor::StackPath,
            header_name: "x-sp-waf".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.9,
        },
        FingerprintSignature {
            vendor: WafVendor::DenyAll,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("DenyAll".to_string()),
            confidence: 0.9,
        },
        FingerprintSignature {
            vendor: WafVendor::FortiWeb,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("FortiWeb".to_string()),
            confidence: 0.9,
        },
        FingerprintSignature {
            vendor: WafVendor::FortiWeb,
            header_name: "fortiwafsid".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.85,
        },
        FingerprintSignature {
            vendor: WafVendor::Radware,
            header_name: "x-sl-compstate".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.85,
        },
        FingerprintSignature {
            vendor: WafVendor::SonicWall,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("SonicWALL".to_string()),
            confidence: 0.9,
        },
        FingerprintSignature {
            vendor: WafVendor::Citrix,
            header_name: "via".to_string(),
            header_pattern: SignaturePattern::Contains("NS-CACHE".to_string()),
            confidence: 0.75,
        },
        FingerprintSignature {
            vendor: WafVendor::Citrix,
            header_name: "cneonction".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.8,
        },
        FingerprintSignature {
            vendor: WafVendor::Palo,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("PanOS".to_string()),
            confidence: 0.85,
        },
        FingerprintSignature {
            vendor: WafVendor::Reblaze,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("Reblaze".to_string()),
            confidence: 0.9,
        },
        FingerprintSignature {
            vendor: WafVendor::Reblaze,
            header_name: "rbzid".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.85,
        },
        FingerprintSignature {
            vendor: WafVendor::SafeDog,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("Safe Dog".to_string()),
            confidence: 0.85,
        },
        FingerprintSignature {
            vendor: WafVendor::SafeDog,
            header_name: "waf-dog".to_string(),
            header_pattern: SignaturePattern::Exists,
            confidence: 0.9,
        },
        FingerprintSignature {
            vendor: WafVendor::Comodo,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("Comodo".to_string()),
            confidence: 0.85,
        },
        FingerprintSignature {
            vendor: WafVendor::WallArm,
            header_name: "server".to_string(),
            header_pattern: SignaturePattern::Contains("wallarm".to_string()),
            confidence: 0.9,
        },
    ]
}

fn build_body_signatures() -> Vec<(WafVendor, String, f64)> {
    vec![
        (
            WafVendor::Cloudflare,
            "Attention Required! | Cloudflare".to_string(),
            0.9,
        ),
        (WafVendor::Cloudflare, "cf-error-details".to_string(), 0.7),
        (WafVendor::Akamai, "Reference&#32;&#35;".to_string(), 0.7),
        (WafVendor::Akamai, "Access Denied".to_string(), 0.3),
        (WafVendor::AwsWaf, "awselb/".to_string(), 0.6),
        (
            WafVendor::ModSecurity,
            "This error was generated by Mod_Security".to_string(),
            0.95,
        ),
        (
            WafVendor::ModSecurity,
            "ModSecurity Action".to_string(),
            0.85,
        ),
        (
            WafVendor::Imperva,
            "Incapsula incident ID".to_string(),
            0.95,
        ),
        (WafVendor::Imperva, "_Incapsula_Resource".to_string(), 0.85),
        (
            WafVendor::F5BigIp,
            "The requested URL was rejected".to_string(),
            0.6,
        ),
        (
            WafVendor::Barracuda,
            "Barracuda Web Application Firewall".to_string(),
            0.9,
        ),
        (
            WafVendor::Sucuri,
            "Access Denied - Sucuri Website Firewall".to_string(),
            0.95,
        ),
        (
            WafVendor::Wordfence,
            "Generated by Wordfence".to_string(),
            0.95,
        ),
        (WafVendor::Wordfence, "wfvt_".to_string(), 0.7),
        (
            WafVendor::AzureFrontDoor,
            "The request is blocked".to_string(),
            0.4,
        ),
        (
            WafVendor::FortiWeb,
            "FortiGuard Intrusion Prevention".to_string(),
            0.85,
        ),
        (WafVendor::Radware, "Radware Bot Manager".to_string(), 0.85),
        (WafVendor::SafeDog, "safed0g.html".to_string(), 0.85),
        (WafVendor::Comodo, "Protected by COMODO".to_string(), 0.9),
        (WafVendor::WallArm, "wallarm-ng".to_string(), 0.8),
    ]
}

fn build_status_hints() -> Vec<(WafVendor, u16, f64)> {
    vec![
        (WafVendor::Cloudflare, 403, 0.1),
        (WafVendor::AwsWaf, 403, 0.1),
        (WafVendor::Imperva, 402, 0.2),
    ]
}

fn build_bypass_database() -> HashMap<WafVendor, BypassStrategy> {
    let mut db = HashMap::new();

    db.insert(WafVendor::Cloudflare, BypassStrategy {
        vendor: WafVendor::Cloudflare,
        preferred_encodings: vec![
            "unicode-normalization".into(),
            "overlong-utf8".into(),
            "double-url".into(),
        ],
        header_mutations: vec![
            ("Transfer-Encoding".into(), "chunked".into()),
            ("Content-Type".into(), "multipart/form-data".into()),
        ],
        timing_advice_ms: (500, 2000),
        notes: "Cloudflare inspects normalized payloads; overlong UTF-8 and chunked TE can bypass regex matching".into(),
    });

    db.insert(
        WafVendor::Akamai,
        BypassStrategy {
            vendor: WafVendor::Akamai,
            preferred_encodings: vec!["html-entity".into(), "double-url".into(), "hex".into()],
            header_mutations: vec![("X-Forwarded-For".into(), "127.0.0.1".into())],
            timing_advice_ms: (1000, 3000),
            notes:
                "Akamai Kona rules heavy on regex; HTML entity encoding and XFF spoofing effective"
                    .into(),
        },
    );

    db.insert(WafVendor::AwsWaf, BypassStrategy {
        vendor: WafVendor::AwsWaf,
        preferred_encodings: vec![
            "unicode-normalization".into(),
            "base64".into(),
            "octal".into(),
        ],
        header_mutations: vec![
            ("X-Forwarded-For".into(), "10.0.0.1".into()),
        ],
        timing_advice_ms: (200, 1000),
        notes: "AWS WAF managed rules use pattern matching; base64 and octal payloads in parameter values bypass common rules".into(),
    });

    db.insert(WafVendor::ModSecurity, BypassStrategy {
        vendor: WafVendor::ModSecurity,
        preferred_encodings: vec![
            "overlong-utf8".into(),
            "null-byte".into(),
            "comment-insertion".into(),
        ],
        header_mutations: vec![],
        timing_advice_ms: (100, 500),
        notes: "CRS paranoia level dependent; comment insertion in SQL and overlong UTF-8 bypass lower paranoia levels".into(),
    });

    db.insert(WafVendor::Imperva, BypassStrategy {
        vendor: WafVendor::Imperva,
        preferred_encodings: vec![
            "double-url".into(),
            "unicode-normalization".into(),
            "hex".into(),
        ],
        header_mutations: vec![
            ("Content-Type".into(), "text/plain".into()),
        ],
        timing_advice_ms: (500, 2500),
        notes: "Imperva uses behavioral analysis; slow requests with unusual Content-Type can evade deep inspection".into(),
    });

    db.insert(WafVendor::F5BigIp, BypassStrategy {
        vendor: WafVendor::F5BigIp,
        preferred_encodings: vec![
            "double-url".into(),
            "html-entity".into(),
        ],
        header_mutations: vec![
            ("Transfer-Encoding".into(), "chunked".into()),
        ],
        timing_advice_ms: (300, 1500),
        notes: "F5 ASM policy-dependent; chunked transfer encoding splits payload across inspection boundaries".into(),
    });

    db.insert(WafVendor::Barracuda, BypassStrategy {
        vendor: WafVendor::Barracuda,
        preferred_encodings: vec![
            "overlong-utf8".into(),
            "double-url".into(),
        ],
        header_mutations: vec![],
        timing_advice_ms: (200, 1000),
        notes: "Barracuda uses signature-based detection; overlong UTF-8 sequences bypass pattern matching".into(),
    });

    db.insert(WafVendor::Sucuri, BypassStrategy {
        vendor: WafVendor::Sucuri,
        preferred_encodings: vec![
            "unicode-normalization".into(),
            "comment-insertion".into(),
        ],
        header_mutations: vec![
            ("X-Originating-IP".into(), "127.0.0.1".into()),
        ],
        timing_advice_ms: (500, 2000),
        notes: "Sucuri cloud-based; origin IP discovery bypasses entirely; otherwise unicode normalization".into(),
    });

    db.insert(WafVendor::Wordfence, BypassStrategy {
        vendor: WafVendor::Wordfence,
        preferred_encodings: vec![
            "double-url".into(),
            "html-entity".into(),
            "unicode-normalization".into(),
        ],
        header_mutations: vec![],
        timing_advice_ms: (100, 500),
        notes: "Wordfence runs at PHP level; double URL encoding decoded only once by Apache, second decode hits app".into(),
    });

    db.insert(WafVendor::AzureFrontDoor, BypassStrategy {
        vendor: WafVendor::AzureFrontDoor,
        preferred_encodings: vec![
            "base64".into(),
            "hex".into(),
            "unicode-normalization".into(),
        ],
        header_mutations: vec![],
        timing_advice_ms: (300, 1500),
        notes: "Azure Front Door uses OWASP CRS; base64 in JSON bodies bypasses body inspection for lower rule sets".into(),
    });

    db.insert(
        WafVendor::Fastly,
        BypassStrategy {
            vendor: WafVendor::Fastly,
            preferred_encodings: vec!["overlong-utf8".into(), "double-url".into()],
            header_mutations: vec![("Fastly-Debug".into(), "1".into())],
            timing_advice_ms: (200, 1000),
            notes: "Fastly uses VCL-based WAF; edge-level inspection with limited decode depth"
                .into(),
        },
    );

    db.insert(
        WafVendor::StackPath,
        BypassStrategy {
            vendor: WafVendor::StackPath,
            preferred_encodings: vec!["html-entity".into(), "hex".into()],
            header_mutations: vec![],
            timing_advice_ms: (200, 1000),
            notes:
                "StackPath SecureCDN uses ModSecurity-based rules; HTML entity encoding effective"
                    .into(),
        },
    );

    db.insert(WafVendor::DenyAll, BypassStrategy {
        vendor: WafVendor::DenyAll,
        preferred_encodings: vec![
            "double-url".into(),
            "null-byte".into(),
        ],
        header_mutations: vec![],
        timing_advice_ms: (300, 1500),
        notes: "DenyAll uses positive security model; null byte truncation can terminate pattern matching".into(),
    });

    db.insert(WafVendor::FortiWeb, BypassStrategy {
        vendor: WafVendor::FortiWeb,
        preferred_encodings: vec![
            "overlong-utf8".into(),
            "unicode-normalization".into(),
        ],
        header_mutations: vec![],
        timing_advice_ms: (200, 1000),
        notes: "FortiWeb signature-based; overlong UTF-8 and Unicode normalization effective at bypassing signatures".into(),
    });

    db.insert(WafVendor::Radware, BypassStrategy {
        vendor: WafVendor::Radware,
        preferred_encodings: vec![
            "double-url".into(),
            "html-entity".into(),
        ],
        header_mutations: vec![],
        timing_advice_ms: (500, 2000),
        notes: "Radware AppWall behavioral analysis; slow low-and-slow requests avoid rate-based triggers".into(),
    });

    db.insert(WafVendor::SonicWall, BypassStrategy {
        vendor: WafVendor::SonicWall,
        preferred_encodings: vec![
            "hex".into(),
            "octal".into(),
        ],
        header_mutations: vec![],
        timing_advice_ms: (200, 1000),
        notes: "SonicWall uses DPI; hex and octal encoded payloads bypass pattern matching at network layer".into(),
    });

    db.insert(WafVendor::Citrix, BypassStrategy {
        vendor: WafVendor::Citrix,
        preferred_encodings: vec![
            "double-url".into(),
            "base64".into(),
        ],
        header_mutations: vec![],
        timing_advice_ms: (300, 1500),
        notes: "Citrix NetScaler AppFW policy-based; double URL encoding bypasses single-decode inspection".into(),
    });

    db.insert(WafVendor::Palo, BypassStrategy {
        vendor: WafVendor::Palo,
        preferred_encodings: vec![
            "overlong-utf8".into(),
            "hex".into(),
        ],
        header_mutations: vec![],
        timing_advice_ms: (200, 1000),
        notes: "Palo Alto NGFW threat prevention uses signatures; overlong UTF-8 evades signature matching".into(),
    });

    db.insert(WafVendor::Reblaze, BypassStrategy {
        vendor: WafVendor::Reblaze,
        preferred_encodings: vec![
            "unicode-normalization".into(),
            "html-entity".into(),
        ],
        header_mutations: vec![],
        timing_advice_ms: (500, 2000),
        notes: "Reblaze ML-based; unicode normalization and HTML entity encoding effective against ML classifiers".into(),
    });

    db.insert(
        WafVendor::SafeDog,
        BypassStrategy {
            vendor: WafVendor::SafeDog,
            preferred_encodings: vec!["double-url".into(), "null-byte".into()],
            header_mutations: vec![],
            timing_advice_ms: (100, 500),
            notes:
                "SafeDog server-side agent; null byte and double URL encoding bypass pattern engine"
                    .into(),
        },
    );

    db.insert(
        WafVendor::Comodo,
        BypassStrategy {
            vendor: WafVendor::Comodo,
            preferred_encodings: vec!["html-entity".into(), "double-url".into()],
            header_mutations: vec![],
            timing_advice_ms: (200, 1000),
            notes:
                "Comodo WAF uses ModSecurity rules; HTML entity encoding and double URL effective"
                    .into(),
        },
    );

    db.insert(
        WafVendor::WallArm,
        BypassStrategy {
            vendor: WafVendor::WallArm,
            preferred_encodings: vec!["unicode-normalization".into(), "overlong-utf8".into()],
            header_mutations: vec![],
            timing_advice_ms: (300, 1500),
            notes: "Wallarm uses ML; unicode normalization variants confuse tokenization layer"
                .into(),
        },
    );

    db
}
