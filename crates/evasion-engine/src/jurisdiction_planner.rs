use serde::{Deserialize, Serialize};

/// Jurisdiction-aware operational planning for proxy chain routing.
///
/// Maintains a database of MLAT treaty relationships, intelligence alliance
/// memberships (Five Eyes, Nine Eyes, Fourteen Eyes), and per-country
/// risk scores to guide traffic routing decisions.

/// Intelligence alliance membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Alliance {
    FiveEyes,
    NineEyes,
    FourteenEyes,
    Shanghai,
    None,
}

impl std::fmt::Display for Alliance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FiveEyes => write!(f, "Five Eyes"),
            Self::NineEyes => write!(f, "Nine Eyes"),
            Self::FourteenEyes => write!(f, "Fourteen Eyes"),
            Self::Shanghai => write!(f, "Shanghai Cooperation"),
            Self::None => write!(f, "None"),
        }
    }
}

/// MLAT treaty status between two jurisdictions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlatStatus {
    Active,
    Limited,
    None,
}

/// Jurisdiction risk classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Country jurisdiction profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JurisdictionProfile {
    pub country_code: String,
    pub country_name: String,
    pub alliance: Alliance,
    pub risk_level: RiskLevel,
    pub has_data_retention_laws: bool,
    pub has_mandatory_decryption: bool,
    pub mlat_partners: Vec<String>,
    pub risk_score: f64,
}

/// Routing recommendation for a proxy chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRecommendation {
    pub recommended_path: Vec<String>,
    pub avoided_countries: Vec<String>,
    pub total_risk_score: f64,
    pub max_hop_risk: RiskLevel,
    pub crosses_alliance_boundary: bool,
}

/// Configuration for the jurisdiction planner.
#[derive(Debug, Clone)]
pub struct JurisdictionPlannerConfig {
    pub avoid_five_eyes: bool,
    pub avoid_fourteen_eyes: bool,
    pub max_risk_level: RiskLevel,
    pub max_hops: usize,
    pub prefer_no_data_retention: bool,
    pub source_country: String,
    pub target_country: String,
}

impl Default for JurisdictionPlannerConfig {
    fn default() -> Self {
        Self {
            avoid_five_eyes: true,
            avoid_fourteen_eyes: false,
            max_risk_level: RiskLevel::Medium,
            max_hops: 3,
            prefer_no_data_retention: true,
            source_country: "US".to_string(),
            target_country: "US".to_string(),
        }
    }
}

/// Five Eyes members.
const FIVE_EYES: &[&str] = &["US", "GB", "CA", "AU", "NZ"];

/// Additional Nine Eyes members (beyond Five Eyes).
const NINE_EYES_EXTRA: &[&str] = &["DK", "FR", "NL", "NO"];

/// Additional Fourteen Eyes members (beyond Nine Eyes).
const FOURTEEN_EYES_EXTRA: &[&str] = &["DE", "BE", "IT", "ES", "SE"];

/// Countries with strong data retention laws.
const DATA_RETENTION_COUNTRIES: &[&str] = &[
    "US", "GB", "AU", "FR", "DE", "IT", "ES", "NL", "SE", "DK", "NO", "BE", "RU", "CN",
];

/// Countries with mandatory decryption laws.
const MANDATORY_DECRYPT_COUNTRIES: &[&str] = &["AU", "GB", "IN", "RU", "CN"];

/// Privacy-friendly jurisdictions commonly used for proxy routing.
const PRIVACY_FRIENDLY: &[(&str, &str, f64)] = &[
    ("CH", "Switzerland", 0.15),
    ("IS", "Iceland", 0.1),
    ("PA", "Panama", 0.2),
    ("RO", "Romania", 0.2),
    ("MY", "Malaysia", 0.25),
    ("MD", "Moldova", 0.3),
    ("BG", "Bulgaria", 0.25),
    ("CZ", "Czech Republic", 0.25),
    ("LU", "Luxembourg", 0.2),
    ("SG", "Singapore", 0.3),
];

/// Jurisdiction planner engine.
pub struct JurisdictionPlanner {
    config: JurisdictionPlannerConfig,
    profiles: Vec<JurisdictionProfile>,
}

impl JurisdictionPlanner {
    pub fn new(config: JurisdictionPlannerConfig) -> Self {
        let profiles = build_default_profiles();
        Self { config, profiles }
    }

    pub fn with_defaults() -> Self {
        Self::new(JurisdictionPlannerConfig::default())
    }

    /// Get the risk score for a specific country.
    pub fn country_risk(&self, country_code: &str) -> Option<f64> {
        self.profiles
            .iter()
            .find(|p| p.country_code == country_code)
            .map(|p| p.risk_score)
    }

    /// Check if a country is in Five Eyes.
    pub fn is_five_eyes(&self, country_code: &str) -> bool {
        FIVE_EYES.contains(&country_code)
    }

    /// Check if a country is in Fourteen Eyes.
    pub fn is_fourteen_eyes(&self, country_code: &str) -> bool {
        FIVE_EYES.contains(&country_code)
            || NINE_EYES_EXTRA.contains(&country_code)
            || FOURTEEN_EYES_EXTRA.contains(&country_code)
    }

    /// Check MLAT status between two countries.
    pub fn mlat_status(&self, country_a: &str, country_b: &str) -> MlatStatus {
        let both_fvey = self.is_five_eyes(country_a) && self.is_five_eyes(country_b);
        if both_fvey {
            return MlatStatus::Active;
        }
        let both_14 = self.is_fourteen_eyes(country_a) && self.is_fourteen_eyes(country_b);
        if both_14 {
            return MlatStatus::Active;
        }
        MlatStatus::Limited
    }

    /// Generate routing recommendation avoiding risky jurisdictions.
    pub fn recommend_route(&self) -> RoutingRecommendation {
        let mut candidates: Vec<_> = self
            .profiles
            .iter()
            .filter(|p| p.risk_level <= self.config.max_risk_level)
            .filter(|p| {
                if self.config.avoid_five_eyes && FIVE_EYES.contains(&p.country_code.as_str()) {
                    return false;
                }
                if self.config.avoid_fourteen_eyes && self.is_fourteen_eyes(&p.country_code) {
                    return false;
                }
                if self.config.prefer_no_data_retention && p.has_data_retention_laws {
                    return false;
                }
                true
            })
            .collect();

        candidates.sort_by(|a, b| a.risk_score.partial_cmp(&b.risk_score).unwrap());

        let hops: Vec<String> = candidates
            .iter()
            .take(self.config.max_hops)
            .map(|p| p.country_code.clone())
            .collect();

        let total_risk: f64 = hops.iter().filter_map(|c| self.country_risk(c)).sum();

        let max_hop_risk = hops
            .iter()
            .filter_map(|c| self.profiles.iter().find(|p| p.country_code == *c))
            .map(|p| p.risk_level)
            .max()
            .unwrap_or(RiskLevel::Low);

        let crosses_alliance = hops.windows(2).any(|w| {
            let a_fvey = self.is_five_eyes(&w[0]);
            let b_fvey = self.is_five_eyes(&w[1]);
            a_fvey != b_fvey
        });

        let avoided: Vec<String> = self
            .profiles
            .iter()
            .filter(|p| {
                (self.config.avoid_five_eyes && self.is_five_eyes(&p.country_code))
                    || p.risk_level > self.config.max_risk_level
            })
            .map(|p| p.country_code.clone())
            .collect();

        RoutingRecommendation {
            recommended_path: hops,
            avoided_countries: avoided,
            total_risk_score: total_risk,
            max_hop_risk,
            crosses_alliance_boundary: crosses_alliance,
        }
    }

    /// Number of jurisdiction profiles loaded.
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// List all privacy-friendly jurisdictions.
    pub fn privacy_friendly_countries(&self) -> Vec<&JurisdictionProfile> {
        self.profiles
            .iter()
            .filter(|p| p.risk_score <= 0.3 && !p.has_data_retention_laws)
            .collect()
    }
}

fn build_default_profiles() -> Vec<JurisdictionProfile> {
    let mut profiles = Vec::new();

    for country in FIVE_EYES {
        profiles.push(JurisdictionProfile {
            country_code: country.to_string(),
            country_name: five_eyes_name(country),
            alliance: Alliance::FiveEyes,
            risk_level: RiskLevel::Critical,
            has_data_retention_laws: true,
            has_mandatory_decryption: MANDATORY_DECRYPT_COUNTRIES.contains(country),
            mlat_partners: FIVE_EYES
                .iter()
                .filter(|c| *c != country)
                .map(|c| c.to_string())
                .collect(),
            risk_score: 0.9,
        });
    }

    for country in NINE_EYES_EXTRA {
        profiles.push(JurisdictionProfile {
            country_code: country.to_string(),
            country_name: nine_eyes_name(country),
            alliance: Alliance::NineEyes,
            risk_level: RiskLevel::High,
            has_data_retention_laws: DATA_RETENTION_COUNTRIES.contains(country),
            has_mandatory_decryption: false,
            mlat_partners: FIVE_EYES.iter().map(|c| c.to_string()).collect(),
            risk_score: 0.75,
        });
    }

    for country in FOURTEEN_EYES_EXTRA {
        profiles.push(JurisdictionProfile {
            country_code: country.to_string(),
            country_name: fourteen_eyes_name(country),
            alliance: Alliance::FourteenEyes,
            risk_level: RiskLevel::High,
            has_data_retention_laws: DATA_RETENTION_COUNTRIES.contains(country),
            has_mandatory_decryption: false,
            mlat_partners: vec![],
            risk_score: 0.65,
        });
    }

    for (code, name, risk) in PRIVACY_FRIENDLY {
        profiles.push(JurisdictionProfile {
            country_code: code.to_string(),
            country_name: name.to_string(),
            alliance: Alliance::None,
            risk_level: if *risk <= 0.2 {
                RiskLevel::Low
            } else {
                RiskLevel::Medium
            },
            has_data_retention_laws: DATA_RETENTION_COUNTRIES.contains(code),
            has_mandatory_decryption: false,
            mlat_partners: vec![],
            risk_score: *risk,
        });
    }

    profiles
}

fn five_eyes_name(code: &str) -> String {
    match code {
        "US" => "United States".to_string(),
        "GB" => "United Kingdom".to_string(),
        "CA" => "Canada".to_string(),
        "AU" => "Australia".to_string(),
        "NZ" => "New Zealand".to_string(),
        _ => code.to_string(),
    }
}

fn nine_eyes_name(code: &str) -> String {
    match code {
        "DK" => "Denmark".to_string(),
        "FR" => "France".to_string(),
        "NL" => "Netherlands".to_string(),
        "NO" => "Norway".to_string(),
        _ => code.to_string(),
    }
}

fn fourteen_eyes_name(code: &str) -> String {
    match code {
        "DE" => "Germany".to_string(),
        "BE" => "Belgium".to_string(),
        "IT" => "Italy".to_string(),
        "ES" => "Spain".to_string(),
        "SE" => "Sweden".to_string(),
        _ => code.to_string(),
    }
}
