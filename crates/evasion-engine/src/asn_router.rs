use std::collections::HashMap;
use std::fmt;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// ASN classification tier reflecting monitoring risk and detection likelihood.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AsnTier {
    /// Tier-1 backbone providers (NTT, Lumen, GTT).
    Tier1,
    /// Residential ISPs — lowest detection risk for scanning traffic.
    Residential,
    /// Commercial data center hosting (AWS, Hetzner, OVH).
    Datacenter,
    /// Bulletproof hosting — high abuse tolerance but flagged by threat intel.
    Bulletproof,
    /// Government-operated networks.
    Government,
    /// University and research networks.
    Academic,
}

impl AsnTier {
    /// Stealth score: higher means less likely to trigger detection (0.0–1.0).
    pub fn stealth_score(&self) -> f64 {
        match self {
            Self::Residential => 0.95,
            Self::Academic => 0.75,
            Self::Tier1 => 0.65,
            Self::Government => 0.55,
            Self::Datacenter => 0.35,
            Self::Bulletproof => 0.10,
        }
    }
}

impl fmt::Display for AsnTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tier1 => write!(f, "Tier-1"),
            Self::Residential => write!(f, "Residential"),
            Self::Datacenter => write!(f, "Datacenter"),
            Self::Bulletproof => write!(f, "Bulletproof"),
            Self::Government => write!(f, "Government"),
            Self::Academic => write!(f, "Academic"),
        }
    }
}

/// Intelligence-sharing alliance membership and treaty risk classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JurisdictionRisk {
    /// Five Eyes member (US, UK, CA, AU, NZ) — highest SIGINT cooperation.
    FiveEyes,
    /// Nine Eyes extension (+ DK, FR, NL, NO).
    NineEyes,
    /// Fourteen Eyes (+ DE, BE, IT, SE, ES).
    FourteenEyes,
    /// Has MLAT treaty with Five Eyes but not a member.
    MlatPartner,
    /// No known intelligence-sharing agreements relevant to SIGINT.
    Neutral,
    /// Jurisdictions with minimal cooperation or adversarial posture.
    Favorable,
}

impl JurisdictionRisk {
    /// Penalty applied to route score (0.0 = no penalty, 1.0 = maximum penalty).
    pub fn penalty(&self) -> f64 {
        match self {
            Self::FiveEyes => 1.0,
            Self::NineEyes => 0.85,
            Self::FourteenEyes => 0.65,
            Self::MlatPartner => 0.40,
            Self::Neutral => 0.10,
            Self::Favorable => 0.0,
        }
    }
}

impl fmt::Display for JurisdictionRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FiveEyes => write!(f, "Five Eyes"),
            Self::NineEyes => write!(f, "Nine Eyes"),
            Self::FourteenEyes => write!(f, "Fourteen Eyes"),
            Self::MlatPartner => write!(f, "MLAT Partner"),
            Self::Neutral => write!(f, "Neutral"),
            Self::Favorable => write!(f, "Favorable"),
        }
    }
}

/// Jurisdiction metadata for a country.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JurisdictionInfo {
    pub country_code: String,
    pub risk: JurisdictionRisk,
    pub has_mlat_with_us: bool,
    pub has_data_retention_laws: bool,
}

/// A single ASN entry in the reputation database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnEntry {
    pub asn_number: u32,
    pub name: String,
    pub tier: AsnTier,
    pub country: String,
    pub jurisdiction: JurisdictionInfo,
}

impl fmt::Display for AsnEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AS{} {} [{}] ({}, {})",
            self.asn_number, self.name, self.tier, self.country, self.jurisdiction.risk
        )
    }
}

/// Configuration for route selection behavior.
#[derive(Debug, Clone)]
pub struct RouteConfig {
    pub avoid_five_eyes: bool,
    pub avoid_fourteen_eyes: bool,
    pub min_hops: usize,
    pub max_hops: usize,
    pub tier_weight: f64,
    pub jurisdiction_weight: f64,
    pub diversity_weight: f64,
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            avoid_five_eyes: true,
            avoid_fourteen_eyes: false,
            min_hops: 2,
            max_hops: 5,
            tier_weight: 0.4,
            jurisdiction_weight: 0.4,
            diversity_weight: 0.2,
        }
    }
}

impl RouteConfig {
    pub fn with_avoid_five_eyes(mut self, avoid: bool) -> Self {
        self.avoid_five_eyes = avoid;
        self
    }

    pub fn with_avoid_fourteen_eyes(mut self, avoid: bool) -> Self {
        self.avoid_fourteen_eyes = avoid;
        self
    }

    pub fn with_min_hops(mut self, n: usize) -> Self {
        self.min_hops = n;
        self
    }

    pub fn with_max_hops(mut self, n: usize) -> Self {
        self.max_hops = n;
        self
    }
}

/// A selected multi-hop route through ASNs.
#[derive(Debug, Clone)]
pub struct SelectedRoute {
    pub hops: Vec<u32>,
    pub total_score: f64,
    pub countries: Vec<String>,
}

/// Non-monitored ASN router for selecting low-detection network paths.
///
/// Maintains a database of ASN entries scored by tier reputation and
/// jurisdiction risk, then selects multi-hop routes that maximize
/// stealth while enforcing path diversity constraints.
pub struct AsnRouter {
    entries: HashMap<u32, AsnEntry>,
    jurisdiction_db: HashMap<String, JurisdictionRisk>,
    config: RouteConfig,
    rng: StdRng,
}

impl AsnRouter {
    pub fn new(config: RouteConfig) -> Self {
        let mut router = Self {
            entries: HashMap::new(),
            jurisdiction_db: HashMap::new(),
            config,
            rng: StdRng::from_os_rng(),
        };
        router.load_jurisdiction_db();
        router.load_default_asns();
        router
    }

    pub fn with_seed(config: RouteConfig, seed: u64) -> Self {
        let mut router = Self {
            entries: HashMap::new(),
            jurisdiction_db: HashMap::new(),
            config,
            rng: StdRng::seed_from_u64(seed),
        };
        router.load_jurisdiction_db();
        router.load_default_asns();
        router
    }

    /// Registers an ASN entry in the reputation database.
    pub fn add_asn(&mut self, entry: AsnEntry) {
        self.entries.insert(entry.asn_number, entry);
    }

    /// Returns the number of ASN entries in the database.
    pub fn database_size(&self) -> usize {
        self.entries.len()
    }

    /// Looks up an ASN entry by number.
    pub fn get_asn(&self, asn_number: u32) -> Option<&AsnEntry> {
        self.entries.get(&asn_number)
    }

    /// Computes a composite score for an ASN (higher = better for routing).
    ///
    /// Score components:
    /// - Tier stealth score weighted by `tier_weight`
    /// - Jurisdiction safety (inverted penalty) weighted by `jurisdiction_weight`
    pub fn score_asn(&self, asn_number: u32) -> f64 {
        let entry = match self.entries.get(&asn_number) {
            Some(e) => e,
            None => return 0.0,
        };

        let tier_score = entry.tier.stealth_score();
        let jurisdiction_safety = 1.0 - entry.jurisdiction.risk.penalty();

        let raw = tier_score * self.config.tier_weight
            + jurisdiction_safety * self.config.jurisdiction_weight;

        let weight_sum = self.config.tier_weight + self.config.jurisdiction_weight;
        if weight_sum > 0.0 {
            raw / weight_sum
        } else {
            0.0
        }
    }

    /// Selects a multi-hop route optimizing for stealth and diversity.
    ///
    /// Filters ASNs by jurisdiction policy, then greedily selects hops
    /// that maximize individual score while enforcing country diversity
    /// between consecutive hops.
    pub fn select_route(&mut self) -> Option<SelectedRoute> {
        let candidate_asns: Vec<u32> = self
            .filtered_candidates()
            .iter()
            .map(|e| e.asn_number)
            .collect();

        if candidate_asns.is_empty() {
            return None;
        }

        let hop_count = self
            .config
            .min_hops
            .min(candidate_asns.len())
            .max(1)
            .min(self.config.max_hops);

        let mut selected_asns: Vec<u32> = Vec::with_capacity(hop_count);
        let mut selected_countries: Vec<String> = Vec::with_capacity(hop_count);

        for _ in 0..hop_count {
            let eligible: Vec<u32> = candidate_asns
                .iter()
                .filter(|&&asn| {
                    !selected_asns.contains(&asn)
                        && selected_countries
                            .last()
                            .map_or(true, |prev_country: &String| {
                                self.entries
                                    .get(&asn)
                                    .map_or(true, |e| &e.country != prev_country)
                            })
                })
                .copied()
                .collect();

            let pick = if eligible.is_empty() {
                let fallback: Vec<u32> = candidate_asns
                    .iter()
                    .filter(|&&asn| !selected_asns.contains(&asn))
                    .copied()
                    .collect();
                if fallback.is_empty() {
                    break;
                }
                self.weighted_select_asn(&fallback)
            } else {
                self.weighted_select_asn(&eligible)
            };

            if let Some(entry) = self.entries.get(&pick) {
                selected_countries.push(entry.country.clone());
            }
            selected_asns.push(pick);
        }

        if selected_asns.is_empty() {
            return None;
        }

        let total_score: f64 = selected_asns.iter().map(|asn| self.score_asn(*asn)).sum();

        Some(SelectedRoute {
            hops: selected_asns,
            total_score,
            countries: selected_countries,
        })
    }

    /// Returns exit-node candidates ranked by score (best first).
    ///
    /// Exit nodes are the final hop where traffic emerges, so they carry
    /// the highest attribution risk. Filters by jurisdiction policy and
    /// returns entries sorted descending by composite score.
    pub fn best_exit_nodes(&self, limit: usize) -> Vec<&AsnEntry> {
        let mut candidates = self.filtered_candidates();
        candidates.sort_by(|a, b| {
            let sa = self.score_asn(a.asn_number);
            let sb = self.score_asn(b.asn_number);
            sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
        });
        candidates.into_iter().take(limit).collect()
    }

    /// Returns true if the given country code belongs to a Five Eyes member.
    pub fn is_five_eyes(country: &str) -> bool {
        matches!(country, "US" | "GB" | "CA" | "AU" | "NZ")
    }

    /// Returns true if the given country code belongs to a Nine Eyes member.
    pub fn is_nine_eyes(country: &str) -> bool {
        Self::is_five_eyes(country) || matches!(country, "DK" | "FR" | "NL" | "NO")
    }

    /// Returns true if the given country code belongs to a Fourteen Eyes member.
    pub fn is_fourteen_eyes(country: &str) -> bool {
        Self::is_nine_eyes(country) || matches!(country, "DE" | "BE" | "IT" | "SE" | "ES")
    }

    /// Classifies a country code into its jurisdiction risk tier.
    pub fn classify_jurisdiction(&self, country_code: &str) -> JurisdictionRisk {
        self.jurisdiction_db
            .get(country_code)
            .copied()
            .unwrap_or(JurisdictionRisk::Neutral)
    }

    /// Returns all ASN entries as a slice-compatible iterator.
    pub fn all_entries(&self) -> Vec<&AsnEntry> {
        self.entries.values().collect()
    }

    /// Removes all entries from the ASN database.
    pub fn clear_database(&mut self) {
        self.entries.clear();
    }

    fn filtered_candidates(&self) -> Vec<&AsnEntry> {
        self.entries
            .values()
            .filter(|e| {
                if self.config.avoid_five_eyes && Self::is_five_eyes(&e.country) {
                    return false;
                }
                if self.config.avoid_fourteen_eyes && Self::is_fourteen_eyes(&e.country) {
                    return false;
                }
                true
            })
            .collect()
    }

    fn weighted_select_asn(&mut self, asn_numbers: &[u32]) -> u32 {
        let scores: Vec<f64> = asn_numbers
            .iter()
            .map(|&asn| self.score_asn(asn).max(0.01))
            .collect();
        let total: f64 = scores.iter().sum();

        let mut roll: f64 = self.rng.random_range(0.0..total);
        for (i, &score) in scores.iter().enumerate() {
            roll -= score;
            if roll <= 0.0 {
                return asn_numbers[i];
            }
        }
        *asn_numbers.last().unwrap()
    }

    fn load_jurisdiction_db(&mut self) {
        let mappings: &[(&str, JurisdictionRisk)] = &[
            ("US", JurisdictionRisk::FiveEyes),
            ("GB", JurisdictionRisk::FiveEyes),
            ("CA", JurisdictionRisk::FiveEyes),
            ("AU", JurisdictionRisk::FiveEyes),
            ("NZ", JurisdictionRisk::FiveEyes),
            ("DK", JurisdictionRisk::NineEyes),
            ("FR", JurisdictionRisk::NineEyes),
            ("NL", JurisdictionRisk::NineEyes),
            ("NO", JurisdictionRisk::NineEyes),
            ("DE", JurisdictionRisk::FourteenEyes),
            ("BE", JurisdictionRisk::FourteenEyes),
            ("IT", JurisdictionRisk::FourteenEyes),
            ("SE", JurisdictionRisk::FourteenEyes),
            ("ES", JurisdictionRisk::FourteenEyes),
            ("JP", JurisdictionRisk::MlatPartner),
            ("KR", JurisdictionRisk::MlatPartner),
            ("IL", JurisdictionRisk::MlatPartner),
            ("SG", JurisdictionRisk::MlatPartner),
            ("BR", JurisdictionRisk::Neutral),
            ("CH", JurisdictionRisk::Neutral),
            ("IS", JurisdictionRisk::Neutral),
            ("RO", JurisdictionRisk::Neutral),
            ("PA", JurisdictionRisk::Favorable),
            ("MD", JurisdictionRisk::Favorable),
            ("RU", JurisdictionRisk::Favorable),
            ("BY", JurisdictionRisk::Favorable),
        ];

        for &(code, risk) in mappings {
            self.jurisdiction_db.insert(code.to_string(), risk);
        }
    }

    fn load_default_asns(&mut self) {
        let defaults = [
            AsnEntry {
                asn_number: 3356,
                name: "Lumen Technologies".to_string(),
                tier: AsnTier::Tier1,
                country: "US".to_string(),
                jurisdiction: JurisdictionInfo {
                    country_code: "US".to_string(),
                    risk: JurisdictionRisk::FiveEyes,
                    has_mlat_with_us: true,
                    has_data_retention_laws: true,
                },
            },
            AsnEntry {
                asn_number: 8708,
                name: "RCS & RDS".to_string(),
                tier: AsnTier::Residential,
                country: "RO".to_string(),
                jurisdiction: JurisdictionInfo {
                    country_code: "RO".to_string(),
                    risk: JurisdictionRisk::Neutral,
                    has_mlat_with_us: false,
                    has_data_retention_laws: false,
                },
            },
            AsnEntry {
                asn_number: 24940,
                name: "Hetzner Online".to_string(),
                tier: AsnTier::Datacenter,
                country: "DE".to_string(),
                jurisdiction: JurisdictionInfo {
                    country_code: "DE".to_string(),
                    risk: JurisdictionRisk::FourteenEyes,
                    has_mlat_with_us: true,
                    has_data_retention_laws: true,
                },
            },
            AsnEntry {
                asn_number: 200019,
                name: "AlexHost".to_string(),
                tier: AsnTier::Bulletproof,
                country: "MD".to_string(),
                jurisdiction: JurisdictionInfo {
                    country_code: "MD".to_string(),
                    risk: JurisdictionRisk::Favorable,
                    has_mlat_with_us: false,
                    has_data_retention_laws: false,
                },
            },
            AsnEntry {
                asn_number: 27699,
                name: "Telefonica Brasil".to_string(),
                tier: AsnTier::Residential,
                country: "BR".to_string(),
                jurisdiction: JurisdictionInfo {
                    country_code: "BR".to_string(),
                    risk: JurisdictionRisk::Neutral,
                    has_mlat_with_us: false,
                    has_data_retention_laws: false,
                },
            },
            AsnEntry {
                asn_number: 2519,
                name: "ARTERIA Networks".to_string(),
                tier: AsnTier::Academic,
                country: "JP".to_string(),
                jurisdiction: JurisdictionInfo {
                    country_code: "JP".to_string(),
                    risk: JurisdictionRisk::MlatPartner,
                    has_mlat_with_us: true,
                    has_data_retention_laws: false,
                },
            },
            AsnEntry {
                asn_number: 56040,
                name: "China Mobile".to_string(),
                tier: AsnTier::Residential,
                country: "CN".to_string(),
                jurisdiction: JurisdictionInfo {
                    country_code: "CN".to_string(),
                    risk: JurisdictionRisk::Favorable,
                    has_mlat_with_us: false,
                    has_data_retention_laws: true,
                },
            },
            AsnEntry {
                asn_number: 47541,
                name: "VNET".to_string(),
                tier: AsnTier::Datacenter,
                country: "RU".to_string(),
                jurisdiction: JurisdictionInfo {
                    country_code: "RU".to_string(),
                    risk: JurisdictionRisk::Favorable,
                    has_mlat_with_us: false,
                    has_data_retention_laws: true,
                },
            },
            AsnEntry {
                asn_number: 786,
                name: "JANET".to_string(),
                tier: AsnTier::Academic,
                country: "GB".to_string(),
                jurisdiction: JurisdictionInfo {
                    country_code: "GB".to_string(),
                    risk: JurisdictionRisk::FiveEyes,
                    has_mlat_with_us: true,
                    has_data_retention_laws: true,
                },
            },
            AsnEntry {
                asn_number: 27552,
                name: "TORIX".to_string(),
                tier: AsnTier::Tier1,
                country: "CA".to_string(),
                jurisdiction: JurisdictionInfo {
                    country_code: "CA".to_string(),
                    risk: JurisdictionRisk::FiveEyes,
                    has_mlat_with_us: true,
                    has_data_retention_laws: true,
                },
            },
            AsnEntry {
                asn_number: 47447,
                name: "23M".to_string(),
                tier: AsnTier::Government,
                country: "DE".to_string(),
                jurisdiction: JurisdictionInfo {
                    country_code: "DE".to_string(),
                    risk: JurisdictionRisk::FourteenEyes,
                    has_mlat_with_us: true,
                    has_data_retention_laws: true,
                },
            },
            AsnEntry {
                asn_number: 47764,
                name: "VPN.ee".to_string(),
                tier: AsnTier::Datacenter,
                country: "PA".to_string(),
                jurisdiction: JurisdictionInfo {
                    country_code: "PA".to_string(),
                    risk: JurisdictionRisk::Favorable,
                    has_mlat_with_us: false,
                    has_data_retention_laws: false,
                },
            },
        ];

        for entry in defaults {
            self.entries.insert(entry.asn_number, entry);
        }
    }
}
