use std::collections::HashMap;

use aegis_protocol::finding::VulnerabilityClass;
use serde::Serialize;

use crate::sarif_emitter::{SarifFinding, SarifLevel};

const CATEGORY_WEIGHTS: &[(&str, f64)] = &[
    ("injection", 0.2),
    ("auth", 0.15),
    ("config", 0.15),
    ("crypto", 0.1),
    ("info_disclosure", 0.1),
    ("access_control", 0.15),
    ("web_security", 0.1),
    ("dependencies", 0.05),
];

const INDUSTRY_AVERAGE: f64 = 68.0;
const TREND_THRESHOLD: f64 = 5.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LetterGrade {
    A,
    B,
    C,
    D,
    F,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Trend {
    Improving,
    Stable,
    Degrading,
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryScore {
    pub category: String,
    pub score: f64,
    pub finding_count: usize,
    pub grade: LetterGrade,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerComparison {
    pub your_score: f64,
    pub industry_average: f64,
    pub percentile: f64,
    pub assessment: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskDashboard {
    pub overall_score: f64,
    pub overall_grade: LetterGrade,
    pub category_scores: Vec<CategoryScore>,
    pub trend: Trend,
    pub peer_comparison: PeerComparison,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

pub fn categorize_vulnerability(class: &VulnerabilityClass) -> &'static str {
    match class {
        VulnerabilityClass::SqlInjection
        | VulnerabilityClass::CommandInjection
        | VulnerabilityClass::NoSqlInjection
        | VulnerabilityClass::XmlExternalEntity
        | VulnerabilityClass::ServerSideTemplateInjection
        | VulnerabilityClass::CrlfInjection => "injection",

        VulnerabilityClass::BrokenAuthentication | VulnerabilityClass::JwtVulnerability => "auth",

        VulnerabilityClass::SecurityMisconfiguration
        | VulnerabilityClass::CloudMisconfiguration
        | VulnerabilityClass::MissingSecurityHeader => "config",

        VulnerabilityClass::WeakCryptography | VulnerabilityClass::SensitiveDataExposure => {
            "crypto"
        }

        VulnerabilityClass::InformationDisclosure | VulnerabilityClass::PathTraversal => {
            "info_disclosure"
        }

        VulnerabilityClass::BrokenAuthorization
        | VulnerabilityClass::InsecureDirectObjectReference
        | VulnerabilityClass::MassAssignment => "access_control",

        VulnerabilityClass::CrossSiteScripting
        | VulnerabilityClass::CrossOriginMisconfiguration
        | VulnerabilityClass::Clickjacking
        | VulnerabilityClass::CachePoisoning
        | VulnerabilityClass::HostHeaderInjection
        | VulnerabilityClass::HeaderInjection
        | VulnerabilityClass::OpenRedirect
        | VulnerabilityClass::HttpRequestSmuggling
        | VulnerabilityClass::PrototypePollution
        | VulnerabilityClass::GraphQlAbuse
        | VulnerabilityClass::ServerSideRequestForgery
        | VulnerabilityClass::RaceCondition => "web_security",

        VulnerabilityClass::KnownVulnerableDependency
        | VulnerabilityClass::SubdomainTakeover
        | VulnerabilityClass::InsufficientInputValidation
        | VulnerabilityClass::InsecureDeserialization => "dependencies",
    }
}

pub fn grade_from_score(score: f64) -> LetterGrade {
    if score >= 90.0 {
        LetterGrade::A
    } else if score >= 80.0 {
        LetterGrade::B
    } else if score >= 70.0 {
        LetterGrade::C
    } else if score >= 60.0 {
        LetterGrade::D
    } else {
        LetterGrade::F
    }
}

fn classify_severity(finding: &SarifFinding) -> SeverityBucket {
    match finding.level {
        SarifLevel::Error => {
            if finding.composite_score >= 8.0 {
                SeverityBucket::Critical
            } else {
                SeverityBucket::High
            }
        }
        SarifLevel::Warning => SeverityBucket::Medium,
        SarifLevel::Note | SarifLevel::None => SeverityBucket::Low,
    }
}

enum SeverityBucket {
    Critical,
    High,
    Medium,
    Low,
}

fn compute_trend(current: f64, previous: Option<f64>) -> Trend {
    match previous {
        None => Trend::Stable,
        Some(prev) => {
            let delta = current - prev;
            if delta >= TREND_THRESHOLD {
                Trend::Improving
            } else if delta <= -TREND_THRESHOLD {
                Trend::Degrading
            } else {
                Trend::Stable
            }
        }
    }
}

fn build_peer_comparison(score: f64) -> PeerComparison {
    let percentile = score.clamp(0.0, 100.0);
    let assessment = if score >= INDUSTRY_AVERAGE + 15.0 {
        "Significantly above industry average".to_string()
    } else if score >= INDUSTRY_AVERAGE + 5.0 {
        "Above industry average".to_string()
    } else if score >= INDUSTRY_AVERAGE - 5.0 {
        "Near industry average".to_string()
    } else if score >= INDUSTRY_AVERAGE - 15.0 {
        "Below industry average".to_string()
    } else {
        "Significantly below industry average".to_string()
    };
    PeerComparison {
        your_score: score,
        industry_average: INDUSTRY_AVERAGE,
        percentile,
        assessment,
    }
}

pub fn compute_dashboard(findings: &[SarifFinding], previous_score: Option<f64>) -> RiskDashboard {
    let mut category_penalties: HashMap<&str, f64> = HashMap::new();
    let mut category_counts: HashMap<&str, usize> = HashMap::new();

    let mut critical_count = 0usize;
    let mut high_count = 0usize;
    let mut medium_count = 0usize;
    let mut low_count = 0usize;

    for finding in findings {
        match classify_severity(finding) {
            SeverityBucket::Critical => critical_count += 1,
            SeverityBucket::High => high_count += 1,
            SeverityBucket::Medium => medium_count += 1,
            SeverityBucket::Low => low_count += 1,
        }

        if let Some(vc) = &finding.vulnerability_class {
            let cat = categorize_vulnerability(vc);
            *category_penalties.entry(cat).or_insert(0.0) += finding.composite_score;
            *category_counts.entry(cat).or_insert(0) += 1;
        }
    }

    let mut category_scores = Vec::with_capacity(CATEGORY_WEIGHTS.len());
    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;

    for &(cat_name, weight) in CATEGORY_WEIGHTS {
        let penalty = category_penalties.get(cat_name).copied().unwrap_or(0.0);
        let count = category_counts.get(cat_name).copied().unwrap_or(0);
        let raw_score = (100.0 - penalty).max(0.0);
        let score = raw_score.min(100.0);
        let grade = grade_from_score(score);

        category_scores.push(CategoryScore {
            category: cat_name.to_string(),
            score,
            finding_count: count,
            grade,
        });

        weighted_sum += score * weight;
        total_weight += weight;
    }

    let overall_score = if total_weight > 0.0 {
        (weighted_sum / total_weight).clamp(0.0, 100.0)
    } else {
        100.0
    };
    let overall_grade = grade_from_score(overall_score);
    let trend = compute_trend(overall_score, previous_score);
    let peer_comparison = build_peer_comparison(overall_score);

    RiskDashboard {
        overall_score,
        overall_grade,
        category_scores,
        trend,
        peer_comparison,
        total_findings: findings.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
    }
}

pub fn to_json(dashboard: &RiskDashboard) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(dashboard)
}
