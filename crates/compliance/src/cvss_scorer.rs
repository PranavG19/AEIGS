use serde::{Deserialize, Serialize};
use std::fmt;

/// CVSS v3.1 Attack Vector metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

/// CVSS v3.1 Attack Complexity metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackComplexity {
    Low,
    High,
}

/// CVSS v3.1 Privileges Required metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

/// CVSS v3.1 User Interaction metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UserInteraction {
    None,
    Required,
}

/// CVSS v3.1 Scope metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Scope {
    Unchanged,
    Changed,
}

/// CVSS v3.1 CIA impact level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Impact {
    None,
    Low,
    High,
}

/// Qualitative severity label derived from a CVSS score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CvssSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for CvssSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CvssSeverity::None => write!(f, "None"),
            CvssSeverity::Low => write!(f, "Low"),
            CvssSeverity::Medium => write!(f, "Medium"),
            CvssSeverity::High => write!(f, "High"),
            CvssSeverity::Critical => write!(f, "Critical"),
        }
    }
}

/// Complete set of CVSS v3.1 base metric values for a vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssMetrics {
    pub attack_vector: AttackVector,
    pub attack_complexity: AttackComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
    pub scope: Scope,
    pub confidentiality: Impact,
    pub integrity: Impact,
    pub availability: Impact,
}

/// Computed CVSS v3.1 score with vector string and severity label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssResult {
    pub score: f64,
    pub vector_string: String,
    pub severity_label: CvssSeverity,
}

/// Computes a CVSS v3.1 base score from the given metric values.
///
/// Implements the exact formula from the FIRST CVSS v3.1 specification,
/// including the "round up" function (ceiling at 1 decimal place).
pub fn compute_cvss(metrics: &CvssMetrics) -> CvssResult {
    let iss = impact_sub_score(metrics);
    let impact = impact_score(iss, metrics.scope);
    let exploitability = exploitability_score(metrics);
    let score = base_score(impact, exploitability, metrics.scope);
    let vector_string = build_vector_string(metrics);
    let severity_label = severity_from_score(score);

    CvssResult {
        score,
        vector_string,
        severity_label,
    }
}

pub fn severity_from_score(score: f64) -> CvssSeverity {
    if score <= 0.0 {
        CvssSeverity::None
    } else if score <= 3.9 {
        CvssSeverity::Low
    } else if score <= 6.9 {
        CvssSeverity::Medium
    } else if score <= 8.9 {
        CvssSeverity::High
    } else {
        CvssSeverity::Critical
    }
}

fn impact_sub_score(metrics: &CvssMetrics) -> f64 {
    let c = impact_weight(metrics.confidentiality);
    let i = impact_weight(metrics.integrity);
    let a = impact_weight(metrics.availability);
    1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
}

fn impact_score(iss: f64, scope: Scope) -> f64 {
    match scope {
        Scope::Unchanged => 6.42 * iss,
        Scope::Changed => 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0),
    }
}

fn exploitability_score(metrics: &CvssMetrics) -> f64 {
    let av = attack_vector_weight(metrics.attack_vector);
    let ac = attack_complexity_weight(metrics.attack_complexity);
    let pr = privileges_required_weight(metrics.privileges_required, metrics.scope);
    let ui = user_interaction_weight(metrics.user_interaction);
    8.22 * av * ac * pr * ui
}

fn base_score(impact: f64, exploitability: f64, scope: Scope) -> f64 {
    if impact <= 0.0 {
        return 0.0;
    }
    let raw = match scope {
        Scope::Unchanged => impact + exploitability,
        Scope::Changed => 1.08 * (impact + exploitability),
    };
    roundup(raw.min(10.0))
}

/// CVSS v3.1 "round up" function: smallest number with 1 decimal place >= input.
fn roundup(value: f64) -> f64 {
    (value * 10.0).ceil() / 10.0
}

fn attack_vector_weight(av: AttackVector) -> f64 {
    match av {
        AttackVector::Network => 0.85,
        AttackVector::Adjacent => 0.62,
        AttackVector::Local => 0.55,
        AttackVector::Physical => 0.20,
    }
}

fn attack_complexity_weight(ac: AttackComplexity) -> f64 {
    match ac {
        AttackComplexity::Low => 0.77,
        AttackComplexity::High => 0.44,
    }
}

fn privileges_required_weight(pr: PrivilegesRequired, scope: Scope) -> f64 {
    match (pr, scope) {
        (PrivilegesRequired::None, _) => 0.85,
        (PrivilegesRequired::Low, Scope::Unchanged) => 0.62,
        (PrivilegesRequired::Low, Scope::Changed) => 0.68,
        (PrivilegesRequired::High, Scope::Unchanged) => 0.27,
        (PrivilegesRequired::High, Scope::Changed) => 0.50,
    }
}

fn user_interaction_weight(ui: UserInteraction) -> f64 {
    match ui {
        UserInteraction::None => 0.85,
        UserInteraction::Required => 0.62,
    }
}

fn impact_weight(impact: Impact) -> f64 {
    match impact {
        Impact::None => 0.0,
        Impact::Low => 0.22,
        Impact::High => 0.56,
    }
}

fn av_abbrev(av: AttackVector) -> &'static str {
    match av {
        AttackVector::Network => "N",
        AttackVector::Adjacent => "A",
        AttackVector::Local => "L",
        AttackVector::Physical => "P",
    }
}

fn ac_abbrev(ac: AttackComplexity) -> &'static str {
    match ac {
        AttackComplexity::Low => "L",
        AttackComplexity::High => "H",
    }
}

fn pr_abbrev(pr: PrivilegesRequired) -> &'static str {
    match pr {
        PrivilegesRequired::None => "N",
        PrivilegesRequired::Low => "L",
        PrivilegesRequired::High => "H",
    }
}

fn ui_abbrev(ui: UserInteraction) -> &'static str {
    match ui {
        UserInteraction::None => "N",
        UserInteraction::Required => "R",
    }
}

fn scope_abbrev(s: Scope) -> &'static str {
    match s {
        Scope::Unchanged => "U",
        Scope::Changed => "C",
    }
}

fn impact_abbrev(i: Impact) -> &'static str {
    match i {
        Impact::None => "N",
        Impact::Low => "L",
        Impact::High => "H",
    }
}

fn build_vector_string(m: &CvssMetrics) -> String {
    format!(
        "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
        av_abbrev(m.attack_vector),
        ac_abbrev(m.attack_complexity),
        pr_abbrev(m.privileges_required),
        ui_abbrev(m.user_interaction),
        scope_abbrev(m.scope),
        impact_abbrev(m.confidentiality),
        impact_abbrev(m.integrity),
        impact_abbrev(m.availability),
    )
}
