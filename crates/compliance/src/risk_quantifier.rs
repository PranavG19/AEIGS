use std::fmt;
use std::fmt::Write;

use aegis_protocol::finding::VulnerabilityClass;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::class_mapper::default_cvss_for_class;
use crate::cvss_scorer::{CvssSeverity, compute_cvss};

/// EPSS-like exploit probability score for a vulnerability class.
/// Values approximate real EPSS distributions by severity tier.
pub fn epss_estimate(vuln: VulnerabilityClass) -> f64 {
    match vuln {
        VulnerabilityClass::SqlInjection => 0.35,
        VulnerabilityClass::CommandInjection => 0.40,
        VulnerabilityClass::ServerSideTemplateInjection => 0.25,
        VulnerabilityClass::InsecureDeserialization => 0.30,
        VulnerabilityClass::ServerSideRequestForgery => 0.20,
        VulnerabilityClass::PathTraversal => 0.25,
        VulnerabilityClass::CrossSiteScripting => 0.15,
        VulnerabilityClass::NoSqlInjection => 0.28,
        VulnerabilityClass::XmlExternalEntity => 0.22,
        VulnerabilityClass::BrokenAuthentication => 0.30,
        VulnerabilityClass::JwtVulnerability => 0.25,
        VulnerabilityClass::BrokenAuthorization => 0.28,
        VulnerabilityClass::InsecureDirectObjectReference => 0.22,
        VulnerabilityClass::MassAssignment => 0.18,
        VulnerabilityClass::SecurityMisconfiguration => 0.10,
        VulnerabilityClass::MissingSecurityHeader => 0.05,
        VulnerabilityClass::CrossOriginMisconfiguration => 0.08,
        VulnerabilityClass::SensitiveDataExposure => 0.12,
        VulnerabilityClass::InformationDisclosure => 0.08,
        VulnerabilityClass::KnownVulnerableDependency => 0.20,
        VulnerabilityClass::HeaderInjection => 0.12,
        VulnerabilityClass::OpenRedirect => 0.10,
        VulnerabilityClass::CrlfInjection => 0.12,
        VulnerabilityClass::InsufficientInputValidation => 0.08,
        VulnerabilityClass::HttpRequestSmuggling => 0.15,
        VulnerabilityClass::RaceCondition => 0.10,
        VulnerabilityClass::SubdomainTakeover => 0.08,
        VulnerabilityClass::PrototypePollution => 0.12,
        VulnerabilityClass::GraphQlAbuse => 0.10,
        VulnerabilityClass::CloudMisconfiguration => 0.15,
        VulnerabilityClass::Clickjacking => 0.05,
        VulnerabilityClass::CachePoisoning => 0.08,
        VulnerabilityClass::HostHeaderInjection => 0.10,
        VulnerabilityClass::WeakCryptography => 0.12,
    }
}

/// Sensitivity level of exposed data, driving expected loss calculations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataSensitivity {
    Public,
    Internal,
    PersonalData,
    FinancialData,
    HealthData,
    Credentials,
}

impl fmt::Display for DataSensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataSensitivity::Public => write!(f, "Public"),
            DataSensitivity::Internal => write!(f, "Internal"),
            DataSensitivity::PersonalData => write!(f, "Personal Data (PII)"),
            DataSensitivity::FinancialData => write!(f, "Financial Data"),
            DataSensitivity::HealthData => write!(f, "Health Data (PHI)"),
            DataSensitivity::Credentials => write!(f, "Credentials"),
        }
    }
}

/// Base cost per record for a breach, in USD, by data sensitivity.
fn base_cost_per_record(sensitivity: DataSensitivity) -> f64 {
    match sensitivity {
        DataSensitivity::Public => 10.0,
        DataSensitivity::Internal => 50.0,
        DataSensitivity::PersonalData => 180.0,
        DataSensitivity::FinancialData => 250.0,
        DataSensitivity::HealthData => 430.0,
        DataSensitivity::Credentials => 200.0,
    }
}

/// Scope of a potential breach, driving record count estimates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreachScope {
    SingleRecord,
    Subset,
    FullDatabase,
    MultiSystem,
}

impl BreachScope {
    pub fn estimated_records(self) -> u64 {
        match self {
            BreachScope::SingleRecord => 1,
            BreachScope::Subset => 1_000,
            BreachScope::FullDatabase => 100_000,
            BreachScope::MultiSystem => 1_000_000,
        }
    }
}

impl fmt::Display for BreachScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BreachScope::SingleRecord => write!(f, "Single Record"),
            BreachScope::Subset => write!(f, "Subset (~1K records)"),
            BreachScope::FullDatabase => write!(f, "Full Database (~100K records)"),
            BreachScope::MultiSystem => write!(f, "Multi-System (~1M records)"),
        }
    }
}

/// A single finding to be risk-quantified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFinding {
    pub vulnerability_class: VulnerabilityClass,
    pub data_sensitivity: DataSensitivity,
    pub breach_scope: BreachScope,
    pub endpoint: String,
}

/// Input configuration for a risk quantification run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskQuantificationInput {
    pub findings: Vec<RiskFinding>,
    pub annual_revenue_usd: f64,
    pub simulation_iterations: u32,
}

/// Quantified risk for a single finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRiskScore {
    pub vulnerability_class: VulnerabilityClass,
    pub endpoint: String,
    pub epss_probability: f64,
    pub cvss_score: f64,
    pub cvss_severity: String,
    pub breach_probability: f64,
    pub expected_loss_usd: f64,
    pub risk_score: f64,
}

/// Confidence interval from Monte Carlo simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    pub p5: f64,
    pub p25: f64,
    pub p50: f64,
    pub p75: f64,
    pub p95: f64,
    pub mean: f64,
}

/// Complete risk quantification output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskQuantificationResult {
    pub finding_risks: Vec<FindingRiskScore>,
    pub total_expected_annual_loss: f64,
    pub total_risk_score: f64,
    pub monte_carlo_loss_distribution: ConfidenceInterval,
    pub risk_as_revenue_percentage: f64,
}

/// Computes breach probability from EPSS and CVSS severity.
///
/// Formula: breach_prob = EPSS × severity_multiplier
/// where severity_multiplier amplifies based on CVSS score tier.
fn breach_probability(epss: f64, cvss_score: f64) -> f64 {
    let severity_multiplier = match CvssSeverity::from(cvss_score) {
        CvssSeverity::Critical => 1.5,
        CvssSeverity::High => 1.2,
        CvssSeverity::Medium => 1.0,
        CvssSeverity::Low => 0.7,
        CvssSeverity::None => 0.3,
    };
    (epss * severity_multiplier).min(1.0)
}

impl CvssSeverity {
    fn from(score: f64) -> Self {
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
}

/// Computes expected loss for a single finding.
fn expected_loss(finding: &RiskFinding) -> f64 {
    let cost = base_cost_per_record(finding.data_sensitivity);
    let records = finding.breach_scope.estimated_records() as f64;
    cost * records
}

/// Quantifies risk for a single finding: probability, expected loss, risk score.
fn quantify_finding(finding: &RiskFinding) -> FindingRiskScore {
    let epss = epss_estimate(finding.vulnerability_class);
    let cvss_metrics = default_cvss_for_class(finding.vulnerability_class);
    let cvss_result = compute_cvss(&cvss_metrics);
    let breach_prob = breach_probability(epss, cvss_result.score);
    let loss = expected_loss(finding);
    let risk = breach_prob * loss;

    FindingRiskScore {
        vulnerability_class: finding.vulnerability_class,
        endpoint: finding.endpoint.clone(),
        epss_probability: epss,
        cvss_score: cvss_result.score,
        cvss_severity: cvss_result.severity_label.to_string(),
        breach_probability: breach_prob,
        expected_loss_usd: loss,
        risk_score: risk,
    }
}

/// Runs Monte Carlo simulation to estimate aggregate annual loss distribution.
///
/// Each iteration: for each finding, flip a weighted coin using breach_probability.
/// If breached, add the expected_loss with a random multiplier [0.5, 2.0] for variance.
/// Produces a distribution of total annual losses.
fn monte_carlo_simulation(
    finding_risks: &[FindingRiskScore],
    iterations: u32,
) -> ConfidenceInterval {
    let mut rng = rand::rng();
    let mut losses: Vec<f64> = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let mut yearly_loss = 0.0;
        for fr in finding_risks {
            let roll: f64 = rng.random();
            if roll < fr.breach_probability {
                let variance_multiplier: f64 = rng.random::<f64>() * 1.5 + 0.5;
                yearly_loss += fr.expected_loss_usd * variance_multiplier;
            }
        }
        losses.push(yearly_loss);
    }

    losses.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let len = losses.len();
    let mean = if len > 0 {
        losses.iter().sum::<f64>() / len as f64
    } else {
        0.0
    };

    ConfidenceInterval {
        p5: percentile(&losses, 5),
        p25: percentile(&losses, 25),
        p50: percentile(&losses, 50),
        p75: percentile(&losses, 75),
        p95: percentile(&losses, 95),
        mean,
    }
}

fn percentile(sorted: &[f64], p: u32) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p as f64 / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Main entry point: quantify risk across all findings with Monte Carlo confidence intervals.
pub fn quantify_risk(input: &RiskQuantificationInput) -> RiskQuantificationResult {
    let finding_risks: Vec<FindingRiskScore> =
        input.findings.iter().map(quantify_finding).collect();

    let total_expected = finding_risks.iter().map(|f| f.risk_score).sum::<f64>();
    let total_risk = finding_risks.iter().map(|f| f.risk_score).sum::<f64>();

    let iterations = if input.simulation_iterations == 0 {
        10_000
    } else {
        input.simulation_iterations
    };
    let mc = monte_carlo_simulation(&finding_risks, iterations);

    let revenue_pct = if input.annual_revenue_usd > 0.0 {
        (total_expected / input.annual_revenue_usd) * 100.0
    } else {
        0.0
    };

    RiskQuantificationResult {
        finding_risks,
        total_expected_annual_loss: total_expected,
        total_risk_score: total_risk,
        monte_carlo_loss_distribution: mc,
        risk_as_revenue_percentage: revenue_pct,
    }
}

/// Formats a risk quantification result as a human-readable report.
pub fn format_risk_report(result: &RiskQuantificationResult) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Risk Quantification Report\n");

    let _ = writeln!(out, "## Executive Summary\n");
    let _ = writeln!(
        out,
        "- **Total Expected Annual Loss:** ${:.2}",
        result.total_expected_annual_loss
    );
    let _ = writeln!(
        out,
        "- **Risk as % of Revenue:** {:.2}%",
        result.risk_as_revenue_percentage
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "## Monte Carlo Analysis (N iterations)\n");
    let mc = &result.monte_carlo_loss_distribution;
    let _ = writeln!(out, "| Percentile | Annual Loss |");
    let _ = writeln!(out, "|------------|-------------|");
    let _ = writeln!(out, "| 5th        | ${:.2} |", mc.p5);
    let _ = writeln!(out, "| 25th       | ${:.2} |", mc.p25);
    let _ = writeln!(out, "| 50th       | ${:.2} |", mc.p50);
    let _ = writeln!(out, "| 75th       | ${:.2} |", mc.p75);
    let _ = writeln!(out, "| 95th       | ${:.2} |", mc.p95);
    let _ = writeln!(out, "| Mean       | ${:.2} |", mc.mean);
    let _ = writeln!(out);

    let _ = writeln!(out, "## Finding-Level Risk\n");
    let _ = writeln!(
        out,
        "| Vulnerability | Endpoint | CVSS | EPSS | Breach Prob | Expected Loss | Risk Score |"
    );
    let _ = writeln!(
        out,
        "|---------------|----------|------|------|-------------|---------------|------------|"
    );
    for fr in &result.finding_risks {
        let _ = writeln!(
            out,
            "| {} | {} | {:.1} ({}) | {:.2} | {:.2} | ${:.2} | ${:.2} |",
            fr.vulnerability_class,
            fr.endpoint,
            fr.cvss_score,
            fr.cvss_severity,
            fr.epss_probability,
            fr.breach_probability,
            fr.expected_loss_usd,
            fr.risk_score,
        );
    }

    out
}
