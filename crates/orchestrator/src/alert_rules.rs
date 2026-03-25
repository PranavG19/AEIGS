use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Severity threshold controlling which findings trigger alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    /// Maps a CVSS-like score (0.0–10.0) to severity.
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s >= 9.0 => AlertSeverity::Critical,
            s if s >= 7.0 => AlertSeverity::High,
            s if s >= 4.0 => AlertSeverity::Medium,
            s if s >= 0.1 => AlertSeverity::Low,
            _ => AlertSeverity::Info,
        }
    }
}

/// A finding that can be evaluated against alert rules.
#[derive(Debug, Clone)]
pub struct AlertFinding {
    pub finding_id: String,
    pub vulnerability_class: VulnerabilityClass,
    pub severity: AlertSeverity,
    pub endpoint: String,
    pub cwe_id: Option<u32>,
    pub owasp_category: Option<String>,
    pub score: f64,
    pub is_new: bool,
}

/// Rate-of-change context passed to the rule engine for spike detection.
#[derive(Debug, Clone)]
pub struct RateOfChangeContext {
    pub findings_current_scan: usize,
    pub findings_previous_scan: usize,
    pub time_delta_secs: u64,
}

impl RateOfChangeContext {
    /// Returns the absolute increase in finding count, or 0 if decreased.
    pub fn delta(&self) -> usize {
        self.findings_current_scan
            .saturating_sub(self.findings_previous_scan)
    }

    /// Returns the percentage increase over the previous scan. Returns 0.0
    /// when the baseline is zero to avoid division by zero.
    pub fn percent_increase(&self) -> f64 {
        if self.findings_previous_scan == 0 {
            return 0.0;
        }
        let delta = self.findings_current_scan as f64 - self.findings_previous_scan as f64;
        (delta / self.findings_previous_scan as f64) * 100.0
    }
}

/// Types of alert rules the engine supports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertRuleKind {
    SeverityThreshold {
        min_severity: AlertSeverity,
    },
    FindingTypeFilter {
        allowed_classes: HashSet<VulnerabilityClass>,
    },
    RateOfChange {
        min_delta: usize,
        min_percent_increase: f64,
    },
    ComplianceViolation {
        owasp_categories: HashSet<String>,
    },
    SpecificCwe {
        cwe_ids: HashSet<u32>,
    },
    EndpointMatch {
        patterns: Vec<String>,
    },
    NewFindingsOnly,
}

/// A named, configurable alert rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub rule_id: String,
    pub name: String,
    pub enabled: bool,
    pub kind: AlertRuleKind,
}

/// Result of evaluating a single finding against all rules.
#[derive(Debug, Clone)]
pub struct AlertMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub finding_id: String,
    pub reason: String,
}

/// Result of evaluating rate-of-change rules.
#[derive(Debug, Clone)]
pub struct RateAlert {
    pub rule_id: String,
    pub rule_name: String,
    pub delta: usize,
    pub percent_increase: f64,
    pub reason: String,
}

/// Configurable engine that evaluates findings against a set of alert rules.
pub struct AlertRuleEngine {
    rules: Vec<AlertRule>,
}

impl AlertRuleEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Adds a rule to the engine.
    pub fn add_rule(&mut self, rule: AlertRule) {
        self.rules.push(rule);
    }

    /// Removes a rule by ID. Returns true if a rule was removed.
    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.rule_id != rule_id);
        self.rules.len() < before
    }

    /// Returns the number of registered rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Evaluates a single finding against all enabled rules.
    /// Returns all matching alerts.
    pub fn evaluate_finding(&self, finding: &AlertFinding) -> Vec<AlertMatch> {
        let mut matches = Vec::new();
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if let Some(reason) = self.check_rule(rule, finding) {
                matches.push(AlertMatch {
                    rule_id: rule.rule_id.clone(),
                    rule_name: rule.name.clone(),
                    finding_id: finding.finding_id.clone(),
                    reason,
                });
            }
        }
        matches
    }

    /// Evaluates a batch of findings and returns all matches.
    pub fn evaluate_batch(&self, findings: &[AlertFinding]) -> Vec<AlertMatch> {
        findings
            .iter()
            .flat_map(|f| self.evaluate_finding(f))
            .collect()
    }

    /// Evaluates rate-of-change rules against aggregate scan context.
    pub fn evaluate_rate_of_change(&self, ctx: &RateOfChangeContext) -> Vec<RateAlert> {
        let mut alerts = Vec::new();
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if let AlertRuleKind::RateOfChange {
                min_delta,
                min_percent_increase,
            } = &rule.kind
            {
                let delta = ctx.delta();
                let pct = ctx.percent_increase();
                if delta >= *min_delta && pct >= *min_percent_increase {
                    alerts.push(RateAlert {
                        rule_id: rule.rule_id.clone(),
                        rule_name: rule.name.clone(),
                        delta,
                        percent_increase: pct,
                        reason: format!(
                            "Finding count increased by {delta} ({pct:.1}%): {} → {}",
                            ctx.findings_previous_scan, ctx.findings_current_scan
                        ),
                    });
                }
            }
        }
        alerts
    }

    fn check_rule(&self, rule: &AlertRule, finding: &AlertFinding) -> Option<String> {
        match &rule.kind {
            AlertRuleKind::SeverityThreshold { min_severity } => {
                if finding.severity >= *min_severity {
                    Some(format!(
                        "Finding {:?} meets severity threshold {:?}",
                        finding.severity, min_severity
                    ))
                } else {
                    None
                }
            }
            AlertRuleKind::FindingTypeFilter { allowed_classes } => {
                if allowed_classes.contains(&finding.vulnerability_class) {
                    Some(format!(
                        "Finding matches watched vulnerability class: {}",
                        finding.vulnerability_class
                    ))
                } else {
                    None
                }
            }
            AlertRuleKind::RateOfChange { .. } => None,
            AlertRuleKind::ComplianceViolation { owasp_categories } => {
                if let Some(cat) = &finding.owasp_category {
                    if owasp_categories.contains(cat) {
                        Some(format!("OWASP compliance violation: {cat}"))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            AlertRuleKind::SpecificCwe { cwe_ids } => {
                if let Some(cwe) = finding.cwe_id {
                    if cwe_ids.contains(&cwe) {
                        Some(format!("Matches watched CWE-{cwe}"))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            AlertRuleKind::EndpointMatch { patterns } => {
                for pattern in patterns {
                    if finding.endpoint.contains(pattern) {
                        return Some(format!(
                            "Endpoint {} matches pattern '{pattern}'",
                            finding.endpoint
                        ));
                    }
                }
                None
            }
            AlertRuleKind::NewFindingsOnly => {
                if finding.is_new {
                    Some("New finding detected".to_string())
                } else {
                    None
                }
            }
        }
    }
}

impl Default for AlertRuleEngine {
    fn default() -> Self {
        Self::new()
    }
}
