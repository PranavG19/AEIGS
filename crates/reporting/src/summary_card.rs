use std::collections::{HashMap, HashSet};

use aegis_protocol::finding::VulnerabilityClass;
use serde::Serialize;

use crate::report_format::{DefenseSummary, ReportMetadata};
use crate::sarif_emitter::SarifFinding;

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummaryCard {
    pub target_info: TargetInfo,
    pub scan_duration: ScanDuration,
    pub severity_breakdown: SeverityBreakdown,
    pub top_critical_findings: Vec<CriticalFinding>,
    pub attack_surface: AttackSurfaceStats,
    pub compliance_status: ScanComplianceStatus,
    pub next_scan_recommendation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetInfo {
    pub url: String,
    pub scan_date: String,
    pub tool_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanDuration {
    pub total_seconds: f64,
    pub phases_completed: u32,
    pub formatted: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SeverityBreakdown {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub total: usize,
    pub overall_rating: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CriticalFinding {
    pub rule_id: String,
    pub vulnerability_class: String,
    pub composite_score: f64,
    pub endpoint: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackSurfaceStats {
    pub total_endpoints: usize,
    pub unique_vulnerability_classes: usize,
    pub endpoints_with_findings: usize,
    pub most_affected_endpoint: Option<String>,
    pub defense_posture: DefensePosture,
}

#[derive(Debug, Clone, Serialize)]
pub struct DefensePosture {
    pub waf_active: bool,
    pub rate_limiting_active: bool,
    pub bot_detection_active: bool,
    pub overall: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanComplianceStatus {
    pub owasp_top10_coverage: Vec<OwaspCategory>,
    pub passing_categories: usize,
    pub total_categories: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct OwaspCategory {
    pub id: String,
    pub name: String,
    pub status: String,
    pub finding_count: usize,
}

pub fn generate_summary_card(
    findings: &[SarifFinding],
    metadata: Option<&ReportMetadata>,
    defense_summary: Option<&DefenseSummary>,
    tool_version: &str,
) -> ScanSummaryCard {
    let (url, duration_secs, phases) = match metadata {
        Some(m) => (
            m.target_url.clone(),
            m.total_duration_secs,
            m.phases_completed,
        ),
        None => (String::new(), 0.0, 0),
    };

    let target_info = TargetInfo {
        url,
        scan_date: chrono_free_now(),
        tool_version: tool_version.to_string(),
    };

    let scan_duration = ScanDuration {
        total_seconds: duration_secs,
        phases_completed: phases,
        formatted: format_duration(duration_secs),
    };

    let severity_breakdown = compute_severity_breakdown(findings);
    let top_critical_findings = extract_top_critical(findings, 5);
    let attack_surface = compute_attack_surface(findings, defense_summary);
    let compliance_status = compute_compliance_status(findings);
    let next_scan_recommendation = recommend_next_scan(findings);

    ScanSummaryCard {
        target_info,
        scan_duration,
        severity_breakdown,
        top_critical_findings,
        attack_surface,
        compliance_status,
        next_scan_recommendation,
    }
}

/// Format seconds into a human-readable duration string.
/// Returns "Xh Ym Zs" for hours, "Xm Ys" for minutes, or "Xs" for seconds.
pub fn format_duration(seconds: f64) -> String {
    let total_secs = seconds as u64;
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    if hours > 0 {
        format!("{hours}h {minutes}m {secs}s")
    } else if minutes > 0 {
        format!("{minutes}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

pub fn card_severity_rating(score: f64) -> &'static str {
    if score >= 70.0 {
        "Critical"
    } else if score >= 40.0 {
        "High"
    } else if score >= 20.0 {
        "Medium"
    } else {
        "Low"
    }
}

pub fn compute_severity_breakdown(findings: &[SarifFinding]) -> SeverityBreakdown {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    for f in findings {
        match card_severity_rating(f.composite_score) {
            "Critical" => critical += 1,
            "High" => high += 1,
            "Medium" => medium += 1,
            _ => low += 1,
        }
    }

    let total = findings.len();
    let overall_rating = if critical > 0 {
        "Critical"
    } else if high > 0 {
        "High"
    } else if medium > 0 {
        "Medium"
    } else if low > 0 {
        "Low"
    } else {
        "Clean"
    }
    .to_string();

    SeverityBreakdown {
        critical,
        high,
        medium,
        low,
        total,
        overall_rating,
    }
}

pub fn extract_top_critical(findings: &[SarifFinding], count: usize) -> Vec<CriticalFinding> {
    let mut sorted: Vec<&SarifFinding> = findings.iter().collect();
    sorted.sort_by(|a, b| {
        b.composite_score
            .partial_cmp(&a.composite_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    sorted
        .into_iter()
        .take(count)
        .map(|f| CriticalFinding {
            rule_id: f.rule_id.clone(),
            vulnerability_class: f
                .vulnerability_class
                .as_ref()
                .map(|vc| format!("{vc}"))
                .unwrap_or_else(|| "Unknown".to_string()),
            composite_score: f.composite_score,
            endpoint: f.endpoint.clone().unwrap_or_else(|| "N/A".to_string()),
            description: f.message.clone(),
        })
        .collect()
}

pub fn compute_attack_surface(
    findings: &[SarifFinding],
    defense_summary: Option<&DefenseSummary>,
) -> AttackSurfaceStats {
    let mut endpoint_counts: HashMap<String, usize> = HashMap::new();
    let mut vuln_classes: HashSet<String> = HashSet::new();

    for f in findings {
        if let Some(ep) = &f.endpoint {
            *endpoint_counts.entry(ep.clone()).or_insert(0) += 1;
        }
        if let Some(vc) = &f.vulnerability_class {
            vuln_classes.insert(format!("{vc}"));
        }
    }

    let total_endpoints = endpoint_counts.len();
    let most_affected_endpoint = endpoint_counts
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(ep, _)| ep.clone());

    let defense_posture = build_defense_posture(defense_summary);

    AttackSurfaceStats {
        total_endpoints,
        unique_vulnerability_classes: vuln_classes.len(),
        endpoints_with_findings: total_endpoints,
        most_affected_endpoint,
        defense_posture,
    }
}

fn build_defense_posture(defense_summary: Option<&DefenseSummary>) -> DefensePosture {
    match defense_summary {
        Some(ds) => {
            let active_count =
                ds.has_waf as u8 + ds.has_rate_limiting as u8 + ds.has_bot_detection as u8;
            let overall = match active_count {
                3 => "Strong",
                2 => "Moderate",
                1 => "Weak",
                _ => "None",
            }
            .to_string();

            DefensePosture {
                waf_active: ds.has_waf,
                rate_limiting_active: ds.has_rate_limiting,
                bot_detection_active: ds.has_bot_detection,
                overall,
            }
        }
        None => DefensePosture {
            waf_active: false,
            rate_limiting_active: false,
            bot_detection_active: false,
            overall: "None".to_string(),
        },
    }
}

pub fn compute_compliance_status(findings: &[SarifFinding]) -> ScanComplianceStatus {
    let owasp_mapping: Vec<(&str, &str, &[VulnerabilityClass])> = vec![
        (
            "A01",
            "Broken Access Control",
            &[
                VulnerabilityClass::BrokenAuthorization,
                VulnerabilityClass::InsecureDirectObjectReference,
                VulnerabilityClass::MassAssignment,
                VulnerabilityClass::CrossOriginMisconfiguration,
            ],
        ),
        (
            "A02",
            "Cryptographic Failures",
            &[
                VulnerabilityClass::WeakCryptography,
                VulnerabilityClass::SensitiveDataExposure,
            ],
        ),
        (
            "A03",
            "Injection",
            &[
                VulnerabilityClass::SqlInjection,
                VulnerabilityClass::CommandInjection,
                VulnerabilityClass::CrossSiteScripting,
                VulnerabilityClass::NoSqlInjection,
                VulnerabilityClass::XmlExternalEntity,
                VulnerabilityClass::ServerSideTemplateInjection,
                VulnerabilityClass::CrlfInjection,
                VulnerabilityClass::HeaderInjection,
            ],
        ),
        (
            "A04",
            "Insecure Design",
            &[
                VulnerabilityClass::RaceCondition,
                VulnerabilityClass::InsufficientInputValidation,
            ],
        ),
        (
            "A05",
            "Security Misconfiguration",
            &[
                VulnerabilityClass::SecurityMisconfiguration,
                VulnerabilityClass::CloudMisconfiguration,
                VulnerabilityClass::MissingSecurityHeader,
            ],
        ),
        (
            "A06",
            "Vulnerable and Outdated Components",
            &[VulnerabilityClass::KnownVulnerableDependency],
        ),
        (
            "A07",
            "Identification and Authentication Failures",
            &[
                VulnerabilityClass::BrokenAuthentication,
                VulnerabilityClass::JwtVulnerability,
            ],
        ),
        (
            "A08",
            "Software and Data Integrity Failures",
            &[
                VulnerabilityClass::InsecureDeserialization,
                VulnerabilityClass::PrototypePollution,
            ],
        ),
        (
            "A09",
            "Security Logging and Monitoring Failures",
            &[], // no current VulnerabilityClass maps here
        ),
        (
            "A10",
            "Server-Side Request Forgery",
            &[VulnerabilityClass::ServerSideRequestForgery],
        ),
    ];

    let finding_classes: Vec<&VulnerabilityClass> = findings
        .iter()
        .filter_map(|f| f.vulnerability_class.as_ref())
        .collect();

    let mut categories = Vec::with_capacity(owasp_mapping.len());
    let mut passing = 0;

    for (id, name, mapped_classes) in &owasp_mapping {
        let count = finding_classes
            .iter()
            .filter(|fc| mapped_classes.contains(fc))
            .count();
        let status = if count == 0 { "Pass" } else { "Fail" };
        if count == 0 {
            passing += 1;
        }
        categories.push(OwaspCategory {
            id: id.to_string(),
            name: name.to_string(),
            status: status.to_string(),
            finding_count: count,
        });
    }

    ScanComplianceStatus {
        owasp_top10_coverage: categories,
        passing_categories: passing,
        total_categories: owasp_mapping.len(),
    }
}

pub fn recommend_next_scan(findings: &[SarifFinding]) -> String {
    let mut has_critical = false;
    let mut has_high = false;
    let mut has_medium = false;
    let mut critical_count = 0usize;

    for f in findings {
        match card_severity_rating(f.composite_score) {
            "Critical" => {
                has_critical = true;
                critical_count += 1;
            }
            "High" => has_high = true,
            "Medium" => has_medium = true,
            _ => {}
        }
    }

    if has_critical {
        format!("Immediate rescan recommended after fixing {critical_count} critical findings")
    } else if has_high {
        "Rescan within 1 week after addressing high-severity findings".to_string()
    } else if has_medium {
        "Rescan within 2 weeks to verify remediation".to_string()
    } else {
        "Schedule routine scan in 30 days".to_string()
    }
}

pub fn summary_card_to_json(card: &ScanSummaryCard) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(card)
}

/// Produces a date string without pulling in the `chrono` crate.
/// Uses `UNIX_EPOCH` elapsed seconds formatted as an ISO-ish stamp.
fn chrono_free_now() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let days = secs / 86400;
    // Good-enough year/month/day from epoch days (no leap-second pedantry).
    let (year, month, day) = epoch_days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}")
}

fn epoch_days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's civil_from_days (public domain).
    days += 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
