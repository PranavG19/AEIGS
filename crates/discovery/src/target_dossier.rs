use serde::{Deserialize, Serialize};

/// Risk level classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
            Self::Informational => write!(f, "Informational"),
        }
    }
}

/// Executive summary of the dossier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub target_name: String,
    pub target_type: TargetType,
    pub overall_risk: RiskLevel,
    pub risk_score: f64,
    pub key_findings: Vec<KeyFinding>,
    pub recommended_actions: Vec<String>,
    pub generated_at: String,
}

/// Whether the target is a person or organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetType {
    Person,
    Organization,
    Both,
}

impl std::fmt::Display for TargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Person => write!(f, "Person"),
            Self::Organization => write!(f, "Organization"),
            Self::Both => write!(f, "Person & Organization"),
        }
    }
}

/// A key finding in the dossier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFinding {
    pub category: FindingCategory,
    pub title: String,
    pub description: String,
    pub risk_level: RiskLevel,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

/// Category of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingCategory {
    CredentialExposure,
    InfrastructureWeakness,
    SocialEngineeringVector,
    DataLeakage,
    MisconfiguredService,
    StaleAsset,
    SupplyChainRisk,
    InsiderThreat,
    PhysicalSecurity,
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CredentialExposure => write!(f, "Credential Exposure"),
            Self::InfrastructureWeakness => write!(f, "Infrastructure Weakness"),
            Self::SocialEngineeringVector => write!(f, "Social Engineering Vector"),
            Self::DataLeakage => write!(f, "Data Leakage"),
            Self::MisconfiguredService => write!(f, "Misconfigured Service"),
            Self::StaleAsset => write!(f, "Stale Asset"),
            Self::SupplyChainRisk => write!(f, "Supply Chain Risk"),
            Self::InsiderThreat => write!(f, "Insider Threat"),
            Self::PhysicalSecurity => write!(f, "Physical Security"),
        }
    }
}

/// An attack surface entry point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceEntry {
    pub entry_point: String,
    pub entry_type: EntryPointType,
    pub risk_score: f64,
    pub technologies: Vec<String>,
    pub vulnerabilities: Vec<String>,
    pub notes: Vec<String>,
}

/// Type of entry point in the attack surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntryPointType {
    WebApplication,
    ApiEndpoint,
    EmailGateway,
    VpnGateway,
    SshServer,
    DatabaseServer,
    CloudStorage,
    DnsServer,
    AdminPanel,
    CiCdPipeline,
    ThirdPartyIntegration,
    MobileApp,
}

impl std::fmt::Display for EntryPointType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WebApplication => write!(f, "Web Application"),
            Self::ApiEndpoint => write!(f, "API Endpoint"),
            Self::EmailGateway => write!(f, "Email Gateway"),
            Self::VpnGateway => write!(f, "VPN Gateway"),
            Self::SshServer => write!(f, "SSH Server"),
            Self::DatabaseServer => write!(f, "Database Server"),
            Self::CloudStorage => write!(f, "Cloud Storage"),
            Self::DnsServer => write!(f, "DNS Server"),
            Self::AdminPanel => write!(f, "Admin Panel"),
            Self::CiCdPipeline => write!(f, "CI/CD Pipeline"),
            Self::ThirdPartyIntegration => write!(f, "Third-Party Integration"),
            Self::MobileApp => write!(f, "Mobile App"),
        }
    }
}

/// Credential intelligence summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub total_breaches: usize,
    pub total_credentials: usize,
    pub api_keys_found: usize,
    pub reuse_probability: f64,
    pub most_recent_breach: Option<String>,
    pub exposed_data_types: Vec<String>,
}

/// Social engineering playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialEngineeringPlaybook {
    pub recommended_pretexts: Vec<RecommendedPretext>,
    pub optimal_timing: Vec<String>,
    pub susceptibility_score: f64,
    pub primary_attack_vector: String,
}

/// A recommended pretext with success estimate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedPretext {
    pub name: String,
    pub description: String,
    pub target_audience: String,
    pub success_estimate: f64,
}

/// Technical attack plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnicalAttackPlan {
    pub priority_targets: Vec<PriorityTarget>,
    pub recommended_tools: Vec<String>,
    pub estimated_timeline: String,
    pub required_resources: Vec<String>,
}

/// A prioritized target for technical testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityTarget {
    pub target: String,
    pub attack_type: String,
    pub priority: u8,
    pub rationale: String,
    pub expected_difficulty: Difficulty,
}

/// Difficulty level for an attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Difficulty {
    Trivial,
    Easy,
    Moderate,
    Hard,
    Expert,
}

impl std::fmt::Display for Difficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trivial => write!(f, "Trivial"),
            Self::Easy => write!(f, "Easy"),
            Self::Moderate => write!(f, "Moderate"),
            Self::Hard => write!(f, "Hard"),
            Self::Expert => write!(f, "Expert"),
        }
    }
}

/// OPSEC assessment of the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsecAssessment {
    pub awareness_level: AwarenessLevel,
    pub security_controls: Vec<SecurityControl>,
    pub training_evidence: Vec<String>,
    pub incident_response_readiness: f64,
    pub overall_opsec_score: f64,
}

/// Target's security awareness level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AwarenessLevel {
    Excellent,
    Good,
    Average,
    Poor,
    Negligible,
}

impl std::fmt::Display for AwarenessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Excellent => write!(f, "Excellent"),
            Self::Good => write!(f, "Good"),
            Self::Average => write!(f, "Average"),
            Self::Poor => write!(f, "Poor"),
            Self::Negligible => write!(f, "Negligible"),
        }
    }
}

/// A detected security control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityControl {
    pub control_name: String,
    pub is_present: bool,
    pub effectiveness: f64,
    pub notes: Option<String>,
}

/// The complete target dossier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetDossier {
    pub executive_summary: ExecutiveSummary,
    pub attack_surface: Vec<AttackSurfaceEntry>,
    pub credential_intel: CredentialSummary,
    pub social_engineering: SocialEngineeringPlaybook,
    pub technical_plan: TechnicalAttackPlan,
    pub opsec_assessment: OpsecAssessment,
}

/// Classify risk level from a numeric score (0-100).
pub fn classify_risk(score: f64) -> RiskLevel {
    match score as u32 {
        80..=100 => RiskLevel::Critical,
        60..=79 => RiskLevel::High,
        40..=59 => RiskLevel::Medium,
        20..=39 => RiskLevel::Low,
        _ => RiskLevel::Informational,
    }
}

/// Generate key findings from gathered intelligence scores.
pub fn generate_key_findings(
    credential_score: f64,
    infra_score: f64,
    social_eng_score: f64,
    breach_count: usize,
    api_keys_found: usize,
    open_ports: usize,
    stale_assets: usize,
) -> Vec<KeyFinding> {
    let mut findings = Vec::new();

    if breach_count > 0 {
        findings.push(KeyFinding {
            category: FindingCategory::CredentialExposure,
            title: format!("{breach_count} breach(es) detected for target credentials"),
            description: format!(
                "Target credentials appear in {breach_count} known data breaches. \
                 Credential reuse or password pattern exploitation is probable."
            ),
            risk_level: if breach_count > 3 {
                RiskLevel::Critical
            } else if breach_count > 1 {
                RiskLevel::High
            } else {
                RiskLevel::Medium
            },
            confidence: 0.90,
            evidence: vec![format!("{breach_count} breaches discovered")],
        });
    }

    if api_keys_found > 0 {
        findings.push(KeyFinding {
            category: FindingCategory::DataLeakage,
            title: format!("{api_keys_found} API key(s) discovered in public repositories"),
            description: format!(
                "Found {api_keys_found} leaked API keys or secrets in public code \
                 repositories and paste sites."
            ),
            risk_level: RiskLevel::Critical,
            confidence: 0.85,
            evidence: vec![format!("{api_keys_found} keys found")],
        });
    }

    if infra_score > 50.0 {
        findings.push(KeyFinding {
            category: FindingCategory::InfrastructureWeakness,
            title: "Elevated infrastructure exposure detected".to_string(),
            description: format!(
                "Infrastructure exposure score of {infra_score:.0}/100 indicates significant \
                 attack surface with {open_ports} open ports discovered."
            ),
            risk_level: classify_risk(infra_score),
            confidence: 0.80,
            evidence: vec![
                format!("{open_ports} open ports"),
                format!("Infra score: {infra_score:.0}"),
            ],
        });
    }

    if social_eng_score > 50.0 {
        findings.push(KeyFinding {
            category: FindingCategory::SocialEngineeringVector,
            title: "High social engineering susceptibility".to_string(),
            description: format!(
                "Target social engineering susceptibility score of {social_eng_score:.0}/100 \
                 suggests viable phishing and pretexting attack vectors."
            ),
            risk_level: classify_risk(social_eng_score),
            confidence: 0.75,
            evidence: vec![format!("SE score: {social_eng_score:.0}")],
        });
    }

    if stale_assets > 0 {
        findings.push(KeyFinding {
            category: FindingCategory::StaleAsset,
            title: format!("{stale_assets} stale or decommissioned asset(s) found"),
            description: format!(
                "Discovered {stale_assets} assets that appear decommissioned but still accessible. \
                 These may have outdated software or unpatched vulnerabilities."
            ),
            risk_level: RiskLevel::Medium,
            confidence: 0.70,
            evidence: vec![format!("{stale_assets} stale assets")],
        });
    }

    if credential_score > 60.0 {
        findings.push(KeyFinding {
            category: FindingCategory::CredentialExposure,
            title: "Significant credential intelligence gathered".to_string(),
            description: format!(
                "Overall credential exposure score of {credential_score:.0}/100 indicates \
                 substantial password and credential intelligence is available for exploitation."
            ),
            risk_level: classify_risk(credential_score),
            confidence: 0.85,
            evidence: vec![format!("Credential score: {credential_score:.0}")],
        });
    }

    findings.sort_by(|a, b| {
        let rank = |r: &RiskLevel| match r {
            RiskLevel::Critical => 0,
            RiskLevel::High => 1,
            RiskLevel::Medium => 2,
            RiskLevel::Low => 3,
            RiskLevel::Informational => 4,
        };
        rank(&a.risk_level).cmp(&rank(&b.risk_level))
    });

    findings
}

/// Build attack surface entries from discovered services.
pub fn build_attack_surface(
    web_endpoints: &[(&str, &[&str])],
    open_services: &[(&str, u16, &str)],
    cloud_assets: &[(&str, &str)],
    third_party: &[(&str, &str)],
) -> Vec<AttackSurfaceEntry> {
    let mut entries = Vec::new();

    for &(endpoint, ref techs) in web_endpoints {
        let risk = if endpoint.contains("admin") || endpoint.contains("dashboard") {
            0.85
        } else if endpoint.contains("api") {
            0.70
        } else if endpoint.contains("login") || endpoint.contains("auth") {
            0.75
        } else {
            0.50
        };

        let entry_type = if endpoint.contains("api") {
            EntryPointType::ApiEndpoint
        } else if endpoint.contains("admin") {
            EntryPointType::AdminPanel
        } else {
            EntryPointType::WebApplication
        };

        entries.push(AttackSurfaceEntry {
            entry_point: endpoint.to_string(),
            entry_type,
            risk_score: risk,
            technologies: techs.iter().map(|t| t.to_string()).collect(),
            vulnerabilities: Vec::new(),
            notes: Vec::new(),
        });
    }

    for &(host, port, service) in open_services {
        let (entry_type, risk) = match (port, service) {
            (22, _) | (_, "ssh") => (EntryPointType::SshServer, 0.40),
            (3306 | 5432 | 27017 | 6379, _) => (EntryPointType::DatabaseServer, 0.90),
            (53, _) | (_, "dns") => (EntryPointType::DnsServer, 0.30),
            (25 | 465 | 587, _) => (EntryPointType::EmailGateway, 0.50),
            (1194, _) | (_, "openvpn") => (EntryPointType::VpnGateway, 0.60),
            _ => (EntryPointType::WebApplication, 0.45),
        };

        entries.push(AttackSurfaceEntry {
            entry_point: format!("{host}:{port}"),
            entry_type,
            risk_score: risk,
            technologies: vec![service.to_string()],
            vulnerabilities: Vec::new(),
            notes: Vec::new(),
        });
    }

    for &(name, provider) in cloud_assets {
        entries.push(AttackSurfaceEntry {
            entry_point: name.to_string(),
            entry_type: EntryPointType::CloudStorage,
            risk_score: 0.55,
            technologies: vec![provider.to_string()],
            vulnerabilities: Vec::new(),
            notes: vec!["Check for public access".to_string()],
        });
    }

    for &(vendor, integration_type) in third_party {
        entries.push(AttackSurfaceEntry {
            entry_point: vendor.to_string(),
            entry_type: EntryPointType::ThirdPartyIntegration,
            risk_score: 0.45,
            technologies: vec![integration_type.to_string()],
            vulnerabilities: Vec::new(),
            notes: vec!["Supply chain attack vector".to_string()],
        });
    }

    entries.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());
    entries
}

/// Generate technical attack plan from findings.
pub fn generate_attack_plan(
    attack_surface: &[AttackSurfaceEntry],
    has_credentials: bool,
    has_api_keys: bool,
) -> TechnicalAttackPlan {
    let mut targets = Vec::new();
    let mut tools = vec!["nmap".to_string(), "burpsuite".to_string()];

    for (idx, entry) in attack_surface.iter().take(10).enumerate() {
        let (attack_type, difficulty) = match entry.entry_type {
            EntryPointType::DatabaseServer => {
                tools.push("sqlmap".to_string());
                (
                    "Database enumeration and injection testing".to_string(),
                    Difficulty::Moderate,
                )
            }
            EntryPointType::WebApplication | EntryPointType::AdminPanel => {
                tools.push("nuclei".to_string());
                (
                    "Web vulnerability scanning and manual testing".to_string(),
                    Difficulty::Moderate,
                )
            }
            EntryPointType::ApiEndpoint => {
                tools.push("ffuf".to_string());
                (
                    "API fuzzing and authentication bypass".to_string(),
                    Difficulty::Hard,
                )
            }
            EntryPointType::SshServer => (
                "SSH brute force and key-based attacks".to_string(),
                Difficulty::Hard,
            ),
            EntryPointType::CloudStorage => {
                tools.push("aws-cli".to_string());
                (
                    "Cloud bucket enumeration and access testing".to_string(),
                    Difficulty::Easy,
                )
            }
            EntryPointType::VpnGateway => (
                "VPN vulnerability assessment".to_string(),
                Difficulty::Expert,
            ),
            _ => (
                "Service enumeration and testing".to_string(),
                Difficulty::Moderate,
            ),
        };

        targets.push(PriorityTarget {
            target: entry.entry_point.clone(),
            attack_type,
            priority: (idx as u8) + 1,
            rationale: format!("Risk score: {:.0}/100", entry.risk_score * 100.0),
            expected_difficulty: difficulty,
        });
    }

    if has_credentials {
        tools.push("hydra".to_string());
        targets.insert(
            0,
            PriorityTarget {
                target: "Credential-based attacks".to_string(),
                attack_type: "Credential stuffing with known breach data".to_string(),
                priority: 0,
                rationale: "Known credentials available from breach data".to_string(),
                expected_difficulty: Difficulty::Easy,
            },
        );
    }

    if has_api_keys {
        targets.insert(
            if has_credentials { 1 } else { 0 },
            PriorityTarget {
                target: "Leaked API key exploitation".to_string(),
                attack_type: "Validate and exploit discovered API keys".to_string(),
                priority: 0,
                rationale: "API keys found in public repositories".to_string(),
                expected_difficulty: Difficulty::Trivial,
            },
        );
    }

    for (idx, target) in targets.iter_mut().enumerate() {
        target.priority = (idx as u8) + 1;
    }

    tools.sort();
    tools.dedup();

    let timeline = if targets.len() > 7 {
        "2-3 weeks estimated for full assessment".to_string()
    } else if targets.len() > 3 {
        "1-2 weeks estimated for full assessment".to_string()
    } else {
        "3-5 days estimated for full assessment".to_string()
    };

    TechnicalAttackPlan {
        priority_targets: targets,
        recommended_tools: tools,
        estimated_timeline: timeline,
        required_resources: vec![
            "Pentest workstation".to_string(),
            "VPN/proxy infrastructure".to_string(),
            "Cloud testing accounts".to_string(),
        ],
    }
}

/// Assess the target's operational security.
pub fn assess_opsec(
    has_dmarc_reject: bool,
    has_dnssec: bool,
    has_security_headers: bool,
    has_waf: bool,
    has_mfa_evidence: bool,
    social_exposure_score: f64,
    breach_count: usize,
) -> OpsecAssessment {
    let mut controls = Vec::new();

    controls.push(SecurityControl {
        control_name: "DMARC Policy (reject)".to_string(),
        is_present: has_dmarc_reject,
        effectiveness: if has_dmarc_reject { 0.85 } else { 0.0 },
        notes: if has_dmarc_reject {
            Some("Strong email authentication".to_string())
        } else {
            Some("Email spoofing possible".to_string())
        },
    });

    controls.push(SecurityControl {
        control_name: "DNSSEC".to_string(),
        is_present: has_dnssec,
        effectiveness: if has_dnssec { 0.80 } else { 0.0 },
        notes: None,
    });

    controls.push(SecurityControl {
        control_name: "Security Headers".to_string(),
        is_present: has_security_headers,
        effectiveness: if has_security_headers { 0.70 } else { 0.0 },
        notes: None,
    });

    controls.push(SecurityControl {
        control_name: "Web Application Firewall".to_string(),
        is_present: has_waf,
        effectiveness: if has_waf { 0.75 } else { 0.0 },
        notes: None,
    });

    controls.push(SecurityControl {
        control_name: "Multi-Factor Authentication".to_string(),
        is_present: has_mfa_evidence,
        effectiveness: if has_mfa_evidence { 0.90 } else { 0.0 },
        notes: None,
    });

    let controls_present = controls.iter().filter(|c| c.is_present).count();
    let total_controls = controls.len();

    let control_score = (controls_present as f64 / total_controls as f64) * 40.0;
    let exposure_penalty = social_exposure_score * 0.30;
    let breach_penalty = (breach_count as f64 / 5.0).min(1.0) * 30.0;

    let opsec_score = (control_score - exposure_penalty - breach_penalty + 50.0)
        .max(0.0)
        .min(100.0);

    let awareness = match opsec_score as u32 {
        80..=100 => AwarenessLevel::Excellent,
        60..=79 => AwarenessLevel::Good,
        40..=59 => AwarenessLevel::Average,
        20..=39 => AwarenessLevel::Poor,
        _ => AwarenessLevel::Negligible,
    };

    let mut training_evidence = Vec::new();
    if has_mfa_evidence {
        training_evidence.push("MFA deployment suggests security awareness program".to_string());
    }
    if has_dmarc_reject && has_security_headers {
        training_evidence.push(
            "Comprehensive email and web security controls indicate trained team".to_string(),
        );
    }
    if breach_count == 0 {
        training_evidence
            .push("No known breaches suggests effective security practices".to_string());
    }

    let ir_readiness = if has_waf && has_mfa_evidence && has_dmarc_reject {
        0.80
    } else if controls_present >= 3 {
        0.60
    } else if controls_present >= 1 {
        0.35
    } else {
        0.15
    };

    OpsecAssessment {
        awareness_level: awareness,
        security_controls: controls,
        training_evidence,
        incident_response_readiness: ir_readiness,
        overall_opsec_score: opsec_score,
    }
}

/// Build the complete target dossier.
pub fn build_target_dossier(
    target_name: &str,
    target_type: TargetType,
    executive_summary: ExecutiveSummary,
    attack_surface: Vec<AttackSurfaceEntry>,
    credential_intel: CredentialSummary,
    social_engineering: SocialEngineeringPlaybook,
    technical_plan: TechnicalAttackPlan,
    opsec_assessment: OpsecAssessment,
) -> TargetDossier {
    TargetDossier {
        executive_summary,
        attack_surface,
        credential_intel,
        social_engineering,
        technical_plan,
        opsec_assessment,
    }
}

/// Render the dossier as structured JSON.
pub fn render_dossier_json(dossier: &TargetDossier) -> String {
    serde_json::to_string_pretty(dossier).unwrap_or_else(|_| "{}".to_string())
}

/// Render the dossier as a markdown report.
pub fn render_dossier_markdown(dossier: &TargetDossier) -> String {
    let mut md = String::new();

    md.push_str("# Target Dossier\n\n");
    md.push_str(&format!("## Executive Summary\n\n"));
    md.push_str(&format!(
        "**Target:** {}\n\n",
        dossier.executive_summary.target_name
    ));
    md.push_str(&format!(
        "**Type:** {}\n\n",
        dossier.executive_summary.target_type
    ));
    md.push_str(&format!(
        "**Overall Risk:** {} ({:.0}/100)\n\n",
        dossier.executive_summary.overall_risk, dossier.executive_summary.risk_score
    ));
    md.push_str(&format!(
        "**Generated:** {}\n\n",
        dossier.executive_summary.generated_at
    ));

    if !dossier.executive_summary.key_findings.is_empty() {
        md.push_str("### Key Findings\n\n");
        for (idx, finding) in dossier.executive_summary.key_findings.iter().enumerate() {
            md.push_str(&format!(
                "{}. **[{}]** {} - {}\n",
                idx + 1,
                finding.risk_level,
                finding.title,
                finding.description
            ));
        }
        md.push('\n');
    }

    md.push_str("## Attack Surface Map\n\n");
    md.push_str("| Entry Point | Type | Risk Score | Technologies |\n");
    md.push_str("|---|---|---|---|\n");
    for entry in &dossier.attack_surface {
        md.push_str(&format!(
            "| {} | {} | {:.0} | {} |\n",
            entry.entry_point,
            entry.entry_type,
            entry.risk_score * 100.0,
            entry.technologies.join(", ")
        ));
    }
    md.push('\n');

    md.push_str("## Credential Intelligence\n\n");
    md.push_str(&format!(
        "- **Total Breaches:** {}\n",
        dossier.credential_intel.total_breaches
    ));
    md.push_str(&format!(
        "- **Total Credentials:** {}\n",
        dossier.credential_intel.total_credentials
    ));
    md.push_str(&format!(
        "- **API Keys Found:** {}\n",
        dossier.credential_intel.api_keys_found
    ));
    md.push_str(&format!(
        "- **Reuse Probability:** {:.0}%\n\n",
        dossier.credential_intel.reuse_probability * 100.0
    ));

    md.push_str("## Social Engineering Playbook\n\n");
    md.push_str(&format!(
        "**Susceptibility:** {:.0}/100\n\n",
        dossier.social_engineering.susceptibility_score
    ));
    md.push_str(&format!(
        "**Primary Vector:** {}\n\n",
        dossier.social_engineering.primary_attack_vector
    ));

    for pretext in &dossier.social_engineering.recommended_pretexts {
        md.push_str(&format!(
            "- **{}** (success est: {:.0}%): {}\n",
            pretext.name,
            pretext.success_estimate * 100.0,
            pretext.description
        ));
    }
    md.push('\n');

    md.push_str("## Technical Attack Plan\n\n");
    md.push_str(&format!(
        "**Timeline:** {}\n\n",
        dossier.technical_plan.estimated_timeline
    ));
    md.push_str("### Priority Targets\n\n");
    for target in &dossier.technical_plan.priority_targets {
        md.push_str(&format!(
            "{}. **{}** - {} [{}]\n",
            target.priority, target.target, target.attack_type, target.expected_difficulty
        ));
    }
    md.push('\n');

    md.push_str("## OPSEC Assessment\n\n");
    md.push_str(&format!(
        "**Awareness Level:** {}\n\n",
        dossier.opsec_assessment.awareness_level
    ));
    md.push_str(&format!(
        "**OPSEC Score:** {:.0}/100\n\n",
        dossier.opsec_assessment.overall_opsec_score
    ));
    md.push_str(&format!(
        "**IR Readiness:** {:.0}%\n\n",
        dossier.opsec_assessment.incident_response_readiness * 100.0
    ));

    md.push_str("### Security Controls\n\n");
    for control in &dossier.opsec_assessment.security_controls {
        let status = if control.is_present {
            "Present"
        } else {
            "Missing"
        };
        md.push_str(&format!(
            "- **{}**: {} (effectiveness: {:.0}%)\n",
            control.control_name,
            status,
            control.effectiveness * 100.0
        ));
    }

    md
}
