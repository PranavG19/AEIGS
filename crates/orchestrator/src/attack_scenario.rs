/// Attack scenario generator: produce realistic multi-step attack narratives.
///
/// Given accumulated intelligence about a target (tech stack, findings, defenses,
/// credentials), generates plausible attack scenarios describing how a real attacker
/// would chain vulnerabilities and techniques to achieve objectives. Each scenario
/// has ordered steps, likelihood assessment, and impact rating.
use aegis_protocol::finding::{EvidenceLevel, VulnerabilityClass};
use serde::{Deserialize, Serialize};

/// The attacker's objective for a scenario.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackObjective {
    DataExfiltration,
    PrivilegeEscalation,
    RemoteCodeExecution,
    AccountTakeover,
    DenialOfService,
    LateralMovement,
    PersistentAccess,
    Custom(String),
}

/// Difficulty level of an attack step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepDifficulty {
    Trivial,
    Easy,
    Moderate,
    Hard,
    Expert,
}

/// A single step in an attack scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioStep {
    pub order: usize,
    pub technique: String,
    pub description: String,
    pub vulnerability_class: Option<VulnerabilityClass>,
    pub target_endpoint: Option<String>,
    pub difficulty: StepDifficulty,
    pub requires_auth: bool,
    pub prerequisites: Vec<String>,
    pub evidence_available: bool,
}

/// A complete attack scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackScenario {
    pub id: String,
    pub name: String,
    pub narrative: String,
    pub objective: AttackObjective,
    pub steps: Vec<ScenarioStep>,
    pub likelihood: f64,
    pub impact: f64,
    pub risk_score: f64,
    pub mitigations: Vec<String>,
    pub affected_assets: Vec<String>,
}

/// Input context for scenario generation.
#[derive(Debug, Clone)]
pub struct ScenarioContext {
    pub target_url: String,
    pub findings: Vec<ScenarioFinding>,
    pub tech_stack: Vec<String>,
    pub has_waf: bool,
    pub has_auth: bool,
    pub known_endpoints: Vec<String>,
}

/// Simplified finding for scenario generation input.
#[derive(Debug, Clone)]
pub struct ScenarioFinding {
    pub vulnerability_class: VulnerabilityClass,
    pub endpoint: String,
    pub severity: f64,
    pub confidence: f64,
    pub evidence_level: EvidenceLevel,
}

/// Result of scenario generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioGenerationResult {
    pub scenarios: Vec<AttackScenario>,
    pub highest_risk: f64,
    pub total_scenarios: usize,
    pub objectives_covered: Vec<AttackObjective>,
}

/// Chain template: known multi-vuln attack patterns.
struct ChainTemplate {
    name: &'static str,
    narrative_template: &'static str,
    required_classes: Vec<VulnerabilityClass>,
    objective: AttackObjective,
    base_likelihood: f64,
    base_impact: f64,
}

fn known_chain_templates() -> Vec<ChainTemplate> {
    vec![
        ChainTemplate {
            name: "SQLi to Data Exfiltration",
            narrative_template: "Attacker discovers SQL injection on {endpoint}, extracts database schema, then dumps sensitive tables including user credentials and PII.",
            required_classes: vec![VulnerabilityClass::SqlInjection],
            objective: AttackObjective::DataExfiltration,
            base_likelihood: 0.85,
            base_impact: 9.5,
        },
        ChainTemplate {
            name: "XSS to Account Takeover",
            narrative_template: "Attacker crafts stored/reflected XSS payload on {endpoint}, steals session cookies or auth tokens, hijacks victim accounts with elevated privileges.",
            required_classes: vec![VulnerabilityClass::CrossSiteScripting],
            objective: AttackObjective::AccountTakeover,
            base_likelihood: 0.7,
            base_impact: 8.0,
        },
        ChainTemplate {
            name: "SSRF to Internal Access",
            narrative_template: "Attacker exploits SSRF on {endpoint} to probe internal services, discovers cloud metadata endpoint, extracts IAM credentials for lateral movement.",
            required_classes: vec![VulnerabilityClass::ServerSideRequestForgery],
            objective: AttackObjective::LateralMovement,
            base_likelihood: 0.65,
            base_impact: 9.0,
        },
        ChainTemplate {
            name: "Command Injection to RCE",
            narrative_template: "Attacker exploits command injection on {endpoint}, establishes reverse shell, escalates privileges on the host, installs persistent backdoor.",
            required_classes: vec![VulnerabilityClass::CommandInjection],
            objective: AttackObjective::RemoteCodeExecution,
            base_likelihood: 0.8,
            base_impact: 10.0,
        },
        ChainTemplate {
            name: "Auth Bypass to Privilege Escalation",
            narrative_template: "Attacker exploits broken authentication on {endpoint}, accesses admin panel, modifies role assignments to escalate privileges across the application.",
            required_classes: vec![VulnerabilityClass::BrokenAuthentication],
            objective: AttackObjective::PrivilegeEscalation,
            base_likelihood: 0.75,
            base_impact: 9.0,
        },
        ChainTemplate {
            name: "SSTI to RCE",
            narrative_template: "Attacker discovers template injection on {endpoint}, crafts payload to escape sandbox, achieves server-side code execution.",
            required_classes: vec![VulnerabilityClass::ServerSideTemplateInjection],
            objective: AttackObjective::RemoteCodeExecution,
            base_likelihood: 0.7,
            base_impact: 9.5,
        },
        ChainTemplate {
            name: "IDOR to Data Exfiltration",
            narrative_template: "Attacker enumerates insecure direct object references on {endpoint}, systematically accesses other users' data, exfiltrates sensitive records.",
            required_classes: vec![VulnerabilityClass::InsecureDirectObjectReference],
            objective: AttackObjective::DataExfiltration,
            base_likelihood: 0.8,
            base_impact: 7.5,
        },
        ChainTemplate {
            name: "SQLi + XSS Chained Attack",
            narrative_template: "Attacker combines SQL injection for data extraction with stored XSS for persistent access. Injects malicious scripts into database, which execute when admin views data.",
            required_classes: vec![
                VulnerabilityClass::SqlInjection,
                VulnerabilityClass::CrossSiteScripting,
            ],
            objective: AttackObjective::PersistentAccess,
            base_likelihood: 0.6,
            base_impact: 9.5,
        },
    ]
}

/// Generate attack scenarios from the provided context.
pub fn generate_scenarios(ctx: &ScenarioContext) -> ScenarioGenerationResult {
    let templates = known_chain_templates();
    let mut scenarios = Vec::new();
    let mut scenario_counter = 0u32;

    for template in &templates {
        let matching_findings: Vec<&ScenarioFinding> = template
            .required_classes
            .iter()
            .filter_map(|required| {
                ctx.findings
                    .iter()
                    .find(|f| f.vulnerability_class == *required)
            })
            .collect();

        if matching_findings.len() != template.required_classes.len() {
            continue;
        }

        scenario_counter += 1;
        let primary = &matching_findings[0];

        let narrative = template
            .narrative_template
            .replace("{endpoint}", &primary.endpoint);

        let waf_penalty = if ctx.has_waf { 0.8 } else { 1.0 };
        let confidence_factor = primary.confidence;
        let likelihood =
            (template.base_likelihood * waf_penalty * confidence_factor).clamp(0.0, 1.0);

        let evidence_boost = match primary.evidence_level {
            EvidenceLevel::Confirmed | EvidenceLevel::Chained => 1.0,
            EvidenceLevel::Controlled => 0.9,
            EvidenceLevel::Statistical => 0.7,
        };
        let impact = (template.base_impact * evidence_boost).clamp(0.0, 10.0);
        let risk_score = likelihood * impact;

        let mut steps = Vec::new();
        for (i, finding) in matching_findings.iter().enumerate() {
            steps.push(ScenarioStep {
                order: i + 1,
                technique: finding.vulnerability_class.to_string(),
                description: format!(
                    "Exploit {} on {}",
                    finding.vulnerability_class, finding.endpoint
                ),
                vulnerability_class: Some(finding.vulnerability_class),
                target_endpoint: Some(finding.endpoint.clone()),
                difficulty: severity_to_difficulty(finding.severity),
                requires_auth: ctx.has_auth,
                prerequisites: if i > 0 {
                    vec![format!("Step {}", i)]
                } else {
                    vec![]
                },
                evidence_available: finding.evidence_level != EvidenceLevel::Statistical,
            });
        }

        let mitigations = generate_mitigations(&template.required_classes);

        scenarios.push(AttackScenario {
            id: format!("scenario-{scenario_counter:03}"),
            name: template.name.to_string(),
            narrative,
            objective: template.objective.clone(),
            steps,
            likelihood,
            impact,
            risk_score,
            mitigations,
            affected_assets: matching_findings
                .iter()
                .map(|f| f.endpoint.clone())
                .collect(),
        });
    }

    scenarios.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let highest_risk = scenarios.first().map(|s| s.risk_score).unwrap_or(0.0);
    let objectives_covered: Vec<AttackObjective> = scenarios
        .iter()
        .map(|s| s.objective.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let total = scenarios.len();

    ScenarioGenerationResult {
        scenarios,
        highest_risk,
        total_scenarios: total,
        objectives_covered,
    }
}

fn severity_to_difficulty(severity: f64) -> StepDifficulty {
    if severity >= 9.0 {
        StepDifficulty::Trivial
    } else if severity >= 7.0 {
        StepDifficulty::Easy
    } else if severity >= 5.0 {
        StepDifficulty::Moderate
    } else if severity >= 3.0 {
        StepDifficulty::Hard
    } else {
        StepDifficulty::Expert
    }
}

fn generate_mitigations(classes: &[VulnerabilityClass]) -> Vec<String> {
    let mut mitigations = Vec::new();
    for class in classes {
        match class {
            VulnerabilityClass::SqlInjection => {
                mitigations.push("Use parameterized queries / prepared statements".to_string());
                mitigations.push("Implement input validation with allowlists".to_string());
            }
            VulnerabilityClass::CrossSiteScripting => {
                mitigations.push("Implement context-aware output encoding".to_string());
                mitigations.push("Deploy Content-Security-Policy headers".to_string());
            }
            VulnerabilityClass::ServerSideRequestForgery => {
                mitigations
                    .push("Validate and allowlist outbound request destinations".to_string());
                mitigations.push("Block access to cloud metadata endpoints".to_string());
            }
            VulnerabilityClass::CommandInjection => {
                mitigations
                    .push("Avoid shell command execution; use language-native APIs".to_string());
                mitigations.push("Implement strict input validation and sandboxing".to_string());
            }
            VulnerabilityClass::BrokenAuthentication => {
                mitigations.push("Implement multi-factor authentication".to_string());
                mitigations
                    .push("Use secure session management with proper token rotation".to_string());
            }
            VulnerabilityClass::ServerSideTemplateInjection => {
                mitigations
                    .push("Use logic-less templates or sandboxed template engines".to_string());
                mitigations
                    .push("Never pass user input directly to template rendering".to_string());
            }
            VulnerabilityClass::InsecureDirectObjectReference => {
                mitigations
                    .push("Implement authorization checks on every resource access".to_string());
                mitigations
                    .push("Use indirect references (UUIDs) instead of sequential IDs".to_string());
            }
            _ => {
                mitigations.push(format!("Remediate {} per OWASP guidelines", class));
            }
        }
    }
    mitigations
}

/// Rank scenarios by risk and return top N.
pub fn top_scenarios(result: &ScenarioGenerationResult, n: usize) -> Vec<&AttackScenario> {
    result.scenarios.iter().take(n).collect()
}

/// Filter scenarios by objective.
pub fn scenarios_by_objective<'a>(
    result: &'a ScenarioGenerationResult,
    objective: &AttackObjective,
) -> Vec<&'a AttackScenario> {
    result
        .scenarios
        .iter()
        .filter(|s| &s.objective == objective)
        .collect()
}
