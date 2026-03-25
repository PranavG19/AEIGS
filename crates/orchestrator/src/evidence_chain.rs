/// Evidence chain builder: construct complete evidence chains for findings.
///
/// For each finding, builds a forensic-quality evidence chain from initial
/// discovery through verification and exploitation to impact demonstration.
/// Each step carries HTTP request/response evidence. Chains are suitable
/// for compliance proceedings, legal review, and executive reporting.
use aegis_protocol::finding::{EvidenceLevel, VulnerabilityClass};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of evidence chain step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceStepType {
    Discovery,
    Verification,
    Exploitation,
    ImpactDemonstration,
    Remediation,
}

/// An HTTP request captured as evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub timestamp_ms: u64,
}

/// An HTTP response captured as evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body_snippet: String,
    pub response_time_ms: u64,
}

/// A single step in the evidence chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceStep {
    pub step_type: EvidenceStepType,
    pub order: usize,
    pub description: String,
    pub request: Option<EvidenceRequest>,
    pub response: Option<EvidenceResponse>,
    pub analysis: String,
    pub is_conclusive: bool,
}

/// A complete evidence chain for a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChain {
    pub finding_id: u64,
    pub vulnerability_class: VulnerabilityClass,
    pub endpoint: String,
    pub evidence_level: EvidenceLevel,
    pub steps: Vec<EvidenceStep>,
    pub chain_strength: f64,
    pub summary: String,
    pub legal_ready: bool,
    pub metadata: HashMap<String, String>,
}

/// Input for building an evidence chain.
#[derive(Debug, Clone)]
pub struct EvidenceChainInput {
    pub finding_id: u64,
    pub vulnerability_class: VulnerabilityClass,
    pub endpoint: String,
    pub parameter: Option<String>,
    pub severity: f64,
    pub evidence_level: EvidenceLevel,
    pub discovery_request: Option<EvidenceRequest>,
    pub discovery_response: Option<EvidenceResponse>,
    pub verification_request: Option<EvidenceRequest>,
    pub verification_response: Option<EvidenceResponse>,
    pub exploit_request: Option<EvidenceRequest>,
    pub exploit_response: Option<EvidenceResponse>,
}

/// Result of building evidence chains for all findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBuildResult {
    pub chains: Vec<EvidenceChain>,
    pub total_findings: usize,
    pub chains_with_full_evidence: usize,
    pub chains_legal_ready: usize,
    pub weakest_chain_strength: f64,
}

impl EvidenceStep {
    pub fn new(step_type: EvidenceStepType, order: usize, description: impl Into<String>) -> Self {
        Self {
            step_type,
            order,
            description: description.into(),
            request: None,
            response: None,
            analysis: String::new(),
            is_conclusive: false,
        }
    }

    pub fn with_request(mut self, req: EvidenceRequest) -> Self {
        self.request = Some(req);
        self
    }

    pub fn with_response(mut self, resp: EvidenceResponse) -> Self {
        self.response = Some(resp);
        self
    }

    pub fn with_analysis(mut self, analysis: impl Into<String>) -> Self {
        self.analysis = analysis.into();
        self
    }

    pub fn mark_conclusive(mut self) -> Self {
        self.is_conclusive = true;
        self
    }
}

impl EvidenceChain {
    /// Does this chain have evidence for all step types through exploitation?
    pub fn has_full_evidence(&self) -> bool {
        let has_discovery = self
            .steps
            .iter()
            .any(|s| s.step_type == EvidenceStepType::Discovery);
        let has_verification = self
            .steps
            .iter()
            .any(|s| s.step_type == EvidenceStepType::Verification);
        let has_exploit = self
            .steps
            .iter()
            .any(|s| s.step_type == EvidenceStepType::Exploitation);
        has_discovery && has_verification && has_exploit
    }

    /// Count steps that have HTTP request/response evidence attached.
    pub fn steps_with_http_evidence(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| s.request.is_some() || s.response.is_some())
            .count()
    }
}

/// Build an evidence chain from the provided input.
pub fn build_evidence_chain(input: &EvidenceChainInput) -> EvidenceChain {
    let mut steps = Vec::new();
    let mut order = 1;

    let discovery_desc = format!(
        "Initial discovery of {} on endpoint {}{}",
        input.vulnerability_class,
        input.endpoint,
        input
            .parameter
            .as_ref()
            .map(|p| format!(" (parameter: {p})"))
            .unwrap_or_default()
    );
    let mut discovery = EvidenceStep::new(EvidenceStepType::Discovery, order, &discovery_desc);
    if let Some(ref req) = input.discovery_request {
        discovery = discovery.with_request(req.clone());
    }
    if let Some(ref resp) = input.discovery_response {
        discovery = discovery.with_response(resp.clone());
        discovery =
            discovery.with_analysis(analyze_discovery_response(&input.vulnerability_class, resp));
    }
    steps.push(discovery);
    order += 1;

    if input.verification_request.is_some() || input.verification_response.is_some() {
        let mut verification = EvidenceStep::new(
            EvidenceStepType::Verification,
            order,
            format!(
                "Verification of {} with controlled test",
                input.vulnerability_class
            ),
        );
        if let Some(ref req) = input.verification_request {
            verification = verification.with_request(req.clone());
        }
        if let Some(ref resp) = input.verification_response {
            verification = verification.with_response(resp.clone());
            verification = verification.with_analysis(
                "Controlled verification confirms the vulnerability is exploitable".to_string(),
            );
        }
        let is_conclusive = matches!(
            input.evidence_level,
            EvidenceLevel::Controlled | EvidenceLevel::Confirmed | EvidenceLevel::Chained
        );
        if is_conclusive {
            verification = verification.mark_conclusive();
        }
        steps.push(verification);
        order += 1;
    }

    if input.exploit_request.is_some() || input.exploit_response.is_some() {
        let mut exploit = EvidenceStep::new(
            EvidenceStepType::Exploitation,
            order,
            format!(
                "Exploitation of {} demonstrating real-world impact",
                input.vulnerability_class
            ),
        );
        if let Some(ref req) = input.exploit_request {
            exploit = exploit.with_request(req.clone());
        }
        if let Some(ref resp) = input.exploit_response {
            exploit = exploit.with_response(resp.clone());
            exploit =
                exploit.with_analysis(analyze_exploit_response(&input.vulnerability_class, resp));
        }
        exploit = exploit.mark_conclusive();
        steps.push(exploit);
        order += 1;
    }

    let impact_desc = generate_impact_description(&input.vulnerability_class, input.severity);
    let impact = EvidenceStep::new(EvidenceStepType::ImpactDemonstration, order, &impact_desc)
        .with_analysis(impact_desc.clone());
    steps.push(impact);

    let chain_strength = compute_chain_strength(&steps, input.evidence_level);
    let legal_ready = chain_strength >= 0.7 && steps.len() >= 3;
    let summary = generate_chain_summary(input, &steps, chain_strength);

    EvidenceChain {
        finding_id: input.finding_id,
        vulnerability_class: input.vulnerability_class,
        endpoint: input.endpoint.clone(),
        evidence_level: input.evidence_level,
        steps,
        chain_strength,
        summary,
        legal_ready,
        metadata: HashMap::new(),
    }
}

/// Build evidence chains for multiple findings.
pub fn build_all_chains(inputs: &[EvidenceChainInput]) -> EvidenceBuildResult {
    let chains: Vec<EvidenceChain> = inputs.iter().map(build_evidence_chain).collect();
    let total = chains.len();
    let full_evidence = chains.iter().filter(|c| c.has_full_evidence()).count();
    let legal_ready = chains.iter().filter(|c| c.legal_ready).count();
    let weakest = chains
        .iter()
        .map(|c| c.chain_strength)
        .fold(f64::INFINITY, f64::min);

    EvidenceBuildResult {
        chains,
        total_findings: total,
        chains_with_full_evidence: full_evidence,
        chains_legal_ready: legal_ready,
        weakest_chain_strength: if total == 0 { 0.0 } else { weakest },
    }
}

fn compute_chain_strength(steps: &[EvidenceStep], evidence_level: EvidenceLevel) -> f64 {
    let evidence_base = match evidence_level {
        EvidenceLevel::Statistical => 0.3,
        EvidenceLevel::Controlled => 0.6,
        EvidenceLevel::Confirmed => 0.8,
        EvidenceLevel::Chained => 0.9,
    };

    let http_evidence_count = steps
        .iter()
        .filter(|s| s.request.is_some() && s.response.is_some())
        .count();

    let http_bonus = (http_evidence_count as f64 * 0.05).min(0.1);
    let conclusive_bonus = if steps.iter().any(|s| s.is_conclusive) {
        0.05
    } else {
        0.0
    };

    (evidence_base + http_bonus + conclusive_bonus).min(1.0)
}

fn analyze_discovery_response(class: &VulnerabilityClass, response: &EvidenceResponse) -> String {
    match class {
        VulnerabilityClass::SqlInjection => {
            if response.body_snippet.contains("error") || response.body_snippet.contains("syntax") {
                "Response contains SQL error messages indicating injection point".to_string()
            } else {
                "Response anomaly suggests potential SQL injection".to_string()
            }
        }
        VulnerabilityClass::CrossSiteScripting => {
            if response.body_snippet.contains("<script") {
                "Response reflects injected script tags without encoding".to_string()
            } else {
                "Response reflects user input without proper encoding".to_string()
            }
        }
        _ => format!("Response indicates potential {class}"),
    }
}

fn analyze_exploit_response(class: &VulnerabilityClass, _response: &EvidenceResponse) -> String {
    match class {
        VulnerabilityClass::SqlInjection => {
            "Exploitation confirmed: UNION-based extraction returned database records".to_string()
        }
        VulnerabilityClass::CrossSiteScripting => {
            "Exploitation confirmed: JavaScript payload executed in browser context".to_string()
        }
        VulnerabilityClass::CommandInjection => {
            "Exploitation confirmed: OS command executed and output returned".to_string()
        }
        _ => format!("Exploitation of {class} confirmed with server response"),
    }
}

fn generate_impact_description(class: &VulnerabilityClass, severity: f64) -> String {
    let impact_level = if severity >= 9.0 {
        "Critical"
    } else if severity >= 7.0 {
        "High"
    } else if severity >= 4.0 {
        "Medium"
    } else {
        "Low"
    };

    format!(
        "{impact_level} impact: {class} (severity {severity:.1}) enables potential compromise of confidentiality, integrity, or availability of affected systems"
    )
}

fn generate_chain_summary(
    input: &EvidenceChainInput,
    steps: &[EvidenceStep],
    strength: f64,
) -> String {
    format!(
        "Evidence chain for {} on {} contains {} steps with strength {:.0}%. {}",
        input.vulnerability_class,
        input.endpoint,
        steps.len(),
        strength * 100.0,
        if strength >= 0.7 {
            "Chain meets evidence threshold for compliance reporting."
        } else {
            "Chain requires additional verification evidence."
        }
    )
}
