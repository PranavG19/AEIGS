use std::collections::HashMap;

use crate::canary_scanner::{CanaryRisk, CanaryToken};
use crate::honeypot_detector::{
    HoneypotDetectorResult, HoneypotIndicator, HoneypotType, IndicatorType,
};
use crate::ids_detector::IdsDetectorResult;

#[derive(Debug, Clone, PartialEq)]
pub struct DeceptionMap {
    pub endpoints: Vec<EndpointClassification>,
    pub canary_credentials: Vec<CanaryCredential>,
    pub honeypot_services: Vec<HoneypotService>,
    pub deception_coverage: DeceptionCoverage,
    pub safe_attack_paths: Vec<String>,
    pub avoid_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EndpointClassification {
    pub path: String,
    pub classification: EndpointType,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointType {
    Real,
    Decoy,
    Honeypot,
    CanaryProtected,
    Unknown,
}

impl std::fmt::Display for EndpointType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Real => write!(f, "Real"),
            Self::Decoy => write!(f, "Decoy"),
            Self::Honeypot => write!(f, "Honeypot"),
            Self::CanaryProtected => write!(f, "Canary-Protected"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CanaryCredential {
    pub credential_type: String,
    pub location: String,
    pub risk_level: CanaryRisk,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HoneypotService {
    pub service_type: HoneypotType,
    pub indicators: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeceptionCoverage {
    pub total_endpoints: usize,
    pub real_endpoints: usize,
    pub decoy_endpoints: usize,
    pub honeypot_endpoints: usize,
    pub canary_protected: usize,
    pub unknown_endpoints: usize,
    pub deception_ratio: f64,
}

impl Default for DeceptionCoverage {
    fn default() -> Self {
        Self {
            total_endpoints: 0,
            real_endpoints: 0,
            decoy_endpoints: 0,
            honeypot_endpoints: 0,
            canary_protected: 0,
            unknown_endpoints: 0,
            deception_ratio: 0.0,
        }
    }
}

impl std::fmt::Display for DeceptionCoverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} endpoints ({} real, {} decoy, {} honeypot, {} canary, {} unknown) — {:.0}% deception",
            self.total_endpoints,
            self.real_endpoints,
            self.decoy_endpoints,
            self.honeypot_endpoints,
            self.canary_protected,
            self.unknown_endpoints,
            self.deception_ratio * 100.0,
        )
    }
}

pub struct DeceptionMapper;

impl std::fmt::Debug for DeceptionMapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeceptionMapper").finish()
    }
}

impl DeceptionMapper {
    pub fn new() -> Self {
        Self
    }

    /// Build a deception map from collected intelligence.
    /// Combines honeypot detection, IDS detection, canary tokens, and endpoint lists.
    pub fn build_map(
        &self,
        discovered_paths: &[String],
        honeypot_result: Option<&HoneypotDetectorResult>,
        _ids_result: Option<&IdsDetectorResult>,
        canary_tokens: &[CanaryToken],
    ) -> DeceptionMap {
        let mut endpoints = Vec::new();
        let mut canary_credentials = Vec::new();
        let mut honeypot_services = Vec::new();
        let mut safe_paths = Vec::new();
        let mut avoid_paths = Vec::new();

        let canary_locations: HashMap<&str, &CanaryToken> = canary_tokens
            .iter()
            .map(|ct| (ct.location.as_str(), ct))
            .collect();

        let honeypot_paths = extract_honeypot_paths(honeypot_result);

        for path in discovered_paths {
            let classification =
                classify_endpoint(path, &canary_locations, &honeypot_paths, honeypot_result);
            match classification.classification {
                EndpointType::Real | EndpointType::Unknown => {
                    safe_paths.push(path.clone());
                }
                EndpointType::Decoy | EndpointType::Honeypot | EndpointType::CanaryProtected => {
                    avoid_paths.push(path.clone());
                }
            }
            endpoints.push(classification);
        }

        for ct in canary_tokens {
            canary_credentials.push(CanaryCredential {
                credential_type: format!("{}", ct.token_type),
                location: ct.location.clone(),
                risk_level: ct.risk_level,
                description: ct.description.clone(),
            });
        }

        if let Some(hp) = honeypot_result {
            if hp.is_honeypot {
                honeypot_services.push(HoneypotService {
                    service_type: hp.honeypot_type.unwrap_or(HoneypotType::Unknown),
                    indicators: hp
                        .indicators
                        .iter()
                        .map(|i| i.description.clone())
                        .collect(),
                    confidence: hp.confidence,
                });
            }
        }

        let coverage = compute_coverage(&endpoints);

        DeceptionMap {
            endpoints,
            canary_credentials,
            honeypot_services,
            deception_coverage: coverage,
            safe_attack_paths: safe_paths,
            avoid_paths,
        }
    }
}

fn classify_endpoint(
    path: &str,
    canary_locations: &HashMap<&str, &CanaryToken>,
    honeypot_paths: &[String],
    honeypot_result: Option<&HoneypotDetectorResult>,
) -> EndpointClassification {
    let mut evidence = Vec::new();
    let mut classification = EndpointType::Unknown;
    let mut confidence = 0.5;

    if canary_locations.contains_key(path) {
        classification = EndpointType::CanaryProtected;
        confidence = 0.9;
        evidence.push(format!("Canary token detected at this path"));
    }

    if honeypot_paths.iter().any(|hp| path.contains(hp.as_str())) {
        classification = EndpointType::Honeypot;
        confidence = 0.85;
        evidence.push("Path matches honeypot indicator".to_string());
    }

    if let Some(hp) = honeypot_result {
        if hp.is_honeypot {
            for ind in &hp.indicators {
                if matches!(
                    ind.indicator_type,
                    IndicatorType::DecoyEndpoint | IndicatorType::TooPermissive
                ) {
                    if classification == EndpointType::Unknown {
                        classification = EndpointType::Decoy;
                        confidence = hp.confidence * 0.7;
                        evidence.push(format!("Honeypot detection: {}", ind.description));
                    }
                }
            }
        }
    }

    if classification == EndpointType::Unknown && is_common_real_path(path) {
        classification = EndpointType::Real;
        confidence = 0.6;
        evidence.push("Path matches common real endpoint pattern".to_string());
    }

    EndpointClassification {
        path: path.to_string(),
        classification,
        confidence,
        evidence,
    }
}

fn extract_honeypot_paths(honeypot_result: Option<&HoneypotDetectorResult>) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(hp) = honeypot_result {
        for ind in &hp.indicators {
            if matches!(
                ind.indicator_type,
                IndicatorType::FakeLoginPage | IndicatorType::DecoyEndpoint
            ) {
                let desc = &ind.description;
                if let Some(start) = desc.find('\'') {
                    if let Some(end) = desc[start + 1..].find('\'') {
                        let path = &desc[start + 1..start + 1 + end];
                        paths.push(path.to_string());
                    }
                }
            }
        }
    }
    paths
}

fn is_common_real_path(path: &str) -> bool {
    let real_patterns = [
        "/api/", "/v1/", "/v2/", "/graphql", "/health", "/status", "/static/", "/assets/", "/css/",
        "/js/", "/images/", "/index", "/home", "/about", "/contact",
    ];
    real_patterns.iter().any(|p| path.contains(p))
}

fn compute_coverage(endpoints: &[EndpointClassification]) -> DeceptionCoverage {
    let total = endpoints.len();
    if total == 0 {
        return DeceptionCoverage::default();
    }

    let real = endpoints
        .iter()
        .filter(|e| e.classification == EndpointType::Real)
        .count();
    let decoy = endpoints
        .iter()
        .filter(|e| e.classification == EndpointType::Decoy)
        .count();
    let honeypot = endpoints
        .iter()
        .filter(|e| e.classification == EndpointType::Honeypot)
        .count();
    let canary = endpoints
        .iter()
        .filter(|e| e.classification == EndpointType::CanaryProtected)
        .count();
    let unknown = endpoints
        .iter()
        .filter(|e| e.classification == EndpointType::Unknown)
        .count();
    let deception = decoy + honeypot + canary;

    DeceptionCoverage {
        total_endpoints: total,
        real_endpoints: real,
        decoy_endpoints: decoy,
        honeypot_endpoints: honeypot,
        canary_protected: canary,
        unknown_endpoints: unknown,
        deception_ratio: deception as f64 / total as f64,
    }
}
