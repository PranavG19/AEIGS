use crate::operation::ModuleIdentifier;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceLevel {
    Statistical,
    Counterfactual,
    Confirmed,
    Chained,
}

impl fmt::Display for EvidenceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvidenceLevel::Statistical => write!(f, "Statistical"),
            EvidenceLevel::Counterfactual => write!(f, "Counterfactual"),
            EvidenceLevel::Confirmed => write!(f, "Confirmed"),
            EvidenceLevel::Chained => write!(f, "Chained"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VulnerabilityClass {
    SqlInjection,
    CrossSiteScripting,
    CommandInjection,
    PathTraversal,
    ServerSideRequestForgery,
    InsecureDeserialization,
    BrokenAuthentication,
    BrokenAuthorization,
    SecurityMisconfiguration,
    SensitiveDataExposure,
    ServerSideTemplateInjection,
    HeaderInjection,
    OpenRedirect,
    CrlfInjection,
    KnownVulnerableDependency,
    InsufficientInputValidation,
}

impl fmt::Display for VulnerabilityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VulnerabilityClass::SqlInjection => write!(f, "SQL Injection"),
            VulnerabilityClass::CrossSiteScripting => write!(f, "Cross-Site Scripting"),
            VulnerabilityClass::CommandInjection => write!(f, "Command Injection"),
            VulnerabilityClass::PathTraversal => write!(f, "Path Traversal"),
            VulnerabilityClass::ServerSideRequestForgery => {
                write!(f, "Server-Side Request Forgery")
            }
            VulnerabilityClass::InsecureDeserialization => write!(f, "Insecure Deserialization"),
            VulnerabilityClass::BrokenAuthentication => write!(f, "Broken Authentication"),
            VulnerabilityClass::BrokenAuthorization => write!(f, "Broken Authorization"),
            VulnerabilityClass::SecurityMisconfiguration => write!(f, "Security Misconfiguration"),
            VulnerabilityClass::SensitiveDataExposure => write!(f, "Sensitive Data Exposure"),
            VulnerabilityClass::ServerSideTemplateInjection => {
                write!(f, "Server-Side Template Injection")
            }
            VulnerabilityClass::HeaderInjection => write!(f, "Header Injection"),
            VulnerabilityClass::OpenRedirect => write!(f, "Open Redirect"),
            VulnerabilityClass::CrlfInjection => write!(f, "CRLF Injection"),
            VulnerabilityClass::KnownVulnerableDependency => {
                write!(f, "Known Vulnerable Dependency")
            }
            VulnerabilityClass::InsufficientInputValidation => {
                write!(f, "Insufficient Input Validation")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingData {
    pub id: u64,
    pub linked_node_ids: Vec<u64>,
    pub vulnerability_class: VulnerabilityClass,
    pub severity: f64,
    pub confidence: f64,
    pub certificate: Vec<u8>,
    pub provenance_module: ModuleIdentifier,
    pub timestamp_unix_ms: u64,
    pub evidence_level: EvidenceLevel,
    #[serde(default)]
    pub confidence_score: Option<f64>,
}

impl FindingData {
    pub fn new(
        id: u64,
        vulnerability_class: VulnerabilityClass,
        severity: f64,
        confidence: f64,
        provenance_module: ModuleIdentifier,
        timestamp_unix_ms: u64,
    ) -> Self {
        Self {
            id,
            linked_node_ids: Vec::new(),
            vulnerability_class,
            severity,
            confidence,
            certificate: Vec::new(),
            provenance_module,
            timestamp_unix_ms,
            evidence_level: EvidenceLevel::Statistical,
            confidence_score: None,
        }
    }

    pub fn with_linked_nodes(mut self, node_ids: Vec<u64>) -> Self {
        self.linked_node_ids = node_ids;
        self
    }

    pub fn with_certificate(mut self, certificate: Vec<u8>) -> Self {
        self.certificate = certificate;
        self
    }

    pub fn with_evidence_level(mut self, level: EvidenceLevel) -> Self {
        self.evidence_level = level;
        self
    }

    pub fn with_confidence_score(mut self, score: f64) -> Self {
        self.confidence_score = Some(score.clamp(0.0, 1.0));
        self
    }

    pub fn effective_confidence(&self) -> f64 {
        self.confidence_score.unwrap_or_else(|| {
            confidence_from_evidence_and_variance(self.evidence_level, 0.0)
        })
    }
}

pub fn confidence_from_evidence_and_variance(evidence: EvidenceLevel, variance: f64) -> f64 {
    let base = match evidence {
        EvidenceLevel::Statistical => 0.4,
        EvidenceLevel::Counterfactual => 0.7,
        EvidenceLevel::Confirmed => 0.9,
        EvidenceLevel::Chained => 0.95,
    };
    let variance_penalty = variance.clamp(0.0, 1.0) * 0.5;
    (base - variance_penalty).clamp(0.0, 1.0)
}
