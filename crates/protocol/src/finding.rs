use crate::operation::ModuleIdentifier;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;

/// A content-addressed stable identity for a finding, computed from its
/// intrinsic properties. Two findings representing the same vulnerability
/// at the same location have equal `FindingId` values even across scans.
///
/// Computed as SHA3-256(endpoint + ":" + vulnerability_class + ":" + parameter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingId {
    bytes: [u8; 32],
}

impl FindingId {
    /// Computes a stable identity from the finding's intrinsic location properties.
    pub fn from_parts(
        endpoint: &str,
        vulnerability_class: VulnerabilityClass,
        parameter: &str,
    ) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(endpoint.as_bytes());
        hasher.update(b":");
        hasher.update(vulnerability_class.to_string().as_bytes());
        hasher.update(b":");
        hasher.update(parameter.as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self { bytes }
    }
}

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
    #[serde(default)]
    pub stable_id: Option<FindingId>,
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
            stable_id: None,
        }
    }

    /// Computes and attaches a stable content-addressed identity to this finding.
    ///
    /// The identity is derived from the endpoint, vulnerability class, and parameter name,
    /// enabling cross-scan deduplication without relying on mutable store indices.
    pub fn with_stable_id(mut self, endpoint: &str, parameter: &str) -> Self {
        self.stable_id = Some(FindingId::from_parts(
            endpoint,
            self.vulnerability_class,
            parameter,
        ));
        self
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
        self.confidence_score
            .unwrap_or_else(|| confidence_from_evidence(self.evidence_level))
    }
}

pub fn confidence_from_evidence(evidence: EvidenceLevel) -> f64 {
    match evidence {
        EvidenceLevel::Statistical => 0.4,
        EvidenceLevel::Counterfactual => 0.7,
        EvidenceLevel::Confirmed => 0.9,
        EvidenceLevel::Chained => 0.95,
    }
}
