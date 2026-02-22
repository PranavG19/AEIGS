use crate::operation::ModuleIdentifier;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;

/// A validated confidence score in the range [0.0, 1.0].
///
/// Always present on `FindingData` — eliminates the dual code path of
/// `Option<f64>` + `effective_confidence()` fallback.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Confidence(f64);

impl Confidence {
    /// Creates a new Confidence value, rejecting values outside [0.0, 1.0] and NaN/Inf.
    pub fn new(value: f64) -> Result<Self, &'static str> {
        if !value.is_finite() {
            return Err("confidence must be finite");
        }
        if !(0.0..=1.0).contains(&value) {
            return Err("confidence must be in [0.0, 1.0]");
        }
        Ok(Self(value))
    }

    /// Maps an `EvidenceLevel` to a default confidence score.
    pub fn from_evidence(level: EvidenceLevel) -> Self {
        Self(match level {
            EvidenceLevel::Statistical => 0.4,
            EvidenceLevel::Controlled => 0.7,
            EvidenceLevel::Confirmed => 0.9,
            EvidenceLevel::Chained => 0.95,
        })
    }

    pub fn value(&self) -> f64 {
        self.0
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Self(0.5)
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}", self.0)
    }
}

impl Serialize for Confidence {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let opt: Option<f64> = Option::deserialize(deserializer)?;
        match opt {
            Some(v) if v.is_finite() && (0.0..=1.0).contains(&v) => Ok(Confidence(v)),
            Some(_) => Ok(Confidence::default()),
            None => Ok(Confidence::default()),
        }
    }
}

/// Provenance-tracked confidence decomposition for a finding.
///
/// Separates the scalar confidence into three independently inspectable
/// components: base rate (`prior`), evidence strength (`likelihood_ratio`),
/// and test method trustworthiness (`methodology_reliability`). The
/// `composite` field is the combined score reported to consumers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FindingConfidence {
    pub prior: f64,
    pub likelihood_ratio: f64,
    pub methodology_reliability: f64,
    pub composite: Confidence,
}

impl FindingConfidence {
    /// Computes a provenance-tracked confidence from its three components.
    ///
    /// `composite = clamp(prior * likelihood_ratio * methodology_reliability, 0.0, 1.0)`
    pub fn compute(prior: f64, likelihood_ratio: f64, methodology_reliability: f64) -> Self {
        let raw = (prior * likelihood_ratio * methodology_reliability).clamp(0.0, 1.0);
        Self {
            prior,
            likelihood_ratio,
            methodology_reliability,
            composite: Confidence::new(raw).unwrap_or_default(),
        }
    }

    /// Wraps an existing `Confidence` as a `FindingConfidence` with default provenance.
    ///
    /// Uses prior=0.5, likelihood_ratio=confidence*2, reliability=1.0 so that
    /// the composite equals the original confidence value.
    pub fn from_simple(confidence: Confidence) -> Self {
        let v = confidence.value();
        Self {
            prior: 0.5,
            likelihood_ratio: v * 2.0,
            methodology_reliability: 1.0,
            composite: confidence,
        }
    }
}

impl fmt::Display for FindingConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.composite)
    }
}

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
    #[serde(alias = "Counterfactual")]
    Controlled,
    Confirmed,
    Chained,
}

impl fmt::Display for EvidenceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvidenceLevel::Statistical => write!(f, "Statistical"),
            EvidenceLevel::Controlled => write!(f, "Controlled"),
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

#[derive(Debug, Clone, Serialize)]
pub struct FindingData {
    pub id: u64,
    pub linked_node_ids: Vec<u64>,
    pub vulnerability_class: VulnerabilityClass,
    pub severity: f64,
    pub confidence: FindingConfidence,
    pub certificate: Vec<u8>,
    pub provenance_module: ModuleIdentifier,
    pub timestamp_unix_ms: u64,
    pub evidence_level: EvidenceLevel,
    #[serde(default)]
    pub stable_id: Option<FindingId>,
}

impl<'de> Deserialize<'de> for FindingData {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            id: u64,
            linked_node_ids: Vec<u64>,
            vulnerability_class: VulnerabilityClass,
            severity: f64,
            confidence: Option<serde_json::Value>,
            certificate: Vec<u8>,
            provenance_module: ModuleIdentifier,
            timestamp_unix_ms: u64,
            evidence_level: EvidenceLevel,
            confidence_score: Option<f64>,
            #[serde(default)]
            stable_id: Option<FindingId>,
        }
        let raw = Raw::deserialize(deserializer)?;

        let confidence = match &raw.confidence {
            Some(serde_json::Value::Object(map)) if map.contains_key("prior") => {
                let prior = map.get("prior").and_then(|v| v.as_f64()).unwrap_or(0.5);
                let lr = map
                    .get("likelihood_ratio")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(1.0);
                let rel = map
                    .get("methodology_reliability")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(1.0);
                FindingConfidence::compute(prior, lr, rel)
            }
            _ => {
                let simple = if let Some(cs) = raw.confidence_score {
                    Confidence::new(cs).unwrap_or_default()
                } else {
                    match &raw.confidence {
                        Some(serde_json::Value::Number(n)) => {
                            let v = n.as_f64().unwrap_or(0.5);
                            Confidence::new(v).unwrap_or_default()
                        }
                        _ => Confidence::default(),
                    }
                };
                FindingConfidence::from_simple(simple)
            }
        };

        Ok(FindingData {
            id: raw.id,
            linked_node_ids: raw.linked_node_ids,
            vulnerability_class: raw.vulnerability_class,
            severity: raw.severity,
            confidence,
            certificate: raw.certificate,
            provenance_module: raw.provenance_module,
            timestamp_unix_ms: raw.timestamp_unix_ms,
            evidence_level: raw.evidence_level,
            stable_id: raw.stable_id,
        })
    }
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
            confidence: FindingConfidence::from_simple(
                Confidence::new(confidence).unwrap_or_default(),
            ),
            certificate: Vec::new(),
            provenance_module,
            timestamp_unix_ms,
            evidence_level: EvidenceLevel::Statistical,
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

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = FindingConfidence::from_simple(confidence);
        self
    }

    pub fn with_finding_confidence(mut self, confidence: FindingConfidence) -> Self {
        self.confidence = confidence;
        self
    }
}

pub fn confidence_from_evidence(evidence: EvidenceLevel) -> Confidence {
    Confidence::from_evidence(evidence)
}
