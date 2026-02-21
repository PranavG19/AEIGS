use std::collections::HashMap;
use std::fmt;

use aegis_protocol::finding::VulnerabilityClass;

use crate::executor::FuzzResponse;
use crate::oracle::BaselineProfile;

/// Evidence produced by a per-vulnerability-class confirmation function.
/// Captures what type of evidence was observed, how confident the function
/// is in the finding, and a human-readable description of the observation.
///
/// `confidence` must be in `0.0..=1.0`.
#[derive(Debug, Clone)]
pub struct ConfirmationEvidence {
    pub evidence_type: EvidenceType,
    pub confidence: f64,
    pub description: String,
}

/// Classifies the kind of observable behavior that confirms a vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceType {
    SqlErrorMessage,
    TimeBasedDelay,
    ReflectedPayload,
    StatusCodeChange,
    InformationDisclosure,
    BehaviorDifference,
    TemplateEvaluation,
    CommandOutput,
    PathContents,
    RedirectToExternal,
    DeserializationMarker,
}

impl fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::SqlErrorMessage => "sql-error-message",
            Self::TimeBasedDelay => "time-based-delay",
            Self::ReflectedPayload => "reflected-payload",
            Self::StatusCodeChange => "status-code-change",
            Self::InformationDisclosure => "information-disclosure",
            Self::BehaviorDifference => "behavior-difference",
            Self::TemplateEvaluation => "template-evaluation",
            Self::CommandOutput => "command-output",
            Self::PathContents => "path-contents",
            Self::RedirectToExternal => "redirect-to-external",
            Self::DeserializationMarker => "deserialization-marker",
        };
        write!(f, "{label}")
    }
}

/// Confirmation function signature: given a treatment response, a control
/// response, the payload that was sent, and a baseline profile for the
/// endpoint, returns evidence if the vulnerability is confirmed.
pub type ConfirmFn =
    fn(&FuzzResponse, &FuzzResponse, &str, &BaselineProfile) -> Option<ConfirmationEvidence>;

/// Builds a registry mapping each vulnerability class to its ordered list
/// of confirmation functions. Functions are tried in order; the first to
/// return Some wins.
pub fn build_confirmation_registry() -> HashMap<VulnerabilityClass, Vec<ConfirmFn>> {
    HashMap::new()
}
