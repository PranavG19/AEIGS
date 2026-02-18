use crate::operation::ModuleIdentifier;
use serde::{Deserialize, Serialize};

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
}
