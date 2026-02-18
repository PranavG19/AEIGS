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
