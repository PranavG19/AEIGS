use aegis_protocol::finding::VulnerabilityClass;

use crate::class_mapper::default_cvss_for_class;
use crate::cvss_scorer::{CvssSeverity, compute_cvss};

fn score_for(vc: VulnerabilityClass) -> f64 {
    compute_cvss(&default_cvss_for_class(vc)).score
}

fn severity_for(vc: VulnerabilityClass) -> CvssSeverity {
    compute_cvss(&default_cvss_for_class(vc)).severity_label
}

const ALL_CLASSES: [VulnerabilityClass; 34] = [
    VulnerabilityClass::SqlInjection,
    VulnerabilityClass::CrossSiteScripting,
    VulnerabilityClass::CommandInjection,
    VulnerabilityClass::PathTraversal,
    VulnerabilityClass::ServerSideRequestForgery,
    VulnerabilityClass::InsecureDeserialization,
    VulnerabilityClass::BrokenAuthentication,
    VulnerabilityClass::BrokenAuthorization,
    VulnerabilityClass::SecurityMisconfiguration,
    VulnerabilityClass::SensitiveDataExposure,
    VulnerabilityClass::ServerSideTemplateInjection,
    VulnerabilityClass::HeaderInjection,
    VulnerabilityClass::OpenRedirect,
    VulnerabilityClass::CrlfInjection,
    VulnerabilityClass::KnownVulnerableDependency,
    VulnerabilityClass::InsufficientInputValidation,
    VulnerabilityClass::NoSqlInjection,
    VulnerabilityClass::XmlExternalEntity,
    VulnerabilityClass::CrossOriginMisconfiguration,
    VulnerabilityClass::MissingSecurityHeader,
    VulnerabilityClass::JwtVulnerability,
    VulnerabilityClass::HttpRequestSmuggling,
    VulnerabilityClass::RaceCondition,
    VulnerabilityClass::SubdomainTakeover,
    VulnerabilityClass::PrototypePollution,
    VulnerabilityClass::GraphQlAbuse,
    VulnerabilityClass::CloudMisconfiguration,
    VulnerabilityClass::Clickjacking,
    VulnerabilityClass::CachePoisoning,
    VulnerabilityClass::HostHeaderInjection,
    VulnerabilityClass::InsecureDirectObjectReference,
    VulnerabilityClass::InformationDisclosure,
    VulnerabilityClass::WeakCryptography,
    VulnerabilityClass::MassAssignment,
];

#[test]
fn sql_injection_score() {
    assert_eq!(score_for(VulnerabilityClass::SqlInjection), 9.1);
    assert_eq!(
        severity_for(VulnerabilityClass::SqlInjection),
        CvssSeverity::Critical
    );
}

#[test]
fn xss_score() {
    assert_eq!(score_for(VulnerabilityClass::CrossSiteScripting), 6.1);
    assert_eq!(
        severity_for(VulnerabilityClass::CrossSiteScripting),
        CvssSeverity::Medium
    );
}

#[test]
fn command_injection_score() {
    assert_eq!(score_for(VulnerabilityClass::CommandInjection), 9.8);
    assert_eq!(
        severity_for(VulnerabilityClass::CommandInjection),
        CvssSeverity::Critical
    );
}

#[test]
fn path_traversal_score() {
    assert_eq!(score_for(VulnerabilityClass::PathTraversal), 7.5);
    assert_eq!(
        severity_for(VulnerabilityClass::PathTraversal),
        CvssSeverity::High
    );
}

#[test]
fn ssrf_score() {
    assert_eq!(score_for(VulnerabilityClass::ServerSideRequestForgery), 8.6);
    assert_eq!(
        severity_for(VulnerabilityClass::ServerSideRequestForgery),
        CvssSeverity::High
    );
}

#[test]
fn insecure_deserialization_score() {
    assert_eq!(score_for(VulnerabilityClass::InsecureDeserialization), 9.8);
    assert_eq!(
        severity_for(VulnerabilityClass::InsecureDeserialization),
        CvssSeverity::Critical
    );
}

#[test]
fn broken_authentication_score() {
    assert_eq!(score_for(VulnerabilityClass::BrokenAuthentication), 9.1);
    assert_eq!(
        severity_for(VulnerabilityClass::BrokenAuthentication),
        CvssSeverity::Critical
    );
}

#[test]
fn broken_authorization_score() {
    assert_eq!(score_for(VulnerabilityClass::BrokenAuthorization), 8.1);
    assert_eq!(
        severity_for(VulnerabilityClass::BrokenAuthorization),
        CvssSeverity::High
    );
}

#[test]
fn security_misconfiguration_score() {
    assert_eq!(score_for(VulnerabilityClass::SecurityMisconfiguration), 6.5);
    assert_eq!(
        severity_for(VulnerabilityClass::SecurityMisconfiguration),
        CvssSeverity::Medium
    );
}

#[test]
fn sensitive_data_exposure_score() {
    assert_eq!(score_for(VulnerabilityClass::SensitiveDataExposure), 7.5);
    assert_eq!(
        severity_for(VulnerabilityClass::SensitiveDataExposure),
        CvssSeverity::High
    );
}

#[test]
fn ssti_score() {
    assert_eq!(
        score_for(VulnerabilityClass::ServerSideTemplateInjection),
        9.8
    );
    assert_eq!(
        severity_for(VulnerabilityClass::ServerSideTemplateInjection),
        CvssSeverity::Critical
    );
}

#[test]
fn header_injection_score() {
    assert_eq!(score_for(VulnerabilityClass::HeaderInjection), 5.3);
    assert_eq!(
        severity_for(VulnerabilityClass::HeaderInjection),
        CvssSeverity::Medium
    );
}

#[test]
fn open_redirect_score() {
    assert_eq!(score_for(VulnerabilityClass::OpenRedirect), 6.1);
    assert_eq!(
        severity_for(VulnerabilityClass::OpenRedirect),
        CvssSeverity::Medium
    );
}

#[test]
fn crlf_injection_score() {
    assert_eq!(score_for(VulnerabilityClass::CrlfInjection), 5.3);
    assert_eq!(
        severity_for(VulnerabilityClass::CrlfInjection),
        CvssSeverity::Medium
    );
}

#[test]
fn known_vulnerable_dependency_score() {
    assert_eq!(
        score_for(VulnerabilityClass::KnownVulnerableDependency),
        7.3
    );
    assert_eq!(
        severity_for(VulnerabilityClass::KnownVulnerableDependency),
        CvssSeverity::High
    );
}

#[test]
fn insufficient_input_validation_score() {
    assert_eq!(
        score_for(VulnerabilityClass::InsufficientInputValidation),
        6.5
    );
    assert_eq!(
        severity_for(VulnerabilityClass::InsufficientInputValidation),
        CvssSeverity::Medium
    );
}

#[test]
fn nosql_injection_score() {
    assert_eq!(score_for(VulnerabilityClass::NoSqlInjection), 9.1);
    assert_eq!(
        severity_for(VulnerabilityClass::NoSqlInjection),
        CvssSeverity::Critical
    );
}

#[test]
fn xxe_score() {
    assert_eq!(score_for(VulnerabilityClass::XmlExternalEntity), 8.6);
    assert_eq!(
        severity_for(VulnerabilityClass::XmlExternalEntity),
        CvssSeverity::High
    );
}

#[test]
fn cross_origin_misconfiguration_score() {
    assert_eq!(
        score_for(VulnerabilityClass::CrossOriginMisconfiguration),
        6.1
    );
    assert_eq!(
        severity_for(VulnerabilityClass::CrossOriginMisconfiguration),
        CvssSeverity::Medium
    );
}

#[test]
fn missing_security_header_score() {
    assert_eq!(score_for(VulnerabilityClass::MissingSecurityHeader), 5.3);
    assert_eq!(
        severity_for(VulnerabilityClass::MissingSecurityHeader),
        CvssSeverity::Medium
    );
}

#[test]
fn jwt_vulnerability_score() {
    assert_eq!(score_for(VulnerabilityClass::JwtVulnerability), 9.1);
    assert_eq!(
        severity_for(VulnerabilityClass::JwtVulnerability),
        CvssSeverity::Critical
    );
}

#[test]
fn http_request_smuggling_score() {
    let score = score_for(VulnerabilityClass::HttpRequestSmuggling);
    assert!(score >= 7.0 && score <= 10.0);
    assert_eq!(
        severity_for(VulnerabilityClass::HttpRequestSmuggling),
        CvssSeverity::High
    );
}

#[test]
fn race_condition_score() {
    let score = score_for(VulnerabilityClass::RaceCondition);
    assert!(score >= 4.0 && score <= 8.0);
}

#[test]
fn subdomain_takeover_score() {
    let score = score_for(VulnerabilityClass::SubdomainTakeover);
    assert!(score >= 5.0 && score <= 8.0);
}

#[test]
fn prototype_pollution_score() {
    let score = score_for(VulnerabilityClass::PrototypePollution);
    assert!(score >= 5.0 && score <= 9.0);
}

#[test]
fn graphql_abuse_score() {
    assert_eq!(score_for(VulnerabilityClass::GraphQlAbuse), 7.3);
}

#[test]
fn cloud_misconfiguration_score() {
    assert_eq!(score_for(VulnerabilityClass::CloudMisconfiguration), 6.5);
}

#[test]
fn clickjacking_score() {
    let score = score_for(VulnerabilityClass::Clickjacking);
    assert!(score >= 3.0 && score <= 5.0);
}

#[test]
fn cache_poisoning_score() {
    let score = score_for(VulnerabilityClass::CachePoisoning);
    assert!(score >= 5.0 && score <= 9.0);
}

#[test]
fn host_header_injection_score() {
    assert_eq!(score_for(VulnerabilityClass::HostHeaderInjection), 5.3);
}

#[test]
fn idor_score() {
    assert_eq!(
        score_for(VulnerabilityClass::InsecureDirectObjectReference),
        8.1
    );
}

#[test]
fn information_disclosure_score() {
    assert_eq!(score_for(VulnerabilityClass::InformationDisclosure), 7.5);
}

#[test]
fn weak_cryptography_score() {
    let score = score_for(VulnerabilityClass::WeakCryptography);
    assert!(score >= 4.0 && score <= 7.0);
}

#[test]
fn mass_assignment_score() {
    let score = score_for(VulnerabilityClass::MassAssignment);
    assert!(score >= 5.0 && score <= 8.0);
}

#[test]
fn all_classes_produce_nonzero_scores() {
    for vc in ALL_CLASSES {
        let score = score_for(vc);
        assert!(score > 0.0, "{vc} produced score {score}");
        assert!(score <= 10.0, "{vc} produced score {score}");
    }
}

#[test]
fn command_injection_more_severe_than_xss() {
    let cmd = score_for(VulnerabilityClass::CommandInjection);
    let xss = score_for(VulnerabilityClass::CrossSiteScripting);
    assert!(cmd > xss);
}

#[test]
fn rce_classes_are_critical() {
    assert_eq!(
        severity_for(VulnerabilityClass::CommandInjection),
        CvssSeverity::Critical
    );
    assert_eq!(
        severity_for(VulnerabilityClass::InsecureDeserialization),
        CvssSeverity::Critical
    );
    assert_eq!(
        severity_for(VulnerabilityClass::ServerSideTemplateInjection),
        CvssSeverity::Critical
    );
}

#[test]
fn vector_strings_are_valid() {
    for vc in ALL_CLASSES {
        let result = compute_cvss(&default_cvss_for_class(vc));
        assert!(
            result.vector_string.starts_with("CVSS:3.1/"),
            "{vc}: bad vector string prefix"
        );
        assert_eq!(
            result.vector_string.matches('/').count(),
            8,
            "{vc}: wrong number of vector components"
        );
    }
}
