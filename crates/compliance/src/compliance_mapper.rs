use std::collections::BTreeMap;
use std::fmt::Write;

use aegis_protocol::finding::VulnerabilityClass;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceMapping {
    pub owasp_2021: Option<String>,
    pub owasp_api_2023: Option<String>,
    pub cwe: String,
    pub pci_dss: Option<String>,
}

/// Maps a `VulnerabilityClass` to its relevant compliance framework references.
///
/// Covers OWASP Top 10 2021, OWASP API Security Top 10 2023, CWE, and PCI-DSS 3.2.1.
/// Exhaustive over all 34 `VulnerabilityClass` variants.
pub fn map_to_compliance(vuln_class: VulnerabilityClass) -> ComplianceMapping {
    match vuln_class {
        VulnerabilityClass::SqlInjection => ComplianceMapping {
            owasp_2021: Some("A03:2021 Injection".into()),
            owasp_api_2023: None,
            cwe: "CWE-89".into(),
            pci_dss: Some("6.5.1".into()),
        },
        VulnerabilityClass::NoSqlInjection => ComplianceMapping {
            owasp_2021: Some("A03:2021 Injection".into()),
            owasp_api_2023: None,
            cwe: "CWE-943".into(),
            pci_dss: Some("6.5.1".into()),
        },
        VulnerabilityClass::CrossSiteScripting => ComplianceMapping {
            owasp_2021: Some("A03:2021 Injection".into()),
            owasp_api_2023: None,
            cwe: "CWE-79".into(),
            pci_dss: Some("6.5.7".into()),
        },
        VulnerabilityClass::CommandInjection => ComplianceMapping {
            owasp_2021: Some("A03:2021 Injection".into()),
            owasp_api_2023: None,
            cwe: "CWE-78".into(),
            pci_dss: Some("6.5.1".into()),
        },
        VulnerabilityClass::PathTraversal => ComplianceMapping {
            owasp_2021: Some("A03:2021 Injection".into()),
            owasp_api_2023: None,
            cwe: "CWE-22".into(),
            pci_dss: Some("6.5.8".into()),
        },
        VulnerabilityClass::XmlExternalEntity => ComplianceMapping {
            owasp_2021: Some("A03:2021 Injection".into()),
            owasp_api_2023: None,
            cwe: "CWE-611".into(),
            pci_dss: Some("6.5.1".into()),
        },
        VulnerabilityClass::ServerSideTemplateInjection => ComplianceMapping {
            owasp_2021: Some("A03:2021 Injection".into()),
            owasp_api_2023: None,
            cwe: "CWE-1336".into(),
            pci_dss: Some("6.5.1".into()),
        },
        VulnerabilityClass::ServerSideRequestForgery => ComplianceMapping {
            owasp_2021: Some("A10:2021 SSRF".into()),
            owasp_api_2023: Some("API7:2023 SSRF".into()),
            cwe: "CWE-918".into(),
            pci_dss: Some("6.5.9".into()),
        },
        VulnerabilityClass::BrokenAuthentication => ComplianceMapping {
            owasp_2021: Some("A07:2021 Auth Failures".into()),
            owasp_api_2023: Some("API2:2023 Broken Auth".into()),
            cwe: "CWE-287".into(),
            pci_dss: Some("6.5.10".into()),
        },
        VulnerabilityClass::BrokenAuthorization => ComplianceMapping {
            owasp_2021: Some("A01:2021 Broken Access Control".into()),
            owasp_api_2023: Some("API5:2023 Broken Function Level AuthZ".into()),
            cwe: "CWE-285".into(),
            pci_dss: Some("6.5.8".into()),
        },
        VulnerabilityClass::InsecureDirectObjectReference => ComplianceMapping {
            owasp_2021: Some("A01:2021 Broken Access Control".into()),
            owasp_api_2023: Some("API1:2023 BOLA".into()),
            cwe: "CWE-639".into(),
            pci_dss: Some("6.5.8".into()),
        },
        VulnerabilityClass::MassAssignment => ComplianceMapping {
            owasp_2021: Some("A01:2021 Broken Access Control".into()),
            owasp_api_2023: Some("API3:2023 Broken Object Property Level AuthZ".into()),
            cwe: "CWE-915".into(),
            pci_dss: Some("6.5.8".into()),
        },
        VulnerabilityClass::JwtVulnerability => ComplianceMapping {
            owasp_2021: Some("A07:2021 Auth Failures".into()),
            owasp_api_2023: Some("API2:2023 Broken Auth".into()),
            cwe: "CWE-347".into(),
            pci_dss: Some("6.5.10".into()),
        },
        VulnerabilityClass::SecurityMisconfiguration => ComplianceMapping {
            owasp_2021: Some("A05:2021 Security Misconfig".into()),
            owasp_api_2023: Some("API8:2023 Security Misconfig".into()),
            cwe: "CWE-16".into(),
            pci_dss: Some("6.5.6".into()),
        },
        VulnerabilityClass::MissingSecurityHeader => ComplianceMapping {
            owasp_2021: Some("A05:2021 Security Misconfig".into()),
            owasp_api_2023: Some("API8:2023 Security Misconfig".into()),
            cwe: "CWE-693".into(),
            pci_dss: Some("6.5.6".into()),
        },
        VulnerabilityClass::CrossOriginMisconfiguration => ComplianceMapping {
            owasp_2021: Some("A05:2021 Security Misconfig".into()),
            owasp_api_2023: Some("API8:2023 Security Misconfig".into()),
            cwe: "CWE-942".into(),
            pci_dss: Some("6.5.6".into()),
        },
        VulnerabilityClass::SensitiveDataExposure => ComplianceMapping {
            owasp_2021: Some("A02:2021 Crypto Failures".into()),
            owasp_api_2023: None,
            cwe: "CWE-200".into(),
            pci_dss: Some("6.5.3".into()),
        },
        VulnerabilityClass::InformationDisclosure => ComplianceMapping {
            owasp_2021: Some("A02:2021 Crypto Failures".into()),
            owasp_api_2023: None,
            cwe: "CWE-200".into(),
            pci_dss: Some("6.5.3".into()),
        },
        VulnerabilityClass::KnownVulnerableDependency => ComplianceMapping {
            owasp_2021: Some("A06:2021 Outdated Components".into()),
            owasp_api_2023: None,
            cwe: "CWE-1395".into(),
            pci_dss: Some("6.5.6".into()),
        },
        VulnerabilityClass::InsecureDeserialization => ComplianceMapping {
            owasp_2021: Some("A08:2021 Integrity Failures".into()),
            owasp_api_2023: None,
            cwe: "CWE-502".into(),
            pci_dss: Some("6.5.1".into()),
        },
        VulnerabilityClass::HeaderInjection => ComplianceMapping {
            owasp_2021: Some("A03:2021 Injection".into()),
            owasp_api_2023: None,
            cwe: "CWE-113".into(),
            pci_dss: Some("6.5.1".into()),
        },
        VulnerabilityClass::OpenRedirect => ComplianceMapping {
            owasp_2021: Some("A01:2021 Broken Access Control".into()),
            owasp_api_2023: None,
            cwe: "CWE-601".into(),
            pci_dss: None,
        },
        VulnerabilityClass::CrlfInjection => ComplianceMapping {
            owasp_2021: Some("A03:2021 Injection".into()),
            owasp_api_2023: None,
            cwe: "CWE-93".into(),
            pci_dss: Some("6.5.1".into()),
        },
        VulnerabilityClass::InsufficientInputValidation => ComplianceMapping {
            owasp_2021: Some("A03:2021 Injection".into()),
            owasp_api_2023: None,
            cwe: "CWE-20".into(),
            pci_dss: Some("6.5.1".into()),
        },
        VulnerabilityClass::HttpRequestSmuggling => ComplianceMapping {
            owasp_2021: Some("A05:2021 Security Misconfig".into()),
            owasp_api_2023: None,
            cwe: "CWE-444".into(),
            pci_dss: Some("6.5.6".into()),
        },
        VulnerabilityClass::RaceCondition => ComplianceMapping {
            owasp_2021: Some("A04:2021 Insecure Design".into()),
            owasp_api_2023: None,
            cwe: "CWE-362".into(),
            pci_dss: None,
        },
        VulnerabilityClass::SubdomainTakeover => ComplianceMapping {
            owasp_2021: Some("A05:2021 Security Misconfig".into()),
            owasp_api_2023: None,
            cwe: "CWE-284".into(),
            pci_dss: None,
        },
        VulnerabilityClass::PrototypePollution => ComplianceMapping {
            owasp_2021: Some("A03:2021 Injection".into()),
            owasp_api_2023: None,
            cwe: "CWE-1321".into(),
            pci_dss: None,
        },
        VulnerabilityClass::GraphQlAbuse => ComplianceMapping {
            owasp_2021: Some("A03:2021 Injection".into()),
            owasp_api_2023: Some("API4:2023 Unrestricted Resource Consumption".into()),
            cwe: "CWE-20".into(),
            pci_dss: None,
        },
        VulnerabilityClass::CloudMisconfiguration => ComplianceMapping {
            owasp_2021: Some("A05:2021 Security Misconfig".into()),
            owasp_api_2023: Some("API8:2023 Security Misconfig".into()),
            cwe: "CWE-16".into(),
            pci_dss: Some("6.5.6".into()),
        },
        VulnerabilityClass::Clickjacking => ComplianceMapping {
            owasp_2021: Some("A05:2021 Security Misconfig".into()),
            owasp_api_2023: None,
            cwe: "CWE-1021".into(),
            pci_dss: Some("6.5.6".into()),
        },
        VulnerabilityClass::CachePoisoning => ComplianceMapping {
            owasp_2021: Some("A05:2021 Security Misconfig".into()),
            owasp_api_2023: None,
            cwe: "CWE-349".into(),
            pci_dss: None,
        },
        VulnerabilityClass::HostHeaderInjection => ComplianceMapping {
            owasp_2021: Some("A03:2021 Injection".into()),
            owasp_api_2023: None,
            cwe: "CWE-644".into(),
            pci_dss: Some("6.5.1".into()),
        },
        VulnerabilityClass::WeakCryptography => ComplianceMapping {
            owasp_2021: Some("A02:2021 Crypto Failures".into()),
            owasp_api_2023: None,
            cwe: "CWE-327".into(),
            pci_dss: Some("6.5.3".into()),
        },
    }
}

/// Extracts the OWASP 2021 category code (e.g., "A03") from a full label.
fn owasp_category_code(label: &str) -> &str {
    label.split(':').next().unwrap_or(label)
}

/// Generates a formatted OWASP Top 10 2021 compliance section from finding mappings.
///
/// Groups findings by OWASP category and produces a markdown section with counts.
pub fn format_owasp_report_section(mappings: &[ComplianceMapping]) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for m in mappings {
        if let Some(ref label) = m.owasp_2021 {
            *counts.entry(label.as_str()).or_default() += 1;
        }
    }

    let mut out = String::from("## OWASP Top 10 2021 Coverage\n");
    for (label, count) in &counts {
        let code = owasp_category_code(label);
        let category_name = label.get(code.len() + 1..).unwrap_or("");
        let suffix = if *count == 1 { "finding" } else { "findings" };
        let _ = writeln!(out, "- {code}:{category_name} \u{2014} {count} {suffix}");
    }
    out
}

/// Generates a formatted PCI-DSS compliance section from finding mappings.
///
/// Groups findings by PCI-DSS requirement and produces a markdown section with counts.
pub fn format_pci_dss_section(mappings: &[ComplianceMapping]) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for m in mappings {
        if let Some(ref req) = m.pci_dss {
            *counts.entry(req.as_str()).or_default() += 1;
        }
    }

    let mut out = String::from("## PCI-DSS 3.2.1 Coverage\n");
    for (req, count) in &counts {
        let suffix = if *count == 1 { "finding" } else { "findings" };
        let _ = writeln!(out, "- Requirement {req} \u{2014} {count} {suffix}");
    }
    out
}
