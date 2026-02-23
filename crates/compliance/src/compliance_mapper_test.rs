use aegis_protocol::finding::VulnerabilityClass;

use crate::compliance_mapper::{
    format_owasp_report_section, format_pci_dss_section, map_to_compliance,
};

fn all_classes() -> Vec<VulnerabilityClass> {
    vec![
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::NoSqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::XmlExternalEntity,
        VulnerabilityClass::ServerSideTemplateInjection,
        VulnerabilityClass::ServerSideRequestForgery,
        VulnerabilityClass::BrokenAuthentication,
        VulnerabilityClass::BrokenAuthorization,
        VulnerabilityClass::InsecureDirectObjectReference,
        VulnerabilityClass::MassAssignment,
        VulnerabilityClass::JwtVulnerability,
        VulnerabilityClass::SecurityMisconfiguration,
        VulnerabilityClass::MissingSecurityHeader,
        VulnerabilityClass::CrossOriginMisconfiguration,
        VulnerabilityClass::SensitiveDataExposure,
        VulnerabilityClass::InformationDisclosure,
        VulnerabilityClass::KnownVulnerableDependency,
        VulnerabilityClass::InsecureDeserialization,
        VulnerabilityClass::HeaderInjection,
        VulnerabilityClass::OpenRedirect,
        VulnerabilityClass::CrlfInjection,
        VulnerabilityClass::InsufficientInputValidation,
        VulnerabilityClass::HttpRequestSmuggling,
        VulnerabilityClass::RaceCondition,
        VulnerabilityClass::SubdomainTakeover,
        VulnerabilityClass::PrototypePollution,
        VulnerabilityClass::GraphQlAbuse,
        VulnerabilityClass::CloudMisconfiguration,
        VulnerabilityClass::Clickjacking,
        VulnerabilityClass::CachePoisoning,
        VulnerabilityClass::HostHeaderInjection,
        VulnerabilityClass::WeakCryptography,
    ]
}

fn is_valid_owasp_2021(s: &str) -> bool {
    s.starts_with('A')
        && s.len() > 8
        && s[1..3].chars().all(|c| c.is_ascii_digit())
        && s[3..].starts_with(":2021 ")
}

fn is_valid_owasp_api_2023(s: &str) -> bool {
    s.starts_with("API")
        && s.len() > 9
        && s[3..].chars().take_while(|c| c.is_ascii_digit()).count() >= 1
        && s.contains(":2023 ")
}

fn is_valid_pci_dss(s: &str) -> bool {
    s.starts_with("6.5.") && s.len() > 4 && s[4..].chars().all(|c| c.is_ascii_digit())
}

#[test]
fn every_class_produces_a_mapping() {
    for class in all_classes() {
        let mapping = map_to_compliance(class);
        assert!(!mapping.cwe.is_empty(), "{class} should have a CWE mapping");
    }
}

#[test]
fn cwe_format_is_valid() {
    for class in all_classes() {
        let mapping = map_to_compliance(class);
        assert!(
            mapping.cwe.starts_with("CWE-"),
            "{class}: CWE '{}' does not start with 'CWE-'",
            mapping.cwe,
        );
        let num = &mapping.cwe[4..];
        assert!(
            num.parse::<u32>().is_ok(),
            "{class}: CWE '{}' has non-numeric suffix '{num}'",
            mapping.cwe,
        );
    }
}

#[test]
fn owasp_2021_format_is_valid() {
    for class in all_classes() {
        let mapping = map_to_compliance(class);
        if let Some(ref owasp) = mapping.owasp_2021 {
            assert!(
                is_valid_owasp_2021(owasp),
                "{class}: OWASP 2021 label '{owasp}' does not match 'AXX:2021 ...' format",
            );
        }
    }
}

#[test]
fn owasp_api_2023_format_is_valid() {
    for class in all_classes() {
        let mapping = map_to_compliance(class);
        if let Some(ref api) = mapping.owasp_api_2023 {
            assert!(
                is_valid_owasp_api_2023(api),
                "{class}: OWASP API 2023 label '{api}' does not match 'APIX:2023 ...' format",
            );
        }
    }
}

#[test]
fn pci_dss_format_is_valid() {
    for class in all_classes() {
        let mapping = map_to_compliance(class);
        if let Some(ref pci) = mapping.pci_dss {
            assert!(
                is_valid_pci_dss(pci),
                "{class}: PCI-DSS '{pci}' does not match '6.5.X' format",
            );
        }
    }
}

#[test]
fn injection_classes_map_to_a03() {
    let injection_classes = [
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::NoSqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::XmlExternalEntity,
        VulnerabilityClass::ServerSideTemplateInjection,
        VulnerabilityClass::HeaderInjection,
        VulnerabilityClass::CrlfInjection,
    ];
    for class in injection_classes {
        let mapping = map_to_compliance(class);
        assert_eq!(
            mapping.owasp_2021.as_deref(),
            Some("A03:2021 Injection"),
            "{class} should map to A03:2021 Injection",
        );
    }
}

#[test]
fn access_control_classes_map_to_a01() {
    let ac_classes = [
        VulnerabilityClass::BrokenAuthorization,
        VulnerabilityClass::InsecureDirectObjectReference,
        VulnerabilityClass::MassAssignment,
    ];
    for class in ac_classes {
        let mapping = map_to_compliance(class);
        assert_eq!(
            mapping.owasp_2021.as_deref(),
            Some("A01:2021 Broken Access Control"),
            "{class} should map to A01:2021 Broken Access Control",
        );
    }
}

#[test]
fn ssrf_has_both_owasp_categories() {
    let m = map_to_compliance(VulnerabilityClass::ServerSideRequestForgery);
    assert_eq!(m.owasp_2021.as_deref(), Some("A10:2021 SSRF"));
    assert_eq!(m.owasp_api_2023.as_deref(), Some("API7:2023 SSRF"));
    assert_eq!(m.cwe, "CWE-918");
    assert_eq!(m.pci_dss.as_deref(), Some("6.5.9"));
}

#[test]
fn sql_injection_specific_mapping() {
    let m = map_to_compliance(VulnerabilityClass::SqlInjection);
    assert_eq!(m.owasp_2021.as_deref(), Some("A03:2021 Injection"));
    assert_eq!(m.owasp_api_2023, None);
    assert_eq!(m.cwe, "CWE-89");
    assert_eq!(m.pci_dss.as_deref(), Some("6.5.1"));
}

#[test]
fn broken_auth_has_api_mapping() {
    let m = map_to_compliance(VulnerabilityClass::BrokenAuthentication);
    assert_eq!(m.owasp_api_2023.as_deref(), Some("API2:2023 Broken Auth"));
}

#[test]
fn idor_has_bola_api_mapping() {
    let m = map_to_compliance(VulnerabilityClass::InsecureDirectObjectReference);
    assert_eq!(m.owasp_api_2023.as_deref(), Some("API1:2023 BOLA"));
}

#[test]
fn graphql_abuse_has_api_mapping() {
    let m = map_to_compliance(VulnerabilityClass::GraphQlAbuse);
    assert_eq!(
        m.owasp_api_2023.as_deref(),
        Some("API4:2023 Unrestricted Resource Consumption"),
    );
}

#[test]
fn classes_without_pci_dss() {
    let no_pci = [
        VulnerabilityClass::OpenRedirect,
        VulnerabilityClass::RaceCondition,
        VulnerabilityClass::SubdomainTakeover,
        VulnerabilityClass::PrototypePollution,
        VulnerabilityClass::GraphQlAbuse,
        VulnerabilityClass::CachePoisoning,
    ];
    for class in no_pci {
        let mapping = map_to_compliance(class);
        assert_eq!(
            mapping.pci_dss, None,
            "{class} should have no PCI-DSS mapping",
        );
    }
}

#[test]
fn owasp_report_section_groups_by_category() {
    let mappings = vec![
        map_to_compliance(VulnerabilityClass::SqlInjection),
        map_to_compliance(VulnerabilityClass::CommandInjection),
        map_to_compliance(VulnerabilityClass::BrokenAuthorization),
    ];
    let section = format_owasp_report_section(&mappings);
    assert!(section.starts_with("## OWASP Top 10 2021 Coverage\n"));
    assert!(section.contains("A01:"));
    assert!(section.contains("A03:"));
    assert!(section.contains("2 findings"));
    assert!(section.contains("1 finding"));
}

#[test]
fn owasp_report_section_empty_input() {
    let section = format_owasp_report_section(&[]);
    assert_eq!(section, "## OWASP Top 10 2021 Coverage\n");
}

#[test]
fn pci_dss_section_groups_by_requirement() {
    let mappings = vec![
        map_to_compliance(VulnerabilityClass::SqlInjection),
        map_to_compliance(VulnerabilityClass::CommandInjection),
        map_to_compliance(VulnerabilityClass::CrossSiteScripting),
    ];
    let section = format_pci_dss_section(&mappings);
    assert!(section.starts_with("## PCI-DSS 3.2.1 Coverage\n"));
    assert!(section.contains("Requirement 6.5.1"));
    assert!(section.contains("Requirement 6.5.7"));
    assert!(section.contains("2 findings"));
    assert!(section.contains("1 finding"));
}

#[test]
fn pci_dss_section_empty_input() {
    let section = format_pci_dss_section(&[]);
    assert_eq!(section, "## PCI-DSS 3.2.1 Coverage\n");
}

#[test]
fn pci_dss_section_skips_none_entries() {
    let mappings = vec![
        map_to_compliance(VulnerabilityClass::OpenRedirect),
        map_to_compliance(VulnerabilityClass::RaceCondition),
    ];
    let section = format_pci_dss_section(&mappings);
    assert_eq!(
        section, "## PCI-DSS 3.2.1 Coverage\n",
        "findings with no PCI-DSS mapping should produce no entries",
    );
}

#[test]
fn variant_count_is_34() {
    assert_eq!(
        all_classes().len(),
        34,
        "all_classes() should cover exactly 34 VulnerabilityClass variants",
    );
}

#[test]
fn compliance_mapping_derives() {
    let m = map_to_compliance(VulnerabilityClass::SqlInjection);
    let cloned = m.clone();
    assert_eq!(m, cloned);
    let formatted = format!("{m:?}");
    assert!(formatted.contains("CWE-89"));
}
