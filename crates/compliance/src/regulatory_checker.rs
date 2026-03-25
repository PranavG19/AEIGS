use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write;

use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};

/// Regulatory framework identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RegulatoryFramework {
    Soc2,
    Iso27001,
    Gdpr,
    Hipaa,
    FedRamp,
}

impl fmt::Display for RegulatoryFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegulatoryFramework::Soc2 => write!(f, "SOC 2"),
            RegulatoryFramework::Iso27001 => write!(f, "ISO 27001"),
            RegulatoryFramework::Gdpr => write!(f, "GDPR"),
            RegulatoryFramework::Hipaa => write!(f, "HIPAA"),
            RegulatoryFramework::FedRamp => write!(f, "FedRAMP"),
        }
    }
}

/// A specific control within a regulatory framework.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FrameworkControl {
    pub framework: RegulatoryFramework,
    pub control_id: String,
    pub control_name: String,
    pub description: String,
}

/// Compliance status for a single control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ControlStatus {
    Compliant,
    NonCompliant,
    PartiallyCompliant,
    NotAssessed,
}

impl fmt::Display for ControlStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlStatus::Compliant => write!(f, "Compliant"),
            ControlStatus::NonCompliant => write!(f, "Non-Compliant"),
            ControlStatus::PartiallyCompliant => write!(f, "Partially Compliant"),
            ControlStatus::NotAssessed => write!(f, "Not Assessed"),
        }
    }
}

/// A finding mapped to a specific framework control with compliance status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFinding {
    pub control: FrameworkControl,
    pub status: ControlStatus,
    pub related_vulnerabilities: Vec<VulnerabilityClass>,
    pub gap_description: String,
    pub remediation: String,
    pub severity: GapSeverity,
}

/// Severity of a compliance gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GapSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl fmt::Display for GapSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GapSeverity::Critical => write!(f, "Critical"),
            GapSeverity::High => write!(f, "High"),
            GapSeverity::Medium => write!(f, "Medium"),
            GapSeverity::Low => write!(f, "Low"),
            GapSeverity::Informational => write!(f, "Informational"),
        }
    }
}

/// Per-framework compliance score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkScore {
    pub framework: RegulatoryFramework,
    pub total_controls: usize,
    pub compliant: usize,
    pub partially_compliant: usize,
    pub non_compliant: usize,
    pub not_assessed: usize,
    pub compliance_percentage: f64,
    pub highest_risk_gaps: Vec<ControlFinding>,
}

/// Complete multi-framework compliance check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheckResult {
    pub framework_scores: Vec<FrameworkScore>,
    pub all_findings: Vec<ControlFinding>,
    pub overall_compliance_percentage: f64,
    pub highest_risk_gaps: Vec<ControlFinding>,
}

/// Maps a vulnerability class to affected controls across all frameworks.
pub fn map_vuln_to_controls(vuln: VulnerabilityClass) -> Vec<FrameworkControl> {
    let mut controls = Vec::new();

    controls.extend(map_vuln_to_soc2(vuln));
    controls.extend(map_vuln_to_iso27001(vuln));
    controls.extend(map_vuln_to_gdpr(vuln));
    controls.extend(map_vuln_to_hipaa(vuln));
    controls.extend(map_vuln_to_fedramp(vuln));

    controls
}

fn map_vuln_to_soc2(vuln: VulnerabilityClass) -> Vec<FrameworkControl> {
    match vuln {
        VulnerabilityClass::SqlInjection
        | VulnerabilityClass::NoSqlInjection
        | VulnerabilityClass::CommandInjection
        | VulnerabilityClass::ServerSideTemplateInjection
        | VulnerabilityClass::XmlExternalEntity => vec![
            FrameworkControl {
                framework: RegulatoryFramework::Soc2,
                control_id: "CC6.1".into(),
                control_name: "Logical and Physical Access Controls".into(),
                description:
                    "Implements logical access security to protect against injection attacks".into(),
            },
            FrameworkControl {
                framework: RegulatoryFramework::Soc2,
                control_id: "CC7.2".into(),
                control_name: "System Monitoring".into(),
                description: "Monitors for anomalous activity including injection attempts".into(),
            },
        ],
        VulnerabilityClass::CrossSiteScripting
        | VulnerabilityClass::HeaderInjection
        | VulnerabilityClass::CrlfInjection
        | VulnerabilityClass::HostHeaderInjection => vec![FrameworkControl {
            framework: RegulatoryFramework::Soc2,
            control_id: "CC6.1".into(),
            control_name: "Logical and Physical Access Controls".into(),
            description: "Input validation to prevent script injection".into(),
        }],
        VulnerabilityClass::BrokenAuthentication | VulnerabilityClass::JwtVulnerability => vec![
            FrameworkControl {
                framework: RegulatoryFramework::Soc2,
                control_id: "CC6.1".into(),
                control_name: "Logical and Physical Access Controls".into(),
                description: "Authentication mechanisms protect system access".into(),
            },
            FrameworkControl {
                framework: RegulatoryFramework::Soc2,
                control_id: "CC6.2".into(),
                control_name: "User Authentication".into(),
                description: "Prior to access, users are authenticated".into(),
            },
        ],
        VulnerabilityClass::BrokenAuthorization
        | VulnerabilityClass::InsecureDirectObjectReference
        | VulnerabilityClass::MassAssignment => vec![FrameworkControl {
            framework: RegulatoryFramework::Soc2,
            control_id: "CC6.3".into(),
            control_name: "Authorization Controls".into(),
            description: "Access is restricted to authorized users and functions".into(),
        }],
        VulnerabilityClass::SensitiveDataExposure
        | VulnerabilityClass::InformationDisclosure
        | VulnerabilityClass::WeakCryptography => vec![FrameworkControl {
            framework: RegulatoryFramework::Soc2,
            control_id: "CC6.7".into(),
            control_name: "Data Protection".into(),
            description: "Data is protected during transmission and storage".into(),
        }],
        VulnerabilityClass::SecurityMisconfiguration
        | VulnerabilityClass::MissingSecurityHeader
        | VulnerabilityClass::CrossOriginMisconfiguration
        | VulnerabilityClass::CloudMisconfiguration => vec![FrameworkControl {
            framework: RegulatoryFramework::Soc2,
            control_id: "CC8.1".into(),
            control_name: "Change Management".into(),
            description: "Configuration changes follow established change management".into(),
        }],
        VulnerabilityClass::KnownVulnerableDependency => vec![FrameworkControl {
            framework: RegulatoryFramework::Soc2,
            control_id: "CC7.1".into(),
            control_name: "Vulnerability Management".into(),
            description: "Known vulnerabilities in dependencies are identified and remediated"
                .into(),
        }],
        _ => vec![FrameworkControl {
            framework: RegulatoryFramework::Soc2,
            control_id: "CC7.2".into(),
            control_name: "System Monitoring".into(),
            description: "Security events are detected and monitored".into(),
        }],
    }
}

fn map_vuln_to_iso27001(vuln: VulnerabilityClass) -> Vec<FrameworkControl> {
    match vuln {
        VulnerabilityClass::SqlInjection
        | VulnerabilityClass::NoSqlInjection
        | VulnerabilityClass::CommandInjection
        | VulnerabilityClass::ServerSideTemplateInjection
        | VulnerabilityClass::CrossSiteScripting => vec![FrameworkControl {
            framework: RegulatoryFramework::Iso27001,
            control_id: "A.14.2.5".into(),
            control_name: "Secure System Engineering Principles".into(),
            description: "Secure coding practices to prevent injection vulnerabilities".into(),
        }],
        VulnerabilityClass::BrokenAuthentication | VulnerabilityClass::JwtVulnerability => {
            vec![FrameworkControl {
                framework: RegulatoryFramework::Iso27001,
                control_id: "A.9.4.2".into(),
                control_name: "Secure Log-on Procedures".into(),
                description: "Authentication mechanisms follow secure log-on procedures".into(),
            }]
        }
        VulnerabilityClass::BrokenAuthorization
        | VulnerabilityClass::InsecureDirectObjectReference
        | VulnerabilityClass::MassAssignment => vec![FrameworkControl {
            framework: RegulatoryFramework::Iso27001,
            control_id: "A.9.4.1".into(),
            control_name: "Information Access Restriction".into(),
            description: "Access to information is restricted based on authorization policies"
                .into(),
        }],
        VulnerabilityClass::SensitiveDataExposure
        | VulnerabilityClass::InformationDisclosure
        | VulnerabilityClass::WeakCryptography => vec![FrameworkControl {
            framework: RegulatoryFramework::Iso27001,
            control_id: "A.10.1.1".into(),
            control_name: "Policy on Use of Cryptographic Controls".into(),
            description: "Cryptographic controls protect data confidentiality and integrity".into(),
        }],
        VulnerabilityClass::KnownVulnerableDependency => vec![FrameworkControl {
            framework: RegulatoryFramework::Iso27001,
            control_id: "A.12.6.1".into(),
            control_name: "Management of Technical Vulnerabilities".into(),
            description: "Technical vulnerabilities are identified and patched promptly".into(),
        }],
        VulnerabilityClass::SecurityMisconfiguration
        | VulnerabilityClass::CloudMisconfiguration => vec![FrameworkControl {
            framework: RegulatoryFramework::Iso27001,
            control_id: "A.12.1.1".into(),
            control_name: "Documented Operating Procedures".into(),
            description: "System configurations follow documented security procedures".into(),
        }],
        _ => vec![FrameworkControl {
            framework: RegulatoryFramework::Iso27001,
            control_id: "A.14.2.5".into(),
            control_name: "Secure System Engineering Principles".into(),
            description: "General secure engineering principles apply".into(),
        }],
    }
}

fn map_vuln_to_gdpr(vuln: VulnerabilityClass) -> Vec<FrameworkControl> {
    match vuln {
        VulnerabilityClass::SensitiveDataExposure | VulnerabilityClass::InformationDisclosure => {
            vec![
                FrameworkControl {
                    framework: RegulatoryFramework::Gdpr,
                    control_id: "Art. 32".into(),
                    control_name: "Security of Processing".into(),
                    description: "Appropriate technical measures to ensure data security".into(),
                },
                FrameworkControl {
                    framework: RegulatoryFramework::Gdpr,
                    control_id: "Art. 33".into(),
                    control_name: "Breach Notification".into(),
                    description: "Data breaches must be reported within 72 hours".into(),
                },
            ]
        }
        VulnerabilityClass::SqlInjection
        | VulnerabilityClass::NoSqlInjection
        | VulnerabilityClass::CommandInjection
        | VulnerabilityClass::PathTraversal => vec![FrameworkControl {
            framework: RegulatoryFramework::Gdpr,
            control_id: "Art. 32".into(),
            control_name: "Security of Processing".into(),
            description: "Injection vulnerabilities compromise data processing security".into(),
        }],
        VulnerabilityClass::BrokenAuthentication
        | VulnerabilityClass::BrokenAuthorization
        | VulnerabilityClass::InsecureDirectObjectReference => vec![FrameworkControl {
            framework: RegulatoryFramework::Gdpr,
            control_id: "Art. 25".into(),
            control_name: "Data Protection by Design".into(),
            description: "Access controls implement data protection by design principles".into(),
        }],
        VulnerabilityClass::WeakCryptography => vec![FrameworkControl {
            framework: RegulatoryFramework::Gdpr,
            control_id: "Art. 32(1)(a)".into(),
            control_name: "Encryption of Personal Data".into(),
            description: "Pseudonymisation and encryption of personal data".into(),
        }],
        _ => vec![FrameworkControl {
            framework: RegulatoryFramework::Gdpr,
            control_id: "Art. 32".into(),
            control_name: "Security of Processing".into(),
            description: "General security measures for personal data processing".into(),
        }],
    }
}

fn map_vuln_to_hipaa(vuln: VulnerabilityClass) -> Vec<FrameworkControl> {
    match vuln {
        VulnerabilityClass::SensitiveDataExposure | VulnerabilityClass::InformationDisclosure => {
            vec![
                FrameworkControl {
                    framework: RegulatoryFramework::Hipaa,
                    control_id: "164.312(a)(1)".into(),
                    control_name: "Access Control".into(),
                    description: "Technical safeguards to control access to ePHI".into(),
                },
                FrameworkControl {
                    framework: RegulatoryFramework::Hipaa,
                    control_id: "164.312(e)(1)".into(),
                    control_name: "Transmission Security".into(),
                    description: "Technical security measures to guard ePHI during transmission"
                        .into(),
                },
            ]
        }
        VulnerabilityClass::BrokenAuthentication | VulnerabilityClass::JwtVulnerability => {
            vec![FrameworkControl {
                framework: RegulatoryFramework::Hipaa,
                control_id: "164.312(d)".into(),
                control_name: "Person or Entity Authentication".into(),
                description: "Verify identity of persons seeking access to ePHI".into(),
            }]
        }
        VulnerabilityClass::BrokenAuthorization
        | VulnerabilityClass::InsecureDirectObjectReference
        | VulnerabilityClass::MassAssignment => vec![FrameworkControl {
            framework: RegulatoryFramework::Hipaa,
            control_id: "164.312(a)(1)".into(),
            control_name: "Access Control".into(),
            description: "Only authorized persons access ePHI".into(),
        }],
        VulnerabilityClass::WeakCryptography => vec![FrameworkControl {
            framework: RegulatoryFramework::Hipaa,
            control_id: "164.312(a)(2)(iv)".into(),
            control_name: "Encryption and Decryption".into(),
            description: "Mechanism to encrypt and decrypt ePHI".into(),
        }],
        VulnerabilityClass::SqlInjection | VulnerabilityClass::CommandInjection => {
            vec![FrameworkControl {
                framework: RegulatoryFramework::Hipaa,
                control_id: "164.312(c)(1)".into(),
                control_name: "Integrity Controls".into(),
                description: "Policies to protect ePHI from improper alteration or destruction"
                    .into(),
            }]
        }
        _ => vec![FrameworkControl {
            framework: RegulatoryFramework::Hipaa,
            control_id: "164.308(a)(1)".into(),
            control_name: "Security Management Process".into(),
            description:
                "Policies and procedures to prevent, detect, contain, and correct violations".into(),
        }],
    }
}

fn map_vuln_to_fedramp(vuln: VulnerabilityClass) -> Vec<FrameworkControl> {
    match vuln {
        VulnerabilityClass::SqlInjection
        | VulnerabilityClass::NoSqlInjection
        | VulnerabilityClass::CommandInjection
        | VulnerabilityClass::CrossSiteScripting => vec![FrameworkControl {
            framework: RegulatoryFramework::FedRamp,
            control_id: "SI-10".into(),
            control_name: "Information Input Validation".into(),
            description: "Check validity of information inputs to prevent injection".into(),
        }],
        VulnerabilityClass::BrokenAuthentication | VulnerabilityClass::JwtVulnerability => {
            vec![FrameworkControl {
                framework: RegulatoryFramework::FedRamp,
                control_id: "IA-2".into(),
                control_name: "Identification and Authentication".into(),
                description: "Uniquely identify and authenticate organizational users".into(),
            }]
        }
        VulnerabilityClass::BrokenAuthorization
        | VulnerabilityClass::InsecureDirectObjectReference => vec![FrameworkControl {
            framework: RegulatoryFramework::FedRamp,
            control_id: "AC-3".into(),
            control_name: "Access Enforcement".into(),
            description: "Enforce approved authorizations for logical access".into(),
        }],
        VulnerabilityClass::SensitiveDataExposure
        | VulnerabilityClass::InformationDisclosure
        | VulnerabilityClass::WeakCryptography => vec![FrameworkControl {
            framework: RegulatoryFramework::FedRamp,
            control_id: "SC-28".into(),
            control_name: "Protection of Information at Rest".into(),
            description: "Protect confidentiality and integrity of information at rest".into(),
        }],
        VulnerabilityClass::KnownVulnerableDependency => vec![FrameworkControl {
            framework: RegulatoryFramework::FedRamp,
            control_id: "RA-5".into(),
            control_name: "Vulnerability Scanning".into(),
            description: "Scan for vulnerabilities in the information system and applications"
                .into(),
        }],
        VulnerabilityClass::SecurityMisconfiguration
        | VulnerabilityClass::CloudMisconfiguration => vec![FrameworkControl {
            framework: RegulatoryFramework::FedRamp,
            control_id: "CM-6".into(),
            control_name: "Configuration Settings".into(),
            description: "Establish and enforce security configuration settings".into(),
        }],
        _ => vec![FrameworkControl {
            framework: RegulatoryFramework::FedRamp,
            control_id: "SI-2".into(),
            control_name: "Flaw Remediation".into(),
            description: "Identify, report, and correct information system flaws".into(),
        }],
    }
}

/// Determines compliance status based on discovered vulnerabilities for a control.
fn assess_control_status(
    control: &FrameworkControl,
    vulns: &[VulnerabilityClass],
) -> ControlStatus {
    if vulns.is_empty() {
        return ControlStatus::NotAssessed;
    }

    let related = map_control_to_vuln_classes(control);
    let violations: Vec<VulnerabilityClass> = vulns
        .iter()
        .filter(|v| related.contains(v))
        .copied()
        .collect();

    if violations.is_empty() {
        ControlStatus::Compliant
    } else if violations.len() >= 2 {
        ControlStatus::NonCompliant
    } else {
        ControlStatus::PartiallyCompliant
    }
}

/// Reverse mapping: which vulnerability classes relate to a given control.
fn map_control_to_vuln_classes(control: &FrameworkControl) -> Vec<VulnerabilityClass> {
    let id = control.control_id.as_str();
    match (control.framework, id) {
        (RegulatoryFramework::Soc2, "CC6.1") => vec![
            VulnerabilityClass::SqlInjection,
            VulnerabilityClass::CommandInjection,
            VulnerabilityClass::CrossSiteScripting,
            VulnerabilityClass::BrokenAuthentication,
            VulnerabilityClass::NoSqlInjection,
        ],
        (RegulatoryFramework::Soc2, "CC6.2") => vec![
            VulnerabilityClass::BrokenAuthentication,
            VulnerabilityClass::JwtVulnerability,
        ],
        (RegulatoryFramework::Soc2, "CC6.3") => vec![
            VulnerabilityClass::BrokenAuthorization,
            VulnerabilityClass::InsecureDirectObjectReference,
            VulnerabilityClass::MassAssignment,
        ],
        (RegulatoryFramework::Soc2, "CC6.7") => vec![
            VulnerabilityClass::SensitiveDataExposure,
            VulnerabilityClass::InformationDisclosure,
            VulnerabilityClass::WeakCryptography,
        ],
        (RegulatoryFramework::Soc2, "CC7.1") => vec![VulnerabilityClass::KnownVulnerableDependency],
        (RegulatoryFramework::Soc2, "CC8.1") => vec![
            VulnerabilityClass::SecurityMisconfiguration,
            VulnerabilityClass::CloudMisconfiguration,
        ],
        (RegulatoryFramework::Iso27001, "A.14.2.5") => vec![
            VulnerabilityClass::SqlInjection,
            VulnerabilityClass::CommandInjection,
            VulnerabilityClass::CrossSiteScripting,
        ],
        (RegulatoryFramework::Iso27001, "A.9.4.2") => vec![
            VulnerabilityClass::BrokenAuthentication,
            VulnerabilityClass::JwtVulnerability,
        ],
        (RegulatoryFramework::Iso27001, "A.9.4.1") => vec![
            VulnerabilityClass::BrokenAuthorization,
            VulnerabilityClass::InsecureDirectObjectReference,
        ],
        (RegulatoryFramework::Iso27001, "A.10.1.1") => vec![
            VulnerabilityClass::WeakCryptography,
            VulnerabilityClass::SensitiveDataExposure,
        ],
        (RegulatoryFramework::Iso27001, "A.12.6.1") => {
            vec![VulnerabilityClass::KnownVulnerableDependency]
        }
        (RegulatoryFramework::Gdpr, "Art. 32") => vec![
            VulnerabilityClass::SqlInjection,
            VulnerabilityClass::SensitiveDataExposure,
            VulnerabilityClass::InformationDisclosure,
        ],
        (RegulatoryFramework::Gdpr, "Art. 25") => vec![
            VulnerabilityClass::BrokenAuthentication,
            VulnerabilityClass::BrokenAuthorization,
        ],
        (RegulatoryFramework::Hipaa, "164.312(a)(1)") => vec![
            VulnerabilityClass::BrokenAuthorization,
            VulnerabilityClass::InsecureDirectObjectReference,
            VulnerabilityClass::SensitiveDataExposure,
        ],
        (RegulatoryFramework::Hipaa, "164.312(d)") => vec![
            VulnerabilityClass::BrokenAuthentication,
            VulnerabilityClass::JwtVulnerability,
        ],
        (RegulatoryFramework::FedRamp, "SI-10") => vec![
            VulnerabilityClass::SqlInjection,
            VulnerabilityClass::CommandInjection,
            VulnerabilityClass::CrossSiteScripting,
        ],
        (RegulatoryFramework::FedRamp, "IA-2") => vec![
            VulnerabilityClass::BrokenAuthentication,
            VulnerabilityClass::JwtVulnerability,
        ],
        (RegulatoryFramework::FedRamp, "AC-3") => vec![
            VulnerabilityClass::BrokenAuthorization,
            VulnerabilityClass::InsecureDirectObjectReference,
        ],
        (RegulatoryFramework::FedRamp, "RA-5") => {
            vec![VulnerabilityClass::KnownVulnerableDependency]
        }
        _ => vec![],
    }
}

/// Gap severity based on vulnerability severity and control importance.
fn gap_severity_for_vuln(vuln: VulnerabilityClass) -> GapSeverity {
    match vuln {
        VulnerabilityClass::SqlInjection
        | VulnerabilityClass::CommandInjection
        | VulnerabilityClass::InsecureDeserialization
        | VulnerabilityClass::ServerSideRequestForgery => GapSeverity::Critical,
        VulnerabilityClass::BrokenAuthentication
        | VulnerabilityClass::BrokenAuthorization
        | VulnerabilityClass::PathTraversal
        | VulnerabilityClass::ServerSideTemplateInjection
        | VulnerabilityClass::NoSqlInjection
        | VulnerabilityClass::XmlExternalEntity => GapSeverity::High,
        VulnerabilityClass::CrossSiteScripting
        | VulnerabilityClass::JwtVulnerability
        | VulnerabilityClass::InsecureDirectObjectReference
        | VulnerabilityClass::MassAssignment
        | VulnerabilityClass::SensitiveDataExposure
        | VulnerabilityClass::WeakCryptography
        | VulnerabilityClass::KnownVulnerableDependency => GapSeverity::Medium,
        VulnerabilityClass::SecurityMisconfiguration
        | VulnerabilityClass::MissingSecurityHeader
        | VulnerabilityClass::CrossOriginMisconfiguration
        | VulnerabilityClass::InformationDisclosure
        | VulnerabilityClass::CloudMisconfiguration => GapSeverity::Low,
        _ => GapSeverity::Informational,
    }
}

/// Checks compliance across all frameworks for discovered vulnerabilities.
///
/// For each vulnerability, maps to affected controls across SOC2, ISO 27001,
/// GDPR, HIPAA, and FedRAMP. Assesses control status, generates per-framework
/// compliance scores, and identifies highest-risk gaps.
pub fn check_regulatory_compliance(
    vulnerabilities: &[VulnerabilityClass],
) -> ComplianceCheckResult {
    let mut all_findings: Vec<ControlFinding> = Vec::new();
    let mut seen_controls: BTreeMap<(RegulatoryFramework, String), Vec<VulnerabilityClass>> =
        BTreeMap::new();

    for &vuln in vulnerabilities {
        let controls = map_vuln_to_controls(vuln);
        for control in controls {
            seen_controls
                .entry((control.framework, control.control_id.clone()))
                .or_default()
                .push(vuln);
        }
    }

    for ((framework, control_id), vulns) in &seen_controls {
        let control = FrameworkControl {
            framework: *framework,
            control_id: control_id.clone(),
            control_name: String::new(),
            description: String::new(),
        };
        let status = assess_control_status(&control, vulns);
        let worst_severity = vulns
            .iter()
            .map(|v| gap_severity_for_vuln(*v))
            .min_by_key(|s| match s {
                GapSeverity::Critical => 0,
                GapSeverity::High => 1,
                GapSeverity::Medium => 2,
                GapSeverity::Low => 3,
                GapSeverity::Informational => 4,
            })
            .unwrap_or(GapSeverity::Informational);

        let full_controls = map_vuln_to_controls(vulns[0]);
        let full_control = full_controls
            .iter()
            .find(|c| c.framework == *framework && c.control_id == *control_id)
            .cloned()
            .unwrap_or(control);

        all_findings.push(ControlFinding {
            control: full_control,
            status,
            related_vulnerabilities: vulns.clone(),
            gap_description: format!(
                "{} related vulnerabilities affect this control",
                vulns.len()
            ),
            remediation: remediation_for_control(*framework, control_id),
            severity: worst_severity,
        });
    }

    let framework_scores = build_framework_scores(&all_findings);
    let overall = if framework_scores.is_empty() {
        0.0
    } else {
        framework_scores
            .iter()
            .map(|fs| fs.compliance_percentage)
            .sum::<f64>()
            / framework_scores.len() as f64
    };

    let mut highest_risk = all_findings
        .iter()
        .filter(|f| matches!(f.severity, GapSeverity::Critical | GapSeverity::High))
        .cloned()
        .collect::<Vec<_>>();
    highest_risk.sort_by_key(|f| match f.severity {
        GapSeverity::Critical => 0,
        GapSeverity::High => 1,
        _ => 2,
    });

    ComplianceCheckResult {
        framework_scores,
        all_findings,
        overall_compliance_percentage: overall,
        highest_risk_gaps: highest_risk,
    }
}

fn build_framework_scores(findings: &[ControlFinding]) -> Vec<FrameworkScore> {
    let frameworks = [
        RegulatoryFramework::Soc2,
        RegulatoryFramework::Iso27001,
        RegulatoryFramework::Gdpr,
        RegulatoryFramework::Hipaa,
        RegulatoryFramework::FedRamp,
    ];

    let mut scores = Vec::new();
    for fw in &frameworks {
        let fw_findings: Vec<&ControlFinding> = findings
            .iter()
            .filter(|f| f.control.framework == *fw)
            .collect();

        if fw_findings.is_empty() {
            continue;
        }

        let total = fw_findings.len();
        let compliant = fw_findings
            .iter()
            .filter(|f| f.status == ControlStatus::Compliant)
            .count();
        let partial = fw_findings
            .iter()
            .filter(|f| f.status == ControlStatus::PartiallyCompliant)
            .count();
        let non_compliant = fw_findings
            .iter()
            .filter(|f| f.status == ControlStatus::NonCompliant)
            .count();
        let not_assessed = fw_findings
            .iter()
            .filter(|f| f.status == ControlStatus::NotAssessed)
            .count();

        let assessed = total - not_assessed;
        let compliance_pct = if assessed > 0 {
            ((compliant as f64 + partial as f64 * 0.5) / assessed as f64) * 100.0
        } else {
            0.0
        };

        let mut gaps: Vec<ControlFinding> = fw_findings
            .iter()
            .filter(|f| matches!(f.severity, GapSeverity::Critical | GapSeverity::High))
            .cloned()
            .cloned()
            .collect();
        gaps.sort_by_key(|g| match g.severity {
            GapSeverity::Critical => 0,
            GapSeverity::High => 1,
            _ => 2,
        });

        scores.push(FrameworkScore {
            framework: *fw,
            total_controls: total,
            compliant,
            partially_compliant: partial,
            non_compliant,
            not_assessed,
            compliance_percentage: compliance_pct,
            highest_risk_gaps: gaps,
        });
    }

    scores
}

fn remediation_for_control(framework: RegulatoryFramework, control_id: &str) -> String {
    match (framework, control_id) {
        (RegulatoryFramework::Soc2, "CC6.1") => {
            "Implement input validation, parameterized queries, and WAF".into()
        }
        (RegulatoryFramework::Soc2, "CC6.2") => "Enforce MFA and strong password policies".into(),
        (RegulatoryFramework::Soc2, "CC6.3") => {
            "Implement RBAC and validate authorization on every request".into()
        }
        (RegulatoryFramework::Soc2, "CC6.7") => {
            "Enable TLS 1.2+, encrypt data at rest, remove exposed secrets".into()
        }
        (RegulatoryFramework::Soc2, "CC7.1") => {
            "Run dependency scanning in CI/CD and patch known CVEs within SLA".into()
        }
        (RegulatoryFramework::Soc2, "CC8.1") => {
            "Establish configuration baselines and automate drift detection".into()
        }
        (RegulatoryFramework::Iso27001, "A.14.2.5") => {
            "Apply secure coding standards and static analysis in CI/CD".into()
        }
        (RegulatoryFramework::Iso27001, "A.9.4.2") => {
            "Strengthen authentication mechanisms and implement MFA".into()
        }
        (RegulatoryFramework::Iso27001, "A.12.6.1") => {
            "Implement vulnerability scanning and timely patching".into()
        }
        (RegulatoryFramework::Gdpr, "Art. 32") => {
            "Implement appropriate technical and organizational security measures".into()
        }
        (RegulatoryFramework::Gdpr, "Art. 25") => {
            "Apply data protection by design principles to access controls".into()
        }
        (RegulatoryFramework::Hipaa, "164.312(a)(1)") => {
            "Implement technical policies for access to ePHI systems".into()
        }
        (RegulatoryFramework::Hipaa, "164.312(d)") => {
            "Implement entity authentication procedures for ePHI access".into()
        }
        (RegulatoryFramework::FedRamp, "SI-10") => {
            "Validate all information inputs and implement output encoding".into()
        }
        (RegulatoryFramework::FedRamp, "IA-2") => {
            "Implement multi-factor authentication for privileged accounts".into()
        }
        (RegulatoryFramework::FedRamp, "AC-3") => {
            "Enforce approved authorizations using RBAC".into()
        }
        (RegulatoryFramework::FedRamp, "RA-5") => {
            "Conduct regular vulnerability scanning and remediate per POA&M".into()
        }
        _ => "Remediate identified vulnerabilities and implement compensating controls".into(),
    }
}

/// Formats a multi-framework compliance report as markdown.
pub fn format_compliance_report(result: &ComplianceCheckResult) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Regulatory Compliance Report\n");
    let _ = writeln!(
        out,
        "**Overall Compliance Score:** {:.1}%\n",
        result.overall_compliance_percentage
    );

    for fs in &result.framework_scores {
        let _ = writeln!(out, "## {}\n", fs.framework);
        let _ = writeln!(
            out,
            "- **Compliance Score:** {:.1}%",
            fs.compliance_percentage
        );
        let _ = writeln!(out, "- **Controls Assessed:** {}", fs.total_controls);
        let _ = writeln!(out, "- **Compliant:** {}", fs.compliant);
        let _ = writeln!(out, "- **Partially Compliant:** {}", fs.partially_compliant);
        let _ = writeln!(out, "- **Non-Compliant:** {}", fs.non_compliant);
        let _ = writeln!(out);
    }

    if !result.highest_risk_gaps.is_empty() {
        let _ = writeln!(out, "## Highest Risk Gaps\n");
        for gap in &result.highest_risk_gaps {
            let _ = writeln!(
                out,
                "- **[{}] {} ({})** \u{2014} {} | {}",
                gap.control.framework,
                gap.control.control_id,
                gap.severity,
                gap.gap_description,
                gap.remediation
            );
        }
    }

    out
}
