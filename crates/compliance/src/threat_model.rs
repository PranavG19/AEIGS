use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write;

use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};

/// STRIDE threat category per Microsoft's threat modeling methodology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StrideCategory {
    Spoofing,
    Tampering,
    Repudiation,
    InformationDisclosure,
    DenialOfService,
    ElevationOfPrivilege,
}

impl fmt::Display for StrideCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StrideCategory::Spoofing => write!(f, "Spoofing"),
            StrideCategory::Tampering => write!(f, "Tampering"),
            StrideCategory::Repudiation => write!(f, "Repudiation"),
            StrideCategory::InformationDisclosure => write!(f, "Information Disclosure"),
            StrideCategory::DenialOfService => write!(f, "Denial of Service"),
            StrideCategory::ElevationOfPrivilege => write!(f, "Elevation of Privilege"),
        }
    }
}

/// Trust boundary between architectural components.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TrustBoundary {
    pub name: String,
    pub from_zone: String,
    pub to_zone: String,
    pub description: String,
}

/// A data flow crossing trust boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DataFlow {
    pub name: String,
    pub source: String,
    pub destination: String,
    pub data_classification: DataClassification,
    pub protocol: String,
}

/// Classification of data sensitivity for risk assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl fmt::Display for DataClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataClassification::Public => write!(f, "Public"),
            DataClassification::Internal => write!(f, "Internal"),
            DataClassification::Confidential => write!(f, "Confidential"),
            DataClassification::Restricted => write!(f, "Restricted"),
        }
    }
}

/// An entry point discovered in the target architecture.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntryPoint {
    pub name: String,
    pub entry_type: EntryPointType,
    pub url_pattern: String,
    pub authentication_required: bool,
}

/// Categorization of entry point types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntryPointType {
    WebEndpoint,
    ApiEndpoint,
    GraphQlEndpoint,
    WebSocket,
    FileUpload,
    AuthenticationFlow,
    AdminPanel,
}

impl fmt::Display for EntryPointType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntryPointType::WebEndpoint => write!(f, "Web Endpoint"),
            EntryPointType::ApiEndpoint => write!(f, "API Endpoint"),
            EntryPointType::GraphQlEndpoint => write!(f, "GraphQL Endpoint"),
            EntryPointType::WebSocket => write!(f, "WebSocket"),
            EntryPointType::FileUpload => write!(f, "File Upload"),
            EntryPointType::AuthenticationFlow => write!(f, "Authentication Flow"),
            EntryPointType::AdminPanel => write!(f, "Admin Panel"),
        }
    }
}

/// A single STRIDE threat identified against an architectural element.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrideThreat {
    pub category: StrideCategory,
    pub target: String,
    pub description: String,
    pub likelihood: ThreatLikelihood,
    pub impact: ThreatImpact,
    pub risk_rating: RiskRating,
    pub related_vulnerabilities: Vec<VulnerabilityClass>,
    pub mitigations: Vec<String>,
}

/// Qualitative likelihood of a threat being exploited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatLikelihood {
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatLikelihood {
    fn score(self) -> u32 {
        match self {
            ThreatLikelihood::Low => 1,
            ThreatLikelihood::Medium => 2,
            ThreatLikelihood::High => 3,
            ThreatLikelihood::Critical => 4,
        }
    }
}

impl fmt::Display for ThreatLikelihood {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatLikelihood::Low => write!(f, "Low"),
            ThreatLikelihood::Medium => write!(f, "Medium"),
            ThreatLikelihood::High => write!(f, "High"),
            ThreatLikelihood::Critical => write!(f, "Critical"),
        }
    }
}

/// Qualitative impact if a threat is realized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatImpact {
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatImpact {
    fn score(self) -> u32 {
        match self {
            ThreatImpact::Low => 1,
            ThreatImpact::Medium => 2,
            ThreatImpact::High => 3,
            ThreatImpact::Critical => 4,
        }
    }
}

impl fmt::Display for ThreatImpact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatImpact::Low => write!(f, "Low"),
            ThreatImpact::Medium => write!(f, "Medium"),
            ThreatImpact::High => write!(f, "High"),
            ThreatImpact::Critical => write!(f, "Critical"),
        }
    }
}

/// Composite risk rating derived from likelihood × impact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskRating {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskRating {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskRating::Low => write!(f, "Low"),
            RiskRating::Medium => write!(f, "Medium"),
            RiskRating::High => write!(f, "High"),
            RiskRating::Critical => write!(f, "Critical"),
        }
    }
}

/// Computes risk rating from likelihood × impact scores.
/// Score matrix: 1-3 = Low, 4-6 = Medium, 8-9 = High, 12-16 = Critical.
pub fn compute_risk_rating(likelihood: ThreatLikelihood, impact: ThreatImpact) -> RiskRating {
    let score = likelihood.score() * impact.score();
    match score {
        1..=3 => RiskRating::Low,
        4..=6 => RiskRating::Medium,
        8..=9 => RiskRating::High,
        _ => RiskRating::Critical,
    }
}

/// Discovered architecture fed into the threat model generator.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveredArchitecture {
    pub target_name: String,
    pub trust_boundaries: Vec<TrustBoundary>,
    pub data_flows: Vec<DataFlow>,
    pub entry_points: Vec<EntryPoint>,
    pub discovered_vulnerabilities: Vec<VulnerabilityClass>,
}

/// Complete STRIDE threat model output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatModel {
    pub target_name: String,
    pub trust_boundaries: Vec<TrustBoundary>,
    pub data_flows: Vec<DataFlow>,
    pub entry_points: Vec<EntryPoint>,
    pub threats: Vec<StrideThreat>,
    pub summary: ThreatModelSummary,
}

/// Aggregated statistics from the threat model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatModelSummary {
    pub total_threats: usize,
    pub critical_threats: usize,
    pub high_threats: usize,
    pub medium_threats: usize,
    pub low_threats: usize,
    pub threats_by_category: BTreeMap<String, usize>,
}

/// Generates a complete STRIDE threat model from discovered architecture.
///
/// For each entry point and data flow, evaluates all six STRIDE categories
/// and produces threats with likelihood, impact, risk rating, and mitigations.
pub fn generate_threat_model(arch: &DiscoveredArchitecture) -> ThreatModel {
    let mut threats = Vec::new();

    for entry_point in &arch.entry_points {
        threats.extend(analyze_entry_point(
            entry_point,
            &arch.discovered_vulnerabilities,
        ));
    }

    for data_flow in &arch.data_flows {
        threats.extend(analyze_data_flow(
            data_flow,
            &arch.discovered_vulnerabilities,
        ));
    }

    for boundary in &arch.trust_boundaries {
        threats.extend(analyze_trust_boundary(
            boundary,
            &arch.discovered_vulnerabilities,
        ));
    }

    let summary = build_summary(&threats);

    ThreatModel {
        target_name: arch.target_name.clone(),
        trust_boundaries: arch.trust_boundaries.clone(),
        data_flows: arch.data_flows.clone(),
        entry_points: arch.entry_points.clone(),
        threats,
        summary,
    }
}

fn analyze_entry_point(ep: &EntryPoint, discovered: &[VulnerabilityClass]) -> Vec<StrideThreat> {
    let mut threats = Vec::new();

    let (spoof_likelihood, spoof_vulns) = if !ep.authentication_required {
        (
            ThreatLikelihood::High,
            vec![VulnerabilityClass::BrokenAuthentication],
        )
    } else if discovered.contains(&VulnerabilityClass::BrokenAuthentication)
        || discovered.contains(&VulnerabilityClass::JwtVulnerability)
    {
        (
            ThreatLikelihood::High,
            vec![
                VulnerabilityClass::BrokenAuthentication,
                VulnerabilityClass::JwtVulnerability,
            ],
        )
    } else {
        (ThreatLikelihood::Low, vec![])
    };

    threats.push(StrideThreat {
        category: StrideCategory::Spoofing,
        target: ep.name.clone(),
        description: format!(
            "An attacker could impersonate a legitimate user at {} ({})",
            ep.name, ep.entry_type
        ),
        likelihood: spoof_likelihood,
        impact: ThreatImpact::High,
        risk_rating: compute_risk_rating(spoof_likelihood, ThreatImpact::High),
        related_vulnerabilities: spoof_vulns,
        mitigations: vec![
            "Enforce multi-factor authentication".into(),
            "Implement strong session management".into(),
            "Use cryptographically secure token generation".into(),
        ],
    });

    let has_injection = discovered.iter().any(|v| {
        matches!(
            v,
            VulnerabilityClass::SqlInjection
                | VulnerabilityClass::CommandInjection
                | VulnerabilityClass::CrossSiteScripting
                | VulnerabilityClass::ServerSideTemplateInjection
                | VulnerabilityClass::NoSqlInjection
        )
    });
    let tamper_likelihood = if has_injection {
        ThreatLikelihood::Critical
    } else {
        ThreatLikelihood::Medium
    };

    threats.push(StrideThreat {
        category: StrideCategory::Tampering,
        target: ep.name.clone(),
        description: format!(
            "An attacker could modify data or inject malicious input at {} ({})",
            ep.name, ep.entry_type
        ),
        likelihood: tamper_likelihood,
        impact: ThreatImpact::High,
        risk_rating: compute_risk_rating(tamper_likelihood, ThreatImpact::High),
        related_vulnerabilities: discovered
            .iter()
            .filter(|v| {
                matches!(
                    v,
                    VulnerabilityClass::SqlInjection
                        | VulnerabilityClass::CommandInjection
                        | VulnerabilityClass::CrossSiteScripting
                        | VulnerabilityClass::ServerSideTemplateInjection
                )
            })
            .copied()
            .collect(),
        mitigations: vec![
            "Validate and sanitize all inputs".into(),
            "Use parameterized queries".into(),
            "Implement Content Security Policy".into(),
        ],
    });

    threats.push(StrideThreat {
        category: StrideCategory::Repudiation,
        target: ep.name.clone(),
        description: format!(
            "Actions at {} may not be properly logged, allowing deniability",
            ep.name
        ),
        likelihood: ThreatLikelihood::Medium,
        impact: ThreatImpact::Medium,
        risk_rating: compute_risk_rating(ThreatLikelihood::Medium, ThreatImpact::Medium),
        related_vulnerabilities: vec![],
        mitigations: vec![
            "Implement comprehensive audit logging".into(),
            "Use tamper-evident log storage".into(),
            "Include timestamps and actor identity in all log entries".into(),
        ],
    });

    let has_info_leak = discovered.iter().any(|v| {
        matches!(
            v,
            VulnerabilityClass::SensitiveDataExposure
                | VulnerabilityClass::InformationDisclosure
                | VulnerabilityClass::PathTraversal
        )
    });
    let info_likelihood = if has_info_leak {
        ThreatLikelihood::High
    } else {
        ThreatLikelihood::Medium
    };

    threats.push(StrideThreat {
        category: StrideCategory::InformationDisclosure,
        target: ep.name.clone(),
        description: format!(
            "Sensitive data could be exposed through {} ({})",
            ep.name, ep.entry_type
        ),
        likelihood: info_likelihood,
        impact: ThreatImpact::High,
        risk_rating: compute_risk_rating(info_likelihood, ThreatImpact::High),
        related_vulnerabilities: discovered
            .iter()
            .filter(|v| {
                matches!(
                    v,
                    VulnerabilityClass::SensitiveDataExposure
                        | VulnerabilityClass::InformationDisclosure
                        | VulnerabilityClass::PathTraversal
                )
            })
            .copied()
            .collect(),
        mitigations: vec![
            "Encrypt data in transit and at rest".into(),
            "Implement proper access controls on sensitive resources".into(),
            "Remove verbose error messages in production".into(),
        ],
    });

    threats.push(StrideThreat {
        category: StrideCategory::DenialOfService,
        target: ep.name.clone(),
        description: format!(
            "{} could be overwhelmed or made unavailable through resource exhaustion",
            ep.name
        ),
        likelihood: ThreatLikelihood::Medium,
        impact: ThreatImpact::Medium,
        risk_rating: compute_risk_rating(ThreatLikelihood::Medium, ThreatImpact::Medium),
        related_vulnerabilities: discovered
            .iter()
            .filter(|v| {
                matches!(
                    v,
                    VulnerabilityClass::GraphQlAbuse | VulnerabilityClass::HttpRequestSmuggling
                )
            })
            .copied()
            .collect(),
        mitigations: vec![
            "Implement rate limiting".into(),
            "Set request size limits".into(),
            "Use query complexity analysis for GraphQL".into(),
        ],
    });

    let has_authz_issue = discovered.iter().any(|v| {
        matches!(
            v,
            VulnerabilityClass::BrokenAuthorization
                | VulnerabilityClass::InsecureDirectObjectReference
                | VulnerabilityClass::MassAssignment
        )
    });
    let eop_likelihood = if has_authz_issue {
        ThreatLikelihood::Critical
    } else if !ep.authentication_required {
        ThreatLikelihood::High
    } else {
        ThreatLikelihood::Medium
    };

    threats.push(StrideThreat {
        category: StrideCategory::ElevationOfPrivilege,
        target: ep.name.clone(),
        description: format!(
            "An attacker could gain elevated access through {} ({})",
            ep.name, ep.entry_type
        ),
        likelihood: eop_likelihood,
        impact: ThreatImpact::Critical,
        risk_rating: compute_risk_rating(eop_likelihood, ThreatImpact::Critical),
        related_vulnerabilities: discovered
            .iter()
            .filter(|v| {
                matches!(
                    v,
                    VulnerabilityClass::BrokenAuthorization
                        | VulnerabilityClass::InsecureDirectObjectReference
                        | VulnerabilityClass::MassAssignment
                )
            })
            .copied()
            .collect(),
        mitigations: vec![
            "Implement principle of least privilege".into(),
            "Enforce role-based access control".into(),
            "Validate authorization on every request".into(),
        ],
    });

    threats
}

fn analyze_data_flow(flow: &DataFlow, discovered: &[VulnerabilityClass]) -> Vec<StrideThreat> {
    let mut threats = Vec::new();

    let tamper_likelihood = match flow.data_classification {
        DataClassification::Restricted | DataClassification::Confidential => ThreatLikelihood::High,
        DataClassification::Internal => ThreatLikelihood::Medium,
        DataClassification::Public => ThreatLikelihood::Low,
    };

    threats.push(StrideThreat {
        category: StrideCategory::Tampering,
        target: flow.name.clone(),
        description: format!(
            "Data in transit from {} to {} ({} data over {}) could be modified",
            flow.source, flow.destination, flow.data_classification, flow.protocol
        ),
        likelihood: tamper_likelihood,
        impact: match flow.data_classification {
            DataClassification::Restricted => ThreatImpact::Critical,
            DataClassification::Confidential => ThreatImpact::High,
            _ => ThreatImpact::Medium,
        },
        risk_rating: compute_risk_rating(
            tamper_likelihood,
            match flow.data_classification {
                DataClassification::Restricted => ThreatImpact::Critical,
                DataClassification::Confidential => ThreatImpact::High,
                _ => ThreatImpact::Medium,
            },
        ),
        related_vulnerabilities: vec![],
        mitigations: vec![
            "Use TLS for all data in transit".into(),
            "Implement message integrity checks".into(),
            "Validate data at trust boundaries".into(),
        ],
    });

    let info_impact = match flow.data_classification {
        DataClassification::Restricted => ThreatImpact::Critical,
        DataClassification::Confidential => ThreatImpact::High,
        DataClassification::Internal => ThreatImpact::Medium,
        DataClassification::Public => ThreatImpact::Low,
    };

    let has_crypto_weakness = discovered.contains(&VulnerabilityClass::WeakCryptography);
    let info_likelihood = if has_crypto_weakness {
        ThreatLikelihood::High
    } else {
        match flow.data_classification {
            DataClassification::Restricted | DataClassification::Confidential => {
                ThreatLikelihood::Medium
            }
            _ => ThreatLikelihood::Low,
        }
    };

    threats.push(StrideThreat {
        category: StrideCategory::InformationDisclosure,
        target: flow.name.clone(),
        description: format!(
            "{} data flowing from {} to {} could be intercepted",
            flow.data_classification, flow.source, flow.destination
        ),
        likelihood: info_likelihood,
        impact: info_impact,
        risk_rating: compute_risk_rating(info_likelihood, info_impact),
        related_vulnerabilities: if has_crypto_weakness {
            vec![VulnerabilityClass::WeakCryptography]
        } else {
            vec![]
        },
        mitigations: vec![
            "Encrypt sensitive data in transit".into(),
            "Use strong cipher suites (TLS 1.2+)".into(),
            "Implement certificate pinning for critical flows".into(),
        ],
    });

    threats
}

fn analyze_trust_boundary(
    boundary: &TrustBoundary,
    discovered: &[VulnerabilityClass],
) -> Vec<StrideThreat> {
    let mut threats = Vec::new();

    let has_ssrf = discovered.contains(&VulnerabilityClass::ServerSideRequestForgery);
    let spoof_likelihood = if has_ssrf {
        ThreatLikelihood::High
    } else {
        ThreatLikelihood::Medium
    };

    threats.push(StrideThreat {
        category: StrideCategory::Spoofing,
        target: boundary.name.clone(),
        description: format!(
            "Trust boundary between {} and {} could be bypassed through spoofed requests",
            boundary.from_zone, boundary.to_zone
        ),
        likelihood: spoof_likelihood,
        impact: ThreatImpact::High,
        risk_rating: compute_risk_rating(spoof_likelihood, ThreatImpact::High),
        related_vulnerabilities: if has_ssrf {
            vec![VulnerabilityClass::ServerSideRequestForgery]
        } else {
            vec![]
        },
        mitigations: vec![
            "Validate requests at trust boundaries".into(),
            "Implement network segmentation".into(),
            "Use mutual TLS between zones".into(),
        ],
    });

    let eop_likelihood = if discovered.contains(&VulnerabilityClass::BrokenAuthorization) {
        ThreatLikelihood::Critical
    } else {
        ThreatLikelihood::Medium
    };

    threats.push(StrideThreat {
        category: StrideCategory::ElevationOfPrivilege,
        target: boundary.name.clone(),
        description: format!(
            "An attacker in {} could escalate to {} zone privileges",
            boundary.from_zone, boundary.to_zone
        ),
        likelihood: eop_likelihood,
        impact: ThreatImpact::Critical,
        risk_rating: compute_risk_rating(eop_likelihood, ThreatImpact::Critical),
        related_vulnerabilities: discovered
            .iter()
            .filter(|v| matches!(v, VulnerabilityClass::BrokenAuthorization))
            .copied()
            .collect(),
        mitigations: vec![
            "Enforce strict access control at boundary".into(),
            "Implement defense in depth".into(),
            "Monitor cross-boundary traffic for anomalies".into(),
        ],
    });

    threats
}

fn build_summary(threats: &[StrideThreat]) -> ThreatModelSummary {
    let mut by_category: BTreeMap<String, usize> = BTreeMap::new();
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    for threat in threats {
        *by_category.entry(threat.category.to_string()).or_default() += 1;
        match threat.risk_rating {
            RiskRating::Critical => critical += 1,
            RiskRating::High => high += 1,
            RiskRating::Medium => medium += 1,
            RiskRating::Low => low += 1,
        }
    }

    ThreatModelSummary {
        total_threats: threats.len(),
        critical_threats: critical,
        high_threats: high,
        medium_threats: medium,
        low_threats: low,
        threats_by_category: by_category,
    }
}

/// Formats a threat model as a human-readable markdown report.
pub fn format_threat_model_report(model: &ThreatModel) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# STRIDE Threat Model: {}\n", model.target_name);

    let _ = writeln!(out, "## Summary\n");
    let _ = writeln!(out, "- **Total Threats:** {}", model.summary.total_threats);
    let _ = writeln!(out, "- **Critical:** {}", model.summary.critical_threats);
    let _ = writeln!(out, "- **High:** {}", model.summary.high_threats);
    let _ = writeln!(out, "- **Medium:** {}", model.summary.medium_threats);
    let _ = writeln!(out, "- **Low:** {}", model.summary.low_threats);
    let _ = writeln!(out);

    let _ = writeln!(out, "## Trust Boundaries\n");
    for boundary in &model.trust_boundaries {
        let _ = writeln!(
            out,
            "- **{}**: {} \u{2192} {} \u{2014} {}",
            boundary.name, boundary.from_zone, boundary.to_zone, boundary.description
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Data Flows\n");
    for flow in &model.data_flows {
        let _ = writeln!(
            out,
            "- **{}**: {} \u{2192} {} ({}, {})",
            flow.name, flow.source, flow.destination, flow.data_classification, flow.protocol
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Entry Points\n");
    for ep in &model.entry_points {
        let auth = if ep.authentication_required {
            "authenticated"
        } else {
            "unauthenticated"
        };
        let _ = writeln!(
            out,
            "- **{}**: {} \u{2014} {} ({})",
            ep.name, ep.url_pattern, ep.entry_type, auth
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Threats\n");
    for (i, threat) in model.threats.iter().enumerate() {
        let _ = writeln!(
            out,
            "### T{:03}: {} \u{2014} {}\n",
            i + 1,
            threat.category,
            threat.target
        );
        let _ = writeln!(out, "{}\n", threat.description);
        let _ = writeln!(
            out,
            "- **Likelihood:** {} | **Impact:** {} | **Risk:** {}",
            threat.likelihood, threat.impact, threat.risk_rating
        );
        if !threat.related_vulnerabilities.is_empty() {
            let vuln_names: Vec<String> = threat
                .related_vulnerabilities
                .iter()
                .map(|v| v.to_string())
                .collect();
            let _ = writeln!(out, "- **Related Findings:** {}", vuln_names.join(", "));
        }
        let _ = writeln!(out, "- **Mitigations:**");
        for m in &threat.mitigations {
            let _ = writeln!(out, "  - {m}");
        }
        let _ = writeln!(out);
    }

    out
}

/// Maps a vulnerability class to its primary STRIDE categories.
pub fn vuln_to_stride_categories(vuln: VulnerabilityClass) -> Vec<StrideCategory> {
    match vuln {
        VulnerabilityClass::SqlInjection
        | VulnerabilityClass::NoSqlInjection
        | VulnerabilityClass::CommandInjection
        | VulnerabilityClass::ServerSideTemplateInjection
        | VulnerabilityClass::HeaderInjection
        | VulnerabilityClass::CrlfInjection
        | VulnerabilityClass::HostHeaderInjection
        | VulnerabilityClass::PrototypePollution => {
            vec![
                StrideCategory::Tampering,
                StrideCategory::InformationDisclosure,
            ]
        }
        VulnerabilityClass::CrossSiteScripting => {
            vec![
                StrideCategory::Tampering,
                StrideCategory::Spoofing,
                StrideCategory::InformationDisclosure,
            ]
        }
        VulnerabilityClass::BrokenAuthentication | VulnerabilityClass::JwtVulnerability => {
            vec![
                StrideCategory::Spoofing,
                StrideCategory::ElevationOfPrivilege,
            ]
        }
        VulnerabilityClass::BrokenAuthorization
        | VulnerabilityClass::InsecureDirectObjectReference
        | VulnerabilityClass::MassAssignment => {
            vec![
                StrideCategory::ElevationOfPrivilege,
                StrideCategory::Tampering,
            ]
        }
        VulnerabilityClass::PathTraversal
        | VulnerabilityClass::SensitiveDataExposure
        | VulnerabilityClass::InformationDisclosure
        | VulnerabilityClass::WeakCryptography => {
            vec![StrideCategory::InformationDisclosure]
        }
        VulnerabilityClass::ServerSideRequestForgery => {
            vec![
                StrideCategory::Spoofing,
                StrideCategory::InformationDisclosure,
            ]
        }
        VulnerabilityClass::SecurityMisconfiguration
        | VulnerabilityClass::MissingSecurityHeader
        | VulnerabilityClass::CrossOriginMisconfiguration
        | VulnerabilityClass::CloudMisconfiguration => {
            vec![
                StrideCategory::InformationDisclosure,
                StrideCategory::Tampering,
            ]
        }
        VulnerabilityClass::InsecureDeserialization => {
            vec![
                StrideCategory::Tampering,
                StrideCategory::ElevationOfPrivilege,
            ]
        }
        VulnerabilityClass::OpenRedirect => {
            vec![StrideCategory::Spoofing]
        }
        VulnerabilityClass::KnownVulnerableDependency => {
            vec![
                StrideCategory::Tampering,
                StrideCategory::ElevationOfPrivilege,
                StrideCategory::InformationDisclosure,
            ]
        }
        VulnerabilityClass::InsufficientInputValidation => {
            vec![StrideCategory::Tampering]
        }
        VulnerabilityClass::XmlExternalEntity => {
            vec![
                StrideCategory::InformationDisclosure,
                StrideCategory::DenialOfService,
            ]
        }
        VulnerabilityClass::HttpRequestSmuggling => {
            vec![StrideCategory::Tampering, StrideCategory::Spoofing]
        }
        VulnerabilityClass::RaceCondition => {
            vec![
                StrideCategory::Tampering,
                StrideCategory::ElevationOfPrivilege,
            ]
        }
        VulnerabilityClass::SubdomainTakeover => {
            vec![StrideCategory::Spoofing]
        }
        VulnerabilityClass::GraphQlAbuse => {
            vec![
                StrideCategory::DenialOfService,
                StrideCategory::InformationDisclosure,
            ]
        }
        VulnerabilityClass::Clickjacking => {
            vec![StrideCategory::Spoofing, StrideCategory::Tampering]
        }
        VulnerabilityClass::CachePoisoning => {
            vec![StrideCategory::Tampering, StrideCategory::Spoofing]
        }
    }
}
