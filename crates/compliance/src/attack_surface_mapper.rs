use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::request::ParameterLocation;

use crate::compliance_mapper::map_to_compliance;

/// A compliance requirement from a specific framework that mandates testing
/// for a particular class of vulnerability.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ComplianceRequirement {
    pub framework: ComplianceFramework,
    pub requirement_id: String,
    pub description: String,
    pub required_vuln_classes: Vec<VulnerabilityClass>,
}

/// Supported compliance frameworks for gap analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ComplianceFramework {
    OwaspTop10_2021,
    PciDss,
    ApiSecurity2023,
}

impl fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComplianceFramework::OwaspTop10_2021 => write!(f, "OWASP Top 10 2021"),
            ComplianceFramework::PciDss => write!(f, "PCI-DSS"),
            ComplianceFramework::ApiSecurity2023 => write!(f, "API Security 2023"),
        }
    }
}

/// Represents a discovered endpoint with its tested vulnerability classes.
#[derive(Debug, Clone)]
pub struct EndpointCoverage {
    pub endpoint: String,
    pub method: String,
    pub tested_classes: HashSet<VulnerabilityClass>,
    pub parameters: Vec<String>,
}

/// A single gap in compliance coverage: a requirement that has not been
/// fully tested on a specific endpoint.
#[derive(Debug, Clone)]
pub struct ComplianceGap {
    pub requirement: ComplianceRequirement,
    pub endpoint: String,
    pub method: String,
    pub tested_classes: Vec<VulnerabilityClass>,
    pub untested_classes: Vec<VulnerabilityClass>,
    pub coverage_ratio: f64,
    pub priority_score: f64,
}

/// A fuzz target generated from a compliance gap.
#[derive(Debug, Clone, PartialEq)]
pub struct GapFuzzTarget {
    pub endpoint: String,
    pub method: String,
    pub parameter: String,
    pub parameter_location: ParameterLocation,
    pub vulnerability_class: VulnerabilityClass,
    pub priority_score: f64,
    pub compliance_source: String,
    pub attempts: u32,
    pub max_attempts: u32,
}

/// Row in the coverage matrix: one entry per (framework, requirement) pair.
#[derive(Debug, Clone)]
pub struct CoverageMatrixEntry {
    pub framework: ComplianceFramework,
    pub requirement_id: String,
    pub total_classes: usize,
    pub tested_classes: usize,
    pub untested_classes: usize,
    pub coverage_pct: f64,
    pub tested_list: Vec<VulnerabilityClass>,
    pub untested_list: Vec<VulnerabilityClass>,
}

/// Full result of an attack surface gap analysis.
#[derive(Debug)]
pub struct AttackSurfaceAnalysis {
    pub gaps: Vec<ComplianceGap>,
    pub fuzz_targets: Vec<GapFuzzTarget>,
    pub coverage_matrix: Vec<CoverageMatrixEntry>,
    pub total_requirements: usize,
    pub fully_covered_requirements: usize,
    pub partially_covered_requirements: usize,
    pub uncovered_requirements: usize,
}

/// Describes the current scan state: what findings exist and on which endpoints.
#[derive(Debug, Clone)]
pub struct ScanState {
    pub findings: Vec<ScanFinding>,
    pub known_endpoints: Vec<KnownEndpoint>,
}

/// A single finding from the scan.
#[derive(Debug, Clone)]
pub struct ScanFinding {
    pub endpoint: String,
    pub method: String,
    pub vulnerability_class: VulnerabilityClass,
    pub parameter: Option<String>,
}

/// An endpoint discovered during recon/crawling.
#[derive(Debug, Clone)]
pub struct KnownEndpoint {
    pub endpoint: String,
    pub method: String,
    pub parameters: Vec<String>,
}

/// Builds the canonical set of compliance requirements across all three frameworks.
///
/// Each requirement maps a framework rule to the vulnerability classes
/// that must be tested in order to satisfy it.
pub fn all_compliance_requirements() -> Vec<ComplianceRequirement> {
    let mut reqs = Vec::new();

    reqs.extend(owasp_top10_requirements());
    reqs.extend(pci_dss_requirements());
    reqs.extend(api_security_2023_requirements());

    reqs
}

fn owasp_top10_requirements() -> Vec<ComplianceRequirement> {
    vec![
        ComplianceRequirement {
            framework: ComplianceFramework::OwaspTop10_2021,
            requirement_id: "A01:2021".into(),
            description: "Broken Access Control".into(),
            required_vuln_classes: vec![
                VulnerabilityClass::BrokenAuthorization,
                VulnerabilityClass::InsecureDirectObjectReference,
                VulnerabilityClass::MassAssignment,
                VulnerabilityClass::OpenRedirect,
            ],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::OwaspTop10_2021,
            requirement_id: "A02:2021".into(),
            description: "Cryptographic Failures".into(),
            required_vuln_classes: vec![
                VulnerabilityClass::SensitiveDataExposure,
                VulnerabilityClass::InformationDisclosure,
                VulnerabilityClass::WeakCryptography,
            ],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::OwaspTop10_2021,
            requirement_id: "A03:2021".into(),
            description: "Injection".into(),
            required_vuln_classes: vec![
                VulnerabilityClass::SqlInjection,
                VulnerabilityClass::NoSqlInjection,
                VulnerabilityClass::CrossSiteScripting,
                VulnerabilityClass::CommandInjection,
                VulnerabilityClass::PathTraversal,
                VulnerabilityClass::XmlExternalEntity,
                VulnerabilityClass::ServerSideTemplateInjection,
                VulnerabilityClass::HeaderInjection,
                VulnerabilityClass::CrlfInjection,
                VulnerabilityClass::InsufficientInputValidation,
                VulnerabilityClass::PrototypePollution,
                VulnerabilityClass::HostHeaderInjection,
            ],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::OwaspTop10_2021,
            requirement_id: "A04:2021".into(),
            description: "Insecure Design".into(),
            required_vuln_classes: vec![VulnerabilityClass::RaceCondition],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::OwaspTop10_2021,
            requirement_id: "A05:2021".into(),
            description: "Security Misconfiguration".into(),
            required_vuln_classes: vec![
                VulnerabilityClass::SecurityMisconfiguration,
                VulnerabilityClass::MissingSecurityHeader,
                VulnerabilityClass::CrossOriginMisconfiguration,
                VulnerabilityClass::HttpRequestSmuggling,
                VulnerabilityClass::SubdomainTakeover,
                VulnerabilityClass::CloudMisconfiguration,
                VulnerabilityClass::Clickjacking,
                VulnerabilityClass::CachePoisoning,
            ],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::OwaspTop10_2021,
            requirement_id: "A06:2021".into(),
            description: "Vulnerable and Outdated Components".into(),
            required_vuln_classes: vec![VulnerabilityClass::KnownVulnerableDependency],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::OwaspTop10_2021,
            requirement_id: "A07:2021".into(),
            description: "Identification and Authentication Failures".into(),
            required_vuln_classes: vec![
                VulnerabilityClass::BrokenAuthentication,
                VulnerabilityClass::JwtVulnerability,
            ],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::OwaspTop10_2021,
            requirement_id: "A08:2021".into(),
            description: "Software and Data Integrity Failures".into(),
            required_vuln_classes: vec![VulnerabilityClass::InsecureDeserialization],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::OwaspTop10_2021,
            requirement_id: "A10:2021".into(),
            description: "Server-Side Request Forgery".into(),
            required_vuln_classes: vec![VulnerabilityClass::ServerSideRequestForgery],
        },
    ]
}

fn pci_dss_requirements() -> Vec<ComplianceRequirement> {
    vec![
        ComplianceRequirement {
            framework: ComplianceFramework::PciDss,
            requirement_id: "6.5.1".into(),
            description: "Injection flaws".into(),
            required_vuln_classes: vec![
                VulnerabilityClass::SqlInjection,
                VulnerabilityClass::NoSqlInjection,
                VulnerabilityClass::CommandInjection,
                VulnerabilityClass::XmlExternalEntity,
                VulnerabilityClass::ServerSideTemplateInjection,
                VulnerabilityClass::InsecureDeserialization,
                VulnerabilityClass::HeaderInjection,
                VulnerabilityClass::CrlfInjection,
                VulnerabilityClass::InsufficientInputValidation,
                VulnerabilityClass::HostHeaderInjection,
            ],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::PciDss,
            requirement_id: "6.5.3".into(),
            description: "Insecure cryptographic storage".into(),
            required_vuln_classes: vec![
                VulnerabilityClass::SensitiveDataExposure,
                VulnerabilityClass::InformationDisclosure,
                VulnerabilityClass::WeakCryptography,
            ],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::PciDss,
            requirement_id: "6.5.6".into(),
            description: "All high risk vulnerabilities".into(),
            required_vuln_classes: vec![
                VulnerabilityClass::SecurityMisconfiguration,
                VulnerabilityClass::MissingSecurityHeader,
                VulnerabilityClass::CrossOriginMisconfiguration,
                VulnerabilityClass::KnownVulnerableDependency,
                VulnerabilityClass::HttpRequestSmuggling,
                VulnerabilityClass::CloudMisconfiguration,
                VulnerabilityClass::Clickjacking,
            ],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::PciDss,
            requirement_id: "6.5.7".into(),
            description: "Cross-site scripting".into(),
            required_vuln_classes: vec![VulnerabilityClass::CrossSiteScripting],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::PciDss,
            requirement_id: "6.5.8".into(),
            description: "Improper access control".into(),
            required_vuln_classes: vec![
                VulnerabilityClass::PathTraversal,
                VulnerabilityClass::BrokenAuthorization,
                VulnerabilityClass::InsecureDirectObjectReference,
                VulnerabilityClass::MassAssignment,
            ],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::PciDss,
            requirement_id: "6.5.9".into(),
            description: "SSRF vulnerabilities".into(),
            required_vuln_classes: vec![VulnerabilityClass::ServerSideRequestForgery],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::PciDss,
            requirement_id: "6.5.10".into(),
            description: "Broken authentication".into(),
            required_vuln_classes: vec![
                VulnerabilityClass::BrokenAuthentication,
                VulnerabilityClass::JwtVulnerability,
            ],
        },
    ]
}

fn api_security_2023_requirements() -> Vec<ComplianceRequirement> {
    vec![
        ComplianceRequirement {
            framework: ComplianceFramework::ApiSecurity2023,
            requirement_id: "API1:2023".into(),
            description: "Broken Object Level Authorization".into(),
            required_vuln_classes: vec![VulnerabilityClass::InsecureDirectObjectReference],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::ApiSecurity2023,
            requirement_id: "API2:2023".into(),
            description: "Broken Authentication".into(),
            required_vuln_classes: vec![
                VulnerabilityClass::BrokenAuthentication,
                VulnerabilityClass::JwtVulnerability,
            ],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::ApiSecurity2023,
            requirement_id: "API3:2023".into(),
            description: "Broken Object Property Level Authorization".into(),
            required_vuln_classes: vec![VulnerabilityClass::MassAssignment],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::ApiSecurity2023,
            requirement_id: "API4:2023".into(),
            description: "Unrestricted Resource Consumption".into(),
            required_vuln_classes: vec![VulnerabilityClass::GraphQlAbuse],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::ApiSecurity2023,
            requirement_id: "API5:2023".into(),
            description: "Broken Function Level Authorization".into(),
            required_vuln_classes: vec![VulnerabilityClass::BrokenAuthorization],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::ApiSecurity2023,
            requirement_id: "API7:2023".into(),
            description: "Server-Side Request Forgery".into(),
            required_vuln_classes: vec![VulnerabilityClass::ServerSideRequestForgery],
        },
        ComplianceRequirement {
            framework: ComplianceFramework::ApiSecurity2023,
            requirement_id: "API8:2023".into(),
            description: "Security Misconfiguration".into(),
            required_vuln_classes: vec![
                VulnerabilityClass::SecurityMisconfiguration,
                VulnerabilityClass::MissingSecurityHeader,
                VulnerabilityClass::CrossOriginMisconfiguration,
                VulnerabilityClass::CloudMisconfiguration,
            ],
        },
    ]
}

/// Computes the CVSS-derived severity weight for prioritizing fuzz targets.
/// Higher-severity classes get higher priority scores.
fn severity_weight(vuln_class: VulnerabilityClass) -> f64 {
    use crate::class_mapper::default_cvss_for_class;
    use crate::cvss_scorer::compute_cvss;

    let metrics = default_cvss_for_class(vuln_class);
    compute_cvss(&metrics).score
}

/// Core analysis: given the current scan state, identify compliance gaps and
/// generate prioritized fuzz targets for untested requirements.
pub fn analyze_attack_surface(scan_state: &ScanState) -> AttackSurfaceAnalysis {
    let requirements = all_compliance_requirements();

    let endpoint_coverage = build_endpoint_coverage(scan_state);
    let all_tested: HashSet<VulnerabilityClass> = scan_state
        .findings
        .iter()
        .map(|f| f.vulnerability_class)
        .collect();

    let mut gaps = Vec::new();
    let mut coverage_entries = Vec::new();

    for req in &requirements {
        let tested_for_req: Vec<VulnerabilityClass> = req
            .required_vuln_classes
            .iter()
            .filter(|c| all_tested.contains(c))
            .copied()
            .collect();

        let untested_for_req: Vec<VulnerabilityClass> = req
            .required_vuln_classes
            .iter()
            .filter(|c| !all_tested.contains(c))
            .copied()
            .collect();

        let total = req.required_vuln_classes.len();
        let tested_count = tested_for_req.len();
        let coverage_pct = if total > 0 {
            (tested_count as f64) / (total as f64) * 100.0
        } else {
            100.0
        };

        coverage_entries.push(CoverageMatrixEntry {
            framework: req.framework,
            requirement_id: req.requirement_id.clone(),
            total_classes: total,
            tested_classes: tested_count,
            untested_classes: untested_for_req.len(),
            coverage_pct,
            tested_list: tested_for_req.clone(),
            untested_list: untested_for_req.clone(),
        });

        if untested_for_req.is_empty() {
            continue;
        }

        for ep in &endpoint_coverage {
            let ep_tested: Vec<VulnerabilityClass> = tested_for_req
                .iter()
                .filter(|c| ep.tested_classes.contains(c))
                .copied()
                .collect();

            let ep_untested: Vec<VulnerabilityClass> = untested_for_req.clone();

            let ep_coverage = if total > 0 {
                (ep_tested.len() as f64) / (total as f64)
            } else {
                1.0
            };

            let max_severity = ep_untested
                .iter()
                .map(|c| severity_weight(*c))
                .fold(0.0_f64, f64::max);

            let gap_count_factor = ep_untested.len() as f64;
            let priority = max_severity * 10.0 + gap_count_factor;

            gaps.push(ComplianceGap {
                requirement: req.clone(),
                endpoint: ep.endpoint.clone(),
                method: ep.method.clone(),
                tested_classes: ep_tested,
                untested_classes: ep_untested,
                coverage_ratio: ep_coverage,
                priority_score: priority,
            });
        }
    }

    gaps.sort_by(|a, b| {
        b.priority_score
            .partial_cmp(&a.priority_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let fuzz_targets = generate_fuzz_targets(&gaps, &endpoint_coverage);

    let fully_covered = coverage_entries
        .iter()
        .filter(|e| e.untested_classes == 0)
        .count();
    let partially_covered = coverage_entries
        .iter()
        .filter(|e| e.untested_classes > 0 && e.tested_classes > 0)
        .count();
    let uncovered = coverage_entries
        .iter()
        .filter(|e| e.tested_classes == 0 && e.total_classes > 0)
        .count();

    AttackSurfaceAnalysis {
        gaps,
        fuzz_targets,
        coverage_matrix: coverage_entries,
        total_requirements: requirements.len(),
        fully_covered_requirements: fully_covered,
        partially_covered_requirements: partially_covered,
        uncovered_requirements: uncovered,
    }
}

fn build_endpoint_coverage(scan_state: &ScanState) -> Vec<EndpointCoverage> {
    let mut ep_map: HashMap<(String, String), EndpointCoverage> = HashMap::new();

    for ep in &scan_state.known_endpoints {
        let key = (ep.endpoint.clone(), ep.method.clone());
        ep_map
            .entry(key)
            .or_insert_with(|| EndpointCoverage {
                endpoint: ep.endpoint.clone(),
                method: ep.method.clone(),
                tested_classes: HashSet::new(),
                parameters: ep.parameters.clone(),
            })
            .parameters
            .extend(ep.parameters.clone());
    }

    for finding in &scan_state.findings {
        let key = (finding.endpoint.clone(), finding.method.clone());
        let entry = ep_map.entry(key).or_insert_with(|| EndpointCoverage {
            endpoint: finding.endpoint.clone(),
            method: finding.method.clone(),
            tested_classes: HashSet::new(),
            parameters: Vec::new(),
        });
        entry.tested_classes.insert(finding.vulnerability_class);
        if let Some(ref p) = finding.parameter
            && !entry.parameters.contains(p)
        {
            entry.parameters.push(p.clone());
        }
    }

    let mut coverages: Vec<EndpointCoverage> = ep_map.into_values().collect();
    coverages.sort_by(|a, b| a.endpoint.cmp(&b.endpoint));

    for cov in &mut coverages {
        cov.parameters.sort();
        cov.parameters.dedup();
    }

    coverages
}

fn generate_fuzz_targets(
    gaps: &[ComplianceGap],
    endpoint_coverages: &[EndpointCoverage],
) -> Vec<GapFuzzTarget> {
    let mut seen: HashSet<(String, String, VulnerabilityClass)> = HashSet::new();
    let mut targets = Vec::new();

    for gap in gaps {
        let ep_cov = endpoint_coverages
            .iter()
            .find(|e| e.endpoint == gap.endpoint && e.method == gap.method);

        let default_param = "body".to_string();
        let first_param = ep_cov
            .and_then(|c| c.parameters.first())
            .unwrap_or(&default_param);

        for vuln_class in &gap.untested_classes {
            let dedup_key = (gap.endpoint.clone(), gap.method.clone(), *vuln_class);
            if !seen.insert(dedup_key) {
                continue;
            }

            let base_severity = severity_weight(*vuln_class);
            let compliance_boost = 1.0 + (1.0 - gap.coverage_ratio) * 0.5;
            let priority = base_severity * compliance_boost;

            targets.push(GapFuzzTarget {
                endpoint: gap.endpoint.clone(),
                method: gap.method.clone(),
                parameter: first_param.clone(),
                parameter_location: ParameterLocation::Query,
                vulnerability_class: *vuln_class,
                priority_score: priority,
                compliance_source: format!(
                    "{} {}",
                    gap.requirement.framework, gap.requirement.requirement_id
                ),
                attempts: 0,
                max_attempts: 5,
            });
        }
    }

    targets.sort_by(|a, b| {
        b.priority_score
            .partial_cmp(&a.priority_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    targets
}

/// Builds a formatted coverage matrix string for reporting.
pub fn format_coverage_matrix(analysis: &AttackSurfaceAnalysis) -> String {
    let mut out = String::from("## Compliance Coverage Matrix\n\n");
    out.push_str("| Framework | Requirement | Tested | Untested | Coverage |\n");
    out.push_str("|-----------|------------|--------|----------|----------|\n");

    for entry in &analysis.coverage_matrix {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {:.0}% |\n",
            entry.framework,
            entry.requirement_id,
            entry.tested_classes,
            entry.untested_classes,
            entry.coverage_pct,
        ));
    }

    out.push_str(&format!(
        "\n**Summary:** {} total requirements, {} fully covered, {} partially covered, {} uncovered\n",
        analysis.total_requirements,
        analysis.fully_covered_requirements,
        analysis.partially_covered_requirements,
        analysis.uncovered_requirements,
    ));

    out
}

/// Returns the coverage matrix grouped by framework.
pub fn coverage_by_framework(
    analysis: &AttackSurfaceAnalysis,
) -> BTreeMap<ComplianceFramework, Vec<&CoverageMatrixEntry>> {
    let mut grouped: BTreeMap<ComplianceFramework, Vec<&CoverageMatrixEntry>> = BTreeMap::new();
    for entry in &analysis.coverage_matrix {
        grouped.entry(entry.framework).or_default().push(entry);
    }
    grouped
}

/// Cross-validates our gap analysis against the existing compliance mapper.
/// Returns true if every VulnerabilityClass in our requirements actually maps
/// to the claimed framework in `map_to_compliance`.
pub fn validate_requirement_mappings() -> Vec<String> {
    let requirements = all_compliance_requirements();
    let mut warnings = Vec::new();

    for req in &requirements {
        for vuln_class in &req.required_vuln_classes {
            let mapping = map_to_compliance(*vuln_class);
            let ok = match req.framework {
                ComplianceFramework::OwaspTop10_2021 => mapping.owasp_2021.is_some(),
                ComplianceFramework::PciDss => mapping.pci_dss.is_some(),
                ComplianceFramework::ApiSecurity2023 => mapping.owasp_api_2023.is_some(),
            };
            if !ok {
                warnings.push(format!(
                    "{} {} claims {} requires testing for {}, but compliance_mapper has no mapping",
                    req.framework, req.requirement_id, req.description, vuln_class
                ));
            }
        }
    }

    warnings
}
