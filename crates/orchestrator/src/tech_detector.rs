use std::fmt;

use aegis_discovery::{DetectedTech, fingerprint_from_headers, fingerprint_from_html};
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::recon_client;
use crate::util::timestamp_ms;

#[derive(Debug, Clone)]
pub struct TechDetection {
    pub name: String,
    pub version: Option<String>,
    pub category: String,
    pub confidence: f64,
    pub evidence: String,
}

pub fn detect_technologies(target: &str) -> Vec<TechDetection> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body = resp.text().unwrap_or_default();

    detect_from_parts(&headers, &body)
}

pub fn detect_from_parts(headers: &[(String, String)], body: &str) -> Vec<TechDetection> {
    let mut detections: Vec<DetectedTech> = fingerprint_from_headers(headers);
    detections.extend(fingerprint_from_html(body));
    dedup_detections(&detections)
}

pub fn dedup_detections(detections: &[DetectedTech]) -> Vec<TechDetection> {
    let mut seen = std::collections::HashSet::new();
    detections
        .iter()
        .filter(|d| seen.insert(d.name.clone()))
        .map(|d| TechDetection {
            name: d.name.clone(),
            version: d.version.clone(),
            category: d.category.to_string(),
            confidence: d.confidence,
            evidence: d.evidence.clone(),
        })
        .collect()
}

pub fn tech_to_operations(detections: &[TechDetection], seq: &mut u64) -> Vec<OperationLogEntry> {
    detections
        .iter()
        .map(|d| {
            *seq += 1;
            let mut props = vec![
                ("name".to_string(), d.name.clone()),
                ("category".to_string(), d.category.clone()),
                ("confidence".to_string(), format!("{:.2}", d.confidence)),
                ("evidence".to_string(), d.evidence.clone()),
                ("source".to_string(), "tech_detect".to_string()),
            ];
            if let Some(v) = &d.version {
                props.push(("version".to_string(), v.clone()));
            }
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Service,
                    properties: props,
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum TechIssue {
    OutdatedVersion {
        name: String,
        version: String,
        category: String,
    },
    EndOfLife {
        name: String,
        version: String,
    },
    KnownVulnerable {
        name: String,
        version: String,
    },
    DefaultConfig {
        name: String,
        evidence: String,
    },
    DebugMode {
        name: String,
        evidence: String,
    },
    MixedTechStack {
        technologies: Vec<String>,
    },
    VersionExposed {
        name: String,
        version: String,
    },
    LegacyProtocol {
        name: String,
        evidence: String,
    },
}

impl fmt::Display for TechIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TechIssue::OutdatedVersion {
                name,
                version,
                category,
            } => write!(f, "Outdated {category} {name} version {version}"),
            TechIssue::EndOfLife { name, version } => {
                write!(f, "{name} {version} has reached end of life")
            }
            TechIssue::KnownVulnerable { name, version } => {
                write!(f, "{name} {version} has known vulnerabilities")
            }
            TechIssue::DefaultConfig { name, evidence } => {
                write!(f, "Default configuration detected for {name}: {evidence}")
            }
            TechIssue::DebugMode { name, evidence } => {
                write!(f, "Debug mode enabled for {name}: {evidence}")
            }
            TechIssue::MixedTechStack { technologies } => {
                write!(
                    f,
                    "Conflicting technologies detected: {}",
                    technologies.join(", ")
                )
            }
            TechIssue::VersionExposed { name, version } => {
                write!(f, "Exact version exposed: {name}/{version}")
            }
            TechIssue::LegacyProtocol { name, evidence } => {
                write!(f, "Legacy technology {name} detected: {evidence}")
            }
        }
    }
}

pub fn tech_issue_severity(issue: &TechIssue) -> f64 {
    match issue {
        TechIssue::KnownVulnerable { .. } => 8.0,
        TechIssue::EndOfLife { .. } => 7.0,
        TechIssue::DebugMode { .. } => 6.0,
        TechIssue::DefaultConfig { .. } => 5.0,
        TechIssue::OutdatedVersion { .. } => 4.0,
        TechIssue::LegacyProtocol { .. } => 4.0,
        TechIssue::MixedTechStack { .. } => 3.0,
        TechIssue::VersionExposed { .. } => 3.0,
    }
}

const OUTDATED_THRESHOLDS: &[(&str, &str)] = &[
    ("nginx", "1.24"),
    ("Apache", "2.4"),
    ("OpenSSL", "3.0"),
    ("PHP", "8.1"),
    ("Node.js", "18.0"),
    ("jQuery", "3.6"),
    ("Bootstrap", "5.2"),
    ("Express", "4.18"),
    ("Django", "4.2"),
    ("Rails", "7.0"),
    ("WordPress", "6.3"),
    ("React", "18.0"),
    ("Angular", "16.0"),
    ("Vue.js", "3.3"),
];

const EOL_VERSIONS: &[(&str, &str)] = &[
    ("PHP", "5."),
    ("PHP", "7."),
    ("Python", "2."),
    ("Node.js", "12."),
    ("Node.js", "14."),
    ("Node.js", "16."),
    ("jQuery", "1."),
    ("Angular", "1."),
    ("AngularJS", "1."),
    ("Rails", "5."),
    ("Django", "2."),
    ("Bootstrap", "3."),
    ("WordPress", "4."),
    ("OpenSSL", "1.0"),
    ("OpenSSL", "1.1"),
];

const KNOWN_VULNERABLE: &[(&str, &str)] = &[
    ("Apache", "2.4.49"),
    ("Apache", "2.4.50"),
    ("OpenSSL", "3.0.0"),
    ("OpenSSL", "3.0.1"),
    ("Log4j", "2.14"),
    ("Log4j", "2.15"),
    ("jQuery", "1.6."),
    ("jQuery", "1.7."),
    ("jQuery", "1.8."),
    ("jQuery", "1.9."),
    ("jQuery", "2.0."),
    ("jQuery", "2.1."),
    ("jQuery", "3.0."),
    ("Spring", "5.3.0"),
    ("WordPress", "5.0.0"),
];

const DEBUG_INDICATORS: &[&str] = &[
    "X-Debug-Token",
    "X-Debug-Token-Link",
    "X-Debug",
    "debug=true",
    "XDEBUG_SESSION",
    "Werkzeug",
    "Django Debug",
    "stack trace",
    "X-Powered-By: Express",
];

const DEFAULT_CONFIG_INDICATORS: &[&str] = &[
    "Welcome to nginx",
    "Apache2 Ubuntu Default Page",
    "Apache2 Debian Default Page",
    "IIS Windows Server",
    "It works!",
    "Test Page for the Apache HTTP Server",
    "Congratulations",
    "default web site",
    "phpinfo()",
    "MAMP",
    "XAMPP",
];

const LEGACY_TECHNOLOGIES: &[&str] = &[
    "FrontPage",
    "Dreamweaver",
    "Flash",
    "Silverlight",
    "ActiveX",
    "COBOL",
    "ColdFusion",
    "Classic ASP",
    "Perl",
    "CGI-BIN",
];

const WEB_SERVER_CATEGORY: &str = "Web Server";

pub fn analyze_tech_stack(detections: &[TechDetection]) -> Vec<TechIssue> {
    let mut issues = Vec::new();

    for d in detections {
        if let Some(version) = &d.version {
            // Version exposed
            issues.push(TechIssue::VersionExposed {
                name: d.name.clone(),
                version: version.clone(),
            });

            // Known vulnerable
            for &(name, vuln_prefix) in KNOWN_VULNERABLE {
                if d.name.eq_ignore_ascii_case(name) && version.starts_with(vuln_prefix) {
                    issues.push(TechIssue::KnownVulnerable {
                        name: d.name.clone(),
                        version: version.clone(),
                    });
                    break;
                }
            }

            // End of life
            for &(name, eol_prefix) in EOL_VERSIONS {
                if d.name.eq_ignore_ascii_case(name) && version.starts_with(eol_prefix) {
                    issues.push(TechIssue::EndOfLife {
                        name: d.name.clone(),
                        version: version.clone(),
                    });
                    break;
                }
            }

            // Outdated version
            for &(name, min_version) in OUTDATED_THRESHOLDS {
                if d.name.eq_ignore_ascii_case(name) && version_less_than(version, min_version) {
                    issues.push(TechIssue::OutdatedVersion {
                        name: d.name.clone(),
                        version: version.clone(),
                        category: d.category.clone(),
                    });
                    break;
                }
            }
        }

        // Debug mode
        for indicator in DEBUG_INDICATORS {
            if d.evidence.contains(indicator) {
                issues.push(TechIssue::DebugMode {
                    name: d.name.clone(),
                    evidence: d.evidence.clone(),
                });
                break;
            }
        }

        // Default config
        for indicator in DEFAULT_CONFIG_INDICATORS {
            if d.evidence.contains(indicator) {
                issues.push(TechIssue::DefaultConfig {
                    name: d.name.clone(),
                    evidence: d.evidence.clone(),
                });
                break;
            }
        }

        // Legacy
        for legacy in LEGACY_TECHNOLOGIES {
            if d.name.eq_ignore_ascii_case(legacy) {
                issues.push(TechIssue::LegacyProtocol {
                    name: d.name.clone(),
                    evidence: d.evidence.clone(),
                });
                break;
            }
        }
    }

    // Mixed tech stack: multiple web servers
    let web_servers: Vec<String> = detections
        .iter()
        .filter(|d| d.category.eq_ignore_ascii_case(WEB_SERVER_CATEGORY))
        .map(|d| d.name.clone())
        .collect();
    if web_servers.len() > 1 {
        issues.push(TechIssue::MixedTechStack {
            technologies: web_servers,
        });
    }

    issues
}

fn version_less_than(actual: &str, threshold: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split('.')
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let a = parse(actual);
    let t = parse(threshold);
    for i in 0..a.len().max(t.len()) {
        let av = a.get(i).copied().unwrap_or(0);
        let tv = t.get(i).copied().unwrap_or(0);
        if av < tv {
            return true;
        }
        if av > tv {
            return false;
        }
    }
    false
}

pub fn tech_issues_to_operations(issues: &[TechIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            let severity = tech_issue_severity(issue);
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                severity,
                0.5,
            )
        })
        .collect()
}
