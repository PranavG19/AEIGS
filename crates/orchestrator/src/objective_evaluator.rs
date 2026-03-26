/// Objective evaluator: determine if the kill chain objective has been achieved.
///
/// Parses objective strings into structured checks and evaluates current state
/// against them. Supports domain admin, database access, file read, credential
/// targets, and network access objectives. Provides partial credit scoring.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Parsed objective type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectiveType {
    DomainAdmin,
    DatabaseAccess,
    FileRead(String),
    CredentialTarget(String),
    NetworkAccess(String),
    Custom(String),
}

/// Evidence collected during kill chain execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedEvidence {
    pub credentials: Vec<EvalCredential>,
    pub file_reads: Vec<String>,
    pub db_connections: Vec<String>,
    pub network_hosts: Vec<String>,
    pub access_level: String,
    pub custom_flags: HashMap<String, bool>,
}

impl Default for CollectedEvidence {
    fn default() -> Self {
        Self {
            credentials: Vec::new(),
            file_reads: Vec::new(),
            db_connections: Vec::new(),
            network_hosts: Vec::new(),
            access_level: "none".to_string(),
            custom_flags: HashMap::new(),
        }
    }
}

/// A credential for objective evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalCredential {
    pub username: String,
    pub credential_type: String,
    pub access_level: String,
    pub groups: Vec<String>,
    pub target_host: Option<String>,
}

/// Result of objective evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectiveResult {
    pub achieved: bool,
    pub objective_type: ObjectiveType,
    pub evidence: Vec<String>,
    pub partial_progress: Vec<PartialProgress>,
    pub impact_pct: f64,
    pub summary: String,
}

/// Partial progress toward an unachieved objective.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialProgress {
    pub description: String,
    pub contribution_pct: f64,
}

/// Parse an objective string into a structured type.
pub fn parse_objective_type(objective: &str) -> ObjectiveType {
    let lower = objective.to_lowercase().trim().to_string();

    if lower.contains("domain admin") || lower == "da" || lower.contains("da access") {
        ObjectiveType::DomainAdmin
    } else if lower.contains("database")
        || lower.contains("db access")
        || lower.contains("db connection")
    {
        ObjectiveType::DatabaseAccess
    } else if lower.starts_with("file:") {
        let path = objective
            .trim_start_matches("file:")
            .trim_start_matches("FILE:")
            .trim()
            .to_string();
        ObjectiveType::FileRead(path)
    } else if lower.starts_with("credential:") {
        let user = objective
            .trim_start_matches("credential:")
            .trim_start_matches("CREDENTIAL:")
            .trim()
            .to_string();
        ObjectiveType::CredentialTarget(user)
    } else if lower.starts_with("network:") {
        let cidr = objective
            .trim_start_matches("network:")
            .trim_start_matches("NETWORK:")
            .trim()
            .to_string();
        ObjectiveType::NetworkAccess(cidr)
    } else {
        ObjectiveType::Custom(objective.to_string())
    }
}

/// Evaluate objective achievement given collected evidence.
pub fn evaluate_objective(objective: &str, evidence: &CollectedEvidence) -> ObjectiveResult {
    let obj_type = parse_objective_type(objective);
    match obj_type {
        ObjectiveType::DomainAdmin => evaluate_domain_admin(evidence),
        ObjectiveType::DatabaseAccess => evaluate_database_access(evidence),
        ObjectiveType::FileRead(ref path) => evaluate_file_read(path, evidence),
        ObjectiveType::CredentialTarget(ref user) => evaluate_credential_target(user, evidence),
        ObjectiveType::NetworkAccess(ref cidr) => evaluate_network_access(cidr, evidence),
        ObjectiveType::Custom(ref desc) => evaluate_custom(desc, evidence),
    }
}

fn evaluate_domain_admin(evidence: &CollectedEvidence) -> ObjectiveResult {
    let da_cred = evidence.credentials.iter().find(|c| {
        c.groups
            .iter()
            .any(|g| g.to_lowercase().contains("domain admin"))
            || c.access_level.to_lowercase().contains("domain admin")
    });

    let access_is_da = evidence
        .access_level
        .to_lowercase()
        .contains("domain admin")
        || evidence.access_level.to_lowercase() == "root";

    let achieved = da_cred.is_some() || access_is_da;

    let mut evidence_list = Vec::new();
    let mut partial = Vec::new();

    if let Some(cred) = da_cred {
        evidence_list.push(format!(
            "Credential for '{}' with Domain Admin access obtained",
            cred.username
        ));
    }
    if access_is_da {
        evidence_list.push(format!(
            "Current access level is '{}'",
            evidence.access_level
        ));
    }

    let impact_pct = if achieved {
        100.0
    } else {
        let mut pct = 0.0;

        if !evidence.credentials.is_empty() {
            let max_access = evidence
                .credentials
                .iter()
                .map(|c| access_level_rank(&c.access_level))
                .max()
                .unwrap_or(0);
            let cred_pct = (max_access as f64 / 5.0) * 50.0;
            pct += cred_pct;
            partial.push(PartialProgress {
                description: format!(
                    "{} credential(s) obtained, highest access: level {}",
                    evidence.credentials.len(),
                    max_access
                ),
                contribution_pct: cred_pct,
            });
        }

        let current_rank = access_level_rank(&evidence.access_level);
        if current_rank > 0 {
            let access_pct = (current_rank as f64 / 5.0) * 40.0;
            pct += access_pct;
            partial.push(PartialProgress {
                description: format!("Current access level: '{}'", evidence.access_level),
                contribution_pct: access_pct,
            });
        }

        if !evidence.network_hosts.is_empty() {
            let host_pct = (evidence.network_hosts.len() as f64 * 2.0).min(10.0);
            pct += host_pct;
            partial.push(PartialProgress {
                description: format!("{} host(s) compromised", evidence.network_hosts.len()),
                contribution_pct: host_pct,
            });
        }

        pct.min(99.0)
    };

    let summary = if achieved {
        "Domain Admin objective achieved.".to_string()
    } else {
        format!(
            "Domain Admin not yet achieved ({:.0}% progress). {}",
            impact_pct,
            partial
                .iter()
                .map(|p| p.description.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        )
    };

    ObjectiveResult {
        achieved,
        objective_type: ObjectiveType::DomainAdmin,
        evidence: evidence_list,
        partial_progress: partial,
        impact_pct,
        summary,
    }
}

fn evaluate_database_access(evidence: &CollectedEvidence) -> ObjectiveResult {
    let achieved = !evidence.db_connections.is_empty();

    let evidence_list: Vec<String> = evidence
        .db_connections
        .iter()
        .map(|db| format!("Database connection established: {db}"))
        .collect();

    let mut partial = Vec::new();
    let impact_pct = if achieved {
        100.0
    } else {
        let mut pct = 0.0;
        let has_sql_cred = evidence
            .credentials
            .iter()
            .any(|c| c.credential_type.contains("database") || c.credential_type.contains("sql"));
        if has_sql_cred {
            pct += 60.0;
            partial.push(PartialProgress {
                description: "Database credentials obtained but connection not yet verified"
                    .to_string(),
                contribution_pct: 60.0,
            });
        }
        pct
    };

    let summary = if achieved {
        format!(
            "Database access achieved via {} connection(s).",
            evidence.db_connections.len()
        )
    } else {
        format!("Database access not yet achieved ({impact_pct:.0}% progress).")
    };

    ObjectiveResult {
        achieved,
        objective_type: ObjectiveType::DatabaseAccess,
        evidence: evidence_list,
        partial_progress: partial,
        impact_pct,
        summary,
    }
}

fn evaluate_file_read(path: &str, evidence: &CollectedEvidence) -> ObjectiveResult {
    let achieved = evidence.file_reads.iter().any(|f| f.contains(path));

    let evidence_list = if achieved {
        vec![format!("File '{path}' successfully read")]
    } else {
        vec![]
    };

    let mut partial = Vec::new();
    let impact_pct = if achieved {
        100.0
    } else {
        let related = evidence
            .file_reads
            .iter()
            .filter(|f| {
                let dir = path.rsplit('/').nth(1).unwrap_or("");
                !dir.is_empty() && f.contains(dir)
            })
            .count();
        let pct = (related as f64 * 20.0).min(80.0);
        if related > 0 {
            partial.push(PartialProgress {
                description: format!("{related} related file(s) read from same directory"),
                contribution_pct: pct,
            });
        }
        pct
    };

    let summary = if achieved {
        format!("File read objective achieved: '{path}'.")
    } else {
        format!("File '{path}' not yet read ({impact_pct:.0}% progress).")
    };

    ObjectiveResult {
        achieved,
        objective_type: ObjectiveType::FileRead(path.to_string()),
        evidence: evidence_list,
        partial_progress: partial,
        impact_pct,
        summary,
    }
}

fn evaluate_credential_target(user: &str, evidence: &CollectedEvidence) -> ObjectiveResult {
    let achieved = evidence
        .credentials
        .iter()
        .any(|c| c.username.to_lowercase() == user.to_lowercase());

    let evidence_list = if achieved {
        vec![format!("Credential for user '{user}' obtained")]
    } else {
        vec![]
    };

    let mut partial = Vec::new();
    let impact_pct = if achieved {
        100.0
    } else {
        if !evidence.credentials.is_empty() {
            let pct = 40.0;
            partial.push(PartialProgress {
                description: format!(
                    "{} other credential(s) obtained but not target user '{user}'",
                    evidence.credentials.len()
                ),
                contribution_pct: pct,
            });
            pct
        } else {
            0.0
        }
    };

    let summary = if achieved {
        format!("Credential objective achieved for user '{user}'.")
    } else {
        format!("Credential for '{user}' not yet obtained ({impact_pct:.0}% progress).")
    };

    ObjectiveResult {
        achieved,
        objective_type: ObjectiveType::CredentialTarget(user.to_string()),
        evidence: evidence_list,
        partial_progress: partial,
        impact_pct,
        summary,
    }
}

fn evaluate_network_access(cidr: &str, evidence: &CollectedEvidence) -> ObjectiveResult {
    let prefix = extract_network_prefix(cidr);
    let matching: Vec<&String> = evidence
        .network_hosts
        .iter()
        .filter(|h| h.starts_with(&prefix))
        .collect();

    let min_hosts = 4;
    let achieved = matching.len() >= min_hosts;

    let evidence_list: Vec<String> = matching
        .iter()
        .map(|h| format!("Host {h} in network {cidr} compromised"))
        .collect();

    let impact_pct = ((matching.len() as f64 / min_hosts as f64) * 100.0).min(100.0);

    let mut partial = Vec::new();
    if !achieved && !matching.is_empty() {
        partial.push(PartialProgress {
            description: format!(
                "{}/{} required hosts in {} compromised",
                matching.len(),
                min_hosts,
                cidr
            ),
            contribution_pct: impact_pct,
        });
    }

    let summary = if achieved {
        format!(
            "Network access objective achieved: {} hosts in {cidr}.",
            matching.len()
        )
    } else {
        format!(
            "Network access {cidr}: {}/{min_hosts} hosts ({impact_pct:.0}% progress).",
            matching.len()
        )
    };

    ObjectiveResult {
        achieved,
        objective_type: ObjectiveType::NetworkAccess(cidr.to_string()),
        evidence: evidence_list,
        partial_progress: partial,
        impact_pct,
        summary,
    }
}

fn evaluate_custom(desc: &str, evidence: &CollectedEvidence) -> ObjectiveResult {
    let achieved = evidence.custom_flags.get(desc).copied().unwrap_or(false);

    let impact_pct = if achieved { 100.0 } else { 0.0 };

    ObjectiveResult {
        achieved,
        objective_type: ObjectiveType::Custom(desc.to_string()),
        evidence: if achieved {
            vec![format!("Custom objective '{desc}' flagged as achieved")]
        } else {
            vec![]
        },
        partial_progress: vec![],
        impact_pct,
        summary: if achieved {
            format!("Custom objective '{desc}' achieved.")
        } else {
            format!("Custom objective '{desc}' not yet achieved.")
        },
    }
}

fn access_level_rank(level: &str) -> u32 {
    let lower = level.to_lowercase();
    if lower.contains("root") || lower.contains("domain admin") {
        5
    } else if lower.contains("local admin") {
        4
    } else if lower.contains("privileged") {
        3
    } else if lower.contains("authenticated") {
        2
    } else if lower.contains("anonymous") {
        1
    } else {
        0
    }
}

fn extract_network_prefix(cidr: &str) -> String {
    let parts: Vec<&str> = cidr.split('/').collect();
    let ip = parts.first().unwrap_or(&"");
    let octets: Vec<&str> = ip.split('.').collect();
    if let Some(mask) = parts.get(1).and_then(|m| m.parse::<u32>().ok()) {
        let prefix_octets = (mask / 8) as usize;
        let kept: Vec<&str> = octets.iter().take(prefix_octets).copied().collect();
        if kept.is_empty() {
            String::new()
        } else {
            format!("{}.", kept.join("."))
        }
    } else {
        format!("{ip}.")
    }
}

/// Evaluate multiple objectives and return all results.
pub fn evaluate_all(objectives: &[String], evidence: &CollectedEvidence) -> Vec<ObjectiveResult> {
    objectives
        .iter()
        .map(|obj| evaluate_objective(obj, evidence))
        .collect()
}
