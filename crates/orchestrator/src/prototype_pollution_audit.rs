use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum PrototypePollutionIssue {
    ProtoReflected { vector: String },
    ConstructorReflected { vector: String },
}

impl std::fmt::Display for PrototypePollutionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProtoReflected { vector } => write!(f, "proto_reflected:{vector}"),
            Self::ConstructorReflected { vector } => write!(f, "constructor_reflected:{vector}"),
        }
    }
}

const CANARY_KEY: &str = "aegispptest";
const CANARY_VALUE: &str = "polluted42";

const POLLUTION_VECTORS: &[(&str, &str)] = &[
    ("__proto__[CANARY]=VALUE", "proto_bracket"),
    ("__proto__.CANARY=VALUE", "proto_dot"),
    ("constructor[prototype][CANARY]=VALUE", "constructor_bracket"),
    ("constructor.prototype.CANARY=VALUE", "constructor_dot"),
];

pub fn audit_prototype_pollution(target: &str) -> Vec<PrototypePollutionIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let base = target.trim_end_matches('/');
    let mut issues = Vec::new();

    for (template, vector_name) in POLLUTION_VECTORS {
        let param = template
            .replace("CANARY", CANARY_KEY)
            .replace("VALUE", CANARY_VALUE);
        let separator = if base.contains('?') { '&' } else { '?' };
        let url = format!("{base}{separator}{param}");

        if let Ok(resp) = client.get(&url).send()
            && let Ok(body) = resp.text()
            && body.contains(CANARY_KEY)
            && body.contains(CANARY_VALUE)
        {
            let issue = if vector_name.starts_with("proto") {
                PrototypePollutionIssue::ProtoReflected {
                    vector: vector_name.to_string(),
                }
            } else {
                PrototypePollutionIssue::ConstructorReflected {
                    vector: vector_name.to_string(),
                }
            };
            issues.push(issue);
        }
    }

    issues
}

#[cfg(test)]
pub(crate) fn analyze_pollution_response(
    body: &str,
    vector_name: &str,
) -> Option<PrototypePollutionIssue> {
    if body.contains(CANARY_KEY) && body.contains(CANARY_VALUE) {
        if vector_name.starts_with("proto") {
            Some(PrototypePollutionIssue::ProtoReflected {
                vector: vector_name.to_string(),
            })
        } else {
            Some(PrototypePollutionIssue::ConstructorReflected {
                vector: vector_name.to_string(),
            })
        }
    } else {
        None
    }
}

pub(crate) fn pollution_severity(issue: &PrototypePollutionIssue) -> f64 {
    match issue {
        PrototypePollutionIssue::ProtoReflected { .. } => 7.5,
        PrototypePollutionIssue::ConstructorReflected { .. } => 7.0,
    }
}

pub fn pollution_to_operations(
    issues: &[PrototypePollutionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::PrototypePollution,
                pollution_severity(issue),
                0.8,
            )
        })
        .collect()
}
