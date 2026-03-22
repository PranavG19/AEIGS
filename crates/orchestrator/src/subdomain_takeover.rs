use std::process::Command;

use aegis_protocol::finding::{Confidence, VulnerabilityClass};
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

const TAKEOVER_FINGERPRINTS: &[(&str, &str)] = &[
    ("github.io", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "no-such-app"),
    ("herokudns.com", "no-such-app"),
    ("s3.amazonaws.com", "NoSuchBucket"),
    ("cloudfront.net", "Bad request"),
    ("azurewebsites.net", "not found"),
    ("trafficmanager.net", "not found"),
    ("pantheonsite.io", "404"),
    ("readme.io", "Project doesnt exist"),
    ("surge.sh", "project not found"),
    ("bitbucket.io", "Repository not found"),
    ("ghost.io", "404"),
    ("netlify.app", "Not Found"),
    ("fly.dev", "404 Not Found"),
];

#[derive(Debug, Clone)]
pub struct TakeoverCandidate {
    pub subdomain: String,
    pub cname: String,
    pub service: String,
}

pub fn check_subdomain_takeover(subdomains: &[String]) -> Vec<TakeoverCandidate> {
    subdomains
        .iter()
        .filter_map(|sub| check_single_subdomain(sub))
        .collect()
}

fn check_single_subdomain(subdomain: &str) -> Option<TakeoverCandidate> {
    let cname = resolve_cname(subdomain)?;
    let (service, _fingerprint) = TAKEOVER_FINGERPRINTS
        .iter()
        .find(|(pattern, _)| cname.contains(pattern))?;
    Some(TakeoverCandidate {
        subdomain: subdomain.to_string(),
        cname: cname.clone(),
        service: service.to_string(),
    })
}

pub(crate) fn resolve_cname(domain: &str) -> Option<String> {
    let output = Command::new("dig")
        .args(["+short", "+time=3", "+tries=1", domain, "CNAME"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let cname = stdout.lines().next()?.trim().trim_end_matches('.');
    if cname.is_empty() {
        None
    } else {
        Some(cname.to_string())
    }
}

pub fn takeover_findings_to_operations(
    candidates: &[TakeoverCandidate],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    candidates
        .iter()
        .map(|_c| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class: VulnerabilityClass::SecurityMisconfiguration,
                    severity: 8.0,
                    confidence: Confidence::new(0.7).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
