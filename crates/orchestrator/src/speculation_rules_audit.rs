use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum SpeculationRulesIssue {
    ApiDetected,
    ExternalPrefetch,
    AggressivePrerender,
    TrackingViaPrefetch,
    WildcardRules,
}

impl std::fmt::Display for SpeculationRulesIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::ExternalPrefetch => write!(f, "external_prefetch"),
            Self::AggressivePrerender => write!(f, "aggressive_prerender"),
            Self::TrackingViaPrefetch => write!(f, "tracking_via_prefetch"),
            Self::WildcardRules => write!(f, "wildcard_rules"),
        }
    }
}

pub fn audit_speculation_rules(target: &str) -> Vec<SpeculationRulesIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_speculation_rules(&body)
}

pub fn analyze_speculation_rules(body: &str) -> Vec<SpeculationRulesIssue> {
    if !body.contains("speculationrules") {
        return Vec::new();
    }

    let has_spec = body.contains("type=\"speculationrules\"")
        || body.contains("type='speculationrules'");

    if !has_spec {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(SpeculationRulesIssue::ApiDetected);

    if body.contains("\"prefetch\"")
        && (body.contains("http://") || body.contains("https://"))
    {
        let has_external = body.contains("://") && !body.contains("localhost");
        if has_external {
            issues.push(SpeculationRulesIssue::ExternalPrefetch);
        }
    }

    if body.contains("\"prerender\"") && body.contains("\"eagerness\"") && body.contains("\"eager\"")
    {
        issues.push(SpeculationRulesIssue::AggressivePrerender);
    }

    if (body.contains("\"prefetch\"") || body.contains("\"prerender\""))
        && (body.contains("utm_") || body.contains("tracking") || body.contains("analytics") || body.contains("pixel"))
    {
        issues.push(SpeculationRulesIssue::TrackingViaPrefetch);
    }

    if body.contains("\"where\"")
        && (body.contains("\"href_matches\"") || body.contains("\"selector_matches\""))
        && body.contains("\"*\"")
    {
        issues.push(SpeculationRulesIssue::WildcardRules);
    }

    issues
}

pub fn speculation_rules_severity(issue: &SpeculationRulesIssue) -> f64 {
    match issue {
        SpeculationRulesIssue::ExternalPrefetch => 6.5,
        SpeculationRulesIssue::TrackingViaPrefetch => 6.0,
        SpeculationRulesIssue::AggressivePrerender => 5.5,
        SpeculationRulesIssue::WildcardRules => 5.0,
        SpeculationRulesIssue::ApiDetected => 2.0,
    }
}

pub fn speculation_rules_to_operations(
    issues: &[SpeculationRulesIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                speculation_rules_severity(issue),
                0.5,
            )
        })
        .collect()
}
