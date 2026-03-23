use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ImportMapIssue {
    ApiDetected,
    ExternalSpecifier,
    PrototypePollution,
    DependencyHijacking,
    ScopeEscalation,
}

impl std::fmt::Display for ImportMapIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::ExternalSpecifier => write!(f, "external_specifier"),
            Self::PrototypePollution => write!(f, "prototype_pollution"),
            Self::DependencyHijacking => write!(f, "dependency_hijacking"),
            Self::ScopeEscalation => write!(f, "scope_escalation"),
        }
    }
}

pub fn audit_import_map(target: &str) -> Vec<ImportMapIssue> {
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
    analyze_import_map(&body)
}

pub fn analyze_import_map(body: &str) -> Vec<ImportMapIssue> {
    if !body.contains("importmap") && !body.contains("import map") {
        return Vec::new();
    }

    let has_importmap = body.contains("type=\"importmap\"") || body.contains("type='importmap'");
    let has_imports = body.contains("\"imports\"") || body.contains("'imports'");

    if !has_importmap && !has_imports {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(ImportMapIssue::ApiDetected);

    if has_imports && (body.contains("http://") || body.contains("https://")) {
        issues.push(ImportMapIssue::ExternalSpecifier);
    }

    if has_imports
        && (body.contains("__proto__")
            || body.contains("constructor")
            || body.contains("prototype"))
    {
        issues.push(ImportMapIssue::PrototypePollution);
    }

    if has_imports
        && (body.contains("lodash") || body.contains("jquery") || body.contains("react"))
        && body.contains("http")
    {
        issues.push(ImportMapIssue::DependencyHijacking);
    }

    if body.contains("\"scopes\"") || body.contains("'scopes'") {
        let scope_count = body.matches("\"scopes\"").count() + body.matches("'scopes'").count();
        if scope_count > 0 && body.contains("../") {
            issues.push(ImportMapIssue::ScopeEscalation);
        }
    }

    issues
}

pub fn import_map_severity(issue: &ImportMapIssue) -> f64 {
    match issue {
        ImportMapIssue::DependencyHijacking => 8.0,
        ImportMapIssue::PrototypePollution => 7.0,
        ImportMapIssue::ScopeEscalation => 6.5,
        ImportMapIssue::ExternalSpecifier => 5.0,
        ImportMapIssue::ApiDetected => 2.0,
    }
}

pub fn import_map_to_operations(
    issues: &[ImportMapIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                import_map_severity(issue),
                0.55,
            )
        })
        .collect()
}
