use aegis_protocol::finding::VulnerabilityClass;
use sarif_rust::types::result::{Fix, Suppression};
use sarif_rust::types::{
    ArtifactLocation, Level, Location, LogicalLocation, Message, MultiformatMessage,
    PhysicalLocation, ReportingConfiguration, ReportingDescriptor, ReportingDescriptorReference,
    Run, SarifLog, Tool, ToolComponent, ToolComponentReference,
};
use std::collections::{HashMap, HashSet};

/// Defense context annotations embedded in SARIF result properties.
#[derive(Debug, Clone, Default)]
pub struct SarifDefenseContext {
    pub waf_vendor: Option<String>,
    pub exploitable_despite_waf: bool,
    pub evasion_technique: Option<String>,
    pub defenses_detected: Vec<String>,
    pub evasion_success_rate: Option<f64>,
    pub stealth_mode_used: bool,
}

/// A vulnerability finding prepared for SARIF 2.1.0 emission.
///
/// Contains rule metadata, location, severity/confidence scores, defense context,
/// optional CWE/ATT&CK/CVE references, and suppression annotations.
pub struct SarifFinding {
    pub rule_id: String,
    pub rule_description: String,
    pub level: SarifLevel,
    pub message: String,
    pub uri: Option<String>,
    pub logical_location_name: Option<String>,
    pub logical_location_kind: Option<String>,
    pub severity: f64,
    pub confidence: f64,
    pub composite_score: f64,
    pub vulnerability_class: Option<VulnerabilityClass>,
    pub related_locations: Vec<RelatedLocation>,
    pub defense_context: Option<SarifDefenseContext>,
    pub evidence_level: Option<String>,
    pub cve_id: Option<String>,
    pub mitigation_rank: Option<u32>,
    /// When set, the SARIF result is annotated with a suppression of this kind.
    /// Use `"inSource"` for known issues accepted as risk.
    pub suppression_kind: Option<String>,
    /// Human-readable justification for the suppression (e.g. `"known-issue"`).
    pub suppression_message: Option<String>,
    pub endpoint: Option<String>,
    pub http_method: Option<String>,
    pub parameter_name: Option<String>,
}

/// An additional location related to a SARIF finding.
pub struct RelatedLocation {
    pub uri: Option<String>,
    pub message: String,
}

/// SARIF result severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SarifLevel {
    Error,
    Warning,
    Note,
    None,
}

impl SarifLevel {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Note => "note",
            Self::None => "none",
        }
    }

    fn to_sarif_level(self) -> Level {
        match self {
            Self::Error => Level::Error,
            Self::Warning => Level::Warning,
            Self::Note => Level::Note,
            Self::None => Level::None,
        }
    }
}

pub fn cwe_for(class: &VulnerabilityClass) -> &'static str {
    match class {
        VulnerabilityClass::SqlInjection => "CWE-89",
        VulnerabilityClass::CrossSiteScripting => "CWE-79",
        VulnerabilityClass::CommandInjection => "CWE-78",
        VulnerabilityClass::PathTraversal => "CWE-22",
        VulnerabilityClass::ServerSideRequestForgery => "CWE-918",
        VulnerabilityClass::InsecureDeserialization => "CWE-502",
        VulnerabilityClass::BrokenAuthentication => "CWE-287",
        VulnerabilityClass::BrokenAuthorization => "CWE-863",
        VulnerabilityClass::SecurityMisconfiguration => "CWE-16",
        VulnerabilityClass::SensitiveDataExposure => "CWE-200",
        VulnerabilityClass::ServerSideTemplateInjection => "CWE-1336",
        VulnerabilityClass::HeaderInjection => "CWE-113",
        VulnerabilityClass::OpenRedirect => "CWE-601",
        VulnerabilityClass::CrlfInjection => "CWE-93",
        VulnerabilityClass::KnownVulnerableDependency => "CWE-1395",
        VulnerabilityClass::InsufficientInputValidation => "CWE-20",
        VulnerabilityClass::NoSqlInjection => "CWE-943",
        VulnerabilityClass::XmlExternalEntity => "CWE-611",
        VulnerabilityClass::CrossOriginMisconfiguration => "CWE-942",
        VulnerabilityClass::MissingSecurityHeader => "CWE-693",
        VulnerabilityClass::JwtVulnerability => "CWE-347",
        VulnerabilityClass::HttpRequestSmuggling => "CWE-444",
        VulnerabilityClass::RaceCondition => "CWE-362",
        VulnerabilityClass::SubdomainTakeover => "CWE-284",
        VulnerabilityClass::PrototypePollution => "CWE-1321",
        VulnerabilityClass::GraphQlAbuse => "CWE-20",
        VulnerabilityClass::CloudMisconfiguration => "CWE-16",
        VulnerabilityClass::Clickjacking => "CWE-1021",
        VulnerabilityClass::CachePoisoning => "CWE-349",
        VulnerabilityClass::HostHeaderInjection => "CWE-644",
        VulnerabilityClass::InsecureDirectObjectReference => "CWE-639",
        VulnerabilityClass::InformationDisclosure => "CWE-200",
        VulnerabilityClass::WeakCryptography => "CWE-327",
        VulnerabilityClass::MassAssignment => "CWE-915",
    }
}

pub fn attack_technique_for(class: &VulnerabilityClass) -> &'static str {
    match class {
        VulnerabilityClass::SqlInjection => "T1190",
        VulnerabilityClass::CrossSiteScripting => "T1189",
        VulnerabilityClass::CommandInjection => "T1059",
        VulnerabilityClass::PathTraversal => "T1083",
        VulnerabilityClass::ServerSideRequestForgery => "T1090",
        VulnerabilityClass::InsecureDeserialization => "T1190",
        VulnerabilityClass::BrokenAuthentication => "T1078",
        VulnerabilityClass::BrokenAuthorization => "T1548",
        VulnerabilityClass::SecurityMisconfiguration => "T1574",
        VulnerabilityClass::SensitiveDataExposure => "T1005",
        VulnerabilityClass::ServerSideTemplateInjection => "T1221",
        VulnerabilityClass::HeaderInjection => "T1071",
        VulnerabilityClass::OpenRedirect => "T1204",
        VulnerabilityClass::CrlfInjection => "T1071",
        VulnerabilityClass::KnownVulnerableDependency => "T1195",
        VulnerabilityClass::InsufficientInputValidation => "T1190",
        VulnerabilityClass::NoSqlInjection => "T1190",
        VulnerabilityClass::XmlExternalEntity => "T1190",
        VulnerabilityClass::CrossOriginMisconfiguration => "T1189",
        VulnerabilityClass::MissingSecurityHeader => "T1574",
        VulnerabilityClass::JwtVulnerability => "T1078",
        VulnerabilityClass::HttpRequestSmuggling => "T1071",
        VulnerabilityClass::RaceCondition => "T1190",
        VulnerabilityClass::SubdomainTakeover => "T1584",
        VulnerabilityClass::PrototypePollution => "T1190",
        VulnerabilityClass::GraphQlAbuse => "T1190",
        VulnerabilityClass::CloudMisconfiguration => "T1574",
        VulnerabilityClass::Clickjacking => "T1189",
        VulnerabilityClass::CachePoisoning => "T1557",
        VulnerabilityClass::HostHeaderInjection => "T1071",
        VulnerabilityClass::InsecureDirectObjectReference => "T1548",
        VulnerabilityClass::InformationDisclosure => "T1005",
        VulnerabilityClass::WeakCryptography => "T1600",
        VulnerabilityClass::MassAssignment => "T1190",
    }
}

pub fn remediation_for(class: &VulnerabilityClass) -> &'static str {
    match class {
        VulnerabilityClass::SqlInjection => {
            "Use parameterized queries or prepared statements instead of string concatenation."
        }
        VulnerabilityClass::CrossSiteScripting => {
            "Apply context-aware output encoding and use a Content Security Policy."
        }
        VulnerabilityClass::CommandInjection => {
            "Avoid shell invocation; use language-native APIs with allow-listed arguments."
        }
        VulnerabilityClass::PathTraversal => {
            "Canonicalize paths and validate they remain within the expected base directory."
        }
        VulnerabilityClass::ServerSideRequestForgery => {
            "Restrict outbound requests to an allow-listed set of hosts and schemes."
        }
        VulnerabilityClass::InsecureDeserialization => {
            "Deserialize only from trusted sources and use safe serialization formats."
        }
        VulnerabilityClass::BrokenAuthentication => {
            "Enforce strong credential policies and implement multi-factor authentication."
        }
        VulnerabilityClass::BrokenAuthorization => {
            "Apply least-privilege access control checks on every request."
        }
        VulnerabilityClass::SecurityMisconfiguration => {
            "Apply hardened defaults and remove unnecessary features, accounts, and permissions."
        }
        VulnerabilityClass::SensitiveDataExposure => {
            "Encrypt sensitive data at rest and in transit; minimize data retention."
        }
        VulnerabilityClass::ServerSideTemplateInjection => {
            "Use a sandboxed template engine and never render user input as template code."
        }
        VulnerabilityClass::HeaderInjection => {
            "Strip or reject CR/LF characters from values used in HTTP headers."
        }
        VulnerabilityClass::OpenRedirect => {
            "Validate redirect targets against an allow-list of trusted destinations."
        }
        VulnerabilityClass::CrlfInjection => {
            "Reject or encode CR and LF characters in all user-controlled output."
        }
        VulnerabilityClass::KnownVulnerableDependency => {
            "Upgrade the dependency to a patched version or apply a vendor-supplied fix."
        }
        VulnerabilityClass::InsufficientInputValidation => {
            "Validate all input against strict schemas at the application boundary."
        }
        VulnerabilityClass::NoSqlInjection => {
            "Use parameterized queries for NoSQL databases and validate input types strictly."
        }
        VulnerabilityClass::XmlExternalEntity => {
            "Disable external entity processing in XML parsers and use less complex data formats."
        }
        VulnerabilityClass::CrossOriginMisconfiguration => {
            "Configure CORS policies to allow only trusted origins and avoid wildcard patterns."
        }
        VulnerabilityClass::MissingSecurityHeader => {
            "Add security headers: Content-Security-Policy, X-Frame-Options, Strict-Transport-Security."
        }
        VulnerabilityClass::JwtVulnerability => {
            "Validate JWT signatures with a strong algorithm; reject 'none' and symmetric key confusion."
        }
        VulnerabilityClass::HttpRequestSmuggling => {
            "Normalize HTTP parsing between front-end and back-end servers; reject ambiguous requests."
        }
        VulnerabilityClass::RaceCondition => {
            "Use atomic operations or pessimistic locking for state-changing operations."
        }
        VulnerabilityClass::SubdomainTakeover => {
            "Remove dangling DNS records and verify ownership of all subdomain targets."
        }
        VulnerabilityClass::PrototypePollution => {
            "Freeze or seal object prototypes; validate and sanitize keys in user-controlled objects."
        }
        VulnerabilityClass::GraphQlAbuse => {
            "Disable introspection in production; enforce query depth and complexity limits."
        }
        VulnerabilityClass::CloudMisconfiguration => {
            "Apply least-privilege IAM policies and enable cloud security posture management."
        }
        VulnerabilityClass::Clickjacking => {
            "Set X-Frame-Options to DENY or SAMEORIGIN and use Content-Security-Policy frame-ancestors."
        }
        VulnerabilityClass::CachePoisoning => {
            "Normalize cache keys and validate Host headers; use cache-control directives."
        }
        VulnerabilityClass::HostHeaderInjection => {
            "Validate the Host header against a whitelist of expected values."
        }
        VulnerabilityClass::InsecureDirectObjectReference => {
            "Enforce authorization checks on every object access; use indirect references."
        }
        VulnerabilityClass::InformationDisclosure => {
            "Remove verbose error messages, debug endpoints, and unnecessary server headers."
        }
        VulnerabilityClass::WeakCryptography => {
            "Use strong, current cryptographic algorithms and proper key management."
        }
        VulnerabilityClass::MassAssignment => {
            "Explicitly whitelist allowed fields for mass assignment; reject unexpected parameters."
        }
    }
}

fn build_cwe_taxonomy() -> ToolComponent {
    let mut tc = ToolComponent::new("CWE");
    tc.version = Some("4.13".to_string());
    tc.information_uri = Some("https://cwe.mitre.org/data/published/cwe_latest.pdf".to_string());
    tc.organization = Some("MITRE".to_string());
    tc.short_description = Some(MultiformatMessage::new(
        "The MITRE Common Weakness Enumeration",
    ));
    tc
}

fn build_attack_taxonomy() -> ToolComponent {
    let mut tc = ToolComponent::new("MITRE ATT&CK");
    tc.version = Some("15.1".to_string());
    tc.information_uri = Some("https://attack.mitre.org/".to_string());
    tc.organization = Some("MITRE".to_string());
    tc.short_description = Some(MultiformatMessage::new(
        "The MITRE ATT&CK knowledge base of adversary tactics and techniques",
    ));
    tc
}

fn attack_taxon_reference(technique_id: &str) -> ReportingDescriptorReference {
    ReportingDescriptorReference {
        id: Some(technique_id.to_string()),
        index: None,
        guid: None,
        tool_component: Some(ToolComponentReference {
            name: Some("MITRE ATT&CK".to_string()),
            index: Some(1),
            guid: None,
            properties: None,
        }),
        properties: None,
    }
}

fn cwe_taxon_reference(cwe_id: &str) -> ReportingDescriptorReference {
    ReportingDescriptorReference {
        id: Some(cwe_id.to_string()),
        index: None,
        guid: None,
        tool_component: Some(ToolComponentReference {
            name: Some("CWE".to_string()),
            index: Some(0),
            guid: None,
            properties: None,
        }),
        properties: None,
    }
}

fn build_rule(finding: &SarifFinding) -> ReportingDescriptor {
    let mut rule = ReportingDescriptor::new(&finding.rule_id);
    rule.short_description = Some(MultiformatMessage::new(&finding.rule_description));
    rule.default_configuration = Some(ReportingConfiguration {
        enabled: None,
        level: Some(match finding.level {
            SarifLevel::Error => sarif_rust::types::NotificationLevel::Error,
            SarifLevel::Warning => sarif_rust::types::NotificationLevel::Warning,
            SarifLevel::Note => sarif_rust::types::NotificationLevel::Note,
            SarifLevel::None => sarif_rust::types::NotificationLevel::None,
        }),
        parameters: None,
        properties: None,
    });
    if let Some(vc) = &finding.vulnerability_class {
        rule.help_uri = Some(format!(
            "https://cwe.mitre.org/data/definitions/{}.html",
            cwe_for(vc).strip_prefix("CWE-").unwrap_or("0")
        ));
    }
    rule
}

fn build_location(finding: &SarifFinding) -> Option<Location> {
    let effective_uri = finding.uri.as_ref().or(finding.endpoint.as_ref());
    let has_physical = effective_uri.is_some();
    let has_logical = finding.logical_location_name.is_some();

    if !has_physical && !has_logical {
        return None;
    }

    let physical = effective_uri
        .map(|uri| PhysicalLocation::with_artifact_location(ArtifactLocation::new(uri)));

    let logical = finding.logical_location_name.as_ref().map(|name| {
        let kind = finding
            .logical_location_kind
            .clone()
            .unwrap_or_else(|| "function".to_string());
        LogicalLocation::with_name(name).with_kind(kind)
    });

    let mut loc = Location::new();
    loc.physical_location = physical;
    if let Some(ll) = logical {
        loc.logical_locations = Some(vec![ll]);
    }
    Some(loc)
}

fn build_related_locations(related: &[RelatedLocation]) -> Option<Vec<Location>> {
    if related.is_empty() {
        return None;
    }
    let locs: Vec<Location> = related
        .iter()
        .enumerate()
        .map(|(i, rl)| {
            let mut loc = Location::new();
            loc.id = Some(i as i32);
            if let Some(uri) = &rl.uri {
                loc.physical_location = Some(PhysicalLocation::with_artifact_location(
                    ArtifactLocation::new(uri),
                ));
            }
            loc.message = Some(Message::new(&rl.message));
            loc
        })
        .collect();
    Some(locs)
}

fn build_fix(class: &VulnerabilityClass) -> Fix {
    Fix {
        description: Some(Message::new(remediation_for(class))),
        artifact_changes: Vec::new(),
        properties: None,
    }
}

fn append_defense_properties(
    props: &mut serde_json::Map<String, serde_json::Value>,
    dc: &SarifDefenseContext,
) {
    let defense_profile = serde_json::json!({
        "defenses_detected": dc.defenses_detected,
    });
    props.insert("defenseProfile".to_string(), defense_profile);
    if let Some(technique) = &dc.evasion_technique {
        props.insert(
            "evasionTechnique".to_string(),
            serde_json::Value::from(technique.clone()),
        );
    }
    props.insert(
        "exploitableDespiteWaf".to_string(),
        serde_json::Value::from(dc.exploitable_despite_waf),
    );
    if let Some(vendor) = &dc.waf_vendor {
        props.insert(
            "wafVendor".to_string(),
            serde_json::Value::from(vendor.clone()),
        );
    }
}

fn build_result(finding: &SarifFinding) -> sarif_rust::types::Result {
    let mut result = sarif_rust::types::Result::new(Message::new(&finding.message));
    result.rule_id = Some(finding.rule_id.clone());
    result.level = Some(finding.level.to_sarif_level());
    result.locations = build_location(finding).map(|l| vec![l]);
    result.related_locations = build_related_locations(&finding.related_locations);

    let mut props = serde_json::Map::new();
    props.insert(
        "severity".to_string(),
        serde_json::Value::from(finding.severity),
    );
    props.insert(
        "confidence".to_string(),
        serde_json::Value::from(finding.confidence),
    );
    props.insert(
        "composite_score".to_string(),
        serde_json::Value::from(finding.composite_score),
    );
    if let Some(dc) = &finding.defense_context {
        append_defense_properties(&mut props, dc);
    }
    if let Some(el) = &finding.evidence_level {
        props.insert(
            "evidenceLevel".to_string(),
            serde_json::Value::from(el.clone()),
        );
    }
    if let Some(cve) = &finding.cve_id {
        props.insert("cveId".to_string(), serde_json::Value::from(cve.clone()));
    }
    if let Some(rank) = finding.mitigation_rank {
        props.insert("mitigationRank".to_string(), serde_json::Value::from(rank));
    }
    if let Some(ref ep) = finding.endpoint {
        props.insert(
            "endpoint".to_string(),
            serde_json::Value::String(ep.clone()),
        );
    }
    if let Some(ref method) = finding.http_method {
        props.insert(
            "httpMethod".to_string(),
            serde_json::Value::String(method.clone()),
        );
    }
    if let Some(ref param) = finding.parameter_name {
        props.insert(
            "parameterName".to_string(),
            serde_json::Value::String(param.clone()),
        );
    }
    if let Some(ref vc) = finding.vulnerability_class {
        props.insert(
            "vulnerabilityClass".to_string(),
            serde_json::Value::String(format!("{:?}", vc)),
        );
    }
    result.properties = Some(props.into_iter().collect());

    if let Some(cve) = &finding.cve_id {
        let nvd_url = format!("https://nvd.nist.gov/vuln/detail/{cve}");
        let mut nvd_loc = Location::new();
        nvd_loc.physical_location = Some(PhysicalLocation::with_artifact_location(
            ArtifactLocation::new(&nvd_url),
        ));
        nvd_loc.message = Some(Message::new(format!("NVD entry for {cve}")));
        let existing = result.related_locations.get_or_insert_with(Vec::new);
        let next_id = existing.len() as i32;
        nvd_loc.id = Some(next_id);
        existing.push(nvd_loc);
    }

    if let Some(vc) = &finding.vulnerability_class {
        result.taxa = Some(vec![
            cwe_taxon_reference(cwe_for(vc)),
            attack_taxon_reference(attack_technique_for(vc)),
        ]);
        result.fixes = Some(vec![build_fix(vc)]);
    }

    if let Some(kind) = &finding.suppression_kind {
        result.suppressions = Some(vec![Suppression {
            kind: kind.clone(),
            status: None,
            justification: finding.suppression_message.clone(),
            location: None,
            guid: None,
            properties: None,
        }]);
    }

    result
}

fn build_run_defense_properties(
    findings: &[SarifFinding],
) -> Option<HashMap<String, serde_json::Value>> {
    let contexts: Vec<&SarifDefenseContext> = findings
        .iter()
        .filter_map(|f| f.defense_context.as_ref())
        .collect();
    if contexts.is_empty() {
        return None;
    }
    let mut all_defenses = HashSet::new();
    let mut evasion_rates = Vec::new();
    let mut any_stealth = false;
    for dc in &contexts {
        for defense in &dc.defenses_detected {
            all_defenses.insert(defense.clone());
        }
        if let Some(rate) = dc.evasion_success_rate {
            evasion_rates.push(rate);
        }
        if dc.stealth_mode_used {
            any_stealth = true;
        }
    }
    let mut props = HashMap::new();
    let mut sorted_defenses: Vec<String> = all_defenses.into_iter().collect();
    sorted_defenses.sort();
    props.insert(
        "defensesDetected".to_string(),
        serde_json::json!(sorted_defenses),
    );
    if !evasion_rates.is_empty() {
        let avg = evasion_rates.iter().sum::<f64>() / evasion_rates.len() as f64;
        props.insert(
            "evasionSuccessRate".to_string(),
            serde_json::Value::from(avg),
        );
    }
    props.insert(
        "stealthModeUsed".to_string(),
        serde_json::Value::from(any_stealth),
    );
    Some(props)
}

pub fn emit_sarif(findings: &[SarifFinding], tool_version: &str) -> SarifLog {
    let mut rules = Vec::new();
    let mut seen_rules = HashSet::new();

    for finding in findings {
        if seen_rules.insert(finding.rule_id.clone()) {
            rules.push(build_rule(finding));
        }
    }

    let results: Vec<sarif_rust::types::Result> = findings.iter().map(build_result).collect();

    let mut driver = ToolComponent::new("AEGIS");
    driver.version = Some(tool_version.to_string());
    driver.rules = if rules.is_empty() { None } else { Some(rules) };

    let mut tool = Tool::new("AEGIS");
    tool.driver = driver;

    let mut run = Run::new(tool);
    run.results = if results.is_empty() {
        Some(Vec::new())
    } else {
        Some(results)
    };
    run.taxonomies = Some(vec![build_cwe_taxonomy(), build_attack_taxonomy()]);
    run.properties = build_run_defense_properties(findings);

    SarifLog::v2_1_0()
        .with_schema(
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        )
        .add_run(run)
}

pub fn sarif_to_json(report: &SarifLog) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}
