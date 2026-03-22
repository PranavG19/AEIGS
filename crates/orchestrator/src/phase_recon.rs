use std::collections::HashSet;
use std::path::{Path, PathBuf};

use aegis_exploiter::{
    AmassWrapper, ExploitContext, ExploitResult, GauWrapper, ToolWrapper, TrufflehogWrapper,
    extract_domain, spawn_with_timeout,
};
use aegis_passive_recon::dependency_parser::{ParsedDependency, parse_lock_file};
use aegis_passive_recon::filesystem_walker::{FileClassification, walk_directory};
use aegis_passive_recon::vuln_database::VulnDatabase;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::phase_error::PhaseError;
use crate::pipeline::{PhaseResult, ScanContext};
use crate::util::{extract_path_from_url, timestamp_ms};

pub fn run_recon(ctx: &mut ScanContext) -> Result<PhaseResult, PhaseError> {
    let mut entries = Vec::new();
    let mut sequence = 0u64;
    let mut findings_count = 0u64;

    let target = ctx.config.target.clone();
    let gau_target = target.clone();
    let amass_target = target.clone();
    let crtsh_target = target.clone();
    let s3_target = target.clone();
    let st_target = target;
    let gau_handle = std::thread::spawn(move || harvest_urls(&gau_target));
    let amass_handle = std::thread::spawn(move || enumerate_subdomains(&amass_target));
    let crtsh_handle = std::thread::spawn(move || query_crtsh(&crtsh_target));
    let st_handle = std::thread::spawn(move || query_securitytrails(&st_target));
    let s3_handle = std::thread::spawn(move || crate::s3_scanner::scan_s3_buckets(&s3_target));
    let shodan_target = ctx.config.target.clone();
    let shodan_handle =
        std::thread::spawn(move || crate::shodan_lookup::shodan_lookup(&shodan_target));
    let trufflehog_handle = ctx.config.source_dir.as_ref().map(|dir| {
        let dir = dir.clone();
        std::thread::spawn(move || scan_secrets(&dir))
    });
    let github_org_handle = ctx.config.github_org.as_ref().map(|org| {
        let org = org.clone();
        std::thread::spawn(move || scan_github_org(&org))
    });

    if let Some(source_dir) = &ctx.config.source_dir {
        let walk =
            walk_directory(source_dir).map_err(|e| PhaseError::FilesystemWalk(e.to_string()))?;
        let lock_files: Vec<_> = walk
            .files
            .iter()
            .filter(|f| f.classification == FileClassification::LockFile)
            .collect();

        let mut all_deps: Vec<ParsedDependency> = Vec::new();
        for lock_file in &lock_files {
            if let Ok(deps) = parse_lock_file(&lock_file.path) {
                all_deps.extend(deps);
            }
        }

        entries.extend(deps_to_operations(&all_deps, &mut sequence));
        entries.extend(vuln_lookup(
            &all_deps,
            &mut sequence,
            ctx.config.scope.vuln_db.as_deref(),
        ));
        entries.extend(walk_to_operations(&walk.files, &mut sequence));
    }

    if let Some(handle) = trufflehog_handle {
        let secrets = handle.join().unwrap_or_default();
        let secret_ops = secret_findings_to_operations(&secrets, &mut sequence);
        findings_count += secret_ops.len() as u64;
        entries.extend(secret_ops);
    }

    if let Some(handle) = github_org_handle {
        let secrets = handle.join().unwrap_or_default();
        let org_ops = secret_findings_to_operations(&secrets, &mut sequence);
        findings_count += org_ops.len() as u64;
        entries.extend(org_ops);
    }

    let gau_urls = gau_handle.join().unwrap_or_default();
    entries.extend(harvested_urls_to_operations(&gau_urls, &mut sequence));

    let subdomains = amass_handle.join().unwrap_or_default();
    entries.extend(subdomains_to_operations(&subdomains, &mut sequence));

    let ct_subdomains = crtsh_handle.join().unwrap_or_default();
    entries.extend(crtsh_to_operations(&ct_subdomains, &mut sequence));

    let st_subdomains = st_handle.join().unwrap_or_default();
    entries.extend(securitytrails_to_operations(&st_subdomains, &mut sequence));

    let s3_findings = s3_handle.join().unwrap_or_default();
    let s3_ops = crate::s3_scanner::s3_findings_to_operations(&s3_findings, &mut sequence);
    findings_count += s3_ops
        .iter()
        .filter(|op| matches!(op.operation, GraphOperation::AddFinding { .. }))
        .count() as u64;
    entries.extend(s3_ops);

    if let Some(shodan_result) = shodan_handle.join().ok().flatten() {
        let shodan_ops = crate::shodan_lookup::shodan_to_operations(&shodan_result, &mut sequence);
        findings_count += shodan_ops
            .iter()
            .filter(|op| matches!(op.operation, GraphOperation::AddFinding { .. }))
            .count() as u64;
        entries.extend(shodan_ops);
    }

    let ops_count = entries.len() as u64;
    if !entries.is_empty() {
        ctx.graph.apply_operations(&entries)?;
    }

    Ok(PhaseResult {
        operations_applied: ops_count,
        findings_count,
    })
}

pub(crate) fn deps_to_operations(
    deps: &[ParsedDependency],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    deps.iter()
        .map(|dep| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Dependency,
                    properties: vec![
                        ("name".to_string(), dep.name.clone()),
                        ("version".to_string(), dep.version.clone()),
                        ("ecosystem".to_string(), format!("{:?}", dep.ecosystem)),
                    ],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

pub(crate) fn vuln_lookup(
    deps: &[ParsedDependency],
    seq: &mut u64,
    vuln_db_path: Option<&Path>,
) -> Vec<OperationLogEntry> {
    let db = match vuln_db_path {
        Some(path) if path.exists() => VulnDatabase::open(path).ok(),
        _ => {
            let default = crate::update_db::default_db_path();
            if default.exists() {
                VulnDatabase::open(&default).ok()
            } else {
                None
            }
        }
    };
    let Some(db) = db else {
        return Vec::new();
    };
    let Ok(matches) = db.check_all_dependencies(deps) else {
        return Vec::new();
    };
    matches
        .iter()
        .map(|m| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class:
                        aegis_protocol::finding::VulnerabilityClass::KnownVulnerableDependency,
                    severity: m.severity,
                    confidence: aegis_protocol::finding::Confidence::new(0.9).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

pub(crate) fn walk_to_operations(
    files: &[aegis_passive_recon::filesystem_walker::ClassifiedFile],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    files
        .iter()
        .filter(|f| f.classification == FileClassification::ConfigFile)
        .map(|f| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Config,
                    properties: vec![("path".to_string(), f.path.to_string_lossy().to_string())],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

pub fn run_recon_standalone(
    source_dir: &Option<PathBuf>,
    vuln_db_path: Option<&Path>,
) -> Result<Vec<OperationLogEntry>, PhaseError> {
    let Some(source_dir) = source_dir else {
        return Ok(Vec::new());
    };

    let walk = walk_directory(source_dir).map_err(|e| PhaseError::FilesystemWalk(e.to_string()))?;
    let lock_files: Vec<_> = walk
        .files
        .iter()
        .filter(|f| f.classification == FileClassification::LockFile)
        .collect();

    let mut all_deps = Vec::new();
    for lock_file in &lock_files {
        if let Ok(deps) = parse_lock_file(&lock_file.path) {
            all_deps.extend(deps);
        }
    }

    let mut sequence = 0u64;
    let mut entries = Vec::new();
    entries.extend(deps_to_operations(&all_deps, &mut sequence));
    entries.extend(vuln_lookup(&all_deps, &mut sequence, vuln_db_path));
    entries.extend(walk_to_operations(&walk.files, &mut sequence));
    Ok(entries)
}

/// Runs gau to harvest historical URLs from web archives.
pub fn harvest_urls(target: &str) -> Vec<String> {
    let wrapper = GauWrapper;
    if !wrapper.is_available() {
        tracing::debug!("gau not installed, skipping URL harvest");
        return Vec::new();
    }
    let context = ExploitContext::new(
        target.to_string(),
        String::new(),
        VulnerabilityClass::InformationDisclosure,
    );
    let command = wrapper.build_command(&context);
    let (stdout, stderr) = match spawn_with_timeout(command, wrapper.timeout(), "gau") {
        Ok(output) => output,
        Err(e) => {
            tracing::warn!(error = %e, "gau URL harvest failed");
            return Vec::new();
        }
    };
    let results = wrapper.parse_output(&stdout, &stderr);
    let mut urls: Vec<String> = results
        .iter()
        .filter_map(|r| r.extracted_data.clone())
        .collect();
    urls.sort();
    urls.dedup();
    if !urls.is_empty() {
        tracing::info!(count = urls.len(), "gau harvested historical URLs");
    }
    urls
}

/// Converts harvested URLs into Endpoint node operations, deduplicating by path.
pub(crate) fn harvested_urls_to_operations(
    urls: &[String],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    let mut seen_paths = HashSet::new();
    urls.iter()
        .filter_map(|url| extract_path_from_url(url))
        .filter(|path| seen_paths.insert(path.clone()))
        .map(|path| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![
                        ("path".to_string(), path),
                        ("method".to_string(), "GET".to_string()),
                        ("source".to_string(), "gau".to_string()),
                    ],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

/// Runs amass for passive subdomain enumeration.
pub fn enumerate_subdomains(target: &str) -> Vec<String> {
    let wrapper = AmassWrapper;
    if !wrapper.is_available() {
        tracing::debug!("amass not installed, skipping subdomain enumeration");
        return Vec::new();
    }
    let context = ExploitContext::new(
        target.to_string(),
        String::new(),
        VulnerabilityClass::InformationDisclosure,
    );
    let command = wrapper.build_command(&context);
    let (stdout, stderr) = match spawn_with_timeout(command, wrapper.timeout(), "amass") {
        Ok(output) => output,
        Err(e) => {
            tracing::warn!(error = %e, "amass subdomain enumeration failed");
            return Vec::new();
        }
    };
    let results = wrapper.parse_output(&stdout, &stderr);
    let mut subdomains: Vec<String> = results
        .iter()
        .filter_map(|r| r.extracted_data.clone())
        .collect();
    subdomains.sort();
    subdomains.dedup();
    if !subdomains.is_empty() {
        tracing::info!(count = subdomains.len(), "amass found subdomains");
    }
    subdomains
}

/// Converts discovered subdomains into Service node operations.
pub(crate) fn subdomains_to_operations(
    subdomains: &[String],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    subdomains_to_operations_with_source(subdomains, "amass", seq)
}

pub(crate) fn subdomains_to_operations_with_source(
    subdomains: &[String],
    source: &str,
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    subdomains
        .iter()
        .map(|subdomain| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Service,
                    properties: vec![
                        ("hostname".to_string(), subdomain.clone()),
                        ("source".to_string(), source.to_string()),
                    ],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

/// Runs trufflehog to scan source directory for leaked secrets.
pub fn scan_secrets(source_dir: &Path) -> Vec<ExploitResult> {
    let wrapper = TrufflehogWrapper;
    if !wrapper.is_available() {
        tracing::debug!("trufflehog not installed, skipping secret scan");
        return Vec::new();
    }
    let context = ExploitContext::new(
        String::new(),
        source_dir.to_string_lossy().to_string(),
        VulnerabilityClass::SensitiveDataExposure,
    );
    let command = wrapper.build_command(&context);
    let (stdout, stderr) = match spawn_with_timeout(command, wrapper.timeout(), "trufflehog") {
        Ok(output) => output,
        Err(e) => {
            tracing::warn!(error = %e, "trufflehog secret scan failed");
            return Vec::new();
        }
    };
    let results = wrapper.parse_output(&stdout, &stderr);
    if !results.is_empty() {
        tracing::info!(count = results.len(), "trufflehog found potential secrets");
    }
    results
}

/// Runs trufflehog in GitHub org mode to scan an organization's repositories.
///
/// Requires trufflehog installed and GITHUB_TOKEN env var for API access.
/// Uses the same output parser as filesystem mode since the JSON format
/// is identical.
pub fn scan_github_org(org: &str) -> Vec<ExploitResult> {
    let wrapper = TrufflehogWrapper;
    if !wrapper.is_available() {
        tracing::debug!("trufflehog not installed, skipping GitHub org scan");
        return Vec::new();
    }
    if std::env::var("GITHUB_TOKEN").is_err() {
        tracing::debug!("GITHUB_TOKEN not set, skipping GitHub org scan");
        return Vec::new();
    }
    let mut command = std::process::Command::new("trufflehog");
    command.args([
        "github",
        "--org",
        org,
        "--json",
        "--results=verified,unknown",
        "--no-update",
    ]);
    // GitHub org scanning is slower than filesystem — double the wrapper's base timeout
    let timeout = wrapper.timeout().saturating_mul(2);
    let (stdout, stderr) = match spawn_with_timeout(command, timeout, "trufflehog-github") {
        Ok(output) => output,
        Err(e) => {
            tracing::warn!(org = %org, error = %e, "trufflehog GitHub org scan failed");
            return Vec::new();
        }
    };
    let results = wrapper.parse_output(&stdout, &stderr);
    if !results.is_empty() {
        tracing::info!(
            org = %org,
            count = results.len(),
            "trufflehog found secrets in GitHub org"
        );
    }
    results
}

/// Queries crt.sh Certificate Transparency logs for subdomains of the target.
///
/// Uses the free crt.sh HTTPS API (no API key needed). Returns deduplicated
/// subdomain names. Returns an empty vec on any network/parse error.
pub fn query_crtsh(target: &str) -> Vec<String> {
    let Some(domain) = extract_domain(target) else {
        tracing::debug!("could not extract domain from target for crt.sh query");
        return Vec::new();
    };
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        tracing::debug!("skipping crt.sh for localhost target");
        return Vec::new();
    }
    let url = format!("https://crt.sh/?q=%.{domain}&output=json");
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "failed to build HTTP client for crt.sh");
            return Vec::new();
        }
    };
    let response = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "crt.sh query failed");
            return Vec::new();
        }
    };
    let body = match response.text() {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read crt.sh response body");
            return Vec::new();
        }
    };
    let subdomains = parse_crtsh_response(&body);
    if !subdomains.is_empty() {
        tracing::info!(
            count = subdomains.len(),
            "crt.sh found subdomains via CT logs"
        );
    }
    subdomains
}

/// Parses crt.sh JSON response into a deduplicated list of subdomain names.
pub(crate) fn parse_crtsh_response(body: &str) -> Vec<String> {
    let entries: Vec<CrtshEntry> = match serde_json::from_str(body) {
        Ok(e) => e,
        Err(_) => {
            tracing::debug!("failed to parse crt.sh JSON response");
            return Vec::new();
        }
    };
    let mut seen = HashSet::new();
    let mut subdomains = Vec::new();
    for entry in &entries {
        for name in entry.name_value.split('\n') {
            let name = name.trim().trim_start_matches("*.");
            if !name.is_empty() && seen.insert(name) {
                subdomains.push(name.to_string());
            }
        }
    }
    subdomains
}

#[derive(serde::Deserialize)]
struct CrtshEntry {
    #[serde(default)]
    name_value: String,
}

pub(crate) fn crtsh_to_operations(subdomains: &[String], seq: &mut u64) -> Vec<OperationLogEntry> {
    subdomains_to_operations_with_source(subdomains, "crtsh", seq)
}

/// Queries SecurityTrails API for subdomains of the target domain.
///
/// Requires `SECURITYTRAILS_API_KEY` environment variable. Returns empty vec
/// if the key is not set or the query fails. Free tier: 50 queries/month.
pub fn query_securitytrails(target: &str) -> Vec<String> {
    let api_key = match std::env::var("SECURITYTRAILS_API_KEY") {
        Ok(key) if !key.is_empty() => key,
        _ => {
            tracing::debug!("SECURITYTRAILS_API_KEY not set, skipping SecurityTrails query");
            return Vec::new();
        }
    };
    let Some(domain) = extract_domain(target) else {
        return Vec::new();
    };
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        return Vec::new();
    }
    let url = format!("https://api.securitytrails.com/v1/domain/{domain}/subdomains");
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "failed to build HTTP client for SecurityTrails");
            return Vec::new();
        }
    };
    let response = match client.get(&url).header("APIKEY", &api_key).send() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "SecurityTrails query failed");
            return Vec::new();
        }
    };
    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            "SecurityTrails returned non-success status"
        );
        return Vec::new();
    }
    let body = match response.text() {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read SecurityTrails response body");
            return Vec::new();
        }
    };
    let subdomains = parse_securitytrails_response(&body, &domain);
    if !subdomains.is_empty() {
        tracing::info!(count = subdomains.len(), "SecurityTrails found subdomains");
    }
    subdomains
}

/// Parses SecurityTrails JSON response into fully-qualified subdomain names.
///
/// SecurityTrails returns subdomain prefixes only (e.g. "www", "api").
/// This function appends the base domain to create FQDNs.
pub(crate) fn parse_securitytrails_response(body: &str, domain: &str) -> Vec<String> {
    let response: SecurityTrailsResponse = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => {
            tracing::debug!("failed to parse SecurityTrails JSON response");
            return Vec::new();
        }
    };
    response
        .subdomains
        .into_iter()
        .filter(|s| !s.is_empty())
        .map(|prefix| format!("{prefix}.{domain}"))
        .collect()
}

#[derive(serde::Deserialize)]
struct SecurityTrailsResponse {
    #[serde(default)]
    subdomains: Vec<String>,
}

pub(crate) fn securitytrails_to_operations(
    subdomains: &[String],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    subdomains_to_operations_with_source(subdomains, "securitytrails", seq)
}

/// Converts trufflehog results into AddFinding operations.
pub(crate) fn secret_findings_to_operations(
    results: &[ExploitResult],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    results
        .iter()
        .map(|r| {
            *seq += 1;
            let severity = r.severity_upgrade.unwrap_or(5.0);
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class: VulnerabilityClass::SensitiveDataExposure,
                    severity,
                    confidence: aegis_protocol::finding::Confidence::new(0.85).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
