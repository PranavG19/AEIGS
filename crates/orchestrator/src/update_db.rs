use std::path::{Path, PathBuf};

use aegis_passive_recon::dependency_parser::{Ecosystem, ParsedDependency, parse_lock_file};
use aegis_passive_recon::filesystem_walker::{FileClassification, walk_directory};
use aegis_passive_recon::vuln_database::{VulnDatabase, VulnerabilityRecord};
use serde::Deserialize;

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const MAX_BATCH_SIZE: usize = 1000;
const DEFAULT_SEVERITY: f64 = 5.0;
const SENTINEL_VERSION: &str = "999999.0.0";

/// CLI arguments for the `update-db` subcommand.
///
/// Parsed from raw `args[2..]` by `parse_update_db_args`. Controls where
/// the vulnerability database is stored, which source directory to scan
/// for lock files, and whether to perform a full refresh.
#[derive(Debug)]
pub struct UpdateDbArgs {
    pub db_path: PathBuf,
    pub source_dir: PathBuf,
    pub full_refresh: bool,
    pub update_wordlists: bool,
    pub update_tools: bool,
}

/// Summary returned after a successful `update-db` run.
///
/// Reports the database path, how many new records were inserted,
/// total record count, and how many unique packages were queried via OSV.
pub struct UpdateDbSummary {
    pub db_path: PathBuf,
    pub new_records: usize,
    pub total_records: u64,
    pub packages_queried: usize,
}

/// Errors from the `update-db` subcommand.
#[derive(Debug)]
pub enum UpdateDbError {
    MissingArg(String),
    Http(String),
    Database(String),
    Io(String),
    NoPackagesFound,
}

impl std::fmt::Display for UpdateDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingArg(name) => write!(f, "missing required argument: --{name}"),
            Self::Http(msg) => write!(f, "HTTP error: {msg}"),
            Self::Database(msg) => write!(f, "database error: {msg}"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::NoPackagesFound => write!(f, "no packages found in source directory"),
        }
    }
}

impl std::error::Error for UpdateDbError {}

pub fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".aegis").join("vuln.db")
}

pub fn parse_update_db_args(args: &[String]) -> Result<UpdateDbArgs, UpdateDbError> {
    let source_dir =
        find_flag(args, "source-dir").ok_or(UpdateDbError::MissingArg("source-dir".to_string()))?;
    let db_path = find_flag(args, "db-path")
        .map(PathBuf::from)
        .unwrap_or_else(default_db_path);
    let full_refresh = args.iter().any(|a| a == "--full-refresh");
    let update_wordlists = args.iter().any(|a| a == "--update-wordlists");
    let update_tools = args.iter().any(|a| a == "--update-tools");

    Ok(UpdateDbArgs {
        db_path,
        source_dir: PathBuf::from(source_dir),
        full_refresh,
        update_wordlists,
        update_tools,
    })
}

pub fn run_update_db(args: &UpdateDbArgs) -> Result<UpdateDbSummary, UpdateDbError> {
    let packages = collect_packages(&args.source_dir)?;
    if packages.is_empty() {
        return Err(UpdateDbError::NoPackagesFound);
    }

    if let Some(parent) = args.db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| UpdateDbError::Io(e.to_string()))?;
    }

    let db =
        VulnDatabase::open(&args.db_path).map_err(|e| UpdateDbError::Database(e.to_string()))?;

    let mut queries: Vec<(String, Ecosystem)> = packages
        .iter()
        .map(|dep| (dep.name.clone(), dep.ecosystem))
        .collect();
    queries.sort();
    queries.dedup();
    let packages_queried = queries.len();

    if args.full_refresh {
        let mut ecosystems_seen = std::collections::HashSet::new();
        for (_, eco) in &queries {
            ecosystems_seen.insert(*eco);
        }
        for eco in &ecosystems_seen {
            db.clear_ecosystem(&eco.to_string())
                .map_err(|e| UpdateDbError::Database(e.to_string()))?;
        }
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| UpdateDbError::Http(e.to_string()))?;

    let mut total_new = 0usize;
    for chunk in queries.chunks(MAX_BATCH_SIZE) {
        let osv_queries: Vec<_> = chunk
            .iter()
            .map(|(name, eco)| (name.clone(), eco.osv_name().to_string()))
            .collect();

        let response = query_osv_batch(&client, &osv_queries)?;

        let mut records = Vec::new();
        for (i, batch_result) in response.results.iter().enumerate() {
            let aegis_ecosystem = chunk[i].1.to_string();
            if let Some(vulns) = &batch_result.vulns {
                for vuln in vulns {
                    records.extend(convert_osv_to_records(vuln, &aegis_ecosystem));
                }
            }
        }

        let inserted = db
            .insert_batch(&records)
            .map_err(|e| UpdateDbError::Database(e.to_string()))?;
        total_new += inserted;
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let mut ecosystems_seen = std::collections::HashSet::new();
    for (_, eco) in &queries {
        ecosystems_seen.insert(*eco);
    }
    for eco in &ecosystems_seen {
        db.set_last_updated(&eco.to_string(), now_ms)
            .map_err(|e| UpdateDbError::Database(e.to_string()))?;
    }

    let total_records = db
        .vulnerability_count()
        .map_err(|e| UpdateDbError::Database(e.to_string()))?;

    Ok(UpdateDbSummary {
        db_path: args.db_path.clone(),
        new_records: total_new,
        total_records,
        packages_queried,
    })
}

fn collect_packages(source_dir: &Path) -> Result<Vec<ParsedDependency>, UpdateDbError> {
    let walk = walk_directory(source_dir).map_err(|e| UpdateDbError::Io(e.to_string()))?;
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
    Ok(all_deps)
}

fn query_osv_batch(
    client: &reqwest::blocking::Client,
    queries: &[(String, String)],
) -> Result<OsvBatchResponse, UpdateDbError> {
    let body = serde_json::json!({
        "queries": queries.iter().map(|(name, eco)| {
            serde_json::json!({
                "package": {
                    "name": name,
                    "ecosystem": eco,
                }
            })
        }).collect::<Vec<_>>()
    });

    let mut last_err = String::new();
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(1 << attempt));
        }
        match client.post(OSV_BATCH_URL).json(&body).send() {
            Ok(resp) if resp.status().is_success() => {
                let parsed: OsvBatchResponse = resp
                    .json()
                    .map_err(|e| UpdateDbError::Http(format!("failed to parse response: {e}")))?;
                return Ok(parsed);
            }
            Ok(resp) => {
                last_err = format!("HTTP {}", resp.status());
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }
    }
    Err(UpdateDbError::Http(format!(
        "failed after 3 attempts: {last_err}"
    )))
}

pub fn convert_osv_to_records(
    vuln: &OsvVulnerability,
    aegis_ecosystem: &str,
) -> Vec<VulnerabilityRecord> {
    let cve_id = extract_cve_id(vuln);
    let severity = extract_severity(&vuln.severity);
    let description = vuln.summary.clone().unwrap_or_default();

    let mut records = Vec::new();
    let Some(affected_list) = &vuln.affected else {
        return records;
    };

    for affected in affected_list {
        let Some(ranges) = &affected.ranges else {
            continue;
        };
        let package_name = affected
            .package
            .as_ref()
            .map(|p| p.name.clone())
            .unwrap_or_default();
        if package_name.is_empty() {
            continue;
        }

        for range in ranges {
            if range.range_type != "SEMVER" && range.range_type != "ECOSYSTEM" {
                continue;
            }
            for (start, end) in extract_version_ranges(&range.events) {
                records.push(VulnerabilityRecord {
                    cve_id: cve_id.clone(),
                    package_name: package_name.clone(),
                    ecosystem: aegis_ecosystem.to_string(),
                    vulnerable_version_start: start,
                    vulnerable_version_end: end,
                    severity,
                    description: description.clone(),
                });
            }
        }
    }
    records
}

pub fn extract_cve_id(vuln: &OsvVulnerability) -> String {
    if let Some(aliases) = &vuln.aliases
        && let Some(cve) = aliases.iter().find(|a| a.starts_with("CVE-"))
    {
        return cve.clone();
    }
    vuln.id.clone()
}

pub fn extract_severity(severity: &Option<Vec<OsvSeverity>>) -> f64 {
    let Some(entries) = severity else {
        return DEFAULT_SEVERITY;
    };
    for entry in entries {
        if let Ok(score) = entry.score.parse::<f64>()
            && score.is_finite()
            && (0.0..=10.0).contains(&score)
        {
            return score;
        }
    }
    DEFAULT_SEVERITY
}

pub fn extract_version_ranges(events: &[OsvEvent]) -> Vec<(String, String)> {
    let mut ranges = Vec::new();
    let mut current_introduced: Option<String> = None;

    for event in events {
        if let Some(introduced) = &event.introduced {
            if let Some(prev) = current_introduced.take() {
                ranges.push((prev, SENTINEL_VERSION.to_string()));
            }
            current_introduced = Some(introduced.clone());
        }
        if current_introduced.is_some() {
            if let Some(fixed) = &event.fixed {
                ranges.push((current_introduced.take().unwrap(), fixed.clone()));
            } else if let Some(last_affected) = &event.last_affected {
                ranges.push((current_introduced.take().unwrap(), last_affected.clone()));
            }
        }
    }

    if let Some(remaining) = current_introduced {
        ranges.push((remaining, SENTINEL_VERSION.to_string()));
    }

    ranges
}

fn find_flag(args: &[String], name: &str) -> Option<String> {
    let flag = format!("--{name}");
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

/// Deserialized batch response from the OSV.dev vulnerability API.
#[derive(Debug, Deserialize)]
pub struct OsvBatchResponse {
    pub results: Vec<OsvBatchResult>,
}

/// A single package result within an OSV batch response.
#[derive(Debug, Deserialize)]
pub struct OsvBatchResult {
    pub vulns: Option<Vec<OsvVulnerability>>,
}

/// An individual vulnerability record from the OSV API.
#[derive(Debug, Deserialize)]
pub struct OsvVulnerability {
    pub id: String,
    pub aliases: Option<Vec<String>>,
    pub summary: Option<String>,
    pub severity: Option<Vec<OsvSeverity>>,
    pub affected: Option<Vec<OsvAffected>>,
}

/// Severity entry from the OSV vulnerability schema (CVSS or similar).
#[derive(Debug, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

/// An affected package entry in an OSV vulnerability.
#[derive(Debug, Deserialize)]
pub struct OsvAffected {
    pub package: Option<OsvPackage>,
    pub ranges: Option<Vec<OsvRange>>,
}

/// Package identifier within an OSV affected entry.
#[derive(Debug, Deserialize)]
pub struct OsvPackage {
    pub name: String,
    pub ecosystem: String,
}

/// Version range within an OSV affected entry (SEMVER or ECOSYSTEM type).
#[derive(Debug, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: String,
    pub events: Vec<OsvEvent>,
}

/// A version lifecycle event (introduced, fixed, or last_affected).
#[derive(Debug, Deserialize)]
pub struct OsvEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
}

#[cfg(test)]
#[path = "update_db_test.rs"]
mod update_db_test;
