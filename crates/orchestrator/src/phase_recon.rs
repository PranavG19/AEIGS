use std::path::PathBuf;

use aegis_passive_recon::dependency_parser::{ParsedDependency, parse_lock_file};
use aegis_passive_recon::filesystem_walker::{FileClassification, walk_directory};
use aegis_passive_recon::vuln_database::VulnDatabase;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::pipeline::{PhaseResult, ScanContext};

pub fn run_recon(ctx: &mut ScanContext) -> Result<PhaseResult, String> {
    let mut entries = Vec::new();
    let mut sequence = 0u64;

    if let Some(source_dir) = &ctx.config.source_dir {
        let walk = walk_directory(source_dir).map_err(|e| e.to_string())?;
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
        entries.extend(vuln_lookup(&all_deps, &mut sequence));
        entries.extend(walk_to_operations(&walk.files, &mut sequence));
    }

    let ops_count = entries.len() as u64;
    if !entries.is_empty() {
        ctx.graph
            .apply_operations(&entries)
            .map_err(|e| format!("{e:?}"))?;
    }

    Ok(PhaseResult {
        operations_applied: ops_count,
        findings_count: 0,
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

pub(crate) fn vuln_lookup(deps: &[ParsedDependency], seq: &mut u64) -> Vec<OperationLogEntry> {
    let Ok(db) = VulnDatabase::open_in_memory() else {
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
                    confidence: 0.9,
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

pub(crate) fn timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn run_recon_standalone(
    source_dir: &Option<PathBuf>,
) -> Result<Vec<OperationLogEntry>, String> {
    let Some(source_dir) = source_dir else {
        return Ok(Vec::new());
    };

    let walk = walk_directory(source_dir).map_err(|e| e.to_string())?;
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
    entries.extend(vuln_lookup(&all_deps, &mut sequence));
    entries.extend(walk_to_operations(&walk.files, &mut sequence));
    Ok(entries)
}
