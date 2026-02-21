use super::*;

use aegis_knowledge_graph::graph::KnowledgeGraph;
use aegis_passive_recon::dependency_parser::{Ecosystem, ParsedDependency};
use aegis_passive_recon::filesystem_walker::{ClassifiedFile, FileClassification};
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::GraphOperation;
use clap::Parser;
use std::io::Write;
use std::path::PathBuf;

fn make_context(source_dir: Option<PathBuf>) -> ScanContext {
    let mut args = vec!["aegis", "--target", "http://localhost:8080"];
    let dir_string;
    if let Some(ref dir) = source_dir {
        dir_string = dir.to_string_lossy().to_string();
        args.push("--source-dir");
        args.push(&dir_string);
    }
    let config = ScanConfig::try_parse_from(args).unwrap();
    let mut capabilities =
        aegis_supervisor::capability_manager::CapabilityManager::new(vec![0u8; 32]);
    pipeline::register_default_policies(&mut capabilities);
    ScanContext {
        config,
        graph: Box::new(KnowledgeGraph::new()),
        defense_profile: None,
        capabilities,
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
    }
}

#[test]
fn run_recon_no_source_dir_returns_zero_operations() {
    let mut ctx = make_context(None);
    let result = run_recon(&mut ctx).unwrap();
    assert_eq!(result.operations_applied, 0);
    assert_eq!(result.findings_count, 0);
}

#[test]
fn run_recon_nonexistent_source_dir_returns_error() {
    let mut ctx = make_context(Some(PathBuf::from("/nonexistent/aegis-test-dir")));
    let result = run_recon(&mut ctx);
    assert!(result.is_err());
}

#[test]
fn deps_to_operations_produces_dependency_nodes() {
    let deps = vec![
        ParsedDependency {
            name: "serde".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Ecosystem::Cargo,
        },
        ParsedDependency {
            name: "tokio".to_string(),
            version: "1.35.0".to_string(),
            ecosystem: Ecosystem::Cargo,
        },
    ];
    let mut seq = 0u64;
    let entries = phase_recon::deps_to_operations(&deps, &mut seq);

    assert_eq!(entries.len(), 2);
    assert_eq!(seq, 2);

    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(entry.sequence_number, (i + 1) as u64);
        match &entry.operation {
            GraphOperation::AddNode {
                node_type,
                properties,
            } => {
                assert_eq!(*node_type, NodeType::Dependency);
                assert_eq!(properties[0].0, "name");
                assert_eq!(properties[0].1, deps[i].name);
                assert_eq!(properties[1].0, "version");
                assert_eq!(properties[1].1, deps[i].version);
                assert_eq!(properties[2].0, "ecosystem");
            }
            _ => panic!("expected AddNode operation"),
        }
    }
}

#[test]
fn vuln_lookup_empty_deps_returns_empty() {
    let deps: Vec<ParsedDependency> = Vec::new();
    let mut seq = 0u64;
    let entries = phase_recon::vuln_lookup(&deps, &mut seq);
    assert!(entries.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn walk_to_operations_filters_config_files() {
    let files = vec![
        ClassifiedFile {
            path: PathBuf::from("app.toml"),
            classification: FileClassification::ConfigFile,
            size_bytes: 100,
        },
        ClassifiedFile {
            path: PathBuf::from("main.rs"),
            classification: FileClassification::SourceCode,
            size_bytes: 200,
        },
        ClassifiedFile {
            path: PathBuf::from("settings.json"),
            classification: FileClassification::ConfigFile,
            size_bytes: 50,
        },
        ClassifiedFile {
            path: PathBuf::from("Cargo.lock"),
            classification: FileClassification::LockFile,
            size_bytes: 300,
        },
    ];
    let mut seq = 0u64;
    let entries = phase_recon::walk_to_operations(&files, &mut seq);

    assert_eq!(entries.len(), 2);
    assert_eq!(seq, 2);

    match &entries[0].operation {
        GraphOperation::AddNode {
            node_type,
            properties,
        } => {
            assert_eq!(*node_type, NodeType::Config);
            assert_eq!(properties[0].1, "app.toml");
        }
        _ => panic!("expected AddNode operation"),
    }

    match &entries[1].operation {
        GraphOperation::AddNode {
            node_type,
            properties,
        } => {
            assert_eq!(*node_type, NodeType::Config);
            assert_eq!(properties[0].1, "settings.json");
        }
        _ => panic!("expected AddNode operation"),
    }
}

#[test]
fn timestamp_ms_returns_nonzero() {
    let ts = util::timestamp_ms();
    assert!(ts > 0);
}

#[test]
fn run_recon_standalone_none_returns_empty() {
    let result = phase_recon::run_recon_standalone(&None).unwrap();
    assert!(result.is_empty());
}

#[test]
fn run_recon_standalone_nonexistent_dir_returns_error() {
    let dir = Some(PathBuf::from("/nonexistent/aegis-standalone-test-dir"));
    let result = phase_recon::run_recon_standalone(&dir);
    assert!(result.is_err());
}

#[test]
fn run_recon_with_existing_empty_dir_returns_zero_operations() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = make_context(Some(tmp.path().to_path_buf()));
    let result = run_recon(&mut ctx).unwrap();
    assert_eq!(result.operations_applied, 0);
    assert_eq!(result.findings_count, 0);
}

#[test]
fn run_recon_with_config_file_creates_config_node_operation() {
    let tmp = tempfile::tempdir().unwrap();
    let toml_path = tmp.path().join("settings.toml");
    std::fs::write(&toml_path, b"[server]\nport = 8080\n").unwrap();

    let mut ctx = make_context(Some(tmp.path().to_path_buf()));
    let result = run_recon(&mut ctx).unwrap();
    assert_eq!(result.operations_applied, 1);
    assert_eq!(result.findings_count, 0);
}

#[test]
fn run_recon_standalone_with_existing_empty_dir_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let result = phase_recon::run_recon_standalone(&Some(tmp.path().to_path_buf())).unwrap();
    assert!(result.is_empty());
}

#[test]
fn run_recon_standalone_with_config_file_returns_one_entry() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("app.toml"), b"[server]\nport = 3000\n").unwrap();

    let result = phase_recon::run_recon_standalone(&Some(tmp.path().to_path_buf())).unwrap();
    assert_eq!(result.len(), 1);
    match &result[0].operation {
        GraphOperation::AddNode { node_type, .. } => {
            assert_eq!(*node_type, NodeType::Config);
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn run_recon_with_multiple_config_files_counts_correctly() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("a.toml"), b"a = 1").unwrap();
    std::fs::write(tmp.path().join("b.json"), b"{}").unwrap();
    std::fs::write(tmp.path().join("main.rs"), b"fn main() {}").unwrap();

    let mut ctx = make_context(Some(tmp.path().to_path_buf()));
    let result = run_recon(&mut ctx).unwrap();
    assert_eq!(result.operations_applied, 2);
}

#[test]
fn vuln_lookup_with_non_matching_deps_returns_empty() {
    let deps = vec![ParsedDependency {
        name: "no-such-package-xyz".to_string(),
        version: "1.0.0".to_string(),
        ecosystem: Ecosystem::Cargo,
    }];
    let mut seq = 0u64;
    let entries = phase_recon::vuln_lookup(&deps, &mut seq);
    assert!(entries.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn deps_to_operations_empty_returns_empty() {
    let deps: Vec<ParsedDependency> = Vec::new();
    let mut seq = 5u64;
    let entries = phase_recon::deps_to_operations(&deps, &mut seq);
    assert!(entries.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn walk_to_operations_empty_file_list_returns_empty() {
    let files: Vec<ClassifiedFile> = Vec::new();
    let mut seq = 0u64;
    let entries = phase_recon::walk_to_operations(&files, &mut seq);
    assert!(entries.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn walk_to_operations_only_non_config_files_returns_empty() {
    let files = vec![
        ClassifiedFile {
            path: PathBuf::from("Cargo.lock"),
            classification: FileClassification::LockFile,
            size_bytes: 100,
        },
        ClassifiedFile {
            path: PathBuf::from("main.rs"),
            classification: FileClassification::SourceCode,
            size_bytes: 200,
        },
    ];
    let mut seq = 0u64;
    let entries = phase_recon::walk_to_operations(&files, &mut seq);
    assert!(entries.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn run_recon_write_config_file_applies_operations_to_graph() {
    let tmp = tempfile::tempdir().unwrap();
    let mut f = std::fs::File::create(tmp.path().join("config.json")).unwrap();
    f.write_all(b"{}").unwrap();
    drop(f);

    let mut ctx = make_context(Some(tmp.path().to_path_buf()));
    let result = run_recon(&mut ctx).unwrap();
    assert_eq!(result.operations_applied, 1);
    assert_eq!(result.findings_count, 0);
    let node_ids = ctx
        .graph
        .nodes_by_type(NodeType::Config)
        .unwrap_or_default();
    assert_eq!(node_ids.len(), 1);
}
