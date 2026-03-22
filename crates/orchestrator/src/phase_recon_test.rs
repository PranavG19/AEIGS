use super::*;

use aegis_exploiter::ExploitResult;
use aegis_knowledge_graph::graph::KnowledgeGraph;
use aegis_passive_recon::dependency_parser::{Ecosystem, ParsedDependency};
use aegis_passive_recon::filesystem_walker::{ClassifiedFile, FileClassification};
use aegis_passive_recon::vuln_database::{VulnDatabase, VulnerabilityRecord};
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
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
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
    let entries = phase_recon::vuln_lookup(&deps, &mut seq, None);
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
    let result = phase_recon::run_recon_standalone(&None, None).unwrap();
    assert!(result.is_empty());
}

#[test]
fn run_recon_standalone_nonexistent_dir_returns_error() {
    let dir = Some(PathBuf::from("/nonexistent/aegis-standalone-test-dir"));
    let result = phase_recon::run_recon_standalone(&dir, None);
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
    let result = phase_recon::run_recon_standalone(&Some(tmp.path().to_path_buf()), None).unwrap();
    assert!(result.is_empty());
}

#[test]
fn run_recon_standalone_with_config_file_returns_one_entry() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("app.toml"), b"[server]\nport = 3000\n").unwrap();

    let result = phase_recon::run_recon_standalone(&Some(tmp.path().to_path_buf()), None).unwrap();
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
    let entries = phase_recon::vuln_lookup(&deps, &mut seq, None);
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

#[test]
fn vuln_lookup_with_populated_db_finds_match() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("test-vuln.db");
    let db = VulnDatabase::open(&db_path).unwrap();
    db.insert_batch(&[VulnerabilityRecord {
        cve_id: "CVE-2024-9999".to_string(),
        package_name: "tokio".to_string(),
        ecosystem: "cargo".to_string(),
        vulnerable_version_start: "1.0.0".to_string(),
        vulnerable_version_end: "1.99.0".to_string(),
        severity: 8.0,
        description: "test vuln".to_string(),
    }])
    .unwrap();

    let deps = vec![ParsedDependency {
        name: "tokio".to_string(),
        version: "1.37.0".to_string(),
        ecosystem: Ecosystem::Cargo,
    }];
    let mut seq = 0u64;
    let entries = phase_recon::vuln_lookup(&deps, &mut seq, Some(&db_path));
    assert_eq!(entries.len(), 1);
    assert_eq!(seq, 1);
    match &entries[0].operation {
        GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 8.0).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding operation"),
    }
}

#[test]
fn harvested_urls_to_operations_creates_endpoint_nodes() {
    let urls = vec![
        "https://example.com/api/users".to_string(),
        "https://example.com/api/items".to_string(),
    ];
    let mut seq = 0u64;
    let ops = phase_recon::harvested_urls_to_operations(&urls, &mut seq);

    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);

    match &ops[0].operation {
        GraphOperation::AddNode {
            node_type,
            properties,
        } => {
            assert_eq!(*node_type, NodeType::Endpoint);
            let map: std::collections::HashMap<&str, &str> = properties
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            assert_eq!(map["path"], "/api/users");
            assert_eq!(map["method"], "GET");
            assert_eq!(map["source"], "gau");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn harvested_urls_to_operations_deduplicates_paths() {
    let urls = vec![
        "https://example.com/api/users".to_string(),
        "https://example.com/api/users?page=2".to_string(),
    ];
    let mut seq = 0u64;
    let ops = phase_recon::harvested_urls_to_operations(&urls, &mut seq);

    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn harvested_urls_to_operations_empty_returns_empty() {
    let urls: Vec<String> = Vec::new();
    let mut seq = 5u64;
    let ops = phase_recon::harvested_urls_to_operations(&urls, &mut seq);

    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn subdomains_to_operations_creates_service_nodes() {
    let subdomains = vec!["api.example.com".to_string(), "www.example.com".to_string()];
    let mut seq = 0u64;
    let ops = phase_recon::subdomains_to_operations(&subdomains, &mut seq);

    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);

    match &ops[0].operation {
        GraphOperation::AddNode {
            node_type,
            properties,
        } => {
            assert_eq!(*node_type, NodeType::Service);
            let map: std::collections::HashMap<&str, &str> = properties
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            assert_eq!(map["hostname"], "api.example.com");
            assert_eq!(map["source"], "amass");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn subdomains_to_operations_empty_returns_empty() {
    let subdomains: Vec<String> = Vec::new();
    let mut seq = 0u64;
    let ops = phase_recon::subdomains_to_operations(&subdomains, &mut seq);

    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn secret_findings_to_operations_creates_findings() {
    let results = vec![
        ExploitResult::new(
            "trufflehog".to_string(),
            true,
            "AWS: AKIA... (true)".to_string(),
            "trufflehog filesystem .".to_string(),
        )
        .with_severity_upgrade(9.5),
        ExploitResult::new(
            "trufflehog".to_string(),
            true,
            "Generic: token... (false)".to_string(),
            "trufflehog filesystem .".to_string(),
        ),
    ];
    let mut seq = 0u64;
    let ops = phase_recon::secret_findings_to_operations(&results, &mut seq);

    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);

    match &ops[0].operation {
        GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 9.5).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
    match &ops[1].operation {
        GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 5.0).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn secret_findings_to_operations_empty_returns_empty() {
    let results: Vec<ExploitResult> = Vec::new();
    let mut seq = 0u64;
    let ops = phase_recon::secret_findings_to_operations(&results, &mut seq);

    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn extract_path_from_url_parses_correctly() {
    assert_eq!(
        util::extract_path_from_url("https://example.com/api/users"),
        Some("/api/users".to_string())
    );
    assert_eq!(
        util::extract_path_from_url("https://example.com/api/items?page=2"),
        Some("/api/items".to_string())
    );
    assert_eq!(
        util::extract_path_from_url("http://localhost:8080/"),
        Some("/".to_string())
    );
    assert_eq!(util::extract_path_from_url("not-a-url"), None);
}

#[test]
fn harvest_urls_returns_empty_when_gau_not_installed() {
    use aegis_exploiter::ToolWrapper;
    if aegis_exploiter::GauWrapper.is_available() {
        return;
    }
    let result = phase_recon::harvest_urls("http://localhost:8080");
    assert!(result.is_empty());
}

#[test]
fn enumerate_subdomains_returns_empty_when_amass_not_installed() {
    use aegis_exploiter::ToolWrapper;
    if aegis_exploiter::AmassWrapper.is_available() {
        return;
    }
    let result = phase_recon::enumerate_subdomains("http://localhost:8080");
    assert!(result.is_empty());
}

#[test]
fn scan_secrets_returns_empty_when_trufflehog_not_installed() {
    use aegis_exploiter::ToolWrapper;
    if aegis_exploiter::TrufflehogWrapper.is_available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let result = phase_recon::scan_secrets(tmp.path());
    assert!(result.is_empty());
}

#[test]
fn parse_crtsh_response_extracts_subdomains() {
    let json = r#"[
        {"name_value": "www.example.com"},
        {"name_value": "api.example.com\nmail.example.com"},
        {"name_value": "*.example.com"}
    ]"#;
    let subs = phase_recon::parse_crtsh_response(json);
    assert_eq!(subs.len(), 4);
    assert!(subs.contains(&"www.example.com".to_string()));
    assert!(subs.contains(&"api.example.com".to_string()));
    assert!(subs.contains(&"mail.example.com".to_string()));
    assert!(subs.contains(&"example.com".to_string()));
}

#[test]
fn parse_crtsh_response_deduplicates() {
    let json = r#"[
        {"name_value": "api.example.com"},
        {"name_value": "api.example.com"},
        {"name_value": "www.example.com"}
    ]"#;
    let subs = phase_recon::parse_crtsh_response(json);
    assert_eq!(subs.len(), 2);
}

#[test]
fn parse_crtsh_response_empty_json() {
    let subs = phase_recon::parse_crtsh_response("[]");
    assert!(subs.is_empty());
}

#[test]
fn parse_crtsh_response_invalid_json() {
    let subs = phase_recon::parse_crtsh_response("not json");
    assert!(subs.is_empty());
}

#[test]
fn parse_crtsh_response_strips_wildcard_prefix() {
    let json = r#"[{"name_value": "*.sub.example.com"}]"#;
    let subs = phase_recon::parse_crtsh_response(json);
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0], "sub.example.com");
}

#[test]
fn crtsh_to_operations_creates_service_nodes() {
    let subdomains = vec!["ct.example.com".to_string(), "log.example.com".to_string()];
    let mut seq = 0u64;
    let ops = phase_recon::crtsh_to_operations(&subdomains, &mut seq);

    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);

    match &ops[0].operation {
        GraphOperation::AddNode {
            node_type,
            properties,
        } => {
            assert_eq!(*node_type, NodeType::Service);
            let map: std::collections::HashMap<&str, &str> = properties
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            assert_eq!(map["hostname"], "ct.example.com");
            assert_eq!(map["source"], "crtsh");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn crtsh_to_operations_empty_returns_empty() {
    let subdomains: Vec<String> = Vec::new();
    let mut seq = 0u64;
    let ops = phase_recon::crtsh_to_operations(&subdomains, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn parse_securitytrails_response_creates_fqdns() {
    let json = r#"{"subdomains": ["www", "api", "mail"], "endpoint": "/v1/domain/example.com/subdomains"}"#;
    let subs = phase_recon::parse_securitytrails_response(json, "example.com");
    assert_eq!(subs.len(), 3);
    assert_eq!(subs[0], "www.example.com");
    assert_eq!(subs[1], "api.example.com");
    assert_eq!(subs[2], "mail.example.com");
}

#[test]
fn parse_securitytrails_response_filters_empty() {
    let json = r#"{"subdomains": ["www", "", "api"]}"#;
    let subs = phase_recon::parse_securitytrails_response(json, "example.com");
    assert_eq!(subs.len(), 2);
    assert_eq!(subs[0], "www.example.com");
    assert_eq!(subs[1], "api.example.com");
}

#[test]
fn parse_securitytrails_response_empty_array() {
    let json = r#"{"subdomains": []}"#;
    let subs = phase_recon::parse_securitytrails_response(json, "example.com");
    assert!(subs.is_empty());
}

#[test]
fn parse_securitytrails_response_invalid_json() {
    let subs = phase_recon::parse_securitytrails_response("not json", "example.com");
    assert!(subs.is_empty());
}

#[test]
fn parse_securitytrails_response_missing_field() {
    let json = r#"{"endpoint": "/v1/domain/example.com/subdomains"}"#;
    let subs = phase_recon::parse_securitytrails_response(json, "example.com");
    assert!(subs.is_empty());
}

#[test]
fn securitytrails_to_operations_creates_service_nodes() {
    let subdomains = vec!["api.example.com".to_string(), "dns.example.com".to_string()];
    let mut seq = 0u64;
    let ops = phase_recon::securitytrails_to_operations(&subdomains, &mut seq);

    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);

    match &ops[0].operation {
        GraphOperation::AddNode {
            node_type,
            properties,
        } => {
            assert_eq!(*node_type, NodeType::Service);
            let map: std::collections::HashMap<&str, &str> = properties
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            assert_eq!(map["hostname"], "api.example.com");
            assert_eq!(map["source"], "securitytrails");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn query_securitytrails_skips_without_api_key() {
    // SECURITYTRAILS_API_KEY is not set in CI/test environments
    if std::env::var("SECURITYTRAILS_API_KEY").is_ok() {
        return;
    }
    let result = phase_recon::query_securitytrails("http://example.com");
    assert!(result.is_empty());
}
