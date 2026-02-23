use crate::backup_scanner::{
    BackupFinding, BackupScanError, BackupScanner, BackupType, classify_path,
    generate_backup_variants,
};
use crate::graph_ops::backup_findings_to_operations;

use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier};

#[test]
fn sensitive_paths_list_covers_env_files() {
    let paths = super::backup_scanner::SENSITIVE_PATHS;
    let env_paths: Vec<&&str> = paths.iter().filter(|p| p.contains(".env")).collect();
    assert!(env_paths.len() >= 7);
    assert!(paths.contains(&"/.env"));
    assert!(paths.contains(&"/.env.bak"));
    assert!(paths.contains(&"/.env.local"));
    assert!(paths.contains(&"/.env.production"));
    assert!(paths.contains(&"/.env.development"));
    assert!(paths.contains(&"/.env.staging"));
    assert!(paths.contains(&"/.env.test"));
}

#[test]
fn sensitive_paths_list_covers_source_control() {
    let paths = super::backup_scanner::SENSITIVE_PATHS;
    assert!(paths.contains(&"/.git/config"));
    assert!(paths.contains(&"/.git/HEAD"));
    assert!(paths.contains(&"/.svn/entries"));
    assert!(paths.contains(&"/.svn/wc.db"));
    assert!(paths.contains(&"/.hg/"));
}

#[test]
fn sensitive_paths_list_covers_database_dumps() {
    let paths = super::backup_scanner::SENSITIVE_PATHS;
    assert!(paths.contains(&"/backup.sql"));
    assert!(paths.contains(&"/dump.sql"));
    assert!(paths.contains(&"/db.sql"));
    assert!(paths.contains(&"/database.sql"));
}

#[test]
fn sensitive_paths_list_covers_config_files() {
    let paths = super::backup_scanner::SENSITIVE_PATHS;
    assert!(paths.contains(&"/web.config"));
    assert!(paths.contains(&"/.htaccess"));
    assert!(paths.contains(&"/.htpasswd"));
    assert!(paths.contains(&"/.aws/credentials"));
    assert!(paths.contains(&"/.docker/config.json"));
    assert!(paths.contains(&"/config/database.yml"));
    assert!(paths.contains(&"/config/secrets.yml"));
}

#[test]
fn sensitive_paths_list_covers_debug_endpoints() {
    let paths = super::backup_scanner::SENSITIVE_PATHS;
    assert!(paths.contains(&"/phpinfo.php"));
    assert!(paths.contains(&"/info.php"));
    assert!(paths.contains(&"/server-status"));
    assert!(paths.contains(&"/server-info"));
}

#[test]
fn sensitive_paths_list_covers_package_manifests() {
    let paths = super::backup_scanner::SENSITIVE_PATHS;
    assert!(paths.contains(&"/composer.json"));
    assert!(paths.contains(&"/package.json"));
    assert!(paths.contains(&"/Gemfile"));
    assert!(paths.contains(&"/requirements.txt"));
    assert!(paths.contains(&"/go.mod"));
}

#[test]
fn generate_backup_variants_empty_input() {
    let variants = generate_backup_variants(&[]);
    assert!(variants.is_empty());
}

#[test]
fn generate_backup_variants_single_path() {
    let paths = vec!["/api/users".to_string()];
    let variants = generate_backup_variants(&paths);
    assert_eq!(variants.len(), 8);
    assert!(variants.contains(&"/api/users.bak".to_string()));
    assert!(variants.contains(&"/api/users.old".to_string()));
    assert!(variants.contains(&"/api/users.orig".to_string()));
    assert!(variants.contains(&"/api/users~".to_string()));
    assert!(variants.contains(&"/api/users.save".to_string()));
    assert!(variants.contains(&"/api/users.swp".to_string()));
    assert!(variants.contains(&"/api/users.tmp".to_string()));
    assert!(variants.contains(&"/api/users.copy".to_string()));
}

#[test]
fn generate_backup_variants_multiple_paths() {
    let paths = vec!["/index.html".to_string(), "/config.php".to_string()];
    let variants = generate_backup_variants(&paths);
    assert_eq!(variants.len(), 16);
    assert!(variants.contains(&"/index.html.bak".to_string()));
    assert!(variants.contains(&"/config.php.old".to_string()));
}

#[test]
fn classify_env_files() {
    assert_eq!(classify_path("/.env"), BackupType::EnvironmentFile);
    assert_eq!(classify_path("/.env.bak"), BackupType::EnvironmentFile);
    assert_eq!(classify_path("/.env.local"), BackupType::EnvironmentFile);
    assert_eq!(
        classify_path("/.env.production"),
        BackupType::EnvironmentFile
    );
}

#[test]
fn classify_source_control() {
    assert_eq!(classify_path("/.git/config"), BackupType::SourceControl);
    assert_eq!(classify_path("/.git/HEAD"), BackupType::SourceControl);
    assert_eq!(classify_path("/.svn/entries"), BackupType::SourceControl);
    assert_eq!(classify_path("/.hg/"), BackupType::SourceControl);
}

#[test]
fn classify_database_dumps() {
    assert_eq!(classify_path("/backup.sql"), BackupType::DatabaseDump);
    assert_eq!(classify_path("/dump.sql"), BackupType::DatabaseDump);
    assert_eq!(classify_path("/db.sql"), BackupType::DatabaseDump);
}

#[test]
fn classify_debug_endpoints() {
    assert_eq!(classify_path("/phpinfo.php"), BackupType::DebugEndpoint);
    assert_eq!(classify_path("/debug/vars"), BackupType::DebugEndpoint);
    assert_eq!(classify_path("/info.php"), BackupType::DebugEndpoint);
}

#[test]
fn classify_source_maps() {
    assert_eq!(classify_path("/app.js.map"), BackupType::SourceMap);
    assert_eq!(classify_path("/style.css.map"), BackupType::SourceMap);
}

#[test]
fn classify_ide_files() {
    assert_eq!(classify_path("/.idea/workspace.xml"), BackupType::IdeFile);
    assert_eq!(classify_path("/.vscode/settings.json"), BackupType::IdeFile);
}

#[test]
fn classify_config_files() {
    assert_eq!(classify_path("/web.config"), BackupType::ConfigurationFile);
    assert_eq!(classify_path("/.htaccess"), BackupType::ConfigurationFile);
    assert_eq!(classify_path("/.htpasswd"), BackupType::ConfigurationFile);
    assert_eq!(
        classify_path("/.aws/credentials"),
        BackupType::ConfigurationFile
    );
    assert_eq!(
        classify_path("/config/database.yml"),
        BackupType::ConfigurationFile
    );
    assert_eq!(
        classify_path("/composer.json"),
        BackupType::ConfigurationFile
    );
    assert_eq!(
        classify_path("/package.json"),
        BackupType::ConfigurationFile
    );
}

#[test]
fn classify_backup_extensions() {
    assert_eq!(classify_path("/index.html.bak"), BackupType::BackupFile);
    assert_eq!(classify_path("/config.old"), BackupType::BackupFile);
    assert_eq!(classify_path("/data.orig"), BackupType::BackupFile);
    assert_eq!(classify_path("/file~"), BackupType::BackupFile);
    assert_eq!(classify_path("/notes.swp"), BackupType::BackupFile);
    assert_eq!(classify_path("/page.tmp"), BackupType::BackupFile);
}

#[test]
fn classify_unknown_defaults_to_backup() {
    assert_eq!(classify_path("/random/path"), BackupType::BackupFile);
}

#[test]
fn classify_is_case_insensitive() {
    assert_eq!(classify_path("/.ENV"), BackupType::EnvironmentFile);
    assert_eq!(classify_path("/.GIT/config"), BackupType::SourceControl);
    assert_eq!(classify_path("/BACKUP.SQL"), BackupType::DatabaseDump);
}

#[test]
fn severity_environment_file() {
    assert_eq!(BackupType::EnvironmentFile.default_severity(), 9.0);
}

#[test]
fn severity_source_control() {
    assert_eq!(BackupType::SourceControl.default_severity(), 8.0);
}

#[test]
fn severity_backup_file() {
    assert_eq!(BackupType::BackupFile.default_severity(), 6.0);
}

#[test]
fn severity_configuration_file() {
    assert_eq!(BackupType::ConfigurationFile.default_severity(), 7.0);
}

#[test]
fn severity_database_dump() {
    assert_eq!(BackupType::DatabaseDump.default_severity(), 9.0);
}

#[test]
fn severity_source_map() {
    assert_eq!(BackupType::SourceMap.default_severity(), 5.0);
}

#[test]
fn severity_ide_file() {
    assert_eq!(BackupType::IdeFile.default_severity(), 3.0);
}

#[test]
fn severity_debug_endpoint() {
    assert_eq!(BackupType::DebugEndpoint.default_severity(), 7.0);
}

#[test]
fn scanner_new_succeeds() {
    let scanner = BackupScanner::new();
    assert!(scanner.is_ok());
}

#[test]
fn scan_rejects_non_localhost() {
    let scanner = BackupScanner::new().unwrap();
    let result = scanner.scan("http://example.com", &[]);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        BackupScanError::NonLocalhostTarget(_)
    ));
}

#[test]
fn scan_rejects_empty_url() {
    let scanner = BackupScanner::new().unwrap();
    let result = scanner.scan("", &[]);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        BackupScanError::InvalidUrl(_)
    ));
}

#[test]
fn scan_accepts_localhost() {
    let scanner = BackupScanner::new().unwrap();
    let result = scanner.scan("http://localhost:39999", &[]);
    assert!(result.is_ok());
}

#[test]
fn scan_accepts_127_0_0_1() {
    let scanner = BackupScanner::new().unwrap();
    let result = scanner.scan("http://127.0.0.1:39999", &[]);
    assert!(result.is_ok());
}

#[test]
fn scan_accepts_ipv6_localhost() {
    let scanner = BackupScanner::new().unwrap();
    let result = scanner.scan("http://[::1]:39999", &[]);
    assert!(result.is_ok());
}

#[test]
fn scan_normalizes_trailing_slash() {
    let scanner = BackupScanner::new().unwrap();
    let result = scanner.scan("http://localhost:39999/", &[]);
    assert!(result.is_ok());
}

#[test]
fn backup_findings_to_operations_empty() {
    let ops = backup_findings_to_operations(&[], 0);
    assert!(ops.is_empty());
}

#[test]
fn backup_findings_to_operations_single_finding() {
    let findings = vec![BackupFinding {
        path: "/.env".to_string(),
        status_code: 200,
        content_length: 256,
        finding_type: BackupType::EnvironmentFile,
        severity: 9.0,
    }];

    let ops = backup_findings_to_operations(&findings, 0);
    assert_eq!(ops.len(), 1);

    let entry = &ops[0];
    assert_eq!(entry.sequence_number, 1);
    assert_eq!(entry.module, ModuleIdentifier::Discovery);

    if let GraphOperation::AddNode {
        node_type,
        properties,
    } = &entry.operation
    {
        assert_eq!(*node_type, NodeType::Endpoint);
        let props: std::collections::HashMap<&str, &str> = properties
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(props["path"], "/.env");
        assert_eq!(props["method"], "GET");
        assert_eq!(props["discovery_source"], "backup_scan");
        assert_eq!(props["status_code"], "200");
        assert_eq!(props["content_length"], "256");
        assert_eq!(props["backup_type"], "EnvironmentFile");
        assert_eq!(props["severity"], "9");
        assert_eq!(props["interesting"], "true");
    } else {
        panic!("expected AddNode operation");
    }
}

#[test]
fn backup_findings_to_operations_sequence_numbers() {
    let findings = vec![
        BackupFinding {
            path: "/.env".to_string(),
            status_code: 200,
            content_length: 100,
            finding_type: BackupType::EnvironmentFile,
            severity: 9.0,
        },
        BackupFinding {
            path: "/.git/config".to_string(),
            status_code: 200,
            content_length: 50,
            finding_type: BackupType::SourceControl,
            severity: 8.0,
        },
        BackupFinding {
            path: "/backup.sql".to_string(),
            status_code: 200,
            content_length: 10000,
            finding_type: BackupType::DatabaseDump,
            severity: 9.0,
        },
    ];

    let ops = backup_findings_to_operations(&findings, 10);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
    assert_eq!(ops[2].sequence_number, 13);
}

#[test]
fn backup_findings_to_operations_timestamps_nonzero() {
    let findings = vec![BackupFinding {
        path: "/.env".to_string(),
        status_code: 200,
        content_length: 100,
        finding_type: BackupType::EnvironmentFile,
        severity: 9.0,
    }];

    let ops = backup_findings_to_operations(&findings, 0);
    assert!(ops[0].timestamp_unix_ms > 0);
}

#[test]
fn backup_type_debug_format() {
    assert_eq!(
        format!("{:?}", BackupType::EnvironmentFile),
        "EnvironmentFile"
    );
    assert_eq!(format!("{:?}", BackupType::SourceControl), "SourceControl");
    assert_eq!(format!("{:?}", BackupType::DatabaseDump), "DatabaseDump");
}

#[test]
fn backup_finding_clone() {
    let finding = BackupFinding {
        path: "/.env".to_string(),
        status_code: 200,
        content_length: 100,
        finding_type: BackupType::EnvironmentFile,
        severity: 9.0,
    };
    let cloned = finding.clone();
    assert_eq!(finding, cloned);
}

#[test]
fn scanner_debug_format() {
    let scanner = BackupScanner::new().unwrap();
    let debug = format!("{:?}", scanner);
    assert!(debug.contains("BackupScanner"));
}

#[test]
fn error_display_invalid_url() {
    let err = BackupScanError::InvalidUrl("bad".to_string());
    assert_eq!(format!("{err}"), "invalid URL: bad");
}

#[test]
fn error_display_non_localhost() {
    let err = BackupScanError::NonLocalhostTarget("http://evil.com".to_string());
    assert_eq!(format!("{err}"), "non-localhost target: http://evil.com");
}

#[test]
fn error_display_http_error() {
    let err = BackupScanError::HttpError("timeout".to_string());
    assert_eq!(format!("{err}"), "HTTP error: timeout");
}

#[test]
fn error_is_std_error() {
    let err = BackupScanError::InvalidUrl("test".to_string());
    let _: &dyn std::error::Error = &err;
}
