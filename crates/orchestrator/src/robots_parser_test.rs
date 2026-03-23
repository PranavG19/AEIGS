use crate::robots_parser::*;
use aegis_protocol::finding::VulnerabilityClass;

#[test]
fn parse_robots_txt_extracts_disallow() {
    let content = "User-agent: *\nDisallow: /admin\nDisallow: /api/internal\n";
    let paths = parse_robots_txt(content);
    assert!(paths.contains(&"/admin".to_string()));
    assert!(paths.contains(&"/api/internal".to_string()));
}

#[test]
fn parse_robots_txt_extracts_allow() {
    let content = "User-agent: *\nAllow: /public\nDisallow: /private\n";
    let paths = parse_robots_txt(content);
    assert!(paths.contains(&"/public".to_string()));
    assert!(paths.contains(&"/private".to_string()));
}

#[test]
fn parse_robots_txt_extracts_sitemap() {
    let content = "Sitemap: https://example.com/sitemap.xml\n";
    let paths = parse_robots_txt(content);
    assert!(paths.contains(&"https://example.com/sitemap.xml".to_string()));
}

#[test]
fn parse_robots_txt_skips_comments_and_empty() {
    let content = "# comment\n\nUser-agent: *\nDisallow: /secret\n";
    let paths = parse_robots_txt(content);
    assert_eq!(paths, vec!["/secret"]);
}

#[test]
fn parse_robots_txt_skips_root_disallow() {
    let content = "User-agent: *\nDisallow: /\nDisallow: /admin\n";
    let paths = parse_robots_txt(content);
    assert_eq!(paths, vec!["/admin"]);
}

#[test]
fn parse_robots_txt_deduplicates() {
    let content = "User-agent: *\nDisallow: /admin\nDisallow: /admin\n";
    let paths = parse_robots_txt(content);
    assert_eq!(paths.iter().filter(|p| *p == "/admin").count(), 1);
}

#[test]
fn parse_robots_txt_preserves_path_case() {
    let content = "Disallow: /API/Internal\nAllow: /Public/Docs\n";
    let paths = parse_robots_txt(content);
    assert!(paths.contains(&"/API/Internal".to_string()));
    assert!(paths.contains(&"/Public/Docs".to_string()));
}

#[test]
fn parse_robots_txt_empty() {
    let paths = parse_robots_txt("");
    assert!(paths.is_empty());
}

#[test]
fn parse_sitemap_urls_extracts_locs() {
    let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset>
  <url><loc>https://example.com/page1</loc></url>
  <url><loc>https://example.com/page2</loc></url>
</urlset>"#;
    let urls = parse_sitemap_urls(content);
    assert_eq!(urls.len(), 2);
    assert!(urls.contains(&"https://example.com/page1".to_string()));
    assert!(urls.contains(&"https://example.com/page2".to_string()));
}

#[test]
fn parse_sitemap_urls_empty() {
    let urls = parse_sitemap_urls("");
    assert!(urls.is_empty());
}

#[test]
fn parse_sitemap_urls_no_locs() {
    let content = "<urlset></urlset>";
    let urls = parse_sitemap_urls(content);
    assert!(urls.is_empty());
}

#[test]
fn discovered_paths_to_operations_creates_nodes() {
    let paths = vec!["/admin".to_string(), "/api".to_string()];
    let mut seq = 0;
    let ops = discovered_paths_to_operations(&paths, "robots.txt", &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
    for op in &ops {
        match &op.operation {
            aegis_protocol::operation::GraphOperation::AddNode {
                node_type,
                properties,
            } => {
                assert_eq!(*node_type, aegis_protocol::node::NodeType::Endpoint);
                let source = properties.iter().find(|(k, _)| k == "source").unwrap();
                assert_eq!(source.1, "robots.txt");
            }
            _ => panic!("expected AddNode"),
        }
    }
}

#[test]
fn discovered_paths_to_operations_empty() {
    let mut seq = 3;
    let ops = discovered_paths_to_operations(&[], "sitemap", &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 3);
}

#[test]
fn fetch_robots_txt_skips_localhost() {
    let paths = fetch_robots_txt("http://localhost:8080");
    assert!(paths.is_empty());
}

#[test]
fn fetch_sitemap_skips_localhost() {
    let urls = fetch_sitemap("http://localhost:8080");
    assert!(urls.is_empty());
}

#[test]
fn analyze_robots_security_detects_admin_panel() {
    let content = "Disallow: /admin\nDisallow: /dashboard\n";
    let issues = analyze_robots_security(content);
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::AdminPanelExposed(p) if p == "/admin"
    )));
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::AdminPanelExposed(p) if p == "/dashboard"
    )));
}

#[test]
fn analyze_robots_security_detects_panel_variant() {
    let content = "Disallow: /control-panel\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::AdminPanelExposed(_)))
    );
}

#[test]
fn analyze_robots_security_detects_manager_variant() {
    let content = "Disallow: /manager\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::AdminPanelExposed(_)))
    );
}

#[test]
fn analyze_robots_security_detects_api_endpoint() {
    let content = "Disallow: /api/internal\nDisallow: /v1/users\n";
    let issues = analyze_robots_security(content);
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::ApiEndpointLeaked(p) if p == "/api/internal"
    )));
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::ApiEndpointLeaked(p) if p == "/v1/users"
    )));
}

#[test]
fn analyze_robots_security_detects_graphql() {
    let content = "Disallow: /graphql\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::ApiEndpointLeaked(_)))
    );
}

#[test]
fn analyze_robots_security_detects_rest_api() {
    let content = "Disallow: /rest/api\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::ApiEndpointLeaked(_)))
    );
}

#[test]
fn analyze_robots_security_detects_backup_files() {
    let content = "Disallow: /backup\nDisallow: /db.sql\nDisallow: /site.bak\n";
    let issues = analyze_robots_security(content);
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::BackupFileExposed(p) if p == "/backup"
    )));
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::BackupFileExposed(p) if p == "/db.sql"
    )));
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::BackupFileExposed(p) if p == "/site.bak"
    )));
}

#[test]
fn analyze_robots_security_detects_dump_files() {
    let content = "Disallow: /data.dump\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::BackupFileExposed(_)))
    );
}

#[test]
fn analyze_robots_security_detects_archive_files() {
    let content = "Disallow: /backup.zip\nDisallow: /archive.tar\n";
    let issues = analyze_robots_security(content);
    let backup_count = issues
        .iter()
        .filter(|i| matches!(i, RobotsSecurityIssue::BackupFileExposed(_)))
        .count();
    assert_eq!(backup_count, 2);
}

#[test]
fn analyze_robots_security_detects_crawl_delay_abuse() {
    let content = "Crawl-delay: 100\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::CrawlDelayAbuse(100)))
    );
}

#[test]
fn analyze_robots_security_ignores_normal_crawl_delay() {
    let content = "Crawl-delay: 5\n";
    let issues = analyze_robots_security(content);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::CrawlDelayAbuse(_)))
    );
}

#[test]
fn analyze_robots_security_detects_wildcard_allow() {
    let content = "Allow: *\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::WildcardAllowAll))
    );
}

#[test]
fn analyze_robots_security_detects_sitemap_leak() {
    let content = "Sitemap: https://example.com/sitemap.xml\n";
    let issues = analyze_robots_security(content);
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::SitemapLocationLeaked(u) if u == "https://example.com/sitemap.xml"
    )));
}

#[test]
fn analyze_robots_security_detects_version_control() {
    let content = "Disallow: /.git\nDisallow: /.svn\nDisallow: /.hg\n";
    let issues = analyze_robots_security(content);
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::VersionControlExposed(p) if p == "/.git"
    )));
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::VersionControlExposed(p) if p == "/.svn"
    )));
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::VersionControlExposed(p) if p == "/.hg"
    )));
}

#[test]
fn analyze_robots_security_detects_bzr() {
    let content = "Disallow: /.bzr\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::VersionControlExposed(_)))
    );
}

#[test]
fn analyze_robots_security_detects_database_paths() {
    let content = "Disallow: /phpmyadmin\nDisallow: /adminer\n";
    let issues = analyze_robots_security(content);
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::DatabasePathExposed(p) if p == "/phpmyadmin"
    )));
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::DatabasePathExposed(p) if p == "/adminer"
    )));
}

#[test]
fn analyze_robots_security_detects_pgadmin() {
    let content = "Disallow: /pgadmin\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::DatabasePathExposed(_)))
    );
}

#[test]
fn analyze_robots_security_detects_mysql_path() {
    let content = "Disallow: /mysql\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::DatabasePathExposed(_)))
    );
}

#[test]
fn analyze_robots_security_detects_staging_environments() {
    let content = "Disallow: /staging\nDisallow: /dev\nDisallow: /test\n";
    let issues = analyze_robots_security(content);
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::StagingEnvironmentLeaked(p) if p == "/staging"
    )));
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::StagingEnvironmentLeaked(p) if p == "/dev"
    )));
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::StagingEnvironmentLeaked(p) if p == "/test"
    )));
}

#[test]
fn analyze_robots_security_detects_uat() {
    let content = "Disallow: /uat\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::StagingEnvironmentLeaked(_)))
    );
}

#[test]
fn analyze_robots_security_detects_qa() {
    let content = "Disallow: /qa\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::StagingEnvironmentLeaked(_)))
    );
}

#[test]
fn analyze_robots_security_detects_demo() {
    let content = "Disallow: /demo\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::StagingEnvironmentLeaked(_)))
    );
}

#[test]
fn analyze_robots_security_detects_sensitive_paths() {
    let content = "Disallow: /secret\nDisallow: /private\nDisallow: /confidential\n";
    let issues = analyze_robots_security(content);
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::SensitivePathDisallowed(p) if p == "/secret"
    )));
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::SensitivePathDisallowed(p) if p == "/private"
    )));
    assert!(issues.iter().any(|i| matches!(
        i,
        RobotsSecurityIssue::SensitivePathDisallowed(p) if p == "/confidential"
    )));
}

#[test]
fn analyze_robots_security_detects_config_files() {
    let content = "Disallow: /config.php\nDisallow: /.env\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::SensitivePathDisallowed(_)))
    );
}

#[test]
fn analyze_robots_security_detects_credentials() {
    let content = "Disallow: /credentials.txt\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::SensitivePathDisallowed(_)))
    );
}

#[test]
fn analyze_robots_security_empty_content() {
    let issues = analyze_robots_security("");
    assert!(issues.is_empty());
}

#[test]
fn analyze_robots_security_comments_only() {
    let content = "# This is a comment\n# Another comment\n";
    let issues = analyze_robots_security(content);
    assert!(issues.is_empty());
}

#[test]
fn analyze_robots_security_skips_empty_disallow() {
    let content = "Disallow:\n";
    let issues = analyze_robots_security(content);
    assert!(issues.is_empty());
}

#[test]
fn analyze_robots_security_case_insensitive_admin() {
    let content = "Disallow: /ADMIN\nDisallow: /Admin\n";
    let issues = analyze_robots_security(content);
    let admin_count = issues
        .iter()
        .filter(|i| matches!(i, RobotsSecurityIssue::AdminPanelExposed(_)))
        .count();
    assert_eq!(admin_count, 2);
}

#[test]
fn analyze_robots_security_case_insensitive_api() {
    let content = "Disallow: /API/internal\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::ApiEndpointLeaked(_)))
    );
}

#[test]
fn analyze_robots_security_multiple_issue_types() {
    let content = "Disallow: /admin\nDisallow: /api/v1\nDisallow: /.git\nSitemap: https://example.com/sitemap.xml\n";
    let issues = analyze_robots_security(content);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::AdminPanelExposed(_)))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::ApiEndpointLeaked(_)))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::VersionControlExposed(_)))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RobotsSecurityIssue::SitemapLocationLeaked(_)))
    );
}

#[test]
fn robots_security_severity_admin_panel() {
    let issue = RobotsSecurityIssue::AdminPanelExposed("/admin".to_string());
    assert_eq!(robots_security_severity(&issue), 0.8);
}

#[test]
fn robots_security_severity_database_path() {
    let issue = RobotsSecurityIssue::DatabasePathExposed("/phpmyadmin".to_string());
    assert_eq!(robots_security_severity(&issue), 0.8);
}

#[test]
fn robots_security_severity_backup_file() {
    let issue = RobotsSecurityIssue::BackupFileExposed("/backup.sql".to_string());
    assert_eq!(robots_security_severity(&issue), 0.75);
}

#[test]
fn robots_security_severity_version_control() {
    let issue = RobotsSecurityIssue::VersionControlExposed("/.git".to_string());
    assert_eq!(robots_security_severity(&issue), 0.7);
}

#[test]
fn robots_security_severity_api_endpoint() {
    let issue = RobotsSecurityIssue::ApiEndpointLeaked("/api/internal".to_string());
    assert_eq!(robots_security_severity(&issue), 0.6);
}

#[test]
fn robots_security_severity_sensitive_path() {
    let issue = RobotsSecurityIssue::SensitivePathDisallowed("/secret".to_string());
    assert_eq!(robots_security_severity(&issue), 0.6);
}

#[test]
fn robots_security_severity_staging() {
    let issue = RobotsSecurityIssue::StagingEnvironmentLeaked("/staging".to_string());
    assert_eq!(robots_security_severity(&issue), 0.5);
}

#[test]
fn robots_security_severity_sitemap() {
    let issue =
        RobotsSecurityIssue::SitemapLocationLeaked("https://example.com/sitemap.xml".to_string());
    assert_eq!(robots_security_severity(&issue), 0.4);
}

#[test]
fn robots_security_severity_wildcard() {
    let issue = RobotsSecurityIssue::WildcardAllowAll;
    assert_eq!(robots_security_severity(&issue), 0.4);
}

#[test]
fn robots_security_severity_crawl_delay() {
    let issue = RobotsSecurityIssue::CrawlDelayAbuse(100);
    assert_eq!(robots_security_severity(&issue), 0.3);
}

#[test]
fn robots_security_to_operations_creates_findings() {
    let issues = vec![
        RobotsSecurityIssue::AdminPanelExposed("/admin".to_string()),
        RobotsSecurityIssue::ApiEndpointLeaked("/api".to_string()),
    ];
    let mut seq = 0;
    let ops = robots_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn robots_security_to_operations_empty() {
    let mut seq = 5;
    let ops = robots_security_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn robots_security_to_operations_uses_correct_vuln_class() {
    let issues = vec![RobotsSecurityIssue::AdminPanelExposed("/admin".to_string())];
    let mut seq = 0;
    let ops = robots_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                VulnerabilityClass::InformationDisclosure
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn robots_security_issue_display_admin_panel() {
    let issue = RobotsSecurityIssue::AdminPanelExposed("/admin".to_string());
    assert_eq!(
        issue.to_string(),
        "Admin panel path exposed in robots.txt: /admin"
    );
}

#[test]
fn robots_security_issue_display_api_endpoint() {
    let issue = RobotsSecurityIssue::ApiEndpointLeaked("/api/internal".to_string());
    assert_eq!(
        issue.to_string(),
        "API endpoint leaked via robots.txt: /api/internal"
    );
}

#[test]
fn robots_security_issue_display_backup_file() {
    let issue = RobotsSecurityIssue::BackupFileExposed("/backup.sql".to_string());
    assert_eq!(issue.to_string(), "Backup file path exposed: /backup.sql");
}

#[test]
fn robots_security_issue_display_crawl_delay() {
    let issue = RobotsSecurityIssue::CrawlDelayAbuse(100);
    assert_eq!(
        issue.to_string(),
        "Abusive crawl-delay detected: 100 seconds"
    );
}

#[test]
fn robots_security_issue_display_wildcard() {
    let issue = RobotsSecurityIssue::WildcardAllowAll;
    assert_eq!(
        issue.to_string(),
        "Wildcard Allow: * directive may override disallows"
    );
}

#[test]
fn robots_security_issue_display_sitemap() {
    let issue =
        RobotsSecurityIssue::SitemapLocationLeaked("https://example.com/sitemap.xml".to_string());
    assert_eq!(
        issue.to_string(),
        "Sitemap URL reveals site structure: https://example.com/sitemap.xml"
    );
}

#[test]
fn robots_security_issue_display_version_control() {
    let issue = RobotsSecurityIssue::VersionControlExposed("/.git".to_string());
    assert_eq!(issue.to_string(), "Version control path exposed: /.git");
}

#[test]
fn robots_security_issue_display_database_path() {
    let issue = RobotsSecurityIssue::DatabasePathExposed("/phpmyadmin".to_string());
    assert_eq!(
        issue.to_string(),
        "Database admin path exposed: /phpmyadmin"
    );
}

#[test]
fn robots_security_issue_display_staging() {
    let issue = RobotsSecurityIssue::StagingEnvironmentLeaked("/staging".to_string());
    assert_eq!(
        issue.to_string(),
        "Staging/dev environment path leaked: /staging"
    );
}

#[test]
fn robots_security_issue_display_sensitive_path() {
    let issue = RobotsSecurityIssue::SensitivePathDisallowed("/secret".to_string());
    assert_eq!(
        issue.to_string(),
        "Sensitive path disallowed reveals endpoint: /secret"
    );
}
