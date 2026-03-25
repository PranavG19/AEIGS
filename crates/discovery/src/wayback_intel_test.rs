use super::wayback_intel::*;
use std::collections::HashSet;

fn make_record(url: &str, timestamp: &str, mime: &str, status: u16) -> CdxRecord {
    CdxRecord {
        url: url.to_string(),
        timestamp: timestamp.to_string(),
        mime_type: mime.to_string(),
        status_code: status,
        digest: "abc123".to_string(),
    }
}

#[test]
fn test_cdx_query_url_generation() {
    let intel = WaybackIntel::new("https://example.com");
    let url = intel.cdx_query_url(1000);
    assert!(url.contains("web.archive.org/cdx/search/cdx"));
    assert!(url.contains("example.com"));
    assert!(url.contains("limit=1000"));
}

#[test]
fn test_parse_cdx_response_valid() {
    let intel = WaybackIntel::new("https://example.com");
    let json = r#"[
        ["original","timestamp","mimetype","statuscode","digest"],
        ["https://example.com/page","20200101120000","text/html","200","abc123"],
        ["https://example.com/api","20210315080000","application/json","200","def456"]
    ]"#;

    let records = intel.parse_cdx_response(json);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].url, "https://example.com/page");
    assert_eq!(records[0].timestamp, "20200101120000");
    assert_eq!(records[0].status_code, 200);
    assert_eq!(records[1].url, "https://example.com/api");
}

#[test]
fn test_parse_cdx_response_empty() {
    let intel = WaybackIntel::new("https://example.com");
    assert!(intel.parse_cdx_response("").is_empty());
    assert!(intel.parse_cdx_response("[]").is_empty());
    assert!(intel.parse_cdx_response("invalid").is_empty());
}

#[test]
fn test_removed_endpoint_detection() {
    let intel = WaybackIntel::new("https://example.com");
    let records = vec![
        make_record("https://example.com/old-page", "20200101", "text/html", 200),
        make_record(
            "https://example.com/still-here",
            "20200101",
            "text/html",
            200,
        ),
    ];
    let live: HashSet<String> = ["https://example.com/still-here".to_string()].into();

    let result = intel.analyze(&records, &live);
    assert!(result
        .removed_endpoints
        .contains(&"https://example.com/old-page".to_string()));
    assert!(!result
        .removed_endpoints
        .contains(&"https://example.com/still-here".to_string()));
}

#[test]
fn test_admin_panel_detection_still_live() {
    let intel = WaybackIntel::new("https://example.com");
    let records = vec![make_record(
        "https://example.com/admin/login",
        "20200601",
        "text/html",
        200,
    )];
    let live: HashSet<String> = ["https://example.com/admin/login".to_string()].into();

    let result = intel.analyze(&records, &live);
    let admin_finding = result
        .findings
        .iter()
        .find(|f| matches!(f.category, WaybackFindingCategory::AdminPanelHidden))
        .expect("should detect admin panel");
    assert_eq!(admin_finding.severity, WaybackSeverity::High);
    assert!(admin_finding.description.contains("STILL ACCESSIBLE"));
}

#[test]
fn test_admin_panel_detection_removed() {
    let intel = WaybackIntel::new("https://example.com");
    let records = vec![make_record(
        "https://example.com/dashboard",
        "20200601",
        "text/html",
        200,
    )];
    let live: HashSet<String> = HashSet::new();

    let result = intel.analyze(&records, &live);
    let admin_finding = result
        .findings
        .iter()
        .find(|f| matches!(f.category, WaybackFindingCategory::AdminPanelHidden));
    assert!(admin_finding.is_some());
    assert_eq!(admin_finding.unwrap().severity, WaybackSeverity::Medium);
}

#[test]
fn test_old_api_version_detection() {
    let intel = WaybackIntel::new("https://example.com");
    let records = vec![
        make_record(
            "https://example.com/api/v1/users",
            "20190101",
            "application/json",
            200,
        ),
        make_record(
            "https://example.com/api/v2/users",
            "20210101",
            "application/json",
            200,
        ),
    ];
    let live: HashSet<String> = HashSet::new();

    let result = intel.analyze(&records, &live);
    assert!(result.old_api_versions.len() >= 2);
    assert!(result
        .findings
        .iter()
        .any(|f| matches!(f.category, WaybackFindingCategory::OldApiVersion)));
}

#[test]
fn test_sensitive_file_detection() {
    let intel = WaybackIntel::new("https://example.com");
    let records = vec![
        make_record("https://example.com/.env", "20200101", "text/plain", 200),
        make_record(
            "https://example.com/config/database.yml",
            "20200101",
            "text/yaml",
            200,
        ),
        make_record(
            "https://example.com/backup.sql",
            "20200101",
            "application/sql",
            200,
        ),
    ];
    let live: HashSet<String> = HashSet::new();

    let result = intel.analyze(&records, &live);
    let config_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| matches!(f.category, WaybackFindingCategory::ConfigFileExposed))
        .collect();
    assert!(config_findings.len() >= 3);

    let env_finding = config_findings.iter().find(|f| f.url.contains(".env"));
    assert!(env_finding.is_some());
    assert_eq!(env_finding.unwrap().severity, WaybackSeverity::Critical);
}

#[test]
fn test_tech_stack_change_detection() {
    let intel = WaybackIntel::new("https://example.com");
    let records = vec![
        make_record(
            "https://example.com/wp-content/themes/theme.css",
            "20190515",
            "text/css",
            200,
        ),
        make_record(
            "https://example.com/_next/static/chunk.js",
            "20210301",
            "application/javascript",
            200,
        ),
    ];
    let live: HashSet<String> = HashSet::new();

    let result = intel.analyze(&records, &live);
    assert!(!result.tech_stack_timeline.is_empty());
    let tech_change = result
        .findings
        .iter()
        .find(|f| matches!(f.category, WaybackFindingCategory::TechStackChange));
    assert!(tech_change.is_some());
}

#[test]
fn test_snapshot_secret_scanning() {
    let intel = WaybackIntel::new("https://example.com");
    let body = r#"
        <script>
            const config = {
                apiKey: "AKIAIOSFODNN7REALKEY",
                dbUrl: "postgres://admin:secret@db.internal:5432/prod"
            };
        </script>
    "#;

    let findings = intel.scan_snapshot_for_secrets("https://example.com/config.js", body);
    assert!(findings.len() >= 2);
    assert!(findings.iter().any(|f| f.description.contains("AWS")));
    assert!(findings
        .iter()
        .any(|f| f.description.contains("PostgreSQL")));
}

#[test]
fn test_snapshot_no_secrets() {
    let intel = WaybackIntel::new("https://example.com");
    let body = "<html><body>Hello World</body></html>";
    let findings = intel.scan_snapshot_for_secrets("https://example.com/", body);
    assert!(findings.is_empty());
}

#[test]
fn test_directory_listing_detection() {
    let intel = WaybackIntel::new("https://example.com");
    let records = vec![make_record(
        "https://example.com/uploads/",
        "20200101",
        "text/html",
        200,
    )];
    let live: HashSet<String> = HashSet::new();

    let result = intel.analyze(&records, &live);
    assert!(result
        .findings
        .iter()
        .any(|f| matches!(f.category, WaybackFindingCategory::DirectoryListing)));
}

#[test]
fn test_non_200_records_ignored() {
    let intel = WaybackIntel::new("https://example.com");
    let records = vec![
        make_record("https://example.com/admin", "20200101", "text/html", 403),
        make_record("https://example.com/.env", "20200101", "text/plain", 404),
    ];
    let live: HashSet<String> = HashSet::new();

    let result = intel.analyze(&records, &live);
    assert!(result.findings.is_empty());
}

#[test]
fn test_unique_url_count() {
    let intel = WaybackIntel::new("https://example.com");
    let records = vec![
        make_record("https://example.com/page", "20200101", "text/html", 200),
        make_record("https://example.com/page", "20210101", "text/html", 200),
        make_record("https://example.com/other", "20200601", "text/html", 200),
    ];
    let live: HashSet<String> = HashSet::new();

    let result = intel.analyze(&records, &live);
    assert_eq!(result.total_snapshots, 3);
    assert_eq!(result.unique_urls, 2);
}

#[test]
fn test_severity_display() {
    assert_eq!(WaybackSeverity::Critical.to_string(), "critical");
    assert_eq!(WaybackSeverity::High.to_string(), "high");
    assert_eq!(WaybackSeverity::Medium.to_string(), "medium");
    assert_eq!(WaybackSeverity::Low.to_string(), "low");
    assert_eq!(WaybackSeverity::Info.to_string(), "info");
}

#[test]
fn test_category_display() {
    assert_eq!(
        WaybackFindingCategory::RemovedEndpoint.to_string(),
        "Removed Endpoint"
    );
    assert_eq!(
        WaybackFindingCategory::AdminPanelHidden.to_string(),
        "Hidden Admin Panel"
    );
    assert_eq!(
        WaybackFindingCategory::SecretInSnapshot.to_string(),
        "Secret in Snapshot"
    );
}

#[test]
fn test_comprehensive_analysis() {
    let intel = WaybackIntel::new("https://example.com");
    let records = vec![
        make_record(
            "https://example.com/wp-content/style.css",
            "20180101",
            "text/css",
            200,
        ),
        make_record(
            "https://example.com/api/v1/users",
            "20190101",
            "application/json",
            200,
        ),
        make_record(
            "https://example.com/_next/static/app.js",
            "20210101",
            "application/javascript",
            200,
        ),
        make_record(
            "https://example.com/api/v2/users",
            "20210101",
            "application/json",
            200,
        ),
        make_record(
            "https://example.com/admin/settings",
            "20200601",
            "text/html",
            200,
        ),
        make_record(
            "https://example.com/config.yml",
            "20200101",
            "text/yaml",
            200,
        ),
        make_record("https://example.com/assets/", "20200101", "text/html", 200),
    ];
    let live: HashSet<String> = [
        "https://example.com/_next/static/app.js".to_string(),
        "https://example.com/api/v2/users".to_string(),
    ]
    .into();

    let result = intel.analyze(&records, &live);
    assert!(result.findings.len() >= 4);
    assert!(!result.tech_stack_timeline.is_empty());
    assert!(!result.old_api_versions.is_empty());
}
