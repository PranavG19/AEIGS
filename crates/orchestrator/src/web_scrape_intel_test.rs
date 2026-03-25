use super::*;

#[test]
fn dork_operator_display() {
    assert_eq!(DorkOperator::Site.to_string(), "site");
    assert_eq!(DorkOperator::Inurl.to_string(), "inurl");
    assert_eq!(DorkOperator::Filetype.to_string(), "filetype");
    assert_eq!(DorkOperator::Intitle.to_string(), "intitle");
}

#[test]
fn search_dork_to_query_simple() {
    let dork = SearchDork {
        operator: DorkOperator::Site,
        value: "example.com".to_string(),
        extra_terms: vec![],
        category: DorkCategory::ConfigFiles,
    };
    assert_eq!(dork.to_query(), "site:example.com");
}

#[test]
fn search_dork_to_query_with_extras() {
    let dork = SearchDork {
        operator: DorkOperator::Site,
        value: "example.com".to_string(),
        extra_terms: vec!["filetype:env".to_string(), "\"password\"".to_string()],
        category: DorkCategory::Credentials,
    };
    assert_eq!(
        dork.to_query(),
        "site:example.com filetype:env \"password\""
    );
}

#[test]
fn generate_dorks_produces_varied_categories() {
    let dorks = generate_dorks("example.com");
    assert!(dorks.len() > 30);

    let categories: std::collections::HashSet<&DorkCategory> =
        dorks.iter().map(|d| &d.category).collect();
    assert!(categories.contains(&DorkCategory::ConfigFiles));
    assert!(categories.contains(&DorkCategory::Credentials));
    assert!(categories.contains(&DorkCategory::ErrorPages));
    assert!(categories.contains(&DorkCategory::AdminPanels));
    assert!(categories.contains(&DorkCategory::BackupFiles));
    assert!(categories.contains(&DorkCategory::SensitiveDocuments));
    assert!(categories.contains(&DorkCategory::DirectoryListings));
    assert!(categories.contains(&DorkCategory::ApiEndpoints));
}

#[test]
fn generate_dorks_all_contain_domain() {
    let dorks = generate_dorks("target.io");
    for dork in &dorks {
        let query = dork.to_query();
        assert!(
            query.contains("target.io"),
            "Dork query does not contain domain: {query}"
        );
    }
}

#[test]
fn generate_paste_queries_coverage() {
    let queries = generate_paste_queries("example.com");
    assert!(queries.len() >= 6);
    assert!(queries.iter().any(|(s, _)| *s == PasteSource::Pastebin));
    assert!(queries.iter().any(|(s, _)| *s == PasteSource::GithubGist));
    assert!(queries.iter().any(|(s, _)| *s == PasteSource::Ghostbin));
}

#[test]
fn generate_forum_queries_coverage() {
    let queries = generate_forum_queries("example.com");
    assert!(queries.len() >= 5);
    assert!(queries.iter().any(|(p, _)| *p == ForumPlatform::Reddit));
    assert!(queries.iter().any(|(p, _)| *p == ForumPlatform::HackerNews));
    assert!(queries
        .iter()
        .any(|(p, _)| *p == ForumPlatform::StackOverflow));
    assert!(queries
        .iter()
        .any(|(p, _)| *p == ForumPlatform::BugBountyForum));
}

#[test]
fn analyze_job_posting_extracts_tech() {
    let text = "Senior Backend Engineer\n\
                We use Python, Django, PostgreSQL, and Docker.\n\
                Deploy on AWS with Kubernetes.";
    let intel = analyze_job_posting(text, "ExampleCorp", "https://jobs.example.com/1");
    assert!(intel.technologies.contains(&"python".to_string()));
    assert!(intel.technologies.contains(&"django".to_string()));
    assert!(intel.technologies.contains(&"postgres".to_string()));
    assert!(intel.technologies.contains(&"docker".to_string()));
    assert!(intel.technologies.contains(&"aws".to_string()));
    assert!(intel.technologies.contains(&"kubernetes".to_string()));
    assert_eq!(intel.company, "ExampleCorp");
}

#[test]
fn analyze_job_posting_extracts_security_indicators() {
    let text = "Security Engineer\n\
                Join our security team. We run a bug bounty program\n\
                and are SOC 2 compliant. Experience with SIEM and incident response required.";
    let intel = analyze_job_posting(text, "SecureCo", "https://jobs.example.com/2");
    assert!(intel
        .security_indicators
        .contains(&SecurityMaturityIndicator::HasSecurityTeam));
    assert!(intel
        .security_indicators
        .contains(&SecurityMaturityIndicator::HasBugBounty));
    assert!(intel
        .security_indicators
        .contains(&SecurityMaturityIndicator::RequiresCompliance));
    assert!(intel
        .security_indicators
        .contains(&SecurityMaturityIndicator::MentionsSiem));
    assert!(intel
        .security_indicators
        .contains(&SecurityMaturityIndicator::HasIncidentResponse));
}

#[test]
fn analyze_job_posting_extracts_team_size() {
    let text = "Join a team of 15 engineers building cutting-edge products.";
    let intel = analyze_job_posting(text, "Co", "url");
    assert!(intel.team_size_hint.is_some());
    assert!(intel.team_size_hint.unwrap().contains("15"));
}

#[test]
fn analyze_job_posting_no_matches() {
    let text = "General position with no specific requirements listed.";
    let intel = analyze_job_posting(text, "Co", "url");
    assert!(intel.technologies.is_empty());
    assert!(intel.security_indicators.is_empty());
    assert!(intel.team_size_hint.is_none());
}

#[test]
fn extract_document_metadata_author_and_paths() {
    let content = "Author: John Smith\n\
                   Creator: Microsoft Word 2019\n\
                   CreationDate: 2024-01-15\n\
                   ModDate: 2024-02-20\n\
                   Some content from /home/jsmith/documents/report.docx\n\
                   Also references C:\\Users\\JSmith\\Desktop\\notes.txt";
    let meta = extract_document_metadata(content, "report.pdf");
    assert_eq!(meta.author.as_deref(), Some("John Smith"));
    assert_eq!(meta.creator_tool.as_deref(), Some("Microsoft Word 2019"));
    assert_eq!(meta.creation_date.as_deref(), Some("2024-01-15"));
    assert_eq!(meta.modification_date.as_deref(), Some("2024-02-20"));
    assert_eq!(meta.internal_paths.len(), 2);
    assert!(meta
        .internal_paths
        .iter()
        .any(|p| p.contains("/home/jsmith")));
    assert!(meta
        .internal_paths
        .iter()
        .any(|p| p.contains("C:\\Users\\JSmith")));
}

#[test]
fn extract_document_metadata_emails() {
    let content = "Contact: admin@example.com or support@example.com for help.\n\
                   Also cc: devops@internal.example.com";
    let meta = extract_document_metadata(content, "info.txt");
    assert_eq!(meta.email_addresses.len(), 3);
    assert!(meta
        .email_addresses
        .contains(&"admin@example.com".to_string()));
    assert!(meta
        .email_addresses
        .contains(&"support@example.com".to_string()));
}

#[test]
fn extract_document_metadata_software_versions() {
    let content = "Generated by Apache 2.4.49\nPHP 8.1.12 module loaded\nPowered by nginx 1.24.0";
    let meta = extract_document_metadata(content, "server.log");
    assert!(meta.software_versions.len() >= 2);
}

#[test]
fn extract_document_metadata_empty() {
    let meta = extract_document_metadata("", "empty.txt");
    assert!(meta.author.is_none());
    assert!(meta.internal_paths.is_empty());
    assert!(meta.email_addresses.is_empty());
}

#[test]
fn generate_wayback_queries_structure() {
    let queries = generate_wayback_queries("example.com");
    assert!(queries.len() >= 10);
    for q in &queries {
        assert!(q.starts_with("https://web.archive.org/cdx/"));
        assert!(q.contains("example.com"));
    }
}

#[test]
fn compute_snapshot_diff_detects_changes() {
    let old = "Line 1\nLine 2\npassword=secret123\nLine 4";
    let new = "Line 1\nLine 2\nLine 4\nLine 5";
    let diff = compute_snapshot_diff(old, new, "https://example.com/config");
    assert!(diff
        .removed_content
        .contains(&"password=secret123".to_string()));
    assert!(diff.added_content.contains(&"Line 5".to_string()));
    assert!(!diff.notable_changes.is_empty());
    assert!(diff.notable_changes[0].contains("sensitive"));
}

#[test]
fn compute_snapshot_diff_identical() {
    let text = "Line 1\nLine 2\nLine 3";
    let diff = compute_snapshot_diff(text, text, "https://example.com");
    assert!(diff.removed_content.is_empty());
    assert!(diff.added_content.is_empty());
    assert!(diff.notable_changes.is_empty());
}

#[test]
fn web_scrape_report_total_items() {
    let mut report = WebScrapeReport::new("example.com");
    assert_eq!(report.total_intel_items(), 0);

    report.paste_entries.push(PasteEntry {
        source: PasteSource::Pastebin,
        url: "https://pastebin.com/abc".to_string(),
        title: "test".to_string(),
        snippet: "content".to_string(),
        timestamp_ms: 1000,
        relevance_score: 0.8,
    });
    report
        .job_intel
        .push(analyze_job_posting("test", "Co", "url"));
    assert_eq!(report.total_intel_items(), 2);
}

#[test]
fn dork_category_display() {
    assert_eq!(DorkCategory::ConfigFiles.to_string(), "Config Files");
    assert_eq!(DorkCategory::Credentials.to_string(), "Credentials");
    assert_eq!(DorkCategory::ApiEndpoints.to_string(), "API Endpoints");
}

#[test]
fn paste_source_display() {
    assert_eq!(PasteSource::Pastebin.to_string(), "Pastebin");
    assert_eq!(PasteSource::GithubGist.to_string(), "GitHub Gist");
}

#[test]
fn forum_platform_display() {
    assert_eq!(ForumPlatform::Reddit.to_string(), "Reddit");
    assert_eq!(ForumPlatform::HackerNews.to_string(), "Hacker News");
}

#[test]
fn security_maturity_indicator_display() {
    assert_eq!(
        SecurityMaturityIndicator::HasSecurityTeam.to_string(),
        "Has Security Team"
    );
    assert_eq!(
        SecurityMaturityIndicator::HasBugBounty.to_string(),
        "Has Bug Bounty"
    );
}

#[test]
fn archive_analysis_config_default() {
    let cfg = ArchiveAnalysisConfig::default();
    assert!(cfg.target_url.is_empty());
    assert_eq!(cfg.max_snapshots, 50);
    assert!(cfg.look_for_removed);
    assert!(cfg.look_for_configs);
    assert!(cfg.look_for_endpoints);
}
