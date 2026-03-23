use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::recon_client;
use crate::util::timestamp_ms;

fn fetch_resource(target: &str, path: &str) -> Option<String> {
    let domain = recon_client::validated_domain(target)?;
    let scheme = if target.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    let url = format!("{scheme}://{domain}/{path}");
    let client = recon_client::default_client()?;
    let resp = client.get(&url).send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.text().ok()
}

pub fn fetch_robots_txt(target: &str) -> Vec<String> {
    let body = match fetch_resource(target, "robots.txt") {
        Some(b) => b,
        None => return Vec::new(),
    };
    parse_robots_txt(&body)
}

pub fn fetch_sitemap(target: &str) -> Vec<String> {
    let body = match fetch_resource(target, "sitemap.xml") {
        Some(b) => b,
        None => return Vec::new(),
    };
    parse_sitemap_urls(&body)
}

pub(crate) fn parse_robots_txt(content: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let Some((directive, value)) = trimmed.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match directive.trim().to_ascii_lowercase().as_str() {
            "disallow" | "allow" => {
                if !value.is_empty() && value != "/" && seen.insert(value.to_string()) {
                    paths.push(value.to_string());
                }
            }
            "sitemap" => {
                if !value.is_empty() {
                    paths.push(value.to_string());
                }
            }
            _ => {}
        }
    }
    paths
}

pub(crate) fn parse_sitemap_urls(content: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(start) = trimmed.find("<loc>")
            && let Some(end) = trimmed.find("</loc>")
        {
            let url = &trimmed[start + 5..end];
            if !url.is_empty() {
                urls.push(url.to_string());
            }
        }
    }
    urls
}

pub fn discovered_paths_to_operations(
    paths: &[String],
    source: &str,
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    paths
        .iter()
        .map(|path| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![
                        ("path".to_string(), path.clone()),
                        ("source".to_string(), source.to_string()),
                    ],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RobotsSecurityIssue {
    SensitivePathDisallowed(String),
    AdminPanelExposed(String),
    ApiEndpointLeaked(String),
    BackupFileExposed(String),
    CrawlDelayAbuse(u32),
    WildcardAllowAll,
    SitemapLocationLeaked(String),
    VersionControlExposed(String),
    DatabasePathExposed(String),
    StagingEnvironmentLeaked(String),
}

impl std::fmt::Display for RobotsSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SensitivePathDisallowed(path) => {
                write!(f, "Sensitive path disallowed reveals endpoint: {path}")
            }
            Self::AdminPanelExposed(path) => {
                write!(f, "Admin panel path exposed in robots.txt: {path}")
            }
            Self::ApiEndpointLeaked(path) => {
                write!(f, "API endpoint leaked via robots.txt: {path}")
            }
            Self::BackupFileExposed(path) => {
                write!(f, "Backup file path exposed: {path}")
            }
            Self::CrawlDelayAbuse(delay) => {
                write!(f, "Abusive crawl-delay detected: {delay} seconds")
            }
            Self::WildcardAllowAll => {
                write!(f, "Wildcard Allow: * directive may override disallows")
            }
            Self::SitemapLocationLeaked(url) => {
                write!(f, "Sitemap URL reveals site structure: {url}")
            }
            Self::VersionControlExposed(path) => {
                write!(f, "Version control path exposed: {path}")
            }
            Self::DatabasePathExposed(path) => {
                write!(f, "Database admin path exposed: {path}")
            }
            Self::StagingEnvironmentLeaked(path) => {
                write!(f, "Staging/dev environment path leaked: {path}")
            }
        }
    }
}

pub fn analyze_robots_security(robots_txt: &str) -> Vec<RobotsSecurityIssue> {
    let mut issues = Vec::new();

    for line in robots_txt.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        let Some((directive, value)) = trimmed.split_once(':') else {
            continue;
        };

        let directive_lower = directive.trim().to_ascii_lowercase();
        let value = value.trim();

        match directive_lower.as_str() {
            "disallow" | "allow" => {
                if directive_lower == "allow" && value == "*" {
                    issues.push(RobotsSecurityIssue::WildcardAllowAll);
                    continue;
                }

                if value.is_empty() {
                    continue;
                }

                let path_lower = value.to_ascii_lowercase();

                // Admin panel detection
                if path_lower.contains("admin")
                    || path_lower.contains("dashboard")
                    || path_lower.contains("panel")
                    || path_lower.contains("control")
                    || path_lower.contains("manager")
                {
                    issues.push(RobotsSecurityIssue::AdminPanelExposed(value.to_string()));
                }

                // API endpoint detection
                if path_lower.contains("/api/")
                    || path_lower.contains("/v1/")
                    || path_lower.contains("/v2/")
                    || path_lower.contains("/graphql")
                    || path_lower.contains("/rest/")
                    || path_lower.contains("/internal")
                {
                    issues.push(RobotsSecurityIssue::ApiEndpointLeaked(value.to_string()));
                }

                // Backup file detection
                if path_lower.contains("backup")
                    || path_lower.contains(".bak")
                    || path_lower.contains(".sql")
                    || path_lower.contains(".dump")
                    || path_lower.contains(".zip")
                    || path_lower.contains(".tar")
                    || path_lower.contains("old")
                {
                    issues.push(RobotsSecurityIssue::BackupFileExposed(value.to_string()));
                }

                // Version control detection
                if path_lower.contains(".git")
                    || path_lower.contains(".svn")
                    || path_lower.contains(".hg")
                    || path_lower.contains(".bzr")
                    || path_lower.contains("/.cvs")
                {
                    issues.push(RobotsSecurityIssue::VersionControlExposed(
                        value.to_string(),
                    ));
                }

                // Database admin detection
                if path_lower.contains("phpmyadmin")
                    || path_lower.contains("adminer")
                    || path_lower.contains("pgadmin")
                    || path_lower.contains("mysql")
                    || path_lower.contains("database")
                    || path_lower.contains("dbadmin")
                {
                    issues.push(RobotsSecurityIssue::DatabasePathExposed(value.to_string()));
                }

                // Staging environment detection
                if path_lower.contains("staging")
                    || path_lower.contains("stage")
                    || path_lower.contains("dev")
                    || path_lower.contains("test")
                    || path_lower.contains("uat")
                    || path_lower.contains("qa")
                    || path_lower.contains("demo")
                {
                    issues.push(RobotsSecurityIssue::StagingEnvironmentLeaked(
                        value.to_string(),
                    ));
                }

                // Sensitive path detection (catch-all for other sensitive patterns)
                if path_lower.contains("secret")
                    || path_lower.contains("private")
                    || path_lower.contains("confidential")
                    || path_lower.contains("internal")
                    || path_lower.contains("config")
                    || path_lower.contains(".env")
                    || path_lower.contains("credentials")
                {
                    issues.push(RobotsSecurityIssue::SensitivePathDisallowed(
                        value.to_string(),
                    ));
                }
            }
            "crawl-delay" => {
                if let Ok(delay) = value.parse::<u32>()
                    && delay > 10
                {
                    issues.push(RobotsSecurityIssue::CrawlDelayAbuse(delay));
                }
            }
            "sitemap" => {
                if !value.is_empty() {
                    issues.push(RobotsSecurityIssue::SitemapLocationLeaked(
                        value.to_string(),
                    ));
                }
            }
            _ => {}
        }
    }

    issues
}

pub fn robots_security_severity(issue: &RobotsSecurityIssue) -> f64 {
    match issue {
        RobotsSecurityIssue::AdminPanelExposed(_) => 0.8,
        RobotsSecurityIssue::DatabasePathExposed(_) => 0.8,
        RobotsSecurityIssue::BackupFileExposed(_) => 0.75,
        RobotsSecurityIssue::VersionControlExposed(_) => 0.7,
        RobotsSecurityIssue::ApiEndpointLeaked(_) => 0.6,
        RobotsSecurityIssue::SensitivePathDisallowed(_) => 0.6,
        RobotsSecurityIssue::StagingEnvironmentLeaked(_) => 0.5,
        RobotsSecurityIssue::SitemapLocationLeaked(_) => 0.4,
        RobotsSecurityIssue::CrawlDelayAbuse(_) => 0.3,
        RobotsSecurityIssue::WildcardAllowAll => 0.4,
    }
}

pub fn robots_security_to_operations(
    issues: &[RobotsSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            let severity = robots_security_severity(issue);
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                severity,
                0.5,
            )
        })
        .collect()
}
