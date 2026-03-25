use std::fmt;

use serde::{Deserialize, Serialize};

use crate::util::timestamp_ms;

/// Types of search engine dork queries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DorkOperator {
    Site,
    Inurl,
    Filetype,
    Intitle,
    Intext,
    Cache,
    Link,
    Related,
    Ext,
}

impl fmt::Display for DorkOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Site => "site",
            Self::Inurl => "inurl",
            Self::Filetype => "filetype",
            Self::Intitle => "intitle",
            Self::Intext => "intext",
            Self::Cache => "cache",
            Self::Link => "link",
            Self::Related => "related",
            Self::Ext => "ext",
        };
        write!(f, "{label}")
    }
}

/// A structured search dork with operator, value, and optional extra terms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchDork {
    pub operator: DorkOperator,
    pub value: String,
    pub extra_terms: Vec<String>,
    pub category: DorkCategory,
}

impl SearchDork {
    pub fn to_query(&self) -> String {
        let base = format!("{}:{}", self.operator, self.value);
        if self.extra_terms.is_empty() {
            base
        } else {
            format!("{} {}", base, self.extra_terms.join(" "))
        }
    }
}

/// Categories of intelligence dork queries target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DorkCategory {
    ConfigFiles,
    Credentials,
    ErrorPages,
    AdminPanels,
    DatabaseExposure,
    DirectoryListings,
    SensitiveDocuments,
    ApiEndpoints,
    BackupFiles,
    VersionInfo,
}

impl fmt::Display for DorkCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ConfigFiles => "Config Files",
            Self::Credentials => "Credentials",
            Self::ErrorPages => "Error Pages",
            Self::AdminPanels => "Admin Panels",
            Self::DatabaseExposure => "Database Exposure",
            Self::DirectoryListings => "Directory Listings",
            Self::SensitiveDocuments => "Sensitive Documents",
            Self::ApiEndpoints => "API Endpoints",
            Self::BackupFiles => "Backup Files",
            Self::VersionInfo => "Version Info",
        };
        write!(f, "{label}")
    }
}

/// Generate a comprehensive set of search dorks for a target domain.
pub fn generate_dorks(domain: &str) -> Vec<SearchDork> {
    let mut dorks = Vec::new();

    let config_extensions = [
        "env", "yml", "yaml", "toml", "ini", "conf", "cfg", "xml", "json",
    ];
    for ext in &config_extensions {
        dorks.push(SearchDork {
            operator: DorkOperator::Site,
            value: domain.to_string(),
            extra_terms: vec![format!("filetype:{ext}")],
            category: DorkCategory::ConfigFiles,
        });
    }

    let cred_terms = [
        "password",
        "api_key",
        "secret",
        "token",
        "credentials",
        "auth",
        "private_key",
        "access_key",
    ];
    for term in &cred_terms {
        dorks.push(SearchDork {
            operator: DorkOperator::Site,
            value: domain.to_string(),
            extra_terms: vec![format!("\"{term}\"")],
            category: DorkCategory::Credentials,
        });
    }

    let error_terms = [
        "\"stack trace\"",
        "\"internal server error\"",
        "\"sql syntax\"",
        "\"fatal error\"",
        "\"debug mode\"",
    ];
    for term in &error_terms {
        dorks.push(SearchDork {
            operator: DorkOperator::Site,
            value: domain.to_string(),
            extra_terms: vec![term.to_string()],
            category: DorkCategory::ErrorPages,
        });
    }

    let admin_paths = [
        "admin",
        "wp-admin",
        "administrator",
        "login",
        "dashboard",
        "cpanel",
        "phpmyadmin",
        "manage",
    ];
    for path in &admin_paths {
        dorks.push(SearchDork {
            operator: DorkOperator::Inurl,
            value: format!("{domain}/{path}"),
            extra_terms: vec![],
            category: DorkCategory::AdminPanels,
        });
    }

    let backup_exts = ["bak", "old", "backup", "swp", "save", "orig", "copy"];
    for ext in &backup_exts {
        dorks.push(SearchDork {
            operator: DorkOperator::Site,
            value: domain.to_string(),
            extra_terms: vec![format!("ext:{ext}")],
            category: DorkCategory::BackupFiles,
        });
    }

    let doc_types = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv"];
    for ext in &doc_types {
        dorks.push(SearchDork {
            operator: DorkOperator::Site,
            value: domain.to_string(),
            extra_terms: vec![format!("filetype:{ext}")],
            category: DorkCategory::SensitiveDocuments,
        });
    }

    dorks.push(SearchDork {
        operator: DorkOperator::Site,
        value: domain.to_string(),
        extra_terms: vec!["intitle:\"index of\"".to_string()],
        category: DorkCategory::DirectoryListings,
    });

    let api_terms = [
        "/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/swagger", "/openapi",
    ];
    for term in &api_terms {
        dorks.push(SearchDork {
            operator: DorkOperator::Inurl,
            value: format!("{domain}{term}"),
            extra_terms: vec![],
            category: DorkCategory::ApiEndpoints,
        });
    }

    dorks
}

/// A paste site entry found during monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasteEntry {
    pub source: PasteSource,
    pub url: String,
    pub title: String,
    pub snippet: String,
    pub timestamp_ms: u64,
    pub relevance_score: f64,
}

/// Supported paste site sources.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PasteSource {
    Pastebin,
    GithubGist,
    Ghostbin,
    Dpaste,
    Hastebin,
}

impl fmt::Display for PasteSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Pastebin => "Pastebin",
            Self::GithubGist => "GitHub Gist",
            Self::Ghostbin => "Ghostbin",
            Self::Dpaste => "Dpaste",
            Self::Hastebin => "Hastebin",
        };
        write!(f, "{label}")
    }
}

/// Generate paste site search patterns for a target.
pub fn generate_paste_queries(domain: &str) -> Vec<(PasteSource, String)> {
    let base_terms = [
        domain.to_string(),
        format!("@{domain}"),
        domain.split('.').next().unwrap_or(domain).to_string(),
    ];
    let mut queries = Vec::new();
    for term in &base_terms {
        queries.push((
            PasteSource::Pastebin,
            format!("site:pastebin.com \"{term}\""),
        ));
        queries.push((
            PasteSource::GithubGist,
            format!("site:gist.github.com \"{term}\""),
        ));
        queries.push((
            PasteSource::Ghostbin,
            format!("site:ghostbin.com \"{term}\""),
        ));
    }
    queries
}

/// A forum/discussion mention of the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForumMention {
    pub platform: ForumPlatform,
    pub url: String,
    pub title: String,
    pub content_preview: String,
    pub author: String,
    pub timestamp_ms: u64,
    pub sentiment: Sentiment,
}

/// Supported forum/discussion platforms.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ForumPlatform {
    Reddit,
    HackerNews,
    StackOverflow,
    SecurityForum,
    BugBountyForum,
}

impl fmt::Display for ForumPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Reddit => "Reddit",
            Self::HackerNews => "Hacker News",
            Self::StackOverflow => "Stack Overflow",
            Self::SecurityForum => "Security Forum",
            Self::BugBountyForum => "Bug Bounty Forum",
        };
        write!(f, "{label}")
    }
}

/// Sentiment classification for mentions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sentiment {
    Positive,
    Neutral,
    Negative,
    SecurityConcern,
}

/// Generate forum search queries for a target.
pub fn generate_forum_queries(domain: &str) -> Vec<(ForumPlatform, String)> {
    let mut queries = Vec::new();
    queries.push((
        ForumPlatform::Reddit,
        format!("site:reddit.com \"{domain}\""),
    ));
    queries.push((
        ForumPlatform::Reddit,
        format!("site:reddit.com \"{domain}\" security vulnerability"),
    ));
    queries.push((
        ForumPlatform::HackerNews,
        format!("site:news.ycombinator.com \"{domain}\""),
    ));
    queries.push((
        ForumPlatform::StackOverflow,
        format!("site:stackoverflow.com \"{domain}\""),
    ));
    queries.push((
        ForumPlatform::BugBountyForum,
        format!("site:hackerone.com \"{domain}\""),
    ));
    queries.push((
        ForumPlatform::BugBountyForum,
        format!("site:bugcrowd.com \"{domain}\""),
    ));
    queries
}

/// Intelligence extracted from job postings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobPostingIntel {
    pub company: String,
    pub title: String,
    pub technologies: Vec<String>,
    pub security_indicators: Vec<SecurityMaturityIndicator>,
    pub team_size_hint: Option<String>,
    pub source_url: String,
}

/// Indicators of security maturity from job postings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityMaturityIndicator {
    HasSecurityTeam,
    UsesSoc,
    HasBugBounty,
    MentionsPentest,
    RequiresCompliance,
    MentionsSiem,
    UsesWaf,
    HasIncidentResponse,
}

impl fmt::Display for SecurityMaturityIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::HasSecurityTeam => "Has Security Team",
            Self::UsesSoc => "Uses SOC",
            Self::HasBugBounty => "Has Bug Bounty",
            Self::MentionsPentest => "Mentions Pentest",
            Self::RequiresCompliance => "Requires Compliance",
            Self::MentionsSiem => "Mentions SIEM",
            Self::UsesWaf => "Uses WAF",
            Self::HasIncidentResponse => "Has Incident Response",
        };
        write!(f, "{label}")
    }
}

/// Technology keywords to search for in job postings.
const TECH_KEYWORDS: &[&str] = &[
    "react",
    "angular",
    "vue",
    "node.js",
    "python",
    "django",
    "flask",
    "ruby",
    "rails",
    "java",
    "spring",
    "kotlin",
    "go",
    "golang",
    "rust",
    "php",
    "laravel",
    "aws",
    "azure",
    "gcp",
    "kubernetes",
    "docker",
    "terraform",
    "jenkins",
    "postgres",
    "mysql",
    "mongodb",
    "redis",
    "elasticsearch",
    "kafka",
    "nginx",
    "apache",
    "cloudflare",
    "graphql",
    "rest api",
];

/// Security maturity keywords and their indicators.
const SECURITY_KEYWORDS: &[(&str, SecurityMaturityIndicator)] = &[
    ("security team", SecurityMaturityIndicator::HasSecurityTeam),
    (
        "security engineer",
        SecurityMaturityIndicator::HasSecurityTeam,
    ),
    ("soc ", SecurityMaturityIndicator::UsesSoc),
    ("security operations", SecurityMaturityIndicator::UsesSoc),
    ("bug bounty", SecurityMaturityIndicator::HasBugBounty),
    (
        "penetration test",
        SecurityMaturityIndicator::MentionsPentest,
    ),
    ("pentest", SecurityMaturityIndicator::MentionsPentest),
    ("soc 2", SecurityMaturityIndicator::RequiresCompliance),
    ("hipaa", SecurityMaturityIndicator::RequiresCompliance),
    ("pci dss", SecurityMaturityIndicator::RequiresCompliance),
    ("iso 27001", SecurityMaturityIndicator::RequiresCompliance),
    ("gdpr", SecurityMaturityIndicator::RequiresCompliance),
    ("siem", SecurityMaturityIndicator::MentionsSiem),
    ("splunk", SecurityMaturityIndicator::MentionsSiem),
    ("waf", SecurityMaturityIndicator::UsesWaf),
    (
        "web application firewall",
        SecurityMaturityIndicator::UsesWaf,
    ),
    (
        "incident response",
        SecurityMaturityIndicator::HasIncidentResponse,
    ),
];

/// Extract technology and security intelligence from job posting text.
pub fn analyze_job_posting(text: &str, company: &str, source_url: &str) -> JobPostingIntel {
    let lower = text.to_lowercase();
    let technologies: Vec<String> = TECH_KEYWORDS
        .iter()
        .filter(|kw| lower.contains(**kw))
        .map(|kw| kw.to_string())
        .collect();

    let mut seen = std::collections::HashSet::new();
    let security_indicators: Vec<SecurityMaturityIndicator> = SECURITY_KEYWORDS
        .iter()
        .filter(|(kw, _)| lower.contains(kw))
        .filter_map(|(_, indicator)| {
            let key = format!("{indicator}");
            if seen.insert(key) {
                Some(indicator.clone())
            } else {
                None
            }
        })
        .collect();

    let team_size_hint = extract_team_size(&lower);

    JobPostingIntel {
        company: company.to_string(),
        title: extract_title_from_text(text),
        technologies,
        security_indicators,
        team_size_hint,
        source_url: source_url.to_string(),
    }
}

fn extract_team_size(text: &str) -> Option<String> {
    let patterns = [
        "team of ",
        "team size",
        "engineers",
        "developers",
        "members",
    ];
    for pattern in &patterns {
        if let Some(pos) = text.find(pattern) {
            let window = &text[pos..std::cmp::min(pos + 60, text.len())];
            for word in window.split_whitespace() {
                if let Ok(n) = word.parse::<u32>() {
                    return Some(format!("~{n} {pattern}"));
                }
            }
        }
    }
    None
}

fn extract_title_from_text(text: &str) -> String {
    text.lines()
        .next()
        .unwrap_or("Unknown Position")
        .trim()
        .chars()
        .take(100)
        .collect()
}

/// Document metadata extracted from public files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentMetadata {
    pub filename: String,
    pub author: Option<String>,
    pub creator_tool: Option<String>,
    pub creation_date: Option<String>,
    pub modification_date: Option<String>,
    pub internal_paths: Vec<String>,
    pub software_versions: Vec<String>,
    pub email_addresses: Vec<String>,
    pub usernames: Vec<String>,
}

/// Extract metadata patterns from document text content.
pub fn extract_document_metadata(content: &str, filename: &str) -> DocumentMetadata {
    let mut metadata = DocumentMetadata {
        filename: filename.to_string(),
        author: None,
        creator_tool: None,
        creation_date: None,
        modification_date: None,
        internal_paths: Vec::new(),
        software_versions: Vec::new(),
        email_addresses: Vec::new(),
        usernames: Vec::new(),
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Author:") {
            metadata.author = Some(rest.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix("Creator:") {
            metadata.creator_tool = Some(rest.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix("CreationDate:") {
            metadata.creation_date = Some(rest.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix("ModDate:") {
            metadata.modification_date = Some(rest.trim().to_string());
        }
    }

    let path_patterns = [
        "/home/",
        "/Users/",
        "C:\\Users\\",
        "C:\\Documents",
        "/var/www/",
        "/opt/",
    ];
    for pattern in &path_patterns {
        for line in content.lines() {
            if let Some(pos) = line.find(pattern) {
                let path: String = line[pos..]
                    .chars()
                    .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
                    .collect();
                if !path.is_empty() && !metadata.internal_paths.contains(&path) {
                    metadata.internal_paths.push(path);
                }
            }
        }
    }

    let email_re = regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").ok();
    if let Some(re) = &email_re {
        for cap in re.find_iter(content) {
            let email = cap.as_str().to_string();
            if !metadata.email_addresses.contains(&email) {
                metadata.email_addresses.push(email);
            }
        }
    }

    let version_re = regex::Regex::new(r"(?i)([\w\s]+)\s+v?(\d+\.\d+(?:\.\d+)*)").ok();
    if let Some(re) = &version_re {
        for cap in re.captures_iter(content) {
            let name = cap[1].trim();
            let version = &cap[2];
            let sw_names = [
                "apache",
                "nginx",
                "php",
                "python",
                "java",
                "node",
                "mysql",
                "postgres",
                "microsoft",
                "office",
                "word",
                "excel",
                "acrobat",
                "openssl",
                "tomcat",
                "iis",
            ];
            if sw_names.iter().any(|n| name.to_lowercase().contains(n)) {
                let entry = format!("{} {}", name.trim(), version);
                if !metadata.software_versions.contains(&entry) {
                    metadata.software_versions.push(entry);
                }
            }
        }
    }

    metadata
}

/// Wayback Machine archive analysis configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveAnalysisConfig {
    pub target_url: String,
    pub max_snapshots: usize,
    pub look_for_removed: bool,
    pub look_for_configs: bool,
    pub look_for_endpoints: bool,
}

impl Default for ArchiveAnalysisConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            max_snapshots: 50,
            look_for_removed: true,
            look_for_configs: true,
            look_for_endpoints: true,
        }
    }
}

/// A diff between two Wayback snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveDiff {
    pub url: String,
    pub old_timestamp: String,
    pub new_timestamp: String,
    pub removed_content: Vec<String>,
    pub added_content: Vec<String>,
    pub notable_changes: Vec<String>,
}

/// Generate Wayback Machine CDX API query URLs for a target.
pub fn generate_wayback_queries(domain: &str) -> Vec<String> {
    let paths = [
        "",
        "robots.txt",
        "sitemap.xml",
        ".env",
        "wp-config.php",
        "config.php",
        ".git/config",
        "api/",
        "swagger.json",
        "admin/",
        ".htaccess",
        "web.config",
    ];
    paths
        .iter()
        .map(|path| {
            format!(
                "https://web.archive.org/cdx/search/cdx?url={domain}/{path}&output=json&limit=10&fl=timestamp,original,statuscode"
            )
        })
        .collect()
}

/// Compute a simple diff between two text snapshots.
pub fn compute_snapshot_diff(old: &str, new: &str, url: &str) -> ArchiveDiff {
    let old_lines: std::collections::HashSet<&str> = old.lines().map(|l| l.trim()).collect();
    let new_lines: std::collections::HashSet<&str> = new.lines().map(|l| l.trim()).collect();

    let removed: Vec<String> = old_lines
        .difference(&new_lines)
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();
    let added: Vec<String> = new_lines
        .difference(&old_lines)
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();

    let sensitive_patterns = [
        "password",
        "secret",
        "api_key",
        "token",
        "credential",
        "admin",
        "internal",
        "private",
    ];
    let mut notable_changes = Vec::new();
    for line in &removed {
        let lower = line.to_lowercase();
        if sensitive_patterns.iter().any(|p| lower.contains(p)) {
            notable_changes.push(format!("Removed sensitive content: {line}"));
        }
    }

    ArchiveDiff {
        url: url.to_string(),
        old_timestamp: String::new(),
        new_timestamp: String::new(),
        removed_content: removed,
        added_content: added,
        notable_changes,
    }
}

/// Aggregated intelligence from all web scraping sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebScrapeReport {
    pub target: String,
    pub dorks_generated: usize,
    pub paste_entries: Vec<PasteEntry>,
    pub forum_mentions: Vec<ForumMention>,
    pub job_intel: Vec<JobPostingIntel>,
    pub document_metadata: Vec<DocumentMetadata>,
    pub archive_diffs: Vec<ArchiveDiff>,
    pub generated_at_ms: u64,
}

impl WebScrapeReport {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            dorks_generated: 0,
            paste_entries: Vec::new(),
            forum_mentions: Vec::new(),
            job_intel: Vec::new(),
            document_metadata: Vec::new(),
            archive_diffs: Vec::new(),
            generated_at_ms: timestamp_ms(),
        }
    }

    pub fn total_intel_items(&self) -> usize {
        self.paste_entries.len()
            + self.forum_mentions.len()
            + self.job_intel.len()
            + self.document_metadata.len()
            + self.archive_diffs.len()
    }
}

#[cfg(test)]
#[path = "web_scrape_intel_test.rs"]
mod tests;
