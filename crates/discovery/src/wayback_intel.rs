/// Historical reconnaissance via the Wayback Machine (web.archive.org).
///
/// Discovers: old endpoints no longer linked, removed pages that may still contain
/// secrets, technology stack changes over time, old API versions still accessible,
/// admin panels removed from navigation but still live.
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Category of a Wayback Machine finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WaybackFindingCategory {
    RemovedEndpoint,
    TechStackChange,
    OldApiVersion,
    AdminPanelHidden,
    SecretInSnapshot,
    RemovedPage,
    ConfigFileExposed,
    DirectoryListing,
}

impl fmt::Display for WaybackFindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemovedEndpoint => write!(f, "Removed Endpoint"),
            Self::TechStackChange => write!(f, "Tech Stack Change"),
            Self::OldApiVersion => write!(f, "Old API Version"),
            Self::AdminPanelHidden => write!(f, "Hidden Admin Panel"),
            Self::SecretInSnapshot => write!(f, "Secret in Snapshot"),
            Self::RemovedPage => write!(f, "Removed Page"),
            Self::ConfigFileExposed => write!(f, "Config File Exposed"),
            Self::DirectoryListing => write!(f, "Directory Listing"),
        }
    }
}

/// Severity of a Wayback finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WaybackSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for WaybackSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// A single Wayback CDX record parsed from the API response.
#[derive(Debug, Clone)]
pub struct CdxRecord {
    pub url: String,
    pub timestamp: String,
    pub mime_type: String,
    pub status_code: u16,
    pub digest: String,
}

/// A finding from Wayback Machine analysis.
#[derive(Debug, Clone)]
pub struct WaybackFinding {
    pub category: WaybackFindingCategory,
    pub severity: WaybackSeverity,
    pub url: String,
    pub description: String,
    pub evidence: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

/// A tech stack snapshot at a given point in time.
#[derive(Debug, Clone)]
pub struct TechStackSnapshot {
    pub timestamp: String,
    pub technologies: Vec<String>,
    pub headers: HashMap<String, String>,
}

/// Result of Wayback Machine intelligence gathering.
#[derive(Debug, Clone)]
pub struct WaybackIntelResult {
    pub target_domain: String,
    pub total_snapshots: usize,
    pub unique_urls: usize,
    pub findings: Vec<WaybackFinding>,
    pub removed_endpoints: Vec<String>,
    pub old_api_versions: Vec<String>,
    pub tech_stack_timeline: Vec<TechStackSnapshot>,
}

/// Patterns indicating admin panels.
const ADMIN_PATTERNS: &[&str] = &[
    "/admin",
    "/administrator",
    "/wp-admin",
    "/dashboard",
    "/manage",
    "/panel",
    "/control",
    "/cms",
    "/backend",
    "/staff",
    "/internal",
    "/console",
    "/phpmyadmin",
    "/adminer",
    "/webmin",
    "/_admin",
    "/site-admin",
    "/siteadmin",
];

/// Patterns indicating API endpoints with version numbers.
const API_VERSION_PATTERNS: &[&str] = &[
    "/api/v1/",
    "/api/v2/",
    "/api/v3/",
    "/api/v4/",
    "/api/v5/",
    "/v1/",
    "/v2/",
    "/v3/",
    "/v4/",
    "/rest/v1/",
    "/rest/v2/",
    "/graphql/v1/",
    "/graphql/v2/",
];

/// File extensions that may contain secrets or sensitive configuration.
const SENSITIVE_EXTENSIONS: &[&str] = &[
    ".env",
    ".config",
    ".conf",
    ".yml",
    ".yaml",
    ".json",
    ".xml",
    ".properties",
    ".ini",
    ".toml",
    ".sql",
    ".bak",
    ".backup",
    ".old",
    ".orig",
    ".swp",
    ".log",
    ".dump",
];

/// Technology detection patterns matched against URL paths and mime types.
const TECH_INDICATORS: &[(&str, &str)] = &[
    ("/wp-content/", "WordPress"),
    ("/wp-includes/", "WordPress"),
    ("/wp-json/", "WordPress"),
    ("/sites/default/", "Drupal"),
    ("/modules/", "Drupal"),
    ("/components/com_", "Joomla"),
    ("/rails/", "Ruby on Rails"),
    ("/assets/application-", "Ruby on Rails"),
    ("/static/admin/", "Django"),
    ("/__debug__/", "Django"),
    ("/laravel/", "Laravel"),
    ("/vendor/laravel/", "Laravel"),
    ("/spring/", "Spring"),
    ("/actuator/", "Spring Boot"),
    ("/next/", "Next.js"),
    ("/_next/", "Next.js"),
    ("/nuxt/", "Nuxt.js"),
    ("/_nuxt/", "Nuxt.js"),
    ("/angular.js", "AngularJS"),
    ("/react/", "React"),
    ("/bundle.js", "Webpack"),
    ("/swagger-ui/", "Swagger"),
    ("/api-docs", "Swagger"),
    ("/graphql", "GraphQL"),
    ("/graphiql", "GraphQL"),
];

/// Analyzes Wayback Machine CDX records for security intelligence.
pub struct WaybackIntel {
    target_domain: String,
}

impl WaybackIntel {
    pub fn new(target_domain: &str) -> Self {
        Self {
            target_domain: target_domain.trim_end_matches('/').to_string(),
        }
    }

    /// Build the CDX API query URL for fetching historical records.
    pub fn cdx_query_url(&self, limit: usize) -> String {
        format!(
            "https://web.archive.org/cdx/search/cdx?url={}/*&output=json&fl=original,timestamp,mimetype,statuscode,digest&collapse=urlkey&limit={}",
            self.target_domain, limit
        )
    }

    /// Parse CDX JSON response into records.
    /// The CDX API returns a JSON array of arrays. First row is header.
    pub fn parse_cdx_response(&self, json_body: &str) -> Vec<CdxRecord> {
        let parsed: Result<Vec<Vec<String>>, _> = serde_json::from_str(json_body);
        let rows = match parsed {
            Ok(r) if r.len() > 1 => r,
            _ => return Vec::new(),
        };

        rows[1..]
            .iter()
            .filter_map(|row| {
                if row.len() >= 5 {
                    Some(CdxRecord {
                        url: row[0].clone(),
                        timestamp: row[1].clone(),
                        mime_type: row[2].clone(),
                        status_code: row[3].parse().unwrap_or(0),
                        digest: row[4].clone(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Analyze CDX records and current live URLs to produce intelligence.
    /// `live_urls` is the set of currently accessible URLs on the target.
    pub fn analyze(
        &self,
        records: &[CdxRecord],
        live_urls: &HashSet<String>,
    ) -> WaybackIntelResult {
        let mut findings = Vec::new();
        let mut removed_endpoints = Vec::new();
        let mut old_api_versions = Vec::new();
        let mut tech_timeline: HashMap<String, HashSet<String>> = HashMap::new();
        let unique_urls: HashSet<&str> = records.iter().map(|r| r.url.as_str()).collect();

        for record in records {
            if record.status_code == 200 {
                self.check_removed_endpoint(
                    record,
                    live_urls,
                    &mut findings,
                    &mut removed_endpoints,
                );
                self.check_admin_panel(record, live_urls, &mut findings);
                self.check_old_api_version(record, &mut findings, &mut old_api_versions);
                self.check_sensitive_file(record, &mut findings);
                self.check_directory_listing(record, &mut findings);
                self.collect_tech_indicators(record, &mut tech_timeline);
            }
        }

        let tech_stack_timeline = self.build_tech_timeline(&tech_timeline);
        self.detect_tech_changes(&tech_stack_timeline, &mut findings);

        old_api_versions.sort();
        old_api_versions.dedup();
        removed_endpoints.sort();
        removed_endpoints.dedup();

        WaybackIntelResult {
            target_domain: self.target_domain.clone(),
            total_snapshots: records.len(),
            unique_urls: unique_urls.len(),
            findings,
            removed_endpoints,
            old_api_versions,
            tech_stack_timeline,
        }
    }

    fn check_removed_endpoint(
        &self,
        record: &CdxRecord,
        live_urls: &HashSet<String>,
        findings: &mut Vec<WaybackFinding>,
        removed: &mut Vec<String>,
    ) {
        if !live_urls.contains(&record.url) {
            let path = extract_path(&record.url);
            if !path.is_empty() && path != "/" {
                removed.push(record.url.clone());
                findings.push(WaybackFinding {
                    category: WaybackFindingCategory::RemovedEndpoint,
                    severity: WaybackSeverity::Low,
                    url: record.url.clone(),
                    description: format!(
                        "Endpoint '{}' was previously accessible but is no longer linked",
                        path
                    ),
                    evidence: format!(
                        "Last seen in Wayback: {} (status {})",
                        record.timestamp, record.status_code
                    ),
                    first_seen: Some(record.timestamp.clone()),
                    last_seen: Some(record.timestamp.clone()),
                });
            }
        }
    }

    fn check_admin_panel(
        &self,
        record: &CdxRecord,
        live_urls: &HashSet<String>,
        findings: &mut Vec<WaybackFinding>,
    ) {
        let path = extract_path(&record.url).to_lowercase();
        let is_admin = ADMIN_PATTERNS.iter().any(|p| path.starts_with(p));
        if !is_admin {
            return;
        }

        let severity = if live_urls.contains(&record.url) {
            WaybackSeverity::High
        } else {
            WaybackSeverity::Medium
        };

        let still_live = if live_urls.contains(&record.url) {
            " and is STILL ACCESSIBLE"
        } else {
            " (removed from navigation, may still be live)"
        };

        findings.push(WaybackFinding {
            category: WaybackFindingCategory::AdminPanelHidden,
            severity,
            url: record.url.clone(),
            description: format!("Admin panel found in Wayback history{}", still_live),
            evidence: format!("Path: {}, timestamp: {}", path, record.timestamp),
            first_seen: Some(record.timestamp.clone()),
            last_seen: Some(record.timestamp.clone()),
        });
    }

    fn check_old_api_version(
        &self,
        record: &CdxRecord,
        findings: &mut Vec<WaybackFinding>,
        old_versions: &mut Vec<String>,
    ) {
        let path = extract_path(&record.url).to_lowercase();
        for pattern in API_VERSION_PATTERNS {
            if path.contains(pattern) {
                old_versions.push(pattern.to_string());
                findings.push(WaybackFinding {
                    category: WaybackFindingCategory::OldApiVersion,
                    severity: WaybackSeverity::Medium,
                    url: record.url.clone(),
                    description: format!(
                        "Old API version '{}' found in historical snapshots — may still accept requests",
                        pattern.trim_end_matches('/')
                    ),
                    evidence: format!("Snapshot timestamp: {}", record.timestamp),
                    first_seen: Some(record.timestamp.clone()),
                    last_seen: Some(record.timestamp.clone()),
                });
                break;
            }
        }
    }

    fn check_sensitive_file(&self, record: &CdxRecord, findings: &mut Vec<WaybackFinding>) {
        let path = extract_path(&record.url).to_lowercase();
        let is_sensitive = SENSITIVE_EXTENSIONS.iter().any(|ext| path.ends_with(ext));
        if !is_sensitive {
            return;
        }

        let severity = if path.contains(".env") || path.contains(".sql") || path.contains(".bak") {
            WaybackSeverity::Critical
        } else if path.contains(".config") || path.contains(".yml") || path.contains(".json") {
            WaybackSeverity::High
        } else {
            WaybackSeverity::Medium
        };

        findings.push(WaybackFinding {
            category: WaybackFindingCategory::ConfigFileExposed,
            severity,
            url: record.url.clone(),
            description: format!(
                "Sensitive file '{}' found in Wayback snapshot — may contain secrets archived by Wayback",
                path
            ),
            evidence: format!("MIME: {}, timestamp: {}", record.mime_type, record.timestamp),
            first_seen: Some(record.timestamp.clone()),
            last_seen: Some(record.timestamp.clone()),
        });
    }

    fn check_directory_listing(&self, record: &CdxRecord, findings: &mut Vec<WaybackFinding>) {
        let path = extract_path(&record.url);
        if path.ends_with('/') && path != "/" && record.mime_type.contains("html") {
            findings.push(WaybackFinding {
                category: WaybackFindingCategory::DirectoryListing,
                severity: WaybackSeverity::Low,
                url: record.url.clone(),
                description: format!(
                    "Directory '{}' served HTML — potential directory listing",
                    path
                ),
                evidence: format!("Timestamp: {}", record.timestamp),
                first_seen: Some(record.timestamp.clone()),
                last_seen: Some(record.timestamp.clone()),
            });
        }
    }

    fn collect_tech_indicators(
        &self,
        record: &CdxRecord,
        timeline: &mut HashMap<String, HashSet<String>>,
    ) {
        let url_lower = record.url.to_lowercase();
        let year = if record.timestamp.len() >= 4 {
            &record.timestamp[..4]
        } else {
            "unknown"
        };

        for &(pattern, tech) in TECH_INDICATORS {
            if url_lower.contains(pattern) {
                timeline
                    .entry(year.to_string())
                    .or_default()
                    .insert(tech.to_string());
            }
        }
    }

    fn build_tech_timeline(
        &self,
        raw: &HashMap<String, HashSet<String>>,
    ) -> Vec<TechStackSnapshot> {
        let mut years: Vec<&String> = raw.keys().collect();
        years.sort();

        years
            .iter()
            .map(|year| {
                let techs = raw.get(*year).cloned().unwrap_or_default();
                let mut sorted: Vec<String> = techs.into_iter().collect();
                sorted.sort();
                TechStackSnapshot {
                    timestamp: (*year).clone(),
                    technologies: sorted,
                    headers: HashMap::new(),
                }
            })
            .collect()
    }

    fn detect_tech_changes(
        &self,
        timeline: &[TechStackSnapshot],
        findings: &mut Vec<WaybackFinding>,
    ) {
        if timeline.len() < 2 {
            return;
        }

        for window in timeline.windows(2) {
            let prev = &window[0];
            let curr = &window[1];

            let prev_set: HashSet<&str> = prev.technologies.iter().map(|s| s.as_str()).collect();
            let curr_set: HashSet<&str> = curr.technologies.iter().map(|s| s.as_str()).collect();

            let added: Vec<&&str> = curr_set.difference(&prev_set).collect();
            let removed: Vec<&&str> = prev_set.difference(&curr_set).collect();

            if !added.is_empty() || !removed.is_empty() {
                let mut desc_parts = Vec::new();
                if !added.is_empty() {
                    let added_str: Vec<&str> = added.iter().map(|s| **s).collect();
                    desc_parts.push(format!("added: {}", added_str.join(", ")));
                }
                if !removed.is_empty() {
                    let removed_str: Vec<&str> = removed.iter().map(|s| **s).collect();
                    desc_parts.push(format!("removed: {}", removed_str.join(", ")));
                }

                findings.push(WaybackFinding {
                    category: WaybackFindingCategory::TechStackChange,
                    severity: WaybackSeverity::Info,
                    url: self.target_domain.clone(),
                    description: format!(
                        "Technology stack changed between {} and {}: {}",
                        prev.timestamp,
                        curr.timestamp,
                        desc_parts.join("; ")
                    ),
                    evidence: format!(
                        "Before: [{}], After: [{}]",
                        prev.technologies.join(", "),
                        curr.technologies.join(", ")
                    ),
                    first_seen: Some(prev.timestamp.clone()),
                    last_seen: Some(curr.timestamp.clone()),
                });
            }
        }
    }

    /// Analyze a raw Wayback snapshot body for embedded secrets.
    pub fn scan_snapshot_for_secrets(&self, url: &str, body: &str) -> Vec<WaybackFinding> {
        let mut findings = Vec::new();

        let secret_patterns: &[(&str, &str, WaybackSeverity)] = &[
            (
                "AKIA",
                "AWS Access Key ID prefix",
                WaybackSeverity::Critical,
            ),
            ("sk_live_", "Stripe secret key", WaybackSeverity::Critical),
            (
                "ghp_",
                "GitHub personal access token",
                WaybackSeverity::Critical,
            ),
            (
                "-----BEGIN RSA PRIVATE KEY",
                "RSA private key",
                WaybackSeverity::Critical,
            ),
            ("password=", "Password parameter", WaybackSeverity::High),
            ("api_key=", "API key parameter", WaybackSeverity::High),
            ("apikey=", "API key parameter", WaybackSeverity::High),
            (
                "postgres://",
                "PostgreSQL connection string",
                WaybackSeverity::Critical,
            ),
            (
                "mysql://",
                "MySQL connection string",
                WaybackSeverity::Critical,
            ),
            (
                "mongodb://",
                "MongoDB connection string",
                WaybackSeverity::Critical,
            ),
        ];

        for &(pattern, label, severity) in secret_patterns {
            if body.contains(pattern) {
                findings.push(WaybackFinding {
                    category: WaybackFindingCategory::SecretInSnapshot,
                    severity,
                    url: url.to_string(),
                    description: format!("{} found in archived snapshot", label),
                    evidence: format!("Pattern '{}' detected in snapshot body", pattern),
                    first_seen: None,
                    last_seen: None,
                });
            }
        }

        findings
    }
}

/// Extract the path portion from a full URL.
fn extract_path(url: &str) -> &str {
    if let Some(idx) = url.find("://") {
        let after_scheme = &url[idx + 3..];
        if let Some(path_idx) = after_scheme.find('/') {
            return &after_scheme[path_idx..];
        }
    }
    "/"
}
