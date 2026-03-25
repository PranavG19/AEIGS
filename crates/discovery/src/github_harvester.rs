use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT};
use serde::{Deserialize, Serialize};

/// A GitHub user profile extracted from the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubProfile {
    pub login: String,
    pub name: Option<String>,
    pub bio: Option<String>,
    pub company: Option<String>,
    pub location: Option<String>,
    pub email: Option<String>,
    pub blog: Option<String>,
    pub twitter_username: Option<String>,
    pub public_repos: u64,
    pub public_gists: u64,
    pub followers: u64,
    pub following: u64,
    pub created_at: String,
    pub avatar_url: String,
}

/// Metadata about a single public repo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubRepo {
    pub name: String,
    pub full_name: String,
    pub description: Option<String>,
    pub language: Option<String>,
    pub stargazers_count: u64,
    pub forks_count: u64,
    pub fork: bool,
    pub created_at: String,
    pub updated_at: String,
    pub html_url: String,
    pub topics: Vec<String>,
}

/// An email address found in commits.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommitEmail {
    pub email: String,
    pub committer_name: String,
    pub repo: String,
    pub commit_sha: String,
}

/// A secret or credential found in commit history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedSecret {
    pub pattern_name: String,
    pub matched_text: String,
    pub repo: String,
    pub commit_sha: String,
    pub file_path: String,
}

/// GitHub organization membership entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubOrg {
    pub login: String,
    pub description: Option<String>,
    pub avatar_url: String,
}

/// Activity-hour distribution for timezone inference.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActivityPattern {
    pub hour_histogram: [u32; 24],
    pub day_histogram: [u32; 7],
    pub estimated_timezone: Option<String>,
    pub total_commits_analyzed: u32,
}

/// A public gist belonging to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubGist {
    pub id: String,
    pub description: Option<String>,
    pub html_url: String,
    pub files: Vec<String>,
    pub created_at: String,
    pub public: bool,
}

/// Aggregated GitHub intelligence for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubIntelligence {
    pub profile: GitHubProfile,
    pub repos: Vec<GitHubRepo>,
    pub organizations: Vec<GitHubOrg>,
    pub commit_emails: Vec<CommitEmail>,
    pub exposed_secrets: Vec<ExposedSecret>,
    pub activity: ActivityPattern,
    pub gists: Vec<GitHubGist>,
    pub language_breakdown: HashMap<String, u64>,
    pub total_stars: u64,
}

/// Configuration for the harvester.
#[derive(Debug, Clone)]
pub struct GitHubHarvesterConfig {
    pub max_repos: usize,
    pub scan_commits: bool,
    pub max_commits_per_repo: usize,
    pub scan_secrets: bool,
    pub timeout_secs: u64,
    pub user_agent: String,
}

impl Default for GitHubHarvesterConfig {
    fn default() -> Self {
        Self {
            max_repos: 100,
            scan_commits: true,
            max_commits_per_repo: 30,
            scan_secrets: true,
            timeout_secs: 15,
            user_agent: "Mozilla/5.0 (compatible; OSINT-Harvester/1.0)".into(),
        }
    }
}

/// Secret detection patterns for commit scanning.
#[derive(Debug, Clone)]
pub struct SecretPattern {
    pub name: &'static str,
    pub regex: &'static str,
}

/// All built-in secret patterns.
pub fn secret_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern { name: "AWS Access Key", regex: r"AKIA[0-9A-Z]{16}" },
        SecretPattern { name: "GitHub Token (classic)", regex: r"ghp_[A-Za-z0-9]{36}" },
        SecretPattern { name: "GitHub OAuth Token", regex: r"gho_[A-Za-z0-9]{36}" },
        SecretPattern { name: "GitHub PAT (fine-grained)", regex: r"github_pat_[A-Za-z0-9_]{82}" },
        SecretPattern { name: "GitHub App Token", regex: r"ghs_[A-Za-z0-9]{36}" },
        SecretPattern { name: "GitHub Refresh Token", regex: r"ghr_[A-Za-z0-9]{36}" },
        SecretPattern { name: "Slack Token", regex: r"xox[baprs]-[0-9a-zA-Z\-]{10,}" },
        SecretPattern { name: "Stripe Secret Key", regex: r"sk_live_[0-9a-zA-Z]{24,}" },
        SecretPattern { name: "Stripe Publishable Key", regex: r"pk_live_[0-9a-zA-Z]{24,}" },
        SecretPattern { name: "Heroku API Key", regex: r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" },
        SecretPattern { name: "Generic Password", regex: r#"(?i)password\s*[=:]\s*["'][^"']{6,}["']"# },
        SecretPattern { name: "Generic Secret", regex: r#"(?i)secret\s*[=:]\s*["'][^"']{6,}["']"# },
        SecretPattern { name: "Generic API Key", regex: r#"(?i)api[_-]?key\s*[=:]\s*["'][^"']{10,}["']"# },
        SecretPattern { name: "Generic Token", regex: r#"(?i)token\s*[=:]\s*["'][^"']{10,}["']"# },
        SecretPattern { name: "Private Key Header", regex: r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----" },
        SecretPattern { name: "Google API Key", regex: r"AIza[0-9A-Za-z\-_]{35}" },
        SecretPattern { name: "SendGrid API Key", regex: r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}" },
        SecretPattern { name: "Twilio API Key", regex: r"SK[0-9a-fA-F]{32}" },
        SecretPattern { name: "Mailgun API Key", regex: r"key-[0-9a-zA-Z]{32}" },
        SecretPattern { name: "AWS Secret Key", regex: r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}" },
    ]
}

/// The main GitHub intelligence harvester.
pub struct GitHubHarvester {
    client: reqwest::Client,
    config: GitHubHarvesterConfig,
    pub compiled_patterns: Vec<(String, Regex)>,
}

impl GitHubHarvester {
    pub fn new(config: GitHubHarvesterConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .expect("failed to build HTTP client");

        let compiled_patterns = if config.scan_secrets {
            secret_patterns()
                .iter()
                .filter_map(|sp| {
                    Regex::new(sp.regex).ok().map(|r| (sp.name.to_string(), r))
                })
                .collect()
        } else {
            Vec::new()
        };

        Self {
            client,
            config,
            compiled_patterns,
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(&self.config.user_agent)
            .unwrap_or_else(|_| HeaderValue::from_static("Mozilla/5.0")));
        headers.insert(ACCEPT, HeaderValue::from_static("application/vnd.github+json"));
        headers.insert("X-GitHub-Api-Version", HeaderValue::from_static("2022-11-28"));
        headers
    }

    /// Harvest full intelligence on a GitHub username.
    pub async fn harvest(&self, username: &str) -> Result<GitHubIntelligence, GitHubHarvesterError> {
        let profile = self.fetch_profile(username).await?;
        let repos = self.fetch_repos(username).await?;
        let organizations = self.fetch_orgs(username).await.unwrap_or_default();
        let gists = self.fetch_gists(username).await.unwrap_or_default();

        let mut commit_emails: HashSet<CommitEmail> = HashSet::new();
        let mut exposed_secrets: Vec<ExposedSecret> = Vec::new();
        let mut activity = ActivityPattern::default();

        if self.config.scan_commits {
            for repo in repos.iter().take(self.config.max_repos) {
                if repo.fork {
                    continue;
                }
                let commits = self.fetch_commits(username, &repo.name).await.unwrap_or_default();
                for commit in &commits {
                    Self::extract_commit_data(
                        commit,
                        &repo.name,
                        &mut commit_emails,
                        &mut activity,
                    );
                    if self.config.scan_secrets {
                        self.scan_commit_for_secrets(commit, &repo.name, &mut exposed_secrets);
                    }
                }
            }
        }

        activity.estimated_timezone = estimate_timezone(&activity.hour_histogram);

        let language_breakdown = build_language_breakdown(&repos);
        let total_stars = repos.iter().map(|r| r.stargazers_count).sum();

        Ok(GitHubIntelligence {
            profile,
            repos,
            organizations,
            commit_emails: commit_emails.into_iter().collect(),
            exposed_secrets,
            activity,
            gists,
            language_breakdown,
            total_stars,
        })
    }

    pub async fn fetch_profile(&self, username: &str) -> Result<GitHubProfile, GitHubHarvesterError> {
        let url = format!("https://api.github.com/users/{username}");
        let resp = self.client.get(&url).headers(self.build_headers()).send().await
            .map_err(|e| GitHubHarvesterError::Network(e.to_string()))?;

        if resp.status().as_u16() == 404 {
            return Err(GitHubHarvesterError::UserNotFound(username.to_string()));
        }
        if resp.status().as_u16() == 403 {
            return Err(GitHubHarvesterError::RateLimited);
        }

        let json: serde_json::Value = resp.json().await
            .map_err(|e| GitHubHarvesterError::ParseError(e.to_string()))?;

        Ok(parse_profile(&json))
    }

    async fn fetch_repos(&self, username: &str) -> Result<Vec<GitHubRepo>, GitHubHarvesterError> {
        let mut all_repos = Vec::new();
        let mut page = 1u32;
        let per_page = 100.min(self.config.max_repos);

        loop {
            let url = format!(
                "https://api.github.com/users/{username}/repos?per_page={per_page}&page={page}&sort=updated"
            );
            let resp = self.client.get(&url).headers(self.build_headers()).send().await
                .map_err(|e| GitHubHarvesterError::Network(e.to_string()))?;

            if resp.status().as_u16() == 403 {
                return Err(GitHubHarvesterError::RateLimited);
            }

            let json: Vec<serde_json::Value> = resp.json().await
                .map_err(|e| GitHubHarvesterError::ParseError(e.to_string()))?;

            if json.is_empty() {
                break;
            }

            for item in &json {
                all_repos.push(parse_repo(item));
            }

            if all_repos.len() >= self.config.max_repos || json.len() < per_page {
                break;
            }
            page += 1;
        }

        all_repos.truncate(self.config.max_repos);
        Ok(all_repos)
    }

    async fn fetch_orgs(&self, username: &str) -> Result<Vec<GitHubOrg>, GitHubHarvesterError> {
        let url = format!("https://api.github.com/users/{username}/orgs");
        let resp = self.client.get(&url).headers(self.build_headers()).send().await
            .map_err(|e| GitHubHarvesterError::Network(e.to_string()))?;

        let json: Vec<serde_json::Value> = resp.json().await
            .map_err(|e| GitHubHarvesterError::ParseError(e.to_string()))?;

        Ok(json.iter().map(parse_org).collect())
    }

    async fn fetch_gists(&self, username: &str) -> Result<Vec<GitHubGist>, GitHubHarvesterError> {
        let url = format!("https://api.github.com/users/{username}/gists?per_page=30");
        let resp = self.client.get(&url).headers(self.build_headers()).send().await
            .map_err(|e| GitHubHarvesterError::Network(e.to_string()))?;

        let json: Vec<serde_json::Value> = resp.json().await
            .map_err(|e| GitHubHarvesterError::ParseError(e.to_string()))?;

        Ok(json.iter().map(parse_gist).collect())
    }

    async fn fetch_commits(&self, username: &str, repo: &str) -> Result<Vec<serde_json::Value>, GitHubHarvesterError> {
        let url = format!(
            "https://api.github.com/repos/{username}/{repo}/commits?per_page={}&author={username}",
            self.config.max_commits_per_repo,
        );
        let resp = self.client.get(&url).headers(self.build_headers()).send().await
            .map_err(|e| GitHubHarvesterError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        resp.json().await
            .map_err(|e| GitHubHarvesterError::ParseError(e.to_string()))
    }

    pub fn extract_commit_data(
        commit: &serde_json::Value,
        repo_name: &str,
        emails: &mut HashSet<CommitEmail>,
        activity: &mut ActivityPattern,
    ) {
        let sha = commit.get("sha").and_then(|v| v.as_str()).unwrap_or("");

        if let Some(commit_obj) = commit.get("commit") {
            if let Some(author) = commit_obj.get("author") {
                if let (Some(email), Some(name)) = (
                    author.get("email").and_then(|v| v.as_str()),
                    author.get("name").and_then(|v| v.as_str()),
                ) {
                    if !email.contains("noreply.github.com") && !email.is_empty() {
                        emails.insert(CommitEmail {
                            email: email.to_string(),
                            committer_name: name.to_string(),
                            repo: repo_name.to_string(),
                            commit_sha: sha.to_string(),
                        });
                    }
                }

                if let Some(date_str) = author.get("date").and_then(|v| v.as_str()) {
                    if let Some((hour, day_of_week)) = parse_commit_datetime(date_str) {
                        activity.hour_histogram[hour] += 1;
                        activity.day_histogram[day_of_week] += 1;
                        activity.total_commits_analyzed += 1;
                    }
                }
            }
        }
    }

    pub fn scan_commit_for_secrets(
        &self,
        commit: &serde_json::Value,
        repo_name: &str,
        secrets: &mut Vec<ExposedSecret>,
    ) {
        let sha = commit.get("sha").and_then(|v| v.as_str()).unwrap_or("");
        let message = commit
            .get("commit")
            .and_then(|c| c.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("");

        for (name, regex) in &self.compiled_patterns {
            for mat in regex.find_iter(message) {
                secrets.push(ExposedSecret {
                    pattern_name: name.clone(),
                    matched_text: mat.as_str().to_string(),
                    repo: repo_name.to_string(),
                    commit_sha: sha.to_string(),
                    file_path: "(commit message)".to_string(),
                });
            }
        }
    }
}

fn parse_profile(json: &serde_json::Value) -> GitHubProfile {
    GitHubProfile {
        login: json.get("login").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        name: json.get("name").and_then(|v| v.as_str()).map(String::from),
        bio: json.get("bio").and_then(|v| v.as_str()).map(String::from),
        company: json.get("company").and_then(|v| v.as_str()).map(String::from),
        location: json.get("location").and_then(|v| v.as_str()).map(String::from),
        email: json.get("email").and_then(|v| v.as_str()).map(String::from),
        blog: json.get("blog").and_then(|v| v.as_str()).map(String::from),
        twitter_username: json.get("twitter_username").and_then(|v| v.as_str()).map(String::from),
        public_repos: json.get("public_repos").and_then(|v| v.as_u64()).unwrap_or(0),
        public_gists: json.get("public_gists").and_then(|v| v.as_u64()).unwrap_or(0),
        followers: json.get("followers").and_then(|v| v.as_u64()).unwrap_or(0),
        following: json.get("following").and_then(|v| v.as_u64()).unwrap_or(0),
        created_at: json.get("created_at").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        avatar_url: json.get("avatar_url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
    }
}

fn parse_repo(json: &serde_json::Value) -> GitHubRepo {
    let topics = json
        .get("topics")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|t| t.as_str().map(String::from)).collect())
        .unwrap_or_default();

    GitHubRepo {
        name: json.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        full_name: json.get("full_name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        description: json.get("description").and_then(|v| v.as_str()).map(String::from),
        language: json.get("language").and_then(|v| v.as_str()).map(String::from),
        stargazers_count: json.get("stargazers_count").and_then(|v| v.as_u64()).unwrap_or(0),
        forks_count: json.get("forks_count").and_then(|v| v.as_u64()).unwrap_or(0),
        fork: json.get("fork").and_then(|v| v.as_bool()).unwrap_or(false),
        created_at: json.get("created_at").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        updated_at: json.get("updated_at").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        html_url: json.get("html_url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        topics,
    }
}

fn parse_org(json: &serde_json::Value) -> GitHubOrg {
    GitHubOrg {
        login: json.get("login").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        description: json.get("description").and_then(|v| v.as_str()).map(String::from),
        avatar_url: json.get("avatar_url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
    }
}

fn parse_gist(json: &serde_json::Value) -> GitHubGist {
    let files = json
        .get("files")
        .and_then(|v| v.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();

    GitHubGist {
        id: json.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        description: json.get("description").and_then(|v| v.as_str()).map(String::from),
        html_url: json.get("html_url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        files,
        created_at: json.get("created_at").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        public: json.get("public").and_then(|v| v.as_bool()).unwrap_or(true),
    }
}

/// Parse ISO 8601 datetime to extract hour (0-23) and day-of-week (0=Mon, 6=Sun).
pub fn parse_commit_datetime(date_str: &str) -> Option<(usize, usize)> {
    if date_str.len() < 19 {
        return None;
    }
    let hour: usize = date_str.get(11..13)?.parse().ok()?;
    let year: i32 = date_str.get(0..4)?.parse().ok()?;
    let month: u32 = date_str.get(5..7)?.parse().ok()?;
    let day: u32 = date_str.get(8..10)?.parse().ok()?;

    let dow = day_of_week(year, month, day);
    Some((hour, dow))
}

/// Zeller-like day-of-week: 0=Mon, 6=Sun.
pub fn day_of_week(year: i32, month: u32, day: u32) -> usize {
    let (y, m) = if month <= 2 {
        (year - 1, month + 12)
    } else {
        (year, month)
    };
    let q = day as i32;
    let k = y % 100;
    let j = y / 100;
    let h = (q + (13 * (m as i32 + 1)) / 5 + k + k / 4 + j / 4 - 2 * j) % 7;
    let h = ((h + 7) % 7) as usize;
    match h {
        0 => 5, // Saturday
        1 => 6, // Sunday
        2 => 0, // Monday
        3 => 1, // Tuesday
        4 => 2, // Wednesday
        5 => 3, // Thursday
        6 => 4, // Friday
        _ => 0,
    }
}

/// Estimate timezone from peak activity hours (UTC).
pub fn estimate_timezone(hour_histogram: &[u32; 24]) -> Option<String> {
    let total: u32 = hour_histogram.iter().sum();
    if total < 5 {
        return None;
    }

    let peak_hour = hour_histogram
        .iter()
        .enumerate()
        .max_by_key(|(_, count)| *count)
        .map(|(hour, _)| hour)?;

    let tz = match peak_hour {
        8..=11 => "UTC+0 (Western Europe / UK)",
        12..=15 => "UTC-5 (US Eastern)",
        16..=19 => "UTC-8 (US Pacific)",
        20..=23 => "UTC-10 (Hawaii) or late-night coder",
        0..=3 => "UTC+5:30 (India) or UTC+8 (East Asia)",
        4..=7 => "UTC+9 (Japan/Korea) or UTC+10 (Australia)",
        _ => return None,
    };
    Some(tz.to_string())
}

pub fn build_language_breakdown(repos: &[GitHubRepo]) -> HashMap<String, u64> {
    let mut langs: HashMap<String, u64> = HashMap::new();
    for repo in repos {
        if let Some(lang) = &repo.language {
            *langs.entry(lang.clone()).or_insert(0) += 1;
        }
    }
    langs
}

/// Errors that can occur during harvesting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitHubHarvesterError {
    UserNotFound(String),
    RateLimited,
    Network(String),
    ParseError(String),
}

impl std::fmt::Display for GitHubHarvesterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserNotFound(u) => write!(f, "GitHub user not found: {u}"),
            Self::RateLimited => write!(f, "GitHub API rate limit exceeded"),
            Self::Network(e) => write!(f, "Network error: {e}"),
            Self::ParseError(e) => write!(f, "Parse error: {e}"),
        }
    }
}

impl std::error::Error for GitHubHarvesterError {}
