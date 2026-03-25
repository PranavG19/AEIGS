use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};

/// Status of a username check on a single platform.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CheckStatus {
    Exists,
    NotFound,
    Suspended,
    RateLimited,
    Error,
    Unknown,
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exists => write!(f, "Exists"),
            Self::NotFound => write!(f, "Not Found"),
            Self::Suspended => write!(f, "Suspended"),
            Self::RateLimited => write!(f, "Rate Limited"),
            Self::Error => write!(f, "Error"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Category of a platform for grouping results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlatformKind {
    Developer,
    Social,
    Professional,
    Media,
    Gaming,
    Messaging,
    Forum,
    Blog,
    Other,
}

impl std::fmt::Display for PlatformKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Developer => write!(f, "Developer"),
            Self::Social => write!(f, "Social"),
            Self::Professional => write!(f, "Professional"),
            Self::Media => write!(f, "Media"),
            Self::Gaming => write!(f, "Gaming"),
            Self::Messaging => write!(f, "Messaging"),
            Self::Forum => write!(f, "Forum"),
            Self::Blog => write!(f, "Blog"),
            Self::Other => write!(f, "Other"),
        }
    }
}

/// Extracted profile data from a successful lookup.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileData {
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
    pub follower_count: Option<u64>,
    pub extra: HashMap<String, String>,
}

/// Result of checking a single platform for a username.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformResult {
    pub username: String,
    pub platform_name: String,
    pub kind: PlatformKind,
    pub url: String,
    pub status: CheckStatus,
    pub profile_data: Option<ProfileData>,
    pub response_time_ms: u64,
    pub http_status: Option<u16>,
}

/// Definition of how to check a platform.
#[derive(Debug, Clone)]
pub struct PlatformDef {
    pub name: &'static str,
    pub kind: PlatformKind,
    pub url_template: &'static str,
    pub detection: DetectionMethod,
}

/// How to determine if a username exists on the platform.
#[derive(Debug, Clone)]
pub enum DetectionMethod {
    StatusCode { exists: u16, not_found: u16 },
    JsonField { path: &'static str, exists_value: Option<&'static str> },
    BodyContains { not_found_marker: &'static str },
    JsonArrayNonEmpty,
    RedirectDetection { login_fragment: &'static str },
}

/// Configuration for the platform checker.
#[derive(Debug, Clone)]
pub struct PlatformCheckerConfig {
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub delay_between_ms: u64,
    pub user_agents: Vec<String>,
}

impl Default for PlatformCheckerConfig {
    fn default() -> Self {
        Self {
            concurrency: 10,
            timeout_secs: 10,
            delay_between_ms: 100,
            user_agents: default_user_agents(),
        }
    }
}

/// The main platform username checker.
pub struct PlatformChecker {
    client: reqwest::Client,
    config: PlatformCheckerConfig,
    platforms: Vec<PlatformDef>,
}

impl PlatformChecker {
    pub fn new(config: PlatformCheckerConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("failed to build HTTP client");
        Self {
            client,
            config,
            platforms: all_platforms(),
        }
    }

    pub fn with_custom_platforms(mut self, platforms: Vec<PlatformDef>) -> Self {
        self.platforms = platforms;
        self
    }

    /// Check a username across all configured platforms concurrently.
    pub async fn check_username(&self, username: &str) -> Vec<PlatformResult> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.concurrency));
        let mut handles = Vec::new();

        for (idx, platform) in self.platforms.iter().enumerate() {
            let sem = semaphore.clone();
            let client = self.client.clone();
            let ua = self.config.user_agents[idx % self.config.user_agents.len()].clone();
            let delay = self.config.delay_between_ms;
            let url = platform.url_template.replace("{}", username);
            let name = platform.name;
            let kind = platform.kind;
            let detection = platform.detection.clone();
            let user = username.to_string();

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.expect("semaphore closed");
                if idx > 0 && delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay * (idx as u64 % 3))).await;
                }
                check_single_platform(&client, &user, name, kind, &url, &detection, &ua).await
            }));
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(_) => {}
            }
        }
        results
    }

    /// Filter results to only existing accounts.
    pub fn filter_existing(results: &[PlatformResult]) -> Vec<&PlatformResult> {
        results.iter().filter(|r| r.status == CheckStatus::Exists).collect()
    }

    /// Group results by platform kind.
    pub fn group_by_kind(results: &[PlatformResult]) -> HashMap<PlatformKind, Vec<&PlatformResult>> {
        let mut groups: HashMap<PlatformKind, Vec<&PlatformResult>> = HashMap::new();
        for r in results {
            groups.entry(r.kind).or_default().push(r);
        }
        groups
    }

    pub fn platform_count(&self) -> usize {
        self.platforms.len()
    }
}

async fn check_single_platform(
    client: &reqwest::Client,
    username: &str,
    platform_name: &'static str,
    kind: PlatformKind,
    url: &str,
    detection: &DetectionMethod,
    user_agent: &str,
) -> PlatformResult {
    let start = std::time::Instant::now();
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_str(user_agent).unwrap_or_else(|_| {
        HeaderValue::from_static("Mozilla/5.0")
    }));
    headers.insert("Accept", HeaderValue::from_static("application/json, text/html, */*"));

    let response = client
        .get(url)
        .headers(headers)
        .send()
        .await;

    let elapsed_ms = start.elapsed().as_millis() as u64;

    match response {
        Ok(resp) => {
            let http_status = resp.status().as_u16();
            let final_url = resp.url().clone().to_string();
            let body = resp.text().await.unwrap_or_default();

            let (status, profile_data) = evaluate_response(
                detection,
                http_status,
                &body,
                &final_url,
                platform_name,
            );

            PlatformResult {
                username: username.to_string(),
                platform_name: platform_name.to_string(),
                kind,
                url: url.to_string(),
                status,
                profile_data,
                response_time_ms: elapsed_ms,
                http_status: Some(http_status),
            }
        }
        Err(_) => PlatformResult {
            username: username.to_string(),
            platform_name: platform_name.to_string(),
            kind,
            url: url.to_string(),
            status: CheckStatus::Error,
            profile_data: None,
            response_time_ms: elapsed_ms,
            http_status: None,
        },
    }
}

fn evaluate_response(
    detection: &DetectionMethod,
    http_status: u16,
    body: &str,
    final_url: &str,
    _platform_name: &str,
) -> (CheckStatus, Option<ProfileData>) {
    if http_status == 429 {
        return (CheckStatus::RateLimited, None);
    }

    match detection {
        DetectionMethod::StatusCode { exists, not_found } => {
            if http_status == *exists {
                let profile = try_parse_json_profile(body);
                (CheckStatus::Exists, profile)
            } else if http_status == *not_found {
                (CheckStatus::NotFound, None)
            } else {
                (CheckStatus::Unknown, None)
            }
        }
        DetectionMethod::JsonField { path, exists_value } => {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                let field_val = json_path_lookup(&json, path);
                match (field_val, exists_value) {
                    (Some(val), Some(expected)) => {
                        if val.as_str().map_or(false, |s| s == *expected) {
                            (CheckStatus::Exists, try_parse_json_profile(body))
                        } else {
                            (CheckStatus::NotFound, None)
                        }
                    }
                    (Some(_), None) => (CheckStatus::Exists, try_parse_json_profile(body)),
                    (None, _) => (CheckStatus::NotFound, None),
                }
            } else if http_status == 200 {
                (CheckStatus::Exists, None)
            } else {
                (CheckStatus::NotFound, None)
            }
        }
        DetectionMethod::BodyContains { not_found_marker } => {
            if body.contains(not_found_marker) {
                (CheckStatus::NotFound, None)
            } else if http_status == 200 {
                (CheckStatus::Exists, None)
            } else {
                (CheckStatus::Unknown, None)
            }
        }
        DetectionMethod::JsonArrayNonEmpty => {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                if json.as_array().map_or(false, |a| !a.is_empty()) {
                    (CheckStatus::Exists, try_parse_json_profile(body))
                } else {
                    (CheckStatus::NotFound, None)
                }
            } else {
                (CheckStatus::Unknown, None)
            }
        }
        DetectionMethod::RedirectDetection { login_fragment } => {
            if final_url.contains(login_fragment) {
                (CheckStatus::NotFound, None)
            } else if http_status == 200 {
                (CheckStatus::Exists, None)
            } else {
                (CheckStatus::Unknown, None)
            }
        }
    }
}

fn json_path_lookup<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

fn try_parse_json_profile(body: &str) -> Option<ProfileData> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    let obj = json.as_object()?;

    let display_name = obj
        .get("name")
        .or_else(|| obj.get("login"))
        .or_else(|| obj.get("display_name"))
        .or_else(|| obj.get("username"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let bio = obj
        .get("bio")
        .or_else(|| obj.get("about"))
        .or_else(|| obj.get("description"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let avatar_url = obj
        .get("avatar_url")
        .or_else(|| obj.get("icon_img"))
        .or_else(|| obj.get("profile_image"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let follower_count = obj
        .get("followers")
        .or_else(|| obj.get("followers_count"))
        .and_then(|v| v.as_u64());

    if display_name.is_some() || bio.is_some() || avatar_url.is_some() {
        Some(ProfileData {
            display_name,
            bio,
            avatar_url,
            follower_count,
            extra: HashMap::new(),
        })
    } else {
        None
    }
}

fn default_user_agents() -> Vec<String> {
    vec![
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into(),
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15".into(),
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0".into(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0".into(),
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into(),
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1".into(),
        "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36".into(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0".into(),
    ]
}

/// All supported platform definitions.
pub fn all_platforms() -> Vec<PlatformDef> {
    vec![
        PlatformDef {
            name: "GitHub",
            kind: PlatformKind::Developer,
            url_template: "https://api.github.com/users/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "GitLab",
            kind: PlatformKind::Developer,
            url_template: "https://gitlab.com/api/v4/users?username={}",
            detection: DetectionMethod::JsonArrayNonEmpty,
        },
        PlatformDef {
            name: "Reddit",
            kind: PlatformKind::Social,
            url_template: "https://www.reddit.com/user/{}/about.json",
            detection: DetectionMethod::JsonField { path: "data.name", exists_value: None },
        },
        PlatformDef {
            name: "HackerNews",
            kind: PlatformKind::Forum,
            url_template: "https://hacker-news.firebaseio.com/v0/user/{}.json",
            detection: DetectionMethod::JsonField { path: "id", exists_value: None },
        },
        PlatformDef {
            name: "Twitter",
            kind: PlatformKind::Social,
            url_template: "https://x.com/{}",
            detection: DetectionMethod::BodyContains { not_found_marker: "This account doesn't exist" },
        },
        PlatformDef {
            name: "Instagram",
            kind: PlatformKind::Social,
            url_template: "https://www.instagram.com/{}/",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "TikTok",
            kind: PlatformKind::Social,
            url_template: "https://www.tiktok.com/@{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "YouTube",
            kind: PlatformKind::Media,
            url_template: "https://www.youtube.com/@{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Twitch",
            kind: PlatformKind::Media,
            url_template: "https://www.twitch.tv/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "LinkedIn",
            kind: PlatformKind::Professional,
            url_template: "https://www.linkedin.com/in/{}/",
            detection: DetectionMethod::RedirectDetection { login_fragment: "/login" },
        },
        PlatformDef {
            name: "DevTo",
            kind: PlatformKind::Blog,
            url_template: "https://dev.to/api/users/by_username?url={}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Medium",
            kind: PlatformKind::Blog,
            url_template: "https://medium.com/@{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Substack",
            kind: PlatformKind::Blog,
            url_template: "https://{}.substack.com",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Telegram",
            kind: PlatformKind::Messaging,
            url_template: "https://t.me/{}",
            detection: DetectionMethod::BodyContains { not_found_marker: "tgme_page_icon" },
        },
        PlatformDef {
            name: "Steam",
            kind: PlatformKind::Gaming,
            url_template: "https://steamcommunity.com/id/{}",
            detection: DetectionMethod::BodyContains { not_found_marker: "The specified profile could not be found" },
        },
        PlatformDef {
            name: "Pinterest",
            kind: PlatformKind::Social,
            url_template: "https://www.pinterest.com/{}/",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Keybase",
            kind: PlatformKind::Developer,
            url_template: "https://keybase.io/_/api/1.0/user/lookup.json?username={}",
            detection: DetectionMethod::JsonField { path: "them.basics", exists_value: None },
        },
        PlatformDef {
            name: "BitBucket",
            kind: PlatformKind::Developer,
            url_template: "https://api.bitbucket.org/2.0/users/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Gravatar",
            kind: PlatformKind::Other,
            url_template: "https://en.gravatar.com/{}.json",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "StackOverflow",
            kind: PlatformKind::Developer,
            url_template: "https://api.stackexchange.com/2.3/users?inname={}&site=stackoverflow",
            detection: DetectionMethod::JsonField { path: "items", exists_value: None },
        },
        PlatformDef {
            name: "Spotify",
            kind: PlatformKind::Media,
            url_template: "https://open.spotify.com/user/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "SoundCloud",
            kind: PlatformKind::Media,
            url_template: "https://soundcloud.com/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Flickr",
            kind: PlatformKind::Media,
            url_template: "https://www.flickr.com/photos/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Vimeo",
            kind: PlatformKind::Media,
            url_template: "https://vimeo.com/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Patreon",
            kind: PlatformKind::Other,
            url_template: "https://www.patreon.com/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Replit",
            kind: PlatformKind::Developer,
            url_template: "https://replit.com/@{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Codepen",
            kind: PlatformKind::Developer,
            url_template: "https://codepen.io/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Kaggle",
            kind: PlatformKind::Developer,
            url_template: "https://www.kaggle.com/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "HuggingFace",
            kind: PlatformKind::Developer,
            url_template: "https://huggingface.co/api/users/{}/overview",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Behance",
            kind: PlatformKind::Professional,
            url_template: "https://www.behance.net/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Dribbble",
            kind: PlatformKind::Professional,
            url_template: "https://dribbble.com/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "About.me",
            kind: PlatformKind::Professional,
            url_template: "https://about.me/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "ProductHunt",
            kind: PlatformKind::Developer,
            url_template: "https://www.producthunt.com/@{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Hashnode",
            kind: PlatformKind::Blog,
            url_template: "https://hashnode.com/@{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Trello",
            kind: PlatformKind::Professional,
            url_template: "https://trello.com/1/members/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "BuyMeACoffee",
            kind: PlatformKind::Other,
            url_template: "https://buymeacoffee.com/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Ko-fi",
            kind: PlatformKind::Other,
            url_template: "https://ko-fi.com/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Xbox",
            kind: PlatformKind::Gaming,
            url_template: "https://www.xbox.com/en-US/play/user/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Roblox",
            kind: PlatformKind::Gaming,
            url_template: "https://www.roblox.com/user.aspx?username={}",
            detection: DetectionMethod::BodyContains { not_found_marker: "Page cannot be found" },
        },
        PlatformDef {
            name: "Mastodon",
            kind: PlatformKind::Social,
            url_template: "https://mastodon.social/@{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Threads",
            kind: PlatformKind::Social,
            url_template: "https://www.threads.net/@{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Bluesky",
            kind: PlatformKind::Social,
            url_template: "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}.bsky.social",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 400 },
        },
        PlatformDef {
            name: "Letterboxd",
            kind: PlatformKind::Media,
            url_template: "https://letterboxd.com/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Goodreads",
            kind: PlatformKind::Media,
            url_template: "https://www.goodreads.com/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Npm",
            kind: PlatformKind::Developer,
            url_template: "https://www.npmjs.com/~{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "PyPI",
            kind: PlatformKind::Developer,
            url_template: "https://pypi.org/user/{}/",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "RubyGems",
            kind: PlatformKind::Developer,
            url_template: "https://rubygems.org/profiles/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "CratesIo",
            kind: PlatformKind::Developer,
            url_template: "https://crates.io/api/v1/users/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "DockerHub",
            kind: PlatformKind::Developer,
            url_template: "https://hub.docker.com/v2/users/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "Exercism",
            kind: PlatformKind::Developer,
            url_template: "https://exercism.org/profiles/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "LeetCode",
            kind: PlatformKind::Developer,
            url_template: "https://leetcode.com/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
    ]
}
