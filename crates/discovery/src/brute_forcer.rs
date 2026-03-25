use std::collections::HashSet;
use std::sync::mpsc;
use std::thread;

use reqwest::blocking::Client;
use url::Url;

use aegis_protocol::target_validation::validate_target_is_localhost;

use crate::wordlist::default_wordlist;

const DEFAULT_CONCURRENCY: usize = 20;
pub(crate) const BASELINE_404_PROBE: &str = "aegis-nonexistent-path-4f7a8b2c-d1e3";
pub(crate) const BODY_SIZE_TOLERANCE: usize = 64;

/// A path found by directory brute-forcing that returned a non-filtered status code.
#[derive(Debug, Clone)]
pub struct DiscoveredPath {
    pub path: String,
    pub status_code: u16,
    pub content_length: usize,
    pub content_type: Option<String>,
    pub interesting: bool,
}

/// Errors that can occur during directory brute-forcing.
#[derive(Debug)]
pub enum BruteForceError {
    InvalidBaseUrl(String),
    NonLocalhostTarget(String),
    HttpError(String),
}

impl std::fmt::Display for BruteForceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBaseUrl(url) => write!(f, "invalid base URL: {url}"),
            Self::NonLocalhostTarget(url) => write!(f, "non-localhost target: {url}"),
            Self::HttpError(msg) => write!(f, "HTTP error: {msg}"),
        }
    }
}

impl std::error::Error for BruteForceError {}

/// Multi-threaded directory brute-forcer for localhost targets.
///
/// Probes wordlist entries (optionally with file extensions) against the target,
/// filtering 404 responses and baseline-matching pages. Use builder methods
/// `with_extensions`, `with_concurrency`, and `with_filter_codes` to customize.
pub struct DirectoryBruster {
    client: Client,
    pub(crate) base_url: String,
    pub(crate) wordlist: Vec<String>,
    extensions: Vec<String>,
    pub(crate) concurrency: usize,
    pub(crate) filter_status_codes: HashSet<u16>,
    baseline_404_size: Option<usize>,
}

impl std::fmt::Debug for DirectoryBruster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryBruster")
            .field("base_url", &self.base_url)
            .field("wordlist_len", &self.wordlist.len())
            .field("extensions", &self.extensions)
            .field("concurrency", &self.concurrency)
            .field("filter_status_codes", &self.filter_status_codes)
            .field("baseline_404_size", &self.baseline_404_size)
            .finish()
    }
}

impl DirectoryBruster {
    pub fn new(base_url: &str, wordlist: Vec<String>) -> Result<Self, BruteForceError> {
        validate_base_url(base_url)?;

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| BruteForceError::HttpError(e.to_string()))?;

        let mut filter_codes = HashSet::new();
        filter_codes.insert(404);

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            wordlist,
            extensions: Vec::new(),
            concurrency: DEFAULT_CONCURRENCY,
            filter_status_codes: filter_codes,
            baseline_404_size: None,
        })
    }

    pub fn with_default_wordlist(base_url: &str) -> Result<Self, BruteForceError> {
        Self::new(base_url, default_wordlist())
    }

    pub fn with_extensions(mut self, extensions: Vec<String>) -> Self {
        self.extensions = extensions;
        self
    }

    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.max(1);
        self
    }

    pub fn with_filter_codes(mut self, codes: HashSet<u16>) -> Self {
        self.filter_status_codes = codes;
        self
    }

    pub fn detect_baseline_404(&mut self) -> Option<usize> {
        let probe_url = format!("{}/{BASELINE_404_PROBE}", self.base_url);
        match self.client.get(&probe_url).send() {
            Ok(resp) => {
                let size = resp
                    .content_length()
                    .map(|l| l as usize)
                    .or_else(|| resp.bytes().ok().map(|b| b.len()));
                self.baseline_404_size = size;
                size
            }
            Err(_) => None,
        }
    }

    pub fn run(&self) -> Vec<DiscoveredPath> {
        let candidates = self.build_candidate_paths();
        if candidates.is_empty() {
            return Vec::new();
        }

        let (tx, rx) = mpsc::channel();
        let chunk_size = (candidates.len() / self.concurrency).max(1);
        let chunks: Vec<Vec<String>> = candidates.chunks(chunk_size).map(|c| c.to_vec()).collect();

        let mut handles = Vec::new();
        for chunk in chunks {
            let tx = tx.clone();
            let client = self.client.clone();
            let base_url = self.base_url.clone();
            let filter_codes = self.filter_status_codes.clone();
            let baseline_size = self.baseline_404_size;

            handles.push(thread::spawn(move || {
                for path in &chunk {
                    let url = format!("{base_url}/{path}");
                    if let Some(result) =
                        probe_path(&client, &url, path, &filter_codes, baseline_size)
                    {
                        let _ = tx.send(result);
                    }
                }
            }));
        }

        drop(tx);

        let mut results: Vec<DiscoveredPath> = rx.into_iter().collect();
        for handle in handles {
            let _ = handle.join();
        }

        results.sort_by(|a, b| a.path.cmp(&b.path));
        results
    }

    pub(crate) fn build_candidate_paths(&self) -> Vec<String> {
        let mut candidates = Vec::new();
        let mut all_extensions: Vec<&str> = vec![""];
        all_extensions.extend(self.extensions.iter().map(String::as_str));

        for word in &self.wordlist {
            for ext in &all_extensions {
                candidates.push(format!("{word}{ext}"));
            }
        }
        candidates
    }
}

pub(crate) fn validate_base_url(url: &str) -> Result<(), BruteForceError> {
    let parsed = Url::parse(url).map_err(|_| BruteForceError::InvalidBaseUrl(url.to_string()))?;
    if parsed.host_str().is_none() {
        return Err(BruteForceError::InvalidBaseUrl(url.to_string()));
    }
    validate_target_is_localhost(url)
        .map_err(|_| BruteForceError::NonLocalhostTarget(url.to_string()))
}

fn probe_path(
    client: &Client,
    url: &str,
    path: &str,
    filter_codes: &HashSet<u16>,
    baseline_size: Option<usize>,
) -> Option<DiscoveredPath> {
    let resp = client.get(url).send().ok()?;
    let status = resp.status().as_u16();

    if filter_codes.contains(&status) {
        return None;
    }

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let body = resp.bytes().ok()?;
    let content_length = body.len();

    if is_baseline_match(content_length, baseline_size) {
        return None;
    }

    Some(DiscoveredPath {
        path: path.to_string(),
        status_code: status,
        content_length,
        content_type,
        interesting: is_interesting_path(path),
    })
}

pub(crate) fn is_baseline_match(size: usize, baseline: Option<usize>) -> bool {
    match baseline {
        Some(baseline_size) => size.abs_diff(baseline_size) <= BODY_SIZE_TOLERANCE,
        None => false,
    }
}

const INTERESTING_KEYWORDS: &[&str] = &[
    "admin",
    "config",
    "backup",
    ".env",
    ".git",
    ".svn",
    "secret",
    "password",
    "credential",
    "dump",
    "debug",
    "phpinfo",
    "actuator",
    "console",
    ".htpasswd",
    ".aws",
    "id_rsa",
    "shadow",
    "private",
    "internal",
];

pub(crate) fn is_interesting_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    INTERESTING_KEYWORDS
        .iter()
        .any(|keyword| lower.contains(keyword))
}
