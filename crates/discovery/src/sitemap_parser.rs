use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};
use aegis_protocol::target_validation::validate_target_is_localhost;
use regex::Regex;
use reqwest::blocking::Client;

use crate::graph_ops::timestamp_ms;

/// Parsed contents of a `robots.txt` file.
#[derive(Debug, Clone, Default)]
pub struct RobotsResult {
    pub disallowed_paths: Vec<String>,
    pub sitemap_urls: Vec<String>,
    pub allowed_paths: Vec<String>,
}

/// URLs extracted from one or more XML sitemaps.
#[derive(Debug, Clone, Default)]
pub struct SitemapResult {
    pub urls: Vec<String>,
}

/// Errors that can occur when fetching or parsing sitemaps and robots.txt.
#[derive(Debug)]
pub enum SitemapError {
    NonLocalhostTarget(String),
    InvalidUrl(String),
    HttpError(String),
}

impl std::fmt::Display for SitemapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonLocalhostTarget(url) => write!(f, "non-localhost target: {url}"),
            Self::InvalidUrl(url) => write!(f, "invalid URL: {url}"),
            Self::HttpError(msg) => write!(f, "HTTP error: {msg}"),
        }
    }
}

impl std::error::Error for SitemapError {}

pub fn parse_robots_txt(content: &str) -> RobotsResult {
    let mut result = RobotsResult::default();

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((directive, value)) = line.split_once(':') {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }

            let value = strip_inline_comment(value);
            if value.is_empty() {
                continue;
            }

            match directive.trim().to_ascii_lowercase().as_str() {
                "disallow" => result.disallowed_paths.push(value),
                "allow" => result.allowed_paths.push(value),
                "sitemap" => {
                    let sitemap_value =
                        reconstruct_url_after_directive(line, directive.trim().len());
                    result.sitemap_urls.push(sitemap_value);
                }
                _ => {}
            }
        }
    }

    result
}

fn strip_inline_comment(value: &str) -> String {
    match value.find(" #") {
        Some(pos) => value[..pos].trim().to_string(),
        None => value.to_string(),
    }
}

/// Reconstruct URL value from a Sitemap directive line.
///
/// URLs contain colons (e.g., `https://...`), so we cannot use the value
/// from the first `split_once(':')`. Instead, we skip past the directive
/// name and its colon to capture the full URL.
fn reconstruct_url_after_directive(line: &str, directive_len: usize) -> String {
    let after_directive = &line[directive_len..];
    let after_colon = after_directive.strip_prefix(':').unwrap_or(after_directive);
    let value = after_colon.trim();
    strip_inline_comment(value)
}

pub fn parse_sitemap_xml(content: &str) -> SitemapResult {
    let loc_re = Regex::new(r"<loc>\s*(.*?)\s*</loc>").expect("valid regex");
    let urls: Vec<String> = loc_re
        .captures_iter(content)
        .map(|cap| cap[1].trim().to_string())
        .filter(|u| !u.is_empty())
        .collect();

    SitemapResult { urls }
}

pub fn fetch_and_parse(target_url: &str) -> Result<(RobotsResult, SitemapResult), SitemapError> {
    validate_target_is_localhost(target_url)
        .map_err(|_| SitemapError::NonLocalhostTarget(target_url.to_string()))?;

    let base = target_url.trim_end_matches('/');
    let client = build_client()?;

    let robots = fetch_robots(&client, base);
    let sitemap = fetch_sitemaps(&client, base, &robots.sitemap_urls);

    Ok((robots, sitemap))
}

fn build_client() -> Result<Client, SitemapError> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .map_err(|e| SitemapError::HttpError(e.to_string()))
}

fn fetch_robots(client: &Client, base: &str) -> RobotsResult {
    let url = format!("{base}/robots.txt");
    match client.get(&url).send() {
        Ok(resp) if resp.status().is_success() => match resp.text() {
            Ok(body) => parse_robots_txt(&body),
            Err(_) => RobotsResult::default(),
        },
        _ => RobotsResult::default(),
    }
}

fn fetch_sitemaps(client: &Client, base: &str, sitemap_urls: &[String]) -> SitemapResult {
    let urls_to_fetch: Vec<String> = if sitemap_urls.is_empty() {
        vec![format!("{base}/sitemap.xml")]
    } else {
        sitemap_urls.to_vec()
    };

    let mut combined = SitemapResult::default();
    for url in &urls_to_fetch {
        if let Some(result) = fetch_single_sitemap(client, url) {
            combined.urls.extend(result.urls);
        }
    }
    combined
}

fn fetch_single_sitemap(client: &Client, url: &str) -> Option<SitemapResult> {
    let resp = client.get(url).send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().ok()?;
    Some(parse_sitemap_xml(&body))
}

pub fn sitemap_results_to_operations(
    robots: &RobotsResult,
    sitemap: &SitemapResult,
    start_sequence: u64,
) -> Vec<OperationLogEntry> {
    let mut ops = Vec::new();
    let mut seq = start_sequence;

    for path in &robots.disallowed_paths {
        seq += 1;
        ops.push(make_endpoint_op(seq, path, "robots_txt_disallowed"));
    }

    for url in &sitemap.urls {
        seq += 1;
        ops.push(make_endpoint_op(seq, url, "sitemap"));
    }

    ops
}

fn make_endpoint_op(sequence_number: u64, path: &str, discovery_source: &str) -> OperationLogEntry {
    let properties = vec![
        ("path".to_string(), path.to_string()),
        ("method".to_string(), "GET".to_string()),
        ("discovery_source".to_string(), discovery_source.to_string()),
    ];

    OperationLogEntry {
        sequence_number,
        module: ModuleIdentifier::Discovery,
        operation: GraphOperation::AddNode {
            node_type: NodeType::Endpoint,
            properties,
        },
        timestamp_unix_ms: timestamp_ms(),
    }
}
