use serde::Deserialize;
use std::process::Command;
use std::time::Duration;

use crate::types::{CrawlConfig, CrawlResult, DiscoveredEndpoint, DiscoverySource};

pub const KATANA_TIMEOUT_SECS: u64 = 300;

pub struct KatanaWrapper;

impl KatanaWrapper {
    pub fn name(&self) -> &str {
        "katana"
    }

    pub fn is_available(&self) -> bool {
        Command::new("katana")
            .arg("-version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    pub fn build_command(&self, url: &str, config: &CrawlConfig, headless: bool) -> Command {
        let mut cmd = Command::new("katana");
        let depth = config.max_depth.to_string();
        if headless {
            cmd.args([
                "-u",
                url,
                "-d",
                &depth,
                "-jc",
                "-headless",
                "-system-chrome",
                "-j",
                "-silent",
            ]);
        } else {
            cmd.args([
                "-u", url, "-d", &depth, "-jc", "-kf", "all", "-aff", "-silent", "-j", "-rl", "50",
                "-timeout", "10", "-t", "10",
            ]);
        }
        if let Some(scope) = &config.scope_regex {
            cmd.args(["-cs", scope]);
        }
        cmd
    }

    pub fn parse_output(&self, stdout: &str) -> CrawlResult {
        let endpoints: Vec<DiscoveredEndpoint> = stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(parse_katana_line)
            .collect();
        let count = endpoints.len() as u32;
        CrawlResult {
            discovered_endpoints: endpoints,
            pages_visited: count,
            ..CrawlResult::default()
        }
    }
}

fn parse_katana_line(line: &str) -> Option<DiscoveredEndpoint> {
    let entry: KatanaEntry = serde_json::from_str(line).ok()?;
    let request = entry.request?;
    let endpoint = request.endpoint?;
    if endpoint.is_empty() {
        return None;
    }
    let method = request.method.unwrap_or_else(|| "GET".to_string());
    Some(DiscoveredEndpoint {
        url: endpoint,
        method,
        parameters: Vec::new(),
        source: DiscoverySource::Link,
    })
}

#[derive(Deserialize)]
struct KatanaEntry {
    request: Option<KatanaRequest>,
}

#[derive(Deserialize)]
struct KatanaRequest {
    method: Option<String>,
    endpoint: Option<String>,
}
