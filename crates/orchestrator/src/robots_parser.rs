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
