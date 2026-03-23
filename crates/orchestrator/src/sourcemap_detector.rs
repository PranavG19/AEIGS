use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

#[derive(Debug, Clone)]
pub struct SourceMapLeak {
    pub script_url: String,
    pub map_url: String,
}

pub fn detect_sourcemaps(target: &str) -> Vec<SourceMapLeak> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    find_sourcemap_references(&body, target)
}

pub(crate) fn find_sourcemap_references(html: &str, base_url: &str) -> Vec<SourceMapLeak> {
    let mut leaks = Vec::new();

    for tag in TagIter::new(html, "script") {
        let Some(src) = html_parser::extract_attr(tag.original, &tag.lower, "src") else {
            continue;
        };

        if !src.ends_with(".js") {
            continue;
        }

        let map_url = format!("{src}.map");
        let full_map_url = resolve_url(base_url, &map_url);
        leaks.push(SourceMapLeak {
            script_url: src,
            map_url: full_map_url,
        });
    }

    extract_sourcemap_comments(html, &mut leaks, base_url);

    leaks
}

fn extract_sourcemap_comments(html: &str, leaks: &mut Vec<SourceMapLeak>, base_url: &str) {
    let patterns = ["//# sourceMappingURL=", "//@ sourceMappingURL="];
    for pattern in &patterns {
        let mut search_from = 0;
        while let Some(pos) = html[search_from..].find(pattern) {
            let abs_pos = search_from + pos + pattern.len();
            let rest = &html[abs_pos..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '\'' || c == '"' || c == '<')
                .unwrap_or(rest.len());
            let map_ref = &rest[..end];
            search_from = abs_pos + end;

            if !map_ref.is_empty() && !map_ref.starts_with("data:") {
                let full_url = resolve_url(base_url, map_ref);
                leaks.push(SourceMapLeak {
                    script_url: String::new(),
                    map_url: full_url,
                });
            }
        }
    }
}

fn resolve_url(base: &str, relative: &str) -> String {
    if relative.starts_with("http://")
        || relative.starts_with("https://")
        || relative.starts_with("//")
    {
        return relative.to_string();
    }
    let base_trimmed = base.trim_end_matches('/');
    if relative.starts_with('/')
        && let Some(origin_end) = base_trimmed.find("//").map(|p| {
            base_trimmed[p + 2..]
                .find('/')
                .map(|s| p + 2 + s)
                .unwrap_or(base_trimmed.len())
        })
    {
        return format!(
            "{}/{}",
            &base_trimmed[..origin_end],
            relative.trim_start_matches('/')
        );
    }
    format!("{base_trimmed}/{relative}")
}

pub fn sourcemap_to_operations(leaks: &[SourceMapLeak], seq: &mut u64) -> Vec<OperationLogEntry> {
    if leaks.is_empty() {
        return Vec::new();
    }

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::InformationDisclosure,
        4.0,
        0.8,
    )]
}
