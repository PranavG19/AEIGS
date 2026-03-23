use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

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
    let lower = html.to_ascii_lowercase();
    let mut search_from = 0;

    while let Some(start) = lower[search_from..].find("<script") {
        let abs_start = search_from + start;
        let Some(end) = lower[abs_start..].find('>') else {
            break;
        };
        let tag = &html[abs_start..abs_start + end + 1];
        let tag_lower = &lower[abs_start..abs_start + end + 1];
        search_from = abs_start + end + 1;

        let Some(src) = extract_src(tag, tag_lower) else {
            continue;
        };

        let map_url = if src.ends_with(".js") {
            format!("{src}.map")
        } else {
            continue;
        };

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

fn extract_src(tag: &str, tag_lower: &str) -> Option<String> {
    let pos = tag_lower.find("src=")?;
    let rest = &tag[pos + 4..];
    let trimmed = rest.trim_start();
    if let Some(stripped) = trimmed.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else if let Some(stripped) = trimmed.strip_prefix('\'') {
        let end = stripped.find('\'')?;
        Some(stripped[..end].to_string())
    } else {
        let end = trimmed
            .find(|c: char| c.is_whitespace() || c == '>')
            .unwrap_or(trimmed.len());
        Some(trimmed[..end].to_string())
    }
}

fn resolve_url(base: &str, relative: &str) -> String {
    if relative.starts_with("http://") || relative.starts_with("https://") || relative.starts_with("//")
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

pub fn sourcemap_to_operations(
    leaks: &[SourceMapLeak],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
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
