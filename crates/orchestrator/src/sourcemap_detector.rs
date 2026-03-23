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

pub fn find_sourcemap_references(html: &str, base_url: &str) -> Vec<SourceMapLeak> {
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

pub fn resolve_url(base: &str, relative: &str) -> String {
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

#[derive(Debug, Clone, PartialEq)]
pub enum SourceMapDetectorIssue {
    ExposedSourceMap { script_url: String, map_url: String },
    ThirdPartySourceMap { script_url: String, cdn: String },
    InlineSourceMap { script_url: String },
    MultipleSourceMaps { count: usize },
    ProductionSourceMap { script_url: String },
    SensitivePathExposed { path: String },
    SourceMapComment { comment_type: String, url: String },
    UnminifiedSource { script_url: String },
}

impl std::fmt::Display for SourceMapDetectorIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExposedSourceMap {
                script_url,
                map_url,
            } => {
                write!(f, "exposed_sourcemap:{script_url}:{map_url}")
            }
            Self::ThirdPartySourceMap { script_url, cdn } => {
                write!(f, "third_party_sourcemap:{script_url}:{cdn}")
            }
            Self::InlineSourceMap { script_url } => write!(f, "inline_sourcemap:{script_url}"),
            Self::MultipleSourceMaps { count } => write!(f, "multiple_sourcemaps:{count}"),
            Self::ProductionSourceMap { script_url } => {
                write!(f, "production_sourcemap:{script_url}")
            }
            Self::SensitivePathExposed { path } => write!(f, "sensitive_path:{path}"),
            Self::SourceMapComment { comment_type, url } => {
                write!(f, "sourcemap_comment:{comment_type}:{url}")
            }
            Self::UnminifiedSource { script_url } => write!(f, "unminified_source:{script_url}"),
        }
    }
}

const SENSITIVE_PATH_PATTERNS: &[&str] = &[
    "/src/",
    "/source/",
    "/private/",
    "/internal/",
    "/admin/",
    "/config/",
    "/secret/",
    "/api/",
    "node_modules",
    ".env",
];

const CDN_HOSTS: &[(&str, &str)] = &[
    ("cdnjs.cloudflare.com", "Cloudflare CDN"),
    ("cdn.jsdelivr.net", "jsDelivr"),
    ("unpkg.com", "unpkg"),
    ("ajax.googleapis.com", "Google CDN"),
    ("code.jquery.com", "jQuery CDN"),
];

const PRODUCTION_INDICATORS: &[&str] = &[".min.js", ".prod.js", ".bundle.js", "vendor.", "chunk."];

pub fn sourcemap_issue_severity(issue: &SourceMapDetectorIssue) -> f64 {
    match issue {
        SourceMapDetectorIssue::SensitivePathExposed { .. } => 7.0,
        SourceMapDetectorIssue::ProductionSourceMap { .. } => 6.0,
        SourceMapDetectorIssue::ExposedSourceMap { .. } => 5.0,
        SourceMapDetectorIssue::InlineSourceMap { .. } => 4.5,
        SourceMapDetectorIssue::SourceMapComment { .. } => 4.5,
        SourceMapDetectorIssue::MultipleSourceMaps { .. } => 5.5,
        SourceMapDetectorIssue::ThirdPartySourceMap { .. } => 4.0,
        SourceMapDetectorIssue::UnminifiedSource { .. } => 3.0,
    }
}

pub fn analyze_sourcemap_leaks(leaks: &[SourceMapLeak], html: &str) -> Vec<SourceMapDetectorIssue> {
    let mut issues = Vec::new();

    for leak in leaks {
        issues.push(SourceMapDetectorIssue::ExposedSourceMap {
            script_url: leak.script_url.clone(),
            map_url: leak.map_url.clone(),
        });

        if is_production_script(&leak.script_url) {
            issues.push(SourceMapDetectorIssue::ProductionSourceMap {
                script_url: leak.script_url.clone(),
            });
        }

        for pattern in SENSITIVE_PATH_PATTERNS {
            if leak.map_url.contains(pattern) || leak.script_url.contains(pattern) {
                issues.push(SourceMapDetectorIssue::SensitivePathExposed {
                    path: if leak.map_url.contains(pattern) {
                        leak.map_url.clone()
                    } else {
                        leak.script_url.clone()
                    },
                });
                break;
            }
        }

        if let Some(cdn) = detect_cdn_host(&leak.script_url) {
            issues.push(SourceMapDetectorIssue::ThirdPartySourceMap {
                script_url: leak.script_url.clone(),
                cdn: cdn.to_string(),
            });
        }

        if !leak.script_url.is_empty()
            && !leak.script_url.contains(".min.")
            && !leak.script_url.contains(".prod.")
        {
            issues.push(SourceMapDetectorIssue::UnminifiedSource {
                script_url: leak.script_url.clone(),
            });
        }
    }

    // Check for sourcemap comments in HTML
    let comment_patterns = [
        ("sourceMappingURL", "//# sourceMappingURL="),
        ("legacy_sourceMappingURL", "//@ sourceMappingURL="),
    ];
    for (comment_type, pattern) in &comment_patterns {
        let mut search_from = 0;
        while let Some(pos) = html[search_from..].find(pattern) {
            let abs_pos = search_from + pos + pattern.len();
            let rest = &html[abs_pos..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '\'' || c == '"' || c == '<')
                .unwrap_or(rest.len());
            let url = &rest[..end];
            search_from = abs_pos + end;
            if !url.is_empty() && !url.starts_with("data:") {
                issues.push(SourceMapDetectorIssue::SourceMapComment {
                    comment_type: comment_type.to_string(),
                    url: url.to_string(),
                });
            }
        }
    }

    // Check for inline sourcemaps (data: URIs in sourceMappingURL)
    let mut search_from = 0;
    let inline_pattern = "sourceMappingURL=data:";
    while let Some(pos) = html[search_from..].find(inline_pattern) {
        issues.push(SourceMapDetectorIssue::InlineSourceMap {
            script_url: String::new(),
        });
        search_from = search_from + pos + inline_pattern.len();
    }

    if leaks.len() > 5 {
        issues.push(SourceMapDetectorIssue::MultipleSourceMaps { count: leaks.len() });
    }

    issues
}

fn is_production_script(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    PRODUCTION_INDICATORS.iter().any(|p| lower.contains(p))
}

fn detect_cdn_host(url: &str) -> Option<&'static str> {
    let normalized = if url.starts_with("//") {
        format!("https:{url}")
    } else {
        url.to_string()
    };
    let after_scheme = normalized.split("//").nth(1)?;
    let host = after_scheme.split('/').next()?;
    let host = host.split(':').next()?;
    let host_lower = host.to_ascii_lowercase();
    CDN_HOSTS
        .iter()
        .find(|(h, _)| host_lower == *h)
        .map(|(_, name)| *name)
}

pub fn sourcemap_issues_to_operations(
    issues: &[SourceMapDetectorIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                sourcemap_issue_severity(issue),
                0.5,
            )
        })
        .collect()
}
