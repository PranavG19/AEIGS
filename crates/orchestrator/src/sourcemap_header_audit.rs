use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum SourceMapIssue {
    HeaderExposed { url: String },
    InlineSourceMap { file_type: String },
    SourceMappingUrlComment { url: String },
    ExternalSourceMapAccessible { url: String },
    MultipleSourceMaps { count: usize },
    SourceMapToThirdParty { url: String },
    UnprotectedSourceMapPath { path: String },
}

impl std::fmt::Display for SourceMapIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderExposed { .. } => write!(f, "header_exposed"),
            Self::InlineSourceMap { .. } => write!(f, "inline_source_map"),
            Self::SourceMappingUrlComment { .. } => write!(f, "source_mapping_url_comment"),
            Self::ExternalSourceMapAccessible { .. } => {
                write!(f, "external_source_map_accessible")
            }
            Self::MultipleSourceMaps { .. } => write!(f, "multiple_source_maps"),
            Self::SourceMapToThirdParty { .. } => write!(f, "source_map_to_third_party"),
            Self::UnprotectedSourceMapPath { .. } => write!(f, "unprotected_source_map_path"),
        }
    }
}

pub fn sourcemap_severity(issue: &SourceMapIssue) -> f64 {
    match issue {
        SourceMapIssue::HeaderExposed { .. } => 5.0,
        SourceMapIssue::InlineSourceMap { .. } => 6.0,
        SourceMapIssue::SourceMappingUrlComment { .. } => 4.5,
        SourceMapIssue::ExternalSourceMapAccessible { .. } => 5.5,
        SourceMapIssue::MultipleSourceMaps { .. } => 3.0,
        SourceMapIssue::SourceMapToThirdParty { .. } => 5.5,
        SourceMapIssue::UnprotectedSourceMapPath { .. } => 4.0,
    }
}

pub fn audit_sourcemap_header(target: &str) -> Vec<SourceMapIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let sm_value = resp
        .headers()
        .get("sourcemap")
        .or_else(|| resp.headers().get("x-sourcemap"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body = resp.text().unwrap_or_default();
    analyze_sourcemap(sm_value.as_deref(), &body)
}

pub fn analyze_sourcemap(header_value: Option<&str>, body: &str) -> Vec<SourceMapIssue> {
    let mut issues = Vec::new();

    if let Some(val) = header_value {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            issues.push(SourceMapIssue::HeaderExposed {
                url: trimmed.to_string(),
            });
        }
    }

    let mut sourcemap_ref_count = 0usize;
    let mut referenced_urls: Vec<String> = Vec::new();

    for line in body.lines() {
        if let Some(rest) = extract_line_comment_url(line) {
            sourcemap_ref_count += 1;
            let url = rest.trim().to_string();
            if url.starts_with("data:") {
                let file_type = detect_file_type(line);
                issues.push(SourceMapIssue::InlineSourceMap { file_type });
            } else {
                issues.push(SourceMapIssue::SourceMappingUrlComment { url: url.clone() });
                referenced_urls.push(url);
            }
        } else if let Some(rest) = extract_block_comment_url(line) {
            sourcemap_ref_count += 1;
            let url = rest.trim().to_string();
            if url.starts_with("data:") {
                let file_type = detect_file_type(line);
                issues.push(SourceMapIssue::InlineSourceMap { file_type });
            } else {
                issues.push(SourceMapIssue::SourceMappingUrlComment { url: url.clone() });
                referenced_urls.push(url);
            }
        }
    }

    for url in &referenced_urls {
        if is_third_party_url(url) {
            issues.push(SourceMapIssue::SourceMapToThirdParty { url: url.clone() });
        }
    }

    for url in &referenced_urls {
        if url.ends_with(".map") {
            issues.push(SourceMapIssue::ExternalSourceMapAccessible { url: url.clone() });
        }
    }

    if sourcemap_ref_count > 1 {
        issues.push(SourceMapIssue::MultipleSourceMaps {
            count: sourcemap_ref_count,
        });
    }

    let unprotected_paths = detect_unprotected_paths(body);
    for path in unprotected_paths {
        issues.push(SourceMapIssue::UnprotectedSourceMapPath { path });
    }

    issues
}

fn extract_line_comment_url(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    let prefix = "//# sourceMappingURL=";
    if let Some(rest) = trimmed.strip_prefix(prefix)
        && !rest.trim().is_empty()
    {
        return Some(rest);
    }
    None
}

fn extract_block_comment_url(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    let prefix = "/*# sourceMappingURL=";
    if let Some(rest) = trimmed.strip_prefix(prefix) {
        let url_part = rest.trim_end_matches("*/").trim();
        if !url_part.is_empty() {
            return Some(url_part);
        }
    }
    None
}

fn detect_file_type(line: &str) -> String {
    if line.trim().starts_with("/*#") {
        return "css".to_string();
    }
    "js".to_string()
}

fn is_third_party_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

const UNPROTECTED_PREFIXES: &[&str] = &["/js/", "/assets/", "/dist/", "/build/"];

fn detect_unprotected_paths(body: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        for prefix in UNPROTECTED_PREFIXES {
            if let Some(idx) = trimmed.find(prefix) {
                let candidate = &trimmed[idx..];
                if let Some(end) = find_map_path_end(candidate) {
                    let path = &candidate[..end];
                    if path.ends_with(".map") {
                        paths.push(path.to_string());
                    }
                }
            }
        }
    }
    paths
}

fn find_map_path_end(s: &str) -> Option<usize> {
    for (i, ch) in s.char_indices() {
        if i == 0 {
            continue;
        }
        if ch == ' ' || ch == '"' || ch == '\'' || ch == ')' || ch == '>' || ch == '\n' {
            return Some(i);
        }
    }
    Some(s.len())
}

pub fn sourcemap_header_to_operations(
    issues: &[SourceMapIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                sourcemap_severity(issue),
                0.5,
            )
        })
        .collect()
}
