use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const VALID_DIRECTIVES: &[&str] = &["cache", "cookies", "storage", "executioncontexts", "*"];

#[derive(Debug, Clone, PartialEq)]
pub enum ClearSiteDataIssue {
    WildcardOnGet,
    CookieClearOnGet,
    StorageClearOnGet,
    CacheClearOnGet,
    HttpNotHttps,
    ExecutionContextClear,
    MultipleClearDirectives { count: usize },
    ClearOnNavigationResponse,
    UnquotedDirective,
    UnknownDirective { directive: String },
}

impl std::fmt::Display for ClearSiteDataIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WildcardOnGet => write!(f, "wildcard_on_get"),
            Self::CookieClearOnGet => write!(f, "cookie_clear_on_get"),
            Self::StorageClearOnGet => write!(f, "storage_clear_on_get"),
            Self::CacheClearOnGet => write!(f, "cache_clear_on_get"),
            Self::HttpNotHttps => write!(f, "http_not_https"),
            Self::ExecutionContextClear => write!(f, "execution_context_clear"),
            Self::MultipleClearDirectives { count } => {
                write!(f, "multiple_clear_directives_{count}")
            }
            Self::ClearOnNavigationResponse => write!(f, "clear_on_navigation_response"),
            Self::UnquotedDirective => write!(f, "unquoted_directive"),
            Self::UnknownDirective { directive } => write!(f, "unknown_directive_{directive}"),
        }
    }
}

pub fn clear_site_data_severity(issue: &ClearSiteDataIssue) -> f64 {
    match issue {
        ClearSiteDataIssue::WildcardOnGet => 5.5,
        ClearSiteDataIssue::CookieClearOnGet => 4.5,
        ClearSiteDataIssue::StorageClearOnGet => 4.0,
        ClearSiteDataIssue::CacheClearOnGet => 3.0,
        ClearSiteDataIssue::HttpNotHttps => 2.0,
        ClearSiteDataIssue::ExecutionContextClear => 3.5,
        ClearSiteDataIssue::MultipleClearDirectives { .. } => 3.0,
        ClearSiteDataIssue::ClearOnNavigationResponse => 4.0,
        ClearSiteDataIssue::UnquotedDirective => 1.5,
        ClearSiteDataIssue::UnknownDirective { .. } => 2.0,
    }
}

pub fn audit_clear_site_data(target: &str) -> Vec<ClearSiteDataIssue> {
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

    let is_https = target.starts_with("https://");
    let has_location = resp.headers().contains_key("location");
    let value = resp
        .headers()
        .get("clear-site-data")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    analyze_clear_site_data(value.as_deref(), is_https, has_location)
}

pub fn analyze_clear_site_data(
    value: Option<&str>,
    is_https: bool,
    has_location: bool,
) -> Vec<ClearSiteDataIssue> {
    let Some(val) = value else {
        return Vec::new();
    };

    let mut issues = Vec::new();

    if !is_https {
        issues.push(ClearSiteDataIssue::HttpNotHttps);
    }

    if has_location {
        issues.push(ClearSiteDataIssue::ClearOnNavigationResponse);
    }

    let raw_parts: Vec<&str> = val.split(',').map(|s| s.trim()).collect();

    for part in &raw_parts {
        if (!part.starts_with('"') || !part.ends_with('"')) && !part.is_empty() {
            issues.push(ClearSiteDataIssue::UnquotedDirective);
            break;
        }
    }

    let owned_directives: Vec<String> = raw_parts
        .iter()
        .map(|s| s.trim_matches('"').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let directives: Vec<&str> = owned_directives.iter().map(|s| s.as_str()).collect();

    for d in &directives {
        if !VALID_DIRECTIVES.contains(d) {
            issues.push(ClearSiteDataIssue::UnknownDirective {
                directive: (*d).to_string(),
            });
        }
    }

    if directives.contains(&"*") {
        issues.push(ClearSiteDataIssue::WildcardOnGet);
        return issues;
    }

    if directives.len() >= 3 {
        issues.push(ClearSiteDataIssue::MultipleClearDirectives {
            count: directives.len(),
        });
    }

    if directives.contains(&"cookies") {
        issues.push(ClearSiteDataIssue::CookieClearOnGet);
    }

    if directives.contains(&"storage") {
        issues.push(ClearSiteDataIssue::StorageClearOnGet);
    }

    if directives.contains(&"cache") {
        issues.push(ClearSiteDataIssue::CacheClearOnGet);
    }

    if directives.contains(&"executioncontexts") {
        issues.push(ClearSiteDataIssue::ExecutionContextClear);
    }

    issues
}

pub fn clear_site_data_to_operations(
    issues: &[ClearSiteDataIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                clear_site_data_severity(issue),
                0.5,
            )
        })
        .collect()
}
