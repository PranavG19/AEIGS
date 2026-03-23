use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ApiVersionIssue {
    DeprecatedVersionInPath { version: String },
    NoVersionHeader,
    VersionMismatch { path_version: String, header_version: String },
    UnversionedApi,
    MultipleVersionSchemes,
}

impl std::fmt::Display for ApiVersionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeprecatedVersionInPath { version } => {
                write!(f, "deprecated_api_version:{version}")
            }
            Self::NoVersionHeader => write!(f, "no_api_version_header"),
            Self::VersionMismatch {
                path_version,
                header_version,
            } => write!(f, "version_mismatch:{path_version}|{header_version}"),
            Self::UnversionedApi => write!(f, "unversioned_api"),
            Self::MultipleVersionSchemes => write!(f, "multiple_version_schemes"),
        }
    }
}

const DEPRECATED_VERSIONS: &[&str] = &["v0", "v1"];

const VERSION_HEADERS: &[&str] = &[
    "api-version",
    "x-api-version",
    "x-version",
    "accept-version",
];

pub fn audit_api_versioning(target: &str) -> Vec<ApiVersionIssue> {
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

    let version_headers: Vec<(String, String)> = VERSION_HEADERS
        .iter()
        .filter_map(|&h| {
            resp.headers()
                .get(h)
                .and_then(|v| v.to_str().ok())
                .map(|v| (h.to_string(), v.to_string()))
        })
        .collect();

    let path = resp.url().path();

    analyze_api_versioning(path, &version_headers)
}

pub(crate) fn analyze_api_versioning(
    path: &str,
    version_headers: &[(String, String)],
) -> Vec<ApiVersionIssue> {
    let mut issues = Vec::new();

    let path_version = extract_path_version(path);

    if let Some(ref pv) = path_version {
        let pv_lower = pv.to_ascii_lowercase();
        for dep in DEPRECATED_VERSIONS {
            if pv_lower == *dep {
                issues.push(ApiVersionIssue::DeprecatedVersionInPath {
                    version: pv.clone(),
                });
                break;
            }
        }
    }

    let has_path_version = path_version.is_some();
    let has_header_version = !version_headers.is_empty();

    if !has_path_version && !has_header_version {
        issues.push(ApiVersionIssue::UnversionedApi);
    }

    if has_path_version && !has_header_version {
        issues.push(ApiVersionIssue::NoVersionHeader);
    }

    if has_path_version && has_header_version {
        if version_headers.len() > 1 {
            issues.push(ApiVersionIssue::MultipleVersionSchemes);
        }
        if let Some(ref pv) = path_version {
            for (_header, value) in version_headers {
                let header_num = extract_version_number(value);
                let path_num = extract_version_number(pv);
                if let (Some(pn), Some(hn)) = (path_num, header_num)
                    && pn != hn
                {
                    issues.push(ApiVersionIssue::VersionMismatch {
                        path_version: pv.clone(),
                        header_version: value.clone(),
                    });
                }
            }
        }
    }

    issues
}

fn extract_path_version(path: &str) -> Option<String> {
    for segment in path.split('/') {
        let lower = segment.to_ascii_lowercase();
        if lower.starts_with('v') && lower.len() >= 2 && lower[1..].chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return Some(segment.to_string());
        }
    }
    None
}

fn extract_version_number(s: &str) -> Option<u32> {
    let trimmed = s.trim().to_ascii_lowercase();
    let num_str = trimmed.strip_prefix('v').unwrap_or(&trimmed);
    let major = num_str.split('.').next()?;
    major.parse().ok()
}

pub(crate) fn api_version_severity(issue: &ApiVersionIssue) -> f64 {
    match issue {
        ApiVersionIssue::DeprecatedVersionInPath { .. } => 5.0,
        ApiVersionIssue::VersionMismatch { .. } => 4.0,
        ApiVersionIssue::MultipleVersionSchemes => 3.5,
        ApiVersionIssue::UnversionedApi => 3.0,
        ApiVersionIssue::NoVersionHeader => 2.0,
    }
}

pub fn api_version_to_operations(
    issues: &[ApiVersionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .filter(|i| api_version_severity(i) >= 3.0)
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                api_version_severity(issue),
                0.8,
            )
        })
        .collect()
}
