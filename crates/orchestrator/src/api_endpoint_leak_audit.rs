use std::collections::HashSet;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ApiEndpointLeak {
    InternalApiPath { path: String },
    VersionedEndpoint { path: String },
    AdminEndpoint { path: String },
    DebugEndpoint { path: String },
    GraphqlEndpoint { path: String },
}

impl std::fmt::Display for ApiEndpointLeak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalApiPath { path } => write!(f, "internal_api:{path}"),
            Self::VersionedEndpoint { path } => write!(f, "versioned_api:{path}"),
            Self::AdminEndpoint { path } => write!(f, "admin_endpoint:{path}"),
            Self::DebugEndpoint { path } => write!(f, "debug_endpoint:{path}"),
            Self::GraphqlEndpoint { path } => write!(f, "graphql_endpoint:{path}"),
        }
    }
}

const INTERNAL_PREFIXES: &[&str] = &[
    "/api/internal",
    "/api/private",
    "/api/admin",
    "/internal/",
    "/_internal/",
    "/api/debug",
    "/api/test",
    "/api/staging",
    "/api/dev",
];

const ADMIN_PATTERNS: &[&str] = &[
    "/admin/",
    "/administrator/",
    "/manage/",
    "/management/",
    "/dashboard/api",
    "/backoffice/",
    "/console/",
    "/panel/",
];

const DEBUG_PATTERNS: &[&str] = &[
    "/debug/",
    "/trace/",
    "/healthcheck",
    "/health",
    "/metrics",
    "/actuator/",
    "/status",
    "/__debug__",
    "/_profiler",
    "/phpinfo",
    "/server-status",
    "/server-info",
    "/elmah.axd",
];

const GRAPHQL_PATTERNS: &[&str] = &[
    "/graphql",
    "/graphiql",
    "/altair",
    "/playground",
    "/api/graphql",
    "/gql",
    "/v1/graphql",
];

pub fn audit_api_endpoint_leaks(target: &str) -> Vec<ApiEndpointLeak> {
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
    analyze_api_endpoint_leaks(&body)
}

pub fn analyze_api_endpoint_leaks(body: &str) -> Vec<ApiEndpointLeak> {
    let paths = extract_paths(body);
    let mut issues = Vec::new();
    let mut seen = HashSet::new();

    for path in &paths {
        let lower = path.to_ascii_lowercase();

        for &prefix in INTERNAL_PREFIXES {
            if lower.starts_with(prefix) && seen.insert(("internal", path.clone())) {
                issues.push(ApiEndpointLeak::InternalApiPath {
                    path: path.clone(),
                });
                break;
            }
        }

        if is_versioned_api(&lower) && seen.insert(("versioned", path.clone())) {
            issues.push(ApiEndpointLeak::VersionedEndpoint {
                path: path.clone(),
            });
        }

        for &pattern in ADMIN_PATTERNS {
            if lower.contains(pattern) && seen.insert(("admin", path.clone())) {
                issues.push(ApiEndpointLeak::AdminEndpoint {
                    path: path.clone(),
                });
                break;
            }
        }

        for &pattern in DEBUG_PATTERNS {
            if lower.starts_with(pattern) || lower.contains(pattern) {
                if seen.insert(("debug", path.clone())) {
                    issues.push(ApiEndpointLeak::DebugEndpoint {
                        path: path.clone(),
                    });
                }
                break;
            }
        }

        for &pattern in GRAPHQL_PATTERNS {
            if lower == pattern || lower.starts_with(&format!("{pattern}/")) {
                if seen.insert(("graphql", path.clone())) {
                    issues.push(ApiEndpointLeak::GraphqlEndpoint {
                        path: path.clone(),
                    });
                }
                break;
            }
        }
    }

    issues
}

fn extract_paths(body: &str) -> Vec<String> {
    let mut paths = HashSet::new();

    for prefix in ["\"", "'", "`"] {
        let search = format!("{prefix}/");
        let mut pos = 0;
        while let Some(idx) = body[pos..].find(&search) {
            let abs = pos + idx + prefix.len();
            let remaining = &body[abs..];
            let end = remaining
                .find(['"', '\'', '`', ' ', '<', '>', '\n', '\r'])
                .unwrap_or(remaining.len().min(200));
            let path = &remaining[..end];
            if is_likely_api_path(path) {
                paths.insert(path.to_string());
            }
            pos = abs + end;
        }
    }

    paths.into_iter().collect()
}

fn is_likely_api_path(path: &str) -> bool {
    if path.len() < 4 || path.len() > 200 {
        return false;
    }
    if !path.starts_with('/') {
        return false;
    }
    if path.contains("..") || path.contains("\\") {
        return false;
    }
    let ext_pos = path.rfind('.');
    if let Some(pos) = ext_pos {
        let ext = &path[pos..];
        if matches!(
            ext,
            ".js" | ".css" | ".png" | ".jpg" | ".gif" | ".svg" | ".ico" | ".woff" | ".woff2"
                | ".ttf" | ".eot" | ".map"
        ) {
            return false;
        }
    }
    true
}

fn is_versioned_api(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if !lower.contains("/api/") && !lower.starts_with("/api") {
        return false;
    }
    let version_patterns = [
        "/v1/", "/v2/", "/v3/", "/v4/", "/v1", "/v2", "/v3", "/v4",
    ];
    version_patterns.iter().any(|p| lower.contains(p))
}

pub fn api_endpoint_leak_severity(issue: &ApiEndpointLeak) -> f64 {
    match issue {
        ApiEndpointLeak::AdminEndpoint { .. } => 6.5,
        ApiEndpointLeak::DebugEndpoint { .. } => 6.0,
        ApiEndpointLeak::InternalApiPath { .. } => 5.5,
        ApiEndpointLeak::GraphqlEndpoint { .. } => 4.5,
        ApiEndpointLeak::VersionedEndpoint { .. } => 3.0,
    }
}

pub fn api_endpoint_leak_to_operations(
    issues: &[ApiEndpointLeak],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                api_endpoint_leak_severity(issue),
                0.7,
            )
        })
        .collect()
}
