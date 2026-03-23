use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ServiceWorkerIssue {
    SwRegistered { scope: String },
    SwOnHttpOrigin,
    SwImportsExternalScript { url: String },
    SwBroadScope { scope: String },
    SwCachesCredentials,
}

impl std::fmt::Display for ServiceWorkerIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SwRegistered { scope } => write!(f, "sw_registered:{scope}"),
            Self::SwOnHttpOrigin => write!(f, "sw_http_origin"),
            Self::SwImportsExternalScript { url } => write!(f, "sw_external_import:{url}"),
            Self::SwBroadScope { scope } => write!(f, "sw_broad_scope:{scope}"),
            Self::SwCachesCredentials => write!(f, "sw_caches_credentials"),
        }
    }
}

pub fn audit_service_worker(target: &str) -> Vec<ServiceWorkerIssue> {
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

    let is_http = target.starts_with("http://");
    let body = resp.text().unwrap_or_default();
    analyze_service_worker_usage(&body, is_http)
}

pub fn analyze_service_worker_usage(body: &str, is_http: bool) -> Vec<ServiceWorkerIssue> {
    let mut issues = Vec::new();

    let registrations = extract_sw_registrations(body);

    for (sw_path, scope) in &registrations {
        issues.push(ServiceWorkerIssue::SwRegistered {
            scope: scope.clone().unwrap_or_else(|| sw_path.clone()),
        });

        if is_http {
            issues.push(ServiceWorkerIssue::SwOnHttpOrigin);
        }

        if let Some(s) = scope
            && (s == "/" || s == "/*")
        {
            issues.push(ServiceWorkerIssue::SwBroadScope {
                scope: s.clone(),
            });
        }
    }

    if body.contains("importScripts(") {
        for url in extract_import_urls(body) {
            if url.starts_with("http://") || url.starts_with("https://") {
                issues.push(ServiceWorkerIssue::SwImportsExternalScript { url });
            }
        }
    }

    let body_lower = body.to_ascii_lowercase();
    if body_lower.contains("cache.put")
        || body_lower.contains("cache.add")
        || body_lower.contains("caches.open")
    {
        let has_credential_caching = body_lower.contains("authorization")
            || body_lower.contains("cookie")
            || body_lower.contains("token")
            || body_lower.contains("credential");
        if has_credential_caching {
            issues.push(ServiceWorkerIssue::SwCachesCredentials);
        }
    }

    issues
}

fn extract_sw_registrations(body: &str) -> Vec<(String, Option<String>)> {
    let mut results = Vec::new();
    let prefix = "serviceWorker.register(";
    let mut search = body;

    while let Some(pos) = search.find(prefix) {
        let after = &search[pos + prefix.len()..];
        if let Some(path) = extract_quoted(after) {
            let scope = if let Some(scope_pos) = after.find("scope") {
                let scope_after = &after[scope_pos..];
                if let Some(colon_pos) = scope_after.find(':') {
                    extract_quoted(&scope_after[colon_pos + 1..])
                } else {
                    None
                }
            } else {
                None
            };
            results.push((path, scope));
        }
        search = &search[pos + prefix.len()..];
    }

    results
}

fn extract_import_urls(body: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let prefix = "importScripts(";
    let mut search = body;

    while let Some(pos) = search.find(prefix) {
        let after = &search[pos + prefix.len()..];
        if let Some(url) = extract_quoted(after) {
            urls.push(url);
        }
        search = &search[pos + prefix.len()..];
    }

    urls
}

fn extract_quoted(s: &str) -> Option<String> {
    let trimmed = s.trim_start();
    let quote = trimmed.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let inner = &trimmed[1..];
    let end = inner.find(quote)?;
    Some(inner[..end].to_string())
}

pub fn service_worker_severity(issue: &ServiceWorkerIssue) -> f64 {
    match issue {
        ServiceWorkerIssue::SwImportsExternalScript { .. } => 7.5,
        ServiceWorkerIssue::SwOnHttpOrigin => 7.0,
        ServiceWorkerIssue::SwCachesCredentials => 6.0,
        ServiceWorkerIssue::SwBroadScope { .. } => 4.0,
        ServiceWorkerIssue::SwRegistered { .. } => 2.0,
    }
}

pub fn service_worker_to_operations(
    issues: &[ServiceWorkerIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                service_worker_severity(issue),
                0.75,
            )
        })
        .collect()
}
