use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum ServiceWorkerIssue {
    ApiDetected,
    HttpOrigin,
    ExternalImport { url: String },
    BroadScope { scope: String },
    CachesCredentials,
    UnvalidatedCachePut,
    InterceptionWithoutAuth,
    NoUpdateMechanism,
}

impl std::fmt::Display for ServiceWorkerIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::HttpOrigin => write!(f, "http_origin"),
            Self::ExternalImport { url } => write!(f, "external_import:{url}"),
            Self::BroadScope { scope } => write!(f, "broad_scope:{scope}"),
            Self::CachesCredentials => write!(f, "caches_credentials"),
            Self::UnvalidatedCachePut => write!(f, "unvalidated_cache_put"),
            Self::InterceptionWithoutAuth => write!(f, "interception_without_auth"),
            Self::NoUpdateMechanism => write!(f, "no_update_mechanism"),
        }
    }
}

pub fn service_worker_severity(issue: &ServiceWorkerIssue) -> f64 {
    match issue {
        ServiceWorkerIssue::ExternalImport { .. } => 8.0,
        ServiceWorkerIssue::InterceptionWithoutAuth => 7.5,
        ServiceWorkerIssue::HttpOrigin => 7.0,
        ServiceWorkerIssue::CachesCredentials => 6.5,
        ServiceWorkerIssue::UnvalidatedCachePut => 6.0,
        ServiceWorkerIssue::BroadScope { .. } => 5.0,
        ServiceWorkerIssue::NoUpdateMechanism => 4.0,
        ServiceWorkerIssue::ApiDetected => 2.0,
    }
}

pub fn audit_service_worker(target: &str) -> Vec<ServiceWorkerIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    let is_http = target.starts_with("http://");
    analyze_service_worker(&body, is_http)
}

pub fn analyze_service_worker(body: &str, is_http: bool) -> Vec<ServiceWorkerIssue> {
    let mut issues = Vec::new();

    let has_sw_api = body.contains("navigator.serviceWorker.register")
        || body.contains("ServiceWorker")
        || body.contains("serviceWorker.controller")
        || body.contains("importScripts(")
        || body.contains("addEventListener('fetch'")
        || body.contains("addEventListener(\"fetch\"")
        || body.contains("cache.put")
        || body.contains("cache.add")
        || body.contains("caches.open")
        || body.contains("caches.match")
        || body.contains("skipWaiting")
        || body.contains("clients.claim");

    if !has_sw_api {
        return issues;
    }

    issues.push(ServiceWorkerIssue::ApiDetected);

    if is_http {
        issues.push(ServiceWorkerIssue::HttpOrigin);
    }

    let registrations = extract_sw_registrations(body);
    for (_path, scope) in &registrations {
        if let Some(s) = scope
            && (s == "/" || s == "/*")
        {
            issues.push(ServiceWorkerIssue::BroadScope { scope: s.clone() });
        }
    }

    if body.contains("importScripts(") {
        for url in extract_import_urls(body) {
            if url.starts_with("http://") || url.starts_with("https://") {
                issues.push(ServiceWorkerIssue::ExternalImport { url });
            }
        }
    }

    let has_caching = body.contains("cache.put")
        || body.contains("cache.add")
        || body.contains("caches.open")
        || body.contains("caches.match");

    if has_caching {
        let has_credentials = body.contains("Authorization")
            || body.contains("Cookie")
            || body.contains("Token")
            || body.contains("password")
            || body.contains("secret");

        if has_credentials {
            issues.push(ServiceWorkerIssue::CachesCredentials);
        }

        let has_validation = body.contains("response.ok")
            || body.contains("response.status")
            || body.contains("response.headers");

        if !has_validation && body.contains("cache.put") {
            issues.push(ServiceWorkerIssue::UnvalidatedCachePut);
        }
    }

    if body.contains("addEventListener('fetch'") || body.contains("addEventListener(\"fetch\"") {
        let has_auth_check = body.contains("Authorization")
            || body.contains("authenticate")
            || body.contains("checkAuth")
            || body.contains("verifyToken");

        if !has_auth_check {
            issues.push(ServiceWorkerIssue::InterceptionWithoutAuth);
        }
    }

    let has_update = body.contains("skipWaiting") || body.contains("clients.claim");
    if !has_update {
        issues.push(ServiceWorkerIssue::NoUpdateMechanism);
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
                0.5,
            )
        })
        .collect()
}
