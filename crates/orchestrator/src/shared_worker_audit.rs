use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum SharedWorkerIssue {
    ApiDetected,
    CrossTabDataLeak,
    ExternalWorkerScript,
    PersistentConnection,
    CryptoMining,
}

impl std::fmt::Display for SharedWorkerIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::CrossTabDataLeak => write!(f, "cross_tab_data_leak"),
            Self::ExternalWorkerScript => write!(f, "external_worker_script"),
            Self::PersistentConnection => write!(f, "persistent_connection"),
            Self::CryptoMining => write!(f, "crypto_mining"),
        }
    }
}

pub fn audit_shared_worker(target: &str) -> Vec<SharedWorkerIssue> {
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
    analyze_shared_worker(&body)
}

pub fn analyze_shared_worker(body: &str) -> Vec<SharedWorkerIssue> {
    if !body.contains("SharedWorker") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(SharedWorkerIssue::ApiDetected);

    if has_cross_tab_data_leak(body) {
        issues.push(SharedWorkerIssue::CrossTabDataLeak);
    }

    if has_external_worker_script(body) {
        issues.push(SharedWorkerIssue::ExternalWorkerScript);
    }

    if has_persistent_connection(body) {
        issues.push(SharedWorkerIssue::PersistentConnection);
    }

    if has_crypto_mining(body) {
        issues.push(SharedWorkerIssue::CryptoMining);
    }

    issues
}

fn has_cross_tab_data_leak(body: &str) -> bool {
    let has_messaging = body.contains("postMessage") || body.contains("onmessage");
    let has_storage = body.contains("localStorage")
        || body.contains("sessionStorage")
        || body.contains("cookie")
        || body.contains("credential");
    has_messaging && has_storage
}

fn has_external_worker_script(body: &str) -> bool {
    let marker = "new SharedWorker(";
    let mut search_from = 0;
    while let Some(pos) = body[search_from..].find(marker) {
        let start = search_from + pos + marker.len();
        let rest = &body[start..];
        let window = &rest[..rest.len().min(200)];
        if window.contains("://") {
            return true;
        }
        search_from = start;
    }
    false
}

fn has_persistent_connection(body: &str) -> bool {
    let has_connection =
        body.contains("WebSocket") || body.contains("EventSource") || body.contains("fetch(");
    let has_cleanup = body.contains("close(") || body.contains("terminate");
    has_connection && !has_cleanup
}

fn has_crypto_mining(body: &str) -> bool {
    let has_crypto_hint =
        body.contains("crypto") || body.contains("hash") || body.contains("mine") || body.contains("wasm");
    let has_loop = body.contains("while")
        || body.contains("for(")
        || body.contains("for (")
        || body.contains("setInterval");
    has_crypto_hint && has_loop
}

pub fn shared_worker_severity(issue: &SharedWorkerIssue) -> f64 {
    match issue {
        SharedWorkerIssue::CryptoMining => 8.0,
        SharedWorkerIssue::ExternalWorkerScript => 7.5,
        SharedWorkerIssue::CrossTabDataLeak => 7.0,
        SharedWorkerIssue::PersistentConnection => 6.0,
        SharedWorkerIssue::ApiDetected => 2.0,
    }
}

pub fn shared_worker_to_operations(
    issues: &[SharedWorkerIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                shared_worker_severity(issue),
                0.5,
            )
        })
        .collect()
}
