use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebLocksIssue {
    LockRequestDetected,
    LockQueryDetected,
    ExcessiveLockNames,
    SharedLockMode,
    StealLockOption,
    NoAbortSignal,
}

impl std::fmt::Display for WebLocksIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LockRequestDetected => write!(f, "lock_request_detected"),
            Self::LockQueryDetected => write!(f, "lock_query_detected"),
            Self::ExcessiveLockNames => write!(f, "excessive_lock_names"),
            Self::SharedLockMode => write!(f, "shared_lock_mode"),
            Self::StealLockOption => write!(f, "steal_lock_option"),
            Self::NoAbortSignal => write!(f, "no_abort_signal"),
        }
    }
}

pub fn audit_web_locks(target: &str) -> Vec<WebLocksIssue> {
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
    analyze_web_locks(&body)
}

pub fn analyze_web_locks(body: &str) -> Vec<WebLocksIssue> {
    if !body.contains("navigator.locks") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("navigator.locks.request") {
        issues.push(WebLocksIssue::LockRequestDetected);

        if body.contains("steal") && body.contains("true") {
            issues.push(WebLocksIssue::StealLockOption);
        }

        if !body.contains("AbortController") && !body.contains("signal") {
            issues.push(WebLocksIssue::NoAbortSignal);
        }

        let lock_name_count = count_unique_lock_names(body);
        if lock_name_count > 5 {
            issues.push(WebLocksIssue::ExcessiveLockNames);
        }

        if body.contains("\"shared\"") || body.contains("'shared'") {
            issues.push(WebLocksIssue::SharedLockMode);
        }
    }

    if body.contains("navigator.locks.query") {
        issues.push(WebLocksIssue::LockQueryDetected);
    }

    issues
}

fn count_unique_lock_names(body: &str) -> usize {
    let mut names = std::collections::HashSet::new();
    let marker = "navigator.locks.request(";
    let mut search_from = 0;
    while let Some(pos) = body[search_from..].find(marker) {
        let start = search_from + pos + marker.len();
        if start >= body.len() {
            break;
        }
        let rest = &body[start..];
        let name = if let Some(stripped) = rest.strip_prefix('"') {
            stripped.split('"').next()
        } else if let Some(stripped) = rest.strip_prefix('\'') {
            stripped.split('\'').next()
        } else {
            None
        };
        if let Some(n) = name {
            names.insert(n);
        }
        search_from = start;
    }
    names.len()
}

pub fn web_locks_severity(issue: &WebLocksIssue) -> f64 {
    match issue {
        WebLocksIssue::StealLockOption => 6.0,
        WebLocksIssue::LockQueryDetected => 5.5,
        WebLocksIssue::ExcessiveLockNames => 5.0,
        WebLocksIssue::SharedLockMode => 4.5,
        WebLocksIssue::NoAbortSignal => 4.0,
        WebLocksIssue::LockRequestDetected => 3.0,
    }
}

pub fn web_locks_to_operations(
    issues: &[WebLocksIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                web_locks_severity(issue),
                0.7,
            )
        })
        .collect()
}
