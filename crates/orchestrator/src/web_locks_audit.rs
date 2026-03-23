use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum WebLocksIssue {
    ApiDetected,
    DeadlockRisk,
    ResourceStarvation,
    SharedStateCorruption,
    LockEnumeration,
}

impl std::fmt::Display for WebLocksIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DeadlockRisk => write!(f, "deadlock_risk"),
            Self::ResourceStarvation => write!(f, "resource_starvation"),
            Self::SharedStateCorruption => write!(f, "shared_state_corruption"),
            Self::LockEnumeration => write!(f, "lock_enumeration"),
        }
    }
}

pub fn web_locks_severity(issue: &WebLocksIssue) -> f64 {
    match issue {
        WebLocksIssue::ApiDetected => 2.0,
        WebLocksIssue::DeadlockRisk => 6.0,
        WebLocksIssue::ResourceStarvation => 6.5,
        WebLocksIssue::SharedStateCorruption => 7.5,
        WebLocksIssue::LockEnumeration => 5.0,
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
    let mut issues = Vec::new();

    let has_lock_request = body.contains("navigator.locks.request");
    let has_lock_query = body.contains("navigator.locks.query");
    let has_lock_manager = body.contains("LockManager");

    if has_lock_request || has_lock_query || has_lock_manager {
        issues.push(WebLocksIssue::ApiDetected);
    }

    if has_lock_request {
        let has_nested_request = body.matches("navigator.locks.request").count() >= 2;
        let has_timeout = body.contains("signal:") || body.contains("AbortController");

        if has_nested_request && !has_timeout {
            issues.push(WebLocksIssue::DeadlockRisk);
        }

        let has_catch = body.contains(".catch(") || body.contains("} catch");
        let has_finally = body.contains(".finally(") || body.contains("} finally");

        if !has_catch && !has_finally {
            issues.push(WebLocksIssue::ResourceStarvation);
        }

        let has_shared_mode = body.contains("mode: \"shared\"") || body.contains("mode:'shared'");
        let has_write_operation =
            body.contains("=") && (body.contains("state") || body.contains("data"));

        if has_shared_mode && has_write_operation {
            issues.push(WebLocksIssue::SharedStateCorruption);
        }
    }

    if has_lock_query {
        issues.push(WebLocksIssue::LockEnumeration);
    }

    issues
}

pub fn web_locks_to_operations(issues: &[WebLocksIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                web_locks_severity(issue),
                0.5,
            )
        })
        .collect()
}
