use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;
use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ObservableIssue {
    ApiDetected,
    MemoryLeak,
    InfiniteStream,
    SideEffectExfiltration,
    ErrorSuppression,
}

impl std::fmt::Display for ObservableIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "observable_api_detected"),
            Self::MemoryLeak => write!(f, "observable_memory_leak"),
            Self::InfiniteStream => write!(f, "observable_infinite_stream"),
            Self::SideEffectExfiltration => write!(f, "observable_side_effect_exfiltration"),
            Self::ErrorSuppression => write!(f, "observable_error_suppression"),
        }
    }
}

pub fn audit_observable(target: &str) -> Vec<ObservableIssue> {
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
    analyze_observable(&body)
}

pub fn analyze_observable(body: &str) -> Vec<ObservableIssue> {
    let mut issues = Vec::new();

    let has_observable_api = body.contains("Observable")
        || body.contains("observable")
        || body.contains("subscribe")
        || body.contains("Subscriber");

    if has_observable_api {
        issues.push(ObservableIssue::ApiDetected);

        let has_subscribe_call = body.contains("subscribe(");
        let has_observable_creation = body.contains("new Observable");
        let has_cleanup = body.contains("unsubscribe")
            || body.contains("complete")
            || body.contains("abort")
            || body.contains("teardown");

        if (has_subscribe_call || has_observable_creation) && !has_cleanup {
            issues.push(ObservableIssue::MemoryLeak);
        }

        let has_unbounded = body.contains("interval")
            || body.contains("setInterval")
            || body.contains("requestAnimationFrame");
        let has_limiter = body.contains("take")
            || body.contains("takeUntil")
            || body.contains("limit")
            || body.contains("unsubscribe");

        if has_unbounded && !has_limiter {
            issues.push(ObservableIssue::InfiniteStream);
        }

        let has_exfil = body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest");

        if has_subscribe_call && has_exfil {
            issues.push(ObservableIssue::SideEffectExfiltration);
        }

        let has_error_handling = body.contains("catch") || body.contains("error");
        let has_error_propagation = body.contains("throw")
            || body.contains("reject")
            || body.contains("console.error")
            || body.contains("report");

        if has_subscribe_call && has_error_handling && !has_error_propagation {
            issues.push(ObservableIssue::ErrorSuppression);
        }
    }

    issues
}

pub fn observable_severity(issue: &ObservableIssue) -> f64 {
    match issue {
        ObservableIssue::ApiDetected => 2.0,
        ObservableIssue::MemoryLeak => 6.5,
        ObservableIssue::InfiniteStream => 6.0,
        ObservableIssue::SideEffectExfiltration => 7.0,
        ObservableIssue::ErrorSuppression => 5.5,
    }
}

pub fn observable_to_operations(
    issues: &[ObservableIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                observable_severity(issue),
                0.5,
            )
        })
        .collect()
}
