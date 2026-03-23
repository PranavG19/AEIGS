use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;
use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum AbortControllerIssue {
    ApiDetected,
    DenialOfService,
    SecurityBypass,
    RaceCondition,
    ResourceLeak,
}

impl std::fmt::Display for AbortControllerIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DenialOfService => write!(f, "denial_of_service"),
            Self::SecurityBypass => write!(f, "security_bypass"),
            Self::RaceCondition => write!(f, "race_condition"),
            Self::ResourceLeak => write!(f, "resource_leak"),
        }
    }
}

pub fn audit_abort_controller(target: &str) -> Vec<AbortControllerIssue> {
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
    analyze_abort_controller(&body)
}

pub fn analyze_abort_controller(body: &str) -> Vec<AbortControllerIssue> {
    let mut issues = Vec::new();

    let has_abort_controller = body.contains("AbortController");
    let has_abort_signal = body.contains("AbortSignal");
    let has_signal_aborted = body.contains("signal.aborted");
    let api_detected = has_abort_controller || has_abort_signal || has_signal_aborted;

    if api_detected {
        issues.push(AbortControllerIssue::ApiDetected);
    }

    let has_abort_call = body.contains("abort()");
    let has_new_abort_controller = body.contains("new AbortController");

    if api_detected && has_abort_call {
        let has_timing = body.contains("setInterval")
            || body.contains("setTimeout")
            || body.contains("requestAnimationFrame");
        let has_cleanup = body.contains("clearInterval")
            || body.contains("clearTimeout")
            || body.contains("cancelAnimationFrame");

        if has_timing && !has_cleanup {
            issues.push(AbortControllerIssue::DenialOfService);
        }
    }

    if api_detected && has_abort_call {
        let has_security = body.contains("csrf")
            || body.contains("token")
            || body.contains("auth")
            || body.contains("verify")
            || body.contains("captcha");

        if has_security {
            issues.push(AbortControllerIssue::SecurityBypass);
        }
    }

    if api_detected && has_abort_call {
        let has_race = body.contains("Promise.race")
            || body.contains("Promise.any")
            || body.contains("setTimeout");
        let has_request = body.contains("fetch(") || body.contains("XMLHttpRequest");

        if has_race && has_request {
            issues.push(AbortControllerIssue::RaceCondition);
        }
    }

    if has_new_abort_controller {
        let has_cleanup = body.contains("abort()")
            || body.contains("removeEventListener")
            || body.contains("finally");

        if !has_cleanup {
            issues.push(AbortControllerIssue::ResourceLeak);
        }
    }

    issues
}

pub fn abort_controller_severity(issue: &AbortControllerIssue) -> f64 {
    match issue {
        AbortControllerIssue::ApiDetected => 2.0,
        AbortControllerIssue::DenialOfService => 7.0,
        AbortControllerIssue::SecurityBypass => 7.5,
        AbortControllerIssue::RaceCondition => 6.5,
        AbortControllerIssue::ResourceLeak => 5.5,
    }
}

pub fn abort_controller_to_operations(
    issues: &[AbortControllerIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                abort_controller_severity(issue),
                0.5,
            )
        })
        .collect()
}
