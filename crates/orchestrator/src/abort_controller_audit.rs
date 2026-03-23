use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

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

#[derive(Debug, Clone, PartialEq)]
pub enum AbortControllerSecurityIssue {
    MissingAbortController,
    AbortSignalLeak,
    RaceConditionOnAbort,
    UnhandledAbortError,
    AbortControllerReuse,
    AbortTimeoutMissing,
    CascadingAbortFailure,
    AbortWithoutCleanup,
    AbortSignalCrossOrigin,
    GlobalAbortController,
}

impl std::fmt::Display for AbortControllerSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAbortController => write!(f, "missing_abort_controller"),
            Self::AbortSignalLeak => write!(f, "abort_signal_leak"),
            Self::RaceConditionOnAbort => write!(f, "race_condition_on_abort"),
            Self::UnhandledAbortError => write!(f, "unhandled_abort_error"),
            Self::AbortControllerReuse => write!(f, "abort_controller_reuse"),
            Self::AbortTimeoutMissing => write!(f, "abort_timeout_missing"),
            Self::CascadingAbortFailure => write!(f, "cascading_abort_failure"),
            Self::AbortWithoutCleanup => write!(f, "abort_without_cleanup"),
            Self::AbortSignalCrossOrigin => write!(f, "abort_signal_cross_origin"),
            Self::GlobalAbortController => write!(f, "global_abort_controller"),
        }
    }
}

pub fn analyze_abort_controller_security(body: &str) -> Vec<AbortControllerSecurityIssue> {
    let mut issues = Vec::new();

    let has_fetch = body.contains("fetch(");
    let has_xhr = body.contains("XMLHttpRequest");
    let has_abort_controller = body.contains("AbortController");
    let has_abort_signal = body.contains("AbortSignal");

    if (has_fetch || has_xhr) && !has_abort_controller && !has_abort_signal {
        issues.push(AbortControllerSecurityIssue::MissingAbortController);
    }

    if has_abort_signal || has_abort_controller {
        let has_window_signal =
            body.contains("window.signal") || body.contains("globalThis.signal");
        let has_export_signal = body.contains("export const signal")
            || body.contains("export let signal")
            || body.contains("module.exports.signal");

        if has_window_signal || has_export_signal {
            issues.push(AbortControllerSecurityIssue::AbortSignalLeak);
        }
    }

    if has_abort_controller {
        let has_abort_call = body.contains(".abort()");
        let has_promise_race = body.contains("Promise.race") || body.contains("Promise.any");
        let has_event_listener = body.contains("addEventListener");

        if has_abort_call && has_promise_race && !has_event_listener {
            issues.push(AbortControllerSecurityIssue::RaceConditionOnAbort);
        }
    }

    if has_abort_controller || has_abort_signal {
        let has_abort_call = body.contains(".abort()");
        let has_try_catch = body.contains("try") && body.contains("catch");
        let has_abort_error = body.contains("AbortError") || body.contains("DOMException");

        if has_abort_call && !has_try_catch && !has_abort_error {
            issues.push(AbortControllerSecurityIssue::UnhandledAbortError);
        }
    }

    if has_abort_controller {
        let controller_count = body.matches("new AbortController").count();
        let abort_count = body.matches(".abort()").count();

        if controller_count > 0 && abort_count > controller_count {
            issues.push(AbortControllerSecurityIssue::AbortControllerReuse);
        }
    }

    if has_abort_controller && has_fetch {
        let has_timeout = body.contains("setTimeout")
            || body.contains("setInterval")
            || body.contains("timeout:")
            || body.contains("AbortSignal.timeout");

        if !has_timeout {
            issues.push(AbortControllerSecurityIssue::AbortTimeoutMissing);
        }
    }

    if has_abort_controller {
        let has_multiple_signals =
            body.matches("signal:").count() > 1 || body.matches(".signal").count() > 1;
        let has_abort_all =
            body.contains("abortAll") || body.contains("abort()") && body.contains("forEach");

        if has_multiple_signals && !has_abort_all {
            issues.push(AbortControllerSecurityIssue::CascadingAbortFailure);
        }
    }

    if has_abort_controller {
        let has_abort_call = body.contains(".abort()");
        let has_cleanup = body.contains("removeEventListener")
            || body.contains("clearInterval")
            || body.contains("clearTimeout")
            || body.contains("finally")
            || body.contains("cleanup");

        if has_abort_call && !has_cleanup {
            issues.push(AbortControllerSecurityIssue::AbortWithoutCleanup);
        }
    }

    if has_abort_signal || has_abort_controller {
        let has_postmessage = body.contains("postMessage");
        let has_cross_origin = body.contains("cors")
            || body.contains("crossorigin")
            || body.contains("Access-Control");

        if has_postmessage && has_cross_origin {
            issues.push(AbortControllerSecurityIssue::AbortSignalCrossOrigin);
        }
    }

    if has_abort_controller {
        let has_window_controller = body.contains("window.controller")
            || body.contains("globalThis.controller")
            || body.contains("self.controller");
        let has_global_var = body.contains("var controller")
            || body.contains("let controller") && !body.contains("const controller");

        if has_window_controller || has_global_var {
            issues.push(AbortControllerSecurityIssue::GlobalAbortController);
        }
    }

    issues
}

pub fn abort_controller_security_severity(issue: &AbortControllerSecurityIssue) -> f64 {
    match issue {
        AbortControllerSecurityIssue::MissingAbortController => 4.5,
        AbortControllerSecurityIssue::AbortSignalLeak => 7.0,
        AbortControllerSecurityIssue::RaceConditionOnAbort => 6.5,
        AbortControllerSecurityIssue::UnhandledAbortError => 5.0,
        AbortControllerSecurityIssue::AbortControllerReuse => 6.0,
        AbortControllerSecurityIssue::AbortTimeoutMissing => 5.5,
        AbortControllerSecurityIssue::CascadingAbortFailure => 6.5,
        AbortControllerSecurityIssue::AbortWithoutCleanup => 5.5,
        AbortControllerSecurityIssue::AbortSignalCrossOrigin => 8.0,
        AbortControllerSecurityIssue::GlobalAbortController => 6.0,
    }
}

pub fn abort_controller_security_to_operations(
    issues: &[AbortControllerSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                abort_controller_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
