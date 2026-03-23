use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum ViewTransitionIssue {
    ApiDetected,
    DomManipulationInCallback,
    SensitiveContentExposure,
    CrossDocumentWithoutOriginCheck,
    TransitionCallbackOverride,
}

impl std::fmt::Display for ViewTransitionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DomManipulationInCallback => write!(f, "dom_manipulation_in_callback"),
            Self::SensitiveContentExposure => write!(f, "sensitive_content_exposure"),
            Self::CrossDocumentWithoutOriginCheck => {
                write!(f, "cross_document_without_origin_check")
            }
            Self::TransitionCallbackOverride => write!(f, "transition_callback_override"),
        }
    }
}

pub fn view_transition_severity(issue: &ViewTransitionIssue) -> f64 {
    match issue {
        ViewTransitionIssue::ApiDetected => 2.0,
        ViewTransitionIssue::DomManipulationInCallback => 7.0,
        ViewTransitionIssue::SensitiveContentExposure => 6.0,
        ViewTransitionIssue::CrossDocumentWithoutOriginCheck => 8.0,
        ViewTransitionIssue::TransitionCallbackOverride => 7.5,
    }
}

pub fn audit_view_transition(target: &str) -> Vec<ViewTransitionIssue> {
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
    analyze_view_transition(&body)
}

pub fn analyze_view_transition(body: &str) -> Vec<ViewTransitionIssue> {
    let mut issues = Vec::new();

    let has_view_transition_api = body.contains("document.startViewTransition")
        || body.contains("ViewTransition")
        || body.contains("view-transition-name");

    if has_view_transition_api {
        issues.push(ViewTransitionIssue::ApiDetected);
    }

    if has_view_transition_api {
        if body.contains(".innerHTML") || body.contains("document.write") {
            issues.push(ViewTransitionIssue::DomManipulationInCallback);
        }

        if body.contains("password")
            || body.contains("Password")
            || body.contains("token")
            || body.contains("Token")
            || body.contains("secret")
            || body.contains("Secret")
        {
            issues.push(ViewTransitionIssue::SensitiveContentExposure);
        }

        if body.contains("navigation.addEventListener") && !body.contains("origin") {
            issues.push(ViewTransitionIssue::CrossDocumentWithoutOriginCheck);
        }

        if (body.contains(".updateCallbackDone")
            || body.contains(".ready")
            || body.contains(".finished"))
            && body.contains("=")
        {
            issues.push(ViewTransitionIssue::TransitionCallbackOverride);
        }
    }

    issues
}

pub fn view_transition_to_operations(
    issues: &[ViewTransitionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                view_transition_severity(issue),
                0.5,
            )
        })
        .collect()
}
