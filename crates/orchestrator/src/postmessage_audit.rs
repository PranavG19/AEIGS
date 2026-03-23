use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum PostMessageIssue {
    ApiDetected,
    WildcardTargetOrigin,
    MessageHandlerNoOriginCheck,
    DomInjectionViaMessage,
    SensitiveDataInMessage,
    CrossFrameNoValidation,
    PrototypePollutionRisk,
}

impl std::fmt::Display for PostMessageIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "postmessage_api_detected"),
            Self::WildcardTargetOrigin => write!(f, "postmessage_wildcard_origin"),
            Self::MessageHandlerNoOriginCheck => write!(f, "message_handler_no_origin"),
            Self::DomInjectionViaMessage => write!(f, "dom_injection_via_message"),
            Self::SensitiveDataInMessage => write!(f, "sensitive_data_in_message"),
            Self::CrossFrameNoValidation => write!(f, "cross_frame_no_validation"),
            Self::PrototypePollutionRisk => write!(f, "prototype_pollution_risk"),
        }
    }
}

pub fn postmessage_severity(issue: &PostMessageIssue) -> f64 {
    match issue {
        PostMessageIssue::DomInjectionViaMessage => 9.0,
        PostMessageIssue::PrototypePollutionRisk => 8.5,
        PostMessageIssue::SensitiveDataInMessage => 7.5,
        PostMessageIssue::MessageHandlerNoOriginCheck => 6.5,
        PostMessageIssue::CrossFrameNoValidation => 5.5,
        PostMessageIssue::WildcardTargetOrigin => 5.0,
        PostMessageIssue::ApiDetected => 2.0,
    }
}

pub fn audit_postmessage(target: &str) -> Vec<PostMessageIssue> {
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
    analyze_postmessage(&body)
}

pub fn analyze_postmessage(body: &str) -> Vec<PostMessageIssue> {
    let mut issues = Vec::new();

    let has_postmessage_api = body.contains("postMessage")
        || body.contains("addEventListener('message'")
        || body.contains("addEventListener(\"message\"")
        || body.contains("onmessage");

    if !has_postmessage_api {
        return issues;
    }

    issues.push(PostMessageIssue::ApiDetected);

    if body.contains(".postMessage(") && (body.contains(", \"*\"") || body.contains(", '*'")) {
        issues.push(PostMessageIssue::WildcardTargetOrigin);
    }

    let has_message_handler = body.contains("addEventListener(\"message\"")
        || body.contains("addEventListener('message'")
        || body.contains("onmessage =")
        || body.contains("onmessage=");

    if has_message_handler {
        let has_origin_check = (body.contains("event.origin") || body.contains("e.origin") || body.contains("evt.origin"))
            && (body.contains("!==") || body.contains("!=") || body.contains("===") || body.contains("=="));

        if !has_origin_check {
            issues.push(PostMessageIssue::MessageHandlerNoOriginCheck);
        }

        if (body.contains("innerHTML") || body.contains("eval(") || body.contains("document.write("))
            && (body.contains("event.data") || body.contains("e.data") || body.contains("evt.data"))
        {
            issues.push(PostMessageIssue::DomInjectionViaMessage);
        }

        if (body.contains("__proto__") || body.contains("constructor.prototype"))
            && (body.contains("event.data") || body.contains("e.data") || body.contains("evt.data"))
        {
            issues.push(PostMessageIssue::PrototypePollutionRisk);
        }
    }

    if (body.contains("password") || body.contains("token") || body.contains("secret") || body.contains("credential")) && body.contains(".postMessage(") {
        issues.push(PostMessageIssue::SensitiveDataInMessage);
    }

    if (body.contains("parent.postMessage") || body.contains("frames[") && body.contains(".postMessage"))
        && !body.contains("event.origin")
        && !body.contains("e.origin")
    {
        issues.push(PostMessageIssue::CrossFrameNoValidation);
    }

    issues
}

pub fn postmessage_to_operations(
    issues: &[PostMessageIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossSiteScripting,
                postmessage_severity(issue),
                0.5,
            )
        })
        .collect()
}
