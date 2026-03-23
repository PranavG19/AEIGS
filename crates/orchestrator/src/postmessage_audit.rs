use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum PostMessageIssue {
    WildcardTargetOrigin,
    MessageHandlerNoOriginCheck,
    MessageHandlerUsesEval,
    MessageHandlerUsesInnerHtml,
    PostMessageToWildcard,
}

impl std::fmt::Display for PostMessageIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WildcardTargetOrigin => write!(f, "postmessage_wildcard_origin"),
            Self::MessageHandlerNoOriginCheck => write!(f, "message_handler_no_origin"),
            Self::MessageHandlerUsesEval => write!(f, "message_handler_eval"),
            Self::MessageHandlerUsesInnerHtml => write!(f, "message_handler_innerhtml"),
            Self::PostMessageToWildcard => write!(f, "postmessage_to_wildcard"),
        }
    }
}

pub fn audit_postmessage(target: &str) -> Vec<PostMessageIssue> {
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

    let body = resp.text().unwrap_or_default();
    analyze_postmessage_usage(&body)
}

pub fn analyze_postmessage_usage(body: &str) -> Vec<PostMessageIssue> {
    let mut issues = Vec::new();

    if body.contains(".postMessage(")
        && (body.contains("\"*\"") || body.contains("'*'"))
    {
        issues.push(PostMessageIssue::WildcardTargetOrigin);
    }

    let has_message_handler = body.contains("addEventListener(\"message\"")
        || body.contains("addEventListener('message'")
        || body.contains("onmessage");

    if has_message_handler {
        let has_origin_check = body.contains(".origin")
            && (body.contains("event.origin") || body.contains("e.origin"));

        if !has_origin_check {
            issues.push(PostMessageIssue::MessageHandlerNoOriginCheck);
        }

        if body.contains("eval(") && has_message_handler {
            issues.push(PostMessageIssue::MessageHandlerUsesEval);
        }

        if body.contains("innerHTML") && has_message_handler {
            issues.push(PostMessageIssue::MessageHandlerUsesInnerHtml);
        }
    }

    issues
}

pub fn postmessage_severity(issue: &PostMessageIssue) -> f64 {
    match issue {
        PostMessageIssue::MessageHandlerUsesEval => 8.0,
        PostMessageIssue::MessageHandlerUsesInnerHtml => 7.0,
        PostMessageIssue::MessageHandlerNoOriginCheck => 6.5,
        PostMessageIssue::WildcardTargetOrigin => 5.0,
        PostMessageIssue::PostMessageToWildcard => 5.0,
    }
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
                0.7,
            )
        })
        .collect()
}
