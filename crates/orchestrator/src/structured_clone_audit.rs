use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum StructuredCloneIssue {
    ApiDetected,
    PrototypePollution,
    SensitiveDataClone,
    CrossOriginLeak,
    LargeObjectDos,
}

impl std::fmt::Display for StructuredCloneIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::PrototypePollution => write!(f, "prototype_pollution"),
            Self::SensitiveDataClone => write!(f, "sensitive_data_clone"),
            Self::CrossOriginLeak => write!(f, "cross_origin_leak"),
            Self::LargeObjectDos => write!(f, "large_object_dos"),
        }
    }
}

pub fn structured_clone_severity(issue: &StructuredCloneIssue) -> f64 {
    match issue {
        StructuredCloneIssue::ApiDetected => 2.0,
        StructuredCloneIssue::PrototypePollution => 7.5,
        StructuredCloneIssue::SensitiveDataClone => 7.0,
        StructuredCloneIssue::CrossOriginLeak => 6.5,
        StructuredCloneIssue::LargeObjectDos => 5.5,
    }
}

pub fn audit_structured_clone(target: &str) -> Vec<StructuredCloneIssue> {
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
    analyze_structured_clone(&body)
}

pub fn analyze_structured_clone(body: &str) -> Vec<StructuredCloneIssue> {
    let mut issues = Vec::new();

    let has_structured_clone = body.contains("structuredClone");
    let has_post_message = body.contains("postMessage");
    let has_message_channel = body.contains("MessageChannel");
    let has_any_api = has_structured_clone || has_post_message || has_message_channel;

    if has_any_api {
        issues.push(StructuredCloneIssue::ApiDetected);
    }

    if has_any_api
        && (body.contains("__proto__")
            || body.contains("constructor.prototype")
            || body.contains("Object.assign"))
    {
        issues.push(StructuredCloneIssue::PrototypePollution);
    }

    if has_any_api
        && (body.contains("password")
            || body.contains("token")
            || body.contains("secret")
            || body.contains("credential")
            || body.contains("apiKey"))
    {
        issues.push(StructuredCloneIssue::SensitiveDataClone);
    }

    if has_any_api
        && has_post_message
        && (body.contains("http://") || body.contains("https://"))
        && !(body.contains("origin") || body.contains("same-origin"))
    {
        issues.push(StructuredCloneIssue::CrossOriginLeak);
    }

    if has_structured_clone
        && (body.contains("while")
            || body.contains("for")
            || body.contains("map")
            || body.contains("Array"))
        && !(body.contains("limit") || body.contains("maxSize") || body.contains("slice"))
    {
        issues.push(StructuredCloneIssue::LargeObjectDos);
    }

    issues
}

pub fn structured_clone_to_operations(
    issues: &[StructuredCloneIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                structured_clone_severity(issue),
                0.5,
            )
        })
        .collect()
}
