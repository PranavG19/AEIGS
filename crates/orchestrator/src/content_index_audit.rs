use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ContentIndexIssue {
    ApiDetected,
    OfflineContentInjection,
    IndexEnumeration,
    PhishingContent,
    SilentRegistration,
    ExcessiveEntries,
}

impl std::fmt::Display for ContentIndexIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::OfflineContentInjection => write!(f, "offline_content_injection"),
            Self::IndexEnumeration => write!(f, "index_enumeration"),
            Self::PhishingContent => write!(f, "phishing_content"),
            Self::SilentRegistration => write!(f, "silent_registration"),
            Self::ExcessiveEntries => write!(f, "excessive_entries"),
        }
    }
}

pub fn audit_content_index(target: &str) -> Vec<ContentIndexIssue> {
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
    analyze_content_index(&body)
}

pub fn analyze_content_index(body: &str) -> Vec<ContentIndexIssue> {
    if !body.contains("ContentIndex") && !body.contains("contentIndex") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(ContentIndexIssue::ApiDetected);

    let has_add = body.contains(".add(");
    if has_add {
        if !body.contains("click") && !body.contains("submit") && !body.contains("pointerdown") {
            issues.push(ContentIndexIssue::SilentRegistration);
        }

        if body.contains("url:") && (body.contains("http://") || body.contains("data:")) {
            issues.push(ContentIndexIssue::OfflineContentInjection);
        }

        if body.contains("login")
            || body.contains("password")
            || body.contains("bank")
            || body.contains("verify")
        {
            issues.push(ContentIndexIssue::PhishingContent);
        }

        if body.contains("for(")
            || body.contains("for ")
            || body.contains("forEach")
            || body.contains("map(")
        {
            issues.push(ContentIndexIssue::ExcessiveEntries);
        }
    }

    if body.contains("getAll(") {
        issues.push(ContentIndexIssue::IndexEnumeration);
    }

    issues
}

pub fn content_index_severity(issue: &ContentIndexIssue) -> f64 {
    match issue {
        ContentIndexIssue::PhishingContent => 7.5,
        ContentIndexIssue::OfflineContentInjection => 7.0,
        ContentIndexIssue::ExcessiveEntries => 5.5,
        ContentIndexIssue::SilentRegistration => 5.0,
        ContentIndexIssue::IndexEnumeration => 4.5,
        ContentIndexIssue::ApiDetected => 2.5,
    }
}

pub fn content_index_to_operations(
    issues: &[ContentIndexIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                content_index_severity(issue),
                0.6,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContentIndexSecurityIssue {
    IndexDataExfiltration,
    IndexEnumeration,
    IndexWithoutConsent,
    IndexSensitiveContent,
    IndexCrossOrigin,
    IndexPersistentTracking,
    IndexOverwrite,
    IndexInBackground,
    ExcessiveIndexEntries,
    IndexWithoutServiceWorker,
}

impl std::fmt::Display for ContentIndexSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IndexDataExfiltration => write!(f, "index_data_exfiltration"),
            Self::IndexEnumeration => write!(f, "index_enumeration"),
            Self::IndexWithoutConsent => write!(f, "index_without_consent"),
            Self::IndexSensitiveContent => write!(f, "index_sensitive_content"),
            Self::IndexCrossOrigin => write!(f, "index_cross_origin"),
            Self::IndexPersistentTracking => write!(f, "index_persistent_tracking"),
            Self::IndexOverwrite => write!(f, "index_overwrite"),
            Self::IndexInBackground => write!(f, "index_in_background"),
            Self::ExcessiveIndexEntries => write!(f, "excessive_index_entries"),
            Self::IndexWithoutServiceWorker => write!(f, "index_without_service_worker"),
        }
    }
}

pub fn analyze_content_index_security(body: &str) -> Vec<ContentIndexSecurityIssue> {
    if !body.contains("ContentIndex")
        && !body.contains("contentIndex")
        && !body.contains("index.add")
        && !body.contains("index.delete")
        && !body.contains("index.getAll")
    {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // IndexDataExfiltration: fetch + index.add combination
    if (body.contains("fetch(") || body.contains("XMLHttpRequest")) && body.contains("index.add(") {
        issues.push(ContentIndexSecurityIssue::IndexDataExfiltration);
    }

    // IndexEnumeration: getAll()
    if body.contains("getAll()") || body.contains("index.getAll()") {
        issues.push(ContentIndexSecurityIssue::IndexEnumeration);
    }

    // IndexWithoutConsent: index.add without user interaction
    if body.contains("index.add(")
        && !body.contains("click")
        && !body.contains("submit")
        && !body.contains("pointerdown")
        && !body.contains("touchstart")
    {
        issues.push(ContentIndexSecurityIssue::IndexWithoutConsent);
    }

    // IndexSensitiveContent: passwords, tokens, secrets in index
    if body.contains("index.add(")
        && (body.contains("password")
            || body.contains("token")
            || body.contains("secret")
            || body.contains("api_key")
            || body.contains("apiKey"))
    {
        issues.push(ContentIndexSecurityIssue::IndexSensitiveContent);
    }

    // IndexCrossOrigin: postMessage or iframe with index operations
    if (body.contains("postMessage")
        || body.contains("'message'")
        || body.contains("\"message\"")
        || body.contains("iframe"))
        && (body.contains("index.add") || body.contains("index.getAll"))
    {
        issues.push(ContentIndexSecurityIssue::IndexCrossOrigin);
    }

    // IndexPersistentTracking: localStorage/sessionStorage + index operations
    if (body.contains("localStorage") || body.contains("sessionStorage"))
        && (body.contains("index.add") || body.contains("index.getAll"))
    {
        issues.push(ContentIndexSecurityIssue::IndexPersistentTracking);
    }

    // IndexOverwrite: delete followed by add with same id
    if body.contains("index.delete(") && body.contains("index.add(") {
        issues.push(ContentIndexSecurityIssue::IndexOverwrite);
    }

    // IndexInBackground: visibilitychange + index operations
    if body.contains("visibilitychange")
        && (body.contains("index.add") || body.contains("index.delete"))
    {
        issues.push(ContentIndexSecurityIssue::IndexInBackground);
    }

    // ExcessiveIndexEntries: loops with index.add
    if body.contains("index.add(")
        && (body.contains("for(")
            || body.contains("for ")
            || body.contains("forEach")
            || body.contains("while(")
            || body.contains("while ")
            || body.contains("map("))
    {
        issues.push(ContentIndexSecurityIssue::ExcessiveIndexEntries);
    }

    // IndexWithoutServiceWorker: index operations without serviceWorker context
    if (body.contains("index.add")
        || body.contains("index.delete")
        || body.contains("index.getAll"))
        && !body.contains("serviceWorker")
        && !body.contains("registration")
    {
        issues.push(ContentIndexSecurityIssue::IndexWithoutServiceWorker);
    }

    issues
}

pub fn content_index_security_severity(issue: &ContentIndexSecurityIssue) -> f64 {
    match issue {
        ContentIndexSecurityIssue::IndexDataExfiltration => 9.0,
        ContentIndexSecurityIssue::IndexSensitiveContent => 8.5,
        ContentIndexSecurityIssue::IndexCrossOrigin => 8.0,
        ContentIndexSecurityIssue::IndexOverwrite => 7.5,
        ContentIndexSecurityIssue::IndexPersistentTracking => 7.0,
        ContentIndexSecurityIssue::IndexInBackground => 6.5,
        ContentIndexSecurityIssue::IndexWithoutConsent => 6.0,
        ContentIndexSecurityIssue::ExcessiveIndexEntries => 5.5,
        ContentIndexSecurityIssue::IndexEnumeration => 5.0,
        ContentIndexSecurityIssue::IndexWithoutServiceWorker => 3.0,
    }
}

pub fn content_index_security_to_operations(
    issues: &[ContentIndexSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                content_index_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
