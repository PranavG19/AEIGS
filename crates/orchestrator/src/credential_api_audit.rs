use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum CredentialApiIssue {
    GetDetected,
    StoreDetected,
    CreateDetected,
    MediationSilent,
    NoPreventSilentAccess,
    FederatedCredential,
    PasswordCredential,
}

impl std::fmt::Display for CredentialApiIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GetDetected => write!(f, "get_detected"),
            Self::StoreDetected => write!(f, "store_detected"),
            Self::CreateDetected => write!(f, "create_detected"),
            Self::MediationSilent => write!(f, "mediation_silent"),
            Self::NoPreventSilentAccess => write!(f, "no_prevent_silent_access"),
            Self::FederatedCredential => write!(f, "federated_credential"),
            Self::PasswordCredential => write!(f, "password_credential"),
        }
    }
}

pub fn audit_credential_api(target: &str) -> Vec<CredentialApiIssue> {
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
    analyze_credential_api(&body)
}

pub fn analyze_credential_api(body: &str) -> Vec<CredentialApiIssue> {
    if !body.contains("navigator.credentials")
        && !body.contains("PasswordCredential")
        && !body.contains("FederatedCredential")
    {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("navigator.credentials.get") {
        issues.push(CredentialApiIssue::GetDetected);

        if body.contains("\"silent\"") || body.contains("'silent'") {
            issues.push(CredentialApiIssue::MediationSilent);
        }
    }

    if body.contains("navigator.credentials.store") {
        issues.push(CredentialApiIssue::StoreDetected);
    }

    if body.contains("navigator.credentials.create") {
        issues.push(CredentialApiIssue::CreateDetected);
    }

    if body.contains("PasswordCredential") {
        issues.push(CredentialApiIssue::PasswordCredential);
    }

    if body.contains("FederatedCredential") {
        issues.push(CredentialApiIssue::FederatedCredential);
    }

    let has_get_or_store =
        body.contains("navigator.credentials.get") || body.contains("navigator.credentials.store");
    if has_get_or_store && !body.contains("preventSilentAccess") {
        issues.push(CredentialApiIssue::NoPreventSilentAccess);
    }

    issues
}

pub fn credential_api_severity(issue: &CredentialApiIssue) -> f64 {
    match issue {
        CredentialApiIssue::MediationSilent => 6.5,
        CredentialApiIssue::PasswordCredential => 6.0,
        CredentialApiIssue::StoreDetected => 5.5,
        CredentialApiIssue::NoPreventSilentAccess => 5.0,
        CredentialApiIssue::FederatedCredential => 4.5,
        CredentialApiIssue::CreateDetected => 4.0,
        CredentialApiIssue::GetDetected => 3.5,
    }
}

pub fn credential_api_to_operations(
    issues: &[CredentialApiIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                credential_api_severity(issue),
                0.7,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum CredentialApiSecurityIssue {
    CredentialPhishing,
    CredentialExfiltration,
    CredentialWithoutUserGesture,
    CredentialCrossOrigin,
    SilentCredentialAccess,
    CredentialPersistentTracking,
    FederatedCredentialAbuse,
    CredentialEnumeration,
    CredentialInBackground,
    WeakCredentialStorage,
}

impl std::fmt::Display for CredentialApiSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CredentialPhishing => write!(f, "credential_phishing"),
            Self::CredentialExfiltration => write!(f, "credential_exfiltration"),
            Self::CredentialWithoutUserGesture => write!(f, "credential_without_user_gesture"),
            Self::CredentialCrossOrigin => write!(f, "credential_cross_origin"),
            Self::SilentCredentialAccess => write!(f, "silent_credential_access"),
            Self::CredentialPersistentTracking => write!(f, "credential_persistent_tracking"),
            Self::FederatedCredentialAbuse => write!(f, "federated_credential_abuse"),
            Self::CredentialEnumeration => write!(f, "credential_enumeration"),
            Self::CredentialInBackground => write!(f, "credential_in_background"),
            Self::WeakCredentialStorage => write!(f, "weak_credential_storage"),
        }
    }
}

pub fn analyze_credential_api_security(body: &str) -> Vec<CredentialApiSecurityIssue> {
    if !body.contains("navigator.credentials")
        && !body.contains("PasswordCredential")
        && !body.contains("FederatedCredential")
    {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if (body.contains("PasswordCredential") || body.contains("navigator.credentials.store"))
        && body.contains("store")
    {
        issues.push(CredentialApiSecurityIssue::CredentialPhishing);
    }

    if (body.contains("navigator.credentials.get") || body.contains("navigator.credentials.store"))
        && (body.contains("fetch(") || body.contains("XMLHttpRequest"))
    {
        issues.push(CredentialApiSecurityIssue::CredentialExfiltration);
    }

    let has_credential_access = body.contains("navigator.credentials.get")
        || body.contains("navigator.credentials.store")
        || body.contains("navigator.credentials.create");
    let has_user_gesture =
        body.contains("click") || body.contains("keydown") || body.contains("pointerdown");
    if has_credential_access && !has_user_gesture {
        issues.push(CredentialApiSecurityIssue::CredentialWithoutUserGesture);
    }

    if body.contains("postMessage") && body.contains("credential") {
        issues.push(CredentialApiSecurityIssue::CredentialCrossOrigin);
    }

    if body.contains("mediation") && body.contains("\"silent\"")
        || body.contains("mediation") && body.contains("'silent'")
    {
        issues.push(CredentialApiSecurityIssue::SilentCredentialAccess);
    }

    if body.contains("credential") && body.contains(".id") {
        issues.push(CredentialApiSecurityIssue::CredentialPersistentTracking);
    }

    if body.contains("FederatedCredential")
        && (body.contains("provider") || body.contains("protocol"))
    {
        issues.push(CredentialApiSecurityIssue::FederatedCredentialAbuse);
    }

    if body.contains("navigator.credentials.get")
        && (body.contains("for") || body.contains("forEach"))
    {
        issues.push(CredentialApiSecurityIssue::CredentialEnumeration);
    }

    if body.contains("visibilitychange")
        && (body.contains("navigator.credentials.get")
            || body.contains("navigator.credentials.store"))
    {
        issues.push(CredentialApiSecurityIssue::CredentialInBackground);
    }

    if body.contains("PasswordCredential") && !body.contains("encrypt") && !body.contains("crypto")
    {
        issues.push(CredentialApiSecurityIssue::WeakCredentialStorage);
    }

    issues
}

pub fn credential_api_security_severity(issue: &CredentialApiSecurityIssue) -> f64 {
    match issue {
        CredentialApiSecurityIssue::CredentialPhishing => 9.0,
        CredentialApiSecurityIssue::CredentialExfiltration => 8.5,
        CredentialApiSecurityIssue::SilentCredentialAccess => 7.5,
        CredentialApiSecurityIssue::CredentialCrossOrigin => 7.0,
        CredentialApiSecurityIssue::FederatedCredentialAbuse => 6.5,
        CredentialApiSecurityIssue::CredentialWithoutUserGesture => 6.0,
        CredentialApiSecurityIssue::CredentialEnumeration => 5.5,
        CredentialApiSecurityIssue::CredentialPersistentTracking => 5.0,
        CredentialApiSecurityIssue::WeakCredentialStorage => 4.5,
        CredentialApiSecurityIssue::CredentialInBackground => 4.0,
    }
}

pub fn credential_api_security_to_operations(
    issues: &[CredentialApiSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                credential_api_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
