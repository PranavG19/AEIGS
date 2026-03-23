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
    if !body.contains("navigator.credentials") && !body.contains("PasswordCredential")
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

    let has_get_or_store = body.contains("navigator.credentials.get")
        || body.contains("navigator.credentials.store");
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
