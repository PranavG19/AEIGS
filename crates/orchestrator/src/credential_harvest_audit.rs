use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum CredentialHarvestIssue {
    CrossOriginFormAction { action: String },
    HiddenLoginForm,
    PasswordFieldInHiddenContainer,
    DataUriFormAction,
    JavascriptFormAction,
    FormTargetBlank,
    SuspiciousFormInputNames,
}

impl std::fmt::Display for CredentialHarvestIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CrossOriginFormAction { action } => {
                write!(f, "cross_origin_form:{action}")
            }
            Self::HiddenLoginForm => write!(f, "hidden_login_form"),
            Self::PasswordFieldInHiddenContainer => write!(f, "hidden_password_field"),
            Self::DataUriFormAction => write!(f, "data_uri_form_action"),
            Self::JavascriptFormAction => write!(f, "javascript_form_action"),
            Self::FormTargetBlank => write!(f, "form_target_blank"),
            Self::SuspiciousFormInputNames => write!(f, "suspicious_input_names"),
        }
    }
}

pub fn audit_credential_harvest(target: &str) -> Vec<CredentialHarvestIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_credential_harvest(&body, "")
}

pub fn analyze_credential_harvest(body: &str, site_domain: &str) -> Vec<CredentialHarvestIssue> {
    let lower = body.to_ascii_lowercase();
    if !lower.contains("<form") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    let mut pos = 0;

    while let Some(idx) = lower[pos..].find("<form") {
        let abs = pos + idx;
        let tag_end = match lower[abs..].find('>') {
            Some(e) => e,
            None => break,
        };
        let tag = &lower[abs..abs + tag_end + 1];
        let form_end = lower[abs..].find("</form").unwrap_or(lower.len() - abs);
        let form_body = &lower[abs..abs + form_end];

        check_form_action(tag, site_domain, &mut issues);
        check_form_target(tag, &mut issues);
        check_hidden_login(tag, form_body, &mut issues);
        check_hidden_password(form_body, &mut issues);
        check_suspicious_inputs(form_body, &mut issues);

        pos = abs + form_end;
    }

    issues
}

fn extract_action(tag: &str) -> Option<&str> {
    let start = tag.find("action=")?;
    let rest = &tag[start + 7..];
    let (delim, skip) = if rest.starts_with('"') {
        ('"', 1)
    } else if rest.starts_with('\'') {
        ('\'', 1)
    } else {
        (' ', 0)
    };
    let value = &rest[skip..];
    let end = value.find(delim).or_else(|| value.find('>'))?;
    Some(&value[..end])
}

fn check_form_action(
    tag: &str,
    site_domain: &str,
    issues: &mut Vec<CredentialHarvestIssue>,
) {
    let Some(action) = extract_action(tag) else {
        return;
    };

    if action.starts_with("data:") {
        issues.push(CredentialHarvestIssue::DataUriFormAction);
        return;
    }

    if action.starts_with("javascript:") {
        issues.push(CredentialHarvestIssue::JavascriptFormAction);
        return;
    }

    if (action.starts_with("http://") || action.starts_with("https://"))
        && !site_domain.is_empty()
        && !action.contains(site_domain)
    {
        issues.push(CredentialHarvestIssue::CrossOriginFormAction {
            action: action.to_string(),
        });
    }
}

fn check_form_target(tag: &str, issues: &mut Vec<CredentialHarvestIssue>) {
    if tag.contains("target=\"_blank") || tag.contains("target='_blank") {
        issues.push(CredentialHarvestIssue::FormTargetBlank);
    }
}

fn check_hidden_login(
    tag: &str,
    form_body: &str,
    issues: &mut Vec<CredentialHarvestIssue>,
) {
    let is_hidden = tag.contains("display:none")
        || tag.contains("display: none")
        || tag.contains("visibility:hidden")
        || tag.contains("visibility: hidden")
        || tag.contains("opacity:0")
        || tag.contains("opacity: 0");
    if is_hidden && has_password_field(form_body) {
        issues.push(CredentialHarvestIssue::HiddenLoginForm);
    }
}

fn check_hidden_password(form_body: &str, issues: &mut Vec<CredentialHarvestIssue>) {
    if !has_password_field(form_body) {
        return;
    }
    let patterns = [
        "style=\"display:none",
        "style=\"display: none",
        "style='display:none",
        "style='display: none",
        "style=\"visibility:hidden",
        "style=\"visibility: hidden",
        "style='visibility:hidden",
        "style='visibility: hidden",
        "style=\"position:absolute",
        "style='position:absolute",
    ];
    for p in &patterns {
        if let Some(idx) = form_body.find(*p) {
            let after = &form_body[idx..];
            if after.contains("type=\"password") || after.contains("type='password") {
                issues.push(CredentialHarvestIssue::PasswordFieldInHiddenContainer);
                return;
            }
        }
    }
}

fn check_suspicious_inputs(form_body: &str, issues: &mut Vec<CredentialHarvestIssue>) {
    let suspicious = [
        "name=\"ssn",
        "name=\"social_security",
        "name=\"credit_card",
        "name=\"creditcard",
        "name=\"cc_number",
        "name=\"card_number",
        "name=\"pin",
        "name=\"cvv",
        "name=\"bank_account",
    ];
    let count = suspicious.iter().filter(|s| form_body.contains(**s)).count();
    if count >= 2 {
        issues.push(CredentialHarvestIssue::SuspiciousFormInputNames);
    }
}

fn has_password_field(form_body: &str) -> bool {
    form_body.contains("type=\"password") || form_body.contains("type='password")
}

pub fn credential_harvest_severity(issue: &CredentialHarvestIssue) -> f64 {
    match issue {
        CredentialHarvestIssue::HiddenLoginForm => 8.0,
        CredentialHarvestIssue::PasswordFieldInHiddenContainer => 7.5,
        CredentialHarvestIssue::DataUriFormAction => 7.0,
        CredentialHarvestIssue::JavascriptFormAction => 6.5,
        CredentialHarvestIssue::CrossOriginFormAction { .. } => 6.0,
        CredentialHarvestIssue::SuspiciousFormInputNames => 5.5,
        CredentialHarvestIssue::FormTargetBlank => 3.0,
    }
}

pub fn credential_harvest_to_operations(
    issues: &[CredentialHarvestIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                credential_harvest_severity(issue),
                0.8,
            )
        })
        .collect()
}
