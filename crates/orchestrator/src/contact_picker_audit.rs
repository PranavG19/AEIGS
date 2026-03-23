use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ContactPickerIssue {
    ApiDetected,
    ContactExfiltration,
    ExcessiveProperties,
    NoUserActivation,
    MultipleSelect,
    EmailHarvesting,
}

impl std::fmt::Display for ContactPickerIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::ContactExfiltration => write!(f, "contact_exfiltration"),
            Self::ExcessiveProperties => write!(f, "excessive_properties"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::MultipleSelect => write!(f, "multiple_select"),
            Self::EmailHarvesting => write!(f, "email_harvesting"),
        }
    }
}

pub fn audit_contact_picker(target: &str) -> Vec<ContactPickerIssue> {
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
    analyze_contact_picker(&body)
}

pub fn analyze_contact_picker(body: &str) -> Vec<ContactPickerIssue> {
    if !body.contains("ContactsManager") && !body.contains("navigator.contacts") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(ContactPickerIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(ContactPickerIssue::ContactExfiltration);
    }

    let prop_count = count_contact_properties(body);
    if prop_count >= 3 {
        issues.push(ContactPickerIssue::ExcessiveProperties);
    }

    if !body.contains("click") && !body.contains("pointerdown") && !body.contains("touchstart") {
        issues.push(ContactPickerIssue::NoUserActivation);
    }

    if body.contains("multiple: true") || body.contains("multiple:true") {
        issues.push(ContactPickerIssue::MultipleSelect);
    }

    if body.contains("\"email\"") || body.contains("'email'") {
        issues.push(ContactPickerIssue::EmailHarvesting);
    }

    issues
}

fn count_contact_properties(body: &str) -> usize {
    let props = [
        "\"name\"",
        "'name'",
        "\"email\"",
        "'email'",
        "\"tel\"",
        "'tel'",
        "\"address\"",
        "'address'",
        "\"icon\"",
        "'icon'",
    ];
    props.iter().filter(|p| body.contains(*p)).count()
}

pub fn contact_picker_severity(issue: &ContactPickerIssue) -> f64 {
    match issue {
        ContactPickerIssue::ContactExfiltration => 7.0,
        ContactPickerIssue::EmailHarvesting => 6.0,
        ContactPickerIssue::ExcessiveProperties => 5.5,
        ContactPickerIssue::MultipleSelect => 5.0,
        ContactPickerIssue::NoUserActivation => 4.5,
        ContactPickerIssue::ApiDetected => 3.0,
    }
}

pub fn contact_picker_to_operations(
    issues: &[ContactPickerIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                contact_picker_severity(issue),
                0.7,
            )
        })
        .collect()
}
