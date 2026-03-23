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

#[derive(Debug, Clone, PartialEq)]
pub enum ContactPickerSecurityIssue {
    ContactDataExfiltration,
    ContactWithoutConsent,
    ExcessiveContactProperties,
    ContactFingerprinting,
    ContactInBackground,
    ContactCrossOrigin,
    ContactPersistence,
    ContactBulkAccess,
    ContactWithoutUserGesture,
    ContactSilentCollection,
}

impl std::fmt::Display for ContactPickerSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContactDataExfiltration => write!(f, "contact_data_exfiltration"),
            Self::ContactWithoutConsent => write!(f, "contact_without_consent"),
            Self::ExcessiveContactProperties => write!(f, "excessive_contact_properties"),
            Self::ContactFingerprinting => write!(f, "contact_fingerprinting"),
            Self::ContactInBackground => write!(f, "contact_in_background"),
            Self::ContactCrossOrigin => write!(f, "contact_cross_origin"),
            Self::ContactPersistence => write!(f, "contact_persistence"),
            Self::ContactBulkAccess => write!(f, "contact_bulk_access"),
            Self::ContactWithoutUserGesture => write!(f, "contact_without_user_gesture"),
            Self::ContactSilentCollection => write!(f, "contact_silent_collection"),
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

pub fn analyze_contact_picker_security(body: &str) -> Vec<ContactPickerSecurityIssue> {
    if !body.contains("ContactsManager")
        && !body.contains("contacts.select")
        && !body.contains("navigator.contacts")
    {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if (body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest"))
        && body.contains("contacts.select")
    {
        issues.push(ContactPickerSecurityIssue::ContactDataExfiltration);
    }

    let body_lower = body.to_lowercase();
    if !body_lower.contains("permission")
        && !body_lower.contains("consent")
        && !body_lower.contains("confirm")
    {
        issues.push(ContactPickerSecurityIssue::ContactWithoutConsent);
    }

    let prop_count = [
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
    ]
    .iter()
    .filter(|p| body.contains(*p))
    .count();

    if prop_count >= 5 {
        issues.push(ContactPickerSecurityIssue::ExcessiveContactProperties);
    }

    if (body.contains("fingerprint") || body.contains("deviceId") || body.contains("trackingId"))
        && body.contains("contacts")
    {
        issues.push(ContactPickerSecurityIssue::ContactFingerprinting);
    }

    if (body.contains("document.hidden") || body.contains("visibilityState"))
        && body.contains("contacts.select")
    {
        issues.push(ContactPickerSecurityIssue::ContactInBackground);
    }

    if (body.contains("postMessage") || body.contains("iframe")) && body.contains("contacts.select")
    {
        issues.push(ContactPickerSecurityIssue::ContactCrossOrigin);
    }

    if (body.contains("localStorage")
        || body.contains("indexedDB")
        || body.contains("sessionStorage"))
        && body.contains("contacts")
    {
        issues.push(ContactPickerSecurityIssue::ContactPersistence);
    }

    if body.contains("multiple: true") || body.contains("multiple:true") {
        issues.push(ContactPickerSecurityIssue::ContactBulkAccess);
    }

    if !body.contains("click")
        && !body.contains("keydown")
        && !body.contains("pointerdown")
        && body.contains("contacts.select")
    {
        issues.push(ContactPickerSecurityIssue::ContactWithoutUserGesture);
    }

    if !body_lower.contains("ui")
        && !body_lower.contains("indicator")
        && !body_lower.contains("notification")
        && body.contains("contacts.select")
    {
        issues.push(ContactPickerSecurityIssue::ContactSilentCollection);
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

pub fn contact_picker_security_severity(issue: &ContactPickerSecurityIssue) -> f64 {
    match issue {
        ContactPickerSecurityIssue::ContactDataExfiltration => 9.0,
        ContactPickerSecurityIssue::ContactFingerprinting => 8.5,
        ContactPickerSecurityIssue::ContactCrossOrigin => 8.0,
        ContactPickerSecurityIssue::ContactPersistence => 7.5,
        ContactPickerSecurityIssue::ContactBulkAccess => 7.0,
        ContactPickerSecurityIssue::ContactWithoutConsent => 6.5,
        ContactPickerSecurityIssue::ExcessiveContactProperties => 6.0,
        ContactPickerSecurityIssue::ContactInBackground => 5.5,
        ContactPickerSecurityIssue::ContactWithoutUserGesture => 5.0,
        ContactPickerSecurityIssue::ContactSilentCollection => 4.5,
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

pub fn contact_picker_security_to_operations(
    issues: &[ContactPickerSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                contact_picker_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
