use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebHidIssue {
    ApiDetected,
    DataExfiltration,
    NoUserActivation,
    RawDataAccess,
    DeviceEnumeration,
    PersistentConnection,
}

impl std::fmt::Display for WebHidIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::RawDataAccess => write!(f, "raw_data_access"),
            Self::DeviceEnumeration => write!(f, "device_enumeration"),
            Self::PersistentConnection => write!(f, "persistent_connection"),
        }
    }
}

pub fn audit_webhid(target: &str) -> Vec<WebHidIssue> {
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
    analyze_webhid(&body)
}

pub fn analyze_webhid(body: &str) -> Vec<WebHidIssue> {
    if !body.contains("navigator.hid") && !body.contains("HIDDevice") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebHidIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(WebHidIssue::DataExfiltration);
    }

    if !body.contains("click") && !body.contains("keydown") && !body.contains("pointerdown") {
        issues.push(WebHidIssue::NoUserActivation);
    }

    if body.contains("sendReport")
        || body.contains("sendFeatureReport")
        || body.contains("receiveFeatureReport")
    {
        issues.push(WebHidIssue::RawDataAccess);
    }

    if body.contains("getDevices") || body.contains("requestDevice") {
        issues.push(WebHidIssue::DeviceEnumeration);
    }

    if body.contains("oninputreport") || body.contains("inputreport") {
        issues.push(WebHidIssue::PersistentConnection);
    }

    issues
}

pub fn webhid_severity(issue: &WebHidIssue) -> f64 {
    match issue {
        WebHidIssue::DataExfiltration => 7.5,
        WebHidIssue::RawDataAccess => 7.0,
        WebHidIssue::PersistentConnection => 6.0,
        WebHidIssue::DeviceEnumeration => 5.5,
        WebHidIssue::NoUserActivation => 5.0,
        WebHidIssue::ApiDetected => 3.0,
    }
}

pub fn webhid_to_operations(issues: &[WebHidIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                webhid_severity(issue),
                0.6,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum WebHidSecurityIssue {
    HidDeviceEnumeration,
    HidKeylogging,
    HidWithoutPermission,
    HidDataExfiltration,
    HidDeviceFingerprinting,
    HidOutputReport,
    HidFeatureReport,
    HidCrossOrigin,
    HidPersistentConnection,
    HidInBackground,
}

impl std::fmt::Display for WebHidSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HidDeviceEnumeration => write!(f, "hid_device_enumeration"),
            Self::HidKeylogging => write!(f, "hid_keylogging"),
            Self::HidWithoutPermission => write!(f, "hid_without_permission"),
            Self::HidDataExfiltration => write!(f, "hid_data_exfiltration"),
            Self::HidDeviceFingerprinting => write!(f, "hid_device_fingerprinting"),
            Self::HidOutputReport => write!(f, "hid_output_report"),
            Self::HidFeatureReport => write!(f, "hid_feature_report"),
            Self::HidCrossOrigin => write!(f, "hid_cross_origin"),
            Self::HidPersistentConnection => write!(f, "hid_persistent_connection"),
            Self::HidInBackground => write!(f, "hid_in_background"),
        }
    }
}

pub fn analyze_webhid_security(body: &str) -> Vec<WebHidSecurityIssue> {
    if !body.contains("navigator.hid") && !body.contains("HIDDevice") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("getDevices()") {
        issues.push(WebHidSecurityIssue::HidDeviceEnumeration);
    }

    let has_keyboard = body.contains("usage: 6")
        || body.contains("usagePage: 1")
        || body.contains("keyboard")
        || body.contains("0x0006")
        || body.contains("0x0001");
    if has_keyboard && (body.contains("receiveFeatureReport") || body.contains("oninputreport")) {
        issues.push(WebHidSecurityIssue::HidKeylogging);
    }

    let has_user_gesture = body.contains("click")
        || body.contains("keydown")
        || body.contains("pointerdown")
        || body.contains("touchstart")
        || body.contains("mousedown");
    if !has_user_gesture && body.contains("requestDevice") {
        issues.push(WebHidSecurityIssue::HidWithoutPermission);
    }

    let has_network = body.contains("fetch(")
        || body.contains("sendBeacon")
        || body.contains("XMLHttpRequest")
        || body.contains("WebSocket")
        || body.contains("navigator.sendBeacon");
    if has_network && (body.contains("sendReport") || body.contains("receiveFeatureReport")) {
        issues.push(WebHidSecurityIssue::HidDataExfiltration);
    }

    let has_fingerprint_pattern = (body.contains("getDevices") && body.contains("length"))
        || (body.contains("vendorId") && body.contains("productId"))
        || body.contains("navigator.hid.getDevices().then(d => d.map");
    if has_fingerprint_pattern {
        issues.push(WebHidSecurityIssue::HidDeviceFingerprinting);
    }

    if body.contains("sendReport(") {
        issues.push(WebHidSecurityIssue::HidOutputReport);
    }

    if body.contains("sendFeatureReport") || body.contains("receiveFeatureReport") {
        issues.push(WebHidSecurityIssue::HidFeatureReport);
    }

    let has_cross_origin = body.contains("postMessage")
        || body.contains("iframe")
        || body.contains("window.parent")
        || body.contains("window.opener");
    if has_cross_origin && body.contains("navigator.hid") {
        issues.push(WebHidSecurityIssue::HidCrossOrigin);
    }

    if body.contains("oninputreport")
        || (body.contains("addEventListener") && body.contains("inputreport"))
    {
        issues.push(WebHidSecurityIssue::HidPersistentConnection);
    }

    let has_background = body.contains("visibilitychange")
        || body.contains("document.hidden")
        || body.contains("document.visibilityState")
        || body.contains("onvisibilitychange");
    if has_background && body.contains("navigator.hid") {
        issues.push(WebHidSecurityIssue::HidInBackground);
    }

    issues
}

pub fn webhid_security_severity(issue: &WebHidSecurityIssue) -> f64 {
    match issue {
        WebHidSecurityIssue::HidKeylogging => 9.0,
        WebHidSecurityIssue::HidDataExfiltration => 8.5,
        WebHidSecurityIssue::HidWithoutPermission => 7.5,
        WebHidSecurityIssue::HidOutputReport => 7.0,
        WebHidSecurityIssue::HidFeatureReport => 6.5,
        WebHidSecurityIssue::HidDeviceFingerprinting => 6.0,
        WebHidSecurityIssue::HidCrossOrigin => 5.5,
        WebHidSecurityIssue::HidInBackground => 5.0,
        WebHidSecurityIssue::HidPersistentConnection => 4.5,
        WebHidSecurityIssue::HidDeviceEnumeration => 4.0,
    }
}

pub fn webhid_security_to_operations(
    issues: &[WebHidSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                webhid_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
