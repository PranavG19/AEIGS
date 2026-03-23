use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebNfcIssue {
    ApiDetected,
    DataExfiltration,
    NoUserActivation,
    WriteCapability,
    ContinuousScanning,
    UrlRecordInjection,
}

impl std::fmt::Display for WebNfcIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::WriteCapability => write!(f, "write_capability"),
            Self::ContinuousScanning => write!(f, "continuous_scanning"),
            Self::UrlRecordInjection => write!(f, "url_record_injection"),
        }
    }
}

pub fn audit_web_nfc(target: &str) -> Vec<WebNfcIssue> {
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
    analyze_web_nfc(&body)
}

pub fn analyze_web_nfc(body: &str) -> Vec<WebNfcIssue> {
    if !body.contains("NDEFReader") && !body.contains("NDEFWriter") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebNfcIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(WebNfcIssue::DataExfiltration);
    }

    if !body.contains("click") && !body.contains("keydown") && !body.contains("pointerdown") {
        issues.push(WebNfcIssue::NoUserActivation);
    }

    if body.contains(".write(") || body.contains("NDEFWriter") {
        issues.push(WebNfcIssue::WriteCapability);
    }

    if body.contains(".scan(") || body.contains("onreading") || body.contains("\"reading\"") {
        issues.push(WebNfcIssue::ContinuousScanning);
    }

    if body.contains("NDEFRecord") && body.contains("url") {
        issues.push(WebNfcIssue::UrlRecordInjection);
    }

    issues
}

pub fn web_nfc_severity(issue: &WebNfcIssue) -> f64 {
    match issue {
        WebNfcIssue::WriteCapability => 7.5,
        WebNfcIssue::DataExfiltration => 7.0,
        WebNfcIssue::UrlRecordInjection => 6.5,
        WebNfcIssue::ContinuousScanning => 5.5,
        WebNfcIssue::NoUserActivation => 5.0,
        WebNfcIssue::ApiDetected => 3.0,
    }
}

pub fn web_nfc_to_operations(issues: &[WebNfcIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                web_nfc_severity(issue),
                0.6,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum WebNfcSecurityIssue {
    NfcDataExfiltration,
    NfcTagCloning,
    NfcWithoutPermission,
    NfcWriteAbuse,
    NfcRelayAttack,
    NfcCrossOrigin,
    NfcPersistentReading,
    NfcPaymentInterception,
    NfcInBackground,
    NfcUrlInjection,
}

impl std::fmt::Display for WebNfcSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NfcDataExfiltration => write!(f, "nfc_data_exfiltration"),
            Self::NfcTagCloning => write!(f, "nfc_tag_cloning"),
            Self::NfcWithoutPermission => write!(f, "nfc_without_permission"),
            Self::NfcWriteAbuse => write!(f, "nfc_write_abuse"),
            Self::NfcRelayAttack => write!(f, "nfc_relay_attack"),
            Self::NfcCrossOrigin => write!(f, "nfc_cross_origin"),
            Self::NfcPersistentReading => write!(f, "nfc_persistent_reading"),
            Self::NfcPaymentInterception => write!(f, "nfc_payment_interception"),
            Self::NfcInBackground => write!(f, "nfc_in_background"),
            Self::NfcUrlInjection => write!(f, "nfc_url_injection"),
        }
    }
}

pub fn analyze_web_nfc_security(body: &str) -> Vec<WebNfcSecurityIssue> {
    if !body.contains("NDEFReader") && !body.contains("NDEFWriter") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // NfcDataExfiltration: reading tag + external send
    if (body.contains("NDEFReader") || body.contains(".scan("))
        && (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest")
            || body.contains("WebSocket"))
    {
        issues.push(WebNfcSecurityIssue::NfcDataExfiltration);
    }

    // NfcTagCloning: reading serialNumber + write operations
    if body.contains("serialNumber") && (body.contains(".write(") || body.contains("makeReadOnly"))
    {
        issues.push(WebNfcSecurityIssue::NfcTagCloning);
    }

    // NfcWithoutPermission: no permission query before NFC access
    if (body.contains("NDEFReader") || body.contains("NDEFWriter"))
        && !body.contains("navigator.permissions.query")
        && !body.contains("\"nfc\"")
    {
        issues.push(WebNfcSecurityIssue::NfcWithoutPermission);
    }

    // NfcWriteAbuse: writing without validation
    if body.contains(".write(") && !body.contains("validate") && !body.contains("sanitize") {
        issues.push(WebNfcSecurityIssue::NfcWriteAbuse);
    }

    // NfcRelayAttack: WebSocket + NFC operations (potential relay)
    if (body.contains("NDEFReader") || body.contains("NDEFWriter")) && body.contains("WebSocket") {
        issues.push(WebNfcSecurityIssue::NfcRelayAttack);
    }

    // NfcCrossOrigin: postMessage + NFC data
    if (body.contains("NDEFReader") || body.contains("message.data"))
        && body.contains("postMessage")
    {
        issues.push(WebNfcSecurityIssue::NfcCrossOrigin);
    }

    // NfcPersistentReading: setInterval/setTimeout with scan
    if (body.contains("setInterval") || body.contains("setTimeout"))
        && (body.contains(".scan(") || body.contains("onreading"))
    {
        issues.push(WebNfcSecurityIssue::NfcPersistentReading);
    }

    // NfcPaymentInterception: payment-related keywords + NFC
    if (body.contains("NDEFReader") || body.contains(".scan("))
        && (body.contains("payment")
            || body.contains("card")
            || body.contains("credit")
            || body.contains("wallet"))
    {
        issues.push(WebNfcSecurityIssue::NfcPaymentInterception);
    }

    // NfcInBackground: visibilitychange listener absent + NFC
    if (body.contains("NDEFReader") || body.contains(".scan("))
        && !body.contains("visibilitychange")
        && !body.contains("document.hidden")
    {
        issues.push(WebNfcSecurityIssue::NfcInBackground);
    }

    // NfcUrlInjection: URL record writing without validation
    if body.contains("NDEFRecord")
        && body.contains("url")
        && (body.contains(".write(") || body.contains("push("))
        && !body.contains("URL.parse")
        && !body.contains("new URL(")
    {
        issues.push(WebNfcSecurityIssue::NfcUrlInjection);
    }

    issues
}

pub fn web_nfc_security_severity(issue: &WebNfcSecurityIssue) -> f64 {
    match issue {
        WebNfcSecurityIssue::NfcPaymentInterception => 9.0,
        WebNfcSecurityIssue::NfcTagCloning => 8.5,
        WebNfcSecurityIssue::NfcRelayAttack => 8.0,
        WebNfcSecurityIssue::NfcDataExfiltration => 7.5,
        WebNfcSecurityIssue::NfcWriteAbuse => 7.0,
        WebNfcSecurityIssue::NfcUrlInjection => 6.5,
        WebNfcSecurityIssue::NfcCrossOrigin => 6.0,
        WebNfcSecurityIssue::NfcPersistentReading => 5.5,
        WebNfcSecurityIssue::NfcWithoutPermission => 5.0,
        WebNfcSecurityIssue::NfcInBackground => 4.5,
    }
}

pub fn web_nfc_security_to_operations(
    issues: &[WebNfcSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                web_nfc_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
