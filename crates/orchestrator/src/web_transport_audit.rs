use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebTransportIssue {
    ApiDetected,
    DataExfiltration,
    UnencryptedEndpoint,
    BidirectionalStream,
    DatagramAbuse,
    NoCloseHandling,
}

impl std::fmt::Display for WebTransportIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::UnencryptedEndpoint => write!(f, "unencrypted_endpoint"),
            Self::BidirectionalStream => write!(f, "bidirectional_stream"),
            Self::DatagramAbuse => write!(f, "datagram_abuse"),
            Self::NoCloseHandling => write!(f, "no_close_handling"),
        }
    }
}

pub fn audit_web_transport(target: &str) -> Vec<WebTransportIssue> {
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
    analyze_web_transport(&body)
}

pub fn analyze_web_transport(body: &str) -> Vec<WebTransportIssue> {
    if !body.contains("WebTransport") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebTransportIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(WebTransportIssue::DataExfiltration);
    }

    if body.contains("http://") && body.contains("WebTransport(") {
        issues.push(WebTransportIssue::UnencryptedEndpoint);
    }

    if body.contains("createBidirectionalStream") || body.contains("incomingBidirectionalStreams") {
        issues.push(WebTransportIssue::BidirectionalStream);
    }

    if body.contains("datagrams") && (body.contains(".writable") || body.contains(".readable")) {
        issues.push(WebTransportIssue::DatagramAbuse);
    }

    if !body.contains(".close") && !body.contains("closed") {
        issues.push(WebTransportIssue::NoCloseHandling);
    }

    issues
}

pub fn web_transport_severity(issue: &WebTransportIssue) -> f64 {
    match issue {
        WebTransportIssue::DataExfiltration => 7.0,
        WebTransportIssue::UnencryptedEndpoint => 6.5,
        WebTransportIssue::BidirectionalStream => 5.5,
        WebTransportIssue::DatagramAbuse => 5.0,
        WebTransportIssue::NoCloseHandling => 4.0,
        WebTransportIssue::ApiDetected => 3.0,
    }
}

pub fn web_transport_to_operations(
    issues: &[WebTransportIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                web_transport_severity(issue),
                0.7,
            )
        })
        .collect()
}
