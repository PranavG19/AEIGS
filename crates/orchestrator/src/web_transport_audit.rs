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

#[derive(Debug, Clone, PartialEq)]
pub enum WebTransportSecurityIssue {
    UnencryptedTransport,
    TransportDataExfiltration,
    TransportCrossOrigin,
    TransportInBackground,
    TransportHighFrequency,
    TransportWithoutCertCheck,
    TransportBidirectionalAbuse,
    TransportDatagramFlood,
    TransportPersistence,
    TransportToInternalNetwork,
}

impl std::fmt::Display for WebTransportSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnencryptedTransport => write!(f, "unencrypted_transport"),
            Self::TransportDataExfiltration => write!(f, "transport_data_exfiltration"),
            Self::TransportCrossOrigin => write!(f, "transport_cross_origin"),
            Self::TransportInBackground => write!(f, "transport_in_background"),
            Self::TransportHighFrequency => write!(f, "transport_high_frequency"),
            Self::TransportWithoutCertCheck => write!(f, "transport_without_cert_check"),
            Self::TransportBidirectionalAbuse => write!(f, "transport_bidirectional_abuse"),
            Self::TransportDatagramFlood => write!(f, "transport_datagram_flood"),
            Self::TransportPersistence => write!(f, "transport_persistence"),
            Self::TransportToInternalNetwork => write!(f, "transport_to_internal_network"),
        }
    }
}

pub fn analyze_web_transport_security(body: &str) -> Vec<WebTransportSecurityIssue> {
    if !body.contains("WebTransport") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // UnencryptedTransport: WebTransport without TLS
    if body.contains("http://") && body.contains("WebTransport(") {
        issues.push(WebTransportSecurityIssue::UnencryptedTransport);
    }

    // TransportDataExfiltration: sending data to external endpoints
    if body.contains("WebTransport")
        && (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest"))
    {
        issues.push(WebTransportSecurityIssue::TransportDataExfiltration);
    }

    // TransportCrossOrigin: cross-origin WebTransport connections
    if body.contains("WebTransport")
        && (body.contains("://")
            && (body.contains(".com") || body.contains(".net") || body.contains(".org")))
        && !body.contains("same-origin")
    {
        issues.push(WebTransportSecurityIssue::TransportCrossOrigin);
    }

    // TransportInBackground: transport active when page hidden
    if body.contains("WebTransport")
        && (body.contains("visibilitychange") || body.contains("document.hidden"))
    {
        issues.push(WebTransportSecurityIssue::TransportInBackground);
    }

    // TransportHighFrequency: excessive stream creation
    if body.contains("createBidirectionalStream")
        && (body.contains("setInterval") || body.contains("while(") || body.contains("for("))
    {
        issues.push(WebTransportSecurityIssue::TransportHighFrequency);
    }

    // TransportWithoutCertCheck: ignoring certificate validation
    if body.contains("WebTransport")
        && (body.contains("allowPooling")
            || body.contains("serverCertificateHashes")
            || body.contains("requireUnreliable"))
    {
        issues.push(WebTransportSecurityIssue::TransportWithoutCertCheck);
    }

    // TransportBidirectionalAbuse: bidirectional stream data theft
    if body.contains("createBidirectionalStream")
        && (body.contains("localStorage")
            || body.contains("sessionStorage")
            || body.contains("cookie"))
    {
        issues.push(WebTransportSecurityIssue::TransportBidirectionalAbuse);
    }

    // TransportDatagramFlood: datagram flooding for DoS
    if body.contains("datagrams.writable")
        && (body.contains("setInterval") || body.contains("while(") || body.contains("for("))
    {
        issues.push(WebTransportSecurityIssue::TransportDatagramFlood);
    }

    // TransportPersistence: maintaining persistent connections
    if body.contains("WebTransport")
        && (body.contains("reconnect") || body.contains("retry") || body.contains("keepalive"))
    {
        issues.push(WebTransportSecurityIssue::TransportPersistence);
    }

    // TransportToInternalNetwork: connecting to internal IPs
    if body.contains("WebTransport")
        && (body.contains("127.0.0.1")
            || body.contains("localhost")
            || body.contains("192.168.")
            || body.contains("10.0.")
            || body.contains("172.16."))
    {
        issues.push(WebTransportSecurityIssue::TransportToInternalNetwork);
    }

    issues
}

pub fn web_transport_security_severity(issue: &WebTransportSecurityIssue) -> f64 {
    match issue {
        WebTransportSecurityIssue::TransportDataExfiltration => 8.5,
        WebTransportSecurityIssue::UnencryptedTransport => 8.0,
        WebTransportSecurityIssue::TransportBidirectionalAbuse => 7.5,
        WebTransportSecurityIssue::TransportToInternalNetwork => 7.0,
        WebTransportSecurityIssue::TransportWithoutCertCheck => 6.5,
        WebTransportSecurityIssue::TransportCrossOrigin => 6.0,
        WebTransportSecurityIssue::TransportDatagramFlood => 5.5,
        WebTransportSecurityIssue::TransportHighFrequency => 5.0,
        WebTransportSecurityIssue::TransportInBackground => 4.5,
        WebTransportSecurityIssue::TransportPersistence => 4.0,
    }
}

pub fn web_transport_security_to_operations(
    issues: &[WebTransportSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                web_transport_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
