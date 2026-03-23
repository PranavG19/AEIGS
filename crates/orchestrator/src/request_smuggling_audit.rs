use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum RequestSmugglingIssue {
    DualContentLength,
    DualTransferEncoding,
    TransferEncodingAndContentLength,
    ObfuscatedTransferEncoding { variant: String },
    Http2Downgrade,
    InvalidHostAccepted,
    ConnectionUpgradePresent,
    ProxyHeaderManipulation { header: String },
    ContentLengthInJsCode,
    TransferEncodingInJsCode,
    ChunkedEncodingReference,
    H2cUpgradeIndicator,
    FrontendBackendDesync,
    WebsocketUpgradeVulnerable,
}

impl std::fmt::Display for RequestSmugglingIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DualContentLength => write!(f, "dual_content_length"),
            Self::DualTransferEncoding => write!(f, "dual_transfer_encoding"),
            Self::TransferEncodingAndContentLength => write!(f, "te_and_cl_both_present"),
            Self::ObfuscatedTransferEncoding { variant } => {
                write!(f, "obfuscated_te:{variant}")
            }
            Self::Http2Downgrade => write!(f, "http2_downgrade"),
            Self::InvalidHostAccepted => write!(f, "invalid_host_accepted"),
            Self::ConnectionUpgradePresent => write!(f, "connection_upgrade_present"),
            Self::ProxyHeaderManipulation { header } => {
                write!(f, "proxy_header_manipulation:{header}")
            }
            Self::ContentLengthInJsCode => write!(f, "content_length_in_js_code"),
            Self::TransferEncodingInJsCode => write!(f, "transfer_encoding_in_js_code"),
            Self::ChunkedEncodingReference => write!(f, "chunked_encoding_reference"),
            Self::H2cUpgradeIndicator => write!(f, "h2c_upgrade_indicator"),
            Self::FrontendBackendDesync => write!(f, "frontend_backend_desync"),
            Self::WebsocketUpgradeVulnerable => write!(f, "websocket_upgrade_vulnerable"),
        }
    }
}

pub fn request_smuggling_severity(issue: &RequestSmugglingIssue) -> f64 {
    match issue {
        RequestSmugglingIssue::DualContentLength => 9.0,
        RequestSmugglingIssue::TransferEncodingAndContentLength => 8.5,
        RequestSmugglingIssue::DualTransferEncoding => 8.0,
        RequestSmugglingIssue::FrontendBackendDesync => 8.5,
        RequestSmugglingIssue::ObfuscatedTransferEncoding { .. } => 7.5,
        RequestSmugglingIssue::Http2Downgrade => 7.0,
        RequestSmugglingIssue::WebsocketUpgradeVulnerable => 7.0,
        RequestSmugglingIssue::ProxyHeaderManipulation { .. } => 6.5,
        RequestSmugglingIssue::ConnectionUpgradePresent => 5.5,
        RequestSmugglingIssue::InvalidHostAccepted => 5.0,
        RequestSmugglingIssue::H2cUpgradeIndicator => 4.5,
        RequestSmugglingIssue::ChunkedEncodingReference => 3.5,
        RequestSmugglingIssue::TransferEncodingInJsCode => 3.0,
        RequestSmugglingIssue::ContentLengthInJsCode => 2.5,
    }
}

pub fn audit_request_smuggling(target: &str) -> Vec<RequestSmugglingIssue> {
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

    let mut issues = analyze_request_smuggling(&body);

    if let Ok(resp) = client
        .get(target)
        .header("Transfer-Encoding", "chunked")
        .header("Content-Length", "0")
        .send()
    {
        let te_count = resp.headers().get_all("Transfer-Encoding").iter().count();
        let cl_count = resp.headers().get_all("Content-Length").iter().count();

        if te_count > 0 && cl_count > 0 {
            issues.push(RequestSmugglingIssue::TransferEncodingAndContentLength);
        }
        if cl_count > 1 {
            issues.push(RequestSmugglingIssue::DualContentLength);
        }
        if te_count > 1 {
            issues.push(RequestSmugglingIssue::DualTransferEncoding);
        }

        for te_value in resp.headers().get_all("Transfer-Encoding") {
            if let Ok(val_str) = te_value.to_str() {
                let val_trimmed = val_str.trim();
                if !is_valid_transfer_encoding(val_trimmed) {
                    issues.push(RequestSmugglingIssue::ObfuscatedTransferEncoding {
                        variant: val_str.to_string(),
                    });
                }
            }
        }

        if let Some(upgrade_val) = resp.headers().get("Upgrade")
            && let Ok(upgrade_str) = upgrade_val.to_str()
        {
            let upgrade_lower = upgrade_str.to_ascii_lowercase();
            if upgrade_lower.contains("h2c") {
                issues.push(RequestSmugglingIssue::Http2Downgrade);
            }
            if upgrade_lower.contains("websocket")
                && let Some(conn_val) = resp.headers().get("Connection")
                && let Ok(conn_str) = conn_val.to_str()
                && conn_str.to_ascii_lowercase().contains("upgrade")
            {
                issues.push(RequestSmugglingIssue::WebsocketUpgradeVulnerable);
            }
        }

        if let Some(conn) = resp.headers().get("Connection")
            && let Ok(conn_str) = conn.to_str()
            && conn_str.to_ascii_lowercase().contains("upgrade")
        {
            issues.push(RequestSmugglingIssue::ConnectionUpgradePresent);
        }
    }

    if let Ok(resp) = client
        .get(target)
        .header("Host", "smuggle-test.invalid")
        .send()
        && resp.status().is_success()
    {
        issues.push(RequestSmugglingIssue::InvalidHostAccepted);
    }

    let proxy_headers = ["X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP"];
    for proxy_header in &proxy_headers {
        if let Ok(resp) = client
            .get(target)
            .header(*proxy_header, "evil.example.com")
            .send()
            && let Ok(response_body) = resp.text()
            && response_body.contains("evil.example.com")
        {
            issues.push(RequestSmugglingIssue::ProxyHeaderManipulation {
                header: proxy_header.to_string(),
            });
            break;
        }
    }

    if let Ok(resp) = client
        .get(target)
        .header("Transfer-Encoding", "chunked")
        .send()
        && let Ok(te_body) = resp.text()
        && !te_body.is_empty()
        && te_body.len() != body.len()
    {
        issues.push(RequestSmugglingIssue::FrontendBackendDesync);
    }

    issues
}

pub fn analyze_request_smuggling(body: &str) -> Vec<RequestSmugglingIssue> {
    let mut issues = Vec::new();

    let content_length_patterns = [
        "Content-Length:",
        "content-length:",
        "contentLength",
        "setRequestHeader('Content-Length'",
        "setRequestHeader(\"Content-Length\"",
        ".contentLength",
    ];

    for pattern in &content_length_patterns {
        if body.contains(pattern) {
            issues.push(RequestSmugglingIssue::ContentLengthInJsCode);
            break;
        }
    }

    let transfer_encoding_patterns = [
        "Transfer-Encoding:",
        "transfer-encoding:",
        "transferEncoding",
        "setRequestHeader('Transfer-Encoding'",
        "setRequestHeader(\"Transfer-Encoding\"",
        ".transferEncoding",
    ];

    for pattern in &transfer_encoding_patterns {
        if body.contains(pattern) {
            issues.push(RequestSmugglingIssue::TransferEncodingInJsCode);
            break;
        }
    }

    let chunked_patterns = ["chunked", "Transfer-Encoding: chunked"];
    for pattern in &chunked_patterns {
        if body.contains(pattern) {
            issues.push(RequestSmugglingIssue::ChunkedEncodingReference);
            break;
        }
    }

    let h2c_patterns = ["h2c", "HTTP/2", "protocol: 'h2c'", "Upgrade: h2c"];
    for pattern in &h2c_patterns {
        if body.contains(pattern) {
            issues.push(RequestSmugglingIssue::H2cUpgradeIndicator);
            break;
        }
    }

    issues
}

fn is_valid_transfer_encoding(value: &str) -> bool {
    const VALID_TE: &[&str] = &["chunked", "identity", "gzip", "compress", "deflate", "br"];
    VALID_TE.contains(&value)
}

pub fn smuggling_to_operations(
    issues: &[RequestSmugglingIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::HttpRequestSmuggling,
                request_smuggling_severity(issue),
                0.8,
            )
        })
        .collect()
}
