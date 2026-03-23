use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum SmugglingIssue {
    DualTransferEncoding,
    TransferEncodingAndContentLength,
    ObfuscatedTransferEncoding { variant: String },
    Http11WithoutHostValidation,
}

impl std::fmt::Display for SmugglingIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DualTransferEncoding => write!(f, "dual_transfer_encoding"),
            Self::TransferEncodingAndContentLength => {
                write!(f, "te_and_cl_both_present")
            }
            Self::ObfuscatedTransferEncoding { variant } => {
                write!(f, "obfuscated_te:{variant}")
            }
            Self::Http11WithoutHostValidation => {
                write!(f, "http11_no_host_validation")
            }
        }
    }
}

pub fn audit_request_smuggling(target: &str) -> Vec<SmugglingIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let mut issues = Vec::new();

    if let Ok(resp) = client
        .get(target)
        .header("transfer-encoding", "chunked")
        .header("content-length", "0")
        .send()
    {
        let te = resp
            .headers()
            .get("transfer-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let cl = resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !te.is_empty() && !cl.is_empty() {
            issues.push(SmugglingIssue::TransferEncodingAndContentLength);
        }
    }

    if let Ok(resp) = client
        .get(target)
        .header("host", "smuggle-test.invalid")
        .send()
        && resp.status().is_success()
    {
        issues.push(SmugglingIssue::Http11WithoutHostValidation);
    }

    issues
}

pub fn analyze_smuggling_headers(
    has_te: bool,
    has_cl: bool,
    te_values: &[&str],
    accepts_invalid_host: bool,
) -> Vec<SmugglingIssue> {
    let mut issues = Vec::new();

    if has_te && has_cl {
        issues.push(SmugglingIssue::TransferEncodingAndContentLength);
    }

    if te_values.len() > 1 {
        issues.push(SmugglingIssue::DualTransferEncoding);
    }

    const VALID_TE: &[&str] = &["chunked", "identity", "gzip", "compress", "deflate"];
    for &te in te_values {
        if !VALID_TE.contains(&te) {
            issues.push(SmugglingIssue::ObfuscatedTransferEncoding {
                variant: te.to_string(),
            });
        }
    }

    if accepts_invalid_host {
        issues.push(SmugglingIssue::Http11WithoutHostValidation);
    }

    issues
}

pub(crate) fn smuggling_severity(issue: &SmugglingIssue) -> f64 {
    match issue {
        SmugglingIssue::DualTransferEncoding => 8.0,
        SmugglingIssue::TransferEncodingAndContentLength => 7.5,
        SmugglingIssue::ObfuscatedTransferEncoding { .. } => 7.0,
        SmugglingIssue::Http11WithoutHostValidation => 5.0,
    }
}

pub fn smuggling_to_operations(
    issues: &[SmugglingIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::HttpRequestSmuggling,
                smuggling_severity(issue),
                0.8,
            )
        })
        .collect()
}
