use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum EncodingApiIssue {
    ApiDetected,
    DataExfiltration,
    BufferOverflow,
    EncodingBypass,
    ResourceExhaustion,
}

impl std::fmt::Display for EncodingApiIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::BufferOverflow => write!(f, "buffer_overflow"),
            Self::EncodingBypass => write!(f, "encoding_bypass"),
            Self::ResourceExhaustion => write!(f, "resource_exhaustion"),
        }
    }
}

pub fn audit_encoding_api(target: &str) -> Vec<EncodingApiIssue> {
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
    analyze_encoding_api(&body)
}

pub fn analyze_encoding_api(body: &str) -> Vec<EncodingApiIssue> {
    let has_encoder = body.contains("TextEncoder");
    let has_decoder = body.contains("TextDecoder");

    if !has_encoder && !has_decoder {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(EncodingApiIssue::ApiDetected);

    if (has_encoder || body.contains("encode("))
        && (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("WebSocket")
            || body.contains("XMLHttpRequest"))
        && (body.contains("btoa") || body.contains("atob") || body.contains("base64"))
    {
        issues.push(EncodingApiIssue::DataExfiltration);
    }

    if (has_decoder || has_encoder)
        && (body.contains("ArrayBuffer") || body.contains("Uint8Array"))
        && (body.contains("while") || body.contains("for(") || body.contains("for ("))
        && !body.contains("limit")
        && !body.contains("maxLength")
    {
        issues.push(EncodingApiIssue::BufferOverflow);
    }

    if (has_decoder || has_encoder)
        && (body.contains("innerHTML") || body.contains("document.write") || body.contains("eval("))
        && !body.contains("sanitize")
        && !body.contains("escape")
    {
        issues.push(EncodingApiIssue::EncodingBypass);
    }

    if (has_encoder || has_decoder)
        && (body.contains("encodeInto") || body.contains("decode("))
        && (body.contains("loop") || body.contains("while") || body.contains("setInterval"))
        && !body.contains("break")
        && !body.contains("clearInterval")
    {
        issues.push(EncodingApiIssue::ResourceExhaustion);
    }

    issues
}

pub fn encoding_api_severity(issue: &EncodingApiIssue) -> f64 {
    match issue {
        EncodingApiIssue::ApiDetected => 2.0,
        EncodingApiIssue::DataExfiltration => 7.0,
        EncodingApiIssue::BufferOverflow => 6.5,
        EncodingApiIssue::EncodingBypass => 7.5,
        EncodingApiIssue::ResourceExhaustion => 5.5,
    }
}

pub fn encoding_api_to_operations(
    issues: &[EncodingApiIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                encoding_api_severity(issue),
                0.5,
            )
        })
        .collect()
}
