use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum CompressionStreamIssue {
    ApiDetected,
    ZipBombRisk,
    DataExfiltration,
    ResourceExhaustion,
    UntrustedDecompression,
}

impl std::fmt::Display for CompressionStreamIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::ZipBombRisk => write!(f, "zip_bomb_risk"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::ResourceExhaustion => write!(f, "resource_exhaustion"),
            Self::UntrustedDecompression => write!(f, "untrusted_decompression"),
        }
    }
}

pub fn audit_compression_stream(target: &str) -> Vec<CompressionStreamIssue> {
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
    analyze_compression_stream(&body)
}

pub fn analyze_compression_stream(body: &str) -> Vec<CompressionStreamIssue> {
    let has_compress = body.contains("CompressionStream");
    let has_decompress = body.contains("DecompressionStream");

    if !has_compress && !has_decompress {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(CompressionStreamIssue::ApiDetected);

    if has_decompress
        && !body.contains("limit") && !body.contains("maxSize") && !body.contains("MAX_SIZE")
        && (body.contains("pipeThrough") || body.contains("pipeTo"))
    {
        issues.push(CompressionStreamIssue::ZipBombRisk);
    }

    if has_compress
        && (body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest"))
    {
        issues.push(CompressionStreamIssue::DataExfiltration);
    }

    if (has_compress || has_decompress)
        && (body.contains("while") || body.contains("for(") || body.contains("for ("))
        && !body.contains("break") && !body.contains("limit")
    {
        issues.push(CompressionStreamIssue::ResourceExhaustion);
    }

    if has_decompress
        && (body.contains("user") || body.contains("input") || body.contains("upload") || body.contains("file"))
        && !body.contains("validate") && !body.contains("sanitize")
    {
        issues.push(CompressionStreamIssue::UntrustedDecompression);
    }

    issues
}

pub fn compression_stream_severity(issue: &CompressionStreamIssue) -> f64 {
    match issue {
        CompressionStreamIssue::ZipBombRisk => 8.0,
        CompressionStreamIssue::ResourceExhaustion => 7.0,
        CompressionStreamIssue::DataExfiltration => 6.5,
        CompressionStreamIssue::UntrustedDecompression => 6.0,
        CompressionStreamIssue::ApiDetected => 2.0,
    }
}

pub fn compression_stream_to_operations(
    issues: &[CompressionStreamIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                compression_stream_severity(issue),
                0.5,
            )
        })
        .collect()
}
