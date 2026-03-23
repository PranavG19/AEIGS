use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum CompressionStreamIssue {
    ApiDetected,
    ZipBombRisk,
    NoSizeLimits,
    TimingLeakRisk,
    NoChecksumValidation,
}

impl std::fmt::Display for CompressionStreamIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::ZipBombRisk => write!(f, "zip_bomb_risk"),
            Self::NoSizeLimits => write!(f, "no_size_limits"),
            Self::TimingLeakRisk => write!(f, "timing_leak_risk"),
            Self::NoChecksumValidation => write!(f, "no_checksum_validation"),
        }
    }
}

pub fn compression_stream_severity(issue: &CompressionStreamIssue) -> f64 {
    match issue {
        CompressionStreamIssue::ApiDetected => 2.0,
        CompressionStreamIssue::ZipBombRisk => 8.0,
        CompressionStreamIssue::NoSizeLimits => 7.0,
        CompressionStreamIssue::TimingLeakRisk => 6.0,
        CompressionStreamIssue::NoChecksumValidation => 5.0,
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
    let mut issues = Vec::new();

    let has_compression_stream = body.contains("CompressionStream")
        || body.contains("DecompressionStream")
        || body.contains("new CompressionStream");

    if has_compression_stream {
        issues.push(CompressionStreamIssue::ApiDetected);
    }

    if has_compression_stream && body.contains("untrusted") {
        issues.push(CompressionStreamIssue::ZipBombRisk);
    }

    if has_compression_stream
        && !body.contains("maxSize")
        && !body.contains("sizeLimit")
        && !body.contains("byteLimit")
    {
        issues.push(CompressionStreamIssue::NoSizeLimits);
    }

    if has_compression_stream && body.contains("secret") {
        issues.push(CompressionStreamIssue::TimingLeakRisk);
    }

    if has_compression_stream
        && !body.contains("checksum")
        && !body.contains("integrity")
        && !body.contains("hash")
    {
        issues.push(CompressionStreamIssue::NoChecksumValidation);
    }

    issues
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
