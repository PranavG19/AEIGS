use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Severity for signing bypass findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SigningBypassSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for SigningBypassSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningBypassSeverity::Info => write!(f, "Info"),
            SigningBypassSeverity::Low => write!(f, "Low"),
            SigningBypassSeverity::Medium => write!(f, "Medium"),
            SigningBypassSeverity::High => write!(f, "High"),
            SigningBypassSeverity::Critical => write!(f, "Critical"),
        }
    }
}

/// Signed request replay attack result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySignedRequestResult {
    pub technique: ReplayTechnique,
    pub original_timestamp: String,
    pub replayed_timestamp: String,
    pub nonce: Option<String>,
    pub accepted: bool,
    pub severity: SigningBypassSeverity,
    pub description: String,
}

/// Replay attack techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayTechnique {
    ExactReplay,
    TimestampShift,
    NonceReuse,
    CrossEndpointReplay,
    MethodSwitchReplay,
}

impl fmt::Display for ReplayTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplayTechnique::ExactReplay => write!(f, "Exact Replay"),
            ReplayTechnique::TimestampShift => write!(f, "Timestamp Shift"),
            ReplayTechnique::NonceReuse => write!(f, "Nonce Reuse"),
            ReplayTechnique::CrossEndpointReplay => write!(f, "Cross-Endpoint Replay"),
            ReplayTechnique::MethodSwitchReplay => write!(f, "Method Switch Replay"),
        }
    }
}

/// Algorithm confusion attack result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmConfusionResult {
    pub technique: AlgoConfusionTechnique,
    pub original_algorithm: String,
    pub manipulated_algorithm: String,
    pub signature_header: String,
    pub severity: SigningBypassSeverity,
    pub description: String,
}

/// Algorithm confusion techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlgoConfusionTechnique {
    HmacToNone,
    RsaToHmac,
    Sha256ToSha1,
    Sha256ToMd5,
    CustomAlgorithm,
    AlgorithmHeaderStrip,
}

impl fmt::Display for AlgoConfusionTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlgoConfusionTechnique::HmacToNone => write!(f, "HMAC to None"),
            AlgoConfusionTechnique::RsaToHmac => write!(f, "RSA to HMAC"),
            AlgoConfusionTechnique::Sha256ToSha1 => write!(f, "SHA-256 to SHA-1"),
            AlgoConfusionTechnique::Sha256ToMd5 => write!(f, "SHA-256 to MD5"),
            AlgoConfusionTechnique::CustomAlgorithm => write!(f, "Custom Algorithm"),
            AlgoConfusionTechnique::AlgorithmHeaderStrip => {
                write!(f, "Algorithm Header Strip")
            }
        }
    }
}

/// Empty signature attack result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmptySignatureResult {
    pub technique: EmptySignatureTechnique,
    pub signature_value: String,
    pub severity: SigningBypassSeverity,
    pub description: String,
}

/// Empty/missing signature techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmptySignatureTechnique {
    EmptyString,
    NullByte,
    WhitespaceOnly,
    MissingHeader,
    ZeroLength,
    InvalidBase64,
}

impl fmt::Display for EmptySignatureTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmptySignatureTechnique::EmptyString => write!(f, "Empty String"),
            EmptySignatureTechnique::NullByte => write!(f, "Null Byte"),
            EmptySignatureTechnique::WhitespaceOnly => write!(f, "Whitespace Only"),
            EmptySignatureTechnique::MissingHeader => write!(f, "Missing Header"),
            EmptySignatureTechnique::ZeroLength => write!(f, "Zero-Length HMAC"),
            EmptySignatureTechnique::InvalidBase64 => write!(f, "Invalid Base64"),
        }
    }
}

/// Clock skew exploitation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockSkewResult {
    pub offset_seconds: i64,
    pub direction: ClockSkewDirection,
    pub timestamp_sent: String,
    pub accepted: bool,
    pub severity: SigningBypassSeverity,
    pub description: String,
}

/// Clock skew direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClockSkewDirection {
    Future,
    Past,
}

impl fmt::Display for ClockSkewDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClockSkewDirection::Future => write!(f, "Future"),
            ClockSkewDirection::Past => write!(f, "Past"),
        }
    }
}

/// Partial coverage bypass result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialCoverageResult {
    pub technique: PartialCoverageTechnique,
    pub unsigned_component: String,
    pub manipulation: String,
    pub severity: SigningBypassSeverity,
    pub description: String,
}

/// Partial signing coverage techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartialCoverageTechnique {
    UnsignedQueryParams,
    UnsignedHeaders,
    UnsignedBody,
    UnsignedMethod,
    UnsignedPath,
    UnsignedFragment,
    HeaderOrderManipulation,
    CasingManipulation,
}

impl fmt::Display for PartialCoverageTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PartialCoverageTechnique::UnsignedQueryParams => {
                write!(f, "Unsigned Query Parameters")
            }
            PartialCoverageTechnique::UnsignedHeaders => write!(f, "Unsigned Headers"),
            PartialCoverageTechnique::UnsignedBody => write!(f, "Unsigned Body"),
            PartialCoverageTechnique::UnsignedMethod => write!(f, "Unsigned HTTP Method"),
            PartialCoverageTechnique::UnsignedPath => write!(f, "Unsigned Path"),
            PartialCoverageTechnique::UnsignedFragment => write!(f, "Unsigned Fragment"),
            PartialCoverageTechnique::HeaderOrderManipulation => {
                write!(f, "Header Order Manipulation")
            }
            PartialCoverageTechnique::CasingManipulation => {
                write!(f, "Casing Manipulation")
            }
        }
    }
}

/// Top-level signing bypass finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningBypassFinding {
    pub category: SigningBypassCategory,
    pub severity: SigningBypassSeverity,
    pub title: String,
    pub detail: String,
}

/// Signing bypass attack category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningBypassCategory {
    ReplayAttack,
    AlgorithmConfusion,
    EmptySignature,
    ClockSkewExploitation,
    PartialCoverage,
}

impl fmt::Display for SigningBypassCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningBypassCategory::ReplayAttack => write!(f, "Replay Attack"),
            SigningBypassCategory::AlgorithmConfusion => write!(f, "Algorithm Confusion"),
            SigningBypassCategory::EmptySignature => write!(f, "Empty Signature"),
            SigningBypassCategory::ClockSkewExploitation => {
                write!(f, "Clock Skew Exploitation")
            }
            SigningBypassCategory::PartialCoverage => write!(f, "Partial Coverage"),
        }
    }
}

/// Signing metadata parsed from a signed request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningMetadata {
    pub algorithm: String,
    pub timestamp: String,
    pub nonce: Option<String>,
    pub signed_headers: Vec<String>,
    pub signature: String,
}

/// Parse signing metadata from common header formats.
pub fn parse_signing_metadata(
    auth_header: &str,
    signature_header: Option<&str>,
    timestamp_header: Option<&str>,
) -> SigningMetadata {
    let mut algorithm = "unknown".to_string();
    let mut timestamp = String::new();
    let mut nonce = None;
    let mut signed_headers = Vec::new();
    let mut signature = String::new();

    if auth_header.contains("algorithm=") {
        algorithm = extract_param(auth_header, "algorithm");
    } else if auth_header.contains("SHA256") || auth_header.contains("sha256") {
        algorithm = "hmac-sha256".to_string();
    } else if auth_header.contains("SHA1") || auth_header.contains("sha1") {
        algorithm = "hmac-sha1".to_string();
    }

    if auth_header.contains("timestamp=") {
        timestamp = extract_param(auth_header, "timestamp");
    } else if let Some(ts) = timestamp_header {
        timestamp = ts.to_string();
    }

    if auth_header.contains("nonce=") {
        nonce = Some(extract_param(auth_header, "nonce"));
    }

    if auth_header.contains("headers=") {
        let headers_str = extract_param_quoted(auth_header, "headers");
        signed_headers = headers_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
    }

    if let Some(sig) = signature_header {
        signature = sig.to_string();
    } else if auth_header.contains("signature=") {
        signature = extract_param(auth_header, "signature");
    } else {
        let parts: Vec<&str> = auth_header.rsplitn(2, ' ').collect();
        if parts.len() == 2 {
            signature = parts[0].to_string();
        }
    }

    SigningMetadata {
        algorithm,
        timestamp,
        nonce,
        signed_headers,
        signature,
    }
}

fn extract_param(header: &str, param: &str) -> String {
    let search = format!("{}=", param);
    if let Some(start) = header.find(&search) {
        let value_start = start + search.len();
        let rest = &header[value_start..];
        let rest = rest.trim_start_matches('"');
        let end = rest.find(['"', ',', ' ']).unwrap_or(rest.len());
        rest[..end].to_string()
    } else {
        String::new()
    }
}

fn extract_param_quoted(header: &str, param: &str) -> String {
    let search = format!("{}=", param);
    if let Some(start) = header.find(&search) {
        let value_start = start + search.len();
        let rest = &header[value_start..];
        if let Some(inner) = rest.strip_prefix('"') {
            let end = inner.find('"').unwrap_or(inner.len());
            inner[..end].to_string()
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            rest[..end].trim().to_string()
        }
    } else {
        String::new()
    }
}

/// Generate signed request replay attack tests.
pub fn generate_replay_attacks(
    metadata: &SigningMetadata,
    endpoint: &str,
) -> Vec<ReplaySignedRequestResult> {
    let mut results = Vec::new();

    results.push(ReplaySignedRequestResult {
        technique: ReplayTechnique::ExactReplay,
        original_timestamp: metadata.timestamp.clone(),
        replayed_timestamp: metadata.timestamp.clone(),
        nonce: metadata.nonce.clone(),
        accepted: false,
        severity: SigningBypassSeverity::High,
        description: "Replay the exact signed request to test if server rejects duplicate nonce/timestamp combinations".to_string(),
    });

    let shifted_timestamps = vec![
        ("5 seconds ago", "-5"),
        ("30 seconds ago", "-30"),
        ("5 minutes ago", "-300"),
        ("1 hour ago", "-3600"),
        ("1 day ago", "-86400"),
    ];
    for (label, offset) in &shifted_timestamps {
        results.push(ReplaySignedRequestResult {
            technique: ReplayTechnique::TimestampShift,
            original_timestamp: metadata.timestamp.clone(),
            replayed_timestamp: format!("{}({}s)", metadata.timestamp, offset),
            nonce: metadata.nonce.clone(),
            accepted: false,
            severity: SigningBypassSeverity::High,
            description: format!(
                "Replay signed request with timestamp shifted {} to probe replay window",
                label
            ),
        });
    }

    if let Some(ref nonce_val) = metadata.nonce {
        results.push(ReplaySignedRequestResult {
            technique: ReplayTechnique::NonceReuse,
            original_timestamp: metadata.timestamp.clone(),
            replayed_timestamp: "current".to_string(),
            nonce: Some(nonce_val.clone()),
            accepted: false,
            severity: SigningBypassSeverity::Critical,
            description:
                "Reuse captured nonce with fresh timestamp to test if server tracks consumed nonces"
                    .to_string(),
        });
    }

    results.push(ReplaySignedRequestResult {
        technique: ReplayTechnique::CrossEndpointReplay,
        original_timestamp: metadata.timestamp.clone(),
        replayed_timestamp: metadata.timestamp.clone(),
        nonce: metadata.nonce.clone(),
        accepted: false,
        severity: SigningBypassSeverity::Critical,
        description: format!(
            "Replay signature from {} against a different endpoint to test if endpoint is part of signed content",
            endpoint
        ),
    });

    results.push(ReplaySignedRequestResult {
        technique: ReplayTechnique::MethodSwitchReplay,
        original_timestamp: metadata.timestamp.clone(),
        replayed_timestamp: metadata.timestamp.clone(),
        nonce: metadata.nonce.clone(),
        accepted: false,
        severity: SigningBypassSeverity::High,
        description: "Replay GET-signed request as POST (or vice versa) to test if HTTP method is part of signed content".to_string(),
    });

    results
}

/// Generate algorithm confusion attack tests.
pub fn generate_algorithm_confusion_tests(
    metadata: &SigningMetadata,
) -> Vec<AlgorithmConfusionResult> {
    let mut results = Vec::new();

    results.push(AlgorithmConfusionResult {
        technique: AlgoConfusionTechnique::HmacToNone,
        original_algorithm: metadata.algorithm.clone(),
        manipulated_algorithm: "none".to_string(),
        signature_header: String::new(),
        severity: SigningBypassSeverity::Critical,
        description: "Set algorithm to 'none' with empty signature to test if server accepts unsigned requests".to_string(),
    });

    results.push(AlgorithmConfusionResult {
        technique: AlgoConfusionTechnique::RsaToHmac,
        original_algorithm: metadata.algorithm.clone(),
        manipulated_algorithm: "hmac-sha256".to_string(),
        signature_header: format!(
            "hmac_with_public_key_{}",
            &metadata.signature[..metadata.signature.len().min(16)]
        ),
        severity: SigningBypassSeverity::Critical,
        description: "Switch from RSA to HMAC and sign with the public key to exploit algorithm confusion in JWT-style verification".to_string(),
    });

    results.push(AlgorithmConfusionResult {
        technique: AlgoConfusionTechnique::Sha256ToSha1,
        original_algorithm: metadata.algorithm.clone(),
        manipulated_algorithm: "hmac-sha1".to_string(),
        signature_header: "sha1_signed_placeholder".to_string(),
        severity: SigningBypassSeverity::High,
        description:
            "Downgrade from SHA-256 to SHA-1 to test if server accepts weaker hash algorithm"
                .to_string(),
    });

    results.push(AlgorithmConfusionResult {
        technique: AlgoConfusionTechnique::Sha256ToMd5,
        original_algorithm: metadata.algorithm.clone(),
        manipulated_algorithm: "md5".to_string(),
        signature_header: "md5_signed_placeholder".to_string(),
        severity: SigningBypassSeverity::High,
        description: "Downgrade to MD5 to test for broken hash algorithm acceptance".to_string(),
    });

    results.push(AlgorithmConfusionResult {
        technique: AlgoConfusionTechnique::CustomAlgorithm,
        original_algorithm: metadata.algorithm.clone(),
        manipulated_algorithm: "custom-v1".to_string(),
        signature_header: metadata.signature.clone(),
        severity: SigningBypassSeverity::Medium,
        description:
            "Set algorithm to unknown value to test if server falls back to no verification"
                .to_string(),
    });

    results.push(AlgorithmConfusionResult {
        technique: AlgoConfusionTechnique::AlgorithmHeaderStrip,
        original_algorithm: metadata.algorithm.clone(),
        manipulated_algorithm: "<stripped>".to_string(),
        signature_header: metadata.signature.clone(),
        severity: SigningBypassSeverity::High,
        description:
            "Remove algorithm parameter entirely to test if server defaults to a weaker algorithm"
                .to_string(),
    });

    results
}

/// Generate empty/missing signature attack tests.
pub fn generate_empty_signature_tests() -> Vec<EmptySignatureResult> {
    vec![
        EmptySignatureResult {
            technique: EmptySignatureTechnique::EmptyString,
            signature_value: String::new(),
            severity: SigningBypassSeverity::Critical,
            description: "Send empty string as signature to test if server treats empty as valid"
                .to_string(),
        },
        EmptySignatureResult {
            technique: EmptySignatureTechnique::NullByte,
            signature_value: "\0".to_string(),
            severity: SigningBypassSeverity::Critical,
            description: "Send null byte as signature to test C-string truncation in verification"
                .to_string(),
        },
        EmptySignatureResult {
            technique: EmptySignatureTechnique::WhitespaceOnly,
            signature_value: "   ".to_string(),
            severity: SigningBypassSeverity::High,
            description: "Send whitespace-only signature to test if server trims before comparison"
                .to_string(),
        },
        EmptySignatureResult {
            technique: EmptySignatureTechnique::MissingHeader,
            signature_value: "<header_omitted>".to_string(),
            severity: SigningBypassSeverity::Critical,
            description: "Omit signature header entirely to test if verification is mandatory"
                .to_string(),
        },
        EmptySignatureResult {
            technique: EmptySignatureTechnique::ZeroLength,
            signature_value: compute_hmac_empty_key(""),
            severity: SigningBypassSeverity::High,
            description:
                "Send HMAC computed with empty key to test for empty-secret misconfiguration"
                    .to_string(),
        },
        EmptySignatureResult {
            technique: EmptySignatureTechnique::InvalidBase64,
            signature_value: "!!!not-base64!!!".to_string(),
            severity: SigningBypassSeverity::Medium,
            description:
                "Send non-base64 string as signature to test error handling in decode path"
                    .to_string(),
        },
    ]
}

/// Generate clock skew exploitation tests.
pub fn generate_clock_skew_tests(current_timestamp: &str) -> Vec<ClockSkewResult> {
    let offsets = vec![
        (30, ClockSkewDirection::Future, "30 seconds in the future"),
        (300, ClockSkewDirection::Future, "5 minutes in the future"),
        (3600, ClockSkewDirection::Future, "1 hour in the future"),
        (86400, ClockSkewDirection::Future, "1 day in the future"),
        (30, ClockSkewDirection::Past, "30 seconds in the past"),
        (300, ClockSkewDirection::Past, "5 minutes in the past"),
        (3600, ClockSkewDirection::Past, "1 hour in the past"),
        (86400, ClockSkewDirection::Past, "1 day in the past"),
        (604800, ClockSkewDirection::Past, "1 week in the past"),
    ];

    offsets
        .into_iter()
        .map(|(offset, direction, label)| {
            let sign = match direction {
                ClockSkewDirection::Future => "+",
                ClockSkewDirection::Past => "-",
            };
            ClockSkewResult {
                offset_seconds: offset,
                direction,
                timestamp_sent: format!("{}({}{}s)", current_timestamp, sign, offset),
                accepted: false,
                severity: if offset >= 3600 {
                    SigningBypassSeverity::Critical
                } else if offset >= 300 {
                    SigningBypassSeverity::High
                } else {
                    SigningBypassSeverity::Medium
                },
                description: format!(
                    "Send request with timestamp {} to probe acceptable clock skew window",
                    label
                ),
            }
        })
        .collect()
}

/// Generate partial signing coverage tests.
pub fn generate_partial_coverage_tests(signed_headers: &[String]) -> Vec<PartialCoverageResult> {
    let mut results = Vec::new();

    let all_important_headers = vec![
        "host",
        "content-type",
        "content-length",
        "x-forwarded-for",
        "x-api-key",
        "authorization",
    ];

    let signed_lower: Vec<String> = signed_headers.iter().map(|h| h.to_lowercase()).collect();

    for header in &all_important_headers {
        if !signed_lower.iter().any(|sh| sh == header) {
            results.push(PartialCoverageResult {
                technique: PartialCoverageTechnique::UnsignedHeaders,
                unsigned_component: header.to_string(),
                manipulation: format!("Modify '{}' header without invalidating signature", header),
                severity: if *header == "host" || *header == "authorization" {
                    SigningBypassSeverity::Critical
                } else {
                    SigningBypassSeverity::High
                },
                description: format!(
                    "Header '{}' not included in signed headers list; can be modified without breaking signature",
                    header
                ),
            });
        }
    }

    results.push(PartialCoverageResult {
        technique: PartialCoverageTechnique::UnsignedQueryParams,
        unsigned_component: "query string".to_string(),
        manipulation: "Append ?admin=true to URL without invalidating signature".to_string(),
        severity: SigningBypassSeverity::High,
        description: "Test if query parameters are included in the signed content by appending extra parameters".to_string(),
    });

    results.push(PartialCoverageResult {
        technique: PartialCoverageTechnique::UnsignedBody,
        unsigned_component: "request body".to_string(),
        manipulation: "Modify request body content while keeping original signature".to_string(),
        severity: SigningBypassSeverity::Critical,
        description: "Test if request body is part of signed content by modifying body while preserving signature".to_string(),
    });

    results.push(PartialCoverageResult {
        technique: PartialCoverageTechnique::UnsignedMethod,
        unsigned_component: "HTTP method".to_string(),
        manipulation: "Change GET to POST (or vice versa) with same signature".to_string(),
        severity: SigningBypassSeverity::High,
        description: "Test if HTTP method is part of the signed content by switching methods"
            .to_string(),
    });

    results.push(PartialCoverageResult {
        technique: PartialCoverageTechnique::UnsignedPath,
        unsigned_component: "URL path".to_string(),
        manipulation: "Change /api/users to /api/admin with same signature".to_string(),
        severity: SigningBypassSeverity::Critical,
        description: "Test if URL path is part of signed content by changing the path component"
            .to_string(),
    });

    results.push(PartialCoverageResult {
        technique: PartialCoverageTechnique::UnsignedFragment,
        unsigned_component: "URL fragment".to_string(),
        manipulation: "Add #admin fragment to URL".to_string(),
        severity: SigningBypassSeverity::Low,
        description: "Test if URL fragment is processed server-side by adding fragment component"
            .to_string(),
    });

    results.push(PartialCoverageResult {
        technique: PartialCoverageTechnique::HeaderOrderManipulation,
        unsigned_component: "header ordering".to_string(),
        manipulation: "Reorder signed headers to test if canonicalization is order-dependent"
            .to_string(),
        severity: SigningBypassSeverity::Medium,
        description: "Reorder headers included in signature to test canonical form sensitivity"
            .to_string(),
    });

    results.push(PartialCoverageResult {
        technique: PartialCoverageTechnique::CasingManipulation,
        unsigned_component: "header casing".to_string(),
        manipulation: "Change 'Content-Type' to 'content-type' in signed headers".to_string(),
        severity: SigningBypassSeverity::Medium,
        description: "Change header name casing to test if signature canonicalization handles case normalization".to_string(),
    });

    results
}

fn compute_hmac_empty_key(data: &str) -> String {
    let hash = Sha256::digest(data.as_bytes());
    format!("{:x}", hash)
}

/// Run the full signing bypass analysis.
pub fn run_signing_bypass_analysis(
    auth_header: &str,
    signature_header: Option<&str>,
    timestamp_header: Option<&str>,
    endpoint: &str,
) -> Vec<SigningBypassFinding> {
    let mut findings = Vec::new();
    let metadata = parse_signing_metadata(auth_header, signature_header, timestamp_header);

    let replay_tests = generate_replay_attacks(&metadata, endpoint);
    for test in &replay_tests {
        findings.push(SigningBypassFinding {
            category: SigningBypassCategory::ReplayAttack,
            severity: test.severity,
            title: format!("{} attack", test.technique),
            detail: test.description.clone(),
        });
    }

    let algo_tests = generate_algorithm_confusion_tests(&metadata);
    for test in &algo_tests {
        findings.push(SigningBypassFinding {
            category: SigningBypassCategory::AlgorithmConfusion,
            severity: test.severity,
            title: format!(
                "{}: {} → {}",
                test.technique, test.original_algorithm, test.manipulated_algorithm
            ),
            detail: test.description.clone(),
        });
    }

    let empty_tests = generate_empty_signature_tests();
    for test in &empty_tests {
        findings.push(SigningBypassFinding {
            category: SigningBypassCategory::EmptySignature,
            severity: test.severity,
            title: format!("{} signature", test.technique),
            detail: test.description.clone(),
        });
    }

    if !metadata.timestamp.is_empty() {
        let skew_tests = generate_clock_skew_tests(&metadata.timestamp);
        for test in &skew_tests {
            findings.push(SigningBypassFinding {
                category: SigningBypassCategory::ClockSkewExploitation,
                severity: test.severity,
                title: format!(
                    "{} {} {}s",
                    test.direction, test.direction, test.offset_seconds
                ),
                detail: test.description.clone(),
            });
        }
    }

    let coverage_tests = generate_partial_coverage_tests(&metadata.signed_headers);
    for test in &coverage_tests {
        findings.push(SigningBypassFinding {
            category: SigningBypassCategory::PartialCoverage,
            severity: test.severity,
            title: format!("{}: {}", test.technique, test.unsigned_component),
            detail: test.description.clone(),
        });
    }

    findings
}
