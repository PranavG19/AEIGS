use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Severity for mobile API findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MobileApiSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for MobileApiSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MobileApiSeverity::Info => write!(f, "Info"),
            MobileApiSeverity::Low => write!(f, "Low"),
            MobileApiSeverity::Medium => write!(f, "Medium"),
            MobileApiSeverity::High => write!(f, "High"),
            MobileApiSeverity::Critical => write!(f, "Critical"),
        }
    }
}

/// Certificate pinning bypass detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertPinningBypassResult {
    pub endpoint: String,
    pub pinning_detected: bool,
    pub bypass_possible: bool,
    pub bypass_methods: Vec<CertPinningBypassMethod>,
    pub severity: MobileApiSeverity,
    pub description: String,
}

/// Known certificate pinning bypass techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertPinningBypassMethod {
    FridaHook,
    ObjctionBypass,
    NetworkSecurityConfigOverride,
    TrustManagerFactory,
    SslPinningDisable,
    ProxyCertInjection,
}

impl fmt::Display for CertPinningBypassMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertPinningBypassMethod::FridaHook => write!(f, "Frida Hook"),
            CertPinningBypassMethod::ObjctionBypass => write!(f, "Objection Bypass"),
            CertPinningBypassMethod::NetworkSecurityConfigOverride => {
                write!(f, "Network Security Config Override")
            }
            CertPinningBypassMethod::TrustManagerFactory => write!(f, "TrustManagerFactory"),
            CertPinningBypassMethod::SslPinningDisable => write!(f, "SSL Pinning Disable"),
            CertPinningBypassMethod::ProxyCertInjection => write!(f, "Proxy Cert Injection"),
        }
    }
}

/// API key extraction pattern match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyExtractionResult {
    pub source: ApiKeySource,
    pub pattern_name: String,
    pub matched_value: String,
    pub key_type: ApiKeyType,
    pub severity: MobileApiSeverity,
    pub description: String,
}

/// Where the API key was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiKeySource {
    HttpHeader,
    QueryParameter,
    RequestBody,
    BinaryBlob,
    HardcodedString,
}

impl fmt::Display for ApiKeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiKeySource::HttpHeader => write!(f, "HTTP Header"),
            ApiKeySource::QueryParameter => write!(f, "Query Parameter"),
            ApiKeySource::RequestBody => write!(f, "Request Body"),
            ApiKeySource::BinaryBlob => write!(f, "Binary Blob"),
            ApiKeySource::HardcodedString => write!(f, "Hardcoded String"),
        }
    }
}

/// Recognized API key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiKeyType {
    GoogleMaps,
    AwsAccessKey,
    StripeKey,
    FirebaseKey,
    TwilioKey,
    SendGridKey,
    GenericBearer,
    GenericApiKey,
    Unknown,
}

impl fmt::Display for ApiKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiKeyType::GoogleMaps => write!(f, "Google Maps API Key"),
            ApiKeyType::AwsAccessKey => write!(f, "AWS Access Key"),
            ApiKeyType::StripeKey => write!(f, "Stripe Key"),
            ApiKeyType::FirebaseKey => write!(f, "Firebase Key"),
            ApiKeyType::TwilioKey => write!(f, "Twilio Key"),
            ApiKeyType::SendGridKey => write!(f, "SendGrid Key"),
            ApiKeyType::GenericBearer => write!(f, "Generic Bearer Token"),
            ApiKeyType::GenericApiKey => write!(f, "Generic API Key"),
            ApiKeyType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Binary protocol detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryProtocolResult {
    pub endpoint: String,
    pub protocol: DetectedBinaryProtocol,
    pub confidence: f64,
    pub indicators: Vec<String>,
    pub severity: MobileApiSeverity,
    pub description: String,
}

/// Known binary protocol types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectedBinaryProtocol {
    Protobuf,
    MessagePack,
    Flatbuffers,
    Thrift,
    Cbor,
    CustomBinary,
    None,
}

impl fmt::Display for DetectedBinaryProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetectedBinaryProtocol::Protobuf => write!(f, "Protocol Buffers"),
            DetectedBinaryProtocol::MessagePack => write!(f, "MessagePack"),
            DetectedBinaryProtocol::Flatbuffers => write!(f, "FlatBuffers"),
            DetectedBinaryProtocol::Thrift => write!(f, "Thrift"),
            DetectedBinaryProtocol::Cbor => write!(f, "CBOR"),
            DetectedBinaryProtocol::CustomBinary => write!(f, "Custom Binary"),
            DetectedBinaryProtocol::None => write!(f, "None"),
        }
    }
}

/// Push notification abuse finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushNotificationAbuse {
    pub abuse_type: PushAbuseType,
    pub endpoint: String,
    pub severity: MobileApiSeverity,
    pub description: String,
    pub proof_payload: String,
}

/// Push notification abuse categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PushAbuseType {
    TokenLeakage,
    UnauthorizedPush,
    TopicEnumeration,
    PayloadInjection,
    RegistrationSpoof,
}

impl fmt::Display for PushAbuseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PushAbuseType::TokenLeakage => write!(f, "Token Leakage"),
            PushAbuseType::UnauthorizedPush => write!(f, "Unauthorized Push"),
            PushAbuseType::TopicEnumeration => write!(f, "Topic Enumeration"),
            PushAbuseType::PayloadInjection => write!(f, "Payload Injection"),
            PushAbuseType::RegistrationSpoof => write!(f, "Registration Spoof"),
        }
    }
}

/// Device token manipulation finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTokenManipulation {
    pub manipulation_type: DeviceTokenAttack,
    pub original_token: String,
    pub manipulated_token: String,
    pub severity: MobileApiSeverity,
    pub description: String,
}

/// Device token attack categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceTokenAttack {
    TokenReplay,
    TokenForge,
    TokenEnumeration,
    CrossUserTokenSwap,
    ExpiredTokenReuse,
}

impl fmt::Display for DeviceTokenAttack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceTokenAttack::TokenReplay => write!(f, "Token Replay"),
            DeviceTokenAttack::TokenForge => write!(f, "Token Forge"),
            DeviceTokenAttack::TokenEnumeration => write!(f, "Token Enumeration"),
            DeviceTokenAttack::CrossUserTokenSwap => write!(f, "Cross-User Token Swap"),
            DeviceTokenAttack::ExpiredTokenReuse => write!(f, "Expired Token Reuse"),
        }
    }
}

/// Top-level mobile API finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileApiFinding {
    pub category: MobileApiAttackCategory,
    pub severity: MobileApiSeverity,
    pub title: String,
    pub detail: String,
}

/// Attack category for mobile API findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MobileApiAttackCategory {
    CertificatePinningBypass,
    ApiKeyExposure,
    BinaryProtocolAbuse,
    PushNotificationAbuse,
    DeviceTokenManipulation,
}

impl fmt::Display for MobileApiAttackCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MobileApiAttackCategory::CertificatePinningBypass => {
                write!(f, "Certificate Pinning Bypass")
            }
            MobileApiAttackCategory::ApiKeyExposure => write!(f, "API Key Exposure"),
            MobileApiAttackCategory::BinaryProtocolAbuse => write!(f, "Binary Protocol Abuse"),
            MobileApiAttackCategory::PushNotificationAbuse => {
                write!(f, "Push Notification Abuse")
            }
            MobileApiAttackCategory::DeviceTokenManipulation => {
                write!(f, "Device Token Manipulation")
            }
        }
    }
}

/// API key patterns for detection in traffic and binary blobs.
struct ApiKeyPattern {
    name: &'static str,
    prefix: &'static str,
    min_length: usize,
    key_type: ApiKeyType,
}

const API_KEY_PATTERNS: &[ApiKeyPattern] = &[
    ApiKeyPattern {
        name: "AWS Access Key",
        prefix: "AKIA",
        min_length: 20,
        key_type: ApiKeyType::AwsAccessKey,
    },
    ApiKeyPattern {
        name: "Stripe Secret Key",
        prefix: "sk_live_",
        min_length: 24,
        key_type: ApiKeyType::StripeKey,
    },
    ApiKeyPattern {
        name: "Stripe Publishable Key",
        prefix: "pk_live_",
        min_length: 24,
        key_type: ApiKeyType::StripeKey,
    },
    ApiKeyPattern {
        name: "Twilio API Key",
        prefix: "SK",
        min_length: 34,
        key_type: ApiKeyType::TwilioKey,
    },
    ApiKeyPattern {
        name: "SendGrid API Key",
        prefix: "SG.",
        min_length: 34,
        key_type: ApiKeyType::SendGridKey,
    },
];

/// Header names commonly carrying API keys.
const API_KEY_HEADERS: &[&str] = &[
    "x-api-key",
    "authorization",
    "x-auth-token",
    "x-access-token",
    "api-key",
    "apikey",
];

/// Query parameter names commonly carrying API keys.
const API_KEY_PARAMS: &[&str] = &["key", "api_key", "apikey", "access_token", "token", "auth"];

/// Detect certificate pinning configuration from response headers and behavior.
pub fn detect_cert_pinning(
    endpoint: &str,
    response_headers: &HashMap<String, String>,
    tls_error_on_proxy: bool,
) -> CertPinningBypassResult {
    let mut pinning_indicators = Vec::new();

    if let Some(hpkp) = response_headers.get("public-key-pins") {
        pinning_indicators.push(format!("HPKP header present: {}", hpkp));
    }
    if let Some(hpkp_ro) = response_headers.get("public-key-pins-report-only") {
        pinning_indicators.push(format!("HPKP-RO header present: {}", hpkp_ro));
    }
    if response_headers
        .get("expect-ct")
        .map_or(false, |v| v.contains("enforce"))
    {
        pinning_indicators.push("Expect-CT with enforce directive".to_string());
    }

    if tls_error_on_proxy {
        pinning_indicators.push("Connection fails through intercepting proxy".to_string());
    }

    let pinning_detected = !pinning_indicators.is_empty();

    let bypass_methods = if pinning_detected {
        vec![
            CertPinningBypassMethod::FridaHook,
            CertPinningBypassMethod::ObjctionBypass,
            CertPinningBypassMethod::NetworkSecurityConfigOverride,
            CertPinningBypassMethod::TrustManagerFactory,
            CertPinningBypassMethod::SslPinningDisable,
            CertPinningBypassMethod::ProxyCertInjection,
        ]
    } else {
        Vec::new()
    };

    let (severity, description) = if pinning_detected && tls_error_on_proxy {
        (
            MobileApiSeverity::Medium,
            format!(
                "Certificate pinning detected on {} with {} indicators; runtime bypass possible via Frida/Objection",
                endpoint,
                pinning_indicators.len()
            ),
        )
    } else if pinning_detected {
        (
            MobileApiSeverity::Low,
            format!(
                "Pinning headers present on {} but not enforced at TLS level; {} indicators found",
                endpoint,
                pinning_indicators.len()
            ),
        )
    } else {
        (
            MobileApiSeverity::High,
            format!(
                "No certificate pinning detected on {}; traffic interception trivial via proxy",
                endpoint
            ),
        )
    };

    CertPinningBypassResult {
        endpoint: endpoint.to_string(),
        pinning_detected,
        bypass_possible: pinning_detected,
        bypass_methods,
        severity,
        description,
    }
}

/// Extract API keys from HTTP headers.
pub fn extract_api_keys_from_headers(
    headers: &HashMap<String, String>,
) -> Vec<ApiKeyExtractionResult> {
    let mut results = Vec::new();

    for (header_name, header_value) in headers {
        let lower_name = header_name.to_lowercase();

        if !API_KEY_HEADERS.iter().any(|h| lower_name.contains(h)) {
            continue;
        }

        let value = header_value.trim();
        if value.is_empty() {
            continue;
        }

        let token_value = if lower_name == "authorization" {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
                .unwrap_or(value)
        } else {
            value
        };

        let key_type = classify_api_key(token_value);
        let pattern_name = if lower_name == "authorization" {
            "Authorization Bearer Token"
        } else {
            "API Key Header"
        };

        results.push(ApiKeyExtractionResult {
            source: ApiKeySource::HttpHeader,
            pattern_name: pattern_name.to_string(),
            matched_value: mask_key(token_value),
            key_type,
            severity: severity_for_key_type(key_type),
            description: format!(
                "API key of type {} found in header '{}'",
                key_type, header_name
            ),
        });
    }

    results
}

/// Extract API keys from query parameters.
pub fn extract_api_keys_from_params(query_string: &str) -> Vec<ApiKeyExtractionResult> {
    let mut results = Vec::new();

    for pair in query_string.split('&') {
        let mut kv = pair.splitn(2, '=');
        let key = kv.next().unwrap_or("");
        let val = kv.next().unwrap_or("");

        if val.is_empty() {
            continue;
        }

        let lower_key = key.to_lowercase();
        if !API_KEY_PARAMS.iter().any(|p| lower_key == *p) {
            continue;
        }

        let key_type = classify_api_key(val);
        results.push(ApiKeyExtractionResult {
            source: ApiKeySource::QueryParameter,
            pattern_name: format!("Query parameter '{}'", key),
            matched_value: mask_key(val),
            key_type,
            severity: MobileApiSeverity::High,
            description: format!(
                "API key exposed in URL query parameter '{}'; logged in server access logs, browser history, and referrer headers",
                key
            ),
        });
    }

    results
}

/// Scan a binary blob or string content for hardcoded API keys.
pub fn extract_api_keys_from_content(content: &str) -> Vec<ApiKeyExtractionResult> {
    let mut results = Vec::new();

    for pattern in API_KEY_PATTERNS {
        for (idx, _) in content.match_indices(pattern.prefix) {
            let remaining = &content[idx..];
            let candidate: String = remaining
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.' || *c == '-')
                .collect();

            if candidate.len() >= pattern.min_length {
                results.push(ApiKeyExtractionResult {
                    source: ApiKeySource::HardcodedString,
                    pattern_name: pattern.name.to_string(),
                    matched_value: mask_key(&candidate),
                    key_type: pattern.key_type,
                    severity: MobileApiSeverity::Critical,
                    description: format!(
                        "Hardcoded {} found in application binary/source at offset {}",
                        pattern.name, idx
                    ),
                });
            }
        }
    }

    if content.contains("AIza") {
        for (idx, _) in content.match_indices("AIza") {
            let remaining = &content[idx..];
            let candidate: String = remaining
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            if candidate.len() >= 35 {
                results.push(ApiKeyExtractionResult {
                    source: ApiKeySource::HardcodedString,
                    pattern_name: "Google Maps API Key".to_string(),
                    matched_value: mask_key(&candidate),
                    key_type: ApiKeyType::GoogleMaps,
                    severity: MobileApiSeverity::High,
                    description: format!("Hardcoded Google API key found at offset {}", idx),
                });
            }
        }
    }

    results
}

/// Detect binary protocol from response content-type and body bytes.
pub fn detect_binary_protocol(
    endpoint: &str,
    content_type: &str,
    body: &[u8],
) -> BinaryProtocolResult {
    let lower_ct = content_type.to_lowercase();
    let mut indicators = Vec::new();
    let mut protocol = DetectedBinaryProtocol::None;
    let mut confidence = 0.0;

    if lower_ct.contains("protobuf") || lower_ct.contains("x-protobuf") {
        protocol = DetectedBinaryProtocol::Protobuf;
        confidence = 0.95;
        indicators.push("Content-Type contains protobuf".to_string());
    } else if lower_ct.contains("msgpack") || lower_ct.contains("x-msgpack") {
        protocol = DetectedBinaryProtocol::MessagePack;
        confidence = 0.95;
        indicators.push("Content-Type contains msgpack".to_string());
    } else if lower_ct.contains("flatbuffers") || lower_ct.contains("x-flatbuffers") {
        protocol = DetectedBinaryProtocol::Flatbuffers;
        confidence = 0.90;
        indicators.push("Content-Type contains flatbuffers".to_string());
    } else if lower_ct.contains("thrift") || lower_ct.contains("x-thrift") {
        protocol = DetectedBinaryProtocol::Thrift;
        confidence = 0.90;
        indicators.push("Content-Type contains thrift".to_string());
    } else if lower_ct.contains("cbor") {
        protocol = DetectedBinaryProtocol::Cbor;
        confidence = 0.90;
        indicators.push("Content-Type contains cbor".to_string());
    }

    if protocol == DetectedBinaryProtocol::None && !body.is_empty() {
        if let Some(detected) = heuristic_binary_detect(body) {
            protocol = detected.0;
            confidence = detected.1;
            indicators.push(detected.2);
        }
    }

    let severity = match protocol {
        DetectedBinaryProtocol::None => MobileApiSeverity::Info,
        _ if confidence >= 0.8 => MobileApiSeverity::Medium,
        _ => MobileApiSeverity::Low,
    };

    let description = match protocol {
        DetectedBinaryProtocol::None => {
            format!("No binary protocol detected on {}", endpoint)
        }
        _ => {
            format!(
                "{} detected on {} (confidence: {:.0}%); binary protocol may bypass WAF text-based rules",
                protocol, endpoint, confidence * 100.0
            )
        }
    };

    BinaryProtocolResult {
        endpoint: endpoint.to_string(),
        protocol,
        confidence,
        indicators,
        severity,
        description,
    }
}

/// Heuristic detection of binary protocols from raw bytes.
fn heuristic_binary_detect(body: &[u8]) -> Option<(DetectedBinaryProtocol, f64, String)> {
    if !body.is_empty() {
        let first = body[0];
        if (0x80..=0x8f).contains(&first)
            || (0x90..=0x9f).contains(&first)
            || (0xa0..=0xbf).contains(&first)
            || first == 0xdc
            || first == 0xdd
            || first == 0xde
            || first == 0xdf
        {
            return Some((
                DetectedBinaryProtocol::MessagePack,
                0.55,
                format!("First byte 0x{:02x} matches MessagePack type marker", first),
            ));
        }
    }

    if body.len() >= 2 {
        let first = body[0];
        if (first & 0x07) <= 5 && first != 0 {
            let wire_type = first & 0x07;
            if wire_type == 0 || wire_type == 2 {
                return Some((
                    DetectedBinaryProtocol::Protobuf,
                    0.6,
                    format!(
                        "First byte 0x{:02x} consistent with protobuf varint field tag",
                        first
                    ),
                ));
            }
        }
    }

    if body.len() >= 4 {
        let non_text = body
            .iter()
            .filter(|b| **b < 0x20 && **b != 0x0a && **b != 0x0d && **b != 0x09)
            .count();
        let ratio = non_text as f64 / body.len() as f64;
        if ratio > 0.15 {
            return Some((
                DetectedBinaryProtocol::CustomBinary,
                0.4,
                format!(
                    "{:.0}% non-printable bytes suggest custom binary protocol",
                    ratio * 100.0
                ),
            ));
        }
    }

    None
}

/// Generate push notification abuse test payloads.
pub fn generate_push_abuse_payloads(
    endpoint: &str,
    device_token: &str,
) -> Vec<PushNotificationAbuse> {
    vec![
        PushNotificationAbuse {
            abuse_type: PushAbuseType::TokenLeakage,
            endpoint: endpoint.to_string(),
            severity: MobileApiSeverity::High,
            description: "Device push token exposed in API response; attacker can send unsolicited notifications".to_string(),
            proof_payload: format!("{{\"device_token\": \"{}\"}}", device_token),
        },
        PushNotificationAbuse {
            abuse_type: PushAbuseType::UnauthorizedPush,
            endpoint: endpoint.to_string(),
            severity: MobileApiSeverity::High,
            description: "Push notification endpoint accepts requests without authentication".to_string(),
            proof_payload: format!(
                "{{\"to\": \"{}\", \"title\": \"test\", \"body\": \"unauthorized push\"}}",
                device_token
            ),
        },
        PushNotificationAbuse {
            abuse_type: PushAbuseType::TopicEnumeration,
            endpoint: endpoint.to_string(),
            severity: MobileApiSeverity::Medium,
            description: "Push topic names are guessable; attacker can subscribe to arbitrary notification channels".to_string(),
            proof_payload: "{\"topics\": [\"admin\", \"internal\", \"debug\", \"all-users\"]}".to_string(),
        },
        PushNotificationAbuse {
            abuse_type: PushAbuseType::PayloadInjection,
            endpoint: endpoint.to_string(),
            severity: MobileApiSeverity::High,
            description: "Push notification payload allows HTML/script injection in title or body fields".to_string(),
            proof_payload: format!(
                "{{\"to\": \"{}\", \"title\": \"<script>alert(1)</script>\", \"body\": \"<img src=x onerror=alert(1)>\"}}",
                device_token
            ),
        },
        PushNotificationAbuse {
            abuse_type: PushAbuseType::RegistrationSpoof,
            endpoint: endpoint.to_string(),
            severity: MobileApiSeverity::Medium,
            description: "Device registration endpoint accepts arbitrary token format without validation".to_string(),
            proof_payload: "{\"device_token\": \"AAAA-FAKE-TOKEN-0000\", \"platform\": \"ios\"}".to_string(),
        },
    ]
}

/// Generate device token manipulation test cases.
pub fn generate_device_token_manipulations(original_token: &str) -> Vec<DeviceTokenManipulation> {
    let mut manipulations = Vec::new();

    manipulations.push(DeviceTokenManipulation {
        manipulation_type: DeviceTokenAttack::TokenReplay,
        original_token: original_token.to_string(),
        manipulated_token: original_token.to_string(),
        severity: MobileApiSeverity::High,
        description: "Replaying captured device token to hijack push notification delivery"
            .to_string(),
    });

    let forged = if original_token.len() > 4 {
        format!(
            "{}FORGED",
            &original_token[..original_token.len() - 6.min(original_token.len())]
        )
    } else {
        "FORGED_TOKEN".to_string()
    };
    manipulations.push(DeviceTokenManipulation {
        manipulation_type: DeviceTokenAttack::TokenForge,
        original_token: original_token.to_string(),
        manipulated_token: forged,
        severity: MobileApiSeverity::Medium,
        description: "Forging device token by modifying suffix to test server-side validation"
            .to_string(),
    });

    if original_token.len() >= 8 {
        let base = &original_token[..original_token.len() - 2];
        let enumerated: Vec<String> = (0..5).map(|i| format!("{}{:02x}", base, i)).collect();
        manipulations.push(DeviceTokenManipulation {
            manipulation_type: DeviceTokenAttack::TokenEnumeration,
            original_token: original_token.to_string(),
            manipulated_token: enumerated.join(","),
            severity: MobileApiSeverity::High,
            description: "Enumerating device tokens by incrementing last bytes to discover other users' tokens".to_string(),
        });
    }

    manipulations.push(DeviceTokenManipulation {
        manipulation_type: DeviceTokenAttack::CrossUserTokenSwap,
        original_token: original_token.to_string(),
        manipulated_token: format!("victim_{}", original_token),
        severity: MobileApiSeverity::Critical,
        description: "Swapping device token in registration to redirect another user's notifications to attacker device".to_string(),
    });

    manipulations.push(DeviceTokenManipulation {
        manipulation_type: DeviceTokenAttack::ExpiredTokenReuse,
        original_token: original_token.to_string(),
        manipulated_token: original_token.to_string(),
        severity: MobileApiSeverity::Medium,
        description:
            "Reusing expired/rotated device token to test if server properly invalidates old tokens"
                .to_string(),
    });

    manipulations
}

fn classify_api_key(value: &str) -> ApiKeyType {
    if value.starts_with("AKIA") && value.len() >= 20 {
        return ApiKeyType::AwsAccessKey;
    }
    if value.starts_with("sk_live_") || value.starts_with("pk_live_") {
        return ApiKeyType::StripeKey;
    }
    if value.starts_with("AIza") && value.len() >= 35 {
        return ApiKeyType::GoogleMaps;
    }
    if value.starts_with("SG.") && value.len() >= 34 {
        return ApiKeyType::SendGridKey;
    }
    if value.starts_with("SK") && value.len() == 34 {
        return ApiKeyType::TwilioKey;
    }
    if value.len() > 20
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return ApiKeyType::GenericApiKey;
    }
    ApiKeyType::Unknown
}

fn severity_for_key_type(key_type: ApiKeyType) -> MobileApiSeverity {
    match key_type {
        ApiKeyType::AwsAccessKey => MobileApiSeverity::Critical,
        ApiKeyType::StripeKey => MobileApiSeverity::Critical,
        ApiKeyType::SendGridKey => MobileApiSeverity::High,
        ApiKeyType::TwilioKey => MobileApiSeverity::High,
        ApiKeyType::GoogleMaps => MobileApiSeverity::Medium,
        ApiKeyType::FirebaseKey => MobileApiSeverity::High,
        ApiKeyType::GenericBearer => MobileApiSeverity::High,
        ApiKeyType::GenericApiKey => MobileApiSeverity::Medium,
        ApiKeyType::Unknown => MobileApiSeverity::Low,
    }
}

fn mask_key(key: &str) -> String {
    if key.len() <= 8 {
        return "*".repeat(key.len());
    }
    let visible = 4;
    format!("{}...{}", &key[..visible], &key[key.len() - visible..])
}

/// Run the full mobile API security analysis.
pub fn run_mobile_api_analysis(
    endpoint: &str,
    response_headers: &HashMap<String, String>,
    tls_error_on_proxy: bool,
    query_string: Option<&str>,
    response_body: Option<&str>,
    content_type: Option<&str>,
    body_bytes: Option<&[u8]>,
    device_token: Option<&str>,
) -> Vec<MobileApiFinding> {
    let mut findings = Vec::new();

    let pinning = detect_cert_pinning(endpoint, response_headers, tls_error_on_proxy);
    if pinning.severity >= MobileApiSeverity::Medium || !pinning.pinning_detected {
        findings.push(MobileApiFinding {
            category: MobileApiAttackCategory::CertificatePinningBypass,
            severity: pinning.severity,
            title: if pinning.pinning_detected {
                "Certificate pinning detected but bypassable".to_string()
            } else {
                "No certificate pinning detected".to_string()
            },
            detail: pinning.description,
        });
    }

    let header_keys = extract_api_keys_from_headers(response_headers);
    for key_finding in &header_keys {
        findings.push(MobileApiFinding {
            category: MobileApiAttackCategory::ApiKeyExposure,
            severity: key_finding.severity,
            title: format!("{} in {}", key_finding.key_type, key_finding.source),
            detail: key_finding.description.clone(),
        });
    }

    if let Some(qs) = query_string {
        let param_keys = extract_api_keys_from_params(qs);
        for key_finding in &param_keys {
            findings.push(MobileApiFinding {
                category: MobileApiAttackCategory::ApiKeyExposure,
                severity: key_finding.severity,
                title: format!("{} in URL parameter", key_finding.key_type),
                detail: key_finding.description.clone(),
            });
        }
    }

    if let Some(body) = response_body {
        let content_keys = extract_api_keys_from_content(body);
        for key_finding in &content_keys {
            findings.push(MobileApiFinding {
                category: MobileApiAttackCategory::ApiKeyExposure,
                severity: key_finding.severity,
                title: format!("Hardcoded {} in response", key_finding.key_type),
                detail: key_finding.description.clone(),
            });
        }
    }

    if let Some(ct) = content_type {
        let bytes = body_bytes.unwrap_or(&[]);
        let binary = detect_binary_protocol(endpoint, ct, bytes);
        if binary.protocol != DetectedBinaryProtocol::None {
            findings.push(MobileApiFinding {
                category: MobileApiAttackCategory::BinaryProtocolAbuse,
                severity: binary.severity,
                title: format!("{} protocol detected", binary.protocol),
                detail: binary.description,
            });
        }
    }

    if let Some(token) = device_token {
        let push_abuses = generate_push_abuse_payloads(endpoint, token);
        for abuse in &push_abuses {
            findings.push(MobileApiFinding {
                category: MobileApiAttackCategory::PushNotificationAbuse,
                severity: abuse.severity,
                title: format!("{} on push endpoint", abuse.abuse_type),
                detail: abuse.description.clone(),
            });
        }

        let token_manips = generate_device_token_manipulations(token);
        for manip in &token_manips {
            findings.push(MobileApiFinding {
                category: MobileApiAttackCategory::DeviceTokenManipulation,
                severity: manip.severity,
                title: format!("{} attack", manip.manipulation_type),
                detail: manip.description.clone(),
            });
        }
    }

    findings
}
