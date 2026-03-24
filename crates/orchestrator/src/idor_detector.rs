use std::collections::{HashMap, HashSet};

/// ID pattern types detected by the IDOR detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdPatternType {
    Sequential,
    UuidV1,
    UuidV4,
    Base64Encoded,
    HexEncoded,
    Hashid,
}

impl std::fmt::Display for IdPatternType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sequential => write!(f, "sequential_integer"),
            Self::UuidV1 => write!(f, "uuid_v1"),
            Self::UuidV4 => write!(f, "uuid_v4"),
            Self::Base64Encoded => write!(f, "base64_encoded"),
            Self::HexEncoded => write!(f, "hex_encoded"),
            Self::Hashid => write!(f, "hashid"),
        }
    }
}

/// Result of classifying an ID string.
#[derive(Debug, Clone, PartialEq)]
pub struct IdClassification {
    pub value: String,
    pub pattern: IdPatternType,
    pub confidence: f64,
    pub decoded_value: Option<String>,
}

/// Extracted components from a UUID v1.
#[derive(Debug, Clone, PartialEq)]
pub struct UuidV1Components {
    pub timestamp_hex: String,
    pub timestamp_100ns_intervals: u64,
    pub clock_seq: u16,
    pub mac_address: String,
    pub is_predictable: bool,
}

/// Privilege level for authorization testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrivilegeLevel {
    Unauthenticated,
    RegularUser,
    Admin,
}

impl std::fmt::Display for PrivilegeLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthenticated => write!(f, "unauthenticated"),
            Self::RegularUser => write!(f, "regular_user"),
            Self::Admin => write!(f, "admin"),
        }
    }
}

/// A discovered reference point — a parameter that carries an object ID.
#[derive(Debug, Clone, PartialEq)]
pub struct ReferencePoint {
    pub parameter_name: String,
    pub location: ParameterLocation,
    pub sample_value: String,
    pub pattern: IdPatternType,
    pub resource_type: Option<String>,
}

/// Where a parameter was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParameterLocation {
    Path,
    Query,
    Body,
    Header,
}

impl std::fmt::Display for ParameterLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path => write!(f, "path"),
            Self::Query => write!(f, "query"),
            Self::Body => write!(f, "body"),
            Self::Header => write!(f, "header"),
        }
    }
}

/// Classification of a response comparison result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessResult {
    /// Identical response content — access was granted.
    FullAccess,
    /// Different response — access was denied or different resource.
    Denied,
    /// Partial data returned — some fields redacted.
    PartialAccess,
    /// Server returned an error status.
    Error,
}

impl std::fmt::Display for AccessResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FullAccess => write!(f, "full_access"),
            Self::Denied => write!(f, "denied"),
            Self::PartialAccess => write!(f, "partial_access"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// Result of comparing two HTTP responses.
#[derive(Debug, Clone, PartialEq)]
pub struct ResponseDiff {
    pub access_result: AccessResult,
    pub status_a: u16,
    pub status_b: u16,
    pub body_similarity: f64,
    pub shared_fields: Vec<String>,
    pub missing_fields: Vec<String>,
    pub extra_fields: Vec<String>,
}

/// A test plan for horizontal privilege escalation.
#[derive(Debug, Clone)]
pub struct HorizontalTestPlan {
    pub endpoint: String,
    pub method: String,
    pub target_parameter: String,
    pub original_id: String,
    pub replacement_ids: Vec<String>,
    pub privilege_level: PrivilegeLevel,
}

/// A test plan for vertical privilege escalation.
#[derive(Debug, Clone)]
pub struct VerticalTestPlan {
    pub endpoint: String,
    pub method: String,
    pub required_privilege: PrivilegeLevel,
    pub test_with_privilege: PrivilegeLevel,
    pub description: String,
}

/// A multi-step IDOR chain.
#[derive(Debug, Clone)]
pub struct IdorChain {
    pub steps: Vec<IdorChainStep>,
    pub description: String,
    pub severity: ChainSeverity,
}

/// A single step in a multi-step IDOR chain.
#[derive(Debug, Clone)]
pub struct IdorChainStep {
    pub endpoint: String,
    pub method: String,
    pub action: String,
    pub extracts: Option<String>,
}

/// Severity of a chained IDOR attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ChainSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// A plan for bulk enumeration of sequential/predictable IDs.
#[derive(Debug, Clone)]
pub struct BulkEnumerationPlan {
    pub endpoint: String,
    pub method: String,
    pub parameter: String,
    pub pattern: IdPatternType,
    pub start_value: String,
    pub estimated_range: u64,
    pub step: u64,
}

/// Endpoint descriptor for the IDOR detector.
#[derive(Debug, Clone)]
pub struct EndpointDescriptor {
    pub path: String,
    pub method: String,
    pub parameters: Vec<ParameterDescriptor>,
    pub requires_auth: bool,
    pub admin_only: bool,
}

/// A single parameter on an endpoint.
#[derive(Debug, Clone)]
pub struct ParameterDescriptor {
    pub name: String,
    pub location: ParameterLocation,
    pub sample_value: Option<String>,
}

/// Intelligent IDOR detection engine.
///
/// Goes beyond the basic `IdorAnalyzer` with deep ID pattern recognition,
/// privilege escalation test generation, reference point discovery,
/// response diffing, multi-step chain analysis, and bulk enumeration planning.
pub struct IdorDetector;

const ID_PARAM_SUFFIXES: &[&str] = &[
    "_id", "Id", "_key", "Key", "_ref", "Ref", "_num", "Num", "_no", "No", "_code", "Code",
];

const RESOURCE_PARAM_PREFIXES: &[&str] = &[
    "user", "account", "order", "invoice", "document", "file", "report", "project", "customer",
    "product", "payment", "ticket", "message", "comment", "post", "session", "group", "team",
    "org", "company",
];

const ADMIN_PATH_SEGMENTS: &[&str] = &[
    "admin",
    "manage",
    "dashboard",
    "internal",
    "system",
    "config",
    "settings",
    "control",
    "backoffice",
    "superuser",
];

impl IdorDetector {
    /// Classifies an ID string into one of the supported pattern types.
    pub fn classify_id(value: &str) -> Option<IdClassification> {
        if value.is_empty() {
            return None;
        }

        if let Some(c) = try_classify_uuid(value) {
            return Some(c);
        }
        if let Some(c) = try_classify_sequential(value) {
            return Some(c);
        }
        if let Some(c) = try_classify_base64(value) {
            return Some(c);
        }
        if let Some(c) = try_classify_hex(value) {
            return Some(c);
        }
        if let Some(c) = try_classify_hashid(value) {
            return Some(c);
        }
        None
    }

    /// Analyzes a UUID v1 to extract timestamp and MAC address components.
    pub fn analyze_uuid_v1(uuid_str: &str) -> Option<UuidV1Components> {
        let clean = uuid_str.replace('-', "");
        if clean.len() != 32 {
            return None;
        }
        if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }

        let version_nibble = u8::from_str_radix(&clean[12..13], 16).ok()?;
        if version_nibble != 1 {
            return None;
        }

        let time_low = &clean[0..8];
        let time_mid = &clean[8..12];
        let time_hi = &clean[13..16];

        let timestamp_hex = format!("{}{}{}", time_hi, time_mid, time_low);
        let timestamp_100ns = u64::from_str_radix(&timestamp_hex, 16).ok()?;

        let clock_seq_hi = u8::from_str_radix(&clean[16..18], 16).ok()? & 0x3F;
        let clock_seq_lo = u8::from_str_radix(&clean[18..20], 16).ok()?;
        let clock_seq = ((clock_seq_hi as u16) << 8) | (clock_seq_lo as u16);

        let mac_bytes: Vec<String> = (0..6)
            .map(|i| clean[20 + i * 2..22 + i * 2].to_string())
            .collect();
        let mac_address = mac_bytes.join(":");

        let multicast_bit = u8::from_str_radix(&clean[20..22], 16).ok()? & 0x01;
        let is_predictable = multicast_bit == 0;

        Some(UuidV1Components {
            timestamp_hex,
            timestamp_100ns_intervals: timestamp_100ns,
            clock_seq,
            mac_address,
            is_predictable,
        })
    }

    /// Discovers reference points — parameters that carry object IDs.
    pub fn discover_reference_points(endpoints: &[EndpointDescriptor]) -> Vec<ReferencePoint> {
        let mut refs = Vec::new();
        for ep in endpoints {
            for param in &ep.parameters {
                if let Some(rp) = analyze_parameter_as_reference(param, &ep.path) {
                    refs.push(rp);
                }
            }
            extract_path_references(&ep.path, &mut refs);
        }
        dedup_references(&mut refs);
        refs
    }

    /// Compares two HTTP responses and classifies the access result.
    pub fn diff_responses(
        status_a: u16,
        body_a: &str,
        status_b: u16,
        body_b: &str,
    ) -> ResponseDiff {
        if (400..600).contains(&status_b) {
            return ResponseDiff {
                access_result: AccessResult::Error,
                status_a,
                status_b,
                body_similarity: 0.0,
                shared_fields: Vec::new(),
                missing_fields: Vec::new(),
                extra_fields: Vec::new(),
            };
        }

        let fields_a = extract_json_keys(body_a);
        let fields_b = extract_json_keys(body_b);

        let shared: Vec<String> = fields_a.intersection(&fields_b).cloned().collect();
        let missing: Vec<String> = fields_a.difference(&fields_b).cloned().collect();
        let extra: Vec<String> = fields_b.difference(&fields_a).cloned().collect();

        let similarity = compute_body_similarity(body_a, body_b);

        let access_result = if similarity > 0.95 && status_a == status_b {
            AccessResult::FullAccess
        } else if similarity < 0.1 || status_a != status_b {
            AccessResult::Denied
        } else {
            AccessResult::PartialAccess
        };

        ResponseDiff {
            access_result,
            status_a,
            status_b,
            body_similarity: similarity,
            shared_fields: shared,
            missing_fields: missing,
            extra_fields: extra,
        }
    }

    /// Generates horizontal privilege escalation test plans.
    pub fn plan_horizontal_tests(
        endpoints: &[EndpointDescriptor],
        known_ids: &[(&str, &str)],
    ) -> Vec<HorizontalTestPlan> {
        let id_map: HashMap<&str, Vec<&str>> = {
            let mut m: HashMap<&str, Vec<&str>> = HashMap::new();
            for &(param, value) in known_ids {
                m.entry(param).or_default().push(value);
            }
            m
        };

        let mut plans = Vec::new();
        for ep in endpoints {
            if ep.admin_only {
                continue;
            }
            for param in &ep.parameters {
                let lower = param.name.to_lowercase();
                if !is_id_like_param(&lower) {
                    continue;
                }
                let original = param
                    .sample_value
                    .clone()
                    .unwrap_or_else(|| "1".to_string());
                let replacements = generate_replacement_ids(&original, &param.name, &id_map);
                if replacements.is_empty() {
                    continue;
                }
                plans.push(HorizontalTestPlan {
                    endpoint: ep.path.clone(),
                    method: ep.method.clone(),
                    target_parameter: param.name.clone(),
                    original_id: original,
                    replacement_ids: replacements,
                    privilege_level: PrivilegeLevel::RegularUser,
                });
            }
        }
        plans
    }

    /// Generates vertical privilege escalation test plans.
    pub fn plan_vertical_tests(endpoints: &[EndpointDescriptor]) -> Vec<VerticalTestPlan> {
        let mut plans = Vec::new();
        for ep in endpoints {
            if ep.admin_only {
                plans.push(VerticalTestPlan {
                    endpoint: ep.path.clone(),
                    method: ep.method.clone(),
                    required_privilege: PrivilegeLevel::Admin,
                    test_with_privilege: PrivilegeLevel::RegularUser,
                    description: format!(
                        "Access admin endpoint {} {} with regular user token",
                        ep.method, ep.path
                    ),
                });
                plans.push(VerticalTestPlan {
                    endpoint: ep.path.clone(),
                    method: ep.method.clone(),
                    required_privilege: PrivilegeLevel::Admin,
                    test_with_privilege: PrivilegeLevel::Unauthenticated,
                    description: format!(
                        "Access admin endpoint {} {} without authentication",
                        ep.method, ep.path
                    ),
                });
            } else if ep.requires_auth {
                plans.push(VerticalTestPlan {
                    endpoint: ep.path.clone(),
                    method: ep.method.clone(),
                    required_privilege: PrivilegeLevel::RegularUser,
                    test_with_privilege: PrivilegeLevel::Unauthenticated,
                    description: format!(
                        "Access authenticated endpoint {} {} without authentication",
                        ep.method, ep.path
                    ),
                });
            }
        }
        plans
    }

    /// Detects multi-step IDOR chains from endpoint relationships.
    pub fn detect_chains(endpoints: &[EndpointDescriptor]) -> Vec<IdorChain> {
        let mut chains = Vec::new();

        let listing_eps: Vec<&EndpointDescriptor> = endpoints
            .iter()
            .filter(|e| e.method.eq_ignore_ascii_case("GET") && path_looks_like_collection(&e.path))
            .collect();

        let detail_eps: Vec<&EndpointDescriptor> = endpoints
            .iter()
            .filter(|e| e.method.eq_ignore_ascii_case("GET") && path_has_id_placeholder(&e.path))
            .collect();

        let mutation_eps: Vec<&EndpointDescriptor> = endpoints
            .iter()
            .filter(|e| {
                matches!(e.method.to_uppercase().as_str(), "PUT" | "PATCH" | "DELETE")
                    && path_has_id_placeholder(&e.path)
            })
            .collect();

        for listing in &listing_eps {
            let listing_resource = extract_resource_name(&listing.path);
            for detail in &detail_eps {
                let detail_resource = extract_resource_name(&detail.path);
                if listing_resource == detail_resource {
                    chains.push(IdorChain {
                        steps: vec![
                            IdorChainStep {
                                endpoint: listing.path.clone(),
                                method: "GET".to_string(),
                                action: format!("List {} to extract IDs", listing_resource),
                                extracts: Some("object_ids".to_string()),
                            },
                            IdorChainStep {
                                endpoint: detail.path.clone(),
                                method: "GET".to_string(),
                                action: format!(
                                    "Access individual {} with extracted ID",
                                    detail_resource
                                ),
                                extracts: None,
                            },
                        ],
                        description: format!(
                            "Enumerate {} via listing, then access individual records",
                            listing_resource
                        ),
                        severity: ChainSeverity::Medium,
                    });
                }
            }

            for mutation in &mutation_eps {
                let mut_resource = extract_resource_name(&mutation.path);
                if listing_resource == mut_resource {
                    chains.push(IdorChain {
                        steps: vec![
                            IdorChainStep {
                                endpoint: listing.path.clone(),
                                method: "GET".to_string(),
                                action: format!("List {} to extract IDs", listing_resource),
                                extracts: Some("object_ids".to_string()),
                            },
                            IdorChainStep {
                                endpoint: mutation.path.clone(),
                                method: mutation.method.clone(),
                                action: format!("Modify/delete {} with extracted ID", mut_resource),
                                extracts: None,
                            },
                        ],
                        description: format!(
                            "Enumerate {} via listing, then {} individual records",
                            listing_resource,
                            mutation.method.to_uppercase()
                        ),
                        severity: ChainSeverity::High,
                    });
                }
            }
        }

        for detail in &detail_eps {
            if detail.admin_only {
                for listing in &listing_eps {
                    if !listing.admin_only {
                        let resource = extract_resource_name(&detail.path);
                        chains.push(IdorChain {
                            steps: vec![
                                IdorChainStep {
                                    endpoint: listing.path.clone(),
                                    method: "GET".to_string(),
                                    action: "Extract IDs from public listing".to_string(),
                                    extracts: Some("object_ids".to_string()),
                                },
                                IdorChainStep {
                                    endpoint: detail.path.clone(),
                                    method: "GET".to_string(),
                                    action: format!(
                                        "Access admin {} detail with extracted ID",
                                        resource
                                    ),
                                    extracts: None,
                                },
                            ],
                            description: format!(
                                "Use public listing to access admin-only {} details",
                                resource
                            ),
                            severity: ChainSeverity::Critical,
                        });
                    }
                }
            }
        }

        chains
    }

    /// Creates bulk enumeration plans for endpoints with sequential/predictable IDs.
    pub fn plan_bulk_enumeration(endpoints: &[EndpointDescriptor]) -> Vec<BulkEnumerationPlan> {
        let mut plans = Vec::new();
        for ep in endpoints {
            if !ep.method.eq_ignore_ascii_case("GET") {
                continue;
            }
            for param in &ep.parameters {
                let sample = match &param.sample_value {
                    Some(v) if !v.is_empty() => v.clone(),
                    _ => continue,
                };
                if let Some(classification) = Self::classify_id(&sample) {
                    let (start, range, step) = match classification.pattern {
                        IdPatternType::Sequential => {
                            let num: u64 = sample.parse().unwrap_or(1);
                            let start = num.saturating_sub(100).max(1);
                            (start.to_string(), 200_u64, 1_u64)
                        }
                        IdPatternType::HexEncoded => {
                            let num = u64::from_str_radix(&sample, 16).unwrap_or(1);
                            let start = num.saturating_sub(100);
                            (format!("{:x}", start), 200, 1)
                        }
                        _ => continue,
                    };
                    plans.push(BulkEnumerationPlan {
                        endpoint: ep.path.clone(),
                        method: ep.method.clone(),
                        parameter: param.name.clone(),
                        pattern: classification.pattern,
                        start_value: start,
                        estimated_range: range,
                        step,
                    });
                }
            }
        }
        plans
    }

    /// Returns all supported ID pattern types (for acceptance criterion check).
    pub fn supported_pattern_types() -> Vec<IdPatternType> {
        vec![
            IdPatternType::Sequential,
            IdPatternType::UuidV1,
            IdPatternType::UuidV4,
            IdPatternType::Base64Encoded,
            IdPatternType::HexEncoded,
            IdPatternType::Hashid,
        ]
    }
}

fn try_classify_uuid(value: &str) -> Option<IdClassification> {
    if value.len() != 36 {
        return None;
    }
    let positions_ok = value.chars().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => c == '-',
        _ => c.is_ascii_hexdigit(),
    });
    if !positions_ok {
        return None;
    }

    let version_char = value.as_bytes()[14];
    let version = (version_char as char).to_digit(16)?;

    match version {
        1 => Some(IdClassification {
            value: value.to_string(),
            pattern: IdPatternType::UuidV1,
            confidence: 0.95,
            decoded_value: None,
        }),
        4 => Some(IdClassification {
            value: value.to_string(),
            pattern: IdPatternType::UuidV4,
            confidence: 0.9,
            decoded_value: None,
        }),
        _ => Some(IdClassification {
            value: value.to_string(),
            pattern: IdPatternType::UuidV4,
            confidence: 0.5,
            decoded_value: None,
        }),
    }
}

fn try_classify_sequential(value: &str) -> Option<IdClassification> {
    if value.is_empty() || value.len() > 20 {
        return None;
    }
    if !value.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(IdClassification {
        value: value.to_string(),
        pattern: IdPatternType::Sequential,
        confidence: 0.85,
        decoded_value: None,
    })
}

fn try_classify_base64(value: &str) -> Option<IdClassification> {
    if value.len() < 4 {
        return None;
    }
    let is_b64_chars = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    if !is_b64_chars {
        return None;
    }
    if value.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if value.chars().all(|c| c.is_ascii_hexdigit()) && value.len().is_multiple_of(2) {
        return None;
    }

    let has_b64_special = value.contains('+') || value.contains('/') || value.ends_with('=');
    let valid_b64_length = value.len().is_multiple_of(4);

    if !has_b64_special && !valid_b64_length {
        return None;
    }

    let decoded = decode_base64_simple(value);
    let decoded_value = decoded.filter(|d| d.chars().all(|c| c.is_ascii_graphic() || c == ' '));

    Some(IdClassification {
        value: value.to_string(),
        pattern: IdPatternType::Base64Encoded,
        confidence: if has_b64_special { 0.9 } else { 0.6 },
        decoded_value,
    })
}

fn try_classify_hex(value: &str) -> Option<IdClassification> {
    if value.len() < 8 || !value.len().is_multiple_of(2) {
        return None;
    }
    if value.len() == 36 && value.chars().filter(|&c| c == '-').count() == 4 {
        return None;
    }
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if value.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    let decoded = decode_hex_to_string(value);

    Some(IdClassification {
        value: value.to_string(),
        pattern: IdPatternType::HexEncoded,
        confidence: 0.7,
        decoded_value: decoded,
    })
}

fn try_classify_hashid(value: &str) -> Option<IdClassification> {
    if value.len() < 3 || value.len() > 30 {
        return None;
    }
    if value.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !value.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    if value.chars().all(|c| c.is_ascii_hexdigit())
        && value.len() >= 8
        && value.len().is_multiple_of(2)
    {
        return None;
    }
    let has_mixed_case = value.chars().any(|c| c.is_ascii_uppercase())
        && value.chars().any(|c| c.is_ascii_lowercase());
    let has_digits = value.chars().any(|c| c.is_ascii_digit());
    let has_alpha = value.chars().any(|c| c.is_ascii_alphabetic());
    if has_mixed_case && has_digits && has_alpha && value.len() >= 5 {
        return Some(IdClassification {
            value: value.to_string(),
            pattern: IdPatternType::Hashid,
            confidence: 0.65,
            decoded_value: None,
        });
    }
    None
}

fn analyze_parameter_as_reference(
    param: &ParameterDescriptor,
    endpoint_path: &str,
) -> Option<ReferencePoint> {
    let lower = param.name.to_lowercase();
    if !is_id_like_param(&lower) {
        return None;
    }
    let sample = param
        .sample_value
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let pattern = if let Some(c) = IdorDetector::classify_id(&sample) {
        c.pattern
    } else {
        IdPatternType::Sequential
    };
    let resource_type = infer_resource_type(&lower, endpoint_path);

    Some(ReferencePoint {
        parameter_name: param.name.clone(),
        location: param.location,
        sample_value: sample,
        pattern,
        resource_type,
    })
}

fn extract_path_references(path: &str, refs: &mut Vec<ReferencePoint>) {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for (i, segment) in segments.iter().enumerate() {
        let is_placeholder = segment.starts_with(':') || segment.starts_with('{');
        if !is_placeholder {
            continue;
        }
        let param_name = segment
            .trim_start_matches(':')
            .trim_start_matches('{')
            .trim_end_matches('}')
            .to_string();

        let resource_type = if i > 0 {
            Some(segments[i - 1].to_string())
        } else {
            None
        };

        refs.push(ReferencePoint {
            parameter_name: param_name,
            location: ParameterLocation::Path,
            sample_value: String::new(),
            pattern: IdPatternType::Sequential,
            resource_type,
        });
    }
}

fn dedup_references(refs: &mut Vec<ReferencePoint>) {
    let mut seen = HashSet::new();
    refs.retain(|r| {
        let key = (r.parameter_name.clone(), r.location);
        seen.insert(key)
    });
}

fn is_id_like_param(lower: &str) -> bool {
    if lower == "id" {
        return true;
    }
    for suffix in ID_PARAM_SUFFIXES {
        if lower.ends_with(&suffix.to_lowercase()) {
            return true;
        }
    }
    for prefix in RESOURCE_PARAM_PREFIXES {
        let with_id = format!("{}_id", prefix);
        let with_id_camel = format!("{}Id", prefix);
        if lower == with_id || lower == with_id_camel.to_lowercase() {
            return true;
        }
    }
    false
}

fn infer_resource_type(param_lower: &str, endpoint_path: &str) -> Option<String> {
    for prefix in RESOURCE_PARAM_PREFIXES {
        if param_lower.starts_with(prefix) {
            return Some(prefix.to_string());
        }
    }
    let segments: Vec<&str> = endpoint_path.split('/').filter(|s| !s.is_empty()).collect();
    if let Some(last_noun) = segments.iter().rev().find(|s| {
        !s.starts_with(':') && !s.starts_with('{') && !s.chars().all(|c| c.is_ascii_digit())
    }) {
        return Some(last_noun.to_string());
    }
    None
}

fn generate_replacement_ids(
    original: &str,
    param_name: &str,
    id_map: &HashMap<&str, Vec<&str>>,
) -> Vec<String> {
    let mut replacements = Vec::new();

    if let Some(known) = id_map.get(param_name) {
        for &v in known {
            if v != original {
                replacements.push(v.to_string());
            }
        }
    }

    if let Ok(num) = original.parse::<u64>() {
        if num > 0 {
            replacements.push((num - 1).to_string());
        }
        replacements.push((num + 1).to_string());
        replacements.push((num + 100).to_string());
    }

    replacements.sort();
    replacements.dedup();
    replacements
}

fn extract_json_keys(body: &str) -> HashSet<String> {
    let mut keys = HashSet::new();
    for part in body.split('"') {
        if part.ends_with(':') || body.contains(&format!("\"{}\":", part)) {
            let trimmed = part.trim();
            if !trimmed.is_empty()
                && trimmed.len() < 100
                && trimmed
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                keys.insert(trimmed.to_string());
            }
        }
    }
    keys
}

fn compute_body_similarity(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let len_a = a.len() as f64;
    let len_b = b.len() as f64;
    let max_len = len_a.max(len_b);

    let trigrams_a = char_trigrams(a);
    let trigrams_b = char_trigrams(b);

    if trigrams_a.is_empty() && trigrams_b.is_empty() {
        return len_a.min(len_b) / max_len;
    }

    let intersection = trigrams_a.intersection(&trigrams_b).count() as f64;
    let union = trigrams_a.union(&trigrams_b).count() as f64;

    if union == 0.0 {
        return 0.0;
    }
    intersection / union
}

fn char_trigrams(s: &str) -> HashSet<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut set = HashSet::new();
    if chars.len() < 3 {
        set.insert(s.to_string());
        return set;
    }
    for window in chars.windows(3) {
        set.insert(window.iter().collect());
    }
    set
}

fn path_looks_like_collection(path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return false;
    }
    let last = segments[segments.len() - 1];
    !last.starts_with(':')
        && !last.starts_with('{')
        && !last.chars().all(|c| c.is_ascii_digit())
        && (last.ends_with('s') || last.ends_with("list") || last.ends_with("all"))
}

fn path_has_id_placeholder(path: &str) -> bool {
    path.split('/')
        .filter(|s| !s.is_empty())
        .any(|s| s.starts_with(':') || s.starts_with('{') || s.chars().all(|c| c.is_ascii_digit()))
}

fn extract_resource_name(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for seg in &segments {
        if !seg.starts_with(':')
            && !seg.starts_with('{')
            && !seg.chars().all(|c| c.is_ascii_digit())
            && !ADMIN_PATH_SEGMENTS.contains(seg)
            && *seg != "api"
            && *seg != "v1"
            && *seg != "v2"
        {
            return seg.to_string();
        }
    }
    "resource".to_string()
}

fn decode_base64_simple(value: &str) -> Option<String> {
    let clean = value.trim_end_matches('=');
    let mut bits = Vec::new();
    for ch in clean.chars() {
        let val = match ch {
            'A'..='Z' => ch as u8 - b'A',
            'a'..='z' => ch as u8 - b'a' + 26,
            '0'..='9' => ch as u8 - b'0' + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        for bit in (0..6).rev() {
            bits.push((val >> bit) & 1);
        }
    }
    let mut bytes = Vec::new();
    for chunk in bits.chunks(8) {
        if chunk.len() < 8 {
            break;
        }
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | bit;
        }
        bytes.push(byte);
    }
    String::from_utf8(bytes).ok()
}

fn decode_hex_to_string(value: &str) -> Option<String> {
    let bytes: Vec<u8> = (0..value.len())
        .step_by(2)
        .filter_map(|i| {
            if i + 2 <= value.len() {
                u8::from_str_radix(&value[i..i + 2], 16).ok()
            } else {
                None
            }
        })
        .collect();
    let s = String::from_utf8(bytes).ok()?;
    if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        Some(s)
    } else {
        None
    }
}
