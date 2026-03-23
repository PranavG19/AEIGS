use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ContentTypeConfusionIssue {
    AcceptsXmlWhenExpectingJson {
        endpoint: String,
    },
    XxeIndicator {
        endpoint: String,
        indicator: String,
    },
    AcceptsMultipleContentTypes {
        endpoint: String,
        accepted: Vec<String>,
    },
    MismatchedResponseType {
        request_ct: String,
        response_ct: String,
    },
    PolyglotPayload {
        content_type: String,
    },
    ContentTypeHeaderInjection {
        header: String,
    },
    MultipartBoundaryConfusion,
    CharsetOverride {
        declared: String,
        actual: String,
    },
    NullByteInContentType,
    WildcardAcceptHeader,
    ContentTypeParameterPollution,
    DoubleContentTypeHeader,
    ContentTypeCaseSensitivity,
    ContentLengthMismatch,
}

impl std::fmt::Display for ContentTypeConfusionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AcceptsXmlWhenExpectingJson { endpoint } => {
                write!(f, "accepts_xml_for_json:{endpoint}")
            }
            Self::XxeIndicator {
                endpoint,
                indicator,
            } => {
                write!(f, "xxe_indicator:{endpoint}:{indicator}")
            }
            Self::AcceptsMultipleContentTypes { endpoint, accepted } => {
                write!(f, "multi_ct:{endpoint}:{}", accepted.join(","))
            }
            Self::MismatchedResponseType {
                request_ct,
                response_ct,
            } => {
                write!(f, "ct_mismatch:{request_ct}->{response_ct}")
            }
            Self::PolyglotPayload { content_type } => {
                write!(f, "polyglot_payload:{content_type}")
            }
            Self::ContentTypeHeaderInjection { header } => {
                write!(f, "ct_header_injection:{header}")
            }
            Self::MultipartBoundaryConfusion => {
                write!(f, "multipart_boundary_confusion")
            }
            Self::CharsetOverride { declared, actual } => {
                write!(f, "charset_override:{declared}->{actual}")
            }
            Self::NullByteInContentType => {
                write!(f, "null_byte_in_content_type")
            }
            Self::WildcardAcceptHeader => {
                write!(f, "wildcard_accept_header")
            }
            Self::ContentTypeParameterPollution => {
                write!(f, "content_type_parameter_pollution")
            }
            Self::DoubleContentTypeHeader => {
                write!(f, "double_content_type_header")
            }
            Self::ContentTypeCaseSensitivity => {
                write!(f, "content_type_case_sensitivity")
            }
            Self::ContentLengthMismatch => {
                write!(f, "content_length_mismatch")
            }
        }
    }
}

const TEST_CONTENT_TYPES: &[&str] = &[
    "application/xml",
    "text/xml",
    "application/x-www-form-urlencoded",
];

pub fn audit_content_type_confusion(target: &str) -> Vec<ContentTypeConfusionIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let mut issues = Vec::new();

    let json_resp = client
        .post(target)
        .header("Content-Type", "application/json")
        .body("{}")
        .send();
    let json_status = json_resp.as_ref().ok().map(|r| r.status().as_u16());

    for &ct in TEST_CONTENT_TYPES {
        let body = if ct.contains("xml") {
            "<root></root>"
        } else {
            "key=value"
        };

        if let Ok(resp) = client
            .post(target)
            .header("Content-Type", ct)
            .body(body)
            .send()
        {
            let status = resp.status().as_u16();
            if let Some(js) = json_status
                && js < 400
                && status < 400
                && ct.contains("xml")
            {
                issues.push(ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson {
                    endpoint: target.to_string(),
                });
            }
        }
    }

    issues
}

pub fn analyze_content_type_confusion(
    json_status: u16,
    xml_status: u16,
    xml_body: &str,
    endpoint: &str,
) -> Vec<ContentTypeConfusionIssue> {
    let mut issues = Vec::new();

    if json_status < 400 && xml_status < 400 {
        issues.push(ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson {
            endpoint: endpoint.to_string(),
        });
    }

    if xml_status < 400 {
        if xml_body.contains("root:") || xml_body.contains("/bin/") {
            issues.push(ContentTypeConfusionIssue::XxeIndicator {
                endpoint: endpoint.to_string(),
                indicator: "file_content_leak".to_string(),
            });
        }
        if xml_body.contains("169.254.169.254") || xml_body.contains("metadata") {
            issues.push(ContentTypeConfusionIssue::XxeIndicator {
                endpoint: endpoint.to_string(),
                indicator: "ssrf_metadata_leak".to_string(),
            });
        }
    }

    issues
}

pub fn analyze_response_type_mismatch(
    request_content_type: &str,
    response_content_type: &str,
) -> Option<ContentTypeConfusionIssue> {
    let req_ct = request_content_type.to_ascii_lowercase();
    let resp_ct = response_content_type.to_ascii_lowercase();

    let req_is_json = req_ct.contains("json");
    let resp_is_json = resp_ct.contains("json");
    let req_is_xml = req_ct.contains("xml");
    let resp_is_xml = resp_ct.contains("xml");

    if (req_is_json && resp_is_xml) || (req_is_xml && resp_is_json) {
        return Some(ContentTypeConfusionIssue::MismatchedResponseType {
            request_ct: request_content_type.to_string(),
            response_ct: response_content_type.to_string(),
        });
    }

    None
}

pub fn analyze_content_type_confusion_advanced(
    content_type: Option<&str>,
    headers: &[(&str, &str)],
    body: &str,
) -> Vec<ContentTypeConfusionIssue> {
    let mut issues = Vec::new();

    // PolyglotPayload: body starts with patterns valid in multiple formats
    if let Some(ct) = content_type {
        let ct_lower = ct.to_ascii_lowercase();
        if body.starts_with("%PDF") && !ct_lower.contains("pdf") {
            issues.push(ContentTypeConfusionIssue::PolyglotPayload {
                content_type: ct.to_string(),
            });
        }
        if (body.starts_with("GIF89a") || body.starts_with("GIF87a"))
            && !ct_lower.contains("image")
            && !ct_lower.contains("gif")
        {
            issues.push(ContentTypeConfusionIssue::PolyglotPayload {
                content_type: ct.to_string(),
            });
        }
        if body.starts_with("<script") && !ct_lower.contains("html") && !ct_lower.contains("xml") {
            issues.push(ContentTypeConfusionIssue::PolyglotPayload {
                content_type: ct.to_string(),
            });
        }
    }

    // ContentTypeHeaderInjection: CRLF injection in headers
    for (name, value) in headers {
        if (name.eq_ignore_ascii_case("content-type")
            || name.to_ascii_lowercase().contains("content"))
            && (value.contains("\r\n") || value.to_ascii_lowercase().contains("%0d%0a"))
        {
            issues.push(ContentTypeConfusionIssue::ContentTypeHeaderInjection {
                header: value.to_string(),
            });
        }
    }

    // MultipartBoundaryConfusion: multipart with mismatched boundary
    if let Some(ct) = content_type
        && ct.to_ascii_lowercase().contains("multipart")
        && let Some(boundary_start) = ct.find("boundary=")
    {
        let boundary = &ct[boundary_start + 9..];
        let boundary_clean = boundary.split(';').next().unwrap_or(boundary).trim();
        if body.contains("--") && !body.contains(&format!("--{}", boundary_clean)) {
            issues.push(ContentTypeConfusionIssue::MultipartBoundaryConfusion);
        }
    }

    // CharsetOverride: multiple different charset declarations
    let mut charsets = Vec::new();
    if let Some(ct) = content_type
        && let Some(charset_start) = ct.find("charset=")
    {
        let charset = &ct[charset_start + 8..];
        let charset_clean = charset
            .split(';')
            .next()
            .unwrap_or(charset)
            .trim()
            .to_ascii_lowercase();
        charsets.push(("header".to_string(), charset_clean));
    }

    if body.contains("<meta")
        && body.contains("charset=")
        && let Some(meta_start) = body.find("charset=")
    {
        let meta_charset_raw = &body[meta_start + 8..];
        let meta_charset_raw = meta_charset_raw.trim_start();
        let (start_offset, quote_char) = if meta_charset_raw.starts_with('"') {
            (1, '"')
        } else if meta_charset_raw.starts_with('\'') {
            (1, '\'')
        } else {
            (0, '>')
        };
        let meta_charset_raw = &meta_charset_raw[start_offset..];
        if let Some(end_pos) = meta_charset_raw.find(quote_char) {
            let meta_charset = meta_charset_raw[..end_pos].trim().to_ascii_lowercase();
            if !meta_charset.is_empty() {
                charsets.push(("body".to_string(), meta_charset));
            }
        }
    }

    if charsets.len() >= 2 {
        let declared = &charsets[0].1;
        let actual = &charsets[1].1;
        if declared != actual {
            issues.push(ContentTypeConfusionIssue::CharsetOverride {
                declared: declared.clone(),
                actual: actual.clone(),
            });
        }
    }

    // NullByteInContentType: null byte in content-type
    if let Some(ct) = content_type
        && (ct.contains("%00") || ct.contains('\0'))
    {
        issues.push(ContentTypeConfusionIssue::NullByteInContentType);
    }

    // WildcardAcceptHeader: Accept: */* with content negotiation
    let has_wildcard_accept = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("accept") && v.contains("*/*"));
    let has_content_negotiation = headers.iter().any(|(k, _v)| {
        k.eq_ignore_ascii_case("accept-language")
            || k.eq_ignore_ascii_case("accept-encoding")
            || k.eq_ignore_ascii_case("accept-charset")
    });
    if has_wildcard_accept && has_content_negotiation {
        issues.push(ContentTypeConfusionIssue::WildcardAcceptHeader);
    }

    // ContentTypeParameterPollution: duplicate parameter keys
    if let Some(ct) = content_type {
        let parts: Vec<&str> = ct.split(';').map(|s| s.trim()).collect();
        let params: Vec<&str> = parts
            .iter()
            .skip(1)
            .filter_map(|p| p.split('=').next())
            .collect();
        let mut seen = std::collections::HashSet::new();
        for param in params {
            if !seen.insert(param.to_ascii_lowercase()) {
                issues.push(ContentTypeConfusionIssue::ContentTypeParameterPollution);
                break;
            }
        }
    }

    // DoubleContentTypeHeader: multiple content-type headers
    let ct_count = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .count();
    if ct_count > 1 {
        issues.push(ContentTypeConfusionIssue::DoubleContentTypeHeader);
    }

    // ContentTypeCaseSensitivity: non-standard casing
    if let Some(ct) = content_type {
        let first_part = ct.split(';').next().unwrap_or(ct).trim();
        if first_part != first_part.to_ascii_lowercase()
            && (first_part.contains("Application")
                || first_part.contains("Text")
                || first_part.contains("Image")
                || first_part.contains("JSON")
                || first_part.contains("XML"))
        {
            issues.push(ContentTypeConfusionIssue::ContentTypeCaseSensitivity);
        }
    }

    // ContentLengthMismatch: Content-Length differs from actual body length
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length")
            && let Ok(declared_len) = value.parse::<usize>()
        {
            let actual_len = body.len();
            let diff = declared_len.abs_diff(actual_len);
            if diff > 10 && diff as f64 / actual_len.max(1) as f64 > 0.1 {
                issues.push(ContentTypeConfusionIssue::ContentLengthMismatch);
                break;
            }
        }
    }

    issues
}

pub fn content_type_confusion_severity(issue: &ContentTypeConfusionIssue) -> f64 {
    match issue {
        ContentTypeConfusionIssue::XxeIndicator { .. } => 9.0,
        ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson { .. } => 6.0,
        ContentTypeConfusionIssue::MismatchedResponseType { .. } => 4.0,
        ContentTypeConfusionIssue::AcceptsMultipleContentTypes { .. } => 3.5,
        ContentTypeConfusionIssue::PolyglotPayload { .. } => 8.0,
        ContentTypeConfusionIssue::ContentTypeHeaderInjection { .. } => 8.5,
        ContentTypeConfusionIssue::MultipartBoundaryConfusion => 6.0,
        ContentTypeConfusionIssue::CharsetOverride { .. } => 5.5,
        ContentTypeConfusionIssue::NullByteInContentType => 7.5,
        ContentTypeConfusionIssue::WildcardAcceptHeader => 4.0,
        ContentTypeConfusionIssue::ContentTypeParameterPollution => 6.5,
        ContentTypeConfusionIssue::DoubleContentTypeHeader => 5.0,
        ContentTypeConfusionIssue::ContentTypeCaseSensitivity => 3.0,
        ContentTypeConfusionIssue::ContentLengthMismatch => 4.5,
    }
}

pub fn content_type_confusion_to_operations(
    issues: &[ContentTypeConfusionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::XmlExternalEntity,
                content_type_confusion_severity(issue),
                0.7,
            )
        })
        .collect()
}
