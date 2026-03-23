use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone)]
pub struct ContentTypeIssue {
    pub kind: ContentTypeIssueKind,
    pub severity: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContentTypeIssueKind {
    MissingNosniff,
    MissingContentType,
    OctetStreamForHtml,
    CharsetMissing,
}

impl std::fmt::Display for ContentTypeIssueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingNosniff => {
                write!(f, "X-Content-Type-Options: nosniff not set")
            }
            Self::MissingContentType => write!(f, "missing Content-Type header"),
            Self::OctetStreamForHtml => {
                write!(
                    f,
                    "Content-Type is application/octet-stream for HTML content"
                )
            }
            Self::CharsetMissing => {
                write!(f, "Content-Type missing charset for text response")
            }
        }
    }
}

pub fn audit_content_type(target: &str) -> Vec<ContentTypeIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let nosniff = resp
        .headers()
        .get("x-content-type-options")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    analyze_content_type(nosniff.as_deref(), content_type.as_deref())
}

pub fn analyze_content_type(
    nosniff: Option<&str>,
    content_type: Option<&str>,
) -> Vec<ContentTypeIssue> {
    let mut issues = Vec::new();

    match nosniff {
        Some(v) if v.trim().eq_ignore_ascii_case("nosniff") => {}
        _ => {
            issues.push(ContentTypeIssue {
                kind: ContentTypeIssueKind::MissingNosniff,
                severity: 3.5,
            });
        }
    }

    let Some(ct) = content_type else {
        issues.push(ContentTypeIssue {
            kind: ContentTypeIssueKind::MissingContentType,
            severity: 4.0,
        });
        return issues;
    };

    let lower = ct.to_ascii_lowercase();

    if lower.contains("application/octet-stream") {
        issues.push(ContentTypeIssue {
            kind: ContentTypeIssueKind::OctetStreamForHtml,
            severity: 4.5,
        });
    }

    if lower.starts_with("text/") && !lower.contains("charset") {
        issues.push(ContentTypeIssue {
            kind: ContentTypeIssueKind::CharsetMissing,
            severity: 2.0,
        });
    }

    issues
}

pub fn content_type_to_operations(
    issues: &[ContentTypeIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues.iter().map(|i| i.severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        max_severity,
        0.85,
    )]
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContentTypeSecurityIssue {
    MimeSniffingVulnerable,
    JsonWithHtmlContent,
    XmlWithScript,
    SvgWithScript,
    CsvInjection,
    TextPlainWithHtml,
    MultipartBoundaryExposed,
    CharsetMismatch,
    ContentTypeDoubleEncoded,
    InconsistentMimeType,
}

impl std::fmt::Display for ContentTypeSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MimeSniffingVulnerable => {
                write!(
                    f,
                    "MIME sniffing vulnerability: HTML content without nosniff"
                )
            }
            Self::JsonWithHtmlContent => {
                write!(f, "JSON content-type with HTML body")
            }
            Self::XmlWithScript => {
                write!(f, "XML content with embedded script")
            }
            Self::SvgWithScript => {
                write!(f, "SVG content with inline JavaScript")
            }
            Self::CsvInjection => {
                write!(
                    f,
                    "CSV injection vulnerability: formula characters detected"
                )
            }
            Self::TextPlainWithHtml => {
                write!(f, "text/plain content-type with HTML body")
            }
            Self::MultipartBoundaryExposed => {
                write!(f, "multipart boundary token exposed")
            }
            Self::CharsetMismatch => {
                write!(f, "charset header mismatch with content")
            }
            Self::ContentTypeDoubleEncoded => {
                write!(f, "content-type header contains encoded characters")
            }
            Self::InconsistentMimeType => {
                write!(f, "content-type inconsistent with actual content")
            }
        }
    }
}

pub fn analyze_content_type_security(
    content_type: Option<&str>,
    nosniff: Option<&str>,
    body: &str,
) -> Vec<ContentTypeSecurityIssue> {
    let mut issues = Vec::new();

    // Skip analysis for empty/whitespace-only bodies
    if body.trim().is_empty() {
        return issues;
    }

    let ct_lower = content_type.map(|s| s.to_ascii_lowercase());
    let nosniff_enabled = nosniff
        .map(|v| v.trim().eq_ignore_ascii_case("nosniff"))
        .unwrap_or(false);

    // 1. MimeSniffingVulnerable
    if !nosniff_enabled
        && looks_like_html(body)
        && let Some(ref ct) = ct_lower
        && !ct.contains("text/html")
    {
        issues.push(ContentTypeSecurityIssue::MimeSniffingVulnerable);
    }

    if let Some(ref ct) = ct_lower {
        // 2. JsonWithHtmlContent
        if ct.contains("application/json") && contains_html_tags(body) {
            issues.push(ContentTypeSecurityIssue::JsonWithHtmlContent);
        }

        // 3. XmlWithScript
        if (ct.contains("application/xml") || ct.contains("text/xml")) && contains_script_tag(body)
        {
            issues.push(ContentTypeSecurityIssue::XmlWithScript);
        }

        // 4. SvgWithScript
        if ct.contains("image/svg") && contains_script_tag(body) {
            issues.push(ContentTypeSecurityIssue::SvgWithScript);
        }

        // 5. CsvInjection
        if ct.contains("text/csv") && has_csv_formula(body) {
            issues.push(ContentTypeSecurityIssue::CsvInjection);
        }

        // 6. TextPlainWithHtml
        if ct.contains("text/plain") && starts_with_html(body) {
            issues.push(ContentTypeSecurityIssue::TextPlainWithHtml);
        }

        // 7. MultipartBoundaryExposed
        if ct.contains("multipart/")
            && let Some(boundary) = extract_boundary(content_type.unwrap_or(""))
            && body.contains(&boundary)
        {
            issues.push(ContentTypeSecurityIssue::MultipartBoundaryExposed);
        }

        // 8. CharsetMismatch
        if let Some(declared_charset) = extract_charset(content_type.unwrap_or(""))
            && has_charset_mismatch(&declared_charset, body)
        {
            issues.push(ContentTypeSecurityIssue::CharsetMismatch);
        }

        // 9. ContentTypeDoubleEncoded
        if content_type.unwrap_or("").contains('%') || content_type.unwrap_or("").contains("\\x") {
            issues.push(ContentTypeSecurityIssue::ContentTypeDoubleEncoded);
        }

        // 10. InconsistentMimeType
        if is_mime_type_inconsistent(ct, body) {
            issues.push(ContentTypeSecurityIssue::InconsistentMimeType);
        }
    }

    issues
}

pub fn content_type_security_severity(issue: &ContentTypeSecurityIssue) -> f64 {
    match issue {
        ContentTypeSecurityIssue::MimeSniffingVulnerable => 6.5,
        ContentTypeSecurityIssue::JsonWithHtmlContent => 5.5,
        ContentTypeSecurityIssue::XmlWithScript => 7.0,
        ContentTypeSecurityIssue::SvgWithScript => 7.5,
        ContentTypeSecurityIssue::CsvInjection => 6.0,
        ContentTypeSecurityIssue::TextPlainWithHtml => 4.5,
        ContentTypeSecurityIssue::MultipartBoundaryExposed => 3.0,
        ContentTypeSecurityIssue::CharsetMismatch => 3.5,
        ContentTypeSecurityIssue::ContentTypeDoubleEncoded => 5.0,
        ContentTypeSecurityIssue::InconsistentMimeType => 4.0,
    }
}

pub fn content_type_security_to_operations(
    issues: &[ContentTypeSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            let severity = content_type_security_severity(issue);
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                severity,
                0.5,
            )
        })
        .collect()
}

fn looks_like_html(body: &str) -> bool {
    let trimmed = body.trim();
    trimmed.starts_with("<!DOCTYPE html")
        || trimmed.starts_with("<html")
        || trimmed.starts_with("<HTML")
        || contains_html_tags(body)
}

fn contains_html_tags(body: &str) -> bool {
    let html_tags = [
        "<html", "<head", "<body", "<div", "<span", "<script", "<style", "<img", "<a ", "<form",
        "<input", "<button",
    ];
    let lower = body.to_ascii_lowercase();
    html_tags.iter().any(|tag| lower.contains(tag))
}

fn starts_with_html(body: &str) -> bool {
    let trimmed = body.trim();
    trimmed.starts_with("<!DOCTYPE") || trimmed.starts_with("<html") || trimmed.starts_with("<HTML")
}

fn contains_script_tag(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("<script") || lower.contains("javascript:")
}

fn has_csv_formula(body: &str) -> bool {
    let lines: Vec<&str> = body.lines().take(10).collect();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.starts_with('=')
            || trimmed.starts_with('+')
            || trimmed.starts_with('-')
            || trimmed.starts_with('@')
        {
            return true;
        }
    }
    false
}

fn extract_boundary(content_type: &str) -> Option<String> {
    if let Some(idx) = content_type.find("boundary=") {
        let boundary_str = &content_type[idx + 9..];
        let boundary = boundary_str
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"');
        if !boundary.is_empty() {
            return Some(boundary.to_string());
        }
    }
    None
}

fn extract_charset(content_type: &str) -> Option<String> {
    if let Some(idx) = content_type.find("charset=") {
        let charset_str = &content_type[idx + 8..];
        let charset = charset_str
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_ascii_lowercase();
        if !charset.is_empty() {
            return Some(charset);
        }
    }
    None
}

fn has_charset_mismatch(declared_charset: &str, body: &str) -> bool {
    // Check BOM
    if body.starts_with("\u{FEFF}") && !declared_charset.contains("utf") {
        return true;
    }

    // Check meta charset in HTML
    if body.contains("<meta") {
        let lower = body.to_ascii_lowercase();
        if let Some(meta_start) = lower.find("<meta")
            && let Some(meta_end) = lower[meta_start..].find('>')
        {
            let meta_tag = &lower[meta_start..meta_start + meta_end];
            if meta_tag.contains("charset")
                && let Some(cs_idx) = meta_tag.find("charset")
            {
                let after_charset = &meta_tag[cs_idx + 7..].trim_start();
                if let Some(equals_idx) = after_charset.find('=') {
                    let after_equals = after_charset[equals_idx + 1..].trim_start();
                    let meta_charset = after_equals
                        .trim_start_matches('"')
                        .trim_start_matches('\'')
                        .split('"')
                        .next()
                        .unwrap_or("")
                        .split('\'')
                        .next()
                        .unwrap_or("")
                        .split(|c: char| c.is_whitespace() || c == '>')
                        .next()
                        .unwrap_or("")
                        .trim();
                    if !meta_charset.is_empty() && !declared_charset.contains(meta_charset) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

fn is_mime_type_inconsistent(content_type: &str, body: &str) -> bool {
    let trimmed = body.trim();

    if content_type.contains("application/json")
        && !trimmed.starts_with('{')
        && !trimmed.starts_with('[')
    {
        return true;
    }

    if content_type.contains("text/html") && !looks_like_html(body) {
        return true;
    }

    if (content_type.contains("application/xml") || content_type.contains("text/xml"))
        && !trimmed.starts_with("<?xml")
        && !trimmed.starts_with('<')
    {
        return true;
    }

    false
}
