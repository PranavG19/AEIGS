use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum XxeIssue {
    DtdDeclaration,
    ExternalEntityRef,
    ParameterEntity,
    XmlProcessingInstruction,
    SoapEndpoint,
    XsltProcessing,
    XmlContentType,
    SvgUpload,
}

impl std::fmt::Display for XxeIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DtdDeclaration => write!(f, "dtd_declaration"),
            Self::ExternalEntityRef => write!(f, "external_entity_ref"),
            Self::ParameterEntity => write!(f, "parameter_entity"),
            Self::XmlProcessingInstruction => write!(f, "xml_processing_instruction"),
            Self::SoapEndpoint => write!(f, "soap_endpoint"),
            Self::XsltProcessing => write!(f, "xslt_processing"),
            Self::XmlContentType => write!(f, "xml_content_type"),
            Self::SvgUpload => write!(f, "svg_upload"),
        }
    }
}

pub fn scan_xxe(target: &str) -> Vec<XxeIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_xxe_indicators(&body)
}

pub fn analyze_xxe_indicators(body: &str) -> Vec<XxeIssue> {
    let lower = body.to_ascii_lowercase();
    let mut issues = Vec::new();

    if lower.contains("<!doctype") && (lower.contains("system") || lower.contains("public")) {
        issues.push(XxeIssue::DtdDeclaration);
    }

    if lower.contains("<!entity") && (lower.contains("system") || lower.contains("public")) {
        issues.push(XxeIssue::ExternalEntityRef);
    }

    if lower.contains('%') && has_parameter_entity_pattern(&lower) {
        issues.push(XxeIssue::ParameterEntity);
    }

    if lower.contains("<?xml-stylesheet") || has_processing_instruction(&lower) {
        issues.push(XxeIssue::XmlProcessingInstruction);
    }

    if lower.contains("<soap:envelope") || lower.contains("wsdl") || lower.contains("<soap:body") {
        issues.push(XxeIssue::SoapEndpoint);
    }

    if lower.contains("xsl:")
        || lower.contains("xslt")
        || (lower.contains("stylesheet") && lower.contains("xml"))
    {
        issues.push(XxeIssue::XsltProcessing);
    }

    if lower.contains("application/xml") || lower.contains("text/xml") {
        issues.push(XxeIssue::XmlContentType);
    }

    if has_svg_upload_pattern(&lower) {
        issues.push(XxeIssue::SvgUpload);
    }

    issues
}

fn has_parameter_entity_pattern(lower: &str) -> bool {
    for (i, _) in lower.match_indices('%') {
        let rest = &lower[i + 1..];
        let word_end = rest
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(rest.len());
        if word_end > 0 && rest[word_end..].starts_with(';') {
            return true;
        }
    }
    false
}

fn has_processing_instruction(lower: &str) -> bool {
    let mut pos = 0;
    while let Some(idx) = lower[pos..].find("<?") {
        let abs = pos + idx;
        let after = &lower[abs + 2..];
        if !after.starts_with("xml ") && !after.starts_with("xml?") && after.contains("?>") {
            return true;
        }
        pos = abs + 2;
    }
    false
}

fn has_svg_upload_pattern(lower: &str) -> bool {
    if lower.contains("accept=") && lower.contains("image/svg") {
        return true;
    }
    if lower.contains("accept=") && lower.contains(".svg") {
        return true;
    }
    if (lower.contains("upload") || lower.contains("file")) && lower.contains(".svg") {
        return true;
    }
    false
}

pub fn xxe_severity(issue: &XxeIssue) -> f64 {
    match issue {
        XxeIssue::ExternalEntityRef => 9.0,
        XxeIssue::ParameterEntity => 8.5,
        XxeIssue::DtdDeclaration => 8.0,
        XxeIssue::XsltProcessing => 7.5,
        XxeIssue::SoapEndpoint => 7.0,
        XxeIssue::SvgUpload => 6.5,
        XxeIssue::XmlContentType => 6.0,
        XxeIssue::XmlProcessingInstruction => 5.5,
    }
}

pub fn xxe_to_operations(issues: &[XxeIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::XmlExternalEntity,
                xxe_severity(issue),
                0.7,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum XxeSecurityIssue {
    XxeExfiltration,
    XxeSsrf,
    XxeRce,
    XxeFileRead,
    XxeDos,
    XxeBlind,
    UnsafeXmlParser,
    XmlInputUnvalidated,
    XxeInJsonApi,
    SoapInjection,
}

impl std::fmt::Display for XxeSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::XxeExfiltration => write!(f, "xxe_exfiltration"),
            Self::XxeSsrf => write!(f, "xxe_ssrf"),
            Self::XxeRce => write!(f, "xxe_rce"),
            Self::XxeFileRead => write!(f, "xxe_file_read"),
            Self::XxeDos => write!(f, "xxe_dos"),
            Self::XxeBlind => write!(f, "xxe_blind"),
            Self::UnsafeXmlParser => write!(f, "unsafe_xml_parser"),
            Self::XmlInputUnvalidated => write!(f, "xml_input_unvalidated"),
            Self::XxeInJsonApi => write!(f, "xxe_in_json_api"),
            Self::SoapInjection => write!(f, "soap_injection"),
        }
    }
}

pub fn analyze_xxe_security(body: &str) -> Vec<XxeSecurityIssue> {
    let lower = body.to_ascii_lowercase();
    if !lower.contains("xml")
        && !lower.contains("<!entity")
        && !lower.contains("<!doctype")
        && !lower.contains("soap")
        && !lower.contains("xsl")
    {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if (lower.contains("<!entity") || lower.contains("<!doctype"))
        && (lower.contains("fetch(") || lower.contains("xmlhttprequest"))
    {
        issues.push(XxeSecurityIssue::XxeExfiltration);
    }

    if lower.contains("xml")
        && (lower.contains("localhost")
            || lower.contains("127.0.0.1")
            || lower.contains("169.254.169.254"))
    {
        issues.push(XxeSecurityIssue::XxeSsrf);
    }

    if lower.contains("expect://") || lower.contains("php://") {
        issues.push(XxeSecurityIssue::XxeRce);
    }

    if lower.contains("file://")
        && (lower.contains("xml") || lower.contains("<!entity") || lower.contains("<!doctype"))
    {
        issues.push(XxeSecurityIssue::XxeFileRead);
    }

    if has_dos_pattern(&lower) {
        issues.push(XxeSecurityIssue::XxeDos);
    }

    if has_blind_xxe_pattern(&lower) {
        issues.push(XxeSecurityIssue::XxeBlind);
    }

    if lower.contains("disable_external_entities=false")
        || lower.contains("feature_external_entities")
        || lower.contains("resolve_externals")
        || lower.contains("external-general-entities")
    {
        issues.push(XxeSecurityIssue::UnsafeXmlParser);
    }

    if lower.contains("xml")
        && (lower.contains("input") || lower.contains("parse") || lower.contains("load"))
        && !lower.contains("schema")
        && !lower.contains("validate")
        && !lower.contains("sanitize")
    {
        issues.push(XxeSecurityIssue::XmlInputUnvalidated);
    }

    if lower.contains("application/json")
        && (lower.contains("application/xml") || lower.contains("text/xml"))
    {
        issues.push(XxeSecurityIssue::XxeInJsonApi);
    }

    if (lower.contains("<soap:") || lower.contains("wsdl"))
        && (lower.contains("user") || lower.contains("input") || lower.contains("param"))
    {
        issues.push(XxeSecurityIssue::SoapInjection);
    }

    issues
}

fn has_dos_pattern(lower: &str) -> bool {
    if lower.contains("&lol;") || lower.contains("&lol1;") || lower.contains("&lol2;") {
        return true;
    }
    let entity_count = lower.matches("<!entity").count();
    if entity_count >= 3 && lower.contains("&") {
        return true;
    }
    false
}

fn has_blind_xxe_pattern(lower: &str) -> bool {
    if lower.contains("<!entity") && lower.contains("http://") && lower.contains(".dtd") {
        return true;
    }
    if lower.contains("<!entity") && lower.contains("https://") && lower.contains(".dtd") {
        return true;
    }
    if lower.contains("<!doctype") && lower.contains("system") && lower.contains("http") {
        return true;
    }
    false
}

pub fn xxe_security_severity(issue: &XxeSecurityIssue) -> f64 {
    match issue {
        XxeSecurityIssue::XxeRce => 9.5,
        XxeSecurityIssue::XxeFileRead => 9.0,
        XxeSecurityIssue::XxeExfiltration => 8.5,
        XxeSecurityIssue::XxeSsrf => 8.5,
        XxeSecurityIssue::XxeBlind => 8.0,
        XxeSecurityIssue::XxeDos => 7.5,
        XxeSecurityIssue::UnsafeXmlParser => 7.0,
        XxeSecurityIssue::SoapInjection => 7.0,
        XxeSecurityIssue::XxeInJsonApi => 6.5,
        XxeSecurityIssue::XmlInputUnvalidated => 6.0,
    }
}

pub fn xxe_security_to_operations(
    issues: &[XxeSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::XmlExternalEntity,
                xxe_security_severity(issue),
                0.6,
            )
        })
        .collect()
}

#[cfg(test)]
#[path = "xxe_scanner_test.rs"]
mod xxe_scanner_test;
