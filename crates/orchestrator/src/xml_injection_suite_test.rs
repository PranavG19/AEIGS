use super::*;
use std::collections::HashSet;

#[test]
fn generates_all_eight_injection_types() {
    let config = BillionLaughsConfig::default();
    let payloads = generate_all_payloads(&config);
    let types: HashSet<XmlInjectionType> = payloads.iter().map(|p| p.injection_type).collect();

    assert!(types.contains(&XmlInjectionType::XInclude));
    assert!(types.contains(&XmlInjectionType::XmlSchemaPoisoning));
    assert!(types.contains(&XmlInjectionType::XPathInjection));
    assert!(types.contains(&XmlInjectionType::XsltInjection));
    assert!(types.contains(&XmlInjectionType::XmlSignatureWrapping));
    assert!(types.contains(&XmlInjectionType::DtdDenialOfService));
    assert!(types.contains(&XmlInjectionType::NamespaceConfusion));
    assert!(types.contains(&XmlInjectionType::SoapInjection));
    assert_eq!(types.len(), 8);
}

#[test]
fn injection_type_coverage_returns_eight_variants() {
    let coverage = injection_type_coverage();
    assert_eq!(coverage.len(), 8);
    let unique: HashSet<XmlInjectionType> = coverage.into_iter().collect();
    assert_eq!(unique.len(), 8);
}

#[test]
fn xinclude_payloads_contain_xinclude_namespace() {
    let payloads = generate_xinclude_payloads();
    assert!(payloads.len() >= 3);
    for p in &payloads {
        assert_eq!(p.injection_type, XmlInjectionType::XInclude);
        assert!(
            p.payload.contains("xi:include") || p.payload.contains("XInclude"),
            "XInclude payload missing xi:include tag: {}",
            p.payload
        );
    }
}

#[test]
fn xpath_payloads_have_at_least_five_extraction_payloads() {
    let payloads = generate_xpath_payloads();
    assert!(
        payloads.len() >= 5,
        "Expected >=5 XPath payloads, got {}",
        payloads.len()
    );
    let auth_bypass: Vec<_> = payloads
        .iter()
        .filter(|p| p.description.contains("auth bypass"))
        .collect();
    assert!(
        auth_bypass.len() >= 2,
        "Expected >=2 auth bypass payloads, got {}",
        auth_bypass.len()
    );
    let extraction: Vec<_> = payloads
        .iter()
        .filter(|p| p.description.contains("extraction"))
        .collect();
    assert!(
        extraction.len() >= 2,
        "Expected >=2 extraction payloads, got {}",
        extraction.len()
    );
}

#[test]
fn xslt_payloads_cover_java_dotnet_php() {
    let payloads = generate_xslt_payloads();
    assert!(payloads.len() >= 6);

    let java = generate_xslt_java_payloads();
    let dotnet = generate_xslt_dotnet_payloads();
    let php = generate_xslt_php_payloads();

    assert!(!java.is_empty(), "Java XSLT payloads missing");
    assert!(!dotnet.is_empty(), ".NET XSLT payloads missing");
    assert!(!php.is_empty(), "PHP XSLT payloads missing");

    for p in &java {
        assert!(
            p.payload.contains("xalan")
                || p.payload.contains("apache")
                || p.payload.contains("document("),
            "Java payload missing Xalan/document reference"
        );
    }
    for p in &dotnet {
        assert!(
            p.payload.contains("microsoft") || p.payload.contains("unparsed-text"),
            ".NET payload missing MSXSL reference"
        );
    }
    for p in &php {
        assert!(
            p.payload.contains("php.net") || p.payload.contains("php:function"),
            "PHP payload missing PHP reference"
        );
    }
}

#[test]
fn xslt_payloads_for_processor_filters_correctly() {
    let java = xslt_payloads_for_processor(XsltProcessor::Java);
    let dotnet = xslt_payloads_for_processor(XsltProcessor::DotNet);
    let php = xslt_payloads_for_processor(XsltProcessor::Php);

    assert_eq!(java.len(), generate_xslt_java_payloads().len());
    assert_eq!(dotnet.len(), generate_xslt_dotnet_payloads().len());
    assert_eq!(php.len(), generate_xslt_php_payloads().len());
}

#[test]
fn billion_laughs_default_depth_is_five() {
    let config = BillionLaughsConfig::default();
    assert_eq!(config.expansion_depth, 5);
    let payloads = generate_billion_laughs_payloads(&config);
    assert!(payloads.len() >= 2);

    let laughs = &payloads[0];
    assert_eq!(laughs.injection_type, XmlInjectionType::DtdDenialOfService);
    assert!(laughs.payload.contains("<!DOCTYPE"));
    assert!(laughs.payload.contains("<!ENTITY"));
}

#[test]
fn billion_laughs_configurable_depth() {
    let shallow = BillionLaughsConfig::default().with_depth(2);
    let deep = BillionLaughsConfig::default().with_depth(8);

    let shallow_payloads = generate_billion_laughs_payloads(&shallow);
    let deep_payloads = generate_billion_laughs_payloads(&deep);

    let shallow_laughs = &shallow_payloads[0];
    let deep_laughs = &deep_payloads[0];

    assert!(
        deep_laughs.payload.len() > shallow_laughs.payload.len(),
        "Deeper expansion should produce longer payload"
    );
    assert!(deep_laughs.severity >= shallow_laughs.severity);
}

#[test]
fn billion_laughs_depth_clamped_at_ten() {
    let config = BillionLaughsConfig::default().with_depth(255);
    assert_eq!(config.expansion_depth, 10);
}

#[test]
fn billion_laughs_custom_entity_name() {
    let config = BillionLaughsConfig::default().with_entity_name("boom".to_string());
    let payloads = generate_billion_laughs_payloads(&config);
    assert!(payloads[0].payload.contains("boom"));
    assert!(!payloads[0].payload.contains("&lol"));
}

#[test]
fn signature_wrapping_payloads_present() {
    let payloads = generate_signature_wrapping_payloads();
    assert!(payloads.len() >= 2);
    for p in &payloads {
        assert_eq!(p.injection_type, XmlInjectionType::XmlSignatureWrapping);
        assert!(
            p.payload.contains("Signature") || p.payload.contains("Reference"),
            "Sig wrapping payload missing signature elements"
        );
    }
}

#[test]
fn namespace_confusion_payloads_present() {
    let payloads = generate_namespace_confusion_payloads();
    assert!(payloads.len() >= 2);
    for p in &payloads {
        assert_eq!(p.injection_type, XmlInjectionType::NamespaceConfusion);
        assert!(p.payload.contains("xmlns"));
    }
}

#[test]
fn soap_injection_payloads_present() {
    let payloads = generate_soap_injection_payloads();
    assert!(payloads.len() >= 3);
    for p in &payloads {
        assert_eq!(p.injection_type, XmlInjectionType::SoapInjection);
    }
}

#[test]
fn schema_poisoning_payloads_present() {
    let payloads = generate_schema_poisoning_payloads();
    assert!(payloads.len() >= 2);
    for p in &payloads {
        assert_eq!(p.injection_type, XmlInjectionType::XmlSchemaPoisoning);
    }
}

#[test]
fn all_payloads_have_nonzero_severity() {
    let config = BillionLaughsConfig::default();
    let payloads = generate_all_payloads(&config);
    for p in &payloads {
        assert!(
            p.severity > 0.0,
            "Payload has zero severity: {}",
            p.description
        );
        assert!(
            p.severity <= 10.0,
            "Payload severity exceeds 10.0: {}",
            p.description
        );
    }
}

#[test]
fn all_payloads_have_nonempty_description() {
    let config = BillionLaughsConfig::default();
    let payloads = generate_all_payloads(&config);
    for p in &payloads {
        assert!(!p.description.is_empty(), "Empty description for payload");
        assert!(!p.payload.is_empty(), "Empty payload string");
    }
}

#[test]
fn injection_type_display_formatting() {
    assert_eq!(XmlInjectionType::XInclude.to_string(), "xinclude_injection");
    assert_eq!(
        XmlInjectionType::XPathInjection.to_string(),
        "xpath_injection"
    );
    assert_eq!(
        XmlInjectionType::DtdDenialOfService.to_string(),
        "dtd_denial_of_service"
    );
    assert_eq!(
        XmlInjectionType::SoapInjection.to_string(),
        "soap_injection"
    );
}

#[test]
fn xslt_processor_display_formatting() {
    assert_eq!(XsltProcessor::Java.to_string(), "java_xalan");
    assert_eq!(XsltProcessor::DotNet.to_string(), "dotnet");
    assert_eq!(XsltProcessor::Php.to_string(), "php");
}

#[test]
fn injection_type_severity_ranges() {
    for t in injection_type_coverage() {
        let sev = injection_type_severity(t);
        assert!(sev >= 5.0, "{t} severity too low: {sev}");
        assert!(sev <= 10.0, "{t} severity too high: {sev}");
    }
}

#[test]
fn xml_injection_to_operations_produces_entries() {
    let payloads = generate_xinclude_payloads();
    let mut seq = 0u64;
    let ops = xml_injection_to_operations(&payloads, &mut seq);
    assert_eq!(ops.len(), payloads.len());
    assert_eq!(seq, payloads.len() as u64);
}

#[test]
fn detect_xinclude_indicator() {
    let body = r#"root:x:0:0:root:/root:/bin/bash xi:include file:/// leaked"#;
    let detected = detect_xml_injection_indicators(body);
    assert!(detected.contains(&XmlInjectionType::XInclude));
}

#[test]
fn detect_xpath_indicator() {
    let body = "Error in XPath query: //user password field not found admin";
    let detected = detect_xml_injection_indicators(body);
    assert!(detected.contains(&XmlInjectionType::XPathInjection));
}

#[test]
fn detect_xslt_rce_indicator() {
    let body = "xsl:template match exec() runtime output";
    let detected = detect_xml_injection_indicators(body);
    assert!(detected.contains(&XmlInjectionType::XsltInjection));
}

#[test]
fn detect_billion_laughs_indicator() {
    let body = r#"<!ENTITY a "x"> &a;&b;&c;&d;&e;&f;&g; something"#;
    let detected = detect_xml_injection_indicators(body);
    assert!(detected.contains(&XmlInjectionType::DtdDenialOfService));
}

#[test]
fn detect_namespace_rebinding() {
    let body = r#"<root xmlns:sec="http://legit.com"><child xmlns:sec="http://evil.com">override</child></root>"#;
    let detected = detect_xml_injection_indicators(body);
    assert!(detected.contains(&XmlInjectionType::NamespaceConfusion));
}

#[test]
fn detect_soap_injection_indicator() {
    let body = r#"<soap:Envelope><!-- admin </soap:Body> delete"#;
    let detected = detect_xml_injection_indicators(body);
    assert!(detected.contains(&XmlInjectionType::SoapInjection));
}

#[test]
fn detect_signature_wrapping_indicator() {
    let body = r##"<Wrapper><Signature><Reference URI="#a"/></Signature><Object Id="a"/><Object Id="b"/></Wrapper>"##;
    let detected = detect_xml_injection_indicators(body);
    assert!(detected.contains(&XmlInjectionType::XmlSignatureWrapping));
}

#[test]
fn detect_schema_poisoning_indicator() {
    let body = r#"xsi:schemaLocation="http://evil.com/override.xsd" loaded successfully"#;
    let detected = detect_xml_injection_indicators(body);
    assert!(detected.contains(&XmlInjectionType::XmlSchemaPoisoning));
}

#[test]
fn detect_no_indicators_on_clean_body() {
    let body = "This is a normal HTML page with no XML content at all.";
    let detected = detect_xml_injection_indicators(body);
    assert!(detected.is_empty());
}

#[test]
fn severity_for_depth_boundaries() {
    assert_eq!(severity_for_depth(0), 5.0);
    assert_eq!(severity_for_depth(2), 5.0);
    assert_eq!(severity_for_depth(3), 7.0);
    assert_eq!(severity_for_depth(5), 7.0);
    assert_eq!(severity_for_depth(6), 8.0);
    assert_eq!(severity_for_depth(8), 8.0);
    assert_eq!(severity_for_depth(9), 9.0);
    assert_eq!(severity_for_depth(10), 9.0);
}

#[test]
fn total_payload_count_sufficient() {
    let config = BillionLaughsConfig::default();
    let payloads = generate_all_payloads(&config);
    assert!(
        payloads.len() >= 25,
        "Expected >=25 total payloads, got {}",
        payloads.len()
    );
}
