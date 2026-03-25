use super::dom_clobbering::*;

const HTML_GLOBAL_OVERRIDE: &str = r#"
<div id="config" class="settings">some content</div>
<span id="userData" name="userData">test</span>
"#;

const JS_GLOBAL_OVERRIDE: &str = r#"
var url = config.href + "/api";
fetch(userData.value);
"#;

const HTML_FORM_DOCUMENT_CLOBBER: &str = r#"
<form name="cookie">
    <input type="text" value="hijacked">
</form>
<img name="location" src="x">
<embed name="write" src="x">
"#;

const HTML_ANCHOR_HREF: &str = r#"
<a id="configUrl" href="https://evil.com/config.json">link</a>
<a id="apiEndpoint" href="javascript:alert(1)">api</a>
"#;

const JS_ANCHOR_TARGET: &str = r#"
var endpoint = configUrl.href;
fetch(apiEndpoint.toString());
"#;

const HTML_NESTED_FORM: &str = r#"
<form id="settings">
    <input name="apiKey" value="stolen">
    <input name="secret" value="leaked">
</form>
"#;

const HTML_BUILTIN_SHADOW: &str = r#"
<div id="location">somewhere</div>
<span id="fetch">intercepted</span>
<img id="alert" src="x">
<input id="name" value="clobbered">
"#;

const HTML_CLEAN_NO_CLOBBER: &str = r#"
<div class="container">
    <p>No named elements that could clobber anything</p>
    <span class="label">safe</span>
</div>
"#;

const JS_CLEAN: &str = r#"
var x = document.getElementById("safe");
console.log(x.textContent);
"#;

const HTML_MIXED_ATTACKS: &str = r#"
<a id="config" href="javascript:alert(1)"></a>
<form name="cookie"><input name="domain" value="evil.com"></form>
<div id="location">clobbered</div>
<form id="settings"><input name="apiKey" value="stolen"></form>
"#;

const JS_MIXED: &str = r#"
var url = config.href;
fetch(url);
"#;

#[test]
fn detects_named_element_global_override() {
    let config = DomClobberingConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_dom_clobbering(HTML_GLOBAL_OVERRIDE, JS_GLOBAL_OVERRIDE, &config);

    assert!(
        analysis.named_elements.len() >= 2,
        "should find at least 2 named elements, found {}",
        analysis.named_elements.len()
    );

    let global_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.clobber_type == DomClobberingType::NamedElementGlobalOverride)
        .collect();

    assert!(
        !global_findings.is_empty(),
        "should detect global override clobbering"
    );

    let config_finding = global_findings
        .iter()
        .find(|f| f.clobbered_name == "config");
    assert!(config_finding.is_some(), "should find 'config' clobbered");
}

#[test]
fn detects_form_document_property_clobber() {
    let config = DomClobberingConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_dom_clobbering(HTML_FORM_DOCUMENT_CLOBBER, "", &config);

    let form_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.clobber_type == DomClobberingType::FormDocumentPropertyClobber)
        .collect();

    assert!(
        form_findings.len() >= 2,
        "should detect document.cookie and document.location clobbering, found {}",
        form_findings.len()
    );

    let cookie_finding = form_findings.iter().find(|f| f.clobbered_name == "cookie");
    assert!(
        cookie_finding.is_some(),
        "should find document.cookie clobber"
    );
    assert_eq!(
        cookie_finding.unwrap().severity,
        DomClobberingSeverity::Critical,
        "document.cookie clobber should be critical"
    );
}

#[test]
fn detects_anchor_href_clobber() {
    let config = DomClobberingConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_dom_clobbering(HTML_ANCHOR_HREF, JS_ANCHOR_TARGET, &config);

    let anchor_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.clobber_type == DomClobberingType::AnchorHrefClobber)
        .collect();

    assert!(
        !anchor_findings.is_empty(),
        "should detect anchor href clobbering"
    );

    let has_configurl = anchor_findings
        .iter()
        .any(|f| f.clobbered_name == "configUrl");
    assert!(has_configurl, "should detect configUrl anchor clobber");
}

#[test]
fn detects_nested_element_clobber() {
    let config = DomClobberingConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_dom_clobbering(HTML_NESTED_FORM, "", &config);

    let nested_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.clobber_type == DomClobberingType::NestedElementClobber)
        .collect();

    assert!(
        !nested_findings.is_empty(),
        "should detect nested form→input clobber chain"
    );

    let settings_api = nested_findings
        .iter()
        .find(|f| f.clobbered_name == "settings.apiKey");
    assert!(settings_api.is_some(), "should find settings.apiKey chain");
}

#[test]
fn detects_builtin_api_shadow() {
    let config = DomClobberingConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_dom_clobbering(HTML_BUILTIN_SHADOW, "", &config);

    let shadow_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.clobber_type == DomClobberingType::BuiltinApiShadow)
        .collect();

    assert!(
        shadow_findings.len() >= 3,
        "should detect multiple builtin API shadows, found {}",
        shadow_findings.len()
    );

    let location_shadow = shadow_findings
        .iter()
        .find(|f| f.clobbered_name == "location");
    assert!(location_shadow.is_some(), "should detect location shadow");
    assert_eq!(
        location_shadow.unwrap().severity,
        DomClobberingSeverity::Critical,
        "location shadow should be critical"
    );

    let fetch_shadow = shadow_findings.iter().find(|f| f.clobbered_name == "fetch");
    assert!(fetch_shadow.is_some(), "should detect fetch shadow");
}

#[test]
fn clean_html_produces_no_findings() {
    let config = DomClobberingConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_dom_clobbering(HTML_CLEAN_NO_CLOBBER, JS_CLEAN, &config);

    assert_eq!(
        analysis.findings.len(),
        0,
        "clean HTML should produce no clobbering findings"
    );
}

#[test]
fn generates_payloads_for_target_name() {
    let payloads = generate_clobbering_payloads("config");

    assert!(
        payloads.len() >= 10,
        "should generate at least 10 payload variants"
    );

    let has_img = payloads.iter().any(|p| p.contains("<img"));
    let has_form = payloads.iter().any(|p| p.contains("<form"));
    let has_anchor = payloads.iter().any(|p| p.contains("<a "));
    let has_object = payloads.iter().any(|p| p.contains("<object"));

    assert!(has_img, "payloads should include img variant");
    assert!(has_form, "payloads should include form variant");
    assert!(has_anchor, "payloads should include anchor variant");
    assert!(has_object, "payloads should include object variant");

    for payload in &payloads {
        assert!(
            payload.contains("config"),
            "all payloads should target 'config'"
        );
    }
}

#[test]
fn poc_html_generation() {
    let config = DomClobberingConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_dom_clobbering(HTML_GLOBAL_OVERRIDE, JS_GLOBAL_OVERRIDE, &config);

    let findings_with_poc: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.poc_html.is_some())
        .collect();

    assert!(
        !findings_with_poc.is_empty(),
        "should generate PoC HTML for findings"
    );

    for f in &findings_with_poc {
        let poc = f.poc_html.as_ref().unwrap();
        assert!(poc.contains("<!DOCTYPE html>"), "PoC should be valid HTML");
        assert!(
            poc.contains("<script>"),
            "PoC should include exploitation script"
        );
    }
}

#[test]
fn summary_counts_correct() {
    let config = DomClobberingConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_dom_clobbering(HTML_MIXED_ATTACKS, JS_MIXED, &config);

    assert!(
        analysis.summary.total_findings > 0,
        "mixed attacks should produce findings"
    );
    assert_eq!(
        analysis.summary.total_findings,
        analysis.findings.len(),
        "summary count should match findings vec length"
    );

    let actual_critical = analysis
        .findings
        .iter()
        .filter(|f| f.severity == DomClobberingSeverity::Critical)
        .count();
    assert_eq!(
        analysis.summary.critical_count, actual_critical,
        "summary critical_count should match"
    );

    let actual_high = analysis
        .findings
        .iter()
        .filter(|f| f.severity == DomClobberingSeverity::High)
        .count();
    assert_eq!(
        analysis.summary.high_count, actual_high,
        "summary high_count should match"
    );
}

#[test]
fn findings_sorted_by_severity_descending() {
    let config = DomClobberingConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_dom_clobbering(HTML_MIXED_ATTACKS, JS_MIXED, &config);

    for pair in analysis.findings.windows(2) {
        assert!(
            pair[0].severity >= pair[1].severity,
            "findings should be sorted by severity descending: {:?} came before {:?}",
            pair[0].severity,
            pair[1].severity,
        );
    }
}

#[test]
fn extract_named_elements_parses_attributes() {
    let html = r#"<div id="test1" class="foo"><input name="field1" type="text"><a id="link1" href="http://example.com">x</a>"#;
    let elements = extract_named_elements(html);

    assert!(elements.len() >= 3, "should find 3 named elements");

    let div = elements.iter().find(|e| e.tag == "div");
    assert!(div.is_some());
    assert_eq!(div.unwrap().id.as_deref(), Some("test1"));

    let input = elements.iter().find(|e| e.tag == "input");
    assert!(input.is_some());
    assert_eq!(input.unwrap().name.as_deref(), Some("field1"));

    let anchor = elements.iter().find(|e| e.tag == "a");
    assert!(anchor.is_some());
    assert_eq!(anchor.unwrap().href.as_deref(), Some("http://example.com"));
}

#[test]
fn extract_js_targets_finds_global_property_access() {
    let js = r#"
var url = myConfig.href + "/endpoint";
var val = settings.value;
"#;
    let targets = extract_js_clobber_targets(js);

    let names: Vec<&str> = targets.iter().map(|t| t.variable_name.as_str()).collect();

    assert!(names.contains(&"myConfig"), "should find myConfig target");
    assert!(names.contains(&"settings"), "should find settings target");
}

#[test]
fn disabled_poc_generation() {
    let config = DomClobberingConfig::default()
        .with_target("http://localhost:3000")
        .with_poc(false)
        .with_payloads(false);

    let analysis = analyze_dom_clobbering(HTML_GLOBAL_OVERRIDE, JS_GLOBAL_OVERRIDE, &config);

    for f in &analysis.findings {
        assert!(
            f.poc_html.is_none(),
            "should not generate PoC when disabled"
        );
        assert!(
            f.payload.is_none(),
            "should not generate payloads when disabled"
        );
    }
}

#[test]
fn severity_display_formatting() {
    assert_eq!(format!("{}", DomClobberingSeverity::Critical), "critical");
    assert_eq!(format!("{}", DomClobberingSeverity::High), "high");
    assert_eq!(format!("{}", DomClobberingSeverity::Medium), "medium");
    assert_eq!(format!("{}", DomClobberingSeverity::Low), "low");
    assert_eq!(format!("{}", DomClobberingSeverity::Info), "info");
}

#[test]
fn clobber_type_display_formatting() {
    assert_eq!(
        format!("{}", DomClobberingType::NamedElementGlobalOverride),
        "named-element-global-override"
    );
    assert_eq!(
        format!("{}", DomClobberingType::AnchorHrefClobber),
        "anchor-href-clobber"
    );
    assert_eq!(
        format!("{}", DomClobberingType::FormDocumentPropertyClobber),
        "form-document-property-clobber"
    );
    assert_eq!(
        format!("{}", DomClobberingType::NestedElementClobber),
        "nested-element-clobber"
    );
    assert_eq!(
        format!("{}", DomClobberingType::BuiltinApiShadow),
        "builtin-api-shadow"
    );
}

#[test]
fn config_builder_pattern() {
    let config = DomClobberingConfig::default()
        .with_target("http://test.com")
        .with_payloads(false)
        .with_poc(true);

    assert_eq!(config.target_url, "http://test.com");
    assert!(!config.generate_payloads);
    assert!(config.generate_poc);
}
