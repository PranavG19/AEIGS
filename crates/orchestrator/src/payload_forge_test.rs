use super::*;
use aegis_protocol::defense_context::DefenseContext;
use aegis_protocol::finding::VulnerabilityClass;

fn no_waf() -> DefenseContext {
    DefenseContext::default()
}

fn with_xss_waf() -> DefenseContext {
    DefenseContext {
        has_waf: true,
        waf_vendor: Some("Cloudflare".to_string()),
        waf_blocked_categories: vec![VulnerabilityClass::CrossSiteScripting],
        rate_limit_rps: None,
        bot_detection_present: false,
        bot_detection_evaded: false,
    }
}

fn with_sqli_waf() -> DefenseContext {
    DefenseContext {
        has_waf: true,
        waf_vendor: Some("ModSecurity".to_string()),
        waf_blocked_categories: vec![VulnerabilityClass::SqlInjection],
        rate_limit_rps: None,
        bot_detection_present: false,
        bot_detection_evaded: false,
    }
}

fn with_waf_all() -> DefenseContext {
    DefenseContext {
        has_waf: true,
        waf_vendor: Some("AWS WAF".to_string()),
        waf_blocked_categories: vec![
            VulnerabilityClass::SqlInjection,
            VulnerabilityClass::CrossSiteScripting,
            VulnerabilityClass::CommandInjection,
        ],
        rate_limit_rps: Some(10.0),
        bot_detection_present: true,
        bot_detection_evaded: false,
    }
}

#[test]
fn url_encode_preserves_safe_chars() {
    assert_eq!(url_encode("hello"), "hello");
    assert_eq!(url_encode("a-b_c.d~e"), "a-b_c.d~e");
}

#[test]
fn url_encode_encodes_special_chars() {
    let encoded = url_encode("' OR 1=1--");
    assert!(encoded.contains("%27"));
    assert!(encoded.contains("%20"));
    assert!(!encoded.contains("'"));
}

#[test]
fn double_url_encode_double_encodes() {
    let double = double_url_encode("'");
    assert_eq!(double, "%2527");
}

#[test]
fn html_entity_encode_encodes_angle_brackets() {
    let encoded = html_entity_encode("<script>");
    assert!(encoded.contains("&#x3c;"));
    assert!(encoded.contains("&#x3e;"));
    assert!(!encoded.contains("<"));
}

#[test]
fn unicode_escape_encodes_alphanumeric() {
    let escaped = unicode_escape("alert");
    assert!(escaped.contains("\\u0061"));
    assert!(escaped.contains("\\u006c"));
}

#[test]
fn case_toggle_alternates() {
    let toggled = case_toggle("script");
    assert_eq!(toggled, "ScRiPt");
}

#[test]
fn sql_comment_insert_breaks_keywords() {
    let commented = sql_comment_insert("UNION SELECT");
    assert!(commented.contains("/**/UNION/**/"));
    assert!(commented.contains("/**/SELECT/**/"));
}

#[test]
fn xss_payloads_no_waf_baseline() {
    let payloads = generate_xss_payloads(PayloadContext::HtmlBody, &no_waf());
    assert!(!payloads.is_empty());
    assert!(payloads
        .iter()
        .all(|p| p.vulnerability_class == VulnerabilityClass::CrossSiteScripting));
    assert!(payloads.iter().any(|p| p.raw.contains("onerror")));
    assert!(payloads.iter().any(|p| p.raw.contains("svg")));
}

#[test]
fn xss_payloads_waf_generates_evasions() {
    let no_waf_count = generate_xss_payloads(PayloadContext::HtmlBody, &no_waf()).len();
    let waf_count = generate_xss_payloads(PayloadContext::HtmlBody, &with_xss_waf()).len();
    assert!(
        waf_count > no_waf_count,
        "WAF should generate more evasion payloads: {} vs {}",
        waf_count,
        no_waf_count,
    );
}

#[test]
fn xss_payloads_waf_includes_encoded_variants() {
    let payloads = generate_xss_payloads(PayloadContext::HtmlBody, &with_xss_waf());
    assert!(payloads.iter().any(|p| !p.encoding_chain.is_empty()));
    assert!(payloads
        .iter()
        .any(|p| p.encoding_chain.contains(&EncodingStep::CaseToggle)));
    assert!(payloads
        .iter()
        .any(|p| p.encoding_chain.contains(&EncodingStep::HtmlEntityEncode)));
    assert!(payloads
        .iter()
        .any(|p| p.encoding_chain.contains(&EncodingStep::DoubleUrlEncode)));
}

#[test]
fn xss_attribute_context() {
    let payloads = generate_xss_payloads(PayloadContext::HtmlAttribute, &no_waf());
    assert!(payloads.iter().any(|p| p.raw.contains("onfocus")));
    assert!(payloads.iter().any(|p| p.raw.starts_with("\"")));
}

#[test]
fn xss_js_string_context() {
    let payloads = generate_xss_payloads(PayloadContext::JavaScriptString, &no_waf());
    assert!(payloads.iter().any(|p| p.raw.contains("alert")));
    assert!(payloads.iter().any(|p| p.raw.starts_with("'")));
}

#[test]
fn sqli_payloads_no_waf() {
    let payloads = generate_sqli_payloads(PayloadContext::SqlString, &no_waf());
    assert!(!payloads.is_empty());
    assert!(payloads
        .iter()
        .all(|p| p.vulnerability_class == VulnerabilityClass::SqlInjection));
    assert!(payloads.iter().any(|p| p.raw.contains("UNION")));
    assert!(payloads.iter().any(|p| p.raw.contains("SLEEP")));
}

#[test]
fn sqli_payloads_waf_generates_evasions() {
    let no_waf_count = generate_sqli_payloads(PayloadContext::SqlString, &no_waf()).len();
    let waf_count = generate_sqli_payloads(PayloadContext::SqlString, &with_sqli_waf()).len();
    assert!(waf_count > no_waf_count);
}

#[test]
fn sqli_payloads_waf_includes_mysql_bypass() {
    let payloads = generate_sqli_payloads(PayloadContext::SqlString, &with_sqli_waf());
    assert!(payloads.iter().any(|p| p.raw.contains("/*!50000")));
}

#[test]
fn sqli_numeric_context() {
    let payloads = generate_sqli_payloads(PayloadContext::SqlNumeric, &no_waf());
    assert!(payloads.iter().any(|p| p.raw.starts_with("1")));
}

#[test]
fn ssti_payloads_cover_engines() {
    let payloads = generate_ssti_payloads();
    assert!(!payloads.is_empty());

    let raws: Vec<&str> = payloads.iter().map(|p| p.raw.as_str()).collect();
    assert!(raws.iter().any(|r| r.contains("{{7*7}}")));
    assert!(raws.iter().any(|r| r.contains("${7*7}")));
    assert!(raws.iter().any(|r| r.contains("<%= 7*7 %>")));
    assert!(raws.iter().any(|r| r.contains("config.__class__")));
    assert!(raws.iter().any(|r| r.contains("freemarker")));
    assert!(raws.iter().any(|r| r.contains("process.mainModule")));
}

#[test]
fn cmdi_payloads_baseline() {
    let payloads = generate_cmdi_payloads(&no_waf());
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.raw.contains("; id")));
    assert!(payloads.iter().any(|p| p.raw.contains("$(id)")));
    assert!(payloads.iter().any(|p| p.raw.contains("sleep")));
}

#[test]
fn cmdi_payloads_waf_adds_ifs_bypass() {
    let base_count = generate_cmdi_payloads(&no_waf()).len();
    let waf_payloads = generate_cmdi_payloads(&with_waf_all());
    assert!(waf_payloads.len() > base_count);
    assert!(waf_payloads.iter().any(|p| p.raw.contains("${IFS}")));
    assert!(waf_payloads.iter().any(|p| p.raw.contains("printf")));
}

#[test]
fn ssrf_payloads_cover_cloud_metadata() {
    let payloads = generate_ssrf_payloads();
    assert!(payloads.iter().any(|p| p.raw.contains("169.254.169.254")));
    assert!(payloads.iter().any(|p| p.raw.contains("metadata.google")));
    assert!(payloads.iter().any(|p| p.raw.contains("file://")));
    assert!(payloads.iter().any(|p| p.raw.contains("gopher://")));
}

#[test]
fn ssrf_payloads_include_ip_obfuscation() {
    let payloads = generate_ssrf_payloads();
    assert!(payloads.iter().any(|p| p.raw.contains("0x7f")));
    assert!(payloads.iter().any(|p| p.raw.contains("0177")));
    assert!(payloads.iter().any(|p| p.raw.contains("[::1]")));
    assert!(payloads.iter().any(|p| p.raw.contains("2130706433")));
}

#[test]
fn forge_payloads_dispatches_by_class() {
    let xss = forge_payloads(
        VulnerabilityClass::CrossSiteScripting,
        PayloadContext::HtmlBody,
        &no_waf(),
    );
    assert!(!xss.is_empty());
    assert!(xss
        .iter()
        .all(|p| p.vulnerability_class == VulnerabilityClass::CrossSiteScripting));

    let sqli = forge_payloads(
        VulnerabilityClass::SqlInjection,
        PayloadContext::SqlString,
        &no_waf(),
    );
    assert!(!sqli.is_empty());

    let unknown = forge_payloads(
        VulnerabilityClass::Clickjacking,
        PayloadContext::HtmlBody,
        &no_waf(),
    );
    assert!(unknown.is_empty());
}

#[test]
fn apply_encoding_chain_url() {
    let result = apply_encoding_chain("' OR 1=1", &[EncodingStep::UrlEncode]);
    assert!(result.contains("%27"));
    assert!(!result.contains("'"));
}

#[test]
fn apply_encoding_chain_double_url() {
    let result = apply_encoding_chain("'", &[EncodingStep::DoubleUrlEncode]);
    assert_eq!(result, "%2527");
}

#[test]
fn apply_encoding_chain_multiple_steps() {
    let result = apply_encoding_chain(
        "<script>",
        &[EncodingStep::HtmlEntityEncode, EncodingStep::UrlEncode],
    );
    assert!(!result.contains("<"));
    assert!(result.contains("%"));
}

#[test]
fn apply_encoding_chain_case_toggle() {
    let result = apply_encoding_chain("alert", &[EncodingStep::CaseToggle]);
    assert_eq!(result, "AlErT");
}

#[test]
fn apply_encoding_chain_whitespace_sub() {
    let result = apply_encoding_chain("a b c", &[EncodingStep::WhitespaceSubstitution]);
    assert_eq!(result, "a\tb\tc");
}

#[test]
fn apply_encoding_chain_null_byte() {
    let result = apply_encoding_chain("test", &[EncodingStep::NullByteInject]);
    assert!(result.ends_with('\0'));
}

#[test]
fn apply_encoding_chain_base64() {
    let result = apply_encoding_chain("test", &[EncodingStep::Base64]);
    assert_eq!(result, "dGVzdA==");
}

#[test]
fn payload_context_display() {
    assert_eq!(format!("{}", PayloadContext::HtmlBody), "html_body");
    assert_eq!(format!("{}", PayloadContext::SqlString), "sql_string");
    assert_eq!(
        format!("{}", PayloadContext::CommandArgument),
        "cmd_argument"
    );
}

#[test]
fn encoding_step_display() {
    assert_eq!(format!("{}", EncodingStep::UrlEncode), "url_encode");
    assert_eq!(
        format!("{}", EncodingStep::DoubleUrlEncode),
        "double_url_encode"
    );
    assert_eq!(format!("{}", EncodingStep::Base64), "base64");
}

#[test]
fn bypass_target_set_when_waf_present() {
    let payloads = generate_xss_payloads(PayloadContext::HtmlBody, &with_xss_waf());
    let evasion_payloads: Vec<&ForgedPayload> = payloads
        .iter()
        .filter(|p| !p.encoding_chain.is_empty())
        .collect();

    assert!(!evasion_payloads.is_empty());
    for p in &evasion_payloads {
        assert_eq!(
            p.bypass_target.as_deref(),
            Some("Cloudflare"),
            "evasion payload should target Cloudflare WAF",
        );
    }
}

#[test]
fn xss_js_template_context() {
    let payloads = generate_xss_payloads(PayloadContext::JavaScriptTemplate, &no_waf());
    assert!(payloads.iter().any(|p| p.raw.contains("${alert")));
}

#[test]
fn forged_payload_has_all_fields() {
    let payloads = forge_payloads(
        VulnerabilityClass::ServerSideRequestForgery,
        PayloadContext::UrlParameter,
        &no_waf(),
    );
    for p in &payloads {
        assert!(!p.raw.is_empty());
        assert_eq!(
            p.vulnerability_class,
            VulnerabilityClass::ServerSideRequestForgery
        );
        assert!(!p.evasion_notes.is_empty());
    }
}
