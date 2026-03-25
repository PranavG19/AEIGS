use super::param_pollution::*;

#[test]
fn generates_at_least_five_patterns() {
    let patterns = all_patterns();
    assert!(
        patterns.len() >= 5,
        "expected ≥5 pollution patterns, got {}",
        patterns.len()
    );
}

#[test]
fn all_eight_patterns_present() {
    let patterns = all_patterns();
    assert_eq!(patterns.len(), 8);
    assert!(patterns.contains(&PollutionPattern::DuplicateQueryParam));
    assert!(patterns.contains(&PollutionPattern::ArrayNotation));
    assert!(patterns.contains(&PollutionPattern::UrlBodyCollision));
    assert!(patterns.contains(&PollutionPattern::SemicolonDelimiter));
    assert!(patterns.contains(&PollutionPattern::MixedEncoding));
    assert!(patterns.contains(&PollutionPattern::ContentTypeMismatch));
    assert!(patterns.contains(&PollutionPattern::WafBypass));
    assert!(patterns.contains(&PollutionPattern::JsonDuplicateKey));
}

#[test]
fn generate_payloads_returns_nonempty() {
    let payloads = generate_hpp_payloads("search", None);
    assert!(!payloads.is_empty());
}

#[test]
fn generate_payloads_covers_all_patterns() {
    let payloads = generate_hpp_payloads("q", None);
    let patterns: Vec<PollutionPattern> = payloads.iter().map(|p| p.pattern).collect();
    for expected in all_patterns() {
        assert!(patterns.contains(&expected), "missing pattern: {expected}");
    }
}

#[test]
fn duplicate_query_contains_both_canaries() {
    let payloads = generate_hpp_payloads("id", None);
    let dup = payloads
        .iter()
        .find(|p| p.pattern == PollutionPattern::DuplicateQueryParam)
        .unwrap();
    assert!(dup.query_string.contains("AEGIS_FIRST_7f3a"));
    assert!(dup.query_string.contains("AEGIS_LAST_9b2e"));
    assert!(dup.body.is_none());
}

#[test]
fn array_notation_uses_brackets() {
    let payloads = generate_hpp_payloads("color", None);
    let arr = payloads
        .iter()
        .find(|p| p.pattern == PollutionPattern::ArrayNotation)
        .unwrap();
    assert!(arr.query_string.contains("color[]="));
}

#[test]
fn url_body_collision_has_both_locations() {
    let payloads = generate_hpp_payloads("token", None);
    let ub = payloads
        .iter()
        .find(|p| p.pattern == PollutionPattern::UrlBodyCollision)
        .unwrap();
    assert!(ub.query_string.contains("token="));
    assert!(ub.body.is_some());
    assert!(ub.body.as_ref().unwrap().contains("token="));
    assert_eq!(
        ub.content_type.as_deref(),
        Some("application/x-www-form-urlencoded")
    );
}

#[test]
fn semicolon_delimiter_format() {
    let payloads = generate_hpp_payloads("lang", None);
    let semi = payloads
        .iter()
        .find(|p| p.pattern == PollutionPattern::SemicolonDelimiter)
        .unwrap();
    assert!(semi.query_string.contains(';'));
    assert!(semi.query_string.starts_with("lang="));
}

#[test]
fn mixed_encoding_payload() {
    let payloads = generate_hpp_payloads("name", None);
    let mixed = payloads
        .iter()
        .find(|p| p.pattern == PollutionPattern::MixedEncoding)
        .unwrap();
    assert!(mixed.query_string.contains("name="));
}

#[test]
fn content_type_mismatch_is_multipart() {
    let payloads = generate_hpp_payloads("file", None);
    let ct = payloads
        .iter()
        .find(|p| p.pattern == PollutionPattern::ContentTypeMismatch)
        .unwrap();
    assert!(
        ct.content_type
            .as_ref()
            .unwrap()
            .starts_with("multipart/form-data")
    );
    assert!(ct.body.as_ref().unwrap().contains("Content-Disposition"));
}

#[test]
fn json_duplicate_key_has_json_body() {
    let payloads = generate_hpp_payloads("user", Some("<img src=x onerror=alert(1)>"));
    let json = payloads
        .iter()
        .find(|p| p.pattern == PollutionPattern::JsonDuplicateKey)
        .unwrap();
    assert_eq!(json.content_type.as_deref(), Some("application/json"));
    let body = json.body.as_ref().unwrap();
    assert!(body.contains("safe_value"));
    assert!(body.contains("alert(1)"));
}

#[test]
fn waf_bypass_generates_three_variants() {
    let payloads = generate_waf_bypass_payloads("q", "<script>alert(1)</script>");
    assert_eq!(payloads.len(), 3);
    for p in &payloads {
        assert_eq!(p.pattern, PollutionPattern::WafBypass);
    }
}

#[test]
fn waf_bypass_first_variant_benign_then_malicious() {
    let payloads = generate_waf_bypass_payloads("input", "' OR 1=1--");
    let first = &payloads[0];
    assert!(
        first
            .query_string
            .starts_with("input=safe_normal_value&input=")
    );
    assert!(first.body.is_none());
}

#[test]
fn waf_bypass_url_vs_body_variants() {
    let payloads = generate_waf_bypass_payloads("cmd", "| cat /etc/passwd");
    let url_mal = &payloads[1];
    assert!(url_mal.body.is_some());
    assert!(url_mal.body.as_ref().unwrap().contains("safe_normal_value"));

    let body_mal = &payloads[2];
    assert!(body_mal.query_string.contains("safe_normal_value"));
    assert!(body_mal.body.is_some());
}

#[test]
fn detect_precedence_first() {
    let body = "Result: AEGIS_FIRST_7f3a";
    assert_eq!(detect_precedence(body), ParamPrecedence::First);
}

#[test]
fn detect_precedence_last() {
    let body = "Result: AEGIS_LAST_9b2e";
    assert_eq!(detect_precedence(body), ParamPrecedence::Last);
}

#[test]
fn detect_precedence_concatenated() {
    let body = "Result: AEGIS_FIRST_7f3a,AEGIS_LAST_9b2e";
    assert_eq!(detect_precedence(body), ParamPrecedence::Concatenated);
}

#[test]
fn detect_precedence_concatenated_with_space() {
    let body = "Result: AEGIS_FIRST_7f3a, AEGIS_LAST_9b2e";
    assert_eq!(detect_precedence(body), ParamPrecedence::Concatenated);
}

#[test]
fn detect_precedence_array() {
    let body = "Values: [AEGIS_FIRST_7f3a, AEGIS_LAST_9b2e]";
    assert_eq!(detect_precedence(body), ParamPrecedence::Array);
}

#[test]
fn detect_precedence_unknown() {
    let body = "No parameters reflected here.";
    assert_eq!(detect_precedence(body), ParamPrecedence::Unknown);
}

#[test]
fn fingerprint_php() {
    let fw = fingerprint_framework(ParamPrecedence::Last, true, false);
    assert_eq!(fw, DetectedFramework::Php);
}

#[test]
fn fingerprint_aspnet() {
    let fw = fingerprint_framework(ParamPrecedence::Concatenated, false, false);
    assert_eq!(fw, DetectedFramework::AspNet);
}

#[test]
fn fingerprint_java_servlet() {
    let fw = fingerprint_framework(ParamPrecedence::Last, false, true);
    assert_eq!(fw, DetectedFramework::JavaServlet);
}

#[test]
fn fingerprint_flask() {
    let fw = fingerprint_framework(ParamPrecedence::First, false, false);
    assert_eq!(fw, DetectedFramework::PythonFlask);
}

#[test]
fn fingerprint_express() {
    let fw = fingerprint_framework(ParamPrecedence::Last, false, false);
    assert_eq!(fw, DetectedFramework::NodeExpress);
}

#[test]
fn fingerprint_ruby_rails() {
    let fw = fingerprint_framework(ParamPrecedence::First, true, false);
    assert_eq!(fw, DetectedFramework::RubyRails);
}

#[test]
fn fingerprint_unknown_fallback() {
    let fw = fingerprint_framework(ParamPrecedence::Unknown, false, false);
    assert_eq!(fw, DetectedFramework::Unknown);
}

#[test]
fn analyze_response_returns_finding_for_reflected_canary() {
    let payload = HppPayload {
        pattern: PollutionPattern::DuplicateQueryParam,
        query_string: "q=AEGIS_FIRST_7f3a&q=AEGIS_LAST_9b2e".to_string(),
        body: None,
        content_type: None,
        description: "test payload".to_string(),
    };
    let finding = analyze_hpp_response(
        "/search",
        "GET",
        &payload,
        "You searched for: AEGIS_LAST_9b2e",
        200,
    );
    assert!(finding.is_some());
    let f = finding.unwrap();
    assert_eq!(f.precedence, ParamPrecedence::Last);
    assert_eq!(f.endpoint, "/search");
    assert_eq!(f.method, "GET");
}

#[test]
fn analyze_response_none_on_server_error() {
    let payload = HppPayload {
        pattern: PollutionPattern::DuplicateQueryParam,
        query_string: "q=AEGIS_FIRST_7f3a&q=AEGIS_LAST_9b2e".to_string(),
        body: None,
        content_type: None,
        description: "test".to_string(),
    };
    let finding = analyze_hpp_response("/err", "GET", &payload, "AEGIS_LAST_9b2e", 500);
    assert!(finding.is_none());
}

#[test]
fn analyze_response_none_when_no_canary_reflected() {
    let payload = HppPayload {
        pattern: PollutionPattern::DuplicateQueryParam,
        query_string: "q=AEGIS_FIRST_7f3a&q=AEGIS_LAST_9b2e".to_string(),
        body: None,
        content_type: None,
        description: "test".to_string(),
    };
    let finding = analyze_hpp_response("/noreflect", "GET", &payload, "nothing here", 200);
    assert!(finding.is_none());
}

#[test]
fn waf_bypass_severity_is_highest() {
    let payload = HppPayload {
        pattern: PollutionPattern::WafBypass,
        query_string: "q=safe&q=evil".to_string(),
        body: None,
        content_type: None,
        description: "waf bypass".to_string(),
    };
    let finding = analyze_hpp_response("/admin", "GET", &payload, "AEGIS_LAST_9b2e reflected", 200);
    assert!(finding.is_some());
    assert!(finding.unwrap().severity >= 8.0);
}

#[test]
fn pattern_display_is_kebab_case() {
    assert_eq!(
        PollutionPattern::DuplicateQueryParam.to_string(),
        "duplicate-query-param"
    );
    assert_eq!(PollutionPattern::WafBypass.to_string(), "waf-bypass");
    assert_eq!(
        PollutionPattern::JsonDuplicateKey.to_string(),
        "json-duplicate-key"
    );
}

#[test]
fn precedence_display() {
    assert_eq!(ParamPrecedence::First.to_string(), "first");
    assert_eq!(ParamPrecedence::Last.to_string(), "last");
    assert_eq!(ParamPrecedence::Concatenated.to_string(), "concatenated");
    assert_eq!(ParamPrecedence::Array.to_string(), "array");
    assert_eq!(ParamPrecedence::Unknown.to_string(), "unknown");
}

#[test]
fn framework_display() {
    assert_eq!(DetectedFramework::Php.to_string(), "PHP");
    assert_eq!(DetectedFramework::AspNet.to_string(), "ASP.NET");
    assert_eq!(
        DetectedFramework::NodeExpress.to_string(),
        "Node.js/Express"
    );
}

#[test]
fn custom_malicious_value_propagates() {
    let payloads = generate_hpp_payloads("input", Some("' UNION SELECT * FROM users--"));
    let waf = payloads
        .iter()
        .find(|p| p.pattern == PollutionPattern::WafBypass)
        .unwrap();
    assert!(
        waf.query_string.contains("UNION") || waf.query_string.contains("%27"),
        "malicious payload not found in WAF bypass"
    );
}

#[test]
fn json_duplicate_key_escapes_special_chars() {
    let payloads = generate_hpp_payloads("key\"with", Some("val\"evil"));
    let json = payloads
        .iter()
        .find(|p| p.pattern == PollutionPattern::JsonDuplicateKey)
        .unwrap();
    let body = json.body.as_ref().unwrap();
    assert!(body.contains("key\\\"with"));
    assert!(body.contains("val\\\"evil"));
}

#[test]
fn url_encode_special_characters() {
    let payloads = generate_hpp_payloads("a b", None);
    let mixed = payloads
        .iter()
        .find(|p| p.pattern == PollutionPattern::MixedEncoding)
        .unwrap();
    assert!(mixed.query_string.contains("a%20b"));
}

#[test]
fn analyze_concatenated_response_detects_aspnet() {
    let payload = HppPayload {
        pattern: PollutionPattern::DuplicateQueryParam,
        query_string: "q=AEGIS_FIRST_7f3a&q=AEGIS_LAST_9b2e".to_string(),
        body: None,
        content_type: None,
        description: "dup query".to_string(),
    };
    let finding = analyze_hpp_response(
        "/api/data",
        "POST",
        &payload,
        "Received: AEGIS_FIRST_7f3a,AEGIS_LAST_9b2e",
        200,
    );
    let f = finding.unwrap();
    assert_eq!(f.precedence, ParamPrecedence::Concatenated);
    assert_eq!(f.detected_framework, DetectedFramework::AspNet);
}
