use super::*;

#[test]
fn default_config_has_sensible_values() {
    let config = ResponseInjectionConfig::default();
    assert_eq!(config.target_header, "X-Injected");
    assert_eq!(config.attacker_domain, "evil.com");
    assert!(config.include_encoding_variants);
}

#[test]
fn config_builder_overrides_target_header() {
    let config = ResponseInjectionConfig::default().with_target_header("X-Custom");
    assert_eq!(config.target_header, "X-Custom");
}

#[test]
fn config_builder_overrides_attacker_domain() {
    let config = ResponseInjectionConfig::default().with_attacker_domain("attacker.io");
    assert_eq!(config.attacker_domain, "attacker.io");
}

#[test]
fn config_builder_disables_encoding_variants() {
    let config = ResponseInjectionConfig::default().with_encoding_variants(false);
    assert!(!config.include_encoding_variants);
}

#[test]
fn generates_at_least_eight_technique_payloads() {
    let config = ResponseInjectionConfig::default().with_encoding_variants(false);
    let payloads = generate_response_injection_payloads(&config);
    assert!(
        payloads.len() >= 8,
        "expected >=8 payloads without encoding variants, got {}",
        payloads.len()
    );
}

#[test]
fn generates_at_least_five_crlf_encoding_variants() {
    assert!(
        encoding_variant_count() >= 5,
        "expected >=5 CRLF encoding variants, got {}",
        encoding_variant_count()
    );
}

#[test]
fn crlf_encoding_all_returns_correct_count() {
    let all = CrlfEncoding::all();
    assert_eq!(all.len(), 7);
}

#[test]
fn every_payload_has_detection_signature() {
    let config = ResponseInjectionConfig::default();
    let payloads = generate_response_injection_payloads(&config);
    for payload in &payloads {
        assert!(
            !payload.detection.pattern.is_empty(),
            "payload for {:?} has empty detection pattern",
            payload.technique
        );
        assert!(
            !payload.detection.description.is_empty(),
            "payload for {:?} has empty detection description",
            payload.technique
        );
    }
}

#[test]
fn every_payload_has_nonempty_description() {
    let config = ResponseInjectionConfig::default();
    let payloads = generate_response_injection_payloads(&config);
    for payload in &payloads {
        assert!(!payload.description.is_empty());
    }
}

#[test]
fn encoding_variants_included_by_default() {
    let config = ResponseInjectionConfig::default();
    let payloads = generate_response_injection_payloads(&config);
    let variant_count = payloads
        .iter()
        .filter(|p| p.technique == ResponseInjectionTechnique::EncodingVariant)
        .count();
    assert!(
        variant_count >= 5,
        "expected >=5 encoding variant payloads, got {variant_count}"
    );
}

#[test]
fn encoding_variants_excluded_when_disabled() {
    let config = ResponseInjectionConfig::default().with_encoding_variants(false);
    let payloads = generate_response_injection_payloads(&config);
    let variant_count = payloads
        .iter()
        .filter(|p| p.technique == ResponseInjectionTechnique::EncodingVariant)
        .count();
    assert_eq!(variant_count, 0);
}

#[test]
fn crlf_injection_payloads_contain_crlf_sequence() {
    let config = ResponseInjectionConfig::default();
    let payloads = generate_response_injection_payloads(&config);
    let crlf_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.technique == ResponseInjectionTechnique::CrlfInjection)
        .collect();
    assert!(crlf_payloads.len() >= 2);
    for p in &crlf_payloads {
        assert!(
            p.payload.contains("%0d%0a")
                || p.payload.contains("%0D%0A")
                || p.payload.contains("\r\n"),
            "CRLF payload missing CRLF sequence: {}",
            p.payload
        );
    }
}

#[test]
fn response_splitting_payloads_contain_double_crlf() {
    let config = ResponseInjectionConfig::default();
    let payloads = generate_response_injection_payloads(&config);
    let splitting: Vec<_> = payloads
        .iter()
        .filter(|p| p.technique == ResponseInjectionTechnique::ResponseSplitting)
        .collect();
    assert!(splitting.len() >= 2);
    for p in &splitting {
        let double_crlf = format!(
            "{}{}",
            CrlfEncoding::UrlEncodedLower.sequence(),
            CrlfEncoding::UrlEncodedLower.sequence()
        );
        assert!(
            p.payload.contains(&double_crlf),
            "Response splitting payload should contain double CRLF: {}",
            p.payload
        );
    }
}

#[test]
fn set_cookie_injection_payloads_target_set_cookie_header() {
    let config = ResponseInjectionConfig::default();
    let payloads = generate_response_injection_payloads(&config);
    let cookie_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.technique == ResponseInjectionTechnique::SetCookieInjection)
        .collect();
    assert!(cookie_payloads.len() >= 2);
    for p in &cookie_payloads {
        assert!(p.payload.contains("Set-Cookie:"));
    }
}

#[test]
fn location_injection_payloads_contain_location_header() {
    let config = ResponseInjectionConfig::default();
    let payloads = generate_response_injection_payloads(&config);
    let location_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.technique == ResponseInjectionTechnique::LocationInjection)
        .collect();
    assert!(location_payloads.len() >= 2);
    for p in &location_payloads {
        assert!(p.payload.contains("Location:"));
    }
}

#[test]
fn content_type_injection_forces_text_html_or_xhtml() {
    let config = ResponseInjectionConfig::default();
    let payloads = generate_response_injection_payloads(&config);
    let ct_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.technique == ResponseInjectionTechnique::ContentTypeInjection)
        .collect();
    assert!(ct_payloads.len() >= 2);
    for p in &ct_payloads {
        assert!(
            p.payload.contains("text/html") || p.payload.contains("xhtml+xml"),
            "Content-Type payload should force HTML type: {}",
            p.payload
        );
    }
}

#[test]
fn cache_poisoning_payloads_inject_cache_control() {
    let config = ResponseInjectionConfig::default();
    let payloads = generate_response_injection_payloads(&config);
    let cache_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.technique == ResponseInjectionTechnique::CachePoisoning)
        .collect();
    assert!(cache_payloads.len() >= 2);
    for p in &cache_payloads {
        assert!(p.payload.contains("Cache-Control:"));
    }
}

#[test]
fn cors_injection_payloads_contain_acao_header() {
    let config = ResponseInjectionConfig::default();
    let payloads = generate_response_injection_payloads(&config);
    let cors_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.technique == ResponseInjectionTechnique::CorsHeaderInjection)
        .collect();
    assert!(cors_payloads.len() >= 2);
    for p in &cors_payloads {
        assert!(p.payload.contains("Access-Control-Allow-Origin:"));
    }
}

#[test]
fn xss_via_header_payloads_contain_script_or_link() {
    let config = ResponseInjectionConfig::default();
    let payloads = generate_response_injection_payloads(&config);
    let xss_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.technique == ResponseInjectionTechnique::XssViaResponseHeader)
        .collect();
    assert!(xss_payloads.len() >= 2);
    for p in &xss_payloads {
        assert!(
            p.payload.contains("<script>") || p.payload.contains("Link:"),
            "XSS header payload should contain script or Link: {}",
            p.payload
        );
    }
}

#[test]
fn technique_count_returns_eight() {
    assert_eq!(technique_count(), 8);
}

#[test]
fn all_eight_techniques_represented_in_payloads() {
    let config = ResponseInjectionConfig::default().with_encoding_variants(false);
    let payloads = generate_response_injection_payloads(&config);
    let techniques: std::collections::HashSet<_> = payloads.iter().map(|p| p.technique).collect();

    assert!(techniques.contains(&ResponseInjectionTechnique::CrlfInjection));
    assert!(techniques.contains(&ResponseInjectionTechnique::ResponseSplitting));
    assert!(techniques.contains(&ResponseInjectionTechnique::SetCookieInjection));
    assert!(techniques.contains(&ResponseInjectionTechnique::LocationInjection));
    assert!(techniques.contains(&ResponseInjectionTechnique::ContentTypeInjection));
    assert!(techniques.contains(&ResponseInjectionTechnique::CachePoisoning));
    assert!(techniques.contains(&ResponseInjectionTechnique::CorsHeaderInjection));
    assert!(techniques.contains(&ResponseInjectionTechnique::XssViaResponseHeader));
}

#[test]
fn detect_injection_finds_header_match() {
    let headers = vec![
        ("X-Injected".to_string(), "injected-value".to_string()),
        ("Content-Type".to_string(), "text/plain".to_string()),
    ];
    let signatures = vec![DetectionSignature {
        method: DetectionMethod::ResponseHeaderPresent,
        pattern: "X-Injected: injected-value".to_string(),
        description: "test".to_string(),
    }];
    let matches = detect_injection_in_response(&headers, "", &signatures);
    assert_eq!(matches.len(), 1);
    assert!(matches[0].matched_value.contains("injected-value"));
}

#[test]
fn detect_injection_finds_body_match() {
    let signatures = vec![DetectionSignature {
        method: DetectionMethod::ResponseBodyContains,
        pattern: "<script>alert(1)</script>".to_string(),
        description: "test".to_string(),
    }];
    let body = "<html><body><script>alert(1)</script></body></html>";
    let matches = detect_injection_in_response(&[], body, &signatures);
    assert_eq!(matches.len(), 1);
}

#[test]
fn detect_injection_finds_set_cookie_match() {
    let headers = vec![(
        "set-cookie".to_string(),
        "sessionid=attacker_controlled; Path=/".to_string(),
    )];
    let signatures = vec![DetectionSignature {
        method: DetectionMethod::SetCookieReflected,
        pattern: "Set-Cookie: sessionid=attacker_controlled".to_string(),
        description: "test".to_string(),
    }];
    let matches = detect_injection_in_response(&headers, "", &signatures);
    assert_eq!(matches.len(), 1);
}

#[test]
fn detect_injection_finds_location_redirect() {
    let headers = vec![(
        "Location".to_string(),
        "https://evil.com/phishing".to_string(),
    )];
    let signatures = vec![DetectionSignature {
        method: DetectionMethod::RedirectLocation,
        pattern: "Location: https://evil.com/phishing".to_string(),
        description: "test".to_string(),
    }];
    let matches = detect_injection_in_response(&headers, "", &signatures);
    assert_eq!(matches.len(), 1);
}

#[test]
fn detect_injection_finds_content_type_change() {
    let headers = vec![("content-type".to_string(), "text/html".to_string())];
    let signatures = vec![DetectionSignature {
        method: DetectionMethod::ContentTypeChanged,
        pattern: "Content-Type: text/html".to_string(),
        description: "test".to_string(),
    }];
    let matches = detect_injection_in_response(&headers, "", &signatures);
    assert_eq!(matches.len(), 1);
}

#[test]
fn detect_injection_finds_cors_header() {
    let headers = vec![(
        "Access-Control-Allow-Origin".to_string(),
        "https://evil.com".to_string(),
    )];
    let signatures = vec![DetectionSignature {
        method: DetectionMethod::CorsHeaderReflected,
        pattern: "Access-Control-Allow-Origin: https://evil.com".to_string(),
        description: "test".to_string(),
    }];
    let matches = detect_injection_in_response(&headers, "", &signatures);
    assert_eq!(matches.len(), 1);
}

#[test]
fn detect_injection_returns_empty_on_no_match() {
    let headers = vec![("Content-Type".to_string(), "text/plain".to_string())];
    let signatures = vec![DetectionSignature {
        method: DetectionMethod::ResponseHeaderPresent,
        pattern: "X-Injected: something".to_string(),
        description: "test".to_string(),
    }];
    let matches = detect_injection_in_response(&headers, "safe body", &signatures);
    assert!(matches.is_empty());
}

#[test]
fn crlf_encoding_display_is_human_readable() {
    let display = format!("{}", CrlfEncoding::UrlEncodedLower);
    assert!(display.contains("%0d%0a"));
}

#[test]
fn technique_display_is_human_readable() {
    let display = format!("{}", ResponseInjectionTechnique::CrlfInjection);
    assert_eq!(display, "CRLF Injection");
}

#[test]
fn detection_method_display_is_human_readable() {
    let display = format!("{}", DetectionMethod::ResponseHeaderPresent);
    assert_eq!(display, "response header present");
}

#[test]
fn custom_attacker_domain_appears_in_payloads() {
    let config = ResponseInjectionConfig::default()
        .with_attacker_domain("hacker.test")
        .with_encoding_variants(false);
    let payloads = generate_response_injection_payloads(&config);
    let domain_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.payload.contains("hacker.test"))
        .collect();
    assert!(
        !domain_payloads.is_empty(),
        "expected at least one payload referencing custom attacker domain"
    );
}

#[test]
fn custom_target_header_appears_in_crlf_payloads() {
    let config = ResponseInjectionConfig::default()
        .with_target_header("X-Pwned")
        .with_encoding_variants(false);
    let payloads = generate_response_injection_payloads(&config);
    let header_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| {
            p.technique == ResponseInjectionTechnique::CrlfInjection
                && p.payload.contains("X-Pwned")
        })
        .collect();
    assert!(!header_payloads.is_empty());
}

#[test]
fn total_payload_count_with_variants_exceeds_without() {
    let with = ResponseInjectionConfig::default();
    let without = ResponseInjectionConfig::default().with_encoding_variants(false);
    let count_with = generate_response_injection_payloads(&with).len();
    let count_without = generate_response_injection_payloads(&without).len();
    assert!(count_with > count_without);
}

#[test]
fn encoding_variant_payloads_each_have_distinct_encoding() {
    let config = ResponseInjectionConfig::default();
    let payloads = generate_response_injection_payloads(&config);
    let encodings: Vec<_> = payloads
        .iter()
        .filter(|p| p.technique == ResponseInjectionTechnique::EncodingVariant)
        .filter_map(|p| p.encoding)
        .collect();
    let unique: std::collections::HashSet<_> = encodings.iter().collect();
    assert_eq!(
        encodings.len(),
        unique.len(),
        "encoding variant payloads should each use a distinct encoding"
    );
}

#[test]
fn detect_multiple_response_bodies_pattern() {
    let signatures = vec![DetectionSignature {
        method: DetectionMethod::MultipleResponseBodies,
        pattern: "HTTP/1.1 200 OK".to_string(),
        description: "test".to_string(),
    }];
    let body =
        "first response\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>";
    let matches = detect_injection_in_response(&[], body, &signatures);
    assert_eq!(matches.len(), 1);
}
