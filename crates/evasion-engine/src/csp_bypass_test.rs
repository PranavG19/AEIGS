use super::*;

#[test]
fn parse_basic_script_src() {
    let csp = CspPolicy::parse("script-src 'self' https://cdn.example.com", false);
    let sources = csp.directives.get(&CspDirective::ScriptSrc).unwrap();
    assert_eq!(sources, &["'self'", "https://cdn.example.com"]);
    assert!(!csp.report_only);
}

#[test]
fn parse_multiple_directives() {
    let csp = CspPolicy::parse(
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src *; font-src https://fonts.googleapis.com; connect-src https://api.example.com; object-src 'none'; media-src 'self'; frame-src https://youtube.com; child-src 'self'; base-uri 'self'",
        false,
    );
    assert!(csp.directives.len() >= 10);
    assert!(csp.directives.contains_key(&CspDirective::DefaultSrc));
    assert!(csp.directives.contains_key(&CspDirective::ScriptSrc));
    assert!(csp.directives.contains_key(&CspDirective::StyleSrc));
    assert!(csp.directives.contains_key(&CspDirective::ImgSrc));
    assert!(csp.directives.contains_key(&CspDirective::FontSrc));
    assert!(csp.directives.contains_key(&CspDirective::ConnectSrc));
    assert!(csp.directives.contains_key(&CspDirective::ObjectSrc));
    assert!(csp.directives.contains_key(&CspDirective::MediaSrc));
    assert!(csp.directives.contains_key(&CspDirective::FrameSrc));
    assert!(csp.directives.contains_key(&CspDirective::ChildSrc));
    assert!(csp.directives.contains_key(&CspDirective::BaseUri));
}

#[test]
fn parse_report_only_flag() {
    let csp = CspPolicy::parse("default-src 'self'", true);
    assert!(csp.report_only);
}

#[test]
fn parse_enforced_flag() {
    let csp = CspPolicy::parse("default-src 'self'", false);
    assert!(!csp.report_only);
}

#[test]
fn parse_empty_header() {
    let csp = CspPolicy::parse("", false);
    assert!(csp.directives.is_empty());
}

#[test]
fn parse_ignores_unknown_directives() {
    let csp = CspPolicy::parse("unknown-directive 'self'; script-src 'self'", false);
    assert_eq!(csp.directives.len(), 1);
    assert!(csp.directives.contains_key(&CspDirective::ScriptSrc));
}

#[test]
fn effective_sources_falls_back_to_default() {
    let csp = CspPolicy::parse("default-src 'self' https://cdn.example.com", false);
    let sources = csp.effective_sources(CspDirective::ScriptSrc).unwrap();
    assert_eq!(sources, &["'self'", "https://cdn.example.com"]);
}

#[test]
fn effective_sources_uses_specific_over_default() {
    let csp = CspPolicy::parse(
        "default-src 'none'; script-src 'self' https://cdn.example.com",
        false,
    );
    let sources = csp.effective_sources(CspDirective::ScriptSrc).unwrap();
    assert_eq!(sources, &["'self'", "https://cdn.example.com"]);
}

#[test]
fn detect_unsafe_inline() {
    let csp = CspPolicy::parse("script-src 'self' 'unsafe-inline'", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(weaknesses
        .iter()
        .any(|w| matches!(w, CspWeakness::UnsafeInline)));
}

#[test]
fn detect_unsafe_eval() {
    let csp = CspPolicy::parse("script-src 'self' 'unsafe-eval'", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(weaknesses
        .iter()
        .any(|w| matches!(w, CspWeakness::UnsafeEval)));
}

#[test]
fn detect_wildcard_domain() {
    let csp = CspPolicy::parse("script-src 'self' *.example.com", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(weaknesses.iter().any(
        |w| matches!(w, CspWeakness::WildcardDomain { pattern } if pattern == "*.example.com")
    ));
}

#[test]
fn detect_global_wildcard() {
    let csp = CspPolicy::parse("script-src *", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(weaknesses
        .iter()
        .any(|w| matches!(w, CspWeakness::WildcardDomain { pattern } if pattern == "*")));
}

#[test]
fn detect_jsonp_endpoint_googleapis() {
    let csp = CspPolicy::parse("script-src 'self' https://ajax.googleapis.com", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(weaknesses.iter().any(|w| matches!(w, CspWeakness::JsonpEndpoint { domain, .. } if domain == "ajax.googleapis.com")));
}

#[test]
fn detect_jsonp_endpoint_cdnjs() {
    let csp = CspPolicy::parse("script-src 'self' https://cdnjs.cloudflare.com", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(weaknesses.iter().any(|w| matches!(w, CspWeakness::JsonpEndpoint { domain, .. } if domain == "cdnjs.cloudflare.com")));
}

#[test]
fn detect_framework_injection_angularjs() {
    let csp = CspPolicy::parse("script-src 'self' https://ajax.googleapis.com", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(weaknesses.iter().any(|w| matches!(
        w,
        CspWeakness::FrameworkTemplateInjection { framework, .. } if framework == "AngularJS"
    )));
}

#[test]
fn detect_data_uri() {
    let csp = CspPolicy::parse("script-src 'self' data:", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(weaknesses.iter().any(|w| matches!(w, CspWeakness::DataUri)));
}

#[test]
fn detect_blob_uri() {
    let csp = CspPolicy::parse("script-src 'self' blob:", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(weaknesses.iter().any(|w| matches!(w, CspWeakness::BlobUri)));
}

#[test]
fn detect_missing_base_uri() {
    let csp = CspPolicy::parse("script-src 'self'", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(weaknesses
        .iter()
        .any(|w| matches!(w, CspWeakness::MissingBaseUri)));
}

#[test]
fn no_missing_base_uri_when_present() {
    let csp = CspPolicy::parse("script-src 'self'; base-uri 'self'", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(!weaknesses
        .iter()
        .any(|w| matches!(w, CspWeakness::MissingBaseUri)));
}

#[test]
fn detect_nonce_reuse_short_nonce() {
    let csp = CspPolicy::parse("script-src 'nonce-abc'", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(weaknesses
        .iter()
        .any(|w| matches!(w, CspWeakness::NonceReuse { nonce } if nonce == "abc")));
}

#[test]
fn detect_nonce_reuse_numeric_nonce() {
    let csp = CspPolicy::parse("script-src 'nonce-123456789012'", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(weaknesses
        .iter()
        .any(|w| matches!(w, CspWeakness::NonceReuse { nonce } if nonce == "123456789012")));
}

#[test]
fn no_nonce_reuse_for_strong_nonce() {
    let csp = CspPolicy::parse("script-src 'nonce-a1b2c3d4e5f6g7h8i9j0'", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(!weaknesses
        .iter()
        .any(|w| matches!(w, CspWeakness::NonceReuse { .. })));
}

#[test]
fn detect_missing_object_src() {
    let csp = CspPolicy::parse("script-src 'self'", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(weaknesses
        .iter()
        .any(|w| matches!(w, CspWeakness::MissingObjectSrc)));
}

#[test]
fn no_missing_object_src_when_present() {
    let csp = CspPolicy::parse("script-src 'self'; object-src 'none'", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(!weaknesses
        .iter()
        .any(|w| matches!(w, CspWeakness::MissingObjectSrc)));
}

#[test]
fn no_missing_object_src_when_default_is_none() {
    let csp = CspPolicy::parse("default-src 'none'; script-src 'self'", false);
    let weaknesses = csp.detect_weaknesses();
    assert!(!weaknesses
        .iter()
        .any(|w| matches!(w, CspWeakness::MissingObjectSrc)));
}

#[test]
fn generate_bypasses_unsafe_inline_produces_payloads() {
    let csp = CspPolicy::parse(
        "script-src 'self' 'unsafe-inline'; base-uri 'self'; object-src 'none'",
        false,
    );
    let bypasses = csp.generate_bypasses();
    assert!(bypasses.len() >= 3);
    assert!(bypasses.iter().any(|b| b.payload.contains("<script>")));
    assert!(bypasses.iter().any(|b| b.payload.contains("onerror")));
}

#[test]
fn generate_bypasses_unsafe_eval_produces_payloads() {
    let csp = CspPolicy::parse(
        "script-src 'self' 'unsafe-eval'; base-uri 'self'; object-src 'none'",
        false,
    );
    let bypasses = csp.generate_bypasses();
    assert!(bypasses.iter().any(|b| b.payload.contains("eval(")));
    assert!(bypasses.iter().any(|b| b.payload.contains("new Function")));
}

#[test]
fn generate_bypasses_data_uri_produces_base64_payload() {
    let csp = CspPolicy::parse(
        "script-src 'self' data:; base-uri 'self'; object-src 'none'",
        false,
    );
    let bypasses = csp.generate_bypasses();
    assert!(bypasses.iter().any(|b| b.payload.contains("base64")));
}

#[test]
fn generate_bypasses_jsonp_produces_callback_payload() {
    let csp = CspPolicy::parse(
        "script-src 'self' https://ajax.googleapis.com; base-uri 'self'; object-src 'none'",
        false,
    );
    let bypasses = csp.generate_bypasses();
    assert!(bypasses
        .iter()
        .any(|b| b.payload.contains("callback=alert")));
}

#[test]
fn generate_bypasses_missing_base_uri_produces_base_tag() {
    let csp = CspPolicy::parse("script-src 'self'; object-src 'none'", false);
    let bypasses = csp.generate_bypasses();
    assert!(bypasses.iter().any(|b| b.payload.contains("<base ")));
}

#[test]
fn generate_bypasses_blob_uri_produces_blob_payload() {
    let csp = CspPolicy::parse(
        "script-src 'self' blob:; base-uri 'self'; object-src 'none'",
        false,
    );
    let bypasses = csp.generate_bypasses();
    assert!(bypasses.iter().any(|b| b.payload.contains("Blob")));
}

#[test]
fn generate_bypasses_nonce_reuse_includes_nonce_in_payload() {
    let csp = CspPolicy::parse(
        "script-src 'nonce-abc123'; base-uri 'self'; object-src 'none'",
        false,
    );
    let bypasses = csp.generate_bypasses();
    assert!(bypasses
        .iter()
        .any(|b| b.payload.contains("nonce=\"abc123\"")));
}

#[test]
fn jsonp_database_has_at_least_10_domains() {
    assert!(jsonp_domain_count() >= 10);
}

#[test]
fn known_jsonp_domains_includes_major_cdns() {
    let domains = known_jsonp_domains();
    assert!(domains.contains(&"cdnjs.cloudflare.com"));
    assert!(domains.contains(&"ajax.googleapis.com"));
    assert!(domains.contains(&"cdn.jsdelivr.net"));
}

#[test]
fn weakness_count_at_least_8_patterns() {
    let csp = CspPolicy::parse(
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.example.com data: blob: \
         https://ajax.googleapis.com 'nonce-abc'",
        false,
    );
    let weaknesses = csp.detect_weaknesses();
    let unique_types: std::collections::HashSet<String> = weaknesses
        .iter()
        .map(|w| std::mem::discriminant(w))
        .map(|d| format!("{d:?}"))
        .collect();
    assert!(
        unique_types.len() >= 8,
        "Expected >=8 unique weakness types, got {}: {:?}",
        unique_types.len(),
        unique_types
    );
}

#[test]
fn csp_directive_display() {
    assert_eq!(CspDirective::ScriptSrc.to_string(), "script-src");
    assert_eq!(CspDirective::DefaultSrc.to_string(), "default-src");
    assert_eq!(CspDirective::BaseUri.to_string(), "base-uri");
}

#[test]
fn csp_weakness_display_messages() {
    let w = CspWeakness::UnsafeInline;
    assert!(w.to_string().contains("unsafe-inline"));

    let w = CspWeakness::DataUri;
    assert!(w.to_string().contains("data:"));
}

#[test]
fn parse_report_uri_and_report_to() {
    let csp = CspPolicy::parse(
        "default-src 'self'; report-uri /csp-report; report-to csp-endpoint",
        false,
    );
    assert!(csp.directives.contains_key(&CspDirective::ReportUri));
    assert!(csp.directives.contains_key(&CspDirective::ReportTo));
}

#[test]
fn parse_worker_src() {
    let csp = CspPolicy::parse("worker-src 'self' blob:", false);
    let sources = csp.directives.get(&CspDirective::WorkerSrc).unwrap();
    assert_eq!(sources, &["'self'", "blob:"]);
}

#[test]
fn parse_form_action() {
    let csp = CspPolicy::parse("form-action 'self' https://submit.example.com", false);
    assert!(csp.directives.contains_key(&CspDirective::FormAction));
}

#[test]
fn parse_frame_ancestors() {
    let csp = CspPolicy::parse("frame-ancestors 'none'", false);
    assert!(csp.directives.contains_key(&CspDirective::FrameAncestors));
}

#[test]
fn wildcard_bypass_payload_includes_attacker_domain() {
    let csp = CspPolicy::parse(
        "script-src *.example.com; base-uri 'self'; object-src 'none'",
        false,
    );
    let bypasses = csp.generate_bypasses();
    assert!(bypasses
        .iter()
        .any(|b| b.payload.contains("attacker.example.com")));
}

#[test]
fn framework_injection_angularjs_payload() {
    let csp = CspPolicy::parse(
        "script-src https://cdnjs.cloudflare.com; base-uri 'self'; object-src 'none'",
        false,
    );
    let bypasses = csp.generate_bypasses();
    assert!(bypasses
        .iter()
        .any(|b| b.payload.contains("ng-app") && b.payload.contains("ng-csp")));
}

#[test]
fn missing_object_src_bypass_uses_object_tag() {
    let csp = CspPolicy::parse("script-src 'self'; base-uri 'self'", false);
    let bypasses = csp.generate_bypasses();
    assert!(bypasses.iter().any(|b| b.payload.contains("<object")));
}

#[test]
fn strict_csp_has_few_weaknesses() {
    let csp = CspPolicy::parse(
        "default-src 'none'; script-src 'nonce-a8f3kJd9xLmPq2wR7nTs'; \
         style-src 'self'; img-src 'self'; base-uri 'self'; object-src 'none'",
        false,
    );
    let weaknesses = csp.detect_weaknesses();
    assert!(
        weaknesses.is_empty(),
        "Strict CSP should have no weaknesses but got: {weaknesses:?}"
    );
}
