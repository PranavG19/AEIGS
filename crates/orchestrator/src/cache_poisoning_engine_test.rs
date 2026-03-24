use super::cache_poisoning_engine::*;
use std::collections::HashMap;

fn make_headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn unkeyed_headers_has_at_least_ten() {
    let headers = commonly_unkeyed_headers();
    assert!(
        headers.len() >= 10,
        "expected >=10 unkeyed headers, got {}",
        headers.len()
    );
}

#[test]
fn unkeyed_headers_contains_known_entries() {
    let headers = commonly_unkeyed_headers();
    assert!(headers.contains(&"X-Forwarded-Host"));
    assert!(headers.contains(&"X-Forwarded-Scheme"));
    assert!(headers.contains(&"X-Original-URL"));
    assert!(headers.contains(&"X-Rewrite-URL"));
    assert!(headers.contains(&"X-Forwarded-For"));
    assert!(headers.contains(&"X-Host"));
    assert!(headers.contains(&"X-Forwarded-Proto"));
    assert!(headers.contains(&"True-Client-IP"));
}

#[test]
fn detect_cache_hit_from_x_cache() {
    let headers = make_headers(&[("X-Cache", "HIT")]);
    let result = detect_cache_status(&headers);
    assert_eq!(result.status, CacheStatus::Hit);
    assert_eq!(result.cache_header.as_deref(), Some("X-Cache"));
}

#[test]
fn detect_cache_hit_from_cf_status() {
    let headers = make_headers(&[("CF-Cache-Status", "HIT")]);
    let result = detect_cache_status(&headers);
    assert_eq!(result.status, CacheStatus::Hit);
}

#[test]
fn detect_cache_miss_from_x_cache() {
    let headers = make_headers(&[("X-Cache", "MISS")]);
    let result = detect_cache_status(&headers);
    assert_eq!(result.status, CacheStatus::Miss);
}

#[test]
fn detect_cache_hit_from_age_header() {
    let headers = make_headers(&[("Age", "120")]);
    let result = detect_cache_status(&headers);
    assert_eq!(result.status, CacheStatus::Hit);
    assert_eq!(result.age_seconds, Some(120));
}

#[test]
fn detect_cache_unknown_when_no_indicators() {
    let headers = make_headers(&[("Content-Type", "text/html")]);
    let result = detect_cache_status(&headers);
    assert_eq!(result.status, CacheStatus::Unknown);
    assert!(result.cache_header.is_none());
}

#[test]
fn extract_ttl_from_max_age() {
    let headers = make_headers(&[
        ("Cache-Control", "public, max-age=3600"),
        ("X-Cache", "HIT"),
    ]);
    let result = detect_cache_status(&headers);
    assert_eq!(result.ttl_seconds, Some(3600));
}

#[test]
fn extract_ttl_prefers_s_maxage() {
    let headers = make_headers(&[
        ("Cache-Control", "public, max-age=60, s-maxage=7200"),
        ("X-Cache", "HIT"),
    ]);
    let result = detect_cache_status(&headers);
    assert_eq!(result.ttl_seconds, Some(7200));
}

#[test]
fn parse_vary_headers() {
    let headers = make_headers(&[("Vary", "Accept-Encoding, Cookie, Origin")]);
    let result = detect_cache_status(&headers);
    assert_eq!(result.vary_headers.len(), 3);
    assert!(result.vary_headers.contains(&"accept-encoding".to_string()));
    assert!(result.vary_headers.contains(&"cookie".to_string()));
    assert!(result.vary_headers.contains(&"origin".to_string()));
}

#[test]
fn cache_buster_is_unique() {
    let a = generate_cache_buster("cb", 1);
    let b = generate_cache_buster("cb", 2);
    assert_ne!(a, b);
    assert!(a.starts_with("cb_"));
    assert!(b.starts_with("cb_"));
}

#[test]
fn cache_buster_seeded_is_deterministic() {
    let a = generate_cache_buster_seeded("test", 42);
    let b = generate_cache_buster_seeded("test", 42);
    assert_eq!(a, b);
    assert_eq!(a, "test_42");
}

#[test]
fn detect_reflection_in_body() {
    let canary = "evil.example.com";
    let body = "<html><head><link rel='canonical' href='http://evil.example.com/'></head></html>";
    let headers = make_headers(&[]);
    let result = detect_reflection(canary, body, &headers, 200);
    assert_eq!(result, Some(ReflectionTarget::Body));
}

#[test]
fn detect_reflection_in_header() {
    let canary = "evil.example.com";
    let body = "<html></html>";
    let headers = make_headers(&[("Location", "https://evil.example.com/redirect")]);
    let result = detect_reflection(canary, body, &headers, 302);
    assert_eq!(
        result,
        Some(ReflectionTarget::Header {
            name: "Location".to_string()
        })
    );
}

#[test]
fn detect_reflection_none() {
    let canary = "evil.example.com";
    let body = "<html>normal content</html>";
    let headers = make_headers(&[("Content-Type", "text/html")]);
    let result = detect_reflection(canary, body, &headers, 200);
    assert_eq!(result, None);
}

#[test]
fn test_unkeyed_header_reflected() {
    let baseline_body = "<html>baseline</html>";
    let baseline_headers = make_headers(&[("Content-Type", "text/html")]);

    let probed_body = "<html>evil.test reflected</html>";
    let probed_headers = make_headers(&[("Content-Type", "text/html")]);

    let result = test_unkeyed_header(
        "X-Forwarded-Host",
        "evil.test",
        baseline_body,
        &baseline_headers,
        probed_body,
        &probed_headers,
        200,
    );

    assert!(result.is_some());
    let uh = result.unwrap();
    assert_eq!(uh.name, "X-Forwarded-Host");
    assert_eq!(uh.reflected_in, ReflectionTarget::Body);
}

#[test]
fn test_unkeyed_header_no_diff() {
    let body = "<html>same</html>";
    let headers = make_headers(&[("Content-Type", "text/html")]);

    let result = test_unkeyed_header(
        "X-Forwarded-Host",
        "evil.test",
        body,
        &headers,
        body,
        &headers,
        200,
    );

    assert!(result.is_none());
}

#[test]
fn fat_get_reflected_and_cached() {
    let canary = "injected_val";
    let fat_body = "<html>injected_val in response</html>";
    let fat_headers = make_headers(&[]);
    let second_get_body = "<html>injected_val still here</html>";

    let result = analyze_fat_get(
        "callback",
        canary,
        fat_body,
        &fat_headers,
        200,
        second_get_body,
    );
    assert!(result.reflected);
    assert!(result.cached);
    assert_eq!(result.parameter, "callback");
}

#[test]
fn fat_get_not_reflected() {
    let canary = "injected_val";
    let fat_body = "<html>normal</html>";
    let fat_headers = make_headers(&[]);
    let second_body = "<html>normal</html>";

    let result = analyze_fat_get("callback", canary, fat_body, &fat_headers, 200, second_body);
    assert!(!result.reflected);
    assert!(!result.cached);
}

#[test]
fn parameter_cloak_confirmed() {
    let body = "<html>smuggled_xss</html>";
    let headers = make_headers(&[]);

    let result = test_parameter_cloak(
        CloakTechnique::SemicolonSeparator,
        "utm_content",
        "smuggled_xss",
        body,
        &headers,
    );
    assert!(result.confirmed);
    assert_eq!(result.technique, CloakTechnique::SemicolonSeparator);
}

#[test]
fn parameter_cloak_not_confirmed() {
    let body = "<html>clean</html>";
    let headers = make_headers(&[]);

    let result = test_parameter_cloak(
        CloakTechnique::DuplicateParam,
        "lang",
        "evil",
        body,
        &headers,
    );
    assert!(!result.confirmed);
}

#[test]
fn build_cloak_url_semicolon() {
    let url = build_cloak_url(
        "https://example.com/path",
        "utm_content",
        "payload",
        &CloakTechnique::SemicolonSeparator,
    );
    assert_eq!(
        url,
        "https://example.com/path?cachebust=1;utm_content=payload"
    );
}

#[test]
fn build_cloak_url_duplicate_param() {
    let url = build_cloak_url(
        "https://example.com/path?q=1",
        "lang",
        "evil",
        &CloakTechnique::DuplicateParam,
    );
    assert_eq!(url, "https://example.com/path?q=1&lang=benign&lang=evil");
}

#[test]
fn build_cloak_url_encoded_ampersand() {
    let url = build_cloak_url(
        "https://example.com/page",
        "cb",
        "xss",
        &CloakTechnique::UrlEncodedAmpersand,
    );
    assert_eq!(url, "https://example.com/page?cachebust=1%26cb=xss");
}

#[test]
fn build_cloak_url_trailing_dot() {
    let url = build_cloak_url(
        "https://example.com/page",
        "x",
        "y",
        &CloakTechnique::TrailingDot,
    );
    assert_eq!(url, "https://example.com/page.?x=y");
}

#[test]
fn build_cloak_url_path_param() {
    let url = build_cloak_url(
        "https://example.com/api/resource",
        "admin",
        "true",
        &CloakTechnique::PathParameterInjection,
    );
    assert_eq!(url, "https://example.com/api/resource;admin=true");
}

#[test]
fn severity_score_scales_with_unkeyed() {
    let s0 = severity_score(0, false, false, None);
    let s3 = severity_score(3, false, false, None);
    let s10 = severity_score(10, false, false, None);
    assert!(s0 < s3);
    assert!(s3 < s10);
    assert!(s10 <= 10.0);
}

#[test]
fn severity_score_capped_at_ten() {
    let score = severity_score(10, true, true, Some(7200));
    assert!(score <= 10.0);
}

#[test]
fn severity_with_fat_get_and_cloak() {
    let base = severity_score(2, false, false, None);
    let with_fat = severity_score(2, true, false, None);
    let with_cloak = severity_score(2, false, true, None);
    let with_both = severity_score(2, true, true, None);
    assert!(with_fat > base);
    assert!(with_cloak > base);
    assert!(with_both > with_fat);
    assert!(with_both > with_cloak);
}

#[test]
fn severity_ttl_bonus() {
    let short = severity_score(1, false, false, Some(60));
    let long = severity_score(1, false, false, Some(7200));
    assert!(long > short);
}

#[test]
fn vary_covers_matches() {
    let vary = vec!["cookie".into(), "origin".into()];
    assert!(vary_covers(&vary, "Cookie"));
    assert!(vary_covers(&vary, "Origin"));
    assert!(!vary_covers(&vary, "X-Custom"));
}

#[test]
fn vary_covers_wildcard() {
    let vary = vec!["*".into()];
    assert!(vary_covers(&vary, "anything"));
}

#[test]
fn detect_cdn_cloudflare() {
    let headers = make_headers(&[("cf-ray", "abc123")]);
    let cdn = detect_cdn_presence(&headers);
    assert_eq!(cdn.as_deref(), Some("Cloudflare"));
}

#[test]
fn detect_cdn_cloudfront() {
    let headers = make_headers(&[("x-amz-cf-id", "dist123")]);
    let cdn = detect_cdn_presence(&headers);
    assert_eq!(cdn.as_deref(), Some("CloudFront"));
}

#[test]
fn detect_cdn_none() {
    let headers = make_headers(&[("Content-Type", "text/html")]);
    let cdn = detect_cdn_presence(&headers);
    assert!(cdn.is_none());
}

#[test]
fn summarize_findings_produces_output() {
    let result = CachePoisoningScanResult {
        target_url: "https://example.com".into(),
        probe: CacheProbeResult {
            status: CacheStatus::Hit,
            age_seconds: Some(60),
            ttl_seconds: Some(3600),
            cache_header: Some("X-Cache".into()),
            cache_value: Some("HIT".into()),
            vary_headers: vec!["accept-encoding".into()],
        },
        unkeyed_headers: vec![UnkeyedHeader {
            name: "X-Forwarded-Host".into(),
            reflected_in: ReflectionTarget::Body,
            payload_delivered: "evil.com".into(),
        }],
        fat_get_results: vec![FatGetResult {
            parameter: "cb".into(),
            reflected: true,
            cached: true,
        }],
        cloak_results: vec![ParameterCloakResult {
            technique: CloakTechnique::SemicolonSeparator,
            parameter: "utm".into(),
            smuggled_value: "xss".into(),
            confirmed: true,
        }],
        cache_buster_used: "cb_123".into(),
    };

    let findings = summarize_findings(&result);
    assert!(findings.len() >= 4);
    assert!(findings[0].contains("cached"));
    assert!(findings.iter().any(|f| f.contains("Unkeyed header")));
    assert!(findings.iter().any(|f| f.contains("Fat GET")));
    assert!(findings.iter().any(|f| f.contains("Parameter cloak")));
}

#[test]
fn cache_status_display() {
    assert_eq!(format!("{}", CacheStatus::Hit), "HIT");
    assert_eq!(format!("{}", CacheStatus::Miss), "MISS");
    assert_eq!(format!("{}", CacheStatus::Unknown), "UNKNOWN");
}

#[test]
fn reflection_target_display() {
    assert_eq!(format!("{}", ReflectionTarget::Body), "body");
    assert_eq!(
        format!(
            "{}",
            ReflectionTarget::Header {
                name: "Location".into()
            }
        ),
        "header:Location"
    );
    assert_eq!(format!("{}", ReflectionTarget::StatusCode), "status_code");
}

#[test]
fn cloak_technique_display() {
    assert_eq!(
        format!("{}", CloakTechnique::SemicolonSeparator),
        "semicolon_separator"
    );
    assert_eq!(
        format!("{}", CloakTechnique::DuplicateParam),
        "duplicate_param"
    );
    assert_eq!(
        format!("{}", CloakTechnique::UrlEncodedAmpersand),
        "url_encoded_ampersand"
    );
    assert_eq!(format!("{}", CloakTechnique::TrailingDot), "trailing_dot");
    assert_eq!(
        format!("{}", CloakTechnique::PathParameterInjection),
        "path_param_injection"
    );
}

#[test]
fn cache_status_headers_list_nonempty() {
    let names = cache_status_header_names();
    assert!(names.len() >= 10);
    assert!(names.contains(&"x-cache"));
    assert!(names.contains(&"cf-cache-status"));
    assert!(names.contains(&"x-varnish"));
    assert!(names.contains(&"age"));
}

#[test]
fn detect_cache_hit_tcp_hit() {
    let headers = make_headers(&[("X-Cache", "TCP_HIT from proxy")]);
    let result = detect_cache_status(&headers);
    assert_eq!(result.status, CacheStatus::Hit);
}

#[test]
fn detect_cache_miss_bypass() {
    let headers = make_headers(&[("X-Cache", "BYPASS")]);
    let result = detect_cache_status(&headers);
    assert_eq!(result.status, CacheStatus::Miss);
}

#[test]
fn hit_overrides_miss_when_both_present() {
    let headers = make_headers(&[("X-Cache", "MISS"), ("CF-Cache-Status", "HIT")]);
    let result = detect_cache_status(&headers);
    assert_eq!(result.status, CacheStatus::Hit);
}
