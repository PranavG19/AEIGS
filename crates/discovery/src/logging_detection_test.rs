use super::logging_detection::*;

#[test]
fn cloudflare_waf_detected_from_cf_ray_header() {
    let headers = vec![
        ("cf-ray".to_string(), "abc123-LAX".to_string()),
        ("server".to_string(), "cloudflare".to_string()),
    ];
    let result = fingerprint_waf_from_headers(&headers).unwrap();
    assert_eq!(result.vendor, WafVendor::Cloudflare);
    assert!(result.confidence >= 0.95);
    assert!(!result.bypass_hints.is_empty());
}

#[test]
fn akamai_waf_detected_from_headers() {
    let headers = vec![(
        "x-akamai-transformed".to_string(),
        "9 - 0 pmb=mRUM,2".to_string(),
    )];
    let result = fingerprint_waf_from_headers(&headers).unwrap();
    assert_eq!(result.vendor, WafVendor::Akamai);
    assert!(result.confidence >= 0.90);
}

#[test]
fn aws_waf_detected_from_amzn_headers() {
    let headers = vec![("x-amzn-waf-action".to_string(), "block".to_string())];
    let result = fingerprint_waf_from_headers(&headers).unwrap();
    assert_eq!(result.vendor, WafVendor::AwsWaf);
    assert!(result.confidence >= 0.95);
}

#[test]
fn imperva_waf_detected_from_iinfo_header() {
    let headers = vec![("x-iinfo".to_string(), "10-42-0".to_string())];
    let result = fingerprint_waf_from_headers(&headers).unwrap();
    assert_eq!(result.vendor, WafVendor::Imperva);
    assert!(result.confidence >= 0.90);
}

#[test]
fn sucuri_waf_detected_from_sucuri_id() {
    let headers = vec![("x-sucuri-id".to_string(), "abcdef123".to_string())];
    let result = fingerprint_waf_from_headers(&headers).unwrap();
    assert_eq!(result.vendor, WafVendor::Sucuri);
    assert!(result.confidence >= 0.95);
}

#[test]
fn f5_bigip_waf_detected_from_server_header() {
    let headers = vec![("server".to_string(), "BigIP".to_string())];
    let result = fingerprint_waf_from_headers(&headers).unwrap();
    assert_eq!(result.vendor, WafVendor::F5BigIp);
}

#[test]
fn barracuda_waf_detected_from_cookie() {
    let headers = vec![(
        "barra_counter_session".to_string(),
        "session123".to_string(),
    )];
    let result = fingerprint_waf_from_headers(&headers).unwrap();
    assert_eq!(result.vendor, WafVendor::Barracuda);
}

#[test]
fn modsecurity_detected_from_server_header() {
    let headers = vec![(
        "server".to_string(),
        "Apache/2.4 mod_security/2.9".to_string(),
    )];
    let result = fingerprint_waf_from_headers(&headers).unwrap();
    assert_eq!(result.vendor, WafVendor::ModSecurity);
}

#[test]
fn no_waf_detected_from_clean_headers() {
    let headers = vec![
        ("server".to_string(), "nginx/1.20".to_string()),
        ("content-type".to_string(), "text/html".to_string()),
    ];
    let result = fingerprint_waf_from_headers(&headers);
    assert!(result.is_none());
}

#[test]
fn cloudflare_waf_detected_from_block_page() {
    let body =
        "<html><title>Attention Required! | Cloudflare</title><body>Ray ID: abc123</body></html>";
    let result = fingerprint_waf_from_body(body).unwrap();
    assert_eq!(result.vendor, WafVendor::Cloudflare);
}

#[test]
fn imperva_detected_from_incapsula_body() {
    let body = "<html><body>Incapsula incident ID: 12345</body></html>";
    let result = fingerprint_waf_from_body(body).unwrap();
    assert_eq!(result.vendor, WafVendor::Imperva);
}

#[test]
fn combined_waf_fingerprint_merges_evidence() {
    let headers = vec![("cf-ray".to_string(), "abc-LAX".to_string())];
    let body = "Attention Required! | Cloudflare";
    let result = fingerprint_waf(&headers, body).unwrap();
    assert_eq!(result.vendor, WafVendor::Cloudflare);
    assert!(result.evidence.len() >= 2);
}

#[test]
fn bot_detection_cloudflare_challenge() {
    let body = "<script src=\"/cdn-cgi/challenge-platform/generate\"></script>";
    let results = detect_bot_protection(body);
    assert!(!results.is_empty());
    let cf = results
        .iter()
        .find(|r| r.platform == BotDetectionPlatform::Cloudflare)
        .unwrap();
    assert!(cf.javascript_challenge);
}

#[test]
fn bot_detection_perimeterx() {
    let body = "<script>window._pxAppId='PX12345';</script><script src=\"perimeterx\"></script>";
    let results = detect_bot_protection(body);
    let px = results
        .iter()
        .find(|r| r.platform == BotDetectionPlatform::PerimeterX)
        .unwrap();
    assert!(px.confidence >= 0.80);
}

#[test]
fn bot_detection_datadome() {
    let body = "<script>DataDome.init({});</script>";
    let results = detect_bot_protection(body);
    let dd = results
        .iter()
        .find(|r| r.platform == BotDetectionPlatform::DataDome)
        .unwrap();
    assert!(dd.confidence >= 0.90);
}

#[test]
fn bot_detection_from_cookies_akamai() {
    let headers = vec![(
        "Set-Cookie".to_string(),
        "_abck=abc123; path=/; secure".to_string(),
    )];
    let results = detect_bot_from_cookies(&headers);
    let ak = results
        .iter()
        .find(|r| r.platform == BotDetectionPlatform::Akamai)
        .unwrap();
    assert!(ak.confidence >= 0.85);
}

#[test]
fn bot_detection_captcha_present() {
    let body = "<div class=\"g-recaptcha\"></div>";
    let results = detect_bot_protection(body);
    assert!(results.is_empty() || results.iter().all(|r| r.captcha_present));
}

#[test]
fn no_bot_detection_on_clean_page() {
    let body = "<html><body><h1>Hello World</h1></body></html>";
    let results = detect_bot_protection(body);
    assert!(results.is_empty());
}

#[test]
fn honeypot_fake_admin_panel_detected() {
    let responses = vec![(
        "/admin".to_string(),
        200u16,
        50u64,
        "<form><input name='user'><input name='pass'>login</form>".to_string(),
    )];
    let results = detect_honeypots(&responses);
    assert!(
        results
            .iter()
            .any(|h| h.indicator_type == HoneypotType::FakeAdminPanel)
    );
}

#[test]
fn honeypot_tarpit_detected_for_slow_response() {
    let responses = vec![(
        "/admin.php".to_string(),
        200u16,
        15000u64,
        "please wait while we verify your request".to_string(),
    )];
    let results = detect_honeypots(&responses);
    assert!(
        results
            .iter()
            .any(|h| h.indicator_type == HoneypotType::TarpitEndpoint)
    );
}

#[test]
fn honeypot_canary_token_detected() {
    let responses = vec![(
        "/api/data".to_string(),
        200u16,
        100u64,
        "<img src='https://canarytokens.com/track/abc123.png'>".to_string(),
    )];
    let results = detect_honeypots(&responses);
    assert!(
        results
            .iter()
            .any(|h| h.indicator_type == HoneypotType::CanaryToken)
    );
}

#[test]
fn honeypot_hidden_form_field_detected() {
    let responses = vec![(
        "/register".to_string(),
        200u16,
        100u64,
        r#"<form><input type="text" name="honeypot" style="display:none"><input name="email"></form>"#.to_string(),
    )];
    let results = detect_honeypots(&responses);
    assert!(
        results
            .iter()
            .any(|h| h.indicator_type == HoneypotType::HiddenFormField)
    );
}

#[test]
fn logging_blind_spot_static_asset() {
    let data = vec![("/static/app.js".to_string(), vec![10, 11, 10], false, false)];
    let results = detect_logging_blind_spots(&data);
    assert!(
        results
            .iter()
            .any(|b| b.reason == BlindSpotReason::StaticAssetPath)
    );
}

#[test]
fn logging_blind_spot_health_check() {
    let data = vec![("/healthz".to_string(), vec![5, 5, 5], true, true)];
    let results = detect_logging_blind_spots(&data);
    assert!(
        results
            .iter()
            .any(|b| b.reason == BlindSpotReason::HealthCheckEndpoint)
    );
}

#[test]
fn logging_blind_spot_missing_request_id() {
    let data = vec![("/api/users".to_string(), vec![50, 55, 48], false, true)];
    let results = detect_logging_blind_spots(&data);
    assert!(
        results
            .iter()
            .any(|b| b.reason == BlindSpotReason::MissingCorrelationId)
    );
}

#[test]
fn logging_blind_spot_no_rate_limit() {
    let data = vec![("/api/search".to_string(), vec![50, 55, 48], true, false)];
    let results = detect_logging_blind_spots(&data);
    assert!(
        results
            .iter()
            .any(|b| b.reason == BlindSpotReason::NoRateLimitEnforced)
    );
}

#[test]
fn logging_blind_spot_low_timing_variance() {
    let data = vec![(
        "/api/config".to_string(),
        vec![10, 10, 10, 10, 10],
        true,
        true,
    )];
    let results = detect_logging_blind_spots(&data);
    assert!(
        results
            .iter()
            .any(|b| b.reason == BlindSpotReason::NoTimingVariance)
    );
}

#[test]
fn rate_limit_parsed_from_standard_headers() {
    let headers = vec![
        ("X-RateLimit-Limit".to_string(), "100".to_string()),
        ("X-RateLimit-Remaining".to_string(), "95".to_string()),
        ("X-RateLimit-Reset".to_string(), "60".to_string()),
    ];
    let result = parse_rate_limit_headers("/api/data", &headers).unwrap();
    assert_eq!(result.requests_per_window, 100);
    assert_eq!(result.window_seconds, 60);
    assert_eq!(result.endpoint, "/api/data");
}

#[test]
fn rate_limit_parsed_ietf_headers() {
    let headers = vec![
        ("RateLimit-Limit".to_string(), "50".to_string()),
        ("RateLimit-Remaining".to_string(), "49".to_string()),
        ("RateLimit-Reset".to_string(), "30".to_string()),
    ];
    let result = parse_rate_limit_headers("/api/v2", &headers).unwrap();
    assert_eq!(result.requests_per_window, 50);
    assert_eq!(result.window_seconds, 30);
}

#[test]
fn rate_limit_with_retry_after() {
    let headers = vec![
        ("X-RateLimit-Limit".to_string(), "10".to_string()),
        ("Retry-After".to_string(), "120".to_string()),
    ];
    let result = parse_rate_limit_headers("/login", &headers).unwrap();
    assert_eq!(result.retry_after_seconds, Some(120));
}

#[test]
fn rate_limit_type_inferred_per_ip() {
    let headers = vec![
        ("X-RateLimit-Limit".to_string(), "100".to_string()),
        ("X-RateLimit-Scope".to_string(), "ip".to_string()),
    ];
    let result = parse_rate_limit_headers("/api", &headers).unwrap();
    assert_eq!(result.limit_type, RateLimitType::PerIp);
}

#[test]
fn no_rate_limit_from_missing_headers() {
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    let result = parse_rate_limit_headers("/api", &headers);
    assert!(result.is_none());
}

#[test]
fn account_lockout_detected_at_threshold() {
    let attempts: Vec<(u32, u16, String)> = vec![
        (1, 401, "Invalid credentials".to_string()),
        (2, 401, "Invalid credentials".to_string()),
        (3, 401, "Invalid credentials".to_string()),
        (4, 401, "Invalid credentials".to_string()),
        (
            5,
            429,
            "Too many login attempts. Account temporarily blocked.".to_string(),
        ),
    ];
    let result = analyze_account_lockout("/login", &attempts).unwrap();
    assert_eq!(result.max_attempts, 5);
    assert!(result.lockout_duration_seconds.is_some());
}

#[test]
fn account_lockout_with_captcha_threshold() {
    let attempts: Vec<(u32, u16, String)> = vec![
        (1, 401, "Invalid".to_string()),
        (2, 401, "Invalid".to_string()),
        (3, 200, "Please solve the captcha".to_string()),
        (4, 401, "Invalid".to_string()),
        (5, 429, "Locked".to_string()),
    ];
    let result = analyze_account_lockout("/auth", &attempts).unwrap();
    assert_eq!(result.captcha_threshold, Some(3));
}

#[test]
fn account_lockout_empty_attempts_returns_none() {
    let result = analyze_account_lockout("/login", &[]);
    assert!(result.is_none());
}

#[test]
fn siem_new_security_headers_detected() {
    let baseline = vec![("content-type".to_string(), "text/html".to_string())];
    let triggered = vec![
        ("content-type".to_string(), "text/html".to_string()),
        ("x-request-id".to_string(), "abc-123-def".to_string()),
        ("x-trace-id".to_string(), "trace-xyz".to_string()),
    ];
    let findings = detect_siem_indicators(&baseline, &triggered, 50, 50);
    assert!(
        findings
            .iter()
            .any(|f| f.category == DetectionCategory::SiemIndicator)
    );
}

#[test]
fn siem_timing_increase_detected() {
    let baseline = vec![];
    let triggered = vec![];
    let findings = detect_siem_indicators(&baseline, &triggered, 50, 200);
    assert!(findings.iter().any(|f| {
        f.category == DetectionCategory::SiemIndicator && f.description.contains("time increased")
    }));
}

#[test]
fn response_timing_progressive_slowdown() {
    let timings: Vec<(u32, u64)> = vec![
        (1, 50),
        (2, 55),
        (3, 48),
        (4, 52),
        (5, 200),
        (6, 250),
        (7, 300),
        (8, 280),
    ];
    let findings = analyze_response_timing(&timings);
    assert!(
        findings
            .iter()
            .any(|f| f.category == DetectionCategory::ResponseTimingAnalysis)
    );
}

#[test]
fn response_timing_spikes_detected() {
    let timings: Vec<(u32, u64)> = vec![
        (1, 50),
        (2, 55),
        (3, 1000),
        (4, 48),
        (5, 52),
        (6, 1200),
        (7, 50),
        (8, 55),
    ];
    let findings = analyze_response_timing(&timings);
    assert!(findings.iter().any(|f| {
        f.category == DetectionCategory::ResponseTimingAnalysis && f.description.contains("spikes")
    }));
}

#[test]
fn response_timing_too_few_samples() {
    let timings: Vec<(u32, u64)> = vec![(1, 50), (2, 55)];
    let findings = analyze_response_timing(&timings);
    assert!(findings.is_empty());
}

#[test]
fn full_report_aggregates_all_categories() {
    let headers = vec![
        ("cf-ray".to_string(), "abc-LAX".to_string()),
        ("server".to_string(), "cloudflare".to_string()),
    ];
    let body = "<script src=\"/cdn-cgi/challenge-platform/gen\"></script>";
    let endpoint_data = vec![(
        "/static/app.js".to_string(),
        vec![10u64, 10, 10],
        false,
        false,
    )];
    let honeypot_responses = vec![(
        "/admin".to_string(),
        200u16,
        50u64,
        "<form>login</form>".to_string(),
    )];
    let rl_headers: Vec<(String, String)> = vec![
        ("X-RateLimit-Limit".to_string(), "100".to_string()),
        ("X-RateLimit-Reset".to_string(), "60".to_string()),
    ];
    let rate_limit_endpoints: Vec<(&str, &[(String, String)])> =
        vec![("/api", rl_headers.as_slice())];
    let lockout_attempts: Vec<(u32, u16, String)> =
        vec![(1, 401, "fail".to_string()), (2, 429, "locked".to_string())];
    let lockout_data: Vec<LockoutData<'_>> = vec![("/login", lockout_attempts.as_slice())];
    let baseline_h = vec![("content-type".to_string(), "text/html".to_string())];
    let triggered_h = vec![
        ("content-type".to_string(), "text/html".to_string()),
        ("x-request-id".to_string(), "id-abc".to_string()),
    ];
    let siem = SiemComparisonData {
        baseline_headers: &baseline_h,
        triggered_headers: &triggered_h,
        baseline_time_ms: 50,
        triggered_time_ms: 50,
    };
    let timings = vec![(1u32, 50u64), (2, 55), (3, 48)];

    let report = build_monitoring_report(
        &headers,
        body,
        &endpoint_data,
        &honeypot_responses,
        &rate_limit_endpoints,
        &lockout_data,
        &siem,
        &timings,
    );

    assert!(report.has_waf());
    assert!(report.has_bot_detection());
    assert!(!report.blind_spots.is_empty());
    assert!(!report.rate_limits.is_empty());
    assert!(!report.lockout_profiles.is_empty());
    assert!(report.finding_count() >= 4);

    let categories = report.categories_detected();
    assert!(categories.contains(&DetectionCategory::WafFingerprinting));
    assert!(categories.contains(&DetectionCategory::BotDetection));
}

#[test]
fn waf_vendor_display_strings() {
    assert_eq!(WafVendor::Cloudflare.to_string(), "Cloudflare");
    assert_eq!(WafVendor::Akamai.to_string(), "Akamai");
    assert_eq!(WafVendor::AwsWaf.to_string(), "AWS WAF");
    assert_eq!(WafVendor::Imperva.to_string(), "Imperva");
    assert_eq!(WafVendor::ModSecurity.to_string(), "ModSecurity");
    assert_eq!(WafVendor::Sucuri.to_string(), "Sucuri");
    assert_eq!(WafVendor::F5BigIp.to_string(), "F5 BIG-IP");
    assert_eq!(WafVendor::Barracuda.to_string(), "Barracuda");
    assert_eq!(WafVendor::Unknown.to_string(), "Unknown WAF");
}

#[test]
fn detection_category_display_strings() {
    assert_eq!(
        DetectionCategory::WafFingerprinting.to_string(),
        "WAF Fingerprinting"
    );
    assert_eq!(
        DetectionCategory::SiemIndicator.to_string(),
        "SIEM Indicator"
    );
    assert_eq!(
        DetectionCategory::HoneypotDetection.to_string(),
        "Honeypot Detection"
    );
    assert_eq!(
        DetectionCategory::LoggingBlindSpot.to_string(),
        "Logging Blind Spot"
    );
    assert_eq!(
        DetectionCategory::RateLimitProbing.to_string(),
        "Rate Limit Probing"
    );
    assert_eq!(DetectionCategory::BotDetection.to_string(), "Bot Detection");
    assert_eq!(
        DetectionCategory::AccountLockout.to_string(),
        "Account Lockout"
    );
    assert_eq!(
        DetectionCategory::ResponseTimingAnalysis.to_string(),
        "Response Timing Analysis"
    );
}

#[test]
fn bot_detection_platform_display_strings() {
    assert_eq!(
        BotDetectionPlatform::Cloudflare.to_string(),
        "Cloudflare Bot Management"
    );
    assert_eq!(BotDetectionPlatform::PerimeterX.to_string(), "PerimeterX");
    assert_eq!(BotDetectionPlatform::DataDome.to_string(), "DataDome");
    assert_eq!(BotDetectionPlatform::Kasada.to_string(), "Kasada");
    assert_eq!(BotDetectionPlatform::Shape.to_string(), "Shape Security");
}

#[test]
fn honeypot_type_display_strings() {
    assert_eq!(HoneypotType::FakeAdminPanel.to_string(), "Fake Admin Panel");
    assert_eq!(HoneypotType::CanaryToken.to_string(), "Canary Token");
    assert_eq!(HoneypotType::DecoyEndpoint.to_string(), "Decoy Endpoint");
    assert_eq!(HoneypotType::TarpitEndpoint.to_string(), "Tarpit Endpoint");
    assert_eq!(
        HoneypotType::HiddenFormField.to_string(),
        "Hidden Form Field"
    );
}

#[test]
fn blind_spot_reason_display_strings() {
    assert_eq!(
        BlindSpotReason::NoTimingVariance.to_string(),
        "No timing variance (likely no logging)"
    );
    assert_eq!(
        BlindSpotReason::StaticErrorResponse.to_string(),
        "Static error response"
    );
    assert_eq!(
        BlindSpotReason::MissingCorrelationId.to_string(),
        "Missing correlation/request ID"
    );
}

#[test]
fn rate_limit_type_display_strings() {
    assert_eq!(RateLimitType::PerIp.to_string(), "Per-IP");
    assert_eq!(RateLimitType::PerToken.to_string(), "Per-Token");
    assert_eq!(RateLimitType::Global.to_string(), "Global");
    assert_eq!(RateLimitType::Sliding.to_string(), "Sliding Window");
}
