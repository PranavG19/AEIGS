use super::*;
use std::collections::HashMap;
use std::time::Duration;

fn make_observation(
    url: &str,
    status: u16,
    time_ms: u64,
    content_len: Option<usize>,
    content_type: Option<&str>,
    redirects: usize,
    frames: Option<usize>,
    error_event: bool,
    cached: Option<bool>,
) -> XsLeakObservation {
    XsLeakObservation {
        url: url.to_string(),
        status_code: status,
        response_time: Duration::from_millis(time_ms),
        content_length: content_len,
        content_type: content_type.map(String::from),
        redirect_count: redirects,
        frame_count: frames,
        has_error_event: error_event,
        cached,
        headers: HashMap::new(),
    }
}

#[test]
fn category_display_all_variants() {
    let categories = XsLeakCategory::all();
    assert_eq!(categories.len(), 12);
    for cat in categories {
        let display = cat.to_string();
        assert!(!display.is_empty());
    }
}

#[test]
fn category_vulnerability_class_mapping() {
    assert_eq!(
        XsLeakCategory::FrameCounting.to_vulnerability_class(),
        VulnerabilityClass::InformationDisclosure
    );
    assert_eq!(
        XsLeakCategory::PostMessageLeak.to_vulnerability_class(),
        VulnerabilityClass::CrossOriginMisconfiguration
    );
    assert_eq!(
        XsLeakCategory::WindowPropertyLeak.to_vulnerability_class(),
        VulnerabilityClass::CrossOriginMisconfiguration
    );
    assert_eq!(
        XsLeakCategory::CacheTimingProbe.to_vulnerability_class(),
        VulnerabilityClass::InformationDisclosure
    );
}

#[test]
fn browser_feature_display() {
    let features = [
        BrowserFeature::Iframes,
        BrowserFeature::Fetch,
        BrowserFeature::PerformanceObserver,
        BrowserFeature::ServiceWorker,
        BrowserFeature::TextFragment,
    ];
    for feat in &features {
        assert!(!feat.to_string().is_empty());
    }
}

#[test]
fn required_features_non_empty() {
    for cat in XsLeakCategory::all() {
        let features = cat.required_features();
        assert!(
            !features.is_empty(),
            "Category {} should require at least one browser feature",
            cat
        );
    }
}

#[test]
fn defense_display() {
    let defenses = [
        XsLeakDefense::FrameProtection,
        XsLeakDefense::Coop,
        XsLeakDefense::Corp,
        XsLeakDefense::Coep,
        XsLeakDefense::SameSiteCookies,
        XsLeakDefense::NoCacheStore,
        XsLeakDefense::VaryCookie,
        XsLeakDefense::FetchMetadata,
        XsLeakDefense::ExplicitContentType,
    ];
    for d in &defenses {
        assert!(!d.to_string().is_empty());
    }
}

#[test]
fn defense_header_patterns() {
    let patterns = XsLeakDefense::FrameProtection.header_patterns();
    assert!(patterns.len() >= 2);
    assert!(patterns.iter().any(|(k, _)| *k == "x-frame-options"));

    let coop = XsLeakDefense::Coop.header_patterns();
    assert_eq!(coop.len(), 1);
    assert_eq!(coop[0].0, "cross-origin-opener-policy");
}

#[test]
fn detect_defenses_xfo() {
    let mut headers = HashMap::new();
    headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
    let defenses = detect_defenses(&headers);
    assert!(defenses.contains(&XsLeakDefense::FrameProtection));
}

#[test]
fn detect_defenses_coop() {
    let mut headers = HashMap::new();
    headers.insert(
        "Cross-Origin-Opener-Policy".to_string(),
        "same-origin".to_string(),
    );
    let defenses = detect_defenses(&headers);
    assert!(defenses.contains(&XsLeakDefense::Coop));
}

#[test]
fn detect_defenses_corp() {
    let mut headers = HashMap::new();
    headers.insert(
        "Cross-Origin-Resource-Policy".to_string(),
        "same-origin".to_string(),
    );
    let defenses = detect_defenses(&headers);
    assert!(defenses.contains(&XsLeakDefense::Corp));
}

#[test]
fn detect_defenses_coep() {
    let mut headers = HashMap::new();
    headers.insert(
        "Cross-Origin-Embedder-Policy".to_string(),
        "require-corp".to_string(),
    );
    let defenses = detect_defenses(&headers);
    assert!(defenses.contains(&XsLeakDefense::Coep));
}

#[test]
fn detect_defenses_samesite_cookies() {
    let mut headers = HashMap::new();
    headers.insert(
        "Set-Cookie".to_string(),
        "session=abc; SameSite=Strict; Secure".to_string(),
    );
    let defenses = detect_defenses(&headers);
    assert!(defenses.contains(&XsLeakDefense::SameSiteCookies));
}

#[test]
fn detect_defenses_no_cache() {
    let mut headers = HashMap::new();
    headers.insert(
        "Cache-Control".to_string(),
        "no-store, no-cache".to_string(),
    );
    let defenses = detect_defenses(&headers);
    assert!(defenses.contains(&XsLeakDefense::NoCacheStore));
}

#[test]
fn detect_defenses_vary_cookie() {
    let mut headers = HashMap::new();
    headers.insert("Vary".to_string(), "Accept-Encoding, Cookie".to_string());
    let defenses = detect_defenses(&headers);
    assert!(defenses.contains(&XsLeakDefense::VaryCookie));
}

#[test]
fn detect_defenses_content_type_charset() {
    let mut headers = HashMap::new();
    headers.insert(
        "Content-Type".to_string(),
        "text/html; charset=utf-8".to_string(),
    );
    let defenses = detect_defenses(&headers);
    assert!(defenses.contains(&XsLeakDefense::ExplicitContentType));
}

#[test]
fn detect_defenses_csp_frame_ancestors() {
    let mut headers = HashMap::new();
    headers.insert(
        "Content-Security-Policy".to_string(),
        "default-src 'self'; frame-ancestors 'none'".to_string(),
    );
    let defenses = detect_defenses(&headers);
    assert!(defenses.contains(&XsLeakDefense::FrameProtection));
}

#[test]
fn detect_defenses_empty_headers() {
    let headers = HashMap::new();
    let defenses = detect_defenses(&headers);
    assert!(defenses.is_empty());
}

#[test]
fn detect_defenses_multiple() {
    let mut headers = HashMap::new();
    headers.insert("X-Frame-Options".to_string(), "SAMEORIGIN".to_string());
    headers.insert(
        "Cross-Origin-Opener-Policy".to_string(),
        "same-origin".to_string(),
    );
    headers.insert(
        "Cross-Origin-Resource-Policy".to_string(),
        "same-origin".to_string(),
    );
    headers.insert("Cache-Control".to_string(), "no-store".to_string());
    let defenses = detect_defenses(&headers);
    assert!(defenses.len() >= 4);
}

#[test]
fn generate_probe_catalog_non_empty() {
    let catalog = generate_probe_catalog();
    assert!(
        catalog.len() >= 15,
        "Catalog should have 15+ probes, got {}",
        catalog.len()
    );
}

#[test]
fn probe_catalog_covers_all_categories() {
    let catalog = generate_probe_catalog();
    let covered: std::collections::HashSet<XsLeakCategory> =
        catalog.iter().map(|p| p.category).collect();

    for cat in XsLeakCategory::all() {
        assert!(
            covered.contains(cat),
            "Category {} not covered by any probe",
            cat
        );
    }
}

#[test]
fn probe_ids_unique() {
    let catalog = generate_probe_catalog();
    let ids: Vec<&str> = catalog.iter().map(|p| p.id.as_str()).collect();
    let unique: std::collections::HashSet<&str> = ids.iter().copied().collect();
    assert_eq!(ids.len(), unique.len(), "Probe IDs must be unique");
}

#[test]
fn probe_has_js_payload() {
    let catalog = generate_probe_catalog();
    for probe in &catalog {
        assert!(
            !probe.js_payload.is_empty(),
            "Probe {} should have JS payload",
            probe.id
        );
    }
}

#[test]
fn probe_has_defenses() {
    let catalog = generate_probe_catalog();
    for probe in &catalog {
        assert!(
            !probe.defenses.is_empty(),
            "Probe {} should list at least one defense",
            probe.id
        );
    }
}

#[test]
fn inclusion_method_display() {
    let methods = [
        InclusionMethod::Iframe,
        InclusionMethod::ImgTag,
        InclusionMethod::ScriptTag,
        InclusionMethod::ObjectTag,
        InclusionMethod::FetchNoCors,
        InclusionMethod::WindowOpen,
        InclusionMethod::CssImport,
        InclusionMethod::Beacon,
    ];
    for m in &methods {
        assert!(!m.to_string().is_empty());
    }
}

#[test]
fn observable_display() {
    let observables = [
        Observable::EventTiming,
        Observable::FrameCount,
        Observable::ErrorVsLoad,
        Observable::CacheHitMiss,
        Observable::PerformanceEntry,
    ];
    for o in &observables {
        assert!(!o.to_string().is_empty());
    }
}

#[test]
fn differential_frame_count_detected() {
    let auth = make_observation(
        "http://target/dashboard",
        200,
        100,
        None,
        None,
        0,
        Some(3),
        false,
        None,
    );
    let unauth = make_observation(
        "http://target/dashboard",
        302,
        50,
        None,
        None,
        1,
        Some(0),
        false,
        None,
    );
    let diff = analyze_differential(XsLeakCategory::FrameCounting, &auth, &unauth);
    assert!(diff.signal_detected);
    assert!(diff.signal_strength > 0.0);
}

#[test]
fn differential_frame_count_same() {
    let auth = make_observation(
        "http://target/page",
        200,
        100,
        None,
        None,
        0,
        Some(0),
        false,
        None,
    );
    let unauth = make_observation(
        "http://target/page",
        200,
        110,
        None,
        None,
        0,
        Some(0),
        false,
        None,
    );
    let diff = analyze_differential(XsLeakCategory::FrameCounting, &auth, &unauth);
    assert!(!diff.signal_detected);
}

#[test]
fn differential_error_event_detected() {
    let auth = make_observation(
        "http://target/avatar.png",
        200,
        50,
        None,
        None,
        0,
        None,
        false,
        None,
    );
    let unauth = make_observation(
        "http://target/avatar.png",
        403,
        30,
        None,
        None,
        0,
        None,
        true,
        None,
    );
    let diff = analyze_differential(XsLeakCategory::ErrorEventDetection, &auth, &unauth);
    assert!(diff.signal_detected);
    assert!((diff.signal_strength - 1.0).abs() < f64::EPSILON);
}

#[test]
fn differential_error_event_same() {
    let auth = make_observation(
        "http://target/public.png",
        200,
        50,
        None,
        None,
        0,
        None,
        false,
        None,
    );
    let unauth = make_observation(
        "http://target/public.png",
        200,
        55,
        None,
        None,
        0,
        None,
        false,
        None,
    );
    let diff = analyze_differential(XsLeakCategory::ErrorEventDetection, &auth, &unauth);
    assert!(!diff.signal_detected);
}

#[test]
fn differential_cache_timing_detected() {
    let auth = make_observation(
        "http://target/api",
        200,
        10,
        None,
        None,
        0,
        None,
        false,
        Some(true),
    );
    let unauth = make_observation(
        "http://target/api",
        200,
        200,
        None,
        None,
        0,
        None,
        false,
        Some(false),
    );
    let diff = analyze_differential(XsLeakCategory::CacheTimingProbe, &auth, &unauth);
    assert!(diff.signal_detected);
    assert!((diff.signal_strength - 0.8).abs() < f64::EPSILON);
}

#[test]
fn differential_redirect_count_detected() {
    let auth = make_observation(
        "http://target/profile",
        200,
        100,
        None,
        None,
        0,
        None,
        false,
        None,
    );
    let unauth = make_observation(
        "http://target/profile",
        302,
        150,
        None,
        None,
        2,
        None,
        false,
        None,
    );
    let diff = analyze_differential(XsLeakCategory::RedirectCounting, &auth, &unauth);
    assert!(diff.signal_detected);
    assert!(diff.signal_strength > 0.0);
}

#[test]
fn differential_content_type_detected() {
    let auth = make_observation(
        "http://target/data",
        200,
        100,
        None,
        Some("application/json"),
        0,
        None,
        false,
        None,
    );
    let unauth = make_observation(
        "http://target/data",
        200,
        100,
        None,
        Some("text/html"),
        0,
        None,
        false,
        None,
    );
    let diff = analyze_differential(XsLeakCategory::ContentTypeSniffing, &auth, &unauth);
    assert!(diff.signal_detected);
    assert!((diff.signal_strength - 0.9).abs() < f64::EPSILON);
}

#[test]
fn differential_performance_api_timing() {
    let auth = make_observation(
        "http://target/heavy",
        200,
        500,
        None,
        None,
        0,
        None,
        false,
        None,
    );
    let unauth = make_observation(
        "http://target/heavy",
        200,
        100,
        None,
        None,
        0,
        None,
        false,
        None,
    );
    let diff = analyze_differential(XsLeakCategory::PerformanceApiLeak, &auth, &unauth);
    assert!(diff.signal_detected);
    assert!(diff.signal_strength > 0.0);
}

#[test]
fn differential_performance_api_similar() {
    let auth = make_observation(
        "http://target/page",
        200,
        100,
        None,
        None,
        0,
        None,
        false,
        None,
    );
    let unauth = make_observation(
        "http://target/page",
        200,
        110,
        None,
        None,
        0,
        None,
        false,
        None,
    );
    let diff = analyze_differential(XsLeakCategory::PerformanceApiLeak, &auth, &unauth);
    assert!(!diff.signal_detected);
}

#[test]
fn differential_size_based_leak() {
    let auth = make_observation(
        "http://target/profile",
        200,
        200,
        Some(50000),
        None,
        0,
        None,
        false,
        None,
    );
    let unauth = make_observation(
        "http://target/profile",
        200,
        50,
        Some(500),
        None,
        0,
        None,
        false,
        None,
    );
    let diff = analyze_differential(XsLeakCategory::SizeBasedLeak, &auth, &unauth);
    assert!(diff.signal_detected);
    assert!(diff.signal_strength > 0.9);
}

#[test]
fn differential_size_based_similar() {
    let auth = make_observation(
        "http://target/page",
        200,
        100,
        Some(1000),
        None,
        0,
        None,
        false,
        None,
    );
    let unauth = make_observation(
        "http://target/page",
        200,
        100,
        Some(1100),
        None,
        0,
        None,
        false,
        None,
    );
    let diff = analyze_differential(XsLeakCategory::SizeBasedLeak, &auth, &unauth);
    assert!(!diff.signal_detected);
}

#[test]
fn viable_categories_no_defenses() {
    let viable = viable_categories(&[]);
    assert!(
        viable.len() >= 10,
        "With no defenses, most categories should be viable"
    );
}

#[test]
fn viable_categories_full_defense() {
    let all_defenses = vec![
        XsLeakDefense::FrameProtection,
        XsLeakDefense::Coop,
        XsLeakDefense::Corp,
        XsLeakDefense::Coep,
        XsLeakDefense::SameSiteCookies,
        XsLeakDefense::NoCacheStore,
        XsLeakDefense::VaryCookie,
        XsLeakDefense::FetchMetadata,
        XsLeakDefense::ExplicitContentType,
    ];
    let viable = viable_categories(&all_defenses);
    assert!(
        viable.len() < 12,
        "Full defense stack should reduce viable categories"
    );
}

#[test]
fn analyze_target_no_defenses_with_signals() {
    let headers = HashMap::new();
    let observations = vec![
        (
            XsLeakCategory::FrameCounting,
            make_observation(
                "http://t/dash",
                200,
                100,
                None,
                None,
                0,
                Some(3),
                false,
                None,
            ),
            make_observation(
                "http://t/dash",
                302,
                50,
                None,
                None,
                1,
                Some(0),
                false,
                None,
            ),
        ),
        (
            XsLeakCategory::ErrorEventDetection,
            make_observation("http://t/img", 200, 50, None, None, 0, None, false, None),
            make_observation("http://t/img", 403, 30, None, None, 0, None, true, None),
        ),
    ];
    let report = analyze_target("http://t", &headers, &observations);
    assert!(report.risk_score > 0.0);
    assert!(report.defenses_detected.is_empty());
    assert!(report.viable_leak_categories.len() >= 10);
    assert_eq!(report.differentials.len(), 2);
    assert!(report.differentials.iter().all(|d| d.signal_detected));
    assert!(report.summary.contains("XS-Leak signals"));
}

#[test]
fn analyze_target_with_defenses_no_signals() {
    let mut headers = HashMap::new();
    headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
    headers.insert(
        "Cross-Origin-Opener-Policy".to_string(),
        "same-origin".to_string(),
    );
    let observations = vec![];
    let report = analyze_target("http://t", &headers, &observations);
    assert!((report.risk_score - 0.0).abs() < f64::EPSILON);
    assert!(report.defenses_detected.len() >= 2);
    assert!(report.summary.contains("No XS-Leak signals"));
}

#[test]
fn rank_probes_no_defenses() {
    let ranked = rank_probes_by_likelihood(&[]);
    assert!(!ranked.is_empty());
    for (_, prob) in &ranked {
        assert!(
            (*prob - 1.0).abs() < f64::EPSILON,
            "With no defenses, all probes should have 1.0 probability"
        );
    }
}

#[test]
fn rank_probes_with_defenses_sorted() {
    let defenses = vec![XsLeakDefense::FrameProtection, XsLeakDefense::Coop];
    let ranked = rank_probes_by_likelihood(&defenses);
    assert!(!ranked.is_empty());

    for i in 1..ranked.len() {
        assert!(
            ranked[i - 1].1 >= ranked[i].1,
            "Probes should be sorted by descending probability"
        );
    }

    let has_reduced = ranked.iter().any(|(_, p)| *p < 1.0);
    assert!(has_reduced, "Some probes should have reduced probability");
}

#[test]
fn frame_counting_probes_have_html() {
    let probes = frame_counting_probes();
    assert!(probes.len() >= 2);
    for probe in &probes {
        assert!(!probe.html_payload.is_empty());
        assert!(probe.html_payload.contains("TARGET_URL"));
    }
}

#[test]
fn error_event_probes_variety() {
    let probes = error_event_probes();
    assert!(probes.len() >= 3);
    let methods: std::collections::HashSet<InclusionMethod> =
        probes.iter().map(|p| p.inclusion_method).collect();
    assert!(
        methods.len() >= 2,
        "Error event probes should use different inclusion methods"
    );
}

#[test]
fn cache_timing_probes_threshold() {
    let probes = cache_timing_probes();
    assert!(!probes.is_empty());
    for probe in &probes {
        assert!(
            probe.defenses.contains(&XsLeakDefense::NoCacheStore)
                || probe.defenses.contains(&XsLeakDefense::Corp),
            "Cache probes should list cache or CORP defense"
        );
    }
}

#[test]
fn postmessage_probe_window_open() {
    let probes = postmessage_probes();
    assert_eq!(probes.len(), 1);
    assert_eq!(probes[0].inclusion_method, InclusionMethod::WindowOpen);
    assert!(probes[0].js_payload.contains("message"));
}

#[test]
fn text_fragment_probe_scroll() {
    let probes = text_fragment_probes();
    assert_eq!(probes.len(), 1);
    assert!(probes[0].js_payload.contains(":~:text="));
    assert_eq!(probes[0].observable, Observable::ScrollPosition);
}

#[test]
fn connection_pool_probe_saturation() {
    let probes = connection_pool_probes();
    assert_eq!(probes.len(), 1);
    assert!(probes[0].js_payload.contains("AbortController"));
    assert!(probes[0].timing_threshold >= Duration::from_millis(500));
}

#[test]
fn window_property_probes_cover_name_and_history() {
    let probes = window_property_probes();
    assert!(probes.len() >= 2);
    let has_name = probes
        .iter()
        .any(|p| p.js_payload.contains("window.name") || p.js_payload.contains("w.name"));
    let has_history = probes
        .iter()
        .any(|p| p.js_payload.contains("history.length"));
    assert!(has_name, "Should have window.name probe");
    assert!(has_history, "Should have history.length probe");
}

#[test]
fn report_summary_format() {
    let headers = HashMap::new();
    let report = analyze_target("http://example.com", &headers, &[]);
    assert!(report.summary.contains("http://example.com"));
    assert!(report.target_url == "http://example.com");
}

#[test]
fn differential_postmessage_status_difference() {
    let auth = make_observation("http://t/sso", 200, 300, None, None, 0, None, false, None);
    let unauth = make_observation("http://t/sso", 401, 50, None, None, 0, None, false, None);
    let diff = analyze_differential(XsLeakCategory::PostMessageLeak, &auth, &unauth);
    assert!(diff.signal_detected);
    assert!((diff.signal_strength - 1.0).abs() < f64::EPSILON);
}

#[test]
fn redirect_counting_zero_delta() {
    let auth = make_observation("http://t/page", 200, 100, None, None, 0, None, false, None);
    let unauth = make_observation("http://t/page", 200, 100, None, None, 0, None, false, None);
    let diff = analyze_differential(XsLeakCategory::RedirectCounting, &auth, &unauth);
    assert!(!diff.signal_detected);
    assert!((diff.signal_strength - 0.0).abs() < f64::EPSILON);
}

#[test]
fn content_type_same_no_signal() {
    let auth = make_observation(
        "http://t/api",
        200,
        100,
        None,
        Some("application/json"),
        0,
        None,
        false,
        None,
    );
    let unauth = make_observation(
        "http://t/api",
        200,
        100,
        None,
        Some("application/json"),
        0,
        None,
        false,
        None,
    );
    let diff = analyze_differential(XsLeakCategory::ContentTypeSniffing, &auth, &unauth);
    assert!(!diff.signal_detected);
}

#[test]
fn size_based_zero_sizes() {
    let auth = make_observation(
        "http://t/page",
        200,
        100,
        Some(0),
        None,
        0,
        None,
        false,
        None,
    );
    let unauth = make_observation(
        "http://t/page",
        200,
        100,
        Some(0),
        None,
        0,
        None,
        false,
        None,
    );
    let diff = analyze_differential(XsLeakCategory::SizeBasedLeak, &auth, &unauth);
    assert!(!diff.signal_detected);
}

#[test]
fn analyze_target_mixed_signals() {
    let headers = HashMap::new();
    let observations = vec![
        (
            XsLeakCategory::FrameCounting,
            make_observation(
                "http://t/dash",
                200,
                100,
                None,
                None,
                0,
                Some(3),
                false,
                None,
            ),
            make_observation(
                "http://t/dash",
                302,
                50,
                None,
                None,
                1,
                Some(0),
                false,
                None,
            ),
        ),
        (
            XsLeakCategory::ErrorEventDetection,
            make_observation("http://t/img", 200, 50, None, None, 0, None, false, None),
            make_observation("http://t/img", 200, 55, None, None, 0, None, false, None),
        ),
    ];
    let report = analyze_target("http://t", &headers, &observations);
    let detected = report
        .differentials
        .iter()
        .filter(|d| d.signal_detected)
        .count();
    assert_eq!(detected, 1, "Only frame counting should detect signal");
    assert!(report.risk_score > 0.0);
}
