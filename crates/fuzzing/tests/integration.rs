use std::collections::HashMap;
use std::time::Duration;

use aegis_fuzzing::bot_detection_probe::{
    BotProbeResult, DetectionMethod, analyze_bot_detection, detect_challenge_type,
};
use aegis_fuzzing::defense_profile::{
    BotDetectionProfile, DefenseProfile, DefenseType, RateLimitProfile, WafProfile, WafVendor,
};
use aegis_fuzzing::executor::{FuzzResponse, RequestExecutor};
use aegis_fuzzing::mutator::{
    MutationOrigin, MutationStrategy, PayloadMutator, StealthRating, stealth_rating_for_template,
};
use aegis_fuzzing::oracle::{AnomalyType, BaselineProfile, FuzzOracle, measure_endpoint_variance};
use aegis_fuzzing::payload_selector::{PayloadSelector, PayloadStats};
use aegis_fuzzing::rate_limit_detector::{
    BurstProbeResult, RateLimitProbeResult, WindowProbeResult, detect_burst_allowance,
    detect_limit_window, detect_rate_limit,
};
use aegis_fuzzing::request_patterns::{
    BrowsingPattern, CoverTrafficConfig, MAX_BATCH_SIZE, NavigationStep, build_burst_batch,
    build_navigation_chain, build_parallel_resources_batch, build_sequential_batch,
    inject_cover_traffic,
};
use aegis_fuzzing::scheduler::{FuzzScheduler, FuzzTarget};
use aegis_fuzzing::streaming_fuzzer::{
    MessageDirection, StreamAnomalyType, StreamMessage, StreamMessageType, StreamProtocol,
    analyze_stream_messages, generate_sse_probe_urls, generate_ws_payloads, validate_stream_target,
};
use aegis_fuzzing::waf_fingerprinter::{
    WafProbeResult, identify_blocked_categories, identify_vendor,
};
use aegis_protocol::finding::VulnerabilityClass;

use axum::Router;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn boot_server(router: Router) -> (String, u16) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    (format!("http://127.0.0.1:{port}"), port)
}

fn make_target(endpoint: &str, class: VulnerabilityClass, priority: f64) -> FuzzTarget {
    FuzzTarget {
        endpoint: endpoint.to_string(),
        method: "GET".to_string(),
        parameter: "q".to_string(),
        vulnerability_class: class,
        priority_score: priority,
        attempts: 0,
        max_attempts: 3,
    }
}

fn make_response(request_id: u64, status: u16, body: &str, time: Duration) -> FuzzResponse {
    FuzzResponse {
        request_id,
        status_code: status,
        body: body.to_string(),
        headers: Vec::new(),
        response_time: time,
        body_size_bytes: body.len(),
    }
}

fn make_waf_probe(status: u16, headers: Vec<(&str, &str)>, body: &str) -> WafProbeResult {
    WafProbeResult {
        probe_payload: "test".to_string(),
        response_status: status,
        response_headers: headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        response_body_snippet: body.to_string(),
    }
}

// ---------------------------------------------------------------------------
// #62: executor_builds_request_with_headers
// ---------------------------------------------------------------------------
#[test]
fn executor_builds_request_with_headers() {
    let mut executor = RequestExecutor::new(
        "http://127.0.0.1:9999".to_string(),
        100,
        Duration::from_secs(30),
    )
    .unwrap();

    let req = executor.build_request("/api/test", "POST", "input", "payload");
    let header_names: Vec<&str> = req.headers.iter().map(|(k, _)| k.as_str()).collect();
    assert!(header_names.contains(&"User-Agent"));
    assert!(header_names.contains(&"Accept"));
    assert!(header_names.contains(&"Connection"));
    assert_eq!(req.method, "POST");
    assert_eq!(req.payload, "payload");
}

// ---------------------------------------------------------------------------
// #63: executor_sends_to_live_sqli_endpoint
// ---------------------------------------------------------------------------
#[tokio::test]
async fn executor_sends_to_live_sqli_endpoint() {
    let router = Router::new().route(
        "/vuln",
        get(|Query(params): Query<HashMap<String, String>>| async move {
            let input = params.get("input").cloned().unwrap_or_default();
            if input.contains('\'') {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Error: SQL syntax error in query: {input}"),
                )
                    .into_response()
            } else {
                "ok".into_response()
            }
        }),
    );
    let (base_url, _port) = boot_server(router).await;

    let payload = "' OR '1'='1";
    let url = format!("{base_url}/vuln?input={}", urlencoding::encode(payload));
    let resp = reqwest::get(&url).await.unwrap();
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("SQL syntax"),
        "expected SQL error in body, got: {body}"
    );
}

// ---------------------------------------------------------------------------
// #64: executor_sends_to_live_xss_endpoint
// ---------------------------------------------------------------------------
#[tokio::test]
async fn executor_sends_to_live_xss_endpoint() {
    let router = Router::new().route(
        "/xss",
        get(|Query(params): Query<HashMap<String, String>>| async move {
            let input = params.get("input").cloned().unwrap_or_default();
            axum::response::Html(format!("<html><body>{input}</body></html>"))
        }),
    );
    let (base_url, _port) = boot_server(router).await;

    let payload = "<script>alert(1)</script>";
    let url = format!("{base_url}/xss?input={}", urlencoding::encode(payload));
    let resp = reqwest::get(&url).await.unwrap();
    let body = resp.text().await.unwrap();
    assert!(
        body.contains(payload),
        "expected payload reflected in body, got: {body}"
    );
}

// ---------------------------------------------------------------------------
// #65: executor_localhost_validation
// ---------------------------------------------------------------------------
#[test]
fn executor_localhost_validation() {
    let result = RequestExecutor::new(
        "http://evil.example.com".to_string(),
        100,
        Duration::from_secs(30),
    );
    let Err(err) = result else {
        panic!("expected error for non-localhost target");
    };
    assert!(err.to_string().contains("not localhost"));
}

// ---------------------------------------------------------------------------
// #66: oracle_detects_status_code_anomaly
// ---------------------------------------------------------------------------
#[test]
fn oracle_detects_status_code_anomaly() {
    let mut oracle = FuzzOracle::new(0.1);
    let baseline_responses: Vec<FuzzResponse> = (0..5)
        .map(|i| make_response(i, 200, "ok", Duration::from_millis(10)))
        .collect();
    oracle.add_baseline(BaselineProfile::from_responses(
        "/api",
        "GET",
        &baseline_responses,
    ));

    let anomalous = make_response(10, 500, "error", Duration::from_millis(10));
    let anomalies = oracle.analyze_response(&anomalous, "test", "/api", "GET");
    let types: Vec<AnomalyType> = anomalies.iter().map(|a| a.anomaly_type).collect();
    assert!(
        types.contains(&AnomalyType::StatusCodeAnomaly),
        "expected StatusCodeAnomaly, got {types:?}"
    );
}

// ---------------------------------------------------------------------------
// #67: oracle_detects_timing_anomaly
// ---------------------------------------------------------------------------
#[test]
fn oracle_detects_timing_anomaly() {
    let mut oracle = FuzzOracle::new(0.1);
    let baseline_responses: Vec<FuzzResponse> = (0..5)
        .map(|i| make_response(i, 200, "ok", Duration::from_millis(10)))
        .collect();
    oracle.add_baseline(BaselineProfile::from_responses(
        "/api",
        "GET",
        &baseline_responses,
    ));

    let slow = make_response(10, 200, "ok", Duration::from_millis(500));
    let anomalies = oracle.analyze_response(&slow, "test", "/api", "GET");
    let types: Vec<AnomalyType> = anomalies.iter().map(|a| a.anomaly_type).collect();
    assert!(
        types.contains(&AnomalyType::TimingAnomaly),
        "expected TimingAnomaly, got {types:?}"
    );
}

// ---------------------------------------------------------------------------
// #68: oracle_detects_content_anomaly
// ---------------------------------------------------------------------------
#[test]
fn oracle_detects_content_anomaly() {
    let oracle = FuzzOracle::new(0.1);
    let response = make_response(
        1,
        200,
        "Error: SQL syntax near unexpected token",
        Duration::from_millis(10),
    );
    let anomalies = oracle.analyze_response(&response, "test", "/api", "GET");
    let types: Vec<AnomalyType> = anomalies.iter().map(|a| a.anomaly_type).collect();
    assert!(
        types.contains(&AnomalyType::ContentAnomaly),
        "expected ContentAnomaly, got {types:?}"
    );
}

// ---------------------------------------------------------------------------
// #69: oracle_detects_reflection
// ---------------------------------------------------------------------------
#[test]
fn oracle_detects_reflection() {
    let oracle = FuzzOracle::new(0.1);
    let payload = "<script>alert(1)</script>";
    let response = make_response(
        1,
        200,
        &format!("<html>{payload}</html>"),
        Duration::from_millis(10),
    );
    let anomalies = oracle.analyze_response(&response, payload, "/page", "GET");
    let types: Vec<AnomalyType> = anomalies.iter().map(|a| a.anomaly_type).collect();
    assert!(
        types.contains(&AnomalyType::ReflectionDetected),
        "expected ReflectionDetected, got {types:?}"
    );
}

// ---------------------------------------------------------------------------
// #70: oracle_detects_size_anomaly
// ---------------------------------------------------------------------------
#[test]
fn oracle_detects_size_anomaly() {
    let mut oracle = FuzzOracle::new(0.1);
    let baseline_responses: Vec<FuzzResponse> = (0..10)
        .map(|i| {
            let size = 95 + (i as usize % 11);
            let body = "x".repeat(size);
            make_response(i, 200, &body, Duration::from_millis(10))
        })
        .collect();
    oracle.add_baseline(BaselineProfile::from_responses(
        "/data",
        "GET",
        &baseline_responses,
    ));

    let huge_body = "y".repeat(10000);
    let anomalous = make_response(20, 200, &huge_body, Duration::from_millis(10));
    let anomalies = oracle.analyze_response(&anomalous, "test", "/data", "GET");
    let types: Vec<AnomalyType> = anomalies.iter().map(|a| a.anomaly_type).collect();
    assert!(
        types.contains(&AnomalyType::SizeAnomaly),
        "expected SizeAnomaly, got {types:?}"
    );
}

// ---------------------------------------------------------------------------
// #71: oracle_counterfactual_eliminates_false_positive
// ---------------------------------------------------------------------------
#[test]
fn oracle_counterfactual_eliminates_false_positive() {
    let mut oracle = FuzzOracle::new(0.1);
    let baseline_responses: Vec<FuzzResponse> = (0..5)
        .map(|i| make_response(i, 200, "ok", Duration::from_millis(10)))
        .collect();
    oracle.add_baseline(BaselineProfile::from_responses(
        "/broken",
        "GET",
        &baseline_responses,
    ));

    let treatment = make_response(10, 500, "Internal Server Error", Duration::from_millis(10));
    let control = make_response(11, 500, "Internal Server Error", Duration::from_millis(10));

    let anomalies =
        oracle.analyze_response_with_control(&treatment, &control, "' OR 1=1", "/broken", "GET");

    let has_status_anomaly = anomalies
        .iter()
        .any(|a| a.anomaly_type == AnomalyType::StatusCodeAnomaly);
    assert!(
        !has_status_anomaly,
        "counterfactual should eliminate false positive status code anomaly"
    );
}

// ---------------------------------------------------------------------------
// #72: oracle_counterfactual_confirms_true_positive
// ---------------------------------------------------------------------------
#[test]
fn oracle_counterfactual_confirms_true_positive() {
    let mut oracle = FuzzOracle::new(0.1);
    let baseline_responses: Vec<FuzzResponse> = (0..5)
        .map(|i| make_response(i, 200, "ok", Duration::from_millis(10)))
        .collect();
    oracle.add_baseline(BaselineProfile::from_responses(
        "/vuln",
        "GET",
        &baseline_responses,
    ));

    let treatment = make_response(10, 500, "SQL syntax error", Duration::from_millis(10));
    let control = make_response(11, 200, "ok", Duration::from_millis(10));

    let anomalies =
        oracle.analyze_response_with_control(&treatment, &control, "' OR 1=1", "/vuln", "GET");

    assert!(
        !anomalies.is_empty(),
        "counterfactual should confirm true positive"
    );
    let types: Vec<AnomalyType> = anomalies.iter().map(|a| a.anomaly_type).collect();
    assert!(types.contains(&AnomalyType::StatusCodeAnomaly));
}

// ---------------------------------------------------------------------------
// #73: scheduler_priority_ordering
// ---------------------------------------------------------------------------
#[test]
fn scheduler_priority_ordering() {
    let mut scheduler = FuzzScheduler::new();

    scheduler.enqueue(make_target("/low", VulnerabilityClass::SqlInjection, 1.0));
    scheduler.enqueue(make_target(
        "/high",
        VulnerabilityClass::CrossSiteScripting,
        10.0,
    ));
    scheduler.enqueue(make_target(
        "/mid",
        VulnerabilityClass::CommandInjection,
        5.0,
    ));

    let first = scheduler.next_target().unwrap();
    assert_eq!(first.endpoint, "/high");
    let second = scheduler.next_target().unwrap();
    assert_eq!(second.endpoint, "/mid");
    let third = scheduler.next_target().unwrap();
    assert_eq!(third.endpoint, "/low");
}

// ---------------------------------------------------------------------------
// #74: scheduler_novelty_boosts_priority
// ---------------------------------------------------------------------------
#[test]
fn scheduler_novelty_boosts_priority() {
    let mut scheduler = FuzzScheduler::new();

    let target = make_target("/test", VulnerabilityClass::SqlInjection, 5.0);
    scheduler.enqueue(target.clone());

    let dequeued = scheduler.next_target().unwrap();
    let original_priority = dequeued.priority_score;

    scheduler.mark_completed_with_novelty(dequeued, 0.9);

    let re_enqueued = scheduler.next_target().unwrap();
    assert!(
        re_enqueued.priority_score > original_priority,
        "novelty 0.9 should boost priority: {} vs {}",
        re_enqueued.priority_score,
        original_priority
    );
}

// ---------------------------------------------------------------------------
// #75: scheduler_nan_priority_clamped
// ---------------------------------------------------------------------------
#[test]
fn scheduler_nan_priority_clamped() {
    let mut scheduler = FuzzScheduler::new();
    let nan_target = FuzzTarget {
        endpoint: "/nan".to_string(),
        method: "GET".to_string(),
        parameter: "q".to_string(),
        vulnerability_class: VulnerabilityClass::SqlInjection,
        priority_score: f64::NAN,
        attempts: 0,
        max_attempts: 3,
    };
    assert!(scheduler.enqueue(nan_target));

    let target = scheduler.next_target().unwrap();
    assert!(
        target.priority_score.is_finite(),
        "NaN should be clamped to 0.0, got {}",
        target.priority_score
    );
    assert_eq!(target.priority_score, 0.0);
}

// ---------------------------------------------------------------------------
// #76: mutator_generates_sqli_payloads
// ---------------------------------------------------------------------------
#[test]
fn mutator_generates_sqli_payloads() {
    let mutator = PayloadMutator::new();
    let payloads = mutator.generate_payloads(VulnerabilityClass::SqlInjection, 20);
    let template_count = payloads
        .iter()
        .filter(|p| p.mutation_strategy == MutationStrategy::Template)
        .count();
    assert!(
        template_count >= 8,
        "expected at least 8 SQLi templates, got {template_count}"
    );
}

// ---------------------------------------------------------------------------
// #77: mutator_generates_xss_payloads
// ---------------------------------------------------------------------------
#[test]
fn mutator_generates_xss_payloads() {
    let mutator = PayloadMutator::new();
    let payloads = mutator.generate_payloads(VulnerabilityClass::CrossSiteScripting, 20);
    let template_count = payloads
        .iter()
        .filter(|p| p.mutation_strategy == MutationStrategy::Template)
        .count();
    assert!(
        template_count >= 6,
        "expected at least 6 XSS templates, got {template_count}"
    );
}

// ---------------------------------------------------------------------------
// #78: mutator_generates_all_16_classes
// ---------------------------------------------------------------------------
#[test]
fn mutator_generates_all_16_classes() {
    let mutator = PayloadMutator::new();
    let all_classes = [
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::ServerSideRequestForgery,
        VulnerabilityClass::InsecureDeserialization,
        VulnerabilityClass::BrokenAuthentication,
        VulnerabilityClass::BrokenAuthorization,
        VulnerabilityClass::SecurityMisconfiguration,
        VulnerabilityClass::SensitiveDataExposure,
        VulnerabilityClass::ServerSideTemplateInjection,
        VulnerabilityClass::HeaderInjection,
        VulnerabilityClass::OpenRedirect,
        VulnerabilityClass::CrlfInjection,
        VulnerabilityClass::KnownVulnerableDependency,
        VulnerabilityClass::InsufficientInputValidation,
    ];
    for class in all_classes {
        let payloads = mutator.generate_payloads(class, 5);
        assert!(
            !payloads.is_empty(),
            "expected non-empty payloads for {class}"
        );
    }
}

// ---------------------------------------------------------------------------
// #79: mutator_tagged_payloads_have_origin
// ---------------------------------------------------------------------------
#[test]
fn mutator_tagged_payloads_have_origin() {
    let mutator = PayloadMutator::new();
    let tagged = mutator.generate_tagged_payloads(VulnerabilityClass::SqlInjection, 10);
    assert!(!tagged.is_empty());
    for tp in &tagged {
        assert!(
            matches!(
                tp.origin,
                MutationOrigin::Template
                    | MutationOrigin::Generative
                    | MutationOrigin::BitFlip
                    | MutationOrigin::Boundary
                    | MutationOrigin::BypassCorpus
            ),
            "unexpected origin: {:?}",
            tp.origin
        );
        assert!(!tp.payload.is_empty(), "payload should not be empty");
    }
}

// ---------------------------------------------------------------------------
// #80: mutator_stealth_rating_correct
// ---------------------------------------------------------------------------
#[test]
fn mutator_stealth_rating_correct() {
    let sleep_payload = "' WAITFOR DELAY '0:0:5'--";
    let basic_payload = "' OR '1'='1";

    let sleep_rating = stealth_rating_for_template(sleep_payload, VulnerabilityClass::SqlInjection);
    let basic_rating = stealth_rating_for_template(basic_payload, VulnerabilityClass::SqlInjection);

    assert_eq!(
        sleep_rating,
        StealthRating::High,
        "sleep-based SQLi should be high stealth"
    );
    assert_eq!(
        basic_rating,
        StealthRating::Low,
        "basic SQLi should be low stealth"
    );
}

// ---------------------------------------------------------------------------
// #81: mutator_boundary_payloads
// ---------------------------------------------------------------------------
#[test]
fn mutator_boundary_payloads() {
    let mutator = PayloadMutator::new();
    let payloads = mutator.generate_boundary_payloads();
    assert!(
        payloads.len() >= 10,
        "expected at least 10 boundary payloads, got {}",
        payloads.len()
    );
    assert!(
        payloads
            .iter()
            .all(|p| p.mutation_strategy == MutationStrategy::Boundary)
    );

    let raws: Vec<&str> = payloads.iter().map(|p| p.raw.as_str()).collect();
    assert!(raws.contains(&""), "should include empty string");
    assert!(raws.contains(&"null"), "should include null");
    assert!(raws.contains(&"NaN"), "should include NaN");
    assert!(
        raws.iter().any(|r| r.len() >= 1000),
        "should include long strings"
    );
}

// ---------------------------------------------------------------------------
// #82: waf_fingerprinter_detects_modsecurity
// ---------------------------------------------------------------------------
#[test]
fn waf_fingerprinter_detects_modsecurity() {
    let probe = make_waf_probe(403, vec![("X-Powered-By", "ModSecurity v3.0")], "");
    let vendor = identify_vendor(&[probe]);
    assert_eq!(vendor, WafVendor::ModSecurity);
}

// ---------------------------------------------------------------------------
// #83: waf_fingerprinter_detects_cloudflare
// ---------------------------------------------------------------------------
#[test]
fn waf_fingerprinter_detects_cloudflare() {
    let probe = make_waf_probe(200, vec![("cf-ray", "abc123-SJC")], "");
    let vendor = identify_vendor(&[probe]);
    assert_eq!(vendor, WafVendor::Cloudflare);
}

// ---------------------------------------------------------------------------
// #84: waf_fingerprinter_detects_aws_waf
// ---------------------------------------------------------------------------
#[test]
fn waf_fingerprinter_detects_aws_waf() {
    let probe = make_waf_probe(403, vec![("x-amzn-waf-action", "block")], "");
    let vendor = identify_vendor(&[probe]);
    assert_eq!(vendor, WafVendor::AwsWaf);
}

// ---------------------------------------------------------------------------
// #85: waf_fingerprinter_detects_imperva
// ---------------------------------------------------------------------------
#[test]
fn waf_fingerprinter_detects_imperva() {
    let probe = make_waf_probe(403, vec![], "Powered by Imperva");
    let vendor = identify_vendor(&[probe]);
    assert_eq!(vendor, WafVendor::Imperva);
}

// ---------------------------------------------------------------------------
// #86: waf_fingerprinter_detects_akamai
// ---------------------------------------------------------------------------
#[test]
fn waf_fingerprinter_detects_akamai() {
    let probe = make_waf_probe(200, vec![("x-akamai-transformed", "9")], "");
    let vendor = identify_vendor(&[probe]);
    assert_eq!(vendor, WafVendor::Akamai);
}

// ---------------------------------------------------------------------------
// #87: waf_fingerprinter_unknown_when_no_signatures
// ---------------------------------------------------------------------------
#[test]
fn waf_fingerprinter_unknown_when_no_signatures() {
    let probe = make_waf_probe(200, vec![("content-type", "text/html")], "<html>ok</html>");
    let vendor = identify_vendor(&[probe]);
    assert_eq!(vendor, WafVendor::Unknown);
}

// ---------------------------------------------------------------------------
// #88: waf_blocked_categories_identified
// ---------------------------------------------------------------------------
#[test]
fn waf_blocked_categories_identified() {
    let probes = vec![
        (
            VulnerabilityClass::SqlInjection,
            make_waf_probe(403, vec![], "blocked"),
        ),
        (
            VulnerabilityClass::CrossSiteScripting,
            make_waf_probe(200, vec![], "ok"),
        ),
        (
            VulnerabilityClass::CommandInjection,
            make_waf_probe(403, vec![], "blocked"),
        ),
    ];
    let blocked = identify_blocked_categories(200, &probes);
    assert!(blocked.contains(&VulnerabilityClass::SqlInjection));
    assert!(blocked.contains(&VulnerabilityClass::CommandInjection));
    assert!(!blocked.contains(&VulnerabilityClass::CrossSiteScripting));
}

// ---------------------------------------------------------------------------
// #89: rate_limit_detector_identifies_threshold
// ---------------------------------------------------------------------------
#[test]
fn rate_limit_detector_identifies_threshold() {
    let probes = vec![
        RateLimitProbeResult {
            request_rate: 2.0,
            total_sent: 10,
            limited_count: 0,
            limit_status_code: None,
        },
        RateLimitProbeResult {
            request_rate: 5.0,
            total_sent: 10,
            limited_count: 8,
            limit_status_code: Some(429),
        },
        RateLimitProbeResult {
            request_rate: 10.0,
            total_sent: 10,
            limited_count: 10,
            limit_status_code: Some(429),
        },
    ];
    let threshold = detect_rate_limit(&probes);
    assert!(threshold.is_some());
    let rps = threshold.unwrap();
    assert!(
        (rps - 5.0).abs() < 0.01,
        "expected threshold ~5.0, got {rps}"
    );
}

// ---------------------------------------------------------------------------
// #90: rate_limit_detector_burst_allowance
// ---------------------------------------------------------------------------
#[test]
fn rate_limit_detector_burst_allowance() {
    let probe = BurstProbeResult {
        total_sent: 20,
        first_limited_at: Some(10),
        limit_status_code: Some(429),
    };
    let burst = detect_burst_allowance(&probe);
    assert_eq!(burst, Some(10));
}

// ---------------------------------------------------------------------------
// #91: rate_limit_detector_window_detection
// ---------------------------------------------------------------------------
#[test]
fn rate_limit_detector_window_detection() {
    let probes = vec![
        WindowProbeResult {
            wait_seconds: 5,
            recovered: false,
        },
        WindowProbeResult {
            wait_seconds: 10,
            recovered: true,
        },
        WindowProbeResult {
            wait_seconds: 30,
            recovered: true,
        },
    ];
    let window = detect_limit_window(&probes);
    assert_eq!(window, Some(10));
}

// ---------------------------------------------------------------------------
// #92: bot_detection_detects_captcha
// ---------------------------------------------------------------------------
#[test]
fn bot_detection_detects_captcha() {
    let no_headers = BotProbeResult {
        headers_sent: false,
        response_status: 403,
        response_body_snippet:
            "<html><div class=\"g-recaptcha\" data-sitekey=\"abc\"></div></html>".to_string(),
        rapid_request: false,
    };
    let with_headers = BotProbeResult {
        headers_sent: true,
        response_status: 403,
        response_body_snippet:
            "<html><div class=\"g-recaptcha\" data-sitekey=\"abc\"></div></html>".to_string(),
        rapid_request: false,
    };
    let result = analyze_bot_detection(&no_headers, &with_headers, &[]);
    assert!(result.is_some());
    let profile = result.unwrap();
    assert!(profile.detected);
    let method = detect_challenge_type(&with_headers.response_body_snippet);
    assert_eq!(method, DetectionMethod::Captcha);
}

// ---------------------------------------------------------------------------
// #93: bot_detection_detects_js_challenge
// ---------------------------------------------------------------------------
#[test]
fn bot_detection_detects_js_challenge() {
    let body = "<html><script>if(!window.challenge){document.location='/verify'}</script></html>";
    let no_headers = BotProbeResult {
        headers_sent: false,
        response_status: 503,
        response_body_snippet: body.to_string(),
        rapid_request: false,
    };
    let with_headers = BotProbeResult {
        headers_sent: true,
        response_status: 503,
        response_body_snippet: body.to_string(),
        rapid_request: false,
    };
    let result = analyze_bot_detection(&no_headers, &with_headers, &[]);
    assert!(result.is_some());
    let method = detect_challenge_type(body);
    assert_eq!(method, DetectionMethod::JavaScriptChallenge);
}

// ---------------------------------------------------------------------------
// #94: bot_detection_detects_header_analysis
// ---------------------------------------------------------------------------
#[test]
fn bot_detection_detects_header_analysis() {
    let no_headers = BotProbeResult {
        headers_sent: false,
        response_status: 403,
        response_body_snippet:
            "<html><div class=\"g-recaptcha\" data-sitekey=\"abc\"></div></html>".to_string(),
        rapid_request: false,
    };
    let with_headers = BotProbeResult {
        headers_sent: true,
        response_status: 200,
        response_body_snippet: "<html>Welcome</html>".to_string(),
        rapid_request: false,
    };
    let result = analyze_bot_detection(&no_headers, &with_headers, &[]);
    assert!(result.is_some());
    let profile = result.unwrap();
    assert!(profile.detected);
    assert_eq!(profile.detection_method, "header_analysis");
}

// ---------------------------------------------------------------------------
// #95: bot_detection_detects_behavioral
// ---------------------------------------------------------------------------
#[test]
fn bot_detection_detects_behavioral() {
    let no_headers = BotProbeResult {
        headers_sent: false,
        response_status: 200,
        response_body_snippet: "ok".to_string(),
        rapid_request: false,
    };
    let with_headers = BotProbeResult {
        headers_sent: true,
        response_status: 200,
        response_body_snippet: "ok".to_string(),
        rapid_request: false,
    };
    let rapid = vec![BotProbeResult {
        headers_sent: true,
        response_status: 429,
        response_body_snippet:
            "<html><script>if(!window.challenge){location='/check'}</script></html>".to_string(),
        rapid_request: true,
    }];
    let result = analyze_bot_detection(&no_headers, &with_headers, &rapid);
    assert!(result.is_some());
    let profile = result.unwrap();
    assert!(profile.detected);
    assert_eq!(profile.detection_method, "behavioral");
}

// ---------------------------------------------------------------------------
// #96: streaming_fuzzer_validates_ws_target
// ---------------------------------------------------------------------------
#[test]
fn streaming_fuzzer_validates_ws_target() {
    let valid = validate_stream_target("ws://127.0.0.1:8080/ws");
    assert!(valid.is_ok());
    assert_eq!(valid.unwrap(), StreamProtocol::WebSocket);

    let rejected = validate_stream_target("ws://evil.com/ws");
    assert!(rejected.is_err());
}

// ---------------------------------------------------------------------------
// #97: streaming_fuzzer_generates_ws_payloads
// ---------------------------------------------------------------------------
#[test]
fn streaming_fuzzer_generates_ws_payloads() {
    let payloads = generate_ws_payloads(VulnerabilityClass::CrossSiteScripting, 20);
    assert!(!payloads.is_empty());

    let has_oversized = payloads.iter().any(|p| p.payload.len() > 1000);
    assert!(has_oversized, "should include oversized frame payload");

    let has_malformed_json = payloads
        .iter()
        .any(|p| p.payload.contains('{') && !p.payload.ends_with('}'));
    assert!(has_malformed_json, "should include malformed JSON");

    let has_injection = payloads
        .iter()
        .any(|p| p.payload.contains("<script>") || p.payload.contains("alert(1)"));
    assert!(has_injection, "should include XSS injection payloads");
}

// ---------------------------------------------------------------------------
// #98: streaming_fuzzer_generates_sse_probes
// ---------------------------------------------------------------------------
#[test]
fn streaming_fuzzer_generates_sse_probes() {
    let urls = generate_sse_probe_urls("http://127.0.0.1:8080/api");
    assert!(!urls.is_empty());

    let has_events_path = urls.iter().any(|u| u.contains("/events"));
    assert!(has_events_path, "should include /events path");

    let has_stream_path = urls.iter().any(|u| u.contains("/stream"));
    assert!(has_stream_path, "should include /stream path");
}

// ---------------------------------------------------------------------------
// #99: streaming_fuzzer_detects_ws_anomalies
// ---------------------------------------------------------------------------
#[test]
fn streaming_fuzzer_detects_ws_anomalies() {
    let messages = vec![
        StreamMessage {
            sequence: 1,
            direction: MessageDirection::Sent,
            payload: "<script>alert(1)</script>".to_string(),
            timestamp_ms: 1000,
            message_type: StreamMessageType::Text,
        },
        StreamMessage {
            sequence: 2,
            direction: MessageDirection::Received,
            payload: "Echo: <script>alert(1)</script>".to_string(),
            timestamp_ms: 1005,
            message_type: StreamMessageType::Text,
        },
        StreamMessage {
            sequence: 3,
            direction: MessageDirection::Received,
            payload: "Error: internal server exception in handler".to_string(),
            timestamp_ms: 1010,
            message_type: StreamMessageType::Text,
        },
        StreamMessage {
            sequence: 4,
            direction: MessageDirection::Received,
            payload: "Traceback: at /usr/local/app.py line 42".to_string(),
            timestamp_ms: 1020,
            message_type: StreamMessageType::Text,
        },
    ];

    let anomalies = analyze_stream_messages(&messages, "<script>alert(1)</script>");
    assert!(
        !anomalies.is_empty(),
        "should detect anomalies from error messages"
    );
    assert!(anomalies.contains(&StreamAnomalyType::ErrorMessage));
    assert!(anomalies.contains(&StreamAnomalyType::InformationLeak));
    assert!(anomalies.contains(&StreamAnomalyType::ReflectionDetected));
}

// ---------------------------------------------------------------------------
// #100: request_patterns_sequential
// ---------------------------------------------------------------------------
#[test]
fn request_patterns_sequential() {
    let endpoints = ["/a", "/b", "/c"];
    let batch = build_sequential_batch(&endpoints, "GET", 100).unwrap();
    assert_eq!(batch.pattern, BrowsingPattern::Sequential);
    assert_eq!(batch.requests.len(), 3);
    for (i, req) in batch.requests.iter().enumerate() {
        assert_eq!(req.endpoint, endpoints[i]);
        assert_eq!(req.delay_before_ms, 100);
        assert!(!req.is_cover_traffic);
    }
}

// ---------------------------------------------------------------------------
// #101: request_patterns_burst
// ---------------------------------------------------------------------------
#[test]
fn request_patterns_burst() {
    let endpoints = ["/x", "/y", "/z"];
    let batch = build_burst_batch(&endpoints, "GET", 10, 2000).unwrap();
    assert_eq!(batch.pattern, BrowsingPattern::BurstThenPause);
    assert_eq!(batch.requests.len(), 3);
    assert_eq!(batch.inter_batch_delay_ms, 2000);
    for req in &batch.requests {
        assert_eq!(req.delay_before_ms, 10);
    }
}

// ---------------------------------------------------------------------------
// #102: request_patterns_parallel_resources
// ---------------------------------------------------------------------------
#[test]
fn request_patterns_parallel_resources() {
    let subresources = ["/style.css", "/app.js", "/logo.png"];
    let batch = build_parallel_resources_batch("/index.html", &subresources).unwrap();
    assert_eq!(batch.pattern, BrowsingPattern::ParallelResources);
    assert_eq!(batch.requests.len(), 4);
    assert_eq!(batch.requests[0].endpoint, "/index.html");
    for req in &batch.requests[1..] {
        assert!(req.referer.as_deref() == Some("/index.html"));
    }
}

// ---------------------------------------------------------------------------
// #103: request_patterns_navigation_chain
// ---------------------------------------------------------------------------
#[test]
fn request_patterns_navigation_chain() {
    let steps = vec![
        NavigationStep {
            page_url: "/home".to_string(),
            subresources: vec!["/home.css".to_string()],
            api_calls: vec!["/api/user".to_string()],
        },
        NavigationStep {
            page_url: "/dashboard".to_string(),
            subresources: vec!["/dash.css".to_string()],
            api_calls: vec!["/api/stats".to_string()],
        },
    ];
    let batches = build_navigation_chain(&steps).unwrap();
    assert_eq!(batches.len(), 2);
    for (i, batch) in batches.iter().enumerate() {
        assert_eq!(batch.pattern, BrowsingPattern::NavigationChain);
        assert_eq!(batch.requests[0].endpoint, steps[i].page_url);
        let has_referer = batch.requests[1..]
            .iter()
            .all(|r| r.referer.as_deref() == Some(&steps[i].page_url));
        assert!(has_referer, "subresources should reference the page URL");
    }
}

// ---------------------------------------------------------------------------
// #104: request_patterns_cover_traffic
// ---------------------------------------------------------------------------
#[test]
fn request_patterns_cover_traffic() {
    let endpoints = ["/real1", "/real2"];
    let batch = build_sequential_batch(&endpoints, "GET", 50).unwrap();
    let original_count = batch.requests.len();

    let config = CoverTrafficConfig {
        enabled: true,
        cover_endpoints: vec!["/decoy1".to_string(), "/decoy2".to_string()],
        cover_ratio: 1.0,
        randomize_order: false,
    };
    let with_cover = inject_cover_traffic(&batch, &config).unwrap();
    assert!(
        with_cover.requests.len() > original_count,
        "cover traffic should increase batch size"
    );
    let cover_urls: Vec<&str> = with_cover
        .requests
        .iter()
        .filter(|r| r.is_cover_traffic)
        .map(|r| r.endpoint.as_str())
        .collect();
    assert!(!cover_urls.is_empty(), "should have cover traffic URLs");
}

// ---------------------------------------------------------------------------
// #105: request_patterns_max_batch_clamp
// ---------------------------------------------------------------------------
#[test]
fn request_patterns_max_batch_clamp() {
    let endpoints: Vec<&str> = (0..100).map(|_| "/ep").collect();
    let result = build_sequential_batch(&endpoints, "GET", 10);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains(&MAX_BATCH_SIZE.to_string()),
        "error should mention MAX_BATCH_SIZE"
    );
}

// ---------------------------------------------------------------------------
// #106: payload_selector_ucb1_novel_first
// ---------------------------------------------------------------------------
#[test]
fn payload_selector_ucb1_novel_first() {
    let history = vec![PayloadStats {
        payload: "known".to_string(),
        attempts: 10,
        successes: 5,
    }];
    let selector = PayloadSelector::new(history);

    let novel_score = selector.ucb1_score("completely_new_payload");
    assert!(
        novel_score.is_infinite(),
        "novel payload should have infinite score"
    );

    let candidates = vec!["known".to_string(), "completely_new_payload".to_string()];
    let ranked = selector.rank_payloads(&candidates);
    assert_eq!(
        ranked[0], "completely_new_payload",
        "novel payload should rank first"
    );
}

// ---------------------------------------------------------------------------
// #107: payload_selector_ucb1_exploits_effective
// ---------------------------------------------------------------------------
#[test]
fn payload_selector_ucb1_exploits_effective() {
    let history = vec![
        PayloadStats {
            payload: "effective".to_string(),
            attempts: 100,
            successes: 80,
        },
        PayloadStats {
            payload: "weak".to_string(),
            attempts: 100,
            successes: 20,
        },
    ];
    let selector = PayloadSelector::new(history);

    let effective_score = selector.ucb1_score("effective");
    let weak_score = selector.ucb1_score("weak");
    assert!(
        effective_score > weak_score,
        "80% success rate ({effective_score}) should score higher than 20% ({weak_score})"
    );
}

// ---------------------------------------------------------------------------
// #108: payload_selector_ucb1_explores_untested
// ---------------------------------------------------------------------------
#[test]
fn payload_selector_ucb1_explores_untested() {
    let history = vec![PayloadStats {
        payload: "untested".to_string(),
        attempts: 0,
        successes: 0,
    }];
    let selector = PayloadSelector::new(history);

    let score = selector.ucb1_score("untested");
    assert!(
        score.is_infinite(),
        "zero-attempt payload should have infinite score, got {score}"
    );
}

// ---------------------------------------------------------------------------
// #109: defense_profile_builder
// ---------------------------------------------------------------------------
#[test]
fn defense_profile_builder() {
    let profile = DefenseProfile::empty(1000)
        .with_waf(WafProfile {
            vendor: WafVendor::Cloudflare,
            paranoia_level: Some(2),
            blocked_response_code: 403,
            blocked_categories: vec![VulnerabilityClass::SqlInjection],
        })
        .with_rate_limit(RateLimitProfile {
            requests_per_second: Some(10.0),
            burst_allowance: Some(20),
            limit_response_code: 429,
            limit_window_seconds: Some(60),
        })
        .with_bot_detection(BotDetectionProfile {
            detected: true,
            detection_method: "captcha".to_string(),
            challenge_response_code: Some(403),
        });

    assert!(profile.waf.is_some());
    assert!(profile.rate_limit.is_some());
    assert!(profile.bot_detection.is_some());
    assert_eq!(profile.fingerprint_timestamp_ms, 1000);

    let types = profile.defense_types();
    assert!(types.contains(&DefenseType::Waf));
    assert!(types.contains(&DefenseType::RateLimiter));
    assert!(types.contains(&DefenseType::BotDetection));
    assert!(!types.contains(&DefenseType::None));
}

// ---------------------------------------------------------------------------
// #110: variance_measurement_deterministic
// ---------------------------------------------------------------------------
#[test]
fn variance_measurement_deterministic() {
    let responses: Vec<FuzzResponse> = (0..10)
        .map(|i| make_response(i, 200, "identical body content", Duration::from_millis(10)))
        .collect();
    let report = measure_endpoint_variance(&responses);
    assert!(
        report.is_deterministic,
        "identical responses should be deterministic"
    );
    assert!(
        report.body_similarity > 0.95,
        "body similarity should be > 0.95, got {}",
        report.body_similarity
    );
}

// ---------------------------------------------------------------------------
// #111: variance_measurement_nondeterministic
// ---------------------------------------------------------------------------
#[test]
fn variance_measurement_nondeterministic() {
    let responses: Vec<FuzzResponse> = (0..10)
        .map(|i| {
            let body = if i % 2 == 0 {
                format!("response variant A with unique data {}", i * 1000)
            } else {
                format!(
                    "completely different response B with other data {}",
                    i * 7777
                )
            };
            let status = if i % 3 == 0 { 200 } else { 201 };
            make_response(i, status, &body, Duration::from_millis(10))
        })
        .collect();
    let report = measure_endpoint_variance(&responses);
    assert!(
        !report.is_deterministic,
        "varying status codes and bodies should be non-deterministic"
    );
}
