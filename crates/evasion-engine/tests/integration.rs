use std::collections::HashSet;
use std::net::SocketAddr;

use aegis_evasion_engine::{
    EncodingStrategy, EncodingTransformer, EvasionTransport, FingerprintMapping, HeaderTransformer,
    HttpClientConfig, JitterDistribution, Persona, PersonaId, SessionManager, TimingController,
    TlsConfig, TlsFingerprint, TlsVersion, ja3_hash, persona_catalog, persona_tls_config,
};
use aegis_protocol::request::FuzzRequest;

async fn start_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/{*path}",
            axum::routing::any(|headers: axum::http::HeaderMap, body: String| async move {
                let mut header_lines: Vec<String> = headers
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("")))
                    .collect();
                header_lines.sort();
                let header_dump = header_lines.join("\n");
                format!("HEADERS:\n{header_dump}\nBODY:\n{body}")
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}

// ---------------------------------------------------------------------------
// #112 transport_sends_to_live_server
// ---------------------------------------------------------------------------
#[tokio::test]
async fn transport_sends_to_live_server() {
    let (addr, _handle) = start_echo_server().await;
    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let request = FuzzRequest {
        request_id: 112,
        endpoint: format!("http://{addr}/test"),
        method: "GET".to_string(),
        parameter_name: "q".to_string(),
        payload: "hello".to_string(),
        headers: vec![],
    };

    let response = transport.send(&request).await.unwrap();
    assert_eq!(response.status_code, 200);
    assert!(response.body.contains("HEADERS:"));
    assert!(response.request_id == 112);
}

// ---------------------------------------------------------------------------
// #113 transport_applies_persona_headers
// ---------------------------------------------------------------------------
#[tokio::test]
async fn transport_applies_persona_headers() {
    let (addr, _handle) = start_echo_server().await;

    let catalog = persona_catalog();
    let chrome = catalog
        .iter()
        .find(|p| p.id == PersonaId::ChromeDesktop)
        .unwrap();

    let mut transport = EvasionTransport::builder()
        .with_persona(chrome)
        .with_timing_seed(0)
        .build();

    let request = FuzzRequest {
        request_id: 113,
        endpoint: format!("http://{addr}/headers"),
        method: "GET".to_string(),
        parameter_name: "x".to_string(),
        payload: "y".to_string(),
        headers: vec![],
    };

    let response = transport.send(&request).await.unwrap();
    let body_lower = response.body.to_lowercase();
    assert!(
        body_lower.contains("chrome"),
        "Chrome UA should appear in request headers, body was: {}",
        response.body
    );
    assert!(
        body_lower.contains("sec-fetch"),
        "Sec-Fetch headers should appear for ChromeDesktop, body was: {}",
        response.body
    );
}

// ---------------------------------------------------------------------------
// #114 transport_rotates_personas
// ---------------------------------------------------------------------------
#[tokio::test]
async fn transport_rotates_personas() {
    let (addr, _handle) = start_echo_server().await;

    let mut transport = EvasionTransport::builder()
        .with_max_requests_per_session(1)
        .with_persona_rotation(1)
        .with_timing_seed(0)
        .build();

    let mut seen_persona_ids = HashSet::new();

    for i in 0..10 {
        seen_persona_ids.insert(transport.persona_id());

        let request = FuzzRequest {
            request_id: 1140 + i,
            endpoint: format!("http://{addr}/rotate"),
            method: "GET".to_string(),
            parameter_name: "n".to_string(),
            payload: i.to_string(),
            headers: vec![],
        };

        transport.send(&request).await.unwrap();
    }
    seen_persona_ids.insert(transport.persona_id());

    assert!(
        seen_persona_ids.len() >= 2,
        "expected multiple distinct personas, saw {seen_persona_ids:?}"
    );
}

// ---------------------------------------------------------------------------
// #115 transport_localhost_enforcement
// ---------------------------------------------------------------------------
#[tokio::test]
async fn transport_localhost_enforcement() {
    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let request = FuzzRequest {
        request_id: 115,
        endpoint: "http://example.com/evil".to_string(),
        method: "GET".to_string(),
        parameter_name: "q".to_string(),
        payload: "test".to_string(),
        headers: vec![],
    };

    let result = transport.send(&request).await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not localhost"),
        "error should mention localhost enforcement, got: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// #116 persona_catalog_loads_all_10
// ---------------------------------------------------------------------------
#[test]
fn persona_catalog_loads_all_10() {
    let catalog = persona_catalog();
    assert_eq!(catalog.len(), 10);

    let ids: HashSet<PersonaId> = catalog.iter().map(|p| p.id).collect();
    assert_eq!(ids.len(), 10);

    for persona in &catalog {
        assert!(!persona.user_agent.is_empty());
        assert!(!persona.accept_header.is_empty());
        assert!(!persona.header_order.is_empty());
    }
}

// ---------------------------------------------------------------------------
// #117 persona_chrome_desktop_headers
// ---------------------------------------------------------------------------
#[test]
fn persona_chrome_desktop_headers() {
    let catalog = persona_catalog();
    let chrome = catalog
        .iter()
        .find(|p| p.id == PersonaId::ChromeDesktop)
        .unwrap();

    assert!(chrome.user_agent.contains("Chrome/"));
    assert!(chrome.accept_header.contains("text/html"));
    assert!(chrome.accept_language.contains("en-US"));

    let sec_fetch_names: Vec<&str> = chrome
        .sec_fetch_headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect();
    assert!(sec_fetch_names.contains(&"Sec-Fetch-Site"));
    assert!(sec_fetch_names.contains(&"Sec-Fetch-Mode"));
    assert!(sec_fetch_names.contains(&"Sec-Fetch-Dest"));
}

// ---------------------------------------------------------------------------
// #118 persona_firefox_desktop_headers
// ---------------------------------------------------------------------------
#[test]
fn persona_firefox_desktop_headers() {
    let catalog = persona_catalog();
    let firefox = catalog
        .iter()
        .find(|p| p.id == PersonaId::FirefoxDesktop)
        .unwrap();

    assert!(
        firefox.user_agent.contains("Firefox/"),
        "Firefox UA expected, got: {}",
        firefox.user_agent
    );
    assert!(firefox.accept_header.contains("text/html"));

    let chrome = catalog
        .iter()
        .find(|p| p.id == PersonaId::ChromeDesktop)
        .unwrap();
    assert_ne!(
        firefox.header_order, chrome.header_order,
        "Firefox should have different header order than Chrome"
    );
}

// ---------------------------------------------------------------------------
// #119 persona_curl_minimal_headers
// ---------------------------------------------------------------------------
#[test]
fn persona_curl_minimal_headers() {
    let catalog = persona_catalog();
    let curl = catalog
        .iter()
        .find(|p| p.id == PersonaId::CurlClient)
        .unwrap();

    assert!(
        curl.user_agent.contains("curl/"),
        "curl UA expected, got: {}",
        curl.user_agent
    );
    assert_eq!(curl.accept_header, "*/*");
    assert!(
        curl.sec_fetch_headers.is_empty(),
        "curl should have no Sec-Fetch headers"
    );
}

// ---------------------------------------------------------------------------
// #120 persona_googlebot_headers
// ---------------------------------------------------------------------------
#[test]
fn persona_googlebot_headers() {
    let catalog = persona_catalog();
    let bot = catalog
        .iter()
        .find(|p| p.id == PersonaId::Googlebot)
        .unwrap();

    assert!(
        bot.user_agent.contains("Googlebot"),
        "Googlebot UA expected, got: {}",
        bot.user_agent
    );
    assert!(
        bot.sec_fetch_headers.is_empty(),
        "Googlebot should have no Sec-Fetch headers"
    );
}

// ---------------------------------------------------------------------------
// #121 header_transformer_applies_transforms
// ---------------------------------------------------------------------------
#[test]
fn header_transformer_applies_transforms() {
    let transformer = HeaderTransformer::new();
    let catalog = persona_catalog();
    let chrome = catalog
        .iter()
        .find(|p| p.id == PersonaId::ChromeDesktop)
        .unwrap();

    let result = transformer.transform(&[], chrome);

    let find_header = |name: &str| {
        result
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };

    assert!(find_header("User-Agent").unwrap().contains("Chrome/"));
    assert!(find_header("Accept").is_some());
    assert!(find_header("Accept-Language").is_some());
    assert!(find_header("Accept-Encoding").is_some());
    assert!(find_header("Sec-Fetch-Site").is_some());
}

// ---------------------------------------------------------------------------
// #122 header_transformer_preserves_custom_headers
// ---------------------------------------------------------------------------
#[test]
fn header_transformer_preserves_custom_headers() {
    let transformer = HeaderTransformer::new();
    let catalog = persona_catalog();
    let chrome = catalog
        .iter()
        .find(|p| p.id == PersonaId::ChromeDesktop)
        .unwrap();

    let custom = vec![("X-Custom-Token".to_string(), "secret-123".to_string())];
    let result = transformer.transform(&custom, chrome);

    let custom_header = result
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-custom-token"));
    assert!(custom_header.is_some());
    assert_eq!(custom_header.unwrap().1, "secret-123");

    assert!(
        result
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("user-agent")),
        "persona headers should also be present"
    );
}

// ---------------------------------------------------------------------------
// #123 encoding_transformer_url_encodes
// ---------------------------------------------------------------------------
#[test]
fn encoding_transformer_url_encodes() {
    let transformer = EncodingTransformer::new();
    let payload = "<script>alert('xss')</script>";
    let results = transformer.encode(
        payload,
        aegis_protocol::finding::VulnerabilityClass::CrossSiteScripting,
    );

    let double_url = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::DoubleUrlEncoding)
        .expect("DoubleUrlEncoding strategy should be present for XSS");

    assert!(double_url.encoded.contains("%253C"));
    assert!(double_url.encoded.contains("%253E"));
    assert!(double_url.encoded.contains("%2527"));
    assert_eq!(double_url.original, payload);
}

// ---------------------------------------------------------------------------
// #124 encoding_transformer_double_encodes
// ---------------------------------------------------------------------------
#[test]
fn encoding_transformer_double_encodes() {
    let transformer = EncodingTransformer::new();
    let payload = "test value/path";
    let results = transformer.encode(
        payload,
        aegis_protocol::finding::VulnerabilityClass::SqlInjection,
    );

    let double_url = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::DoubleUrlEncoding)
        .expect("DoubleUrlEncoding strategy should be present for SQLi");

    assert!(
        double_url.encoded.contains("%2520"),
        "space should be double-encoded to %2520, got: {}",
        double_url.encoded
    );
    assert!(
        double_url.encoded.contains("%252F"),
        "slash should be double-encoded to %252F, got: {}",
        double_url.encoded
    );
}

// ---------------------------------------------------------------------------
// #125 timing_controller_applies_jitter
// ---------------------------------------------------------------------------
#[test]
fn timing_controller_applies_jitter() {
    let persona = Persona::custom(PersonaId::ChromeDesktop)
        .with_user_agent("test")
        .with_accept_header("*/*")
        .with_request_interval(100, 500)
        .with_jitter_distribution(JitterDistribution::Uniform)
        .build();

    let mut controller = TimingController::from_persona(&persona, 42);

    assert_eq!(
        controller.compute_delay_ms(),
        0,
        "first call should return 0"
    );

    controller.record_request();

    let delays: Vec<u64> = (0..20).map(|_| controller.compute_delay_ms()).collect();

    for delay in &delays {
        assert!(
            *delay >= 100 && *delay <= 500,
            "delay {delay} out of persona range [100, 500]"
        );
    }

    let unique: HashSet<u64> = delays.iter().copied().collect();
    assert!(
        unique.len() > 1,
        "expected jitter variation, all delays were identical: {delays:?}"
    );
}

// ---------------------------------------------------------------------------
// #126 timing_controller_normal_distribution
// ---------------------------------------------------------------------------
#[test]
fn timing_controller_normal_distribution() {
    let mut controller = TimingController::new(100, 500, JitterDistribution::Normal, 42);
    controller.record_request();

    let delays: Vec<u64> = (0..500).map(|_| controller.compute_delay_ms()).collect();
    let mean = 300u64;
    let near_mean = delays.iter().filter(|d| d.abs_diff(mean) <= 100).count();

    assert!(
        near_mean > delays.len() / 3,
        "Normal distribution should cluster around mean 300: {near_mean}/{} within 100 of mean",
        delays.len()
    );
}

// ---------------------------------------------------------------------------
// #127 timing_controller_exponential_distribution
// ---------------------------------------------------------------------------
#[test]
fn timing_controller_exponential_distribution() {
    let mut controller = TimingController::new(100, 500, JitterDistribution::Exponential, 42);
    controller.record_request();

    let delays: Vec<u64> = (0..500).map(|_| controller.compute_delay_ms()).collect();
    let midpoint = (100 + 500) / 2;
    let below_mid = delays.iter().filter(|d| **d < midpoint).count();

    assert!(
        below_mid > delays.len() / 3,
        "Exponential distribution should skew toward minimum: {below_mid}/{} below midpoint {midpoint}",
        delays.len()
    );
}

// ---------------------------------------------------------------------------
// #128 session_manager_rotates_cookies
// ---------------------------------------------------------------------------
#[test]
fn session_manager_rotates_cookies() {
    let mut manager = SessionManager::new(3);

    manager.process_set_cookie("sid=aaa");
    manager.record_request("http://localhost/1");
    manager.record_request("http://localhost/2");

    let headers_before = manager.session_headers();
    let cookie_before = headers_before
        .iter()
        .find(|(k, _)| k == "Cookie")
        .map(|(_, v)| v.clone());
    assert!(
        cookie_before.is_some(),
        "cookies should be present before rotation"
    );

    manager.record_request("http://localhost/3");
    assert_eq!(
        manager.session_id(),
        1,
        "session should have rotated at threshold"
    );

    let headers_after = manager.session_headers();
    let cookie_after = headers_after
        .iter()
        .find(|(k, _)| k == "Cookie")
        .map(|(_, v)| v.clone());
    assert!(
        cookie_after.is_none(),
        "cookies should be cleared after rotation"
    );
}

// ---------------------------------------------------------------------------
// #129 session_manager_preserves_session_within_window
// ---------------------------------------------------------------------------
#[test]
fn session_manager_preserves_session_within_window() {
    let mut manager = SessionManager::new(50);

    manager.process_set_cookie("token=xyz123");

    for i in 0..10 {
        manager.record_request(&format!("http://localhost/{i}"));
    }

    assert_eq!(manager.session_id(), 0, "session should not have rotated");

    let headers = manager.session_headers();
    let cookie = headers.iter().find(|(k, _)| k == "Cookie");
    assert!(cookie.is_some(), "cookies should persist within window");
    assert!(
        cookie.unwrap().1.contains("token=xyz123"),
        "original cookie value should be preserved"
    );
}

// ---------------------------------------------------------------------------
// #130 tls_fingerprint_mapping_all_personas
// ---------------------------------------------------------------------------
#[test]
fn tls_fingerprint_mapping_all_personas() {
    let mapping = FingerprintMapping::all_personas();
    assert_eq!(mapping.mapping.len(), 10);

    assert_eq!(
        mapping.mapping[&PersonaId::ChromeDesktop],
        TlsFingerprint::Chrome120
    );
    assert_eq!(
        mapping.mapping[&PersonaId::FirefoxDesktop],
        TlsFingerprint::Firefox121
    );
    assert_eq!(
        mapping.mapping[&PersonaId::SafariDesktop],
        TlsFingerprint::Safari17
    );
    assert_eq!(
        mapping.mapping[&PersonaId::EdgeDesktop],
        TlsFingerprint::Edge120
    );
    assert_eq!(
        mapping.mapping[&PersonaId::CurlClient],
        TlsFingerprint::Curl
    );

    for persona_id in [
        PersonaId::ChromeDesktop,
        PersonaId::FirefoxDesktop,
        PersonaId::SafariDesktop,
        PersonaId::ChromeMobile,
        PersonaId::Googlebot,
        PersonaId::EdgeDesktop,
        PersonaId::OperaDesktop,
        PersonaId::SafariMobile,
        PersonaId::CurlClient,
        PersonaId::PythonRequests,
    ] {
        assert!(
            mapping.mapping.contains_key(&persona_id),
            "mapping should contain {persona_id:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// #131 tls_chrome_edge_share_ja3
// ---------------------------------------------------------------------------
#[test]
fn tls_chrome_edge_share_ja3() {
    let chrome_ja3 = ja3_hash(&TlsFingerprint::Chrome120);
    let edge_ja3 = ja3_hash(&TlsFingerprint::Edge120);
    assert_eq!(
        chrome_ja3, edge_ja3,
        "Chrome120 and Edge120 should share JA3 (Chromium-based)"
    );
    assert!(!chrome_ja3.is_empty(), "JA3 hashes should be non-empty");
}

// ---------------------------------------------------------------------------
// #132 tls_firefox_different_ja3
// ---------------------------------------------------------------------------
#[test]
fn tls_firefox_different_ja3() {
    let firefox_ja3 = ja3_hash(&TlsFingerprint::Firefox121);
    let chrome_ja3 = ja3_hash(&TlsFingerprint::Chrome120);
    assert_ne!(
        firefox_ja3, chrome_ja3,
        "Firefox121 JA3 should differ from Chrome120"
    );
}

// ---------------------------------------------------------------------------
// #133 tls_config_builder_chain
// ---------------------------------------------------------------------------
#[test]
fn tls_config_builder_chain() {
    let config = TlsConfig::default()
        .with_fingerprint(TlsFingerprint::Chrome120)
        .with_min_tls_version(TlsVersion::Tls13)
        .with_http2(false)
        .with_accept_invalid_certs(true);

    assert_eq!(config.fingerprint, TlsFingerprint::Chrome120);
    assert_eq!(config.min_tls_version, TlsVersion::Tls13);
    assert!(!config.enable_http2);
    assert!(config.accept_invalid_certs);
}

// ---------------------------------------------------------------------------
// #134 http_client_config_serialization
// ---------------------------------------------------------------------------
#[test]
fn http_client_config_serialization() {
    let original = HttpClientConfig::default()
        .with_timeout_ms(60000)
        .with_max_redirects(5)
        .with_user_agent("test-agent/1.0".to_string())
        .with_tls(
            TlsConfig::default()
                .with_fingerprint(TlsFingerprint::Firefox121)
                .with_min_tls_version(TlsVersion::Tls13),
        );

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: HttpClientConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.timeout_ms, original.timeout_ms);
    assert_eq!(deserialized.max_redirects, original.max_redirects);
    assert_eq!(deserialized.user_agent, original.user_agent);
    assert_eq!(deserialized.backend, original.backend);
    assert_eq!(deserialized.tls.fingerprint, original.tls.fingerprint);
    assert_eq!(
        deserialized.tls.min_tls_version,
        original.tls.min_tls_version
    );
    assert_eq!(deserialized.tls.enable_http2, original.tls.enable_http2);
    assert_eq!(
        deserialized.tls.accept_invalid_certs,
        original.tls.accept_invalid_certs
    );
}

// ---------------------------------------------------------------------------
// #135 persona_tls_config_curl_no_http2
// ---------------------------------------------------------------------------
#[test]
fn persona_tls_config_curl_no_http2() {
    let config = persona_tls_config(PersonaId::CurlClient);
    assert!(
        !config.enable_http2,
        "CurlClient should have HTTP/2 disabled to match real curl behavior"
    );
    assert_eq!(config.fingerprint, TlsFingerprint::Curl);
}

// ---------------------------------------------------------------------------
// #136 persona_tls_config_browsers_http2
// ---------------------------------------------------------------------------
#[test]
fn persona_tls_config_browsers_http2() {
    let browser_personas = [
        PersonaId::ChromeDesktop,
        PersonaId::FirefoxDesktop,
        PersonaId::SafariDesktop,
        PersonaId::ChromeMobile,
        PersonaId::EdgeDesktop,
        PersonaId::OperaDesktop,
        PersonaId::SafariMobile,
        PersonaId::Googlebot,
        PersonaId::PythonRequests,
    ];

    for persona_id in browser_personas {
        let config = persona_tls_config(persona_id);
        assert!(
            config.enable_http2,
            "{persona_id:?} should have HTTP/2 enabled"
        );
    }
}
