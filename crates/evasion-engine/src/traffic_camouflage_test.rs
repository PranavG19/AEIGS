use super::traffic_camouflage::*;

fn make_engine() -> TrafficCamouflageEngine {
    TrafficCamouflageEngine::with_seed(CamouflageConfig::default(), 42)
}

#[test]
fn create_fronted_request_uses_cdn_sni() {
    let engine = make_engine();
    let req = engine.create_fronted_request("evil.target.com", "/api/v1", "GET", None);
    assert_eq!(req.sni_hostname, CdnFrontDomain::CloudFront.sni_hostname());
    assert_eq!(req.actual_host, "evil.target.com");
    assert_eq!(req.path, "/api/v1");
    assert!(req.headers.get("Host").unwrap() == "evil.target.com");
}

#[test]
fn fronted_request_hides_target_behind_cdn() {
    let engine = make_engine();
    let req = engine.create_fronted_request("secret.target.com", "/scan", "POST", Some(b"test"));
    assert_ne!(req.sni_hostname, "secret.target.com");
    assert_eq!(req.body, Some(b"test".to_vec()));
}

#[test]
fn traffic_schedule_mixes_cover_and_scan() {
    let mut engine = make_engine();
    let urls = vec!["http://target.com/a", "http://target.com/b"];
    let schedule = engine.generate_traffic_schedule(&urls);
    let cover_count = schedule.iter().filter(|e| e.is_cover).count();
    let scan_count = schedule.iter().filter(|e| !e.is_cover).count();
    assert_eq!(scan_count, 2);
    assert!(cover_count > 0);
    assert!(cover_count > scan_count);
}

#[test]
fn cover_scan_ratio_reflects_configuration() {
    let mut engine = make_engine();
    let urls = vec!["http://target.com/x"];
    engine.generate_traffic_schedule(&urls);
    let ratio = engine.cover_scan_ratio();
    assert!(ratio > 1.0);
}

#[test]
fn embed_payload_base64_query() {
    let engine = TrafficCamouflageEngine::with_seed(
        CamouflageConfig::default().with_embedding(EmbeddingStrategy::Base64InQueryParam),
        42,
    );
    let embedded = engine.embed_payload("<script>alert(1)</script>", "http://target.com/search");
    assert_eq!(embedded.strategy, EmbeddingStrategy::Base64InQueryParam);
    assert!(embedded.outer_url.contains("?q="));
    assert_ne!(embedded.encoded_payload, embedded.original_payload);
}

#[test]
fn embed_payload_json_injection() {
    let engine = TrafficCamouflageEngine::with_seed(
        CamouflageConfig::default().with_embedding(EmbeddingStrategy::JsonFieldInjection),
        42,
    );
    let embedded = engine.embed_payload("' OR 1=1 --", "http://target.com/api");
    assert_eq!(embedded.strategy, EmbeddingStrategy::JsonFieldInjection);
    assert!(embedded.encoded_payload.contains("preferences"));
    assert!(embedded.outer_content_type.contains("json"));
}

#[test]
fn embed_payload_multipart() {
    let engine = TrafficCamouflageEngine::with_seed(
        CamouflageConfig::default().with_embedding(EmbeddingStrategy::MultipartBoundary),
        42,
    );
    let embedded = engine.embed_payload("test_payload", "http://target.com/upload");
    assert_eq!(embedded.strategy, EmbeddingStrategy::MultipartBoundary);
    assert!(embedded.outer_content_type.contains("multipart"));
    assert!(embedded.encoded_payload.contains("WebKitFormBoundary"));
}

#[test]
fn embed_payload_chunked() {
    let engine = TrafficCamouflageEngine::with_seed(
        CamouflageConfig::default().with_embedding(EmbeddingStrategy::ChunkedTransferEncoding),
        42,
    );
    let embedded = engine.embed_payload("chunked_test", "http://target.com/data");
    assert_eq!(
        embedded.strategy,
        EmbeddingStrategy::ChunkedTransferEncoding
    );
    assert!(embedded.encoded_payload.contains("\r\n0\r\n"));
}

#[test]
fn embed_payload_cookie() {
    let engine = TrafficCamouflageEngine::with_seed(
        CamouflageConfig::default().with_embedding(EmbeddingStrategy::CookieValue),
        42,
    );
    let embedded = engine.embed_payload("cookie_test", "http://target.com/");
    assert_eq!(embedded.strategy, EmbeddingStrategy::CookieValue);
    assert!(embedded.encoded_payload.contains("session="));
    assert!(embedded.encoded_payload.contains("HttpOnly"));
}

#[test]
fn mimic_headers_https() {
    let engine = TrafficCamouflageEngine::with_seed(
        CamouflageConfig::default().with_mimic(MimicProtocol::Https),
        42,
    );
    let headers = engine.mimic_headers();
    assert!(headers.contains_key("Accept"));
    assert!(headers.contains_key("Accept-Encoding"));
    assert!(headers.contains_key("Connection"));
}

#[test]
fn mimic_headers_doh() {
    let engine = TrafficCamouflageEngine::with_seed(
        CamouflageConfig::default().with_mimic(MimicProtocol::DnsOverHttps),
        42,
    );
    let headers = engine.mimic_headers();
    assert_eq!(headers.get("Accept").unwrap(), "application/dns-message");
}

#[test]
fn mimic_headers_websocket() {
    let engine = TrafficCamouflageEngine::with_seed(
        CamouflageConfig::default().with_mimic(MimicProtocol::WebSocket),
        42,
    );
    let headers = engine.mimic_headers();
    assert_eq!(headers.get("Upgrade").unwrap(), "websocket");
    assert!(headers.contains_key("Sec-WebSocket-Key"));
}

#[test]
fn bandwidth_tracking() {
    let mut engine = make_engine();
    assert!(!engine.would_exceed_bandwidth(500));
    engine.record_bytes_sent(900_000);
    assert!(engine.bandwidth_utilization() > 0.5);
    engine.record_bytes_sent(500_000);
    assert!(engine.would_exceed_bandwidth(500_000));
    engine.reset_bandwidth_window();
    assert_eq!(engine.bandwidth_utilization(), 0.0);
}

#[test]
fn sni_mode_returns_configured_value() {
    let engine = TrafficCamouflageEngine::with_seed(
        CamouflageConfig::default().with_sni_mode(SniMode::Esni),
        42,
    );
    assert_eq!(engine.sni_mode(), SniMode::Esni);
}

#[test]
fn cdn_front_domain_display() {
    assert!(format!("{}", CdnFrontDomain::GoogleApis).contains("googleapis"));
    assert!(format!("{}", CdnFrontDomain::CloudFront).contains("cloudfront"));
}

#[test]
fn traffic_distribution_pareto_produces_varied_delays() {
    let mut engine = TrafficCamouflageEngine::with_seed(
        CamouflageConfig::default().with_distribution(TrafficDistribution::Pareto),
        42,
    );
    let urls = vec![
        "http://target.com/1",
        "http://target.com/2",
        "http://target.com/3",
    ];
    let schedule = engine.generate_traffic_schedule(&urls);
    let delays: Vec<u64> = schedule.iter().map(|e| e.delay_ms).collect();
    let has_variation = delays.windows(2).any(|w| w[0] != w[1]);
    assert!(has_variation);
}

#[test]
fn traffic_distribution_lognormal() {
    let mut engine = TrafficCamouflageEngine::with_seed(
        CamouflageConfig::default().with_distribution(TrafficDistribution::LogNormal),
        42,
    );
    let urls = vec!["http://target.com/a"];
    let schedule = engine.generate_traffic_schedule(&urls);
    assert!(!schedule.is_empty());
    assert!(schedule.iter().all(|e| e.delay_ms > 0));
}

#[test]
fn traffic_distribution_uniform() {
    let mut engine = TrafficCamouflageEngine::with_seed(
        CamouflageConfig::default().with_distribution(TrafficDistribution::Uniform),
        42,
    );
    let urls = vec!["http://target.com/a"];
    let schedule = engine.generate_traffic_schedule(&urls);
    assert!(schedule
        .iter()
        .all(|e| e.delay_ms >= 100 && e.delay_ms < 2000));
}

#[test]
fn config_builder_pattern() {
    let config = CamouflageConfig::default()
        .with_cdn(CdnFrontDomain::Akamai)
        .with_sni_mode(SniMode::Ech)
        .with_cover_ratio(0.5)
        .with_distribution(TrafficDistribution::Exponential)
        .with_max_bandwidth(2_000_000)
        .with_mimic(MimicProtocol::Quic)
        .with_embedding(EmbeddingStrategy::CookieValue);
    assert_eq!(config.preferred_cdn, CdnFrontDomain::Akamai);
    assert_eq!(config.sni_mode, SniMode::Ech);
    assert!((config.cover_traffic_ratio - 0.5).abs() < f64::EPSILON);
    assert_eq!(config.max_bandwidth_bps, 2_000_000);
}

#[test]
fn embedding_strategy_display() {
    assert_eq!(
        format!("{}", EmbeddingStrategy::Base64InQueryParam),
        "base64-query"
    );
    assert_eq!(
        format!("{}", EmbeddingStrategy::JsonFieldInjection),
        "json-field"
    );
    assert_eq!(
        format!("{}", EmbeddingStrategy::MultipartBoundary),
        "multipart"
    );
    assert_eq!(
        format!("{}", EmbeddingStrategy::ChunkedTransferEncoding),
        "chunked"
    );
    assert_eq!(format!("{}", EmbeddingStrategy::CookieValue), "cookie");
}

#[test]
fn mimic_protocol_display() {
    assert_eq!(format!("{}", MimicProtocol::Https), "HTTPS");
    assert_eq!(format!("{}", MimicProtocol::DnsOverHttps), "DoH");
    assert_eq!(format!("{}", MimicProtocol::Ntp), "NTP");
    assert_eq!(format!("{}", MimicProtocol::Quic), "QUIC");
    assert_eq!(format!("{}", MimicProtocol::WebSocket), "WebSocket");
}

#[test]
fn total_requests_tracks_all_traffic() {
    let mut engine = make_engine();
    let urls = vec!["http://target.com/a", "http://target.com/b"];
    let schedule = engine.generate_traffic_schedule(&urls);
    assert_eq!(engine.total_requests(), schedule.len() as u64);
}

#[test]
fn bandwidth_profile_new() {
    let bp = BandwidthProfile::new(1_000_000);
    assert_eq!(bp.max_bytes_per_second, 1_000_000);
    assert_eq!(bp.burst_allowance_bytes, 200_000);
    assert_eq!(bp.current_window_bytes, 0);
    assert!(!bp.would_exceed(1_000_000));
}
