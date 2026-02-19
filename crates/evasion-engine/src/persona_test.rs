use super::*;
use std::collections::HashSet;

#[test]
fn persona_id_variants_exist() {
    let ids = vec![
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
    ];
    assert_eq!(ids.len(), 10);
}

#[test]
fn persona_id_derives_work() {
    let id = PersonaId::ChromeDesktop;
    let cloned = id;
    assert_eq!(id, cloned);
    assert_eq!(format!("{:?}", id), "ChromeDesktop");

    let mut set = HashSet::new();
    set.insert(id);
    assert!(set.contains(&PersonaId::ChromeDesktop));
}

#[test]
fn jitter_distribution_variants() {
    let distributions = vec![
        JitterDistribution::Uniform,
        JitterDistribution::Exponential,
        JitterDistribution::Normal,
    ];
    assert_eq!(distributions.len(), 3);
    assert_ne!(JitterDistribution::Uniform, JitterDistribution::Normal);
}

#[test]
fn catalog_returns_ten_personas() {
    let catalog = persona_catalog();
    assert_eq!(catalog.len(), 10);
}

#[test]
fn catalog_personas_have_unique_ids() {
    let catalog = persona_catalog();
    let ids: HashSet<PersonaId> = catalog.iter().map(|p| p.id).collect();
    assert_eq!(ids.len(), 10);
}

#[test]
fn each_persona_has_nonempty_user_agent() {
    for persona in persona_catalog() {
        assert!(
            !persona.user_agent.is_empty(),
            "{:?} has empty user_agent",
            persona.id
        );
    }
}

#[test]
fn each_persona_has_nonempty_accept_header() {
    for persona in persona_catalog() {
        assert!(
            !persona.accept_header.is_empty(),
            "{:?} has empty accept_header",
            persona.id
        );
    }
}

#[test]
fn chrome_desktop_has_sec_fetch_headers() {
    let catalog = persona_catalog();
    let chrome = catalog
        .iter()
        .find(|p| p.id == PersonaId::ChromeDesktop)
        .unwrap();
    assert!(!chrome.sec_fetch_headers.is_empty());

    let header_names: Vec<&str> = chrome
        .sec_fetch_headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect();
    assert!(header_names.contains(&"Sec-Fetch-Site"));
    assert!(header_names.contains(&"Sec-Fetch-Mode"));
    assert!(header_names.contains(&"Sec-Fetch-Dest"));
}

#[test]
fn googlebot_has_no_sec_fetch_headers() {
    let catalog = persona_catalog();
    let bot = catalog
        .iter()
        .find(|p| p.id == PersonaId::Googlebot)
        .unwrap();
    assert!(bot.sec_fetch_headers.is_empty());
}

#[test]
fn persona_builder_creates_custom_persona() {
    let persona = Persona::custom(PersonaId::ChromeDesktop)
        .with_user_agent("CustomBot/1.0")
        .with_accept_header("text/html")
        .with_accept_language("fr-FR")
        .with_accept_encoding("gzip")
        .with_sec_fetch_headers(vec![(
            "Sec-Fetch-Site".to_string(),
            "same-origin".to_string(),
        )])
        .with_header_order(vec!["Host".to_string(), "User-Agent".to_string()])
        .with_request_interval(100, 500)
        .with_jitter_distribution(JitterDistribution::Exponential)
        .build();

    assert_eq!(persona.id, PersonaId::ChromeDesktop);
    assert_eq!(persona.user_agent, "CustomBot/1.0");
    assert_eq!(persona.accept_header, "text/html");
    assert_eq!(persona.accept_language, "fr-FR");
    assert_eq!(persona.accept_encoding, "gzip");
    assert_eq!(persona.sec_fetch_headers.len(), 1);
    assert_eq!(persona.header_order.len(), 2);
    assert_eq!(persona.min_request_interval_ms, 100);
    assert_eq!(persona.max_request_interval_ms, 500);
    assert_eq!(persona.jitter_distribution, JitterDistribution::Exponential);
}

#[test]
fn persona_serialization_roundtrip() {
    let original = persona_catalog().into_iter().next().unwrap();
    let json = serde_json::to_string(&original).unwrap();
    let deserialized: Persona = serde_json::from_str(&json).unwrap();

    assert_eq!(original.id, deserialized.id);
    assert_eq!(original.user_agent, deserialized.user_agent);
    assert_eq!(original.accept_header, deserialized.accept_header);
    assert_eq!(original.accept_language, deserialized.accept_language);
    assert_eq!(original.accept_encoding, deserialized.accept_encoding);
    assert_eq!(original.sec_fetch_headers, deserialized.sec_fetch_headers);
    assert_eq!(original.header_order, deserialized.header_order);
    assert_eq!(
        original.min_request_interval_ms,
        deserialized.min_request_interval_ms
    );
    assert_eq!(
        original.max_request_interval_ms,
        deserialized.max_request_interval_ms
    );
    assert_eq!(
        original.jitter_distribution,
        deserialized.jitter_distribution
    );
}

#[test]
fn default_intervals_are_positive() {
    for persona in persona_catalog() {
        assert!(
            persona.min_request_interval_ms > 0,
            "{:?} has zero min interval",
            persona.id
        );
        assert!(
            persona.max_request_interval_ms > 0,
            "{:?} has zero max interval",
            persona.id
        );
        assert!(
            persona.max_request_interval_ms >= persona.min_request_interval_ms,
            "{:?} has max < min interval",
            persona.id
        );
    }
}

#[test]
fn builder_defaults_are_reasonable() {
    let persona = Persona::custom(PersonaId::FirefoxDesktop)
        .with_user_agent("Test/1.0")
        .with_accept_header("*/*")
        .build();

    assert!(persona.min_request_interval_ms > 0);
    assert!(persona.max_request_interval_ms > persona.min_request_interval_ms);
    assert_eq!(persona.jitter_distribution, JitterDistribution::Uniform);
}

#[test]
fn edge_desktop_persona_exists() {
    let catalog = persona_catalog();
    let edge = catalog.iter().find(|p| p.id == PersonaId::EdgeDesktop);
    assert!(edge.is_some());
    let edge = edge.unwrap();
    assert!(!edge.user_agent.is_empty());
    assert!(edge.user_agent.contains("Edg/"));
}

#[test]
fn opera_desktop_persona_exists() {
    let catalog = persona_catalog();
    let opera = catalog.iter().find(|p| p.id == PersonaId::OperaDesktop);
    assert!(opera.is_some());
    let opera = opera.unwrap();
    assert!(!opera.user_agent.is_empty());
    assert!(opera.user_agent.contains("OPR/"));
}

#[test]
fn safari_mobile_persona_exists() {
    let catalog = persona_catalog();
    let safari_mobile = catalog.iter().find(|p| p.id == PersonaId::SafariMobile);
    assert!(safari_mobile.is_some());
    let safari_mobile = safari_mobile.unwrap();
    assert!(!safari_mobile.user_agent.is_empty());
    assert!(safari_mobile.user_agent.contains("iPhone"));
}

#[test]
fn curl_client_persona_exists() {
    let catalog = persona_catalog();
    let curl = catalog.iter().find(|p| p.id == PersonaId::CurlClient);
    assert!(curl.is_some());
    let curl = curl.unwrap();
    assert!(!curl.user_agent.is_empty());
    assert!(curl.user_agent.contains("curl/"));
    assert!(curl.sec_fetch_headers.is_empty());
}

#[test]
fn python_requests_persona_exists() {
    let catalog = persona_catalog();
    let python = catalog.iter().find(|p| p.id == PersonaId::PythonRequests);
    assert!(python.is_some());
    let python = python.unwrap();
    assert!(!python.user_agent.is_empty());
    assert!(python.user_agent.contains("python-requests/"));
    assert!(python.sec_fetch_headers.is_empty());
}
