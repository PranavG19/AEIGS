use super::*;
use std::collections::HashSet;
use std::io::Write;

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

#[test]
fn load_persona_catalog_default_returns_ten_personas() {
    let catalog = load_persona_catalog(None).unwrap();
    assert_eq!(catalog.len(), 10);
}

#[test]
fn load_persona_catalog_from_file() {
    let catalog = persona_catalog();
    let json = serde_json::to_string_pretty(&catalog).unwrap();
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{json}").unwrap();

    let loaded = load_persona_catalog(Some(tmp.path())).unwrap();
    assert_eq!(loaded.len(), 10);
    assert_eq!(loaded[0].id, PersonaId::ChromeDesktop);
}

#[test]
fn load_persona_catalog_custom_single_persona() {
    let json = r#"[{
        "id": "CurlClient",
        "user_agent": "MyCurl/9.0",
        "accept_header": "*/*",
        "accept_language": "en",
        "accept_encoding": "gzip",
        "sec_fetch_headers": [],
        "header_order": ["Host", "User-Agent"],
        "min_request_interval_ms": 100,
        "max_request_interval_ms": 200,
        "jitter_distribution": "Uniform"
    }]"#;
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{json}").unwrap();

    let loaded = load_persona_catalog(Some(tmp.path())).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].user_agent, "MyCurl/9.0");
}

#[test]
fn load_persona_catalog_nonexistent_file_returns_io_error() {
    let result = load_persona_catalog(Some(std::path::Path::new("/nonexistent/personas.json")));
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), CatalogError::Io(_)));
}

#[test]
fn load_persona_catalog_invalid_json_returns_parse_error() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{{ not valid json !!").unwrap();
    let result = load_persona_catalog(Some(tmp.path()));
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), CatalogError::Parse(_)));
}

#[test]
fn load_persona_catalog_empty_array_returns_empty_catalog_error() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "[]").unwrap();
    let result = load_persona_catalog(Some(tmp.path()));
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), CatalogError::EmptyCatalog));
}

#[test]
fn load_persona_catalog_duplicate_ids_returns_error() {
    let json = r#"[
        {
            "id": "CurlClient",
            "user_agent": "curl/1.0",
            "accept_header": "*/*",
            "accept_language": "en",
            "accept_encoding": "gzip",
            "sec_fetch_headers": [],
            "header_order": [],
            "min_request_interval_ms": 100,
            "max_request_interval_ms": 200,
            "jitter_distribution": "Uniform"
        },
        {
            "id": "CurlClient",
            "user_agent": "curl/2.0",
            "accept_header": "*/*",
            "accept_language": "en",
            "accept_encoding": "gzip",
            "sec_fetch_headers": [],
            "header_order": [],
            "min_request_interval_ms": 100,
            "max_request_interval_ms": 200,
            "jitter_distribution": "Uniform"
        }
    ]"#;
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{json}").unwrap();
    let result = load_persona_catalog(Some(tmp.path()));
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CatalogError::DuplicateId(PersonaId::CurlClient)
    ));
}

#[test]
fn load_persona_catalog_empty_user_agent_returns_error() {
    let json = r#"[{
        "id": "CurlClient",
        "user_agent": "",
        "accept_header": "*/*",
        "accept_language": "en",
        "accept_encoding": "gzip",
        "sec_fetch_headers": [],
        "header_order": [],
        "min_request_interval_ms": 100,
        "max_request_interval_ms": 200,
        "jitter_distribution": "Uniform"
    }]"#;
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{json}").unwrap();
    let result = load_persona_catalog(Some(tmp.path()));
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CatalogError::EmptyUserAgent(PersonaId::CurlClient)
    ));
}

#[test]
fn load_persona_catalog_empty_accept_header_returns_error() {
    let json = r#"[{
        "id": "CurlClient",
        "user_agent": "curl/1.0",
        "accept_header": "",
        "accept_language": "en",
        "accept_encoding": "gzip",
        "sec_fetch_headers": [],
        "header_order": [],
        "min_request_interval_ms": 100,
        "max_request_interval_ms": 200,
        "jitter_distribution": "Uniform"
    }]"#;
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{json}").unwrap();
    let result = load_persona_catalog(Some(tmp.path()));
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CatalogError::EmptyAcceptHeader(PersonaId::CurlClient)
    ));
}

#[test]
fn catalog_error_display_variants() {
    let io_err = CatalogError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
    assert!(
        io_err
            .to_string()
            .contains("failed to read persona catalog")
    );

    let parse_err = CatalogError::Parse(serde_json::from_str::<Vec<Persona>>("bad").unwrap_err());
    assert!(
        parse_err
            .to_string()
            .contains("failed to parse persona catalog")
    );

    let empty_err = CatalogError::EmptyCatalog;
    assert!(empty_err.to_string().contains("at least one persona"));

    let dup_err = CatalogError::DuplicateId(PersonaId::Googlebot);
    assert!(dup_err.to_string().contains("duplicate persona id"));

    let ua_err = CatalogError::EmptyUserAgent(PersonaId::ChromeDesktop);
    assert!(ua_err.to_string().contains("empty user_agent"));

    let accept_err = CatalogError::EmptyAcceptHeader(PersonaId::FirefoxDesktop);
    assert!(accept_err.to_string().contains("empty accept_header"));
}

#[test]
fn catalog_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(CatalogError::EmptyCatalog);
    assert!(!err.to_string().is_empty());
}

#[test]
fn default_catalog_json_matches_persona_catalog() {
    let from_json = load_persona_catalog(None).unwrap();
    let from_fn = persona_catalog();
    assert_eq!(from_json.len(), from_fn.len());
    for (a, b) in from_json.iter().zip(from_fn.iter()) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.user_agent, b.user_agent);
        assert_eq!(a.accept_header, b.accept_header);
        assert_eq!(a.header_order, b.header_order);
    }
}
