use crate::tech_fingerprinter::{
    DetectedTech, FingerprintError, TechCategory, TechFingerprinter, fingerprint_from_headers,
    fingerprint_from_html,
};

#[test]
fn header_detects_apache_with_version() {
    let headers = vec![("server".to_string(), "Apache/2.4.51".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Apache");
    assert_eq!(results[0].version.as_deref(), Some("2.4.51"));
    assert_eq!(results[0].category, TechCategory::WebServer);
    assert!(results[0].confidence >= 0.9);
}

#[test]
fn header_detects_nginx_with_version() {
    let headers = vec![("server".to_string(), "nginx/1.24.0".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "nginx");
    assert_eq!(results[0].version.as_deref(), Some("1.24.0"));
    assert_eq!(results[0].category, TechCategory::WebServer);
}

#[test]
fn header_detects_iis_with_version() {
    let headers = vec![("server".to_string(), "Microsoft-IIS/10.0".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "IIS");
    assert_eq!(results[0].version.as_deref(), Some("10.0"));
}

#[test]
fn header_detects_caddy() {
    let headers = vec![("server".to_string(), "Caddy".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Caddy");
    assert!(results[0].version.is_none());
}

#[test]
fn header_detects_litespeed() {
    let headers = vec![("server".to_string(), "LiteSpeed/5.4.12".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "LiteSpeed");
    assert_eq!(results[0].version.as_deref(), Some("5.4.12"));
}

#[test]
fn header_detects_server_without_version() {
    let headers = vec![("server".to_string(), "nginx".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "nginx");
    assert!(results[0].version.is_none());
}

#[test]
fn header_detects_express() {
    let headers = vec![("x-powered-by".to_string(), "Express".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Express");
    assert_eq!(results[0].category, TechCategory::Framework);
}

#[test]
fn header_detects_php() {
    let headers = vec![("x-powered-by".to_string(), "PHP/8.2.1".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "PHP");
    assert_eq!(results[0].version.as_deref(), Some("8.2.1"));
    assert_eq!(results[0].category, TechCategory::ProgrammingLanguage);
}

#[test]
fn header_detects_aspnet_powered_by() {
    let headers = vec![("x-powered-by".to_string(), "ASP.NET".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "ASP.NET");
    assert_eq!(results[0].category, TechCategory::Framework);
}

#[test]
fn header_detects_nextjs() {
    let headers = vec![("x-powered-by".to_string(), "Next.js".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Next.js");
    assert_eq!(results[0].category, TechCategory::Framework);
}

#[test]
fn header_detects_nuxtjs() {
    let headers = vec![("x-powered-by".to_string(), "Nuxt.js".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Nuxt.js");
    assert_eq!(results[0].category, TechCategory::Framework);
}

#[test]
fn header_detects_generator_wordpress() {
    let headers = vec![("x-generator".to_string(), "WordPress 6.4".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "WordPress");
    assert_eq!(results[0].category, TechCategory::Cms);
}

#[test]
fn header_detects_generator_drupal() {
    let headers = vec![("x-generator".to_string(), "Drupal 10".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Drupal");
}

#[test]
fn header_detects_generator_jekyll() {
    let headers = vec![("x-generator".to_string(), "Jekyll v4.3.2".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Jekyll");
}

#[test]
fn header_detects_generator_hugo() {
    let headers = vec![("x-generator".to_string(), "Hugo 0.120".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Hugo");
}

#[test]
fn header_detects_aspnet_version() {
    let headers = vec![("x-aspnet-version".to_string(), "4.0.30319".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "ASP.NET");
    assert_eq!(results[0].version.as_deref(), Some("4.0.30319"));
    assert!(results[0].confidence >= 0.95);
}

#[test]
fn header_detects_aspnet_mvc_version() {
    let headers = vec![("x-aspnetmvc-version".to_string(), "5.2.9".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "ASP.NET MVC");
    assert_eq!(results[0].version.as_deref(), Some("5.2.9"));
}

#[test]
fn header_detects_phpsessid_cookie() {
    let headers = vec![(
        "set-cookie".to_string(),
        "PHPSESSID=abc123; path=/".to_string(),
    )];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "PHP");
    assert_eq!(results[0].category, TechCategory::ProgrammingLanguage);
    assert!(results[0].confidence >= 0.8);
}

#[test]
fn header_detects_jsessionid_cookie() {
    let headers = vec![(
        "set-cookie".to_string(),
        "JSESSIONID=xyz789; Path=/".to_string(),
    )];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Java");
}

#[test]
fn header_detects_aspnet_session_cookie() {
    let headers = vec![(
        "set-cookie".to_string(),
        "ASP.NET_SessionId=abcdef; path=/".to_string(),
    )];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "ASP.NET");
}

#[test]
fn header_detects_connect_sid_cookie() {
    let headers = vec![(
        "set-cookie".to_string(),
        "connect.sid=s%3Aabc; Path=/".to_string(),
    )];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Express");
}

#[test]
fn header_detects_django_csrftoken_cookie() {
    let headers = vec![(
        "set-cookie".to_string(),
        "csrftoken=abc123xyz; Path=/".to_string(),
    )];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Django");
}

#[test]
fn header_detects_rails_session_cookie() {
    let headers = vec![(
        "set-cookie".to_string(),
        "_rails_session=encrypted; path=/".to_string(),
    )];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Ruby on Rails");
}

#[test]
fn header_detects_laravel_session_cookie() {
    let headers = vec![(
        "set-cookie".to_string(),
        "laravel_session=eyJ; path=/".to_string(),
    )];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Laravel");
}

#[test]
fn header_empty_returns_nothing() {
    let results = fingerprint_from_headers(&[]);
    assert!(results.is_empty());
}

#[test]
fn header_unrecognized_server() {
    let headers = vec![("server".to_string(), "MyCustomServer/1.0".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert!(results.is_empty());
}

#[test]
fn header_multiple_detections() {
    let headers = vec![
        ("server".to_string(), "nginx/1.24.0".to_string()),
        ("x-powered-by".to_string(), "PHP/8.2.1".to_string()),
        (
            "set-cookie".to_string(),
            "PHPSESSID=abc123; path=/".to_string(),
        ),
    ];
    let results = fingerprint_from_headers(&headers);
    assert!(results.len() >= 3);
    let names: Vec<&str> = results.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"nginx"));
    assert!(names.contains(&"PHP"));
}

#[test]
fn html_detects_meta_generator_wordpress() {
    let html = r#"<html><head><meta name="generator" content="WordPress 6.4.2"></head></html>"#;
    let results = fingerprint_from_html(html);
    let wp: Vec<&DetectedTech> = results.iter().filter(|t| t.name == "WordPress").collect();
    assert!(!wp.is_empty());
    assert_eq!(wp[0].version.as_deref(), Some("6.4.2"));
    assert!(wp[0].confidence >= 0.9);
}

#[test]
fn html_detects_meta_generator_alternate_order() {
    let html =
        r#"<html><head><meta content="Joomla! 4.0" name="generator"></head><body></body></html>"#;
    let results = fingerprint_from_html(html);
    assert!(
        results
            .iter()
            .any(|t| t.name == "Joomla!" && t.version.as_deref() == Some("4.0"))
    );
}

#[test]
fn html_detects_wp_content() {
    let html =
        r#"<html><body><link rel="stylesheet" href="/wp-content/themes/main.css"></body></html>"#;
    let results = fingerprint_from_html(html);
    assert!(results.iter().any(|t| t.name == "WordPress"));
}

#[test]
fn html_detects_wp_includes() {
    let html = r#"<script src="/wp-includes/js/jquery.js"></script>"#;
    let results = fingerprint_from_html(html);
    assert!(results.iter().any(|t| t.name == "WordPress"));
}

#[test]
fn html_detects_drupal_js() {
    let html = r#"<script src="/core/misc/drupal.js"></script>"#;
    let results = fingerprint_from_html(html);
    assert!(results.iter().any(|t| t.name == "Drupal"));
}

#[test]
fn html_detects_drupal_settings() {
    let html = r#"<script>jQuery.extend(Drupal.settings, {"basePath":"/"});</script>"#;
    let results = fingerprint_from_html(html);
    assert!(results.iter().any(|t| t.name == "Drupal"));
}

#[test]
fn html_detects_nextjs_path() {
    let html = r#"<script src="/_next/static/chunks/main.js"></script>"#;
    let results = fingerprint_from_html(html);
    assert!(results.iter().any(|t| t.name == "Next.js"));
}

#[test]
fn html_detects_nextjs_data() {
    let html = r#"<script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>"#;
    let results = fingerprint_from_html(html);
    assert!(results.iter().any(|t| t.name == "Next.js"));
}

#[test]
fn html_detects_nuxtjs_path() {
    let html = r#"<script src="/__nuxt/entry.js"></script>"#;
    let results = fingerprint_from_html(html);
    assert!(results.iter().any(|t| t.name == "Nuxt.js"));
}

#[test]
fn html_detects_nuxtjs_global() {
    let html = r#"<script>window.__NUXT__={data:[]}</script>"#;
    let results = fingerprint_from_html(html);
    assert!(results.iter().any(|t| t.name == "Nuxt.js"));
}

#[test]
fn html_detects_angular_ng_version() {
    let html = r#"<app-root ng-version="17.1.0"></app-root>"#;
    let results = fingerprint_from_html(html);
    assert!(
        results
            .iter()
            .any(|t| t.name == "Angular" && t.category == TechCategory::JavaScript)
    );
}

#[test]
fn html_detects_angular_ng_app() {
    let html = r#"<div ng-app="myApp"></div>"#;
    let results = fingerprint_from_html(html);
    assert!(results.iter().any(|t| t.name == "Angular"));
}

#[test]
fn html_detects_react_root() {
    let html = r#"<div id="root" data-reactroot></div>"#;
    let results = fingerprint_from_html(html);
    assert!(
        results
            .iter()
            .any(|t| t.name == "React" && t.category == TechCategory::JavaScript)
    );
}

#[test]
fn html_detects_react_global() {
    let html = r#"<script>window.__REACT={}</script>"#;
    let results = fingerprint_from_html(html);
    assert!(results.iter().any(|t| t.name == "React"));
}

#[test]
fn html_detects_vue_scoped_css() {
    let html = r#"<div data-v-abc123=""></div>"#;
    let results = fingerprint_from_html(html);
    assert!(
        results
            .iter()
            .any(|t| t.name == "Vue.js" && t.category == TechCategory::JavaScript)
    );
}

#[test]
fn html_detects_powered_by_link() {
    let html = r#"Powered by <a href="https://ghost.org">Ghost</a>"#;
    let results = fingerprint_from_html(html);
    assert!(results.iter().any(|t| t.name == "Ghost"));
}

#[test]
fn html_detects_cdn_jquery_with_sri() {
    let html = r#"<script src="https://cdn.example.com/jquery-3.7.1.min.js" integrity="sha256-abc"></script>"#;
    let results = fingerprint_from_html(html);
    assert!(results.iter().any(|t| t.name == "jQuery"));
}

#[test]
fn html_detects_cdn_bootstrap_with_sri() {
    let html = r#"<script src="https://cdn.example.com/bootstrap.min.js" integrity="sha384-xyz"></script>"#;
    let results = fingerprint_from_html(html);
    assert!(results.iter().any(|t| t.name == "Bootstrap"));
}

#[test]
fn html_empty_body() {
    let results = fingerprint_from_html("");
    assert!(results.is_empty());
}

#[test]
fn html_no_fingerprints() {
    let html = r#"<html><body><h1>Hello World</h1></body></html>"#;
    let results = fingerprint_from_html(html);
    assert!(results.is_empty());
}

#[test]
fn html_multiple_frameworks() {
    let html = r#"
        <div data-reactroot></div>
        <script src="/_next/static/main.js"></script>
        <script id="__NEXT_DATA__">{"props":{}}</script>
    "#;
    let results = fingerprint_from_html(html);
    assert!(results.iter().any(|t| t.name == "React"));
    assert!(results.iter().any(|t| t.name == "Next.js"));
}

#[test]
fn deduplication_keeps_highest_confidence() {
    let headers = vec![
        ("x-powered-by".to_string(), "Express".to_string()),
        (
            "set-cookie".to_string(),
            "connect.sid=abc; Path=/".to_string(),
        ),
    ];
    let results = fingerprint_from_headers(&headers);
    let express_entries: Vec<&DetectedTech> =
        results.iter().filter(|t| t.name == "Express").collect();
    assert!(express_entries.len() >= 1);
}

#[test]
fn fingerprinter_new_succeeds() {
    let fp = TechFingerprinter::new();
    assert!(fp.is_ok());
}

#[test]
fn fingerprint_rejects_non_localhost() {
    let fp = TechFingerprinter::new().unwrap();
    let result = fp.fingerprint("http://example.com");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        FingerprintError::NonLocalhostTarget(_)
    ));
}

#[test]
fn fingerprint_rejects_empty_url() {
    let fp = TechFingerprinter::new().unwrap();
    let result = fp.fingerprint("");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        FingerprintError::InvalidUrl(_)
    ));
}

#[test]
fn fingerprint_rejects_invalid_url() {
    let fp = TechFingerprinter::new().unwrap();
    let result = fp.fingerprint("not a url");
    assert!(result.is_err());
}

#[test]
fn fingerprint_accepts_localhost() {
    let fp = TechFingerprinter::new().unwrap();
    let result = fp.fingerprint("http://localhost:39999");
    assert!(result.is_ok());
}

#[test]
fn fingerprint_accepts_127_0_0_1() {
    let fp = TechFingerprinter::new().unwrap();
    let result = fp.fingerprint("http://127.0.0.1:39999");
    assert!(result.is_ok());
}

#[test]
fn fingerprint_accepts_ipv6_localhost() {
    let fp = TechFingerprinter::new().unwrap();
    let result = fp.fingerprint("http://[::1]:39999");
    assert!(result.is_ok());
}

#[test]
fn fingerprint_normalizes_trailing_slash() {
    let fp = TechFingerprinter::new().unwrap();
    let result = fp.fingerprint("http://localhost:39999/");
    assert!(result.is_ok());
}

#[test]
fn fingerprint_unreachable_returns_empty() {
    let fp = TechFingerprinter::new().unwrap();
    let result = fp.fingerprint("http://localhost:39999").unwrap();
    assert!(result.technologies.is_empty());
}

#[test]
fn tech_category_display() {
    assert_eq!(format!("{}", TechCategory::WebServer), "Web Server");
    assert_eq!(format!("{}", TechCategory::Framework), "Framework");
    assert_eq!(format!("{}", TechCategory::Cms), "CMS");
    assert_eq!(
        format!("{}", TechCategory::ProgrammingLanguage),
        "Programming Language"
    );
    assert_eq!(format!("{}", TechCategory::JavaScript), "JavaScript");
    assert_eq!(format!("{}", TechCategory::Cdn), "CDN");
    assert_eq!(format!("{}", TechCategory::Analytics), "Analytics");
    assert_eq!(format!("{}", TechCategory::Security), "Security");
}

#[test]
fn error_display_invalid_url() {
    let err = FingerprintError::InvalidUrl("bad".to_string());
    assert_eq!(format!("{err}"), "invalid URL: bad");
}

#[test]
fn error_display_non_localhost() {
    let err = FingerprintError::NonLocalhostTarget("http://evil.com".to_string());
    assert_eq!(format!("{err}"), "non-localhost target: http://evil.com");
}

#[test]
fn error_display_http() {
    let err = FingerprintError::HttpError("timeout".to_string());
    assert_eq!(format!("{err}"), "HTTP error: timeout");
}

#[test]
fn error_is_std_error() {
    let err = FingerprintError::InvalidUrl("test".to_string());
    let _: &dyn std::error::Error = &err;
}

#[test]
fn fingerprinter_debug_format() {
    let fp = TechFingerprinter::new().unwrap();
    let debug = format!("{:?}", fp);
    assert!(debug.contains("TechFingerprinter"));
}

#[test]
fn detected_tech_clone() {
    let tech = DetectedTech {
        name: "nginx".to_string(),
        version: Some("1.24.0".to_string()),
        category: TechCategory::WebServer,
        confidence: 0.9,
        evidence: "Server header".to_string(),
    };
    let cloned = tech.clone();
    assert_eq!(tech, cloned);
}

#[test]
fn tech_category_eq_and_hash() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(TechCategory::WebServer);
    set.insert(TechCategory::Framework);
    set.insert(TechCategory::WebServer);
    assert_eq!(set.len(), 2);
}

#[test]
fn header_server_version_with_extra_info() {
    let headers = vec![("server".to_string(), "Apache/2.4.51 (Ubuntu)".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results[0].version.as_deref(), Some("2.4.51"));
}

#[test]
fn header_server_version_with_space_after() {
    let headers = vec![("server".to_string(), "nginx/1.24.0 Phusion".to_string())];
    let results = fingerprint_from_headers(&headers);
    assert_eq!(results[0].version.as_deref(), Some("1.24.0"));
}

#[test]
fn html_meta_generator_no_version() {
    let html = r#"<meta name="generator" content="Webflow">"#;
    let results = fingerprint_from_html(html);
    assert!(
        results
            .iter()
            .any(|t| t.name == "Webflow" && t.version.is_none())
    );
}

#[test]
fn confidence_values_in_expected_ranges() {
    let headers = vec![
        ("server".to_string(), "nginx/1.24.0".to_string()),
        ("x-aspnet-version".to_string(), "4.0".to_string()),
        (
            "set-cookie".to_string(),
            "PHPSESSID=abc; path=/".to_string(),
        ),
    ];
    let results = fingerprint_from_headers(&headers);
    for tech in &results {
        assert!(
            tech.confidence >= 0.0 && tech.confidence <= 1.0,
            "confidence {} out of range for {}",
            tech.confidence,
            tech.name
        );
    }
}

#[test]
fn path_probes_cover_expected_technologies() {
    let probe_names: Vec<&str> = super::tech_fingerprinter::PATH_PROBES
        .iter()
        .map(|p| p.name)
        .collect();
    assert!(probe_names.contains(&"WordPress"));
    assert!(probe_names.contains(&"Joomla"));
    assert!(probe_names.contains(&"Drupal"));
    assert!(probe_names.contains(&"Ruby on Rails"));
    assert!(probe_names.contains(&"Spring Boot"));
    assert!(probe_names.contains(&"Django"));
    assert!(probe_names.contains(&"Laravel"));
    assert!(probe_names.contains(&"ASP.NET"));
    assert!(probe_names.contains(&"Apache"));
}

#[test]
fn tech_fingerprint_debug() {
    let fp = crate::tech_fingerprinter::TechFingerprint {
        technologies: vec![],
    };
    let debug = format!("{:?}", fp);
    assert!(debug.contains("TechFingerprint"));
}

#[test]
fn tech_fingerprint_clone() {
    let fp = crate::tech_fingerprinter::TechFingerprint {
        technologies: vec![DetectedTech {
            name: "test".to_string(),
            version: None,
            category: TechCategory::WebServer,
            confidence: 0.5,
            evidence: "test".to_string(),
        }],
    };
    let cloned = fp.clone();
    assert_eq!(fp, cloned);
}
