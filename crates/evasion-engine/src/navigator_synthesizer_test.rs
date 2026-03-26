use super::navigator_synthesizer::*;
use super::PersonaId;

#[test]
fn chrome_desktop_platform_is_win32() {
    let nav = synthesize_navigator(PersonaId::ChromeDesktop, &NavigatorSynthConfig::default());
    assert_eq!(nav.platform, "Win32");
}

#[test]
fn safari_desktop_platform_is_macintel() {
    let nav = synthesize_navigator(PersonaId::SafariDesktop, &NavigatorSynthConfig::default());
    assert_eq!(nav.platform, "MacIntel");
}

#[test]
fn firefox_desktop_platform_is_linux() {
    let nav = synthesize_navigator(PersonaId::FirefoxDesktop, &NavigatorSynthConfig::default());
    assert_eq!(nav.platform, "Linux x86_64");
}

#[test]
fn chrome_mobile_has_touch_points() {
    let nav = synthesize_navigator(PersonaId::ChromeMobile, &NavigatorSynthConfig::default());
    assert!(nav.max_touch_points > 0);
}

#[test]
fn desktop_has_zero_touch_points() {
    let nav = synthesize_navigator(PersonaId::ChromeDesktop, &NavigatorSynthConfig::default());
    assert_eq!(nav.max_touch_points, 0);
}

#[test]
fn hardware_concurrency_in_valid_range() {
    let nav = synthesize_navigator(PersonaId::ChromeDesktop, &NavigatorSynthConfig::default());
    assert!(nav.hardware_concurrency >= 4 && nav.hardware_concurrency <= 16);
}

#[test]
fn mobile_hardware_concurrency_in_mobile_range() {
    let nav = synthesize_navigator(PersonaId::ChromeMobile, &NavigatorSynthConfig::default());
    assert!(nav.hardware_concurrency >= 4 && nav.hardware_concurrency <= 8);
}

#[test]
fn device_memory_is_positive() {
    let nav = synthesize_navigator(PersonaId::ChromeDesktop, &NavigatorSynthConfig::default());
    assert!(nav.device_memory_gb > 0.0);
}

#[test]
fn languages_include_locale() {
    let config = NavigatorSynthConfig {
        locale: "fr-FR".to_string(),
        secondary_languages: vec!["fr".to_string(), "en".to_string()],
        seed: 0,
    };
    let nav = synthesize_navigator(PersonaId::ChromeDesktop, &config);
    assert_eq!(nav.languages[0], "fr-FR");
    assert!(nav.languages.contains(&"fr".to_string()));
    assert!(nav.languages.contains(&"en".to_string()));
}

#[test]
fn languages_no_duplicates() {
    let config = NavigatorSynthConfig {
        locale: "en-US".to_string(),
        secondary_languages: vec!["en-US".to_string(), "en".to_string()],
        seed: 0,
    };
    let nav = synthesize_navigator(PersonaId::ChromeDesktop, &config);
    let mut seen = std::collections::HashSet::new();
    for lang in &nav.languages {
        assert!(seen.insert(lang), "duplicate language: {}", lang);
    }
}

#[test]
fn webdriver_is_always_false() {
    let nav = synthesize_navigator(PersonaId::ChromeDesktop, &NavigatorSynthConfig::default());
    assert!(!nav.webdriver);
}

#[test]
fn cookie_enabled_is_true() {
    let nav = synthesize_navigator(PersonaId::ChromeDesktop, &NavigatorSynthConfig::default());
    assert!(nav.cookie_enabled);
}

#[test]
fn chrome_vendor_is_google() {
    let nav = synthesize_navigator(PersonaId::ChromeDesktop, &NavigatorSynthConfig::default());
    assert_eq!(nav.vendor, "Google Inc.");
}

#[test]
fn firefox_vendor_is_empty() {
    let nav = synthesize_navigator(PersonaId::FirefoxDesktop, &NavigatorSynthConfig::default());
    assert!(nav.vendor.is_empty());
}

#[test]
fn safari_vendor_is_apple() {
    let nav = synthesize_navigator(PersonaId::SafariDesktop, &NavigatorSynthConfig::default());
    assert_eq!(nav.vendor, "Apple Computer, Inc.");
}

#[test]
fn mobile_disables_pdf_viewer() {
    let nav = synthesize_navigator(PersonaId::ChromeMobile, &NavigatorSynthConfig::default());
    assert!(!nav.pdf_viewer_enabled);
}

#[test]
fn desktop_enables_pdf_viewer() {
    let nav = synthesize_navigator(PersonaId::ChromeDesktop, &NavigatorSynthConfig::default());
    assert!(nav.pdf_viewer_enabled);
}

#[test]
fn validate_passes_for_valid_chrome() {
    let nav = synthesize_navigator(PersonaId::ChromeDesktop, &NavigatorSynthConfig::default());
    let errors = validate_navigator(&nav);
    assert!(errors.is_empty(), "errors: {:?}", errors);
}

#[test]
fn validate_catches_wrong_platform() {
    let mut nav = synthesize_navigator(PersonaId::ChromeDesktop, &NavigatorSynthConfig::default());
    nav.platform = "MacIntel".to_string();
    let errors = validate_navigator(&nav);
    assert!(errors.iter().any(|e| e.contains("platform")));
}

#[test]
fn validate_catches_webdriver_true() {
    let mut nav = synthesize_navigator(PersonaId::ChromeDesktop, &NavigatorSynthConfig::default());
    nav.webdriver = true;
    let errors = validate_navigator(&nav);
    assert!(errors.iter().any(|e| e.contains("webdriver")));
}

#[test]
fn different_seeds_can_produce_different_concurrency() {
    let mut seen = std::collections::HashSet::new();
    for seed in 0..20 {
        let config = NavigatorSynthConfig {
            seed,
            ..Default::default()
        };
        let nav = synthesize_navigator(PersonaId::ChromeDesktop, &config);
        seen.insert(nav.hardware_concurrency);
    }
    assert!(
        seen.len() > 1,
        "expected multiple concurrency values across seeds"
    );
}

#[test]
fn user_agent_contains_chrome_for_chrome() {
    let nav = synthesize_navigator(PersonaId::ChromeDesktop, &NavigatorSynthConfig::default());
    assert!(nav.user_agent.contains("Chrome"));
}

#[test]
fn user_agent_contains_firefox_for_firefox() {
    let nav = synthesize_navigator(PersonaId::FirefoxDesktop, &NavigatorSynthConfig::default());
    assert!(nav.user_agent.contains("Firefox"));
}

#[test]
fn all_personas_produce_valid_navigators() {
    let personas = [
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
    for p in &personas {
        let nav = synthesize_navigator(*p, &NavigatorSynthConfig::default());
        let errors = validate_navigator(&nav);
        assert!(errors.is_empty(), "persona {:?} errors: {:?}", p, errors);
    }
}
