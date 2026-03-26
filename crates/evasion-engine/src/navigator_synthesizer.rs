use serde::{Deserialize, Serialize};

use crate::PersonaId;

/// Complete set of `navigator` JavaScript API properties for a browser identity.
///
/// Anti-bot systems correlate these values with the User-Agent to detect spoofing.
/// Every field must be internally consistent with the claimed browser and OS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigatorProperties {
    pub persona: PersonaId,
    pub hardware_concurrency: u32,
    pub device_memory_gb: f64,
    pub platform: String,
    pub languages: Vec<String>,
    pub max_touch_points: u32,
    pub user_agent: String,
    pub app_version: String,
    pub vendor: String,
    pub product: String,
    pub product_sub: String,
    pub do_not_track: Option<String>,
    pub cookie_enabled: bool,
    pub pdf_viewer_enabled: bool,
    pub webdriver: bool,
}

/// Configuration controlling which property ranges to use.
#[derive(Debug, Clone)]
pub struct NavigatorSynthConfig {
    pub locale: String,
    pub secondary_languages: Vec<String>,
    pub seed: u64,
}

impl Default for NavigatorSynthConfig {
    fn default() -> Self {
        Self {
            locale: "en-US".to_string(),
            secondary_languages: vec!["en".to_string()],
            seed: 0,
        }
    }
}

/// Hardware concurrency options per platform class.
const DESKTOP_CONCURRENCY: &[u32] = &[4, 6, 8, 12, 16];
const MOBILE_CONCURRENCY: &[u32] = &[4, 6, 8];
const BOT_CONCURRENCY: &[u32] = &[2, 4];

/// Device memory tiers reported by `navigator.deviceMemory` (Chrome only, rounded).
const DESKTOP_MEMORY_GB: &[f64] = &[4.0, 8.0, 16.0, 32.0];
const MOBILE_MEMORY_GB: &[f64] = &[2.0, 4.0, 6.0, 8.0];

/// Platform strings matching real `navigator.platform` values.
const WINDOWS_PLATFORM: &str = "Win32";
const MACOS_PLATFORM: &str = "MacIntel";
const LINUX_PLATFORM: &str = "Linux x86_64";
const ANDROID_PLATFORM: &str = "Linux armv81";
const IOS_PLATFORM: &str = "iPhone";

/// Synthesize a complete navigator property set for the given persona.
///
/// The seed selects among plausible hardware configurations so each session
/// gets a distinct-but-valid identity. All returned values are cross-validated
/// to match what a real browser of that type would report.
pub fn synthesize_navigator(
    persona: PersonaId,
    config: &NavigatorSynthConfig,
) -> NavigatorProperties {
    let seed = config.seed;

    let (concurrency_options, memory_options, is_mobile) = match persona {
        PersonaId::ChromeDesktop
        | PersonaId::FirefoxDesktop
        | PersonaId::SafariDesktop
        | PersonaId::EdgeDesktop
        | PersonaId::OperaDesktop => (DESKTOP_CONCURRENCY, DESKTOP_MEMORY_GB, false),
        PersonaId::ChromeMobile | PersonaId::SafariMobile => {
            (MOBILE_CONCURRENCY, MOBILE_MEMORY_GB, true)
        }
        PersonaId::Googlebot | PersonaId::CurlClient | PersonaId::PythonRequests => {
            (BOT_CONCURRENCY, &[4.0, 8.0][..], false)
        }
    };

    let hardware_concurrency = concurrency_options[(seed as usize) % concurrency_options.len()];
    let device_memory_gb = memory_options[(seed as usize) % memory_options.len()];

    let platform = platform_string(persona);
    let max_touch_points = if is_mobile { 5 } else { 0 };

    let mut languages = vec![config.locale.clone()];
    for lang in &config.secondary_languages {
        if !languages.contains(lang) {
            languages.push(lang.clone());
        }
    }

    let (user_agent, app_version, vendor, product_sub) = ua_components(persona, seed);

    NavigatorProperties {
        persona,
        hardware_concurrency,
        device_memory_gb,
        platform: platform.to_string(),
        languages,
        max_touch_points,
        user_agent,
        app_version,
        vendor,
        product: "Gecko".to_string(),
        product_sub,
        do_not_track: Some("1".to_string()),
        cookie_enabled: true,
        pdf_viewer_enabled: !is_mobile,
        webdriver: false,
    }
}

fn platform_string(persona: PersonaId) -> &'static str {
    match persona {
        PersonaId::ChromeDesktop | PersonaId::EdgeDesktop | PersonaId::OperaDesktop => {
            WINDOWS_PLATFORM
        }
        PersonaId::SafariDesktop => MACOS_PLATFORM,
        PersonaId::FirefoxDesktop => LINUX_PLATFORM,
        PersonaId::ChromeMobile => ANDROID_PLATFORM,
        PersonaId::SafariMobile => IOS_PLATFORM,
        PersonaId::Googlebot | PersonaId::CurlClient | PersonaId::PythonRequests => LINUX_PLATFORM,
    }
}

fn ua_components(persona: PersonaId, seed: u64) -> (String, String, String, String) {
    let chrome_versions = ["120.0.6099.109", "121.0.6167.85", "122.0.6261.69"];
    let firefox_versions = ["121.0", "122.0", "123.0"];
    let safari_versions = ["17.2.1", "17.3", "17.4"];

    let idx = (seed as usize) % 3;

    match persona {
        PersonaId::ChromeDesktop => {
            let ver = chrome_versions[idx];
            (
                format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36"),
                format!("5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36"),
                "Google Inc.".to_string(),
                "20030107".to_string(),
            )
        }
        PersonaId::FirefoxDesktop => {
            let ver = firefox_versions[idx];
            (
                format!("Mozilla/5.0 (X11; Linux x86_64; rv:{ver}) Gecko/20100101 Firefox/{ver}"),
                format!("5.0 (X11)"),
                String::new(),
                "20100101".to_string(),
            )
        }
        PersonaId::SafariDesktop => {
            let ver = safari_versions[idx];
            (
                format!("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{ver} Safari/605.1.15"),
                format!("5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{ver} Safari/605.1.15"),
                "Apple Computer, Inc.".to_string(),
                "20030107".to_string(),
            )
        }
        PersonaId::EdgeDesktop => {
            let ver = chrome_versions[idx];
            (
                format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36 Edg/{ver}"),
                format!("5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36 Edg/{ver}"),
                "Google Inc.".to_string(),
                "20030107".to_string(),
            )
        }
        PersonaId::ChromeMobile => {
            let ver = chrome_versions[idx];
            (
                format!("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Mobile Safari/537.36"),
                format!("5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Mobile Safari/537.36"),
                "Google Inc.".to_string(),
                "20030107".to_string(),
            )
        }
        PersonaId::SafariMobile => {
            let ver = safari_versions[idx];
            (
                format!("Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{ver} Mobile/15E148 Safari/604.1"),
                format!("5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{ver} Mobile/15E148 Safari/604.1"),
                "Apple Computer, Inc.".to_string(),
                "20030107".to_string(),
            )
        }
        PersonaId::Googlebot => (
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)".to_string(),
            "5.0 (compatible; Googlebot/2.1)".to_string(),
            String::new(),
            "20030107".to_string(),
        ),
        PersonaId::OperaDesktop => {
            let ver = chrome_versions[idx];
            (
                format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36 OPR/106.0.0.0"),
                format!("5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36 OPR/106.0.0.0"),
                "Google Inc.".to_string(),
                "20030107".to_string(),
            )
        }
        PersonaId::CurlClient => (
            "curl/8.4.0".to_string(),
            "curl/8.4.0".to_string(),
            String::new(),
            String::new(),
        ),
        PersonaId::PythonRequests => (
            "python-requests/2.31.0".to_string(),
            "python-requests/2.31.0".to_string(),
            String::new(),
            String::new(),
        ),
    }
}

/// Validates that navigator properties are internally consistent.
pub fn validate_navigator(props: &NavigatorProperties) -> Vec<String> {
    let mut errors = Vec::new();

    if props.webdriver {
        errors.push("webdriver should be false for evasion".to_string());
    }

    if props.languages.is_empty() {
        errors.push("languages list is empty".to_string());
    }

    let expected_platform = platform_string(props.persona);
    if props.platform != expected_platform {
        errors.push(format!(
            "platform '{}' does not match expected '{}' for {:?}",
            props.platform, expected_platform, props.persona
        ));
    }

    let is_mobile = matches!(
        props.persona,
        PersonaId::ChromeMobile | PersonaId::SafariMobile
    );
    if is_mobile && props.max_touch_points == 0 {
        errors.push("mobile persona should have max_touch_points > 0".to_string());
    }
    if !is_mobile && props.max_touch_points > 0 {
        errors.push("desktop persona should have max_touch_points == 0".to_string());
    }

    if props.hardware_concurrency == 0 {
        errors.push("hardware_concurrency should be > 0".to_string());
    }

    if props.device_memory_gb <= 0.0 {
        errors.push("device_memory_gb should be > 0".to_string());
    }

    errors
}
