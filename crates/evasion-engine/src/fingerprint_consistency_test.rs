use super::fingerprint_consistency::*;
use super::PersonaId;

#[test]
fn deterministic_canvas_hash_same_seed_same_result() {
    let fp1 = generate_fingerprint(PersonaId::ChromeDesktop, 42);
    let fp2 = generate_fingerprint(PersonaId::ChromeDesktop, 42);
    assert_eq!(fp1.canvas_hash, fp2.canvas_hash);
}

#[test]
fn deterministic_audio_context_hash_same_seed() {
    let fp1 = generate_fingerprint(PersonaId::FirefoxDesktop, 99);
    let fp2 = generate_fingerprint(PersonaId::FirefoxDesktop, 99);
    assert_eq!(fp1.audio_context_hash, fp2.audio_context_hash);
}

#[test]
fn different_seeds_produce_different_hashes() {
    let fp1 = generate_fingerprint(PersonaId::ChromeDesktop, 1);
    let fp2 = generate_fingerprint(PersonaId::ChromeDesktop, 2);
    assert_ne!(fp1.canvas_hash, fp2.canvas_hash);
}

#[test]
fn different_personas_produce_different_hashes() {
    let fp1 = generate_fingerprint(PersonaId::ChromeDesktop, 42);
    let fp2 = generate_fingerprint(PersonaId::SafariDesktop, 42);
    assert_ne!(fp1.canvas_hash, fp2.canvas_hash);
}

#[test]
fn webgl_renderer_matches_os_family() {
    let fp = generate_fingerprint(PersonaId::SafariDesktop, 0);
    assert!(
        fp.webgl_renderer.contains("Apple"),
        "Safari should get Apple GPU, got: {}",
        fp.webgl_renderer
    );
    assert_eq!(fp.webgl_vendor, "Apple");
}

#[test]
fn windows_persona_gets_windows_fonts() {
    let fp = generate_fingerprint(PersonaId::ChromeDesktop, 0);
    assert!(fp.font_list.contains(&"Segoe UI".to_string()));
    assert!(fp.font_list.contains(&"Calibri".to_string()));
}

#[test]
fn macos_persona_gets_macos_fonts() {
    let fp = generate_fingerprint(PersonaId::SafariDesktop, 0);
    assert!(fp.font_list.contains(&"Helvetica Neue".to_string()));
    assert!(fp.font_list.contains(&"San Francisco".to_string()));
}

#[test]
fn linux_persona_gets_linux_fonts() {
    let fp = generate_fingerprint(PersonaId::FirefoxDesktop, 0);
    assert!(fp.font_list.contains(&"DejaVu Sans".to_string()));
    assert!(fp.font_list.contains(&"Liberation Sans".to_string()));
}

#[test]
fn android_persona_gets_android_fonts() {
    let fp = generate_fingerprint(PersonaId::ChromeMobile, 0);
    assert!(fp.font_list.contains(&"Roboto".to_string()));
}

#[test]
fn ios_persona_gets_ios_fonts() {
    let fp = generate_fingerprint(PersonaId::SafariMobile, 0);
    assert!(fp.font_list.contains(&"San Francisco".to_string()));
    assert!(fp.font_list.contains(&"Helvetica Neue".to_string()));
}

#[test]
fn gpu_renderer_string_matches_os() {
    let fp = generate_fingerprint(PersonaId::SafariDesktop, 0);
    assert!(
        fp.gpu_renderer_string.contains("Apple"),
        "macOS persona should get Apple GPU renderer, got: {}",
        fp.gpu_renderer_string
    );
}

#[test]
fn validate_fingerprint_passes_for_valid() {
    let fp = generate_fingerprint(PersonaId::ChromeDesktop, 42);
    let errors = validate_fingerprint(&fp);
    assert!(errors.is_empty(), "expected no errors, got: {:?}", errors);
}

#[test]
fn validate_fingerprint_catches_empty_canvas() {
    let mut fp = generate_fingerprint(PersonaId::ChromeDesktop, 42);
    fp.canvas_hash = String::new();
    let errors = validate_fingerprint(&fp);
    assert!(errors.iter().any(|e| e.contains("canvas_hash")));
}

#[test]
fn validate_fingerprint_catches_wrong_renderer() {
    let mut fp = generate_fingerprint(PersonaId::ChromeDesktop, 42);
    fp.webgl_renderer = "Apple M1 Pro".to_string();
    let errors = validate_fingerprint(&fp);
    assert!(errors.iter().any(|e| e.contains("webgl_renderer")));
}

#[test]
fn fingerprint_database_caches() {
    let mut db = FingerprintDatabase::new();
    assert_eq!(db.cache_size(), 0);
    let _ = db.get_or_generate(PersonaId::ChromeDesktop, 1);
    assert_eq!(db.cache_size(), 1);
    let _ = db.get_or_generate(PersonaId::ChromeDesktop, 1);
    assert_eq!(db.cache_size(), 1);
    let _ = db.get_or_generate(PersonaId::ChromeDesktop, 2);
    assert_eq!(db.cache_size(), 2);
}

#[test]
fn fingerprint_database_clear() {
    let mut db = FingerprintDatabase::new();
    let _ = db.get_or_generate(PersonaId::ChromeDesktop, 1);
    let _ = db.get_or_generate(PersonaId::FirefoxDesktop, 2);
    assert_eq!(db.cache_size(), 2);
    db.clear();
    assert_eq!(db.cache_size(), 0);
}

#[test]
fn os_family_mapping_covers_all_personas() {
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
        let _ = OsFamily::from_persona(*p);
        let fp = generate_fingerprint(*p, 0);
        assert!(!fp.canvas_hash.is_empty());
        assert!(!fp.font_list.is_empty());
    }
}

#[test]
fn canvas_hash_is_hex_encoded() {
    let fp = generate_fingerprint(PersonaId::ChromeDesktop, 42);
    assert_eq!(fp.canvas_hash.len(), 16);
    assert!(fp.canvas_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn audio_context_hash_is_hex_encoded() {
    let fp = generate_fingerprint(PersonaId::ChromeDesktop, 42);
    assert_eq!(fp.audio_context_hash.len(), 16);
    assert!(fp.audio_context_hash.chars().all(|c| c.is_ascii_hexdigit()));
}
