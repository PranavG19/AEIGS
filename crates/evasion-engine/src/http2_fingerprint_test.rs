use super::*;

#[test]
fn database_contains_all_browser_profiles() {
    let db = Http2FingerprintDb::new();
    assert_eq!(db.len(), 7);
    assert!(!db.is_empty());

    assert!(db.get(&Http2BrowserId::Chrome120_125).is_some());
    assert!(db.get(&Http2BrowserId::Firefox120_125).is_some());
    assert!(db.get(&Http2BrowserId::Safari17).is_some());
    assert!(db.get(&Http2BrowserId::Edge120_125).is_some());
    assert!(db.get(&Http2BrowserId::Curl).is_some());
    assert!(db.get(&Http2BrowserId::GoNetHttp).is_some());
    assert!(db.get(&Http2BrowserId::PythonHttpx).is_some());
}

#[test]
fn all_personas_have_h2_mapping() {
    let db = Http2FingerprintDb::new();
    let personas = [
        PersonaId::ChromeDesktop,
        PersonaId::ChromeMobile,
        PersonaId::FirefoxDesktop,
        PersonaId::SafariDesktop,
        PersonaId::SafariMobile,
        PersonaId::EdgeDesktop,
        PersonaId::OperaDesktop,
        PersonaId::Googlebot,
        PersonaId::CurlClient,
        PersonaId::PythonRequests,
    ];
    for persona in personas {
        assert!(
            db.for_persona(persona).is_some(),
            "no H2 fingerprint for {persona:?}"
        );
    }
}

#[test]
fn chrome_settings_match_real_captures() {
    let db = Http2FingerprintDb::new();
    let chrome = db.get(&Http2BrowserId::Chrome120_125).unwrap();

    assert_eq!(
        chrome.settings_values.get(&Http2Setting::HeaderTableSize),
        Some(&65536)
    );
    assert_eq!(
        chrome.settings_values.get(&Http2Setting::EnablePush),
        Some(&0)
    );
    assert_eq!(
        chrome
            .settings_values
            .get(&Http2Setting::MaxConcurrentStreams),
        Some(&1000)
    );
    assert_eq!(
        chrome.settings_values.get(&Http2Setting::InitialWindowSize),
        Some(&6291456)
    );
    assert_eq!(
        chrome.settings_values.get(&Http2Setting::MaxHeaderListSize),
        Some(&262144)
    );

    assert_eq!(chrome.connection_window_update, 15663105);
}

#[test]
fn chrome_settings_order_correct() {
    let db = Http2FingerprintDb::new();
    let chrome = db.get(&Http2BrowserId::Chrome120_125).unwrap();

    assert_eq!(
        chrome.settings_order,
        vec![
            Http2Setting::HeaderTableSize,
            Http2Setting::EnablePush,
            Http2Setting::MaxConcurrentStreams,
            Http2Setting::InitialWindowSize,
            Http2Setting::MaxHeaderListSize,
        ]
    );
}

#[test]
fn firefox_differs_from_chrome() {
    let db = Http2FingerprintDb::new();
    let chrome = db.get(&Http2BrowserId::Chrome120_125).unwrap();
    let firefox = db.get(&Http2BrowserId::Firefox120_125).unwrap();

    assert_ne!(
        chrome.connection_window_update,
        firefox.connection_window_update
    );
    assert_ne!(chrome.pseudo_header_order, firefox.pseudo_header_order);
    assert_ne!(chrome.settings_order, firefox.settings_order);
}

#[test]
fn safari_has_webkit_pseudo_header_order() {
    let db = Http2FingerprintDb::new();
    let safari = db.get(&Http2BrowserId::Safari17).unwrap();

    assert_eq!(
        safari.pseudo_header_order,
        PseudoHeaderOrder::MethodSchemePathAuthorityWebkit
    );
    assert_eq!(
        safari.pseudo_header_order.header_names(),
        vec![":method", ":scheme", ":path", ":authority"]
    );
}

#[test]
fn firefox_has_mozilla_pseudo_header_order() {
    let db = Http2FingerprintDb::new();
    let firefox = db.get(&Http2BrowserId::Firefox120_125).unwrap();

    assert_eq!(
        firefox.pseudo_header_order,
        PseudoHeaderOrder::MethodPathAuthoritySchemeMozilla
    );
    assert_eq!(
        firefox.pseudo_header_order.header_names(),
        vec![":method", ":path", ":authority", ":scheme"]
    );
}

#[test]
fn edge_matches_chrome_settings() {
    let db = Http2FingerprintDb::new();
    let chrome = db.get(&Http2BrowserId::Chrome120_125).unwrap();
    let edge = db.get(&Http2BrowserId::Edge120_125).unwrap();

    assert_eq!(chrome.settings_values, edge.settings_values);
    assert_eq!(chrome.settings_order, edge.settings_order);
    assert_eq!(
        chrome.connection_window_update,
        edge.connection_window_update
    );
    assert_eq!(chrome.pseudo_header_order, edge.pseudo_header_order);
    assert_eq!(chrome.priority_frames, edge.priority_frames);
}

#[test]
fn akamai_fingerprint_format_chrome() {
    let db = Http2FingerprintDb::new();
    let chrome = db.get(&Http2BrowserId::Chrome120_125).unwrap();
    let fp = chrome.akamai_fingerprint();

    assert!(fp.contains("1:65536"));
    assert!(fp.contains("2:0"));
    assert!(fp.contains("3:1000"));
    assert!(fp.contains("4:6291456"));
    assert!(fp.contains("6:262144"));
    assert!(fp.contains("|15663105|"));
}

#[test]
fn akamai_fingerprint_format_firefox() {
    let db = Http2FingerprintDb::new();
    let firefox = db.get(&Http2BrowserId::Firefox120_125).unwrap();
    let fp = firefox.akamai_fingerprint();

    assert!(fp.contains("|12517377|"));
}

#[test]
fn identify_chrome_from_observed_params() {
    let db = Http2FingerprintDb::new();

    let mut settings = HashMap::new();
    settings.insert(Http2Setting::HeaderTableSize, 65536);
    settings.insert(Http2Setting::EnablePush, 0);
    settings.insert(Http2Setting::MaxConcurrentStreams, 1000);
    settings.insert(Http2Setting::InitialWindowSize, 6291456);
    settings.insert(Http2Setting::MaxHeaderListSize, 262144);

    let observed = ObservedHttp2Params {
        settings,
        settings_order: vec![
            Http2Setting::HeaderTableSize,
            Http2Setting::EnablePush,
            Http2Setting::MaxConcurrentStreams,
            Http2Setting::InitialWindowSize,
            Http2Setting::MaxHeaderListSize,
        ],
        connection_window_update: Some(15663105),
        priority_frame_count: 3,
        pseudo_header_order: Some(PseudoHeaderOrder::MethodAuthoritySchemePathChromium),
    };

    let result = db.identify(&observed);
    assert!(result.is_some());
    let (browser_id, confidence) = result.unwrap();
    assert!(
        browser_id == Http2BrowserId::Chrome120_125 || browser_id == Http2BrowserId::Edge120_125
    );
    assert!(confidence > 0.95, "confidence={confidence} should be >0.95");
}

#[test]
fn identify_firefox_from_observed_params() {
    let db = Http2FingerprintDb::new();

    let mut settings = HashMap::new();
    settings.insert(Http2Setting::HeaderTableSize, 65536);
    settings.insert(Http2Setting::InitialWindowSize, 131072);
    settings.insert(Http2Setting::MaxFrameSize, 16384);

    let observed = ObservedHttp2Params {
        settings,
        settings_order: vec![
            Http2Setting::HeaderTableSize,
            Http2Setting::InitialWindowSize,
            Http2Setting::MaxFrameSize,
        ],
        connection_window_update: Some(12517377),
        priority_frame_count: 5,
        pseudo_header_order: Some(PseudoHeaderOrder::MethodPathAuthoritySchemeMozilla),
    };

    let result = db.identify(&observed);
    assert!(result.is_some());
    let (browser_id, confidence) = result.unwrap();
    assert_eq!(browser_id, Http2BrowserId::Firefox120_125);
    assert!(confidence > 0.90, "confidence={confidence} should be >0.90");
}

#[test]
fn identify_safari_from_observed_params() {
    let db = Http2FingerprintDb::new();

    let mut settings = HashMap::new();
    settings.insert(Http2Setting::EnablePush, 1);
    settings.insert(Http2Setting::MaxConcurrentStreams, 100);
    settings.insert(Http2Setting::InitialWindowSize, 2097152);
    settings.insert(Http2Setting::MaxHeaderListSize, 0);

    let observed = ObservedHttp2Params {
        settings,
        settings_order: vec![
            Http2Setting::EnablePush,
            Http2Setting::MaxConcurrentStreams,
            Http2Setting::InitialWindowSize,
            Http2Setting::MaxHeaderListSize,
        ],
        connection_window_update: Some(10485760),
        priority_frame_count: 1,
        pseudo_header_order: Some(PseudoHeaderOrder::MethodSchemePathAuthorityWebkit),
    };

    let result = db.identify(&observed);
    assert!(result.is_some());
    let (browser_id, confidence) = result.unwrap();
    assert_eq!(browser_id, Http2BrowserId::Safari17);
    assert!(confidence > 0.90);
}

#[test]
fn unknown_params_return_none_below_threshold() {
    let db = Http2FingerprintDb::new();

    let mut settings = HashMap::new();
    settings.insert(Http2Setting::HeaderTableSize, 99999);
    settings.insert(Http2Setting::InitialWindowSize, 99999);

    let observed = ObservedHttp2Params {
        settings,
        settings_order: vec![],
        connection_window_update: Some(12345),
        priority_frame_count: 0,
        pseudo_header_order: None,
    };

    let result = db.identify(&observed);
    assert!(result.is_none());
}

#[test]
fn settings_to_wire_preserves_order() {
    let db = Http2FingerprintDb::new();
    let chrome = db.get(&Http2BrowserId::Chrome120_125).unwrap();
    let wire = settings_to_wire(chrome);

    assert_eq!(wire[0].0, 0x1); // HEADER_TABLE_SIZE
    assert_eq!(wire[1].0, 0x2); // ENABLE_PUSH
    assert_eq!(wire[2].0, 0x3); // MAX_CONCURRENT_STREAMS
    assert_eq!(wire[3].0, 0x4); // INITIAL_WINDOW_SIZE
    assert_eq!(wire[4].0, 0x6); // MAX_HEADER_LIST_SIZE

    assert_eq!(wire[0].1, 65536);
    assert_eq!(wire[1].1, 0);
    assert_eq!(wire[2].1, 1000);
    assert_eq!(wire[3].1, 6291456);
    assert_eq!(wire[4].1, 262144);
}

#[test]
fn setting_wire_ids_match_rfc7540() {
    assert_eq!(Http2Setting::HeaderTableSize.wire_id(), 0x1);
    assert_eq!(Http2Setting::EnablePush.wire_id(), 0x2);
    assert_eq!(Http2Setting::MaxConcurrentStreams.wire_id(), 0x3);
    assert_eq!(Http2Setting::InitialWindowSize.wire_id(), 0x4);
    assert_eq!(Http2Setting::MaxFrameSize.wire_id(), 0x5);
    assert_eq!(Http2Setting::MaxHeaderListSize.wire_id(), 0x6);
}

#[test]
fn pseudo_header_order_chromium_correct() {
    let order = PseudoHeaderOrder::MethodAuthoritySchemePathChromium;
    assert_eq!(
        order.header_names(),
        vec![":method", ":authority", ":scheme", ":path"]
    );
}

#[test]
fn pseudo_header_order_custom() {
    let order = PseudoHeaderOrder::Custom(vec![
        ":scheme".to_string(),
        ":method".to_string(),
        ":path".to_string(),
        ":authority".to_string(),
    ]);
    assert_eq!(
        order.header_names(),
        vec![":scheme", ":method", ":path", ":authority"]
    );
}

#[test]
fn h2_fingerprint_for_persona_returns_correct_browser() {
    let chrome_fp = h2_fingerprint_for_persona(PersonaId::ChromeDesktop);
    assert_eq!(chrome_fp.browser_id, Http2BrowserId::Chrome120_125);

    let firefox_fp = h2_fingerprint_for_persona(PersonaId::FirefoxDesktop);
    assert_eq!(firefox_fp.browser_id, Http2BrowserId::Firefox120_125);

    let safari_fp = h2_fingerprint_for_persona(PersonaId::SafariDesktop);
    assert_eq!(safari_fp.browser_id, Http2BrowserId::Safari17);

    let edge_fp = h2_fingerprint_for_persona(PersonaId::EdgeDesktop);
    assert_eq!(edge_fp.browser_id, Http2BrowserId::Edge120_125);

    let curl_fp = h2_fingerprint_for_persona(PersonaId::CurlClient);
    assert_eq!(curl_fp.browser_id, Http2BrowserId::Curl);
}

#[test]
fn all_fingerprints_have_nonempty_settings() {
    let db = Http2FingerprintDb::new();
    for fp in db.all() {
        assert!(
            !fp.settings_values.is_empty(),
            "{} has empty SETTINGS",
            fp.browser_id
        );
        assert!(
            !fp.settings_order.is_empty(),
            "{} has empty settings_order",
            fp.browser_id
        );
    }
}

#[test]
fn all_fingerprints_have_nonzero_window_update() {
    let db = Http2FingerprintDb::new();
    for fp in db.all() {
        assert!(
            fp.connection_window_update > 0,
            "{} has zero connection_window_update",
            fp.browser_id
        );
    }
}

#[test]
fn browser_window_update_sizes_are_distinct() {
    let db = Http2FingerprintDb::new();
    let chrome = db.get(&Http2BrowserId::Chrome120_125).unwrap();
    let firefox = db.get(&Http2BrowserId::Firefox120_125).unwrap();
    let safari = db.get(&Http2BrowserId::Safari17).unwrap();
    let curl = db.get(&Http2BrowserId::Curl).unwrap();

    let values = [
        chrome.connection_window_update,
        firefox.connection_window_update,
        safari.connection_window_update,
        curl.connection_window_update,
    ];
    let mut unique = values.to_vec();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        values.len(),
        "browser WINDOW_UPDATE values should be distinct"
    );
}

#[test]
fn chrome_window_update_is_15mb_minus_default() {
    let db = Http2FingerprintDb::new();
    let chrome = db.get(&Http2BrowserId::Chrome120_125).unwrap();
    // Chrome's WINDOW_UPDATE = INITIAL_WINDOW_SIZE (6MB*something) adjusted
    // The exact value 15663105 = 15*1024*1024 - 65535 + some delta
    assert_eq!(chrome.connection_window_update, 15663105);
}

#[test]
fn curl_has_no_priority_frames() {
    let db = Http2FingerprintDb::new();
    let curl = db.get(&Http2BrowserId::Curl).unwrap();
    assert!(curl.priority_frames.is_empty());
}

#[test]
fn chrome_has_priority_frames() {
    let db = Http2FingerprintDb::new();
    let chrome = db.get(&Http2BrowserId::Chrome120_125).unwrap();
    assert!(!chrome.priority_frames.is_empty());
    assert_eq!(chrome.priority_frames.len(), 3);
    assert!(chrome.priority_frames[0].exclusive);
}

#[test]
fn display_impls_return_nonempty_strings() {
    assert!(!Http2Setting::HeaderTableSize.to_string().is_empty());
    assert!(!Http2Setting::EnablePush.to_string().is_empty());
    assert!(!Http2BrowserId::Chrome120_125.to_string().is_empty());
    assert!(!Http2BrowserId::Firefox120_125.to_string().is_empty());
    assert!(!Http2BrowserId::Safari17.to_string().is_empty());
}

#[test]
fn partial_match_still_identifies_with_lower_confidence() {
    let db = Http2FingerprintDb::new();

    // Provide 4/5 Chrome settings + correct WINDOW_UPDATE + correct pseudo-header order
    // but omit settings_order and have wrong priority count — partial match
    let mut settings = HashMap::new();
    settings.insert(Http2Setting::HeaderTableSize, 65536);
    settings.insert(Http2Setting::EnablePush, 0);
    settings.insert(Http2Setting::InitialWindowSize, 6291456);
    settings.insert(Http2Setting::MaxConcurrentStreams, 1000);

    let observed = ObservedHttp2Params {
        settings,
        settings_order: vec![],
        connection_window_update: Some(15663105),
        priority_frame_count: 0,
        pseudo_header_order: Some(PseudoHeaderOrder::MethodAuthoritySchemePathChromium),
    };

    let result = db.identify(&observed);
    assert!(result.is_some());
    let (browser_id, confidence) = result.unwrap();
    assert!(
        browser_id == Http2BrowserId::Chrome120_125 || browser_id == Http2BrowserId::Edge120_125
    );
    // 4/5 settings (0.32) + WINDOW_UPDATE (0.20) + pseudo-header (0.15) = 0.67
    assert!(
        confidence > 0.6 && confidence < 0.95,
        "confidence={confidence} expected partial"
    );
}

#[test]
fn go_net_http_is_identifiable() {
    let db = Http2FingerprintDb::new();

    let mut settings = HashMap::new();
    settings.insert(Http2Setting::EnablePush, 0);
    settings.insert(Http2Setting::InitialWindowSize, 4194304);
    settings.insert(Http2Setting::MaxHeaderListSize, 10485760);

    let observed = ObservedHttp2Params {
        settings,
        settings_order: vec![
            Http2Setting::EnablePush,
            Http2Setting::InitialWindowSize,
            Http2Setting::MaxHeaderListSize,
        ],
        connection_window_update: Some(1073741824),
        priority_frame_count: 0,
        pseudo_header_order: None,
    };

    let result = db.identify(&observed);
    assert!(result.is_some());
    let (browser_id, _) = result.unwrap();
    assert_eq!(browser_id, Http2BrowserId::GoNetHttp);
}
