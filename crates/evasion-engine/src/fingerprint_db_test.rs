use super::*;

#[test]
fn database_contains_at_least_50_entries() {
    let db = FingerprintDb::new();
    assert!(
        db.len() >= 50,
        "database has {} entries, expected ≥50",
        db.len()
    );
}

#[test]
fn database_is_not_empty() {
    let db = FingerprintDb::new();
    assert!(!db.is_empty());
}

#[test]
fn all_four_browser_families_present() {
    let db = FingerprintDb::new();
    assert!(!db.by_browser(BrowserFamily::Chrome).is_empty());
    assert!(!db.by_browser(BrowserFamily::Firefox).is_empty());
    assert!(!db.by_browser(BrowserFamily::Safari).is_empty());
    assert!(!db.by_browser(BrowserFamily::Edge).is_empty());
}

#[test]
fn three_os_families_present_for_chrome() {
    let db = FingerprintDb::new();
    let chrome = db.by_browser(BrowserFamily::Chrome);
    let oses: std::collections::HashSet<OsFamily> = chrome.iter().map(|e| e.id.os).collect();
    assert!(oses.contains(&OsFamily::Windows));
    assert!(oses.contains(&OsFamily::MacOs));
    assert!(oses.contains(&OsFamily::Linux));
}

#[test]
fn safari_has_macos_and_ios() {
    let db = FingerprintDb::new();
    let safari = db.by_browser(BrowserFamily::Safari);
    let oses: std::collections::HashSet<OsFamily> = safari.iter().map(|e| e.id.os).collect();
    assert!(oses.contains(&OsFamily::MacOs));
    assert!(oses.contains(&OsFamily::Ios));
}

#[test]
fn lookup_by_fingerprint_id() {
    let db = FingerprintDb::new();
    let id = FingerprintId {
        browser: BrowserFamily::Chrome,
        version: 120,
        os: OsFamily::Windows,
    };
    let entry = db.get(&id);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().id, id);
}

#[test]
fn lookup_nonexistent_returns_none() {
    let db = FingerprintDb::new();
    let id = FingerprintId {
        browser: BrowserFamily::Chrome,
        version: 999,
        os: OsFamily::Windows,
    };
    assert!(db.get(&id).is_none());
}

#[test]
fn persona_mapping_chrome_desktop() {
    let db = FingerprintDb::new();
    let entry = db.for_persona(PersonaId::ChromeDesktop);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().id.browser, BrowserFamily::Chrome);
}

#[test]
fn persona_mapping_firefox_desktop() {
    let db = FingerprintDb::new();
    let entry = db.for_persona(PersonaId::FirefoxDesktop);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().id.browser, BrowserFamily::Firefox);
}

#[test]
fn persona_mapping_safari_desktop() {
    let db = FingerprintDb::new();
    let entry = db.for_persona(PersonaId::SafariDesktop);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().id.browser, BrowserFamily::Safari);
}

#[test]
fn persona_mapping_edge_desktop() {
    let db = FingerprintDb::new();
    let entry = db.for_persona(PersonaId::EdgeDesktop);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().id.browser, BrowserFamily::Edge);
}

#[test]
fn ja4_compute_produces_valid_format() {
    let db = FingerprintDb::new();
    let entry = db
        .get(&FingerprintId {
            browser: BrowserFamily::Chrome,
            version: 125,
            os: OsFamily::Windows,
        })
        .unwrap();
    let ja4 = entry.ja4.compute();
    assert!(ja4.starts_with('t'), "JA4 must start with 't': {ja4}");
    let parts: Vec<&str> = ja4.split('_').collect();
    assert_eq!(parts.len(), 4, "JA4 must have 4 sections: {ja4}");
}

#[test]
fn ja4_differs_between_chrome_and_firefox() {
    let db = FingerprintDb::new();
    let chrome = db
        .get(&FingerprintId {
            browser: BrowserFamily::Chrome,
            version: 125,
            os: OsFamily::Windows,
        })
        .unwrap();
    let firefox = db
        .get(&FingerprintId {
            browser: BrowserFamily::Firefox,
            version: 125,
            os: OsFamily::Windows,
        })
        .unwrap();
    assert_ne!(chrome.ja4.compute(), firefox.ja4.compute());
}

#[test]
fn ja4s_compute_produces_valid_format() {
    let ja4s = Ja4sFingerprint {
        tls_version: 0x0303,
        chosen_cipher: cipher_suites::TLS_AES_128_GCM_SHA256,
        extensions: vec![extensions::SERVER_NAME, extensions::SUPPORTED_VERSIONS],
        alpn_selected: Some(AlpnProtocol::H2),
    };
    let result = ja4s.compute();
    assert!(result.starts_with('s'));
    let parts: Vec<&str> = result.split('_').collect();
    assert_eq!(parts.len(), 4);
}

#[test]
fn ja4h_compute_produces_valid_format() {
    let db = FingerprintDb::new();
    let entry = db
        .get(&FingerprintId {
            browser: BrowserFamily::Chrome,
            version: 120,
            os: OsFamily::Windows,
        })
        .unwrap();
    let ja4h = entry.ja4h.compute();
    let parts: Vec<&str> = ja4h.split('_').collect();
    assert_eq!(parts.len(), 4, "JA4H must have 4 sections: {ja4h}");
}

#[test]
fn ja4h_differs_between_chrome_and_firefox() {
    let db = FingerprintDb::new();
    let chrome = db
        .get(&FingerprintId {
            browser: BrowserFamily::Chrome,
            version: 125,
            os: OsFamily::Windows,
        })
        .unwrap();
    let firefox = db
        .get(&FingerprintId {
            browser: BrowserFamily::Firefox,
            version: 125,
            os: OsFamily::Windows,
        })
        .unwrap();
    assert_ne!(chrome.ja4h.compute(), firefox.ja4h.compute());
}

#[test]
fn ja4t_compute_produces_valid_format() {
    let ja4t = windows_ja4t();
    let result = ja4t.compute();
    let parts: Vec<&str> = result.split('_').collect();
    assert_eq!(parts.len(), 5, "JA4T must have 5 sections: {result}");
}

#[test]
fn ja4t_differs_between_windows_and_linux() {
    let win = windows_ja4t().compute();
    let linux = linux_ja4t().compute();
    assert_ne!(win, linux);
}

#[test]
fn ja4t_ttl_range_bucketing() {
    let mut fp = windows_ja4t();
    fp.ttl = 128;
    let result = fp.compute();
    assert!(
        result.contains("128"),
        "TTL 128 should bucket to 128: {result}"
    );

    fp.ttl = 64;
    let result = fp.compute();
    assert!(
        result.contains("64"),
        "TTL 64 should bucket to 64: {result}"
    );
}

#[test]
fn ja4x_compute_produces_valid_format() {
    let ja4x = standard_ja4x();
    let result = ja4x.compute();
    let parts: Vec<&str> = result.split('_').collect();
    assert_eq!(parts.len(), 3, "JA4X must have 3 sections: {result}");
}

#[test]
fn ja4x_rsa_vs_ecdsa_differ() {
    let rsa = standard_ja4x().compute();
    let ecdsa = ecdsa_ja4x().compute();
    assert_ne!(rsa, ecdsa);
}

#[test]
fn akamai_compute_produces_valid_format() {
    let akamai = chromium_akamai();
    let result = akamai.compute();
    let parts: Vec<&str> = result.split('|').collect();
    assert_eq!(
        parts.len(),
        4,
        "Akamai must have 4 pipe-separated sections: {result}"
    );
}

#[test]
fn akamai_differs_between_chrome_and_firefox() {
    let chrome = chromium_akamai().compute();
    let firefox = firefox_akamai().compute();
    assert_ne!(chrome, firefox);
}

#[test]
fn match_ja4_finds_exact_entry() {
    let db = FingerprintDb::new();
    let id = FingerprintId {
        browser: BrowserFamily::Chrome,
        version: 125,
        os: OsFamily::Windows,
    };
    let entry = db.get(&id).unwrap();
    let ja4 = entry.ja4.compute();

    let matches = db.match_ja4(&ja4);
    assert!(!matches.is_empty(), "should find at least one match");
    assert!(
        matches[0].1 > 0.9,
        "best match score should be >0.9, got {}",
        matches[0].1
    );
}

#[test]
fn match_ja4_empty_string_returns_empty() {
    let db = FingerprintDb::new();
    let matches = db.match_ja4("");
    assert!(matches.is_empty());
}

#[test]
fn match_ja4h_finds_exact_entry() {
    let db = FingerprintDb::new();
    let id = FingerprintId {
        browser: BrowserFamily::Firefox,
        version: 125,
        os: OsFamily::Linux,
    };
    let entry = db.get(&id).unwrap();
    let ja4h = entry.ja4h.compute();

    let matches = db.match_ja4h(&ja4h);
    assert!(!matches.is_empty(), "should find at least one match");
    assert!(
        matches[0].1 > 0.9,
        "best match score should be >0.9, got {}",
        matches[0].1
    );
}

#[test]
fn by_browser_returns_correct_family() {
    let db = FingerprintDb::new();
    for entry in db.by_browser(BrowserFamily::Firefox) {
        assert_eq!(entry.id.browser, BrowserFamily::Firefox);
    }
}

#[test]
fn by_os_returns_correct_os() {
    let db = FingerprintDb::new();
    for entry in db.by_os(OsFamily::Windows) {
        assert_eq!(entry.id.os, OsFamily::Windows);
    }
}

#[test]
fn all_entries_have_nonempty_user_agent() {
    let db = FingerprintDb::new();
    for entry in db.all() {
        assert!(
            !entry.user_agent.is_empty(),
            "entry {:?} has empty user_agent",
            entry.id
        );
    }
}

#[test]
fn unique_fingerprint_ids() {
    let db = FingerprintDb::new();
    let mut seen = std::collections::HashSet::new();
    for entry in db.all() {
        assert!(
            seen.insert(entry.id.clone()),
            "duplicate fingerprint id: {:?}",
            entry.id
        );
    }
}

#[test]
fn sha256_known_vector() {
    let hash = sha256(b"abc");
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_empty_input() {
    let hash = sha256(b"");
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn fingerprint_id_display() {
    let id = FingerprintId {
        browser: BrowserFamily::Chrome,
        version: 125,
        os: OsFamily::Windows,
    };
    assert_eq!(format!("{id}"), "Chrome 125 on Windows");
}

#[test]
fn tcp_option_kind_values() {
    assert_eq!(TcpOption::Mss.kind(), 2);
    assert_eq!(TcpOption::WindowScale.kind(), 3);
    assert_eq!(TcpOption::SackPermitted.kind(), 4);
    assert_eq!(TcpOption::Timestamps.kind(), 8);
    assert_eq!(TcpOption::Nop.kind(), 1);
    assert_eq!(TcpOption::EndOfOptions.kind(), 0);
}
