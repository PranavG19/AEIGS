use super::*;

#[test]
fn database_contains_all_profiles() {
    let db = TlsClientHelloDb::new();
    assert_eq!(db.len(), 7);
    assert!(!db.is_empty());
    assert!(db.get(&TlsClientHelloBrowserId::Chrome120).is_some());
    assert!(db.get(&TlsClientHelloBrowserId::Chrome125).is_some());
    assert!(db.get(&TlsClientHelloBrowserId::Firefox121).is_some());
    assert!(db.get(&TlsClientHelloBrowserId::Firefox125).is_some());
    assert!(db.get(&TlsClientHelloBrowserId::Safari17).is_some());
    assert!(db.get(&TlsClientHelloBrowserId::Edge120).is_some());
    assert!(db.get(&TlsClientHelloBrowserId::Curl).is_some());
}

#[test]
fn all_personas_have_clienthello_mapping() {
    let db = TlsClientHelloDb::new();
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
            "no ClientHello profile for {persona:?}"
        );
    }
}

#[test]
fn chrome_cipher_order_starts_with_tls13() {
    let db = TlsClientHelloDb::new();
    let chrome = db.get(&TlsClientHelloBrowserId::Chrome120).unwrap();

    assert_eq!(
        chrome.cipher_suites[0],
        cipher_suites::TLS_AES_128_GCM_SHA256
    );
    assert_eq!(
        chrome.cipher_suites[1],
        cipher_suites::TLS_AES_256_GCM_SHA384
    );
    assert_eq!(
        chrome.cipher_suites[2],
        cipher_suites::TLS_CHACHA20_POLY1305_SHA256
    );
}

#[test]
fn firefox_cipher_order_differs_from_chrome() {
    let db = TlsClientHelloDb::new();
    let chrome = db.get(&TlsClientHelloBrowserId::Chrome120).unwrap();
    let firefox = db.get(&TlsClientHelloBrowserId::Firefox121).unwrap();

    assert_ne!(chrome.cipher_suites, firefox.cipher_suites);
    // Firefox puts CHACHA20 second, Chrome puts AES256 second
    assert_eq!(
        firefox.cipher_suites[1],
        cipher_suites::TLS_CHACHA20_POLY1305_SHA256
    );
    assert_eq!(
        chrome.cipher_suites[1],
        cipher_suites::TLS_AES_256_GCM_SHA384
    );
}

#[test]
fn chrome_has_kyber768_in_supported_groups() {
    let db = TlsClientHelloDb::new();
    let chrome = db.get(&TlsClientHelloBrowserId::Chrome120).unwrap();

    assert!(
        chrome
            .supported_groups
            .contains(&named_groups::X25519_KYBER768)
    );
    assert_eq!(chrome.supported_groups[0], named_groups::X25519_KYBER768);
}

#[test]
fn safari_has_no_kyber768() {
    let db = TlsClientHelloDb::new();
    let safari = db.get(&TlsClientHelloBrowserId::Safari17).unwrap();

    assert!(
        !safari
            .supported_groups
            .contains(&named_groups::X25519_KYBER768)
    );
    assert_eq!(safari.supported_groups[0], named_groups::X25519);
}

#[test]
fn firefox_has_ffdhe_groups() {
    let db = TlsClientHelloDb::new();
    let firefox = db.get(&TlsClientHelloBrowserId::Firefox121).unwrap();

    assert!(firefox.supported_groups.contains(&named_groups::FFDHE2048));
    assert!(firefox.supported_groups.contains(&named_groups::FFDHE3072));
}

#[test]
fn chrome_has_no_ffdhe_groups() {
    let db = TlsClientHelloDb::new();
    let chrome = db.get(&TlsClientHelloBrowserId::Chrome120).unwrap();

    assert!(!chrome.supported_groups.contains(&named_groups::FFDHE2048));
}

#[test]
fn firefox_supports_delegated_credentials() {
    let db = TlsClientHelloDb::new();
    let firefox = db.get(&TlsClientHelloBrowserId::Firefox121).unwrap();

    assert!(firefox.supports_delegated_credentials);
    assert!(firefox.supports_post_handshake_auth);
    assert!(
        firefox
            .extension_order
            .contains(&extensions::DELEGATED_CREDENTIALS)
    );
    assert!(
        firefox
            .extension_order
            .contains(&extensions::POST_HANDSHAKE_AUTH)
    );
}

#[test]
fn chrome_does_not_support_delegated_credentials() {
    let db = TlsClientHelloDb::new();
    let chrome = db.get(&TlsClientHelloBrowserId::Chrome120).unwrap();

    assert!(!chrome.supports_delegated_credentials);
    assert!(!chrome.supports_post_handshake_auth);
}

#[test]
fn chrome_has_compressed_certificate() {
    let db = TlsClientHelloDb::new();
    let chrome = db.get(&TlsClientHelloBrowserId::Chrome120).unwrap();

    assert!(!chrome.compress_certificate_algorithms.is_empty());
    assert_eq!(chrome.compress_certificate_algorithms[0], 2); // brotli
    assert!(
        chrome
            .extension_order
            .contains(&extensions::COMPRESSED_CERTIFICATE)
    );
}

#[test]
fn firefox_has_record_size_limit() {
    let db = TlsClientHelloDb::new();
    let firefox = db.get(&TlsClientHelloBrowserId::Firefox121).unwrap();

    assert_eq!(firefox.record_size_limit, Some(16385));
    assert!(
        firefox
            .extension_order
            .contains(&extensions::RECORD_SIZE_LIMIT)
    );
}

#[test]
fn edge_matches_chrome_ciphers() {
    let db = TlsClientHelloDb::new();
    let chrome = db.get(&TlsClientHelloBrowserId::Chrome120).unwrap();
    let edge = db.get(&TlsClientHelloBrowserId::Edge120).unwrap();

    assert_eq!(chrome.cipher_suites, edge.cipher_suites);
    assert_eq!(chrome.extension_order, edge.extension_order);
    assert_eq!(chrome.supported_groups, edge.supported_groups);
}

#[test]
fn all_profiles_have_nonempty_cipher_suites() {
    let db = TlsClientHelloDb::new();
    for profile in db.all() {
        assert!(
            !profile.cipher_suites.is_empty(),
            "{} has empty cipher suites",
            profile.browser_id
        );
    }
}

#[test]
fn all_profiles_have_nonempty_supported_groups() {
    let db = TlsClientHelloDb::new();
    for profile in db.all() {
        assert!(
            !profile.supported_groups.is_empty(),
            "{} has empty supported_groups",
            profile.browser_id
        );
    }
}

#[test]
fn all_profiles_have_nonempty_sig_algs() {
    let db = TlsClientHelloDb::new();
    for profile in db.all() {
        assert!(
            !profile.signature_algorithms.is_empty(),
            "{} has empty signature_algorithms",
            profile.browser_id
        );
    }
}

#[test]
fn all_profiles_have_alpn() {
    let db = TlsClientHelloDb::new();
    for profile in db.all() {
        assert!(
            !profile.alpn_protocols.is_empty(),
            "{} has empty ALPN",
            profile.browser_id
        );
        assert!(profile.alpn_protocols.contains(&AlpnProtocol::H2));
    }
}

#[test]
fn all_profiles_pass_validation() {
    let db = TlsClientHelloDb::new();
    for profile in db.all() {
        let issues = validate_clienthello(profile);
        assert!(
            issues.is_empty(),
            "{} has validation issues: {:?}",
            profile.browser_id,
            issues
        );
    }
}

#[test]
fn key_share_groups_subset_of_supported_groups() {
    let db = TlsClientHelloDb::new();
    for profile in db.all() {
        for kg in &profile.key_share_groups {
            assert!(
                profile.supported_groups.contains(kg),
                "{}: key_share group 0x{:04X} not in supported_groups",
                profile.browser_id,
                kg
            );
        }
    }
}

#[test]
fn ja3_string_contains_version_and_ciphers() {
    let db = TlsClientHelloDb::new();
    let chrome = db.get(&TlsClientHelloBrowserId::Chrome120).unwrap();
    let ja3 = chrome.ja3_string();

    assert!(ja3.starts_with("771,")); // 0x0303 = 771
    assert!(ja3.contains("4865")); // TLS_AES_128_GCM_SHA256
    assert!(ja3.contains("4866")); // TLS_AES_256_GCM_SHA384
}

#[test]
fn ja3_hash_is_32_hex_chars() {
    let db = TlsClientHelloDb::new();
    let chrome = db.get(&TlsClientHelloBrowserId::Chrome120).unwrap();
    let hash = chrome.ja3_hash();

    assert_eq!(hash.len(), 32);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn ja3_hashes_differ_between_browsers() {
    let db = TlsClientHelloDb::new();
    let chrome = db.get(&TlsClientHelloBrowserId::Chrome120).unwrap();
    let firefox = db.get(&TlsClientHelloBrowserId::Firefox121).unwrap();
    let safari = db.get(&TlsClientHelloBrowserId::Safari17).unwrap();

    let chrome_ja3 = chrome.ja3_hash();
    let firefox_ja3 = firefox.ja3_hash();
    let safari_ja3 = safari.ja3_hash();

    assert_ne!(chrome_ja3, firefox_ja3);
    assert_ne!(chrome_ja3, safari_ja3);
    assert_ne!(firefox_ja3, safari_ja3);
}

#[test]
fn ja4_string_has_correct_format() {
    let db = TlsClientHelloDb::new();
    let chrome = db.get(&TlsClientHelloBrowserId::Chrome120).unwrap();
    let ja4 = chrome.ja4_string();

    assert!(ja4.starts_with("t12d")); // TLS 1.2 record layer, has SNI
    assert!(ja4.contains('_'));
}

#[test]
fn extension_ordering_differs_per_browser() {
    let db = TlsClientHelloDb::new();
    let chrome = db.get(&TlsClientHelloBrowserId::Chrome120).unwrap();
    let firefox = db.get(&TlsClientHelloBrowserId::Firefox121).unwrap();
    let safari = db.get(&TlsClientHelloBrowserId::Safari17).unwrap();

    assert_ne!(chrome.extension_order, firefox.extension_order);
    assert_ne!(chrome.extension_order, safari.extension_order);
    assert_ne!(firefox.extension_order, safari.extension_order);
}

#[test]
fn identify_chrome_by_cipher_order() {
    let db = TlsClientHelloDb::new();
    let chrome = db.get(&TlsClientHelloBrowserId::Chrome120).unwrap();

    let result = db.identify_by_cipher_order(&chrome.cipher_suites);
    assert!(result.is_some());
    let browser_id = result.unwrap();
    assert!(
        browser_id == TlsClientHelloBrowserId::Chrome120
            || browser_id == TlsClientHelloBrowserId::Chrome125
            || browser_id == TlsClientHelloBrowserId::Edge120
    );
}

#[test]
fn unknown_cipher_order_returns_none() {
    let db = TlsClientHelloDb::new();
    let result = db.identify_by_cipher_order(&[0xFFFF, 0xFFFE]);
    assert!(result.is_none());
}

#[test]
fn tls_fingerprint_mapping_works() {
    let db = TlsClientHelloDb::new();

    assert!(db.for_tls_fingerprint(TlsFingerprint::Chrome120).is_some());
    assert!(db.for_tls_fingerprint(TlsFingerprint::Firefox121).is_some());
    assert!(db.for_tls_fingerprint(TlsFingerprint::Safari17).is_some());
    assert!(db.for_tls_fingerprint(TlsFingerprint::Edge120).is_some());
    assert!(db.for_tls_fingerprint(TlsFingerprint::Curl).is_some());
}

#[test]
fn clienthello_for_persona_returns_correct_browser() {
    let chrome = clienthello_for_persona(PersonaId::ChromeDesktop);
    assert_eq!(chrome.browser_id, TlsClientHelloBrowserId::Chrome125);

    let firefox = clienthello_for_persona(PersonaId::FirefoxDesktop);
    assert_eq!(firefox.browser_id, TlsClientHelloBrowserId::Firefox125);

    let safari = clienthello_for_persona(PersonaId::SafariDesktop);
    assert_eq!(safari.browser_id, TlsClientHelloBrowserId::Safari17);

    let edge = clienthello_for_persona(PersonaId::EdgeDesktop);
    assert_eq!(edge.browser_id, TlsClientHelloBrowserId::Edge120);

    let curl = clienthello_for_persona(PersonaId::CurlClient);
    assert_eq!(curl.browser_id, TlsClientHelloBrowserId::Curl);
}

#[test]
fn alpn_protocol_display() {
    assert_eq!(AlpnProtocol::H2.to_string(), "h2");
    assert_eq!(AlpnProtocol::Http11.to_string(), "http/1.1");
}

#[test]
fn alpn_protocol_wire_bytes() {
    assert_eq!(AlpnProtocol::H2.wire_bytes(), b"h2");
    assert_eq!(AlpnProtocol::Http11.wire_bytes(), b"http/1.1");
}

#[test]
fn psk_key_exchange_mode_wire_ids() {
    assert_eq!(PskKeyExchangeMode::PskKe.wire_id(), 0);
    assert_eq!(PskKeyExchangeMode::PskDheKe.wire_id(), 1);
}

#[test]
fn browser_id_display_nonempty() {
    assert!(!TlsClientHelloBrowserId::Chrome120.to_string().is_empty());
    assert!(!TlsClientHelloBrowserId::Firefox121.to_string().is_empty());
    assert!(!TlsClientHelloBrowserId::Safari17.to_string().is_empty());
    assert!(!TlsClientHelloBrowserId::Curl.to_string().is_empty());
}

#[test]
fn cipher_suite_constants_are_correct() {
    assert_eq!(cipher_suites::TLS_AES_128_GCM_SHA256, 0x1301);
    assert_eq!(cipher_suites::TLS_AES_256_GCM_SHA384, 0x1302);
    assert_eq!(cipher_suites::TLS_CHACHA20_POLY1305_SHA256, 0x1303);
    assert_eq!(cipher_suites::ECDHE_ECDSA_AES_128_GCM_SHA256, 0xC02B);
    assert_eq!(cipher_suites::ECDHE_RSA_AES_128_GCM_SHA256, 0xC02F);
}

#[test]
fn extension_constants_are_correct() {
    assert_eq!(extensions::SERVER_NAME, 0);
    assert_eq!(extensions::SUPPORTED_GROUPS, 10);
    assert_eq!(extensions::SIGNATURE_ALGORITHMS, 13);
    assert_eq!(extensions::KEY_SHARE, 51);
    assert_eq!(extensions::SUPPORTED_VERSIONS, 43);
    assert_eq!(extensions::PSK_KEY_EXCHANGE_MODES, 45);
}

#[test]
fn named_group_constants_are_correct() {
    assert_eq!(named_groups::X25519, 0x001D);
    assert_eq!(named_groups::SECP256R1, 0x0017);
    assert_eq!(named_groups::SECP384R1, 0x0018);
    assert_eq!(named_groups::X25519_KYBER768, 0x6399);
}

#[test]
fn sig_alg_constants_are_correct() {
    assert_eq!(sig_algs::ECDSA_SECP256R1_SHA256, 0x0403);
    assert_eq!(sig_algs::RSA_PSS_RSAE_SHA256, 0x0804);
    assert_eq!(sig_algs::RSA_PKCS1_SHA256, 0x0401);
}

#[test]
fn curl_has_minimal_extension_set() {
    let db = TlsClientHelloDb::new();
    let curl = db.get(&TlsClientHelloBrowserId::Curl).unwrap();

    assert!(
        !curl
            .extension_order
            .contains(&extensions::COMPRESSED_CERTIFICATE)
    );
    assert!(
        !curl
            .extension_order
            .contains(&extensions::APPLICATION_SETTINGS)
    );
    assert!(
        !curl
            .extension_order
            .contains(&extensions::DELEGATED_CREDENTIALS)
    );
    assert!(curl.compress_certificate_algorithms.is_empty());
}

#[test]
fn safari_has_encrypt_then_mac() {
    let db = TlsClientHelloDb::new();
    let safari = db.get(&TlsClientHelloBrowserId::Safari17).unwrap();

    assert!(
        safari
            .extension_order
            .contains(&extensions::ENCRYPT_THEN_MAC)
    );
}

#[test]
fn chrome_has_no_encrypt_then_mac() {
    let db = TlsClientHelloDb::new();
    let chrome = db.get(&TlsClientHelloBrowserId::Chrome120).unwrap();

    assert!(
        !chrome
            .extension_order
            .contains(&extensions::ENCRYPT_THEN_MAC)
    );
}

#[test]
fn md5_hash_known_value() {
    // MD5("") = d41d8cd98f00b204e9800998ecf8427e
    let hash = md5_hash(b"");
    assert_eq!(format!("{hash:032x}"), "d41d8cd98f00b204e9800998ecf8427e");
}

#[test]
fn md5_hash_hello_world() {
    // MD5("Hello, World!") = 65a8e27d8879283831b664bd8b7f0ad4
    let hash = md5_hash(b"Hello, World!");
    assert_eq!(format!("{hash:032x}"), "65a8e27d8879283831b664bd8b7f0ad4");
}

#[test]
fn validate_detects_key_share_not_in_supported_groups() {
    let mut profile = chrome_120_clienthello();
    profile.key_share_groups = vec![0xFFFF]; // bogus group
    let issues = validate_clienthello(&profile);
    assert!(!issues.is_empty());
    assert!(issues[0].contains("key_share group"));
}

#[test]
fn validate_detects_empty_cipher_suites() {
    let mut profile = chrome_120_clienthello();
    profile.cipher_suites = vec![];
    let issues = validate_clienthello(&profile);
    assert!(issues.iter().any(|i| i.contains("empty cipher suite")));
}
