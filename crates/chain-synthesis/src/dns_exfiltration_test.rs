use crate::dns_exfiltration::*;

// =========================================================================
// Encoding roundtrip tests
// =========================================================================

#[test]
fn hex_roundtrip_simple() {
    let data = b"hello world";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(data, &config).unwrap();
    let decoded = decode_exfil(&payload.chunks, DnsEncoding::Hex, false, payload.crc32).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn base32_roundtrip_simple() {
    let data = b"hello world";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Base32, false);
    let payload = encode_exfil(data, &config).unwrap();
    let decoded = decode_exfil(&payload.chunks, DnsEncoding::Base32, false, payload.crc32).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn roundtrip_with_compression() {
    let data = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, true);
    let payload = encode_exfil(data, &config).unwrap();
    assert!(payload.compressed);
    let decoded = decode_exfil(&payload.chunks, DnsEncoding::Hex, true, payload.crc32).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn roundtrip_base32_compressed() {
    let data = b"repeated_data_repeated_data_repeated_data";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Base32, true);
    let payload = encode_exfil(data, &config).unwrap();
    let decoded = decode_exfil(&payload.chunks, DnsEncoding::Base32, true, payload.crc32).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn roundtrip_empty_data() {
    let data = b"";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(data, &config).unwrap();
    let decoded = decode_exfil(&payload.chunks, DnsEncoding::Hex, false, payload.crc32).unwrap();
    assert_eq!(decoded, data.to_vec());
}

#[test]
fn roundtrip_binary_data() {
    let data: Vec<u8> = (0..=255).collect();
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(&data, &config).unwrap();
    let decoded = decode_exfil(&payload.chunks, DnsEncoding::Hex, false, payload.crc32).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn roundtrip_binary_base32() {
    let data: Vec<u8> = (0..=255).collect();
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Base32, false);
    let payload = encode_exfil(&data, &config).unwrap();
    let decoded = decode_exfil(&payload.chunks, DnsEncoding::Base32, false, payload.crc32).unwrap();
    assert_eq!(decoded, data);
}

// =========================================================================
// DNS label limit enforcement
// =========================================================================

#[test]
fn labels_respect_63_char_limit() {
    let data = vec![0xAB; 512];
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(&data, &config).unwrap();
    let errors = validate_payload(&payload);
    assert!(errors.is_empty(), "validation errors: {errors:?}");

    for chunk in &payload.chunks {
        for label in chunk.query_name.split('.') {
            assert!(
                label.len() <= 63,
                "label '{}' is {} chars, exceeds 63",
                label,
                label.len()
            );
        }
    }
}

#[test]
fn total_query_name_respects_253_limit() {
    let data = vec![0xFF; 256];
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(&data, &config).unwrap();
    for chunk in &payload.chunks {
        assert!(
            chunk.query_name.len() <= 253,
            "query name is {} chars: {}",
            chunk.query_name.len(),
            chunk.query_name
        );
    }
}

#[test]
fn long_collector_domain_still_valid() {
    let data = b"test data here";
    let long_domain = "sub.domain.very.long.collector.example.com";
    let config = DnsExfilConfig::new(long_domain, DnsEncoding::Hex, false);
    let payload = encode_exfil(data, &config).unwrap();
    let errors = validate_payload(&payload);
    assert!(errors.is_empty(), "validation errors: {errors:?}");
}

// =========================================================================
// Multi-query chunking
// =========================================================================

#[test]
fn large_data_produces_multiple_chunks() {
    let data = vec![0x42; 1024];
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(&data, &config).unwrap();
    assert!(
        payload.chunks.len() > 1,
        "expected multiple chunks, got {}",
        payload.chunks.len()
    );
}

#[test]
fn chunks_have_sequential_numbers() {
    let data = vec![0x42; 1024];
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(&data, &config).unwrap();
    for (i, chunk) in payload.chunks.iter().enumerate() {
        assert_eq!(chunk.sequence, i as u16);
    }
}

#[test]
fn total_queries_includes_checksum() {
    let data = b"test";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(data, &config).unwrap();
    assert_eq!(payload.total_queries, payload.chunks.len() + 1);
}

// =========================================================================
// CRC32 integrity verification
// =========================================================================

#[test]
fn crc32_mismatch_detected() {
    let data = b"integrity check";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(data, &config).unwrap();
    let wrong_crc = payload.crc32 ^ 0xFFFFFFFF;
    let result = decode_exfil(&payload.chunks, DnsEncoding::Hex, false, wrong_crc);
    assert!(matches!(result, Err(DnsExfilError::InvalidChecksum { .. })));
}

#[test]
fn checksum_query_contains_crc() {
    let data = b"check crc";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(data, &config).unwrap();
    assert!(
        payload
            .checksum_query
            .contains(&format!("crc-{:08x}", payload.crc32))
    );
}

#[test]
fn checksum_query_contains_count() {
    let data = b"check count";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(data, &config).unwrap();
    assert!(
        payload
            .checksum_query
            .contains(&format!("cnt-{:04x}", payload.chunks.len()))
    );
}

// =========================================================================
// Payload generation — at least 6 languages
// =========================================================================

#[test]
fn bash_payload_uses_dig() {
    let data = b"secret";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(data, &config).unwrap();
    let script = generate_exfil_script(&payload, PayloadLanguage::Bash);
    assert!(script.contains("dig +short"));
    assert!(script.contains("c.test.com"));
}

#[test]
fn python_payload_uses_socket() {
    let data = b"secret";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(data, &config).unwrap();
    let script = generate_exfil_script(&payload, PayloadLanguage::Python);
    assert!(script.contains("socket.getaddrinfo"));
}

#[test]
fn php_payload_uses_gethostbyname() {
    let data = b"secret";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(data, &config).unwrap();
    let script = generate_exfil_script(&payload, PayloadLanguage::Php);
    assert!(script.contains("gethostbyname"));
    assert!(script.contains("<?php"));
}

#[test]
fn ruby_payload_uses_resolv() {
    let data = b"secret";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(data, &config).unwrap();
    let script = generate_exfil_script(&payload, PayloadLanguage::Ruby);
    assert!(script.contains("Resolv.getaddress"));
}

#[test]
fn perl_payload_uses_gethostbyname() {
    let data = b"secret";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(data, &config).unwrap();
    let script = generate_exfil_script(&payload, PayloadLanguage::Perl);
    assert!(script.contains("gethostbyname"));
    assert!(script.contains("use Socket"));
}

#[test]
fn powershell_payload_uses_resolve_dnsname() {
    let data = b"secret";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(data, &config).unwrap();
    let script = generate_exfil_script(&payload, PayloadLanguage::Powershell);
    assert!(script.contains("Resolve-DnsName"));
}

#[test]
fn all_six_languages_generate_non_empty_scripts() {
    let data = b"exfil";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(data, &config).unwrap();

    let languages = [
        PayloadLanguage::Bash,
        PayloadLanguage::Python,
        PayloadLanguage::Php,
        PayloadLanguage::Ruby,
        PayloadLanguage::Perl,
        PayloadLanguage::Powershell,
    ];
    for lang in &languages {
        let script = generate_exfil_script(&payload, *lang);
        assert!(!script.is_empty(), "script for {lang} should not be empty");
        assert!(
            script.contains("c.test.com"),
            "script for {lang} should reference collector domain"
        );
    }
}

// =========================================================================
// OOB callback payloads
// =========================================================================

#[test]
fn oob_blind_sqli_payload() {
    let p = generate_oob_payload(OobVulnType::BlindSqli, "tok123", "c.test.com");
    assert_eq!(p.vuln_type, OobVulnType::BlindSqli);
    assert_eq!(p.expected_query, "tok123.c.test.com");
    assert!(p.injection_payload.contains("LOAD_FILE"));
    assert!(p.injection_payload.contains("tok123.c.test.com"));
}

#[test]
fn oob_ssrf_payload() {
    let p = generate_oob_payload(OobVulnType::Ssrf, "tok456", "c.test.com");
    assert_eq!(p.vuln_type, OobVulnType::Ssrf);
    assert!(p.injection_payload.starts_with("http://"));
    assert!(p.injection_payload.contains("tok456.c.test.com"));
}

#[test]
fn oob_xxe_payload() {
    let p = generate_oob_payload(OobVulnType::Xxe, "tok789", "c.test.com");
    assert_eq!(p.vuln_type, OobVulnType::Xxe);
    assert!(p.injection_payload.contains("DOCTYPE"));
    assert!(p.injection_payload.contains("tok789.c.test.com"));
}

#[test]
fn oob_blind_xss_payload() {
    let p = generate_oob_payload(OobVulnType::BlindXss, "xss01", "c.test.com");
    assert_eq!(p.vuln_type, OobVulnType::BlindXss);
    assert!(p.injection_payload.contains("<script>"));
    assert!(p.injection_payload.contains("xss01.c.test.com"));
}

#[test]
fn oob_blind_rce_payload() {
    let p = generate_oob_payload(OobVulnType::BlindRce, "rce01", "c.test.com");
    assert_eq!(p.vuln_type, OobVulnType::BlindRce);
    assert!(p.injection_payload.contains("curl"));
    assert!(p.injection_payload.contains("rce01.c.test.com"));
}

// =========================================================================
// Display / formatting coverage
// =========================================================================

#[test]
fn encoding_display() {
    assert_eq!(format!("{}", DnsEncoding::Hex), "hex");
    assert_eq!(format!("{}", DnsEncoding::Base32), "base32");
}

#[test]
fn language_display() {
    assert_eq!(format!("{}", PayloadLanguage::Bash), "bash");
    assert_eq!(format!("{}", PayloadLanguage::Python), "python");
    assert_eq!(format!("{}", PayloadLanguage::Powershell), "powershell");
}

#[test]
fn oob_vuln_type_display() {
    assert_eq!(format!("{}", OobVulnType::BlindSqli), "blind-sqli");
    assert_eq!(format!("{}", OobVulnType::Ssrf), "ssrf");
    assert_eq!(format!("{}", OobVulnType::Xxe), "xxe");
}

#[test]
fn error_display() {
    let err = DnsExfilError::LabelTooLong(99);
    assert!(format!("{err}").contains("99"));

    let err = DnsExfilError::InvalidChecksum {
        expected: 0xAABBCCDD,
        actual: 0x11223344,
    };
    assert!(format!("{err}").contains("mismatch"));
}

// =========================================================================
// Validation
// =========================================================================

#[test]
fn validate_good_payload_returns_no_errors() {
    let data = b"validate me";
    let config = DnsExfilConfig::new("c.test.com", DnsEncoding::Hex, false);
    let payload = encode_exfil(data, &config).unwrap();
    assert!(validate_payload(&payload).is_empty());
}
