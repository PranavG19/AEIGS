use super::lotl_protocol::*;

#[test]
fn all_protocols_have_valid_ports() {
    let protocols = [
        EnterpriseProtocol::Ldap,
        EnterpriseProtocol::Smb,
        EnterpriseProtocol::WinRm,
        EnterpriseProtocol::Dcom,
        EnterpriseProtocol::Kerberos,
        EnterpriseProtocol::Ntlm,
    ];
    for p in &protocols {
        assert!(p.default_port() > 0, "{p:?} must have valid port");
        assert!(p.secure_port() > 0, "{p:?} must have valid secure port");
        assert!(p.max_payload_size() >= 1024, "{p:?} payload size too small");
    }
}

#[test]
fn all_protocols_have_carrier_operations() {
    let protocols = [
        EnterpriseProtocol::Ldap,
        EnterpriseProtocol::Smb,
        EnterpriseProtocol::WinRm,
        EnterpriseProtocol::Dcom,
        EnterpriseProtocol::Kerberos,
        EnterpriseProtocol::Ntlm,
    ];
    for p in &protocols {
        let ops = p.carrier_operations();
        assert!(
            !ops.is_empty(),
            "{p:?} must have at least one carrier operation"
        );
        for op in ops {
            assert!(!op.is_empty(), "{p:?} has empty operation name");
        }
    }
}

#[test]
fn embed_and_extract_roundtrip_ldap() {
    let config = LotlConfig::new(EnterpriseProtocol::Ldap);
    let mut piggy = LotlPiggyback::with_seed(config, 42);

    let payload = b"SELECT * FROM users WHERE admin=true; --";
    let messages = piggy.embed_payload(payload, "dc01.corp.local").unwrap();
    assert!(!messages.is_empty());

    for msg in &messages {
        assert_eq!(msg.protocol, EnterpriseProtocol::Ldap);
        assert!(!msg.operation.is_empty());
        assert_eq!(msg.target_host, "dc01.corp.local");
        assert!(!msg.raw_message.is_empty());
    }

    let extracted = piggy.extract_payload(&messages).unwrap();
    assert_eq!(&extracted[..payload.len()], payload);
}

#[test]
fn embed_and_extract_roundtrip_smb() {
    let config = LotlConfig::new(EnterpriseProtocol::Smb).with_encryption(true);
    let mut piggy = LotlPiggyback::with_seed(config, 99);

    let payload = b"mimikatz sekurlsa::logonpasswords";
    let messages = piggy
        .embed_payload(payload, "fileserver.corp.local")
        .unwrap();
    assert!(!messages.is_empty());

    for msg in &messages {
        assert_eq!(msg.protocol, EnterpriseProtocol::Smb);
    }

    let extracted = piggy.extract_payload(&messages).unwrap();
    assert_eq!(&extracted[..payload.len()], payload);
}

#[test]
fn embed_and_extract_roundtrip_winrm() {
    let config = LotlConfig::new(EnterpriseProtocol::WinRm);
    let mut piggy = LotlPiggyback::with_seed(config, 77);

    let payload = b"powershell -enc ZQBjAGgAbwAgACIAaABlAGwAbABvACIA";
    let messages = piggy.embed_payload(payload, "ws01.corp.local").unwrap();
    assert!(!messages.is_empty());

    let extracted = piggy.extract_payload(&messages).unwrap();
    assert_eq!(&extracted[..payload.len()], payload);
}

#[test]
fn embed_and_extract_roundtrip_dcom() {
    let config = LotlConfig::new(EnterpriseProtocol::Dcom);
    let mut piggy = LotlPiggyback::with_seed(config, 33);

    let payload = b"DCOM lateral movement payload";
    let messages = piggy.embed_payload(payload, "app01.corp.local").unwrap();
    assert!(!messages.is_empty());

    let extracted = piggy.extract_payload(&messages).unwrap();
    assert_eq!(&extracted[..payload.len()], payload);
}

#[test]
fn embed_and_extract_roundtrip_kerberos() {
    let config = LotlConfig::new(EnterpriseProtocol::Kerberos);
    let mut piggy = LotlPiggyback::with_seed(config, 55);

    let payload = b"kerberoast ticket request";
    let messages = piggy.embed_payload(payload, "kdc.corp.local").unwrap();
    assert!(!messages.is_empty());

    let extracted = piggy.extract_payload(&messages).unwrap();
    assert_eq!(&extracted[..payload.len()], payload);
}

#[test]
fn large_payload_fragments_correctly() {
    let config = LotlConfig::new(EnterpriseProtocol::Ldap).with_max_fragment_size(50);
    let mut piggy = LotlPiggyback::with_seed(config, 42);

    let payload = vec![0x41u8; 200];
    let messages = piggy.embed_payload(&payload, "dc01.corp.local").unwrap();
    assert!(
        messages.len() >= 4,
        "200 bytes at 50/fragment should produce at least 4 messages, got {}",
        messages.len()
    );

    for (i, msg) in messages.iter().enumerate() {
        assert_eq!(msg.sequence, i);
        assert_eq!(msg.total_fragments, messages.len());
    }

    let extracted = piggy.extract_payload(&messages).unwrap();
    assert_eq!(&extracted[..payload.len()], payload.as_slice());
}

#[test]
fn unfragmented_rejects_oversized_payload() {
    let config = LotlConfig {
        fragment_large_payloads: false,
        ..LotlConfig::new(EnterpriseProtocol::Kerberos)
    };
    let mut piggy = LotlPiggyback::with_seed(config, 1);

    let payload = vec![0x42u8; 10_000];
    let result = piggy.embed_payload(&payload, "kdc.corp.local");
    assert!(result.is_err());
}

#[test]
fn cover_message_has_no_payload() {
    let config = LotlConfig::new(EnterpriseProtocol::Smb);
    let mut piggy = LotlPiggyback::with_seed(config, 42);

    let cover = piggy.generate_cover_message("fileserver.corp.local");
    assert!(cover.embedded_payload.is_empty());
    assert_eq!(cover.protocol, EnterpriseProtocol::Smb);
    assert!(!cover.operation.is_empty());
    assert!(!cover.raw_message.is_empty());
}

#[test]
fn statistics_track_correctly() {
    let config = LotlConfig::new(EnterpriseProtocol::Ldap);
    let mut piggy = LotlPiggyback::with_seed(config, 42);

    assert_eq!(piggy.messages_generated(), 0);
    assert_eq!(piggy.bytes_embedded(), 0);

    let _ = piggy
        .embed_payload(b"test data", "dc01.corp.local")
        .unwrap();
    assert!(piggy.messages_generated() > 0);
    assert!(piggy.bytes_embedded() > 0);

    piggy.generate_cover_message("dc01.corp.local");
    assert!(piggy.messages_generated() >= 2);
}

#[test]
fn session_id_is_consistent() {
    let config = LotlConfig::new(EnterpriseProtocol::WinRm);
    let mut piggy = LotlPiggyback::with_seed(config, 42);

    let sid = piggy.session_id().to_string();
    assert!(!sid.is_empty());

    let messages = piggy.embed_payload(b"test", "ws01.corp.local").unwrap();
    for msg in &messages {
        assert_eq!(msg.session_id, sid);
    }
}

#[test]
fn jitter_within_bounds() {
    let config = LotlConfig::new(EnterpriseProtocol::Ldap).with_timing_jitter_ms(1000);
    let mut piggy = LotlPiggyback::with_seed(config, 42);

    for _ in 0..100 {
        let jitter = piggy.next_jitter_ms();
        assert!(jitter <= 1000, "jitter {jitter} exceeds max 1000");
    }
}

#[test]
fn zero_jitter_returns_zero() {
    let config = LotlConfig::new(EnterpriseProtocol::Ldap).with_timing_jitter_ms(0);
    let mut piggy = LotlPiggyback::with_seed(config, 42);
    assert_eq!(piggy.next_jitter_ms(), 0);
}

#[test]
fn ldap_raw_message_starts_with_sequence_tag() {
    let config = LotlConfig::new(EnterpriseProtocol::Ldap);
    let mut piggy = LotlPiggyback::with_seed(config, 42);

    let messages = piggy.embed_payload(b"test", "dc01.corp.local").unwrap();
    for msg in &messages {
        assert_eq!(
            msg.raw_message[0], 0x30,
            "LDAP message must start with SEQUENCE tag"
        );
    }
}

#[test]
fn smb_raw_message_has_magic_bytes() {
    let config = LotlConfig::new(EnterpriseProtocol::Smb);
    let mut piggy = LotlPiggyback::with_seed(config, 42);

    let messages = piggy.embed_payload(b"test", "fs01.corp.local").unwrap();
    for msg in &messages {
        assert_eq!(
            &msg.raw_message[..4],
            b"\xfeSMB",
            "SMB2 message must start with magic bytes"
        );
    }
}

#[test]
fn winrm_raw_message_contains_soap_envelope() {
    let config = LotlConfig::new(EnterpriseProtocol::WinRm);
    let mut piggy = LotlPiggyback::with_seed(config, 42);

    let messages = piggy.embed_payload(b"test", "ws01.corp.local").unwrap();
    for msg in &messages {
        let raw_str = String::from_utf8_lossy(&msg.raw_message);
        assert!(
            raw_str.contains("Envelope"),
            "WinRM message must contain SOAP Envelope"
        );
    }
}

#[test]
fn ntlm_raw_message_has_signature() {
    let config = LotlConfig::new(EnterpriseProtocol::Ntlm);
    let mut piggy = LotlPiggyback::with_seed(config, 42);

    let messages = piggy.embed_payload(b"test", "dc01.corp.local").unwrap();
    for msg in &messages {
        assert_eq!(
            &msg.raw_message[..7],
            b"NTLMSSP",
            "NTLM message must start with NTLMSSP signature"
        );
    }
}

#[test]
fn encrypted_payload_differs_from_plaintext() {
    let config_enc = LotlConfig::new(EnterpriseProtocol::Ldap).with_encryption(true);
    let config_plain = LotlConfig::new(EnterpriseProtocol::Ldap).with_encryption(false);

    let mut piggy_enc = LotlPiggyback::with_seed(config_enc, 42);
    let mut piggy_plain = LotlPiggyback::with_seed(config_plain, 42);

    let payload = b"sensitive data";
    let msgs_enc = piggy_enc.embed_payload(payload, "dc01.corp.local").unwrap();
    let msgs_plain = piggy_plain
        .embed_payload(payload, "dc01.corp.local")
        .unwrap();

    // The embedded payloads in encrypted messages should differ from plaintext
    // (XOR encryption changes bytes unless key happens to be all zeros)
    let enc_bytes = &msgs_enc[0].embedded_payload;
    let plain_bytes = &msgs_plain[0].embedded_payload;
    assert_ne!(enc_bytes, plain_bytes);
}

#[test]
fn legitimate_fields_populated_per_protocol() {
    let protocols = [
        EnterpriseProtocol::Ldap,
        EnterpriseProtocol::Smb,
        EnterpriseProtocol::WinRm,
        EnterpriseProtocol::Dcom,
        EnterpriseProtocol::Kerberos,
        EnterpriseProtocol::Ntlm,
    ];

    for proto in &protocols {
        let config = LotlConfig::new(*proto);
        let mut piggy = LotlPiggyback::with_seed(config, 42);
        let messages = piggy.embed_payload(b"test", "target.corp.local").unwrap();
        for msg in &messages {
            assert!(
                !msg.legitimate_fields.is_empty(),
                "{proto:?} must populate legitimate fields"
            );
        }
    }
}
