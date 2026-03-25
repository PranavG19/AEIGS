use super::encrypted_channel_blend::*;

#[test]
fn tunnel_provider_doh_endpoints_are_https() {
    let providers = [
        TunnelProvider::Cloudflare,
        TunnelProvider::Google,
        TunnelProvider::Quad9,
        TunnelProvider::NextDns,
        TunnelProvider::CleanBrowsing,
    ];
    for p in &providers {
        assert!(
            p.doh_endpoint().starts_with("https://"),
            "{p:?} DoH endpoint must be HTTPS"
        );
    }
}

#[test]
fn tunnel_provider_dot_port_is_853() {
    let providers = [
        TunnelProvider::Cloudflare,
        TunnelProvider::Google,
        TunnelProvider::Quad9,
        TunnelProvider::NextDns,
        TunnelProvider::CleanBrowsing,
    ];
    for p in &providers {
        let (_host, port) = p.dot_endpoint();
        assert_eq!(port, 853, "{p:?} DoT port must be 853");
    }
}

#[test]
fn tunnel_provider_has_whitelisted_ips() {
    let providers = [
        TunnelProvider::Cloudflare,
        TunnelProvider::Google,
        TunnelProvider::Quad9,
    ];
    for p in &providers {
        assert!(
            !p.whitelisted_ips().is_empty(),
            "{p:?} must have whitelisted IPs"
        );
    }
}

#[test]
fn base32_encoding_roundtrip() {
    let encoding = DataEncoding::Base32Subdomain;
    let data = b"hello encrypted channel";
    let encoded = encoding.encode(data);
    assert!(!encoded.is_empty());
    let decoded = encoding.decode(&encoded).unwrap();
    assert_eq!(&decoded[..data.len()], data);
}

#[test]
fn base64_encoding_roundtrip() {
    let encoding = DataEncoding::Base64TxtRecord;
    let data = b"test payload data for tunnel";
    let encoded = encoding.encode(data);
    assert!(!encoded.is_empty());
    let decoded = encoding.decode(&encoded).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn hex_encoding_roundtrip() {
    let encoding = DataEncoding::HexCname;
    let data = b"hex test data";
    let encoded = encoding.encode(data);
    assert_eq!(encoded.len(), data.len() * 2);
    let decoded = encoding.decode(&encoded).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn compressed_base64_roundtrip() {
    let encoding = DataEncoding::CompressedBase64;
    let data = b"AAAAAABBBBBBCCCCCC this is repeated data AAAAAABBBBBB";
    let encoded = encoding.encode(data);
    assert!(!encoded.is_empty());
    let decoded = encoding.decode(&encoded).unwrap();
    assert_eq!(&decoded[..data.len()], data);
}

#[test]
fn encode_payload_chunks_large_data() {
    let profile = TunnelProfile::doh(TunnelProvider::Cloudflare);
    let max_per = profile.encoding.max_payload_per_message();
    let mut blender = EncryptedChannelBlender::with_seed(profile, 42);

    let data = vec![0x41u8; max_per * 3 + 10];
    let chunks = blender.encode_payload(&data).unwrap();
    assert_eq!(chunks.len(), 4);

    for (i, chunk) in chunks.iter().enumerate() {
        assert_eq!(chunk.sequence, i);
        assert_eq!(chunk.total_chunks, 4);
        assert!(!chunk.encoded_data.is_empty());
        assert!(!chunk.dns_query_name.is_empty());
    }
}

#[test]
fn encode_decode_roundtrip_through_chunks() {
    let profile = TunnelProfile::doh(TunnelProvider::Google);
    let mut blender = EncryptedChannelBlender::with_seed(profile, 123);

    let original = b"This is sensitive C2 data that must survive chunking and reassembly intact";
    let chunks = blender.encode_payload(original).unwrap();
    assert!(!chunks.is_empty());

    let reconstructed = blender.decode_chunks(&chunks).unwrap();
    assert_eq!(&reconstructed[..original.len()], original.as_slice());
}

#[test]
fn empty_payload_returns_no_chunks() {
    let profile = TunnelProfile::doh(TunnelProvider::Quad9);
    let mut blender = EncryptedChannelBlender::with_seed(profile, 1);

    let chunks = blender.encode_payload(b"").unwrap();
    assert!(chunks.is_empty());
}

#[test]
fn tunnel_stats_track_correctly() {
    let profile = TunnelProfile::doh(TunnelProvider::Cloudflare);
    let mut blender = EncryptedChannelBlender::with_seed(profile, 42);

    let data = vec![0x42u8; 500];
    let _ = blender.encode_payload(&data).unwrap();
    let stats = blender.stats();
    assert!(stats.chunks_sent > 0);
    assert_eq!(stats.bytes_tunneled, 500);
    assert_eq!(stats.provider, TunnelProvider::Cloudflare);
    assert_eq!(stats.protocol, TunnelProtocol::DnsOverHttps);
}

#[test]
fn visible_sni_matches_provider() {
    let profile = TunnelProfile::doh(TunnelProvider::Google);
    let blender = EncryptedChannelBlender::with_seed(profile, 1);
    assert_eq!(blender.visible_sni(), "dns.google");
}

#[test]
fn doh_url_returns_provider_endpoint() {
    let profile = TunnelProfile::doh(TunnelProvider::Cloudflare);
    let blender = EncryptedChannelBlender::with_seed(profile, 1);
    assert_eq!(blender.doh_url(), "https://cloudflare-dns.com/dns-query");
}

#[test]
fn next_delay_respects_timing_bounds() {
    let profile =
        TunnelProfile::doh(TunnelProvider::Google).with_timing(TimingProfile::browser_like());
    let mut blender = EncryptedChannelBlender::with_seed(profile, 42);

    for _ in 0..100 {
        let delay = blender.next_delay_ms();
        assert!(
            delay <= 60000,
            "delay {delay}ms exceeds reasonable upper bound"
        );
    }
}

#[test]
fn dot_profile_uses_base32() {
    let profile = TunnelProfile::dot(TunnelProvider::Cloudflare);
    assert_eq!(profile.protocol, TunnelProtocol::DnsOverTls);
    assert!(matches!(profile.encoding, DataEncoding::Base32Subdomain));
}

#[test]
fn ech_profile_uses_compressed_base64() {
    let profile = TunnelProfile::ech(TunnelProvider::Google);
    assert_eq!(profile.protocol, TunnelProtocol::EncryptedClientHello);
    assert!(matches!(profile.encoding, DataEncoding::CompressedBase64));
}

#[test]
fn multi_provider_round_robins() {
    let profiles = vec![
        TunnelProfile::doh(TunnelProvider::Cloudflare),
        TunnelProfile::doh(TunnelProvider::Google),
    ];
    let mut multi = MultiProviderBlender::new(profiles);
    assert_eq!(multi.channel_count(), 2);

    let data = b"test data";
    let chunks1 = multi.encode_payload(data).unwrap();
    let chunks2 = multi.encode_payload(data).unwrap();

    let stats = multi.aggregate_stats();
    assert_eq!(stats.len(), 2);
    assert!(stats[0].chunks_sent > 0 || stats[1].chunks_sent > 0);
    assert!(
        !chunks1.is_empty() && !chunks2.is_empty(),
        "both providers should produce chunks"
    );
}

#[test]
fn multi_provider_empty_channels_returns_error() {
    let mut multi = MultiProviderBlender::new(Vec::new());
    let result = multi.encode_payload(b"data");
    assert!(result.is_err());
}

#[test]
fn dns_query_name_includes_domain_suffix() {
    let profile =
        TunnelProfile::doh(TunnelProvider::Cloudflare).with_domain_suffix("exfil-test.net");
    let mut blender = EncryptedChannelBlender::with_seed(profile, 42);

    let chunks = blender.encode_payload(b"test").unwrap();
    for chunk in &chunks {
        assert!(
            chunk.dns_query_name.ends_with("exfil-test.net"),
            "query name '{}' must end with domain suffix",
            chunk.dns_query_name
        );
    }
}

#[test]
fn timing_profiles_have_valid_bounds() {
    let profiles = [
        TimingProfile::browser_like(),
        TimingProfile::persistent_slow(),
        TimingProfile::rapid_exfil(),
    ];
    for tp in &profiles {
        assert!(tp.min_interval_ms <= tp.mean_interval_ms);
        assert!(tp.mean_interval_ms <= tp.max_interval_ms);
        assert!(tp.burst_size >= 1);
    }
}

#[test]
fn hex_decode_rejects_odd_length() {
    let encoding = DataEncoding::HexCname;
    let result = encoding.decode("abc");
    assert!(result.is_err());
}

#[test]
fn base32_decode_rejects_invalid_chars() {
    let encoding = DataEncoding::Base32Subdomain;
    let result = encoding.decode("HELLO!!!");
    assert!(result.is_err());
}
