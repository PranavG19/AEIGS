use super::ip_spoof_headers::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn spoof_header_names_cover_all_eleven() {
    let names: Vec<&str> = SpoofHeader::all().iter().map(|h| h.header_name()).collect();
    assert_eq!(names.len(), 11);
    assert!(names.contains(&"X-Forwarded-For"));
    assert!(names.contains(&"X-Real-IP"));
    assert!(names.contains(&"X-Originating-IP"));
    assert!(names.contains(&"X-Remote-IP"));
    assert!(names.contains(&"X-Remote-Addr"));
    assert!(names.contains(&"True-Client-IP"));
    assert!(names.contains(&"CF-Connecting-IP"));
    assert!(names.contains(&"Fastly-Client-IP"));
    assert!(names.contains(&"X-Cluster-Client-IP"));
    assert!(names.contains(&"X-Client-IP"));
    assert!(names.contains(&"Forwarded"));
}

#[test]
fn single_ipv4_generates_plain_value() {
    let gen = IpSpoofHeaderGenerator::new();
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
    let result = gen.generate(SpoofHeader::XForwardedFor, &SpoofStrategy::SingleIp(ip));
    assert_eq!(result.name, "X-Forwarded-For");
    assert_eq!(result.value, "203.0.113.42");
}

#[test]
fn single_ipv6_generates_plain_value() {
    let gen = IpSpoofHeaderGenerator::new();
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let result = gen.generate(SpoofHeader::XRealIp, &SpoofStrategy::SingleIp(ip));
    assert_eq!(result.name, "X-Real-IP");
    assert_eq!(result.value, "2001:db8::1");
}

#[test]
fn chain_produces_comma_separated_ips() {
    let gen = IpSpoofHeaderGenerator::new();
    let chain = vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
    ];
    let result = gen.generate(SpoofHeader::XForwardedFor, &SpoofStrategy::Chain(chain));
    assert_eq!(result.value, "10.0.0.1, 172.16.0.1, 203.0.113.5");
}

#[test]
fn forwarded_header_uses_rfc7239_format_ipv4() {
    let gen = IpSpoofHeaderGenerator::new();
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 17));
    let result = gen.generate(SpoofHeader::Forwarded, &SpoofStrategy::SingleIp(ip));
    assert_eq!(result.name, "Forwarded");
    assert_eq!(result.value, "for=198.51.100.17");
}

#[test]
fn forwarded_header_uses_rfc7239_format_ipv6() {
    let gen = IpSpoofHeaderGenerator::new();
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let result = gen.generate(SpoofHeader::Forwarded, &SpoofStrategy::SingleIp(ip));
    assert_eq!(result.name, "Forwarded");
    assert!(result.value.starts_with("for=\"["));
    assert!(result.value.contains("2001:db8::1"));
}

#[test]
fn forwarded_chain_produces_multiple_for_entries() {
    let gen = IpSpoofHeaderGenerator::new();
    let chain = vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
    ];
    let result = gen.generate(SpoofHeader::Forwarded, &SpoofStrategy::Chain(chain));
    assert_eq!(result.value, "for=10.0.0.1, for=192.168.1.1");
}

#[test]
fn internal_ip_class_representatives_are_in_correct_ranges() {
    assert_eq!(
        InternalIpClass::Loopback.representative_ip(),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    );
    assert_eq!(
        InternalIpClass::ClassA.representative_ip(),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    );
    assert_eq!(
        InternalIpClass::ClassB.representative_ip(),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))
    );
    assert_eq!(
        InternalIpClass::ClassC.representative_ip(),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    );
    assert_eq!(
        InternalIpClass::LinkLocal.representative_ip(),
        IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))
    );
    assert_eq!(
        InternalIpClass::Ipv6Loopback.representative_ip(),
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    );
}

#[test]
fn internal_ip_random_stays_in_range() {
    for _ in 0..50 {
        match InternalIpClass::ClassA.random_ip() {
            IpAddr::V4(v4) => assert_eq!(v4.octets()[0], 10),
            _ => panic!("expected IPv4"),
        }
        match InternalIpClass::ClassB.random_ip() {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                assert_eq!(octets[0], 172);
                assert!((16..=31).contains(&octets[1]));
            }
            _ => panic!("expected IPv4"),
        }
        match InternalIpClass::ClassC.random_ip() {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                assert_eq!(octets[0], 192);
                assert_eq!(octets[1], 168);
            }
            _ => panic!("expected IPv4"),
        }
    }
}

#[test]
fn generate_all_produces_eleven_headers() {
    let gen = IpSpoofHeaderGenerator::new();
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let results = gen.generate_all(&SpoofStrategy::SingleIp(ip));
    assert_eq!(results.len(), 11);
    let names: Vec<&str> = results.iter().map(|h| h.name.as_str()).collect();
    assert!(names.contains(&"X-Forwarded-For"));
    assert!(names.contains(&"Forwarded"));
    assert!(names.contains(&"CF-Connecting-IP"));
}

#[test]
fn generate_internal_variants_covers_all_classes() {
    let gen = IpSpoofHeaderGenerator::new();
    let results = gen.generate_internal_variants(SpoofHeader::TrueClientIp);
    assert_eq!(results.len(), InternalIpClass::all().len());
    assert!(results.iter().all(|h| h.name == "True-Client-IP"));
    let values: Vec<&str> = results.iter().map(|h| h.value.as_str()).collect();
    assert!(values.contains(&"127.0.0.1"));
    assert!(values.contains(&"10.0.0.1"));
    assert!(values.contains(&"192.168.1.1"));
}

#[test]
fn generate_full_matrix_size() {
    let gen = IpSpoofHeaderGenerator::new();
    let results = gen.generate_full_matrix();
    let expected = SpoofHeader::all().len() * InternalIpClass::all().len();
    assert_eq!(results.len(), expected);
}

#[test]
fn generate_chain_produces_correct_hop_count() {
    let gen = IpSpoofHeaderGenerator::new();
    let result = gen.generate_chain(SpoofHeader::XForwardedFor, 5);
    let parts: Vec<&str> = result.value.split(", ").collect();
    assert_eq!(parts.len(), 5);
}

#[test]
fn generate_ipv6_produces_valid_address() {
    let gen = IpSpoofHeaderGenerator::new();
    let result = gen.generate_ipv6(SpoofHeader::XClientIp);
    assert_eq!(result.name, "X-Client-IP");
    assert!(result.value.contains(':'));
}

#[test]
fn ip_range_random_stays_in_subnet() {
    let range = IpRange::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    for _ in 0..100 {
        let ip = range.random_ip();
        let octets = ip.octets();
        assert_eq!(octets[0], 192);
        assert_eq!(octets[1], 168);
        assert_eq!(octets[2], 1);
        assert!(octets[3] > 0);
    }
}

#[test]
fn random_from_range_strategy() {
    let gen = IpSpoofHeaderGenerator::new();
    let range = IpRange::new(Ipv4Addr::new(10, 10, 0, 0), 16);
    let strategy = SpoofStrategy::RandomFromRange(range);
    let result = gen.generate(SpoofHeader::XRealIp, &strategy);
    assert!(result.value.starts_with("10.10."));
}

#[test]
fn default_constructor() {
    let gen = IpSpoofHeaderGenerator::default();
    let result = gen.generate(
        SpoofHeader::XForwardedFor,
        &SpoofStrategy::SingleIp(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    );
    assert_eq!(result.value, "127.0.0.1");
}
