use super::doh_enforcer::*;
use std::time::Instant;

#[test]
fn test_default_providers() {
    let enforcer = DohEnforcer::with_default_providers();
    assert_eq!(enforcer.providers().len(), 3);
    assert_eq!(
        enforcer.active_provider().endpoint_url(),
        "https://cloudflare-dns.com/dns-query"
    );
}

#[test]
fn test_provider_rotation() {
    let mut enforcer = DohEnforcer::with_default_providers();
    assert!(matches!(
        enforcer.active_provider(),
        DohProvider::Cloudflare
    ));
    enforcer.rotate_provider();
    assert!(matches!(enforcer.active_provider(), DohProvider::Google));
    enforcer.rotate_provider();
    assert!(matches!(enforcer.active_provider(), DohProvider::Quad9));
    enforcer.rotate_provider();
    assert!(matches!(
        enforcer.active_provider(),
        DohProvider::Cloudflare
    ));
}

#[test]
fn test_rfc8484_wire_format_encode() {
    let wire = DnsWireFormat::encode_query("example.com", DnsRecordType::A, 0x1234);
    // Header: 12 bytes
    assert_eq!(wire[0], 0x12);
    assert_eq!(wire[1], 0x34);
    // Flags: RD=1
    assert_eq!(wire[2], 0x01);
    assert_eq!(wire[3], 0x00);
    // QDCOUNT = 1
    assert_eq!(wire[4], 0x00);
    assert_eq!(wire[5], 0x01);
    // QNAME: 7example3com0
    assert_eq!(wire[12], 7); // "example" length
    assert_eq!(&wire[13..20], b"example");
    assert_eq!(wire[20], 3); // "com" length
    assert_eq!(&wire[21..24], b"com");
    assert_eq!(wire[24], 0); // root label
                             // QTYPE = A (1)
    assert_eq!(wire[25], 0x00);
    assert_eq!(wire[26], 0x01);
    // QCLASS = IN (1)
    assert_eq!(wire[27], 0x00);
    assert_eq!(wire[28], 0x01);
}

#[test]
fn test_wire_format_decode_response() {
    // Build a minimal valid DNS response with one A record
    let mut resp = vec![
        0x12, 0x34, // ID
        0x81, 0x80, // Flags: QR=1, RD=1, RA=1
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x01, // ANCOUNT = 1
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
    ];
    // Question: example.com A IN
    resp.push(7);
    resp.extend_from_slice(b"example");
    resp.push(3);
    resp.extend_from_slice(b"com");
    resp.push(0);
    resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    // Answer: pointer to offset 12, type A, class IN, TTL=300, RDLENGTH=4, 93.184.216.34
    resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer
    resp.extend_from_slice(&[0x00, 0x01]); // type A
    resp.extend_from_slice(&[0x00, 0x01]); // class IN
    resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL = 300
    resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
    resp.extend_from_slice(&[93, 184, 216, 34]); // 93.184.216.34

    let decoded = DnsWireFormat::decode_response(&resp).unwrap();
    assert_eq!(decoded.id, 0x1234);
    assert_eq!(decoded.rcode, 0);
    assert_eq!(decoded.answers.len(), 1);
    assert_eq!(decoded.answers[0].record_type, 1);
    assert_eq!(decoded.answers[0].ttl, 300);
    assert_eq!(decoded.answers[0].value, "93.184.216.34");
}

#[test]
fn test_cache_insert_and_lookup() {
    let mut enforcer = DohEnforcer::with_default_providers();
    let entry = CachedDnsEntry {
        domain: "example.com".to_string(),
        record_type: DnsRecordType::A,
        values: vec!["93.184.216.34".to_string()],
        ttl_secs: 300,
        cached_at: Some(Instant::now()),
    };
    enforcer.cache_insert(entry);
    assert_eq!(enforcer.cache_size(), 1);
    let hit = enforcer.cache_lookup("example.com", DnsRecordType::A);
    assert!(hit.is_some());
    assert_eq!(hit.unwrap().values[0], "93.184.216.34");
}

#[test]
fn test_cache_miss_on_different_type() {
    let mut enforcer = DohEnforcer::with_default_providers();
    let entry = CachedDnsEntry {
        domain: "example.com".to_string(),
        record_type: DnsRecordType::A,
        values: vec!["93.184.216.34".to_string()],
        ttl_secs: 300,
        cached_at: Some(Instant::now()),
    };
    enforcer.cache_insert(entry);
    let miss = enforcer.cache_lookup("example.com", DnsRecordType::AAAA);
    assert!(miss.is_none());
}

#[test]
fn test_expired_cache_entry() {
    let mut enforcer = DohEnforcer::with_default_providers();
    let entry = CachedDnsEntry {
        domain: "expired.com".to_string(),
        record_type: DnsRecordType::A,
        values: vec!["1.2.3.4".to_string()],
        ttl_secs: 0, // immediately expired
        cached_at: Some(Instant::now()),
    };
    enforcer.cache_insert(entry);
    // TTL=0 means the entry is expired right away
    std::thread::sleep(std::time::Duration::from_millis(5));
    let miss = enforcer.cache_lookup("expired.com", DnsRecordType::A);
    assert!(miss.is_none());
}

#[test]
fn test_build_doh_request() {
    let enforcer = DohEnforcer::with_default_providers();
    let req = enforcer.build_doh_request("example.com", DnsRecordType::A);
    assert_eq!(req.content_type, "application/dns-message");
    assert_eq!(req.accept, "application/dns-message");
    assert!(req.url.contains("cloudflare-dns.com"));
    assert!(!req.body.is_empty());
}

#[test]
fn test_leak_detection_all_doh() {
    let mut enforcer = DohEnforcer::with_default_providers();
    enforcer.log_query(DnsQueryLog {
        domain: "example.com".to_string(),
        record_type: DnsRecordType::A,
        provider: DohProvider::Cloudflare,
        cache_hit: false,
        latency_ms: 50,
    });
    enforcer.log_query(DnsQueryLog {
        domain: "test.org".to_string(),
        record_type: DnsRecordType::AAAA,
        provider: DohProvider::Google,
        cache_hit: false,
        latency_ms: 30,
    });
    let result = enforcer.check_for_leaks();
    assert!(result.all_via_doh);
    assert!(!result.udp_53_detected);
    assert!(result.plain_dns_queries.is_empty());
}

#[test]
fn test_query_log() {
    let mut enforcer = DohEnforcer::with_default_providers();
    assert!(enforcer.query_log().is_empty());
    enforcer.log_query(DnsQueryLog {
        domain: "example.com".to_string(),
        record_type: DnsRecordType::A,
        provider: DohProvider::Cloudflare,
        cache_hit: true,
        latency_ms: 0,
    });
    assert_eq!(enforcer.query_log().len(), 1);
    assert!(enforcer.query_log()[0].cache_hit);
}

#[test]
fn test_custom_provider() {
    let enforcer = DohEnforcer::new(vec![DohProvider::Custom(
        "https://my-doh.example.com/dns-query".to_string(),
    )]);
    assert_eq!(
        enforcer.active_provider().endpoint_url(),
        "https://my-doh.example.com/dns-query"
    );
}

#[test]
fn test_evict_expired() {
    let mut enforcer = DohEnforcer::with_default_providers();
    enforcer.cache_insert(CachedDnsEntry {
        domain: "fresh.com".to_string(),
        record_type: DnsRecordType::A,
        values: vec!["1.1.1.1".to_string()],
        ttl_secs: 3600,
        cached_at: Some(Instant::now()),
    });
    enforcer.cache_insert(CachedDnsEntry {
        domain: "stale.com".to_string(),
        record_type: DnsRecordType::A,
        values: vec!["2.2.2.2".to_string()],
        ttl_secs: 0,
        cached_at: Some(Instant::now()),
    });
    std::thread::sleep(std::time::Duration::from_millis(5));
    let evicted = enforcer.evict_expired();
    assert_eq!(evicted, 1);
    assert_eq!(enforcer.cache_size(), 1);
}

#[test]
fn test_wire_format_decode_error_rcode() {
    let resp = vec![
        0x00, 0x01, // ID
        0x81, 0x83, // Flags: RCODE=3 (NXDOMAIN)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let result = DnsWireFormat::decode_response(&resp);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("RCODE=3"));
}

#[test]
fn test_wire_format_too_short() {
    let result = DnsWireFormat::decode_response(&[0x00, 0x01]);
    assert!(result.is_err());
}
