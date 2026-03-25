#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::notifications::{
        AlertNotification, CustomHttpConfig, DeduplicationTracker, DeliveryResult, EmailConfig,
        HttpMethod, NotificationChannel, NotificationDispatcher, NotificationFormatter,
        PagerDutyConfig, WebhookConfig, WebhookFormat,
    };

    fn sample_notification() -> AlertNotification {
        AlertNotification {
            notification_id: "notif-001".to_string(),
            title: "Critical SQLi Found".to_string(),
            message: "SQL injection in /api/users endpoint".to_string(),
            severity: "critical".to_string(),
            target_url: "http://example.com".to_string(),
            finding_count: 3,
            timestamp_ms: 1_700_000_000_000,
            details: HashMap::new(),
        }
    }

    #[test]
    fn format_slack_contains_required_fields() {
        let notif = sample_notification();
        let payload = NotificationFormatter::format_slack(&notif);
        assert!(payload.contains("Critical SQLi Found"));
        assert!(payload.contains("http://example.com"));
        assert!(payload.contains("#ff0000"));
        assert!(payload.contains("\"3\""));
    }

    #[test]
    fn format_discord_contains_embed() {
        let notif = sample_notification();
        let payload = NotificationFormatter::format_discord(&notif);
        assert!(payload.contains("embeds"));
        assert!(payload.contains("Critical SQLi Found"));
        assert!(payload.contains("16711680")); // red
    }

    #[test]
    fn format_teams_contains_message_card() {
        let notif = sample_notification();
        let payload = NotificationFormatter::format_teams(&notif);
        assert!(payload.contains("MessageCard"));
        assert!(payload.contains("FF0000"));
        assert!(payload.contains("http://example.com"));
    }

    #[test]
    fn format_generic_is_valid_json() {
        let notif = sample_notification();
        let payload = NotificationFormatter::format_generic(&notif);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["title"], "Critical SQLi Found");
        assert_eq!(parsed["finding_count"], 3);
    }

    #[test]
    fn format_pagerduty_contains_routing_key() {
        let notif = sample_notification();
        let payload = NotificationFormatter::format_pagerduty(&notif, "test-routing-key");
        assert!(payload.contains("test-routing-key"));
        assert!(payload.contains("trigger"));
        assert!(payload.contains("critical")); // mapped severity
    }

    #[test]
    fn pagerduty_severity_mapping() {
        let mut notif = sample_notification();
        notif.severity = "medium".to_string();
        let payload = NotificationFormatter::format_pagerduty(&notif, "key");
        assert!(payload.contains("warning"));

        notif.severity = "low".to_string();
        let payload = NotificationFormatter::format_pagerduty(&notif, "key");
        assert!(payload.contains("info"));
    }

    #[test]
    fn dedup_tracker_prevents_duplicates() {
        let mut tracker = DeduplicationTracker::new(60_000);
        let notif = sample_notification();

        assert!(!tracker.is_duplicate(&notif, 1000));
        tracker.mark_sent(&notif, 1000);
        assert!(tracker.is_duplicate(&notif, 2000));
        assert!(tracker.is_duplicate(&notif, 60_999));
    }

    #[test]
    fn dedup_tracker_allows_after_window() {
        let mut tracker = DeduplicationTracker::new(60_000);
        let notif = sample_notification();

        tracker.mark_sent(&notif, 1000);
        assert!(!tracker.is_duplicate(&notif, 62_000));
    }

    #[test]
    fn dedup_tracker_evicts_expired() {
        let mut tracker = DeduplicationTracker::new(10_000);
        let notif = sample_notification();

        tracker.mark_sent(&notif, 1000);
        assert_eq!(tracker.tracked_count(), 1);

        tracker.evict_expired(12_000);
        assert_eq!(tracker.tracked_count(), 0);
    }

    #[test]
    fn dedup_different_notifications_not_deduplicated() {
        let mut tracker = DeduplicationTracker::new(60_000);
        let n1 = sample_notification();
        let mut n2 = sample_notification();
        n2.title = "Different Finding".to_string();

        tracker.mark_sent(&n1, 1000);
        assert!(!tracker.is_duplicate(&n2, 2000));
    }

    #[test]
    fn dispatcher_add_and_remove_channels() {
        let mut dispatcher = NotificationDispatcher::new(60_000);
        assert_eq!(dispatcher.channel_count(), 0);

        dispatcher.add_channel(
            "slack-1",
            NotificationChannel::Webhook(WebhookConfig {
                url: "https://hooks.slack.com/test".to_string(),
                format: WebhookFormat::Slack,
                channel_name: Some("#alerts".to_string()),
            }),
        );
        assert_eq!(dispatcher.channel_count(), 1);

        assert!(dispatcher.remove_channel("slack-1"));
        assert_eq!(dispatcher.channel_count(), 0);
        assert!(!dispatcher.remove_channel("nonexistent"));
    }

    #[test]
    fn dispatcher_dispatches_to_all_channels() {
        let mut dispatcher = NotificationDispatcher::new(60_000);
        dispatcher.add_channel(
            "slack",
            NotificationChannel::Webhook(WebhookConfig {
                url: "https://hooks.slack.com/test".to_string(),
                format: WebhookFormat::Slack,
                channel_name: None,
            }),
        );
        dispatcher.add_channel(
            "discord",
            NotificationChannel::Webhook(WebhookConfig {
                url: "https://discord.com/api/webhooks/test".to_string(),
                format: WebhookFormat::Discord,
                channel_name: None,
            }),
        );

        let notif = sample_notification();
        let results = dispatcher.dispatch(&notif, 1000);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_success()));
    }

    #[test]
    fn dispatcher_deduplicates() {
        let mut dispatcher = NotificationDispatcher::new(60_000);
        dispatcher.add_channel(
            "webhook",
            NotificationChannel::Webhook(WebhookConfig {
                url: "https://example.com/hook".to_string(),
                format: WebhookFormat::Generic,
                channel_name: None,
            }),
        );

        let notif = sample_notification();
        let r1 = dispatcher.dispatch(&notif, 1000);
        assert!(r1[0].is_success());

        let r2 = dispatcher.dispatch(&notif, 2000);
        assert!(matches!(r2[0], DeliveryResult::Deduplicated { .. }));
    }

    #[test]
    fn format_for_email_channel() {
        let notif = sample_notification();
        let channel = NotificationChannel::Email(EmailConfig {
            smtp_host: "smtp.example.com".to_string(),
            smtp_port: 587,
            from_address: "aegis@example.com".to_string(),
            to_addresses: vec!["admin@example.com".to_string()],
            use_tls: true,
        });
        let payload = NotificationDispatcher::format_for_channel(&notif, &channel);
        assert!(payload.contains("Subject: Critical SQLi Found"));
        assert!(payload.contains("http://example.com"));
    }

    #[test]
    fn format_for_custom_http_with_template() {
        let notif = sample_notification();
        let channel = NotificationChannel::CustomHttp(CustomHttpConfig {
            url: "https://api.example.com/callback".to_string(),
            method: HttpMethod::Post,
            headers: HashMap::new(),
            body_template: Some(
                "ALERT: {title} | {severity} | {target} | count={count}".to_string(),
            ),
        });
        let payload = NotificationDispatcher::format_for_channel(&notif, &channel);
        assert_eq!(
            payload,
            "ALERT: Critical SQLi Found | critical | http://example.com | count=3"
        );
    }

    #[test]
    fn format_for_custom_http_without_template() {
        let notif = sample_notification();
        let channel = NotificationChannel::CustomHttp(CustomHttpConfig {
            url: "https://api.example.com/callback".to_string(),
            method: HttpMethod::Post,
            headers: HashMap::new(),
            body_template: None,
        });
        let payload = NotificationDispatcher::format_for_channel(&notif, &channel);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["title"], "Critical SQLi Found");
    }

    #[test]
    fn format_for_pagerduty_channel() {
        let notif = sample_notification();
        let channel = NotificationChannel::PagerDuty(PagerDutyConfig {
            routing_key: "my-key".to_string(),
            severity_mapping: HashMap::new(),
        });
        let payload = NotificationDispatcher::format_for_channel(&notif, &channel);
        assert!(payload.contains("my-key"));
        assert!(payload.contains("trigger"));
    }

    #[test]
    fn delivery_result_channel_id() {
        let success = DeliveryResult::Success {
            channel_id: "ch-1".to_string(),
        };
        assert_eq!(success.channel_id(), "ch-1");

        let failed = DeliveryResult::Failed {
            channel_id: "ch-2".to_string(),
            error: "timeout".to_string(),
        };
        assert_eq!(failed.channel_id(), "ch-2");
        assert!(!failed.is_success());

        let dedup = DeliveryResult::Deduplicated {
            channel_id: "ch-3".to_string(),
        };
        assert_eq!(dedup.channel_id(), "ch-3");
    }

    #[test]
    fn slack_color_varies_by_severity() {
        let mut notif = sample_notification();
        notif.severity = "high".to_string();
        let payload = NotificationFormatter::format_slack(&notif);
        assert!(payload.contains("#ff6600"));

        notif.severity = "medium".to_string();
        let payload = NotificationFormatter::format_slack(&notif);
        assert!(payload.contains("#ffcc00"));

        notif.severity = "low".to_string();
        let payload = NotificationFormatter::format_slack(&notif);
        assert!(payload.contains("#0066ff"));
    }
}
