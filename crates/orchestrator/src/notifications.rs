use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Supported notification channels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationChannel {
    Webhook(WebhookConfig),
    Email(EmailConfig),
    PagerDuty(PagerDutyConfig),
    CustomHttp(CustomHttpConfig),
}

/// Webhook configuration (Slack, Discord, Teams compatible).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub format: WebhookFormat,
    pub channel_name: Option<String>,
}

/// Wire format for webhook payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WebhookFormat {
    Slack,
    Discord,
    Teams,
    Generic,
}

/// Email notification configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub from_address: String,
    pub to_addresses: Vec<String>,
    pub use_tls: bool,
}

/// PagerDuty integration configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PagerDutyConfig {
    pub routing_key: String,
    pub severity_mapping: HashMap<String, String>,
}

/// Custom HTTP callback configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomHttpConfig {
    pub url: String,
    pub method: HttpMethod,
    pub headers: HashMap<String, String>,
    pub body_template: Option<String>,
}

/// HTTP methods supported for custom callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    Post,
    Put,
    Patch,
}

/// An alert notification to be sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertNotification {
    pub notification_id: String,
    pub title: String,
    pub message: String,
    pub severity: String,
    pub target_url: String,
    pub finding_count: usize,
    pub timestamp_ms: u64,
    pub details: HashMap<String, String>,
}

/// Outcome of a notification delivery attempt.
#[derive(Debug, Clone)]
pub enum DeliveryResult {
    Success { channel_id: String },
    Failed { channel_id: String, error: String },
    Deduplicated { channel_id: String },
}

impl DeliveryResult {
    pub fn is_success(&self) -> bool {
        matches!(self, DeliveryResult::Success { .. })
    }

    pub fn channel_id(&self) -> &str {
        match self {
            DeliveryResult::Success { channel_id }
            | DeliveryResult::Failed { channel_id, .. }
            | DeliveryResult::Deduplicated { channel_id } => channel_id,
        }
    }
}

/// Per-channel formatting of notifications into their wire format.
pub struct NotificationFormatter;

impl NotificationFormatter {
    /// Formats a notification as a Slack webhook JSON payload.
    pub fn format_slack(notification: &AlertNotification) -> String {
        let color = match notification.severity.as_str() {
            "critical" => "#ff0000",
            "high" => "#ff6600",
            "medium" => "#ffcc00",
            "low" => "#0066ff",
            _ => "#999999",
        };
        format!(
            r#"{{"attachments":[{{"color":"{}","title":"{}","text":"{}","fields":[{{"title":"Target","value":"{}","short":true}},{{"title":"Findings","value":"{}","short":true}},{{"title":"Severity","value":"{}","short":true}}],"ts":{}}}]}}"#,
            color,
            notification.title,
            notification.message,
            notification.target_url,
            notification.finding_count,
            notification.severity,
            notification.timestamp_ms / 1000,
        )
    }

    /// Formats a notification as a Discord webhook JSON payload.
    pub fn format_discord(notification: &AlertNotification) -> String {
        let color = match notification.severity.as_str() {
            "critical" => 16711680,
            "high" => 16737280,
            "medium" => 16763904,
            "low" => 26367,
            _ => 10066329,
        };
        format!(
            r#"{{"embeds":[{{"title":"{}","description":"{}","color":{},"fields":[{{"name":"Target","value":"{}","inline":true}},{{"name":"Findings","value":"{}","inline":true}}]}}]}}"#,
            notification.title,
            notification.message,
            color,
            notification.target_url,
            notification.finding_count,
        )
    }

    /// Formats a notification as a Microsoft Teams adaptive card payload.
    pub fn format_teams(notification: &AlertNotification) -> String {
        format!(
            r#"{{"@type":"MessageCard","summary":"{}","themeColor":"{}","title":"{}","sections":[{{"facts":[{{"name":"Target","value":"{}"}},{{"name":"Severity","value":"{}"}},{{"name":"Findings","value":"{}"}}],"text":"{}"}}]}}"#,
            notification.title,
            match notification.severity.as_str() {
                "critical" => "FF0000",
                "high" => "FF6600",
                "medium" => "FFCC00",
                _ => "0066FF",
            },
            notification.title,
            notification.target_url,
            notification.severity,
            notification.finding_count,
            notification.message,
        )
    }

    /// Formats as a generic JSON payload.
    pub fn format_generic(notification: &AlertNotification) -> String {
        serde_json::to_string(notification).unwrap_or_else(|_| "{}".to_string())
    }

    /// Formats for PagerDuty Events API v2.
    pub fn format_pagerduty(notification: &AlertNotification, routing_key: &str) -> String {
        let pd_severity = match notification.severity.as_str() {
            "critical" => "critical",
            "high" => "error",
            "medium" => "warning",
            _ => "info",
        };
        format!(
            r#"{{"routing_key":"{}","event_action":"trigger","payload":{{"summary":"{}","source":"{}","severity":"{}","custom_details":{{"message":"{}","finding_count":{},"timestamp_ms":{}}}}}}}"#,
            routing_key,
            notification.title,
            notification.target_url,
            pd_severity,
            notification.message,
            notification.finding_count,
            notification.timestamp_ms,
        )
    }
}

/// Tracks recently sent notifications for deduplication.
pub struct DeduplicationTracker {
    sent_keys: HashSet<String>,
    window_ms: u64,
    entries: Vec<(String, u64)>,
}

impl DeduplicationTracker {
    pub fn new(window_ms: u64) -> Self {
        Self {
            sent_keys: HashSet::new(),
            window_ms,
            entries: Vec::new(),
        }
    }

    /// Generates a dedup key from notification fields.
    pub fn dedup_key(notification: &AlertNotification) -> String {
        format!(
            "{}:{}:{}:{}",
            notification.target_url,
            notification.severity,
            notification.title,
            notification.finding_count,
        )
    }

    /// Returns true if the notification is a duplicate within the window.
    pub fn is_duplicate(&self, notification: &AlertNotification, now_ms: u64) -> bool {
        let key = Self::dedup_key(notification);
        for (k, ts) in &self.entries {
            if k == &key && now_ms.saturating_sub(*ts) < self.window_ms {
                return true;
            }
        }
        false
    }

    /// Marks a notification as sent.
    pub fn mark_sent(&mut self, notification: &AlertNotification, now_ms: u64) {
        let key = Self::dedup_key(notification);
        self.sent_keys.insert(key.clone());
        self.entries.push((key, now_ms));
    }

    /// Evicts entries older than the deduplication window.
    pub fn evict_expired(&mut self, now_ms: u64) {
        self.entries.retain(|(k, ts)| {
            if now_ms.saturating_sub(*ts) >= self.window_ms {
                self.sent_keys.remove(k);
                false
            } else {
                true
            }
        });
    }

    /// Number of tracked entries.
    pub fn tracked_count(&self) -> usize {
        self.entries.len()
    }
}

/// Manages notification channels and dispatches alerts with deduplication.
pub struct NotificationDispatcher {
    channels: Vec<(String, NotificationChannel)>,
    dedup: DeduplicationTracker,
}

impl NotificationDispatcher {
    pub fn new(dedup_window_ms: u64) -> Self {
        Self {
            channels: Vec::new(),
            dedup: DeduplicationTracker::new(dedup_window_ms),
        }
    }

    /// Registers a notification channel with a unique ID.
    pub fn add_channel(&mut self, channel_id: &str, channel: NotificationChannel) {
        self.channels.push((channel_id.to_string(), channel));
    }

    /// Removes a channel by ID. Returns true if removed.
    pub fn remove_channel(&mut self, channel_id: &str) -> bool {
        let before = self.channels.len();
        self.channels.retain(|(id, _)| id != channel_id);
        self.channels.len() < before
    }

    /// Returns the number of registered channels.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Formats a notification for a specific channel, returning the payload string.
    pub fn format_for_channel(
        notification: &AlertNotification,
        channel: &NotificationChannel,
    ) -> String {
        match channel {
            NotificationChannel::Webhook(cfg) => match cfg.format {
                WebhookFormat::Slack => NotificationFormatter::format_slack(notification),
                WebhookFormat::Discord => NotificationFormatter::format_discord(notification),
                WebhookFormat::Teams => NotificationFormatter::format_teams(notification),
                WebhookFormat::Generic => NotificationFormatter::format_generic(notification),
            },
            NotificationChannel::Email(_cfg) => {
                format!(
                    "Subject: {}\n\n{}\n\nTarget: {}\nSeverity: {}\nFindings: {}",
                    notification.title,
                    notification.message,
                    notification.target_url,
                    notification.severity,
                    notification.finding_count,
                )
            }
            NotificationChannel::PagerDuty(cfg) => {
                NotificationFormatter::format_pagerduty(notification, &cfg.routing_key)
            }
            NotificationChannel::CustomHttp(cfg) => {
                if let Some(template) = &cfg.body_template {
                    template
                        .replace("{title}", &notification.title)
                        .replace("{message}", &notification.message)
                        .replace("{severity}", &notification.severity)
                        .replace("{target}", &notification.target_url)
                        .replace("{count}", &notification.finding_count.to_string())
                } else {
                    NotificationFormatter::format_generic(notification)
                }
            }
        }
    }

    /// Dispatches a notification to all channels with deduplication.
    ///
    /// Returns results per channel. Does NOT actually perform HTTP requests;
    /// this module produces formatted payloads for the caller to send.
    pub fn dispatch(
        &mut self,
        notification: &AlertNotification,
        now_ms: u64,
    ) -> Vec<DeliveryResult> {
        self.dedup.evict_expired(now_ms);

        if self.dedup.is_duplicate(notification, now_ms) {
            return self
                .channels
                .iter()
                .map(|(id, _)| DeliveryResult::Deduplicated {
                    channel_id: id.clone(),
                })
                .collect();
        }

        self.dedup.mark_sent(notification, now_ms);

        let mut results = Vec::new();
        for (id, channel) in &self.channels {
            let _payload = Self::format_for_channel(notification, channel);
            results.push(DeliveryResult::Success {
                channel_id: id.clone(),
            });
        }
        results
    }
}
