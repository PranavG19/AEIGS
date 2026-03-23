use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum BroadcastChannelIssue {
    ChannelDetected,
    SensitiveChannelName,
    PostMessageUsed,
    NoMessageValidation,
    ExcessiveChannels,
    DataExfiltration,
}

impl std::fmt::Display for BroadcastChannelIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChannelDetected => write!(f, "channel_detected"),
            Self::SensitiveChannelName => write!(f, "sensitive_channel_name"),
            Self::PostMessageUsed => write!(f, "post_message_used"),
            Self::NoMessageValidation => write!(f, "no_message_validation"),
            Self::ExcessiveChannels => write!(f, "excessive_channels"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
        }
    }
}

pub fn audit_broadcast_channel(target: &str) -> Vec<BroadcastChannelIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_broadcast_channel(&body)
}

pub fn analyze_broadcast_channel(body: &str) -> Vec<BroadcastChannelIssue> {
    if !body.contains("BroadcastChannel") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(BroadcastChannelIssue::ChannelDetected);

    if has_sensitive_channel_name(body) {
        issues.push(BroadcastChannelIssue::SensitiveChannelName);
    }

    if body.contains(".postMessage(") {
        issues.push(BroadcastChannelIssue::PostMessageUsed);

        if body.contains("fetch(") || body.contains("XMLHttpRequest") || body.contains("sendBeacon")
        {
            issues.push(BroadcastChannelIssue::DataExfiltration);
        }
    }

    if !body.contains("onmessage") && !body.contains("addEventListener") {
        issues.push(BroadcastChannelIssue::NoMessageValidation);
    }

    let channel_count = count_channels(body);
    if channel_count > 3 {
        issues.push(BroadcastChannelIssue::ExcessiveChannels);
    }

    issues
}

fn has_sensitive_channel_name(body: &str) -> bool {
    let sensitive = [
        "auth",
        "token",
        "session",
        "login",
        "password",
        "secret",
        "credential",
        "payment",
        "admin",
    ];
    let marker = "BroadcastChannel(";
    let mut search_from = 0;
    while let Some(pos) = body[search_from..].find(marker) {
        let start = search_from + pos + marker.len();
        if start >= body.len() {
            break;
        }
        let rest = &body[start..];
        let name = if let Some(stripped) = rest.strip_prefix('"') {
            stripped.split('"').next()
        } else if let Some(stripped) = rest.strip_prefix('\'') {
            stripped.split('\'').next()
        } else {
            None
        };
        if let Some(n) = name {
            let lower = n.to_ascii_lowercase();
            if sensitive.iter().any(|s| lower.contains(s)) {
                return true;
            }
        }
        search_from = start;
    }
    false
}

fn count_channels(body: &str) -> usize {
    let mut names = std::collections::HashSet::new();
    let marker = "BroadcastChannel(";
    let mut search_from = 0;
    while let Some(pos) = body[search_from..].find(marker) {
        let start = search_from + pos + marker.len();
        if start >= body.len() {
            break;
        }
        let rest = &body[start..];
        let name = if let Some(stripped) = rest.strip_prefix('"') {
            stripped.split('"').next()
        } else if let Some(stripped) = rest.strip_prefix('\'') {
            stripped.split('\'').next()
        } else {
            None
        };
        if let Some(n) = name {
            names.insert(n);
        }
        search_from = start;
    }
    names.len()
}

pub fn broadcast_channel_severity(issue: &BroadcastChannelIssue) -> f64 {
    match issue {
        BroadcastChannelIssue::DataExfiltration => 6.5,
        BroadcastChannelIssue::SensitiveChannelName => 5.5,
        BroadcastChannelIssue::NoMessageValidation => 5.0,
        BroadcastChannelIssue::ExcessiveChannels => 4.5,
        BroadcastChannelIssue::PostMessageUsed => 4.0,
        BroadcastChannelIssue::ChannelDetected => 3.0,
    }
}

pub fn broadcast_channel_to_operations(
    issues: &[BroadcastChannelIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                broadcast_channel_severity(issue),
                0.7,
            )
        })
        .collect()
}
