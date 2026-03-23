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

#[derive(Debug, Clone, PartialEq)]
pub enum BroadcastChannelSecurityIssue {
    CrossOriginDataLeak,
    SensitiveDataBroadcast,
    ChannelNameEnumeration,
    ReplayAttack,
    BroadcastWithoutValidation,
    ChannelFlooding,
    BroadcastInBackground,
    BroadcastSessionHijack,
    BroadcastFingerprinting,
    UnencryptedBroadcast,
}

impl std::fmt::Display for BroadcastChannelSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CrossOriginDataLeak => write!(f, "cross_origin_data_leak"),
            Self::SensitiveDataBroadcast => write!(f, "sensitive_data_broadcast"),
            Self::ChannelNameEnumeration => write!(f, "channel_name_enumeration"),
            Self::ReplayAttack => write!(f, "replay_attack"),
            Self::BroadcastWithoutValidation => write!(f, "broadcast_without_validation"),
            Self::ChannelFlooding => write!(f, "channel_flooding"),
            Self::BroadcastInBackground => write!(f, "broadcast_in_background"),
            Self::BroadcastSessionHijack => write!(f, "broadcast_session_hijack"),
            Self::BroadcastFingerprinting => write!(f, "broadcast_fingerprinting"),
            Self::UnencryptedBroadcast => write!(f, "unencrypted_broadcast"),
        }
    }
}

pub fn analyze_broadcast_channel_security(body: &str) -> Vec<BroadcastChannelSecurityIssue> {
    if !body.contains("BroadcastChannel")
        && !body.contains("postMessage")
        && !body.contains("onmessage")
    {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if has_cross_origin_data_leak(body) {
        issues.push(BroadcastChannelSecurityIssue::CrossOriginDataLeak);
    }

    if has_sensitive_data_broadcast(body) {
        issues.push(BroadcastChannelSecurityIssue::SensitiveDataBroadcast);
    }

    if has_channel_name_enumeration(body) {
        issues.push(BroadcastChannelSecurityIssue::ChannelNameEnumeration);
    }

    if has_replay_attack(body) {
        issues.push(BroadcastChannelSecurityIssue::ReplayAttack);
    }

    if has_broadcast_without_validation(body) {
        issues.push(BroadcastChannelSecurityIssue::BroadcastWithoutValidation);
    }

    if has_channel_flooding(body) {
        issues.push(BroadcastChannelSecurityIssue::ChannelFlooding);
    }

    if has_broadcast_in_background(body) {
        issues.push(BroadcastChannelSecurityIssue::BroadcastInBackground);
    }

    if has_broadcast_session_hijack(body) {
        issues.push(BroadcastChannelSecurityIssue::BroadcastSessionHijack);
    }

    if has_broadcast_fingerprinting(body) {
        issues.push(BroadcastChannelSecurityIssue::BroadcastFingerprinting);
    }

    if has_unencrypted_broadcast(body) {
        issues.push(BroadcastChannelSecurityIssue::UnencryptedBroadcast);
    }

    issues
}

fn has_cross_origin_data_leak(body: &str) -> bool {
    if !body.contains("BroadcastChannel") {
        return false;
    }
    (body.contains("postMessage") && body.contains("iframe"))
        || (body.contains("BroadcastChannel") && body.contains("window.parent.postMessage"))
        || (body.contains("BroadcastChannel") && body.contains("contentWindow.postMessage"))
}

fn has_sensitive_data_broadcast(body: &str) -> bool {
    if !body.contains("BroadcastChannel") {
        return false;
    }
    let sensitive_patterns = [
        "password",
        "token",
        "credential",
        "ssn",
        "social_security",
        "api_key",
        "apiKey",
        "secret",
        "privateKey",
        "auth_token",
    ];
    let has_broadcast = body.contains(".postMessage(");
    has_broadcast && sensitive_patterns.iter().any(|p| body.contains(p))
}

fn has_channel_name_enumeration(body: &str) -> bool {
    if !body.contains("BroadcastChannel") {
        return false;
    }
    (body.contains("for") && body.contains("BroadcastChannel("))
        || (body.contains("forEach") && body.contains("BroadcastChannel"))
        || (body.contains("map(") && body.contains("BroadcastChannel"))
        || (body.contains("while") && body.contains("BroadcastChannel"))
}

fn has_replay_attack(body: &str) -> bool {
    if !body.contains("BroadcastChannel") {
        return false;
    }
    (body.contains("localStorage.setItem") && body.contains("onmessage"))
        || (body.contains("sessionStorage.setItem") && body.contains("onmessage"))
        || (body.contains(".push(") && body.contains("onmessage") && body.contains("postMessage"))
}

fn has_broadcast_without_validation(body: &str) -> bool {
    if !body.contains("BroadcastChannel") || !body.contains(".postMessage(") {
        return false;
    }
    !body.contains("if (")
        && !body.contains("validate")
        && !body.contains("typeof")
        && !body.contains("instanceof")
}

fn has_channel_flooding(body: &str) -> bool {
    if !body.contains("BroadcastChannel") {
        return false;
    }
    (body.contains("setInterval") && body.contains(".postMessage("))
        || (body.contains("setTimeout")
            && body.contains(".postMessage(")
            && body.contains("recursive"))
        || (body.contains("while (true)") && body.contains(".postMessage("))
}

fn has_broadcast_in_background(body: &str) -> bool {
    if !body.contains("BroadcastChannel") {
        return false;
    }
    (body.contains("visibilitychange") && body.contains(".postMessage("))
        || (body.contains("document.hidden") && body.contains(".postMessage("))
        || (body.contains("document.visibilityState") && body.contains(".postMessage("))
}

fn has_broadcast_session_hijack(body: &str) -> bool {
    if !body.contains("BroadcastChannel") {
        return false;
    }
    let session_patterns = ["sessionStorage", "localStorage.getItem", "document.cookie"];
    let has_broadcast = body.contains(".postMessage(");
    has_broadcast && session_patterns.iter().any(|p| body.contains(p))
}

fn has_broadcast_fingerprinting(body: &str) -> bool {
    if !body.contains("BroadcastChannel") {
        return false;
    }
    (body.contains("performance.now()") && body.contains("BroadcastChannel"))
        || (body.contains("Date.now()")
            && body.contains("onmessage")
            && body.contains("postMessage"))
        || (body.contains("timestamp")
            && body.contains("BroadcastChannel")
            && body.contains("measure"))
}

fn has_unencrypted_broadcast(body: &str) -> bool {
    if !body.contains("BroadcastChannel") || !body.contains(".postMessage(") {
        return false;
    }
    let has_sensitive = ["password", "token", "ssn", "credit_card", "api_key"]
        .iter()
        .any(|p| body.contains(p));
    let has_encryption = body.contains("encrypt")
        || body.contains("crypto.subtle")
        || body.contains("CryptoJS")
        || body.contains("cipher");
    has_sensitive && !has_encryption
}

pub fn broadcast_channel_security_severity(issue: &BroadcastChannelSecurityIssue) -> f64 {
    match issue {
        BroadcastChannelSecurityIssue::BroadcastSessionHijack => 9.0,
        BroadcastChannelSecurityIssue::SensitiveDataBroadcast => 8.5,
        BroadcastChannelSecurityIssue::UnencryptedBroadcast => 8.0,
        BroadcastChannelSecurityIssue::CrossOriginDataLeak => 7.5,
        BroadcastChannelSecurityIssue::ReplayAttack => 7.0,
        BroadcastChannelSecurityIssue::BroadcastWithoutValidation => 6.5,
        BroadcastChannelSecurityIssue::ChannelNameEnumeration => 5.5,
        BroadcastChannelSecurityIssue::ChannelFlooding => 5.0,
        BroadcastChannelSecurityIssue::BroadcastFingerprinting => 4.5,
        BroadcastChannelSecurityIssue::BroadcastInBackground => 3.0,
    }
}

pub fn broadcast_channel_security_to_operations(
    issues: &[BroadcastChannelSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                broadcast_channel_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
