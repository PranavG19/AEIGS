use crate::broadcast_channel_audit::*;

#[test]
fn no_broadcast_no_issues() {
    assert!(analyze_broadcast_channel("<html></html>").is_empty());
}

#[test]
fn detects_channel() {
    let body = r#"<script>const ch = new BroadcastChannel("updates")</script>"#;
    let issues = analyze_broadcast_channel(body);
    assert!(issues.contains(&BroadcastChannelIssue::ChannelDetected));
}

#[test]
fn detects_sensitive_name_auth() {
    let body = r#"<script>new BroadcastChannel("auth-sync")</script>"#;
    let issues = analyze_broadcast_channel(body);
    assert!(issues.contains(&BroadcastChannelIssue::SensitiveChannelName));
}

#[test]
fn detects_sensitive_name_token() {
    let body = r#"<script>new BroadcastChannel("token_refresh")</script>"#;
    let issues = analyze_broadcast_channel(body);
    assert!(issues.contains(&BroadcastChannelIssue::SensitiveChannelName));
}

#[test]
fn no_sensitive_with_normal_name() {
    let body = r#"<script>new BroadcastChannel("tab-sync")</script>"#;
    let issues = analyze_broadcast_channel(body);
    assert!(!issues.contains(&BroadcastChannelIssue::SensitiveChannelName));
}

#[test]
fn detects_post_message() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        ch.postMessage({type: "update"});
    </script>"#;
    let issues = analyze_broadcast_channel(body);
    assert!(issues.contains(&BroadcastChannelIssue::PostMessageUsed));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        ch.postMessage(data);
        fetch("/api/collect", {body: JSON.stringify(data)});
    </script>"#;
    let issues = analyze_broadcast_channel(body);
    assert!(issues.contains(&BroadcastChannelIssue::DataExfiltration));
}

#[test]
fn detects_no_message_validation() {
    let body = r#"<script>new BroadcastChannel("sync")</script>"#;
    let issues = analyze_broadcast_channel(body);
    assert!(issues.contains(&BroadcastChannelIssue::NoMessageValidation));
}

#[test]
fn no_validation_issue_with_handler() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        ch.onmessage = (e) => handleMessage(e);
    </script>"#;
    let issues = analyze_broadcast_channel(body);
    assert!(!issues.contains(&BroadcastChannelIssue::NoMessageValidation));
}

#[test]
fn detects_excessive_channels() {
    let body = r#"<script>
        new BroadcastChannel("a");
        new BroadcastChannel("b");
        new BroadcastChannel("c");
        new BroadcastChannel("d");
    </script>"#;
    let issues = analyze_broadcast_channel(body);
    assert!(issues.contains(&BroadcastChannelIssue::ExcessiveChannels));
}

#[test]
fn no_excessive_with_few_channels() {
    let body = r#"<script>
        new BroadcastChannel("a");
        new BroadcastChannel("b");
    </script>"#;
    let issues = analyze_broadcast_channel(body);
    assert!(!issues.contains(&BroadcastChannelIssue::ExcessiveChannels));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(broadcast_channel_severity(&BroadcastChannelIssue::DataExfiltration), 6.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(broadcast_channel_severity(&BroadcastChannelIssue::ChannelDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        BroadcastChannelIssue::ChannelDetected,
        BroadcastChannelIssue::DataExfiltration,
    ];
    let mut seq = 0;
    let ops = broadcast_channel_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(BroadcastChannelIssue::ChannelDetected.to_string(), "channel_detected");
    assert_eq!(BroadcastChannelIssue::SensitiveChannelName.to_string(), "sensitive_channel_name");
    assert_eq!(BroadcastChannelIssue::PostMessageUsed.to_string(), "post_message_used");
    assert_eq!(BroadcastChannelIssue::NoMessageValidation.to_string(), "no_message_validation");
    assert_eq!(BroadcastChannelIssue::ExcessiveChannels.to_string(), "excessive_channels");
    assert_eq!(BroadcastChannelIssue::DataExfiltration.to_string(), "data_exfiltration");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_broadcast_channel("").is_empty());
}
