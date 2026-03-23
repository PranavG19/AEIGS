use super::*;

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
    assert_eq!(
        broadcast_channel_severity(&BroadcastChannelIssue::DataExfiltration),
        6.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        broadcast_channel_severity(&BroadcastChannelIssue::ChannelDetected),
        3.0
    );
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
    assert_eq!(
        BroadcastChannelIssue::ChannelDetected.to_string(),
        "channel_detected"
    );
    assert_eq!(
        BroadcastChannelIssue::SensitiveChannelName.to_string(),
        "sensitive_channel_name"
    );
    assert_eq!(
        BroadcastChannelIssue::PostMessageUsed.to_string(),
        "post_message_used"
    );
    assert_eq!(
        BroadcastChannelIssue::NoMessageValidation.to_string(),
        "no_message_validation"
    );
    assert_eq!(
        BroadcastChannelIssue::ExcessiveChannels.to_string(),
        "excessive_channels"
    );
    assert_eq!(
        BroadcastChannelIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_broadcast_channel("").is_empty());
}

#[test]
fn test_empty_body_no_security_issues() {
    assert!(analyze_broadcast_channel_security("").is_empty());
}

#[test]
fn test_no_broadcast_channel_no_security_issues() {
    let body = r#"<script>console.log("hello");</script>"#;
    assert!(analyze_broadcast_channel_security(body).is_empty());
}

#[test]
fn test_cross_origin_data_leak_with_iframe() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        ch.onmessage = (e) => {
            const iframe = document.getElementById("frame");
            iframe.contentWindow.postMessage(e.data, "*");
        };
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::CrossOriginDataLeak));
}

#[test]
fn test_cross_origin_data_leak_with_parent() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        ch.onmessage = (e) => window.parent.postMessage(e.data, "*");
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::CrossOriginDataLeak));
}

#[test]
fn test_no_cross_origin_leak_without_iframe() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        ch.postMessage({type: "update"});
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(!issues.contains(&BroadcastChannelSecurityIssue::CrossOriginDataLeak));
}

#[test]
fn test_sensitive_data_broadcast_password() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        ch.postMessage({password: userPassword});
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::SensitiveDataBroadcast));
}

#[test]
fn test_sensitive_data_broadcast_token() {
    let body = r#"<script>
        const ch = new BroadcastChannel("auth");
        ch.postMessage({token: authToken, user: userId});
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::SensitiveDataBroadcast));
}

#[test]
fn test_sensitive_data_broadcast_ssn() {
    let body = r#"<script>
        const ch = new BroadcastChannel("data");
        ch.postMessage({ssn: "123-45-6789"});
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::SensitiveDataBroadcast));
}

#[test]
fn test_no_sensitive_data_broadcast_without_sensitive_fields() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        ch.postMessage({count: 5, status: "ok"});
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(!issues.contains(&BroadcastChannelSecurityIssue::SensitiveDataBroadcast));
}

#[test]
fn test_channel_name_enumeration_for_loop() {
    let body = r#"<script>
        for (let i = 0; i < names.length; i++) {
            const ch = new BroadcastChannel(names[i]);
            ch.postMessage("probe");
        }
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::ChannelNameEnumeration));
}

#[test]
fn test_channel_name_enumeration_foreach() {
    let body = r#"<script>
        channels.forEach(name => {
            const ch = new BroadcastChannel(name);
            ch.onmessage = handler;
        });
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::ChannelNameEnumeration));
}

#[test]
fn test_channel_name_enumeration_map() {
    let body = r#"<script>
        const listeners = channelNames.map(name => new BroadcastChannel(name));
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::ChannelNameEnumeration));
}

#[test]
fn test_no_channel_enumeration_single_channel() {
    let body = r#"<script>
        const ch = new BroadcastChannel("myChannel");
        ch.postMessage("data");
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(!issues.contains(&BroadcastChannelSecurityIssue::ChannelNameEnumeration));
}

#[test]
fn test_replay_attack_localstorage() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        ch.onmessage = (e) => {
            localStorage.setItem("captured", JSON.stringify(e.data));
            ch.postMessage(e.data);
        };
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::ReplayAttack));
}

#[test]
fn test_replay_attack_sessionstorage() {
    let body = r#"<script>
        const ch = new BroadcastChannel("auth");
        ch.onmessage = (e) => {
            sessionStorage.setItem("msg", e.data);
        };
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::ReplayAttack));
}

#[test]
fn test_replay_attack_array_push() {
    let body = r#"<script>
        const messages = [];
        const ch = new BroadcastChannel("log");
        ch.onmessage = (e) => {
            messages.push(e.data);
            ch.postMessage(messages[0]);
        };
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::ReplayAttack));
}

#[test]
fn test_no_replay_attack_without_storage() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        ch.onmessage = (e) => console.log(e.data);
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(!issues.contains(&BroadcastChannelSecurityIssue::ReplayAttack));
}

#[test]
fn test_broadcast_without_validation() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        ch.postMessage(userInput);
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::BroadcastWithoutValidation));
}

#[test]
fn test_no_broadcast_without_validation_when_validated() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        if (typeof data === "string") {
            ch.postMessage(data);
        }
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(!issues.contains(&BroadcastChannelSecurityIssue::BroadcastWithoutValidation));
}

#[test]
fn test_no_broadcast_without_validation_with_validate_function() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        const validated = validate(data);
        ch.postMessage(validated);
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(!issues.contains(&BroadcastChannelSecurityIssue::BroadcastWithoutValidation));
}

#[test]
fn test_channel_flooding_setinterval() {
    let body = r#"<script>
        const ch = new BroadcastChannel("spam");
        setInterval(() => {
            ch.postMessage("flood");
        }, 10);
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::ChannelFlooding));
}

#[test]
fn test_channel_flooding_while_loop() {
    let body = r#"<script>
        const ch = new BroadcastChannel("spam");
        while (true) {
            ch.postMessage("attack");
        }
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::ChannelFlooding));
}

#[test]
fn test_no_channel_flooding_single_message() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        ch.postMessage("single message");
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(!issues.contains(&BroadcastChannelSecurityIssue::ChannelFlooding));
}

#[test]
fn test_broadcast_in_background_visibilitychange() {
    let body = r#"<script>
        const ch = new BroadcastChannel("tracking");
        document.addEventListener("visibilitychange", () => {
            ch.postMessage({event: "visibility", time: Date.now()});
        });
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::BroadcastInBackground));
}

#[test]
fn test_broadcast_in_background_document_hidden() {
    let body = r#"<script>
        const ch = new BroadcastChannel("stealth");
        if (document.hidden) {
            ch.postMessage("background activity");
        }
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::BroadcastInBackground));
}

#[test]
fn test_broadcast_in_background_visibility_state() {
    let body = r#"<script>
        const ch = new BroadcastChannel("monitor");
        if (document.visibilityState === "hidden") {
            ch.postMessage({state: "hidden"});
        }
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::BroadcastInBackground));
}

#[test]
fn test_no_broadcast_in_background_normal() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        ch.postMessage({data: "normal"});
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(!issues.contains(&BroadcastChannelSecurityIssue::BroadcastInBackground));
}

#[test]
fn test_broadcast_session_hijack_sessionstorage() {
    let body = r#"<script>
        const ch = new BroadcastChannel("hijack");
        const session = sessionStorage.getItem("token");
        ch.postMessage({session: session});
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::BroadcastSessionHijack));
}

#[test]
fn test_broadcast_session_hijack_cookie() {
    let body = r#"<script>
        const ch = new BroadcastChannel("steal");
        ch.postMessage({cookies: document.cookie});
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::BroadcastSessionHijack));
}

#[test]
fn test_broadcast_session_hijack_localstorage() {
    let body = r#"<script>
        const ch = new BroadcastChannel("exfil");
        const token = localStorage.getItem("authToken");
        ch.postMessage(token);
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::BroadcastSessionHijack));
}

#[test]
fn test_no_broadcast_session_hijack_without_storage() {
    let body = r#"<script>
        const ch = new BroadcastChannel("safe");
        ch.postMessage({data: "normal data"});
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(!issues.contains(&BroadcastChannelSecurityIssue::BroadcastSessionHijack));
}

#[test]
fn test_broadcast_fingerprinting_performance_now() {
    let body = r#"<script>
        const ch = new BroadcastChannel("timing");
        const start = performance.now();
        doWork();
        const end = performance.now();
        ch.postMessage({duration: end - start});
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::BroadcastFingerprinting));
}

#[test]
fn test_broadcast_fingerprinting_date_now() {
    let body = r#"<script>
        const ch = new BroadcastChannel("profile");
        ch.onmessage = (e) => {
            const now = Date.now();
            ch.postMessage({timestamp: now, data: e.data});
        };
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::BroadcastFingerprinting));
}

#[test]
fn test_broadcast_fingerprinting_timestamp_measure() {
    let body = r#"<script>
        const ch = new BroadcastChannel("metrics");
        const timestamp = Date.now();
        performance.measure("test", "start", "end");
        ch.postMessage({timestamp, measure: "test"});
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::BroadcastFingerprinting));
}

#[test]
fn test_no_broadcast_fingerprinting_normal() {
    let body = r#"<script>
        const ch = new BroadcastChannel("data");
        ch.postMessage({value: 42});
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(!issues.contains(&BroadcastChannelSecurityIssue::BroadcastFingerprinting));
}

#[test]
fn test_unencrypted_broadcast_password() {
    let body = r#"<script>
        const ch = new BroadcastChannel("creds");
        ch.postMessage({password: userPassword});
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::UnencryptedBroadcast));
}

#[test]
fn test_unencrypted_broadcast_token() {
    let body = r#"<script>
        const ch = new BroadcastChannel("auth");
        ch.postMessage({token: apiToken});
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(issues.contains(&BroadcastChannelSecurityIssue::UnencryptedBroadcast));
}

#[test]
fn test_no_unencrypted_broadcast_with_encryption() {
    let body = r#"<script>
        const ch = new BroadcastChannel("secure");
        const encrypted = encrypt(password);
        ch.postMessage({data: encrypted});
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(!issues.contains(&BroadcastChannelSecurityIssue::UnencryptedBroadcast));
}

#[test]
fn test_no_unencrypted_broadcast_with_crypto_subtle() {
    let body = r#"<script>
        const ch = new BroadcastChannel("secure");
        crypto.subtle.encrypt(algorithm, key, data).then(encrypted => {
            ch.postMessage({password: encrypted});
        });
    </script>"#;
    let issues = analyze_broadcast_channel_security(body);
    assert!(!issues.contains(&BroadcastChannelSecurityIssue::UnencryptedBroadcast));
}

#[test]
fn test_display_trait() {
    assert_eq!(
        BroadcastChannelSecurityIssue::CrossOriginDataLeak.to_string(),
        "cross_origin_data_leak"
    );
    assert_eq!(
        BroadcastChannelSecurityIssue::SensitiveDataBroadcast.to_string(),
        "sensitive_data_broadcast"
    );
    assert_eq!(
        BroadcastChannelSecurityIssue::ChannelNameEnumeration.to_string(),
        "channel_name_enumeration"
    );
    assert_eq!(
        BroadcastChannelSecurityIssue::ReplayAttack.to_string(),
        "replay_attack"
    );
    assert_eq!(
        BroadcastChannelSecurityIssue::BroadcastWithoutValidation.to_string(),
        "broadcast_without_validation"
    );
    assert_eq!(
        BroadcastChannelSecurityIssue::ChannelFlooding.to_string(),
        "channel_flooding"
    );
    assert_eq!(
        BroadcastChannelSecurityIssue::BroadcastInBackground.to_string(),
        "broadcast_in_background"
    );
    assert_eq!(
        BroadcastChannelSecurityIssue::BroadcastSessionHijack.to_string(),
        "broadcast_session_hijack"
    );
    assert_eq!(
        BroadcastChannelSecurityIssue::BroadcastFingerprinting.to_string(),
        "broadcast_fingerprinting"
    );
    assert_eq!(
        BroadcastChannelSecurityIssue::UnencryptedBroadcast.to_string(),
        "unencrypted_broadcast"
    );
}

#[test]
fn test_severity_range() {
    let all_variants = vec![
        BroadcastChannelSecurityIssue::CrossOriginDataLeak,
        BroadcastChannelSecurityIssue::SensitiveDataBroadcast,
        BroadcastChannelSecurityIssue::ChannelNameEnumeration,
        BroadcastChannelSecurityIssue::ReplayAttack,
        BroadcastChannelSecurityIssue::BroadcastWithoutValidation,
        BroadcastChannelSecurityIssue::ChannelFlooding,
        BroadcastChannelSecurityIssue::BroadcastInBackground,
        BroadcastChannelSecurityIssue::BroadcastSessionHijack,
        BroadcastChannelSecurityIssue::BroadcastFingerprinting,
        BroadcastChannelSecurityIssue::UnencryptedBroadcast,
    ];

    for variant in all_variants {
        let severity = broadcast_channel_security_severity(&variant);
        assert!(
            severity >= 3.0 && severity <= 9.0,
            "Severity {} for {:?} out of range [3.0, 9.0]",
            severity,
            variant
        );
    }
}

#[test]
fn test_operations_generation() {
    let issues = vec![
        BroadcastChannelSecurityIssue::CrossOriginDataLeak,
        BroadcastChannelSecurityIssue::SensitiveDataBroadcast,
    ];
    let mut seq = 0;
    let ops = broadcast_channel_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn test_multiple_security_issues() {
    let body = r#"<script>
        const ch = new BroadcastChannel("sync");
        const messages = [];

        // Cross-origin leak
        ch.onmessage = (e) => {
            const iframe = document.getElementById("frame");
            iframe.contentWindow.postMessage(e.data, "*");

            // Replay attack
            messages.push(e.data);
            localStorage.setItem("captured", JSON.stringify(e.data));

            // Session hijack
            const authToken = sessionStorage.getItem("token");

            // Fingerprinting
            const timing = performance.now();

            ch.postMessage({authToken, timing});
        };

        // Flooding
        setInterval(() => {
            ch.postMessage("spam");
        }, 10);

        // Sensitive data without protection
        const userPassword = getPassword();
        ch.postMessage({password: userPassword});
    </script>"#;

    let issues = analyze_broadcast_channel_security(body);

    assert!(issues.contains(&BroadcastChannelSecurityIssue::CrossOriginDataLeak));
    assert!(issues.contains(&BroadcastChannelSecurityIssue::ReplayAttack));
    assert!(issues.contains(&BroadcastChannelSecurityIssue::BroadcastSessionHijack));
    assert!(issues.contains(&BroadcastChannelSecurityIssue::BroadcastFingerprinting));
    assert!(issues.contains(&BroadcastChannelSecurityIssue::ChannelFlooding));
    assert!(issues.contains(&BroadcastChannelSecurityIssue::SensitiveDataBroadcast));
    assert!(issues.contains(&BroadcastChannelSecurityIssue::UnencryptedBroadcast));
}

#[test]
fn test_severity_session_hijack_highest() {
    assert_eq!(
        broadcast_channel_security_severity(&BroadcastChannelSecurityIssue::BroadcastSessionHijack),
        9.0
    );
}

#[test]
fn test_severity_background_lowest() {
    assert_eq!(
        broadcast_channel_security_severity(&BroadcastChannelSecurityIssue::BroadcastInBackground),
        3.0
    );
}
