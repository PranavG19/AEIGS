use crate::background_sync_audit::*;

#[test]
fn no_sync_no_issues() {
    assert!(analyze_background_sync("<html></html>").is_empty());
}

#[test]
fn detects_sync_register() {
    let body = r#"<script>reg.sync.register("sync-tag")</script>"#;
    let issues = analyze_background_sync(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncRegisterDetected));
}

#[test]
fn detects_periodic_sync() {
    let body = r#"<script>reg.periodicSync.register("update", {minInterval: 3600000})</script>"#;
    let issues = analyze_background_sync(body);
    assert!(issues.contains(&BackgroundSyncIssue::PeriodicSyncDetected));
}

#[test]
fn detects_short_min_interval() {
    let body = r#"<script>reg.periodicSync.register("check", {minInterval: 5000})</script>"#;
    let issues = analyze_background_sync(body);
    assert!(issues.contains(&BackgroundSyncIssue::ShortMinInterval));
}

#[test]
fn no_short_interval_when_large() {
    let body = r#"<script>reg.periodicSync.register("check", {minInterval: 86400000})</script>"#;
    let issues = analyze_background_sync(body);
    assert!(!issues.contains(&BackgroundSyncIssue::ShortMinInterval));
}

#[test]
fn detects_excessive_sync_tags() {
    let body = r#"<script>
        reg.sync.register("a");
        reg.sync.register("b");
        reg.sync.register("c");
        reg.sync.register("d");
        reg.sync.register("e");
        reg.sync.register("f");
    </script>"#;
    let issues = analyze_background_sync(body);
    assert!(issues.contains(&BackgroundSyncIssue::ExcessiveSyncTags));
}

#[test]
fn no_excessive_with_few_tags() {
    let body = r#"<script>
        reg.sync.register("a");
        reg.sync.register("b");
    </script>"#;
    let issues = analyze_background_sync(body);
    assert!(!issues.contains(&BackgroundSyncIssue::ExcessiveSyncTags));
}

#[test]
fn detects_sync_with_fetch() {
    let body = r#"<script>
        reg.sync.register("upload");
        fetch("/api/upload", {method: "POST"});
    </script>"#;
    let issues = analyze_background_sync(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithFetch));
}

#[test]
fn detects_no_permission_check() {
    let body = r#"<script>reg.periodicSync.register("update", {minInterval: 3600000})</script>"#;
    let issues = analyze_background_sync(body);
    assert!(issues.contains(&BackgroundSyncIssue::NoPermissionCheck));
}

#[test]
fn no_permission_issue_when_checked() {
    let body = r#"<script>
        const status = await navigator.permissions.query({name: 'periodic-background-sync'});
        reg.periodicSync.register("update", {minInterval: 3600000});
    </script>"#;
    let issues = analyze_background_sync(body);
    assert!(!issues.contains(&BackgroundSyncIssue::NoPermissionCheck));
}

#[test]
fn severity_periodic_highest() {
    assert_eq!(
        background_sync_severity(&BackgroundSyncIssue::PeriodicSyncDetected),
        6.0
    );
}

#[test]
fn severity_register_lowest() {
    assert_eq!(
        background_sync_severity(&BackgroundSyncIssue::SyncRegisterDetected),
        3.5
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        BackgroundSyncIssue::SyncRegisterDetected,
        BackgroundSyncIssue::SyncWithFetch,
    ];
    let mut seq = 0;
    let ops = background_sync_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        BackgroundSyncIssue::SyncRegisterDetected.to_string(),
        "sync_register_detected"
    );
    assert_eq!(
        BackgroundSyncIssue::PeriodicSyncDetected.to_string(),
        "periodic_sync_detected"
    );
    assert_eq!(
        BackgroundSyncIssue::ShortMinInterval.to_string(),
        "short_min_interval"
    );
    assert_eq!(
        BackgroundSyncIssue::ExcessiveSyncTags.to_string(),
        "excessive_sync_tags"
    );
    assert_eq!(
        BackgroundSyncIssue::SyncWithFetch.to_string(),
        "sync_with_fetch"
    );
    assert_eq!(
        BackgroundSyncIssue::NoPermissionCheck.to_string(),
        "no_permission_check"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_background_sync("").is_empty());
}

#[test]
fn security_analysis_no_sync_no_issues() {
    let body = "<html><script>fetch('/api')</script></html>";
    assert!(analyze_background_sync_security(body).is_empty());
}

#[test]
fn security_analysis_empty_body() {
    assert!(analyze_background_sync_security("").is_empty());
}

#[test]
fn detects_sync_data_exfiltration_sendbeacon() {
    let body = r#"<script>
        reg.sync.register("upload");
        navigator.sendBeacon("/track", data);
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncDataExfiltration));
}

#[test]
fn detects_sync_data_exfiltration_xmlhttprequest() {
    let body = r#"<script>
        reg.periodicSync.register("sync");
        const xhr = new XMLHttpRequest();
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncDataExfiltration));
}

#[test]
fn detects_sync_data_exfiltration_sendbeacon_variant() {
    let body = r#"<script>
        reg.sync.register("tag");
        sendBeacon("/analytics");
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncDataExfiltration));
}

#[test]
fn detects_sync_with_geolocation_getcurrentposition() {
    let body = r#"<script>
        reg.sync.register("location");
        navigator.geolocation.getCurrentPosition(callback);
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithGeolocation));
}

#[test]
fn detects_sync_with_geolocation_watchposition() {
    let body = r#"<script>
        reg.periodicSync.register("track");
        navigator.geolocation.watchPosition(handler);
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithGeolocation));
}

#[test]
fn detects_sync_with_geolocation_keyword() {
    let body = r#"<script>
        reg.sync.register("geo");
        if (navigator.geolocation) { }
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithGeolocation));
}

#[test]
fn detects_sync_cross_origin_postmessage() {
    let body = r#"<script>
        reg.sync.register("msg");
        window.postMessage(data, "*");
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncCrossOrigin));
}

#[test]
fn detects_sync_cross_origin_keyword() {
    let body = r#"<script>
        reg.periodicSync.register("data");
        fetch("/api", {mode: "cross-origin"});
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncCrossOrigin));
}

#[test]
fn detects_sync_cross_origin_iframe() {
    let body = r#"<script>
        reg.sync.register("embed");
        const iframe = document.createElement("iframe");
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncCrossOrigin));
}

#[test]
fn detects_sync_with_crypto_subtle() {
    let body = r#"<script>
        reg.sync.register("secure");
        await crypto.subtle.encrypt(algorithm, key, data);
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithCrypto));
}

#[test]
fn detects_sync_with_crypto_key() {
    let body = r#"<script>
        reg.periodicSync.register("keys");
        const key = await crypto.subtle.generateKey();
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithCrypto));
}

#[test]
fn detects_sync_with_crypto_encrypt() {
    let body = r#"<script>
        reg.sync.register("data");
        const encrypted = encrypt(plaintext);
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithCrypto));
}

#[test]
fn detects_sync_with_crypto_decrypt() {
    let body = r#"<script>
        reg.sync.register("data");
        const plaintext = decrypt(ciphertext);
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithCrypto));
}

#[test]
fn detects_periodic_sync_abuse_mine() {
    let body = r#"<script>
        reg.periodicSync.register("worker", {minInterval: 60000});
        mine(block);
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::PeriodicSyncAbuseRisk));
}

#[test]
fn detects_periodic_sync_abuse_miner() {
    let body = r#"<script>
        reg.periodicSync.register("bg");
        const miner = new CryptoMiner();
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::PeriodicSyncAbuseRisk));
}

#[test]
fn detects_periodic_sync_abuse_crypto() {
    let body = r#"<script>
        reg.periodicSync.register("proc");
        const miner = initCryptoMiner();
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::PeriodicSyncAbuseRisk));
}

#[test]
fn detects_periodic_sync_abuse_blockchain() {
    let body = r#"<script>
        reg.periodicSync.register("chain");
        updateblockchain();
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::PeriodicSyncAbuseRisk));
}

#[test]
fn no_periodic_sync_abuse_for_regular_sync() {
    let body = r#"<script>
        reg.sync.register("worker");
        mine(block);
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(!issues.contains(&BackgroundSyncIssue::PeriodicSyncAbuseRisk));
}

#[test]
fn detects_sync_in_service_worker_keyword() {
    let body = r#"<script>
        reg.sync.register("sw");
        navigator.serviceWorker.register("/sw.js");
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncInServiceWorker));
}

#[test]
fn detects_sync_in_service_worker_registration() {
    let body = r#"<script>
        const registration = await navigator.ServiceWorkerRegistration;
        registration.sync.register("tag");
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncInServiceWorker));
}

#[test]
fn detects_sync_in_service_worker_self() {
    let body = r#"<script>
        reg.sync.register("task");
        self.addEventListener("fetch", event => {});
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncInServiceWorker));
}

#[test]
fn detects_sync_with_indexed_db() {
    let body = r#"<script>
        reg.sync.register("store");
        const db = indexedDB.open("mydb");
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithIndexedDb));
}

#[test]
fn detects_sync_with_indexed_db_transaction() {
    let body = r#"<script>
        reg.periodicSync.register("data");
        const tx = db.IDBTransaction;
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithIndexedDb));
}

#[test]
fn detects_sync_with_indexed_db_objectstore() {
    let body = r#"<script>
        reg.sync.register("persist");
        const store = tx.objectStore("items");
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithIndexedDb));
}

#[test]
fn detects_sync_retry_loop() {
    let body = r#"<script>
        reg.sync.register("attempt");
        if (retry < maxRetries) { }
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncRetryLoop));
}

#[test]
fn detects_sync_retry_loop_retrycount() {
    let body = r#"<script>
        reg.periodicSync.register("check");
        retryCount++;
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncRetryLoop));
}

#[test]
fn detects_sync_retry_loop_maxretries() {
    let body = r#"<script>
        reg.sync.register("task");
        const maxRetries = 5;
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncRetryLoop));
}

#[test]
fn detects_sync_retry_loop_backoff() {
    let body = r#"<script>
        reg.sync.register("exp");
        await backoff(attempt);
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncRetryLoop));
}

#[test]
fn detects_sync_with_notifications() {
    let body = r#"<script>
        reg.sync.register("notify");
        new Notification("Update available");
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithNotifications));
}

#[test]
fn detects_sync_with_notifications_show() {
    let body = r#"<script>
        reg.periodicSync.register("alert");
        registration.showNotification("New message");
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithNotifications));
}

#[test]
fn detects_sync_with_notifications_push() {
    let body = r#"<script>
        reg.sync.register("push");
        const sub = await registration.PushManager.subscribe();
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithNotifications));
}

#[test]
fn detects_sync_without_user_activation() {
    let body = r#"<script>
        reg.sync.register("auto");
        doBackgroundWork();
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithoutUserActivation));
}

#[test]
fn no_sync_without_user_activation_when_click() {
    let body = r#"<script>
        button.addEventListener("click", () => {
            reg.sync.register("user");
        });
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(!issues.contains(&BackgroundSyncIssue::SyncWithoutUserActivation));
}

#[test]
fn no_sync_without_user_activation_when_onclick() {
    let body = r#"<script>
        elem.onclick = () => {
            reg.periodicSync.register("interact");
        };
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(!issues.contains(&BackgroundSyncIssue::SyncWithoutUserActivation));
}

#[test]
fn no_sync_without_user_activation_when_addeventlistener() {
    let body = r#"<script>
        element.addEventListener("submit", () => {
            reg.sync.register("form");
        });
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(!issues.contains(&BackgroundSyncIssue::SyncWithoutUserActivation));
}

#[test]
fn no_sync_without_user_activation_when_user_activation() {
    let body = r#"<script>
        reg.sync.register("gated");
        // Check user-activation before syncing
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(!issues.contains(&BackgroundSyncIssue::SyncWithoutUserActivation));
}

#[test]
fn display_new_variants() {
    assert_eq!(
        BackgroundSyncIssue::SyncDataExfiltration.to_string(),
        "sync_data_exfiltration"
    );
    assert_eq!(
        BackgroundSyncIssue::SyncWithGeolocation.to_string(),
        "sync_with_geolocation"
    );
    assert_eq!(
        BackgroundSyncIssue::SyncCrossOrigin.to_string(),
        "sync_cross_origin"
    );
    assert_eq!(
        BackgroundSyncIssue::SyncWithCrypto.to_string(),
        "sync_with_crypto"
    );
    assert_eq!(
        BackgroundSyncIssue::PeriodicSyncAbuseRisk.to_string(),
        "periodic_sync_abuse_risk"
    );
    assert_eq!(
        BackgroundSyncIssue::SyncInServiceWorker.to_string(),
        "sync_in_service_worker"
    );
    assert_eq!(
        BackgroundSyncIssue::SyncWithIndexedDb.to_string(),
        "sync_with_indexed_db"
    );
    assert_eq!(
        BackgroundSyncIssue::SyncRetryLoop.to_string(),
        "sync_retry_loop"
    );
    assert_eq!(
        BackgroundSyncIssue::SyncWithNotifications.to_string(),
        "sync_with_notifications"
    );
    assert_eq!(
        BackgroundSyncIssue::SyncWithoutUserActivation.to_string(),
        "sync_without_user_activation"
    );
}

#[test]
fn severity_periodic_abuse_highest() {
    assert_eq!(
        background_sync_severity(&BackgroundSyncIssue::PeriodicSyncAbuseRisk),
        8.0
    );
}

#[test]
fn severity_data_exfiltration() {
    assert_eq!(
        background_sync_severity(&BackgroundSyncIssue::SyncDataExfiltration),
        7.5
    );
}

#[test]
fn severity_geolocation() {
    assert_eq!(
        background_sync_severity(&BackgroundSyncIssue::SyncWithGeolocation),
        7.0
    );
}

#[test]
fn severity_crypto() {
    assert_eq!(
        background_sync_severity(&BackgroundSyncIssue::SyncWithCrypto),
        7.0
    );
}

#[test]
fn severity_cross_origin() {
    assert_eq!(
        background_sync_severity(&BackgroundSyncIssue::SyncCrossOrigin),
        6.5
    );
}

#[test]
fn severity_indexed_db() {
    assert_eq!(
        background_sync_severity(&BackgroundSyncIssue::SyncWithIndexedDb),
        5.5
    );
}

#[test]
fn severity_notifications() {
    assert_eq!(
        background_sync_severity(&BackgroundSyncIssue::SyncWithNotifications),
        5.5
    );
}

#[test]
fn severity_service_worker() {
    assert_eq!(
        background_sync_severity(&BackgroundSyncIssue::SyncInServiceWorker),
        5.0
    );
}

#[test]
fn severity_retry_loop() {
    assert_eq!(
        background_sync_severity(&BackgroundSyncIssue::SyncRetryLoop),
        4.5
    );
}

#[test]
fn severity_without_user_activation() {
    assert_eq!(
        background_sync_severity(&BackgroundSyncIssue::SyncWithoutUserActivation),
        4.0
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        BackgroundSyncIssue::SyncDataExfiltration,
        BackgroundSyncIssue::PeriodicSyncAbuseRisk,
    ];
    let mut seq = 0;
    let ops = background_sync_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn multiple_security_issues_detected() {
    let body = r#"<script>
        reg.sync.register("complex");
        navigator.sendBeacon("/track");
        navigator.geolocation.getCurrentPosition(cb);
        window.postMessage(data, "*");
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncDataExfiltration));
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithGeolocation));
    assert!(issues.contains(&BackgroundSyncIssue::SyncCrossOrigin));
    assert!(issues.len() >= 3);
}

#[test]
fn security_analysis_with_periodic_sync() {
    let body = r#"<script>
        reg.periodicSync.register("data");
        indexedDB.open("cache");
        retryCount = 0;
    </script>"#;
    let issues = analyze_background_sync_security(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithIndexedDb));
    assert!(issues.contains(&BackgroundSyncIssue::SyncRetryLoop));
}
