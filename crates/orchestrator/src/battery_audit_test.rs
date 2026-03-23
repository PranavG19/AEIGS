use crate::battery_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_battery("");
    assert!(issues.is_empty());
}

#[test]
fn no_battery_no_issues() {
    let body = "var x = document.title;";
    let issues = analyze_battery(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_battery_api() {
    let body = "navigator.getBattery().then(battery => {});";
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::BatteryApiUsed));
}

#[test]
fn detects_battery_level() {
    let body = r#"
        navigator.getBattery().then(battery => {
            console.log(battery.level);
        });
    "#;
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::BatteryLevelRead));
}

#[test]
fn detects_charging_state() {
    let body = r#"
        navigator.getBattery().then(battery => {
            console.log(battery.charging);
        });
    "#;
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::ChargingStateRead));
}

#[test]
fn detects_discharging_time() {
    let body = r#"
        navigator.getBattery().then(battery => {
            console.log(battery.dischargingTime);
        });
    "#;
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::ChargingStateRead));
}

#[test]
fn detects_event_listener() {
    let body = r#"
        navigator.getBattery().then(battery => {
            battery.addEventListener('levelchange', update);
        });
    "#;
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::BatteryEventListener));
}

#[test]
fn detects_charging_change_event() {
    let body = r#"
        navigator.getBattery().then(battery => {
            battery.addEventListener('chargingchange', update);
        });
    "#;
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::BatteryEventListener));
}

#[test]
fn detects_battery_data_sent() {
    let body = r#"
        navigator.getBattery().then(battery => {
            fetch('/track', {body: JSON.stringify({level: battery.level})});
        });
    "#;
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::BatteryDataSent));
}

#[test]
fn no_data_sent_without_network() {
    let body = r#"
        navigator.getBattery().then(battery => {
            console.log(battery.level);
        });
    "#;
    let issues = analyze_battery(body);
    assert!(!issues.contains(&BatteryIssue::BatteryDataSent));
}

#[test]
fn detects_battery_manager() {
    let body = "if (typeof BatteryManager !== 'undefined') { }";
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::BatteryApiUsed));
}

#[test]
fn severity_data_sent_highest() {
    assert_eq!(battery_severity(&BatteryIssue::BatteryDataSent), 6.0);
}

#[test]
fn severity_api_used_lowest() {
    assert_eq!(battery_severity(&BatteryIssue::BatteryApiUsed), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![BatteryIssue::BatteryApiUsed, BatteryIssue::BatteryLevelRead];
    let mut seq = 0;
    let ops = battery_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(BatteryIssue::BatteryApiUsed.to_string(), "battery_api");
    assert_eq!(
        BatteryIssue::BatteryLevelRead.to_string(),
        "battery_level_read"
    );
    assert_eq!(
        BatteryIssue::ChargingStateRead.to_string(),
        "charging_state_read"
    );
    assert_eq!(
        BatteryIssue::BatteryEventListener.to_string(),
        "battery_event_listener"
    );
    assert_eq!(
        BatteryIssue::BatteryDataSent.to_string(),
        "battery_data_sent"
    );
    assert_eq!(
        BatteryIssue::BatteryFingerprinting.to_string(),
        "battery_fingerprinting"
    );
    assert_eq!(
        BatteryIssue::BatteryCrossOriginSharing.to_string(),
        "battery_cross_origin_sharing"
    );
    assert_eq!(
        BatteryIssue::BatteryInWorker.to_string(),
        "battery_in_worker"
    );
    assert_eq!(
        BatteryIssue::BatteryWithStorage.to_string(),
        "battery_with_storage"
    );
    assert_eq!(
        BatteryIssue::BatteryBasedCryptomining.to_string(),
        "battery_based_cryptomining"
    );
    assert_eq!(
        BatteryIssue::BatteryDrainAttack.to_string(),
        "battery_drain_attack"
    );
    assert_eq!(
        BatteryIssue::BatteryThresholdTracking.to_string(),
        "battery_threshold_tracking"
    );
    assert_eq!(
        BatteryIssue::BatteryWithDeviceMemory.to_string(),
        "battery_with_device_memory"
    );
    assert_eq!(
        BatteryIssue::BatteryWithNetworkInfo.to_string(),
        "battery_with_network_info"
    );
    assert_eq!(
        BatteryIssue::BatteryPersistentMonitoring.to_string(),
        "battery_persistent_monitoring"
    );
}

#[test]
fn security_empty_body_no_issues() {
    let issues = analyze_battery_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_no_battery_no_issues() {
    let body = "var x = document.title; fingerprint();";
    let issues = analyze_battery_security(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_battery_fingerprinting_with_fingerprint() {
    let body = r#"
        navigator.getBattery().then(battery => {
            const fingerprint = generateFingerprint(battery.level);
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryFingerprinting));
}

#[test]
fn detects_battery_fingerprinting_with_hash() {
    let body = r#"
        navigator.getBattery().then(battery => {
            const hash = hashCode(battery.level);
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryFingerprinting));
}

#[test]
fn detects_battery_fingerprinting_with_canvas() {
    let body = r#"
        navigator.getBattery().then(battery => {
            const canvas = document.createElement('canvas');
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryFingerprinting));
}

#[test]
fn detects_battery_fingerprinting_with_screen() {
    let body = r#"
        navigator.getBattery().then(battery => {
            const width = screen.width;
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryFingerprinting));
}

#[test]
fn detects_battery_cross_origin_sharing_postmessage() {
    let body = r#"
        navigator.getBattery().then(battery => {
            window.parent.postMessage({level: battery.level}, '*');
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryCrossOriginSharing));
}

#[test]
fn detects_battery_cross_origin_sharing_iframe() {
    let body = r#"
        navigator.getBattery().then(battery => {
            const iframe = document.createElement('iframe');
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryCrossOriginSharing));
}

#[test]
fn detects_battery_cross_origin_sharing_keyword() {
    let body = r#"
        navigator.getBattery().then(battery => {
            // cross-origin data sharing
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryCrossOriginSharing));
}

#[test]
fn detects_battery_in_worker() {
    let body = r#"
        const worker = new Worker('battery-worker.js');
        navigator.getBattery().then(battery => {
            worker.postMessage(battery.level);
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryInWorker));
}

#[test]
fn detects_battery_in_shared_worker() {
    let body = r#"
        const worker = new SharedWorker('battery-worker.js');
        navigator.getBattery().then(battery => {
            worker.port.postMessage(battery.level);
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryInWorker));
}

#[test]
fn detects_battery_with_localstorage() {
    let body = r#"
        navigator.getBattery().then(battery => {
            localStorage.setItem('battery', battery.level);
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryWithStorage));
}

#[test]
fn detects_battery_with_sessionstorage() {
    let body = r#"
        navigator.getBattery().then(battery => {
            sessionStorage.setItem('battery', battery.level);
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryWithStorage));
}

#[test]
fn detects_battery_with_indexeddb() {
    let body = r#"
        navigator.getBattery().then(battery => {
            const request = indexedDB.open('batteryDB');
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryWithStorage));
}

#[test]
fn detects_battery_based_cryptomining_mine() {
    let body = r#"
        navigator.getBattery().then(battery => {
            if (battery.charging) {
                startMine();
            }
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryBasedCryptomining));
}

#[test]
fn detects_battery_based_cryptomining_miner() {
    let body = r#"
        navigator.getBattery().then(battery => {
            const miner = new CryptoMiner();
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryBasedCryptomining));
}

#[test]
fn detects_battery_based_cryptomining_crypto() {
    let body = r#"
        navigator.getBattery().then(battery => {
            crypto.subtle.digest('SHA-256', data);
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryBasedCryptomining));
}

#[test]
fn detects_battery_based_cryptomining_wasm() {
    let body = r#"
        navigator.getBattery().then(battery => {
            WebAssembly.instantiate(wasmModule);
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryBasedCryptomining));
}

#[test]
fn detects_battery_drain_attack_while_true() {
    let body = r#"
        navigator.getBattery().then(battery => {
            while(true) { compute(); }
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryDrainAttack));
}

#[test]
fn detects_battery_drain_attack_while_true_spaced() {
    let body = r#"
        navigator.getBattery().then(battery => {
            while (true) { compute(); }
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryDrainAttack));
}

#[test]
fn detects_battery_drain_attack_for_infinite() {
    let body = r#"
        navigator.getBattery().then(battery => {
            for(;;) { compute(); }
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryDrainAttack));
}

#[test]
fn detects_battery_drain_attack_infinite_keyword() {
    let body = r#"
        navigator.getBattery().then(battery => {
            // infinite loop attack
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryDrainAttack));
}

#[test]
fn detects_battery_threshold_tracking_less_than() {
    let body = r#"
        navigator.getBattery().then(battery => {
            if (battery.level < 0.2) { track(); }
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryThresholdTracking));
}

#[test]
fn detects_battery_threshold_tracking_less_equal() {
    let body = r#"
        navigator.getBattery().then(battery => {
            if (battery.level <= 0.15) { track(); }
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryThresholdTracking));
}

#[test]
fn detects_battery_threshold_tracking_greater_than() {
    let body = r#"
        navigator.getBattery().then(battery => {
            if (battery.level > 0.8) { track(); }
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryThresholdTracking));
}

#[test]
fn detects_battery_threshold_tracking_threshold_keyword() {
    let body = r#"
        navigator.getBattery().then(battery => {
            const threshold = 0.2;
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryThresholdTracking));
}

#[test]
fn detects_battery_threshold_tracking_low_keyword() {
    let body = r#"
        navigator.getBattery().then(battery => {
            if (battery.level) { showLowBatteryWarning(); }
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryThresholdTracking));
}

#[test]
fn detects_battery_with_device_memory() {
    let body = r#"
        navigator.getBattery().then(battery => {
            const mem = navigator.deviceMemory;
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryWithDeviceMemory));
}

#[test]
fn detects_battery_with_hardware_concurrency() {
    let body = r#"
        navigator.getBattery().then(battery => {
            const cores = navigator.hardwareConcurrency;
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryWithDeviceMemory));
}

#[test]
fn detects_battery_with_network_info_effective_type() {
    let body = r#"
        navigator.getBattery().then(battery => {
            const type = navigator.connection.effectiveType;
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryWithNetworkInfo));
}

#[test]
fn detects_battery_with_network_info_connection() {
    let body = r#"
        navigator.getBattery().then(battery => {
            const conn = navigator.connection;
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryWithNetworkInfo));
}

#[test]
fn detects_battery_with_network_info_network_information() {
    let body = r#"
        navigator.getBattery().then(battery => {
            if (NetworkInformation) { }
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryWithNetworkInfo));
}

#[test]
fn detects_battery_persistent_monitoring_setinterval() {
    let body = r#"
        navigator.getBattery().then(battery => {
            battery.addEventListener('levelchange', update);
            setInterval(poll, 1000);
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryPersistentMonitoring));
}

#[test]
fn detects_battery_persistent_monitoring_requestanimationframe() {
    let body = r#"
        navigator.getBattery().then(battery => {
            battery.addEventListener('chargingchange', update);
            requestAnimationFrame(poll);
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryPersistentMonitoring));
}

#[test]
fn no_persistent_monitoring_without_event_listener() {
    let body = r#"
        navigator.getBattery().then(battery => {
            setInterval(poll, 1000);
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(!issues.contains(&BatteryIssue::BatteryPersistentMonitoring));
}

#[test]
fn no_persistent_monitoring_without_interval() {
    let body = r#"
        navigator.getBattery().then(battery => {
            battery.addEventListener('levelchange', update);
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(!issues.contains(&BatteryIssue::BatteryPersistentMonitoring));
}

#[test]
fn severity_cryptomining_highest() {
    assert_eq!(
        battery_severity(&BatteryIssue::BatteryBasedCryptomining),
        8.5
    );
}

#[test]
fn severity_drain_attack_high() {
    assert_eq!(battery_severity(&BatteryIssue::BatteryDrainAttack), 8.0);
}

#[test]
fn severity_cross_origin_high() {
    assert_eq!(
        battery_severity(&BatteryIssue::BatteryCrossOriginSharing),
        7.0
    );
}

#[test]
fn severity_fingerprinting_medium_high() {
    assert_eq!(battery_severity(&BatteryIssue::BatteryFingerprinting), 6.5);
}

#[test]
fn severity_persistent_monitoring_medium_high() {
    assert_eq!(
        battery_severity(&BatteryIssue::BatteryPersistentMonitoring),
        6.5
    );
}

#[test]
fn severity_with_storage_medium() {
    assert_eq!(battery_severity(&BatteryIssue::BatteryWithStorage), 6.0);
}

#[test]
fn severity_with_device_memory_medium() {
    assert_eq!(
        battery_severity(&BatteryIssue::BatteryWithDeviceMemory),
        6.0
    );
}

#[test]
fn severity_in_worker_medium_low() {
    assert_eq!(battery_severity(&BatteryIssue::BatteryInWorker), 5.5);
}

#[test]
fn severity_with_network_info_medium_low() {
    assert_eq!(battery_severity(&BatteryIssue::BatteryWithNetworkInfo), 5.5);
}

#[test]
fn severity_threshold_tracking_medium_low() {
    assert_eq!(
        battery_severity(&BatteryIssue::BatteryThresholdTracking),
        5.0
    );
}

#[test]
fn battery_security_to_operations_creates_entries() {
    let issues = vec![
        BatteryIssue::BatteryFingerprinting,
        BatteryIssue::BatteryBasedCryptomining,
    ];
    let mut seq = 0;
    let ops = battery_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn multiple_security_issues_detected() {
    let body = r#"
        navigator.getBattery().then(battery => {
            const fingerprint = hashCode(battery.level);
            localStorage.setItem('battery', battery.level);
            window.parent.postMessage({level: battery.level}, '*');
        });
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryFingerprinting));
    assert!(issues.contains(&BatteryIssue::BatteryWithStorage));
    assert!(issues.contains(&BatteryIssue::BatteryCrossOriginSharing));
}

#[test]
fn battery_manager_triggers_security_analysis() {
    let body = r#"
        if (typeof BatteryManager !== 'undefined') {
            const fingerprint = generateHash();
        }
    "#;
    let issues = analyze_battery_security(body);
    assert!(issues.contains(&BatteryIssue::BatteryFingerprinting));
}
