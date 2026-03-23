use crate::device_memory_audit::*;

#[test]
fn no_device_memory_no_issues() {
    assert!(analyze_device_memory("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_navigator() {
    let body = r#"<script>const mem = navigator.deviceMemory;</script>"#;
    let issues = analyze_device_memory(body);
    assert!(issues.contains(&DeviceMemoryIssue::ApiDetected));
}

#[test]
fn detects_client_hint_header() {
    let body = r#"<meta http-equiv="Accept-CH" content="Device-Memory">"#;
    let issues = analyze_device_memory(body);
    assert!(issues.contains(&DeviceMemoryIssue::ClientHintHeader));
}

#[test]
fn detects_fingerprinting_vector() {
    let body = r#"<script>const mem = navigator.deviceMemory;</script>"#;
    let issues = analyze_device_memory(body);
    assert!(issues.contains(&DeviceMemoryIssue::FingerprintingVector));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const mem = navigator.deviceMemory;
        fetch("/track", {body: JSON.stringify({memory: mem})});
    </script>"#;
    let issues = analyze_device_memory(body);
    assert!(issues.contains(&DeviceMemoryIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>const mem = navigator.deviceMemory; console.log(mem);</script>"#;
    let issues = analyze_device_memory(body);
    assert!(!issues.contains(&DeviceMemoryIssue::DataExfiltration));
}

#[test]
fn detects_combined_fingerprint() {
    let body = r#"<script>
        const fp = {
            memory: navigator.deviceMemory,
            cores: navigator.hardwareConcurrency
        };
    </script>"#;
    let issues = analyze_device_memory(body);
    assert!(issues.contains(&DeviceMemoryIssue::CombinedFingerprint));
}

#[test]
fn no_combined_without_other_apis() {
    let body = r#"<script>const mem = navigator.deviceMemory;</script>"#;
    let issues = analyze_device_memory(body);
    assert!(!issues.contains(&DeviceMemoryIssue::CombinedFingerprint));
}

#[test]
fn detects_lowercase_header() {
    let body = r#"<meta http-equiv="Accept-CH" content="device-memory">"#;
    let issues = analyze_device_memory(body);
    assert!(issues.contains(&DeviceMemoryIssue::ClientHintHeader));
}

#[test]
fn severity_combined_highest() {
    assert_eq!(
        device_memory_severity(&DeviceMemoryIssue::CombinedFingerprint),
        7.0
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(device_memory_severity(&DeviceMemoryIssue::ApiDetected), 2.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        DeviceMemoryIssue::ApiDetected,
        DeviceMemoryIssue::FingerprintingVector,
    ];
    let mut seq = 0;
    let ops = device_memory_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(DeviceMemoryIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        DeviceMemoryIssue::FingerprintingVector.to_string(),
        "fingerprinting_vector"
    );
    assert_eq!(
        DeviceMemoryIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        DeviceMemoryIssue::CombinedFingerprint.to_string(),
        "combined_fingerprint"
    );
    assert_eq!(
        DeviceMemoryIssue::ClientHintHeader.to_string(),
        "client_hint_header"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_device_memory("").is_empty());
}

// New security analysis tests

#[test]
fn security_no_device_memory_no_issues() {
    let body = r#"<script>const quality = "high";</script>"#;
    assert!(analyze_device_memory_security(body).is_empty());
}

#[test]
fn security_detects_memory_based_content_adaptation() {
    let body = r#"<script>
        const mem = navigator.deviceMemory;
        const quality = mem < 4 ? 'low' : 'high';
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryBasedContentAdaptation));
}

#[test]
fn security_content_adaptation_requires_quality() {
    let body = r#"<script>const mem = navigator.deviceMemory;</script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(!issues.contains(&DeviceMemoryIssue::MemoryBasedContentAdaptation));
}

#[test]
fn security_content_adaptation_resolution() {
    let body = r#"<script>
        if (deviceMemory < 4) {
            resolution = 720;
        }
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryBasedContentAdaptation));
}

#[test]
fn security_content_adaptation_adaptive() {
    let body = r#"<script>adaptive = deviceMemory > 4;</script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryBasedContentAdaptation));
}

#[test]
fn security_content_adaptation_low_end() {
    let body = r#"<script>const lowEnd = deviceMemory <= 2;</script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryBasedContentAdaptation));
}

#[test]
fn security_detects_cross_origin_memory_sharing() {
    let body = r#"<script>
        const mem = deviceMemory;
        parent.postMessage({memory: mem}, '*');
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::CrossOriginMemorySharing));
}

#[test]
fn security_cross_origin_shared_array_buffer() {
    let body = r#"<script>
        const sab = new SharedArrayBuffer(deviceMemory * 1024);
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::CrossOriginMemorySharing));
}

#[test]
fn security_cross_origin_explicit() {
    let body = r#"<script>
        fetch('https://cross-origin.com', {
            body: JSON.stringify({deviceMemory})
        });
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::CrossOriginMemorySharing));
}

#[test]
fn security_cross_origin_requires_keyword() {
    let body = r#"<script>const mem = deviceMemory;</script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(!issues.contains(&DeviceMemoryIssue::CrossOriginMemorySharing));
}

#[test]
fn security_detects_worker_memory_access() {
    let body = r#"<script>
        const worker = new Worker('worker.js');
        worker.postMessage({memory: deviceMemory});
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::WorkerMemoryAccess));
}

#[test]
fn security_worker_shared_worker() {
    let body = r#"<script>
        const sw = new SharedWorker('shared.js');
        sw.port.postMessage(deviceMemory);
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::WorkerMemoryAccess));
}

#[test]
fn security_worker_service_worker() {
    let body = r#"<script>
        navigator.serviceWorker.register('sw.js').then(reg => {
            reg.active.postMessage({deviceMemory});
        });
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::WorkerMemoryAccess));
}

#[test]
fn security_worker_requires_worker_keyword() {
    let body = r#"<script>const mem = deviceMemory;</script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(!issues.contains(&DeviceMemoryIssue::WorkerMemoryAccess));
}

#[test]
fn security_detects_memory_threshold_branching() {
    let body = r#"<script>
        if (deviceMemory < 4) {
            loadLowQualityAssets();
        }
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryThresholdBranching));
}

#[test]
fn security_threshold_less_equal() {
    let body = r#"<script>const isLowMem = deviceMemory <= 2;</script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryThresholdBranching));
}

#[test]
fn security_threshold_greater() {
    let body = r#"<script>const isHighMem = deviceMemory > 8;</script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryThresholdBranching));
}

#[test]
fn security_threshold_explicit_keyword() {
    let body = r#"<script>
        const threshold = 4;
        if (deviceMemory < threshold) {}
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryThresholdBranching));
}

#[test]
fn security_threshold_if_pattern() {
    let body = r#"<script>if.*deviceMemory</script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryThresholdBranching));
}

#[test]
fn security_detects_memory_in_local_storage() {
    let body = r#"<script>
        localStorage.setItem('deviceMemory', deviceMemory);
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryInLocalStorage));
}

#[test]
fn security_local_storage_session_storage() {
    let body = r#"<script>
        sessionStorage.memory = deviceMemory;
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryInLocalStorage));
}

#[test]
fn security_local_storage_requires_storage_keyword() {
    let body = r#"<script>const mem = deviceMemory;</script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(!issues.contains(&DeviceMemoryIssue::MemoryInLocalStorage));
}

#[test]
fn security_detects_memory_in_cookies() {
    let body = r#"<script>
        document.cookie = 'deviceMemory=' + deviceMemory;
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryInCookies));
}

#[test]
fn security_cookies_set_cookie() {
    let body = r#"<script>
        setCookie('mem', deviceMemory);
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryInCookies));
}

#[test]
fn security_cookies_cookie_generic() {
    let body = r#"<script>
        Cookie.set('memory', deviceMemory);
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryInCookies));
}

#[test]
fn security_cookies_requires_cookie_keyword() {
    let body = r#"<script>const mem = deviceMemory;</script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(!issues.contains(&DeviceMemoryIssue::MemoryInCookies));
}

#[test]
fn security_detects_memory_based_resource_loading() {
    let body = r#"<script>
        const img = document.createElement('img');
        img.src= deviceMemory > 4 ? 'hq.jpg' : 'lq.jpg';
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryBasedResourceLoading));
}

#[test]
fn security_resource_loading_href() {
    let body = r#"<script>
        link.href= `/style-${deviceMemory}.css`;
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryBasedResourceLoading));
}

#[test]
fn security_resource_loading_import() {
    let body = r#"<script>
        const module = deviceMemory > 4 ? 'hq' : 'lq';
        import(`${module}.js`);
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryBasedResourceLoading));
}

#[test]
fn security_resource_loading_load_script() {
    let body = r#"<script>
        loadScript(deviceMemory > 4 ? 'hq.js' : 'lq.js');
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryBasedResourceLoading));
}

#[test]
fn security_resource_loading_requires_loading_keyword() {
    let body = r#"<script>const mem = deviceMemory;</script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(!issues.contains(&DeviceMemoryIssue::MemoryBasedResourceLoading));
}

#[test]
fn security_detects_memory_with_battery_status() {
    let body = r#"<script>
        Promise.all([
            navigator.getBattery(),
            Promise.resolve(deviceMemory)
        ]).then(([battery, mem]) => {
            track(battery.level, mem);
        });
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryWithBatteryStatus));
}

#[test]
fn security_battery_status_battery_keyword() {
    let body = r#"<script>
        const battery = await navigator.getBattery();
        const fp = {battery: battery.level, memory: deviceMemory};
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryWithBatteryStatus));
}

#[test]
fn security_battery_status_battery_manager() {
    let body = r#"<script>
        // BatteryManager API
        const data = {deviceMemory, batteryLevel};
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryWithBatteryStatus));
}

#[test]
fn security_battery_requires_battery_keyword() {
    let body = r#"<script>const mem = deviceMemory;</script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(!issues.contains(&DeviceMemoryIssue::MemoryWithBatteryStatus));
}

#[test]
fn security_detects_memory_with_network_info() {
    let body = r#"<script>
        const conn = navigator.connection.effectiveType;
        const fp = {memory: deviceMemory, network: conn};
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryWithNetworkInfo));
}

#[test]
fn security_network_info_navigator_connection() {
    let body = r#"<script>
        const netInfo = navigator.connection;
        track({deviceMemory, netInfo});
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryWithNetworkInfo));
}

#[test]
fn security_network_info_network_information() {
    let body = r#"<script>
        // NetworkInformation API
        const data = {deviceMemory, downlink};
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryWithNetworkInfo));
}

#[test]
fn security_network_requires_network_keyword() {
    let body = r#"<script>const mem = deviceMemory;</script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(!issues.contains(&DeviceMemoryIssue::MemoryWithNetworkInfo));
}

#[test]
fn security_detects_memory_timing_attack() {
    let body = r#"<script>
        const start = performance.now();
        const mem = deviceMemory;
        const elapsed = performance.now() - start;
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryTimingAttack));
}

#[test]
fn security_timing_attack_date_now() {
    let body = r#"<script>
        const t0 = Date.now();
        const mem = deviceMemory;
        const delta = Date.now() - t0;
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryTimingAttack));
}

#[test]
fn security_timing_attack_performance_mark() {
    let body = r#"<script>
        performance.mark('mem-start');
        const mem = deviceMemory;
        performance.mark('mem-end');
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryTimingAttack));
}

#[test]
fn security_timing_requires_timing_keyword() {
    let body = r#"<script>const mem = deviceMemory;</script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(!issues.contains(&DeviceMemoryIssue::MemoryTimingAttack));
}

#[test]
fn security_combined_multiple_issues() {
    let body = r#"<script>
        const mem = deviceMemory;
        localStorage.setItem('memory', mem);
        document.cookie = 'mem=' + mem;
        const worker = new Worker('w.js');
        worker.postMessage(mem);
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryInLocalStorage));
    assert!(issues.contains(&DeviceMemoryIssue::MemoryInCookies));
    assert!(issues.contains(&DeviceMemoryIssue::WorkerMemoryAccess));
}

#[test]
fn security_realistic_fingerprinting_script() {
    let body = r#"<script>
        const fingerprint = {
            memory: navigator.deviceMemory,
            cores: navigator.hardwareConcurrency,
            battery: await navigator.getBattery(),
            network: navigator.connection.effectiveType
        };
        localStorage.setItem('fp', JSON.stringify(fingerprint));
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryInLocalStorage));
    assert!(issues.contains(&DeviceMemoryIssue::MemoryWithBatteryStatus));
    assert!(issues.contains(&DeviceMemoryIssue::MemoryWithNetworkInfo));
}

#[test]
fn security_realistic_adaptive_loading() {
    let body = r#"<script>
        const mem = deviceMemory;
        const quality = mem < 4 ? 'low' : mem > 8 ? 'ultra' : 'medium';
        const script = document.createElement('script');
        script.src= `/assets/${quality}/bundle.js`;
        document.head.appendChild(script);
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::MemoryBasedContentAdaptation));
    assert!(issues.contains(&DeviceMemoryIssue::MemoryThresholdBranching));
    assert!(issues.contains(&DeviceMemoryIssue::MemoryBasedResourceLoading));
}

#[test]
fn security_realistic_cross_origin_sharing() {
    let body = r#"<script>
        const sab = new SharedArrayBuffer(deviceMemory * 1024);
        const worker = new SharedWorker('processor.js');
        worker.port.postMessage(sab);
        parent.postMessage({memory: deviceMemory}, 'https://analytics.example.com');
    </script>"#;
    let issues = analyze_device_memory_security(body);
    assert!(issues.contains(&DeviceMemoryIssue::CrossOriginMemorySharing));
    assert!(issues.contains(&DeviceMemoryIssue::WorkerMemoryAccess));
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        DeviceMemoryIssue::MemoryTimingAttack,
        DeviceMemoryIssue::CrossOriginMemorySharing,
    ];
    let mut seq = 0;
    let ops = device_memory_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_display_new_variants() {
    assert_eq!(
        DeviceMemoryIssue::MemoryBasedContentAdaptation.to_string(),
        "memory_based_content_adaptation"
    );
    assert_eq!(
        DeviceMemoryIssue::CrossOriginMemorySharing.to_string(),
        "cross_origin_memory_sharing"
    );
    assert_eq!(
        DeviceMemoryIssue::WorkerMemoryAccess.to_string(),
        "worker_memory_access"
    );
    assert_eq!(
        DeviceMemoryIssue::MemoryThresholdBranching.to_string(),
        "memory_threshold_branching"
    );
    assert_eq!(
        DeviceMemoryIssue::MemoryInLocalStorage.to_string(),
        "memory_in_local_storage"
    );
    assert_eq!(
        DeviceMemoryIssue::MemoryInCookies.to_string(),
        "memory_in_cookies"
    );
    assert_eq!(
        DeviceMemoryIssue::MemoryBasedResourceLoading.to_string(),
        "memory_based_resource_loading"
    );
    assert_eq!(
        DeviceMemoryIssue::MemoryWithBatteryStatus.to_string(),
        "memory_with_battery_status"
    );
    assert_eq!(
        DeviceMemoryIssue::MemoryWithNetworkInfo.to_string(),
        "memory_with_network_info"
    );
    assert_eq!(
        DeviceMemoryIssue::MemoryTimingAttack.to_string(),
        "memory_timing_attack"
    );
}

#[test]
fn security_severity_timing_attack_highest() {
    assert_eq!(
        device_memory_severity(&DeviceMemoryIssue::MemoryTimingAttack),
        8.0
    );
}

#[test]
fn security_severity_cross_origin_high() {
    assert_eq!(
        device_memory_severity(&DeviceMemoryIssue::CrossOriginMemorySharing),
        7.5
    );
}

#[test]
fn security_severity_content_adaptation_lowest() {
    assert_eq!(
        device_memory_severity(&DeviceMemoryIssue::MemoryBasedContentAdaptation),
        3.0
    );
}

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_device_memory_security("").is_empty());
}

#[test]
fn security_no_false_positive_on_similar_keywords() {
    let body = r#"<script>
        const memory = calculateMemory();
        const worker = new WorkerPool();
    </script>"#;
    // Should not trigger because 'deviceMemory' is absent
    assert!(analyze_device_memory_security(body).is_empty());
}
